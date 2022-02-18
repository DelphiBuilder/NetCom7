unit ncSources;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit creates a TCP Server Source and a TCP Client Source compoents,
// along with their threads dealing with handling commands.
//
// The idea behind the source components is to be able to extend the sockets
// to handle well defined buffers. Sockets on their own are streaming so
// you have to implement a mechanism of picking the buffers from the stream
// to process.
//
// The components implemented here introduce an ExecCommand which sends to
// the peer (be it a client or a server) the command along with its data to
// be executed. The peer then calls the OnHandleCommand with the data supplied,
// and packs the result back to the calling peer. If an exception is raised,
// it is packed and raised back at the caller, so that client/server applications
// can utilise the exception mechanisms.
//
// The buffer packing and unpacking from the stream can handle garbage thrown
// at it.
//
// These components have built in encryption and compression, set by the
// corresponding properties.
//
// 14 Feb 2022 by Andreas Toth - andreas.toth@xtra.co.nz
// - Added UDP and IPv6 support
//
// 12/8/2020
// - Complete re-engineering of the base component
//
// 16/12/2010
// - Initial creation
//
// Written by Demos Bill
//
// /////////////////////////////////////////////////////////////////////////////

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
{$IFDEF MSWINDOWS}
  Winapi.Windows,
  Winapi.Winsock2,
{$ELSE}
  Posix.SysSocket,
  Posix.Unistd,
{$ENDIF}
  System.Classes,
  System.SysUtils,
  System.SyncObjs,
  System.Math,
  System.ZLib,
  System.Diagnostics,
  System.TimeSpan,
  System.RTLConsts,
  System.Types,
  ncCommandPacking,
  ncLines,
  ncSocketList,
  ncThreads,
  ncSockets,
  ncPendingCommandsList,
  ncCompression,
  ncEncryption;

type
  TncCommandDirection =
  (
    cdIncoming,
    cdOutgoing
  );

  ENetComInvalidCommandHandler = class(Exception);
  ENetComCommandExecutionTimeout = class(Exception);
  ENetComResultIsException = class(Exception);

resourcestring
  ENetComInvalidCommandHandlerMessage = 'Cannot attach component, it does not support the command handler interface';
  ENetComCommandExecutionTimeoutMessage = 'Command execution timeout';

type
  TMagicHeaderType = UInt32;
  PMagicHeaderType = ^TMagicHeaderType;

const
  MagicHeader: TMagicHeaderType = $ACF0FF00; // Bin: 10101100111100001111111100000000

  DefPort = 17233;

  DefExecThreadPriority = ntpNormal;
  DefExecThreads = 0;
  DefExecThreadsPerCPU = 4;
  DefExecThreadsGrowUpto = 32;

  DefExecCommandTimeout = 15000;

  DefEventsUseMainThread = False;
  DefNoDelay = True;

  DefCompression = zcNone;
  DefEncryption = etNoEncryption;
  DefEncryptionKey = 'SetEncryptionKey';
  DefEncryptOnHashedKey = True;

type
  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncSourceLine

  // Bring in TncLine from ncLines so that components placed on a form will
  // not have to reference ncLines unit
  TncLine = ncLines.TncLine;

  TncSourceLine = class(TncLine)
  protected
    MessageData, HeaderBytes: TBytes;
    BytesToEndOfMessage: UInt64;
  protected
    function CreateLineObject: TncLine; override;
  public
    constructor Create; overload; override;
  end;

  TncOnSourceConnectDisconnect = procedure(Sender: TObject; aLine: TncLine) of object;
  TncOnSourceReconnected = procedure(Sender: TObject; aLine: TncLine) of object;
  TncOnSourceHandleCommand = function(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TBytes; aRequiresResult: Boolean; const aSenderComponent, aReceiverComponent: string): TBytes of object;
  TncOnAsyncExecCommandResult = procedure(Sender: TObject; aLine: TncLine; aCmd: Integer; const aResult: TBytes; aResultIsError: Boolean; const aSenderComponent, aReceiverComponent: string) of object;

  IncCommandHandler = interface
    ['{22337701-9561-489A-8593-82EAA3B1B431}']
    function GetOnConnected: TncOnSourceConnectDisconnect;
    procedure SetOnConnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnDisconnected: TncOnSourceConnectDisconnect;
    procedure SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
    function GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    procedure SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);

    function GetComponentName: string;

    property OnConnected: TncOnSourceConnectDisconnect read GetOnConnected write SetOnConnected;
    property OnDisconnected: TncOnSourceConnectDisconnect read GetOnDisconnected write SetOnDisconnected;
    property OnHandleCommand: TncOnSourceHandleCommand read GetOnHandleCommand write SetOnHandleCommand;
    property OnAsyncExecCommandResult: TncOnAsyncExecCommandResult read GetOnAsyncExecCommandResult write SetOnAsyncExecCommandResult;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncSourceBase
  // Is the base for handling Exec and Handle command for the ServerSource and ClientSource

  TncSourceBase = class(TComponent, IncCommandHandler)
  private
    FCommandExecTimeout: Cardinal;
    FCommandProcessorThreadPriority: TncThreadPriority;
    FCommandProcessorThreads: Integer;
    FCommandProcessorThreadsPerCPU: Integer;
    FCommandProcessorThreadsGrowUpto: Integer;
    FEventsUseMainThread: Boolean;
    FCompression: TncCompressionLevel;
    FEncryption: TEncryptorType;
    FEncryptionKey: string;
    FEncryptOnHashedKey: Boolean;

    FOnConnected: TncOnSourceConnectDisconnect;
    FOnDisconnected: TncOnSourceConnectDisconnect;
    FOnHandleCommand: TncOnSourceHandleCommand;
    FOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;

    // From socket
    function GetActive: Boolean;
    procedure SetActive(const Value: Boolean);
    function GetKeepAlive: Boolean;
    procedure SetKeepAlive(const Value: Boolean);
    function GetNoDelay: Boolean;
    procedure SetNoDelay(const Value: Boolean);
    function GetPort: Integer;
    procedure SetPort(const Value: Integer);
    function GetReaderThreadPriority: TncThreadPriority;
    procedure SetReaderThreadPriority(const Value: TncThreadPriority);

    // For implementing the IncCommandHandler interface
    function GetComponentName: string;
    function GetOnConnected: TncOnSourceConnectDisconnect;
    procedure SetOnConnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnDisconnected: TncOnSourceConnectDisconnect;
    procedure SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
    function GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    procedure SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);

    // Property getters and setters
    function GetExecCommandTimeout: Cardinal;
    procedure SetExecCommandTimeout(const Value: Cardinal);
    function GetCommandProcessorThreadPriority: TncThreadPriority;
    procedure SetCommandProcessorThreadPriority(const Value: TncThreadPriority);
    function GetCommandProcessorThreads: Integer;
    procedure SetCommandProcessorThreads(const Value: Integer);
    function GetCommandProcessorThreadsPerCPU: Integer;
    procedure SetCommandProcessorThreadsPerCPU(const Value: Integer);
    function GetCommandProcessorThreadsGrowUpto: Integer;
    procedure SetCommandProcessorThreadsGrowUpto(const Value: Integer);
    function GetEventsUseMainThread: Boolean;
    procedure SetEventsUseMainThread(const Value: Boolean);
    function GetCompression: TncCompressionLevel;
    procedure SetCompression(const Value: TncCompressionLevel);
    function GetEncryption: TEncryptorType;
    procedure SetEncryption(const Value: TEncryptorType);
    function GetEncryptionKey: string;
    procedure SetEncryptionKey(const Value: string);
    function GetEncryptOnHashedKey: Boolean;
    procedure SetEncryptOnHashedKey(const Value: Boolean);
  private
    // To set the component active on loaded if was set at design time
    WasSetActive: Boolean;
    WithinConnectionHandler: Boolean;
  protected
    PropertyLock: TCriticalSection;
    CommandHandlers: array of IncCommandHandler;
    UniqueSentID: TncCommandUniqueID;
    HandleCommandThreadPool: TncThreadPool;
    Socket: TncCustomSocket;
    ExecuteSerialiser: TCriticalSection;

    LastConnectedLine: TncLine;
    LastDisconnectedLine: TncLine;
    LastReconnectedLine: TncLine;

    PendingCommandsList: TPendingCommandsList;

    procedure Loaded; override;
    procedure CallConnectedEvents;
    procedure SocketConnected(Sender: TObject; aLine: TncLine);
    procedure CallDisconnectedEvents;
    procedure SocketDisconnected(Sender: TObject; aLine: TncLine);
    procedure CallReconnectedEvents;
    procedure SocketReconnected(Sender: TObject; aLine: TncLine);
    procedure SocketReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
    procedure WriteMessage(aLine: TncSourceLine; const aBuf: TBytes); virtual;
    procedure WriteCommand(aLine: TncSourceLine; const aCmd: TncCommand); inline;
    procedure HandleReceivedCommand(aLine: TncSourceLine; const aCommandBytes: TBytes); inline;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function ExecCommand(aLine: TncLine; const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True; const aAsyncExecute: Boolean = False; const aPeerComponentHandler: string = ''; const aSourceComponentHandler: string = ''): TBytes; overload; virtual;

    procedure AddCommandHandler(aHandler: TComponent);
    procedure RemoveCommandHandler(aHandler: TComponent);
  published
    // From socket
    property Active: Boolean read GetActive write SetActive default False;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default True;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default True;

    // New properties for sources
    property CommandProcessorThreadPriority: TncThreadPriority read GetCommandProcessorThreadPriority write SetCommandProcessorThreadPriority default DefExecThreadPriority;
    property CommandProcessorThreads: Integer read GetCommandProcessorThreads write SetCommandProcessorThreads default DefExecThreads;
    property CommandProcessorThreadsPerCPU: Integer read GetCommandProcessorThreadsPerCPU write SetCommandProcessorThreadsPerCPU default DefExecThreadsPerCPU;
    property CommandProcessorThreadsGrowUpto: Integer read GetCommandProcessorThreadsGrowUpto write SetCommandProcessorThreadsGrowUpto default DefExecThreadsGrowUpto;
    property ExecCommandTimeout: Cardinal read GetExecCommandTimeout write SetExecCommandTimeout default DefExecCommandTimeout;
    property EventsUseMainThread: Boolean read GetEventsUseMainThread write SetEventsUseMainThread default DefEventsUseMainThread;
    property Compression: TncCompressionLevel read GetCompression write SetCompression default DefCompression;
    property Encryption: TEncryptorType read GetEncryption write SetEncryption default DefEncryption;
    property EncryptionKey: string read GetEncryptionKey write SetEncryptionKey;
    property EncryptOnHashedKey: Boolean read GetEncryptOnHashedKey write SetEncryptOnHashedKey default DefEncryptOnHashedKey;

    property OnConnected: TncOnSourceConnectDisconnect read GetOnConnected write SetOnConnected;
    property OnDisconnected: TncOnSourceConnectDisconnect read GetOnDisconnected write SetOnDisconnected;
    property OnHandleCommand: TncOnSourceHandleCommand read GetOnHandleCommand write SetOnHandleCommand;
    property OnAsyncExecCommandResult: TncOnAsyncExecCommandResult read GetOnAsyncExecCommandResult write SetOnAsyncExecCommandResult;
  end;

  THandleCommandThreadWorkType = (htwtAsyncResponse, htwtOnHandleCommand);

  THandleCommandThread = class(TncReadyThread)
  public
    WorkType: THandleCommandThreadWorkType;
    OnHandleCommand: TncOnSourceHandleCommand;
    OnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    Source: TncSourceBase;
    Line: TncSourceLine;
    Command: TncCommand;
    CommandHandler: IncCommandHandler;

    procedure CallOnAsyncEvents;
    procedure CallOnHandleEvents;
    procedure ProcessEvent; override;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncClientSource
  // Connects to a server source
  TncClientSource = class(TncSourceBase)
  private
    FOnReconnected: TncOnSourceReconnected;
    function GetHost: string;
    procedure SetHost(const Value: string);
    function GetReconnect: Boolean;
    procedure SetReconnect(const Value: Boolean);
    function GetReconnectInterval: Cardinal;
    procedure SetReconnectInterval(const Value: Cardinal);
  protected
    procedure WriteMessage(aLine: TncSourceLine; const aBuf: TBytes); override;
    function GetLine: TncLine;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function ExecCommand(const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True; const aAsyncExecute: Boolean = False; const aPeerComponentHandler: string = ''; const aSourceComponentHandler: string = ''): TBytes; overload; virtual;

    property Line: TncLine read GetLine;
  published
    property Host: string read GetHost write SetHost;
    property Reconnect: Boolean read GetReconnect write SetReconnect default True;
    property ReconnectInterval: Cardinal read GetReconnectInterval write SetReconnectInterval default DefCntReconnectInterval;
    property OnReconnected: TncOnSourceReconnected read FOnReconnected write FOnReconnected;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncServerSource
  TncServerSource = class(TncSourceBase)
  private
  protected
    function GetLines: TThreadLineList;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure ShutDownLine(aLine: TncLine);
    property Lines: TThreadLineList read GetLines;
  end;

implementation

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncSourceLine }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncSourceLine.Create;
begin
  inherited Create;
  BytesToEndOfMessage := 0;
  SetLength(HeaderBytes, 0);
end;

function TncSourceLine.CreateLineObject: TncLine;
begin
  Result := TncSourceLine.Create; // Create its own kind of objects
end;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncSourceBase }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncSourceBase.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  PropertyLock := TCriticalSection.Create;
  ExecuteSerialiser := TCriticalSection.Create;

  Socket := nil;
  WasSetActive := False;
  WithinConnectionHandler := False;

  // For encryption purposes this is not set to zero
  Randomize;
  UniqueSentID := Random(4096);

  FCommandProcessorThreadPriority := DefExecThreadPriority;
  FCommandProcessorThreads := DefExecThreads;
  FCommandProcessorThreadsPerCPU := DefExecThreadsPerCPU;
  FCommandProcessorThreadsGrowUpto := DefExecThreadsGrowUpto;

  FCommandExecTimeout := DefExecCommandTimeout;
  FEventsUseMainThread := DefEventsUseMainThread;
  FCompression := DefCompression;
  FEncryption := DefEncryption;
  FEncryptionKey := DefEncryptionKey;
  FEncryptOnHashedKey := DefEncryptOnHashedKey;

  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnHandleCommand := nil;
  FOnAsyncExecCommandResult := nil;

  PendingCommandsList := TPendingCommandsList.Create;
  HandleCommandThreadPool := TncThreadPool.Create(THandleCommandThread);
end;

destructor TncSourceBase.Destroy;
begin
  HandleCommandThreadPool.Free;
  PendingCommandsList.Free;
  ExecuteSerialiser.Free;
  PropertyLock.Free;
  inherited Destroy;
end;

procedure TncSourceBase.Loaded;
begin
  inherited Loaded;

  HandleCommandThreadPool.SetThreadPriority(FCommandProcessorThreadPriority);
  HandleCommandThreadPool.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
    FCommandProcessorThreadPriority);

  if WasSetActive then
    Socket.Active := True;
end;

procedure TncSourceBase.AddCommandHandler(aHandler: TComponent);
var
  Handler: IncCommandHandler;
  Len: Integer;
begin
  if aHandler.GetInterface(IncCommandHandler, Handler) then
    try
      Len := Length(CommandHandlers);
      SetLength(CommandHandlers, Len + 1);
      CommandHandlers[Len] := Handler;
    finally
      Handler := nil;
    end
  else
    raise ENetComInvalidCommandHandler.Create(ENetComInvalidCommandHandlerMessage);
end;

procedure TncSourceBase.RemoveCommandHandler(aHandler: TComponent);
var
  Handler: IncCommandHandler;
  i: Integer;
begin
  if aHandler.GetInterface(IncCommandHandler, Handler) then
    try
      for i := 0 to High(CommandHandlers) do
        if CommandHandlers[i] = Handler then
        begin
          CommandHandlers[i] := CommandHandlers[High(CommandHandlers)];
          CommandHandlers[High(CommandHandlers)] := nil;
          SetLength(CommandHandlers, Length(CommandHandlers) - 1);
          Break;
        end;
    finally
      Handler := nil;
    end
end;

procedure TncSourceBase.CallConnectedEvents;
var
  i: Integer;
begin
  WithinConnectionHandler := True;
  try
    if Assigned(OnConnected) then
      try
        OnConnected(Self, LastConnectedLine);
      except
      end;

    for i := 0 to High(CommandHandlers) do
      try
        if Assigned(CommandHandlers[i].OnConnected) then
          CommandHandlers[i].OnConnected(Self, LastConnectedLine);
      except
      end;
  finally
    WithinConnectionHandler := False;
  end;
end;

procedure TncSourceBase.SocketConnected(Sender: TObject; aLine: TncLine);
begin
  LastConnectedLine := aLine;
  if EventsUseMainThread then
    Socket.LineProcessor.Synchronize(Socket.LineProcessor, CallConnectedEvents)
  else
    CallConnectedEvents;
end;

procedure TncSourceBase.CallDisconnectedEvents;
var
  i: Integer;
begin
  WithinConnectionHandler := True;
  try
    if Assigned(FOnDisconnected) then
      try
        OnDisconnected(Self, LastDisconnectedLine);
      except
      end;

    for i := 0 to High(CommandHandlers) do
      try
        if Assigned(CommandHandlers[i].OnDisconnected) then
          CommandHandlers[i].OnDisconnected(Self, LastDisconnectedLine);
      except
      end;
  finally
    WithinConnectionHandler := False;
  end;
end;

procedure TncSourceBase.SocketDisconnected(Sender: TObject; aLine: TncLine);
begin
  LastDisconnectedLine := aLine;
  if EventsUseMainThread then
    Socket.LineProcessor.Synchronize(Socket.LineProcessor, CallDisconnectedEvents)
  else
    CallDisconnectedEvents;
end;

procedure TncSourceBase.CallReconnectedEvents;
begin
  WithinConnectionHandler := True;
  try
    if Assigned(TncClientSource(Self).OnReconnected) then
      try
        TncClientSource(Self).OnReconnected(Self, LastReconnectedLine);
      except
      end;
  finally
    WithinConnectionHandler := False;
  end;
end;

procedure TncSourceBase.SocketReconnected(Sender: TObject; aLine: TncLine);
begin
  LastReconnectedLine := aLine;
  if EventsUseMainThread then
    Socket.LineProcessor.Synchronize(Socket.LineProcessor, CallReconnectedEvents)
  else
    CallReconnectedEvents;
end;

procedure TncSourceBase.WriteMessage(aLine: TncSourceLine; const aBuf: TBytes);
var
  MessageBytes, FinalBuf: TBytes;
  MsgByteCount, HeaderBytes: UInt64;
begin
  MessageBytes := aBuf;
  // Get message data compressed and encrypted
  if Encryption <> etNoEncryption then
    MessageBytes := EncryptBytes(MessageBytes, EncryptionKey, Encryption, EncryptOnHashedKey, False);
  if Compression <> zcNone then
    MessageBytes := CompressBytes(MessageBytes, Compression);
  MsgByteCount := Length(MessageBytes);

  // Send 4 bytes of header, and 4 bytes how long the message will be
  HeaderBytes := SizeOf(TMagicHeaderType) + SizeOf(MsgByteCount);
  SetLength(FinalBuf, HeaderBytes + MsgByteCount);

  PMagicHeaderType(@FinalBuf[0])^ := MagicHeader; // Write MagicHeader
  PUint64(@FinalBuf[SizeOf(MagicHeader)])^ := MsgByteCount; // Write ByteCount
  move(MessageBytes[0], FinalBuf[HeaderBytes], MsgByteCount); // Write actual message

  aLine.SendBuffer(FinalBuf[0], Length(FinalBuf));
end;

procedure TncSourceBase.WriteCommand(aLine: TncSourceLine; const aCmd: TncCommand);
begin
  WriteMessage(aLine, aCmd.ToBytes);
end;

function TncSourceBase.ExecCommand(

  aLine: TncLine; const aCmd: Integer; const aData: TBytes = nil;

  const aRequiresResult: Boolean = True; const aAsyncExecute: Boolean = False;

  const aPeerComponentHandler: string = ''; const aSourceComponentHandler: string = ''): TBytes;

var
  Command: TncCommand;
  IDSent: TncCommandUniqueID;
  ReceivedResultEvent: TLightweightEvent;
  PendingNdx: Integer;
  WaitForEventTimeout: Integer;
begin
  PropertyLock.Acquire;
  try
    IDSent := UniqueSentID;

    // Random is here for encryption purposes
    UniqueSentID := UniqueSentID + TncCommandUniqueID(Random(4096)) mod High(TncCommandUniqueID);

    Command.CommandType := ctInitiator;
    Command.UniqueID := IDSent;
    Command.Cmd := aCmd;
    Command.Data := aData;
    Command.RequiresResult := aRequiresResult;
    Command.AsyncExecute := aAsyncExecute;
    Command.ResultIsErrorString := False;
    if aSourceComponentHandler = '' then
      Command.SourceComponentHandler := Name
    else
      Command.SourceComponentHandler := aSourceComponentHandler;
    Command.PeerComponentHandler := aPeerComponentHandler;

    if aRequiresResult and (not aAsyncExecute) then
    begin
      ReceivedResultEvent := TLightweightEvent.Create;
      PendingNdx := PendingCommandsList.Add(IDSent, ReceivedResultEvent);
      try
        // Send command over to peer
        WriteCommand(TncSourceLine(aLine), Command);
      except
        PendingCommandsList.Delete(PendingNdx);
        ReceivedResultEvent.Free;
        raise;
      end;
    end
    else
    begin
      // Send command over to peer
      WriteCommand(TncSourceLine(aLine), Command);
      Exit; // Nothing more to do
    end;
  finally
    PropertyLock.Release;
  end;

  // We are here because we require a result and this is not an AsyncExecute
  SetLength(Result, 0);
  try
    try
      aLine.LastReceived := TStopWatch.GetTimeStamp;
      if WithinConnectionHandler then
        WaitForEventTimeout := 0
      else
        WaitForEventTimeout := ExecCommandTimeout;
      while ReceivedResultEvent.WaitFor(WaitForEventTimeout) <> wrSignaled do
      begin
        if not aLine.Active then
          Abort;

        // If we are withing an OnConnect/OnDisconnect/OnReconnect handler,
        // the socket reading is paused, so we need to process it here
        if WithinConnectionHandler then
        begin
          ExecuteSerialiser.Acquire;
          try
            if (Socket is TncTCPClient) then
            begin
              if ReadableAnySocket(TncTCPClient(Socket).ReadSocketHandles, ExecCommandTimeout) then
              begin
                TncClientProcessor(TncTCPClient(Socket).LineProcessor).SocketProcess;
                TncClientProcessor(TncTCPClient(Socket).LineProcessor).ReadySocketsChanged := True;
              end;
            end
            else
            begin
              TncServerProcessor(TncTCPServer(Socket).LineProcessor).ReadySockets := Readable(TncTCPServer(Socket).ReadSocketHandles, ExecCommandTimeout);
              if Length(TncServerProcessor(TncTCPServer(Socket).LineProcessor).ReadySockets) > 0 then
                TncServerProcessor(TncTCPServer(Socket).LineProcessor).SocketProcess;
              TncServerProcessor(TncTCPServer(Socket).LineProcessor).ReadySocketsChanged := True;
            end;
          finally
            ExecuteSerialiser.Release;
          end;
        end;

        if TStopWatch.GetTimeStamp - aLine.LastReceived >= ExecCommandTimeout * TTimeSpan.TicksPerMillisecond then
          raise ENetComCommandExecutionTimeout.Create(ENetComCommandExecutionTimeoutMessage);
      end;
    except
      PropertyLock.Acquire;
      try
        PendingCommandsList.Delete(PendingCommandsList.IndexOf(IDSent));
      finally
        PropertyLock.Release;
      end;
      raise;
    end;

    // We are here because we got the result
    // Get the result of the command into the result of this function
    PropertyLock.Acquire;
    try
      PendingNdx := PendingCommandsList.IndexOf(IDSent);
      try
        Command := PendingCommandsList.Results[PendingNdx];
        if Command.ResultIsErrorString then
          raise ENetComResultIsException.Create(StringOf(Command.Data))
        else
          Result := Command.Data;
      finally
        PendingCommandsList.Delete(PendingNdx);
      end;
    finally
      PropertyLock.Release;
    end;
  finally
    ReceivedResultEvent.Free; // Event not needed any more
  end;
end;

// This is run in the reader's thread context
procedure TncSourceBase.HandleReceivedCommand(aLine: TncSourceLine; const aCommandBytes: TBytes);
var
  Command: TncCommand;
  HandleCommandThread: THandleCommandThread;
  PendingNdx: Integer;
begin
  Command.FromBytes(aCommandBytes);
  case Command.CommandType of
    ctInitiator:
      begin
        // Handle the command from the thread pool
        HandleCommandThreadPool.Serialiser.Acquire;
        try
          HandleCommandThread := THandleCommandThread(HandleCommandThreadPool.RequestReadyThread);
          HandleCommandThread.WorkType := htwtOnHandleCommand;
          HandleCommandThread.OnHandleCommand := OnHandleCommand;
          HandleCommandThread.Source := Self;
          HandleCommandThread.Line := aLine;
          HandleCommandThread.Command := Command;
          HandleCommandThreadPool.RunRequestedThread(HandleCommandThread);
        finally
          HandleCommandThreadPool.Serialiser.Release;
        end;
      end;
    ctResponse:
      if Command.AsyncExecute then
      begin
        // Handle the command from the thread pool
        HandleCommandThreadPool.Serialiser.Acquire;
        try
          HandleCommandThread := THandleCommandThread(HandleCommandThreadPool.RequestReadyThread);
          HandleCommandThread.WorkType := htwtAsyncResponse;
          HandleCommandThread.OnAsyncExecCommandResult := OnAsyncExecCommandResult;
          HandleCommandThread.Source := Self;
          HandleCommandThread.Line := aLine;
          HandleCommandThread.Command := Command;
          HandleCommandThreadPool.RunRequestedThread(HandleCommandThread);
        finally
          HandleCommandThreadPool.Serialiser.Release;
        end;
      end
      else
      begin
        PropertyLock.Acquire;
        try
          // Find the event to set from the PendingCommandsList
          PendingNdx := PendingCommandsList.IndexOf(Command.UniqueID);
          // We may not find a pending command as the ExecCommand may have
          // timed out, so do nothing in that case
          if PendingNdx <> -1 then
          begin
            PendingCommandsList.Results[PendingNdx] := Command;
            PendingCommandsList.ReceivedResultEvents[PendingNdx].SetEvent;
          end;
        finally
          PropertyLock.Release;
        end;
      end;
  end;
end;

// Only from one thread called here, the reader thread, or the main vcl
procedure TncSourceBase.SocketReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
var
  Line: TncSourceLine;
  MagicInt: TMagicHeaderType;
  Ofs, BytesToRead, MesLen: UInt64;
begin
  // From SocketProcess from
  Line := TncSourceLine(aLine);

  Ofs := 0;
  while Ofs < aBufCount do
  begin
    if Line.BytesToEndOfMessage > 0 then
    begin
      BytesToRead := Min(Line.BytesToEndOfMessage, UInt64(aBufCount) - Ofs);

      // Add to MessageData, BytesToRead from aBuf [Ofs]
      MesLen := Length(Line.MessageData);
      SetLength(Line.MessageData, MesLen + BytesToRead);
      move(aBuf[Ofs], Line.MessageData[MesLen], BytesToRead);

      Ofs := Ofs + BytesToRead;

      Line.BytesToEndOfMessage := Line.BytesToEndOfMessage - BytesToRead;
    end;

    if Line.BytesToEndOfMessage = 0 then
    begin
      if Length(Line.MessageData) > 0 then
        try
          try
            // Get message data uncompressed and unencrypted
            if Compression <> zcNone then
              Line.MessageData := DecompressBytes(Line.MessageData);
            if Encryption <> etNoEncryption then
              Line.MessageData := DecryptBytes(Line.MessageData, EncryptionKey, Encryption, EncryptOnHashedKey, False);

            HandleReceivedCommand(Line, Line.MessageData);
          finally
            // Dispose MessageData, we are complete
            SetLength(Line.MessageData, 0);
          end;
        except
        end;

      // Read a character
      if Ofs < aBufCount then
      begin
        if Length(Line.HeaderBytes) < SizeOf(TMagicHeaderType) + SizeOf(UInt64) then
        begin
          SetLength(Line.HeaderBytes, Length(Line.HeaderBytes) + 1);

          Line.HeaderBytes[High(Line.HeaderBytes)] := aBuf[Ofs];
          Inc(Ofs);
        end
        else
        begin
          MagicInt := PMagicHeaderType(@Line.HeaderBytes[0])^;
          if MagicInt <> MagicHeader then
          begin
            SetLength(Line.HeaderBytes, 0);
            Dec(Ofs, SizeOf(TMagicHeaderType) + SizeOf(UInt64) - 1);
          end
          else
          begin
            // If a whole integer is read, prepare to read message
            Line.BytesToEndOfMessage := PUint64(@Line.HeaderBytes[SizeOf(TMagicHeaderType)])^;
            SetLength(Line.HeaderBytes, 0);
          end;
        end;
      end;
    end; // if Line.BytesToEndOfMessage = 0
  end; // while Ofs < aBufCount
end;

function TncSourceBase.GetActive: Boolean;
begin
  Result := Socket.Active;
end;

procedure TncSourceBase.SetActive(const Value: Boolean);
begin
  if csLoading in ComponentState then
    WasSetActive := Value
  else
    Socket.Active := Value;
end;

function TncSourceBase.GetKeepAlive: Boolean;
begin
  Result := Socket.KeepAlive;
end;

procedure TncSourceBase.SetKeepAlive(const Value: Boolean);
begin
  Socket.KeepAlive := Value;
end;

function TncSourceBase.GetNoDelay: Boolean;
begin
  Result := Socket.NoDelay;
end;

procedure TncSourceBase.SetNoDelay(const Value: Boolean);
begin
  Socket.NoDelay := Value;
end;

function TncSourceBase.GetPort: Integer;
begin
  Result := Socket.Port;
end;

procedure TncSourceBase.SetPort(const Value: Integer);
begin
  Socket.Port := Value;
end;

function TncSourceBase.GetReaderThreadPriority: TncThreadPriority;
begin
  Result := Socket.ReaderThreadPriority;
end;

procedure TncSourceBase.SetReaderThreadPriority(const Value: TncThreadPriority);
begin
  Socket.ReaderThreadPriority := Value;
end;

function TncSourceBase.GetExecCommandTimeout: Cardinal;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandExecTimeout;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetExecCommandTimeout(const Value: Cardinal);
begin
  PropertyLock.Acquire;
  try
    FCommandExecTimeout := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetCommandProcessorThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadPriority;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCommandProcessorThreadPriority(const Value: TncThreadPriority);
begin
  PropertyLock.Acquire;
  try
    FCommandProcessorThreadPriority := Value;
    if not(csLoading in ComponentState) then
      HandleCommandThreadPool.SetThreadPriority(Value);
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetCommandProcessorThreads: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreads;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCommandProcessorThreads(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FCommandProcessorThreads := Value;
    if Value <> 0 then
      FCommandProcessorThreadsPerCPU := 0;

    if not(csLoading in ComponentState) then
      HandleCommandThreadPool.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
        FCommandProcessorThreadPriority);
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetCommandProcessorThreadsPerCPU: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadsPerCPU;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCommandProcessorThreadsPerCPU(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FCommandProcessorThreadsPerCPU := Value;
    if Value <> 0 then
      FCommandProcessorThreads := 0;

    if not(csLoading in ComponentState) then
      HandleCommandThreadPool.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
        FCommandProcessorThreadPriority);
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetCommandProcessorThreadsGrowUpto: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadsGrowUpto;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCommandProcessorThreadsGrowUpto(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FCommandProcessorThreadsGrowUpto := Value;
    HandleCommandThreadPool.GrowUpto := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetEventsUseMainThread: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FEventsUseMainThread;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetEventsUseMainThread(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FEventsUseMainThread := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetCompression: TZCompressionLevel;
begin
  PropertyLock.Acquire;
  try
    Result := FCompression;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCompression(const Value: TZCompressionLevel);
begin
  PropertyLock.Acquire;
  try
    FCompression := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetEncryption: TEncryptorType;
begin
  PropertyLock.Acquire;
  try
    Result := FEncryption;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetEncryption(const Value: TEncryptorType);
begin
  PropertyLock.Acquire;
  try
    FEncryption := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetEncryptionKey: string;
begin
  PropertyLock.Acquire;
  try
    Result := FEncryptionKey;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetEncryptionKey(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FEncryptionKey := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetEncryptOnHashedKey: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FEncryptOnHashedKey;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetEncryptOnHashedKey(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FEncryptOnHashedKey := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetComponentName: string;
begin
  Result := Name;
end;

function TncSourceBase.GetOnConnected: TncOnSourceConnectDisconnect;
begin
  Result := FOnConnected;
end;

procedure TncSourceBase.SetOnConnected(const Value: TncOnSourceConnectDisconnect);
begin
  FOnConnected := Value;
end;

function TncSourceBase.GetOnDisconnected: TncOnSourceConnectDisconnect;
begin
  Result := FOnDisconnected;
end;

procedure TncSourceBase.SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
begin
  FOnDisconnected := Value;
end;

function TncSourceBase.GetOnHandleCommand: TncOnSourceHandleCommand;
begin
  Result := FOnHandleCommand;
end;

procedure TncSourceBase.SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
begin
  FOnHandleCommand := Value;
end;

function TncSourceBase.GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
begin
  Result := FOnAsyncExecCommandResult;
end;

procedure TncSourceBase.SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
begin
  FOnAsyncExecCommandResult := Value;
end;

{ THandleCommandThread }

procedure THandleCommandThread.CallOnAsyncEvents;
begin
  if Assigned(CommandHandler.OnAsyncExecCommandResult) then

    CommandHandler.OnAsyncExecCommandResult(

      Source, Line,

      Command.Cmd, Command.Data,

      Command.ResultIsErrorString,

      Command.SourceComponentHandler, Command.PeerComponentHandler);
end;

procedure THandleCommandThread.CallOnHandleEvents;
begin
  if Assigned(CommandHandler.OnHandleCommand) then
    try
      Command.Data := CommandHandler.OnHandleCommand(

        Source, Line,

        Command.Cmd, Command.Data, Command.RequiresResult,

        Command.SourceComponentHandler, Command.PeerComponentHandler);

      Command.ResultIsErrorString := False;
    except
      on E: Exception do
      begin
        Command.ResultIsErrorString := True;
        Command.Data := BytesOf(E.ClassName + ' error: ' + E.Message);
      end;
    end
  else
    SetLength(Command.Data, 0);
end;

procedure THandleCommandThread.ProcessEvent;
var
  i: Integer;
begin
  // Find which command handler handles the events
  CommandHandler := nil;
  for i := 0 to High(Source.CommandHandlers) do
    if Source.CommandHandlers[i].GetComponentName = Command.PeerComponentHandler then
    begin
      CommandHandler := Source.CommandHandlers[i];
      Break;
    end;
  if not Assigned(CommandHandler) then
    Source.GetInterface(IncCommandHandler, CommandHandler);

  case WorkType of
    htwtAsyncResponse:
      if Source.EventsUseMainThread then
        Synchronize(CallOnAsyncEvents)
      else
        CallOnAsyncEvents;
    htwtOnHandleCommand:
      begin
        Command.ResultIsErrorString := False;

        if Source.EventsUseMainThread then
          Synchronize(CallOnHandleEvents)
        else
          CallOnHandleEvents;

        // Send the response
        if Command.RequiresResult then
        begin
          Command.CommandType := ctResponse;
          Source.WriteCommand(Line, Command);
        end;
      end;
  end;
end;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncClientSource }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type
  TncTCPClientSourceSocket = class(TncTCPClient)
  protected
    function CreateLineObject: TncLine; override;
  end;

function TncTCPClientSourceSocket.CreateLineObject: TncLine;
begin
  Result := TncSourceLine.Create;
end;

constructor TncClientSource.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FOnReconnected := nil;

  Socket := TncTCPClientSourceSocket.Create(nil);
  Socket.Port := DefPort;
  Socket.NoDelay := DefNoDelay;
  Socket.EventsUseMainThread := False;
  Socket.OnConnected := SocketConnected;
  Socket.OnDisconnected := SocketDisconnected;
  Socket.OnReadData := SocketReadData;
  TncTCPClient(Socket).OnReconnected := SocketReconnected;
end;

destructor TncClientSource.Destroy;
begin
  Socket.Free;
  inherited Destroy;
end;

function TncClientSource.GetLine: TncLine;
begin
  Result := TncTCPClient(Socket).Line;
end;

procedure TncClientSource.WriteMessage(aLine: TncSourceLine; const aBuf: TBytes);
begin
  Active := True;
  inherited WriteMessage(aLine, aBuf);
end;

function TncClientSource.ExecCommand(

  const aCmd: Integer; const aData: TBytes = nil;

  const aRequiresResult: Boolean = True; const aAsyncExecute: Boolean = False;

  const aPeerComponentHandler: string = ''; const aSourceComponentHandler: string = ''): TBytes;
begin
  if not Active then
    Active := True;

  Result := ExecCommand(TncSourceLine(GetLine), aCmd, aData, aRequiresResult, aAsyncExecute, aPeerComponentHandler, aSourceComponentHandler);
end;

function TncClientSource.GetHost: string;
begin
  Result := TncTCPClient(Socket).Host;
end;

procedure TncClientSource.SetHost(const Value: string);
begin
  TncTCPClient(Socket).Host := Value;
end;

function TncClientSource.GetReconnect: Boolean;
begin
  Result := TncTCPClient(Socket).Reconnect;
end;

procedure TncClientSource.SetReconnect(const Value: Boolean);
begin
  TncTCPClient(Socket).Reconnect := Value;
end;

function TncClientSource.GetReconnectInterval: Cardinal;
begin
  Result := TncTCPClient(Socket).ReconnectInterval;
end;

procedure TncClientSource.SetReconnectInterval(const Value: Cardinal);
begin
  TncTCPClient(Socket).ReconnectInterval := Value;
end;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncServerSource }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type
  TncTCPServerSourceSocket = class(TncTCPServer)
  protected
    function CreateLineObject: TncLine; override;
  end;

function TncTCPServerSourceSocket.CreateLineObject: TncLine;
begin
  Result := TncSourceLine.Create;
end;

constructor TncServerSource.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  Socket := TncTCPServerSourceSocket.Create(nil);
  Socket.NoDelay := DefNoDelay;
  Socket.Port := DefPort;
  Socket.EventsUseMainThread := False;
  Socket.OnConnected := SocketConnected;
  Socket.OnDisconnected := SocketDisconnected;
  Socket.OnReadData := SocketReadData;
end;

destructor TncServerSource.Destroy;
begin
  Socket.Free;
  inherited Destroy;
end;

function TncServerSource.GetLines: TThreadLineList;
begin
  Result := TncTCPServer(Socket).Lines;
end;

procedure TncServerSource.ShutDownLine(aLine: TncLine);
begin
  TncTCPServer(Socket).ShutDownLine(aLine);
end;

end.
