unit ncSources;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows, Winapi.Winsock2,
  {$ELSE}
  Posix.SysSocket, Posix.Unistd,
  {$ENDIF}
  System.Classes, System.SysUtils, System.SyncObjs, System.Math, System.ZLib,
  System.Diagnostics, System.RTLConsts, System.Types,
  ncCommandPacking, ncLines, ncSocketList, ncThreads, ncSockets, ncCompression, ncEncryption;

type
  TncCommandDirection = (cdIncoming, cdOutgoing);

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
  MagicHeader: TMagicHeaderType = $ACF0FF00;  // Bin: 10101100111100001111111100000000

  DefPort = 17233;

  DefCommandExecTimeout = 15000;

  DefExecThreadPriority = ntpNormal;
  DefExecThreads = 0;
  DefExecThreadsPerCPU = 5;
  DefExecThreadsGrowUpto = 100;

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

  TPendingCommand = record
  public
    Line: TncSourceLine;
    Command: TncCommand;
    CommandEvent: TEvent;
  end;

  PPendingCommand = ^TPendingCommand;

  TUnhandledCommand = record
  public
    Line: TncSourceLine;
    Command: TncCommand;
  end;

  PUnhandledCommand = ^TUnhandledCommand;

  TncOnSourceConnectDisconnect = procedure(Sender: TObject; aLine: TncLine) of object;
  TncOnSourceReconnected = procedure(Sender: TObject; aLine: TncLine) of object;
  TncOnSourceHandleCommand = function(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TBytes; aRequiresResult: Boolean;
    const aSenderComponent, aReceiverComponent: string): TBytes of object;
  TncOnAsyncExecCommandResult = procedure(Sender: TObject; aLine: TncLine; aCmd: Integer; const aResult: TBytes; aResultIsError: Boolean;
    const aSenderComponent, aReceiverComponent: string) of object;

  IncCommandHandler = interface
    ['{22337701-9561-489A-8593-82EAA3B1B431}']
    procedure Connected(aLine: TncLine);
    procedure Disconnected(aLine: TncLine);

    function GetComponentName: string;

    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
    property OnHandleCommand: TncOnSourceHandleCommand read GetOnHandleCommand write SetOnHandleCommand;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncSourceBase
  // Is the base for handling Exec and Handle command for the ServerSource and ClientSource
  TncCommandProcessor = class; // forward declaration

  TncSourceBase = class(TComponent)
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
    function GetOnConnected: TncOnSourceConnectDisconnect;
    procedure SetOnConnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnDisconnected: TncOnSourceConnectDisconnect;
    procedure SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);

    // Sources new functionality
    function GetCommandExecTimeout: Cardinal;
    procedure SetCommandExecTimeout(const Value: Cardinal);
    function GetCommandProcessorPriority: TncThreadPriority;
    procedure SetCommandProcessorPriority(const Value: TncThreadPriority);
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
    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
  private
    CommandHandlers: array of IncCommandHandler;
    UniqueSentID: Integer;
    WasSetActive: Boolean;
    procedure HandleCommand(aLine: TncSourceLine; var aUnpackedCommand: TncCommand);
    function GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    procedure SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
  protected
    PropertyLock: TCriticalSection;
    PendingCommands: TSocketList;
    PendingCommandsLock: TCriticalSection;
    UnhandledCommands: TSocketList;
    UnhandledCommandsLock: TCriticalSection;

    CommandProcessor: TncCommandProcessor;
    Socket: TncTCPBase;

    procedure Loaded; override;
    procedure SocketConnected(Sender: TObject; aLine: TncLine);
    procedure SocketDisconnected(Sender: TObject; aLine: TncLine);
    procedure SocketReconnected(Sender: TObject; aLine: TncLine);
    procedure SocketReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
    procedure WriteMessage(aLine: TncSourceLine; const aBuf: TBytes); virtual;
    procedure WriteCommand(aLine: TncSourceLine; const aCmd: TncCommand);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function ExecCommand(

      aLine: TncLine; const aCmd: Integer; const aData: TBytes = nil;

      const aRequiresResult: Boolean = True; const aAsyncExecute: Boolean = False;

      const aPeerComponentHandler: string = ''; const aSourceComponentHandler: string = ''): TBytes; overload; virtual;

    procedure AddCommandHandler(aHandler: TComponent);
    procedure RemoveCommandHandler(aHandler: TComponent);
    procedure ProcessSocketEvents;
  published
    // From socket
    property Active: Boolean read GetActive write SetActive default False;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default True;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default True;

    // New properties for sources
    property CommandExecTimeout: Cardinal read GetCommandExecTimeout write SetCommandExecTimeout default DefCommandExecTimeout;
    property CommandProcessorThreadPriority: TncThreadPriority read GetCommandProcessorPriority write SetCommandProcessorPriority default DefExecThreadPriority;
    property CommandProcessorThreads: Integer read GetCommandProcessorThreads write SetCommandProcessorThreads default DefExecThreads;
    property CommandProcessorThreadsPerCPU: Integer read GetCommandProcessorThreadsPerCPU write SetCommandProcessorThreadsPerCPU default DefExecThreadsPerCPU;
    property CommandProcessorThreadsGrowUpto: Integer read GetCommandProcessorThreadsGrowUpto write SetCommandProcessorThreadsGrowUpto
      default DefExecThreadsGrowUpto;
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

  THandleCommandWorker = class(TncReadyThread)
  public
    OnHandleCommand: TncOnSourceHandleCommand;
    Source: TncSourceBase;
    Line: TncSourceLine;
    UnpackedCommand: TncCommand;
    procedure ProcessEvent; override;
  end;

  TncCommandProcessor = class(TncThreadPool)
  public
    procedure CompletePendingEventsForLine(aLine: TncLine);
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
    function GetOnReconnected: TncOnSourceReconnected;
    procedure SetOnReconnected(const Value: TncOnSourceReconnected);
  protected
    procedure WriteMessage(aLine: TncSourceLine; const aBuf: TBytes); override;
    function GetLine: TncLine;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function ExecCommand(

      const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True;

      const aAsyncExecute: Boolean = False; const aPeerComponentHandler: string = '';

      const aSourceComponentHandler: string = ''): TBytes; overload; virtual;

    property Line: TncLine read GetLine;
  published
    property Host: string read GetHost write SetHost;
    property Reconnect: Boolean read GetReconnect write SetReconnect default True;
    property ReconnectInterval: Cardinal read GetReconnectInterval write SetReconnectInterval default DefCntReconnectInterval;
    property OnReconnected: TncOnSourceReconnected read GetOnReconnected write SetOnReconnected;
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
  PendingCommandsLock := TCriticalSection.Create;
  PendingCommands := TSocketList.Create;
  PendingCommands.Duplicates := dupIgnore;

  UnhandledCommandsLock := TCriticalSection.Create;
  UnhandledCommands := TSocketList.Create;
  UnhandledCommands.Duplicates := dupIgnore;

  Socket := nil;
  WasSetActive := False;

  UniqueSentID := Random(high(Integer) - 1); // for encryption purposes

  FCommandExecTimeout := DefCommandExecTimeout;
  FCommandProcessorThreadPriority := DefExecThreadPriority;
  FCommandProcessorThreads := DefExecThreads;
  FCommandProcessorThreadsPerCPU := DefExecThreadsPerCPU;
  FCommandProcessorThreadsGrowUpto := DefExecThreadsGrowUpto;
  FEventsUseMainThread := DefEventsUseMainThread;
  FCompression := DefCompression;
  FEncryption := DefEncryption;
  FEncryptionKey := DefEncryptionKey;
  FEncryptOnHashedKey := DefEncryptOnHashedKey;

  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnHandleCommand := nil;
  FOnAsyncExecCommandResult := nil;

  CommandProcessor := TncCommandProcessor.Create(THandleCommandWorker);
end;

destructor TncSourceBase.Destroy;
begin
  UnhandledCommands.Free;
  UnhandledCommandsLock.Free;
  PendingCommands.Free;
  PendingCommandsLock.Free;
  PropertyLock.Free;
  inherited Destroy;
  CommandProcessor.Free;
end;

procedure TncSourceBase.Loaded;
begin
  inherited Loaded;

  if FEventsUseMainThread then
    CommandProcessor.SetExecThreads(0, ntpNormal)
  else
  begin
    CommandProcessor.SetThreadPriority(FCommandProcessorThreadPriority);
    CommandProcessor.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
      FCommandProcessorThreadPriority);
  end;

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

procedure TncSourceBase.ProcessSocketEvents;
begin
  if EventsUseMainThread then
    if Socket is TncCustomTCPClient then
    begin
      TncClientProcessor(Socket.LineProcessor).SocketProcess;
    end
    else if Socket is TncCustomTCPServer then
    begin
      TncServerProcessor(Socket.LineProcessor).SocketProcess;
    end;
end;

procedure TncSourceBase.SocketConnected(Sender: TObject; aLine: TncLine);
var
  i: Integer;
begin
  if Assigned(OnConnected) then
    try
      OnConnected(Sender, aLine);
    except
    end;

  for i := 0 to High(CommandHandlers) do
    try
      CommandHandlers[i].Connected(TncSourceLine(aLine));
    except
    end;
end;

procedure TncSourceBase.SocketDisconnected(Sender: TObject; aLine: TncLine);
var
  i: Integer;
begin
  if Assigned(FOnDisconnected) then
    try
      OnDisconnected(Sender, TncSourceLine(aLine));
    except
    end;

  for i := 0 to High(CommandHandlers) do
    try
      CommandHandlers[i].Disconnected(TncSourceLine(aLine));
    except
    end;

  // Also inform all commands for the aLine, in the command processor, to terminate
  CommandProcessor.CompletePendingEventsForLine(aLine);
end;

procedure TncSourceBase.SocketReconnected(Sender: TObject; aLine: TncLine);
begin
  if Assigned(TncClientSource(Self).OnReconnected) then
    TncClientSource(Self).OnReconnected(Sender, TncSourceLine(aLine));
end;

procedure TncSourceBase.HandleCommand(aLine: TncSourceLine; var aUnpackedCommand: TncCommand);
var
  Worker: THandleCommandWorker;
  i: Integer;
  FoundComponent: IncCommandHandler;
begin
  // Process command to be executed directly,
  // or add it to the thread pool to process
  aUnpackedCommand.ResultIsErrorString := False;
  if EventsUseMainThread then
  begin
    // Handle the command directly
    // or send to appropriate subcomponent
    FoundComponent := nil;
    for i := 0 to High(CommandHandlers) do
      if CommandHandlers[i].GetComponentName = aUnpackedCommand.PeerComponentHandler then
      begin
        FoundComponent := CommandHandlers[i];
        Break;
      end;

    if (Trim(aUnpackedCommand.PeerComponentHandler) = '') or (FoundComponent = nil) then
    begin
      if Assigned(OnHandleCommand) then
        try
          aUnpackedCommand.Data := OnHandleCommand(Self, aLine, aUnpackedCommand.Cmd, aUnpackedCommand.Data, aUnpackedCommand.RequiresResult,
            aUnpackedCommand.SourceComponentHandler, aUnpackedCommand.PeerComponentHandler);
          aUnpackedCommand.ResultIsErrorString := False;
        except
          on E: Exception do
          begin
            aUnpackedCommand.ResultIsErrorString := True;
            aUnpackedCommand.Data := BytesOf(E.ClassName + ' error: ' + E.Message);
          end;
        end
      else
        SetLength(aUnpackedCommand.Data, 0);
    end
    else
    begin
      if not Assigned(FoundComponent) then
      begin
        aUnpackedCommand.ResultIsErrorString := True;
        aUnpackedCommand.Data := BytesOf('Error: Peer component ' + aUnpackedCommand.PeerComponentHandler + ' not found');
      end
      else
      begin
        if Assigned(FoundComponent.OnHandleCommand) then
          try
            aUnpackedCommand.Data := FoundComponent.OnHandleCommand(Self, aLine, aUnpackedCommand.Cmd, aUnpackedCommand.Data, aUnpackedCommand.RequiresResult,
              aUnpackedCommand.SourceComponentHandler, aUnpackedCommand.PeerComponentHandler);
            aUnpackedCommand.ResultIsErrorString := False;
          except
            on E: Exception do
            begin
              aUnpackedCommand.ResultIsErrorString := True;
              aUnpackedCommand.Data := BytesOf(E.ClassName + ' error: ' + E.Message);
            end;
          end
        else
          SetLength(aUnpackedCommand.Data, 0);
      end;
    end;

    // Send the response
    if aUnpackedCommand.RequiresResult then
    begin
      aUnpackedCommand.CommandType := ctResponse;
      WriteCommand(aLine, aUnpackedCommand);
    end;
  end
  else
  begin
    // Handle the command from the thread pool
    Worker := THandleCommandWorker(CommandProcessor.RequestReadyThread);
    Worker.OnHandleCommand := OnHandleCommand;
    Worker.Source := Self;
    Worker.Line := aLine;
    Worker.UnpackedCommand := aUnpackedCommand;
    CommandProcessor.RunRequestedThread(Worker);
  end;
end;

// Only from one thread called here, the reader thread, or the main vcl
procedure TncSourceBase.SocketReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);

  function LastPendingCommandIsOnLine(aLine: TncSourceLine): Boolean;
  begin
    Result := False;

    if PendingCommands.Count > 0 then
      Result := PPendingCommand(PendingCommands.Lines[PendingCommands.Count - 1])^.Line = aLine;
  end;

var
  Line: TncSourceLine;
  Ofs, BytesToRead, MesLen: UInt64;
  UnpackedCommand: TPendingCommand;
  PendingCommandsNdx: Integer;
  MagicInt: UInt32;
  UnhandledCommand: ^TUnhandledCommand;

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

            // Get MessageData and convert it into a ncCommand
            UnpackedCommand.Command.FromBytes(Line.MessageData);
            case UnpackedCommand.Command.CommandType of
              ctInitiator:
                begin
                  PendingCommandsLock.Acquire;
                  try
                    if (PendingCommands.Count = 0) or LastPendingCommandIsOnLine(Line) then // if we are not ExecCommand'ed anything
                      // The peer is sending a command to be handled here
                      HandleCommand(Line, UnpackedCommand.Command)
                    else
                    begin
                      // Postpone HandleCommand until we are finished
                      New(UnhandledCommand);
                      UnhandledCommandsLock.Acquire;
                      try
                        UnhandledCommand^.Line := Line;
                        UnhandledCommand^.Command := UnpackedCommand.Command;
                        UnhandledCommands.AddObject(UnhandledCommand^.Command.UniqueID, TncLine(UnhandledCommand));
                      finally
                        UnhandledCommandsLock.Release;
                      end;
                    end;
                  finally
                    PendingCommandsLock.Release;
                  end;
                end;
              ctResponse:
                // We had requested a command, we got its response
                begin
                  PendingCommandsLock.Acquire;
                  try
                    PendingCommandsNdx := PendingCommands.IndexOf(UnpackedCommand.Command.UniqueID);
                    if PendingCommandsNdx <> -1 then
                      with PPendingCommand(PendingCommands.Lines[PendingCommandsNdx])^ do
                      begin
                        if Command.AsyncExecute then
                        begin
                          try
                            if Assigned(OnAsyncExecCommandResult) then
                              OnAsyncExecCommandResult(Self,

                                Line,

                                Command.Cmd,

                                UnpackedCommand.Command.Data,

                                UnpackedCommand.Command.ResultIsErrorString,

                                UnpackedCommand.Command.SourceComponentHandler,

                                UnpackedCommand.Command.PeerComponentHandler);

                          finally
                            Dispose(PPendingCommand(PendingCommands.Lines[PendingCommandsNdx]));
                            PendingCommands.Delete(PendingCommandsNdx);
                          end;
                        end
                        else
                        begin
                          Command.Data := UnpackedCommand.Command.Data;
                          SetLength(UnpackedCommand.Command.Data, 0);
                          Command.ResultIsErrorString := UnpackedCommand.Command.ResultIsErrorString;

                          CommandEvent.SetEvent;
                        end;
                      end;
                  finally
                    PendingCommandsLock.Release;
                  end;
                end;
            end;
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
            Line.BytesToEndOfMessage := PUInt64(@Line.HeaderBytes[SizeOf(TMagicHeaderType)])^;
            SetLength(Line.HeaderBytes, 0);
          end;
        end;
      end;
    end; // if Line.BytesToEndOfMessage = 0
  end; // while Ofs < aBufCount
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
  PendingCommand: ^TPendingCommand;
  PendingCommandNdx: Integer;
  WaitTime: Integer;
  TheCommand: PUnhandledCommand;
begin
  try
    New(PendingCommand);
    try
      PendingCommandsLock.Acquire;
      try
        PendingCommand^.Line := TncSourceLine(aLine);
        with PendingCommand^.Command do
        begin
          CommandType := ctInitiator;
          UniqueID := UniqueSentID;
          UniqueSentID := UniqueSentID + 1;
          UniqueSentID := UniqueSentID mod (high(Integer) - 1);
          Cmd := aCmd;
          Data := aData;
          RequiresResult := aRequiresResult;
          AsyncExecute := aAsyncExecute;
          PeerComponentHandler := aPeerComponentHandler;
          if aSourceComponentHandler = '' then
            SourceComponentHandler := Name
          else
            SourceComponentHandler := aSourceComponentHandler;
        end;

        if aRequiresResult or aAsyncExecute then
        begin
          if not aAsyncExecute then
            PendingCommand^.CommandEvent := TEvent.Create;
          // Add it to the list of pending commands, pass the address of the pending command record
          PendingCommands.AddObject(PendingCommand^.Command.UniqueID, TncLine(PendingCommand));
        end;
      finally
        PendingCommandsLock.Release;
      end;

      try
        WriteCommand(TncSourceLine(aLine), PendingCommand^.Command);

        if aRequiresResult and not aAsyncExecute then
        begin
          // Wait for the command to come back
          ProcessSocketEvents;
          if EventsUseMainThread then
            WaitTime := 0
          else
            WaitTime := 100;
          while PendingCommand.CommandEvent.WaitFor(WaitTime) <> wrSignaled do
          begin
            if not aLine.Active then
              Abort;

            ProcessSocketEvents;

            if TStopWatch.GetTimeStamp - aLine.LastReceived >= CommandExecTimeout then
              raise ENetComCommandExecutionTimeout.Create(ENetComCommandExecutionTimeoutMessage);
          end;

          // Get the result of the command into the result of this function
          with PendingCommand.Command do
          begin
            if ResultIsErrorString then
              raise ENetComResultIsException.Create(StringOf(Data))
            else
              Result := Data;
          end;
        end;
      finally
        if aRequiresResult and not aAsyncExecute then
        begin
          PendingCommand.CommandEvent.Free;
          PendingCommandsLock.Acquire;
          try
            PendingCommandNdx := PendingCommands.IndexOf(PendingCommand.Command.UniqueID);
            if PendingCommandNdx <> -1 then
              PendingCommands.Delete(PendingCommandNdx);
          finally
            PendingCommandsLock.Release;
          end;
        end;
      end;
    finally
      if aRequiresResult and not aAsyncExecute then
        Dispose(PendingCommand);
    end;

  finally
    PendingCommandsLock.Acquire;
    try
      if PendingCommands.Count = 0 then
      begin
        UnhandledCommandsLock.Acquire;
        try
          while (UnhandledCommands.Count > 0) do
          begin
            TheCommand := PUnhandledCommand(UnhandledCommands.Lines[0]);
            try
              UnhandledCommands.Delete(0);
              try
                HandleCommand(TheCommand^.Line, TheCommand^.Command);
              except
              end;
            finally
              Dispose(TheCommand);
            end;
          end;
        finally
          UnhandledCommandsLock.Release;
        end;
      end;
    finally
      PendingCommandsLock.Release;
    end;
  end;
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

function TncSourceBase.GetCommandExecTimeout: Cardinal;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandExecTimeout;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCommandExecTimeout(const Value: Cardinal);
begin
  PropertyLock.Acquire;
  try
    FCommandExecTimeout := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetCommandProcessorPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadPriority;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetCommandProcessorPriority(const Value: TncThreadPriority);
begin
  PropertyLock.Acquire;
  try
    FCommandProcessorThreadPriority := Value;
    if not(csLoading in ComponentState) then
      CommandProcessor.SetThreadPriority(Value);
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
      if EventsUseMainThread then
        CommandProcessor.SetExecThreads(0, ntpNormal)
      else
        CommandProcessor.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
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
      if EventsUseMainThread then
        CommandProcessor.SetExecThreads(0, ntpNormal)
      else
        CommandProcessor.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
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
    CommandProcessor.GrowUpto := Value;
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

    if not(csLoading in ComponentState) then
      if Value then
        CommandProcessor.SetExecThreads(0, ntpNormal)
      else
        CommandProcessor.SetExecThreads(Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
          FCommandProcessorThreadPriority);
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

function TncSourceBase.GetOnConnected: TncOnSourceConnectDisconnect;
begin
  PropertyLock.Acquire;
  try
    Result := FOnConnected;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetOnConnected(const Value: TncOnSourceConnectDisconnect);
begin
  PropertyLock.Acquire;
  try
    FOnConnected := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetOnDisconnected: TncOnSourceConnectDisconnect;
begin
  PropertyLock.Acquire;
  try
    Result := FOnDisconnected;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
begin
  PropertyLock.Acquire;
  try
    FOnDisconnected := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetOnHandleCommand: TncOnSourceHandleCommand;
begin
  PropertyLock.Acquire;
  try
    Result := FOnHandleCommand;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
begin
  PropertyLock.Acquire;
  try
    FOnHandleCommand := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSourceBase.GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
begin
  PropertyLock.Acquire;
  try
    Result := FOnAsyncExecCommandResult;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSourceBase.SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
begin
  PropertyLock.Acquire;
  try
    FOnAsyncExecCommandResult := Value;
  finally
    PropertyLock.Release;
  end;
end;

{ THandleCommandWorker }

procedure THandleCommandWorker.ProcessEvent;
var
  i: Integer;
  FoundComponent: IncCommandHandler;
begin
  // TODO: Put here to also execute the new OnAsyncExecuteResult

  FoundComponent := nil;
  for i := 0 to High(Source.CommandHandlers) do
    if Source.CommandHandlers[i].GetComponentName = UnpackedCommand.PeerComponentHandler then
    begin
      FoundComponent := Source.CommandHandlers[i];
      Break;
    end;

  // Handle the command directly
  UnpackedCommand.ResultIsErrorString := False;
  if (Trim(UnpackedCommand.PeerComponentHandler) = '') or (FoundComponent = nil) then
  begin
    if Assigned(OnHandleCommand) then
      try
        UnpackedCommand.Data := OnHandleCommand(Self, Line, UnpackedCommand.Cmd, UnpackedCommand.Data, UnpackedCommand.RequiresResult,
          UnpackedCommand.SourceComponentHandler, UnpackedCommand.PeerComponentHandler);
        UnpackedCommand.ResultIsErrorString := False;
      except
        on E: Exception do
        begin
          UnpackedCommand.ResultIsErrorString := True;
          UnpackedCommand.Data := BytesOf(E.ClassName + ' error: ' + E.Message);
        end;
      end
    else
      SetLength(UnpackedCommand.Data, 0);
  end
  else
  begin
    // This does not apply anymore as it is redirected above
    if not Assigned(FoundComponent) then
    begin
      UnpackedCommand.ResultIsErrorString := True;
      UnpackedCommand.Data := BytesOf('Error: Peer component ' + UnpackedCommand.PeerComponentHandler + ' not found');
    end
    else
    begin
      if Assigned(FoundComponent.OnHandleCommand) then
        try
          UnpackedCommand.Data := FoundComponent.OnHandleCommand(Self, Line, UnpackedCommand.Cmd, UnpackedCommand.Data, UnpackedCommand.RequiresResult,
            UnpackedCommand.SourceComponentHandler, UnpackedCommand.PeerComponentHandler);
          UnpackedCommand.ResultIsErrorString := False;
        except
          on E: Exception do
          begin
            UnpackedCommand.ResultIsErrorString := True;
            UnpackedCommand.Data := BytesOf(E.ClassName + ' error: ' + E.Message);
          end;
        end
      else
        SetLength(UnpackedCommand.Data, 0);
    end;
  end;

  // Send the response
  if UnpackedCommand.RequiresResult then
  begin
    UnpackedCommand.CommandType := ctResponse;
    Source.WriteCommand(Line, UnpackedCommand);
  end;
end;

{ TncCommandProcessor }

procedure TncCommandProcessor.CompletePendingEventsForLine(aLine: TncLine);
var
  i: Integer;
begin
  Serialiser.Acquire;
  try
    for i := 0 to High(Threads) do
      if THandleCommandWorker(Threads[i]).Line = aLine then // processing our line
        Threads[i].ReadyEvent.WaitFor(Infinite); // It is still processing,
    // wait until it is in ready state again
  finally
    Serialiser.Release;
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

function TncClientSource.GetOnReconnected: TncOnSourceReconnected;
begin
  PropertyLock.Acquire;
  try
    Result := FOnReconnected;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncClientSource.SetOnReconnected(const Value: TncOnSourceReconnected);
begin
  PropertyLock.Acquire;
  try
    FOnReconnected := Value;
  finally
    PropertyLock.Release;
  end;
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

end.
