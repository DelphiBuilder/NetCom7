unit ncSockets;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit creates a TCP Server and TCP Client socket, along with their
// threads dealing with reading from the socket
//
// 9/8/2020
// - Added a ShutDownLine in the TCPServer component so as to allow to
// shutdown a line even when within a read operation
//
// 8/8/2020
// - Got rid of any windows specific api calls so that we can compile for
// all plaforms. All platform specific stuff are now dealt in ncLines.pas
//
// 6/8/2010
// - Optimised performance
// - Put a lock in Active property so as to make sure reconnect works properly
// - Got rid of disconnect exceptions
// - Added resource strings to all exception messages
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
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
{$IFDEF MSWINDOWS}
  Winapi.Windows, Winapi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, System.SyncObjs, System.Math, System.Diagnostics, System.TimeSpan,
  ncLines, ncSocketList, ncThreads;

const
  DefPort = 16233;
  DefHost = 'LocalHost';
  DefReadBufferLen = 1024 * 1024; // 1 MB
  DefReaderThreadPriority = ntpNormal;
  DefCntReconnectInterval = 1000;
  DefEventsUseMainThread = False;
  DefUseReaderThread = True;
  DefNoDelay = False;
  DefKeepAlive = True;

resourcestring
  ECannotSetPortWhileConnectionIsActiveStr = 'Cannot set Port property whilst the connection is active';
  ECannotSetHostWhileConnectionIsActiveStr = 'Cannot set Host property whilst the connection is active';
  ECannotSetUseReaderThreadWhileActiveStr = 'Cannot set UseReaderThread property whilst the connection is active';
  ECannotReceiveIfUseReaderThreadStr =
    'Cannot receive data if UseReaderThread is set. Use OnReadData event handler to get the data or set UseReaderThread property to false';

type
  EPropertySetError = class(Exception);
  ENonActiveSocket = class(Exception);
  ECannotReceiveIfUseReaderThread = class(Exception);

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TThreadLineList
  // Thread safe object, used by the main components

  TThreadLineList = class
  private
    FList: TSocketList;
    FLock: TCriticalSection;
  protected
    procedure Add(const Item: TncLine); inline;
    procedure Clear; inline;
    procedure Remove(Item: TncLine); inline;
  public
    constructor Create;
    destructor Destroy; override;
    function LockList: TSocketList;
    procedure UnlockList;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Base object for all TCP Sockets
  TncOnConnectDisconnect = procedure(Sender: TObject; aLine: TncLine) of object;
  TncOnReadData = procedure(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer) of object;
  TncOnReconnected = procedure(Sender: TObject; aLine: TncLine) of object;

  TncTCPBase = class(TComponent)
  private
    FInitActive: Boolean;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FNoDelay: Boolean;
    FKeepAlive: Boolean;
    FOnConnected: TncOnConnectDisconnect;
    FOnDisconnected: TncOnConnectDisconnect;
    FOnReadData: TncOnReadData;
    function GetActive: Boolean; virtual; abstract;
    procedure SetActive(const Value: Boolean);
    function GetPort: Integer;
    procedure SetPort(const Value: Integer);
    function GetReaderThreadPriority: TncThreadPriority;
    procedure SetReaderThreadPriority(const Value: TncThreadPriority);
    function GetEventsUseMainThread: Boolean;
    procedure SetEventsUseMainThread(const Value: Boolean);
    function GetNoDelay: Boolean;
    procedure SetNoDelay(const Value: Boolean);
    function GetKeepAlive: Boolean;
    procedure SetKeepAlive(const Value: Boolean);
  private
    FUseReaderThread: Boolean;
    procedure DoActivate(aActivate: Boolean); virtual; abstract;
    procedure SetUseReaderThread(const Value: Boolean);
  protected
    PropertyLock, ShutDownLock: TCriticalSection;
    ReadBuf: TBytes;
    procedure Loaded; override;
    function CreateLineObject: TncLine; virtual;
  public
    LineProcessor: TncReadyThread;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    property Active: Boolean read GetActive write SetActive default False;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property EventsUseMainThread: Boolean read GetEventsUseMainThread write SetEventsUseMainThread default DefEventsUseMainThread;
    property UseReaderThread: Boolean read FUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default DefNoDelay;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default DefKeepAlive;
    property OnConnected: TncOnConnectDisconnect read FOnConnected write FOnConnected;
    property OnDisconnected: TncOnConnectDisconnect read FOnDisconnected write FOnDisconnected;
    property OnReadData: TncOnReadData read FOnReadData write FOnReadData;
  published
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Client Socket
  TncClientProcessor = class;

  TncCustomTCPClient = class(TncTCPBase)
  private
    FHost: string;
    FReconnect: Boolean;
    FReconnectInterval: Cardinal;
    FOnReconnected: TncOnReconnected;
    function GetActive: Boolean; override;
    procedure SetHost(const Value: string);
    function GetHost: string;
    function GetReconnect: Boolean;
    procedure SetReconnect(const Value: Boolean);
    function GetReconnectInterval: Cardinal;
    procedure SetReconnectInterval(const Value: Cardinal);
  protected
    ReadSocketHandles: TSocketHandleArray;
    WasConnected: Boolean;
    LastConnectAttempt: Int64;
    procedure DoActivate(aActivate: Boolean); override;
    procedure DataSocketConnected(aLine: TncLine);
    procedure DataSocketDisconnected(aLine: TncLine);
  public
    Line: TncLine;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Send(const aBuf; aBufSize: Integer); overload; inline;
    procedure Send(const aBytes: TBytes); overload; inline;
    procedure Send(const aStr: string); overload; inline;
    function Receive(aTimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(var aBytes: TBytes): Integer; inline;
    property Host: string read GetHost write SetHost;
    property Reconnect: Boolean read GetReconnect write SetReconnect default True;
    property ReconnectInterval: Cardinal read GetReconnectInterval write SetReconnectInterval default DefCntReconnectInterval;
    property OnReconnected: TncOnReconnected read FOnReconnected write FOnReconnected;
  end;

  TncTCPClient = class(TncCustomTCPClient)
  published
    property Active;
    property Port;
    property Host;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property NoDelay;
    property KeepAlive;
    property Reconnect;
    property ReconnectInterval;
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
    property OnReconnected;
  end;

  TncClientProcessor = class(TncReadyThread)
  private
    FClientSocket: TncCustomTCPClient;
  public
    constructor Create(aClientSocket: TncCustomTCPClient);
    procedure SocketWasReconnected;
    procedure SocketProcess; inline;
    procedure ProcessEvent; override;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Server Socket
  TncServerProcessor = class;

  TncCustomTCPServer = class(TncTCPBase)
  private
    function GetActive: Boolean; override;
  protected
    Listener: TncLine;
    ReadSocketHandles: TSocketHandleArray;
    LinesToShutDown: array of TncLine;
    procedure DataSocketConnected(aLine: TncLine);
    procedure DataSocketDisconnected(aLine: TncLine);
    procedure DoActivate(aActivate: Boolean); override;
  public
    Lines: TThreadLineList;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure ShutDownLine(aLine: TncLine);
    procedure Send(aLine: TncLine; const aBuf; aBufSize: Integer); overload; inline;
    procedure Send(aLine: TncLine; const aBytes: TBytes); overload; inline;
    procedure Send(aLine: TncLine; const aStr: string); overload; inline;
    function Receive(aLine: TncLine; aTimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(aLine: TncLine; var aBytes: TBytes): Integer; inline;
  end;

  TncTCPServer = class(TncCustomTCPServer)
  public
  published
    property Active;
    property Port;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property NoDelay;
    property KeepAlive;
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
  end;

  TncServerProcessor = class(TncReadyThread)
  private
    FServerSocket: TncCustomTCPServer;
    ReadySockets: TSocketHandleArray;
    procedure CheckLinesToShutDown;
  public
    constructor Create(aServerSocket: TncCustomTCPServer);
    procedure SocketProcess; inline;
    procedure ProcessEvent; override;
  end;

  // We bring in TncLine so that a form that uses our components does
  // not have to reference ncLines unit to get the type
  TncLine = ncLines.TncLine;

  // We make a descendant of TncLine so that we can access the API functions.
  // These API functions are not made puclic in TncLine so that the user cannot
  // mangle up the line
  TncLineInternal = class(TncLine);

implementation

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TThreadLineList }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TThreadLineList.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FList := TSocketList.Create;
end;

destructor TThreadLineList.Destroy;
begin
  LockList;
  try
    FList.Free;
    inherited Destroy;
  finally
    UnlockList;
    FLock.Free;
  end;
end;

procedure TThreadLineList.Add(const Item: TncLine);
begin
  LockList;
  try
    // FList has Duplicates to dupError, so we know if this is already in the
    // list it will not be accepted
    FList.Add(Item.Handle, Item);
  finally
    UnlockList;
  end;
end;

procedure TThreadLineList.Clear;
begin
  LockList;
  try
    FList.Clear;
  finally
    UnlockList;
  end;
end;

procedure TThreadLineList.Remove(Item: TncLine);
begin
  LockList;
  try
    FList.Delete(FList.IndexOf(Item.Handle));
  finally
    UnlockList;
  end;
end;

function TThreadLineList.LockList: TSocketList;
begin
  FLock.Acquire;
  Result := FList;
end;

procedure TThreadLineList.UnlockList;
begin
  FLock.Release;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncTCPBase }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncTCPBase.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  PropertyLock := TCriticalSection.Create;
  ShutDownLock := TCriticalSection.Create;

  FInitActive := False;
  FPort := DefPort;
  FEventsUseMainThread := DefEventsUseMainThread;
  FUseReaderThread := DefUseReaderThread;
  FNoDelay := DefNoDelay;
  FKeepAlive := DefKeepAlive;
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnReadData := nil;

  SetLength(ReadBuf, DefReadBufferLen);
end;

destructor TncTCPBase.Destroy;
begin
  ShutDownLock.Free;
  PropertyLock.Free;
  inherited Destroy;
end;

procedure TncTCPBase.Loaded;
begin
  inherited Loaded;

  if FInitActive then
    DoActivate(True);
end;

function TncTCPBase.CreateLineObject: TncLine;
begin
  Result := TncLineInternal.Create;
end;

procedure TncTCPBase.SetActive(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    if not(csLoading in ComponentState) then
      DoActivate(Value);

    FInitActive := GetActive; // we only care here for the loaded event
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetPort: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FPort;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetPort(const Value: Integer);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetPortWhileConnectionIsActiveStr);

  PropertyLock.Acquire;
  try
    FPort := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetReaderThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := ToNcThreadPriority(LineProcessor.Priority);
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetReaderThreadPriority(const Value: TncThreadPriority);
begin
  PropertyLock.Acquire;
  try
    try
      LineProcessor.Priority := FromNcThreadPriority(Value);
    except
      // Some android devices cannot handle changing priority
    end;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetEventsUseMainThread: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FEventsUseMainThread;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetEventsUseMainThread(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FEventsUseMainThread := Value;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetUseReaderThread(const Value: Boolean);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetUseReaderThreadWhileActiveStr);

  PropertyLock.Acquire;
  try
    FUseReaderThread := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetNoDelay: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FNoDelay;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetNoDelay(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FNoDelay := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetKeepAlive: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FKeepAlive;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetKeepAlive(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FKeepAlive := Value;
  finally
    PropertyLock.Release;
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomTCPClient }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomTCPClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FHost := DefHost;
  FReconnect := True;
  FReconnectInterval := DefCntReconnectInterval;
  FOnReconnected := nil;

  LastConnectAttempt := TStopWatch.GetTimeStamp;
  WasConnected := False;

  Line := CreateLineObject;
  TncLineInternal(Line).OnConnected := DataSocketConnected;
  TncLineInternal(Line).OnDisconnected := DataSocketDisconnected;

  LineProcessor := TncClientProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
  LineProcessor.WaitForReady;
end;

destructor TncCustomTCPClient.Destroy;
begin
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Line.Free;

  inherited Destroy;
end;

procedure TncCustomTCPClient.DoActivate(aActivate: Boolean);
begin
  if aActivate = GetActive then
    Exit;

  if aActivate then
    TncLineInternal(Line).CreateClientHandle(FHost, FPort)
  else
  begin
    WasConnected := False;
    TncLineInternal(Line).DestroyHandle;
  end;
end;

procedure TncCustomTCPClient.DataSocketConnected(aLine: TncLine);
begin
  SetLength(ReadSocketHandles, 1);
  ReadSocketHandles[0] := Line.Handle;

  if NoDelay then
    try
      TncLineInternal(Line).EnableNoDelay;
    except
    end;

  if KeepAlive then
    try
      TncLineInternal(Line).EnableKeepAlive;
    except
    end;

  if Assigned(OnConnected) and not(csDestroying in ComponentState) then
    try
      OnConnected(Self, aLine);
    except
    end;

  LastConnectAttempt := TStopWatch.GetTimeStamp;
  WasConnected := True;

  if UseReaderThread then
    LineProcessor.Run; // Will just set events, this does not wait
end;

procedure TncCustomTCPClient.DataSocketDisconnected(aLine: TncLine);
begin
  if Assigned(OnDisconnected) and not(csDestroying in ComponentState) then
    try
      OnDisconnected(Self, aLine);
    except
    end;
end;

procedure TncCustomTCPClient.Send(const aBuf; aBufSize: Integer);
begin
  Active := True;
  TncLineInternal(Line).SendBuffer(aBuf, aBufSize);
end;

procedure TncCustomTCPClient.Send(const aBytes: TBytes);
begin
  if Length(aBytes) > 0 then
    Send(aBytes[0], Length(aBytes));
end;

procedure TncCustomTCPClient.Send(const aStr: string);
begin
  Send(BytesOf(aStr));
end;

function TncCustomTCPClient.Receive(aTimeout: Cardinal): TBytes;
var
  BufRead: Integer;
begin
  if UseReaderThread then
    raise ECannotReceiveIfUseReaderThread.Create(ECannotReceiveIfUseReaderThreadStr);

  Active := True;

  if not ReadableAnySocket([Line.Handle], aTimeout) then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  BufRead := TncLineInternal(Line).RecvBuffer(ReadBuf[0], Length(ReadBuf));
  Result := Copy(ReadBuf, 0, BufRead)
end;

function TncCustomTCPClient.ReceiveRaw(var aBytes: TBytes): Integer;
begin
  Result := TncLineInternal(Line).RecvBuffer(aBytes[0], Length(aBytes));
end;

function TncCustomTCPClient.GetActive: Boolean;
begin
  Result := Line.Active;
end;

function TncCustomTCPClient.GetHost: string;
begin
  PropertyLock.Acquire;
  try
    Result := FHost;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomTCPClient.SetHost(const Value: string);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetHostWhileConnectionIsActiveStr);

  PropertyLock.Acquire;
  try
    FHost := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomTCPClient.GetReconnect: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FReconnect;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomTCPClient.SetReconnect(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FReconnect := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomTCPClient.GetReconnectInterval: Cardinal;
begin
  PropertyLock.Acquire;
  try
    Result := FReconnectInterval;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomTCPClient.SetReconnectInterval(const Value: Cardinal);
begin
  PropertyLock.Acquire;
  try
    FReconnectInterval := Value;
  finally
    PropertyLock.Release;
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncClientProcessor }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncClientProcessor.Create(aClientSocket: TncCustomTCPClient);
begin
  FClientSocket := aClientSocket;
  inherited Create;
end;

procedure TncClientProcessor.SocketProcess;
var
  BufRead: Integer;
begin
  BufRead := TncLineInternal(FClientSocket.Line).RecvBuffer(FClientSocket.ReadBuf[0], Length(FClientSocket.ReadBuf));
  if Assigned(FClientSocket.OnReadData) then
    try
      FClientSocket.OnReadData(FClientSocket, FClientSocket.Line, FClientSocket.ReadBuf, BufRead);
    except
    end;
end;

procedure TncClientProcessor.SocketWasReconnected;
begin
  if Assigned(FClientSocket.FOnReconnected) then
    FClientSocket.FOnReconnected(FClientSocket, FClientSocket.Line);
  if Assigned(FClientSocket.FOnConnected) then
    FClientSocket.FOnConnected(FClientSocket, FClientSocket.Line);
end;

procedure TncClientProcessor.ProcessEvent;
var
  PrevOnConnect: TncOnConnectDisconnect;
  WasReconnected: Boolean;
begin
  while (not Terminated) do // Repeat handling until terminated
    try
      if FClientSocket.Line.Active then // Repeat reading socket until disconnected
      begin
        if ReadableAnySocket(FClientSocket.ReadSocketHandles, 250) then
          if FClientSocket.EventsUseMainThread then
            Synchronize(SocketProcess) // for synchronize
          else
            SocketProcess;
      end
      else
      // Is not Active, try reconnecting if was connected
      begin
        // Logic for reconnect mode
        if FClientSocket.Reconnect and FClientSocket.WasConnected then
        begin
          // A minimal sleep time of 30 msec is required in Android before
          // reattempting to connect on a recently deactivated network connection.
          // We have put it to 60 for safety
          Sleep(60);
          if Terminated then
            Break;
          if TStopWatch.GetTimeStamp - FClientSocket.LastConnectAttempt > FClientSocket.ReconnectInterval * TTimeSpan.TicksPerMillisecond then
          begin
            FClientSocket.LastConnectAttempt := TStopWatch.GetTimeStamp;

            WasReconnected := False;
            FClientSocket.PropertyLock.Acquire;
            try
              if not FClientSocket.Active then
              begin
                PrevOnConnect := FClientSocket.OnConnected;
                try
                  // Disable firing the event in the wrong thread in case it gets connected
                  FClientSocket.OnConnected := nil;
                  FClientSocket.Active := True;
                  WasReconnected := True;
                finally
                  FClientSocket.OnConnected := PrevOnConnect;
                end;
              end;
            finally
              FClientSocket.PropertyLock.Release;
            end;
            if WasReconnected then
              if FClientSocket.EventsUseMainThread then
                Synchronize(SocketWasReconnected)
              else
                SocketWasReconnected;
          end;
        end
        else
          Exit;
      end;
    except
      // Something was disconnected, continue processing
    end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomTCPServer }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomTCPServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  Listener := CreateLineObject;
  TncLineInternal(Listener).OnConnected := DataSocketConnected;
  TncLineInternal(Listener).OnDisconnected := DataSocketDisconnected;

  Lines := TThreadLineList.Create;
  LineProcessor := TncServerProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
end;

destructor TncCustomTCPServer.Destroy;
begin
  // Will get Sockets.Lines disposed off
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Lines.Free;
  Listener.Free;

  inherited Destroy;
end;

function TncCustomTCPServer.GetActive: Boolean;
begin
  Result := Listener.Active;
end;

procedure TncCustomTCPServer.DoActivate(aActivate: Boolean);
begin
  if aActivate = GetActive then
    Exit;

  if aActivate then
    TncLineInternal(Listener).CreateServerHandle(FPort)
  else
  begin
    TncLineInternal(Listener).DestroyHandle;
    LineProcessor.WaitForReady;

    while Lines.FList.Count > 0 do
      TncLineInternal(Lines.FList.Lines[0]).DestroyHandle;
  end;
end;

procedure TncCustomTCPServer.ShutDownLine(aLine: TncLine);
begin
  if UseReaderThread then
  begin
    ShutDownLock.Acquire;
    try
      SetLength(LinesToShutDown, Length(LinesToShutDown) + 1);
      LinesToShutDown[High(LinesToShutDown)] := aLine;
    finally
      ShutDownLock.Release;
    end;
  end
  else
  begin
    Lines.Remove(aLine);
    aLine.Free;
  end;
end;

procedure TncCustomTCPServer.DataSocketConnected(aLine: TncLine);
begin
  if aLine = Listener then
  begin
    SetLength(ReadSocketHandles, 1);
    ReadSocketHandles[0] := Listener.Handle;
    LineProcessor.WaitForReady;
    if UseReaderThread then
      LineProcessor.Run;
  end
  else
  begin
    SetLength(ReadSocketHandles, Length(ReadSocketHandles) + 1);
    ReadSocketHandles[High(ReadSocketHandles)] := aLine.Handle;

    if NoDelay then
      try
        TncLineInternal(aLine).EnableNoDelay;
      except
      end;

    if KeepAlive then
      try
        TncLineInternal(aLine).EnableKeepAlive;
      except
      end;

    if Assigned(OnConnected) and not(csDestroying in ComponentState) then
      try
        OnConnected(Self, aLine);
      except
      end;
  end;
end;

procedure TncCustomTCPServer.DataSocketDisconnected(aLine: TncLine);
var
  i: Integer;
begin
  if aLine <> Listener then
  begin
    for i := 0 to High(ReadSocketHandles) do
      if ReadSocketHandles[i] = aLine.Handle then
      begin
        ReadSocketHandles[i] := ReadSocketHandles[High(ReadSocketHandles)];
        SetLength(ReadSocketHandles, Length(ReadSocketHandles) - 1);
        Break;
      end;

    // Try to see first if we can lock the list so that we immediatelly
    // destroy the line (the lock might be held by code in the OnReadData)
    if Lines.FLock.TryEnter then
      try
        if Assigned(OnDisconnected) and not(csDestroying in ComponentState) then
          try
            OnDisconnected(Self, aLine);
          except
          end;

        Lines.FList.Delete(Lines.FList.IndexOf(aLine.Handle));
        aLine.Free;
      finally
        Lines.FLock.Leave;
      end
    else
      ShutDownLine(aLine);
  end;
end;

procedure TncCustomTCPServer.Send(aLine: TncLine; const aBuf; aBufSize: Integer);
begin
  TncLineInternal(aLine).SendBuffer(aBuf, aBufSize);
end;

procedure TncCustomTCPServer.Send(aLine: TncLine; const aBytes: TBytes);
begin
  if Length(aBytes) > 0 then
    Send(aLine, aBytes[0], Length(aBytes));
end;

procedure TncCustomTCPServer.Send(aLine: TncLine; const aStr: string);
begin
  Send(aLine, BytesOf(aStr));
end;

function TncCustomTCPServer.Receive(aLine: TncLine; aTimeout: Cardinal): TBytes;
var
  i: Integer;
  BufRead: Integer;
  DataSockets: TSocketList;
  Line: TncLine;
  ReadySockets: TSocketHandleArray;
begin
  if UseReaderThread then
    raise ECannotReceiveIfUseReaderThread.Create(ECannotReceiveIfUseReaderThreadStr);

  SetLength(Result, 0);
  ReadySockets := Readable(ReadSocketHandles, aTimeout);

  DataSockets := Lines.LockList;
  try
    for i := 0 to High(ReadySockets) do
      if ReadySockets[i] = Listener.Handle then
        // New line is here, accept it and create a new TncLine object
        Lines.Add(TncLineInternal(Listener).AcceptLine)
      else if aLine.Handle = ReadySockets[i] then
        try
          Line := DataSockets.Lines[DataSockets.IndexOf(ReadySockets[i])];
          BufRead := TncLineInternal(Line).RecvBuffer(ReadBuf[0], Length(ReadBuf));
          Result := Copy(ReadBuf, 0, BufRead)
        except
        end;
  finally
    Lines.UnlockList;
  end;
end;

function TncCustomTCPServer.ReceiveRaw(aLine: TncLine; var aBytes: TBytes): Integer;
begin
  Result := TncLineInternal(aLine).RecvBuffer(aBytes[0], Length(aBytes));
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncServerProcessor }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncServerProcessor.Create(aServerSocket: TncCustomTCPServer);
begin
  FServerSocket := aServerSocket;
  inherited Create;
end;

procedure TncServerProcessor.SocketProcess;
var
  i: Integer;
  BufRead: Integer;
  DataSockets: TSocketList;
  Line: TncLine;
begin
  CheckLinesToShutDown;

  // DataSockets list is handled by this thread, so we don't lock the list
  // We do this as we need the list to be unlocked if the programmer
  // needs to access it/lock it from the OnReadData handler
  DataSockets := FServerSocket.Lines.FList;
  for i := 0 to High(ReadySockets) do
    if ReadySockets[i] = FServerSocket.Listener.Handle then
    begin
      // We will process new lines only if the Lines thread list is not locked
      // (It may be locked from code running in the OnReadData)
      if FServerSocket.Lines.FLock.TryEnter then
        try
          CheckLinesToShutDown;
          // New line is here, accept it and create a new TncLine object
          FServerSocket.Lines.Add(TncLineInternal(FServerSocket.Listener).AcceptLine);
        finally
          FServerSocket.Lines.FLock.Leave;
        end;
    end
    else
      try
        Line := DataSockets.Lines[DataSockets.IndexOf(ReadySockets[i])];
        BufRead := TncLineInternal(Line).RecvBuffer(FServerSocket.ReadBuf[0], Length(FServerSocket.ReadBuf));
        if Assigned(FServerSocket.OnReadData) then
          FServerSocket.OnReadData(FServerSocket, Line, FServerSocket.ReadBuf, BufRead);
      except
      end;
end;

procedure TncServerProcessor.CheckLinesToShutDown;
var
  i: Integer;
begin
  // The list may be locked from custom code executed in the OnReadData handler
  // So we will not delete anything, or lock the list, until this lock is freed
  if FServerSocket.Lines.FLock.TryEnter then
    try
      FServerSocket.ShutDownLock.Acquire;
      try
        for i := 0 to High(FServerSocket.LinesToShutDown) do
          try
            if FServerSocket.LinesToShutDown[i].Active then
              TncLineInternal(FServerSocket.LinesToShutDown[i]).DestroyHandle
            else
              FServerSocket.DataSocketDisconnected(FServerSocket.LinesToShutDown[i]);
          except
          end;
        SetLength(FServerSocket.LinesToShutDown, 0);
      finally
        FServerSocket.ShutDownLock.Release;
      end;
    finally
      FServerSocket.Lines.FLock.Leave;
    end;
end;

procedure TncServerProcessor.ProcessEvent;
begin
  if FServerSocket.EventsUseMainThread then
    while FServerSocket.Listener.Active and (not Terminated) do
      try
        ReadySockets := Readable(FServerSocket.ReadSocketHandles, 500);
        Synchronize(SocketProcess);
      except
      end
  else
    while FServerSocket.Listener.Active and (not Terminated) do
      try
        ReadySockets := Readable(FServerSocket.ReadSocketHandles, 500);
        SocketProcess;
      except
      end;
end;

end.
