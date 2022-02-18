unit ncSockets;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit creates a TCP Server and TCP Client socket, along with their
// threads dealing with reading from the socket
//
// 14 Feb 2022 by Andreas Toth - andreas.toth@xtra.co.nz
// - Added UDP and IPv6 support
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
  System.Diagnostics,
  System.TimeSpan,
  ncLines,
  ncSocketList,
  ncThreads;

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
  DefBroadcast = False;

resourcestring
  ECannotSetFamilyWhileConnectionIsActiveStr = 'Cannot set Family property whilst the connection is active';
  ECannotSetPortWhileConnectionIsActiveStr = 'Cannot set Port property whilst the connection is active';
  ECannotSetHostWhileConnectionIsActiveStr = 'Cannot set Host property whilst the connection is active';
  ECannotSetUseReaderThreadWhileActiveStr = 'Cannot set UseReaderThread property whilst the connection is active';
  ECannotReceiveIfUseReaderThreadStr = 'Cannot receive data if UseReaderThread is set. Use OnReadData event handler to get the data or set UseReaderThread property to False';

type
  EPropertySetError = class(Exception);
  ENonActiveSocket = class(Exception);
  ECannotReceiveIfUseReaderThread = class(Exception);

  // We bring in TncLine so that a form that uses our components does
  // not have to reference ncLines unit to get the type
  TncLine = ncLines.TncLine;

  // We make a descendant of TncLine so that we can access the API functions.
  // These API functions are not made puclic in TncLine so that the user cannot
  // mangle up the line.
  //
  // Note that this descendant must be declared in the interface section in
  // order to be able to use it inline even though the purpose of it only
  // serves the implementation section of this unit as using it from another
  // unit will once again hide the protected API functions.
  TncLineAccess = class(TncLine);

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TThreadLineList
  // Thread safe object, used by the main components

  TThreadLineList = class
  private
    FList: TSocketList;
    FListCopy: TSocketList;
    FLock: TCriticalSection;
    FLockCount: Integer;
  protected
    procedure Add(const AItem: TncLine); inline;
    procedure Clear; inline;
    procedure Remove(AItem: TncLine); inline;

    function LockListNoCopy: TSocketList;
    procedure UnlockListNoCopy;
  public
    constructor Create;
    destructor Destroy; override;

    function LockList: TSocketList;
    procedure UnlockList;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Base object for all sockets
  TncOnConnectDisconnect = procedure(Sender: TObject; ALine: TncLine) of object;
  TncOnReadData = procedure(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer) of object;
  TncOnReconnected = procedure(Sender: TObject; ALine: TncLine) of object;

  TncCustomSocket = class;
  TncCustomSocketClass = class of TncCustomSocket;

  TncCustomSocket = class(TComponent)
  private
    FInitActive: Boolean;
    FFamily: TAddressType;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FNoDelay: Boolean;
    FKeepAlive: Boolean;
    FBroadcast: Boolean;
    FOnConnected: TncOnConnectDisconnect;
    FOnDisconnected: TncOnConnectDisconnect;
    FOnReadData: TncOnReadData;

    function GetActive: Boolean; virtual; abstract;
    procedure SetActive(const AValue: Boolean);

    function GetFamily: TAddressType;
    procedure SetFamily(const AValue: TAddressType);

    function GetPort: Integer;
    procedure SetPort(const AValue: Integer);

    function GetReaderThreadPriority: TncThreadPriority;
    procedure SetReaderThreadPriority(const AValue: TncThreadPriority);

    function GetEventsUseMainThread: Boolean;
    procedure SetEventsUseMainThread(const AValue: Boolean);
  protected
    function GetNoDelay: Boolean;
    procedure SetNoDelay(const AValue: Boolean);

    function GetKeepAlive: Boolean;
    procedure SetKeepAlive(const AValue: Boolean);

    function GetBroadcast: Boolean;
    procedure SetBroadcast(const AValue: Boolean);
  private
    FUseReaderThread: Boolean;

    procedure DoActivate(AActivate: Boolean); virtual; abstract;
    procedure SetUseReaderThread(const AValue: Boolean);
  protected
    PropertyLock: TCriticalSection;
    ShutdownLock: TCriticalSection;
    ReadBuf: TBytes;

    procedure Loaded; override;
    function CreateLineObject: TncLine; virtual;
  public
    LineProcessor: TncReadyThread;

    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    property Family: TAddressType read GetFamily write SetFamily default TncLineAccess.DefaultFamily;
    function Kind: TSocketType; virtual; abstract;
    property Active: Boolean read GetActive write SetActive default False;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property EventsUseMainThread: Boolean read GetEventsUseMainThread write SetEventsUseMainThread default DefEventsUseMainThread;
    property UseReaderThread: Boolean read FUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default DefNoDelay;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default DefKeepAlive;
    property Broadcast: Boolean read GetBroadcast write SetBroadcast default DefBroadcast;
    property OnConnected: TncOnConnectDisconnect read FOnConnected write FOnConnected;
    property OnDisconnected: TncOnConnectDisconnect read FOnDisconnected write FOnDisconnected;
    property OnReadData: TncOnReadData read FOnReadData write FOnReadData;

    function IsConnectionBased: Boolean;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Client socket
  TncClientProcessor = class;

  TncCustomSocketClient = class;
  TncCustomSocketClientClass = class of TncCustomSocketClient;

  TncCustomSocketClient = class(TncCustomSocket)
  private
    FHost: string;
    FReconnect: Boolean;
    FReconnectInterval: Cardinal;
    FOnReconnected: TncOnReconnected;

    function GetActive: Boolean; override;

    procedure SetHost(const AValue: string);
    function GetHost: string;

    function GetReconnect: Boolean;
    procedure SetReconnect(const AValue: Boolean);

    function GetReconnectInterval: Cardinal;
    procedure SetReconnectInterval(const AValue: Cardinal);
  protected
    WasConnected: Boolean;
    LastConnectAttempt: Int64;

    procedure DoActivate(AActivate: Boolean); override;

    procedure DataSocketConnected(ALine: TncLine);
    procedure DataSocketDisconnected(ALine: TncLine);
  public
    ReadSocketHandles: TSocketHandleArray;
    Line: TncLine;

    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    property Host: string read GetHost write SetHost;

    procedure Send(const ABuffer; ABufferSize: Integer); overload; inline;
    procedure Send(const ABytes: TBytes); overload; inline;
    procedure Send(const AString: string); overload; inline;

    function Receive(ATimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(var ABytes: TBytes): Integer; inline;

    property Reconnect: Boolean read GetReconnect write SetReconnect default True;
    property ReconnectInterval: Cardinal read GetReconnectInterval write SetReconnectInterval default DefCntReconnectInterval;
    property OnReconnected: TncOnReconnected read FOnReconnected write FOnReconnected;
  end;

  TncCustomUDPClient = class(TncCustomSocketClient)
  public
    constructor Create(AOwner: TComponent); override;

    function Kind: TSocketType; override;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default False;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default False;
  end;

  TncUDPClient = class(TncCustomUDPClient)
  published
    property Active;
    property Family;
    property Port;
    property Host;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property Broadcast;
    property OnReadData;
  end;

  TncCustomTCPClient = class(TncCustomSocketClient)
  public
    function Kind: TSocketType; override;
  end;

  TncTCPClient = class(TncCustomTCPClient)
  published
    property Active;
    property Family;
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
    FClientSocket: TncCustomSocketClient;
  public
    ReadySocketsChanged: Boolean;

    constructor Create(aClientSocket: TncCustomSocketClient);

    procedure SocketWasReconnected;
    procedure SocketProcess; inline;
    procedure ProcessEvent; override;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Server Socket
  TncServerProcessor = class;

  TncCustomSocketServer = class;
  TncCustomSocketServerClass = class of TncCustomSocketServer;

  TncCustomSocketServer = class(TncCustomSocket)
  private
    function GetActive: Boolean; override;
  protected
    Listener: TncLine;
    LinesToShutdown: array of TncLine;

    procedure DataSocketConnected(ALine: TncLine);
    procedure DataSocketDisconnected(ALine: TncLine);
    procedure DoActivate(AActivate: Boolean); override;
  public
    ReadSocketHandles: TSocketHandleArray;
    Lines: TThreadLineList;

    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure ShutdownLine(ALine: TncLine);

    procedure Send(ALine: TncLine; const ABuffer; ABufferSize: Integer); overload; inline;
    procedure Send(ALine: TncLine; const ABytes: TBytes); overload; inline;
    procedure Send(ALine: TncLine; const AString: string); overload; inline;

    function Receive(ALine: TncLine; ATimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(ALine: TncLine; var ABytes: TBytes): Integer; inline;
  end;

  TncCustomUDPServer = class(TncCustomSocketServer)
  public
    constructor Create(AOwner: TComponent); override;

    function Kind: TSocketType; override;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default False;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default False;
  end;

  TncCustomTCPServer = class(TncCustomSocketServer)
  public
    function Kind: TSocketType; override;
  end;

  TncUDPServer = class(TncCustomUDPServer)
  published
    property Active;
    property Family;
    property Port;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property Broadcast;
    property OnReadData;
  end;

  TncTCPServer = class(TncCustomTCPServer)
  published
    property Active;
    property Family;
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
    FServerSocket: TncCustomSocketServer;

    procedure CheckLinesToShutdown;
  public
    ReadySockets: TSocketHandleArray;
    ReadySocketsChanged: Boolean;

    constructor Create(AServerSocket: TncCustomSocketServer);

    procedure SocketProcess; inline;
    procedure ProcessEvent; override;
  end;

implementation

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TThreadLineList }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TThreadLineList.Create;
begin
  inherited Create;

  FLock := TCriticalSection.Create;
  FList := TSocketList.Create;
  FLockCount := 0;
end;

destructor TThreadLineList.Destroy;
begin
  if Assigned(FLock) then
  begin
    LockListNoCopy;
    try
      FreeAndNil(FList);

      inherited Destroy;
    finally
      UnlockListNoCopy;
      FreeAndNil(FLock);
    end;
  end else
  begin
    FreeAndNil(FList);

    inherited Destroy;
  end;
end;

procedure TThreadLineList.Add(const AItem: TncLine);
begin
  LockListNoCopy;
  try
    // FList has Duplicates to dupError, so we know if this is already in the
    // list it will not be accepted
    FList.Add(AItem.Handle, AItem);
  finally
    UnlockListNoCopy;
  end;
end;

procedure TThreadLineList.Clear;
begin
  LockListNoCopy;
  try
    FList.Clear;
  finally
    UnlockListNoCopy;
  end;
end;

procedure TThreadLineList.Remove(AItem: TncLine);
begin
  LockListNoCopy;
  try
    FList.Delete(FList.IndexOf(AItem.Handle));
  finally
    UnlockListNoCopy;
  end;
end;

function TThreadLineList.LockListNoCopy: TSocketList;
begin
  FLock.Acquire;
  Result := FList;
end;

procedure TThreadLineList.UnlockListNoCopy;
begin
  FLock.Release;
end;

function TThreadLineList.LockList: TSocketList;
begin
  FLock.Acquire;
  try
    if FLockCount = 0 then
    begin
      FListCopy := TSocketList.Create;
      FListCopy.Assign(FList);
    end;

    Result := FListCopy;
    FLockCount := FLockCount + 1;
  finally
    FLock.Release;
  end;
end;

procedure TThreadLineList.UnlockList;
begin
  FLock.Acquire;
  try
    if FLockCount = 0 then
      raise Exception.Create('Cannot unlock a non-locked list');

    FLockCount := FLockCount - 1;

    if FLockCount = 0 then
    begin
      FreeAndNil(FListCopy);
    end;
  finally
    FLock.Release;
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomSocket }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomSocket.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  PropertyLock := TCriticalSection.Create;
  ShutdownLock := TCriticalSection.Create;

  FInitActive := False;
  FFamily := TncLineAccess.DefaultFamily;
  FPort := DefPort;
  FEventsUseMainThread := DefEventsUseMainThread;
  FUseReaderThread := DefUseReaderThread;
  FNoDelay := DefNoDelay;
  FKeepAlive := DefKeepAlive;
  FBroadcast := DefBroadcast;
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnReadData := nil;

  SetLength(ReadBuf, DefReadBufferLen);
end;

destructor TncCustomSocket.Destroy;
begin
  FreeAndNil(ShutdownLock);
  FreeAndNil(PropertyLock);

  inherited Destroy;
end;

procedure TncCustomSocket.Loaded;
begin
  inherited Loaded;

  if FInitActive then
  begin
    DoActivate(True);
  end;
end;

function TncCustomSocket.CreateLineObject: TncLine;
begin
  Result := TncLineAccess.Create;
  TncLineAccess(Result).SetKind(Kind);
end;

function TncCustomSocket.IsConnectionBased: Boolean;
begin
  Result := Kind = stTCP;
end;

procedure TncCustomSocket.SetActive(const AValue: Boolean);
begin
  PropertyLock.Acquire;
  try
    if not (csLoading in ComponentState) then
    begin
      DoActivate(AValue);
    end;

    if not (csDestroying in ComponentState) then
    begin
      FInitActive := GetActive; // We only care here for the loaded event
    end;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetFamily: TAddressType;
begin
  PropertyLock.Acquire;
  try
    Result := FFamily;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetFamily(const AValue: TAddressType);
begin
  if not (csLoading in ComponentState) then
  begin
    if Active then
    begin
      raise EPropertySetError.Create(ECannotSetFamilyWhileConnectionIsActiveStr);
    end;
  end;

  PropertyLock.Acquire;
  try
    FFamily := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetPort: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FPort;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetPort(const AValue: Integer);
begin
  if not (csLoading in ComponentState) then
  begin
    if Active then
    begin
      raise EPropertySetError.Create(ECannotSetPortWhileConnectionIsActiveStr);
    end;
  end;

  PropertyLock.Acquire;
  try
    FPort := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetReaderThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := ToNcThreadPriority(LineProcessor.Priority);
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetReaderThreadPriority(const AValue: TncThreadPriority);
begin
  PropertyLock.Acquire;
  try
    try
      LineProcessor.Priority := FromNcThreadPriority(AValue);
    except
      // Some android devices cannot handle changing priority
    end;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetEventsUseMainThread: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FEventsUseMainThread;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetEventsUseMainThread(const AValue: Boolean);
begin
  PropertyLock.Acquire;
  try
    FEventsUseMainThread := AValue;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetUseReaderThread(const AValue: Boolean);
begin
  if not (csLoading in ComponentState) then
  begin
    if Active then
    begin
      raise EPropertySetError.Create(ECannotSetUseReaderThreadWhileActiveStr);
    end;
  end;

  PropertyLock.Acquire;
  try
    FUseReaderThread := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetNoDelay: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FNoDelay;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetNoDelay(const AValue: Boolean);
begin
  PropertyLock.Acquire;
  try
    FNoDelay := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetKeepAlive: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FKeepAlive;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetKeepAlive(const AValue: Boolean);
begin
  PropertyLock.Acquire;
  try
    FKeepAlive := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocket.GetBroadcast: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FBroadcast;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocket.SetBroadcast(const AValue: Boolean);
begin
  PropertyLock.Acquire;
  try
    FBroadcast := AValue;
  finally
    PropertyLock.Release;
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomSocketClient }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomSocketClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FHost := DefHost;
  FReconnect := True;
  FReconnectInterval := DefCntReconnectInterval;
  FOnReconnected := nil;

  LastConnectAttempt := TStopWatch.GetTimeStamp;
  WasConnected := False;

  Line := CreateLineObject;
  TncLineAccess(Line).OnConnected := DataSocketConnected;
  TncLineAccess(Line).OnDisconnected := DataSocketDisconnected;

  LineProcessor := TncClientProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
  LineProcessor.WaitForReady;
end;

destructor TncCustomSocketClient.Destroy;
begin
  if Assigned(PropertyLock) then
  begin
    Active := False; // Active protected by PropertyLock
  end;

  if Assigned(LineProcessor) then
  begin
    LineProcessor.Terminate;
    LineProcessor.WakeupEvent.SetEvent;
    LineProcessor.WaitFor;

    FreeAndNil(LineProcessor);
  end;

  FreeAndNil(Line);

  inherited Destroy;
end;

procedure TncCustomSocketClient.DoActivate(AActivate: Boolean);
begin
  if AActivate = GetActive then
  begin
    Exit; // ==>
  end;

  if AActivate then
  begin
    TncLineAccess(Line).CreateClientHandle(FHost, FPort);
    // if there were no exceptions, and line is still not active,
    // that means the user has deactivated it in the OnConnect handler

    if not Line.Active then
    begin
      WasConnected := False;
    end;
  end else
  begin
    WasConnected := False;
    TncLineAccess(Line).DestroyHandle;
  end;
end;

procedure TncCustomSocketClient.DataSocketConnected(ALine: TncLine);
begin
  SetLength(ReadSocketHandles, 1);
  ReadSocketHandles[0] := Line.Handle;

  if NoDelay then
  try
    TncLineAccess(Line).EnableNoDelay;
  except
    // Ignore
  end;

  if KeepAlive then
  try
    TncLineAccess(Line).EnableKeepAlive;
  except
    // Ignore
  end;

  if Broadcast then
  try
    TncLineAccess(Line).EnableBroadcast;
  except
    // Ignore
  end;

  if Assigned(OnConnected) then
  try
    OnConnected(Self, ALine);
  except
    // Ignore
  end;

  LastConnectAttempt := TStopWatch.GetTimeStamp;
  WasConnected := True;

  if UseReaderThread then
  begin
    LineProcessor.Run; // Will just set events, this does not wait
  end;
end;

procedure TncCustomSocketClient.DataSocketDisconnected(ALine: TncLine);
begin
  if Assigned(OnDisconnected) then
  try
    OnDisconnected(Self, ALine);
  except
    // Ignore
  end;
end;

procedure TncCustomSocketClient.Send(const ABuffer; ABufferSize: Integer);
begin
  Active := True;
  TncLineAccess(Line).SendBuffer(ABuffer, ABufferSize);
end;

procedure TncCustomSocketClient.Send(const ABytes: TBytes);
begin
  if Length(ABytes) > 0 then
  begin
    Send(ABytes[0], Length(ABytes));
  end;
end;

procedure TncCustomSocketClient.Send(const AString: string);
begin
  Send(BytesOf(AString));
end;

function TncCustomSocketClient.Receive(ATimeout: Cardinal): TBytes;
var
  BufRead: Integer;
begin
  if UseReaderThread then
  begin
    raise ECannotReceiveIfUseReaderThread.Create(ECannotReceiveIfUseReaderThreadStr);
  end;

  Active := True;

  if not ReadableAnySocket([Line.Handle], ATimeout) then
  begin
    SetLength(Result, 0);
    Exit; // ==>
  end;

  BufRead := TncLineAccess(Line).RecvBuffer(ReadBuf[0], Length(ReadBuf));
  Result := Copy(ReadBuf, 0, BufRead)
end;

function TncCustomSocketClient.ReceiveRaw(var ABytes: TBytes): Integer;
begin
  Result := TncLineAccess(Line).RecvBuffer(ABytes[0], Length(ABytes));
end;

function TncCustomSocketClient.GetActive: Boolean;
begin
  Result := Assigned(Line) and Line.Active;
end;

function TncCustomSocketClient.GetHost: string;
begin
  PropertyLock.Acquire;
  try
    Result := FHost;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocketClient.SetHost(const AValue: string);
begin
  if not (csLoading in ComponentState) then
  begin
    if Active then
    begin
      raise EPropertySetError.Create(ECannotSetHostWhileConnectionIsActiveStr);
    end;
  end;

  PropertyLock.Acquire;
  try
    FHost := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocketClient.GetReconnect: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FReconnect;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocketClient.SetReconnect(const AValue: Boolean);
begin
  PropertyLock.Acquire;
  try
    FReconnect := AValue;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomSocketClient.GetReconnectInterval: Cardinal;
begin
  PropertyLock.Acquire;
  try
    Result := FReconnectInterval;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomSocketClient.SetReconnectInterval(const AValue: Cardinal);
begin
  PropertyLock.Acquire;
  try
    FReconnectInterval := AValue;
  finally
    PropertyLock.Release;
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomUDPClient }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomUDPClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FNoDelay := False;
  FKeepAlive := False;
end;

function TncCustomUDPClient.Kind: TSocketType;
begin
  Result := stUDP;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomTCPClient }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function TncCustomTCPClient.Kind: TSocketType;
begin
  Result := stTCP;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncClientProcessor }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncClientProcessor.Create(aClientSocket: TncCustomSocketClient);
begin
  FClientSocket := aClientSocket;
  ReadySocketsChanged := False;

  inherited Create;
end;

procedure TncClientProcessor.SocketProcess;
var
  BufRead: Integer;
begin
  BufRead := TncLineAccess(FClientSocket.Line).RecvBuffer(FClientSocket.ReadBuf[0], Length(FClientSocket.ReadBuf));

  if Assigned(FClientSocket.OnReadData) then
  try
    FClientSocket.OnReadData(FClientSocket, FClientSocket.Line, FClientSocket.ReadBuf, BufRead);
  except
    // Ignore
  end;
end;

procedure TncClientProcessor.SocketWasReconnected;
begin
  if Assigned(FClientSocket.FOnReconnected) then
  begin
    FClientSocket.FOnReconnected(FClientSocket, FClientSocket.Line);
  end;

  if Assigned(FClientSocket.FOnConnected) then
  begin
    FClientSocket.FOnConnected(FClientSocket, FClientSocket.Line);
  end;
end;

procedure TncClientProcessor.ProcessEvent;
var
  PrevOnConnect: TncOnConnectDisconnect;
  WasReconnected: Boolean;
begin
  while not Terminated do // Repeat handling until terminated
  try
    if (not FClientSocket.IsConnectionBased) or FClientSocket.Line.Active then // Repeat reading socket until disconnected
    begin
      if ReadableAnySocket(FClientSocket.ReadSocketHandles, 250) then
      begin
        if ReadySocketsChanged then
        begin
          ReadySocketsChanged := False;
          Continue; // ==>
        end;

        if FClientSocket.EventsUseMainThread then
        begin
          Synchronize(SocketProcess);
        end else
        begin
          SocketProcess;
        end;
      end;
    end else // Not Active, try reconnecting if connection-based and was connected
    begin
      if (not FClientSocket.IsConnectionBased) or (not (FClientSocket.Reconnect and FClientSocket.WasConnected)) then
      begin
        Exit; // ==>
      end;

      // A minimal sleep time of 30 msec is required in Android before
      // reattempting to connect on a recently deactivated network connection.
      // We have put it to 60 for safety
      Sleep(60);

      if Terminated then
      begin
        Break; // ==>
      end;

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
        begin
          if FClientSocket.EventsUseMainThread then
          begin
            Synchronize(SocketWasReconnected);
          end else
          begin
            SocketWasReconnected;
          end;
        end;
      end;
    end;
  except
    // Something was disconnected, continue processing
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomSocketServer }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomSocketServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  Listener := CreateLineObject;
  TncLineAccess(Listener).OnConnected := DataSocketConnected;
  TncLineAccess(Listener).OnDisconnected := DataSocketDisconnected;

  Lines := TThreadLineList.Create;

  LineProcessor := TncServerProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
end;

destructor TncCustomSocketServer.Destroy;
begin
  if IsConnectionBased and Assigned(PropertyLock) then
  begin
    // Disposes of Lines
    Active := False; // Protected by PropertyLock
  end;

  if Assigned(LineProcessor) then
  begin
    LineProcessor.Terminate;
    LineProcessor.WakeupEvent.SetEvent;
    LineProcessor.WaitFor;

    FreeAndNil(LineProcessor);
  end;

  FreeAndNil(Lines);
  FreeAndNil(Listener);

  inherited Destroy;
end;

function TncCustomSocketServer.GetActive: Boolean;
begin
  Result := Assigned(Listener) and Listener.Active;
end;

procedure TncCustomSocketServer.DoActivate(AActivate: Boolean);
var
  DataSockets: TSocketList;
  i: Integer;
begin
  if AActivate = GetActive then
  begin
    Exit; // ==>
  end;

  if AActivate then
  begin
    TncLineAccess(Listener).CreateServerHandle(FPort);
  end else
  begin
    TncLineAccess(Listener).DestroyHandle;

    // Delphi complains about the free that it does nothing except nil the variable
    // That is under the mostly forgettable and thankgoodness "gotten rid off"
    // ARC compilers...
{$HINTS OFF}
    DataSockets := Lines.LockListNoCopy;
    try
      for i := 0 to DataSockets.Count - 1 do
      try
        TncLineAccess(DataSockets.Lines[i]).DestroyHandle;
        FreeAndNil(DataSockets.Lines[i]);
      except
        // Ignore
      end;

      DataSockets.Clear;
    finally
      Lines.UnlockListNoCopy;
    end;
  end;
end;

procedure TncCustomSocketServer.ShutdownLine(ALine: TncLine);
var
  i: Integer;
begin
  if UseReaderThread then
  begin
    ShutdownLock.Acquire;
    try
      for i := Low(LinesToShutdown) to High(LinesToShutdown) do
      begin
        if LinesToShutdown[i] = ALine then
        begin
          Exit; // ==>
        end;
      end;

      SetLength(LinesToShutdown, Length(LinesToShutdown) + 1);
      LinesToShutdown[High(LinesToShutdown)] := ALine;
    finally
      ShutdownLock.Release;
    end;
  end else
  begin
    Lines.Remove(ALine);
    FreeAndNil(ALine);
  end;
end;

procedure TncCustomSocketServer.DataSocketConnected(ALine: TncLine);
begin
  if ALine = Listener then
  begin
    SetLength(ReadSocketHandles, 1);
    ReadSocketHandles[0] := Listener.Handle;

    if UseReaderThread then
    begin
      LineProcessor.WaitForReady;
      LineProcessor.Run;
    end;
  end else
  begin
    SetLength(ReadSocketHandles, Length(ReadSocketHandles) + 1);
    ReadSocketHandles[High(ReadSocketHandles)] := ALine.Handle;

    if NoDelay then
    try
      TncLineAccess(ALine).EnableNoDelay;
    except
      // Ignore
    end;

    if KeepAlive then
    try
      TncLineAccess(ALine).EnableKeepAlive;
    except
      // Ignore
    end;

    if Assigned(OnConnected) then
    try
      OnConnected(Self, ALine);
    except
      // Ignore
    end;
  end;
end;

procedure TncCustomSocketServer.DataSocketDisconnected(ALine: TncLine);
var
  i: Integer;
begin
  if ALine = Listener then
  begin
    SetLength(ReadSocketHandles, 0);
  end else
  begin
    if Assigned(OnDisconnected) then
    try
      OnDisconnected(Self, ALine);
    except
      // ==>
    end;

    for i := Low(ReadSocketHandles) to High(ReadSocketHandles) do
    begin
      if ReadSocketHandles[i] = ALine.Handle then
      begin
        ReadSocketHandles[i] := ReadSocketHandles[High(ReadSocketHandles)];
        SetLength(ReadSocketHandles, Length(ReadSocketHandles) - 1);

        Exit; // ==>
      end;
    end;
  end;
end;

procedure TncCustomSocketServer.Send(ALine: TncLine; const ABuffer; ABufferSize: Integer);
begin
  TncLineAccess(ALine).SendBuffer(ABuffer, ABufferSize);
end;

procedure TncCustomSocketServer.Send(ALine: TncLine; const ABytes: TBytes);
begin
  if Length(ABytes) > 0 then
  begin
    Send(ALine, ABytes[0], Length(ABytes));
  end;
end;

procedure TncCustomSocketServer.Send(ALine: TncLine; const AString: string);
begin
  Send(ALine, BytesOf(AString));
end;

function TncCustomSocketServer.Receive(ALine: TncLine; ATimeout: Cardinal): TBytes;
var
  i: Integer;
  BufRead: Integer;
  LineNdx: Integer;
  DataSockets: TSocketList;
  Line: TncLine;
  ReadySockets: TSocketHandleArray;
begin
  if UseReaderThread then
  begin
    raise ECannotReceiveIfUseReaderThread.Create(ECannotReceiveIfUseReaderThreadStr);
  end;

  SetLength(Result, 0);
  ReadySockets := Readable(ReadSocketHandles, ATimeout);

  for i := Low(ReadySockets) to High(ReadySockets) do
  try
    if ReadySockets[i] = Listener.Handle then
    begin
      // New line is here, accept it and create a new TncLine object
      Lines.Add(TncLineAccess(Listener).AcceptLine);
    end;
  except
    // ==>
  end;

  DataSockets := Lines.LockListNoCopy;
  try
    for i := Low(ReadySockets) to High(ReadySockets) do
      try
        if ALine.Handle = ReadySockets[i] then
        begin
          LineNdx := DataSockets.IndexOf(ReadySockets[i]);

          if LineNdx = -1 then
          begin
            Continue; // ==>
          end;

          Line := DataSockets.Lines[LineNdx];
          try
            if not Line.Active then
            begin
              Abort; // ==>
            end;

            BufRead := TncLineAccess(Line).RecvBuffer(ReadBuf[0], Length(ReadBuf));
            Result := Copy(ReadBuf, 0, BufRead);
          except
            // Line has disconnected, destroy the line
            DataSockets.Delete(LineNdx);
            FreeAndNil(Line);
          end;
        end;
      except
        // ==>
      end;
  finally
    Lines.UnlockListNoCopy;
  end;
end;

function TncCustomSocketServer.ReceiveRaw(ALine: TncLine; var ABytes: TBytes): Integer;
begin
  Result := TncLineAccess(ALine).RecvBuffer(ABytes[0], Length(ABytes));
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomUDPServer }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomUDPServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FNoDelay := False;
  FKeepAlive := False;
end;

function TncCustomUDPServer.Kind: TSocketType;
begin
  Result := stUDP;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomTCPServer }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function TncCustomTCPServer.Kind: TSocketType;
begin
  Result := stTCP;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncServerProcessor }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncServerProcessor.Create(AServerSocket: TncCustomSocketServer);
begin
  FServerSocket := AServerSocket;
  ReadySocketsChanged := False;

  inherited Create;
end;

procedure TncServerProcessor.CheckLinesToShutdown;
var
  i: Integer;
begin
  // The list may be locked from custom code executed in the OnReadData handler
  // So we will not delete anything, or lock the list, until this lock is freed
  if FServerSocket.Lines.FLock.TryEnter then
  try
    FServerSocket.ShutdownLock.Acquire;
    try
      for i := Low(FServerSocket.LinesToShutdown) to High(FServerSocket.LinesToShutdown) do
      try
        FServerSocket.Lines.Remove(FServerSocket.LinesToShutdown[i]);
        TncLineAccess(FServerSocket.LinesToShutdown[i]).DestroyHandle;
        FreeAndNil(FServerSocket.LinesToShutdown[i]);
      except
        // ==>
      end;

      SetLength(FServerSocket.LinesToShutdown, 0);
    finally
      FServerSocket.ShutdownLock.Release;
    end;
  finally
    FServerSocket.Lines.FLock.Leave;
  end;
end;

procedure TncServerProcessor.SocketProcess;
var
  i: Integer;
  LineNdx: Integer;
  BufRead: Integer;
  ReadySocketsHigh: Integer;
  DataSockets: TSocketList;
  Line: TncLine;
  j: Integer;
begin
  ReadySocketsHigh := High(ReadySockets);

  // First accept new lines
  i := Low(ReadySockets);

  while i <= ReadySocketsHigh do
  begin
    try
      if ReadySockets[i] = FServerSocket.Listener.Handle then
      begin
        // New line is here, accept it and create a new TncLine object
        if ReadySocketsChanged then
        begin
          ReadySocketsChanged := False;
          Exit; // ==>
        end;

        FServerSocket.Lines.Add(TncLineAccess(FServerSocket.Listener).AcceptLine);

        Delete(ReadySockets, i, 1);
        ReadySocketsHigh := ReadySocketsHigh - 1;
        i := i - 1;
      end;
    except
      // ==>
    end;

    i := i + 1;
  end;

  if ReadySocketsChanged then
  begin
    ReadySocketsChanged := False;
    Exit; // ==>
  end;

  // Check for new data
  DataSockets := FServerSocket.Lines.FList;

  for i := Low(ReadySockets) to ReadySocketsHigh do
  try
    LineNdx := DataSockets.IndexOf(ReadySockets[i]);

    if LineNdx = -1 then
    begin
      for j := Low(FServerSocket.ReadSocketHandles) to High(FServerSocket.ReadSocketHandles) do
      begin
        if FServerSocket.ReadSocketHandles[j] = ReadySockets[i] then
        begin
          FServerSocket.ReadSocketHandles[j] := FServerSocket.ReadSocketHandles[High(FServerSocket.ReadSocketHandles)];
          SetLength(FServerSocket.ReadSocketHandles, Length(FServerSocket.ReadSocketHandles) - 1);

          Break; // ==>
        end;
      end;

      Continue; // ==>
    end;

    Line := DataSockets.Lines[LineNdx];
    try
      if not Line.Active then
      begin
        Abort; // ==>
      end;

      if ReadySocketsChanged then
      begin
        ReadySocketsChanged := False;
        Exit; // ==>
      end;

      BufRead := TncLineAccess(Line).RecvBuffer(FServerSocket.ReadBuf[0], Length(FServerSocket.ReadBuf));

      if Assigned(FServerSocket.OnReadData) then
      begin
        FServerSocket.OnReadData(FServerSocket, Line, FServerSocket.ReadBuf, BufRead);
      end;
    except
      // Line has disconnected, destroy the line
      DataSockets.Delete(LineNdx);
      FreeAndNil(Line);
    end;

    if ReadySocketsChanged then
    begin
      ReadySocketsChanged := False;
      Exit; // ==>
    end;
  except
    // Ignore
  end;
end;

procedure TncServerProcessor.ProcessEvent;
begin
  if FServerSocket.EventsUseMainThread then
  begin
    while FServerSocket.Listener.Active and (not Terminated) do
    try
      ReadySockets := Readable(FServerSocket.ReadSocketHandles, 500);
      Synchronize(SocketProcess);
      CheckLinesToShutdown;
    except
      // Ignore
    end;
  end else
  begin
    while FServerSocket.Listener.Active and (not Terminated) do
    try
      ReadySockets := Readable(FServerSocket.ReadSocketHandles, 500);
      SocketProcess;
      CheckLinesToShutdown;
    except
      // Ignore
    end;
  end;
end;

end.
