unit ncTSockets;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit creates TncServer and TncClient components that provide
// raw socket functionality with thread pool processing for received data.
//
// Unlike TncSourceBase which is limited to command protocol processing,
// these components allow custom protocol handling while still benefiting
// from the thread pool architecture for performance.
//
// Component Architecture:
// - TncServer: Raw TCP server with thread pool data processing
// - TncClient: Raw TCP client with thread pool data processing
// - TncSocketBase: Base class with common thread pool functionality
// - TDataProcessingThread: Worker thread for processing raw data
//
// Key Features:
// - Raw socket data processing with thread pool
// - Reader threads for network I/O (non-blocking)
// - Processing threads for data handling (OnReadData event)
// - Component composition pattern wrapping TncTCPServer/TncTCPClient
// - All socket properties delegated to underlying components
//
// Architecture:
// Network Data -> Reader Thread -> Processing Thread Pool -> OnReadData Event
//
//
// 12/07/2025
// - Initial creation
//
// Written by J.Pauwels
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
  Winapi.Windows, Winapi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, System.SyncObjs, System.Math,
  System.Diagnostics, System.TimeSpan, System.RTLConsts, System.Types,
  ncLines, ncSocketList, ncThreads, ncSockets;

type
  // Event type for raw data processing
  TncOnServerReadData = procedure(
    Sender: TObject; 
    aLine: TncLine; 
    const aBuf: TBytes; 
    aBufCount: Integer) of object;

  TncOnServerConnectDisconnect = procedure(
    Sender: TObject; 
    aLine: TncLine) of object;

  TncOnServerReconnected = procedure(
    Sender: TObject; 
    aLine: TncLine) of object;

const
  DefDataProcessorThreadPriority = ntpNormal;
  DefDataProcessorThreads = 0;
  DefDataProcessorThreadsPerCPU = 4;
  DefDataProcessorThreadsGrowUpto = 32;
  DefServerEventsUseMainThread = False;

type

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncSocketBase
  // Base class for TncServer and TncClient providing thread pool data processing
  // Copies the TncSourceBase pattern but for raw data instead of commands
  
  TncSocketBase = class(TComponent)
  private
    FDataProcessorThreadPriority: TncThreadPriority;
    FDataProcessorThreads: Integer;
    FDataProcessorThreadsPerCPU: Integer;
    FDataProcessorThreadsGrowUpto: Integer;
    FEventsUseMainThread: Boolean;
    
    FOnConnected: TncOnServerConnectDisconnect;
    FOnDisconnected: TncOnServerConnectDisconnect;
    FOnReadData: TncOnServerReadData;
    
    // Socket property delegation getters/setters
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
    function GetFamily: TAddressType;
    procedure SetFamily(const Value: TAddressType);
    function GetReadBufferLen: Integer;
    procedure SetReadBufferLen(const Value: Integer);
    function GetUseReaderThread: Boolean;
    procedure SetUseReaderThread(const Value: Boolean);
    
    // Thread pool property getters/setters
    function GetDataProcessorThreadPriority: TncThreadPriority;
    procedure SetDataProcessorThreadPriority(const Value: TncThreadPriority);
    function GetDataProcessorThreads: Integer;
    procedure SetDataProcessorThreads(const Value: Integer);
    function GetDataProcessorThreadsPerCPU: Integer;
    procedure SetDataProcessorThreadsPerCPU(const Value: Integer);
    function GetDataProcessorThreadsGrowUpto: Integer;
    procedure SetDataProcessorThreadsGrowUpto(const Value: Integer);
    function GetEventsUseMainThread: Boolean;
    procedure SetEventsUseMainThread(const Value: Boolean);
  private
    // To set the component active on loaded if was set at design time
    WasSetActive: Boolean;
    WithinConnectionHandler: Boolean;
  protected
    PropertyLock: TCriticalSection;
    DataProcessorThreadPool: TncThreadPool;
    Socket: TncTCPBase;
    
    LastConnectedLine, LastDisconnectedLine, LastReconnectedLine: TncLine;
    
    procedure Loaded; override;
    procedure CallConnectedEvents;
    procedure SocketConnected(Sender: TObject; aLine: TncLine);
    procedure CallDisconnectedEvents;
    procedure SocketDisconnected(Sender: TObject; aLine: TncLine);
    procedure CallReconnectedEvents;
    procedure SocketReconnected(Sender: TObject; aLine: TncLine);
    procedure SocketReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    
    function GetThreadPoolThreadCount: Integer;
    function GetThreadPoolActiveThreadCount: Integer;
  published
    // Socket properties (delegated to underlying socket)
    property Active: Boolean read GetActive write SetActive default False;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default DefNoDelay;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default DefKeepAlive;
    property Family: TAddressType read GetFamily write SetFamily default DefFamily;
    property ReadBufferLen: Integer read GetReadBufferLen write SetReadBufferLen default DefReadBufferLen;
    property UseReaderThread: Boolean read GetUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    
    // Thread pool properties  
    property DataProcessorThreadPriority: TncThreadPriority read GetDataProcessorThreadPriority write SetDataProcessorThreadPriority default DefDataProcessorThreadPriority;
    property DataProcessorThreads: Integer read GetDataProcessorThreads write SetDataProcessorThreads default DefDataProcessorThreads;
    property DataProcessorThreadsPerCPU: Integer read GetDataProcessorThreadsPerCPU write SetDataProcessorThreadsPerCPU default DefDataProcessorThreadsPerCPU;
    property DataProcessorThreadsGrowUpto: Integer read GetDataProcessorThreadsGrowUpto write SetDataProcessorThreadsGrowUpto default DefDataProcessorThreadsGrowUpto;
    property EventsUseMainThread: Boolean read GetEventsUseMainThread write SetEventsUseMainThread default DefServerEventsUseMainThread;
    
    // Events
    property OnConnected: TncOnServerConnectDisconnect read FOnConnected write FOnConnected;
    property OnDisconnected: TncOnServerConnectDisconnect read FOnDisconnected write FOnDisconnected;
    property OnReadData: TncOnServerReadData read FOnReadData write FOnReadData;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TDataProcessingThread
  // Worker thread that processes raw data from the thread pool
  // Copies the THandleCommandThread pattern for consistency
  
  TDataProcessingThread = class(TncReadyThread)
  public
    OnReadData: TncOnServerReadData;
    Server: TncSocketBase;
    Line: TncLine;
    Buffer: TBytes;
    BufferCount: Integer;
    
    procedure CallOnReadDataEvent;
    procedure ProcessEvent; override;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncServer
  // Server component providing raw socket functionality with thread pool processing
  
  TncServer = class(TncSocketBase)
  private
    function GetLines: TThreadLineList;
  protected
    function GetReaderThreadPriority: TncThreadPriority; // Override to access server-specific property
    procedure SetReaderThreadPriority(const Value: TncThreadPriority); // Override to access server-specific property
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    
    procedure Send(aLine: TncLine; const aBuf; aBufSize: Integer); overload; inline;
    procedure Send(aLine: TncLine; const aBytes: TBytes); overload; inline;
    procedure Send(aLine: TncLine; const aStr: string); overload; inline;
    procedure ShutDownLine(aLine: TncLine);
    property Lines: TThreadLineList read GetLines;
  published
    // Inherited properties from TncSocketBase
    property Active;
    property Port;
    property ReaderThreadPriority;
    property NoDelay;
    property KeepAlive;
    property Family;
    property ReadBufferLen;
    property UseReaderThread;
    property DataProcessorThreadPriority;
    property DataProcessorThreads;
    property DataProcessorThreadsPerCPU;
    property DataProcessorThreadsGrowUpto;
    property EventsUseMainThread;
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncClient
  // Client component providing raw socket functionality with thread pool processing
  
  TncClient = class(TncSocketBase)
  private
    FOnReconnected: TncOnServerReconnected;
    function GetHost: string;
    procedure SetHost(const Value: string);
    function GetReconnect: Boolean;
    procedure SetReconnect(const Value: Boolean);
    function GetReconnectInterval: Cardinal;
    procedure SetReconnectInterval(const Value: Cardinal);
    function GetLine: TncLine;
  protected
    function GetReaderThreadPriority: TncThreadPriority; // Override to access client-specific property
    procedure SetReaderThreadPriority(const Value: TncThreadPriority); // Override to access client-specific property
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    
    procedure Send(const aBuf; aBufSize: Integer); overload; inline;
    procedure Send(const aBytes: TBytes); overload; inline;
    procedure Send(const aStr: string); overload; inline;
    function Receive(aTimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(var aBytes: TBytes): Integer; inline;
    
    property Line: TncLine read GetLine;
  published
    // Inherited properties from TncSocketBase
    property Active;
    property Port;
    property ReaderThreadPriority;
    property NoDelay;
    property KeepAlive;
    property Family;
    property ReadBufferLen;
    property UseReaderThread;
    property DataProcessorThreadPriority;
    property DataProcessorThreads;
    property DataProcessorThreadsPerCPU;
    property DataProcessorThreadsGrowUpto;
    property EventsUseMainThread;
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
    
    // Client-specific properties
    property Host: string read GetHost write SetHost;
    property Reconnect: Boolean read GetReconnect write SetReconnect default True;
    property ReconnectInterval: Cardinal read GetReconnectInterval write SetReconnectInterval default DefCntReconnectInterval;
    property OnReconnected: TncOnServerReconnected read FOnReconnected write FOnReconnected;
  end;

implementation

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TDataProcessingThread }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

procedure TDataProcessingThread.CallOnReadDataEvent;
begin
  if Assigned(OnReadData) then
    try
      OnReadData(Server, Line, Buffer, BufferCount);
    except
      // Swallow exceptions to prevent thread termination
    end;
end;

procedure TDataProcessingThread.ProcessEvent;
begin
  if Server.EventsUseMainThread then
    Synchronize(CallOnReadDataEvent)
  else
    CallOnReadDataEvent;
end;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncSocketBase }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncSocketBase.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  
  PropertyLock := TCriticalSection.Create;
  
  Socket := nil;
  WasSetActive := False;
  WithinConnectionHandler := False;
  
  FDataProcessorThreadPriority := DefDataProcessorThreadPriority;
  FDataProcessorThreads := DefDataProcessorThreads;
  FDataProcessorThreadsPerCPU := DefDataProcessorThreadsPerCPU;
  FDataProcessorThreadsGrowUpto := DefDataProcessorThreadsGrowUpto;
  FEventsUseMainThread := DefServerEventsUseMainThread;
  
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnReadData := nil;
  
  DataProcessorThreadPool := TncThreadPool.Create(TDataProcessingThread);
end;

destructor TncSocketBase.Destroy;
begin
  DataProcessorThreadPool.Free;
  PropertyLock.Free;
  inherited Destroy;
end;

function TncSocketBase.GetThreadPoolThreadCount: Integer;
begin
  Result := DataProcessorThreadPool.GetThreadCount;
end;

function TncSocketBase.GetThreadPoolActiveThreadCount: Integer;
begin
  Result := DataProcessorThreadPool.GetActiveThreadCount;
end;

procedure TncSocketBase.Loaded;
begin
  inherited Loaded;
  
  DataProcessorThreadPool.SetThreadPriority(FDataProcessorThreadPriority);
  DataProcessorThreadPool.SetExecThreads(
    Max(1, Max(FDataProcessorThreads, GetNumberOfProcessors * FDataProcessorThreadsPerCPU)),
    FDataProcessorThreadPriority);
  
  if WasSetActive then
    Socket.Active := True;
end;

procedure TncSocketBase.CallConnectedEvents;
begin
  WithinConnectionHandler := True;
  try
    if Assigned(OnConnected) then
      try
        OnConnected(Self, LastConnectedLine);
      except
      end;
  finally
    WithinConnectionHandler := False;
  end;
end;

procedure TncSocketBase.SocketConnected(Sender: TObject; aLine: TncLine);
begin
  LastConnectedLine := aLine;
  if EventsUseMainThread then
    Socket.LineProcessor.Synchronize(Socket.LineProcessor, CallConnectedEvents)
  else
    CallConnectedEvents;
end;

procedure TncSocketBase.CallDisconnectedEvents;
begin
  WithinConnectionHandler := True;
  try
    if Assigned(OnDisconnected) then
      try
        OnDisconnected(Self, LastDisconnectedLine);
      except
      end;
  finally
    WithinConnectionHandler := False;
  end;
end;

procedure TncSocketBase.SocketDisconnected(Sender: TObject; aLine: TncLine);
begin
  LastDisconnectedLine := aLine;
  if EventsUseMainThread then
    Socket.LineProcessor.Synchronize(Socket.LineProcessor, CallDisconnectedEvents)
  else
    CallDisconnectedEvents;
end;

procedure TncSocketBase.CallReconnectedEvents;
begin
  WithinConnectionHandler := True;
  try
    if Assigned(TncClient(Self).OnReconnected) then
      try
        TncClient(Self).OnReconnected(Self, LastReconnectedLine);
      except
      end;
  finally
    WithinConnectionHandler := False;
  end;
end;

procedure TncSocketBase.SocketReconnected(Sender: TObject; aLine: TncLine);
begin
  LastReconnectedLine := aLine;
  if EventsUseMainThread then
    Socket.LineProcessor.Synchronize(Socket.LineProcessor, CallReconnectedEvents)
  else
    CallReconnectedEvents;
end;

// This is the key method - it queues raw data processing to the thread pool
procedure TncSocketBase.SocketReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
var
  DataProcessingThread: TDataProcessingThread;
begin
  // Queue the data processing to the thread pool
  DataProcessorThreadPool.Serialiser.Acquire;
  try
    DataProcessingThread := TDataProcessingThread(DataProcessorThreadPool.RequestReadyThread);
    DataProcessingThread.OnReadData := OnReadData;
    DataProcessingThread.Server := Self;
    DataProcessingThread.Line := aLine;
    DataProcessingThread.Buffer := Copy(aBuf, 0, aBufCount); // Copy the buffer to avoid race conditions
    DataProcessingThread.BufferCount := aBufCount;
    DataProcessorThreadPool.RunRequestedThread(DataProcessingThread);
  finally
    DataProcessorThreadPool.Serialiser.Release;
  end;
end;

// Socket property delegation methods
function TncSocketBase.GetActive: Boolean;
begin
  Result := Socket.Active;
end;

procedure TncSocketBase.SetActive(const Value: Boolean);
begin
  if csLoading in ComponentState then
    WasSetActive := Value
  else
    Socket.Active := Value;
end;

function TncSocketBase.GetFamily: TAddressType;
begin
  Result := Socket.Family;
end;

procedure TncSocketBase.SetFamily(const Value: TAddressType);
begin
  Socket.Family := Value;
end;

function TncSocketBase.GetKeepAlive: Boolean;
begin
  Result := Socket.KeepAlive;
end;

procedure TncSocketBase.SetKeepAlive(const Value: Boolean);
begin
  Socket.KeepAlive := Value;
end;

function TncSocketBase.GetNoDelay: Boolean;
begin
  Result := Socket.NoDelay;
end;

procedure TncSocketBase.SetNoDelay(const Value: Boolean);
begin
  Socket.NoDelay := Value;
end;

function TncSocketBase.GetPort: Integer;
begin
  Result := Socket.Port;
end;

procedure TncSocketBase.SetPort(const Value: Integer);
begin
  Socket.Port := Value;
end;

function TncSocketBase.GetReaderThreadPriority: TncThreadPriority;
begin
  Result := Socket.ReaderThreadPriority;
end;

procedure TncSocketBase.SetReaderThreadPriority(const Value: TncThreadPriority);
begin
  Socket.ReaderThreadPriority := Value;
end;

function TncSocketBase.GetReadBufferLen: Integer;
begin
  Result := Socket.ReadBufferLen;
end;

procedure TncSocketBase.SetReadBufferLen(const Value: Integer);
begin
  Socket.ReadBufferLen := Value;
end;

function TncSocketBase.GetUseReaderThread: Boolean;
begin
  Result := Socket.UseReaderThread;
end;

procedure TncSocketBase.SetUseReaderThread(const Value: Boolean);
begin
  Socket.UseReaderThread := Value;
end;

// Thread pool property methods
function TncSocketBase.GetDataProcessorThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := FDataProcessorThreadPriority;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSocketBase.SetDataProcessorThreadPriority(const Value: TncThreadPriority);
begin
  PropertyLock.Acquire;
  try
    FDataProcessorThreadPriority := Value;
    if not (csLoading in ComponentState) then
      DataProcessorThreadPool.SetThreadPriority(Value);
  finally
    PropertyLock.Release;
  end;
end;

function TncSocketBase.GetDataProcessorThreads: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FDataProcessorThreads;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSocketBase.SetDataProcessorThreads(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FDataProcessorThreads := Value;
    if Value <> 0 then
      FDataProcessorThreadsPerCPU := 0;
    
    if not (csLoading in ComponentState) then
      DataProcessorThreadPool.SetExecThreads(
        Max(1, Max(FDataProcessorThreads, GetNumberOfProcessors * FDataProcessorThreadsPerCPU)),
        FDataProcessorThreadPriority);
  finally
    PropertyLock.Release;
  end;
end;

function TncSocketBase.GetDataProcessorThreadsPerCPU: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FDataProcessorThreadsPerCPU;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSocketBase.SetDataProcessorThreadsPerCPU(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FDataProcessorThreadsPerCPU := Value;
    if Value <> 0 then
      FDataProcessorThreads := 0;
    
    if not (csLoading in ComponentState) then
      DataProcessorThreadPool.SetExecThreads(
        Max(1, Max(FDataProcessorThreads, GetNumberOfProcessors * FDataProcessorThreadsPerCPU)),
        FDataProcessorThreadPriority);
  finally
    PropertyLock.Release;
  end;
end;

function TncSocketBase.GetDataProcessorThreadsGrowUpto: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FDataProcessorThreadsGrowUpto;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSocketBase.SetDataProcessorThreadsGrowUpto(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FDataProcessorThreadsGrowUpto := Value;
    if not (csLoading in ComponentState) then
      DataProcessorThreadPool.GrowUpto := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncSocketBase.GetEventsUseMainThread: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FEventsUseMainThread;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncSocketBase.SetEventsUseMainThread(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FEventsUseMainThread := Value;
  finally
    PropertyLock.Release;
  end;
end;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncServer }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  
  // Create the underlying TCP server socket
  Socket := TncTCPServer.Create(nil);
  Socket.Family := afIPv4;
  Socket.Port := DefPort;
  Socket.NoDelay := DefNoDelay;
  Socket.EventsUseMainThread := False;
  Socket.OnConnected := SocketConnected;
  Socket.OnDisconnected := SocketDisconnected;
  Socket.OnReadData := SocketReadData;
end;

destructor TncServer.Destroy;
begin
  Socket.Free;
  inherited Destroy;
end;

function TncServer.GetLines: TThreadLineList;
begin
  Result := TncTCPServer(Socket).Lines;
end;

procedure TncServer.Send(aLine: TncLine; const aBuf; aBufSize: Integer);
begin
  TncTCPServer(Socket).Send(aLine, aBuf, aBufSize);
end;

procedure TncServer.Send(aLine: TncLine; const aBytes: TBytes);
begin
  TncTCPServer(Socket).Send(aLine, aBytes);
end;

procedure TncServer.Send(aLine: TncLine; const aStr: string);
begin
  TncTCPServer(Socket).Send(aLine, aStr);
end;

procedure TncServer.ShutDownLine(aLine: TncLine);
begin
  TncTCPServer(Socket).ShutDownLine(aLine);
end;

// Override to access server-specific property
function TncServer.GetReaderThreadPriority: TncThreadPriority;
begin
  Result := TncTCPServer(Socket).ReaderThreadPriority;
end;

procedure TncServer.SetReaderThreadPriority(const Value: TncThreadPriority);
begin
  TncTCPServer(Socket).ReaderThreadPriority := Value;
end;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncClient }
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  
  FOnReconnected := nil;
  
  // Create the underlying TCP client socket
  Socket := TncTCPClient.Create(nil);
  Socket.Family := afIPv4;
  Socket.Port := DefPort;
  Socket.NoDelay := DefNoDelay;
  Socket.EventsUseMainThread := False;
  Socket.OnConnected := SocketConnected;
  Socket.OnDisconnected := SocketDisconnected;
  Socket.OnReadData := SocketReadData;
  TncTCPClient(Socket).OnReconnected := SocketReconnected;
end;

destructor TncClient.Destroy;
begin
  Socket.Free;
  inherited Destroy;
end;

function TncClient.GetLine: TncLine;
begin
  Result := TncTCPClient(Socket).Line;
end;

procedure TncClient.Send(const aBuf; aBufSize: Integer);
begin
  TncTCPClient(Socket).Send(aBuf, aBufSize);
end;

procedure TncClient.Send(const aBytes: TBytes);
begin
  TncTCPClient(Socket).Send(aBytes);
end;

procedure TncClient.Send(const aStr: string);
begin
  TncTCPClient(Socket).Send(aStr);
end;

function TncClient.Receive(aTimeout: Cardinal = 2000): TBytes;
begin
  Result := TncTCPClient(Socket).Receive(aTimeout);
end;

function TncClient.ReceiveRaw(var aBytes: TBytes): Integer;
begin
  Result := TncTCPClient(Socket).ReceiveRaw(aBytes);
end;

function TncClient.GetHost: string;
begin
  Result := TncTCPClient(Socket).Host;
end;

procedure TncClient.SetHost(const Value: string);
begin
  TncTCPClient(Socket).Host := Value;
end;

function TncClient.GetReconnect: Boolean;
begin
  Result := TncTCPClient(Socket).Reconnect;
end;

procedure TncClient.SetReconnect(const Value: Boolean);
begin
  TncTCPClient(Socket).Reconnect := Value;
end;

function TncClient.GetReconnectInterval: Cardinal;
begin
  Result := TncTCPClient(Socket).ReconnectInterval;
end;

procedure TncClient.SetReconnectInterval(const Value: Cardinal);
begin
  TncTCPClient(Socket).ReconnectInterval := Value;
end;

// Override to access client-specific property
function TncClient.GetReaderThreadPriority: TncThreadPriority;
begin
  Result := TncTCPClient(Socket).ReaderThreadPriority;
end;

procedure TncClient.SetReaderThreadPriority(const Value: TncThreadPriority);
begin
  TncTCPClient(Socket).ReaderThreadPriority := Value;
end;

end. 