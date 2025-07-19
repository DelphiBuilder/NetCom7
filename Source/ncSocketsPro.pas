unit ncSocketsPro;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 ncSocketsPro - Enhanced TCP Components with Dual Protocol Support
//
// This unit extends ncSockets with dual protocol capabilities, allowing both
// raw data (text/binary) and structured command protocols to coexist on the
// same connection.
//
// Key Features:
// - Automatic protocol detection via magic header ($ACF0FF00)
// - OnReadData: Handles raw data and custom protocols (like ncSockets)
// - OnCommand: Handles structured binary commands with guaranteed delivery
// - Full backward compatibility with ncSockets
// - Advanced TCP fragmentation handling with state machine
// - TLS support, IPv6, and all ncSockets features preserved
// - CRITICAL FIX: Per-connection TLS context storage for multiple concurrent TLS connections
//
// Usage:
// - Drop-in replacement for ncSockets (TncTCPClient -> TncTCPProClient)
// - Custom protocols work exactly like ncSockets via OnReadData
// - Enhanced features available via SendCommand/OnCommand for guaranteed delivery
//
// 15/07/2025 - by J.Pauwels
// - CRITICAL FIX: Implemented per-connection TLS context storage to support multiple concurrent TLS connections
// - Fixed TLS multiple client connection issue using TncTlsConnectionContext class
//
// 15/07/2025 - by J.Pauwels
// - Added OnCommand event for guaranteed delivery of commands
// - Added SendCommand method for sending commands
// - Added TncCommand type for command handling
// - Added TncCommandPacking unit for command packing/unpacking
//
// 15/07/2025 - by J.Pauwels
// - Initial creation
//
// Written by J.Pauwels
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
  System.SysUtils,
  System.Classes,
  System.Diagnostics,
  System.Math,
  System.TimeSpan,
  System.SyncObjs,
  Generics.Collections,
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  Winapi.Winsock2,
  ncSChannel,
  {$ELSE}
  Posix.SysSocket,
  Posix.Unistd,
  {$ENDIF}
  ncSocketList,
  ncLines,
  ncThreads,
  ncSources, // For binary protocol support
  ncCommandPacking; // For TncCommand type

type
  // TLS Provider enumeration (declared early for use in constants)
  TncTlsProvider = (
    tpSChannel,     // Windows SChannel (Windows only, no external dependencies)
    tpOpenSSL       // OpenSSL (cross-platform, requires OpenSSL DLLs)
  );

  // Forward declarations for SChannel types
  PSChannelClient = ^TSChannelClient;
  PSChannelServer = ^TSChannelServer;

  // Per-connection TLS context storage
  TncTlsConnectionContext = class
  private
    FIsServer: Boolean;
    FClientContext: TSChannelClient;
    FServerContext: TSChannelServer;
  public
    constructor Create(aIsServer: Boolean);
    destructor Destroy; override;
    function GetClientContext: PSChannelClient;
    function GetServerContext: PSChannelServer;
    property IsServer: Boolean read FIsServer;
  end;

  // Protocol magic header type (same as ncSources)
  TMagicHeaderType = UInt32;
  PMagicHeaderType = ^TMagicHeaderType;

const
  DefPort = 16233;
  DefHost = '';
  DefReadBufferLen = 1024 * 1024; // 1 MB
  DefReaderThreadPriority = ntpNormal;
  DefCntReconnectInterval = 1000;
  DefEventsUseMainThread = False;
  DefUseReaderThread = True;
  DefNoDelay = False;
  DefKeepAlive = True;
  DefFamily = afIPv4;
  DefUseTLS = False;
  DefTlsProvider = tpSChannel;
  DefIgnoreCertificateErrors = False;
  
  // Thread Pool Constants (from ncSources)
  DefCommandProcessorThreadPriority = ntpNormal;
  DefCommandProcessorThreads = 0;
  DefCommandProcessorThreadsPerCPU = 4;
  DefCommandProcessorThreadsGrowUpto = 32;
  
  // Protocol magic header (same as ncSources)
  MagicHeader: TMagicHeaderType = $ACF0FF00;

resourcestring
  ECannotSetPortWhileConnectionIsActiveStr = 'Cannot set Port property whilst the connection is active';
  ECannotSetHostWhileConnectionIsActiveStr = 'Cannot set Host property whilst the connection is active';
  ECannotSendWhileSocketInactiveStr = 'Cannot send data while socket is inactive';
  ECannotSetUseReaderThreadWhileActiveStr = 'Cannot set UseReaderThread property whilst the connection is active';
  ECannotReceiveIfUseReaderThreadStr =
    'Cannot receive data if UseReaderThread is set. Use OnReadData event handler to get the data or set UseReaderThread property to false';
  ECannotSetFamilyWhileConnectionIsActiveStr = 'Cannot set Family property whilst the connection is active';
  ETlsProviderNotSupportedStr = 'TLS provider not supported on this platform';
  EOpenSSLNotAvailableStr = 'OpenSSL libraries not available';

type
  EPropertySetError = class(Exception);
  ENonActiveSocket = class(Exception);
  ECannotReceiveIfUseReaderThread = class(Exception);
  ETlsProviderNotSupported = class(Exception);
  EOpenSSLNotAvailable = class(Exception);

  // We bring in TncLine so that a form that uses our components does
  // not have to reference ncLines unit to get the type
  TncLine = ncLines.TncLine;

  // We make a descendant of TncLine so that we can access the API functions.
  // These API functions are not made puclic in TncLine so that the user cannot
  // mangle up the line
  TncLineInternal = class(TncLine);

  // Forward declarations
  TncCustomTCPProServer = class;

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
    procedure Add(const Item: TncLine); inline;
    procedure Clear; inline;
    procedure Remove(Item: TncLine); inline;
    function LockListNoCopy: TSocketList;
    procedure UnlockListNoCopy;
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
  TncOnCommandReceived = procedure(Sender: TObject; aLine: TncLine; 
    aCmd: Integer; const aData: TBytes) of object; // Binary protocol event

  // Command Processing Thread for Thread Pool (from ncSources)
  THandleCommandWorkType = (htwtOnCommand);
  
  THandleCommandThread = class(TncReadyThread)
  private
    FWorkType: THandleCommandWorkType;
    FSource: TComponent;
    FLine: TncLine;
    FCmd: Integer;
    FData: TBytes;
    FOnCommand: TncOnCommandReceived;
    FEventsUseMainThread: Boolean;
    
    procedure CallOnCommandEvent;
  protected
    procedure ProcessEvent; override;
  public
    property WorkType: THandleCommandWorkType read FWorkType write FWorkType;
    property Source: TComponent read FSource write FSource;
    property Line: TncLine read FLine write FLine;
    property Cmd: Integer read FCmd write FCmd;
    property Data: TBytes read FData write FData;
    property OnCommand: TncOnCommandReceived read FOnCommand write FOnCommand;
    property EventsUseMainThread: Boolean read FEventsUseMainThread write FEventsUseMainThread;
  end;

  TncTCPProBase = class(TComponent)
  private
    FInitActive: Boolean;
    FFamily: TAddressType;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FNoDelay: Boolean;
    FKeepAlive: Boolean;
    FReadBufferLen: Integer;
    FOnConnected: TncOnConnectDisconnect;
    FOnDisconnected: TncOnConnectDisconnect;
    FOnReadData: TncOnReadData;
    FLine: TncLine;
    
    // Thread Pool Properties (from ncSources)
    FCommandProcessorThreadPriority: TncThreadPriority;
    FCommandProcessorThreads: Integer;
    FCommandProcessorThreadsPerCPU: Integer;
    FCommandProcessorThreadsGrowUpto: Integer;
    
    // TLS Properties
    FUseTLS: Boolean;
    FTlsProvider: TncTlsProvider;
    FCertificateFile: string;
    FPrivateKeyFile: string;
    FPrivateKeyPassword: string;
    FCACertificatesFile: string;
    FIgnoreCertificateErrors: Boolean;
    FIsServer: Boolean;
    
    function GetReadBufferLen: Integer;
    procedure SetReadBufferLen(const Value: Integer);
    function GetActive: Boolean; virtual; abstract;
    procedure SetActive(const Value: Boolean);
    function GetFamily: TAddressType;
    procedure SetFamily(const Value: TAddressType);

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
    
    // TLS Property Methods
    function GetUseTLS: Boolean;
    procedure SetUseTLS(const Value: Boolean);
    function GetTlsProvider: TncTlsProvider;
    procedure SetTlsProvider(const Value: TncTlsProvider);
    function GetCertificateFile: string;
    procedure SetCertificateFile(const Value: string);
    function GetPrivateKeyFile: string;
    procedure SetPrivateKeyFile(const Value: string);
    function GetPrivateKeyPassword: string;
    procedure SetPrivateKeyPassword(const Value: string);
    function GetCACertificatesFile: string;
    procedure SetCACertificatesFile(const Value: string);
    function GetIgnoreCertificateErrors: Boolean;
    procedure SetIgnoreCertificateErrors(const Value: Boolean);
    
    // Thread Pool Property Methods (from ncSources)
    function GetCommandProcessorThreadPriority: TncThreadPriority;
    procedure SetCommandProcessorThreadPriority(const Value: TncThreadPriority);
    function GetCommandProcessorThreads: Integer;
    procedure SetCommandProcessorThreads(const Value: Integer);
    function GetCommandProcessorThreadsPerCPU: Integer;
    procedure SetCommandProcessorThreadsPerCPU(const Value: Integer);
    function GetCommandProcessorThreadsGrowUpto: Integer;
    procedure SetCommandProcessorThreadsGrowUpto(const Value: Integer);
    
  private
    FUseReaderThread: Boolean;
    procedure DoActivate(aActivate: Boolean); virtual; abstract;
    procedure SetUseReaderThread(const Value: Boolean);
  protected
    PropertyLock, ShutDownLock: TCriticalSection;
    ReadBuf: TBytes;
    
    // Thread Pool Infrastructure (from ncSources)
    HandleCommandThreadPool: TncThreadPool;
    
    procedure Loaded; override;
    function CreateLineObject: TncLine; virtual;
    function GetHost: string; virtual; // Virtual method for TLS
    procedure InitializeTLS(aLine: TncLine); virtual;
    procedure FinalizeTLS(aLine: TncLine); virtual;
    function SendTLS(aLine: TncLine; const aBuf; aBufSize: Integer): Integer; virtual;
    function ReceiveTLS(aLine: TncLine; var aBuf; aBufSize: Integer): Integer; virtual;
    procedure HandleTLSHandshake(aLine: TncLine); virtual;
    procedure HandleTLSHandshakeComplete(aLine: TncLine); virtual;
    property Line: TncLine read FLine;
  public
    LineProcessor: TncReadyThread;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function Kind: TSocketType; virtual;

    property Active: Boolean read GetActive write SetActive default False;
    property Family: TAddressType read GetFamily write SetFamily default afIPv4;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property EventsUseMainThread: Boolean read GetEventsUseMainThread write SetEventsUseMainThread default DefEventsUseMainThread;
    property UseReaderThread: Boolean read FUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    property NoDelay: Boolean read GetNoDelay write SetNoDelay default DefNoDelay;
    property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default DefKeepAlive;
    property OnConnected: TncOnConnectDisconnect read FOnConnected write FOnConnected;
    property OnDisconnected: TncOnConnectDisconnect read FOnDisconnected write FOnDisconnected;
    property OnReadData: TncOnReadData read FOnReadData write FOnReadData;
    property ReadBufferLen: Integer read GetReadBufferLen write SetReadBufferLen default DefReadBufferLen;
    
    // Thread Pool Properties (from ncSources)
    property CommandProcessorThreadPriority: TncThreadPriority read GetCommandProcessorThreadPriority write SetCommandProcessorThreadPriority default DefCommandProcessorThreadPriority;
    property CommandProcessorThreads: Integer read GetCommandProcessorThreads write SetCommandProcessorThreads default DefCommandProcessorThreads;
    property CommandProcessorThreadsPerCPU: Integer read GetCommandProcessorThreadsPerCPU write SetCommandProcessorThreadsPerCPU default DefCommandProcessorThreadsPerCPU;
    property CommandProcessorThreadsGrowUpto: Integer read GetCommandProcessorThreadsGrowUpto write SetCommandProcessorThreadsGrowUpto default DefCommandProcessorThreadsGrowUpto;
    
    // TLS Properties
    property UseTLS: Boolean read GetUseTLS write SetUseTLS default DefUseTLS;
    property TlsProvider: TncTlsProvider read GetTlsProvider write SetTlsProvider default DefTlsProvider;
    property CertificateFile: string read GetCertificateFile write SetCertificateFile;
    property PrivateKeyFile: string read GetPrivateKeyFile write SetPrivateKeyFile;
    property PrivateKeyPassword: string read GetPrivateKeyPassword write SetPrivateKeyPassword;
    property CACertificatesFile: string read GetCACertificatesFile write SetCACertificatesFile;
    property IgnoreCertificateErrors: Boolean read GetIgnoreCertificateErrors write SetIgnoreCertificateErrors default DefIgnoreCertificateErrors;
  published
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Client Socket
  TncClientProcessor = class;

  // Connection state for efficient message handling (ncSources-style)
  TConnectionState = record
    MessageBuffer: TBytes;          // Accumulated message data
    BytesToEndOfMessage: UInt64;    // How many bytes still needed
    MessageType: (mtUnknown, mtBinary, mtText); // Protocol type
    ExpectedMessageLength: UInt64;  // Total expected message length
    HeaderComplete: Boolean;        // Have we read the complete header?
    procedure Reset;
  end;

  TncCustomTCPProClient = class(TncTCPProBase)
  private
    FHost: string;
    FReconnect: Boolean;
    FReconnectInterval: Cardinal;
    FOnReconnected: TncOnReconnected;
    FOnCommand: TncOnCommandReceived; // Binary protocol event
    OriginalOnReadData: TncOnReadData; // Store original handler for protocol detection
    FConnectionState: TConnectionState; // State-based message handling
    function GetActive: Boolean; override;
    // Override OnReadData property to preserve protocol detection
    procedure SetOnReadData(const Value: TncOnReadData);
    procedure SetHost(const Value: string);
    function GetHost: string;
    function GetReconnect: Boolean;
    procedure SetReconnect(const Value: Boolean);
    function GetReconnectInterval: Cardinal;
    procedure SetReconnectInterval(const Value: Cardinal);
  protected
    WasConnected: Boolean;
    LastConnectAttempt: Int64;
    procedure DoActivate(aActivate: Boolean); override;
    procedure DataSocketConnected(aLine: TncLine);
    procedure DataSocketDisconnected(aLine: TncLine);
  public
    ReadSocketHandles: TSocketHandleArray;
    Line: TncLine;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Send(const aBuf; aBufSize: Integer); overload; inline;
    procedure Send(const aBytes: TBytes); overload; inline;
    procedure Send(const aStr: string); overload; inline;
    procedure SendCommand(aCmd: Integer; const aData: TBytes = nil); // Binary protocol method
    function Receive(aTimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(var aBytes: TBytes): Integer; inline;
    procedure InternalReadDataHandler(Sender: TObject; aLine: TncLine; 
      const aBuf: TBytes; aBufCount: Integer); // Protocol detection handler
    property Host: string read GetHost write SetHost;
    property Reconnect: Boolean read GetReconnect write SetReconnect default True;
    property ReconnectInterval: Cardinal read GetReconnectInterval write SetReconnectInterval default DefCntReconnectInterval;
    property OnReconnected: TncOnReconnected read FOnReconnected write FOnReconnected;
    property OnCommand: TncOnCommandReceived read FOnCommand write FOnCommand;
    // Override OnReadData to preserve protocol detection
    property OnReadData: TncOnReadData read FOnReadData write SetOnReadData;
  end;

  TncTCPProClient = class(TncCustomTCPProClient)
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
    property ReadBufferLen;
    property Reconnect;
    property ReconnectInterval;
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
    property OnReconnected;
    property OnCommand;
    
    // Thread Pool Properties (from ncSources)
    property CommandProcessorThreadPriority;
    property CommandProcessorThreads;
    property CommandProcessorThreadsPerCPU;
    property CommandProcessorThreadsGrowUpto;
    
    // TLS Properties
    property UseTLS;
    property TlsProvider;
    property CertificateFile;
    property PrivateKeyFile;
    property PrivateKeyPassword;
    property CACertificatesFile;
    property IgnoreCertificateErrors;
  end;

  TncClientProcessor = class(TncReadyThread)
  private
    FClientSocket: TncCustomTCPProClient;
  public
    ReadySocketsChanged: Boolean;
    constructor Create(aClientSocket: TncCustomTCPProClient);
    procedure SocketWasReconnected;
    procedure SocketProcess; inline;
    procedure ProcessEvent; override;
  end;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Server Socket
  TncServerProcessor = class;

  TncCustomTCPProServer = class(TncTCPProBase)
  private
    FOnCommand: TncOnCommandReceived; // Binary protocol event
    OriginalOnReadData: TncOnReadData; // Store original handler for protocol detection
    FConnectionStates: TDictionary<TncLine, TConnectionState>; // Per-connection state tracking
    function GetActive: Boolean; override;
    // Override OnReadData property to preserve protocol detection
    procedure SetOnReadData(const Value: TncOnReadData);
  protected
    Listener: TncLine;
    LinesToShutDown: array of TncLine;
    procedure DataSocketConnected(aLine: TncLine);
    procedure DataSocketDisconnected(aLine: TncLine);
    procedure DoActivate(aActivate: Boolean); override;
  public
    ReadSocketHandles: TSocketHandleArray;
    Lines: TThreadLineList;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure ShutDownLine(aLine: TncLine);
    procedure Send(aLine: TncLine; const aBuf; aBufSize: Integer); overload; inline;
    procedure Send(aLine: TncLine; const aBytes: TBytes); overload; inline;
    procedure Send(aLine: TncLine; const aStr: string); overload; inline;
    function Receive(aLine: TncLine; aTimeout: Cardinal = 2000): TBytes; inline;
    function ReceiveRaw(aLine: TncLine; var aBytes: TBytes): Integer; inline;
    procedure SendCommand(aLine: TncLine; aCmd: Integer; const aData: TBytes = nil); // Binary protocol method
    procedure InternalReadDataHandler(Sender: TObject; aLine: TncLine; 
      const aBuf: TBytes; aBufCount: Integer); // Protocol detection handler
    property OnCommand: TncOnCommandReceived read FOnCommand write FOnCommand;
    // Override OnReadData to preserve protocol detection
    property OnReadData: TncOnReadData read FOnReadData write SetOnReadData;
  end;

  TncTCPProServer = class(TncCustomTCPProServer)
  public
  published
    property Active;
    property Family;
    property Port;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property NoDelay;
    property KeepAlive;
    property ReadBufferLen;
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
    property OnCommand;
    
    // Thread Pool Properties (from ncSources)
    property CommandProcessorThreadPriority;
    property CommandProcessorThreads;
    property CommandProcessorThreadsPerCPU;
    property CommandProcessorThreadsGrowUpto;
    
    // TLS Properties
    property UseTLS;
    property TlsProvider;
    property CertificateFile;
    property PrivateKeyFile;
    property PrivateKeyPassword;
    property CACertificatesFile;
    property IgnoreCertificateErrors;
  end;

  TncServerProcessor = class(TncReadyThread)
  private
    FServerSocket: TncCustomTCPProServer;
    procedure CheckLinesToShutDown;
  public
    ReadySockets: TSocketHandleArray;
    ReadySocketsChanged: Boolean;
    constructor Create(aServerSocket: TncCustomTCPProServer);
    procedure SocketProcess; inline;
    procedure ProcessEvent; override;
  end;

implementation

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TConnectionState }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

procedure TConnectionState.Reset;
begin
  SetLength(MessageBuffer, 0);
  BytesToEndOfMessage := 0;
  MessageType := mtUnknown;
  ExpectedMessageLength := 0;
  HeaderComplete := False;
end;

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
  LockListNoCopy;
  try
    FList.Free;
    inherited Destroy;
  finally
    UnlockListNoCopy;
    FLock.Free;
  end;
end;

procedure TThreadLineList.Add(const Item: TncLine);
begin
  LockListNoCopy;
  try
    // FList has Duplicates to dupError, so we know if this is already in the
    // list it will not be accepted
    FList.Add(Item.Handle, Item);
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

procedure TThreadLineList.Remove(Item: TncLine);
begin
  LockListNoCopy;
  try
    FList.Delete(FList.IndexOf(Item.Handle));
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
      FListCopy.Free;
  finally
    FLock.Release;
  end;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncTlsConnectionContext }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncTlsConnectionContext.Create(aIsServer: Boolean);
begin
  inherited Create;
  FIsServer := aIsServer;

  // Initialize TLS contexts using FillChar and then set public fields
  FillChar(FClientContext, SizeOf(FClientContext), 0);
  FClientContext.Initialized := False;

  FillChar(FServerContext, SizeOf(FServerContext), 0);
  FServerContext.Initialized := False;
  FServerContext.HandshakeCompleted := False;
end;

destructor TncTlsConnectionContext.Destroy;
begin
  // In a perfect world, FinalizeTLS was already called
  // and all cleanup is done - destructor should be nearly empty

  {$IFDEF DEBUG}
  // Debug check - verify cleanup already happened
  if FIsServer then
    Assert(not FServerContext.Initialized, 'Server TLS context not cleaned up!')
  else
    Assert(not FClientContext.Initialized, 'Client TLS context not cleaned up!');
  {$ENDIF}

  inherited Destroy;
end;

function TncTlsConnectionContext.GetClientContext: PSChannelClient;
begin
  Result := @FClientContext;
end;

function TncTlsConnectionContext.GetServerContext: PSChannelServer;
begin
  Result := @FServerContext;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncTCPProBase }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncTCPProBase.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  PropertyLock := TCriticalSection.Create;
  ShutDownLock := TCriticalSection.Create;

  FInitActive := False;
  FFamily := DefFamily;
  FPort := DefPort;
  FEventsUseMainThread := DefEventsUseMainThread;
  FUseReaderThread := DefUseReaderThread;
  FNoDelay := DefNoDelay;
  FKeepAlive := DefKeepAlive;
  FReadBufferLen := DefReadBufferLen;
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnReadData := nil;

  // Initialize Thread Pool Properties (from ncSources)
  FCommandProcessorThreadPriority := DefCommandProcessorThreadPriority;
  FCommandProcessorThreads := DefCommandProcessorThreads;
  FCommandProcessorThreadsPerCPU := DefCommandProcessorThreadsPerCPU;
  FCommandProcessorThreadsGrowUpto := DefCommandProcessorThreadsGrowUpto;

  // Initialize TLS properties
  FUseTLS := DefUseTLS;
  FTlsProvider := DefTlsProvider;
  FCertificateFile := '';
  FPrivateKeyFile := '';
  FPrivateKeyPassword := '';
  FCACertificatesFile := '';
  FIgnoreCertificateErrors := DefIgnoreCertificateErrors;
  
  FIsServer := False;

  SetLength(ReadBuf, DefReadBufferLen);

  // Create Thread Pool for Command Processing (from ncSources)
  HandleCommandThreadPool := TncThreadPool.Create(THandleCommandThread);

end;

function TncTCPProBase.Kind: TSocketType;
begin
  Result := stTCP;
end;

destructor TncTCPProBase.Destroy;
begin
  Active := False;
  
  // Clean up Thread Pool (from ncSources)
  HandleCommandThreadPool.Free;
  
  // TLS contexts are now managed per-connection and cleaned up in FinalizeTLS
  // No global TLS context cleanup needed
  
  PropertyLock.Free;
  ShutDownLock.Free;
  inherited Destroy;
end;

procedure TncTCPProBase.Loaded;
begin
  inherited Loaded;

  // Configure Thread Pool (from ncSources)
  HandleCommandThreadPool.SetThreadPriority(FCommandProcessorThreadPriority);
  HandleCommandThreadPool.SetExecThreads(
    Max(1, Max(FCommandProcessorThreads, GetNumberOfProcessors * FCommandProcessorThreadsPerCPU)),
    FCommandProcessorThreadPriority);
  HandleCommandThreadPool.GrowUpto := FCommandProcessorThreadsGrowUpto;

  if FInitActive then
    DoActivate(True);
end;

function TncTCPProBase.CreateLineObject: TncLine;
begin
  Result := TncLineInternal.Create;
  TncLineInternal(Result).SetKind(Kind);
  TncLineInternal(Result).SetFamily(FFamily);
  
  // Set up TLS callbacks if TLS is enabled
  if FUseTLS then
  begin
    TncLineInternal(Result).OnBeforeConnected := HandleTLSHandshake;
    TncLineInternal(Result).OnBeforeDisconnected := FinalizeTLS;
  end;
end;

procedure TncTCPProBase.SetActive(const Value: Boolean);
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

function TncTCPProBase.GetFamily: TAddressType;
begin
  PropertyLock.Acquire;
  try
    Result := FFamily;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetFamily(const Value: TAddressType);
begin
  if not (csLoading in ComponentState) then
  begin
    if Active then
      raise EPropertySetError.Create(ECannotSetFamilyWhileConnectionIsActiveStr);
  end;

  PropertyLock.Acquire;
  try
    // Update base class family
    FFamily := Value;

    // Update the Line's family
    if FLine <> nil then
    begin
      TncLineInternal(FLine).SetFamily(Value);
    end;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetPort: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FPort;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetPort(const Value: Integer);
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

function TncTCPProBase.GetReaderThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := ToNcThreadPriority(LineProcessor.Priority);
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetReaderThreadPriority(const Value: TncThreadPriority);
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

function TncTCPProBase.GetEventsUseMainThread: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FEventsUseMainThread;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetEventsUseMainThread(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FEventsUseMainThread := Value;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetUseReaderThread(const Value: Boolean);
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

function TncTCPProBase.GetNoDelay: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FNoDelay;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetNoDelay(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FNoDelay := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetKeepAlive: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FKeepAlive;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetKeepAlive(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FKeepAlive := Value;
  finally
    PropertyLock.Release;
  end;
end;

// Update
function TncTCPProBase.GetReadBufferLen: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FReadBufferLen;
  finally
    PropertyLock.Release;
  end;
end;

// Update
procedure TncTCPProBase.SetReadBufferLen(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FReadBufferLen := Value;
    SetLength(ReadBuf, FReadBufferLen);
  finally
    PropertyLock.Release;
  end;
end;

// TLS Property Methods
function TncTCPProBase.GetUseTLS: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FUseTLS;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetUseTLS(const Value: Boolean);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create('Cannot set UseTLS property whilst the connection is active');

  PropertyLock.Acquire;
  try
    FUseTLS := Value;
    
    // Add TLS callback assignment when TLS is enabled
    if Value then
    begin
      if FIsServer and (Self is TncCustomTCPProServer) then
      begin
        // Server callback assignment
        var Server := TncCustomTCPProServer(Self);
        if Server.Listener <> nil then
        begin
          TncLineInternal(Server.Listener).OnBeforeConnected := HandleTLSHandshake;
          TncLineInternal(Server.Listener).OnBeforeDisconnected := FinalizeTLS;
        end;
      end
      else if not FIsServer and (Self is TncCustomTCPProClient) then
      begin
        // Client callback assignment
        var Client := TncCustomTCPProClient(Self);
        if Client.Line <> nil then
        begin
          TncLineInternal(Client.Line).OnBeforeConnected := HandleTLSHandshake;
          TncLineInternal(Client.Line).OnBeforeDisconnected := FinalizeTLS;
        end;
      end;
    end;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetTlsProvider: TncTlsProvider;
begin
  PropertyLock.Acquire;
  try
    Result := FTlsProvider;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetTlsProvider(const Value: TncTlsProvider);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create('Cannot set TlsProvider property whilst the connection is active');

  PropertyLock.Acquire;
  try
    // Validate provider availability
    case Value of
      tpSChannel:
        begin
          {$IFNDEF MSWINDOWS}
          raise ETlsProviderNotSupported.Create(ETlsProviderNotSupportedStr);
          {$ENDIF}
        end;
      tpOpenSSL:
        begin
          // Future OpenSSL validation - for now, not supported
          raise EOpenSSLNotAvailable.Create(EOpenSSLNotAvailableStr);
        end;
    end;
    
    FTlsProvider := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetCertificateFile: string;
begin
  PropertyLock.Acquire;
  try
    Result := FCertificateFile;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetCertificateFile(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FCertificateFile := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetPrivateKeyFile: string;
begin
  PropertyLock.Acquire;
  try
    Result := FPrivateKeyFile;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetPrivateKeyFile(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FPrivateKeyFile := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetPrivateKeyPassword: string;
begin
  PropertyLock.Acquire;
  try
    Result := FPrivateKeyPassword;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetPrivateKeyPassword(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FPrivateKeyPassword := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetCACertificatesFile: string;
begin
  PropertyLock.Acquire;
  try
    Result := FCACertificatesFile;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetCACertificatesFile(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FCACertificatesFile := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPProBase.GetIgnoreCertificateErrors: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FIgnoreCertificateErrors;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetIgnoreCertificateErrors(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FIgnoreCertificateErrors := Value;
  finally
    PropertyLock.Release;
  end;
end;



// TLS base implementation
function TncTCPProBase.GetHost: string;
begin
  Result := ''; // Default implementation, override in client
end;

// TLS Functionality Methods
procedure TncTCPProBase.InitializeTLS(aLine: TncLine);
var
  TlsContext: TncTlsConnectionContext;
begin
  if not FUseTLS then
    Exit;
  
  if aLine = nil then
    Exit;
  
  // Get or create per-connection TLS context
  if TncLineInternal(aLine).DataObject = nil then
  begin
    TlsContext := TncTlsConnectionContext.Create(FIsServer);
    TncLineInternal(aLine).DataObject := TlsContext;
  end
  else
  begin
    TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
  end;
  
  // Check if TLS is already initialized for this specific connection
  if FIsServer then
  begin
    if TlsContext.GetServerContext^.Initialized then
      Exit;
  end
  else
  begin
    if TlsContext.GetClientContext^.Initialized then
      Exit;
  end;
  
  // Initialize TLS for this specific connection
  if FIsServer then
  begin
    TlsContext.GetServerContext^.AfterConnection(aLine, AnsiString(FCertificateFile), AnsiString(FPrivateKeyPassword));
  end
  else
  begin
    TlsContext.GetClientContext^.AfterConnection(aLine, AnsiString(GetHost), FIgnoreCertificateErrors);
  end;
end;

procedure TncTCPProBase.HandleTLSHandshake(aLine: TncLine);
begin
  // This method is called automatically before OnConnected fires
  // It performs the TLS handshake synchronously
  if FUseTLS and (aLine <> nil) then
  begin
    InitializeTLS(aLine); // Perform the complete TLS handshake
  end;
end;

procedure TncTCPProBase.HandleTLSHandshakeComplete(aLine: TncLine);
begin
  // Call OnConnected for TLS connections after handshake completes
  if FUseTLS and Assigned(OnConnected) then
  begin
    try
      OnConnected(Self, aLine);
    except
      on E: Exception do
        // OnConnected failed - could log this if needed
    end;
  end;
end;

procedure TncTCPProBase.FinalizeTLS(aLine: TncLine);
var
  TlsContext: TncTlsConnectionContext;
begin
  if FUseTLS and (aLine <> nil) and (TncLineInternal(aLine).DataObject <> nil) then
  begin
    try
      TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
      
      case FTlsProvider of
        tpSChannel:
          begin
            {$IFDEF MSWINDOWS}
            if FIsServer then
            begin
              if TlsContext.GetServerContext^.Initialized then
                TlsContext.GetServerContext^.BeforeDisconnection(aLine);
            end
            else
            begin
              if TlsContext.GetClientContext^.Initialized then
                TlsContext.GetClientContext^.BeforeDisconnection(aLine);
            end;
            {$ENDIF}
          end;
        tpOpenSSL:
          begin
            // Future OpenSSL cleanup
          end;
      end;
      
      // Clean up the TLS context object
      TncLineInternal(aLine).DataObject := nil;
      TlsContext.Free;
    except
      on E: Exception do
        // Log error but don't raise exception during cleanup
    end;
  end;
end;

function TncTCPProBase.SendTLS(aLine: TncLine; const aBuf; aBufSize: Integer): Integer;
var
  TlsContext: TncTlsConnectionContext;
begin
  if FUseTLS and (TncLineInternal(aLine).DataObject <> nil) then
  begin
    TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
    
    case FTlsProvider of
      tpSChannel:
        begin
          {$IFDEF MSWINDOWS}
          if FIsServer then
          begin
            if TlsContext.GetServerContext^.Initialized then
              Result := TlsContext.GetServerContext^.Send(aLine, @aBuf, aBufSize)
            else
              Result := TncLineInternal(aLine).SendBuffer(aBuf, aBufSize);
          end
          else
          begin
            if TlsContext.GetClientContext^.Initialized then
              Result := TlsContext.GetClientContext^.Send(aLine, @aBuf, aBufSize)
            else
              Result := TncLineInternal(aLine).SendBuffer(aBuf, aBufSize);
          end;
          {$ELSE}
          raise ETlsProviderNotSupported.Create(ETlsProviderNotSupportedStr);
          {$ENDIF}
        end;
      tpOpenSSL:
        begin
          // Future OpenSSL send implementation
          raise EOpenSSLNotAvailable.Create(EOpenSSLNotAvailableStr);
        end;
    end;
  end
  else
    Result := TncLineInternal(aLine).SendBuffer(aBuf, aBufSize);
end;

function TncTCPProBase.ReceiveTLS(aLine: TncLine; var aBuf; aBufSize: Integer): Integer;
var
  TlsContext: TncTlsConnectionContext;
  WasHandshakeCompleted: Boolean;
begin
  if FUseTLS and (TncLineInternal(aLine).DataObject <> nil) then
  begin
    TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
    
    case FTlsProvider of
      tpSChannel:
        begin
          {$IFDEF MSWINDOWS}
          if FIsServer then
          begin
            if TlsContext.GetServerContext^.Initialized then
            begin
              WasHandshakeCompleted := TlsContext.GetServerContext^.HandshakeCompleted;
              
              Result := TlsContext.GetServerContext^.Receive(aLine, @aBuf, aBufSize);
              
              // CRITICAL FIX: Detect TLS disconnection when Receive returns 0 after handshake completion
              if (Result = 0) and WasHandshakeCompleted then
              begin
                raise Exception.Create('TLS client disconnected');
              end;
              
              // Check if handshake just completed
              if not WasHandshakeCompleted and TlsContext.GetServerContext^.HandshakeCompleted then
              begin
                // Handshake just completed, call OnConnected
                HandleTLSHandshakeComplete(aLine);
                
                // CRITICAL FIX: Return -1 to prevent OnReadData from being triggered with empty data
                // The handshake completion callback has already been called above
                Result := -1;
              end;
            end
            else
              Result := TncLineInternal(aLine).RecvBuffer(aBuf, aBufSize);
          end
          else
          begin
            if TlsContext.GetClientContext^.Initialized then
            begin
              // For client, handshake is complete when Initialized becomes true
              // But we need to track when it JUST became initialized (not if it was already initialized)
              // Since the client calls AfterConnection during OnBeforeConnected, we know that
              // the first call to Receive after OnBeforeConnected is when handshake is complete
              
              Result := TlsContext.GetClientContext^.Receive(aLine, @aBuf, aBufSize);
              
              // CRITICAL FIX: Detect TLS disconnection when Receive returns 0 after handshake completion
              if (Result = 0) and TlsContext.GetClientContext^.Initialized then
              begin
                raise Exception.Create('TLS server disconnected');
              end;
              
              // Client-side handshake completion detection:
              // The client TLS handshake is handled in OnBeforeConnected event
              // So by the time we get here, handshake is already complete
              // We don't need to do anything special for client handshake completion
            end
            else
              Result := TncLineInternal(aLine).RecvBuffer(aBuf, aBufSize);
          end;
          {$ELSE}
          raise ETlsProviderNotSupported.Create(ETlsProviderNotSupportedStr);
          {$ENDIF}
        end;
      tpOpenSSL:
        begin
          // Future OpenSSL receive implementation
          raise EOpenSSLNotAvailable.Create(EOpenSSLNotAvailableStr);
        end;
    end;
  end
  else
    Result := TncLineInternal(aLine).RecvBuffer(aBuf, aBufSize);
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncCustomTCPProClient }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomTCPProClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FIsServer := False; // Set client flag for TLS context selection
  FHost := DefHost;
  FReconnect := True;
  FReconnectInterval := DefCntReconnectInterval;
  FOnReconnected := nil;
  FOnCommand := nil; // Initialize the new field
  OriginalOnReadData := OnReadData; // Store original handler
  OnReadData := InternalReadDataHandler; // Set up protocol detection handler
  FConnectionState.Reset; // Initialize connection state

  LastConnectAttempt := TStopWatch.GetTimeStamp;
  WasConnected := False;

  // Create Line with correct family
  Line := CreateLineObject;
  if Line.Family <> FFamily then
  begin
    TncLineInternal(Line).SetFamily(FFamily);
  end;

  TncLineInternal(Line).OnConnected := DataSocketConnected;
  TncLineInternal(Line).OnDisconnected := DataSocketDisconnected;
  
  // Set up TLS callbacks if TLS is enabled
  if FUseTLS then
  begin
    TncLineInternal(Line).OnBeforeConnected := HandleTLSHandshake;
    TncLineInternal(Line).OnBeforeDisconnected := FinalizeTLS;
  end;

  LineProcessor := TncClientProcessor.Create(Self);
  try
    if LineProcessor.Priority <> FromNcThreadPriority(DefReaderThreadPriority) then
      LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
  LineProcessor.WaitForReady;
end;


destructor TncCustomTCPProClient.Destroy;
begin
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Line.Free;

  inherited Destroy;
end;

procedure TncCustomTCPProClient.DoActivate(aActivate: Boolean);
begin

  if aActivate = GetActive then
    Exit;

  if aActivate then
  begin
    // Verify family setting before creating handle
    if Line.Family <> FFamily then
    begin
      TncLineInternal(Line).SetFamily(FFamily);
    end;

    TncLineInternal(Line).CreateClientHandle(FHost, FPort);

    // if there were no exceptions, and line is still not active,
    // that means the user has deactivated it in the OnConnect handler
    if not Line.Active then
      WasConnected := False;
  end
  else
  begin
    WasConnected := False;
    TncLineInternal(Line).DestroyHandle;
  end;
end;

procedure TncCustomTCPProClient.DataSocketConnected(aLine: TncLine);
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

    try
      TncLineInternal(Line).SetReceiveSize(1048576); // 1MB
      TncLineInternal(Line).SetWriteSize(1048576); // 1MB
      //TncLineInternal(Line).SetReceiveSize(20 * 1048576);

    except
    end;

  // TLS initialization is now handled by OnBeforeConnected event
  
  if Assigned(OnConnected) then
    try
      OnConnected(Self, aLine);
    except
    end;

  LastConnectAttempt := TStopWatch.GetTimeStamp;
  WasConnected := True;

  if UseReaderThread then
    LineProcessor.Run; // Will just set events, this does not wait
end;

procedure TncCustomTCPProClient.DataSocketDisconnected(aLine: TncLine);
begin
  // TLS cleanup is now handled automatically by OnBeforeDisconnected event

  if Assigned(OnDisconnected) then
    try
      OnDisconnected(Self, aLine);
    except
    end;
end;


procedure TncCustomTCPProClient.Send(const aBuf; aBufSize: Integer);
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  SendTLS(Line, aBuf, aBufSize);
end;

procedure TncCustomTCPProClient.Send(const aBytes: TBytes);
begin
  if Length(aBytes) > 0 then
    Send(aBytes[0], Length(aBytes));
end;

procedure TncCustomTCPProClient.Send(const aStr: string);
begin
  Send(BytesOf(aStr));
end;

procedure TncCustomTCPProClient.SendCommand(aCmd: Integer; const aData: TBytes = nil);
var
  Command: TncCommand;
  MessageBytes, FinalBuf: TBytes;
  MsgByteCount, HeaderBytes: UInt64;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);
  
  // Create command like ncSources does
  Command.CommandType := ctInitiator;
  Command.UniqueID := 0; // Simplified for now
  Command.Cmd := aCmd;
  Command.Data := aData;
  Command.RequiresResult := False;
  Command.AsyncExecute := False;
  Command.ResultIsErrorString := False;
  Command.SourceComponentHandler := '';
  Command.PeerComponentHandler := '';
  
  // Convert to bytes like ncSources
  MessageBytes := Command.ToBytes;
  MsgByteCount := Length(MessageBytes);
  
  // Use ncSources protocol format: [Magic: 4][MessageLength: 8][Data: variable]
  HeaderBytes := SizeOf(TMagicHeaderType) + SizeOf(MsgByteCount);
  SetLength(FinalBuf, HeaderBytes + MsgByteCount);
  
  // Write protocol header (same as ncSources)
  PMagicHeaderType(@FinalBuf[0])^ := MagicHeader;                    // Magic: 4 bytes
  PUInt64(@FinalBuf[SizeOf(MagicHeader)])^ := MsgByteCount;         // MessageLength: 8 bytes
  Move(MessageBytes[0], FinalBuf[HeaderBytes], MsgByteCount);       // Data: variable
  
  Send(FinalBuf);
end;

procedure TncCustomTCPProClient.InternalReadDataHandler(Sender: TObject; aLine: TncLine; 
  const aBuf: TBytes; aBufCount: Integer);
var
  Command: TncCommand;
  Ofs: Integer;
  BytesToRead: Integer;
  OldLen: Integer;
  TextData: TBytes;
begin
  // CRITICAL FIX: When TLS is enabled, bypass protocol detection during handshake
  // TLS handshake data should never reach the application layer
  if UseTLS then
  begin
    // Check if TLS handshake is still in progress using per-connection context
    if (TncLineInternal(aLine).DataObject <> nil) then
    begin
      var TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
      if not TlsContext.GetClientContext^.Initialized then
      begin
        // During handshake, pass all data directly to original handler (TLS layer)
        // Protocol detection should only happen AFTER TLS handshake completes
        if Assigned(OriginalOnReadData) then
          OriginalOnReadData(Self, aLine, aBuf, aBufCount);
        Exit; // Don't process for protocol detection during handshake
      end;
    end;
    // If we reach here, TLS handshake is complete and data is decrypted application data
    // Continue with normal protocol detection below
  end;
  
  Ofs := 0;
  
  // Process incoming data using ncSources-style state machine
  while Ofs < aBufCount do
  begin
    // Are we in the middle of accumulating a message?
    if FConnectionState.BytesToEndOfMessage > 0 then
    begin
      // ncSources approach: We know exactly how many bytes we need
      BytesToRead := Min(FConnectionState.BytesToEndOfMessage, aBufCount - Ofs);
      
      // Accumulate data efficiently
      OldLen := Length(FConnectionState.MessageBuffer);
      SetLength(FConnectionState.MessageBuffer, OldLen + BytesToRead);
      Move(aBuf[Ofs], FConnectionState.MessageBuffer[OldLen], BytesToRead);
      
      Ofs := Ofs + BytesToRead;
      FConnectionState.BytesToEndOfMessage := FConnectionState.BytesToEndOfMessage - BytesToRead;
    end;
    
    // Do we have a complete message?
    if FConnectionState.BytesToEndOfMessage = 0 then
    begin
      if Length(FConnectionState.MessageBuffer) > 0 then
      begin
        // Process complete message based on detected protocol
        case FConnectionState.MessageType of
          mtBinary:
            begin
              // Process binary command - Route to Thread Pool (from ncSources)
              try
                Command.FromBytes(FConnectionState.MessageBuffer);
                
                // Route to thread pool for processing like ncSources
                HandleCommandThreadPool.Serialiser.Acquire;
                try
                  var HandleCommandThread := THandleCommandThread(HandleCommandThreadPool.RequestReadyThread);
                  HandleCommandThread.WorkType := htwtOnCommand;
                  HandleCommandThread.Source := Self;
                  HandleCommandThread.Line := aLine;
                  HandleCommandThread.Cmd := Command.Cmd;
                  HandleCommandThread.Data := Command.Data;
                  HandleCommandThread.OnCommand := FOnCommand;
                  HandleCommandThread.EventsUseMainThread := EventsUseMainThread;
                  HandleCommandThreadPool.RunRequestedThread(HandleCommandThread);
                finally
                  HandleCommandThreadPool.Serialiser.Release;
                end;
              except
                // If parsing fails, treat as text
                if Assigned(OriginalOnReadData) then
                  OriginalOnReadData(Self, aLine, FConnectionState.MessageBuffer, Length(FConnectionState.MessageBuffer));
              end;
            end;
          mtText:
            begin
              // Process text data
              if Assigned(OriginalOnReadData) then
                OriginalOnReadData(Self, aLine, FConnectionState.MessageBuffer, Length(FConnectionState.MessageBuffer));
            end;
        end;
        
        // Reset for next message
        FConnectionState.Reset;
      end;
      
      // Start new message detection if we have more data
      if Ofs < aBufCount then
      begin
        // Protocol detection: Check for magic header
        if (aBufCount - Ofs) >= SizeOf(TMagicHeaderType) then
        begin
          if PMagicHeaderType(@aBuf[Ofs])^ = MagicHeader then
          begin
            // Binary protocol detected
            FConnectionState.MessageType := mtBinary;
            
            // Do we have the complete header?
            if (aBufCount - Ofs) >= (SizeOf(TMagicHeaderType) + SizeOf(UInt64)) then
            begin
              // Read message length and set up state
              FConnectionState.ExpectedMessageLength := PUInt64(@aBuf[Ofs + SizeOf(TMagicHeaderType)])^;
              FConnectionState.BytesToEndOfMessage := FConnectionState.ExpectedMessageLength;
              FConnectionState.HeaderComplete := True;
              
              // Skip past header
              Ofs := Ofs + SizeOf(TMagicHeaderType) + SizeOf(UInt64);
              
              // Continue to accumulate message data
              Continue;
            end
            else
            begin
              // Incomplete header - buffer remaining data and wait
              SetLength(TextData, aBufCount - Ofs);
              Move(aBuf[Ofs], TextData[0], aBufCount - Ofs);
              FConnectionState.MessageBuffer := TextData;
              FConnectionState.BytesToEndOfMessage := (SizeOf(TMagicHeaderType) + SizeOf(UInt64)) - (aBufCount - Ofs);
              FConnectionState.MessageType := mtUnknown; // Still detecting
              Break;
            end;
          end
          else
          begin
            // Unknown protocol - pass through directly like ncSockets
            if Assigned(OriginalOnReadData) then
              OriginalOnReadData(Self, aLine, Copy(aBuf, Ofs, aBufCount - Ofs), aBufCount - Ofs);
            Break; // Exit processing, don't accumulate
          end;
        end
        else
        begin
          // Not enough data for magic header check - pass through directly like ncSockets
          if Assigned(OriginalOnReadData) then
            OriginalOnReadData(Self, aLine, Copy(aBuf, Ofs, aBufCount - Ofs), aBufCount - Ofs);
          Break; // Exit processing
        end;
      end;
    end;
  end;
end;

procedure TncCustomTCPProClient.SetOnReadData(const Value: TncOnReadData);
begin
  // Store the user's handler and keep protocol detection active
  OriginalOnReadData := Value;
  inherited OnReadData := InternalReadDataHandler;
end;

function TncCustomTCPProClient.Receive(aTimeout: Cardinal): TBytes;
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

  BufRead := ReceiveTLS(Line, ReadBuf[0], Length(ReadBuf));
  Result := Copy(ReadBuf, 0, BufRead)
end;

function TncCustomTCPProClient.ReceiveRaw(var aBytes: TBytes): Integer;
begin
  Result := ReceiveTLS(Line, aBytes[0], Length(aBytes));
end;

function TncCustomTCPProClient.GetActive: Boolean;
begin
  Result := Line.Active;
end;

function TncCustomTCPProClient.GetHost: string;
begin
  PropertyLock.Acquire;
  try
    Result := FHost;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomTCPProClient.SetHost(const Value: string);
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

function TncCustomTCPProClient.GetReconnect: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FReconnect;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomTCPProClient.SetReconnect(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FReconnect := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomTCPProClient.GetReconnectInterval: Cardinal;
begin
  PropertyLock.Acquire;
  try
    Result := FReconnectInterval;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomTCPProClient.SetReconnectInterval(const Value: Cardinal);
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

constructor TncClientProcessor.Create(aClientSocket: TncCustomTCPProClient);
begin
  FClientSocket := aClientSocket;
  ReadySocketsChanged := False;
  inherited Create;
end;

procedure TncClientProcessor.SocketProcess;
var
  BufRead: Integer;
begin
  BufRead := FClientSocket.ReceiveTLS(FClientSocket.Line, FClientSocket.ReadBuf[0], Length(FClientSocket.ReadBuf));
  if Assigned(FClientSocket.OnReadData) and (BufRead > 0) then
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
        if ReadableAnySocket(FClientSocket.ReadSocketHandles, 100) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          if FClientSocket.EventsUseMainThread then
            Synchronize(SocketProcess) // for synchronize
          else
            SocketProcess;
        end;
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
{ TncCustomTCPProServer }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomTCPProServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  
  FIsServer := True; // Set server flag for TLS context selection
  FOnCommand := nil; // Initialize the new field
  OriginalOnReadData := OnReadData; // Store original handler
  OnReadData := InternalReadDataHandler; // Set up protocol detection handler
  FConnectionStates := TDictionary<TncLine, TConnectionState>.Create; // Initialize state tracking dictionary

  Listener := CreateLineObject;
  if Listener.Family <> FFamily then
  begin
    TncLineInternal(Listener).SetFamily(FFamily);
  end;

  TncLineInternal(Listener).OnConnected := DataSocketConnected;
  TncLineInternal(Listener).OnDisconnected := DataSocketDisconnected;
  
  // Set up TLS callbacks if TLS is enabled
  if FUseTLS then
  begin
    TncLineInternal(Listener).OnBeforeConnected := HandleTLSHandshake;
    TncLineInternal(Listener).OnBeforeDisconnected := FinalizeTLS;
  end;
  Lines := TThreadLineList.Create();

  LineProcessor := TncServerProcessor.Create(Self);
  try
    if LineProcessor.Priority <> FromNcThreadPriority(DefReaderThreadPriority) then
      LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
  LineProcessor.WaitForReady;
end;

destructor TncCustomTCPProServer.Destroy;
begin
  // Will get Sockets.Lines disposed off
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Lines.Free;
  Listener.Free;

  FConnectionStates.Free; // Cleanup state tracking dictionary

  inherited Destroy;
end;

function TncCustomTCPProServer.GetActive: Boolean;
begin
  Result := Listener.Active;
end;

procedure TncCustomTCPProServer.DoActivate(aActivate: Boolean);
var
  DataSockets: TSocketList;
  i: Integer;
begin
  if aActivate = GetActive then
    Exit;

  if aActivate then
  begin
    // Verify family setting before creating handle
    if Assigned(Listener) and (Listener.Family <> FFamily) then
    begin
      TncLineInternal(Listener).SetFamily(FFamily);
    end;
    TncLineInternal(Listener).CreateServerHandle(FPort);
  end
  else
  begin
    if Assigned(Listener) then
      TncLineInternal(Listener).DestroyHandle;

    // Cleanup connected sockets
{$HINTS OFF}
    DataSockets := Lines.LockListNoCopy;
    try
      for i := 0 to DataSockets.Count - 1 do
        try
          if Assigned(DataSockets.Lines[i]) then
          begin
            TncLineInternal(DataSockets.Lines[i]).DestroyHandle;
            DataSockets.Lines[i].Free;
          end;
        except
          //
        end;
      DataSockets.Clear;
    finally
      Lines.UnlockListNoCopy;
    end;
  end;
end;

procedure TncCustomTCPProServer.ShutDownLine(aLine: TncLine);
var
  i: Integer;
begin
  if UseReaderThread then
  begin
    ShutDownLock.Acquire;
    try
      for i := 0 to High(LinesToShutDown) do
        if LinesToShutDown[i] = aLine then
          Exit;

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

procedure TncCustomTCPProServer.DataSocketConnected(aLine: TncLine);
begin
  if aLine = Listener then
  begin
    SetLength(ReadSocketHandles, 1);
    ReadSocketHandles[0] := Listener.Handle;
    if UseReaderThread then
    begin
      LineProcessor.WaitForReady;
      LineProcessor.Run;
    end;
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

    try
      TncLineInternal(aLine).SetReceiveSize(1048576);
      TncLineInternal(aLine).SetWriteSize(1048576);
    except
    end;

    // TLS initialization is now handled by OnBeforeConnected event
    
    // For TLS connections, delay OnConnected until after handshake completes
    if not UseTLS then
    begin
      if Assigned(OnConnected) then
        try
          OnConnected(Self, aLine);
        except
        end;
    end
    else
    begin
      // For TLS connections, OnConnected will be called after handshake completes
      // This is handled in the first successful TLS receive operation
    end;
  end;
end;

// Update : Moves the handle removal before the disconnect event handling
// This prevents other threads from trying to use the handle while the disconnect event is processing.
procedure TncCustomTCPProServer.DataSocketDisconnected(aLine: TncLine);
var
  i: Integer;
begin
  if aLine = Listener then
    SetLength(ReadSocketHandles, 0)
  else
  begin
    // TLS cleanup is now handled automatically by OnBeforeDisconnected event

    // Clean up connection state
    FConnectionStates.Remove(aLine);

    // First remove the handle to prevent further processing
    PropertyLock.Acquire;
    try
      for i := 0 to High(ReadSocketHandles) do
        if ReadSocketHandles[i] = aLine.Handle then
        begin
          ReadSocketHandles[i] := ReadSocketHandles[High(ReadSocketHandles)];
          SetLength(ReadSocketHandles, Length(ReadSocketHandles) - 1);
          Break;
        end;
    finally
      PropertyLock.Release;
    end;

    // Then handle disconnect event
    if Assigned(OnDisconnected) then
      try
        OnDisconnected(Self, aLine);
      except
      end;
  end;
end;

procedure TncCustomTCPProServer.Send(aLine: TncLine; const aBuf; aBufSize: Integer);
begin
  SendTLS(aLine, aBuf, aBufSize);
end;

procedure TncCustomTCPProServer.Send(aLine: TncLine; const aBytes: TBytes);
begin
  if Length(aBytes) > 0 then
    Send(aLine, aBytes[0], Length(aBytes));
end;

procedure TncCustomTCPProServer.Send(aLine: TncLine; const aStr: string);
begin
  Send(aLine, BytesOf(aStr));
end;

function TncCustomTCPProServer.Receive(aLine: TncLine; aTimeout: Cardinal): TBytes;
var
  i, BufRead, LineNdx: Integer;
  DataSockets: TSocketList;
  Line: TncLine;
  ReadySockets: TSocketHandleArray;
begin
  if UseReaderThread then
    raise ECannotReceiveIfUseReaderThread.Create(ECannotReceiveIfUseReaderThreadStr);

  SetLength(Result, 0);
  ReadySockets := Readable(ReadSocketHandles, aTimeout);

  for i := 0 to High(ReadySockets) do
    try
      if ReadySockets[i] = Listener.Handle then
        // New line is here, accept it and create a new TncLine object
        Lines.Add(TncLineInternal(Listener).AcceptLine);
    except
    end;

  DataSockets := Lines.LockListNoCopy;
  try
    for i := 0 to High(ReadySockets) do
      try
        if aLine.Handle = ReadySockets[i] then
        begin
          LineNdx := DataSockets.IndexOf(ReadySockets[i]);
          if LineNdx = -1 then
            Continue;
          Line := DataSockets.Lines[LineNdx];
          try
            if not Line.Active then
              Abort;
            BufRead := ReceiveTLS(Line, ReadBuf[0], Length(ReadBuf));
            Result := Copy(ReadBuf, 0, BufRead);
          except
            // Line has disconnected, destroy the line
            DataSockets.Delete(LineNdx);
            Line.Free;
          end;
        end;
      except
      end;
  finally
    Lines.UnlockListNoCopy;
  end;
end;

function TncCustomTCPProServer.ReceiveRaw(aLine: TncLine; var aBytes: TBytes): Integer;
begin
  Result := ReceiveTLS(aLine, aBytes[0], Length(aBytes));
end;

procedure TncCustomTCPProServer.SendCommand(aLine: TncLine; aCmd: Integer; const aData: TBytes = nil);
var
  Command: TncCommand;
  MessageBytes, FinalBuf: TBytes;
  MsgByteCount, HeaderBytes: UInt64;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);
  
  // Create command like ncSources does
  Command.CommandType := ctInitiator;
  Command.UniqueID := 0; // Simplified for now
  Command.Cmd := aCmd;
  Command.Data := aData;
  Command.RequiresResult := False;
  Command.AsyncExecute := False;
  Command.ResultIsErrorString := False;
  Command.SourceComponentHandler := '';
  Command.PeerComponentHandler := '';
  
  // Convert to bytes like ncSources
  MessageBytes := Command.ToBytes;
  MsgByteCount := Length(MessageBytes);
  
  // Use ncSources protocol format: [Magic: 4][MessageLength: 8][Data: variable]
  HeaderBytes := SizeOf(TMagicHeaderType) + SizeOf(MsgByteCount);
  SetLength(FinalBuf, HeaderBytes + MsgByteCount);
  
  // Write protocol header (same as ncSources)
  PMagicHeaderType(@FinalBuf[0])^ := MagicHeader;                    // Magic: 4 bytes
  PUInt64(@FinalBuf[SizeOf(MagicHeader)])^ := MsgByteCount;         // MessageLength: 8 bytes
  Move(MessageBytes[0], FinalBuf[HeaderBytes], MsgByteCount);       // Data: variable
  
  Send(aLine, FinalBuf);
end;

procedure TncCustomTCPProServer.InternalReadDataHandler(Sender: TObject; aLine: TncLine; 
  const aBuf: TBytes; aBufCount: Integer);
var
  Command: TncCommand;
  ConnectionState: TConnectionState;
  Ofs: Integer;
  BytesToRead: Integer;
  OldLen: Integer;
  TextData: TBytes;
begin
  // CRITICAL FIX: When TLS is enabled, bypass protocol detection during handshake
  // TLS handshake data should never reach the application layer
  if UseTLS then
  begin
    // Check if TLS handshake is still in progress using per-connection context
    if (TncLineInternal(aLine).DataObject <> nil) then
    begin
      var TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
      if not TlsContext.GetServerContext^.HandshakeCompleted then
      begin
        // During handshake, pass all data directly to original handler (TLS layer)
        // Protocol detection should only happen AFTER TLS handshake completes
        if Assigned(OriginalOnReadData) then
          OriginalOnReadData(Self, aLine, aBuf, aBufCount);
        Exit; // Don't process for protocol detection during handshake
      end;
    end;
    // If we reach here, TLS handshake is complete and data is decrypted application data
    // Continue with normal protocol detection below
  end;
  
  // Get or create connection state
  if not FConnectionStates.TryGetValue(aLine, ConnectionState) then
  begin
    ConnectionState.Reset;
    FConnectionStates.Add(aLine, ConnectionState);
  end;
  
  Ofs := 0;
  
  // Process incoming data using ncSources-style state machine
  while Ofs < aBufCount do
  begin
    // Are we in the middle of accumulating a message?
    if ConnectionState.BytesToEndOfMessage > 0 then
    begin
      // ncSources approach: We know exactly how many bytes we need
      BytesToRead := Min(ConnectionState.BytesToEndOfMessage, aBufCount - Ofs);
      
      // Accumulate data efficiently
      OldLen := Length(ConnectionState.MessageBuffer);
      SetLength(ConnectionState.MessageBuffer, OldLen + BytesToRead);
      Move(aBuf[Ofs], ConnectionState.MessageBuffer[OldLen], BytesToRead);
      
      Ofs := Ofs + BytesToRead;
      ConnectionState.BytesToEndOfMessage := ConnectionState.BytesToEndOfMessage - BytesToRead;
    end;
    
    // Do we have a complete message?
    if ConnectionState.BytesToEndOfMessage = 0 then
    begin
      if Length(ConnectionState.MessageBuffer) > 0 then
      begin
        // Process complete message based on detected protocol
        case ConnectionState.MessageType of
          mtBinary:
            begin
              // Process binary command - Route to Thread Pool (from ncSources)
              try
                Command.FromBytes(ConnectionState.MessageBuffer);
                
                // Route to thread pool for processing like ncSources
                HandleCommandThreadPool.Serialiser.Acquire;
                try
                  var HandleCommandThread := THandleCommandThread(HandleCommandThreadPool.RequestReadyThread);
                  HandleCommandThread.WorkType := htwtOnCommand;
                  HandleCommandThread.Source := Self;
                  HandleCommandThread.Line := aLine;
                  HandleCommandThread.Cmd := Command.Cmd;
                  HandleCommandThread.Data := Command.Data;
                  HandleCommandThread.OnCommand := FOnCommand;
                  HandleCommandThread.EventsUseMainThread := EventsUseMainThread;
                  HandleCommandThreadPool.RunRequestedThread(HandleCommandThread);
                finally
                  HandleCommandThreadPool.Serialiser.Release;
                end;
              except
                // If parsing fails, treat as text
                if Assigned(OriginalOnReadData) then
                  OriginalOnReadData(Self, aLine, ConnectionState.MessageBuffer, Length(ConnectionState.MessageBuffer));
              end;
            end;
          mtText:
            begin
              // Process text data
              if Assigned(OriginalOnReadData) then
                OriginalOnReadData(Self, aLine, ConnectionState.MessageBuffer, Length(ConnectionState.MessageBuffer));
            end;
        end;
        
        // Reset for next message
        ConnectionState.Reset;
      end;
      
      // Start new message detection if we have more data
      if Ofs < aBufCount then
      begin
        // Protocol detection: Check for magic header
        if (aBufCount - Ofs) >= SizeOf(TMagicHeaderType) then
        begin
          if PMagicHeaderType(@aBuf[Ofs])^ = MagicHeader then
          begin
            // Binary protocol detected
            ConnectionState.MessageType := mtBinary;
            
            // Do we have the complete header?
            if (aBufCount - Ofs) >= (SizeOf(TMagicHeaderType) + SizeOf(UInt64)) then
            begin
              // Read message length and set up state
              ConnectionState.ExpectedMessageLength := PUInt64(@aBuf[Ofs + SizeOf(TMagicHeaderType)])^;
              ConnectionState.BytesToEndOfMessage := ConnectionState.ExpectedMessageLength;
              ConnectionState.HeaderComplete := True;
              
              // Skip past header
              Ofs := Ofs + SizeOf(TMagicHeaderType) + SizeOf(UInt64);
              
              // Continue to accumulate message data
              Continue;
            end
            else
            begin
              // Incomplete header - buffer remaining data and wait
              SetLength(TextData, aBufCount - Ofs);
              Move(aBuf[Ofs], TextData[0], aBufCount - Ofs);
              ConnectionState.MessageBuffer := TextData;
              ConnectionState.BytesToEndOfMessage := (SizeOf(TMagicHeaderType) + SizeOf(UInt64)) - (aBufCount - Ofs);
              ConnectionState.MessageType := mtUnknown; // Still detecting
              Break;
            end;
          end
          else
          begin
            // Unknown protocol - pass through directly like ncSockets
            if Assigned(OriginalOnReadData) then
              OriginalOnReadData(Self, aLine, Copy(aBuf, Ofs, aBufCount - Ofs), aBufCount - Ofs);
            Break; // Exit processing, don't accumulate
          end;
        end
        else
        begin
          // Not enough data for magic header check - pass through directly like ncSockets
          if Assigned(OriginalOnReadData) then
            OriginalOnReadData(Self, aLine, Copy(aBuf, Ofs, aBufCount - Ofs), aBufCount - Ofs);
          Break; // Exit processing
        end;
      end;
    end;
  end;
  
  // Update connection state
  FConnectionStates.AddOrSetValue(aLine, ConnectionState);
end;

procedure TncCustomTCPProServer.SetOnReadData(const Value: TncOnReadData);
begin
  // Store the user's handler and keep protocol detection active
  OriginalOnReadData := Value;
  inherited OnReadData := InternalReadDataHandler;
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncServerProcessor }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncServerProcessor.Create(aServerSocket: TncCustomTCPProServer);
begin
  FServerSocket := aServerSocket;
  ReadySocketsChanged := False;
  inherited Create;
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
            FServerSocket.Lines.Remove(FServerSocket.LinesToShutDown[i]);
            TncLineInternal(FServerSocket.LinesToShutDown[i]).DestroyHandle;
            TncLineInternal(FServerSocket.LinesToShutDown[i]).Free;
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

procedure TncServerProcessor.SocketProcess;
var
  i, LineNdx, BufRead, ReadySocketsHigh: Integer;
  DataSockets: TSocketList;
  Line: TncLine;
  j: Integer;
begin
  ReadySocketsHigh := High(ReadySockets);

  // First accept new lines
  i := 0;
  while i <= ReadySocketsHigh do
  begin
    try
      if ReadySockets[i] = FServerSocket.Listener.Handle then
      begin
        // New line is here, accept it and create a new TncLine object
        if ReadySocketsChanged then
        begin
          ReadySocketsChanged := False;
          Exit;
        end;
        FServerSocket.Lines.Add(TncLineInternal(FServerSocket.Listener).AcceptLine);

        Delete(ReadySockets, i, 1);
        ReadySocketsHigh := ReadySocketsHigh - 1;
        i := i - 1;
      end;
    except
    end;
    i := i + 1;
  end;

  if ReadySocketsChanged then
  begin
    ReadySocketsChanged := False;
    Exit;
  end;

  // Check for new data
  DataSockets := FServerSocket.Lines.FList;
  for i := 0 to ReadySocketsHigh do
    try
      LineNdx := DataSockets.IndexOf(ReadySockets[i]);
      if LineNdx = -1 then
      begin
        for j := 0 to High(FServerSocket.ReadSocketHandles) do
          if FServerSocket.ReadSocketHandles[j] = ReadySockets[i] then
          begin
            FServerSocket.ReadSocketHandles[j] := FServerSocket.ReadSocketHandles[High(FServerSocket.ReadSocketHandles)];
            SetLength(FServerSocket.ReadSocketHandles, Length(FServerSocket.ReadSocketHandles) - 1);
            Break;
          end;
        Continue;
      end;
      Line := DataSockets.Lines[LineNdx];
      try
        if not Line.Active then
          Abort;
        if ReadySocketsChanged then
        begin
          ReadySocketsChanged := False;
          Exit;
        end;
        BufRead := FServerSocket.ReceiveTLS(Line, FServerSocket.ReadBuf[0], Length(FServerSocket.ReadBuf));
        if Assigned(FServerSocket.OnReadData) and (BufRead > 0) then
          FServerSocket.OnReadData(FServerSocket, Line, FServerSocket.ReadBuf, BufRead);
      except
        // Line has disconnected, destroy the line
        DataSockets.Delete(LineNdx);
        Line.Free;
      end;

      if ReadySocketsChanged then
      begin
        ReadySocketsChanged := False;
        Exit;
      end;
    except
    end;
end;

procedure TncServerProcessor.ProcessEvent;
begin
  if FServerSocket.EventsUseMainThread then
    while FServerSocket.Listener.Active and (not Terminated) do
      try
        ReadySockets := Readable(FServerSocket.ReadSocketHandles, 500);
        Synchronize(SocketProcess);
        CheckLinesToShutDown;
      except
      end
  else
    while FServerSocket.Listener.Active and (not Terminated) do
      try
        ReadySockets := Readable(FServerSocket.ReadSocketHandles, 500);
        SocketProcess;
        CheckLinesToShutDown;
      except
      end;
end;

// Thread Pool Property Implementations (from ncSources)
function TncTCPProBase.GetCommandProcessorThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadPriority;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetCommandProcessorThreadPriority(const Value: TncThreadPriority);
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

function TncTCPProBase.GetCommandProcessorThreads: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreads;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetCommandProcessorThreads(const Value: Integer);
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

function TncTCPProBase.GetCommandProcessorThreadsPerCPU: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadsPerCPU;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetCommandProcessorThreadsPerCPU(const Value: Integer);
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

function TncTCPProBase.GetCommandProcessorThreadsGrowUpto: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FCommandProcessorThreadsGrowUpto;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPProBase.SetCommandProcessorThreadsGrowUpto(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FCommandProcessorThreadsGrowUpto := Value;
    if not(csLoading in ComponentState) then
      HandleCommandThreadPool.GrowUpto := Value;
  finally
    PropertyLock.Release;
  end;
end;

// TLS base implementation

{ THandleCommandThread }

procedure THandleCommandThread.CallOnCommandEvent;
begin
  if Assigned(FOnCommand) then
    try
      FOnCommand(FSource, FLine, FCmd, FData);
    except
      // Swallow exceptions in worker thread to prevent thread termination
    end;
end;

procedure THandleCommandThread.ProcessEvent;
begin
  if FEventsUseMainThread then
    Synchronize(CallOnCommandEvent)
  else
    CallOnCommandEvent;
end;


end.


