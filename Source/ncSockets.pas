unit ncSockets;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit creates a TCP Server and TCP Client socket, along with their
// threads dealing with reading from the socket
//
// 13/07/2025 - by J.Pauwels
// - Added TLS implementation support through SChannel integration
// - Added TLS properties (UseTLS, TlsProvider, CertificateFile) to TncTCPBase
// - Integrated TLS handshake callbacks in OnBeforeConnected architecture
// - Added secure communication capabilities for both server and client
// - CRITICAL FIX: Implemented per-connection TLS context storage to support multiple concurrent TLS connections
//
// 14/01/2025 - by J.Pauwels
// - Defined DefReadBufferLen as a new property
// - Ajust TncCustomTCPServer.DataSocketDisconnected
// - Explicitly set this unit to use TCP
// - Update Client Send method so data cannot be send while socket is inactive
// - Added IPV6 support
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
  System.SysUtils,
  System.Classes,
  System.Diagnostics,
  System.Math,
  System.TimeSpan,
  System.SyncObjs,
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
  ncThreads;

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
  TncCustomTCPServer = class;

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

  TncTCPBase = class(TComponent)
  private
    FInitActive: Boolean;
    FFamily: TAddressType;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FNoDelay: Boolean;
    FKeepAlive: Boolean;
    FReadBufferLen: Integer; // Update
    FOnConnected: TncOnConnectDisconnect;
    FOnDisconnected: TncOnConnectDisconnect;
    FOnReadData: TncOnReadData;
    FLine: TncLine;
    
    // TLS Properties
    FUseTLS: Boolean;
    FTlsProvider: TncTlsProvider;
    FCertificateFile: string;
    FPrivateKeyFile: string;
    FPrivateKeyPassword: string;
    FCACertificatesFile: string;
    FIgnoreCertificateErrors: Boolean;
    FTlsContext: TSChannelClient;
    FTlsServerContext: TSChannelServer;
    FIsServer: Boolean; // Flag to determine if this is a server or client
    
    function GetReadBufferLen: Integer;  // Update
    procedure SetReadBufferLen(const Value: Integer);  // Update
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
    
  private
    FUseReaderThread: Boolean;
    procedure DoActivate(aActivate: Boolean); virtual; abstract;
    procedure SetUseReaderThread(const Value: Boolean);
  protected
    PropertyLock, ShutDownLock: TCriticalSection;
    ReadBuf: TBytes;
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
    property ReadBufferLen: Integer read GetReadBufferLen write SetReadBufferLen default DefReadBufferLen;  // Update
    
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
    FClientSocket: TncCustomTCPClient;
  public
    ReadySocketsChanged: Boolean;
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
  end;

  TncTCPServer = class(TncCustomTCPServer)
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
    property ReadBufferLen; // Update
    property OnConnected;
    property OnDisconnected;
    property OnReadData;
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
    FServerSocket: TncCustomTCPServer;
    procedure CheckLinesToShutDown;
  public
    ReadySockets: TSocketHandleArray;
    ReadySocketsChanged: Boolean;
    constructor Create(aServerSocket: TncCustomTCPServer);
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
  // Clean up TLS contexts
  try
    if FIsServer then
    begin
      if FServerContext.Initialized then
      begin
        // Context cleanup will be handled by BeforeDisconnection call
      end;
    end
    else
    begin
      if FClientContext.Initialized then
      begin
        // Context cleanup will be handled by BeforeDisconnection call
      end;
    end;
  except
    // Ignore cleanup errors
  end;
  
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
{ TThreadLineList }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncTCPBase }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncTCPBase.Create(AOwner: TComponent);
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
  FReadBufferLen := DefReadBufferLen;  // Update
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnReadData := nil;

  // Initialize TLS properties
  FUseTLS := DefUseTLS;
  FTlsProvider := DefTlsProvider;
  FCertificateFile := '';
  FPrivateKeyFile := '';
  FPrivateKeyPassword := '';
  FCACertificatesFile := '';
  FIgnoreCertificateErrors := DefIgnoreCertificateErrors;
  
  // Initialize TLS contexts using FillChar and then set public fields
  FillChar(FTlsContext, SizeOf(FTlsContext), 0);
  FTlsContext.Initialized := False;
  
  FillChar(FTlsServerContext, SizeOf(FTlsServerContext), 0);
  FTlsServerContext.Initialized := False;
  FTlsServerContext.HandshakeCompleted := False;
  
  FIsServer := False;

  SetLength(ReadBuf, DefReadBufferLen);

end;

function TncTCPBase.Kind: TSocketType;
begin
  Result := stTCP;
end;

destructor TncTCPBase.Destroy;
begin
  Active := False;
  
  // TLS contexts are now managed per-connection and cleaned up in FinalizeTLS
  // No global TLS context cleanup needed
  
  PropertyLock.Free;
  ShutDownLock.Free;
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
  TncLineInternal(Result).SetKind(Kind);
  TncLineInternal(Result).SetFamily(FFamily);
  
  // Set up TLS callback if TLS is enabled
  if FUseTLS then
    TncLineInternal(Result).OnBeforeConnected := HandleTLSHandshake;
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

function TncTCPBase.GetFamily: TAddressType;
begin
  PropertyLock.Acquire;
  try
    Result := FFamily;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetFamily(const Value: TAddressType);
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

// Update
function TncTCPBase.GetReadBufferLen: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FReadBufferLen;
  finally
    PropertyLock.Release;
  end;
end;

// Update
procedure TncTCPBase.SetReadBufferLen(const Value: Integer);
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
function TncTCPBase.GetUseTLS: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FUseTLS;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetUseTLS(const Value: Boolean);
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
      if FIsServer and (Self is TncCustomTCPServer) then
      begin
        // Server callback assignment
        var Server := TncCustomTCPServer(Self);
        if Server.Listener <> nil then
        begin
          TncLineInternal(Server.Listener).OnBeforeConnected := HandleTLSHandshake;
        end;
      end
      else if not FIsServer and (Self is TncCustomTCPClient) then
      begin
        // Client callback assignment
        var Client := TncCustomTCPClient(Self);
        if Client.Line <> nil then
        begin
          TncLineInternal(Client.Line).OnBeforeConnected := HandleTLSHandshake;
        end;
      end;
    end;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetTlsProvider: TncTlsProvider;
begin
  PropertyLock.Acquire;
  try
    Result := FTlsProvider;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetTlsProvider(const Value: TncTlsProvider);
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

function TncTCPBase.GetCertificateFile: string;
begin
  PropertyLock.Acquire;
  try
    Result := FCertificateFile;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetCertificateFile(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FCertificateFile := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetPrivateKeyFile: string;
begin
  PropertyLock.Acquire;
  try
    Result := FPrivateKeyFile;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetPrivateKeyFile(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FPrivateKeyFile := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetPrivateKeyPassword: string;
begin
  PropertyLock.Acquire;
  try
    Result := FPrivateKeyPassword;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetPrivateKeyPassword(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FPrivateKeyPassword := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetCACertificatesFile: string;
begin
  PropertyLock.Acquire;
  try
    Result := FCACertificatesFile;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetCACertificatesFile(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FCACertificatesFile := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncTCPBase.GetIgnoreCertificateErrors: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FIgnoreCertificateErrors;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncTCPBase.SetIgnoreCertificateErrors(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FIgnoreCertificateErrors := Value;
  finally
    PropertyLock.Release;
  end;
end;

// TLS base implementation
function TncTCPBase.GetHost: string;
begin
  Result := ''; // Default implementation, override in client
end;

// TLS Functionality Methods
procedure TncTCPBase.InitializeTLS(aLine: TncLine);
var
  TlsContext: TncTlsConnectionContext;
begin
  OutputDebugString(PChar('TLS_INIT: Starting - IsServer: ' + BoolToStr(FIsServer, True) + ', Line: ' + IntToHex(NativeUInt(aLine), 8)));
  
  if not FUseTLS then
    Exit;
  
  if aLine = nil then
    Exit;
  
  // Get or create per-connection TLS context
  if TncLineInternal(aLine).DataObject = nil then
  begin
    OutputDebugString(PChar('TLS_INIT: Creating NEW connection context'));
    TlsContext := TncTlsConnectionContext.Create(FIsServer);
    TncLineInternal(aLine).DataObject := TlsContext;
  end
  else
  begin
    OutputDebugString(PChar('TLS_INIT: ERROR - Context already exists! Possible resource leak'));
    TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
  end;
  
  // Check if TLS is already initialized for this specific connection
  if FIsServer then
  begin
    if TlsContext.GetServerContext^.Initialized then
    begin
      OutputDebugString(PChar('TLS_INIT: Server context already initialized, exiting'));
      Exit;
    end;
  end
  else
  begin
    if TlsContext.GetClientContext^.Initialized then
    begin
      OutputDebugString(PChar('TLS_INIT: Client context already initialized, exiting'));
      Exit;
    end;
  end;
  
  // Initialize TLS for this specific connection
  if FIsServer then
  begin
    OutputDebugString(PChar('TLS_INIT: Calling SChannel server AfterConnection (with aggressive cleanup)'));
    TlsContext.GetServerContext^.AfterConnection(aLine, AnsiString(FCertificateFile), AnsiString(FPrivateKeyPassword));
    OutputDebugString(PChar('TLS_INIT: SChannel server AfterConnection completed'));
  end
  else
  begin
    OutputDebugString(PChar('TLS_INIT: Calling SChannel client AfterConnection (with aggressive cleanup)'));
    TlsContext.GetClientContext^.AfterConnection(aLine, AnsiString(GetHost), FIgnoreCertificateErrors);
    OutputDebugString(PChar('TLS_INIT: SChannel client AfterConnection completed'));
  end;
  
  OutputDebugString(PChar('TLS_INIT: Completed successfully'));
end;

procedure TncTCPBase.HandleTLSHandshake(aLine: TncLine);
begin
  OutputDebugString(PChar('TLS_HANDSHAKE: Called - IsServer: ' + BoolToStr(FIsServer, True) + ', Line: ' + IntToHex(NativeUInt(aLine), 8)));
  
  // This method is called automatically before OnConnected fires
  // It performs the TLS handshake synchronously
  if FUseTLS and (aLine <> nil) then
  begin
    OutputDebugString(PChar('TLS_HANDSHAKE: Starting TLS initialization'));
    try
      InitializeTLS(aLine); // Perform the complete TLS handshake
      OutputDebugString(PChar('TLS_HANDSHAKE: TLS initialization completed successfully'));
    except
      on E: Exception do
      begin
        OutputDebugString(PChar('TLS_HANDSHAKE: EXCEPTION during handshake: ' + E.Message));
        raise; // Re-raise the exception to maintain error handling
      end;
    end;
  end
  else
  begin
    if not FUseTLS then
      OutputDebugString(PChar('TLS_HANDSHAKE: TLS not enabled, skipping'))
    else
      OutputDebugString(PChar('TLS_HANDSHAKE: Line is nil, skipping'));
  end;
  
  OutputDebugString(PChar('TLS_HANDSHAKE: Completed'));
end;

procedure TncTCPBase.HandleTLSHandshakeComplete(aLine: TncLine);
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

procedure TncTCPBase.FinalizeTLS(aLine: TncLine);
var
  TlsContext: TncTlsConnectionContext;
begin
  OutputDebugString(PChar('TLS_CLEANUP: Starting - IsServer: ' + BoolToStr(FIsServer, True) + ', Line: ' + IntToHex(NativeUInt(aLine), 8)));
  
  if FUseTLS and (aLine <> nil) and (TncLineInternal(aLine).DataObject <> nil) then
  begin
    OutputDebugString(PChar('TLS_CLEANUP: Context found, starting cleanup'));
    try
      TlsContext := TncTlsConnectionContext(TncLineInternal(aLine).DataObject);
      
      case FTlsProvider of
        tpSChannel:
          begin
            {$IFDEF MSWINDOWS}
            if FIsServer then
            begin
              if TlsContext.GetServerContext^.Initialized then
              begin
                OutputDebugString(PChar('TLS_CLEANUP: Calling SChannel server BeforeDisconnection'));
                TlsContext.GetServerContext^.BeforeDisconnection(aLine);
                OutputDebugString(PChar('TLS_CLEANUP: SChannel server BeforeDisconnection completed'));
              end
              else
              begin
                OutputDebugString(PChar('TLS_CLEANUP: Server context not initialized, skipping BeforeDisconnection'));
              end;
            end
            else
            begin
              if TlsContext.GetClientContext^.Initialized then
              begin
                OutputDebugString(PChar('TLS_CLEANUP: Calling SChannel client BeforeDisconnection'));
                TlsContext.GetClientContext^.BeforeDisconnection(aLine);
                OutputDebugString(PChar('TLS_CLEANUP: SChannel client BeforeDisconnection completed'));
              end
              else
              begin
                OutputDebugString(PChar('TLS_CLEANUP: Client context not initialized, skipping BeforeDisconnection'));
              end;
            end;
            {$ENDIF}
          end;
        tpOpenSSL:
          begin
            // Future OpenSSL cleanup
          end;
      end;
      
      // Clean up the TLS context object
      OutputDebugString(PChar('TLS_CLEANUP: Freeing TLS context object'));
      TncLineInternal(aLine).DataObject := nil;
      TlsContext.Free;
      OutputDebugString(PChar('TLS_CLEANUP: TLS context object freed successfully'));
    except
      on E: Exception do
      begin
        OutputDebugString(PChar('TLS_CLEANUP: EXCEPTION during cleanup: ' + E.Message));
        // Log error but don't raise exception during cleanup
      end;
    end;
  end
  else
  begin
    if not FUseTLS then
      OutputDebugString(PChar('TLS_CLEANUP: TLS not enabled'))
    else if aLine = nil then
      OutputDebugString(PChar('TLS_CLEANUP: Line is nil'))
    else
      OutputDebugString(PChar('TLS_CLEANUP: No TLS context to clean up'));
  end;
  
  OutputDebugString(PChar('TLS_CLEANUP: Completed'));
end;

function TncTCPBase.SendTLS(aLine: TncLine; const aBuf; aBufSize: Integer): Integer;
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

function TncTCPBase.ReceiveTLS(aLine: TncLine; var aBuf; aBufSize: Integer): Integer;
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
{ TncCustomTCPClient }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomTCPClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FIsServer := False; // Set client flag for TLS context selection
  FHost := DefHost;
  FReconnect := True;
  FReconnectInterval := DefCntReconnectInterval;
  FOnReconnected := nil;

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
  
  // Set up TLS handshake callback if TLS is enabled
  if FUseTLS then
    TncLineInternal(Line).OnBeforeConnected := HandleTLSHandshake;

  LineProcessor := TncClientProcessor.Create(Self);
  try
    if LineProcessor.Priority <> FromNcThreadPriority(DefReaderThreadPriority) then
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
  begin
    // Verify family setting before creating handle
    if Line.Family <> FFamily then
    begin
      TncLineInternal(Line).SetFamily(FFamily);
    end;
    
    // CRITICAL FIX: Reset TLS callback on each connection attempt
    // This ensures proper TLS initialization for reconnections
    if FUseTLS then
    begin
      OutputDebugString(PChar('CLIENT_CONNECT: TLS enabled - checking for residual context'));
      // Ensure any residual TLS context is completely cleared before reconnection
      if TncLineInternal(Line).DataObject <> nil then
      begin
        OutputDebugString(PChar('CLIENT_CONNECT: WARNING - Found residual TLS context! Force cleaning'));
        FinalizeTLS(Line); // Force cleanup of any leftover TLS context
        OutputDebugString(PChar('CLIENT_CONNECT: Residual context cleanup completed'));
      end
      else
      begin
        OutputDebugString(PChar('CLIENT_CONNECT: No residual context found - good'));
      end;
      
      OutputDebugString(PChar('CLIENT_CONNECT: Setting TLS handshake callback'));
      TncLineInternal(Line).OnBeforeConnected := HandleTLSHandshake;
      OutputDebugString(PChar('CLIENT_CONNECT: TLS callback set, creating client handle'));
    end
    else
    begin
      TncLineInternal(Line).OnBeforeConnected := nil;
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

procedure TncCustomTCPClient.DataSocketDisconnected(aLine: TncLine);
begin
  OutputDebugString(PChar('CLIENT_DISCONNECT: Starting - Line: ' + IntToHex(NativeUInt(aLine), 8)));
  
  // Finalize TLS if enabled
  if UseTLS then
  begin
    OutputDebugString(PChar('CLIENT_DISCONNECT: TLS enabled - calling FinalizeTLS'));
    FinalizeTLS(aLine);
    OutputDebugString(PChar('CLIENT_DISCONNECT: FinalizeTLS completed'));
  end
  else
  begin
    OutputDebugString(PChar('CLIENT_DISCONNECT: TLS not enabled'));
  end;

  if Assigned(OnDisconnected) then
    try
      OutputDebugString(PChar('CLIENT_DISCONNECT: Calling OnDisconnected event'));
      OnDisconnected(Self, aLine);
      OutputDebugString(PChar('CLIENT_DISCONNECT: OnDisconnected completed'));
    except
      on E: Exception do
      begin
        OutputDebugString(PChar('CLIENT_DISCONNECT: Exception in OnDisconnected: ' + E.Message));
      end;
    end
  else
  begin
    OutputDebugString(PChar('CLIENT_DISCONNECT: No OnDisconnected event assigned'));
  end;
  
  OutputDebugString(PChar('CLIENT_DISCONNECT: Completed'));
end;


procedure TncCustomTCPClient.Send(const aBuf; aBufSize: Integer);
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  SendTLS(Line, aBuf, aBufSize);
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

  BufRead := ReceiveTLS(Line, ReadBuf[0], Length(ReadBuf));
  Result := Copy(ReadBuf, 0, BufRead)
end;

function TncCustomTCPClient.ReceiveRaw(var aBytes: TBytes): Integer;
begin
  Result := ReceiveTLS(Line, aBytes[0], Length(aBytes));
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
{ TncCustomTCPServer }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncCustomTCPServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  
  FIsServer := True; // Set server flag for TLS context selection

  Listener := CreateLineObject;
  if Listener.Family <> FFamily then
  begin
    TncLineInternal(Listener).SetFamily(FFamily);
  end;

  TncLineInternal(Listener).OnConnected := DataSocketConnected;
  TncLineInternal(Listener).OnDisconnected := DataSocketDisconnected;
  
  // Set up TLS handshake callback if TLS is enabled
  if FUseTLS then
  begin
    TncLineInternal(Listener).OnBeforeConnected := HandleTLSHandshake;
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

procedure TncCustomTCPServer.ShutDownLine(aLine: TncLine);
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

procedure TncCustomTCPServer.DataSocketConnected(aLine: TncLine);
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
procedure TncCustomTCPServer.DataSocketDisconnected(aLine: TncLine);
var
  i: Integer;
begin
  if aLine = Listener then
    SetLength(ReadSocketHandles, 0)
  else
  begin
    // Finalize TLS if enabled
    if UseTLS then
      FinalizeTLS(aLine);

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

procedure TncCustomTCPServer.Send(aLine: TncLine; const aBuf; aBufSize: Integer);
begin
  SendTLS(aLine, aBuf, aBufSize);
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

function TncCustomTCPServer.ReceiveRaw(aLine: TncLine; var aBytes: TBytes): Integer;
begin
  Result := ReceiveTLS(aLine, aBytes[0], Length(aBytes));
end;

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncServerProcessor }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncServerProcessor.Create(aServerSocket: TncCustomTCPServer);
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

end.