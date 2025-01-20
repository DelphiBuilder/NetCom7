// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit implements a TncLine, which is all the WinSock API commands for a
// socket, organised in an object which contains the handle of the socket,
// and also makes sure it checks every API command for errors
//
// 14/01/2025 - by J.Pauwels
// - Fix Linux compilation
// - Added UDP support
// - Added IPV6 support
//
// 9/8/2020
// - Completed multiplatform support, now NetCom can be compiled in all
// platforms
// - Made custom fdset manipulation so that our sockets can handle more than
// 1024 concurrent connections in Linux/Mac/Android!
// See Readable function for implementation
//
// 8/8/2020
// - Created this unit by breaking the code from ncSockets where it was
// initially situated
// - Increased number of concurrent conections from 65536 to infinite
// (to as much memory as the computer has)
// - Added Win64 support
//
// Written by Demos Bill
//
// /////////////////////////////////////////////////////////////////////////////

unit ncLines;

interface

uses
{$IFDEF MSWINDOWS}
  Winapi.Windows, Winapi.Winsock2,
{$ELSE}
  Posix.SysTypes, Posix.SysSelect, Posix.SysSocket, Posix.NetDB, Posix.SysTime,
  Posix.Unistd, {Posix.ArpaInet,}
{$ENDIF}
  System.SyncObjs,
  System.Math,
  System.SysUtils,
  System.Diagnostics,
  System.IOUtils,
  System.Classes,
  ncThreads;

const
  // Flag that indicates that the socket is intended for bind() + listen() when constructing it
  AI_PASSIVE = 1;
  IPV6_V6ONLY = 27;
  AI_ADDRCONFIG = $0020; // Return only if local system configured
  AI_NUMERICHOST = $0004; // Don't use name resolution
  INET6_ADDRSTRLEN = 46;
  // Maximum length of IPv6 address string including null terminator
{$IFDEF MSWINDOWS}
  InvalidSocket = Winapi.Winsock2.INVALID_SOCKET;
  SocketError = SOCKET_ERROR;
{$ELSE}
  InvalidSocket = -1;
  SocketError = -1;
  IPPROTO_TCP = 6;
  TCP_NODELAY = $0001;
{$ENDIF}

type
  TSocketType = (stUDP, stTCP);

const
  CSocketTypeNames: array [TSocketType] of string = ('UDP', 'TCP');

  CRawSocketTypes: array [TSocketType] of Integer = (SOCK_DGRAM, // UDP datagram
    SOCK_STREAM // TCP stream
    );

  CRawProtocolTypes: array [TSocketType] of Integer = (IPPROTO_UDP,
    IPPROTO_TCP);

type
  TAddressType = (afIPv4, afIPv6);

const
  CAddressTypeNames: array [TAddressType] of string = ('IPv4', 'IPv6');

type
{$IFDEF MSWINDOWS}
  TSocketHandle = Winapi.Winsock2.TSocket;

  PAddrInfoW = ^TAddrInfoW;
  PPAddrInfoW = ^PAddrInfoW;

  TAddrInfoW = record
    ai_flags: Integer;
    ai_family: Integer;
    ai_socktype: Integer;
    ai_protocol: Integer;
    ai_addrlen: ULONG; // is NativeUInt
    ai_canonname: PWideChar;
    ai_addr: PSOCKADDR;
    ai_next: PAddrInfoW;
  end;

  TGetAddrInfoW = function(NodeName: PWideChar; ServiceName: PWideChar;
    Hints: PAddrInfoW; ppResult: PPAddrInfoW): Integer; stdcall;
  TFreeAddrInfoW = procedure(ai: PAddrInfoW); stdcall;
{$ELSE}
  TSocketHandle = Integer;
{$ENDIF}
  TSocketHandleArray = array of TSocketHandle;

  EncLineException = class(Exception);

  TncLine = class; // Forward declaration

  TncLineOnConnectDisconnect = procedure(aLine: TncLine) of object;

  TConnectThread = class(TncReadyThread)
  public
    Line: TncLine;
    ConnectResult: Integer;
    procedure ProcessEvent; override;
  end;

  // IPv6
  TIn6Addr = packed record
    case Integer of
      0:
        (s6_bytes: packed array [0 .. 15] of Byte);
      1:
        (s6_words: packed array [0 .. 7] of Word);
  end;

  PIn6Addr = ^TIn6Addr;

  TSockAddrIn6 = packed record
    sin6_family: Word; // AF_INET6
    sin6_port: Word; // Transport level port number
    sin6_flowinfo: Cardinal; // IPv6 flow information
    sin6_addr: TIn6Addr; // IPv6 address
    sin6_scope_id: Cardinal; // Scope ID (new in Windows Socket 2)
  end;

  PSockAddrIn6 = ^TSockAddrIn6;

  TSockAddrStorage = record
    ss_family: Word; // Address family
    __ss_pad1: array [0 .. 5] of Byte; // 6 bytes of padding
    __ss_align: Int64; // Force alignment
    __ss_pad2: array [0 .. 111] of Byte; // 112 bytes of padding
  end;

  PSockAddrStorage = ^TSockAddrStorage;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncLine
  // Bring in all functionality from WinSock API, with appropriate exception raising on errors

  TncLine = class(TObject)
  private const
    DefaultConnectTimeout = 100; // msec
  private
    FKind: TSocketType;
    FFamily: TAddressType;
    FMaxPort: Integer;
    FActive: Boolean;
    FLastSent: Int64;
    FLastReceived: Int64;
    FPeerIP: string;
    FDataObject: TObject;
    FOnConnected: TncLineOnConnectDisconnect;
    FOnDisconnected: TncLineOnConnectDisconnect;
  private
    PropertyLock: TCriticalSection;
    FHandle: TSocketHandle;
    FConnectTimeout: Integer;

{$IFDEF MSWINDOWS}
    AddrResult: PAddrInfoW;
{$ELSE}
    AddrResult: Paddrinfo;
{$ENDIF}
    function IsConnectionBased: Boolean;
    procedure SetConnected;
    procedure SetDisconnected;
    function GetReceiveTimeout: Integer;
    procedure SetReceiveTimeout(const Value: Integer);
    function GetSendTimeout: Integer;
    procedure SetSendTimeout(const Value: Integer);
    function GetLastReceived: Int64;
    procedure SetLastReceived(const Value: Int64);
    function GetLastSent: Int64;
    procedure SetLastSent(const Value: Int64);
  protected const
    DefaultKind = stTCP;

  const
    DefaultFamily = afIPv4;
  protected
    procedure SetKind(const AKind: TSocketType);
    procedure SetFamily(const Value: TAddressType);
    function CreateLineObject: TncLine; virtual;
    procedure Check(aCmdRes: Integer); inline;

    // API functions
    procedure CreateClientHandle(const aHost: string; const aPort: Integer;
      const aBroadcast: Boolean = False);
    procedure CreateServerHandle(const aPort: Integer);
    procedure DestroyHandle;

    function AcceptLine: TncLine; inline;

    function SendBuffer(const aBuf; aLen: Integer): Integer; inline;
    function RecvBuffer(var aBuf; aLen: Integer): Integer; inline;

    procedure EnableNoDelay; inline;
    procedure EnableKeepAlive; inline;
    procedure EnableBroadcast; inline;
    procedure EnableIPv6Only; inline;

    procedure EnableReuseAddress; inline;
    procedure SetReceiveSize(const aBufferSize: Integer);
    procedure SetWriteSize(const aBufferSize: Integer);

    property OnConnected: TncLineOnConnectDisconnect read FOnConnected
      write FOnConnected;
    property OnDisconnected: TncLineOnConnectDisconnect read FOnDisconnected
      write FOnDisconnected;
  public
    constructor Create; overload; virtual;
    destructor Destroy; override;

    property Kind: TSocketType read FKind;
    property Family: TAddressType read FFamily;
    property Handle: TSocketHandle read FHandle;
    property Active: Boolean read FActive;
    property LastSent: Int64 read GetLastSent write SetLastSent;
    property LastReceived: Int64 read GetLastReceived write SetLastReceived;
    property PeerIP: string read FPeerIP;
    property DataObject: TObject read FDataObject write FDataObject;
    property ConnectTimeout: Integer read FConnectTimeout write FConnectTimeout
      default DefaultConnectTimeout;
    property ReceiveTimeout: Integer read GetReceiveTimeout
      write SetReceiveTimeout;
    property SendTimeout: Integer read GetSendTimeout write SetSendTimeout;
  end;

function Readable(const aSocketHandleArray: TSocketHandleArray;
  const aTimeout: Cardinal): TSocketHandleArray;
function ReadableAnySocket(const aSocketHandleArray: TSocketHandleArray;
  const aTimeout: Cardinal): Boolean; inline;

implementation

// Readable checks to see if any socket handles have data
// and if so, overwrites aReadFDS with the data
function Readable(const aSocketHandleArray: TSocketHandleArray;
  const aTimeout: Cardinal): TSocketHandleArray;
{$IFDEF MSWINDOWS}
var
  TimeoutValue: timeval;
  FDSetPtr: PFdSet;
  SocketArrayLength, SocketArrayBytes: Integer;
begin
  TimeoutValue.tv_sec := aTimeout div 1000;
  TimeoutValue.tv_usec := (aTimeout mod 1000) * 1000;

  SocketArrayLength := Length(aSocketHandleArray);
  SocketArrayBytes := SocketArrayLength * SizeOf(TSocketHandle);

  // + 32 is there in case of compiler record field aligning
  GetMem(FDSetPtr, SizeOf(FDSetPtr^.fd_count) + SocketArrayBytes + 32);
  try
    FDSetPtr^.fd_count := SocketArrayLength;
    move(aSocketHandleArray[0], FDSetPtr^.fd_array[0], SocketArrayBytes);

    Select(0, FDSetPtr, nil, nil, @TimeoutValue);

    if FDSetPtr^.fd_count > 0 then
    begin
      SetLength(Result, FDSetPtr^.fd_count);
      move(FDSetPtr^.fd_array[0], Result[0], FDSetPtr^.fd_count *
        SizeOf(TSocketHandle));
    end
    else
      SetLength(Result, 0); // This is needed with newer compilers
  finally
    FreeMem(FDSetPtr);
  end;
end;

{$ELSE}

var
  TimeoutValue: timeval;
  i: Integer;
  SocketHandle: TSocketHandle;
  FDSetPtr: Pfd_set;
  FDArrayLen, FDNdx, ReadySockets, ResultNdx: Integer;
begin
  TimeoutValue.tv_sec := aTimeout div 1000;
  TimeoutValue.tv_usec := (aTimeout mod 1000) * 1000;

  // Find max socket handle
  SocketHandle := 0;
  for i := 0 to High(aSocketHandleArray) do
    if SocketHandle < aSocketHandleArray[i] then
      SocketHandle := aSocketHandleArray[i];

  // NFDBITS is SizeOf(fd_mask) in bits (i.e. SizeOf(fd_mask) * 8))
  FDArrayLen := SocketHandle div NFDBITS + 1;
  GetMem(FDSetPtr, FDArrayLen * SizeOf(fd_mask));
  try
    FillChar(FDSetPtr^.fds_bits[0], FDArrayLen * SizeOf(fd_mask), 0);
    for i := 0 to High(aSocketHandleArray) do
    begin
      SocketHandle := aSocketHandleArray[i];
      FDNdx := SocketHandle div NFDBITS;
      FDSetPtr.fds_bits[FDNdx] := FDSetPtr.fds_bits[FDNdx] or
        (1 shl (SocketHandle mod NFDBITS));
    end;

    ReadySockets := Select(FDArrayLen * NFDBITS, FDSetPtr, nil, nil,
      @TimeoutValue);

    if ReadySockets > 0 then
    begin
      SetLength(Result, ReadySockets);

      ResultNdx := 0;
      for i := 0 to High(aSocketHandleArray) do
      begin
        SocketHandle := aSocketHandleArray[i];
        FDNdx := SocketHandle div NFDBITS;
        if FDSetPtr.fds_bits[FDNdx] and (1 shl (SocketHandle mod NFDBITS)) <> 0
        then
        begin
          Result[ResultNdx] := SocketHandle;
          ResultNdx := ResultNdx + 1;
        end;
      end;
    end
    else
      SetLength(Result, 0);
  finally
    FreeMem(FDSetPtr);
  end;
end;
{$ENDIF}

function ReadableAnySocket(const aSocketHandleArray: TSocketHandleArray;
  const aTimeout: Cardinal): Boolean;
begin
  Result := Length(Readable(aSocketHandleArray, aTimeout)) > 0;
end;

{$IFDEF MSWINDOWS}

var
  DllGetAddrInfo: TGetAddrInfoW = nil;
  DllFreeAddrInfo: TFreeAddrInfoW = nil;

procedure GetAddressInfo(NodeName: PWideChar; ServiceName: PWideChar;
  Hints: PAddrInfoW; ppResult: PPAddrInfoW);
var
  iRes: Integer;
begin
  if LowerCase(string(NodeName)) = 'localhost' then
    NodeName := '127.0.0.1';

  iRes := DllGetAddrInfo(NodeName, ServiceName, Hints, ppResult);
  if iRes <> 0 then
    raise EncLineException.Create(SysErrorMessage(iRes));
end;

procedure FreeAddressInfo(ai: PAddrInfoW);
begin
  DllFreeAddrInfo(ai);
end;

function IsBroadcastAddress(const aHost: string): Boolean;
var
  Octets: TArray<string>;
  LastOctet: Integer;
begin
  // Split the IP into octets
  Octets := aHost.Split(['.']);

  // Basic validation
  if Length(Octets) <> 4 then
    Exit(False);

  // Try to parse last octet
  if not TryStrToInt(Octets[3], LastOctet) then
    Exit(False);

  Result :=
  // Global broadcast
    (aHost = '255.255.255.255') or
  // Limited broadcast
    (aHost = '0.0.0.0') or
  // Subnet broadcast (last octet is 255)
    (LastOctet = 255);
end;

{$ENDIF}
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncLine }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncLine.Create;
begin
  inherited Create;

  PropertyLock := TCriticalSection.Create;
  FHandle := InvalidSocket;
  FKind := DefaultKind;
  FFamily := DefaultFamily;

  FConnectTimeout := DefaultConnectTimeout;
  FActive := False;
  FLastSent := TStopWatch.GetTimeStamp;
  FLastReceived := FLastSent;
  FPeerIP := '127.0.0.1';
  FDataObject := nil;

  FOnConnected := nil;
  FOnDisconnected := nil;
end;

destructor TncLine.Destroy;
begin
  if FActive then
    DestroyHandle;

  PropertyLock.Free;
  inherited Destroy;
end;

function TncLine.CreateLineObject: TncLine;
begin
  Result := TncLine.Create;
  Result.SetKind(Kind);
  Result.SetFamily(Family);
end;

/// /////////////////////////////////////////////////////////////////////////////

procedure TncLine.Check(aCmdRes: Integer);
begin
  if aCmdRes = SocketError then
{$IFDEF MSWINDOWS}
    raise EncLineException.Create(SysErrorMessage(WSAGetLastError));
{$ELSE}
    raise EncLineException.Create(SysErrorMessage(GetLastError));
{$ENDIF}
end;

procedure TncLine.CreateClientHandle(const aHost: string; const aPort: Integer;
  const aBroadcast: Boolean = False);
var
  ConnectThread: TConnectThread;
{$IFDEF MSWINDOWS}
  Hints: TAddrInfoW;
  ErrorCode: Integer;
{$ELSE}
  Hints: addrinfo;
  AnsiHost, AnsiPort: RawByteString;
{$ENDIF}
  ResolveHost: string;
begin
  try
    if IsBroadcastAddress(aHost) and not aBroadcast then
      raise Exception.Create
        ('Cannot use broadcast address when Broadcast is False');

    FillChar(Hints, SizeOf(Hints), 0);

    // Set address family and related flags based on FFamily
    case FFamily of
      afIPv4:
        begin
          Hints.ai_family := AF_INET;
          if LowerCase(aHost) = 'localhost' then
            ResolveHost := '127.0.0.1'
          else
            ResolveHost := aHost;
        end;
      afIPv6:
        begin
          Hints.ai_family := AF_INET6;
          Hints.ai_flags := AI_ADDRCONFIG;
          // Remove AI_NUMERICHOST to allow hostname resolution
          ResolveHost := aHost;
        end;
    end;

    Hints.ai_socktype := CRawSocketTypes[FKind];
    Hints.ai_protocol := CRawProtocolTypes[FKind];

    // Create the socket first
    FHandle := Socket(Hints.ai_family, CRawSocketTypes[FKind],
      CRawProtocolTypes[FKind]);
    if FHandle = InvalidSocket then
    begin
      ErrorCode :=
{$IFDEF MSWINDOWS}WSAGetLastError(){$ELSE}GetLastError(){$ENDIF};
      raise Exception.Create(Format('Socket creation failed: %s',
        [SysErrorMessage(ErrorCode)]));
    end;

    // Resolve the server address and port
{$IFDEF MSWINDOWS}
    GetAddressInfo(PChar(ResolveHost), PChar(IntToStr(aPort)), @Hints,
      @AddrResult);
{$ELSE}
    AnsiHost := RawByteString(ResolveHost);
    AnsiPort := RawByteString(IntToStr(aPort));
    GetAddrInfo(MarshaledAString(AnsiHost), MarshaledAString(AnsiPort), Hints,
      AddrResult);
{$ENDIF}
    try
{$IFNDEF MSWINDOWS}
      EnableReuseAddress;
{$ENDIF}
      if IsConnectionBased then
      begin
        ConnectThread := TConnectThread.Create;
        try
          ConnectThread.Line := Self;
          ConnectThread.ConnectResult := -1;
          ConnectThread.ReadyEvent.WaitFor;
          ConnectThread.ReadyEvent.ResetEvent;
          ConnectThread.WakeupEvent.SetEvent;
          ConnectThread.WaitForReady(FConnectTimeout);
          if ConnectThread.ConnectResult = -1 then
            raise EncLineException.Create('Connect timeout');
          Check(ConnectThread.ConnectResult);
          SetConnected;
        finally
          ConnectThread.FreeOnTerminate := True;
          ConnectThread.Terminate;
          ConnectThread.WakeupEvent.SetEvent;
        end;
      end
      else
      begin
        // For UDP, handle IPv4 and IPv6 differently
        case FFamily of
          afIPv4:
            begin
              // IPv4 UDP needs connect
              if not aBroadcast then
                Check(Connect(FHandle, AddrResult^.ai_addr^,
                  AddrResult^.ai_addrlen));
              SetConnected;
            end;
          afIPv6:
            begin
              // IPv6 UDP works without connect
              SetConnected;
            end;
        end;
      end;

    except
      DestroyHandle;
      raise;
    end;
  finally
{$IFDEF MSWINDOWS}
    FreeAddressInfo(AddrResult);
{$ELSE}
    freeaddrinfo(AddrResult^);
{$ENDIF}
  end;
end;

procedure TncLine.CreateServerHandle(const aPort: Integer);
var
{$IFDEF MSWINDOWS}
  Hints: TAddrInfoW;
{$ELSE}
  Hints: addrinfo;
  AnsiPort: RawByteString;
{$ENDIF}
begin
  FillChar(Hints, SizeOf(Hints), 0);
  case FFamily of
    afIPv4:
      begin
        Hints.ai_family := AF_INET;
      end;
    afIPv6:
      begin
        Hints.ai_family := AF_INET6;
      end;
  end;
  Hints.ai_socktype := CRawSocketTypes[FKind];
  Hints.ai_protocol := CRawProtocolTypes[FKind];
  Hints.ai_flags := AI_PASSIVE; // Inform GetAddrInfo to return a server socket

  // Resolve the server address and port
{$IFDEF MSWINDOWS}
  GetAddressInfo(nil, PChar(IntToStr(aPort)), @Hints, @AddrResult);
{$ELSE}
  AnsiPort := RawByteString(IntToStr(aPort));
  GetAddrInfo(nil, MarshaledAString(AnsiPort), Hints, AddrResult);
{$ENDIF}
  try
    // Create a server listener socket
    FHandle := Socket(AddrResult^.ai_family, AddrResult^.ai_socktype,
      AddrResult^.ai_protocol);
    Check(FHandle);
    try
      EnableIPv6Only;

{$IFNDEF MSWINDOWS}
      EnableReuseAddress;
{$ENDIF}
      // Bind the socket
      Check(bind(FHandle, AddrResult^.ai_addr^, AddrResult^.ai_addrlen));

      // For TCP, we need to listen for incoming connections
      if IsConnectionBased then
        Check(Listen(FHandle, SOMAXCONN));

      SetConnected;
    except
      DestroyHandle;
      raise;
    end;
  finally
{$IFDEF MSWINDOWS}
    FreeAddressInfo(AddrResult);
{$ELSE}
    freeaddrinfo(AddrResult^);
{$ENDIF}
  end;
end;

procedure TncLine.DestroyHandle;
begin
  if FActive then
  begin
    try
{$IFDEF MSWINDOWS}
      Shutdown(FHandle, SD_BOTH);
      CloseSocket(FHandle);
{$ELSE}
      Shutdown(FHandle, SHUT_RDWR);
      Posix.Unistd.__Close(FHandle);
{$ENDIF}
    except
      on E: Exception do
        //
    end;
    try
      SetDisconnected;
    except
      on E: Exception do
        //
    end;
    FHandle := InvalidSocket;
  end;
end;

function TncLine.AcceptLine: TncLine;
var
  NewHandle: TSocketHandle;
{$IFNDEF MSWINDOWS}
  addr: sockaddr;
  AddrLen: socklen_t;
{$ENDIF}
begin
{$IFDEF MSWINDOWS}
  NewHandle := Accept(FHandle, nil, nil);
{$ELSE}
  NewHandle := Accept(FHandle, addr, AddrLen);
{$ENDIF}
  if NewHandle = InvalidSocket then
    Abort; // raise silent exception

  Result := CreateLineObject;

  Result.FHandle := NewHandle;
  Result.OnConnected := OnConnected;
  Result.OnDisconnected := OnDisconnected;
  Result.SetConnected;
end;

function TncLine.SendBuffer(const aBuf; aLen: Integer): Integer;
begin
  if IsConnectionBased then
  begin
    // TCP mode - use stream-oriented send
    Result := Send(FHandle, aBuf, aLen, 0);
    try
      if Result = SocketError then
        Abort; // raise silent exception instead of Check

      LastSent := TStopWatch.GetTimeStamp;
    except
      DestroyHandle;
      raise;
    end;
  end
  else
  begin
    // UDP mode - use datagram send
    Result := Send(FHandle, aBuf, aLen, 0);
    if Result = SocketError then
      Check(Result)
    else
      LastSent := TStopWatch.GetTimeStamp;
  end;
end;

function TncLine.RecvBuffer(var aBuf; aLen: Integer): Integer;
begin
  if IsConnectionBased then
  begin
    // TCP mode - use stream-oriented receive
    Result := recv(FHandle, aBuf, aLen, 0);
    try
      if (Result = SocketError) or (Result = 0) then
        Abort; // raise silent exception instead of Check, something has disconnected

      LastReceived := TStopWatch.GetTimeStamp;
    except
      DestroyHandle;
      raise;
    end;
  end
  else
  begin
    // UDP mode - use datagram receive
    Result := recv(FHandle, aBuf, aLen, 0);
    if Result = SocketError then
      Check(Result)
    else
      LastReceived := TStopWatch.GetTimeStamp;
    // Note: UDP can legitimately receive 0 bytes, so we don't treat it as an error
  end;
end;

procedure TncLine.EnableNoDelay;
var
  optval: Integer;
begin
  optval := 1;
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, IPPROTO_TCP, TCP_NODELAY, PAnsiChar(@optval),
    SizeOf(optval)));
{$ELSE}
  Check(SetSockOpt(FHandle, IPPROTO_TCP, TCP_NODELAY, optval, SizeOf(optval)));
{$ENDIF}
end;

procedure TncLine.EnableKeepAlive;
var
  optval: Integer;
begin
  optval := 1; // any non zero indicates true
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_KEEPALIVE, PAnsiChar(@optval),
    SizeOf(optval)));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_KEEPALIVE, optval, SizeOf(optval)));
{$ENDIF}
end;

procedure TncLine.EnableBroadcast;
var
  optval: Integer;
begin
  optval := 1;
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_BROADCAST, PAnsiChar(@optval),
    SizeOf(optval)));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_BROADCAST, optval, SizeOf(optval)));
{$ENDIF}
end;

procedure TncLine.EnableIPv6Only;
var
  optval: Integer;
begin
  if FFamily = afIPv6 then
  begin
    optval := 1;
{$IFDEF MSWINDOWS}
    Check(SetSockOpt(FHandle, IPPROTO_IPV6, IPV6_V6ONLY, PAnsiChar(@optval),
      SizeOf(optval)));
{$ELSE}
    Check(SetSockOpt(FHandle, IPPROTO_IPV6, IPV6_V6ONLY, optval,
      SizeOf(optval)));
{$ENDIF}
  end;
end;

procedure TncLine.EnableReuseAddress;
var
  optval: Integer;
begin
  optval := 1;
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_REUSEADDR, PAnsiChar(@optval),
    SizeOf(optval)));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_REUSEADDR, optval, SizeOf(optval)));
{$ENDIF}
end;

procedure TncLine.SetKind(const AKind: TSocketType);
begin
  if FHandle = InvalidSocket then // TODO: Raise exception otherwise???
  begin
    FKind := AKind;
  end;
end;

procedure TncLine.SetFamily(const Value: TAddressType);
begin
  if FHandle = InvalidSocket then
  // Only allow changing family when socket is not active
  begin
    FFamily := Value;
  end
  else
    // Form1.Log('WARNING: Attempted to change Family while socket is active');
end;

function TncLine.IsConnectionBased: Boolean;
begin
  Result := FKind = stTCP;
end;

procedure TncLine.SetReceiveSize(const aBufferSize: Integer);
begin
  // min is 512 bytes, max is 1048576
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_RCVBUF, PAnsiChar(@aBufferSize),
    SizeOf(aBufferSize)));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_RCVBUF, aBufferSize,
    SizeOf(aBufferSize)));
{$ENDIF}
end;

procedure TncLine.SetWriteSize(const aBufferSize: Integer);
begin
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_SNDBUF, PAnsiChar(@aBufferSize),
    SizeOf(aBufferSize)));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_RCVBUF, aBufferSize,
    SizeOf(aBufferSize)));
{$ENDIF}
end;

procedure TncLine.SetConnected;
var
  addr: TSockAddrStorage; // Changed from sockaddr to TSockAddrStorage
  AddrSize: {$IFDEF MSWINDOWS}Integer{$ELSE}socklen_t{$ENDIF};
  ipv6Str: array [0 .. INET6_ADDRSTRLEN] of AnsiChar;
begin
  if not FActive then
  begin
    FActive := True;
    LastSent := TStopWatch.GetTimeStamp;
    LastReceived := LastSent;

    if IsConnectionBased then
    begin
      // Get peer information
      AddrSize := SizeOf(TSockAddrStorage); // Use full storage size

      if GetPeerName(FHandle, PSOCKADDR(@addr)^, AddrSize) = 0 then
      begin
        case addr.ss_family of
          AF_INET:
            begin
              var
                addr_in: PSockAddrIn := PSockAddrIn(@addr);
              with addr_in^.sin_addr.S_un_b do
                FPeerIP := Format('%d.%d.%d.%d', [s_b1, s_b2, s_b3, s_b4]);
            end;

          AF_INET6:
            begin
              var
                addr_in6: PSockAddrIn6 := PSockAddrIn6(@addr);
              if inet_ntop(AF_INET6, @addr_in6^.sin6_addr, ipv6Str,
                INET6_ADDRSTRLEN) <> nil then
              begin
                FPeerIP := string(AnsiString(ipv6Str));
                // If this is a link-local address, append the scope ID
                if (Length(FPeerIP) >= 4) and
                  (LowerCase(Copy(FPeerIP, 1, 4)) = 'fe80') then
                  FPeerIP := Format('%s%%%d',
                    [FPeerIP, addr_in6^.sin6_scope_id]);
              end
              else
              begin
                FPeerIP := '::';
              end;
            end;

        else
          begin
            FPeerIP := '';
          end;
        end;
      end
      else
      begin
        var
        ErrorCode :=
{$IFDEF MSWINDOWS}WSAGetLastError(){$ELSE}GetLastError(){$ENDIF};
        FPeerIP := '';
      end;
    end
    else
    begin
      // For UDP, we're always "connected" but might not have peer info yet
      case FFamily of
        afIPv4:
          FPeerIP := '0.0.0.0';
        afIPv6:
          FPeerIP := '::';
      end;
    end;

    if Assigned(OnConnected) then
      try
        OnConnected(Self);
      except
      end;
  end;
end;

procedure TncLine.SetDisconnected;
begin
  if FActive then
  begin
    FActive := False;

    if Assigned(FOnDisconnected) then
      try
        OnDisconnected(Self);
      except
      end;
  end;
end;

function TncLine.GetReceiveTimeout: Integer;
var
  Opt: Cardinal;
  OptSize: {$IFDEF MSWINDOWS}Integer{$ELSE}socklen_t{$ENDIF};
begin
  OptSize := SizeOf(Opt);
{$IFDEF MSWINDOWS}
  Check(GetSockOpt(FHandle, SOL_SOCKET, SO_RCVTIMEO, PAnsiChar(@Opt), OptSize));
{$ELSE}
  Check(GetSockOpt(FHandle, SOL_SOCKET, SO_RCVTIMEO, Opt, OptSize));
{$ENDIF}
  Result := Opt;
end;

procedure TncLine.SetReceiveTimeout(const Value: Integer);
var
  Opt: Cardinal;
  OptSize: Integer;
begin
  Opt := Value;
  OptSize := SizeOf(Opt);
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_RCVTIMEO, PAnsiChar(@Opt), OptSize));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_RCVTIMEO, Opt, OptSize));
{$ENDIF}
end;

function TncLine.GetSendTimeout: Integer;
var
  Opt: Cardinal;
  OptSize: {$IFDEF MSWINDOWS}Integer{$ELSE}socklen_t{$ENDIF};
begin
  OptSize := SizeOf(Opt);
{$IFDEF MSWINDOWS}
  Check(GetSockOpt(FHandle, SOL_SOCKET, SO_SNDTIMEO, PAnsiChar(@Opt), OptSize));
{$ELSE}
  Check(GetSockOpt(FHandle, SOL_SOCKET, SO_SNDTIMEO, Opt, OptSize));
{$ENDIF}
  Result := Opt;
end;

procedure TncLine.SetSendTimeout(const Value: Integer);
var
  Opt: Cardinal;
  OptSize: Integer;
begin
  Opt := Value;
  OptSize := SizeOf(Opt);
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_SNDTIMEO, PAnsiChar(@Opt), OptSize));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_SNDTIMEO, Opt, OptSize));
{$ENDIF}
end;

function TncLine.GetLastReceived: Int64;
begin
  PropertyLock.Acquire;
  try
    Result := FLastReceived;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncLine.SetLastReceived(const Value: Int64);
begin
  PropertyLock.Acquire;
  try
    FLastReceived := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncLine.GetLastSent: Int64;
begin
  PropertyLock.Acquire;
  try
    Result := FLastSent;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncLine.SetLastSent(const Value: Int64);
begin
  PropertyLock.Acquire;
  try
    FLastSent := Value;
  finally
    PropertyLock.Release;
  end;
end;

{$IFDEF MSWINDOWS}

// Windows-specific types and variables
var
  ExtDllHandle: THandle = 0;

procedure AttachAddrInfo;
  procedure SafeLoadFrom(aDll: string);
  begin
    if not Assigned(DllGetAddrInfo) then
    begin
      ExtDllHandle := SafeLoadLibrary(aDll);
      if ExtDllHandle <> 0 then
      begin
        DllGetAddrInfo := GetProcAddress(ExtDllHandle, 'GetAddrInfoW');
        DllFreeAddrInfo := GetProcAddress(ExtDllHandle, 'FreeAddrInfoW');
        if not Assigned(DllGetAddrInfo) then
        begin
          FreeLibrary(ExtDllHandle);
          ExtDllHandle := 0;
        end;
      end;
    end;
  end;

begin
  SafeLoadFrom('ws2_32.dll');
  SafeLoadFrom('wship6.dll');
end;
{$ENDIF}

{ TConnectThread }
procedure TConnectThread.ProcessEvent;
begin
{$IFDEF MSWINDOWS}
  ConnectResult := Connect(Line.FHandle, Line.AddrResult^.ai_addr^,
    Line.AddrResult^.ai_addrlen);
{$ELSE}
  ConnectResult := Connect(Line.FHandle, Line.AddrResult^.ai_addr^,
    Line.AddrResult^.ai_addrlen);
{$ENDIF}
end;

initialization

{$IFDEF MSWINDOWS}

var
  WSAData: TWSAData;
begin
  WSAStartup(MakeWord(2, 2), WSAData);
  AttachAddrInfo;
end;
{$ENDIF}

finalization

{$IFDEF MSWINDOWS}
if ExtDllHandle <> 0 then
  FreeLibrary(ExtDllHandle);
WSACleanup;
{$ENDIF}

end.
