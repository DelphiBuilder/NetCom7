// ////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit implements a TncLine, which is all the WinSock API commands for a
// socket, organised in an object which contains the handle of the socket,
// and also makes sure it checks every API command for errors
//
// 14 Feb 2022 by Andreas Toth - andreas.toth@xtra.co.nz
// - Added UDP and IPv6 support
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
  Winapi.Windows,
  Winapi.Winsock2,
{$ELSE}
  Posix.SysTypes,
  Posix.SysSelect,
  Posix.SysSocket,
  Posix.NetDB,
  Posix.SysTime,
  Posix.Unistd,
  //Posix.ArpaInet,
{$ENDIF}
  System.SyncObjs,
  System.Math,
  System.SysUtils,
  System.Diagnostics;

const
  AI_PASSIVE = 1; // Flag that indicates that the socket is intended for bind() + listen() when constructing it
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
  TSocketType =
  (
    stUDP,
    stTCP
  );

const
  CSocketTypeNames: array[TSocketType] of string =
  (
    'UDP',
    'TCP'
  );

type
  TAddressType =
  (
    afUnspecified,
    afIPv4,
    afIPv6
  );

const
  CAddressTypeNames: array[TAddressType] of string =
  (
    'Unspecified',
    'IPv4',
    'IPv6'
  );

type
{$IFDEF MSWINDOWS}
  TSocketHandle = Winapi.Winsock2.TSocket;
{$ELSE}
  TSocketHandle = Integer;
{$ENDIF}
  TSocketHandleArray = array of TSocketHandle;

  EncLineException = class(Exception);

  TncLine = class;

  TncLineOnConnectDisconnect = procedure(ALine: TncLine) of object;

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // TncLine
  // Bring in all functionality from WinSock API, with appropriate exception raising on errors

  TncLine = class(TObject)
  private
    FFamily: TAddressType;
    FKind: TSocketType;
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

    function IsConnectionBased: Boolean;

    procedure SetConnected;
    procedure SetDisconnected;

    function GetLastReceived: Int64;
    function GetLastSent: Int64;

    procedure SetLastReceived(const AValue: Int64);
    procedure SetLastSent(const AValue: Int64);
  protected
    const DefaultFamily = afIPv4;
    const DefaultKind = stTCP;
  protected
    procedure SetKind(const AKind: TSocketType);

    function CreateLineObject: TncLine; virtual;
    procedure Check(ACmdRes: Integer); inline;

    // API functions
    procedure CreateClientHandle(const AHost: string; const APort: Integer);
    procedure CreateServerHandle(const APort: Integer; const AAddress: string = '');
    procedure DestroyHandle;

    function AcceptLine: TncLine; inline;

    function SendBuffer(const ABuffer; ABufferSize: Integer): Integer; inline;
    function RecvBuffer(var ABuffer; ABufferSize: Integer): Integer; inline;

    procedure EnableNoDelay; inline;
    procedure EnableKeepAlive; inline;
    procedure EnableBroadcast; inline;
    procedure EnableReuseAddress; inline;

    property OnConnected: TncLineOnConnectDisconnect read FOnConnected write FOnConnected;
    property OnDisconnected: TncLineOnConnectDisconnect read FOnDisconnected write FOnDisconnected;
  public
    constructor Create; overload; virtual;
    destructor Destroy; override;

    property Family: TAddressType read FFamily;
    property Kind: TSocketType read FKind;
    property Handle: TSocketHandle read FHandle;
    property Active: Boolean read FActive;
    property LastSent: Int64 read GetLastSent write SetLastSent;
    property LastReceived: Int64 read GetLastReceived write SetLastReceived;
    property PeerIP: string read FPeerIP;
    property DataObject: TObject read FDataObject write FDataObject;
  end;

function Readable(const ASocketHandleArray: TSocketHandleArray; const ATimeout: Cardinal): TSocketHandleArray;
function ReadableAnySocket(const ASocketHandleArray: TSocketHandleArray; const ATimeout: Cardinal): Boolean; inline;

implementation

const
  CRawAddressTypes: array[TAddressType] of Integer =
  (
    AF_UNSPEC,
    AF_INET,
    AF_INET6
  );

  CRawSocketTypes: array[TSocketType] of Integer =
  (
    SOCK_DGRAM, // UDP datagram
    SOCK_STREAM // TCP stream
  );

  CRawProtocolTypes: array[TSocketType] of Integer =
  (
    IPPROTO_UDP,
    IPPROTO_TCP
  );

// Readable checks to see if any socket handles have data
// and if so, overwrites aReadFDS with the data
function Readable(const ASocketHandleArray: TSocketHandleArray; const ATimeout: Cardinal): TSocketHandleArray;
{$IFDEF MSWINDOWS}
var
  TimeoutValue: timeval;
  FDSetPtr: PFdSet;
  SocketArrayLength: Integer;
  SocketArrayBytes: Integer;
begin
  TimeoutValue.tv_sec := ATimeout div 1000;
  TimeoutValue.tv_usec := (ATimeout mod 1000) * 1000;

  SocketArrayLength := Length(ASocketHandleArray);
  SocketArrayBytes := SocketArrayLength * SizeOf(TSocketHandle);

  // + 32 is there in case of compiler record field aligning
  GetMem(FDSetPtr, SizeOf(FDSetPtr^.fd_count) + SocketArrayBytes + 32);
  try
    FDSetPtr^.fd_count := SocketArrayLength;
    Move(ASocketHandleArray[0], FDSetPtr^.fd_array[0], SocketArrayBytes);

    Select(0, FDSetPtr, nil, nil, @TimeoutValue);

    if FDSetPtr^.fd_count > 0 then
    begin
      SetLength(Result, FDSetPtr^.fd_count);
      Move(FDSetPtr^.fd_array[0], Result[0], FDSetPtr^.fd_count * SizeOf(TSocketHandle));
    end else
    begin
      SetLength(Result, 0); // This is needed with newer compilers
    end;
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
  FDArrayLen: Integer;
  FDNdx: Integer;
  ReadySockets: Integer;
  ResultNdx: Integer;
begin
  TimeoutValue.tv_sec := ATimeout div 1000;
  TimeoutValue.tv_usec := (ATimeout mod 1000) * 1000;

  // Find max socket handle
  SocketHandle := 0;

  for i := Low(ASocketHandleArray) to High(ASocketHandleArray) do
  begin
    if SocketHandle < ASocketHandleArray[i] then
    begin
      SocketHandle := ASocketHandleArray[i];
    end;
  end;

  // NFDBITS is SizeOf(fd_mask) in bits (i.e. SizeOf(fd_mask) * 8))
  FDArrayLen := SocketHandle div NFDBITS + 1;
  GetMem(FDSetPtr, FDArrayLen * SizeOf(fd_mask));
  try
    FillChar(FDSetPtr^.fds_bits[0], FDArrayLen * SizeOf(fd_mask), 0);

    for i := Low(ASocketHandleArray) to High(ASocketHandleArray) do
    begin
      SocketHandle := ASocketHandleArray[i];
      FDNdx := SocketHandle div NFDBITS;
      FDSetPtr.fds_bits[FDNdx] := FDSetPtr.fds_bits[FDNdx] or (1 shl (SocketHandle mod NFDBITS));
    end;

    ReadySockets := Select(FDArrayLen * NFDBITS, FDSetPtr, nil, nil, @TimeoutValue);

    if ReadySockets > 0 then
    begin
      SetLength(Result, ReadySockets);
      ResultNdx := 0;

      for i := Low(ASocketHandleArray) to High(ASocketHandleArray) do
      begin
        SocketHandle := ASocketHandleArray[i];
        FDNdx := SocketHandle div NFDBITS;

        if FDSetPtr.fds_bits[FDNdx] and (1 shl (SocketHandle mod NFDBITS)) <> 0 then
        begin
          Result[ResultNdx] := SocketHandle;
          ResultNdx := ResultNdx + 1;
        end;
      end;
    end else
    begin
      SetLength(Result, 0);
    end;
  finally
    FreeMem(FDSetPtr);
  end;
end;
{$ENDIF}

function ReadableAnySocket(const ASocketHandleArray: TSocketHandleArray; const ATimeout: Cardinal): Boolean;
begin
  Result := Length(Readable(ASocketHandleArray, ATimeout)) > 0;
end;

{$IFDEF MSWINDOWS}
type
  PAddrInfoW = ^TAddrInfoW;
  PPAddrInfoW = ^PAddrInfoW;

  TAddrInfoW = record
    ai_flags: Integer;
    ai_family: Integer;
    ai_socktype: Integer;
    ai_protocol: Integer;
    ai_addrlen: ULONG; // NativeUInt
    ai_canonname: PWideChar;
    ai_addr: PSOCKADDR;
    ai_next: PAddrInfoW;
  end;

  TGetAddrInfoW = function(ANodeName: PWideChar; AServiceName: PWideChar; AHints: PAddrInfoW; AResult: PPAddrInfoW): Integer; stdcall;
  TFreeAddrInfoW = procedure(ai: PAddrInfoW); stdcall;

var
  DllGetAddrInfo: TGetAddrInfoW = nil;
  DllFreeAddrInfo: TFreeAddrInfoW = nil;

procedure GetAddressInfo(ANodeName: PWideChar; AServiceName: PWideChar; AHints: PAddrInfoW; AResult: PPAddrInfoW);
var
  iRes: Integer;
begin
  if LowerCase(string(ANodeName)) = 'localhost' then
  begin
    ANodeName := '127.0.0.1';
  end;

  iRes := DllGetAddrInfo(ANodeName, AServiceName, AHints, AResult);

  if iRes <> 0 then
  begin
    raise EncLineException.Create(SysErrorMessage(iRes));
  end;
end;

procedure FreeAddressInfo(ai: PAddrInfoW);
begin
  DllFreeAddrInfo(ai);
end;
{$ENDIF}

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
{ TncLine }
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constructor TncLine.Create;
begin
  inherited Create;

  PropertyLock := TCriticalSection.Create;

  FFamily := DefaultFamily;
  FKind := DefaultKind;
  FHandle := InvalidSocket;

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
  begin
    DestroyHandle;
  end;

  FreeAndNil(PropertyLock);

  inherited Destroy;
end;

function TncLine.CreateLineObject: TncLine;
begin
  Result := TncLine.Create;
  Result.SetKind(Kind);
end;

/// /////////////////////////////////////////////////////////////////////////////

procedure TncLine.Check(ACmdRes: Integer);
begin
  if ACmdRes = SocketError then
  begin
{$IFDEF MSWINDOWS}
    raise EncLineException.Create(SysErrorMessage(WSAGetLastError));
{$ELSE}
    raise EncLineException.Create(SysErrorMessage(GetLastError));
{$ENDIF}
  end;
end;

procedure TncLine.CreateClientHandle(const AHost: string; const APort: Integer);
var
{$IFDEF MSWINDOWS}
  AHints: TAddrInfoW;
  AddrResult: PAddrInfoW;
{$ELSE}
  AHints: addrinfo;
  AddrResult: Paddrinfo;
  AnsiHost: RawByteString;
  AnsiPort: RawByteString;
{$ENDIF}
begin
  try
    FillChar(AHints, SizeOf(AHints), 0);
    AHints.ai_family := CRawAddressTypes[FFamily];
    AHints.ai_socktype := CRawSocketTypes[FKind];
    AHints.ai_protocol := CRawProtocolTypes[FKind]; // Could just be set to 0 to use default protocol for the address family

    // Resolve the server address and port
{$IFDEF MSWINDOWS}
    GetAddressInfo(PChar(AHost), PChar(IntToStr(APort)), @AHints, @AddrResult);
{$ELSE}
    AnsiHost := RawByteString(AHost);
    AnsiPort := RawByteString(IntToStr(APort));

    GetAddrInfo(MarshaledAString(AnsiHost), MarshaledAString(AnsiPort), AHints, AddrResult);
{$ENDIF}
    try
      // Create a SOCKET for connecting to server
      FHandle := Socket(AddrResult^.ai_family, AddrResult^.ai_socktype, AddrResult^.ai_protocol);
      Check(FHandle);
      try
{$IFNDEF MSWINDOWS}
        EnableReuseAddress;
{$ENDIF}
        // Connect to server
        Check(Connect(FHandle, AddrResult^.ai_addr^, AddrResult^.ai_addrlen));
        SetConnected;
      except
        DestroyHandle;
        raise;
      end;
    finally
{$IFDEF MSWINDOWS}
      FreeAddressInfo(AddrResult);
{$ELSE}
      FreeAddrInfo(AddrResult^);
{$ENDIF}
    end;
  except
    FHandle := InvalidSocket;
    raise;
  end;
end;

procedure TncLine.CreateServerHandle(const APort: Integer; const AAddress: string);
var
{$IFDEF MSWINDOWS}
  AHints: TAddrInfoW;
  AddrResult: PAddrInfoW;
{$ELSE}
  AHints: addrinfo;
  AddrResult: Paddrinfo;
  AnsiAddress: RawByteString;
  AnsiPort: RawByteString;
{$ENDIF}
begin
  FillChar(AHints, SizeOf(AHints), 0);
  AHints.ai_family := CRawAddressTypes[FFamily];
  AHints.ai_socktype := CRawSocketTypes[FKind];
  AHints.ai_protocol := CRawProtocolTypes[FKind]; // Could just be set to 0 to use default protocol for the address family

  if AAddress = '' then
  begin
    AHints.ai_flags := AI_PASSIVE; // Use default local address
  end;

  // Resolve the server address and port
{$IFDEF MSWINDOWS}
  if AAddress = '' then
  begin
    GetAddressInfo(nil, PChar(IntToStr(APort)), @AHints, @AddrResult);
  end else
  begin
    GetAddressInfo(PChar(AAddress), PChar(IntToStr(APort)), @AHints, @AddrResult);
  end;
{$ELSE}
  if AAddress = '' then
  begin
    AnsiAddress := nil;
    AnsiPort := RawByteString(IntToStr(APort));
    GetAddrInfo(nil, MarshaledAString(AnsiPort), AHints, AddrResult);
  end else
  begin
    AnsiAddress := RawByteString(AAddress);
    AnsiPort := RawByteString(IntToStr(APort));

    GetAddrInfo(MarshaledAString(AnsiAddress), MarshaledAString(AnsiPort), AHints, AddrResult);
  end;
{$ENDIF}

{$IFDEF MSWINDOWS}
{$ELSE}
{$ENDIF}
  try
    // Create a server listener socket
    FHandle := Socket(AddrResult^.ai_family, AddrResult^.ai_socktype, AddrResult^.ai_protocol);
    Check(FHandle);
    try
{$IFNDEF MSWINDOWS}
      EnableReuseAddress;
{$ENDIF}
      // Setup the listening socket
      Check(Bind(FHandle, AddrResult^.ai_addr^, AddrResult^.ai_addrlen));

      if IsConnectionBased then
      begin
        Check(Listen(FHandle, SOMAXCONN));
      end;

      SetConnected;
    except
      DestroyHandle;
      raise;
    end;
  finally
{$IFDEF MSWINDOWS}
    FreeAddressInfo(AddrResult);
{$ELSE}
    FreeAddrInfo(AddrResult^);
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
      // Ignore
    end;

    try
      SetDisconnected;
    except
      // Ignore
    end;

    FHandle := InvalidSocket;
  end;
end;

function TncLine.AcceptLine: TncLine;
var
  NewHandle: TSocketHandle;
{$IFNDEF MSWINDOWS}
  Addr: sockaddr;
  AddrLen: socklen_t;
{$ENDIF}
begin
  if IsConnectionBased then
  begin
{$IFDEF MSWINDOWS}
    NewHandle := Accept(FHandle, nil, nil);
{$ELSE}
    NewHandle := Accept(FHandle, Addr, AddrLen);
{$ENDIF}

    if NewHandle = InvalidSocket then
    begin
      Abort; // Raise silent exception
    end;

    Result := CreateLineObject;

    Result.FHandle := NewHandle;
    Result.OnConnected := OnConnected;
    Result.OnDisconnected := OnDisconnected;
    Result.SetConnected;
  end else
  begin
    Result := Self; // ???
  end;
end;

function TncLine.SendBuffer(const ABuffer; ABufferSize: Integer): Integer;
begin
  // Send all buffer in one go, the most optimal by far
  Result := Send(FHandle, ABuffer, ABufferSize, 0);
  try
    if Result = SocketError then
    begin
      Abort; // ==> Raise silent exception instead of Check
    end;

    LastSent := TStopWatch.GetTimeStamp;
  except
    DestroyHandle;
    raise;
  end;
end;

function TncLine.RecvBuffer(var ABuffer; ABufferSize: Integer): Integer;
begin
  Result := recv(FHandle, ABuffer, ABufferSize, 0);
  try
    if (Result = SocketError) or (Result = 0) then
    begin
      Abort; // ==> Raise silent exception instead of Check, something has disconnected
    end;

    LastReceived := TStopWatch.GetTimeStamp;
  except
    DestroyHandle;
    raise;
  end;
end;

procedure TncLine.EnableNoDelay;
var
  optval: Integer;
begin
  optval := 1;
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, IPPROTO_TCP, TCP_NODELAY, PAnsiChar(@optval), SizeOf(optval)));
{$ELSE}
  Check(SetSockOpt(FHandle, IPPROTO_TCP, TCP_NODELAY, optval, SizeOf(optval)));
{$ENDIF}
end;

procedure TncLine.EnableKeepAlive;
var
  optval: Integer;
begin
  optval := 1; // Non-zero indicates true
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_KEEPALIVE, PAnsiChar(@optval), SizeOf(optval)));
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
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_BROADCAST, PAnsiChar(@optval), SizeOf(optval)));
{$ELSE}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_BROADCAST, optval, SizeOf(optval)));
{$ENDIF}
end;

procedure TncLine.EnableReuseAddress;
var
  optval: Integer;
begin
  optval := 1;
{$IFDEF MSWINDOWS}
  Check(SetSockOpt(FHandle, SOL_SOCKET, SO_REUSEADDR, PAnsiChar(@optval), SizeOf(optval)));
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

function TncLine.IsConnectionBased: Boolean;
begin
  Result := FKind = stTCP;
end;

procedure TncLine.SetConnected;
var
  Addr: sockaddr;
{$IFDEF MSWINDOWS}
  AddrSize: Integer;
{$ELSE}
  AddrSize: socklen_t;
{$ENDIF}
begin
  if not FActive then
  begin
    FActive := True;

    LastSent := TStopWatch.GetTimeStamp;
    LastReceived := LastSent;

    AddrSize := SizeOf(Addr);

    if GetPeerName(FHandle, Addr, AddrSize) <> SocketError then
    begin
      // FPeerIP := IntToStr(Ord(addr.sin_addr.S_un_b.s_b1)) + '.' + IntToStr(Ord(addr.sin_addr.S_un_b.s_b2)) + '.' + IntToStr(Ord(addr.sin_addr.S_un_b.s_b3)) +
      // '.' + IntToStr(Ord(addr.sin_addr.S_un_b.s_b4));
      FPeerIP := IntToStr(Ord(Addr.sa_data[2])) + '.' +
                 IntToStr(Ord(Addr.sa_data[3])) + '.' +
                 IntToStr(Ord(Addr.sa_data[4])) + '.' +
                 IntToStr(Ord(Addr.sa_data[5]));
    end;

    if Assigned(OnConnected) then
    try
      OnConnected(Self);
    except
      // Ignore
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
      // Ignore
    end;
  end;
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

procedure TncLine.SetLastReceived(const AValue: Int64);
begin
  PropertyLock.Acquire;
  try
    FLastReceived := AValue;
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

procedure TncLine.SetLastSent(const AValue: Int64);
begin
  PropertyLock.Acquire;
  try
    FLastSent := AValue;
  finally
    PropertyLock.Release;
  end;
end;

{$IFDEF MSWINDOWS}
var
  ExtDllHandle: THandle = 0;

procedure AttachAddrInfo;

  procedure SafeLoadFrom(const ADll: string);
  begin
    if not Assigned(DllGetAddrInfo) then
    begin
      ExtDllHandle := SafeLoadLibrary(ADll);

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
  SafeLoadFrom('ws2_32.dll'); // WinSock2 dll
  SafeLoadFrom('wship6.dll'); // WshIp6 dll
end;

var
  WSAData: TWSAData;

initialization
  WSAStartup(MakeWord(2, 2), WSAData); // Require WinSock 2 version
  AttachAddrInfo;

finalization
  if ExtDllHandle <> 0 then
  begin
    FreeLibrary(ExtDllHandle);
  end;

  WSACleanup;
{$ENDIF}

end.
