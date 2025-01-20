unit ncUDPSockets;
// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package - UDP Socket Components
//
// This unit implements UDP Server and UDP Client components
//
// 14/1/2025
// - Initial creation
// Currently implemented :
// - Broadcast
//
// Written by J.Pauwels
//
// /////////////////////////////////////////////////////////////////////////////

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
  System.Classes, System.SysUtils, System.SyncObjs, System.Math, System.Diagnostics, System.TimeSpan,
  ncLines, ncSocketList, ncThreads;

const
  DefPort = 16233;
  DefHost = '';
  DefReadBufferLen = 64 * 1024; // 64KB default for UDP
  DefReaderThreadPriority = ntpNormal;
  DefEventsUseMainThread = False;
  DefUseReaderThread = True;
  DefBroadcast = False;
  DefFamily = afIPv4;

resourcestring
  ECannotSetPortWhileSocketActiveStr = 'Cannot set Port property while socket is active';
  ECannotSetHostWhileSocketActiveStr = 'Cannot set Host property while socket is active';
  ECannotSendWhileSocketInactiveStr = 'Cannot send data while socket is inactive';
  ECannotSetUseReaderThreadWhileSocketActiveStr = 'Cannot set UseReaderThread property while socket is active';
  ECannotReceiveIfUseReaderThreadStr = 'Cannot receive data if UseReaderThread is set. Use OnReadDatagram event handler to get the data or set UseReaderThread property to false';
  ECannotSetFamilyWhileConnectionIsActiveStr = 'Cannot set Family property whilst the connection is active';
type
  EPropertySetError = class(Exception);

  // Event types for UDP
  TncOnDatagramEvent = procedure(Sender: TObject; aLine: TncLine;const aBuf: TBytes; aBufCount: Integer;const SenderAddr: TSockAddrStorage) of object;


  // Base UDP Socket class
  TncUDPBase = class(TComponent)
  private
    FInitActive: Boolean;
    FFamily: TAddressType;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FBroadcast: Boolean;
    FLine: TncLine;
    FReadBufferLen: Integer;
    FOnReadDatagram: TncOnDatagramEvent;
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
    function GetBroadcast: Boolean;
    procedure SetBroadcast(const Value: Boolean);

  private
    FUseReaderThread: Boolean;
    procedure DoActivate(aActivate: Boolean); virtual; abstract;
    procedure SetUseReaderThread(const Value: Boolean);
  protected
    PropertyLock: TCriticalSection;
    ReadBuf: TBytes;
    procedure Loaded; override;
    function CreateLineObject: TncLine; virtual;
    function GetLine: TncLine; virtual; abstract;
  public
    LineProcessor: TncReadyThread;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function Kind: TSocketType; virtual;

    property Active: Boolean read GetActive write SetActive default False;
    property Family: TAddressType read GetFamily write SetFamily default afIPv4;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property EventsUseMainThread: Boolean read FEventsUseMainThread write FEventsUseMainThread default DefEventsUseMainThread;
    property UseReaderThread: Boolean read FUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    property Broadcast: Boolean read GetBroadcast write SetBroadcast default DefBroadcast;
    property OnReadDatagram: TncOnDatagramEvent read FOnReadDatagram write FOnReadDatagram;
    property ReadBufferLen: Integer read GetReadBufferLen write SetReadBufferLen default DefReadBufferLen;
  published
  end;

  // UDP Client implementation
  TncUDPClientProcessor = class;

  TncCustomUDPClient = class(TncUDPBase)
  private
    FHost: string;
    function GetActive: Boolean; override;
    procedure SetHost(const Value: string);
    function GetHost: string;
  protected
    procedure DoActivate(aActivate: Boolean); override;
    function GetLine: TncLine; override;
  public
    ReadSocketHandles: TSocketHandleArray;
    Line: TncLine;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aBytes: TBytes;const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aStr: string; const DestAddr: TSockAddrStorage); overload;
    procedure Send(const aBuf; aBufSize: Integer); overload;
    procedure Send(const aBytes: TBytes); overload;
    procedure Send(const aStr: string); overload;
    function Receive(aTimeout: Cardinal = 2000): TBytes;
    property Host: string read GetHost write SetHost;
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
    property ReadBufferLen;
    property OnReadDatagram;
  end;

  TncUDPClientProcessor = class(TncReadyThread)
  private
    FClientSocket: TncCustomUDPClient;
  public
    ReadySocketsChanged: Boolean;
    constructor Create(aClientSocket: TncCustomUDPClient);
    procedure ProcessDatagram; inline;
    procedure ProcessEvent; override;
  end;

  // UDP Server implementation
  TncUDPServerProcessor = class;

  TncCustomUDPServer = class(TncUDPBase)
  private
    function GetActive: Boolean; override;
  protected
    procedure DoActivate(aActivate: Boolean); override;
    function GetLine: TncLine; override;
  public
    ReadSocketHandles: TSocketHandleArray;
    Line: TncLine;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aBytes: TBytes;const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aStr: string; const DestAddr: TSockAddrStorage); overload;
    function Receive(aTimeout: Cardinal = 2000): TBytes;
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
    property ReadBufferLen;
    property OnReadDatagram;
  end;

  TncUDPServerProcessor = class(TncReadyThread)
  private
    FServerSocket: TncCustomUDPServer;
  public
    ReadySockets: TSocketHandleArray;
    ReadySocketsChanged: Boolean;
    constructor Create(aServerSocket: TncCustomUDPServer);
    procedure ProcessDatagram; inline;
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

{ TncUDPBase }

constructor TncUDPBase.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  PropertyLock := TCriticalSection.Create;

  FInitActive := False;
  FFamily := DefFamily;
  FPort := DefPort;
  FEventsUseMainThread := DefEventsUseMainThread;
  FUseReaderThread := DefUseReaderThread;
  FBroadcast := DefBroadcast;
  FReadBufferLen := DefReadBufferLen;
  FOnReadDatagram := nil;

  SetLength(ReadBuf, DefReadBufferLen);

end;

function TncUDPBase.Kind: TSocketType;
begin
  Result := stUDP;
end;

destructor TncUDPBase.Destroy;
begin
  PropertyLock.Free;
  inherited Destroy;
end;

procedure TncUDPBase.Loaded;
begin
  inherited Loaded;
  if FInitActive then
    DoActivate(True);
end;

function TncUDPBase.CreateLineObject: TncLine;
begin
  Result := TncLine.Create;
  TncLineInternal(Result).SetKind(Kind);
  TncLineInternal(Result).SetFamily(FFamily);
end;

procedure TncUDPBase.SetActive(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    if not(csLoading in ComponentState) then
      DoActivate(Value);
    FInitActive := GetActive;
  finally
    PropertyLock.Release;
  end;
end;

function TncUDPBase.GetFamily: TAddressType;
begin
  PropertyLock.Acquire;
  try
    Result := FFamily;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetFamily(const Value: TAddressType);
begin
  if not(csLoading in ComponentState) then
  begin
    if Active then
      raise EPropertySetError.Create
        (ECannotSetFamilyWhileConnectionIsActiveStr);
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

function TncUDPBase.GetPort: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FPort;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetPort(const Value: Integer);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetPortWhileSocketActiveStr);

  PropertyLock.Acquire;
  try
    FPort := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncUDPBase.GetReaderThreadPriority: TncThreadPriority;
begin
  PropertyLock.Acquire;
  try
    Result := ToNcThreadPriority(LineProcessor.Priority);
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetReaderThreadPriority(const Value: TncThreadPriority);
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

function TncUDPBase.GetBroadcast: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FBroadcast;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetBroadcast(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FBroadcast := Value;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetUseReaderThread(const Value: Boolean);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetUseReaderThreadWhileSocketActiveStr);

  PropertyLock.Acquire;
  try
    FUseReaderThread := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncUDPBase.GetReadBufferLen: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FReadBufferLen;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetReadBufferLen(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FReadBufferLen := Value;
    SetLength(ReadBuf, FReadBufferLen);
  finally
    PropertyLock.Release;
  end;
end;

{ TncCustomUDPClient }

constructor TncCustomUDPClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FHost := DefHost;

  Line := CreateLineObject;

  // Create Line with correct family
  Line := CreateLineObject;
  if Line.Family <> FFamily then
  begin
    TncLineInternal(Line).SetFamily(FFamily);
  end;

  LineProcessor := TncUDPClientProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
end;

destructor TncCustomUDPClient.Destroy;
begin
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Line.Free;

  inherited Destroy;
end;

function TncCustomUDPClient.GetLine: TncLine;
begin
  Result := Line;
end;

procedure TncCustomUDPClient.DoActivate(aActivate: Boolean);
begin
  // Exit if socket is already in requested state
  if aActivate = GetActive then
    Exit;

  if aActivate then
  begin
    try

    // Verify family setting before creating handle
    if Line.Family <> FFamily then
    begin
      TncLineInternal(Line).SetFamily(FFamily);
    end;

      // Create socket handle and establish connection
      TncLineInternal(Line).CreateClientHandle(FHost, FPort, GetBroadcast);

      // Enable broadcast mode if requested
      if GetBroadcast then
        TncLineInternal(Line).EnableBroadcast;

      // Configure socket buffer sizes for optimal performance
      try
        TncLineInternal(Line).SetReceiveSize(GetReadBufferLen);
        TncLineInternal(Line).SetWriteSize(GetReadBufferLen);
      except
        on E: Exception do
        begin
          TncLineInternal(Line).DestroyHandle;
          raise;
        end;
      end;

      // Initialize socket handle array for reading
      SetLength(ReadSocketHandles, 1);
      ReadSocketHandles[0] := Line.Handle;

      // Start reader thread if enabled
      if UseReaderThread then
        LineProcessor.Run;
    except
      on E: Exception do
      begin
        // Clean up on activation failure
        TncLineInternal(Line).DestroyHandle;
        SetLength(ReadSocketHandles, 0);
        raise;
      end;
    end;
  end
  else
  begin
    // Clean up when deactivating
    TncLineInternal(Line).DestroyHandle;
    SetLength(ReadSocketHandles, 0);
  end;
end;

function TncCustomUDPClient.GetActive: Boolean;
begin
  Result := Line.Active;
end;

function TncCustomUDPClient.GetHost: string;
begin
  PropertyLock.Acquire;
  try
    Result := FHost;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomUDPClient.SetHost(const Value: string);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetHostWhileSocketActiveStr);

  PropertyLock.Acquire;
  try
    FHost := Value;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomUDPClient.Send(const aBuf; aBufSize: Integer);
var
  storage: TSockAddrStorage;
  addrV4: PSockAddrIn;
  addrV6: PSockAddrIn6;
  ipv6Addr: TIn6Addr;
  ipParts: TArray<string>;
  scope: string;
  scopeID: Cardinal;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  case Family of
    afIPv4:
      begin
        if GetBroadcast then
        begin
          FillChar(storage, SizeOf(storage), 0);
          storage.ss_family := AF_INET;

          // Cast to sockaddr_in structure for IPv4
          addrV4 := PSockAddrIn(@storage);
          addrV4^.sin_family := AF_INET;
          addrV4^.sin_port := htons(FPort);

          // Parse IPv4 address
          ipParts := FHost.Split(['.']);
          if Length(ipParts) = 4 then
          begin
            var addr := inet_addr(PAnsiChar(AnsiString(FHost)));
            if addr <> INADDR_NONE then
              addrV4^.sin_addr.S_addr := addr
            else
              raise Exception.Create('Invalid IPv4 address format');
          end;

          SendTo(aBuf, aBufSize, storage);
        end
        else
          TncLineInternal(Line).SendBuffer(aBuf, aBufSize);
      end;

    afIPv6:
      begin
        if GetBroadcast then
          raise Exception.Create('Broadcast is not supported in IPv6. Use multicast instead.')
        else if FHost = '' then
          raise Exception.Create('Host address cannot be empty for IPv6')
        else
        begin
          FillChar(storage, SizeOf(storage), 0);
          storage.ss_family := AF_INET6;

          // Cast to sockaddr_in6 structure for IPv6
          addrV6 := PSockAddrIn6(@storage);
          addrV6^.sin6_family := AF_INET6;
          addrV6^.sin6_port := htons(FPort);

          // Handle scope ID for link-local addresses
          scope := '';
          scopeID := 0;
          var hostAddr := FHost;

          // Check for scope ID in address (format: address%scope)
          var scopePos := Pos('%', FHost);
          if scopePos > 0 then
          begin
            hostAddr := Copy(FHost, 1, scopePos - 1);
            scope := Copy(FHost, scopePos + 1, Length(FHost));
            if TryStrToUInt(scope, scopeID) then
              addrV6^.sin6_scope_id := scopeID
            else
              raise Exception.Create('Invalid IPv6 scope ID');
          end;

          // Convert string address to IPv6 binary format
          if inet_pton(AF_INET6, PAnsiChar(AnsiString(hostAddr)), @ipv6Addr) = 1 then
          begin
            addrV6^.sin6_addr := ipv6Addr;
            SendTo(aBuf, aBufSize, storage);
          end
          else
            raise Exception.Create('Invalid IPv6 address format');
        end;
      end;
  end;
end;

procedure TncCustomUDPClient.Send(const aBytes: TBytes);
begin
  if Length(aBytes) > 0 then
    Send(aBytes[0], Length(aBytes));
end;

procedure TncCustomUDPClient.Send(const aStr: string);
begin
  Send(BytesOf(aStr));
end;

// 1. Base SendTo that does the actual sending
procedure TncCustomUDPClient.SendTo(const aBuf; aBufSize: Integer;
  const DestAddr: TSockAddrStorage);
var
  AddrLen: Integer;
{$IFDEF MSWINDOWS}
  BytesSent: Integer;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  // Set proper address length based on family
  case DestAddr.ss_family of
    AF_INET: AddrLen := SizeOf(TSockAddr);
    AF_INET6: AddrLen := SizeOf(TSockAddrIn6);
  else
    AddrLen := SizeOf(TSockAddrStorage);
  end;

  BytesSent := Winapi.Winsock2.sendto(Line.Handle, aBuf, aBufSize, 0,
    Psockaddr(@DestAddr), AddrLen);

  if BytesSent = SOCKET_ERROR then
    raise Exception.Create(SysErrorMessage(WSAGetLastError));
{$ELSE}
  BytesSent: ssize_t;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  // Set proper address length based on family
  case DestAddr.ss_family of
    AF_INET: AddrLen := SizeOf(TSockAddr);
    AF_INET6: AddrLen := SizeOf(TSockAddrIn6);
  else
    AddrLen := SizeOf(TSockAddrStorage);
  end;

  BytesSent := Posix.SysSocket.sendto(Line.Handle, @aBuf, aBufSize, 0,
    Psockaddr(@DestAddr), AddrLen);

  if BytesSent < 0 then
    raise Exception.Create(SysErrorMessage(GetLastError));
{$ENDIF}
end;

// 2. SendTo for byte arrays
procedure TncCustomUDPClient.SendTo(const aBytes: TBytes;
  const DestAddr: TSockAddrStorage);
begin
  if Length(aBytes) > 0 then
    SendTo(aBytes[0], Length(aBytes), DestAddr);
end;

// 3. SendTo for strings
procedure TncCustomUDPClient.SendTo(const aStr: string; const DestAddr: TSockAddrStorage);
var
  bytes: TBytes;
  len: Integer;
begin
  bytes := BytesOf(aStr);
  len := Length(bytes);
  if len > 0 then
    SendTo(bytes[0], len, DestAddr);
end;

// Update Receive function
function TncCustomUDPClient.Receive(aTimeout: Cardinal = 2000): TBytes;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
begin
  if UseReaderThread then
    raise Exception.Create(ECannotReceiveIfUseReaderThreadStr);

  Active := True;

  if not ReadableAnySocket([Line.Handle], aTimeout) then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  BufRead := recvfrom(Line.Handle, ReadBuf[0], Length(ReadBuf), 0,
    PSockAddr(@SenderAddr)^, SenderAddrLen);

  if BufRead > 0 then
    Result := Copy(ReadBuf, 0, BufRead)
  else
    SetLength(Result, 0);
end;

{ TncUDPClientProcessor }

constructor TncUDPClientProcessor.Create(aClientSocket: TncCustomUDPClient);
begin
  FClientSocket := aClientSocket;
  ReadySocketsChanged := False;
  inherited Create;
end;

procedure TncUDPClientProcessor.ProcessDatagram;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
begin
  // Initialize sender address structure
  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  // Receive datagram with proper address structure
  BufRead := recvfrom(FClientSocket.Line.Handle,
    FClientSocket.ReadBuf[0],
    Length(FClientSocket.ReadBuf),
    0,
    PSockAddr(@SenderAddr)^,
    SenderAddrLen);

  if (BufRead > 0) and Assigned(FClientSocket.OnReadDatagram) then
    try
      FClientSocket.OnReadDatagram(FClientSocket,
        FClientSocket.Line,
        FClientSocket.ReadBuf,
        BufRead,
        SenderAddr);
    except
    end;
end;

procedure TncUDPClientProcessor.ProcessEvent;
begin
  while (not Terminated) do
    try
      if FClientSocket.Line.Active then
      begin
        if ReadableAnySocket(FClientSocket.ReadSocketHandles, 100) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          if FClientSocket.EventsUseMainThread then
            Synchronize(ProcessDatagram)
          else
            ProcessDatagram;
        end;
      end
      else
        Exit;
    except
      // Continue processing even after errors
    end;
end;

{ TncCustomUDPServer }

constructor TncCustomUDPServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  Line := CreateLineObject;

  // Create Line with correct family
  Line := CreateLineObject;
  if Line.Family <> FFamily then
  begin
    TncLineInternal(Line).SetFamily(FFamily);
  end;

  LineProcessor := TncUDPServerProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
end;

destructor TncCustomUDPServer.Destroy;
begin
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Line.Free;

  inherited Destroy;
end;

function TncCustomUDPServer.GetLine: TncLine;
begin
  Result := Line;
end;

function TncCustomUDPServer.GetActive: Boolean;
begin
  Result := Line.Active;
end;

procedure TncCustomUDPServer.DoActivate(aActivate: Boolean);
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

    // CreateServerHandle will bind to all interfaces (0.0.0.0)
    // through the AI_PASSIVE flag in ncLines.CreateServerHandle
    TncLineInternal(Line).CreateServerHandle(FPort);

    // Enable broadcast if needed
    if Broadcast then
      TncLineInternal(Line).EnableBroadcast;

    // Set socket buffer sizes for better performance
    try
      TncLineInternal(Line).SetReceiveSize(ReadBufferLen);
      TncLineInternal(Line).SetWriteSize(ReadBufferLen);
    except
      // Ignore buffer size errors
    end;

    SetLength(ReadSocketHandles, 1);
    ReadSocketHandles[0] := Line.Handle;

    if UseReaderThread then
    begin
      LineProcessor.WaitForReady;
      LineProcessor.Run;
    end;
  end
  else
  begin
    TncLineInternal(Line).DestroyHandle;
    SetLength(ReadSocketHandles, 0);
  end;
end;


procedure TncCustomUDPServer.SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddrStorage);
var
  AddrLen: Integer;
{$IFDEF MSWINDOWS}
  BytesSent: Integer;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  // Set proper address length based on family
  case DestAddr.ss_family of
    AF_INET: AddrLen := SizeOf(TSockAddr);
    AF_INET6: AddrLen := SizeOf(TSockAddrIn6);
  else
    AddrLen := SizeOf(TSockAddrStorage);
  end;

  BytesSent := Winapi.Winsock2.sendto(Line.Handle, aBuf, aBufSize, 0,
    Psockaddr(@DestAddr), AddrLen);

  if BytesSent = SOCKET_ERROR then
    raise Exception.Create(SysErrorMessage(WSAGetLastError));
{$ELSE}
  BytesSent: ssize_t;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  // Set proper address length based on family
  case DestAddr.ss_family of
    AF_INET: AddrLen := SizeOf(TSockAddr);
    AF_INET6: AddrLen := SizeOf(TSockAddrIn6);
  else
    AddrLen := SizeOf(TSockAddrStorage);
  end;

  BytesSent := Posix.SysSocket.sendto(Line.Handle, @aBuf, aBufSize, 0,
    Psockaddr(@DestAddr), AddrLen);

  if BytesSent < 0 then
    raise Exception.Create(SysErrorMessage(GetLastError));
{$ENDIF}
end;

procedure TncCustomUDPServer.SendTo(const aBytes: TBytes; const DestAddr: TSockAddrStorage);
begin
  if Length(aBytes) > 0 then
    SendTo(aBytes[0], Length(aBytes), DestAddr);
end;

procedure TncCustomUDPServer.SendTo(const aStr: string; const DestAddr: TSockAddrStorage);
var
  bytes: TBytes;
  len: Integer;
begin
  bytes := BytesOf(aStr);
  len := Length(bytes);
  if len > 0 then
    SendTo(bytes[0], len, DestAddr);
end;

function TncCustomUDPServer.Receive(aTimeout: Cardinal = 2000): TBytes;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
begin
  if UseReaderThread then
    raise Exception.Create(ECannotReceiveIfUseReaderThreadStr);

  if not ReadableAnySocket(ReadSocketHandles, aTimeout) then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  BufRead := recvfrom(Line.Handle, ReadBuf[0], Length(ReadBuf), 0,
    PSockAddr(@SenderAddr)^, SenderAddrLen);

  if BufRead > 0 then
    Result := Copy(ReadBuf, 0, BufRead)
  else
    SetLength(Result, 0);
end;

{ TncUDPServerProcessor }

constructor TncUDPServerProcessor.Create(aServerSocket: TncCustomUDPServer);
begin
  FServerSocket := aServerSocket;
  ReadySocketsChanged := False;
  inherited Create;
end;


procedure TncUDPServerProcessor.ProcessDatagram;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
begin
  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  BufRead := recvfrom(FServerSocket.Line.Handle,
    FServerSocket.ReadBuf[0],
    Length(FServerSocket.ReadBuf),
    0,
    PSockAddr(@SenderAddr)^,
    SenderAddrLen);

  if (BufRead > 0) and Assigned(FServerSocket.OnReadDatagram) then
    try
      FServerSocket.OnReadDatagram(FServerSocket, FServerSocket.Line,
        FServerSocket.ReadBuf, BufRead, SenderAddr);
    except
    end;
end;

procedure TncUDPServerProcessor.ProcessEvent;
begin
  if FServerSocket.EventsUseMainThread then
    while FServerSocket.Active and (not Terminated) do
      try
        if ReadableAnySocket(FServerSocket.ReadSocketHandles, 500) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          Synchronize(ProcessDatagram);
        end;
      except
      end
  else
    while FServerSocket.Active and (not Terminated) do
      try
        if ReadableAnySocket(FServerSocket.ReadSocketHandles, 500) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          ProcessDatagram;
        end;
      except
      end;
end;

end.

