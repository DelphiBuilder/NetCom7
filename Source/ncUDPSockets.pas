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
// - BoundPort
// - BoundPortMin
// - BoundPortMax
// - BoundIP
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
  DefHost = 'LocalHost';
  DefReadBufferLen = 64 * 1024; // 64KB default for UDP
  DefReaderThreadPriority = ntpNormal;
  DefEventsUseMainThread = False;
  DefUseReaderThread = True;
  DefBroadcast = False;

resourcestring
  ECannotSetPortWhileSocketActiveStr = 'Cannot set Port property while socket is active';
  ECannotSetHostWhileSocketActiveStr = 'Cannot set Host property while socket is active';
  ECannotSendWhileSocketInactiveStr = 'Cannot send data while socket is inactive';
  ECannotSetUseReaderThreadWhileSocketActiveStr = 'Cannot set UseReaderThread property while socket is active';
  ECannotReceiveIfUseReaderThreadStr = 'Cannot receive data if UseReaderThread is set. Use OnReadDatagram event handler to get the data or set UseReaderThread property to false';
  ECannotSetBoundIPWhileSocketActiveStr = 'Cannot set BoundIP property while socket is active';
  ECannotSetBoundPortWhileSocketActiveStr = 'Cannot set BoundPort property while socket is active';
  ECannotSetBoundPortMinWhileSocketActiveStr = 'Cannot set BoundPortMin property while socket is active';
  ECannotSetBoundPortMaxWhileSocketActiveStr = 'Cannot set BoundPortMax property while socket is active';

type
  EPropertySetError = class(Exception);

  // Event types for UDP
  TncOnDatagramEvent = procedure(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddr) of object;

  // Base UDP Socket class
  TncUDPBase = class(TComponent)
  private
    FInitActive: Boolean;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FBroadcast: Boolean;
    FBoundIP: string;
    FBoundPort: Integer;
    FBoundPortMin: Integer;
    FBoundPortMax: Integer;
    FReadBufferLen: Integer;
    FOnReadDatagram: TncOnDatagramEvent;
    function GetReadBufferLen: Integer;
    procedure SetReadBufferLen(const Value: Integer);
    function GetActive: Boolean; virtual; abstract;
    procedure SetActive(const Value: Boolean);
    function GetPort: Integer;
    procedure SetPort(const Value: Integer);
    function GetReaderThreadPriority: TncThreadPriority;
    procedure SetReaderThreadPriority(const Value: TncThreadPriority);
    function GetBroadcast: Boolean;
    procedure SetBroadcast(const Value: Boolean);
    function GetBoundIP: string;
    procedure SetBoundIP(const Value: string);
    function GetBoundPort: Integer;
    procedure SetBoundPort(const Value: Integer);
    function GetBoundPortMin: Integer;
    procedure SetBoundPortMin(const Value: Integer);
    function GetBoundPortMax: Integer;
    procedure SetBoundPortMax(const Value: Integer);
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
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property EventsUseMainThread: Boolean read FEventsUseMainThread write FEventsUseMainThread default DefEventsUseMainThread;
    property UseReaderThread: Boolean read FUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    property Broadcast: Boolean read GetBroadcast write SetBroadcast default DefBroadcast;
    property BoundIP: string read GetBoundIP write SetBoundIP;
    property BoundPort: Integer read GetBoundPort write SetBoundPort default 0;
    property BoundPortMin: Integer read GetBoundPortMin write SetBoundPortMin default 0;
    property BoundPortMax: Integer read GetBoundPortMax write SetBoundPortMax default 0;
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
    procedure SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddr); overload;
    procedure SendTo(const aBytes: TBytes; const DestAddr: TSockAddr); overload;
    procedure SendTo(const aStr: string; const DestAddr: TSockAddr); overload;
    procedure Send(const aBuf; aBufSize: Integer); overload;
    procedure Send(const aBytes: TBytes); overload;
    procedure Send(const aStr: string); overload;
    function Receive(aTimeout: Cardinal = 2000): TBytes;
    property Host: string read GetHost write SetHost;
    procedure SetActualBoundPort(const Value: Integer);
  end;

  TncUDPClient = class(TncCustomUDPClient)
  published
    property Active;
    property Port;
    property Host;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property Broadcast;
    property BoundIP;
    property BoundPort;
    property BoundPortMin;
    property BoundPortMax;
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
    procedure SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddr); overload;
    procedure SendTo(const aBytes: TBytes; const DestAddr: TSockAddr); overload;
    procedure SendTo(const aStr: string; const DestAddr: TSockAddr); overload;
    function Receive(aTimeout: Cardinal = 2000): TBytes;
  end;

  TncUDPServer = class(TncCustomUDPServer)
  published
    property Active;
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
  FPort := DefPort;
  FEventsUseMainThread := DefEventsUseMainThread;
  FUseReaderThread := DefUseReaderThread;
  FBroadcast := DefBroadcast;
  FBoundIP := '';
  FBoundPort := 0;
  FBoundPortMin := 0;
  FBoundPortMax := 0;
  FReadBufferLen := DefReadBufferLen;
  FOnReadDatagram := nil;

  SetLength(ReadBuf, DefReadBufferLen);
end;

destructor TncUDPBase.Destroy;
begin
  PropertyLock.Free;
  inherited Destroy;
end;

function TncUDPBase.Kind: TSocketType;
begin
  Result := stUDP;
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

function TncUDPBase.GetBoundIP: string;
begin
  PropertyLock.Acquire;
  try
    Result := FBoundIP;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetBoundIP(const Value: string);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetBoundIPWhileSocketActiveStr);

  PropertyLock.Acquire;
  try
    FBoundIP := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncUDPBase.GetBoundPort: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FBoundPort;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetBoundPort(const Value: Integer);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetBoundPortWhileSocketActiveStr);
  PropertyLock.Acquire;
  try
    FBoundPort := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncUDPBase.GetBoundPortMin: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FBoundPortMin;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetBoundPortMin(const Value: Integer);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetBoundPortMinWhileSocketActiveStr);

  PropertyLock.Acquire;
  try
    FBoundPortMin := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncUDPBase.GetBoundPortMax: Integer;
begin
  PropertyLock.Acquire;
  try
    Result := FBoundPortMax;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncUDPBase.SetBoundPortMax(const Value: Integer);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetBoundPortMaxWhileSocketActiveStr);

  PropertyLock.Acquire;
  try
    FBoundPortMax := Value;
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
var
  boundPort: Integer;
  retryCount: Integer;
  success: Boolean;
begin
  // Exit if socket is already in requested state
  if aActivate = GetActive then
    Exit;

  if aActivate then
  begin
    try
      // First handle socket binding if specified
      if (GetBoundPort > 0) or (GetBoundIP <> '') or
         ((GetBoundPortMin > 0) and (GetBoundPortMax > 0)) then
      begin
        success := False;
        retryCount := 0;

        while (not success) and
              (GetBoundPortMin + retryCount <= GetBoundPortMax) do
        begin
          try
            // Try binding using port range if specified
            if (GetBoundPortMin > 0) and (GetBoundPortMax > 0) then
            begin
              // Attempt to bind to current port in range
              TncLineInternal(Line).TryBindRange(GetBoundIP,
                GetBoundPortMin + retryCount, GetBoundPortMax, boundPort);
              // Update BoundPort to reflect actual bound port
              SetBoundPort(boundPort);
            end
            // Otherwise try binding to specific port
            else if GetBoundPort > 0 then
            begin
              TncLineInternal(Line).BindTo(GetBoundIP, GetBoundPort);
            end;

            // Create socket handle and establish connection
            TncLineInternal(Line).CreateClientHandle(FHost, FPort, GetBroadcast);
            success := True;

          except
            on E: Exception do
            begin
              if E.Message = 'Retrying with next port in range' then
              begin
                Inc(retryCount);
                if GetBoundPortMin + retryCount <= GetBoundPortMax then
                  Continue
                else
                  raise Exception.Create('Failed to bind - all ports in range are in use');
              end
              else
                raise;
            end;
          end;
        end;

        if not success then
          raise Exception.Create('Failed to bind to any port in range');
      end
      else
      begin
        // If no binding requested, just create the socket
        TncLineInternal(Line).CreateClientHandle(FHost, FPort, GetBroadcast);
      end;

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

procedure TncCustomUDPClient.SetActualBoundPort(const Value: Integer);
begin
  PropertyLock.Acquire;
  try
    FBoundPort := Value;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomUDPClient.Send(const aBuf; aBufSize: Integer);
var
  addr: TSockAddr;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  if GetBroadcast then
  begin
    // Setup broadcast address
    FillChar(addr, SizeOf(addr), 0);
    addr.sa_family := AF_INET;

    // Set port
    addr.sa_data[0] := AnsiChar(FPort div 256);
    addr.sa_data[1] := AnsiChar(FPort mod 256);

    // Set broadcast address from Host property
    var ipParts := FHost.Split(['.']);
    if Length(ipParts) = 4 then
    begin
      addr.sa_data[2] := AnsiChar(StrToInt(ipParts[0]));
      addr.sa_data[3] := AnsiChar(StrToInt(ipParts[1]));
      addr.sa_data[4] := AnsiChar(StrToInt(ipParts[2]));
      addr.sa_data[5] := AnsiChar(StrToInt(ipParts[3]));
    end;

    SendTo(aBuf, aBufSize, addr);
  end
  else
    TncLineInternal(Line).SendBuffer(aBuf, aBufSize);
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

procedure TncCustomUDPClient.SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddr);
{$IFDEF MSWINDOWS}
var
  BytesSent: Integer;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  BytesSent := Winapi.Winsock2.sendto(Line.Handle, aBuf, aBufSize, 0, @DestAddr, SizeOf(TSockAddr));
  if BytesSent = SOCKET_ERROR then
    raise Exception.Create(SysErrorMessage(WSAGetLastError));
{$ELSE}
var
  BytesSent: ssize_t;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  BytesSent := Posix.SysSocket.sendto(Line.Handle, @aBuf, aBufSize, 0, @DestAddr, SizeOf(TSockAddr));
  if BytesSent < 0 then
    raise Exception.Create(SysErrorMessage(GetLastError));
{$ENDIF}
end;

procedure TncCustomUDPClient.SendTo(const aBytes: TBytes; const DestAddr: TSockAddr);
begin
  if Length(aBytes) > 0 then
    SendTo(aBytes[0], Length(aBytes), DestAddr);
end;

procedure TncCustomUDPClient.SendTo(const aStr: string; const DestAddr: TSockAddr);
begin
  SendTo(BytesOf(aStr), DestAddr);
end;

function TncCustomUDPClient.Receive(aTimeout: Cardinal = 2000): TBytes;
var
  BufRead: Integer;
  SenderAddr: TSockAddr;
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

  SenderAddrLen := SizeOf(SenderAddr);
  BufRead := recvfrom(Line.Handle, ReadBuf[0], Length(ReadBuf), 0, SenderAddr, SenderAddrLen);

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
  SenderAddr: TSockAddr;
  SenderAddrLen: Integer;
begin
  SenderAddrLen := SizeOf(SenderAddr);
  BufRead := recvfrom(FClientSocket.Line.Handle, FClientSocket.ReadBuf[0],
    Length(FClientSocket.ReadBuf), 0, SenderAddr, SenderAddrLen);

  if (BufRead > 0) and Assigned(FClientSocket.OnReadDatagram) then
    try
      FClientSocket.OnReadDatagram(FClientSocket, FClientSocket.Line,
        FClientSocket.ReadBuf, BufRead, SenderAddr);
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

procedure TncCustomUDPServer.SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddr);
{$IFDEF MSWINDOWS}
var
  BytesSent: Integer;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  BytesSent := Winapi.Winsock2.sendto(Line.Handle, aBuf, aBufSize, 0, @DestAddr, SizeOf(TSockAddr));
  if BytesSent = SOCKET_ERROR then
    raise Exception.Create(SysErrorMessage(WSAGetLastError));
{$ELSE}
var
  BytesSent: ssize_t;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  BytesSent := Posix.SysSocket.sendto(Line.Handle, @aBuf, aBufSize, 0, @DestAddr, SizeOf(TSockAddr));
  if BytesSent < 0 then
    raise Exception.Create(SysErrorMessage(GetLastError));
{$ENDIF}
end;

procedure TncCustomUDPServer.SendTo(const aBytes: TBytes; const DestAddr: TSockAddr);
begin
  if Length(aBytes) > 0 then
    SendTo(aBytes[0], Length(aBytes), DestAddr);
end;

procedure TncCustomUDPServer.SendTo(const aStr: string; const DestAddr: TSockAddr);
begin
  SendTo(BytesOf(aStr), DestAddr);
end;

function TncCustomUDPServer.Receive(aTimeout: Cardinal = 2000): TBytes;
var
  BufRead: Integer;
  SenderAddr: TSockAddr;
  SenderAddrLen: Integer;
begin
  if UseReaderThread then
    raise Exception.Create(ECannotReceiveIfUseReaderThreadStr);

  if not ReadableAnySocket(ReadSocketHandles, aTimeout) then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  SenderAddrLen := SizeOf(SenderAddr);
  BufRead := recvfrom(Line.Handle, ReadBuf[0], Length(ReadBuf), 0, SenderAddr, SenderAddrLen);

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
  SenderAddr: TSockAddr;
  SenderAddrLen: Integer;
begin
  SenderAddrLen := SizeOf(SenderAddr);
  BufRead := recvfrom(FServerSocket.Line.Handle, FServerSocket.ReadBuf[0],
    Length(FServerSocket.ReadBuf), 0, SenderAddr, SenderAddrLen);

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

