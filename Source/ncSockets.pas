unit ncSockets;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
// 16 Dec 2010
// Written by Demos Bill
//
// This unit implements a TncLine, which is all the WinSock API commands for a socket, organised in
// an object which contains the handle of the socket, and also makes sure it checks every API command
// for errors
// It then creates a TCP Server and TCP Client socket, along with their threads dealing with reading
// from the socket
//
// This unit exposes the HostByName which is a newer feature of WinSock and was not included
// in standard Delphi's WinSock.pas
//
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }
{$WARN SYMBOL_PLATFORM OFF}

interface

  uses
    Windows, Classes, SysUtils, SyncObjs, WinSock, ncThreads, ncIntList, RTLConsts, Math;

  const
    DefPort = 16233;
    DefHost = 'LocalHost';
    DefReadBufferLen = 1024 * 1024; // 1 MB
    DefReaderThreadPriority = tpNormal;
    DefCntReconnectInterval = 1000;

  const
    // Flag that indicates that the socket is intended for bind() + listen() when constructing it
    AI_PASSIVE = 1;
    AF_INET6 = 23;

  const
    FD_SETSIZE = 1024 * 64;

  type
    PFDSet = ^TFDSet;

    TFDSet = record
      fd_count: u_int;
      fd_array: array [0 .. FD_SETSIZE - 1] of TSocket;
    end;

  type
    TncLineException = class(Exception)
    end;

    TncLineOnConnectDisconnect = procedure(Sender: TObject) of object;

    PAddrInfo = ^TAddrInfo;
    PPAddrInfo = ^PAddrInfo;

    TAddrInfo = record
      ai_flags: Integer;
      ai_family: Integer;
      ai_socktype: Integer;
      ai_protocol: Integer;
      ai_addrlen: ULONG;
      ai_canonname: PAnsiChar;
      ai_addr: PSOCKADDR;
      ai_next: PAddrInfo;
    end;

    TncLine = class;

    // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // TncLine
    // Bring in all functionality from WinSock API, with appropriate exception raising on errors

    TncLine = class(TObject)
    private
      FActive: Boolean;
      FLastSent: Cardinal;
      FLastReceived: Cardinal;
      FPeerIP: string;
      FDataObject: TObject;
      FOnConnected: TncLineOnConnectDisconnect;
      FOnDisconnected: TncLineOnConnectDisconnect;
      function GetActive: Boolean;
      function GetLastSent: Cardinal;
      procedure SetLastSent(const Value: Cardinal);
      function GetLastReceived: Cardinal;
      procedure SetLastReceived(const Value: Cardinal);
      function GetPeerIP: string;
    private
      PropertyLock: TCriticalSection;
      LastTimeStampLock: TCriticalSection;
      procedure Check(aCmdRes: Integer); inline;
      procedure SetConnected;
      procedure SetDisconnected;
      function GetDataObject: TObject;
      procedure SetDataObject(const Value: TObject);
    protected
      procedure CreateHandle(aFamily, aSocketType, aProtocol: Integer); inline;
      procedure DestroyHandle; inline;

      function CreateLineObject: TncLine; virtual;

      procedure Connect(var name: TSockAddr; namelen: Integer); inline;
      function Accept(addr: PSOCKADDR; addrlen: PInteger): TncLine; inline;

      function Send(var Buf; len, flags: Integer): Integer; inline;
      function Recv(var Buf; len, flags: Integer): Integer;

      // Bind and Listen do not require Shutdown
      procedure Bind(var addr: TSockAddr; namelen: Integer); inline;
      procedure Listen(backlog: Integer); inline;

      function GetSockOpt(level, optname: Integer; optval: PAnsiChar; var optlen: Integer): Integer; inline;
      function SetSockOpt(level, optname: Integer; optval: PAnsiChar; optlen: Integer): Integer; inline;

      // function ioctlsocket(s: TSocket; cmd: DWORD; var arg: u_long): Integer;
      // function getpeername(s: TSocket; var name: TSockAddr; var namelen: Integer): Integer;
      // function getsockname(s: TSocket; var name: TSockAddr; var namelen: Integer): Integer;
      // function recvfrom(s: TSocket; var Buf; len, flags: Integer;
      // var from: TSockAddr; var fromlen: Integer): Integer;
      // function sendto(s: TSocket; var Buf; len, flags: Integer; var addrto: TSockAddr;
      // tolen: Integer): Integer;

      property OnConnected: TncLineOnConnectDisconnect read FOnConnected write FOnConnected;
      property OnDisconnected: TncLineOnConnectDisconnect read FOnDisconnected write FOnDisconnected;
    public
      Handle: WinSock.TSocket;

      constructor Create; overload; virtual;
      constructor Create(aFamily, aSocketType, aProtocol: Integer); overload; virtual;
      destructor Destroy; override;

      procedure Shutdown; // shutdown by connect or accept

      property Active: Boolean read GetActive;
      property LastSent: Cardinal read GetLastSent write SetLastSent;
      property LastReceived: Cardinal read GetLastReceived write SetLastReceived;
      property PeerIP: string read GetPeerIP;
      property DataObject: TObject read GetDataObject write SetDataObject;
    end;

    // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // TThreadLineList
    // Thread safe object, used by the main components

    TSocketHandleList = class(TCustomIntList)
    private
    published
    public
    end;

    TThreadLineList = class
    private
      FList: TSocketHandleList;
      FLock: TRTLCriticalSection;
      FDuplicates: TDuplicates;
      property Duplicates: TDuplicates read FDuplicates write FDuplicates;
    protected
      procedure Add(Item: TncLine);
      procedure Clear;
      procedure Remove(Item: TncLine); inline;
    public
      constructor Create;
      destructor Destroy; override;
      function LockList: TSocketHandleList;
      procedure UnlockList; inline;
    end;

    // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Base object for all TCP Sockets
    TncOnConnectDisconnect = procedure(Sender: TObject; aLine: TncLine) of object;
    TncOnReadData = procedure(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer) of object;
    TncOnReconnected = procedure(Sender: TObject; aLine: TncLine) of object;

    TncTCPProcessor = class(TncReadyThread)
    private
    public
      constructor Create;
      destructor Destroy; override;
      procedure SocketProcess; virtual; abstract;
    end;

    TncTCPBase = class(TComponent)
    private
      FInitActive: Boolean;
      FPort: Integer;
      FReaderUseMainThread: Boolean;
      FNoDelay: Boolean;
      FKeepAlive: Boolean;
      FOnConnected: TncOnConnectDisconnect;
      FOnDisconnected: TncOnConnectDisconnect;
      FOnReadData: TncOnReadData;
      function GetActive: Boolean; virtual; abstract;
      procedure SetActive(const Value: Boolean);
      function GetPort: Integer;
      procedure SetPort(const Value: Integer);
      function GetReaderThreadPriority: TThreadPriority; virtual; abstract;
      procedure SetReaderThreadPriority(const Value: TThreadPriority); virtual; abstract;
      function GetReaderUseMainThread: Boolean;
      procedure SetReaderUseMainThread(const Value: Boolean);
      function GetNoDelay: Boolean;
      procedure SetNoDelay(const Value: Boolean);
      function GetKeepAlive: Boolean;
      procedure SetKeepAlive(const Value: Boolean);
      function GetOnConnected: TncOnConnectDisconnect;
      procedure SetOnConnected(const Value: TncOnConnectDisconnect);
      function GetOnDisconnected: TncOnConnectDisconnect;
      procedure SetOnDisconnected(const Value: TncOnConnectDisconnect);
      function GetOnReadData: TncOnReadData;
      procedure SetOnReadData(const Value: TncOnReadData);
    private
      procedure DoActivate(aActivate: Boolean); virtual; abstract;
    protected
      ReadBuf: TBytes;
      PropertyLock: TCriticalSection;
      procedure Loaded; override;
      function CreateLineObject: TncLine; virtual;
    public
      Processor: TncTCPProcessor;
      constructor Create(AOwner: TComponent); override;
      destructor Destroy; override;
      property Active: Boolean read GetActive write SetActive default False;
      property Port: Integer read GetPort write SetPort default DefPort;
      property ReaderThreadPriority: TThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
      property ReaderUseMainThread: Boolean read GetReaderUseMainThread write SetReaderUseMainThread default False;
      property NoDelay: Boolean read GetNoDelay write SetNoDelay default True;
      property KeepAlive: Boolean read GetKeepAlive write SetKeepAlive default True;
      property OnConnected: TncOnConnectDisconnect read GetOnConnected write SetOnConnected;
      property OnDisconnected: TncOnConnectDisconnect read GetOnDisconnected write SetOnDisconnected;
      property OnReadData: TncOnReadData read GetOnReadData write SetOnReadData;
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
      FWasConnected: Boolean;
      FLastConnectAttempt: Cardinal;
      function GetActive: Boolean; override;
      procedure SetHost(const Value: string);
      function GetHost: string;
      function GetReaderThreadPriority: TThreadPriority; override;
      procedure SetReaderThreadPriority(const Value: TThreadPriority); override;
      function GetReconnect: Boolean;
      procedure SetReconnect(const Value: Boolean);
      function GetReconnectInterval: Cardinal;
      procedure SetReconnectInterval(const Value: Cardinal);
      function GetWasConnected: Boolean;
      procedure SetWasConnected(const Value: Boolean);
      function GetLastConnectAttempt: Cardinal;
      procedure SetLastConnectAttempt(const Value: Cardinal);
    private
      ReadFDS: TFDSet;
      property WasConnected: Boolean read GetWasConnected write SetWasConnected;
      property LastConnectAttempt: Cardinal read GetLastConnectAttempt write SetLastConnectAttempt;
    protected
      procedure DoActivate(aActivate: Boolean); override;
      procedure DataSocketConnected(Sender: TObject);
      procedure DataSocketDisconnected(Sender: TObject);
    public
      LineProcessor: TncClientProcessor;
      DataSocket: TncLine;
      constructor Create(AOwner: TComponent); override;
      destructor Destroy; override;
      procedure Send(var aBuf; aBufSize: Integer); overload; inline;
      procedure Send(const aBytes: TBytes); overload; inline;
      procedure Send(const aStr: AnsiString); overload; inline;
      procedure Send(const aStr: UnicodeString); overload; inline;
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
      property ReaderUseMainThread;
      property NoDelay;
      property KeepAlive;
      property Reconnect;
      property ReconnectInterval;
      property OnConnected;
      property OnDisconnected;
      property OnReadData;
      property OnReconnected;
    end;

    TncClientProcessor = class(TncTCPProcessor)
    private
      FClientSocket: TncCustomTCPClient;
    public
      constructor Create(aClientSocket: TncCustomTCPClient);
      function ReadableSocket(aTimeout: Integer = 10): Boolean;
      procedure SocketProcess; override;
      procedure SocketWasReconnected;
      procedure ProcessEvent; override;
    end;

    // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Server Socket
    TncServerProcessor = class;

    TncCustomTCPServer = class(TncTCPBase)
    private
      function GetActive: Boolean; override;
      function GetReaderThreadPriority: TThreadPriority; override;
      procedure SetReaderThreadPriority(const Value: TThreadPriority); override;
    protected
      ReadFDS: TFDSet;
      Listener: TncLine;
      procedure ListenerConnected(Sender: TObject);
      procedure ListenerDisconnected(Sender: TObject);
      procedure DoActivate(aActivate: Boolean); override;
    public
      DataSockets: TThreadLineList;
      LineProcessor: TncServerProcessor;
      constructor Create(AOwner: TComponent); override;
      destructor Destroy; override;
      procedure Send(aLine: TncLine; var aBuf; aBufSize: Integer); overload; inline;
      procedure Send(aLine: TncLine; const aBytes: TBytes); overload;
      procedure Send(aLine: TncLine; const aStr: AnsiString); overload;
      procedure Send(aLine: TncLine; const aStr: UnicodeString); overload;
    end;

    TncTCPServer = class(TncCustomTCPServer)
    public
    published
      property Active;
      property Port;
      property ReaderThreadPriority;
      property ReaderUseMainThread;
      property NoDelay;
      property KeepAlive;
      property OnConnected;
      property OnDisconnected;
      property OnReadData;
    end;

    TncServerProcessor = class(TncTCPProcessor)
    private
      FServerSocket: TncCustomTCPServer;
    public
      constructor Create(aServerSocket: TncCustomTCPServer);
      procedure SocketProcess; override;
      procedure ProcessEvent; override;
    end;

    // Helper functions
  procedure GetAddrInfo(NodeName: PAnsiChar; ServiceName: PAnsiChar; Hints: PAddrInfo; ppResult: PPAddrInfo);
  procedure FreeAddrInfo(ai: PAddrInfo);

  function Readable(aReadFDS: TFDSet; aTimeOut: Cardinal): TFDSet;
  function ReadableAnySocket(aReadFDS: TFDSet; aTimeOut: Cardinal): Boolean;

  function HostByName(const aHost: string): WinSock.In_addr;

implementation

  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  { TncLine }
  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  constructor TncLine.Create;
  begin
    inherited Create;

    Handle := INVALID_SOCKET;

    PropertyLock := TCriticalSection.Create;
    LastTimeStampLock := TCriticalSection.Create;

    FActive := False;
    FLastSent := 0;
    FLastReceived := 0;
    FPeerIP := '127.0.0.1';
    FDataObject := nil;

    FOnConnected := nil;
    FOnDisconnected := nil;
  end;

  constructor TncLine.Create(aFamily, aSocketType, aProtocol: Integer);
  begin
    inherited Create;

    CreateHandle(aFamily, aSocketType, aProtocol);
  end;

  destructor TncLine.Destroy;
  begin
    if FActive then
      Shutdown;
    if Handle <> INVALID_SOCKET then
      DestroyHandle;

    LastTimeStampLock.Free;
    PropertyLock.Free;

    inherited Destroy;
  end;

  procedure TncLine.CreateHandle(aFamily, aSocketType, aProtocol: Integer);
  begin
    try
      Handle := WinSock.socket(aFamily, aSocketType, aProtocol);
      Check(Handle);
    except
      Handle := INVALID_SOCKET;
      raise ;
    end;
  end;

  function TncLine.CreateLineObject: TncLine;
  begin
    Result := TncLine.Create;
  end;

  procedure TncLine.DestroyHandle;
  begin
    WinSock.CloseSocket(Handle);
    Handle := INVALID_SOCKET;
  end;

  procedure TncLine.Check(aCmdRes: Integer);
  begin
    if aCmdRes = SOCKET_ERROR then // INVALID_SOCKET is also -1
      raise TncLineException.Create(SysErrorMessage(WSAGetLastError));
  end;

  procedure TncLine.Connect(var name: TSockAddr; namelen: Integer);
  begin
    Check(WinSock.Connect(Handle, name, namelen));
    SetConnected;
  end;

  procedure TncLine.Shutdown;
  begin
    SetDisconnected;
    WinSock.Shutdown(Handle, SD_SEND);
  end;

  function TncLine.Send(var Buf; len, flags: Integer): Integer;
  { var
    PBuf: PByte;
    Ofs: Integer; }
  begin
    // Send all buffer in one go, the most optimal by far
    Result := WinSock.Send(Handle, Buf, len, flags);
    try
      if Result = SOCKET_ERROR then
        Abort; // raise silent exception instead of Check

      LastSent := GetTickCount;
      LastReceived := LastSent;
    except
      Shutdown;
      raise ;
    end;
  end;

  function TncLine.Recv(var Buf; len, flags: Integer): Integer;
  begin
    Result := WinSock.Recv(Handle, Buf, len, flags);
    try
      if (Result = SOCKET_ERROR) or (Result = 0) then
        Abort; // raise silent exception instead of Check

      LastReceived := GetTickCount;
    except
      Shutdown;
      raise ;
    end;
  end;

  procedure TncLine.Bind(var addr: TSockAddr; namelen: Integer);
  begin
    Check(WinSock.Bind(Handle, addr, namelen));
  end;

  procedure TncLine.Listen(backlog: Integer);
  begin
    Check(WinSock.Listen(Handle, backlog));
    SetConnected;
  end;

  function TncLine.Accept(addr: PSOCKADDR; addrlen: PInteger): TncLine;
  var
    NewHandle: WinSock.TSocket;
  begin
    NewHandle := WinSock.Accept(Handle, addr, addrlen);
    // Check(NewHandle);
    if NewHandle = SOCKET_ERROR then
      Abort; // raise silent exception instead

    Result := CreateLineObject;

    Result.Handle := NewHandle;
    Result.OnConnected := OnConnected;
    Result.OnDisconnected := OnDisconnected;
    Result.SetConnected;
  end;

  function TncLine.GetSockOpt(level, optname: Integer; optval: PAnsiChar; var optlen: Integer): Integer;
  begin
    Result := WinSock.GetSockOpt(Handle, level, optname, optval, optlen);
    Check(Result);
  end;

  function TncLine.SetSockOpt(level, optname: Integer; optval: PAnsiChar; optlen: Integer): Integer;
  begin
    Result := WinSock.SetSockOpt(Handle, level, optname, optval, optlen);
    Check(Result);
  end;

  procedure TncLine.SetConnected;
  var
    addr: SockAddr_In;
    AddrSize: Integer;
  begin
    if not Active then
    begin
      PropertyLock.Acquire;
      try
        FActive := True;
      finally
        PropertyLock.Release;
      end;

      LastSent := GetTickCount;
      LastReceived := LastSent;

      AddrSize := SizeOf(addr);
      if GetPeerName(Handle, addr, AddrSize) <> SOCKET_ERROR then
      begin
        PropertyLock.Acquire;
        try
          FPeerIP := IntToStr(Ord(addr.sin_addr.S_un_b.s_b1)) + '.' + IntToStr(Ord(addr.sin_addr.S_un_b.s_b2)) + '.' + IntToStr(Ord(addr.sin_addr.S_un_b.s_b3))
            + '.' + IntToStr(Ord(addr.sin_addr.S_un_b.s_b4));
        finally
          PropertyLock.Release;
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
    if Active then
    begin
      PropertyLock.Acquire;
      try
        FActive := False;
      finally
        PropertyLock.Release;
      end;

      if Assigned(FOnDisconnected) then
        try
          OnDisconnected(Self);
        except
        end;

      PropertyLock.Acquire;
      try
        FPeerIP := '127.0.0.1';
      finally
        PropertyLock.Release;
      end;
    end;
  end;

  function TncLine.GetActive: Boolean;
  begin
    PropertyLock.Acquire;
    try
      Result := FActive;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncLine.GetLastSent: Cardinal;
  begin
    LastTimeStampLock.Acquire;
    try
      Result := FLastSent;
    finally
      LastTimeStampLock.Release;
    end;
  end;

  function TncLine.GetLastReceived: Cardinal;
  begin
    LastTimeStampLock.Acquire;
    try
      Result := FLastReceived;
    finally
      LastTimeStampLock.Release;
    end;
  end;

  procedure TncLine.SetLastSent(const Value: Cardinal);
  begin
    LastTimeStampLock.Acquire;
    try
      FLastSent := Value;
    finally
      LastTimeStampLock.Release;
    end;
  end;

  procedure TncLine.SetLastReceived(const Value: Cardinal);
  begin
    LastTimeStampLock.Acquire;
    try
      FLastReceived := Value;
    finally
      LastTimeStampLock.Release;
    end;
  end;

  function TncLine.GetPeerIP: string;
  begin
    PropertyLock.Acquire;
    try
      Result := FPeerIP;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncLine.GetDataObject: TObject;
  begin
    PropertyLock.Acquire;
    try
      Result := FDataObject;
    finally
      PropertyLock.Release;
    end;

  end;

  procedure TncLine.SetDataObject(const Value: TObject);
  begin
    PropertyLock.Acquire;
    try
      FDataObject := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  { TSocketHandleList }
  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  {
  function TSocketHandleList.GetLines(Index: Integer): TncLine;
  begin
    Result := TncLine(Objects[Index]);
  end;
  }
  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  { TThreadLineList }
  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  constructor TThreadLineList.Create;
  begin
    inherited Create;
    InitializeCriticalSection(FLock);
    FList := TSocketHandleList.Create;
    FList.Sorted := True;
    FDuplicates := dupIgnore;
  end;

  destructor TThreadLineList.Destroy;
  begin
    LockList;
    try
      FList.Free;
      inherited Destroy;
    finally
      UnlockList;
      DeleteCriticalSection(FLock);
    end;
  end;

  procedure TThreadLineList.Add(Item: TncLine);
  begin
    LockList;
    try
      if (Duplicates = dupAccept) or (FList.IndexOf(Item.Handle) = -1) then
        FList.AddObject(Item.Handle, Item)
      else if Duplicates = dupError then
        raise Exception.Create('List does not allow duplicates');
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

  function TThreadLineList.LockList: TSocketHandleList;
  begin
    EnterCriticalSection(FLock);
    Result := FList;
  end;

  procedure TThreadLineList.UnlockList;
  begin
    LeaveCriticalSection(FLock);
  end;

  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  { TncTCPBase }
  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  constructor TncTCPBase.Create(AOwner: TComponent);
  begin
    inherited Create(AOwner);

    PropertyLock := TCriticalSection.Create;

    FInitActive := False;
    FPort := DefPort;
    FReaderUseMainThread := False;
    FNoDelay := True;
    FKeepAlive := True;
    FOnConnected := nil;
    FOnDisconnected := nil;
    FOnReadData := nil;

    SetLength(ReadBuf, DefReadBufferLen);
  end;

  destructor TncTCPBase.Destroy;
  begin
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
    Result := TncLine.Create;
  end;

  procedure TncTCPBase.SetActive(const Value: Boolean);
  begin
    if not(csLoading in ComponentState) then
      DoActivate(Value);

    FInitActive := GetActive; // we only care here for the loaded event
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
        raise Exception.Create('Cannot set port whilst the connection is active');

    PropertyLock.Acquire;
    try
      FPort := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncTCPBase.GetOnConnected: TncOnConnectDisconnect;
  begin
    PropertyLock.Acquire;
    try
      Result := FOnConnected;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncTCPBase.SetOnConnected(const Value: TncOnConnectDisconnect);
  begin
    PropertyLock.Acquire;
    try
      FOnConnected := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncTCPBase.GetOnDisconnected: TncOnConnectDisconnect;
  begin
    PropertyLock.Acquire;
    try
      Result := FOnDisconnected;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncTCPBase.SetOnDisconnected(const Value: TncOnConnectDisconnect);
  begin
    PropertyLock.Acquire;
    try
      FOnDisconnected := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncTCPBase.GetOnReadData: TncOnReadData;
  begin
    PropertyLock.Acquire;
    try
      Result := FOnReadData;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncTCPBase.SetOnReadData(const Value: TncOnReadData);
  begin
    PropertyLock.Acquire;
    try
      FOnReadData := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncTCPBase.GetReaderUseMainThread: Boolean;
  begin
    PropertyLock.Acquire;
    try
      Result := FReaderUseMainThread;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncTCPBase.SetReaderUseMainThread(const Value: Boolean);
  begin
    PropertyLock.Acquire;
    try
      FReaderUseMainThread := Value;
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
  { TncTCPProcessor }
  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  constructor TncTCPProcessor.Create;
  begin
    inherited Create;
  end;

  destructor TncTCPProcessor.Destroy;
  begin
    inherited Destroy;
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
    FWasConnected := False;
    FLastConnectAttempt := 0;

    DataSocket := CreateLineObject;
    DataSocket.OnConnected := DataSocketConnected;
    DataSocket.OnDisconnected := DataSocketDisconnected;

    LineProcessor := TncClientProcessor.Create(Self);
    Processor := LineProcessor;
    LineProcessor.Priority := DefReaderThreadPriority;
  end;

  destructor TncCustomTCPClient.Destroy;
  begin
    Active := False;

    LineProcessor.Terminate;
    LineProcessor.WakeupEvent.SetEvent;
    LineProcessor.WaitFor;

    LineProcessor.Free;
    DataSocket.Free;

    inherited Destroy;
  end;

  procedure TncCustomTCPClient.DoActivate(aActivate: Boolean);
  var
    Hints: TAddrInfo;
    AddrResult: PAddrInfo;
  begin
    if aActivate = GetActive then
      Exit;

    if aActivate then
    begin
      ZeroMemory(@Hints, SizeOf(Hints));
      Hints.ai_family := AF_INET;
      Hints.ai_socktype := SOCK_STREAM;
      Hints.ai_protocol := IPPROTO_TCP;

      // Resolve the server address and port
      GetAddrInfo(PAnsiChar(AnsiString(FHost)), PAnsiChar(AnsiString(IntToStr(FPort))), @Hints, @AddrResult);
      try
        // Create a SOCKET for connecting to server
        DataSocket.CreateHandle(AddrResult^.ai_family, AddrResult^.ai_socktype, AddrResult^.ai_protocol);
        try
          // Connect to server
          DataSocket.Connect(AddrResult^.ai_addr^, AddrResult^.ai_addrlen);
        except
          DataSocket.DestroyHandle;
          raise ;
        end;
      finally
        FreeAddrInfo(AddrResult);
      end;
    end
    else
    begin
      WasConnected := False;

      DataSocket.Shutdown;
      DataSocket.DestroyHandle;
    end;
  end;

  procedure TncCustomTCPClient.DataSocketConnected(Sender: TObject);
  var
    optval: Integer;
  begin
    ReadFDS.fd_count := 1;
    ReadFDS.fd_array[0] := DataSocket.Handle;

    if NoDelay then
      try
        optval := 1;
        DataSocket.SetSockOpt(IPPROTO_TCP, TCP_NODELAY, PAnsiChar(@optval), SizeOf(optval));
      except
      end;

    if KeepAlive then
      try
        optval := Integer(True); // any non zero indicates true
        DataSocket.SetSockOpt(SOL_SOCKET, SO_KEEPALIVE, PAnsiChar(@optval), SizeOf(optval));
      except
      end;

    if Assigned(OnConnected) then
      try
        OnConnected(Self, TncLine(Sender));
      except
      end;

    LastConnectAttempt := GetTickCount;
    WasConnected := True;

    LineProcessor.Run; // Will just set events, does not wait
  end;

  procedure TncCustomTCPClient.DataSocketDisconnected(Sender: TObject);
  begin
    // To make it wait before first attempt uncomment following, otherwise,
    // on disconnect, the first connection attempt will be instaneous, and the others will
    // follow after interval expires
    // LastConnectAttempt := GetTickCount;

    if Assigned(OnDisconnected) then
      try
        OnDisconnected(Self, TncLine(Sender));
      except
      end;
  end;

  procedure TncCustomTCPClient.SetLastConnectAttempt(const Value: Cardinal);
  begin
    PropertyLock.Acquire;
    try
      FLastConnectAttempt := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncCustomTCPClient.Send(var aBuf; aBufSize: Integer);
  begin
    if not Active then
      Active := True;


    DataSocket.Send(aBuf, aBufSize, 0);
  end;

  procedure TncCustomTCPClient.Send(const aBytes: TBytes);
  begin
    if Length(aBytes) > 0 then
      Send(aBytes[0], Length(aBytes));
  end;

  procedure TncCustomTCPClient.Send(const aStr: AnsiString);
  begin
    Send(BytesOf(aStr));
  end;

  procedure TncCustomTCPClient.Send(const aStr: UnicodeString);
  begin
    Send(BytesOf(aStr));
  end;

  function TncCustomTCPClient.GetActive: Boolean;
  begin
    Result := DataSocket.Active;
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
        raise Exception.Create('Cannot set host whilst the connection is active');

    PropertyLock.Acquire;
    try
      FHost := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncCustomTCPClient.GetReaderThreadPriority: TThreadPriority;
  begin
    PropertyLock.Acquire;
    try
      Result := LineProcessor.Priority;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncCustomTCPClient.SetReaderThreadPriority(const Value: TThreadPriority);
  begin
    PropertyLock.Acquire;
    try
      LineProcessor.Priority := Value;
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

  function TncCustomTCPClient.GetWasConnected: Boolean;
  begin
    PropertyLock.Acquire;
    try
      Result := FWasConnected;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncCustomTCPClient.SetWasConnected(const Value: Boolean);
  begin
    PropertyLock.Acquire;
    try
      FWasConnected := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  function TncCustomTCPClient.GetLastConnectAttempt: Cardinal;
  begin
    PropertyLock.Acquire;
    try
      Result := FLastConnectAttempt;
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
    if Terminated then
      Exit;

    if ReadableSocket (0) then // make it non blocking
    begin

      BufRead := FClientSocket.DataSocket.Recv(FClientSocket.ReadBuf[0], Length(FClientSocket.ReadBuf), 0);

      if Terminated then
        Exit;
      if Assigned(FClientSocket.OnReadData) then
        try
          FClientSocket.OnReadData(FClientSocket, FClientSocket.DataSocket, FClientSocket.ReadBuf, BufRead);
        except
        end;
    end;
  end;

  procedure TncClientProcessor.SocketWasReconnected;
  begin
    if Assigned(FClientSocket.FOnReconnected) then
      FClientSocket.FOnReconnected(FClientSocket, FClientSocket.DataSocket);
    if Assigned(FClientSocket.OnConnected) then
      FClientSocket.OnConnected(FClientSocket, FClientSocket.DataSocket);
  end;

  function TncClientProcessor.ReadableSocket(aTimeout: Integer = 10): Boolean;
  begin
    try
      Result := ReadableAnySocket(FClientSocket.ReadFDS, aTimeout);
    except
      Result := False;
    end;
  end;

  procedure TncClientProcessor.ProcessEvent;
  var
    PrevOnConnect: TncOnConnectDisconnect;
  begin
    while (not Terminated) do // Repeat handling until terminated
      try
        if FClientSocket.DataSocket.Active then // Repeat reading socket until disconnected
        begin
          if ReadableSocket(10) then
            if FClientSocket.ReaderUseMainThread then
              Synchronize(SocketProcess) // for synchronize
            else
              SocketProcess;
        end
        else
        // Is not Active
        begin
          Sleep(1); // Allow others to work

          // Logic for reconnect mode
          if FClientSocket.Reconnect then
            if FClientSocket.WasConnected then
              if GetTickCount - FClientSocket.LastConnectAttempt > FClientSocket.ReconnectInterval then
              begin
                try
                  PrevOnConnect := FClientSocket.OnConnected;
                  FClientSocket.OnConnected := nil; // Disable firing the event in the wrong thread in case it gets connected
                  try
                    FClientSocket.Active := True;
                    FClientSocket.OnConnected := PrevOnConnect;
                    if FClientSocket.ReaderUseMainThread then
                      Synchronize(SocketWasReconnected)
                    else
                      SocketWasReconnected;
                  finally
                    FClientSocket.OnConnected := PrevOnConnect;
                  end;
                except
                end;
                FClientSocket.LastConnectAttempt := GetTickCount;
              end;
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
    Listener := CreateLineObject;
    Listener.OnConnected := ListenerConnected;
    Listener.OnDisconnected := ListenerDisconnected;

    DataSockets := TThreadLineList.Create;
    LineProcessor := TncServerProcessor.Create(Self);
    Processor := LineProcessor;
    LineProcessor.Priority := DefReaderThreadPriority;

    inherited Create(AOwner);
  end;

  destructor TncCustomTCPServer.Destroy;
  var
    Sockets: TSocketHandleList;
    i: Integer;
  begin
    Active := False;

    LineProcessor.Terminate;
    LineProcessor.WakeupEvent.SetEvent;
    LineProcessor.WaitFor;

    Sockets := DataSockets.LockList;
    try
      for i := 0 to Sockets.Count - 1 do
        Sockets.Objects[i].Free;
    finally
      DataSockets.UnlockList;
    end;
    LineProcessor.Free;

    DataSockets.Free;
    Listener.Free;

    inherited Destroy;
  end;

  function TncCustomTCPServer.GetActive: Boolean;
  begin
    Result := Listener.Active;
  end;

  procedure TncCustomTCPServer.DoActivate(aActivate: Boolean);
  var
    Hints: TAddrInfo;
    AddrResult: PAddrInfo;
    Sockets: TSocketHandleList;
    i: Integer;
  begin
    if aActivate = GetActive then
      Exit;

    if aActivate then
    begin
      ZeroMemory(@Hints, SizeOf(Hints));
      Hints.ai_family := AF_INET;
      Hints.ai_socktype := SOCK_STREAM;
      Hints.ai_protocol := IPPROTO_TCP;
      Hints.ai_flags := AI_PASSIVE; // Inform GetAddrInfo to return a server socket

      // Resolve the server address and port
      GetAddrInfo(nil, PAnsiChar(AnsiString(IntToStr(FPort))), @Hints, @AddrResult);
      try
        // Create a SOCKET for connecting to server
        Listener.CreateHandle(AddrResult^.ai_family, AddrResult^.ai_socktype, AddrResult^.ai_protocol);
        try
          // Setup the TCP listening socket
          Listener.Bind(AddrResult^.ai_addr^, AddrResult^.ai_addrlen);
          Listener.Listen(SOMAXCONN);
        except
          Listener.DestroyHandle;
          raise ;
        end;
      finally
        FreeAddrInfo(AddrResult);
      end;
    end
    else
    begin
      Sockets := DataSockets.LockList;
      try
        for i := 0 to Sockets.Count - 1 do
          try
            TncLine(Sockets.Objects[i]).Shutdown;
            TncLine(Sockets.Objects[i]).Free;
          except
          end;
      finally
        DataSockets.UnlockList;
      end;
      DataSockets.Clear;
      Listener.Shutdown;
      Listener.DestroyHandle;
    end;
  end;

  procedure TncCustomTCPServer.ListenerConnected(Sender: TObject);
  var
    optval: Integer;
  begin
    if Sender = Listener then
    begin
      ReadFDS.fd_count := 1;
      ReadFDS.fd_array[0] := Listener.Handle;
      LineProcessor.WaitForReady;
      LineProcessor.Run;
    end
    else
    begin
      ReadFDS.fd_count := ReadFDS.fd_count + 1;
      ReadFDS.fd_array[ReadFDS.fd_count - 1] := TncLine(Sender).Handle;

      if NoDelay then
        try
          optval := 1;
          TncLine(Sender).SetSockOpt(IPPROTO_TCP, TCP_NODELAY, PAnsiChar(@optval), SizeOf(optval));
        except
        end;

      if KeepAlive then
        try
          optval := Integer(True); // any non zero indicates true
          TncLine(Sender).SetSockOpt(SOL_SOCKET, SO_KEEPALIVE, PAnsiChar(@optval), SizeOf(optval));
        except
        end;

      if Assigned(OnConnected) then
        try
          OnConnected(Self, TncLine(Sender));
        except
        end;
    end;
  end;

  procedure TncCustomTCPServer.ListenerDisconnected(Sender: TObject);
  var
    i: Integer;
  begin
    if Sender = Listener then
    begin
      // Nothing yet in logic
    end
    else
    begin
      for i := 0 to ReadFDS.fd_count - 1 do
        if ReadFDS.fd_array[i] = TncLine(Sender).Handle then
        begin
          ReadFDS.fd_array[i] := ReadFDS.fd_array[ReadFDS.fd_count - 1];
          ReadFDS.fd_count := ReadFDS.fd_count - 1;
          Break;
        end;

      if Assigned(OnDisconnected) then
        OnDisconnected(Self, TncLine(Sender));
    end;
  end;

  function TncCustomTCPServer.GetReaderThreadPriority: TThreadPriority;
  begin
    PropertyLock.Acquire;
    try
      Result := LineProcessor.Priority;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncCustomTCPServer.SetReaderThreadPriority(const Value: TThreadPriority);
  begin
    PropertyLock.Acquire;
    try
      LineProcessor.Priority := Value;
    finally
      PropertyLock.Release;
    end;
  end;

  procedure TncCustomTCPServer.Send(aLine: TncLine; var aBuf; aBufSize: Integer);
  begin
    aLine.Send(aBuf, aBufSize, 0);
  end;

  procedure TncCustomTCPServer.Send(aLine: TncLine; const aBytes: TBytes);
  begin
    if Length(aBytes) > 0 then
      Send(aLine, aBytes[0], Length(aBytes));
  end;

  procedure TncCustomTCPServer.Send(aLine: TncLine; const aStr: AnsiString);
  begin
    Send(aLine, BytesOf(aStr));
  end;

  procedure TncCustomTCPServer.Send(aLine: TncLine; const aStr: UnicodeString);
  begin
    Send(aLine, BytesOf(aStr));
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
    ReadySockets: TFDSet;
    BufRead: Integer;
    DataSockets: TSocketHandleList;
    LineNdx: Integer;
    Line: TncLine;
  begin
    if Terminated then
      Exit;

    ReadySockets := Readable(FServerSocket.ReadFDS, 0);

    if Terminated then
      Exit;
    for i := 0 to ReadySockets.fd_count - 1 do
      try
        if ReadySockets.fd_array[i] = FServerSocket.Listener.Handle then
          FServerSocket.DataSockets.Add(FServerSocket.Listener.Accept(nil, nil))
        else
        begin
          DataSockets := FServerSocket.DataSockets.LockList;
          try
            LineNdx := DataSockets.IndexOf(ReadySockets.fd_array[i]);
            if LineNdx = -1 then // Termination may have taken this out of the list
              Continue;
            Line := TncLine(DataSockets.Objects[LineNdx]);
            try
              BufRead := Line.Recv(FServerSocket.ReadBuf[0], Length(FServerSocket.ReadBuf), 0);
              if Assigned(FServerSocket.OnReadData) then
                try
                  FServerSocket.OnReadData(FServerSocket, Line, FServerSocket.ReadBuf, BufRead);
                except
                end;
            except
              Line.Free;
              DataSockets.Delete(LineNdx);
            end;
          finally
            FServerSocket.DataSockets.UnlockList;
          end;
        end;
      except
      end;
  end;

  procedure TncServerProcessor.ProcessEvent;
  var
    ReadySockets: TFDSet;
  begin
    while FServerSocket.Listener.Active and (not Terminated) do
    begin
      ReadySockets := Readable(FServerSocket.ReadFDS, 10);
      if ReadySockets.fd_count > 0 then
        if FServerSocket.ReaderUseMainThread then
          Synchronize(SocketProcess)
        else
          SocketProcess;
    end;
  end;

  // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Helper Functions

  function HostByName(const aHost: string): WinSock.In_addr;
  var
    LAddrInfo: PAddrInfo;
    Hints: TAddrInfo;
  begin
    if aHost = 'localhost' then
    begin
      Result.S_un_b.s_b1 := #127;
      Result.S_un_b.s_b2 := #0;
      Result.S_un_b.s_b3 := #0;
      Result.S_un_b.s_b4 := #1;
      Exit;
    end;

    Result.S_addr := Inet_addr(PAnsiChar(AnsiString(aHost)));
    if Result.S_addr <> SOCKET_ERROR then
      Exit; // was a proper IP

    ZeroMemory(@Hints, SizeOf(TAddrInfo));
    Hints.ai_family := PF_INET;
    Hints.ai_socktype := SOCK_STREAM;
    LAddrInfo := nil;

    GetAddrInfo(PAnsiChar(AnsiString(aHost)), nil, @Hints, @LAddrInfo);
    try
      Result := LAddrInfo^.ai_addr^.sin_addr;
    finally
      FreeAddrInfo(LAddrInfo);
    end;
  end;

  type
    TGetAddrInfo = function(NodeName: PAnsiChar; ServiceName: PAnsiChar; Hints: PAddrInfo; ppResult: PPAddrInfo): Integer; stdcall;
    TFreeAddrInfo = procedure(ai: PAddrInfo); stdcall;

  var
    DllGetAddrInfo: TGetAddrInfo = nil;
    DllFreeAddrInfo: TFreeAddrInfo = nil;

  procedure GetAddrInfo(NodeName: PAnsiChar; ServiceName: PAnsiChar; Hints: PAddrInfo; ppResult: PPAddrInfo);
  var
    iRes: Integer;
  begin
    if AnsiLowerCase(string(NodeName)) = 'localhost' then
      NodeName := '127.0.0.1';

    iRes := DllGetAddrInfo(NodeName, ServiceName, Hints, ppResult);
    if iRes <> 0 then
      raise TncLineException.Create(SysErrorMessage(iRes));
  end;

  procedure FreeAddrInfo(ai: PAddrInfo);
  begin
    DllFreeAddrInfo(ai);
  end;

  function Readable(aReadFDS: TFDSet; aTimeOut: Cardinal): TFDSet;
  var
    TimeVal: TTimeVal;
    iRes: Integer;
  begin
    if aTimeOut = INFINITE then
      iRes := Select(0, @aReadFDS, nil, nil, nil)
    else
    begin
      TimeVal.tv_sec := aTimeOut div 1000;
      TimeVal.tv_usec := (aTimeOut mod 1000) * 1000;
      iRes := Select(0, @aReadFDS, nil, nil, @TimeVal);
    end;

    if iRes = SOCKET_ERROR then
      raise TncLineException.Create('Socket error');

    // After select, the handles returned are those who are readable
    Result := aReadFDS;
  end;

  // Warning: This function creates an error in an ISAPI!
  function ReadableAnySocket(aReadFDS: TFDSet; aTimeOut: Cardinal): Boolean;
  var
    TimeVal: TTimeVal;
    iRes: Integer;
  begin
    if aTimeOut = INFINITE then
      iRes := Select(0, @aReadFDS, nil, nil, nil)
    else
    begin
      TimeVal.tv_sec := aTimeOut div 1000;
      TimeVal.tv_usec := (aTimeOut mod 1000) * 1000;
      iRes := Select(0, @aReadFDS, nil, nil, @TimeVal);
    end;

    if iRes = SOCKET_ERROR then
      raise TncLineException.Create('Socket error');

    // After select, the handles returned are those who are readable
    Result := aReadFDS.fd_count > 0;
  end;

  var
    ExtDllHandle: Cardinal = 0;

  procedure AttachAddrInfo;
    procedure SafeLoadFrom(aDll: string);
    begin
      if not Assigned(DllGetAddrInfo) then
      begin
        ExtDllHandle := SafeLoadLibrary(aDll);
        if ExtDllHandle <> 0 then
        begin
          DllGetAddrInfo := GetProcAddress(ExtDllHandle, 'getaddrinfo');
          DllFreeAddrInfo := GetProcAddress(ExtDllHandle, 'freeaddrinfo');
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
    SafeLoadFrom('ws2.dll'); // WinSock2 16bit dll
  end;

  var
    WSAData: TWSAData;

initialization

  WSAStartup(MakeWord(2, 2), WSAData); // Require WinSock 2 version
  AttachAddrInfo;

finalization

  if ExtDllHandle <> 0 then
    FreeLibrary(ExtDllHandle);
  WSACleanup;

end.
