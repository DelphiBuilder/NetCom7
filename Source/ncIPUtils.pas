unit ncIPUtils;
// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package - IP Address utils
//
// This unit implements UDP Server and UDP Client components
//
// 21/01/2025
// - Initial creation
// Written by J.Pauwels
//
// /////////////////////////////////////////////////////////////////////////////

interface

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows, Winapi.Winsock2,
  {$ELSE}
  Posix.SysSocket, Posix.NetDB, Posix.NetIf, Posix.ArpaInet,
  {$ENDIF}
  System.SysUtils, System.Classes;

const
  IPV6_ADDR_LEN = 16;  // IPv6 address length in bytes
  IPV6_STR_MAX_LEN = 46; // Maximum string length for IPv6 address including null terminator
  SOCKADDR_STORAGE_SIZE = 128; // Size of sockaddr_storage structure

  {$IFDEF MSWINDOWS}
  AF_INET6 = 23;
  {$ENDIF}

type
  TIn6Addr = record
    case Integer of
      0: (s6_bytes: array[0..15] of Byte);
      1: (s6_words: array[0..7] of Word);
  end;
  PIn6Addr = ^TIn6Addr;

  TSockAddrIn6 = record
    sin6_family: Word;       // AF_INET6
    sin6_port: Word;         // Transport layer port #
    sin6_flowinfo: Cardinal; // IPv6 flow information
    sin6_addr: TIn6Addr;     // IPv6 address
    sin6_scope_id: Cardinal; // Set of interfaces for scope
  end;
  PSockAddrIn6 = ^TSockAddrIn6;

  // Socket storage structure - used for both IPv4 and IPv6
  TSockAddrStorage = record
    ss_family: Word;                    // Address family
    __ss_pad1: array [0..5] of Byte;    // 6 bytes of padding
    __ss_align: Int64;                  // Force alignment
    __ss_pad2: array [0..111] of Byte;  // 112 bytes of padding
  end;
  PSockAddrStorage = ^TSockAddrStorage;

  EIPError = class(Exception);

  // Function types for dynamic loading
  {$IFDEF MSWINDOWS}
  TInetPton = function(Family: Integer; const pszAddrString: PAnsiChar;
    pAddrBuf: Pointer): Integer; stdcall;
  TInetNtop = function(Family: Integer; pAddr: Pointer;
    pStringBuf: PAnsiChar; StringBufSize: size_t): PAnsiChar; stdcall;
  {$ENDIF}

  TncIPUtils = class
  private
    {$IFDEF MSWINDOWS}
    class var
      InetPton: TInetPton;
      InetNtop: TInetNtop;
    class function LoadIPv6Functions: Boolean;
    {$ENDIF}
  public
    class constructor Create;

    // SockAddrStorage methods
    class function StorageToString(const Storage: TSockAddrStorage): string;
    class function IsIPv6Storage(const Storage: TSockAddrStorage): Boolean;
    class function GetStorageFamily(const Storage: TSockAddrStorage): Word;
    class function StorageToIPv6Address(const Storage: TSockAddrStorage;
      out Addr: TSockAddrIn6): Boolean;
    class function GetIPFromStorage(const Storage: TSockAddrStorage): string;
    class function GetPortFromStorage(const Storage: TSockAddrStorage): Word;

    // Existing IPv6 methods
    class function IsIPv6ValidAddress(const AddrStr: string): Boolean;
    class function AddressToString(const Addr: TIn6Addr): string;
    class function StringToAddress(const AddrStr: string; out Addr: TIn6Addr): Boolean;
    class function IsLinkLocal(const AddrStr: string): Boolean;
    class function NormalizeAddress(const AddrStr: string): string;
    class function AddressToPresentation(const Addr: TIn6Addr): string;
    class function PresentationToAddress(const Present: string; var Addr: TIn6Addr): Boolean;
  end;

implementation

{$IFDEF MSWINDOWS}
var
  Ws2_32DllHandle: THandle;


class function TncIPUtils.LoadIPv6Functions: Boolean;
begin
  Result := False;

  if Ws2_32DllHandle = 0 then
    Ws2_32DllHandle := LoadLibrary('ws2_32.dll');

  if Ws2_32DllHandle <> 0 then
  begin
    InetPton := GetProcAddress(Ws2_32DllHandle, 'inet_pton');
    InetNtop := GetProcAddress(Ws2_32DllHandle, 'inet_ntop');
    Result := Assigned(InetPton) and Assigned(InetNtop);
  end;
end;
{$ENDIF}

class constructor TncIPUtils.Create;
begin
  {$IFDEF MSWINDOWS}
  if not LoadIPv6Functions then
    raise EIPError.Create('Failed to load IPv6 functions from ws2_32.dll');
  {$ENDIF}
end;

class function TncIPUtils.StorageToString(const Storage: TSockAddrStorage): string;
begin
  case Storage.ss_family of
    AF_INET:
      begin
        var addr_in := PSockAddrIn(@Storage)^;
        with addr_in.sin_addr.S_un_b do
          Result := Format('%d.%d.%d.%d', [s_b1, s_b2, s_b3, s_b4]);
      end;

    AF_INET6:
      begin
        var addr_in6 := PSockAddrIn6(@Storage)^;
        Result := AddressToString(addr_in6.sin6_addr);
        if IsLinkLocal(Result) then
          Result := Format('%s%%%d', [Result, addr_in6.sin6_scope_id]);
      end;
  else
    Result := '';
  end;
end;

class function TncIPUtils.IsIPv6Storage(const Storage: TSockAddrStorage): Boolean;
begin
  Result := Storage.ss_family = AF_INET6;
end;

class function TncIPUtils.GetStorageFamily(const Storage: TSockAddrStorage): Word;
begin
  Result := Storage.ss_family;
end;

class function TncIPUtils.StorageToIPv6Address(const Storage: TSockAddrStorage;
  out Addr: TSockAddrIn6): Boolean;
begin
  Result := Storage.ss_family = AF_INET6;
  if Result then
    Addr := PSockAddrIn6(@Storage)^;
end;

class function TncIPUtils.GetIPFromStorage(const Storage: TSockAddrStorage): string;
begin
  Result := StorageToString(Storage);
end;

class function TncIPUtils.GetPortFromStorage(const Storage: TSockAddrStorage): Word;
begin
  case Storage.ss_family of
    AF_INET: Result := ntohs(PSockAddrIn(@Storage)^.sin_port);
    AF_INET6: Result := ntohs(PSockAddrIn6(@Storage)^.sin6_port);
  else
    Result := 0;
  end;
end;

class function TncIPUtils.IsIPv6ValidAddress(const AddrStr: string): Boolean;
var
  Addr: TIn6Addr;
begin
  Result := StringToAddress(AddrStr, Addr);
end;

class function TncIPUtils.AddressToString(const Addr: TIn6Addr): string;
var
  StringBuffer: array[0..IPV6_STR_MAX_LEN-1] of AnsiChar;
begin
  {$IFDEF MSWINDOWS}
  if InetNtop(AF_INET6, @Addr, StringBuffer, IPV6_STR_MAX_LEN) = nil then
    raise EIPError.Create('Failed to convert IPv6 address to string: ' +
      SysErrorMessage(WSAGetLastError));
  {$ELSE}
  if Posix.ArpaInet.inet_ntop(AF_INET6, @Addr, StringBuffer, IPV6_STR_MAX_LEN) = nil then
    raise EIPv6Error.Create('Failed to convert IPv6 address to string: ' +
      SysErrorMessage(GetLastError));
  {$ENDIF}

  Result := string(AnsiString(StringBuffer));
end;

class function TncIPUtils.StringToAddress(const AddrStr: string; out Addr: TIn6Addr): Boolean;
var
  AnsiAddr: AnsiString;
begin
  AnsiAddr := AnsiString(AddrStr);
  {$IFDEF MSWINDOWS}
  Result := InetPton(AF_INET6, PAnsiChar(AnsiAddr), @Addr) = 1;
  {$ELSE}
  Result := Posix.ArpaInet.inet_pton(AF_INET6, PAnsiChar(AnsiAddr), @Addr) = 1;
  {$ENDIF}
end;

class function TncIPUtils.IsLinkLocal(const AddrStr: string): Boolean;
begin
  // Link-local addresses start with fe80::/10
  Result := (Length(AddrStr) >= 4) and
            (LowerCase(Copy(AddrStr, 1, 4)) = 'fe80');
end;

class function TncIPUtils.NormalizeAddress(const AddrStr: string): string;
var
  Addr: TIn6Addr;
begin
  if StringToAddress(AddrStr, Addr) then
    Result := AddressToString(Addr)
  else
    raise EIPError.CreateFmt('Invalid IPv6 address: %s', [AddrStr]);
end;

class function TncIPUtils.AddressToPresentation(const Addr: TIn6Addr): string;
var
  i: Integer;
  NonZeroFound: Boolean;
begin
  Result := '';
  NonZeroFound := False;

  // Convert words to hex representation
  for i := 0 to 7 do
  begin
    if (Addr.s6_words[i] <> 0) or NonZeroFound then
    begin
      if Result <> '' then
        Result := Result + ':';
      Result := Result + IntToHex(Addr.s6_words[i], 1);
      NonZeroFound := True;
    end;
  end;

  // Handle all-zero case
  if Result = '' then
    Result := '::'
  else if not NonZeroFound then
    Result := Result + ':';
end;

class function TncIPUtils.PresentationToAddress(const Present: string;
  var Addr: TIn6Addr): Boolean;
begin
  FillChar(Addr, SizeOf(Addr), 0);
  Result := StringToAddress(Present, Addr);
end;

initialization
  {$IFDEF MSWINDOWS}
  Ws2_32DllHandle := 0;
  {$ENDIF}

finalization
  {$IFDEF MSWINDOWS}
  if Ws2_32DllHandle <> 0 then
    FreeLibrary(Ws2_32DllHandle);
  {$ENDIF}

end.

