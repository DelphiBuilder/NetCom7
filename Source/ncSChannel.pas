unit ncSChannel;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit implements TLS/SSL support for NetCom7 through Windows SChannel
// (Secure Channel) API integration. Provides secure communication capabilities
// for both TCP servers and clients using native Windows cryptographic services.
//
// 13/07/2025 - by J.Pauwels
// - Initial creation
//
// Written by J.Pauwels
//
// /////////////////////////////////////////////////////////////////////////////

interface

uses
  SysUtils,
  Classes,
  Windows;

// CryptoAPI types
type
  {$IFNDEF ULONG_PTR}
  ULONG_PTR = NativeUInt;
  {$ENDIF}
  HCRYPTPROV = ULONG_PTR;
  HCERTSTORE = pointer;
  PCCERT_CONTEXT = ^CERT_CONTEXT;
  
  CERT_NAME_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;
  
  CERT_INFO = record
    dwVersion: DWORD;
    SerialNumber: CERT_NAME_BLOB;
    SignatureAlgorithm: record
      pszObjId: PAnsiChar;
      Parameters: CERT_NAME_BLOB;
    end;
    Issuer: CERT_NAME_BLOB;
    NotBefore: FILETIME;
    NotAfter: FILETIME;
    Subject: CERT_NAME_BLOB;
    SubjectPublicKeyInfo: record
      Algorithm: record
        pszObjId: PAnsiChar;
        Parameters: CERT_NAME_BLOB;
      end;
      PublicKey: record
        cbData: DWORD;
        pbData: PByte;
        cUnusedBits: DWORD;
      end;
    end;
    IssuerUniqueId: record
      cbData: DWORD;
      pbData: PByte;
      cUnusedBits: DWORD;
    end;
    SubjectUniqueId: record
      cbData: DWORD;
      pbData: PByte;
      cUnusedBits: DWORD;
    end;
    cExtension: DWORD;
    rgExtension: pointer;
  end;
  PCERT_INFO = ^CERT_INFO;
  
  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: PCERT_INFO;
    hCertStore: HCERTSTORE;
  end;
  
  CRYPT_DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;
  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;
  
  CERT_ENHKEY_USAGE = record
    cUsageIdentifier: DWORD;
    rgpszUsageIdentifier: pointer;
  end;
  PCERT_ENHKEY_USAGE = ^CERT_ENHKEY_USAGE;
  
  CRYPT_OID_INFO = record
    cbSize: DWORD;
    pszOID: PAnsiChar;
    pwszName: PWideChar;
    dwGroupId: DWORD;
    dwValue: DWORD;
    ExtraInfo: CERT_NAME_BLOB;
  end;
  PCRYPT_OID_INFO = ^CRYPT_OID_INFO;

// CryptoAPI functions for certificate loading
var
  CertOpenStore: function(lpszStoreProvider: PAnsiChar; dwEncodingType: DWORD;
    hCryptProv: HCRYPTPROV; dwFlags: DWORD; pvPara: pointer): HCERTSTORE; stdcall;
  CertCloseStore: function(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL; stdcall;
  CertEnumCertificatesInStore: function(hCertStore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall;
  CertFreeCertificateContext: function(pCertContext: PCCERT_CONTEXT): BOOL; stdcall;
  PFXImportCertStore: function(pPFX: PCRYPT_DATA_BLOB; szPassword: PWideChar; dwFlags: DWORD): HCERTSTORE; stdcall;

// CryptoAPI constants
const
  CERT_STORE_PROV_FILENAME = 8;
  CERT_STORE_PROV_MEMORY = 2;
  CERT_STORE_OPEN_EXISTING_FLAG = $00004000;
  CERT_STORE_READONLY_FLAG = $00008000;
  PKCS12_NO_PERSIST_KEY = $00008000;
  PKCS12_INCLUDE_EXTENDED_PROPERTIES = $00000010;
  
  CERT_FIND_ANY = 0;
  CERT_CLOSE_STORE_DEFAULT = 0;
  CERT_CLOSE_STORE_FORCE_FLAG = 1;
  CERT_CLOSE_STORE_CHECK_FLAG = 2;
  
  CRYPT_ASN_ENCODING = $00000001;
  CRYPT_NDR_ENCODING = $00000002;
  X509_ASN_ENCODING = $00000001;
  X509_NDR_ENCODING = $00000002;
  PKCS_7_ASN_ENCODING = $00010000;
  PKCS_7_NDR_ENCODING = $00020000;

{ SChannel low-level API  }

type
  TCredHandle = record
    dwLower: pointer;
    dwUpper: pointer;
  end;
  PCredHandle = ^TCredHandle;

  TCtxtHandle = type TCredHandle;
  PCtxtHandle = ^TCtxtHandle;

  {$ifdef DELPHI5OROLDER}
  PCardinal = ^Cardinal;
  {$endif}

  TSChannelCred = record
    dwVersion: cardinal;
    cCreds: cardinal;
    paCred: pointer;
    hRootStore: THandle;
    cMappers: cardinal;
    aphMappers: pointer;
    cSupportedAlgs: cardinal;
    palgSupportedAlgs: PCardinal;
    grbitEnabledProtocols: cardinal;
    dwMinimumCipherStrength: cardinal;
    dwMaximumCipherStrength: cardinal;
    dwSessionLifespan: cardinal;
    dwFlags: cardinal;
    dwCredFormat: cardinal;
  end;
  PSChannelCred = ^TSChannelCred;

  TSecBuffer = record
    cbBuffer: cardinal;
    BufferType: cardinal;
    pvBuffer: pointer;
  end;
  PSecBuffer = ^TSecBuffer;

  TSecBufferDesc = record
    ulVersion: cardinal;
    cBuffers: cardinal;
    pBuffers: PSecBuffer;
  end;
  PSecBufferDesc = ^TSecBufferDesc;

  TTimeStamp = record
    dwLowDateTime: cardinal;
    dwHighDateTime: cardinal;
  end;
  PTimeStamp = ^TTimeStamp;

  TSecPkgContextStreamSizes = record
    cbHeader: cardinal;
    cbTrailer: cardinal;
    cbMaximumMessage: cardinal;
    cBuffers: cardinal;
    cbBlockSize: cardinal;
  end;
  PSecPkgContextStreamSizes = ^TSecPkgContextStreamSizes;

  ESChannel = class(Exception);

  {$ifdef USERECORDWITHMETHODS}TSChannelClient = record
    {$else}TSChannelClient = object{$endif}
  private
    Cred: TCredHandle;
    Ctxt: TCtxtHandle;
    Sizes: TSecPkgContextStreamSizes;
    Data, Input: AnsiString;
    InputSize, DataPos, DataCount, InputCount: integer;
    SessionClosed: boolean;
    procedure HandshakeLoop(aLine: TObject);
    procedure AppendData(const aBuffer: TSecBuffer);
  public
    Initialized: boolean;
    procedure AfterConnection(aLine: TObject; const aTargetHost: AnsiString; aIgnoreCertificateErrors: boolean);
    procedure BeforeDisconnection(aLine: TObject);
    function Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
    function Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
  end;

  // Server-side SChannel implementation
  {$ifdef USERECORDWITHMETHODS}TSChannelServer = record
    {$else}TSChannelServer = object{$endif}
  private
    Cred: TCredHandle;
    Ctxt: TCtxtHandle;
    Sizes: TSecPkgContextStreamSizes;
    Data, Input: AnsiString;
    InputSize, DataPos, DataCount, InputCount: integer;
    SessionClosed: boolean;
    procedure HandshakeLoop(aLine: TObject);
    procedure AppendData(const aBuffer: TSecBuffer);
  public
    Initialized: boolean;
    HandshakeCompleted: boolean;
    procedure AfterConnection(aLine: TObject; const aCertificateFile, aPrivateKeyPassword: AnsiString);
    procedure BeforeDisconnection(aLine: TObject);
    function Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
    function Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
  end;

var
  AcquireCredentialsHandle: function(pszPrincipal: PAnsiChar;
    pszPackage: PAnsiChar; fCredentialUse: cardinal; pvLogonID: PInt64;
    pAuthData: PSChannelCred; pGetKeyFn: pointer; pvGetKeyArgument: pointer;
    phCredential: PCredHandle; ptsExpiry: PTimeStamp): cardinal; stdcall;
  FreeCredentialsHandle: function(phCredential: PCredHandle): cardinal; stdcall;
  InitializeSecurityContext: function(phCredential: PCredHandle;
    phContext: PCtxtHandle; pszTargetName: PWideChar; fContextReq: cardinal;
    Reserved1: cardinal; TargetDataRep: cardinal; pInput: PSecBufferDesc;
    Reserved2: cardinal; phNewContext: PCtxtHandle; pOutput: PSecBufferDesc;
    pfContextAttr: PCardinal; ptsExpiry: PTimeStamp): cardinal; stdcall;
  AcceptSecurityContext: function(phCredential: PCredHandle;
    phContext: PCtxtHandle; pInput: PSecBufferDesc; fContextReq: cardinal;
    TargetDataRep: cardinal; phNewContext: PCtxtHandle; pOutput: PSecBufferDesc;
    pfContextAttr: PCardinal; ptsExpiry: PTimeStamp): cardinal; stdcall;
  DeleteSecurityContext: function(phContext: PCtxtHandle): cardinal; stdcall;
  ApplyControlToken: function(phContext: PCtxtHandle;
    pInput: PSecBufferDesc): cardinal; stdcall;
  QueryContextAttributes: function(phContext: PCtxtHandle;
    ulAttribute: cardinal; pBuffer: pointer): cardinal; stdcall;
  FreeContextBuffer: function(pvContextBuffer: pointer): cardinal; stdcall;
  EncryptMessage: function(phContext: PCtxtHandle; fQOP: cardinal;
    pMessage: PSecBufferDesc; MessageSeqNo: cardinal): cardinal; stdcall;
  DecryptMessage: function(phContext: PCtxtHandle; pMessage: PSecBufferDesc;
    MessageSeqNo: cardinal; pfQOP: PCardinal): cardinal; stdcall;

const
  SP_PROT_TLS1_0_SERVER = $0040;
  SP_PROT_TLS1_0_CLIENT = $0080;
  SP_PROT_TLS1_1_SERVER = $0100;
  SP_PROT_TLS1_1_CLIENT = $0200;
  SP_PROT_TLS1_2_SERVER = $0400; // first SP_PROT_TLS_SAFE protocol
  SP_PROT_TLS1_2_CLIENT = $0800;
  SP_PROT_TLS1_3_SERVER = $1000; // Windows 11 or Windows Server 2022 ;)
  SP_PROT_TLS1_3_CLIENT = $2000;

  SECPKG_CRED_INBOUND = 1;
  SECPKG_CRED_OUTBOUND = 2;

  ISC_REQ_DELEGATE = $00000001;
  ISC_REQ_MUTUAL_AUTH = $00000002;
  ISC_REQ_REPLAY_DETECT = $00000004;
  ISC_REQ_SEQUENCE_DETECT = $00000008;
  ISC_REQ_CONFIDENTIALITY = $00000010;
  ISC_REQ_USE_SESSION_KEY = $00000020;
  ISC_REQ_PROMPT_FOR_CREDS = $00000040;
  ISC_REQ_USE_SUPPLIED_CREDS = $00000080;
  ISC_REQ_ALLOCATE_MEMORY = $00000100;
  ISC_REQ_USE_DCE_STYLE = $00000200;
  ISC_REQ_DATAGRAM = $00000400;
  ISC_REQ_CONNECTION = $00000800;
  ISC_REQ_CALL_LEVEL = $00001000;
  ISC_REQ_FRAGMENT_SUPPLIED = $00002000;
  ISC_REQ_EXTENDED_ERROR = $00004000;
  ISC_REQ_STREAM = $00008000;
  ISC_REQ_INTEGRITY = $00010000;
  ISC_REQ_IDENTIFY = $00020000;
  ISC_REQ_NULL_SESSION = $00040000;
  ISC_REQ_MANUAL_CRED_VALIDATION = $00080000;
  ISC_REQ_RESERVED1 = $00100000;
  ISC_REQ_FRAGMENT_TO_FIT = $00200000;
  ISC_REQ_FLAGS =
    ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or
    ISC_REQ_CONFIDENTIALITY or ISC_REQ_EXTENDED_ERROR or
    ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_STREAM or
    ISC_REQ_MANUAL_CRED_VALIDATION;

  // Server-side flags for AcceptSecurityContext
  ASC_REQ_DELEGATE = $00000001;
  ASC_REQ_MUTUAL_AUTH = $00000002;
  ASC_REQ_REPLAY_DETECT = $00000004;
  ASC_REQ_SEQUENCE_DETECT = $00000008;
  ASC_REQ_CONFIDENTIALITY = $00000010;
  ASC_REQ_USE_SESSION_KEY = $00000020;
  ASC_REQ_ALLOCATE_MEMORY = $00000100;
  ASC_REQ_USE_DCE_STYLE = $00000200;
  ASC_REQ_DATAGRAM = $00000400;
  ASC_REQ_CONNECTION = $00000800;
  ASC_REQ_CALL_LEVEL = $00001000;
  ASC_REQ_FRAGMENT_SUPPLIED = $00002000;
  ASC_REQ_EXTENDED_ERROR = $00004000;
  ASC_REQ_STREAM = $00008000;
  ASC_REQ_INTEGRITY = $00010000;
  ASC_REQ_LICENSING = $00020000;
  ASC_REQ_IDENTIFY = $00040000;
  ASC_REQ_ALLOW_NULL_SESSION = $00080000;
  ASC_REQ_ALLOW_NON_USER_LOGONS = $00100000;
  ASC_REQ_ALLOW_CONTEXT_REPLAY = $00200000;
  ASC_REQ_FRAGMENT_TO_FIT = $00400000;
  ASC_REQ_FLAGS =
    ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or
    ASC_REQ_CONFIDENTIALITY or ASC_REQ_EXTENDED_ERROR or
    ASC_REQ_ALLOCATE_MEMORY or ASC_REQ_STREAM;

  SECBUFFER_VERSION = 0;
  SECBUFFER_EMPTY = 0;
  SECBUFFER_DATA = 1;
  SECBUFFER_TOKEN = 2;
  SECBUFFER_EXTRA = 5;
  SECBUFFER_STREAM_TRAILER = 6;
  SECBUFFER_STREAM_HEADER = 7;

  SEC_E_OK = 0;
  SEC_I_CONTINUE_NEEDED = $00090312;
  SEC_I_INCOMPLETE_CREDENTIALS = $00090320;
  SEC_I_RENEGOTIATE = $00090321;
  SEC_I_CONTEXT_EXPIRED	= $00090317;
  SEC_E_INCOMPLETE_MESSAGE = $80090318;
  SEC_E_INVALID_TOKEN = $80090308;

  UNISP_NAME = 'Microsoft Unified Security Protocol Provider';
  SECPKG_ATTR_STREAM_SIZES = 4;
  SECURITY_NATIVE_DREP = $10;
  SCHANNEL_SHUTDOWN = 1;
  
  // SChannel Credential Constants
  SCHANNEL_CRED_VERSION = 4;
  SCH_CRED_NO_DEFAULT_CREDS = $00000010;
  SCH_CRED_MANUAL_CRED_VALIDATION = $00000008;


implementation

// Add reference to NetCom7 lines unit
uses ncLines;

// We make a descendant of TncLine so that we can access the protected methods
type
  TncLineInternal = class(TncLine);

var
  SockSChannelApi: Boolean;
  CryptApi: Boolean;

{ Certificate Loading Functions }

function LoadCertificateFromPFX(const FileName: AnsiString; const Password: AnsiString): PCCERT_CONTEXT;
var
  FileHandle: THandle;
  FileSize: DWORD;
  PFXData: array of Byte;
  BytesRead: DWORD;
  PFXBlob: CRYPT_DATA_BLOB;
  CertStore: HCERTSTORE;
  PasswordW: WideString;
begin
  Result := nil;
  
  if not CryptApi then
  begin
    // CryptAPI not available
    Exit;
  end;
    
  // Read PFX file
  FileHandle := CreateFileA(PAnsiChar(FileName), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if FileHandle = INVALID_HANDLE_VALUE then
  begin
    // Failed to open file
    Exit;
  end;
    
  try
    FileSize := GetFileSize(FileHandle, nil);
    if FileSize = INVALID_FILE_SIZE then
    begin
      // Invalid file size
      Exit;
    end;
      
    SetLength(PFXData, FileSize);
    if not ReadFile(FileHandle, PFXData[0], FileSize, BytesRead, nil) or (BytesRead <> FileSize) then
    begin
      // Failed to read file data
      Exit;
    end;
  finally
    CloseHandle(FileHandle);
  end;
  
  // Import PFX
  PFXBlob.cbData := FileSize;
  PFXBlob.pbData := @PFXData[0];
  PasswordW := WideString(string(Password)); // Convert AnsiString to WideString
  
  // Import with no flags to allow private key access (PKCS12_NO_PERSIST_KEY may prevent access)
  CertStore := PFXImportCertStore(@PFXBlob, PWideChar(PasswordW), 0);
  if CertStore = nil then
  begin
    // Fallback to original approach
    CertStore := PFXImportCertStore(@PFXBlob, PWideChar(PasswordW), PKCS12_NO_PERSIST_KEY);
    if CertStore = nil then
    begin
      // PFXImportCertStore failed with all approaches
      Exit;
    end;
  end;
    
  try
    // Get first certificate from store
    Result := CertEnumCertificatesInStore(CertStore, nil);
  finally
    CertCloseStore(CertStore, 0);
  end;
end;

{ TSChannel }

procedure RaiseLastError; // not defined e.g. with Delphi 5
var
  LastError: Integer;
begin
  LastError := GetLastError;
  if LastError <> 0 then
    raise ESChannel.CreateFmt('System Error %d [%s]', [LastError, SysErrorMessage(LastError)])
  else
    raise ESChannel.Create('Unknown SChannel error');
end;

function CheckSEC_E_OK(res: cardinal): cardinal;
begin
  if res <> SEC_E_OK then
  begin
    case res of
      $80090318: raise ESChannel.Create('SEC_E_INCOMPLETE_MESSAGE');
      $80090308: raise ESChannel.Create('SEC_E_INVALID_TOKEN');
      $00090312: raise ESChannel.Create('SEC_I_CONTINUE_NEEDED (unexpected)');
      $00090320: raise ESChannel.Create('SEC_I_INCOMPLETE_CREDENTIALS (unexpected)');
      $00090321: raise ESChannel.Create('SEC_I_RENEGOTIATE (unexpected)');
      $00090317: raise ESChannel.Create('SEC_I_CONTEXT_EXPIRED (unexpected)');
      else
        raise ESChannel.CreateFmt('SChannel error: 0x%08X', [res]);
    end;
  end;
  result := res;
end;

function CheckSocket(res: integer): cardinal;
begin
  if res <= 0 then
    raise ESChannel.CreateFmt('Socket Error %d', [res]);
  result := res;
end;

const
  TLSRECMAXSIZE = 19000; // stack buffers for TSChannelClient.Receive/Send

type
  {$ifdef USERECORDWITHMETHODS}THandshakeBuf = record
    {$else}THandshakeBuf = object{$endif}
  public
    buf: array[0..2] of TSecBuffer;
    input, output: TSecBufferDesc;
    procedure Init;
  end;

procedure THandshakeBuf.Init;
begin
  input.ulVersion := SECBUFFER_VERSION;
  input.cBuffers := 2;
  input.pBuffers := @buf[0];
  buf[0].cbBuffer := 0;
  buf[0].BufferType := SECBUFFER_TOKEN;
  buf[0].pvBuffer := nil;
  buf[1].cbBuffer := 0;
  buf[1].BufferType := SECBUFFER_EMPTY;
  buf[1].pvBuffer := nil;
  output.ulVersion := SECBUFFER_VERSION;
  output.cBuffers := 1;
  output.pBuffers := @buf[2];
  buf[2].cbBuffer := 0;
  buf[2].BufferType := SECBUFFER_TOKEN;
  buf[2].pvBuffer := nil;
end;

{ TSChannelClient - Client-side SChannel implementation }

procedure TSChannelClient.AppendData(const aBuffer: TSecBuffer);
var
  newlen: integer;
begin
  newlen := DataCount + integer(aBuffer.cbBuffer);
  if newlen > Length(Data) then
    SetLength(Data, newlen);
  Move(aBuffer.pvBuffer^, PByteArray(Data)[DataCount], aBuffer.cbBuffer);
  inc(DataCount, aBuffer.cbBuffer);
end;

procedure TSChannelClient.AfterConnection(aLine: TObject; const aTargetHost: AnsiString; aIgnoreCertificateErrors: boolean);
var
  TargetHostString: string;
  f: cardinal;
  res: cardinal;
  schannelCred: TSChannelCred;
  buf: THandshakeBuf;

begin
  // Clean up any existing TLS context from previous connection
  if Initialized then
  begin
    try
      if Cred.dwLower <> nil then
      begin
        DeleteSecurityContext(@Ctxt);
        FreeCredentialsHandle(@Cred);
      end;
    except
      on E: Exception do
      begin
        // Continue with initialization anyway
      end;
    end;
    
    // Reset all state variables
    Cred.dwLower := nil;
    Cred.dwUpper := nil;
    Initialized := false;
    SessionClosed := false;
    DataCount := 0;
    DataPos := 0;
  end;
  
  if not SockSChannelApi then
    raise ESChannel.Create('SChannel API not available');
  
  try
    TargetHostString := string(aTargetHost);
    
    FillChar(schannelCred, SizeOf(schannelCred), 0);
    schannelCred.dwVersion := SCHANNEL_CRED_VERSION;
    schannelCred.dwFlags := SCH_CRED_NO_DEFAULT_CREDS;
    if aIgnoreCertificateErrors then
      schannelCred.dwFlags := schannelCred.dwFlags or SCH_CRED_MANUAL_CRED_VALIDATION;
    
    res := AcquireCredentialsHandle(nil, UNISP_NAME, SECPKG_CRED_OUTBOUND,
      nil, @schannelCred, nil, nil, @Cred, nil);
    if res <> SEC_E_OK then
    begin
      CheckSEC_E_OK(res);
    end;
    
    DataPos := 0;
    DataCount := 0;
    SetLength(Data, TLSRECMAXSIZE);
    
    // Initialize handshake buffer
    buf.Init;
    
    // Client initiates handshake
    res := InitializeSecurityContext(@Cred, nil, PWideChar(WideString(TargetHostString)),
      ISC_REQ_FLAGS, 0, SECURITY_NATIVE_DREP, nil, 0, @Ctxt, @buf.output, @f, nil);
    
    if res <> SEC_I_CONTINUE_NEEDED then
    begin
      CheckSEC_E_OK(res);
    end;
    
    // Send initial handshake data
    try
      TncLineInternal(TncLine(aLine)).SendBuffer(buf.buf[2].pvBuffer^, buf.buf[2].cbBuffer);
      FreeContextBuffer(buf.buf[2].pvBuffer);
    except
      on E: Exception do
      begin
        raise ESChannel.CreateFmt('Failed to send initial handshake: %s', [E.Message]);
      end;
    end;
    
    SetLength(Data, TLSRECMAXSIZE);
    
    // Complete the handshake by calling HandshakeLoop
    try
      HandshakeLoop(aLine);
      
      // Initialize stream sizes after handshake completion
      res := QueryContextAttributes(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes);
      if res <> SEC_E_OK then
      begin
        raise ESChannel.CreateFmt('Failed to query stream sizes: 0x%08X', [res]);
      end;
      
      InputSize := Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
      
      if InputSize > TLSRECMAXSIZE then
        raise ESChannel.CreateFmt('InputSize=%d>%d', [InputSize, TLSRECMAXSIZE]);
      
      SetLength(Input, InputSize);
      
      Initialized := true;
    except
      on E: Exception do
      begin
        raise ESChannel.CreateFmt('Client handshake failed: %s', [E.Message]);
      end;
    end;
  except
    on E: Exception do
    begin
      raise Exception.CreateFmt('Client TLS initialization failed: %s', [E.Message]);
    end;
  end;
end;

procedure TSChannelClient.HandshakeLoop(aLine: TObject);
var
  buf: THandshakeBuf;
  res, f: cardinal;
  Line: TncLine;
begin
  Line := TncLine(aLine);
  res := SEC_I_CONTINUE_NEEDED;
  while (res = SEC_I_CONTINUE_NEEDED) or (res = SEC_E_INCOMPLETE_MESSAGE) do begin
    inc(DataCount, CheckSocket(TncLineInternal(Line).RecvBuffer(
      PByteArray(Data)[DataCount], length(Data) - DataCount)));
    buf.Init;
    buf.buf[0].cbBuffer := DataCount;
    buf.buf[0].BufferType := SECBUFFER_TOKEN;
    buf.buf[0].pvBuffer := pointer(Data);
    res := InitializeSecurityContext(@Cred, @Ctxt, nil, ISC_REQ_FLAGS, 0,
      SECURITY_NATIVE_DREP, @buf.input, 0, @Ctxt, @buf.output, @f, nil);
    if res = SEC_I_INCOMPLETE_CREDENTIALS then
      // check https://stackoverflow.com/a/47479968/458259
      res := InitializeSecurityContext(@Cred, @Ctxt, nil, ISC_REQ_FLAGS, 0,
        SECURITY_NATIVE_DREP, @buf.input, 0, @Ctxt, @buf.output, @f, nil);
    if (res = SEC_E_OK) or (res = SEC_I_CONTINUE_NEEDED) or
       ((f and ISC_REQ_EXTENDED_ERROR) <> 0) then begin
      if (buf.buf[2].cbBuffer <> 0) and (buf.buf[2].pvBuffer <> nil) then begin
        CheckSocket(TncLineInternal(Line).SendBuffer(buf.buf[2].pvBuffer^, buf.buf[2].cbBuffer));
        CheckSEC_E_OK(FreeContextBuffer(buf.buf[2].pvBuffer));
      end;
    end;
    if buf.buf[1].BufferType = SECBUFFER_EXTRA then begin
      // reuse pending Data bytes to avoid SEC_E_INVALID_TOKEN
      Move(PByteArray(Data)[cardinal(DataCount) - buf.buf[1].cbBuffer],
           PByteArray(Data)[0], buf.buf[1].cbBuffer);
      DataCount := buf.buf[1].cbBuffer;
    end else
    if res <> SEC_E_INCOMPLETE_MESSAGE then
      DataCount := 0;
  end;
  CheckSEC_E_OK(res);
end;

procedure TSChannelClient.BeforeDisconnection(aLine: TObject);
var
  desc: TSecBufferDesc;
  buf: TSecBuffer;
  dt, f: cardinal;
  Line: TncLine;
begin
  if Initialized then
  try
    Line := TncLine(aLine);
    if (Line <> nil) and Line.Active then begin
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 1;
      desc.pBuffers := @buf;
      buf.cbBuffer := 4;
      buf.BufferType := SECBUFFER_TOKEN;
      dt := SCHANNEL_SHUTDOWN;
      buf.pvBuffer := @dt;
      if ApplyControlToken(@Ctxt, @desc) = SEC_E_OK then begin
        buf.cbBuffer := 0;
        buf.BufferType := SECBUFFER_TOKEN;
        buf.pvBuffer := nil;
        if InitializeSecurityContext(@Cred, @Ctxt, nil, ISC_REQ_FLAGS, 0,
           SECURITY_NATIVE_DREP, nil, 0, @Ctxt, @desc, @f, nil) = SEC_E_OK then begin
          TncLineInternal(Line).SendBuffer(buf.pvBuffer^, buf.cbBuffer);
          FreeContextBuffer(buf.pvBuffer);
        end;
      end;
    end;
    DeleteSecurityContext(@Ctxt);
    FreeCredentialsHandle(@Cred);
  finally
    Cred.dwLower := nil;
    Cred.dwUpper := nil;
    Initialized := false;
  end;
end;

function TSChannelClient.Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res: cardinal;
  read, i: integer;
  needsRenegotiate: boolean;
  Line: TncLine;

  function DecryptInput: cardinal;
  begin
    buf[0].cbBuffer := InputCount;
    buf[0].BufferType := SECBUFFER_DATA;
    buf[0].pvBuffer := pointer(Input);
    buf[1].cbBuffer := 0;
    buf[1].BufferType := SECBUFFER_EMPTY;
    buf[1].pvBuffer := nil;
    buf[2].cbBuffer := 0;
    buf[2].BufferType := SECBUFFER_EMPTY;
    buf[2].pvBuffer := nil;
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    result := DecryptMessage(@Ctxt, @desc, 0, nil);
  end;
begin
  Line := TncLine(aLine);
  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).RecvBuffer(aBuffer^, aLength);
    exit;
  end;
  result := 0;
  if not SessionClosed then
    while DataCount = 0 do
    try
      DataPos := 0;
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 4;
      desc.pBuffers := @buf[0];
      repeat
        read := TncLineInternal(Line).RecvBuffer(PByteArray(Input)[InputCount], InputSize - InputCount);
        if read <= 0 then begin
          result := read; // return socket error
          exit;
        end;
        inc(InputCount, read);
        res := DecryptInput;
      until res <> SEC_E_INCOMPLETE_MESSAGE;
      needsRenegotiate := false;
      repeat
        case res of
          SEC_I_RENEGOTIATE: 
            begin
              needsRenegotiate := true;
            end;
          SEC_I_CONTEXT_EXPIRED: 
            begin
              SessionClosed := true;
            end;
          SEC_E_INCOMPLETE_MESSAGE: break;
          else CheckSEC_E_OK(res);
        end;
        InputCount := 0;
        for i := 1 to 3 do
          case buf[i].BufferType of
            SECBUFFER_DATA: 
              begin
                AppendData(buf[i]);
              end;
            SECBUFFER_EXTRA: 
              begin
                Move(buf[i].pvBuffer^, pointer(Input)^, buf[i].cbBuffer);
                InputCount := buf[i].cbBuffer;
              end;
          end;
        if InputCount = 0 then
          break;
        res := DecryptInput;
      until false;
      if needsRenegotiate then
      begin
        HandshakeLoop(aLine);
      end;
    except
      on E: Exception do
      begin
        exit; // shutdown the connection on ESChannel fatal error
      end;
    end;
  result := DataCount;
  if aLength < result then
    result := aLength;
  Move(PByteArray(Data)[DataPos], aBuffer^, result);
  inc(DataPos, result);
  dec(DataCount, result);
end;

function TSChannelClient.Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res, sent, s, len, trailer, pending, templen: cardinal;
  temp: array[0..TLSRECMAXSIZE] of byte;
  Line: TncLine;

begin
  Line := TncLine(aLine);
  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).SendBuffer(aBuffer^, aLength);
    exit;
  end;
  
  // Check if Sizes has been initialized
  if Sizes.cbMaximumMessage = 0 then
  begin
    if QueryContextAttributes(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes) <> SEC_E_OK then
    begin
      result := -1;
      exit;
    end;
  end;
  
  result := 0;
  desc.ulVersion := SECBUFFER_VERSION;
  desc.cBuffers := 4;
  desc.pBuffers := @buf[0];
  pending := aLength;
  while pending > 0 do begin
    templen := pending;
    if templen > Sizes.cbMaximumMessage then
      templen := Sizes.cbMaximumMessage;
    Move(aBuffer^, temp[Sizes.cbHeader], templen);
    inc(PByte(aBuffer), templen);
    dec(pending, templen);
    trailer := Sizes.cbHeader + templen;
    buf[0].cbBuffer := Sizes.cbHeader;
    buf[0].BufferType := SECBUFFER_STREAM_HEADER;
    buf[0].pvBuffer := @temp;
    buf[1].cbBuffer := templen;
    buf[1].BufferType := SECBUFFER_DATA;
    buf[1].pvBuffer := @temp[Sizes.cbHeader];
    buf[2].cbBuffer := Sizes.cbTrailer;
    buf[2].BufferType := SECBUFFER_STREAM_TRAILER;
    buf[2].pvBuffer := @temp[trailer];
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    if EncryptMessage(@Ctxt, 0, @desc, 0) <> SEC_E_OK then
    begin
      exit; // shutdown the connection on SChannel error
    end;
    len := buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer;
    sent := 0;
    repeat
      s := TncLineInternal(Line).SendBuffer(PByteArray(@temp)[sent], len);
      if s = len then
        break; // whole message sent
      if s = 0 then
      begin
        exit;  // report connection closed
      end;
      if integer(s) < 0 then begin
        result := s;
        exit; // report socket fatal error
      end
      else begin
        dec(len, s);
        inc(sent, s);
      end;
      Sleep(1); // try again
    until false;
  end;
  result := aLength;
end;

{ TSChannelServer - Server-side SChannel implementation }

procedure TSChannelServer.AppendData(const aBuffer: TSecBuffer);
var
  newlen: integer;
begin
  newlen := DataCount + integer(aBuffer.cbBuffer);
  if newlen > Length(Data) then
    SetLength(Data, newlen);
  Move(aBuffer.pvBuffer^, PByteArray(Data)[DataCount], aBuffer.cbBuffer);
  inc(DataCount, aBuffer.cbBuffer);
end;

procedure TSChannelServer.AfterConnection(aLine: TObject; const aCertificateFile, aPrivateKeyPassword: AnsiString);
var
  buf: THandshakeBuf;
  res, f: cardinal;
  Line: TncLine;
  SchannelCred: TSChannelCred;
  pCertContext: PCCERT_CONTEXT;
  pCertArray: PCCERT_CONTEXT; // Array of one certificate context for paCred

begin
  try
    // Clean up any existing TLS context from previous connection
    if Initialized then
    begin
      try
        if Cred.dwLower <> nil then
        begin
          DeleteSecurityContext(@Ctxt);
          FreeCredentialsHandle(@Cred);
        end;
      except
        on E: Exception do
        begin
          // Continue with initialization anyway
        end;
      end;
      
      // Reset all state variables
      Cred.dwLower := nil;
      Cred.dwUpper := nil;
      Initialized := false;
      HandshakeCompleted := false;
      SessionClosed := false;
      DataCount := 0;
      DataPos := 0;
      InputCount := 0;
    end;
    
    if not SockSChannelApi then
      raise ESChannel.Create('SChannel API not available');
  
  Line := TncLine(aLine);
  
  // Initialize server credentials with certificate
  FillChar(SchannelCred, SizeOf(SchannelCred), 0);
  SchannelCred.dwVersion := 4; // SCHANNEL_CRED_VERSION
  SchannelCred.grbitEnabledProtocols := SP_PROT_TLS1_2_SERVER or SP_PROT_TLS1_3_SERVER;
  SchannelCred.dwFlags := 0; // No special flags for server
  
  // Load certificate from PFX file
  pCertContext := nil;
  if aCertificateFile <> '' then
  begin
    pCertContext := LoadCertificateFromPFX(aCertificateFile, aPrivateKeyPassword);
    if pCertContext <> nil then
    begin
      // CRITICAL FIX: paCred must point to an array of certificate contexts
      pCertArray := pCertContext; // Create array element
      SchannelCred.cCreds := 1;
      SchannelCred.paCred := @pCertArray; // Point to the array (not @pCertContext)
    end
    else
    begin
      raise ESChannel.CreateFmt('Failed to load certificate from: %s', [string(aCertificateFile)]);
    end;
  end
  else
  begin
    raise ESChannel.Create('Certificate file required for TLS server');
  end;
  
  try
    res := AcquireCredentialsHandle(nil, UNISP_NAME, SECPKG_CRED_INBOUND,
      nil, @SchannelCred, nil, nil, @Cred, nil);
      
    if res <> SEC_E_OK then
    begin
      CheckSEC_E_OK(res);
    end;
    
    DataPos := 0;
    DataCount := 0;
    SetLength(Data, TLSRECMAXSIZE);
    SetLength(Input, TLSRECMAXSIZE); // Pre-allocate input buffer
    InputCount := 0;
    DataPos := 0;
    DataCount := 0;
    Initialized := true; // Mark as initialized but handshake not yet completed
    HandshakeCompleted := false; // Handshake will be triggered when first TLS data arrives
    
  finally
    // Free certificate context
    if pCertContext <> nil then
    begin
      CertFreeCertificateContext(pCertContext);
    end;
  end;
  except
    on E: Exception do
    begin
      raise ESChannel.CreateFmt('Server TLS initialization failed: %s', [E.Message]);
    end;
  end;
end;

procedure TSChannelServer.HandshakeLoop(aLine: TObject);
var
  buf: THandshakeBuf;
  res, f: cardinal;
  Line: TncLine;
  fDone: boolean;
  fInitContext: boolean;

begin
  Line := TncLine(aLine);
  fDone := false;
  fInitContext := true;
  
  try
    while not fDone do
    begin
      // Read client data
      try
        inc(DataCount, CheckSocket(TncLineInternal(Line).RecvBuffer(
          PByteArray(Data)[DataCount], length(Data) - DataCount)));
      except
        on E: Exception do
        begin
          raise ESChannel.CreateFmt('Failed to receive client data: %s', [E.Message]);
        end;
      end;
      
      buf.Init;
      buf.buf[0].cbBuffer := DataCount;
      buf.buf[0].BufferType := SECBUFFER_TOKEN;
      buf.buf[0].pvBuffer := pointer(Data);
      
      // Server-side handshake using AcceptSecurityContext
      if fInitContext then
      begin
        // CRITICAL: Server must use AcceptSecurityContext, not InitializeSecurityContext
        res := AcceptSecurityContext(@Cred, nil, @buf.input, 
          ASC_REQ_FLAGS, SECURITY_NATIVE_DREP, @Ctxt, @buf.output, @f, nil);
        fInitContext := false;
      end
      else
      begin
        res := AcceptSecurityContext(@Cred, @Ctxt, @buf.input, 
          ASC_REQ_FLAGS, SECURITY_NATIVE_DREP, @Ctxt, @buf.output, @f, nil);
      end;
      
      case res of
        SEC_E_OK: 
          begin
            fDone := true;
          end;
        SEC_I_CONTINUE_NEEDED: 
          begin
            // Continue handshake
          end;
        SEC_I_INCOMPLETE_CREDENTIALS: 
          begin
            // Continue with current data
          end;
        SEC_E_INCOMPLETE_MESSAGE: 
          begin
            // Need more data from client
            continue;
          end;
        else
        begin
          raise ESChannel.CreateFmt('AcceptSecurityContext failed: 0x%08X', [res]);
        end;
      end;
      
      // Send response to client if needed
      if (buf.buf[2].cbBuffer <> 0) and (buf.buf[2].pvBuffer <> nil) then
      begin
        try
          CheckSocket(TncLineInternal(Line).SendBuffer(buf.buf[2].pvBuffer^, buf.buf[2].cbBuffer));
          CheckSEC_E_OK(FreeContextBuffer(buf.buf[2].pvBuffer));
        except
          on E: Exception do
          begin
            raise ESChannel.CreateFmt('Failed to send server response: %s', [E.Message]);
          end;
        end;
      end;
      
      // Handle extra data
      if buf.buf[1].BufferType = SECBUFFER_EXTRA then
      begin
        Move(PByteArray(Data)[cardinal(DataCount) - buf.buf[1].cbBuffer],
             PByteArray(Data)[0], buf.buf[1].cbBuffer);
        DataCount := buf.buf[1].cbBuffer;
      end
      else if not fDone then
      begin
        DataCount := 0;
      end;
    end;
    
  except
    on E: Exception do
    begin
      raise ESChannel.CreateFmt('TLS handshake failed: %s', [E.Message]);
    end;
  end;
end;

procedure TSChannelServer.BeforeDisconnection(aLine: TObject);
var
  desc: TSecBufferDesc;
  buf: TSecBuffer;
  dt, f: cardinal;
  Line: TncLine;
begin
  if Initialized then
  try
    Line := TncLine(aLine);
    if (Line <> nil) and Line.Active then begin
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 1;
      desc.pBuffers := @buf;
      buf.cbBuffer := 4;
      buf.BufferType := SECBUFFER_TOKEN;
      dt := SCHANNEL_SHUTDOWN;
      buf.pvBuffer := @dt;
      if ApplyControlToken(@Ctxt, @desc) = SEC_E_OK then begin
        buf.cbBuffer := 0;
        buf.BufferType := SECBUFFER_TOKEN;
        buf.pvBuffer := nil;
        if AcceptSecurityContext(@Cred, @Ctxt, nil, ASC_REQ_FLAGS, 
           SECURITY_NATIVE_DREP, @Ctxt, @desc, @f, nil) = SEC_E_OK then begin
          TncLineInternal(Line).SendBuffer(buf.pvBuffer^, buf.cbBuffer);
          FreeContextBuffer(buf.pvBuffer);
        end;
      end;
    end;
    DeleteSecurityContext(@Ctxt);
    FreeCredentialsHandle(@Cred);
  finally
    Cred.dwLower := nil;
    Cred.dwUpper := nil;
    Initialized := false;
    HandshakeCompleted := false;
  end;
end;

function TSChannelServer.Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res: cardinal;
  read, i: integer;
  needsRenegotiate: boolean;
  Line: TncLine;

  function DecryptInput: cardinal;
  begin
    buf[0].cbBuffer := InputCount;
    buf[0].BufferType := SECBUFFER_DATA;
    buf[0].pvBuffer := pointer(Input);
    buf[1].cbBuffer := 0;
    buf[1].BufferType := SECBUFFER_EMPTY;
    buf[1].pvBuffer := nil;
    buf[2].cbBuffer := 0;
    buf[2].BufferType := SECBUFFER_EMPTY;
    buf[2].pvBuffer := nil;
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    result := DecryptMessage(@Ctxt, @desc, 0, nil);
  end;
begin
  Line := TncLine(aLine);
  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).RecvBuffer(aBuffer^, aLength);
    exit;
  end;
  
  // Check if handshake needs to be performed
  if not HandshakeCompleted then
  begin
    try
      HandshakeLoop(aLine);
      CheckSEC_E_OK(QueryContextAttributes(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes));
      InputSize := Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
      if InputSize > TLSRECMAXSIZE then
        raise ESChannel.CreateFmt('InputSize=%d>%d', [InputSize, TLSRECMAXSIZE]);
      SetLength(Input, InputSize);
      HandshakeCompleted := true;
      
      // CRITICAL FIX: Clear any leftover handshake data to prevent it from being returned as application data
      DataCount := 0;
      DataPos := 0;
      InputCount := 0;
      
      // CRITICAL: Return immediately to trigger handshake completion callback
      // We'll return 0 to indicate no application data was received, 
      // but set a special result to indicate handshake completion
      result := 0;
      exit;
    except
      on E: Exception do
      begin
        result := -1; // Return error
        exit;
      end;
    end;
  end;
  
  result := 0;
  if not SessionClosed then
    while DataCount = 0 do
    try
      DataPos := 0;
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 4;
      desc.pBuffers := @buf[0];
      repeat
        read := TncLineInternal(Line).RecvBuffer(PByteArray(Input)[InputCount], InputSize - InputCount);
        if read <= 0 then begin
          result := read; // return socket error
          exit;
        end;
        inc(InputCount, read);
        res := DecryptInput;
      until res <> SEC_E_INCOMPLETE_MESSAGE;
      needsRenegotiate := false;
      repeat
        case res of
          SEC_I_RENEGOTIATE: 
            begin
              needsRenegotiate := true;
            end;
          SEC_I_CONTEXT_EXPIRED: 
            begin
              SessionClosed := true;
            end;
          SEC_E_INCOMPLETE_MESSAGE: break;
          else CheckSEC_E_OK(res);
        end;
        InputCount := 0;
        for i := 1 to 3 do
          case buf[i].BufferType of
            SECBUFFER_DATA: AppendData(buf[i]);
            SECBUFFER_EXTRA: begin
              Move(buf[i].pvBuffer^, pointer(Input)^, buf[i].cbBuffer);
              InputCount := buf[i].cbBuffer;
            end;
          end;
        if InputCount = 0 then
          break;
        res := DecryptInput;
      until false;
      if needsRenegotiate then
        HandshakeLoop(aLine);
    except
      exit; // shutdown the connection on ESChannel fatal error
    end;
  result := DataCount;
  if aLength < result then
    result := aLength;
  Move(PByteArray(Data)[DataPos], aBuffer^, result);
  inc(DataPos, result);
  dec(DataCount, result);
end;

function TSChannelServer.Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res, sent, s, len, trailer, pending, templen: cardinal;
  temp: array[0..TLSRECMAXSIZE] of byte;
  Line: TncLine;

begin
  Line := TncLine(aLine);
  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).SendBuffer(aBuffer^, aLength);
    exit;
  end;
  
  // Check if Sizes has been initialized
  if Sizes.cbMaximumMessage = 0 then
  begin
    if QueryContextAttributes(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes) <> SEC_E_OK then
    begin
      result := -1;
      exit;
    end;
  end;
  
  result := 0;
  desc.ulVersion := SECBUFFER_VERSION;
  desc.cBuffers := 4;
  desc.pBuffers := @buf[0];
  pending := aLength;
  while pending > 0 do begin
    templen := pending;
    if templen > Sizes.cbMaximumMessage then
      templen := Sizes.cbMaximumMessage;
    Move(aBuffer^, temp[Sizes.cbHeader], templen);
    inc(PByte(aBuffer), templen);
    dec(pending, templen);
    trailer := Sizes.cbHeader + templen;
    buf[0].cbBuffer := Sizes.cbHeader;
    buf[0].BufferType := SECBUFFER_STREAM_HEADER;
    buf[0].pvBuffer := @temp;
    buf[1].cbBuffer := templen;
    buf[1].BufferType := SECBUFFER_DATA;
    buf[1].pvBuffer := @temp[Sizes.cbHeader];
    buf[2].cbBuffer := Sizes.cbTrailer;
    buf[2].BufferType := SECBUFFER_STREAM_TRAILER;
    buf[2].pvBuffer := @temp[trailer];
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    if EncryptMessage(@Ctxt, 0, @desc, 0) <> SEC_E_OK then
    begin
      exit; // shutdown the connection on SChannel error
    end;
    len := buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer;
    sent := 0;
    repeat
      s := TncLineInternal(Line).SendBuffer(PByteArray(@temp)[sent], len);
      if s = len then
        break; // whole message sent
      if s = 0 then
      begin
        exit;  // report connection closed
      end;
      if integer(s) < 0 then begin
        result := s;
        exit; // report socket fatal error
      end
      else begin
        dec(len, s);
        inc(sent, s);
      end;
      Sleep(1); // try again
    until false;
  end;
  result := aLength;
end;



initialization
  // Load SChannel API
  SockSChannelApi := False;
  CryptApi := False;
  try
    var SecurityDLL := LoadLibrary('secur32.dll');
    if SecurityDLL <> 0 then
    begin
      @AcquireCredentialsHandle := GetProcAddress(SecurityDLL, 'AcquireCredentialsHandleA');
      @FreeCredentialsHandle := GetProcAddress(SecurityDLL, 'FreeCredentialsHandle');
      @InitializeSecurityContext := GetProcAddress(SecurityDLL, 'InitializeSecurityContextW');
      @AcceptSecurityContext := GetProcAddress(SecurityDLL, 'AcceptSecurityContext');
      @DeleteSecurityContext := GetProcAddress(SecurityDLL, 'DeleteSecurityContext');
      @ApplyControlToken := GetProcAddress(SecurityDLL, 'ApplyControlToken');
      @QueryContextAttributes := GetProcAddress(SecurityDLL, 'QueryContextAttributesA');
      @FreeContextBuffer := GetProcAddress(SecurityDLL, 'FreeContextBuffer');
      @EncryptMessage := GetProcAddress(SecurityDLL, 'EncryptMessage');
      @DecryptMessage := GetProcAddress(SecurityDLL, 'DecryptMessage');
      
      SockSChannelApi := 
        Assigned(AcquireCredentialsHandle) and
        Assigned(FreeCredentialsHandle) and
        Assigned(InitializeSecurityContext) and
        Assigned(AcceptSecurityContext) and
        Assigned(DeleteSecurityContext) and
        Assigned(ApplyControlToken) and
        Assigned(QueryContextAttributes) and
        Assigned(FreeContextBuffer) and
        Assigned(EncryptMessage) and
        Assigned(DecryptMessage);
    end;
    
    // Load CryptoAPI
    var CryptDLL := LoadLibrary('crypt32.dll');
    if CryptDLL <> 0 then
    begin
      @CertOpenStore := GetProcAddress(CryptDLL, 'CertOpenStore');
      @CertCloseStore := GetProcAddress(CryptDLL, 'CertCloseStore');
      @CertEnumCertificatesInStore := GetProcAddress(CryptDLL, 'CertEnumCertificatesInStore');
      @CertFreeCertificateContext := GetProcAddress(CryptDLL, 'CertFreeCertificateContext');
      @PFXImportCertStore := GetProcAddress(CryptDLL, 'PFXImportCertStore');
      
      CryptApi := 
        Assigned(CertOpenStore) and
        Assigned(CertCloseStore) and
        Assigned(CertEnumCertificatesInStore) and
        Assigned(CertFreeCertificateContext) and
        Assigned(PFXImportCertStore);
    end;
    
  except
    on E: Exception do
    begin
      SockSChannelApi := False;
      CryptApi := False;
    end;
  end;

end.