{$R-}
{$Q-}
unit ncEncCrypt2;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  Classes, Sysutils;

resourcestring
  rsHashNotInitialised = 'Hash not initialized';
  rsCipherNotInitialised = 'Cipher not initialized';
  rsCipherInvalidKeySize = 'Invalid key size';
  rsCipherInsufficientMemory = 'Unable to allocate sufficient memory for hash digest';

type
  UInt32Array = array of UInt32;
  PUInt32Array = ^UInt32Array;

  // ******************************************************************************
  // The base class from which all hash algorithms are to be derived

  EEncHashException = class(Exception);

  TncEncHash = class(TComponent)
  protected
    FInitialized: Boolean; // Whether or not the algorithm has been initialized
  public
    destructor Destroy; override;

    // Initialize the hash algorithm
    procedure Init; virtual; abstract;

    // Update the hash buffer with Size bytes of data from Buffer
    procedure Update(const aBuffer; aSize: NativeUInt); virtual; abstract;
    // Update the hash buffer with Size bytes of data from the stream
    procedure UpdateStream(const aStream: TStream; aSize: UInt64);
    // Update the hash buffer with the string
    procedure UpdateStr(const aStr: AnsiString);

    // Create the final digest and clear the stored information
    // The size of the Digest var must be at least equal to the hash size
    procedure Final(var aDigest); virtual; abstract;

    // Clear any stored information with out creating the final digest
    procedure Burn; virtual; abstract;

    // Get the algorithm id
    // Get the algorithm name
    class function GetAlgorithm: string; virtual; abstract;

    // Get the size of the digest produced - in bits
    class function GetHashSize: Integer; virtual; abstract;

    // Tests the implementation with several test vectors
    class function SelfTest: Boolean; virtual; abstract;
    function SelfTestProp: Boolean;

    property Initialized: Boolean read FInitialized;
  published
    property Algorithm: string read GetAlgorithm;
    property HashSize: Integer read GetHashSize;
  end;

  TncEncHashClass = class of TncEncHash;

  // ******************************************************************************
  // The base class from which all encryption components will be derived.
  // Stream ciphers will be derived directly from this class where as
  // Block ciphers will have a further foundation class TncEnc_blockcipher.

  EEncCipherException = class(Exception);

  TncEncCipher = class(TComponent)
  protected
    FInitialized: Boolean; // Whether or not the key setup has been done yet
  public
    constructor Create(aOwner: TComponent); override;
    destructor Destroy; override;

    // Do key setup based on the data in Key, size is in bits
    procedure Init(const Key; Size: NativeUInt; InitVector: Pointer); virtual;
    // Do key setup based on a hash of the key string
    procedure InitStr(const aKey: AnsiString; const aHashType: TncEncHashClass);
    // Clear all stored key information
    procedure Burn; virtual;
    // Reset any stored chaining information
    procedure Reset; virtual; abstract;

    // Encrypt size bytes of data and place in Outdata
    procedure Encrypt(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Decrypt size bytes of data and place in Outdata
    procedure Decrypt(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Encrypt size bytes of data from InStream and place in OutStream
    function EncryptStream(InStream, OutStream: TStream; Size: UInt64): UInt64;
    // Decrypt size bytes of data from InStream and place in OutStream
    function DecryptStream(InStream, OutStream: TStream; Size: UInt64): UInt64;

    // Get the algorithm name
    class function GetAlgorithm: string; virtual; abstract;
    // Get the maximum key size (in bits)
    class function GetMaxKeySize: Integer; virtual; abstract;
    function GetMaxKeySizeProp: Integer;
    // Tests the implementation with several test vectors
    class function SelfTest: Boolean; virtual; abstract;
    function SelfTestProp: Boolean;

    property Initialized: Boolean read FInitialized;
  published
    property Algorithm: string read GetAlgorithm;
    property MaxKeySize: Integer read GetMaxKeySize;
  end;

  TncEncCipherClass = class of TncEncCipher;

  // ******************************************************************************
  // The base class from which all block ciphers are to be derived, this
  // extra class takes care of the different block encryption modes.

  EEncBlockcipherException = class(EEncHashException);
  TncEncCipherMode = (cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR);

  TncEncBlockCipher = class(TncEncCipher)
  protected
    FCipherMode: TncEncCipherMode; // The cipher mode the encrypt method uses
    procedure InitKey(const Key; Size: LongWord); virtual; abstract;
  public
    constructor Create(aOwner: TComponent); override;

    // Encrypt size bytes of data and place in Outdata using CipherMode
    procedure Encrypt(const Indata; var Outdata; Size: NativeUInt); override;
    // Decrypt size bytes of data and place in Outdata using CipherMode
    procedure Decrypt(const Indata; var Outdata; Size: NativeUInt); override;
    // Encrypt a block of data using the ECB method of encryption
    procedure EncryptECB(const Indata; var Outdata); virtual; abstract;
    // Decrypt a block of data using the ECB method of decryption
    procedure DecryptECB(const Indata; var Outdata); virtual; abstract;
    // Encrypt size bytes of data using the CBC method of encryption
    procedure EncryptCBC(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Decrypt size bytes of data using the CBC method of decryption
    procedure DecryptCBC(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Encrypt size bytes of data using the CFB (8 bit) method of encryption
    procedure EncryptCFB8bit(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Decrypt size bytes of data using the CFB (8 bit) method of decryption
    procedure DecryptCFB8bit(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Encrypt size bytes of data using the CFB (block) method of encryption
    procedure EncryptCFBblock(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Decrypt size bytes of data using the CFB (block) method of decryption
    procedure DecryptCFBblock(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Encrypt size bytes of data using the OFB method of encryption
    procedure EncryptOFB(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Decrypt size bytes of data using the OFB method of decryption
    procedure DecryptOFB(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Encrypt size bytes of data using the CTR method of encryption
    procedure EncryptCTR(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;
    // Decrypt size bytes of data using the CTR method of decryption
    procedure DecryptCTR(const Indata; var Outdata; Size: NativeUInt); virtual; abstract;

    // Get the block size of the cipher (in bits)
    class function GetBlockSize: Integer; virtual; abstract;
    function GetBlockSizeProp: Integer;

    // Returns the current chaining information, not the actual IV
    procedure GetIV(var Value); virtual; abstract;
    // Sets the IV to Value and performs a reset
    procedure SetIV(const Value); virtual; abstract;
  published
    property BlockSize: Integer read GetBlockSizeProp;
    property CipherMode: TncEncCipherMode read FCipherMode write FCipherMode default cmCBC;
  end;

  TncEncBlockCipherClass = class of TncEncBlockCipher;

procedure XorBlock(var InData1, InData2; const aSize: NativeUInt); inline;

implementation

uses ncEncryption;

{ TncEncHash }

destructor TncEncHash.Destroy;
begin
  if FInitialized then
    Burn;

  inherited Destroy;
end;

procedure TncEncHash.UpdateStream(const aStream: TStream; aSize: UInt64);
var
  Buffer: array [0 .. 8191] of Byte;
  i, Read: Integer;
begin
  for i := 1 to (aSize div Sizeof(Buffer)) do
  begin
    Read := aStream.Read(Buffer, Sizeof(Buffer));
    Update(Buffer, Read);
  end;
  if (aSize mod Sizeof(Buffer)) <> 0 then
  begin
    Read := aStream.Read(Buffer, aSize mod Sizeof(Buffer));
    Update(Buffer, Read);
  end;
end;

procedure TncEncHash.UpdateStr(const aStr: AnsiString);
begin
  if Length(aStr) > 0 then
    Update(aStr[1], Length(aStr));
end;

{ TncEncCipher }

constructor TncEncCipher.Create(aOwner: TComponent);
begin
  inherited Create(aOwner);
  Burn;
end;

destructor TncEncCipher.Destroy;
begin
  if FInitialized then
    Burn;
  inherited Destroy;
end;

procedure TncEncCipher.Init(const Key; Size: NativeUInt; InitVector: Pointer);
begin
  if FInitialized then
    Burn;
  if (Size <= 0) or ((Size and 3) <> 0) or (Size > NativeUInt(GetMaxKeySize)) then
    raise EEncBlockcipherException.Create(rsCipherInvalidKeySize)
  else
    FInitialized := true;
end;

procedure TncEncCipher.InitStr(const aKey: AnsiString; const aHashType: TncEncHashClass);
var
  Hash: TncEncHash;
  Digest: Pointer;
begin
  if FInitialized then
    Burn;
  try
    GetMem(Digest, aHashType.GetHashSize div 8);
    Hash := aHashType.Create(Self);
    Hash.Init;
    Hash.UpdateStr(aKey);
    Hash.Final(Digest^);
    Hash.Free;
    if MaxKeySize < aHashType.GetHashSize then
      Init(Digest^, MaxKeySize, nil)
    else
      Init(Digest^, aHashType.GetHashSize, nil);
    FillChar(Digest^, aHashType.GetHashSize div 8, $FF);
    FreeMem(Digest);
  except
    raise EEncBlockcipherException.Create(rsCipherInsufficientMemory);
  end;
end;

procedure TncEncCipher.Burn;
begin
  FInitialized := false;
end;

function TncEncCipher.EncryptStream(InStream, OutStream: TStream; Size: UInt64): UInt64;
var
  Buffer: array [0 .. 8191] of Byte;
  i, Read: Integer;
begin
  Result := 0;
  for i := 1 to (Size div Sizeof(Buffer)) do
  begin
    Read := InStream.Read(Buffer, Sizeof(Buffer));
    Inc(Result, Read);
    Encrypt(Buffer, Buffer, Read);
    OutStream.Write(Buffer, Read);
  end;
  if (Size mod Sizeof(Buffer)) <> 0 then
  begin
    Read := InStream.Read(Buffer, Size mod Sizeof(Buffer));
    Inc(Result, Read);
    Encrypt(Buffer, Buffer, Read);
    OutStream.Write(Buffer, Read);
  end;
end;

function TncEncCipher.DecryptStream(InStream, OutStream: TStream; Size: UInt64): UInt64;
var
  Buffer: array [0 .. 8191] of Byte;
  i, Read: Integer;
begin
  Result := 0;
  for i := 1 to (Size div Sizeof(Buffer)) do
  begin
    Read := InStream.Read(Buffer, Sizeof(Buffer));
    Inc(Result, Read);
    Decrypt(Buffer, Buffer, Read);
    OutStream.Write(Buffer, Read);
  end;
  if (Size mod Sizeof(Buffer)) <> 0 then
  begin
    Read := InStream.Read(Buffer, Size mod Sizeof(Buffer));
    Inc(Result, Read);
    Decrypt(Buffer, Buffer, Read);
    OutStream.Write(Buffer, Read);
  end;
end;

{ TncEncBlockCipher }

constructor TncEncBlockCipher.Create(aOwner: TComponent);
begin
  inherited Create(aOwner);
  FCipherMode := cmCBC;
end;

procedure TncEncBlockCipher.Encrypt(const Indata; var Outdata; Size: NativeUInt);
begin
  case FCipherMode of
    cmCBC:
      EncryptCBC(Indata, Outdata, Size);
    cmCFB8bit:
      EncryptCFB8bit(Indata, Outdata, Size);
    cmCFBblock:
      EncryptCFBblock(Indata, Outdata, Size);
    cmOFB:
      EncryptOFB(Indata, Outdata, Size);
    cmCTR:
      EncryptCTR(Indata, Outdata, Size);
  end;
end;

procedure TncEncBlockCipher.Decrypt(const Indata; var Outdata; Size: NativeUInt);
begin
  case FCipherMode of
    cmCBC:
      DecryptCBC(Indata, Outdata, Size);
    cmCFB8bit:
      DecryptCFB8bit(Indata, Outdata, Size);
    cmCFBblock:
      DecryptCFBblock(Indata, Outdata, Size);
    cmOFB:
      DecryptOFB(Indata, Outdata, Size);
    cmCTR:
      DecryptCTR(Indata, Outdata, Size);
  end;
end;

function TncEncHash.SelfTestProp: Boolean;
begin
  Result := SelfTest;
end;

function TncEncCipher.GetMaxKeySizeProp: Integer;
begin
  Result := GetMaxKeySize;
end;

function TncEncCipher.SelfTestProp: Boolean;
begin
  Result := SelfTest;
end;

function TncEncBlockCipher.GetBlockSizeProp: Integer;
begin
  Result := GetBlockSize;
end;

// Helpher functions

procedure XorBlock(var InData1, InData2; const aSize: NativeUInt);
var
  i: NativeUInt;
begin
  for i := 1 to aSize do
    PByte(NativeUInt(@InData1) + i - 1)^ := PByte(NativeUInt(@InData1) + i - 1)^ xor PByte(NativeUInt(@InData2) + i - 1)^;
end;

end.
