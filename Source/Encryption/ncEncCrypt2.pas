{$R-}
{$Q-}
unit ncEncCrypt2;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

  uses
    Classes, Sysutils;

  { ****************************************************************************** }
  { A few predefined types to help out }

  type
    Pbyte = ^byte;
    Pword = ^word;
    Pdword = ^dword;
    Pint64 = ^int64;
    dword = longword;
    Pwordarray = ^Twordarray;
    Twordarray = array [0 .. 19383] of word;
    Pdwordarray = ^Tdwordarray;
    Tdwordarray = array [0 .. 8191] of dword;

    { ****************************************************************************** }
    { The base class from which all hash algorithms are to be derived }

  type
    EncEnc_hash = class(Exception);
      TncEnc_hash = class(TComponent)protected fInitialized: boolean; { Whether or not the algorithm has been initialized }

    public
      property Initialized: boolean read fInitialized;

      { Get the algorithm id }
      class function GetAlgorithm: string; virtual; abstract;
      function GetAlgorithmProp: string;
      { Get the algorithm name }
      class function GetHashSize: integer; virtual; abstract;
      function GetHashSizeProp: integer;
      { Get the size of the digest produced - in bits }
      class function SelfTest: boolean; virtual; abstract;
      function SelfTestProp: boolean;
      { Tests the implementation with several test vectors }

      procedure Init; virtual; abstract;
      { Initialize the hash algorithm }
      procedure Final(var Digest); virtual; abstract;
      { Create the final digest and clear the stored information.
        The size of the Digest var must be at least equal to the hash size }
      procedure Burn; virtual; abstract;
      { Clear any stored information with out creating the final digest }

      procedure Update(const Buffer; Size: longword); virtual; abstract;
      { Update the hash buffer with Size bytes of data from Buffer }
      procedure UpdateStream(Stream: TStream; Size: longword);
      { Update the hash buffer with Size bytes of data from the stream }
      procedure UpdateStr(const Str: AnsiString);
      { Update the hash buffer with the string }

      destructor Destroy; override;

    published
      property Algorithm: string read GetAlgorithmProp;
      property HashSize: integer read GetHashSizeProp;
    end;

    TncEnc_hashclass = class of TncEnc_hash;

    { ****************************************************************************** }
    { The base class from which all encryption components will be derived. }
    { Stream ciphers will be derived directly from this class where as }
    { Block ciphers will have a further foundation class TncEnc_blockcipher. }

  type
    EncEnc_cipher = class(Exception);
      TncEnc_cipher = class(TComponent)protected fInitialized: boolean; // Whether or not the key setup has been done yet
    public
      property Initialized: boolean read fInitialized;

      { Get the algorithm id }
      class function GetAlgorithm: string; virtual; abstract;
      function GetAlgorithmProp: string;
      { Get the algorithm name }
      class function GetMaxKeySize: integer; virtual; abstract;
      function GetMaxKeySizeProp: integer;
      { Get the maximum key size (in bits) }
      class function SelfTest: boolean; virtual; abstract;
      function SelfTestProp: boolean;
      { Tests the implementation with several test vectors }

      procedure Init(const Key; Size: longword; InitVector: pointer); virtual;
      { Do key setup based on the data in Key, size is in bits }
      procedure InitStr(const Key: AnsiString; HashType: TncEnc_hashclass);
      { Do key setup based on a hash of the key string }
      procedure Burn; virtual;
      { Clear all stored key information }
      procedure Reset; virtual; abstract;
      { Reset any stored chaining information }
      procedure Encrypt(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Encrypt size bytes of data and place in Outdata }
      procedure Decrypt(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Decrypt size bytes of data and place in Outdata }
      function EncryptStream(InStream, OutStream: TStream; Size: longword): longword;
      { Encrypt size bytes of data from InStream and place in OutStream }
      function DecryptStream(InStream, OutStream: TStream; Size: longword): longword;
      { Decrypt size bytes of data from InStream and place in OutStream }

      constructor Create(AOwner: TComponent); override;
      destructor Destroy; override;

    published
      property Algorithm: string read GetAlgorithmProp;
      property MaxKeySize: integer read GetMaxKeySizeProp;
    end;

    TncEnc_cipherclass = class of TncEnc_cipher;

    { ****************************************************************************** }
    { The base class from which all block ciphers are to be derived, this }
    { extra class takes care of the different block encryption modes. }

  type
    TncEnc_ciphermode = (cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR);
    // cmCFB8bit is equal to ncEnccrypt v1.xx's CFB mode
    EncEnc_blockcipher = class(EncEnc_cipher);
      TncEnc_blockcipher = class(TncEnc_cipher)protected fCipherMode: TncEnc_ciphermode; { The cipher mode the encrypt method uses }

      procedure InitKey(const Key; Size: longword); virtual; abstract;

    public
      class function GetBlockSize: integer; virtual; abstract;
      function GetBlockSizeProp: integer;
      { Get the block size of the cipher (in bits) }

      procedure SetIV(const Value); virtual; abstract;
      { Sets the IV to Value and performs a reset }
      procedure GetIV(var Value); virtual; abstract;
      { Returns the current chaining information, not the actual IV }

      procedure Encrypt(const Indata; var Outdata; Size: longword); override;
      { Encrypt size bytes of data and place in Outdata using CipherMode }
      procedure Decrypt(const Indata; var Outdata; Size: longword); override;
      { Decrypt size bytes of data and place in Outdata using CipherMode }
      procedure EncryptECB(const Indata; var Outdata); virtual; abstract;
      { Encrypt a block of data using the ECB method of encryption }
      procedure DecryptECB(const Indata; var Outdata); virtual; abstract;
      { Decrypt a block of data using the ECB method of decryption }
      procedure EncryptCBC(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Encrypt size bytes of data using the CBC method of encryption }
      procedure DecryptCBC(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Decrypt size bytes of data using the CBC method of decryption }
      procedure EncryptCFB8bit(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Encrypt size bytes of data using the CFB (8 bit) method of encryption }
      procedure DecryptCFB8bit(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Decrypt size bytes of data using the CFB (8 bit) method of decryption }
      procedure EncryptCFBblock(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Encrypt size bytes of data using the CFB (block) method of encryption }
      procedure DecryptCFBblock(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Decrypt size bytes of data using the CFB (block) method of decryption }
      procedure EncryptOFB(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Encrypt size bytes of data using the OFB method of encryption }
      procedure DecryptOFB(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Decrypt size bytes of data using the OFB method of decryption }
      procedure EncryptCTR(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Encrypt size bytes of data using the CTR method of encryption }
      procedure DecryptCTR(const Indata; var Outdata; Size: longword); virtual; abstract;
      { Decrypt size bytes of data using the CTR method of decryption }

      constructor Create(AOwner: TComponent); override;

    published
      property BlockSize: integer read GetBlockSizeProp;
      property CipherMode: TncEnc_ciphermode read fCipherMode write fCipherMode default cmCBC;
    end;

    TncEnc_blockcipherclass = class of TncEnc_blockcipher;

    { ****************************************************************************** }
    { Helper functions }

  procedure XorBlock(var InData1, InData2; Size: longword);

implementation

  uses ncEncryption;

  { ** TncEnc_hash ***************************************************************** }

  procedure TncEnc_hash.UpdateStream(Stream: TStream; Size: longword);
  var
    Buffer: array [0 .. 8191] of byte;
    i, read: integer;
  begin
    for i := 1 to (Size div Sizeof(Buffer)) do
    begin
      read := Stream.Read(Buffer, Sizeof(Buffer));
      Update(Buffer, read);
    end;
    if (Size mod Sizeof(Buffer)) <> 0 then
    begin
      read := Stream.Read(Buffer, Size mod Sizeof(Buffer));
      Update(Buffer, read);
    end;
  end;

  procedure TncEnc_hash.UpdateStr(const Str: AnsiString);
  begin
    Update(Str[1], Length(Str));
  end;

  destructor TncEnc_hash.Destroy;
  begin
    if fInitialized then
      Burn;
    inherited Destroy;
  end;

  { ** TncEnc_cipher *************************************************************** }

  procedure TncEnc_cipher.Init(const Key; Size: longword; InitVector: pointer);
  begin
    if fInitialized then
      Burn;
    if (Size <= 0) or ((Size and 3) <> 0) or (Size > longword(GetMaxKeySize)) then
      raise EncEnc_cipher.Create('Invalid key size')
    else
      fInitialized := true;
  end;

  procedure TncEnc_cipher.InitStr(const Key: AnsiString; HashType: TncEnc_hashclass);
  var
    Hash: TncEnc_hash;
    Digest: pointer;
  begin
    if fInitialized then
      Burn;
    try
      GetMem(Digest, HashType.GetHashSize div 8);
      Hash := HashType.Create(Self);
      Hash.Init;
      Hash.UpdateStr(Key);
      Hash.Final(Digest^);
      Hash.Free;
      if MaxKeySize < HashType.GetHashSize then
        Init(Digest^, MaxKeySize, nil)
      else
        Init(Digest^, HashType.GetHashSize, nil);
      FillChar(Digest^, HashType.GetHashSize div 8, $FF);
      FreeMem(Digest);
    except
      raise EncEnc_cipher.Create('Unable to allocate sufficient memory for hash digest');
    end;
  end;

  procedure TncEnc_cipher.Burn;
  begin
    fInitialized := false;
  end;

  function TncEnc_cipher.EncryptStream(InStream, OutStream: TStream; Size: longword): longword;
  var
    Buffer: array [0 .. 8191] of byte;
    i, Read: longword;
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

  function TncEnc_cipher.DecryptStream(InStream, OutStream: TStream; Size: longword): longword;
  var
    Buffer: array [0 .. 8191] of byte;
    i, Read: longword;
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

  constructor TncEnc_cipher.Create(AOwner: TComponent);
  begin
    inherited Create(AOwner);
    Burn;
  end;

  destructor TncEnc_cipher.Destroy;
  begin
    if fInitialized then
      Burn;
    inherited Destroy;
  end;

  { ** TncEnc_blockcipher ********************************************************** }

  procedure TncEnc_blockcipher.Encrypt(const Indata; var Outdata; Size: longword);
  begin
    case fCipherMode of
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

  procedure TncEnc_blockcipher.Decrypt(const Indata; var Outdata; Size: longword);
  begin
    case fCipherMode of
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

  constructor TncEnc_blockcipher.Create(AOwner: TComponent);
  begin
    inherited Create(AOwner);
    fCipherMode := cmCBC;
  end;

  { ** Helpher functions ********************************************************* }
  procedure XorBlock(var InData1, InData2; Size: longword);
  var
    i: longword;
  begin
    for i := 1 to Size do
      Pbyte(longword(@InData1) + i - 1)^ := Pbyte(longword(@InData1) + i - 1)^ xor Pbyte(longword(@InData2) + i - 1)^;
  end;

  function TncEnc_hash.GetAlgorithmProp: string;
  begin
    Result := GetAlgorithm;
  end;

  function TncEnc_hash.GetHashSizeProp: integer;
  begin
    Result := GetHashSize;
  end;

  function TncEnc_hash.SelfTestProp: boolean;
  begin
    Result := SelfTest;
  end;

  function TncEnc_cipher.GetAlgorithmProp: string;
  begin
    Result := GetAlgorithm;
  end;

  function TncEnc_cipher.GetMaxKeySizeProp: integer;
  begin
    Result := GetMaxKeySize;
  end;

  function TncEnc_cipher.SelfTestProp: boolean;
  begin
    Result := SelfTest;
  end;

  function TncEnc_blockcipher.GetBlockSizeProp: integer;
  begin
    Result := GetBlockSize;
  end;

end.
