unit ncEncBlockciphers;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  System.Classes, System.Sysutils, ncEnccrypt2;

{ ****************************************************************************** }
{ Base type definition for 64 bit block ciphers }
type
  TncEnc_blockcipher64 = class(TncEncBlockCipher)
  private
    IV, CV: array [0 .. 7] of Byte;
    procedure IncCounter;
  public
    class function GetBlockSize: Integer; override;
    { Get the block size of the cipher (in bits) }

    procedure Reset; override;
    { Reset any stored chaining information }
    procedure Burn; override;
    { Clear all stored key information and chaining information }
    procedure SetIV(const Value); override;
    { Sets the IV to Value and performs a reset }
    procedure GetIV(var Value); override;
    { Returns the current chaining information, not the actual IV }
    procedure Init(const Key; Size: NativeUInt; InitVector: Pointer); override;
    { Do key setup based on the data in Key, size is in bits }

    procedure EncryptCBC(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CBC method of encryption }
    procedure DecryptCBC(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CBC method of decryption }
    procedure EncryptCFB8bit(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CFB (8 bit) method of encryption }
    procedure DecryptCFB8bit(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CFB (8 bit) method of decryption }
    procedure EncryptCFBblock(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CFB (block) method of encryption }
    procedure DecryptCFBblock(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CFB (block) method of decryption }
    procedure EncryptOFB(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the OFB method of encryption }
    procedure DecryptOFB(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the OFB method of decryption }
    procedure EncryptCTR(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CTR method of encryption }
    procedure DecryptCTR(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CTR method of decryption }
  end;

  { ****************************************************************************** }
  { Base type definition for 128 bit block ciphers }
type
  TncEnc_blockcipher128 = class(TncEncBlockCipher)
  private
    IV, CV: array [0 .. 15] of Byte;

    procedure IncCounter;
  public
    class function GetBlockSize: Integer; override;
    { Get the block size of the cipher (in bits) }

    procedure Reset; override;
    { Reset any stored chaining information }
    procedure Burn; override;
    { Clear all stored key information and chaining information }
    procedure SetIV(const Value); override;
    { Sets the IV to Value and performs a reset }
    procedure GetIV(var Value); override;
    { Returns the current chaining information, not the actual IV }
    procedure Init(const Key; Size: NativeUInt; InitVector: Pointer); override;
    { Do key setup based on the data in Key, size is in bits }

    procedure EncryptCBC(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CBC method of encryption }
    procedure DecryptCBC(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CBC method of decryption }
    procedure EncryptCFB8bit(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CFB (8 bit) method of encryption }
    procedure DecryptCFB8bit(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CFB (8 bit) method of decryption }
    procedure EncryptCFBblock(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CFB (block) method of encryption }
    procedure DecryptCFBblock(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CFB (block) method of decryption }
    procedure EncryptOFB(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the OFB method of encryption }
    procedure DecryptOFB(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the OFB method of decryption }
    procedure EncryptCTR(const Indata; var Outdata; Size: NativeUInt); override;
    { Encrypt size bytes of data using the CTR method of encryption }
    procedure DecryptCTR(const Indata; var Outdata; Size: NativeUInt); override;
    { Decrypt size bytes of data using the CTR method of decryption }
  end;

implementation

{ ** TncEnc_blockcipher64 ******************************************************** }

procedure TncEnc_blockcipher64.IncCounter;
var
  i: Integer;
begin
  Inc(CV[7]);
  i := 7;
  while (i > 0) and (CV[i] = 0) do
  begin
    Inc(CV[i - 1]);
    Dec(i);
  end;
end;

class function TncEnc_blockcipher64.GetBlockSize: Integer;
begin
  Result := 64;
end;

procedure TncEnc_blockcipher64.Init(const Key; Size: NativeUInt; InitVector: Pointer);
begin
  inherited Init(Key, Size, InitVector);
  InitKey(Key, Size);
  if InitVector = nil then
  begin
    FillChar(IV, 8, 0);
    EncryptECB(IV, IV);
    Reset;
  end
  else
  begin
    Move(InitVector^, IV, 8);
    Reset;
  end;
end;

procedure TncEnc_blockcipher64.SetIV(const Value);
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  Move(Value, IV, 8);
  Reset;
end;

procedure TncEnc_blockcipher64.GetIV(var Value);
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  Move(CV, Value, 8);
end;

procedure TncEnc_blockcipher64.Reset;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised)
  else
    Move(IV, CV, 8);
end;

procedure TncEnc_blockcipher64.Burn;
begin
  FillChar(IV, 8, $FF);
  FillChar(CV, 8, $FF);
  inherited Burn;
end;

procedure TncEnc_blockcipher64.EncryptCBC(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    Move(p1^, p2^, 8);
    XorBlock(p2^, CV, 8);
    EncryptECB(p2^, p2^);
    Move(p2^, CV, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, CV, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.DecryptCBC(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
  Temp: array [0 .. 7] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    Move(p1^, p2^, 8);
    Move(p1^, Temp, 8);
    DecryptECB(p2^, p2^);
    XorBlock(p2^, CV, 8);
    Move(Temp, CV, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, CV, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.EncryptCFB8bit(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
  Temp: array [0 .. 7] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to Size do
  begin
    EncryptECB(CV, Temp);
    p2^ := p1^ xor Temp[0];
    Move(CV[1], CV[0], 8 - 1);
    CV[7] := p2^;
    Inc(p1);
    Inc(p2);
  end;
end;

procedure TncEnc_blockcipher64.DecryptCFB8bit(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
  TempByte: Byte;
  Temp: array [0 .. 7] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to Size do
  begin
    TempByte := p1^;
    EncryptECB(CV, Temp);
    p2^ := p1^ xor Temp[0];
    Move(CV[1], CV[0], 8 - 1);
    CV[7] := TempByte;
    Inc(p1);
    Inc(p2);
  end;
end;

procedure TncEnc_blockcipher64.EncryptCFBblock(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, 8);
    XorBlock(p2^, CV, 8);
    Move(p2^, CV, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, CV, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.DecryptCFBblock(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
  Temp: array [0 .. 7] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    Move(p1^, Temp, 8);
    EncryptECB(CV, CV);
    Move(p1^, p2^, 8);
    XorBlock(p2^, CV, 8);
    Move(Temp, CV, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, CV, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.EncryptOFB(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, 8);
    XorBlock(p2^, CV, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, CV, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.DecryptOFB(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, 8);
    XorBlock(p2^, CV, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, CV, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.EncryptCTR(const Indata; var Outdata; Size: NativeUInt);
var
  Temp: array [0 .. 7] of Byte;
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, 8);
    XorBlock(p2^, Temp, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, Temp, Size mod 8);
  end;
end;

procedure TncEnc_blockcipher64.DecryptCTR(const Indata; var Outdata; Size: NativeUInt);
var
  Temp: array [0 .. 7] of Byte;
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 8) do
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, 8);
    XorBlock(p2^, Temp, 8);
    p1 := Pointer(NativeUInt(p1) + 8);
    p2 := Pointer(NativeUInt(p2) + 8);
  end;
  if (Size mod 8) <> 0 then
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, Size mod 8);
    XorBlock(p2^, Temp, Size mod 8);
  end;
end;

{ ** TncEnc_blockcipher128 ******************************************************** }

procedure TncEnc_blockcipher128.IncCounter;
var
  i: Integer;
begin
  Inc(CV[15]);
  i := 15;
  while (i > 0) and (CV[i] = 0) do
  begin
    Inc(CV[i - 1]);
    Dec(i);
  end;
end;

class function TncEnc_blockcipher128.GetBlockSize: Integer;
begin
  Result := 128;
end;

procedure TncEnc_blockcipher128.Init(const Key; Size: NativeUInt; InitVector: Pointer);
begin
  inherited Init(Key, Size, InitVector);
  InitKey(Key, Size);
  if InitVector = nil then
  begin
    FillChar(IV, 16, 0);
    EncryptECB(IV, IV);
    Reset;
  end
  else
  begin
    Move(InitVector^, IV, 16);
    Reset;
  end;
end;

procedure TncEnc_blockcipher128.SetIV(const Value);
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  Move(Value, IV, 16);
  Reset;
end;

procedure TncEnc_blockcipher128.GetIV(var Value);
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  Move(CV, Value, 16);
end;

procedure TncEnc_blockcipher128.Reset;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised)
  else
    Move(IV, CV, 16);
end;

procedure TncEnc_blockcipher128.Burn;
begin
  FillChar(IV, 16, $FF);
  FillChar(CV, 16, $FF);
  inherited Burn;
end;

procedure TncEnc_blockcipher128.EncryptCBC(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    Move(p1^, p2^, 16);
    XorBlock(p2^, CV, 16);
    EncryptECB(p2^, p2^);
    Move(p2^, CV, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, CV, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.DecryptCBC(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
  Temp: array [0 .. 15] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    Move(p1^, p2^, 16);
    Move(p1^, Temp, 16);
    DecryptECB(p2^, p2^);
    XorBlock(p2^, CV, 16);
    Move(Temp, CV, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, CV, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.EncryptCFB8bit(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
  Temp: array [0 .. 15] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to Size do
  begin
    EncryptECB(CV, Temp);
    p2^ := p1^ xor Temp[0];
    Move(CV[1], CV[0], 15);
    CV[15] := p2^;
    Inc(p1);
    Inc(p2);
  end;
end;

procedure TncEnc_blockcipher128.DecryptCFB8bit(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
  TempByte: Byte;
  Temp: array [0 .. 15] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to Size do
  begin
    TempByte := p1^;
    EncryptECB(CV, Temp);
    p2^ := p1^ xor Temp[0];
    Move(CV[1], CV[0], 15);
    CV[15] := TempByte;
    Inc(p1);
    Inc(p2);
  end;
end;

procedure TncEnc_blockcipher128.EncryptCFBblock(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, 16);
    XorBlock(p2^, CV, 16);
    Move(p2^, CV, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, CV, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.DecryptCFBblock(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pbyte;
  Temp: array [0 .. 15] of Byte;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    Move(p1^, Temp, 16);
    EncryptECB(CV, CV);
    Move(p1^, p2^, 16);
    XorBlock(p2^, CV, 16);
    Move(Temp, CV, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, CV, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.EncryptOFB(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, 16);
    XorBlock(p2^, CV, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, CV, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.DecryptOFB(const Indata; var Outdata; Size: NativeUInt);
var
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, 16);
    XorBlock(p2^, CV, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, CV);
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, CV, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.EncryptCTR(const Indata; var Outdata; Size: NativeUInt);
var
  Temp: array [0 .. 15] of Byte;
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, 16);
    XorBlock(p2^, Temp, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, Temp, Size mod 16);
  end;
end;

procedure TncEnc_blockcipher128.DecryptCTR(const Indata; var Outdata; Size: NativeUInt);
var
  Temp: array [0 .. 15] of Byte;
  i: longword;
  p1, p2: Pointer;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  p1 := @Indata;
  p2 := @Outdata;
  for i := 1 to (Size div 16) do
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, 16);
    XorBlock(p2^, Temp, 16);
    p1 := Pointer(NativeUInt(p1) + 16);
    p2 := Pointer(NativeUInt(p2) + 16);
  end;
  if (Size mod 16) <> 0 then
  begin
    EncryptECB(CV, Temp);
    IncCounter;
    Move(p1^, p2^, Size mod 16);
    XorBlock(p2^, Temp, Size mod 16);
  end;
end;

end.
