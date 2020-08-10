{$R-}
{$Q-}
unit ncEncMd5;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  System.Classes, System.Sysutils, ncEnccrypt2;

type
  TncEnc_md5 = class(TncEnc_hash)
  protected
    LenHi, LenLo: longword;
    Index: DWord;
    CurrentHash: array [0 .. 3] of DWord;
    HashBuffer: array [0 .. 63] of byte;
    procedure Compress;
  public
    class function GetAlgorithm: string; override;
    class function GetHashSize: integer; override;
    class function SelfTest: boolean; override;
    procedure Init; override;
    procedure Burn; override;
    procedure Update(const Buffer; Size: longword); override;
    procedure Final(var Digest); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

function LRot32(a, b: longword): longword;
begin
  Result := (a shl b) or (a shr (32 - b));
end;

procedure TncEnc_md5.Compress;
var
  Data: array [0 .. 15] of DWord;
  a, b, C, D: DWord;
begin
  Move(HashBuffer, Data, Sizeof(Data));
  a := CurrentHash[0];
  b := CurrentHash[1];
  C := CurrentHash[2];
  D := CurrentHash[3];

  a := b + LRot32(a + (D xor (b and (C xor D))) + Data[0] + $D76AA478, 7);
  D := a + LRot32(D + (C xor (a and (b xor C))) + Data[1] + $E8C7B756, 12);
  C := D + LRot32(C + (b xor (D and (a xor b))) + Data[2] + $242070DB, 17);
  b := C + LRot32(b + (a xor (C and (D xor a))) + Data[3] + $C1BDCEEE, 22);
  a := b + LRot32(a + (D xor (b and (C xor D))) + Data[4] + $F57C0FAF, 7);
  D := a + LRot32(D + (C xor (a and (b xor C))) + Data[5] + $4787C62A, 12);
  C := D + LRot32(C + (b xor (D and (a xor b))) + Data[6] + $A8304613, 17);
  b := C + LRot32(b + (a xor (C and (D xor a))) + Data[7] + $FD469501, 22);
  a := b + LRot32(a + (D xor (b and (C xor D))) + Data[8] + $698098D8, 7);
  D := a + LRot32(D + (C xor (a and (b xor C))) + Data[9] + $8B44F7AF, 12);
  C := D + LRot32(C + (b xor (D and (a xor b))) + Data[10] + $FFFF5BB1, 17);
  b := C + LRot32(b + (a xor (C and (D xor a))) + Data[11] + $895CD7BE, 22);
  a := b + LRot32(a + (D xor (b and (C xor D))) + Data[12] + $6B901122, 7);
  D := a + LRot32(D + (C xor (a and (b xor C))) + Data[13] + $FD987193, 12);
  C := D + LRot32(C + (b xor (D and (a xor b))) + Data[14] + $A679438E, 17);
  b := C + LRot32(b + (a xor (C and (D xor a))) + Data[15] + $49B40821, 22);

  a := b + LRot32(a + (C xor (D and (b xor C))) + Data[1] + $F61E2562, 5);
  D := a + LRot32(D + (b xor (C and (a xor b))) + Data[6] + $C040B340, 9);
  C := D + LRot32(C + (a xor (b and (D xor a))) + Data[11] + $265E5A51, 14);
  b := C + LRot32(b + (D xor (a and (C xor D))) + Data[0] + $E9B6C7AA, 20);
  a := b + LRot32(a + (C xor (D and (b xor C))) + Data[5] + $D62F105D, 5);
  D := a + LRot32(D + (b xor (C and (a xor b))) + Data[10] + $02441453, 9);
  C := D + LRot32(C + (a xor (b and (D xor a))) + Data[15] + $D8A1E681, 14);
  b := C + LRot32(b + (D xor (a and (C xor D))) + Data[4] + $E7D3FBC8, 20);
  a := b + LRot32(a + (C xor (D and (b xor C))) + Data[9] + $21E1CDE6, 5);
  D := a + LRot32(D + (b xor (C and (a xor b))) + Data[14] + $C33707D6, 9);
  C := D + LRot32(C + (a xor (b and (D xor a))) + Data[3] + $F4D50D87, 14);
  b := C + LRot32(b + (D xor (a and (C xor D))) + Data[8] + $455A14ED, 20);
  a := b + LRot32(a + (C xor (D and (b xor C))) + Data[13] + $A9E3E905, 5);
  D := a + LRot32(D + (b xor (C and (a xor b))) + Data[2] + $FCEFA3F8, 9);
  C := D + LRot32(C + (a xor (b and (D xor a))) + Data[7] + $676F02D9, 14);
  b := C + LRot32(b + (D xor (a and (C xor D))) + Data[12] + $8D2A4C8A, 20);

  a := b + LRot32(a + (b xor C xor D) + Data[5] + $FFFA3942, 4);
  D := a + LRot32(D + (a xor b xor C) + Data[8] + $8771F681, 11);
  C := D + LRot32(C + (D xor a xor b) + Data[11] + $6D9D6122, 16);
  b := C + LRot32(b + (C xor D xor a) + Data[14] + $FDE5380C, 23);
  a := b + LRot32(a + (b xor C xor D) + Data[1] + $A4BEEA44, 4);
  D := a + LRot32(D + (a xor b xor C) + Data[4] + $4BDECFA9, 11);
  C := D + LRot32(C + (D xor a xor b) + Data[7] + $F6BB4B60, 16);
  b := C + LRot32(b + (C xor D xor a) + Data[10] + $BEBFBC70, 23);
  a := b + LRot32(a + (b xor C xor D) + Data[13] + $289B7EC6, 4);
  D := a + LRot32(D + (a xor b xor C) + Data[0] + $EAA127FA, 11);
  C := D + LRot32(C + (D xor a xor b) + Data[3] + $D4EF3085, 16);
  b := C + LRot32(b + (C xor D xor a) + Data[6] + $04881D05, 23);
  a := b + LRot32(a + (b xor C xor D) + Data[9] + $D9D4D039, 4);
  D := a + LRot32(D + (a xor b xor C) + Data[12] + $E6DB99E5, 11);
  C := D + LRot32(C + (D xor a xor b) + Data[15] + $1FA27CF8, 16);
  b := C + LRot32(b + (C xor D xor a) + Data[2] + $C4AC5665, 23);

  a := b + LRot32(a + (C xor (b or (not D))) + Data[0] + $F4292244, 6);
  D := a + LRot32(D + (b xor (a or (not C))) + Data[7] + $432AFF97, 10);
  C := D + LRot32(C + (a xor (D or (not b))) + Data[14] + $AB9423A7, 15);
  b := C + LRot32(b + (D xor (C or (not a))) + Data[5] + $FC93A039, 21);
  a := b + LRot32(a + (C xor (b or (not D))) + Data[12] + $655B59C3, 6);
  D := a + LRot32(D + (b xor (a or (not C))) + Data[3] + $8F0CCC92, 10);
  C := D + LRot32(C + (a xor (D or (not b))) + Data[10] + $FFEFF47D, 15);
  b := C + LRot32(b + (D xor (C or (not a))) + Data[1] + $85845DD1, 21);
  a := b + LRot32(a + (C xor (b or (not D))) + Data[8] + $6FA87E4F, 6);
  D := a + LRot32(D + (b xor (a or (not C))) + Data[15] + $FE2CE6E0, 10);
  C := D + LRot32(C + (a xor (D or (not b))) + Data[6] + $A3014314, 15);
  b := C + LRot32(b + (D xor (C or (not a))) + Data[13] + $4E0811A1, 21);
  a := b + LRot32(a + (C xor (b or (not D))) + Data[4] + $F7537E82, 6);
  D := a + LRot32(D + (b xor (a or (not C))) + Data[11] + $BD3AF235, 10);
  C := D + LRot32(C + (a xor (D or (not b))) + Data[2] + $2AD7D2BB, 15);
  b := C + LRot32(b + (D xor (C or (not a))) + Data[9] + $EB86D391, 21);

  Inc(CurrentHash[0], a);
  Inc(CurrentHash[1], b);
  Inc(CurrentHash[2], C);
  Inc(CurrentHash[3], D);
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_md5.GetHashSize: integer;
begin
  Result := 128;
end;

class function TncEnc_md5.GetAlgorithm: string;
begin
  Result := 'MD5';
end;

class function TncEnc_md5.SelfTest: boolean;
const
  Test1Out: array [0 .. 15] of byte = ($90, $01, $50, $98, $3C, $D2, $4F, $B0, $D6, $96, $3F, $7D, $28, $E1, $7F, $72);
  Test2Out: array [0 .. 15] of byte = ($C3, $FC, $D3, $D7, $61, $92, $E4, $00, $7D, $FB, $49, $6C, $CA, $67, $E1, $3B);
var
  TestHash: TncEnc_md5;
  TestOut: array [0 .. 19] of byte;
begin
  TestHash := TncEnc_md5.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abc');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Init;
  TestHash.UpdateStr('abcdefghijklmnopqrstuvwxyz');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out)) and Result;
  TestHash.Free;
end;

procedure TncEnc_md5.Init;
begin
  Burn;
  CurrentHash[0] := $67452301;
  CurrentHash[1] := $EFCDAB89;
  CurrentHash[2] := $98BADCFE;
  CurrentHash[3] := $10325476;
  fInitialized := true;
end;

procedure TncEnc_md5.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  fInitialized := false;
end;

procedure TncEnc_md5.Update(const Buffer; Size: longword);
var
  PBuf: ^byte;
begin
  if not fInitialized then
    raise EncEnc_hash.Create('Hash not initialized');

  Inc(LenHi, Size shr 29);
  Inc(LenLo, Size * 8);
  if LenLo < (Size * 8) then
    Inc(LenHi);

  PBuf := @Buffer;
  while Size > 0 do
  begin
    if (Sizeof(HashBuffer) - Index) <= DWord(Size) then
    begin
      Move(PBuf^, HashBuffer[Index], Sizeof(HashBuffer) - Index);
      Dec(Size, Sizeof(HashBuffer) - Index);
      Inc(PBuf, Sizeof(HashBuffer) - Index);
      Compress;
    end
    else
    begin
      Move(PBuf^, HashBuffer[Index], Size);
      Inc(Index, Size);
      Size := 0;
    end;
  end;
end;

procedure TncEnc_md5.Final(var Digest);
begin
  if not fInitialized then
    raise EncEnc_hash.Create('Hash not initialized');
  HashBuffer[Index] := $80;
  if Index >= 56 then
    Compress;
  PDWord(@HashBuffer[56])^ := LenLo;
  PDWord(@HashBuffer[60])^ := LenHi;
  Compress;
  Move(CurrentHash, Digest, Sizeof(CurrentHash));
  Burn;
end;

end.
