{$R-}
{$Q-}
unit ncEncSha1;

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
  TncEnc_sha1 = class(TncEncHash)
  protected
    LenHi, LenLo: UInt32;
    Index: UInt32;
    CurrentHash: array [0 .. 4] of UInt32;
    HashBuffer: array [0 .. 63] of Byte;
    procedure Compress;
  public
    class function GetAlgorithm: string; override;
    class function GetHashSize: Integer; override;
    class function SelfTest: Boolean; override;
    procedure Init; override;
    procedure Update(const aBuffer; aSize: NativeUInt); override;
    procedure Final(var Digest); override;
    procedure Burn; override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

function SwapUInt32(const a: UInt32): UInt32; inline;
begin
  Result := ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

procedure TncEnc_sha1.Compress;
var
  a, B, C, D, E: UInt32;
  W: array [0 .. 79] of UInt32;
  i: longword;
begin
  Index := 0;
  Move(HashBuffer, W, Sizeof(HashBuffer));
  for i := 0 to 15 do
    W[i] := SwapUInt32(W[i]);
  for i := 16 to 79 do
    W[i] := ((W[i - 3] xor W[i - 8] xor W[i - 14] xor W[i - 16]) shl 1) or ((W[i - 3] xor W[i - 8] xor W[i - 14] xor W[i - 16]) shr 31);
  a := CurrentHash[0];
  B := CurrentHash[1];
  C := CurrentHash[2];
  D := CurrentHash[3];
  E := CurrentHash[4];

  Inc(E, ((a shl 5) or (a shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[0]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (C xor (a and (B xor C))) + $5A827999 + W[1]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (B xor (E and (a xor B))) + $5A827999 + W[2]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (a xor (D and (E xor a))) + $5A827999 + W[3]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[4]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[5]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (C xor (a and (B xor C))) + $5A827999 + W[6]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (B xor (E and (a xor B))) + $5A827999 + W[7]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (a xor (D and (E xor a))) + $5A827999 + W[8]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[9]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[10]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (C xor (a and (B xor C))) + $5A827999 + W[11]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (B xor (E and (a xor B))) + $5A827999 + W[12]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (a xor (D and (E xor a))) + $5A827999 + W[13]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[14]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[15]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (C xor (a and (B xor C))) + $5A827999 + W[16]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (B xor (E and (a xor B))) + $5A827999 + W[17]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (a xor (D and (E xor a))) + $5A827999 + W[18]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[19]);
  C := (C shl 30) or (C shr 2);

  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[20]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $6ED9EBA1 + W[21]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $6ED9EBA1 + W[22]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $6ED9EBA1 + W[23]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[24]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[25]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $6ED9EBA1 + W[26]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $6ED9EBA1 + W[27]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $6ED9EBA1 + W[28]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[29]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[30]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $6ED9EBA1 + W[31]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $6ED9EBA1 + W[32]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $6ED9EBA1 + W[33]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[34]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[35]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $6ED9EBA1 + W[36]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $6ED9EBA1 + W[37]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $6ED9EBA1 + W[38]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[39]);
  C := (C shl 30) or (C shr 2);

  Inc(E, ((a shl 5) or (a shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[40]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + ((a and B) or (C and (a or B))) + $8F1BBCDC + W[41]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + ((E and a) or (B and (E or a))) + $8F1BBCDC + W[42]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + ((D and E) or (a and (D or E))) + $8F1BBCDC + W[43]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[44]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[45]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + ((a and B) or (C and (a or B))) + $8F1BBCDC + W[46]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + ((E and a) or (B and (E or a))) + $8F1BBCDC + W[47]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + ((D and E) or (a and (D or E))) + $8F1BBCDC + W[48]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[49]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[50]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + ((a and B) or (C and (a or B))) + $8F1BBCDC + W[51]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + ((E and a) or (B and (E or a))) + $8F1BBCDC + W[52]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + ((D and E) or (a and (D or E))) + $8F1BBCDC + W[53]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[54]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[55]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + ((a and B) or (C and (a or B))) + $8F1BBCDC + W[56]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + ((E and a) or (B and (E or a))) + $8F1BBCDC + W[57]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + ((D and E) or (a and (D or E))) + $8F1BBCDC + W[58]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[59]);
  C := (C shl 30) or (C shr 2);

  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $CA62C1D6 + W[60]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $CA62C1D6 + W[61]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $CA62C1D6 + W[62]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $CA62C1D6 + W[63]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[64]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $CA62C1D6 + W[65]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $CA62C1D6 + W[66]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $CA62C1D6 + W[67]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $CA62C1D6 + W[68]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[69]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $CA62C1D6 + W[70]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $CA62C1D6 + W[71]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $CA62C1D6 + W[72]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $CA62C1D6 + W[73]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[74]);
  C := (C shl 30) or (C shr 2);
  Inc(E, ((a shl 5) or (a shr 27)) + (B xor C xor D) + $CA62C1D6 + W[75]);
  B := (B shl 30) or (B shr 2);
  Inc(D, ((E shl 5) or (E shr 27)) + (a xor B xor C) + $CA62C1D6 + W[76]);
  a := (a shl 30) or (a shr 2);
  Inc(C, ((D shl 5) or (D shr 27)) + (E xor a xor B) + $CA62C1D6 + W[77]);
  E := (E shl 30) or (E shr 2);
  Inc(B, ((C shl 5) or (C shr 27)) + (D xor E xor a) + $CA62C1D6 + W[78]);
  D := (D shl 30) or (D shr 2);
  Inc(a, ((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[79]);
  C := (C shl 30) or (C shr 2);

  CurrentHash[0] := CurrentHash[0] + a;
  CurrentHash[1] := CurrentHash[1] + B;
  CurrentHash[2] := CurrentHash[2] + C;
  CurrentHash[3] := CurrentHash[3] + D;
  CurrentHash[4] := CurrentHash[4] + E;
  FillChar(W, Sizeof(W), 0);
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_sha1.GetAlgorithm: string;
begin
  Result := 'SHA1';
end;

class function TncEnc_sha1.GetHashSize: Integer;
begin
  Result := 160;
end;

class function TncEnc_sha1.SelfTest: Boolean;
const
  Test1Out: array [0 .. 19] of Byte = ($A9, $99, $3E, $36, $47, $06, $81, $6A, $BA, $3E, $25, $71, $78, $50, $C2, $6C, $9C, $D0, $D8, $9D);
  Test2Out: array [0 .. 19] of Byte = ($84, $98, $3E, $44, $1C, $3B, $D2, $6E, $BA, $AE, $4A, $A1, $F9, $51, $29, $E5, $E5, $46, $70, $F1);
var
  TestHash: TncEnc_sha1;
  TestOut: array [0 .. 19] of Byte;
begin
  TestHash := TncEnc_sha1.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abc');
  TestHash.Final(TestOut);
  Result := Boolean(CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out)));
  TestHash.Init;
  TestHash.UpdateStr('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
  TestHash.Final(TestOut);
  Result := Boolean(CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out))) and Result;
  TestHash.Free;
end;

procedure TncEnc_sha1.Init;
begin
  Burn;
  CurrentHash[0] := $67452301;
  CurrentHash[1] := $EFCDAB89;
  CurrentHash[2] := $98BADCFE;
  CurrentHash[3] := $10325476;
  CurrentHash[4] := $C3D2E1F0;
  FInitialized := true;
end;

procedure TncEnc_sha1.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  FInitialized := false;
end;

procedure TncEnc_sha1.Update(const aBuffer; aSize: NativeUInt);
var
  PBuf: ^Byte;
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  Inc(LenHi, aSize shr 29);
  Inc(LenLo, aSize * 8);
  if LenLo < (aSize * 8) then
    Inc(LenHi);

  PBuf := @aBuffer;
  while aSize > 0 do
  begin
    if (Sizeof(HashBuffer) - Index) <= aSize then
    begin
      Move(PBuf^, HashBuffer[Index], Sizeof(HashBuffer) - Index);
      Dec(aSize, Sizeof(HashBuffer) - Index);
      Inc(PBuf, Sizeof(HashBuffer) - Index);
      Compress;
    end
    else
    begin
      Move(PBuf^, HashBuffer[Index], aSize);
      Inc(Index, aSize);
      aSize := 0;
    end;
  end;
end;

procedure TncEnc_sha1.Final(var Digest);
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  HashBuffer[Index] := $80;
  if Index >= 56 then
    Compress;
  PUInt32(@HashBuffer[56])^ := SwapUInt32(LenHi);
  PUInt32(@HashBuffer[60])^ := SwapUInt32(LenLo);
  Compress;
  CurrentHash[0] := SwapUInt32(CurrentHash[0]);
  CurrentHash[1] := SwapUInt32(CurrentHash[1]);
  CurrentHash[2] := SwapUInt32(CurrentHash[2]);
  CurrentHash[3] := SwapUInt32(CurrentHash[3]);
  CurrentHash[4] := SwapUInt32(CurrentHash[4]);
  Move(CurrentHash, Digest, Sizeof(CurrentHash));
  Burn;
end;

end.
