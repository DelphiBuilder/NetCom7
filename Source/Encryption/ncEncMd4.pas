{$R-}
{$Q-}
unit ncEncMd4;

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
  TncEnc_md4 = class(TncEncHash)
  protected
    LenHi, LenLo: UInt32;
    Index: UInt32;
    CurrentHash: array [0 .. 3] of UInt32;
    HashBuffer: array [0 .. 63] of Byte;
    procedure Compress;
  public
    class function GetAlgorithm: string; override;
    class function GetHashSize: Integer; override;
    class function SelfTest: Boolean; override;
    procedure Init; override;
    procedure Update(const Buffer; Size: NativeUInt); override;
    procedure Final(var Digest); override;
    procedure Burn; override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

function LRot32(const AVal: UInt32; AShift: Byte): UInt32; inline;
begin
  Result := (AVal shl AShift) or (AVal shr (32 - AShift));
end;

procedure TncEnc_md4.Compress;
var
  Data: array [0 .. 15] of UInt32;
  a, b, C, D: UInt32;
begin
  Move(HashBuffer, Data, Sizeof(Data));
  a := CurrentHash[0];
  b := CurrentHash[1];
  C := CurrentHash[2];
  D := CurrentHash[3];

  a := LRot32(a + (D xor (b and (C xor D))) + Data[0], 3);
  D := LRot32(D + (C xor (a and (b xor C))) + Data[1], 7);
  C := LRot32(C + (b xor (D and (a xor b))) + Data[2], 11);
  b := LRot32(b + (a xor (C and (D xor a))) + Data[3], 19);
  a := LRot32(a + (D xor (b and (C xor D))) + Data[4], 3);
  D := LRot32(D + (C xor (a and (b xor C))) + Data[5], 7);
  C := LRot32(C + (b xor (D and (a xor b))) + Data[6], 11);
  b := LRot32(b + (a xor (C and (D xor a))) + Data[7], 19);
  a := LRot32(a + (D xor (b and (C xor D))) + Data[8], 3);
  D := LRot32(D + (C xor (a and (b xor C))) + Data[9], 7);
  C := LRot32(C + (b xor (D and (a xor b))) + Data[10], 11);
  b := LRot32(b + (a xor (C and (D xor a))) + Data[11], 19);
  a := LRot32(a + (D xor (b and (C xor D))) + Data[12], 3);
  D := LRot32(D + (C xor (a and (b xor C))) + Data[13], 7);
  C := LRot32(C + (b xor (D and (a xor b))) + Data[14], 11);
  b := LRot32(b + (a xor (C and (D xor a))) + Data[15], 19);

  a := LRot32(a + ((b and C) or (b and D) or (C and D)) + Data[0] + $5A827999, 3);
  D := LRot32(D + ((a and b) or (a and C) or (b and C)) + Data[4] + $5A827999, 5);
  C := LRot32(C + ((D and a) or (D and b) or (a and b)) + Data[8] + $5A827999, 9);
  b := LRot32(b + ((C and D) or (C and a) or (D and a)) + Data[12] + $5A827999, 13);
  a := LRot32(a + ((b and C) or (b and D) or (C and D)) + Data[1] + $5A827999, 3);
  D := LRot32(D + ((a and b) or (a and C) or (b and C)) + Data[5] + $5A827999, 5);
  C := LRot32(C + ((D and a) or (D and b) or (a and b)) + Data[9] + $5A827999, 9);
  b := LRot32(b + ((C and D) or (C and a) or (D and a)) + Data[13] + $5A827999, 13);
  a := LRot32(a + ((b and C) or (b and D) or (C and D)) + Data[2] + $5A827999, 3);
  D := LRot32(D + ((a and b) or (a and C) or (b and C)) + Data[6] + $5A827999, 5);
  C := LRot32(C + ((D and a) or (D and b) or (a and b)) + Data[10] + $5A827999, 9);
  b := LRot32(b + ((C and D) or (C and a) or (D and a)) + Data[14] + $5A827999, 13);
  a := LRot32(a + ((b and C) or (b and D) or (C and D)) + Data[3] + $5A827999, 3);
  D := LRot32(D + ((a and b) or (a and C) or (b and C)) + Data[7] + $5A827999, 5);
  C := LRot32(C + ((D and a) or (D and b) or (a and b)) + Data[11] + $5A827999, 9);
  b := LRot32(b + ((C and D) or (C and a) or (D and a)) + Data[15] + $5A827999, 13);

  a := LRot32(a + (b xor C xor D) + Data[0] + $6ED9EBA1, 3);
  D := LRot32(D + (a xor b xor C) + Data[8] + $6ED9EBA1, 9);
  C := LRot32(C + (D xor a xor b) + Data[4] + $6ED9EBA1, 11);
  b := LRot32(b + (C xor D xor a) + Data[12] + $6ED9EBA1, 15);
  a := LRot32(a + (b xor C xor D) + Data[2] + $6ED9EBA1, 3);
  D := LRot32(D + (a xor b xor C) + Data[10] + $6ED9EBA1, 9);
  C := LRot32(C + (D xor a xor b) + Data[6] + $6ED9EBA1, 11);
  b := LRot32(b + (C xor D xor a) + Data[14] + $6ED9EBA1, 15);
  a := LRot32(a + (b xor C xor D) + Data[1] + $6ED9EBA1, 3);
  D := LRot32(D + (a xor b xor C) + Data[9] + $6ED9EBA1, 9);
  C := LRot32(C + (D xor a xor b) + Data[5] + $6ED9EBA1, 11);
  b := LRot32(b + (C xor D xor a) + Data[13] + $6ED9EBA1, 15);
  a := LRot32(a + (b xor C xor D) + Data[3] + $6ED9EBA1, 3);
  D := LRot32(D + (a xor b xor C) + Data[11] + $6ED9EBA1, 9);
  C := LRot32(C + (D xor a xor b) + Data[7] + $6ED9EBA1, 11);
  b := LRot32(b + (C xor D xor a) + Data[15] + $6ED9EBA1, 15);

  Inc(CurrentHash[0], a);
  Inc(CurrentHash[1], b);
  Inc(CurrentHash[2], C);
  Inc(CurrentHash[3], D);
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_md4.GetHashSize: Integer;
begin
  Result := 128;
end;

class function TncEnc_md4.GetAlgorithm: string;
begin
  Result := 'MD4';
end;

class function TncEnc_md4.SelfTest: Boolean;
const
  Test1Out: array [0 .. 15] of Byte = ($A4, $48, $01, $7A, $AF, $21, $D8, $52, $5F, $C1, $0A, $E8, $7A, $A6, $72, $9D);
  Test2Out: array [0 .. 15] of Byte = ($D7, $9E, $1C, $30, $8A, $A5, $BB, $CD, $EE, $A8, $ED, $63, $DF, $41, $2D, $A9);
var
  TestHash: TncEnc_md4;
  TestOut: array [0 .. 19] of Byte;
begin
  TestHash := TncEnc_md4.Create(nil);
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

procedure TncEnc_md4.Init;
begin
  Burn;
  CurrentHash[0] := $67452301;
  CurrentHash[1] := $EFCDAB89;
  CurrentHash[2] := $98BADCFE;
  CurrentHash[3] := $10325476;
  FInitialized := true;
end;

procedure TncEnc_md4.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  FInitialized := false;
end;

procedure TncEnc_md4.Update(const Buffer; Size: NativeUInt);
var
  PBuf: ^Byte;
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  Inc(LenHi, Size shr 29);
  Inc(LenLo, Size * 8);
  if LenLo < (Size * 8) then
    Inc(LenHi);

  PBuf := @Buffer;
  while Size > 0 do
  begin
    if (Sizeof(HashBuffer) - Index) <= Size then
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

procedure TncEnc_md4.Final(var Digest);
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  HashBuffer[Index] := $80;
  if Index >= 56 then
    Compress;
  PUInt32(@HashBuffer[56])^ := LenLo;
  PUInt32(@HashBuffer[60])^ := LenHi;
  Compress;
  Move(CurrentHash, Digest, Sizeof(CurrentHash));
  Burn;
end;

end.
