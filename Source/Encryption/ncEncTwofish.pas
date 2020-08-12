{$R-}
{$Q-}
unit ncEncTwofish;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  System.Classes, System.Sysutils, ncEnccrypt2, ncEncblockciphers;

const
  INPUTWHITEN = 0;
  OUTPUTWHITEN = 4;
  NUMROUNDS = 16;
  ROUNDSUBKEYS = (OUTPUTWHITEN + 4);
  TOTALSUBKEYS = (ROUNDSUBKEYS + NUMROUNDS * 2);
  RS_GF_FDBK = $14D;
  MDS_GF_FDBK = $169;
  SK_STEP = $02020202;
  SK_BUMP = $01010101;
  SK_ROTL = 9;

type
  TncEnc_twofish = class(TncEnc_blockcipher128)
  protected
    SubKeys: array [0 .. TOTALSUBKEYS - 1] of DWord;
    sbox: array [0 .. 3, 0 .. 255] of DWord;
    procedure InitKey(const Key; Size: longword); override;
  public
    class function GetAlgorithm: string; override;
    class function GetMaxKeySize: integer; override;
    class function SelfTest: boolean; override;
    procedure Burn; override;
    procedure EncryptECB(const InData; var OutData); override;
    procedure DecryptECB(const InData; var OutData); override;
    constructor Create(AOwner: TComponent); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

const
  p8x8: array [0 .. 1, 0 .. 255] of byte = (($A9, $67, $B3, $E8, $04, $FD, $A3, $76, $9A, $92, $80, $78, $E4, $DD, $D1, $38, $0D, $C6, $35, $98, $18, $F7, $EC,
    $6C, $43, $75, $37, $26, $FA, $13, $94, $48, $F2, $D0, $8B, $30, $84, $54, $DF, $23, $19, $5B, $3D, $59, $F3, $AE, $A2, $82, $63, $01, $83, $2E, $D9, $51,
    $9B, $7C, $A6, $EB, $A5, $BE, $16, $0C, $E3, $61, $C0, $8C, $3A, $F5, $73, $2C, $25, $0B, $BB, $4E, $89, $6B, $53, $6A, $B4, $F1, $E1, $E6, $BD, $45, $E2,
    $F4, $B6, $66, $CC, $95, $03, $56, $D4, $1C, $1E, $D7, $FB, $C3, $8E, $B5, $E9, $CF, $BF, $BA, $EA, $77, $39, $AF, $33, $C9, $62, $71, $81, $79, $09, $AD,
    $24, $CD, $F9, $D8, $E5, $C5, $B9, $4D, $44, $08, $86, $E7, $A1, $1D, $AA, $ED, $06, $70, $B2, $D2, $41, $7B, $A0, $11, $31, $C2, $27, $90, $20, $F6, $60,
    $FF, $96, $5C, $B1, $AB, $9E, $9C, $52, $1B, $5F, $93, $0A, $EF, $91, $85, $49, $EE, $2D, $4F, $8F, $3B, $47, $87, $6D, $46, $D6, $3E, $69, $64, $2A, $CE,
    $CB, $2F, $FC, $97, $05, $7A, $AC, $7F, $D5, $1A, $4B, $0E, $A7, $5A, $28, $14, $3F, $29, $88, $3C, $4C, $02, $B8, $DA, $B0, $17, $55, $1F, $8A, $7D, $57,
    $C7, $8D, $74, $B7, $C4, $9F, $72, $7E, $15, $22, $12, $58, $07, $99, $34, $6E, $50, $DE, $68, $65, $BC, $DB, $F8, $C8, $A8, $2B, $40, $DC, $FE, $32, $A4,
    $CA, $10, $21, $F0, $D3, $5D, $0F, $00, $6F, $9D, $36, $42, $4A, $5E, $C1, $E0), ($75, $F3, $C6, $F4, $DB, $7B, $FB, $C8, $4A, $D3, $E6, $6B, $45, $7D, $E8,
    $4B, $D6, $32, $D8, $FD, $37, $71, $F1, $E1, $30, $0F, $F8, $1B, $87, $FA, $06, $3F, $5E, $BA, $AE, $5B, $8A, $00, $BC, $9D, $6D, $C1, $B1, $0E, $80, $5D,
    $D2, $D5, $A0, $84, $07, $14, $B5, $90, $2C, $A3, $B2, $73, $4C, $54, $92, $74, $36, $51, $38, $B0, $BD, $5A, $FC, $60, $62, $96, $6C, $42, $F7, $10, $7C,
    $28, $27, $8C, $13, $95, $9C, $C7, $24, $46, $3B, $70, $CA, $E3, $85, $CB, $11, $D0, $93, $B8, $A6, $83, $20, $FF, $9F, $77, $C3, $CC, $03, $6F, $08, $BF,
    $40, $E7, $2B, $E2, $79, $0C, $AA, $82, $41, $3A, $EA, $B9, $E4, $9A, $A4, $97, $7E, $DA, $7A, $17, $66, $94, $A1, $1D, $3D, $F0, $DE, $B3, $0B, $72, $A7,
    $1C, $EF, $D1, $53, $3E, $8F, $33, $26, $5F, $EC, $76, $2A, $49, $81, $88, $EE, $21, $C4, $1A, $EB, $D9, $C5, $39, $99, $CD, $AD, $31, $8B, $01, $18, $23,
    $DD, $1F, $4E, $2D, $F9, $48, $4F, $F2, $65, $8E, $78, $5C, $58, $19, $8D, $E5, $98, $57, $67, $7F, $05, $64, $AF, $63, $B6, $FE, $F5, $B7, $3C, $A5, $CE,
    $E9, $68, $44, $E0, $4D, $43, $69, $29, $2E, $AC, $15, $59, $A8, $0A, $9E, $6E, $47, $DF, $34, $35, $6A, $CF, $DC, $22, $C9, $C0, $9B, $89, $D4, $ED, $AB,
    $12, $A2, $0D, $52, $BB, $02, $2F, $A9, $D7, $61, $1E, $B4, $50, $04, $F6, $C2, $16, $25, $86, $56, $55, $09, $BE, $91));

var
  MDS: array [0 .. 3, 0 .. 255] of DWord;
  MDSDone: boolean;

class function TncEnc_twofish.GetAlgorithm: string;
begin
  Result := 'Twofish';
end;

class function TncEnc_twofish.GetMaxKeySize: integer;
begin
  Result := 256;
end;

class function TncEnc_twofish.SelfTest: boolean;
const
  Out128: array [0 .. 15] of byte = ($5D, $9D, $4E, $EF, $FA, $91, $51, $57, $55, $24, $F1, $15, $81, $5A, $12, $E0);
  Out192: array [0 .. 15] of byte = ($E7, $54, $49, $21, $2B, $EE, $F9, $F4, $A3, $90, $BD, $86, $0A, $64, $09, $41);
  Out256: array [0 .. 15] of byte = ($37, $FE, $26, $FF, $1C, $F6, $61, $75, $F5, $DD, $F4, $C3, $3B, $97, $A2, $05);
var
  i: integer;
  Key: array [0 .. 31] of byte;
  Block: array [0 .. 15] of byte;
  Cipher: TncEnc_twofish;
begin
  Cipher := TncEnc_twofish.Create(nil);
  FillChar(Key, Sizeof(Key), 0);
  FillChar(Block, Sizeof(Block), 0);
  for i := 1 to 49 do
  begin
    Cipher.Init(Key, 128, nil);
    Move(Block, Key, 16);
    Cipher.EncryptECB(Block, Block);
    Cipher.Burn;
  end;
  Result := boolean(CompareMem(@Block, @Out128, 16));
  FillChar(Key, Sizeof(Key), 0);
  FillChar(Block, Sizeof(Block), 0);
  for i := 1 to 49 do
  begin
    Cipher.Init(Key, 192, nil);
    Move(Key[0], Key[16], 8);
    Move(Block, Key, 16);
    Cipher.EncryptECB(Block, Block);
    Cipher.Burn;
  end;
  Result := Result and boolean(CompareMem(@Block, @Out192, 16));
  FillChar(Key, Sizeof(Key), 0);
  FillChar(Block, Sizeof(Block), 0);
  for i := 1 to 49 do
  begin
    Cipher.Init(Key, 256, nil);
    Move(Key[0], Key[16], 16);
    Move(Block, Key, 16);
    Cipher.EncryptECB(Block, Block);
    Cipher.Burn;
  end;
  Result := Result and boolean(CompareMem(@Block, @Out256, 16));
  Cipher.Burn;
  Cipher.Free;
end;

function LFSR1(x: DWord): DWord;
begin
  if (x and 1) <> 0 then
    Result := (x shr 1) xor (MDS_GF_FDBK div 2)
  else
    Result := (x shr 1);
end;

function LFSR2(x: DWord): DWord;
begin
  if (x and 2) <> 0 then
    if (x and 1) <> 0 then
      Result := (x shr 2) xor (MDS_GF_FDBK div 2) xor (MDS_GF_FDBK div 4)
    else
      Result := (x shr 2) xor (MDS_GF_FDBK div 2)
  else if (x and 1) <> 0 then
    Result := (x shr 2) xor (MDS_GF_FDBK div 4)
  else
    Result := (x shr 2);
end;

function Mul_X(x: DWord): DWord;
begin
  Result := x xor LFSR2(x);
end;

function Mul_Y(x: DWord): DWord;
begin
  Result := x xor LFSR1(x) xor LFSR2(x);
end;

function RS_MDS_Encode(lK0, lK1: DWord): DWord;
var
  lR, nJ, lG2, lG3: DWord;
  bB: byte;
begin
  lR := lK1;
  for nJ := 0 to 3 do
  begin
    bB := lR shr 24;
    if (bB and $80) <> 0 then
      lG2 := ((bB shl 1) xor RS_GF_FDBK) and $FF
    else
      lG2 := (bB shl 1) and $FF;
    if (bB and 1) <> 0 then
      lG3 := ((bB shr 1) and $7F) xor (RS_GF_FDBK shr 1) xor lG2
    else
      lG3 := ((bB shr 1) and $7F) xor lG2;
    lR := (lR shl 8) xor (lG3 shl 24) xor (lG2 shl 16) xor (lG3 shl 8) xor bB;
  end;
  lR := lR xor lK0;
  for nJ := 0 to 3 do
  begin
    bB := lR shr 24;
    if (bB and $80) <> 0 then
      lG2 := ((bB shl 1) xor RS_GF_FDBK) and $FF
    else
      lG2 := (bB shl 1) and $FF;
    if (bB and 1) <> 0 then
      lG3 := ((bB shr 1) and $7F) xor (RS_GF_FDBK shr 1) xor lG2
    else
      lG3 := ((bB shr 1) and $7F) xor lG2;
    lR := (lR shl 8) xor (lG3 shl 24) xor (lG2 shl 16) xor (lG3 shl 8) xor bB;
  end;
  Result := lR;
end;

function f32(x: DWord; K32: PDWordArray; Len: DWord): DWord;
var
  t0, t1, t2, t3: DWord;
begin
  t0 := x and $FF;
  t1 := (x shr 8) and $FF;
  t2 := (x shr 16) and $FF;
  t3 := x shr 24;
  if Len = 256 then
  begin
    t0 := p8x8[1, t0] xor ((K32^[3]) and $FF);
    t1 := p8x8[0, t1] xor ((K32^[3] shr 8) and $FF);
    t2 := p8x8[0, t2] xor ((K32^[3] shr 16) and $FF);
    t3 := p8x8[1, t3] xor ((K32^[3] shr 24));
  end;
  if Len >= 192 then
  begin
    t0 := p8x8[1, t0] xor ((K32^[2]) and $FF);
    t1 := p8x8[1, t1] xor ((K32^[2] shr 8) and $FF);
    t2 := p8x8[0, t2] xor ((K32^[2] shr 16) and $FF);
    t3 := p8x8[0, t3] xor ((K32^[2] shr 24));
  end;
  Result := MDS[0, p8x8[0, p8x8[0, t0] xor ((K32^[1]) and $FF)] xor ((K32^[0]) and $FF)
    ] xor MDS[1, p8x8[0, p8x8[1, t1] xor ((K32^[1] shr 8) and $FF)] xor ((K32^[0] shr 8) and $FF)
    ] xor MDS[2, p8x8[1, p8x8[0, t2] xor ((K32^[1] shr 16) and $FF)] xor ((K32^[0] shr 16) and $FF)
    ] xor MDS[3, p8x8[1, p8x8[1, t3] xor ((K32^[1] shr 24))] xor ((K32^[0] shr 24))];
end;

procedure Xor256(Dst, Src: PDWordArray; v: byte);
var
  i, j: DWord;
begin
  i := 0;
  j := v * $01010101;
  while i < 64 do
  begin
    Dst^[i] := Src^[i] xor j;
    Dst^[i + 1] := Src^[i + 1] xor j;
    Dst^[i + 2] := Src^[i + 2] xor j;
    Dst^[i + 3] := Src^[i + 3] xor j;
    Inc(i, 4);
  end;
end;

procedure TncEnc_twofish.InitKey(const Key; Size: longword);
const
  subkeyCnt = ROUNDSUBKEYS + 2 * NUMROUNDS;
var
  key32: array [0 .. 7] of DWord;
  k32e, k32o, sboxkeys: array [0 .. 3] of DWord;
  k64Cnt, i, j, A, B, q: DWord;
  L0, L1: array [0 .. 255] of byte;
begin
  FillChar(key32, Sizeof(key32), 0);
  Move(Key, key32, Size div 8);
  if Size <= 128 then { pad the key to either 128bit, 192bit or 256bit }
    Size := 128
  else if Size <= 192 then
    Size := 192
  else
    Size := 256;
  k64Cnt := Size div 64;
  j := k64Cnt - 1;
  for i := 0 to j do
  begin
    k32e[i] := key32[2 * i];
    k32o[i] := key32[2 * i + 1];
    sboxkeys[j] := RS_MDS_Encode(k32e[i], k32o[i]);
    Dec(j);
  end;
  q := 0;
  for i := 0 to ((subkeyCnt div 2) - 1) do
  begin
    A := f32(q, @k32e, Size);
    B := f32(q + SK_BUMP, @k32o, Size);
    B := (B shl 8) or (B shr 24);
    SubKeys[2 * i] := A + B;
    B := A + 2 * B;
    SubKeys[2 * i + 1] := (B shl SK_ROTL) or (B shr (32 - SK_ROTL));
    Inc(q, SK_STEP);
  end;
  case Size of
    128:
      begin
        Xor256(@L0, @p8x8[0], (sboxkeys[1] and $FF));
        A := (sboxkeys[0] and $FF);
        i := 0;
        while i < 256 do
        begin
          sbox[0 and 2, 2 * i + (0 and 1)] := MDS[0, p8x8[0, L0[i]] xor A];
          sbox[0 and 2, 2 * i + (0 and 1) + 2] := MDS[0, p8x8[0, L0[i + 1]] xor A];
          Inc(i, 2);
        end;
        Xor256(@L0, @p8x8[1], (sboxkeys[1] shr 8) and $FF);
        A := (sboxkeys[0] shr 8) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[1 and 2, 2 * i + (1 and 1)] := MDS[1, p8x8[0, L0[i]] xor A];
          sbox[1 and 2, 2 * i + (1 and 1) + 2] := MDS[1, p8x8[0, L0[i + 1]] xor A];
          Inc(i, 2);
        end;
        Xor256(@L0, @p8x8[0], (sboxkeys[1] shr 16) and $FF);
        A := (sboxkeys[0] shr 16) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[2 and 2, 2 * i + (2 and 1)] := MDS[2, p8x8[1, L0[i]] xor A];
          sbox[2 and 2, 2 * i + (2 and 1) + 2] := MDS[2, p8x8[1, L0[i + 1]] xor A];
          Inc(i, 2);
        end;
        Xor256(@L0, @p8x8[1], (sboxkeys[1] shr 24));
        A := (sboxkeys[0] shr 24);
        i := 0;
        while i < 256 do
        begin
          sbox[3 and 2, 2 * i + (3 and 1)] := MDS[3, p8x8[1, L0[i]] xor A];
          sbox[3 and 2, 2 * i + (3 and 1) + 2] := MDS[3, p8x8[1, L0[i + 1]] xor A];
          Inc(i, 2);
        end;
      end;
    192:
      begin
        Xor256(@L0, @p8x8[1], sboxkeys[2] and $FF);
        A := sboxkeys[0] and $FF;
        B := sboxkeys[1] and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[0 and 2, 2 * i + (0 and 1)] := MDS[0, p8x8[0, p8x8[0, L0[i]] xor B] xor A];
          sbox[0 and 2, 2 * i + (0 and 1) + 2] := MDS[0, p8x8[0, p8x8[0, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
        Xor256(@L0, @p8x8[1], (sboxkeys[2] shr 8) and $FF);
        A := (sboxkeys[0] shr 8) and $FF;
        B := (sboxkeys[1] shr 8) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[1 and 2, 2 * i + (1 and 1)] := MDS[1, p8x8[0, p8x8[1, L0[i]] xor B] xor A];
          sbox[1 and 2, 2 * i + (1 and 1) + 2] := MDS[1, p8x8[0, p8x8[1, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
        Xor256(@L0, @p8x8[0], (sboxkeys[2] shr 16) and $FF);
        A := (sboxkeys[0] shr 16) and $FF;
        B := (sboxkeys[1] shr 16) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[2 and 2, 2 * i + (2 and 1)] := MDS[2, p8x8[1, p8x8[0, L0[i]] xor B] xor A];
          sbox[2 and 2, 2 * i + (2 and 1) + 2] := MDS[2, p8x8[1, p8x8[0, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
        Xor256(@L0, @p8x8[0], (sboxkeys[2] shr 24));
        A := (sboxkeys[0] shr 24);
        B := (sboxkeys[1] shr 24);
        i := 0;
        while i < 256 do
        begin
          sbox[3 and 2, 2 * i + (3 and 1)] := MDS[3, p8x8[1, p8x8[1, L0[i]] xor B] xor A];
          sbox[3 and 2, 2 * i + (3 and 1) + 2] := MDS[3, p8x8[1, p8x8[1, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
      end;
    256:
      begin
        Xor256(@L1, @p8x8[1], (sboxkeys[3]) and $FF);
        i := 0;
        while i < 256 do
        begin
          L0[i] := p8x8[1, L1[i]];
          L0[i + 1] := p8x8[1, L1[i + 1]];
          Inc(i, 2);
        end;
        Xor256(@L0, @L0, (sboxkeys[2]) and $FF);
        A := (sboxkeys[0]) and $FF;
        B := (sboxkeys[1]) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[0 and 2, 2 * i + (0 and 1)] := MDS[0, p8x8[0, p8x8[0, L0[i]] xor B] xor A];
          sbox[0 and 2, 2 * i + (0 and 1) + 2] := MDS[0, p8x8[0, p8x8[0, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
        Xor256(@L1, @p8x8[0], (sboxkeys[3] shr 8) and $FF);
        i := 0;
        while i < 256 do
        begin
          L0[i] := p8x8[1, L1[i]];
          L0[i + 1] := p8x8[1, L1[i + 1]];
          Inc(i, 2);
        end;
        Xor256(@L0, @L0, (sboxkeys[2] shr 8) and $FF);
        A := (sboxkeys[0] shr 8) and $FF;
        B := (sboxkeys[1] shr 8) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[1 and 2, 2 * i + (1 and 1)] := MDS[1, p8x8[0, p8x8[1, L0[i]] xor B] xor A];
          sbox[1 and 2, 2 * i + (1 and 1) + 2] := MDS[1, p8x8[0, p8x8[1, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;

        Xor256(@L1, @p8x8[0], (sboxkeys[3] shr 16) and $FF);
        i := 0;
        while i < 256 do
        begin
          L0[i] := p8x8[0, L1[i]];
          L0[i + 1] := p8x8[0, L1[i + 1]];
          Inc(i, 2);
        end;
        Xor256(@L0, @L0, (sboxkeys[2] shr 16) and $FF);
        A := (sboxkeys[0] shr 16) and $FF;
        B := (sboxkeys[1] shr 16) and $FF;
        i := 0;
        while i < 256 do
        begin
          sbox[2 and 2, 2 * i + (2 and 1)] := MDS[2, p8x8[1, p8x8[0, L0[i]] xor B] xor A];
          sbox[2 and 2, 2 * i + (2 and 1) + 2] := MDS[2, p8x8[1, p8x8[0, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
        Xor256(@L1, @p8x8[1], (sboxkeys[3] shr 24));
        i := 0;
        while i < 256 do
        begin
          L0[i] := p8x8[0, L1[i]];
          L0[i + 1] := p8x8[0, L1[i + 1]];
          Inc(i, 2);
        end;
        Xor256(@L0, @L0, (sboxkeys[2] shr 24));
        A := (sboxkeys[0] shr 24);
        B := (sboxkeys[1] shr 24);
        i := 0;
        while i < 256 do
        begin
          sbox[3 and 2, 2 * i + (3 and 1)] := MDS[3, p8x8[1, p8x8[1, L0[i]] xor B] xor A];
          sbox[3 and 2, 2 * i + (3 and 1) + 2] := MDS[3, p8x8[1, p8x8[1, L0[i + 1]] xor B] xor A];
          Inc(i, 2);
        end;
      end;
  end;
end;

procedure TncEnc_twofish.Burn;
begin
  FillChar(sbox, Sizeof(sbox), $FF);
  FillChar(SubKeys, Sizeof(SubKeys), $FF);
  inherited Burn;
end;

procedure TncEnc_twofish.EncryptECB(const InData; var OutData);
var
  i: longword;
  t0, t1: DWord;
  x: array [0 .. 3] of DWord;
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  x[0] := PDWord(@InData)^ xor SubKeys[INPUTWHITEN];
  x[1] := PDWord(longword(@InData) + 4)^ xor SubKeys[INPUTWHITEN + 1];
  x[2] := PDWord(longword(@InData) + 8)^ xor SubKeys[INPUTWHITEN + 2];
  x[3] := PDWord(longword(@InData) + 12)^ xor SubKeys[INPUTWHITEN + 3];
  i := 0;
  while i <= NUMROUNDS - 2 do
  begin
    t0 := sbox[0, (x[0] shl 1) and $1FE] xor sbox[0, ((x[0] shr 7) and $1FE) + 1] xor sbox[2, (x[0] shr 15) and $1FE] xor sbox[2, ((x[0] shr 23) and $1FE) + 1];
    t1 := sbox[0, ((x[1] shr 23) and $1FE)] xor sbox[0, ((x[1] shl 1) and $1FE) + 1] xor sbox[2, ((x[1] shr 7) and $1FE)
      ] xor sbox[2, ((x[1] shr 15) and $1FE) + 1];
    x[3] := (x[3] shl 1) or (x[3] shr 31);
    x[2] := x[2] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * i]);
    x[3] := x[3] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * i + 1]);
    x[2] := (x[2] shr 1) or (x[2] shl 31);

    t0 := sbox[0, (x[2] shl 1) and $1FE] xor sbox[0, ((x[2] shr 7) and $1FE) + 1] xor sbox[2, ((x[2] shr 15) and $1FE)
      ] xor sbox[2, ((x[2] shr 23) and $1FE) + 1];
    t1 := sbox[0, ((x[3] shr 23) and $1FE)] xor sbox[0, ((x[3] shl 1) and $1FE) + 1] xor sbox[2, ((x[3] shr 7) and $1FE)
      ] xor sbox[2, ((x[3] shr 15) and $1FE) + 1];
    x[1] := (x[1] shl 1) or (x[1] shr 31);
    x[0] := x[0] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1)]);
    x[1] := x[1] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1) + 1]);
    x[0] := (x[0] shr 1) or (x[0] shl 31);
    Inc(i, 2);
  end;
  PDWord(longword(@OutData) + 0)^ := x[2] xor SubKeys[OUTPUTWHITEN];
  PDWord(longword(@OutData) + 4)^ := x[3] xor SubKeys[OUTPUTWHITEN + 1];
  PDWord(longword(@OutData) + 8)^ := x[0] xor SubKeys[OUTPUTWHITEN + 2];
  PDWord(longword(@OutData) + 12)^ := x[1] xor SubKeys[OUTPUTWHITEN + 3];
end;

procedure TncEnc_twofish.DecryptECB(const InData; var OutData);
var
  i: integer;
  t0, t1: DWord;
  x: array [0 .. 3] of DWord;
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  x[2] := PDWord(@InData)^ xor SubKeys[OUTPUTWHITEN];
  x[3] := PDWord(longword(@InData) + 4)^ xor SubKeys[OUTPUTWHITEN + 1];
  x[0] := PDWord(longword(@InData) + 8)^ xor SubKeys[OUTPUTWHITEN + 2];
  x[1] := PDWord(longword(@InData) + 12)^ xor SubKeys[OUTPUTWHITEN + 3];
  i := NUMROUNDS - 2;
  while i >= 0 do
  begin
    t0 := sbox[0, (x[2] shl 1) and $1FE] xor sbox[0, ((x[2] shr 7) and $1FE) + 1] xor sbox[2, ((x[2] shr 15) and $1FE)
      ] xor sbox[2, ((x[2] shr 23) and $1FE) + 1];
    t1 := sbox[0, ((x[3] shr 23) and $1FE)] xor sbox[0, ((x[3] shl 1) and $1FE) + 1] xor sbox[2, ((x[3] shr 7) and $1FE)
      ] xor sbox[2, ((x[3] shr 15) and $1FE) + 1];
    x[0] := (x[0] shl 1) or (x[0] shr 31);
    x[0] := x[0] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1)]);
    x[1] := x[1] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1) + 1]);
    x[1] := (x[1] shr 1) or (x[1] shl 31);

    t0 := sbox[0, (x[0] shl 1) and $1FE] xor sbox[0, ((x[0] shr 7) and $1FE) + 1] xor sbox[2, (x[0] shr 15) and $1FE] xor sbox[2, ((x[0] shr 23) and $1FE) + 1];
    t1 := sbox[0, ((x[1] shr 23) and $1FE)] xor sbox[0, ((x[1] shl 1) and $1FE) + 1] xor sbox[2, ((x[1] shr 7) and $1FE)
      ] xor sbox[2, ((x[1] shr 15) and $1FE) + 1];
    x[2] := (x[2] shl 1) or (x[2] shr 31);
    x[2] := x[2] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * i]);
    x[3] := x[3] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * i + 1]);
    x[3] := (x[3] shr 1) or (x[3] shl 31);
    Dec(i, 2);
  end;
  PDWord(longword(@OutData) + 0)^ := x[0] xor SubKeys[INPUTWHITEN];
  PDWord(longword(@OutData) + 4)^ := x[1] xor SubKeys[INPUTWHITEN + 1];
  PDWord(longword(@OutData) + 8)^ := x[2] xor SubKeys[INPUTWHITEN + 2];
  PDWord(longword(@OutData) + 12)^ := x[3] xor SubKeys[INPUTWHITEN + 3];
end;

procedure PreCompMDS;
var
  m1, mx, my: array [0 .. 1] of DWord;
  nI: longword;
begin
  for nI := 0 to 255 do
  begin
    m1[0] := p8x8[0, nI];
    mx[0] := Mul_X(m1[0]);
    my[0] := Mul_Y(m1[0]);
    m1[1] := p8x8[1, nI];
    mx[1] := Mul_X(m1[1]);
    my[1] := Mul_Y(m1[1]);
    MDS[0, nI] := (m1[1] shl 0) or (mx[1] shl 8) or (my[1] shl 16) or (my[1] shl 24);
    MDS[1, nI] := (my[0] shl 0) or (my[0] shl 8) or (mx[0] shl 16) or (m1[0] shl 24);
    MDS[2, nI] := (mx[1] shl 0) or (my[1] shl 8) or (m1[1] shl 16) or (my[1] shl 24);
    MDS[3, nI] := (mx[0] shl 0) or (m1[0] shl 8) or (my[0] shl 16) or (mx[0] shl 24);
  end;
end;

constructor TncEnc_twofish.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  if not MDSDone then
  begin
    PreCompMDS;
    MDSDone := true;
  end;
end;

initialization

MDSDone := false;

end.
