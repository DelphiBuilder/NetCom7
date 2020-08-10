{$R-}
{$Q-}
unit ncEncDes;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  System.Classes, System.Sysutils, ncEnccrypt2, ncEncblockciphers;

type
  TncEnc_customdes = class(TncEnc_blockcipher64)
  protected
    procedure DoInit(KeyB: PByteArray; KeyData: PDWordArray);
    procedure EncryptBlock(const InData; var OutData; KeyData: PDWordArray);
    procedure DecryptBlock(const InData; var OutData; KeyData: PDWordArray);
  end;

type
  TncEnc_des = class(TncEnc_customdes)
  protected
    KeyData: array [0 .. 31] of dword;
    procedure InitKey(const Key; Size: longword); override;
  public
    class function GetAlgorithm: string; override;
    class function GetMaxKeySize: integer; override;
    class function SelfTest: boolean; override;
    procedure Burn; override;
    procedure EncryptECB(const InData; var OutData); override;
    procedure DecryptECB(const InData; var OutData); override;
  end;

  TncEnc_3des = class(TncEnc_customdes)
  protected
    KeyData: array [0 .. 2, 0 .. 31] of dword;
    procedure InitKey(const Key; Size: longword); override;
  public
    class function GetAlgorithm: string; override;
    class function GetMaxKeySize: integer; override;
    class function SelfTest: boolean; override;
    procedure Burn; override;
    procedure EncryptECB(const InData; var OutData); override;
    procedure DecryptECB(const InData; var OutData); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

const
  shifts2: array [0 .. 15] of byte = (0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0);

  des_skb: array [0 .. 7, 0 .. 63] of dword = ((
    (* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 *)
    $00000000, $00000010, $20000000, $20000010, $00010000, $00010010, $20010000, $20010010, $00000800, $00000810, $20000800, $20000810, $00010800, $00010810,
    $20010800, $20010810, $00000020, $00000030, $20000020, $20000030, $00010020, $00010030, $20010020, $20010030, $00000820, $00000830, $20000820, $20000830,
    $00010820, $00010830, $20010820, $20010830, $00080000, $00080010, $20080000, $20080010, $00090000, $00090010, $20090000, $20090010, $00080800, $00080810,
    $20080800, $20080810, $00090800, $00090810, $20090800, $20090810, $00080020, $00080030, $20080020, $20080030, $00090020, $00090030, $20090020, $20090030,
    $00080820, $00080830, $20080820, $20080830, $00090820, $00090830, $20090820, $20090830), (
    (* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 *)
    $00000000, $02000000, $00002000, $02002000, $00200000, $02200000, $00202000, $02202000, $00000004, $02000004, $00002004, $02002004, $00200004, $02200004,
    $00202004, $02202004, $00000400, $02000400, $00002400, $02002400, $00200400, $02200400, $00202400, $02202400, $00000404, $02000404, $00002404, $02002404,
    $00200404, $02200404, $00202404, $02202404, $10000000, $12000000, $10002000, $12002000, $10200000, $12200000, $10202000, $12202000, $10000004, $12000004,
    $10002004, $12002004, $10200004, $12200004, $10202004, $12202004, $10000400, $12000400, $10002400, $12002400, $10200400, $12200400, $10202400, $12202400,
    $10000404, $12000404, $10002404, $12002404, $10200404, $12200404, $10202404, $12202404), (
    (* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 *)
    $00000000, $00000001, $00040000, $00040001, $01000000, $01000001, $01040000, $01040001, $00000002, $00000003, $00040002, $00040003, $01000002, $01000003,
    $01040002, $01040003, $00000200, $00000201, $00040200, $00040201, $01000200, $01000201, $01040200, $01040201, $00000202, $00000203, $00040202, $00040203,
    $01000202, $01000203, $01040202, $01040203, $08000000, $08000001, $08040000, $08040001, $09000000, $09000001, $09040000, $09040001, $08000002, $08000003,
    $08040002, $08040003, $09000002, $09000003, $09040002, $09040003, $08000200, $08000201, $08040200, $08040201, $09000200, $09000201, $09040200, $09040201,
    $08000202, $08000203, $08040202, $08040203, $09000202, $09000203, $09040202, $09040203), (
    (* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 *)
    $00000000, $00100000, $00000100, $00100100, $00000008, $00100008, $00000108, $00100108, $00001000, $00101000, $00001100, $00101100, $00001008, $00101008,
    $00001108, $00101108, $04000000, $04100000, $04000100, $04100100, $04000008, $04100008, $04000108, $04100108, $04001000, $04101000, $04001100, $04101100,
    $04001008, $04101008, $04001108, $04101108, $00020000, $00120000, $00020100, $00120100, $00020008, $00120008, $00020108, $00120108, $00021000, $00121000,
    $00021100, $00121100, $00021008, $00121008, $00021108, $00121108, $04020000, $04120000, $04020100, $04120100, $04020008, $04120008, $04020108, $04120108,
    $04021000, $04121000, $04021100, $04121100, $04021008, $04121008, $04021108, $04121108), (
    (* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 *)
    $00000000, $10000000, $00010000, $10010000, $00000004, $10000004, $00010004, $10010004, $20000000, $30000000, $20010000, $30010000, $20000004, $30000004,
    $20010004, $30010004, $00100000, $10100000, $00110000, $10110000, $00100004, $10100004, $00110004, $10110004, $20100000, $30100000, $20110000, $30110000,
    $20100004, $30100004, $20110004, $30110004, $00001000, $10001000, $00011000, $10011000, $00001004, $10001004, $00011004, $10011004, $20001000, $30001000,
    $20011000, $30011000, $20001004, $30001004, $20011004, $30011004, $00101000, $10101000, $00111000, $10111000, $00101004, $10101004, $00111004, $10111004,
    $20101000, $30101000, $20111000, $30111000, $20101004, $30101004, $20111004, $30111004), (
    (* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 *)
    $00000000, $08000000, $00000008, $08000008, $00000400, $08000400, $00000408, $08000408, $00020000, $08020000, $00020008, $08020008, $00020400, $08020400,
    $00020408, $08020408, $00000001, $08000001, $00000009, $08000009, $00000401, $08000401, $00000409, $08000409, $00020001, $08020001, $00020009, $08020009,
    $00020401, $08020401, $00020409, $08020409, $02000000, $0A000000, $02000008, $0A000008, $02000400, $0A000400, $02000408, $0A000408, $02020000, $0A020000,
    $02020008, $0A020008, $02020400, $0A020400, $02020408, $0A020408, $02000001, $0A000001, $02000009, $0A000009, $02000401, $0A000401, $02000409, $0A000409,
    $02020001, $0A020001, $02020009, $0A020009, $02020401, $0A020401, $02020409, $0A020409), (
    (* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 *)
    $00000000, $00000100, $00080000, $00080100, $01000000, $01000100, $01080000, $01080100, $00000010, $00000110, $00080010, $00080110, $01000010, $01000110,
    $01080010, $01080110, $00200000, $00200100, $00280000, $00280100, $01200000, $01200100, $01280000, $01280100, $00200010, $00200110, $00280010, $00280110,
    $01200010, $01200110, $01280010, $01280110, $00000200, $00000300, $00080200, $00080300, $01000200, $01000300, $01080200, $01080300, $00000210, $00000310,
    $00080210, $00080310, $01000210, $01000310, $01080210, $01080310, $00200200, $00200300, $00280200, $00280300, $01200200, $01200300, $01280200, $01280300,
    $00200210, $00200310, $00280210, $00280310, $01200210, $01200310, $01280210, $01280310), (
    (* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 *)
    $00000000, $04000000, $00040000, $04040000, $00000002, $04000002, $00040002, $04040002, $00002000, $04002000, $00042000, $04042000, $00002002, $04002002,
    $00042002, $04042002, $00000020, $04000020, $00040020, $04040020, $00000022, $04000022, $00040022, $04040022, $00002020, $04002020, $00042020, $04042020,
    $00002022, $04002022, $00042022, $04042022, $00000800, $04000800, $00040800, $04040800, $00000802, $04000802, $00040802, $04040802, $00002800, $04002800,
    $00042800, $04042800, $00002802, $04002802, $00042802, $04042802, $00000820, $04000820, $00040820, $04040820, $00000822, $04000822, $00040822, $04040822,
    $00002820, $04002820, $00042820, $04042820, $00002822, $04002822, $00042822, $04042822));

  des_sptrans: array [0 .. 7, 0 .. 63] of dword = ((
    (* nibble 0 *)
    $02080800, $00080000, $02000002, $02080802, $02000000, $00080802, $00080002, $02000002, $00080802, $02080800, $02080000, $00000802, $02000802, $02000000,
    $00000000, $00080002, $00080000, $00000002, $02000800, $00080800, $02080802, $02080000, $00000802, $02000800, $00000002, $00000800, $00080800, $02080002,
    $00000800, $02000802, $02080002, $00000000, $00000000, $02080802, $02000800, $00080002, $02080800, $00080000, $00000802, $02000800, $02080002, $00000800,
    $00080800, $02000002, $00080802, $00000002, $02000002, $02080000, $02080802, $00080800, $02080000, $02000802, $02000000, $00000802, $00080002, $00000000,
    $00080000, $02000000, $02000802, $02080800, $00000002, $02080002, $00000800, $00080802), (
    (* nibble 1 *)
    $40108010, $00000000, $00108000, $40100000, $40000010, $00008010, $40008000, $00108000, $00008000, $40100010, $00000010, $40008000, $00100010, $40108000,
    $40100000, $00000010, $00100000, $40008010, $40100010, $00008000, $00108010, $40000000, $00000000, $00100010, $40008010, $00108010, $40108000, $40000010,
    $40000000, $00100000, $00008010, $40108010, $00100010, $40108000, $40008000, $00108010, $40108010, $00100010, $40000010, $00000000, $40000000, $00008010,
    $00100000, $40100010, $00008000, $40000000, $00108010, $40008010, $40108000, $00008000, $00000000, $40000010, $00000010, $40108010, $00108000, $40100000,
    $40100010, $00100000, $00008010, $40008000, $40008010, $00000010, $40100000, $00108000), (
    (* nibble 2 *)
    $04000001, $04040100, $00000100, $04000101, $00040001, $04000000, $04000101, $00040100, $04000100, $00040000, $04040000, $00000001, $04040101, $00000101,
    $00000001, $04040001, $00000000, $00040001, $04040100, $00000100, $00000101, $04040101, $00040000, $04000001, $04040001, $04000100, $00040101, $04040000,
    $00040100, $00000000, $04000000, $00040101, $04040100, $00000100, $00000001, $00040000, $00000101, $00040001, $04040000, $04000101, $00000000, $04040100,
    $00040100, $04040001, $00040001, $04000000, $04040101, $00000001, $00040101, $04000001, $04000000, $04040101, $00040000, $04000100, $04000101, $00040100,
    $04000100, $00000000, $04040001, $00000101, $04000001, $00040101, $00000100, $04040000), (
    (* nibble 3 *)
    $00401008, $10001000, $00000008, $10401008, $00000000, $10400000, $10001008, $00400008, $10401000, $10000008, $10000000, $00001008, $10000008, $00401008,
    $00400000, $10000000, $10400008, $00401000, $00001000, $00000008, $00401000, $10001008, $10400000, $00001000, $00001008, $00000000, $00400008, $10401000,
    $10001000, $10400008, $10401008, $00400000, $10400008, $00001008, $00400000, $10000008, $00401000, $10001000, $00000008, $10400000, $10001008, $00000000,
    $00001000, $00400008, $00000000, $10400008, $10401000, $00001000, $10000000, $10401008, $00401008, $00400000, $10401008, $00000008, $10001000, $00401008,
    $00400008, $00401000, $10400000, $10001008, $00001008, $10000000, $10000008, $10401000), (
    (* nibble 4 *)
    $08000000, $00010000, $00000400, $08010420, $08010020, $08000400, $00010420, $08010000, $00010000, $00000020, $08000020, $00010400, $08000420, $08010020,
    $08010400, $00000000, $00010400, $08000000, $00010020, $00000420, $08000400, $00010420, $00000000, $08000020, $00000020, $08000420, $08010420, $00010020,
    $08010000, $00000400, $00000420, $08010400, $08010400, $08000420, $00010020, $08010000, $00010000, $00000020, $08000020, $08000400, $08000000, $00010400,
    $08010420, $00000000, $00010420, $08000000, $00000400, $00010020, $08000420, $00000400, $00000000, $08010420, $08010020, $08010400, $00000420, $00010000,
    $00010400, $08010020, $08000400, $00000420, $00000020, $00010420, $08010000, $08000020), (
    (* nibble 5 *)
    $80000040, $00200040, $00000000, $80202000, $00200040, $00002000, $80002040, $00200000, $00002040, $80202040, $00202000, $80000000, $80002000, $80000040,
    $80200000, $00202040, $00200000, $80002040, $80200040, $00000000, $00002000, $00000040, $80202000, $80200040, $80202040, $80200000, $80000000, $00002040,
    $00000040, $00202000, $00202040, $80002000, $00002040, $80000000, $80002000, $00202040, $80202000, $00200040, $00000000, $80002000, $80000000, $00002000,
    $80200040, $00200000, $00200040, $80202040, $00202000, $00000040, $80202040, $00202000, $00200000, $80002040, $80000040, $80200000, $00202040, $00000000,
    $00002000, $80000040, $80002040, $80202000, $80200000, $00002040, $00000040, $80200040), (
    (* nibble 6 *)
    $00004000, $00000200, $01000200, $01000004, $01004204, $00004004, $00004200, $00000000, $01000000, $01000204, $00000204, $01004000, $00000004, $01004200,
    $01004000, $00000204, $01000204, $00004000, $00004004, $01004204, $00000000, $01000200, $01000004, $00004200, $01004004, $00004204, $01004200, $00000004,
    $00004204, $01004004, $00000200, $01000000, $00004204, $01004000, $01004004, $00000204, $00004000, $00000200, $01000000, $01004004, $01000204, $00004204,
    $00004200, $00000000, $00000200, $01000004, $00000004, $01000200, $00000000, $01000204, $01000200, $00004200, $00000204, $00004000, $01004204, $01000000,
    $01004200, $00000004, $00004004, $01004204, $01000004, $01004200, $01004000, $00004004), (
    (* nibble 7 *)
    $20800080, $20820000, $00020080, $00000000, $20020000, $00800080, $20800000, $20820080, $00000080, $20000000, $00820000, $00020080, $00820080, $20020080,
    $20000080, $20800000, $00020000, $00820080, $00800080, $20020000, $20820080, $20000080, $00000000, $00820000, $20000000, $00800000, $20020080, $20800080,
    $00800000, $00020000, $20820000, $00000080, $00800000, $00020000, $20000080, $20820080, $00020080, $20000000, $00000000, $00820000, $20800080, $20020080,
    $20020000, $00800080, $20820000, $00000080, $00800080, $20020000, $20820080, $00800000, $20800000, $20000080, $00820000, $00020080, $20020080, $20800000,
    $00000080, $20820000, $00820080, $00000000, $20000000, $20800080, $00020000, $00820080));

procedure hperm_op(var a, t: dword; n, m: dword);
begin
  t := ((a shl (16 - n)) xor a) and m;
  a := a xor t xor (t shr (16 - n));
end;

procedure perm_op(var a, b, t: dword; n, m: dword);
begin
  t := ((a shr n) xor b) and m;
  b := b xor t;
  a := a xor (t shl n);
end;

procedure TncEnc_customdes.DoInit(KeyB: PByteArray; KeyData: PDWordArray);
var
  c, d, t, s, t2, i: dword;
begin
  c := KeyB^[0] or (KeyB^[1] shl 8) or (KeyB^[2] shl 16) or (KeyB^[3] shl 24);
  d := KeyB^[4] or (KeyB^[5] shl 8) or (KeyB^[6] shl 16) or (KeyB^[7] shl 24);
  perm_op(d, c, t, 4, $0F0F0F0F);
  hperm_op(c, t, dword(-2), $CCCC0000);
  hperm_op(d, t, dword(-2), $CCCC0000);
  perm_op(d, c, t, 1, $55555555);
  perm_op(c, d, t, 8, $00FF00FF);
  perm_op(d, c, t, 1, $55555555);
  d := ((d and $FF) shl 16) or (d and $FF00) or ((d and $FF0000) shr 16) or ((c and $F0000000) shr 4);
  c := c and $FFFFFFF;
  for i := 0 to 15 do
  begin
    if shifts2[i] <> 0 then
    begin
      c := ((c shr 2) or (c shl 26));
      d := ((d shr 2) or (d shl 26));
    end
    else
    begin
      c := ((c shr 1) or (c shl 27));
      d := ((d shr 1) or (d shl 27));
    end;
    c := c and $FFFFFFF;
    d := d and $FFFFFFF;
    s := des_skb[0, c and $3F] or des_skb[1, ((c shr 6) and $03) or ((c shr 7) and $3C)] or des_skb[2, ((c shr 13) and $0F) or ((c shr 14) and $30)] or
      des_skb[3, ((c shr 20) and $01) or ((c shr 21) and $06) or ((c shr 22) and $38)];
    t := des_skb[4, d and $3F] or des_skb[5, ((d shr 7) and $03) or ((d shr 8) and $3C)] or des_skb[6, (d shr 15) and $3F] or
      des_skb[7, ((d shr 21) and $0F) or ((d shr 22) and $30)];
    t2 := ((t shl 16) or (s and $FFFF));
    KeyData^[(i shl 1)] := ((t2 shl 2) or (t2 shr 30));
    t2 := ((s shr 16) or (t and $FFFF0000));
    KeyData^[(i shl 1) + 1] := ((t2 shl 6) or (t2 shr 26));
  end;
end;

procedure TncEnc_customdes.EncryptBlock(const InData; var OutData; KeyData: PDWordArray);
var
  l, r, t, u: dword;
  i: longint;
begin
  r := PDword(@InData)^;
  l := PDword(dword(@InData) + 4)^;
  t := ((l shr 4) xor r) and $0F0F0F0F;
  r := r xor t;
  l := l xor (t shl 4);
  t := ((r shr 16) xor l) and $0000FFFF;
  l := l xor t;
  r := r xor (t shl 16);
  t := ((l shr 2) xor r) and $33333333;
  r := r xor t;
  l := l xor (t shl 2);
  t := ((r shr 8) xor l) and $00FF00FF;
  l := l xor t;
  r := r xor (t shl 8);
  t := ((l shr 1) xor r) and $55555555;
  r := r xor t;
  l := l xor (t shl 1);
  r := (r shr 29) or (r shl 3);
  l := (l shr 29) or (l shl 3);
  i := 0;
  while i < 32 do
  begin
    u := r xor KeyData^[i];
    t := r xor KeyData^[i + 1];
    t := (t shr 4) or (t shl 28);
    l := l xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    u := l xor KeyData^[i + 2];
    t := l xor KeyData^[i + 3];
    t := (t shr 4) or (t shl 28);
    r := r xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    u := r xor KeyData^[i + 4];
    t := r xor KeyData^[i + 5];
    t := (t shr 4) or (t shl 28);
    l := l xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    u := l xor KeyData^[i + 6];
    t := l xor KeyData^[i + 7];
    t := (t shr 4) or (t shl 28);
    r := r xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    Inc(i, 8);
  end;
  r := (r shr 3) or (r shl 29);
  l := (l shr 3) or (l shl 29);
  t := ((r shr 1) xor l) and $55555555;
  l := l xor t;
  r := r xor (t shl 1);
  t := ((l shr 8) xor r) and $00FF00FF;
  r := r xor t;
  l := l xor (t shl 8);
  t := ((r shr 2) xor l) and $33333333;
  l := l xor t;
  r := r xor (t shl 2);
  t := ((l shr 16) xor r) and $0000FFFF;
  r := r xor t;
  l := l xor (t shl 16);
  t := ((r shr 4) xor l) and $0F0F0F0F;
  l := l xor t;
  r := r xor (t shl 4);
  PDword(@OutData)^ := l;
  PDword(dword(@OutData) + 4)^ := r;
end;

procedure TncEnc_customdes.DecryptBlock(const InData; var OutData; KeyData: PDWordArray);
var
  l, r, t, u: dword;
  i: longint;
begin
  r := PDword(@InData)^;
  l := PDword(dword(@InData) + 4)^;
  t := ((l shr 4) xor r) and $0F0F0F0F;
  r := r xor t;
  l := l xor (t shl 4);
  t := ((r shr 16) xor l) and $0000FFFF;
  l := l xor t;
  r := r xor (t shl 16);
  t := ((l shr 2) xor r) and $33333333;
  r := r xor t;
  l := l xor (t shl 2);
  t := ((r shr 8) xor l) and $00FF00FF;
  l := l xor t;
  r := r xor (t shl 8);
  t := ((l shr 1) xor r) and $55555555;
  r := r xor t;
  l := l xor (t shl 1);
  r := (r shr 29) or (r shl 3);
  l := (l shr 29) or (l shl 3);
  i := 30;
  while i > 0 do
  begin
    u := r xor KeyData^[i];
    t := r xor KeyData^[i + 1];
    t := (t shr 4) or (t shl 28);
    l := l xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    u := l xor KeyData^[i - 2];
    t := l xor KeyData^[i - 1];
    t := (t shr 4) or (t shl 28);
    r := r xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    u := r xor KeyData^[i - 4];
    t := r xor KeyData^[i - 3];
    t := (t shr 4) or (t shl 28);
    l := l xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    u := l xor KeyData^[i - 6];
    t := l xor KeyData^[i - 5];
    t := (t shr 4) or (t shl 28);
    r := r xor des_sptrans[0, (u shr 2) and $3F] xor des_sptrans[2, (u shr 10) and $3F] xor des_sptrans[4, (u shr 18) and $3F] xor des_sptrans
      [6, (u shr 26) and $3F] xor des_sptrans[1, (t shr 2) and $3F] xor des_sptrans[3, (t shr 10) and $3F] xor des_sptrans[5, (t shr 18) and $3F]
      xor des_sptrans[7, (t shr 26) and $3F];
    Dec(i, 8);
  end;
  r := (r shr 3) or (r shl 29);
  l := (l shr 3) or (l shl 29);
  t := ((r shr 1) xor l) and $55555555;
  l := l xor t;
  r := r xor (t shl 1);
  t := ((l shr 8) xor r) and $00FF00FF;
  r := r xor t;
  l := l xor (t shl 8);
  t := ((r shr 2) xor l) and $33333333;
  l := l xor t;
  r := r xor (t shl 2);
  t := ((l shr 16) xor r) and $0000FFFF;
  r := r xor t;
  l := l xor (t shl 16);
  t := ((r shr 4) xor l) and $0F0F0F0F;
  l := l xor t;
  r := r xor (t shl 4);
  PDword(@OutData)^ := l;
  PDword(dword(@OutData) + 4)^ := r;
end;

class function TncEnc_des.GetMaxKeySize: integer;
begin
  Result := 64;
end;

class function TncEnc_des.GetAlgorithm: string;
begin
  Result := 'DES';
end;

class function TncEnc_des.SelfTest: boolean;
const
  InData1: array [0 .. 7] of byte = ($07, $56, $D8, $E0, $77, $47, $61, $D2);
  OutData1: array [0 .. 7] of byte = ($0C, $D3, $DA, $02, $00, $21, $DC, $09);
  Key1: array [0 .. 7] of byte = ($01, $70, $F1, $75, $46, $8F, $B5, $E6);
  InData2: array [0 .. 7] of byte = ($48, $0D, $39, $00, $6E, $E7, $62, $F2);
  OutData2: array [0 .. 7] of byte = ($A1, $F9, $91, $55, $41, $02, $0B, $56);
  Key2: array [0 .. 7] of byte = ($02, $58, $16, $16, $46, $29, $B0, $07);
var
  Cipher: TncEnc_des;
  Data: array [0 .. 7] of byte;
begin
  Cipher := TncEnc_des.Create(nil);
  Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
  Cipher.EncryptECB(InData1, Data);
  Result := boolean(CompareMem(@Data, @OutData1, Sizeof(Data)));
  Cipher.DecryptECB(Data, Data);
  Result := Result and boolean(CompareMem(@Data, @InData1, Sizeof(Data)));
  Cipher.Burn;
  Cipher.Init(Key2, Sizeof(Key2) * 8, nil);
  Cipher.EncryptECB(InData2, Data);
  Result := Result and boolean(CompareMem(@Data, @OutData2, Sizeof(Data)));
  Cipher.DecryptECB(Data, Data);
  Result := Result and boolean(CompareMem(@Data, @InData2, Sizeof(Data)));
  Cipher.Burn;
  Cipher.Free;
end;

procedure TncEnc_des.InitKey(const Key; Size: longword);
var
  KeyB: array [0 .. 7] of byte;
begin
  FillChar(KeyB, Sizeof(KeyB), 0);
  Move(Key, KeyB, Size div 8);
  DoInit(@KeyB, @KeyData);
end;

procedure TncEnc_des.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), 0);
  inherited Burn;
end;

procedure TncEnc_des.EncryptECB(const InData; var OutData);
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  EncryptBlock(InData, OutData, @KeyData);
end;

procedure TncEnc_des.DecryptECB(const InData; var OutData);
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  DecryptBlock(InData, OutData, @KeyData);
end;

{ ****************************************************************************** }
class function TncEnc_3des.GetMaxKeySize: integer;
begin
  Result := 192;
end;

class function TncEnc_3des.GetAlgorithm: string;
begin
  Result := '3DES';
end;

class function TncEnc_3des.SelfTest: boolean;
const
  Key: array [0 .. 23] of byte = ($01, $23, $45, $67, $89, $AB, $CD, $EF, $FE, $DC, $BA, $98, $76, $54, $32, $10, $89, $AB, $CD, $EF, $01, $23, $45, $67);
  PlainText: array [0 .. 7] of byte = ($01, $23, $45, $67, $89, $AB, $CD, $E7);
  CipherText: array [0 .. 7] of byte = ($DE, $0B, $7C, $06, $AE, $5E, $0E, $D5);
var
  Cipher: TncEnc_3des;
  Block: array [0 .. 7] of byte;
begin
  Cipher := TncEnc_3des.Create(nil);
  Cipher.Init(Key, Sizeof(Key) * 8, nil);
  Cipher.EncryptECB(PlainText, Block);
  Result := CompareMem(@Block, @CipherText, Sizeof(CipherText));
  Cipher.DecryptECB(Block, Block);
  Result := Result and CompareMem(@Block, @PlainText, Sizeof(PlainText));
  Cipher.Free;
end;

procedure TncEnc_3des.InitKey(const Key; Size: longword);
var
  KeyB: array [0 .. 2, 0 .. 7] of byte;
begin
  FillChar(KeyB, Sizeof(KeyB), 0);
  Move(Key, KeyB, Size div 8);
  DoInit(@KeyB[0], @KeyData[0]);
  DoInit(@KeyB[1], @KeyData[1]);
  if Size > 128 then
    DoInit(@KeyB[2], @KeyData[2])
  else
    Move(KeyData[0], KeyData[2], 128);
end;

procedure TncEnc_3des.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), 0);
  inherited Burn;
end;

procedure TncEnc_3des.EncryptECB(const InData; var OutData);
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  EncryptBlock(InData, OutData, @KeyData[0]);
  DecryptBlock(OutData, OutData, @KeyData[1]);
  EncryptBlock(OutData, OutData, @KeyData[2]);
end;

procedure TncEnc_3des.DecryptECB(const InData; var OutData);
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  DecryptBlock(InData, OutData, @KeyData[2]);
  EncryptBlock(OutData, OutData, @KeyData[1]);
  DecryptBlock(OutData, OutData, @KeyData[0]);
end;

end.
