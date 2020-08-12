{$R-}
{$Q-}
unit ncEncSha256;

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
  TncEnc_sha256 = class(TncEnc_hash)
  protected
    LenHi, LenLo: longword;
    Index: DWord;
    CurrentHash: array [0 .. 7] of DWord;
    HashBuffer: array [0 .. 63] of byte;
    procedure Compress;
  public
    class function GetAlgorithm: string; override;
    class function GetHashSize: integer; override;
    class function SelfTest: boolean; override;
    procedure Init; override;
    procedure Final(var Digest); override;
    procedure Burn; override;
    procedure Update(const Buffer; Size: longword); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

function SwapDWord(a: DWord): DWord;
begin
  Result := ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

procedure TncEnc_sha256.Compress;
var
  a, b, c, d, e, f, g, h, t1, t2: DWord;
  W: array [0 .. 63] of DWord;
  i: longword;
begin
  Index := 0;
  a := CurrentHash[0];
  b := CurrentHash[1];
  c := CurrentHash[2];
  d := CurrentHash[3];
  e := CurrentHash[4];
  f := CurrentHash[5];
  g := CurrentHash[6];
  h := CurrentHash[7];
  Move(HashBuffer, W, Sizeof(HashBuffer));
  for i := 0 to 15 do
    W[i] := SwapDWord(W[i]);
  for i := 16 to 63 do
    W[i] := (((W[i - 2] shr 17) or (W[i - 2] shl 15)) xor ((W[i - 2] shr 19) or (W[i - 2] shl 13)) xor (W[i - 2] shr 10)) + W[i - 7] +
      (((W[i - 15] shr 7) or (W[i - 15] shl 25)) xor ((W[i - 15] shr 18) or (W[i - 15] shl 14)) xor (W[i - 15] shr 3)) + W[i - 16];
  {
    Non-optimised version
    for i:= 0 to 63 do
    begin
    t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) +
    ((e and f) xor (not e and g)) + K[i] + W[i];
    t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) +
    ((a and b) xor (a and c) xor (b and c));
    h:= g; g:= f; f:= e; e:= d + t1; d:= c; c:= b; b:= a; a:= t1 + t2;
    end;
  }

  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $428A2F98 + W[0];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $71374491 + W[1];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $B5C0FBCF + W[2];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $E9B5DBA5 + W[3];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $3956C25B + W[4];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $59F111F1 + W[5];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $923F82A4 + W[6];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $AB1C5ED5 + W[7];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $D807AA98 + W[8];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $12835B01 + W[9];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $243185BE + W[10];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $550C7DC3 + W[11];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $72BE5D74 + W[12];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $80DEB1FE + W[13];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $9BDC06A7 + W[14];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $C19BF174 + W[15];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $E49B69C1 + W[16];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $EFBE4786 + W[17];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $0FC19DC6 + W[18];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $240CA1CC + W[19];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $2DE92C6F + W[20];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4A7484AA + W[21];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5CB0A9DC + W[22];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $76F988DA + W[23];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $983E5152 + W[24];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $A831C66D + W[25];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $B00327C8 + W[26];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $BF597FC7 + W[27];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $C6E00BF3 + W[28];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $D5A79147 + W[29];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $06CA6351 + W[30];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $14292967 + W[31];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $27B70A85 + W[32];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $2E1B2138 + W[33];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $4D2C6DFC + W[34];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $53380D13 + W[35];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $650A7354 + W[36];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $766A0ABB + W[37];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $81C2C92E + W[38];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $92722C85 + W[39];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $A2BFE8A1 + W[40];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $A81A664B + W[41];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $C24B8B70 + W[42];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $C76C51A3 + W[43];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $D192E819 + W[44];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $D6990624 + W[45];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $F40E3585 + W[46];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $106AA070 + W[47];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $19A4C116 + W[48];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $1E376C08 + W[49];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $2748774C + W[50];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $34B0BCB5 + W[51];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $391C0CB3 + W[52];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4ED8AA4A + W[53];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5B9CCA4F + W[54];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $682E6FF3 + W[55];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;
  t1 := h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $748F82EE + W[56];
  t2 := (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h := t1 + t2;
  d := d + t1;
  t1 := g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $78A5636F + W[57];
  t2 := (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g := t1 + t2;
  c := c + t1;
  t1 := f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $84C87814 + W[58];
  t2 := (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f := t1 + t2;
  b := b + t1;
  t1 := e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $8CC70208 + W[59];
  t2 := (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e := t1 + t2;
  a := a + t1;
  t1 := d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $90BEFFFA + W[60];
  t2 := (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d := t1 + t2;
  h := h + t1;
  t1 := c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $A4506CEB + W[61];
  t2 := (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c := t1 + t2;
  g := g + t1;
  t1 := b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $BEF9A3F7 + W[62];
  t2 := (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b := t1 + t2;
  f := f + t1;
  t1 := a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $C67178F2 + W[63];
  t2 := (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a := t1 + t2;
  e := e + t1;

  CurrentHash[0] := CurrentHash[0] + a;
  CurrentHash[1] := CurrentHash[1] + b;
  CurrentHash[2] := CurrentHash[2] + c;
  CurrentHash[3] := CurrentHash[3] + d;
  CurrentHash[4] := CurrentHash[4] + e;
  CurrentHash[5] := CurrentHash[5] + f;
  CurrentHash[6] := CurrentHash[6] + g;
  CurrentHash[7] := CurrentHash[7] + h;
  FillChar(W, Sizeof(W), 0);
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_sha256.GetAlgorithm: string;
begin
  Result := 'SHA256';
end;

class function TncEnc_sha256.GetHashSize: integer;
begin
  Result := 256;
end;

class function TncEnc_sha256.SelfTest: boolean;
const
  Test1Out: array [0 .. 31] of byte = ($BA, $78, $16, $BF, $8F, $01, $CF, $EA, $41, $41, $40, $DE, $5D, $AE, $22, $23, $B0, $03, $61, $A3, $96, $17, $7A, $9C,
    $B4, $10, $FF, $61, $F2, $00, $15, $AD);
  Test2Out: array [0 .. 31] of byte = ($24, $8D, $6A, $61, $D2, $06, $38, $B8, $E5, $C0, $26, $93, $0C, $3E, $60, $39, $A3, $3C, $E4, $59, $64, $FF, $21, $67,
    $F6, $EC, $ED, $D4, $19, $DB, $06, $C1);
var
  TestHash: TncEnc_sha256;
  TestOut: array [0 .. 31] of byte;
begin
  TestHash := TncEnc_sha256.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abc');
  TestHash.Final(TestOut);
  Result := boolean(CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out)));
  TestHash.Init;
  TestHash.UpdateStr('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
  TestHash.Final(TestOut);
  Result := boolean(CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out))) and Result;
  TestHash.Free;
end;

procedure TncEnc_sha256.Init;
begin
  Burn;
  CurrentHash[0] := $6A09E667;
  CurrentHash[1] := $BB67AE85;
  CurrentHash[2] := $3C6EF372;
  CurrentHash[3] := $A54FF53A;
  CurrentHash[4] := $510E527F;
  CurrentHash[5] := $9B05688C;
  CurrentHash[6] := $1F83D9AB;
  CurrentHash[7] := $5BE0CD19;
  fInitialized := true;
end;

procedure TncEnc_sha256.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  fInitialized := false;
end;

procedure TncEnc_sha256.Update(const Buffer; Size: longword);
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

procedure TncEnc_sha256.Final(var Digest);
begin
  if not fInitialized then
    raise EncEnc_hash.Create('Hash not initialized');
  HashBuffer[Index] := $80;
  if Index >= 56 then
    Compress;
  PDWord(@HashBuffer[56])^ := SwapDWord(LenHi);
  PDWord(@HashBuffer[60])^ := SwapDWord(LenLo);
  Compress;
  CurrentHash[0] := SwapDWord(CurrentHash[0]);
  CurrentHash[1] := SwapDWord(CurrentHash[1]);
  CurrentHash[2] := SwapDWord(CurrentHash[2]);
  CurrentHash[3] := SwapDWord(CurrentHash[3]);
  CurrentHash[4] := SwapDWord(CurrentHash[4]);
  CurrentHash[5] := SwapDWord(CurrentHash[5]);
  CurrentHash[6] := SwapDWord(CurrentHash[6]);
  CurrentHash[7] := SwapDWord(CurrentHash[7]);
  Move(CurrentHash, Digest, Sizeof(CurrentHash));
  Burn;
end;

end.
