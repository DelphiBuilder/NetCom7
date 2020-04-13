{$R-}
{$Q-}
{$WARN BOUNDS_ERROR OFF}
{$WARN COMBINING_SIGNED_UNSIGNED64 OFF}
unit ncEncSha512;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

  uses
    Classes, Sysutils, ncEnccrypt2;

  type
    TncEnc_sha512base = class(TncEnc_hash)
    protected
      LenHi, LenLo: int64;
      Index: DWord;
      CurrentHash: array [0 .. 7] of int64;
      HashBuffer: array [0 .. 127] of byte;
      procedure Compress;
    public
      procedure Update(const Buffer; Size: longword); override;
      procedure Burn; override;
    end;

    TncEnc_sha384 = class(TncEnc_sha512base)
    public
      class function GetAlgorithm: string; override;
      class function GetHashSize: integer; override;
      class function SelfTest: boolean; override;
      procedure Init; override;
      procedure Final(var Digest); override;
    end;

    TncEnc_sha512 = class(TncEnc_sha512base)
    public
      class function GetAlgorithm: string; override;
      class function GetHashSize: integer; override;
      class function SelfTest: boolean; override;
      procedure Init; override;
      procedure Final(var Digest); override;
    end;

    { ****************************************************************************** }
    { ****************************************************************************** }
implementation

  uses ncEncryption;

  function SwapDWord(a: int64): int64;
  begin
    Result := ((a and $FF) shl 56) or ((a and $FF00) shl 40) or ((a and $FF0000) shl 24) or ((a and $FF000000) shl 8) or ((a and $FF00000000) shr 8) or
      ((a and $FF0000000000) shr 24) or ((a and $FF000000000000) shr 40) or ((a and $FF00000000000000) shr 56);
  end;

  procedure TncEnc_sha512base.Compress;
  var
    a, b, c, d, e, f, g, h, t1, t2: int64;
    W: array [0 .. 79] of int64;
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
    for i := 16 to 79 do
      W[i] := (((W[i - 2] shr 19) or (W[i - 2] shl 45)) xor ((W[i - 2] shr 61) or (W[i - 2] shl 3)) xor (W[i - 2] shr 6)) + W[i - 7] +
        (((W[i - 15] shr 1) or (W[i - 15] shl 63)) xor ((W[i - 15] shr 8) or (W[i - 15] shl 56)) xor (W[i - 15] shr 7)) + W[i - 16];

    {
      Non-optimised version
      for i:= 0 to 79 do
      begin
      t1:= h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) +
      ((e and f) xor (not e and g)) + K[i] + W[i];
      t2:= (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) +
      ((a and b) xor (a and c) xor (b and c));
      h:= g; g:= f; f:= e; e:= d + t1; d:= c; c:= b; b:= a; a:= t1 + t2;
      end;
    }

    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $428A2F98D728AE22 + W[0];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $7137449123EF65CD + W[1];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $B5C0FBCFEC4D3B2F + W[2];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $E9B5DBA58189DBBC + W[3];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $3956C25BF348B538 + W[4];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $59F111F1B605D019 + W[5];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $923F82A4AF194F9B + W[6];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $AB1C5ED5DA6D8118 + W[7];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $D807AA98A3030242 + W[8];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $12835B0145706FBE + W[9];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $243185BE4EE4B28C + W[10];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $550C7DC3D5FFB4E2 + W[11];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $72BE5D74F27B896F + W[12];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $80DEB1FE3B1696B1 + W[13];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $9BDC06A725C71235 + W[14];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $C19BF174CF692694 + W[15];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $E49B69C19EF14AD2 + W[16];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $EFBE4786384F25E3 + W[17];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $0FC19DC68B8CD5B5 + W[18];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $240CA1CC77AC9C65 + W[19];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $2DE92C6F592B0275 + W[20];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $4A7484AA6EA6E483 + W[21];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $5CB0A9DCBD41FBD4 + W[22];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $76F988DA831153B5 + W[23];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $983E5152EE66DFAB + W[24];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $A831C66D2DB43210 + W[25];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $B00327C898FB213F + W[26];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $BF597FC7BEEF0EE4 + W[27];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $C6E00BF33DA88FC2 + W[28];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $D5A79147930AA725 + W[29];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $06CA6351E003826F + W[30];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $142929670A0E6E70 + W[31];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $27B70A8546D22FFC + W[32];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $2E1B21385C26C926 + W[33];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $4D2C6DFC5AC42AED + W[34];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $53380D139D95B3DF + W[35];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $650A73548BAF63DE + W[36];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $766A0ABB3C77B2A8 + W[37];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $81C2C92E47EDAEE6 + W[38];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $92722C851482353B + W[39];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $A2BFE8A14CF10364 + W[40];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $A81A664BBC423001 + W[41];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $C24B8B70D0F89791 + W[42];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $C76C51A30654BE30 + W[43];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $D192E819D6EF5218 + W[44];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $D69906245565A910 + W[45];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $F40E35855771202A + W[46];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $106AA07032BBD1B8 + W[47];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $19A4C116B8D2D0C8 + W[48];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $1E376C085141AB53 + W[49];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $2748774CDF8EEB99 + W[50];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $34B0BCB5E19B48A8 + W[51];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $391C0CB3C5C95A63 + W[52];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $4ED8AA4AE3418ACB + W[53];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $5B9CCA4F7763E373 + W[54];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $682E6FF3D6B2B8A3 + W[55];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $748F82EE5DEFB2FC + W[56];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $78A5636F43172F60 + W[57];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $84C87814A1F0AB72 + W[58];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $8CC702081A6439EC + W[59];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $90BEFFFA23631E28 + W[60];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $A4506CEBDE82BDE9 + W[61];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $BEF9A3F7B2C67915 + W[62];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $C67178F2E372532B + W[63];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $CA273ECEEA26619C + W[64];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $D186B8C721C0C207 + W[65];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $EADA7DD6CDE0EB1E + W[66];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $F57D4F7FEE6ED178 + W[67];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $06F067AA72176FBA + W[68];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $0A637DC5A2C898A6 + W[69];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $113F9804BEF90DAE + W[70];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $1B710B35131C471B + W[71];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;
    t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g))
      + $28DB77F523047D84 + W[72];
    t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
    d := d + t1;
    h := t1 + t2;
    t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f))
      + $32CAAB7B40C72493 + W[73];
    t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
    c := c + t1;
    g := t1 + t2;
    t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e))
      + $3C9EBE0A15C9BEBC + W[74];
    t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
    b := b + t1;
    f := t1 + t2;
    t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d))
      + $431D67C49C100D4C + W[75];
    t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
    a := a + t1;
    e := t1 + t2;
    t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c))
      + $4CC5D4BECB3E42B6 + W[76];
    t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
    h := h + t1;
    d := t1 + t2;
    t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b))
      + $597F299CFC657E2A + W[77];
    t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
    g := g + t1;
    c := t1 + t2;
    t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a))
      + $5FCB6FAB3AD6FAEC + W[78];
    t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
    f := f + t1;
    b := t1 + t2;
    t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h))
      + $6C44198C4A475817 + W[79];
    t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
    e := e + t1;
    a := t1 + t2;

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

  procedure TncEnc_sha512base.Burn;
  begin
    LenHi := 0;
    LenLo := 0;
    Index := 0;
    FillChar(HashBuffer, Sizeof(HashBuffer), 0);
    FillChar(CurrentHash, Sizeof(CurrentHash), 0);
    fInitialized := false;
  end;

  procedure TncEnc_sha512base.Update(const Buffer; Size: longword);
  var
    PBuf: ^byte;
  begin
    if not fInitialized then
      raise EncEnc_hash.Create('Hash not initialized');

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

  { ****************************************************************************** }
  class function TncEnc_sha384.GetAlgorithm: string;
  begin
    Result := 'SHA384';
  end;

  class function TncEnc_sha384.GetHashSize: integer;
  begin
    Result := 384;
  end;

  class function TncEnc_sha384.SelfTest: boolean;
  const
    Test1Out: array [0 .. 47] of byte = ($CB, $00, $75, $3F, $45, $A3, $5E, $8B, $B5, $A0, $3D, $69, $9A, $C6, $50, $07, $27, $2C, $32, $AB, $0E, $DE, $D1,
      $63, $1A, $8B, $60, $5A, $43, $FF, $5B, $ED, $80, $86, $07, $2B, $A1, $E7, $CC, $23, $58, $BA, $EC, $A1, $34, $C8, $25, $A7);
    Test2Out: array [0 .. 47] of byte = ($09, $33, $0C, $33, $F7, $11, $47, $E8, $3D, $19, $2F, $C7, $82, $CD, $1B, $47, $53, $11, $1B, $17, $3B, $3B, $05,
      $D2, $2F, $A0, $80, $86, $E3, $B0, $F7, $12, $FC, $C7, $C7, $1A, $55, $7E, $2D, $B9, $66, $C3, $E9, $FA, $91, $74, $60, $39);
  var
    TestHash: TncEnc_sha384;
    TestOut: array [0 .. 47] of byte;
  begin
    TestHash := TncEnc_sha384.Create(nil);
    TestHash.Init;
    TestHash.UpdateStr('abc');
    TestHash.Final(TestOut);
    Result := boolean(CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out)));
    TestHash.Init;
    TestHash.UpdateStr('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu');
    TestHash.Final(TestOut);
    Result := boolean(CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out))) and Result;
    TestHash.Free;
  end;

  procedure TncEnc_sha384.Init;
  begin
    Burn;
    CurrentHash[0] := $CBBB9D5DC1059ED8;
    CurrentHash[1] := $629A292A367CD507;
    CurrentHash[2] := $9159015A3070DD17;
    CurrentHash[3] := $152FECD8F70E5939;
    CurrentHash[4] := $67332667FFC00B31;
    CurrentHash[5] := $8EB44A8768581511;
    CurrentHash[6] := $DB0C2E0D64F98FA7;
    CurrentHash[7] := $47B5481DBEFA4FA4;
    fInitialized := true;
  end;

  procedure TncEnc_sha384.Final(var Digest);
  begin
    if not fInitialized then
      raise EncEnc_hash.Create('Hash not initialized');
    HashBuffer[Index] := $80;
    if Index >= 112 then
      Compress;
    Pint64(@HashBuffer[112])^ := SwapDWord(LenHi);
    Pint64(@HashBuffer[120])^ := SwapDWord(LenLo);
    Compress;
    CurrentHash[0] := SwapDWord(CurrentHash[0]);
    CurrentHash[1] := SwapDWord(CurrentHash[1]);
    CurrentHash[2] := SwapDWord(CurrentHash[2]);
    CurrentHash[3] := SwapDWord(CurrentHash[3]);
    CurrentHash[4] := SwapDWord(CurrentHash[4]);
    CurrentHash[5] := SwapDWord(CurrentHash[5]);
    Move(CurrentHash, Digest, 384 div 8);
    Burn;
  end;

  { ****************************************************************************** }
  class function TncEnc_sha512.GetAlgorithm: string;
  begin
    Result := 'SHA512';
  end;

  class function TncEnc_sha512.GetHashSize: integer;
  begin
    Result := 512;
  end;

  class function TncEnc_sha512.SelfTest: boolean;
  const
    Test1Out: array [0 .. 63] of byte = ($DD, $AF, $35, $A1, $93, $61, $7A, $BA, $CC, $41, $73, $49, $AE, $20, $41, $31, $12, $E6, $FA, $4E, $89, $A9, $7E,
      $A2, $0A, $9E, $EE, $E6, $4B, $55, $D3, $9A, $21, $92, $99, $2A, $27, $4F, $C1, $A8, $36, $BA, $3C, $23, $A3, $FE, $EB, $BD, $45, $4D, $44, $23, $64,
      $3C, $E8, $0E, $2A, $9A, $C9, $4F, $A5, $4C, $A4, $9F);
    Test2Out: array [0 .. 63] of byte = ($8E, $95, $9B, $75, $DA, $E3, $13, $DA, $8C, $F4, $F7, $28, $14, $FC, $14, $3F, $8F, $77, $79, $C6, $EB, $9F, $7F,
      $A1, $72, $99, $AE, $AD, $B6, $88, $90, $18, $50, $1D, $28, $9E, $49, $00, $F7, $E4, $33, $1B, $99, $DE, $C4, $B5, $43, $3A, $C7, $D3, $29, $EE, $B6,
      $DD, $26, $54, $5E, $96, $E5, $5B, $87, $4B, $E9, $09);
  var
    TestHash: TncEnc_sha512;
    TestOut: array [0 .. 63] of byte;
  begin
    TestHash := TncEnc_sha512.Create(nil);
    TestHash.Init;
    TestHash.UpdateStr('abc');
    TestHash.Final(TestOut);
    Result := boolean(CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out)));
    TestHash.Init;
    TestHash.UpdateStr('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu');
    TestHash.Final(TestOut);
    Result := boolean(CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out))) and Result;
    TestHash.Free;
  end;

  procedure TncEnc_sha512.Init;
  begin
    Burn;
    CurrentHash[0] := $6A09E667F3BCC908;
    CurrentHash[1] := $BB67AE8584CAA73B;
    CurrentHash[2] := $3C6EF372FE94F82B;
    CurrentHash[3] := $A54FF53A5F1D36F1;
    CurrentHash[4] := $510E527FADE682D1;
    CurrentHash[5] := $9B05688C2B3E6C1F;
    CurrentHash[6] := $1F83D9ABFB41BD6B;
    CurrentHash[7] := $5BE0CD19137E2179;
    fInitialized := true;
  end;

  procedure TncEnc_sha512.Final(var Digest);
  begin
    if not fInitialized then
      raise EncEnc_hash.Create('Hash not initialized');
    HashBuffer[Index] := $80;
    if Index >= 112 then
      Compress;
    Pint64(@HashBuffer[112])^ := SwapDWord(LenHi);
    Pint64(@HashBuffer[120])^ := SwapDWord(LenLo);
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
