{$R-}
{$Q-}
{$WARN BOUNDS_ERROR OFF}
unit ncEncSha512;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
// 13 Dec 2010, 23/3/2024
//
// Written by Demos Bill
// VasDemos@yahoo.co.uk
//
// This portion of NetCom adapts DCPCrypt into the library,
// so that is does not depend on any DCP package the programmer may have installed.
// The reason is because if there is an error in any encryption/decryption class,
// That error should be maintained the same for any compilation of this library,
// that is for any client using it.
// To adapt DCPCrypt, a few changes had to be made:
// 1. cosmetic changes (underscores were removed)
// 2. performance changes
// - const parameters when applicable
// - inlined functions when necessary
// 3. bug fixes:
// - all ciphers do pointer walking arithmetic under only win32
// For example, in DCPblowfish.pas, line 209, 210, you would find:
// xL:= Pdword(@InData)^;
// xR:= Pdword(longword(@InData)+4)^;
// That would treat, wrongly, the address of @InData as a 32 bit unsigned int,
// so all this type of pointer arithmetic has been replaced with the proper:
// xL:= Pdword(@InData)^;
// xR:= Pdword(NativeUInt(@InData)+4)^;
// - All Pdword and dword references have been replaced with their appropriate
// intrinsic types.
//
// Bellow is tribute to David Barton for supplying such a gem to the software community:
//
{ ****************************************************************************** }
{ * Copyright (c) 1999-2002 David Barton                                       * }
{ * Permission is hereby granted, free of charge, to any person obtaining a    * }
{ * copy of this software and associated documentation files (the "Software"), * }
{ * to deal in the Software without restriction, including without limitation  * }
{ * the rights to use, copy, modify, merge, publish, distribute, sublicense,   * }
{ * and/or sell copies of the Software, and to permit persons to whom the      * }
{ * Software is furnished to do so, subject to the following conditions:       * }
{ *                                                                            * }
{ * The above copyright notice and this permission notice shall be included in * }
{ * all copies or substantial portions of the Software.                        * }
{ *                                                                            * }
{ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR * }
{ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   * }
{ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    * }
{ * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER * }
{ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING    * }
{ * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER        * }
{ * DEALINGS IN THE SOFTWARE.                                                  * }
{ ****************************************************************************** }
//
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
  TncEnc_sha512base = class(TncEncHash)
  protected
    LenHi, LenLo: UInt64;
    Index: UInt64;
    CurrentHash: array [0 .. 7] of UInt64;
    HashBuffer: array [0 .. 127] of byte;
    procedure Compress;
  public
    procedure Update(const aBuffer; aSize: NativeUInt); override;
    procedure Burn; override;
  end;

  TncEnc_sha384 = class(TncEnc_sha512base)
  public
    class function GetAlgorithm: string; override;
    class function GetHashSize: Integer; override;
    class function SelfTest: Boolean; override;
    procedure Init; override;
    procedure Final(var Digest); override;
  end;

  TncEnc_sha512 = class(TncEnc_sha512base)
  public
    class function GetAlgorithm: string; override;
    class function GetHashSize: Integer; override;
    class function SelfTest: Boolean; override;
    procedure Init; override;
    procedure Final(var Digest); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

function SwapUInt64(const a: UInt64): UInt64; inline;
begin
  Result := ((a and $FF) shl 56) or ((a and $FF00) shl 40) or ((a and $FF0000) shl 24) or ((a and $FF000000) shl 8) or ((a and $FF00000000) shr 8) or ((a and $FF0000000000) shr 24) or ((a and $FF000000000000) shr 40) or ((a and $FF00000000000000) shr 56);
end;

procedure TncEnc_sha512base.Compress;
var
  a, b, c, d, e, f, g, h, t1, t2: UInt64;
  W: array [0 .. 79] of UInt64;
  i: Integer;
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
    W[i] := SwapUInt64(W[i]);
  for i := 16 to 79 do
    W[i] := (((W[i - 2] shr 19) or (W[i - 2] shl 45)) xor ((W[i - 2] shr 61) or (W[i - 2] shl 3)) xor (W[i - 2] shr 6)) + W[i - 7] + (((W[i - 15] shr 1) or (W[i - 15] shl 63)) xor ((W[i - 15] shr 8) or (W[i - 15] shl 56)) xor (W[i - 15] shr 7)) + W[i - 16];

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

  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($428A2F98D728AE22) + W[0];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($7137449123EF65CD) + W[1];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($B5C0FBCFEC4D3B2F) + W[2];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($E9B5DBA58189DBBC) + W[3];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($3956C25BF348B538) + W[4];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($59F111F1B605D019) + W[5];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($923F82A4AF194F9B) + W[6];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($AB1C5ED5DA6D8118) + W[7];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($D807AA98A3030242) + W[8];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($12835B0145706FBE) + W[9];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($243185BE4EE4B28C) + W[10];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($550C7DC3D5FFB4E2) + W[11];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($72BE5D74F27B896F) + W[12];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($80DEB1FE3B1696B1) + W[13];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($9BDC06A725C71235) + W[14];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($C19BF174CF692694) + W[15];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($E49B69C19EF14AD2) + W[16];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($EFBE4786384F25E3) + W[17];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($0FC19DC68B8CD5B5) + W[18];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($240CA1CC77AC9C65) + W[19];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($2DE92C6F592B0275) + W[20];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($4A7484AA6EA6E483) + W[21];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($5CB0A9DCBD41FBD4) + W[22];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($76F988DA831153B5) + W[23];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($983E5152EE66DFAB) + W[24];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($A831C66D2DB43210) + W[25];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($B00327C898FB213F) + W[26];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($BF597FC7BEEF0EE4) + W[27];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($C6E00BF33DA88FC2) + W[28];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($D5A79147930AA725) + W[29];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($06CA6351E003826F) + W[30];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($142929670A0E6E70) + W[31];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($27B70A8546D22FFC) + W[32];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($2E1B21385C26C926) + W[33];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($4D2C6DFC5AC42AED) + W[34];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($53380D139D95B3DF) + W[35];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($650A73548BAF63DE) + W[36];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($766A0ABB3C77B2A8) + W[37];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($81C2C92E47EDAEE6) + W[38];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($92722C851482353B) + W[39];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($A2BFE8A14CF10364) + W[40];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($A81A664BBC423001) + W[41];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($C24B8B70D0F89791) + W[42];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($C76C51A30654BE30) + W[43];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($D192E819D6EF5218) + W[44];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($D69906245565A910) + W[45];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($F40E35855771202A) + W[46];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($106AA07032BBD1B8) + W[47];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($19A4C116B8D2D0C8) + W[48];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($1E376C085141AB53) + W[49];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($2748774CDF8EEB99) + W[50];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($34B0BCB5E19B48A8) + W[51];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($391C0CB3C5C95A63) + W[52];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($4ED8AA4AE3418ACB) + W[53];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($5B9CCA4F7763E373) + W[54];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($682E6FF3D6B2B8A3) + W[55];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($748F82EE5DEFB2FC) + W[56];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($78A5636F43172F60) + W[57];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($84C87814A1F0AB72) + W[58];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($8CC702081A6439EC) + W[59];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($90BEFFFA23631E28) + W[60];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($A4506CEBDE82BDE9) + W[61];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($BEF9A3F7B2C67915) + W[62];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($C67178F2E372532B) + W[63];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($CA273ECEEA26619C) + W[64];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($D186B8C721C0C207) + W[65];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($EADA7DD6CDE0EB1E) + W[66];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($F57D4F7FEE6ED178) + W[67];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($06F067AA72176FBA) + W[68];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($0A637DC5A2C898A6) + W[69];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($113F9804BEF90DAE) + W[70];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($1B710B35131C471B) + W[71];
  t2 := (((b shr 28) or (b shl 36)) xor ((b shr 34) or (b shl 30)) xor ((b shr 39) or (b shl 25))) + ((b and c) xor (b and d) xor (c and d));
  e := e + t1;
  a := t1 + t2;
  t1 := h + (((e shr 14) or (e shl 50)) xor ((e shr 18) or (e shl 46)) xor ((e shr 41) or (e shl 23))) + ((e and f) xor (not e and g)) + UInt64($28DB77F523047D84) + W[72];
  t2 := (((a shr 28) or (a shl 36)) xor ((a shr 34) or (a shl 30)) xor ((a shr 39) or (a shl 25))) + ((a and b) xor (a and c) xor (b and c));
  d := d + t1;
  h := t1 + t2;
  t1 := g + (((d shr 14) or (d shl 50)) xor ((d shr 18) or (d shl 46)) xor ((d shr 41) or (d shl 23))) + ((d and e) xor (not d and f)) + UInt64($32CAAB7B40C72493) + W[73];
  t2 := (((h shr 28) or (h shl 36)) xor ((h shr 34) or (h shl 30)) xor ((h shr 39) or (h shl 25))) + ((h and a) xor (h and b) xor (a and b));
  c := c + t1;
  g := t1 + t2;
  t1 := f + (((c shr 14) or (c shl 50)) xor ((c shr 18) or (c shl 46)) xor ((c shr 41) or (c shl 23))) + ((c and d) xor (not c and e)) + UInt64($3C9EBE0A15C9BEBC) + W[74];
  t2 := (((g shr 28) or (g shl 36)) xor ((g shr 34) or (g shl 30)) xor ((g shr 39) or (g shl 25))) + ((g and h) xor (g and a) xor (h and a));
  b := b + t1;
  f := t1 + t2;
  t1 := e + (((b shr 14) or (b shl 50)) xor ((b shr 18) or (b shl 46)) xor ((b shr 41) or (b shl 23))) + ((b and c) xor (not b and d)) + UInt64($431D67C49C100D4C) + W[75];
  t2 := (((f shr 28) or (f shl 36)) xor ((f shr 34) or (f shl 30)) xor ((f shr 39) or (f shl 25))) + ((f and g) xor (f and h) xor (g and h));
  a := a + t1;
  e := t1 + t2;
  t1 := d + (((a shr 14) or (a shl 50)) xor ((a shr 18) or (a shl 46)) xor ((a shr 41) or (a shl 23))) + ((a and b) xor (not a and c)) + UInt64($4CC5D4BECB3E42B6) + W[76];
  t2 := (((e shr 28) or (e shl 36)) xor ((e shr 34) or (e shl 30)) xor ((e shr 39) or (e shl 25))) + ((e and f) xor (e and g) xor (f and g));
  h := h + t1;
  d := t1 + t2;
  t1 := c + (((h shr 14) or (h shl 50)) xor ((h shr 18) or (h shl 46)) xor ((h shr 41) or (h shl 23))) + ((h and a) xor (not h and b)) + UInt64($597F299CFC657E2A) + W[77];
  t2 := (((d shr 28) or (d shl 36)) xor ((d shr 34) or (d shl 30)) xor ((d shr 39) or (d shl 25))) + ((d and e) xor (d and f) xor (e and f));
  g := g + t1;
  c := t1 + t2;
  t1 := b + (((g shr 14) or (g shl 50)) xor ((g shr 18) or (g shl 46)) xor ((g shr 41) or (g shl 23))) + ((g and h) xor (not g and a)) + UInt64($5FCB6FAB3AD6FAEC) + W[78];
  t2 := (((c shr 28) or (c shl 36)) xor ((c shr 34) or (c shl 30)) xor ((c shr 39) or (c shl 25))) + ((c and d) xor (c and e) xor (d and e));
  f := f + t1;
  b := t1 + t2;
  t1 := a + (((f shr 14) or (f shl 50)) xor ((f shr 18) or (f shl 46)) xor ((f shr 41) or (f shl 23))) + ((f and g) xor (not f and h)) + UInt64($6C44198C4A475817) + W[79];
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
  FInitialized := false;
end;

procedure TncEnc_sha512base.Update(const aBuffer; aSize: NativeUInt);
var
  PBuf: ^byte;
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

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

{ ****************************************************************************** }
class function TncEnc_sha384.GetAlgorithm: string;
begin
  Result := 'SHA384';
end;

class function TncEnc_sha384.GetHashSize: Integer;
begin
  Result := 384;
end;

class function TncEnc_sha384.SelfTest: Boolean;
const
  Test1Out: array [0 .. 47] of byte = ($CB, $00, $75, $3F, $45, $A3, $5E, $8B, $B5, $A0, $3D, $69, $9A, $C6, $50, $07, $27, $2C, $32, $AB, $0E, $DE, $D1, $63, $1A, $8B, $60, $5A, $43, $FF, $5B, $ED, $80, $86, $07, $2B, $A1, $E7, $CC, $23, $58, $BA, $EC, $A1, $34, $C8, $25, $A7);
  Test2Out: array [0 .. 47] of byte = ($09, $33, $0C, $33, $F7, $11, $47, $E8, $3D, $19, $2F, $C7, $82, $CD, $1B, $47, $53, $11, $1B, $17, $3B, $3B, $05, $D2, $2F, $A0, $80, $86, $E3, $B0, $F7, $12, $FC, $C7, $C7, $1A, $55, $7E, $2D, $B9, $66, $C3, $E9, $FA, $91, $74, $60, $39);
var
  TestHash: TncEnc_sha384;
  TestOut: array [0 .. 47] of byte;
begin
  TestHash := TncEnc_sha384.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abc');
  TestHash.Final(TestOut);
  Result := Boolean(CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out)));
  TestHash.Init;
  TestHash.UpdateStr('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu');
  TestHash.Final(TestOut);
  Result := Boolean(CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out))) and Result;
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
  FInitialized := true;
end;

procedure TncEnc_sha384.Final(var Digest);
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  HashBuffer[Index] := $80;
  if Index >= 112 then
    Compress;
  PUInt64(@HashBuffer[112])^ := SwapUInt64(LenHi);
  PUInt64(@HashBuffer[120])^ := SwapUInt64(LenLo);
  Compress;
  CurrentHash[0] := SwapUInt64(CurrentHash[0]);
  CurrentHash[1] := SwapUInt64(CurrentHash[1]);
  CurrentHash[2] := SwapUInt64(CurrentHash[2]);
  CurrentHash[3] := SwapUInt64(CurrentHash[3]);
  CurrentHash[4] := SwapUInt64(CurrentHash[4]);
  CurrentHash[5] := SwapUInt64(CurrentHash[5]);
  Move(CurrentHash, Digest, 384 div 8);
  Burn;
end;

{ ****************************************************************************** }
class function TncEnc_sha512.GetAlgorithm: string;
begin
  Result := 'SHA512';
end;

class function TncEnc_sha512.GetHashSize: Integer;
begin
  Result := 512;
end;

class function TncEnc_sha512.SelfTest: Boolean;
const
  Test1Out: array [0 .. 63] of byte = ($DD, $AF, $35, $A1, $93, $61, $7A, $BA, $CC, $41, $73, $49, $AE, $20, $41, $31, $12, $E6, $FA, $4E, $89, $A9, $7E, $A2, $0A, $9E, $EE, $E6, $4B, $55, $D3, $9A, $21, $92, $99, $2A, $27, $4F, $C1, $A8, $36, $BA, $3C, $23, $A3, $FE, $EB, $BD, $45, $4D, $44, $23, $64, $3C, $E8, $0E,
    $2A, $9A, $C9, $4F, $A5, $4C, $A4, $9F);
  Test2Out: array [0 .. 63] of byte = ($8E, $95, $9B, $75, $DA, $E3, $13, $DA, $8C, $F4, $F7, $28, $14, $FC, $14, $3F, $8F, $77, $79, $C6, $EB, $9F, $7F, $A1, $72, $99, $AE, $AD, $B6, $88, $90, $18, $50, $1D, $28, $9E, $49, $00, $F7, $E4, $33, $1B, $99, $DE, $C4, $B5, $43, $3A, $C7, $D3, $29, $EE, $B6, $DD, $26, $54,
    $5E, $96, $E5, $5B, $87, $4B, $E9, $09);
var
  TestHash: TncEnc_sha512;
  TestOut: array [0 .. 63] of byte;
begin
  TestHash := TncEnc_sha512.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abc');
  TestHash.Final(TestOut);
  Result := Boolean(CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out)));
  TestHash.Init;
  TestHash.UpdateStr('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu');
  TestHash.Final(TestOut);
  Result := Boolean(CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out))) and Result;
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
  FInitialized := true;
end;

procedure TncEnc_sha512.Final(var Digest);
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  HashBuffer[Index] := $80;
  if Index >= 112 then
    Compress;
  PUInt64(@HashBuffer[112])^ := SwapUInt64(LenHi);
  PUInt64(@HashBuffer[120])^ := SwapUInt64(LenLo);
  Compress;
  CurrentHash[0] := SwapUInt64(CurrentHash[0]);
  CurrentHash[1] := SwapUInt64(CurrentHash[1]);
  CurrentHash[2] := SwapUInt64(CurrentHash[2]);
  CurrentHash[3] := SwapUInt64(CurrentHash[3]);
  CurrentHash[4] := SwapUInt64(CurrentHash[4]);
  CurrentHash[5] := SwapUInt64(CurrentHash[5]);
  CurrentHash[6] := SwapUInt64(CurrentHash[6]);
  CurrentHash[7] := SwapUInt64(CurrentHash[7]);
  Move(CurrentHash, Digest, Sizeof(CurrentHash));
  Burn;
end;

end.
