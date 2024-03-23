{$R-}
{$Q-}
unit ncEncHaval;

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
// - all cyphers do pointer walking arithmetic under only win32
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
  TncEnc_haval = class(TncEncHash)
  protected
    LenHi, LenLo: UInt32;
    Index: UInt32;
    CurrentHash: array [0 .. 7] of UInt32;
    HashBuffer: array [0 .. 127] of Byte;
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

  { Choose how many passes (previous versions of ncEnccrypt uses 5 passes) }
  { ONLY UNCOMMENT ONE! }
  // {$DEFINE PASS3}
  // {$DEFINE PASS4}
{$DEFINE PASS5}
  { Choose digest length (previous versions of ncEnccrypt uses 256bits) }
  { ONLY UNCOMMENT ONE! }
  // {$DEFINE DIGEST128}
  // {$DEFINE DIGEST160}
  // {$DEFINE DIGEST192}
  // {$DEFINE DIGEST224}
{$DEFINE DIGEST256}

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

procedure TncEnc_haval.Compress;
var
  t7, t6, t5, t4, t3, t2, t1, t0: UInt32;
  W: array [0 .. 31] of UInt32;
  Temp: UInt32;
begin
  t0 := CurrentHash[0];
  t1 := CurrentHash[1];
  t2 := CurrentHash[2];
  t3 := CurrentHash[3];
  t4 := CurrentHash[4];
  t5 := CurrentHash[5];
  t6 := CurrentHash[6];
  t7 := CurrentHash[7];
  Move(HashBuffer, W, Sizeof(W));
{$IFDEF PASS3}
  Temp := (t2 and (t4 xor t3) xor t6 and t0 xor t5 and t1 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[0];
  Temp := (t1 and (t3 xor t2) xor t5 and t7 xor t4 and t0 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[1];
  Temp := (t0 and (t2 xor t1) xor t4 and t6 xor t3 and t7 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[2];
  Temp := (t7 and (t1 xor t0) xor t3 and t5 xor t2 and t6 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[3];
  Temp := (t6 and (t0 xor t7) xor t2 and t4 xor t1 and t5 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[4];
  Temp := (t5 and (t7 xor t6) xor t1 and t3 xor t0 and t4 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[5];
  Temp := (t4 and (t6 xor t5) xor t0 and t2 xor t7 and t3 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[6];
  Temp := (t3 and (t5 xor t4) xor t7 and t1 xor t6 and t2 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[7];

  Temp := (t2 and (t4 xor t3) xor t6 and t0 xor t5 and t1 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[8];
  Temp := (t1 and (t3 xor t2) xor t5 and t7 xor t4 and t0 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9];
  Temp := (t0 and (t2 xor t1) xor t4 and t6 xor t3 and t7 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[10];
  Temp := (t7 and (t1 xor t0) xor t3 and t5 xor t2 and t6 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[11];
  Temp := (t6 and (t0 xor t7) xor t2 and t4 xor t1 and t5 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[12];
  Temp := (t5 and (t7 xor t6) xor t1 and t3 xor t0 and t4 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[13];
  Temp := (t4 and (t6 xor t5) xor t0 and t2 xor t7 and t3 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[14];
  Temp := (t3 and (t5 xor t4) xor t7 and t1 xor t6 and t2 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[15];

  Temp := (t2 and (t4 xor t3) xor t6 and t0 xor t5 and t1 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[16];
  Temp := (t1 and (t3 xor t2) xor t5 and t7 xor t4 and t0 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[17];
  Temp := (t0 and (t2 xor t1) xor t4 and t6 xor t3 and t7 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[18];
  Temp := (t7 and (t1 xor t0) xor t3 and t5 xor t2 and t6 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[19];
  Temp := (t6 and (t0 xor t7) xor t2 and t4 xor t1 and t5 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[20];
  Temp := (t5 and (t7 xor t6) xor t1 and t3 xor t0 and t4 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[21];
  Temp := (t4 and (t6 xor t5) xor t0 and t2 xor t7 and t3 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[22];
  Temp := (t3 and (t5 xor t4) xor t7 and t1 xor t6 and t2 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[23];

  Temp := (t2 and (t4 xor t3) xor t6 and t0 xor t5 and t1 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[24];
  Temp := (t1 and (t3 xor t2) xor t5 and t7 xor t4 and t0 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[25];
  Temp := (t0 and (t2 xor t1) xor t4 and t6 xor t3 and t7 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[26];
  Temp := (t7 and (t1 xor t0) xor t3 and t5 xor t2 and t6 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[27];
  Temp := (t6 and (t0 xor t7) xor t2 and t4 xor t1 and t5 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[28];
  Temp := (t5 and (t7 xor t6) xor t1 and t3 xor t0 and t4 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[29];
  Temp := (t4 and (t6 xor t5) xor t0 and t2 xor t7 and t3 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[30];
  Temp := (t3 and (t5 xor t4) xor t7 and t1 xor t6 and t2 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[31];

  Temp := (t5 and (t3 and not t0 xor t1 and t2 xor t4 xor t6) xor t1 and (t3 xor t2) xor t0 and t2 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[5] + $452821E6;
  Temp := (t4 and (t2 and not t7 xor t0 and t1 xor t3 xor t5) xor t0 and (t2 xor t1) xor t7 and t1 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[14] + $38D01377;
  Temp := (t3 and (t1 and not t6 xor t7 and t0 xor t2 xor t4) xor t7 and (t1 xor t0) xor t6 and t0 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[26] + $BE5466CF;
  Temp := (t2 and (t0 and not t5 xor t6 and t7 xor t1 xor t3) xor t6 and (t0 xor t7) xor t5 and t7 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[18] + $34E90C6C;
  Temp := (t1 and (t7 and not t4 xor t5 and t6 xor t0 xor t2) xor t5 and (t7 xor t6) xor t4 and t6 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[11] + $C0AC29B7;
  Temp := (t0 and (t6 and not t3 xor t4 and t5 xor t7 xor t1) xor t4 and (t6 xor t5) xor t3 and t5 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[28] + $C97C50DD;
  Temp := (t7 and (t5 and not t2 xor t3 and t4 xor t6 xor t0) xor t3 and (t5 xor t4) xor t2 and t4 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[7] + $3F84D5B5;
  Temp := (t6 and (t4 and not t1 xor t2 and t3 xor t5 xor t7) xor t2 and (t4 xor t3) xor t1 and t3 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[16] + $B5470917;

  Temp := (t5 and (t3 and not t0 xor t1 and t2 xor t4 xor t6) xor t1 and (t3 xor t2) xor t0 and t2 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[0] + $9216D5D9;
  Temp := (t4 and (t2 and not t7 xor t0 and t1 xor t3 xor t5) xor t0 and (t2 xor t1) xor t7 and t1 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[23] + $8979FB1B;
  Temp := (t3 and (t1 and not t6 xor t7 and t0 xor t2 xor t4) xor t7 and (t1 xor t0) xor t6 and t0 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[20] + $D1310BA6;
  Temp := (t2 and (t0 and not t5 xor t6 and t7 xor t1 xor t3) xor t6 and (t0 xor t7) xor t5 and t7 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[22] + $98DFB5AC;
  Temp := (t1 and (t7 and not t4 xor t5 and t6 xor t0 xor t2) xor t5 and (t7 xor t6) xor t4 and t6 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[1] + $2FFD72DB;
  Temp := (t0 and (t6 and not t3 xor t4 and t5 xor t7 xor t1) xor t4 and (t6 xor t5) xor t3 and t5 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[10] + $D01ADFB7;
  Temp := (t7 and (t5 and not t2 xor t3 and t4 xor t6 xor t0) xor t3 and (t5 xor t4) xor t2 and t4 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[4] + $B8E1AFED;
  Temp := (t6 and (t4 and not t1 xor t2 and t3 xor t5 xor t7) xor t2 and (t4 xor t3) xor t1 and t3 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[8] + $6A267E96;

  Temp := (t5 and (t3 and not t0 xor t1 and t2 xor t4 xor t6) xor t1 and (t3 xor t2) xor t0 and t2 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[30] + $BA7C9045;
  Temp := (t4 and (t2 and not t7 xor t0 and t1 xor t3 xor t5) xor t0 and (t2 xor t1) xor t7 and t1 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[3] + $F12C7F99;
  Temp := (t3 and (t1 and not t6 xor t7 and t0 xor t2 xor t4) xor t7 and (t1 xor t0) xor t6 and t0 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $24A19947;
  Temp := (t2 and (t0 and not t5 xor t6 and t7 xor t1 xor t3) xor t6 and (t0 xor t7) xor t5 and t7 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[9] + $B3916CF7;
  Temp := (t1 and (t7 and not t4 xor t5 and t6 xor t0 xor t2) xor t5 and (t7 xor t6) xor t4 and t6 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[17] + $0801F2E2;
  Temp := (t0 and (t6 and not t3 xor t4 and t5 xor t7 xor t1) xor t4 and (t6 xor t5) xor t3 and t5 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[24] + $858EFC16;
  Temp := (t7 and (t5 and not t2 xor t3 and t4 xor t6 xor t0) xor t3 and (t5 xor t4) xor t2 and t4 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[29] + $636920D8;
  Temp := (t6 and (t4 and not t1 xor t2 and t3 xor t5 xor t7) xor t2 and (t4 xor t3) xor t1 and t3 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[6] + $71574E69;

  Temp := (t5 and (t3 and not t0 xor t1 and t2 xor t4 xor t6) xor t1 and (t3 xor t2) xor t0 and t2 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $A458FEA3;
  Temp := (t4 and (t2 and not t7 xor t0 and t1 xor t3 xor t5) xor t0 and (t2 xor t1) xor t7 and t1 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[12] + $F4933D7E;
  Temp := (t3 and (t1 and not t6 xor t7 and t0 xor t2 xor t4) xor t7 and (t1 xor t0) xor t6 and t0 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[15] + $0D95748F;
  Temp := (t2 and (t0 and not t5 xor t6 and t7 xor t1 xor t3) xor t6 and (t0 xor t7) xor t5 and t7 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[13] + $728EB658;
  Temp := (t1 and (t7 and not t4 xor t5 and t6 xor t0 xor t2) xor t5 and (t7 xor t6) xor t4 and t6 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[2] + $718BCD58;
  Temp := (t0 and (t6 and not t3 xor t4 and t5 xor t7 xor t1) xor t4 and (t6 xor t5) xor t3 and t5 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[25] + $82154AEE;
  Temp := (t7 and (t5 and not t2 xor t3 and t4 xor t6 xor t0) xor t3 and (t5 xor t4) xor t2 and t4 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[31] + $7B54A41D;
  Temp := (t6 and (t4 and not t1 xor t2 and t3 xor t5 xor t7) xor t2 and (t4 xor t3) xor t1 and t3 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[27] + $C25A59B5;

  Temp := (t3 and (t5 and t4 xor t6 xor t0) xor t5 and t2 xor t4 and t1 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $9C30D539;
  Temp := (t2 and (t4 and t3 xor t5 xor t7) xor t4 and t1 xor t3 and t0 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9] + $2AF26013;
  Temp := (t1 and (t3 and t2 xor t4 xor t6) xor t3 and t0 xor t2 and t7 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[4] + $C5D1B023;
  Temp := (t0 and (t2 and t1 xor t3 xor t5) xor t2 and t7 xor t1 and t6 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[20] + $286085F0;
  Temp := (t7 and (t1 and t0 xor t2 xor t4) xor t1 and t6 xor t0 and t5 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[28] + $CA417918;
  Temp := (t6 and (t0 and t7 xor t1 xor t3) xor t0 and t5 xor t7 and t4 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[17] + $B8DB38EF;
  Temp := (t5 and (t7 and t6 xor t0 xor t2) xor t7 and t4 xor t6 and t3 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[8] + $8E79DCB0;
  Temp := (t4 and (t6 and t5 xor t7 xor t1) xor t6 and t3 xor t5 and t2 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[22] + $603A180E;

  Temp := (t3 and (t5 and t4 xor t6 xor t0) xor t5 and t2 xor t4 and t1 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[29] + $6C9E0E8B;
  Temp := (t2 and (t4 and t3 xor t5 xor t7) xor t4 and t1 xor t3 and t0 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[14] + $B01E8A3E;
  Temp := (t1 and (t3 and t2 xor t4 xor t6) xor t3 and t0 xor t2 and t7 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[25] + $D71577C1;
  Temp := (t0 and (t2 and t1 xor t3 xor t5) xor t2 and t7 xor t1 and t6 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[12] + $BD314B27;
  Temp := (t7 and (t1 and t0 xor t2 xor t4) xor t1 and t6 xor t0 and t5 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[24] + $78AF2FDA;
  Temp := (t6 and (t0 and t7 xor t1 xor t3) xor t0 and t5 xor t7 and t4 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[30] + $55605C60;
  Temp := (t5 and (t7 and t6 xor t0 xor t2) xor t7 and t4 xor t6 and t3 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[16] + $E65525F3;
  Temp := (t4 and (t6 and t5 xor t7 xor t1) xor t6 and t3 xor t5 and t2 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[26] + $AA55AB94;

  Temp := (t3 and (t5 and t4 xor t6 xor t0) xor t5 and t2 xor t4 and t1 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[31] + $57489862;
  Temp := (t2 and (t4 and t3 xor t5 xor t7) xor t4 and t1 xor t3 and t0 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[15] + $63E81440;
  Temp := (t1 and (t3 and t2 xor t4 xor t6) xor t3 and t0 xor t2 and t7 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[7] + $55CA396A;
  Temp := (t0 and (t2 and t1 xor t3 xor t5) xor t2 and t7 xor t1 and t6 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[3] + $2AAB10B6;
  Temp := (t7 and (t1 and t0 xor t2 xor t4) xor t1 and t6 xor t0 and t5 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[1] + $B4CC5C34;
  Temp := (t6 and (t0 and t7 xor t1 xor t3) xor t0 and t5 xor t7 and t4 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[0] + $1141E8CE;
  Temp := (t5 and (t7 and t6 xor t0 xor t2) xor t7 and t4 xor t6 and t3 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[18] + $A15486AF;
  Temp := (t4 and (t6 and t5 xor t7 xor t1) xor t6 and t3 xor t5 and t2 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[27] + $7C72E993;

  Temp := (t3 and (t5 and t4 xor t6 xor t0) xor t5 and t2 xor t4 and t1 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[13] + $B3EE1411;
  Temp := (t2 and (t4 and t3 xor t5 xor t7) xor t4 and t1 xor t3 and t0 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[6] + $636FBC2A;
  Temp := (t1 and (t3 and t2 xor t4 xor t6) xor t3 and t0 xor t2 and t7 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $2BA9C55D;
  Temp := (t0 and (t2 and t1 xor t3 xor t5) xor t2 and t7 xor t1 and t6 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[10] + $741831F6;
  Temp := (t7 and (t1 and t0 xor t2 xor t4) xor t1 and t6 xor t0 and t5 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[23] + $CE5C3E16;
  Temp := (t6 and (t0 and t7 xor t1 xor t3) xor t0 and t5 xor t7 and t4 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[11] + $9B87931E;
  Temp := (t5 and (t7 and t6 xor t0 xor t2) xor t7 and t4 xor t6 and t3 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[5] + $AFD6BA33;
  Temp := (t4 and (t6 and t5 xor t7 xor t1) xor t6 and t3 xor t5 and t2 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[2] + $6C24CF5C;
{$ELSE}
{$IFDEF PASS4}
  Temp := (t3 and (t0 xor t1) xor t5 and t6 xor t4 and t2 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[0];
  Temp := (t2 and (t7 xor t0) xor t4 and t5 xor t3 and t1 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[1];
  Temp := (t1 and (t6 xor t7) xor t3 and t4 xor t2 and t0 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[2];
  Temp := (t0 and (t5 xor t6) xor t2 and t3 xor t1 and t7 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[3];
  Temp := (t7 and (t4 xor t5) xor t1 and t2 xor t0 and t6 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[4];
  Temp := (t6 and (t3 xor t4) xor t0 and t1 xor t7 and t5 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[5];
  Temp := (t5 and (t2 xor t3) xor t7 and t0 xor t6 and t4 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[6];
  Temp := (t4 and (t1 xor t2) xor t6 and t7 xor t5 and t3 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[7];

  Temp := (t3 and (t0 xor t1) xor t5 and t6 xor t4 and t2 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[8];
  Temp := (t2 and (t7 xor t0) xor t4 and t5 xor t3 and t1 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9];
  Temp := (t1 and (t6 xor t7) xor t3 and t4 xor t2 and t0 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[10];
  Temp := (t0 and (t5 xor t6) xor t2 and t3 xor t1 and t7 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[11];
  Temp := (t7 and (t4 xor t5) xor t1 and t2 xor t0 and t6 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[12];
  Temp := (t6 and (t3 xor t4) xor t0 and t1 xor t7 and t5 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[13];
  Temp := (t5 and (t2 xor t3) xor t7 and t0 xor t6 and t4 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[14];
  Temp := (t4 and (t1 xor t2) xor t6 and t7 xor t5 and t3 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[15];

  Temp := (t3 and (t0 xor t1) xor t5 and t6 xor t4 and t2 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[16];
  Temp := (t2 and (t7 xor t0) xor t4 and t5 xor t3 and t1 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[17];
  Temp := (t1 and (t6 xor t7) xor t3 and t4 xor t2 and t0 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[18];
  Temp := (t0 and (t5 xor t6) xor t2 and t3 xor t1 and t7 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[19];
  Temp := (t7 and (t4 xor t5) xor t1 and t2 xor t0 and t6 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[20];
  Temp := (t6 and (t3 xor t4) xor t0 and t1 xor t7 and t5 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[21];
  Temp := (t5 and (t2 xor t3) xor t7 and t0 xor t6 and t4 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[22];
  Temp := (t4 and (t1 xor t2) xor t6 and t7 xor t5 and t3 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[23];

  Temp := (t3 and (t0 xor t1) xor t5 and t6 xor t4 and t2 xor t0);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[24];
  Temp := (t2 and (t7 xor t0) xor t4 and t5 xor t3 and t1 xor t7);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[25];
  Temp := (t1 and (t6 xor t7) xor t3 and t4 xor t2 and t0 xor t6);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[26];
  Temp := (t0 and (t5 xor t6) xor t2 and t3 xor t1 and t7 xor t5);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[27];
  Temp := (t7 and (t4 xor t5) xor t1 and t2 xor t0 and t6 xor t4);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[28];
  Temp := (t6 and (t3 xor t4) xor t0 and t1 xor t7 and t5 xor t3);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[29];
  Temp := (t5 and (t2 xor t3) xor t7 and t0 xor t6 and t4 xor t2);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[30];
  Temp := (t4 and (t1 xor t2) xor t6 and t7 xor t5 and t3 xor t1);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[31];

  Temp := (t1 and (t6 and not t0 xor t2 and t5 xor t3 xor t4) xor t2 and (t6 xor t5) xor t0 and t5 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[5] + $452821E6;
  Temp := (t0 and (t5 and not t7 xor t1 and t4 xor t2 xor t3) xor t1 and (t5 xor t4) xor t7 and t4 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[14] + $38D01377;
  Temp := (t7 and (t4 and not t6 xor t0 and t3 xor t1 xor t2) xor t0 and (t4 xor t3) xor t6 and t3 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[26] + $BE5466CF;
  Temp := (t6 and (t3 and not t5 xor t7 and t2 xor t0 xor t1) xor t7 and (t3 xor t2) xor t5 and t2 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[18] + $34E90C6C;
  Temp := (t5 and (t2 and not t4 xor t6 and t1 xor t7 xor t0) xor t6 and (t2 xor t1) xor t4 and t1 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[11] + $C0AC29B7;
  Temp := (t4 and (t1 and not t3 xor t5 and t0 xor t6 xor t7) xor t5 and (t1 xor t0) xor t3 and t0 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[28] + $C97C50DD;
  Temp := (t3 and (t0 and not t2 xor t4 and t7 xor t5 xor t6) xor t4 and (t0 xor t7) xor t2 and t7 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[7] + $3F84D5B5;
  Temp := (t2 and (t7 and not t1 xor t3 and t6 xor t4 xor t5) xor t3 and (t7 xor t6) xor t1 and t6 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[16] + $B5470917;

  Temp := (t1 and (t6 and not t0 xor t2 and t5 xor t3 xor t4) xor t2 and (t6 xor t5) xor t0 and t5 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[0] + $9216D5D9;
  Temp := (t0 and (t5 and not t7 xor t1 and t4 xor t2 xor t3) xor t1 and (t5 xor t4) xor t7 and t4 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[23] + $8979FB1B;
  Temp := (t7 and (t4 and not t6 xor t0 and t3 xor t1 xor t2) xor t0 and (t4 xor t3) xor t6 and t3 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[20] + $D1310BA6;
  Temp := (t6 and (t3 and not t5 xor t7 and t2 xor t0 xor t1) xor t7 and (t3 xor t2) xor t5 and t2 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[22] + $98DFB5AC;
  Temp := (t5 and (t2 and not t4 xor t6 and t1 xor t7 xor t0) xor t6 and (t2 xor t1) xor t4 and t1 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[1] + $2FFD72DB;
  Temp := (t4 and (t1 and not t3 xor t5 and t0 xor t6 xor t7) xor t5 and (t1 xor t0) xor t3 and t0 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[10] + $D01ADFB7;
  Temp := (t3 and (t0 and not t2 xor t4 and t7 xor t5 xor t6) xor t4 and (t0 xor t7) xor t2 and t7 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[4] + $B8E1AFED;
  Temp := (t2 and (t7 and not t1 xor t3 and t6 xor t4 xor t5) xor t3 and (t7 xor t6) xor t1 and t6 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[8] + $6A267E96;

  Temp := (t1 and (t6 and not t0 xor t2 and t5 xor t3 xor t4) xor t2 and (t6 xor t5) xor t0 and t5 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[30] + $BA7C9045;
  Temp := (t0 and (t5 and not t7 xor t1 and t4 xor t2 xor t3) xor t1 and (t5 xor t4) xor t7 and t4 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[3] + $F12C7F99;
  Temp := (t7 and (t4 and not t6 xor t0 and t3 xor t1 xor t2) xor t0 and (t4 xor t3) xor t6 and t3 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $24A19947;
  Temp := (t6 and (t3 and not t5 xor t7 and t2 xor t0 xor t1) xor t7 and (t3 xor t2) xor t5 and t2 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[9] + $B3916CF7;
  Temp := (t5 and (t2 and not t4 xor t6 and t1 xor t7 xor t0) xor t6 and (t2 xor t1) xor t4 and t1 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[17] + $0801F2E2;
  Temp := (t4 and (t1 and not t3 xor t5 and t0 xor t6 xor t7) xor t5 and (t1 xor t0) xor t3 and t0 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[24] + $858EFC16;
  Temp := (t3 and (t0 and not t2 xor t4 and t7 xor t5 xor t6) xor t4 and (t0 xor t7) xor t2 and t7 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[29] + $636920D8;
  Temp := (t2 and (t7 and not t1 xor t3 and t6 xor t4 xor t5) xor t3 and (t7 xor t6) xor t1 and t6 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[6] + $71574E69;

  Temp := (t1 and (t6 and not t0 xor t2 and t5 xor t3 xor t4) xor t2 and (t6 xor t5) xor t0 and t5 xor t4);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $A458FEA3;
  Temp := (t0 and (t5 and not t7 xor t1 and t4 xor t2 xor t3) xor t1 and (t5 xor t4) xor t7 and t4 xor t3);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[12] + $F4933D7E;
  Temp := (t7 and (t4 and not t6 xor t0 and t3 xor t1 xor t2) xor t0 and (t4 xor t3) xor t6 and t3 xor t2);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[15] + $0D95748F;
  Temp := (t6 and (t3 and not t5 xor t7 and t2 xor t0 xor t1) xor t7 and (t3 xor t2) xor t5 and t2 xor t1);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[13] + $728EB658;
  Temp := (t5 and (t2 and not t4 xor t6 and t1 xor t7 xor t0) xor t6 and (t2 xor t1) xor t4 and t1 xor t0);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[2] + $718BCD58;
  Temp := (t4 and (t1 and not t3 xor t5 and t0 xor t6 xor t7) xor t5 and (t1 xor t0) xor t3 and t0 xor t7);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[25] + $82154AEE;
  Temp := (t3 and (t0 and not t2 xor t4 and t7 xor t5 xor t6) xor t4 and (t0 xor t7) xor t2 and t7 xor t6);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[31] + $7B54A41D;
  Temp := (t2 and (t7 and not t1 xor t3 and t6 xor t4 xor t5) xor t3 and (t7 xor t6) xor t1 and t6 xor t5);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[27] + $C25A59B5;

  Temp := (t6 and (t2 and t0 xor t1 xor t5) xor t2 and t3 xor t0 and t4 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $9C30D539;
  Temp := (t5 and (t1 and t7 xor t0 xor t4) xor t1 and t2 xor t7 and t3 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9] + $2AF26013;
  Temp := (t4 and (t0 and t6 xor t7 xor t3) xor t0 and t1 xor t6 and t2 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[4] + $C5D1B023;
  Temp := (t3 and (t7 and t5 xor t6 xor t2) xor t7 and t0 xor t5 and t1 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[20] + $286085F0;
  Temp := (t2 and (t6 and t4 xor t5 xor t1) xor t6 and t7 xor t4 and t0 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[28] + $CA417918;
  Temp := (t1 and (t5 and t3 xor t4 xor t0) xor t5 and t6 xor t3 and t7 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[17] + $B8DB38EF;
  Temp := (t0 and (t4 and t2 xor t3 xor t7) xor t4 and t5 xor t2 and t6 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[8] + $8E79DCB0;
  Temp := (t7 and (t3 and t1 xor t2 xor t6) xor t3 and t4 xor t1 and t5 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[22] + $603A180E;

  Temp := (t6 and (t2 and t0 xor t1 xor t5) xor t2 and t3 xor t0 and t4 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[29] + $6C9E0E8B;
  Temp := (t5 and (t1 and t7 xor t0 xor t4) xor t1 and t2 xor t7 and t3 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[14] + $B01E8A3E;
  Temp := (t4 and (t0 and t6 xor t7 xor t3) xor t0 and t1 xor t6 and t2 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[25] + $D71577C1;
  Temp := (t3 and (t7 and t5 xor t6 xor t2) xor t7 and t0 xor t5 and t1 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[12] + $BD314B27;
  Temp := (t2 and (t6 and t4 xor t5 xor t1) xor t6 and t7 xor t4 and t0 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[24] + $78AF2FDA;
  Temp := (t1 and (t5 and t3 xor t4 xor t0) xor t5 and t6 xor t3 and t7 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[30] + $55605C60;
  Temp := (t0 and (t4 and t2 xor t3 xor t7) xor t4 and t5 xor t2 and t6 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[16] + $E65525F3;
  Temp := (t7 and (t3 and t1 xor t2 xor t6) xor t3 and t4 xor t1 and t5 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[26] + $AA55AB94;

  Temp := (t6 and (t2 and t0 xor t1 xor t5) xor t2 and t3 xor t0 and t4 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[31] + $57489862;
  Temp := (t5 and (t1 and t7 xor t0 xor t4) xor t1 and t2 xor t7 and t3 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[15] + $63E81440;
  Temp := (t4 and (t0 and t6 xor t7 xor t3) xor t0 and t1 xor t6 and t2 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[7] + $55CA396A;
  Temp := (t3 and (t7 and t5 xor t6 xor t2) xor t7 and t0 xor t5 and t1 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[3] + $2AAB10B6;
  Temp := (t2 and (t6 and t4 xor t5 xor t1) xor t6 and t7 xor t4 and t0 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[1] + $B4CC5C34;
  Temp := (t1 and (t5 and t3 xor t4 xor t0) xor t5 and t6 xor t3 and t7 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[0] + $1141E8CE;
  Temp := (t0 and (t4 and t2 xor t3 xor t7) xor t4 and t5 xor t2 and t6 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[18] + $A15486AF;
  Temp := (t7 and (t3 and t1 xor t2 xor t6) xor t3 and t4 xor t1 and t5 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[27] + $7C72E993;

  Temp := (t6 and (t2 and t0 xor t1 xor t5) xor t2 and t3 xor t0 and t4 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[13] + $B3EE1411;
  Temp := (t5 and (t1 and t7 xor t0 xor t4) xor t1 and t2 xor t7 and t3 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[6] + $636FBC2A;
  Temp := (t4 and (t0 and t6 xor t7 xor t3) xor t0 and t1 xor t6 and t2 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $2BA9C55D;
  Temp := (t3 and (t7 and t5 xor t6 xor t2) xor t7 and t0 xor t5 and t1 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[10] + $741831F6;
  Temp := (t2 and (t6 and t4 xor t5 xor t1) xor t6 and t7 xor t4 and t0 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[23] + $CE5C3E16;
  Temp := (t1 and (t5 and t3 xor t4 xor t0) xor t5 and t6 xor t3 and t7 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[11] + $9B87931E;
  Temp := (t0 and (t4 and t2 xor t3 xor t7) xor t4 and t5 xor t2 and t6 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[5] + $AFD6BA33;
  Temp := (t7 and (t3 and t1 xor t2 xor t6) xor t3 and t4 xor t1 and t5 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[2] + $6C24CF5C;

  Temp := (t0 and (t4 and not t2 xor t5 and not t6 xor t1 xor t6 xor t3) xor t5 and (t1 and t2 xor t4 xor t6) xor t2 and t6 xor t3);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[24] + $7A325381;
  Temp := (t7 and (t3 and not t1 xor t4 and not t5 xor t0 xor t5 xor t2) xor t4 and (t0 and t1 xor t3 xor t5) xor t1 and t5 xor t2);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[4] + $28958677;
  Temp := (t6 and (t2 and not t0 xor t3 and not t4 xor t7 xor t4 xor t1) xor t3 and (t7 and t0 xor t2 xor t4) xor t0 and t4 xor t1);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[0] + $3B8F4898;
  Temp := (t5 and (t1 and not t7 xor t2 and not t3 xor t6 xor t3 xor t0) xor t2 and (t6 and t7 xor t1 xor t3) xor t7 and t3 xor t0);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[14] + $6B4BB9AF;
  Temp := (t4 and (t0 and not t6 xor t1 and not t2 xor t5 xor t2 xor t7) xor t1 and (t5 and t6 xor t0 xor t2) xor t6 and t2 xor t7);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[2] + $C4BFE81B;
  Temp := (t3 and (t7 and not t5 xor t0 and not t1 xor t4 xor t1 xor t6) xor t0 and (t4 and t5 xor t7 xor t1) xor t5 and t1 xor t6);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[7] + $66282193;
  Temp := (t2 and (t6 and not t4 xor t7 and not t0 xor t3 xor t0 xor t5) xor t7 and (t3 and t4 xor t6 xor t0) xor t4 and t0 xor t5);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[28] + $61D809CC;
  Temp := (t1 and (t5 and not t3 xor t6 and not t7 xor t2 xor t7 xor t4) xor t6 and (t2 and t3 xor t5 xor t7) xor t3 and t7 xor t4);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[23] + $FB21A991;

  Temp := (t0 and (t4 and not t2 xor t5 and not t6 xor t1 xor t6 xor t3) xor t5 and (t1 and t2 xor t4 xor t6) xor t2 and t6 xor t3);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[26] + $487CAC60;
  Temp := (t7 and (t3 and not t1 xor t4 and not t5 xor t0 xor t5 xor t2) xor t4 and (t0 and t1 xor t3 xor t5) xor t1 and t5 xor t2);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[6] + $5DEC8032;
  Temp := (t6 and (t2 and not t0 xor t3 and not t4 xor t7 xor t4 xor t1) xor t3 and (t7 and t0 xor t2 xor t4) xor t0 and t4 xor t1);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[30] + $EF845D5D;
  Temp := (t5 and (t1 and not t7 xor t2 and not t3 xor t6 xor t3 xor t0) xor t2 and (t6 and t7 xor t1 xor t3) xor t7 and t3 xor t0);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[20] + $E98575B1;
  Temp := (t4 and (t0 and not t6 xor t1 and not t2 xor t5 xor t2 xor t7) xor t1 and (t5 and t6 xor t0 xor t2) xor t6 and t2 xor t7);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[18] + $DC262302;
  Temp := (t3 and (t7 and not t5 xor t0 and not t1 xor t4 xor t1 xor t6) xor t0 and (t4 and t5 xor t7 xor t1) xor t5 and t1 xor t6);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[25] + $EB651B88;
  Temp := (t2 and (t6 and not t4 xor t7 and not t0 xor t3 xor t0 xor t5) xor t7 and (t3 and t4 xor t6 xor t0) xor t4 and t0 xor t5);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[19] + $23893E81;
  Temp := (t1 and (t5 and not t3 xor t6 and not t7 xor t2 xor t7 xor t4) xor t6 and (t2 and t3 xor t5 xor t7) xor t3 and t7 xor t4);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[3] + $D396ACC5;

  Temp := (t0 and (t4 and not t2 xor t5 and not t6 xor t1 xor t6 xor t3) xor t5 and (t1 and t2 xor t4 xor t6) xor t2 and t6 xor t3);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[22] + $0F6D6FF3;
  Temp := (t7 and (t3 and not t1 xor t4 and not t5 xor t0 xor t5 xor t2) xor t4 and (t0 and t1 xor t3 xor t5) xor t1 and t5 xor t2);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[11] + $83F44239;
  Temp := (t6 and (t2 and not t0 xor t3 and not t4 xor t7 xor t4 xor t1) xor t3 and (t7 and t0 xor t2 xor t4) xor t0 and t4 xor t1);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[31] + $2E0B4482;
  Temp := (t5 and (t1 and not t7 xor t2 and not t3 xor t6 xor t3 xor t0) xor t2 and (t6 and t7 xor t1 xor t3) xor t7 and t3 xor t0);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[21] + $A4842004;
  Temp := (t4 and (t0 and not t6 xor t1 and not t2 xor t5 xor t2 xor t7) xor t1 and (t5 and t6 xor t0 xor t2) xor t6 and t2 xor t7);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[8] + $69C8F04A;
  Temp := (t3 and (t7 and not t5 xor t0 and not t1 xor t4 xor t1 xor t6) xor t0 and (t4 and t5 xor t7 xor t1) xor t5 and t1 xor t6);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[27] + $9E1F9B5E;
  Temp := (t2 and (t6 and not t4 xor t7 and not t0 xor t3 xor t0 xor t5) xor t7 and (t3 and t4 xor t6 xor t0) xor t4 and t0 xor t5);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[12] + $21C66842;
  Temp := (t1 and (t5 and not t3 xor t6 and not t7 xor t2 xor t7 xor t4) xor t6 and (t2 and t3 xor t5 xor t7) xor t3 and t7 xor t4);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[9] + $F6E96C9A;

  Temp := (t0 and (t4 and not t2 xor t5 and not t6 xor t1 xor t6 xor t3) xor t5 and (t1 and t2 xor t4 xor t6) xor t2 and t6 xor t3);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[1] + $670C9C61;
  Temp := (t7 and (t3 and not t1 xor t4 and not t5 xor t0 xor t5 xor t2) xor t4 and (t0 and t1 xor t3 xor t5) xor t1 and t5 xor t2);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[29] + $ABD388F0;
  Temp := (t6 and (t2 and not t0 xor t3 and not t4 xor t7 xor t4 xor t1) xor t3 and (t7 and t0 xor t2 xor t4) xor t0 and t4 xor t1);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[5] + $6A51A0D2;
  Temp := (t5 and (t1 and not t7 xor t2 and not t3 xor t6 xor t3 xor t0) xor t2 and (t6 and t7 xor t1 xor t3) xor t7 and t3 xor t0);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[15] + $D8542F68;
  Temp := (t4 and (t0 and not t6 xor t1 and not t2 xor t5 xor t2 xor t7) xor t1 and (t5 and t6 xor t0 xor t2) xor t6 and t2 xor t7);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[17] + $960FA728;
  Temp := (t3 and (t7 and not t5 xor t0 and not t1 xor t4 xor t1 xor t6) xor t0 and (t4 and t5 xor t7 xor t1) xor t5 and t1 xor t6);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[10] + $AB5133A3;
  Temp := (t2 and (t6 and not t4 xor t7 and not t0 xor t3 xor t0 xor t5) xor t7 and (t3 and t4 xor t6 xor t0) xor t4 and t0 xor t5);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[16] + $6EEF0B6C;
  Temp := (t1 and (t5 and not t3 xor t6 and not t7 xor t2 xor t7 xor t4) xor t6 and (t2 and t3 xor t5 xor t7) xor t3 and t7 xor t4);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[13] + $137A3BE4;
{$ELSE}
  Temp := (t2 and (t6 xor t1) xor t5 and t4 xor t0 and t3 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[0];
  Temp := (t1 and (t5 xor t0) xor t4 and t3 xor t7 and t2 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[1];
  Temp := (t0 and (t4 xor t7) xor t3 and t2 xor t6 and t1 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[2];
  Temp := (t7 and (t3 xor t6) xor t2 and t1 xor t5 and t0 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[3];
  Temp := (t6 and (t2 xor t5) xor t1 and t0 xor t4 and t7 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[4];
  Temp := (t5 and (t1 xor t4) xor t0 and t7 xor t3 and t6 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[5];
  Temp := (t4 and (t0 xor t3) xor t7 and t6 xor t2 and t5 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[6];
  Temp := (t3 and (t7 xor t2) xor t6 and t5 xor t1 and t4 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[7];

  Temp := (t2 and (t6 xor t1) xor t5 and t4 xor t0 and t3 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[8];
  Temp := (t1 and (t5 xor t0) xor t4 and t3 xor t7 and t2 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9];
  Temp := (t0 and (t4 xor t7) xor t3 and t2 xor t6 and t1 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[10];
  Temp := (t7 and (t3 xor t6) xor t2 and t1 xor t5 and t0 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[11];
  Temp := (t6 and (t2 xor t5) xor t1 and t0 xor t4 and t7 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[12];
  Temp := (t5 and (t1 xor t4) xor t0 and t7 xor t3 and t6 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[13];
  Temp := (t4 and (t0 xor t3) xor t7 and t6 xor t2 and t5 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[14];
  Temp := (t3 and (t7 xor t2) xor t6 and t5 xor t1 and t4 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[15];

  Temp := (t2 and (t6 xor t1) xor t5 and t4 xor t0 and t3 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[16];
  Temp := (t1 and (t5 xor t0) xor t4 and t3 xor t7 and t2 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[17];
  Temp := (t0 and (t4 xor t7) xor t3 and t2 xor t6 and t1 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[18];
  Temp := (t7 and (t3 xor t6) xor t2 and t1 xor t5 and t0 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[19];
  Temp := (t6 and (t2 xor t5) xor t1 and t0 xor t4 and t7 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[20];
  Temp := (t5 and (t1 xor t4) xor t0 and t7 xor t3 and t6 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[21];
  Temp := (t4 and (t0 xor t3) xor t7 and t6 xor t2 and t5 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[22];
  Temp := (t3 and (t7 xor t2) xor t6 and t5 xor t1 and t4 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[23];

  Temp := (t2 and (t6 xor t1) xor t5 and t4 xor t0 and t3 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[24];
  Temp := (t1 and (t5 xor t0) xor t4 and t3 xor t7 and t2 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[25];
  Temp := (t0 and (t4 xor t7) xor t3 and t2 xor t6 and t1 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[26];
  Temp := (t7 and (t3 xor t6) xor t2 and t1 xor t5 and t0 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[27];
  Temp := (t6 and (t2 xor t5) xor t1 and t0 xor t4 and t7 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[28];
  Temp := (t5 and (t1 xor t4) xor t0 and t7 xor t3 and t6 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[29];
  Temp := (t4 and (t0 xor t3) xor t7 and t6 xor t2 and t5 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[30];
  Temp := (t3 and (t7 xor t2) xor t6 and t5 xor t1 and t4 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[31];

  Temp := (t3 and (t4 and not t0 xor t1 and t2 xor t6 xor t5) xor t1 and (t4 xor t2) xor t0 and t2 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[5] + $452821E6;
  Temp := (t2 and (t3 and not t7 xor t0 and t1 xor t5 xor t4) xor t0 and (t3 xor t1) xor t7 and t1 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[14] + $38D01377;
  Temp := (t1 and (t2 and not t6 xor t7 and t0 xor t4 xor t3) xor t7 and (t2 xor t0) xor t6 and t0 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[26] + $BE5466CF;
  Temp := (t0 and (t1 and not t5 xor t6 and t7 xor t3 xor t2) xor t6 and (t1 xor t7) xor t5 and t7 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[18] + $34E90C6C;
  Temp := (t7 and (t0 and not t4 xor t5 and t6 xor t2 xor t1) xor t5 and (t0 xor t6) xor t4 and t6 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[11] + $C0AC29B7;
  Temp := (t6 and (t7 and not t3 xor t4 and t5 xor t1 xor t0) xor t4 and (t7 xor t5) xor t3 and t5 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[28] + $C97C50DD;
  Temp := (t5 and (t6 and not t2 xor t3 and t4 xor t0 xor t7) xor t3 and (t6 xor t4) xor t2 and t4 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[7] + $3F84D5B5;
  Temp := (t4 and (t5 and not t1 xor t2 and t3 xor t7 xor t6) xor t2 and (t5 xor t3) xor t1 and t3 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[16] + $B5470917;

  Temp := (t3 and (t4 and not t0 xor t1 and t2 xor t6 xor t5) xor t1 and (t4 xor t2) xor t0 and t2 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[0] + $9216D5D9;
  Temp := (t2 and (t3 and not t7 xor t0 and t1 xor t5 xor t4) xor t0 and (t3 xor t1) xor t7 and t1 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[23] + $8979FB1B;
  Temp := (t1 and (t2 and not t6 xor t7 and t0 xor t4 xor t3) xor t7 and (t2 xor t0) xor t6 and t0 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[20] + $D1310BA6;
  Temp := (t0 and (t1 and not t5 xor t6 and t7 xor t3 xor t2) xor t6 and (t1 xor t7) xor t5 and t7 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[22] + $98DFB5AC;
  Temp := (t7 and (t0 and not t4 xor t5 and t6 xor t2 xor t1) xor t5 and (t0 xor t6) xor t4 and t6 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[1] + $2FFD72DB;
  Temp := (t6 and (t7 and not t3 xor t4 and t5 xor t1 xor t0) xor t4 and (t7 xor t5) xor t3 and t5 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[10] + $D01ADFB7;
  Temp := (t5 and (t6 and not t2 xor t3 and t4 xor t0 xor t7) xor t3 and (t6 xor t4) xor t2 and t4 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[4] + $B8E1AFED;
  Temp := (t4 and (t5 and not t1 xor t2 and t3 xor t7 xor t6) xor t2 and (t5 xor t3) xor t1 and t3 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[8] + $6A267E96;

  Temp := (t3 and (t4 and not t0 xor t1 and t2 xor t6 xor t5) xor t1 and (t4 xor t2) xor t0 and t2 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[30] + $BA7C9045;
  Temp := (t2 and (t3 and not t7 xor t0 and t1 xor t5 xor t4) xor t0 and (t3 xor t1) xor t7 and t1 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[3] + $F12C7F99;
  Temp := (t1 and (t2 and not t6 xor t7 and t0 xor t4 xor t3) xor t7 and (t2 xor t0) xor t6 and t0 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $24A19947;
  Temp := (t0 and (t1 and not t5 xor t6 and t7 xor t3 xor t2) xor t6 and (t1 xor t7) xor t5 and t7 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[9] + $B3916CF7;
  Temp := (t7 and (t0 and not t4 xor t5 and t6 xor t2 xor t1) xor t5 and (t0 xor t6) xor t4 and t6 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[17] + $0801F2E2;
  Temp := (t6 and (t7 and not t3 xor t4 and t5 xor t1 xor t0) xor t4 and (t7 xor t5) xor t3 and t5 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[24] + $858EFC16;
  Temp := (t5 and (t6 and not t2 xor t3 and t4 xor t0 xor t7) xor t3 and (t6 xor t4) xor t2 and t4 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[29] + $636920D8;
  Temp := (t4 and (t5 and not t1 xor t2 and t3 xor t7 xor t6) xor t2 and (t5 xor t3) xor t1 and t3 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[6] + $71574E69;

  Temp := (t3 and (t4 and not t0 xor t1 and t2 xor t6 xor t5) xor t1 and (t4 xor t2) xor t0 and t2 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $A458FEA3;
  Temp := (t2 and (t3 and not t7 xor t0 and t1 xor t5 xor t4) xor t0 and (t3 xor t1) xor t7 and t1 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[12] + $F4933D7E;
  Temp := (t1 and (t2 and not t6 xor t7 and t0 xor t4 xor t3) xor t7 and (t2 xor t0) xor t6 and t0 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[15] + $0D95748F;
  Temp := (t0 and (t1 and not t5 xor t6 and t7 xor t3 xor t2) xor t6 and (t1 xor t7) xor t5 and t7 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[13] + $728EB658;
  Temp := (t7 and (t0 and not t4 xor t5 and t6 xor t2 xor t1) xor t5 and (t0 xor t6) xor t4 and t6 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[2] + $718BCD58;
  Temp := (t6 and (t7 and not t3 xor t4 and t5 xor t1 xor t0) xor t4 and (t7 xor t5) xor t3 and t5 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[25] + $82154AEE;
  Temp := (t5 and (t6 and not t2 xor t3 and t4 xor t0 xor t7) xor t3 and (t6 xor t4) xor t2 and t4 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[31] + $7B54A41D;
  Temp := (t4 and (t5 and not t1 xor t2 and t3 xor t7 xor t6) xor t2 and (t5 xor t3) xor t1 and t3 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[27] + $C25A59B5;

  Temp := (t4 and (t1 and t3 xor t2 xor t5) xor t1 and t0 xor t3 and t6 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $9C30D539;
  Temp := (t3 and (t0 and t2 xor t1 xor t4) xor t0 and t7 xor t2 and t5 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9] + $2AF26013;
  Temp := (t2 and (t7 and t1 xor t0 xor t3) xor t7 and t6 xor t1 and t4 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[4] + $C5D1B023;
  Temp := (t1 and (t6 and t0 xor t7 xor t2) xor t6 and t5 xor t0 and t3 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[20] + $286085F0;
  Temp := (t0 and (t5 and t7 xor t6 xor t1) xor t5 and t4 xor t7 and t2 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[28] + $CA417918;
  Temp := (t7 and (t4 and t6 xor t5 xor t0) xor t4 and t3 xor t6 and t1 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[17] + $B8DB38EF;
  Temp := (t6 and (t3 and t5 xor t4 xor t7) xor t3 and t2 xor t5 and t0 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[8] + $8E79DCB0;
  Temp := (t5 and (t2 and t4 xor t3 xor t6) xor t2 and t1 xor t4 and t7 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[22] + $603A180E;

  Temp := (t4 and (t1 and t3 xor t2 xor t5) xor t1 and t0 xor t3 and t6 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[29] + $6C9E0E8B;
  Temp := (t3 and (t0 and t2 xor t1 xor t4) xor t0 and t7 xor t2 and t5 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[14] + $B01E8A3E;
  Temp := (t2 and (t7 and t1 xor t0 xor t3) xor t7 and t6 xor t1 and t4 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[25] + $D71577C1;
  Temp := (t1 and (t6 and t0 xor t7 xor t2) xor t6 and t5 xor t0 and t3 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[12] + $BD314B27;
  Temp := (t0 and (t5 and t7 xor t6 xor t1) xor t5 and t4 xor t7 and t2 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[24] + $78AF2FDA;
  Temp := (t7 and (t4 and t6 xor t5 xor t0) xor t4 and t3 xor t6 and t1 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[30] + $55605C60;
  Temp := (t6 and (t3 and t5 xor t4 xor t7) xor t3 and t2 xor t5 and t0 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[16] + $E65525F3;
  Temp := (t5 and (t2 and t4 xor t3 xor t6) xor t2 and t1 xor t4 and t7 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[26] + $AA55AB94;

  Temp := (t4 and (t1 and t3 xor t2 xor t5) xor t1 and t0 xor t3 and t6 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[31] + $57489862;
  Temp := (t3 and (t0 and t2 xor t1 xor t4) xor t0 and t7 xor t2 and t5 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[15] + $63E81440;
  Temp := (t2 and (t7 and t1 xor t0 xor t3) xor t7 and t6 xor t1 and t4 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[7] + $55CA396A;
  Temp := (t1 and (t6 and t0 xor t7 xor t2) xor t6 and t5 xor t0 and t3 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[3] + $2AAB10B6;
  Temp := (t0 and (t5 and t7 xor t6 xor t1) xor t5 and t4 xor t7 and t2 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[1] + $B4CC5C34;
  Temp := (t7 and (t4 and t6 xor t5 xor t0) xor t4 and t3 xor t6 and t1 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[0] + $1141E8CE;
  Temp := (t6 and (t3 and t5 xor t4 xor t7) xor t3 and t2 xor t5 and t0 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[18] + $A15486AF;
  Temp := (t5 and (t2 and t4 xor t3 xor t6) xor t2 and t1 xor t4 and t7 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[27] + $7C72E993;

  Temp := (t4 and (t1 and t3 xor t2 xor t5) xor t1 and t0 xor t3 and t6 xor t5);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[13] + $B3EE1411;
  Temp := (t3 and (t0 and t2 xor t1 xor t4) xor t0 and t7 xor t2 and t5 xor t4);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[6] + $636FBC2A;
  Temp := (t2 and (t7 and t1 xor t0 xor t3) xor t7 and t6 xor t1 and t4 xor t3);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $2BA9C55D;
  Temp := (t1 and (t6 and t0 xor t7 xor t2) xor t6 and t5 xor t0 and t3 xor t2);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[10] + $741831F6;
  Temp := (t0 and (t5 and t7 xor t6 xor t1) xor t5 and t4 xor t7 and t2 xor t1);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[23] + $CE5C3E16;
  Temp := (t7 and (t4 and t6 xor t5 xor t0) xor t4 and t3 xor t6 and t1 xor t0);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[11] + $9B87931E;
  Temp := (t6 and (t3 and t5 xor t4 xor t7) xor t3 and t2 xor t5 and t0 xor t7);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[5] + $AFD6BA33;
  Temp := (t5 and (t2 and t4 xor t3 xor t6) xor t2 and t1 xor t4 and t7 xor t6);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[2] + $6C24CF5C;

  Temp := (t3 and (t5 and not t0 xor t2 and not t1 xor t4 xor t1 xor t6) xor t2 and (t4 and t0 xor t5 xor t1) xor t0 and t1 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[24] + $7A325381;
  Temp := (t2 and (t4 and not t7 xor t1 and not t0 xor t3 xor t0 xor t5) xor t1 and (t3 and t7 xor t4 xor t0) xor t7 and t0 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[4] + $28958677;
  Temp := (t1 and (t3 and not t6 xor t0 and not t7 xor t2 xor t7 xor t4) xor t0 and (t2 and t6 xor t3 xor t7) xor t6 and t7 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[0] + $3B8F4898;
  Temp := (t0 and (t2 and not t5 xor t7 and not t6 xor t1 xor t6 xor t3) xor t7 and (t1 and t5 xor t2 xor t6) xor t5 and t6 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[14] + $6B4BB9AF;
  Temp := (t7 and (t1 and not t4 xor t6 and not t5 xor t0 xor t5 xor t2) xor t6 and (t0 and t4 xor t1 xor t5) xor t4 and t5 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[2] + $C4BFE81B;
  Temp := (t6 and (t0 and not t3 xor t5 and not t4 xor t7 xor t4 xor t1) xor t5 and (t7 and t3 xor t0 xor t4) xor t3 and t4 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[7] + $66282193;
  Temp := (t5 and (t7 and not t2 xor t4 and not t3 xor t6 xor t3 xor t0) xor t4 and (t6 and t2 xor t7 xor t3) xor t2 and t3 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[28] + $61D809CC;
  Temp := (t4 and (t6 and not t1 xor t3 and not t2 xor t5 xor t2 xor t7) xor t3 and (t5 and t1 xor t6 xor t2) xor t1 and t2 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[23] + $FB21A991;

  Temp := (t3 and (t5 and not t0 xor t2 and not t1 xor t4 xor t1 xor t6) xor t2 and (t4 and t0 xor t5 xor t1) xor t0 and t1 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[26] + $487CAC60;
  Temp := (t2 and (t4 and not t7 xor t1 and not t0 xor t3 xor t0 xor t5) xor t1 and (t3 and t7 xor t4 xor t0) xor t7 and t0 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[6] + $5DEC8032;
  Temp := (t1 and (t3 and not t6 xor t0 and not t7 xor t2 xor t7 xor t4) xor t0 and (t2 and t6 xor t3 xor t7) xor t6 and t7 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[30] + $EF845D5D;
  Temp := (t0 and (t2 and not t5 xor t7 and not t6 xor t1 xor t6 xor t3) xor t7 and (t1 and t5 xor t2 xor t6) xor t5 and t6 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[20] + $E98575B1;
  Temp := (t7 and (t1 and not t4 xor t6 and not t5 xor t0 xor t5 xor t2) xor t6 and (t0 and t4 xor t1 xor t5) xor t4 and t5 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[18] + $DC262302;
  Temp := (t6 and (t0 and not t3 xor t5 and not t4 xor t7 xor t4 xor t1) xor t5 and (t7 and t3 xor t0 xor t4) xor t3 and t4 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[25] + $EB651B88;
  Temp := (t5 and (t7 and not t2 xor t4 and not t3 xor t6 xor t3 xor t0) xor t4 and (t6 and t2 xor t7 xor t3) xor t2 and t3 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[19] + $23893E81;
  Temp := (t4 and (t6 and not t1 xor t3 and not t2 xor t5 xor t2 xor t7) xor t3 and (t5 and t1 xor t6 xor t2) xor t1 and t2 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[3] + $D396ACC5;

  Temp := (t3 and (t5 and not t0 xor t2 and not t1 xor t4 xor t1 xor t6) xor t2 and (t4 and t0 xor t5 xor t1) xor t0 and t1 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[22] + $0F6D6FF3;
  Temp := (t2 and (t4 and not t7 xor t1 and not t0 xor t3 xor t0 xor t5) xor t1 and (t3 and t7 xor t4 xor t0) xor t7 and t0 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[11] + $83F44239;
  Temp := (t1 and (t3 and not t6 xor t0 and not t7 xor t2 xor t7 xor t4) xor t0 and (t2 and t6 xor t3 xor t7) xor t6 and t7 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[31] + $2E0B4482;
  Temp := (t0 and (t2 and not t5 xor t7 and not t6 xor t1 xor t6 xor t3) xor t7 and (t1 and t5 xor t2 xor t6) xor t5 and t6 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[21] + $A4842004;
  Temp := (t7 and (t1 and not t4 xor t6 and not t5 xor t0 xor t5 xor t2) xor t6 and (t0 and t4 xor t1 xor t5) xor t4 and t5 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[8] + $69C8F04A;
  Temp := (t6 and (t0 and not t3 xor t5 and not t4 xor t7 xor t4 xor t1) xor t5 and (t7 and t3 xor t0 xor t4) xor t3 and t4 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[27] + $9E1F9B5E;
  Temp := (t5 and (t7 and not t2 xor t4 and not t3 xor t6 xor t3 xor t0) xor t4 and (t6 and t2 xor t7 xor t3) xor t2 and t3 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[12] + $21C66842;
  Temp := (t4 and (t6 and not t1 xor t3 and not t2 xor t5 xor t2 xor t7) xor t3 and (t5 and t1 xor t6 xor t2) xor t1 and t2 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[9] + $F6E96C9A;

  Temp := (t3 and (t5 and not t0 xor t2 and not t1 xor t4 xor t1 xor t6) xor t2 and (t4 and t0 xor t5 xor t1) xor t0 and t1 xor t6);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[1] + $670C9C61;
  Temp := (t2 and (t4 and not t7 xor t1 and not t0 xor t3 xor t0 xor t5) xor t1 and (t3 and t7 xor t4 xor t0) xor t7 and t0 xor t5);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[29] + $ABD388F0;
  Temp := (t1 and (t3 and not t6 xor t0 and not t7 xor t2 xor t7 xor t4) xor t0 and (t2 and t6 xor t3 xor t7) xor t6 and t7 xor t4);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[5] + $6A51A0D2;
  Temp := (t0 and (t2 and not t5 xor t7 and not t6 xor t1 xor t6 xor t3) xor t7 and (t1 and t5 xor t2 xor t6) xor t5 and t6 xor t3);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[15] + $D8542F68;
  Temp := (t7 and (t1 and not t4 xor t6 and not t5 xor t0 xor t5 xor t2) xor t6 and (t0 and t4 xor t1 xor t5) xor t4 and t5 xor t2);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[17] + $960FA728;
  Temp := (t6 and (t0 and not t3 xor t5 and not t4 xor t7 xor t4 xor t1) xor t5 and (t7 and t3 xor t0 xor t4) xor t3 and t4 xor t1);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[10] + $AB5133A3;
  Temp := (t5 and (t7 and not t2 xor t4 and not t3 xor t6 xor t3 xor t0) xor t4 and (t6 and t2 xor t7 xor t3) xor t2 and t3 xor t0);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[16] + $6EEF0B6C;
  Temp := (t4 and (t6 and not t1 xor t3 and not t2 xor t5 xor t2 xor t7) xor t3 and (t5 and t1 xor t6 xor t2) xor t1 and t2 xor t7);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[13] + $137A3BE4;

  Temp := (t1 and (t3 and t4 and t6 xor not t5) xor t3 and t0 xor t4 and t5 xor t6 and t2);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[27] + $BA3BF050;
  Temp := (t0 and (t2 and t3 and t5 xor not t4) xor t2 and t7 xor t3 and t4 xor t5 and t1);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[3] + $7EFB2A98;
  Temp := (t7 and (t1 and t2 and t4 xor not t3) xor t1 and t6 xor t2 and t3 xor t4 and t0);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[21] + $A1F1651D;
  Temp := (t6 and (t0 and t1 and t3 xor not t2) xor t0 and t5 xor t1 and t2 xor t3 and t7);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[26] + $39AF0176;
  Temp := (t5 and (t7 and t0 and t2 xor not t1) xor t7 and t4 xor t0 and t1 xor t2 and t6);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[17] + $66CA593E;
  Temp := (t4 and (t6 and t7 and t1 xor not t0) xor t6 and t3 xor t7 and t0 xor t1 and t5);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[11] + $82430E88;
  Temp := (t3 and (t5 and t6 and t0 xor not t7) xor t5 and t2 xor t6 and t7 xor t0 and t4);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[20] + $8CEE8619;
  Temp := (t2 and (t4 and t5 and t7 xor not t6) xor t4 and t1 xor t5 and t6 xor t7 and t3);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[29] + $456F9FB4;

  Temp := (t1 and (t3 and t4 and t6 xor not t5) xor t3 and t0 xor t4 and t5 xor t6 and t2);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[19] + $7D84A5C3;
  Temp := (t0 and (t2 and t3 and t5 xor not t4) xor t2 and t7 xor t3 and t4 xor t5 and t1);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[0] + $3B8B5EBE;
  Temp := (t7 and (t1 and t2 and t4 xor not t3) xor t1 and t6 xor t2 and t3 xor t4 and t0);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[12] + $E06F75D8;
  Temp := (t6 and (t0 and t1 and t3 xor not t2) xor t0 and t5 xor t1 and t2 xor t3 and t7);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[7] + $85C12073;
  Temp := (t5 and (t7 and t0 and t2 xor not t1) xor t7 and t4 xor t0 and t1 xor t2 and t6);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[13] + $401A449F;
  Temp := (t4 and (t6 and t7 and t1 xor not t0) xor t6 and t3 xor t7 and t0 xor t1 and t5);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[8] + $56C16AA6;
  Temp := (t3 and (t5 and t6 and t0 xor not t7) xor t5 and t2 xor t6 and t7 xor t0 and t4);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[31] + $4ED3AA62;
  Temp := (t2 and (t4 and t5 and t7 xor not t6) xor t4 and t1 xor t5 and t6 xor t7 and t3);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[10] + $363F7706;

  Temp := (t1 and (t3 and t4 and t6 xor not t5) xor t3 and t0 xor t4 and t5 xor t6 and t2);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[5] + $1BFEDF72;
  Temp := (t0 and (t2 and t3 and t5 xor not t4) xor t2 and t7 xor t3 and t4 xor t5 and t1);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[9] + $429B023D;
  Temp := (t7 and (t1 and t2 and t4 xor not t3) xor t1 and t6 xor t2 and t3 xor t4 and t0);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[14] + $37D0D724;
  Temp := (t6 and (t0 and t1 and t3 xor not t2) xor t0 and t5 xor t1 and t2 xor t3 and t7);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[30] + $D00A1248;
  Temp := (t5 and (t7 and t0 and t2 xor not t1) xor t7 and t4 xor t0 and t1 xor t2 and t6);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[18] + $DB0FEAD3;
  Temp := (t4 and (t6 and t7 and t1 xor not t0) xor t6 and t3 xor t7 and t0 xor t1 and t5);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[6] + $49F1C09B;
  Temp := (t3 and (t5 and t6 and t0 xor not t7) xor t5 and t2 xor t6 and t7 xor t0 and t4);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[28] + $075372C9;
  Temp := (t2 and (t4 and t5 and t7 xor not t6) xor t4 and t1 xor t5 and t6 xor t7 and t3);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[24] + $80991B7B;

  Temp := (t1 and (t3 and t4 and t6 xor not t5) xor t3 and t0 xor t4 and t5 xor t6 and t2);
  t7 := ((Temp shr 7) or (Temp shl 25)) + ((t7 shr 11) or (t7 shl 21)) + W[2] + $25D479D8;
  Temp := (t0 and (t2 and t3 and t5 xor not t4) xor t2 and t7 xor t3 and t4 xor t5 and t1);
  t6 := ((Temp shr 7) or (Temp shl 25)) + ((t6 shr 11) or (t6 shl 21)) + W[23] + $F6E8DEF7;
  Temp := (t7 and (t1 and t2 and t4 xor not t3) xor t1 and t6 xor t2 and t3 xor t4 and t0);
  t5 := ((Temp shr 7) or (Temp shl 25)) + ((t5 shr 11) or (t5 shl 21)) + W[16] + $E3FE501A;
  Temp := (t6 and (t0 and t1 and t3 xor not t2) xor t0 and t5 xor t1 and t2 xor t3 and t7);
  t4 := ((Temp shr 7) or (Temp shl 25)) + ((t4 shr 11) or (t4 shl 21)) + W[22] + $B6794C3B;
  Temp := (t5 and (t7 and t0 and t2 xor not t1) xor t7 and t4 xor t0 and t1 xor t2 and t6);
  t3 := ((Temp shr 7) or (Temp shl 25)) + ((t3 shr 11) or (t3 shl 21)) + W[4] + $976CE0BD;
  Temp := (t4 and (t6 and t7 and t1 xor not t0) xor t6 and t3 xor t7 and t0 xor t1 and t5);
  t2 := ((Temp shr 7) or (Temp shl 25)) + ((t2 shr 11) or (t2 shl 21)) + W[1] + $04C006BA;
  Temp := (t3 and (t5 and t6 and t0 xor not t7) xor t5 and t2 xor t6 and t7 xor t0 and t4);
  t1 := ((Temp shr 7) or (Temp shl 25)) + ((t1 shr 11) or (t1 shl 21)) + W[25] + $C1A94FB6;
  Temp := (t2 and (t4 and t5 and t7 xor not t6) xor t4 and t1 xor t5 and t6 xor t7 and t3);
  t0 := ((Temp shr 7) or (Temp shl 25)) + ((t0 shr 11) or (t0 shl 21)) + W[15] + $409F60C4;
{$ENDIF}
{$ENDIF}
  Inc(CurrentHash[0], t0);
  Inc(CurrentHash[1], t1);
  Inc(CurrentHash[2], t2);
  Inc(CurrentHash[3], t3);
  Inc(CurrentHash[4], t4);
  Inc(CurrentHash[5], t5);
  Inc(CurrentHash[6], t6);
  Inc(CurrentHash[7], t7);
  FillChar(W, Sizeof(W), 0);
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_haval.GetHashSize: Integer;
begin
{$IFDEF DIGEST128}
  Result := 128;
{$ELSE}
{$IFDEF DIGEST160}
  Result := 160;
{$ELSE}
{$IFDEF DIGEST192}
  Result := 192;
{$ELSE}
{$IFDEF DIGEST224}
  Result := 224;
{$ELSE}
  Result := 256;
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
end;

class function TncEnc_haval.GetAlgorithm: string;
begin
  Result := 'Haval (';
{$IFDEF DIGEST128}
  Result := Result + '128bit, ';
{$ELSE}
{$IFDEF DIGEST160}
  Result := Result + '160bit, ';
{$ELSE}
{$IFDEF DIGEST192}
  Result := Result + '192bit, ';
{$ELSE}
{$IFDEF DIGEST224}
  Result := Result + '224bit, ';
{$ELSE}
  Result := Result + '256bit, ';
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$IFDEF PASS3}
  Result := Result + '3 passes)';
{$ELSE}
{$IFDEF PASS4}
  Result := Result + '4 passes)';
{$ELSE}
  Result := Result + '5 passes)';
{$ENDIF}
{$ENDIF}
end;

class function TncEnc_haval.SelfTest: Boolean;
{$IFDEF PASS3}
{$IFDEF DIGEST128}
const
  Test1Out: array [0 .. 15] of Byte = ($1B, $DC, $55, $6B, $29, $AD, $02, $EC, $09, $AF, $8C, $66, $47, $7F, $2A, $87);
var
  TestHash: TncEnc_haval;
  TestOut: array [0 .. 15] of Byte;
begin
  TestHash := TncEnc_haval.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Free;
{$ELSE}
{$IFDEF DIGEST160}
const
  Test1Out: array [0 .. 19] of Byte = ($5E, $16, $10, $FC, $ED, $1D, $3A, $DB, $0B, $B1, $8E, $92, $AC, $2B, $11, $F0, $BD, $99, $D8, $ED);

var
  TestHash: TncEnc_haval;
  TestOut: array [0 .. 19] of Byte;
begin
  TestHash := TncEnc_haval.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('a');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Free;
{$ELSE}
begin
  Result := true;
{$ENDIF}
{$ENDIF}
{$ELSE}
{$IFDEF PASS4}
{$IFDEF DIGEST192}
const
  Test1Out: array [0 .. 23] of Byte = ($74, $AA, $31, $18, $2F, $F0, $9B, $CC, $E4, $53, $A7, $F7, $1B, $5A, $7C, $5E, $80, $87, $2F, $A9, $0C, $D9, $3A, $E4);

var
  TestHash: TncEnc_haval;
  TestOut: array [0 .. 23] of Byte;
begin
  TestHash := TncEnc_haval.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('HAVAL');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Free;
{$ELSE}
{$IFDEF DIGEST224}
const
  Test1Out: array [0 .. 27] of Byte = ($14, $4C, $B2, $DE, $11, $F0, $5D, $F7, $C3, $56, $28, $2A, $3B, $48, $57, $96, $DA, $65, $3F, $6B, $70, $28, $68, $C7, $DC, $F4, $AE, $76);

var
  TestHash: TncEnc_haval;
  TestOut: array [0 .. 27] of Byte;
begin
  TestHash := TncEnc_haval.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('0123456789');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Free;
{$ELSE}
begin
  Result := true;
{$ENDIF}
{$ENDIF}
{$ELSE}
{$IFDEF DIGEST256}
const
  Test1Out: array [0 .. 31] of Byte = ($1A, $1D, $C8, $09, $9B, $DA, $A7, $F3, $5B, $4D, $A4, $E8, $05, $F1, $A2, $8F, $EE, $90, $9D, $8D, $EE, $92, $01, $98, $18, $5C, $BC, $AE, $D8, $A1, $0A, $8D);
  Test2Out: array [0 .. 31] of Byte = ($C5, $64, $7F, $C6, $C1, $87, $7F, $FF, $96, $74, $2F, $27, $E9, $26, $6B, $68, $74, $89, $4F, $41, $A0, $8F, $59, $13, $03, $3D, $9D, $53, $2A, $ED, $DB, $39);

var
  TestHash: TncEnc_haval;
  TestOut: array [0 .. 31] of Byte;
begin
  TestHash := TncEnc_haval.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abcdefghijklmnopqrstuvwxyz');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Init;
  TestHash.UpdateStr('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out)) and Result;
  TestHash.Free;
{$ELSE}
begin
  Result := true;
{$ENDIF}
{$ENDIF}
{$ENDIF}
end;

procedure TncEnc_haval.Init;
begin
  Burn;
  CurrentHash[0] := $243F6A88;
  CurrentHash[1] := $85A308D3;
  CurrentHash[2] := $13198A2E;
  CurrentHash[3] := $03707344;
  CurrentHash[4] := $A4093822;
  CurrentHash[5] := $299F31D0;
  CurrentHash[6] := $082EFA98;
  CurrentHash[7] := $EC4E6C89;
  FInitialized := true;
end;

procedure TncEnc_haval.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  FInitialized := false;
end;

procedure TncEnc_haval.Update(const Buffer; Size: NativeUInt);
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

procedure TncEnc_haval.Final(var Digest);
{$IFNDEF DIGEST256}
{$IFNDEF DIGEST224}
var
  Temp: UInt32;
{$ENDIF}
{$ENDIF}
begin
  if not FInitialized then
    raise EEncHashException.Create(rsHashNotInitialised);

  HashBuffer[Index] := $80;
  if Index >= 118 then
    Compress;
{$IFDEF PASS3}
{$IFDEF DIGEST128}
  HashBuffer[118] := ((128 and 3) shl 6) or (3 shl 3) or 1;
  HashBuffer[119] := (128 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST160}
  HashBuffer[118] := ((160 and 3) shl 6) or (3 shl 3) or 1;
  HashBuffer[119] := (160 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST192}
  HashBuffer[118] := ((192 and 3) shl 6) or (3 shl 3) or 1;
  HashBuffer[119] := (192 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST224}
  HashBuffer[118] := ((224 and 3) shl 6) or (3 shl 3) or 1;
  HashBuffer[119] := (224 shr 2) and $FF;
{$ELSE}
  HashBuffer[118] := ((256 and 3) shl 6) or (3 shl 3) or 1;
  HashBuffer[119] := (256 shr 2) and $FF;
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ELSE}
{$IFDEF PASS4}
{$IFDEF DIGEST128}
  HashBuffer[118] := ((128 and 3) shl 6) or (4 shl 3) or 1;
  HashBuffer[119] := (128 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST160}
  HashBuffer[118] := ((160 and 3) shl 6) or (4 shl 3) or 1;
  HashBuffer[119] := (160 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST192}
  HashBuffer[118] := ((192 and 3) shl 6) or (4 shl 3) or 1;
  HashBuffer[119] := (192 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST224}
  HashBuffer[118] := ((224 and 3) shl 6) or (4 shl 3) or 1;
  HashBuffer[119] := (224 shr 2) and $FF;
{$ELSE}
  HashBuffer[118] := ((256 and 3) shl 6) or (4 shl 3) or 1;
  HashBuffer[119] := (256 shr 2) and $FF;
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ELSE}
{$IFDEF DIGEST128}
  HashBuffer[118] := ((128 and 3) shl 6) or (5 shl 3) or 1;
  HashBuffer[119] := (2128 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST160}
  HashBuffer[118] := ((160 and 3) shl 6) or (5 shl 3) or 1;
  HashBuffer[119] := (160 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST192}
  HashBuffer[118] := ((192 and 3) shl 6) or (5 shl 3) or 1;
  HashBuffer[119] := (192 shr 2) and $FF;
{$ELSE}
{$IFDEF DIGEST224}
  HashBuffer[118] := ((224 and 3) shl 6) or (5 shl 3) or 1;
  HashBuffer[119] := (224 shr 2) and $FF;
{$ELSE}
  HashBuffer[118] := ((256 and 3) shl 6) or (5 shl 3) or 1;
  HashBuffer[119] := (256 shr 2) and $FF;
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
  PUInt32(@HashBuffer[120])^ := LenLo;
  PUInt32(@HashBuffer[124])^ := LenHi;
  Compress;
{$IFDEF DIGEST128}
  Temp := (CurrentHash[7] and $000000FF) or (CurrentHash[6] and $FF000000) or (CurrentHash[5] and $00FF0000) or (CurrentHash[4] and $0000FF00);
  Inc(CurrentHash[0], (Temp shr 8) or (Temp shl 24));
  Temp := (CurrentHash[7] and $0000FF00) or (CurrentHash[6] and $000000FF) or (CurrentHash[5] and $FF000000) or (CurrentHash[4] and $00FF0000);
  Inc(CurrentHash[1], (Temp shr 16) or (Temp shl 16));
  Temp := (CurrentHash[7] and $00FF0000) or (CurrentHash[6] and $0000FF00) or (CurrentHash[5] and $000000FF) or (CurrentHash[4] and $FF000000);
  Inc(CurrentHash[2], (Temp shr 24) or (Temp shl 8));
  Temp := (CurrentHash[7] and $FF000000) or (CurrentHash[6] and $00FF0000) or (CurrentHash[5] and $0000FF00) or (CurrentHash[4] and $000000FF);
  Inc(CurrentHash[3], Temp);
  Move(CurrentHash, Digest, 128 div 8);
{$ELSE}
{$IFDEF DIGEST160}
  Temp := (CurrentHash[7] and $3F) or (CurrentHash[6] and ($7F shl 25)) or (CurrentHash[5] and ($3F shl 19));
  Inc(CurrentHash[0], (Temp shr 19) or (Temp shl 13));
  Temp := (CurrentHash[7] and ($3F shl 6)) or (CurrentHash[6] and $3F) or (CurrentHash[5] and ($7F shl 25));
  Inc(CurrentHash[1], (Temp shr 25) or (Temp shl 7));
  Temp := (CurrentHash[7] and ($7F shl 12)) or (CurrentHash[6] and ($3F shl 6)) or (CurrentHash[5] and $3F);
  Inc(CurrentHash[2], Temp);
  Temp := (CurrentHash[7] and ($3F shl 19)) or (CurrentHash[6] and ($7F shl 12)) or (CurrentHash[5] and ($3F shl 6));
  Inc(CurrentHash[3], Temp shr 6);
  Temp := (CurrentHash[7] and ($7F shl 25)) or (CurrentHash[6] and ($3F shl 19)) or (CurrentHash[5] and ($7F shl 12));
  Inc(CurrentHash[4], Temp shr 12);
  Move(CurrentHash, Digest, 160 div 8);
{$ELSE}
{$IFDEF DIGEST192}
  Temp := (CurrentHash[7] and $1F) or (CurrentHash[6] and ($3F shl 26));
  Inc(CurrentHash[0], (Temp shr 26) or (Temp shl 6));
  Temp := (CurrentHash[7] and ($1F shl 5)) or (CurrentHash[6] and $1F);
  Inc(CurrentHash[1], Temp);
  Temp := (CurrentHash[7] and ($3F shl 10)) or (CurrentHash[6] and ($1F shl 5));
  Inc(CurrentHash[2], Temp shr 5);
  Temp := (CurrentHash[7] and ($1F shl 16)) or (CurrentHash[6] and ($3F shl 10));
  Inc(CurrentHash[3], Temp shr 10);
  Temp := (CurrentHash[7] and ($1F shl 21)) or (CurrentHash[6] and ($1F shl 16));
  Inc(CurrentHash[4], Temp shr 16);
  Temp := (CurrentHash[7] and ($3F shl 26)) or (CurrentHash[6] and ($1F shl 21));
  Inc(CurrentHash[5], Temp shr 21);
  Move(CurrentHash, Digest, 192 div 8);
{$ELSE}
{$IFDEF DIGEST224}
  Inc(CurrentHash[0], (CurrentHash[7] shr 27) and $1F);
  Inc(CurrentHash[1], (CurrentHash[7] shr 22) and $1F);
  Inc(CurrentHash[2], (CurrentHash[7] shr 18) and $F);
  Inc(CurrentHash[3], (CurrentHash[7] shr 13) and $1F);
  Inc(CurrentHash[4], (CurrentHash[7] shr 9) and $F);
  Inc(CurrentHash[5], (CurrentHash[7] shr 4) and $1F);
  Inc(CurrentHash[6], CurrentHash[7] and $F);
  Move(CurrentHash, Digest, 224 div 8);
{$ELSE}
  Move(CurrentHash, Digest, 256 div 8);
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
  Burn;
end;

end.
