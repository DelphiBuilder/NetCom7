{$R-}
{$Q-}
unit ncEncRipemd160;

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
  TncEnc_ripemd160 = class(TncEncHash)
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
    procedure Update(const Buffer; Size: NativeUInt); override;
    procedure Final(var Digest); override;
    procedure Burn; override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

procedure TncEnc_ripemd160.Compress;
var
  aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee: UInt32;
  X: array [0 .. 15] of UInt32;
begin
  Move(HashBuffer, X, Sizeof(X));
  aa := CurrentHash[0];
  aaa := CurrentHash[0];
  bb := CurrentHash[1];
  bbb := CurrentHash[1];
  cc := CurrentHash[2];
  ccc := CurrentHash[2];
  dd := CurrentHash[3];
  ddd := CurrentHash[3];
  ee := CurrentHash[4];
  eee := CurrentHash[4];

  aa := aa + (bb xor cc xor dd) + X[0];
  aa := ((aa shl 11) or (aa shr (32 - 11))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + (aa xor bb xor cc) + X[1];
  ee := ((ee shl 14) or (ee shr (32 - 14))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + (ee xor aa xor bb) + X[2];
  dd := ((dd shl 15) or (dd shr (32 - 15))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + (dd xor ee xor aa) + X[3];
  cc := ((cc shl 12) or (cc shr (32 - 12))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + (cc xor dd xor ee) + X[4];
  bb := ((bb shl 5) or (bb shr (32 - 5))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + (bb xor cc xor dd) + X[5];
  aa := ((aa shl 8) or (aa shr (32 - 8))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + (aa xor bb xor cc) + X[6];
  ee := ((ee shl 7) or (ee shr (32 - 7))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + (ee xor aa xor bb) + X[7];
  dd := ((dd shl 9) or (dd shr (32 - 9))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + (dd xor ee xor aa) + X[8];
  cc := ((cc shl 11) or (cc shr (32 - 11))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + (cc xor dd xor ee) + X[9];
  bb := ((bb shl 13) or (bb shr (32 - 13))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + (bb xor cc xor dd) + X[10];
  aa := ((aa shl 14) or (aa shr (32 - 14))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + (aa xor bb xor cc) + X[11];
  ee := ((ee shl 15) or (ee shr (32 - 15))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + (ee xor aa xor bb) + X[12];
  dd := ((dd shl 6) or (dd shr (32 - 6))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + (dd xor ee xor aa) + X[13];
  cc := ((cc shl 7) or (cc shr (32 - 7))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + (cc xor dd xor ee) + X[14];
  bb := ((bb shl 9) or (bb shr (32 - 9))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + (bb xor cc xor dd) + X[15];
  aa := ((aa shl 8) or (aa shr (32 - 8))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));

  ee := ee + ((aa and bb) or ((not aa) and cc)) + X[7] + $5A827999;
  ee := ((ee shl 7) or (ee shr (32 - 7))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee and aa) or ((not ee) and bb)) + X[4] + $5A827999;
  dd := ((dd shl 6) or (dd shr (32 - 6))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd and ee) or ((not dd) and aa)) + X[13] + $5A827999;
  cc := ((cc shl 8) or (cc shr (32 - 8))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc and dd) or ((not cc) and ee)) + X[1] + $5A827999;
  bb := ((bb shl 13) or (bb shr (32 - 13))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb and cc) or ((not bb) and dd)) + X[10] + $5A827999;
  aa := ((aa shl 11) or (aa shr (32 - 11))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa and bb) or ((not aa) and cc)) + X[6] + $5A827999;
  ee := ((ee shl 9) or (ee shr (32 - 9))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee and aa) or ((not ee) and bb)) + X[15] + $5A827999;
  dd := ((dd shl 7) or (dd shr (32 - 7))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd and ee) or ((not dd) and aa)) + X[3] + $5A827999;
  cc := ((cc shl 15) or (cc shr (32 - 15))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc and dd) or ((not cc) and ee)) + X[12] + $5A827999;
  bb := ((bb shl 7) or (bb shr (32 - 7))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb and cc) or ((not bb) and dd)) + X[0] + $5A827999;
  aa := ((aa shl 12) or (aa shr (32 - 12))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa and bb) or ((not aa) and cc)) + X[9] + $5A827999;
  ee := ((ee shl 15) or (ee shr (32 - 15))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee and aa) or ((not ee) and bb)) + X[5] + $5A827999;
  dd := ((dd shl 9) or (dd shr (32 - 9))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd and ee) or ((not dd) and aa)) + X[2] + $5A827999;
  cc := ((cc shl 11) or (cc shr (32 - 11))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc and dd) or ((not cc) and ee)) + X[14] + $5A827999;
  bb := ((bb shl 7) or (bb shr (32 - 7))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb and cc) or ((not bb) and dd)) + X[11] + $5A827999;
  aa := ((aa shl 13) or (aa shr (32 - 13))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa and bb) or ((not aa) and cc)) + X[8] + $5A827999;
  ee := ((ee shl 12) or (ee shr (32 - 12))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));

  dd := dd + ((ee or (not aa)) xor bb) + X[3] + $6ED9EBA1;
  dd := ((dd shl 11) or (dd shr (32 - 11))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd or (not ee)) xor aa) + X[10] + $6ED9EBA1;
  cc := ((cc shl 13) or (cc shr (32 - 13))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc or (not dd)) xor ee) + X[14] + $6ED9EBA1;
  bb := ((bb shl 6) or (bb shr (32 - 6))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb or (not cc)) xor dd) + X[4] + $6ED9EBA1;
  aa := ((aa shl 7) or (aa shr (32 - 7))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa or (not bb)) xor cc) + X[9] + $6ED9EBA1;
  ee := ((ee shl 14) or (ee shr (32 - 14))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee or (not aa)) xor bb) + X[15] + $6ED9EBA1;
  dd := ((dd shl 9) or (dd shr (32 - 9))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd or (not ee)) xor aa) + X[8] + $6ED9EBA1;
  cc := ((cc shl 13) or (cc shr (32 - 13))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc or (not dd)) xor ee) + X[1] + $6ED9EBA1;
  bb := ((bb shl 15) or (bb shr (32 - 15))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb or (not cc)) xor dd) + X[2] + $6ED9EBA1;
  aa := ((aa shl 14) or (aa shr (32 - 14))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa or (not bb)) xor cc) + X[7] + $6ED9EBA1;
  ee := ((ee shl 8) or (ee shr (32 - 8))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee or (not aa)) xor bb) + X[0] + $6ED9EBA1;
  dd := ((dd shl 13) or (dd shr (32 - 13))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd or (not ee)) xor aa) + X[6] + $6ED9EBA1;
  cc := ((cc shl 6) or (cc shr (32 - 6))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc or (not dd)) xor ee) + X[13] + $6ED9EBA1;
  bb := ((bb shl 5) or (bb shr (32 - 5))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb or (not cc)) xor dd) + X[11] + $6ED9EBA1;
  aa := ((aa shl 12) or (aa shr (32 - 12))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa or (not bb)) xor cc) + X[5] + $6ED9EBA1;
  ee := ((ee shl 7) or (ee shr (32 - 7))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee or (not aa)) xor bb) + X[12] + $6ED9EBA1;
  dd := ((dd shl 5) or (dd shr (32 - 5))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));

  cc := cc + ((dd and aa) or (ee and (not aa))) + X[1] + $8F1BBCDC;
  cc := ((cc shl 11) or (cc shr (32 - 11))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc and ee) or (dd and (not ee))) + X[9] + $8F1BBCDC;
  bb := ((bb shl 12) or (bb shr (32 - 12))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb and dd) or (cc and (not dd))) + X[11] + $8F1BBCDC;
  aa := ((aa shl 14) or (aa shr (32 - 14))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa and cc) or (bb and (not cc))) + X[10] + $8F1BBCDC;
  ee := ((ee shl 15) or (ee shr (32 - 15))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee and bb) or (aa and (not bb))) + X[0] + $8F1BBCDC;
  dd := ((dd shl 14) or (dd shr (32 - 14))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd and aa) or (ee and (not aa))) + X[8] + $8F1BBCDC;
  cc := ((cc shl 15) or (cc shr (32 - 15))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc and ee) or (dd and (not ee))) + X[12] + $8F1BBCDC;
  bb := ((bb shl 9) or (bb shr (32 - 9))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb and dd) or (cc and (not dd))) + X[4] + $8F1BBCDC;
  aa := ((aa shl 8) or (aa shr (32 - 8))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa and cc) or (bb and (not cc))) + X[13] + $8F1BBCDC;
  ee := ((ee shl 9) or (ee shr (32 - 9))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee and bb) or (aa and (not bb))) + X[3] + $8F1BBCDC;
  dd := ((dd shl 14) or (dd shr (32 - 14))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd and aa) or (ee and (not aa))) + X[7] + $8F1BBCDC;
  cc := ((cc shl 5) or (cc shr (32 - 5))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + ((cc and ee) or (dd and (not ee))) + X[15] + $8F1BBCDC;
  bb := ((bb shl 6) or (bb shr (32 - 6))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + ((bb and dd) or (cc and (not dd))) + X[14] + $8F1BBCDC;
  aa := ((aa shl 8) or (aa shr (32 - 8))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + ((aa and cc) or (bb and (not cc))) + X[5] + $8F1BBCDC;
  ee := ((ee shl 6) or (ee shr (32 - 6))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + ((ee and bb) or (aa and (not bb))) + X[6] + $8F1BBCDC;
  dd := ((dd shl 5) or (dd shr (32 - 5))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + ((dd and aa) or (ee and (not aa))) + X[2] + $8F1BBCDC;
  cc := ((cc shl 12) or (cc shr (32 - 12))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));

  bb := bb + (cc xor (dd or (not ee))) + X[4] + $A953FD4E;
  bb := ((bb shl 9) or (bb shr (32 - 9))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + (bb xor (cc or (not dd))) + X[0] + $A953FD4E;
  aa := ((aa shl 15) or (aa shr (32 - 15))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + (aa xor (bb or (not cc))) + X[5] + $A953FD4E;
  ee := ((ee shl 5) or (ee shr (32 - 5))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + (ee xor (aa or (not bb))) + X[9] + $A953FD4E;
  dd := ((dd shl 11) or (dd shr (32 - 11))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + (dd xor (ee or (not aa))) + X[7] + $A953FD4E;
  cc := ((cc shl 6) or (cc shr (32 - 6))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + (cc xor (dd or (not ee))) + X[12] + $A953FD4E;
  bb := ((bb shl 8) or (bb shr (32 - 8))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + (bb xor (cc or (not dd))) + X[2] + $A953FD4E;
  aa := ((aa shl 13) or (aa shr (32 - 13))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + (aa xor (bb or (not cc))) + X[10] + $A953FD4E;
  ee := ((ee shl 12) or (ee shr (32 - 12))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + (ee xor (aa or (not bb))) + X[14] + $A953FD4E;
  dd := ((dd shl 5) or (dd shr (32 - 5))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + (dd xor (ee or (not aa))) + X[1] + $A953FD4E;
  cc := ((cc shl 12) or (cc shr (32 - 12))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + (cc xor (dd or (not ee))) + X[3] + $A953FD4E;
  bb := ((bb shl 13) or (bb shr (32 - 13))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));
  aa := aa + (bb xor (cc or (not dd))) + X[8] + $A953FD4E;
  aa := ((aa shl 14) or (aa shr (32 - 14))) + ee;
  cc := ((cc shl 10) or (cc shr (32 - 10)));
  ee := ee + (aa xor (bb or (not cc))) + X[11] + $A953FD4E;
  ee := ((ee shl 11) or (ee shr (32 - 11))) + dd;
  bb := ((bb shl 10) or (bb shr (32 - 10)));
  dd := dd + (ee xor (aa or (not bb))) + X[6] + $A953FD4E;
  dd := ((dd shl 8) or (dd shr (32 - 8))) + cc;
  aa := ((aa shl 10) or (aa shr (32 - 10)));
  cc := cc + (dd xor (ee or (not aa))) + X[15] + $A953FD4E;
  cc := ((cc shl 5) or (cc shr (32 - 5))) + bb;
  ee := ((ee shl 10) or (ee shr (32 - 10)));
  bb := bb + (cc xor (dd or (not ee))) + X[13] + $A953FD4E;
  bb := ((bb shl 6) or (bb shr (32 - 6))) + aa;
  dd := ((dd shl 10) or (dd shr (32 - 10)));

  aaa := aaa + (bbb xor (ccc or (not ddd))) + X[5] + $50A28BE6;
  aaa := ((aaa shl 8) or (aaa shr (32 - 8))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + (aaa xor (bbb or (not ccc))) + X[14] + $50A28BE6;
  eee := ((eee shl 9) or (eee shr (32 - 9))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + (eee xor (aaa or (not bbb))) + X[7] + $50A28BE6;
  ddd := ((ddd shl 9) or (ddd shr (32 - 9))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + (ddd xor (eee or (not aaa))) + X[0] + $50A28BE6;
  ccc := ((ccc shl 11) or (ccc shr (32 - 11))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + (ccc xor (ddd or (not eee))) + X[9] + $50A28BE6;
  bbb := ((bbb shl 13) or (bbb shr (32 - 13))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + (bbb xor (ccc or (not ddd))) + X[2] + $50A28BE6;
  aaa := ((aaa shl 15) or (aaa shr (32 - 15))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + (aaa xor (bbb or (not ccc))) + X[11] + $50A28BE6;
  eee := ((eee shl 15) or (eee shr (32 - 15))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + (eee xor (aaa or (not bbb))) + X[4] + $50A28BE6;
  ddd := ((ddd shl 5) or (ddd shr (32 - 5))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + (ddd xor (eee or (not aaa))) + X[13] + $50A28BE6;
  ccc := ((ccc shl 7) or (ccc shr (32 - 7))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + (ccc xor (ddd or (not eee))) + X[6] + $50A28BE6;
  bbb := ((bbb shl 7) or (bbb shr (32 - 7))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + (bbb xor (ccc or (not ddd))) + X[15] + $50A28BE6;
  aaa := ((aaa shl 8) or (aaa shr (32 - 8))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + (aaa xor (bbb or (not ccc))) + X[8] + $50A28BE6;
  eee := ((eee shl 11) or (eee shr (32 - 11))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + (eee xor (aaa or (not bbb))) + X[1] + $50A28BE6;
  ddd := ((ddd shl 14) or (ddd shr (32 - 14))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + (ddd xor (eee or (not aaa))) + X[10] + $50A28BE6;
  ccc := ((ccc shl 14) or (ccc shr (32 - 14))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + (ccc xor (ddd or (not eee))) + X[3] + $50A28BE6;
  bbb := ((bbb shl 12) or (bbb shr (32 - 12))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + (bbb xor (ccc or (not ddd))) + X[12] + $50A28BE6;
  aaa := ((aaa shl 6) or (aaa shr (32 - 6))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));

  eee := eee + ((aaa and ccc) or (bbb and (not ccc))) + X[6] + $5C4DD124;
  eee := ((eee shl 9) or (eee shr (32 - 9))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee and bbb) or (aaa and (not bbb))) + X[11] + $5C4DD124;
  ddd := ((ddd shl 13) or (ddd shr (32 - 13))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd and aaa) or (eee and (not aaa))) + X[3] + $5C4DD124;
  ccc := ((ccc shl 15) or (ccc shr (32 - 15))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc and eee) or (ddd and (not eee))) + X[7] + $5C4DD124;
  bbb := ((bbb shl 7) or (bbb shr (32 - 7))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb and ddd) or (ccc and (not ddd))) + X[0] + $5C4DD124;
  aaa := ((aaa shl 12) or (aaa shr (32 - 12))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa and ccc) or (bbb and (not ccc))) + X[13] + $5C4DD124;
  eee := ((eee shl 8) or (eee shr (32 - 8))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee and bbb) or (aaa and (not bbb))) + X[5] + $5C4DD124;
  ddd := ((ddd shl 9) or (ddd shr (32 - 9))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd and aaa) or (eee and (not aaa))) + X[10] + $5C4DD124;
  ccc := ((ccc shl 11) or (ccc shr (32 - 11))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc and eee) or (ddd and (not eee))) + X[14] + $5C4DD124;
  bbb := ((bbb shl 7) or (bbb shr (32 - 7))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb and ddd) or (ccc and (not ddd))) + X[15] + $5C4DD124;
  aaa := ((aaa shl 7) or (aaa shr (32 - 7))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa and ccc) or (bbb and (not ccc))) + X[8] + $5C4DD124;
  eee := ((eee shl 12) or (eee shr (32 - 12))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee and bbb) or (aaa and (not bbb))) + X[12] + $5C4DD124;
  ddd := ((ddd shl 7) or (ddd shr (32 - 7))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd and aaa) or (eee and (not aaa))) + X[4] + $5C4DD124;
  ccc := ((ccc shl 6) or (ccc shr (32 - 6))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc and eee) or (ddd and (not eee))) + X[9] + $5C4DD124;
  bbb := ((bbb shl 15) or (bbb shr (32 - 15))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb and ddd) or (ccc and (not ddd))) + X[1] + $5C4DD124;
  aaa := ((aaa shl 13) or (aaa shr (32 - 13))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa and ccc) or (bbb and (not ccc))) + X[2] + $5C4DD124;
  eee := ((eee shl 11) or (eee shr (32 - 11))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));

  ddd := ddd + ((eee or (not aaa)) xor bbb) + X[15] + $6D703EF3;
  ddd := ((ddd shl 9) or (ddd shr (32 - 9))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd or (not eee)) xor aaa) + X[5] + $6D703EF3;
  ccc := ((ccc shl 7) or (ccc shr (32 - 7))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc or (not ddd)) xor eee) + X[1] + $6D703EF3;
  bbb := ((bbb shl 15) or (bbb shr (32 - 15))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb or (not ccc)) xor ddd) + X[3] + $6D703EF3;
  aaa := ((aaa shl 11) or (aaa shr (32 - 11))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa or (not bbb)) xor ccc) + X[7] + $6D703EF3;
  eee := ((eee shl 8) or (eee shr (32 - 8))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee or (not aaa)) xor bbb) + X[14] + $6D703EF3;
  ddd := ((ddd shl 6) or (ddd shr (32 - 6))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd or (not eee)) xor aaa) + X[6] + $6D703EF3;
  ccc := ((ccc shl 6) or (ccc shr (32 - 6))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc or (not ddd)) xor eee) + X[9] + $6D703EF3;
  bbb := ((bbb shl 14) or (bbb shr (32 - 14))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb or (not ccc)) xor ddd) + X[11] + $6D703EF3;
  aaa := ((aaa shl 12) or (aaa shr (32 - 12))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa or (not bbb)) xor ccc) + X[8] + $6D703EF3;
  eee := ((eee shl 13) or (eee shr (32 - 13))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee or (not aaa)) xor bbb) + X[12] + $6D703EF3;
  ddd := ((ddd shl 5) or (ddd shr (32 - 5))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd or (not eee)) xor aaa) + X[2] + $6D703EF3;
  ccc := ((ccc shl 14) or (ccc shr (32 - 14))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc or (not ddd)) xor eee) + X[10] + $6D703EF3;
  bbb := ((bbb shl 13) or (bbb shr (32 - 13))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb or (not ccc)) xor ddd) + X[0] + $6D703EF3;
  aaa := ((aaa shl 13) or (aaa shr (32 - 13))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa or (not bbb)) xor ccc) + X[4] + $6D703EF3;
  eee := ((eee shl 7) or (eee shr (32 - 7))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee or (not aaa)) xor bbb) + X[13] + $6D703EF3;
  ddd := ((ddd shl 5) or (ddd shr (32 - 5))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));

  ccc := ccc + ((ddd and eee) or ((not ddd) and aaa)) + X[8] + $7A6D76E9;
  ccc := ((ccc shl 15) or (ccc shr (32 - 15))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc and ddd) or ((not ccc) and eee)) + X[6] + $7A6D76E9;
  bbb := ((bbb shl 5) or (bbb shr (32 - 5))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb and ccc) or ((not bbb) and ddd)) + X[4] + $7A6D76E9;
  aaa := ((aaa shl 8) or (aaa shr (32 - 8))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa and bbb) or ((not aaa) and ccc)) + X[1] + $7A6D76E9;
  eee := ((eee shl 11) or (eee shr (32 - 11))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee and aaa) or ((not eee) and bbb)) + X[3] + $7A6D76E9;
  ddd := ((ddd shl 14) or (ddd shr (32 - 14))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd and eee) or ((not ddd) and aaa)) + X[11] + $7A6D76E9;
  ccc := ((ccc shl 14) or (ccc shr (32 - 14))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc and ddd) or ((not ccc) and eee)) + X[15] + $7A6D76E9;
  bbb := ((bbb shl 6) or (bbb shr (32 - 6))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb and ccc) or ((not bbb) and ddd)) + X[0] + $7A6D76E9;
  aaa := ((aaa shl 14) or (aaa shr (32 - 14))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa and bbb) or ((not aaa) and ccc)) + X[5] + $7A6D76E9;
  eee := ((eee shl 6) or (eee shr (32 - 6))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee and aaa) or ((not eee) and bbb)) + X[12] + $7A6D76E9;
  ddd := ((ddd shl 9) or (ddd shr (32 - 9))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd and eee) or ((not ddd) and aaa)) + X[2] + $7A6D76E9;
  ccc := ((ccc shl 12) or (ccc shr (32 - 12))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + ((ccc and ddd) or ((not ccc) and eee)) + X[13] + $7A6D76E9;
  bbb := ((bbb shl 9) or (bbb shr (32 - 9))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + ((bbb and ccc) or ((not bbb) and ddd)) + X[9] + $7A6D76E9;
  aaa := ((aaa shl 12) or (aaa shr (32 - 12))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + ((aaa and bbb) or ((not aaa) and ccc)) + X[7] + $7A6D76E9;
  eee := ((eee shl 5) or (eee shr (32 - 5))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + ((eee and aaa) or ((not eee) and bbb)) + X[10] + $7A6D76E9;
  ddd := ((ddd shl 15) or (ddd shr (32 - 15))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + ((ddd and eee) or ((not ddd) and aaa)) + X[14] + $7A6D76E9;
  ccc := ((ccc shl 8) or (ccc shr (32 - 8))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));

  bbb := bbb + (ccc xor ddd xor eee) + X[12];
  bbb := ((bbb shl 8) or (bbb shr (32 - 8))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + (bbb xor ccc xor ddd) + X[15];
  aaa := ((aaa shl 5) or (aaa shr (32 - 5))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + (aaa xor bbb xor ccc) + X[10];
  eee := ((eee shl 12) or (eee shr (32 - 12))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + (eee xor aaa xor bbb) + X[4];
  ddd := ((ddd shl 9) or (ddd shr (32 - 9))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + (ddd xor eee xor aaa) + X[1];
  ccc := ((ccc shl 12) or (ccc shr (32 - 12))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + (ccc xor ddd xor eee) + X[5];
  bbb := ((bbb shl 5) or (bbb shr (32 - 5))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + (bbb xor ccc xor ddd) + X[8];
  aaa := ((aaa shl 14) or (aaa shr (32 - 14))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + (aaa xor bbb xor ccc) + X[7];
  eee := ((eee shl 6) or (eee shr (32 - 6))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + (eee xor aaa xor bbb) + X[6];
  ddd := ((ddd shl 8) or (ddd shr (32 - 8))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + (ddd xor eee xor aaa) + X[2];
  ccc := ((ccc shl 13) or (ccc shr (32 - 13))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + (ccc xor ddd xor eee) + X[13];
  bbb := ((bbb shl 6) or (bbb shr (32 - 6))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));
  aaa := aaa + (bbb xor ccc xor ddd) + X[14];
  aaa := ((aaa shl 5) or (aaa shr (32 - 5))) + eee;
  ccc := ((ccc shl 10) or (ccc shr (32 - 10)));
  eee := eee + (aaa xor bbb xor ccc) + X[0];
  eee := ((eee shl 15) or (eee shr (32 - 15))) + ddd;
  bbb := ((bbb shl 10) or (bbb shr (32 - 10)));
  ddd := ddd + (eee xor aaa xor bbb) + X[3];
  ddd := ((ddd shl 13) or (ddd shr (32 - 13))) + ccc;
  aaa := ((aaa shl 10) or (aaa shr (32 - 10)));
  ccc := ccc + (ddd xor eee xor aaa) + X[9];
  ccc := ((ccc shl 11) or (ccc shr (32 - 11))) + bbb;
  eee := ((eee shl 10) or (eee shr (32 - 10)));
  bbb := bbb + (ccc xor ddd xor eee) + X[11];
  bbb := ((bbb shl 11) or (bbb shr (32 - 11))) + aaa;
  ddd := ((ddd shl 10) or (ddd shr (32 - 10)));

  ddd := ddd + cc + CurrentHash[1];
  CurrentHash[1] := CurrentHash[2] + dd + eee;
  CurrentHash[2] := CurrentHash[3] + ee + aaa;
  CurrentHash[3] := CurrentHash[4] + aa + bbb;
  CurrentHash[4] := CurrentHash[0] + bb + ccc;
  CurrentHash[0] := ddd;
  FillChar(X, Sizeof(X), 0);
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_ripemd160.GetHashSize: Integer;
begin
  Result := 160;
end;

class function TncEnc_ripemd160.GetAlgorithm: string;
begin
  Result := 'RipeMD-160';
end;

class function TncEnc_ripemd160.SelfTest: Boolean;
const
  Test1Out: array [0 .. 19] of Byte = ($0B, $DC, $9D, $2D, $25, $6B, $3E, $E9, $DA, $AE, $34, $7B, $E6, $F4, $DC, $83, $5A, $46, $7F, $FE);
  Test2Out: array [0 .. 19] of Byte = ($F7, $1C, $27, $10, $9C, $69, $2C, $1B, $56, $BB, $DC, $EB, $5B, $9D, $28, $65, $B3, $70, $8D, $BC);
var
  TestHash: TncEnc_ripemd160;
  TestOut: array [0 .. 19] of Byte;
begin
  TestHash := TncEnc_ripemd160.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('a');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Init;
  TestHash.UpdateStr('abcdefghijklmnopqrstuvwxyz');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out)) and Result;
  TestHash.Free;
end;

procedure TncEnc_ripemd160.Init;
begin
  Burn;
  CurrentHash[0] := $67452301;
  CurrentHash[1] := $EFCDAB89;
  CurrentHash[2] := $98BADCFE;
  CurrentHash[3] := $10325476;
  CurrentHash[4] := $C3D2E1F0;
  FInitialized := true;
end;

procedure TncEnc_ripemd160.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  FInitialized := false;
end;

procedure TncEnc_ripemd160.Update(const Buffer; Size: NativeUInt);
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

procedure TncEnc_ripemd160.Final(var Digest);
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
