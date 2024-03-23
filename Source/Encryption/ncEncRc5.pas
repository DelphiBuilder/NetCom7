{$R-}
{$Q-}
unit ncEncRc5;

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
  System.Classes, System.Sysutils, ncEnccrypt2, ncEncblockciphers;

const
  NUMROUNDS = 12; { number of rounds must be between 12-16 }

type
  TncEnc_rc5 = class(TncEnc_blockcipher64)
  protected
    KeyData: array [0 .. ((NUMROUNDS * 2) + 1)] of UInt32;
    procedure InitKey(const Key; Size: longword); override;
  public
    class function GetAlgorithm: string; override;
    class function GetMaxKeySize: Integer; override;
    class function SelfTest: Boolean; override;
    procedure Burn; override;
    procedure EncryptECB(const InData; var OutData); override;
    procedure DecryptECB(const InData; var OutData); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

const
  sBox: array [0 .. 33] of UInt32 = ($B7E15163, $5618CB1C, $F45044D5, $9287BE8E, $30BF3847, $CEF6B200, $6D2E2BB9, $0B65A572, $A99D1F2B, $47D498E4, $E60C129D, $84438C56, $227B060F, $C0B27FC8, $5EE9F981, $FD21733A, $9B58ECF3, $399066AC, $D7C7E065, $75FF5A1E, $1436D3D7, $B26E4D90, $50A5C749, $EEDD4102, $8D14BABB,
    $2B4C3474, $C983AE2D, $67BB27E6, $05F2A19F, $A42A1B58, $42619511, $E0990ECA, $7ED08883, $1D08023C);

function LRot32(const a, b: UInt32): UInt32; inline;
begin
  Result := (a shl b) or (a shr (32 - b));
end;

function RRot32(const a, b: UInt32): UInt32; inline;
begin
  Result := (a shr b) or (a shl (32 - b));
end;

class function TncEnc_rc5.GetAlgorithm: string;
begin
  Result := 'RC5';
end;

class function TncEnc_rc5.GetMaxKeySize: Integer;
begin
  Result := 2048;
end;

class function TncEnc_rc5.SelfTest: Boolean;
const
  Key1: array [0 .. 15] of byte = ($DC, $49, $DB, $13, $75, $A5, $58, $4F, $64, $85, $B4, $13, $B5, $F1, $2B, $AF);
  Plain1: array [0 .. 1] of UInt32 = ($B7B3422F, $92FC6903);
  Cipher1: array [0 .. 1] of UInt32 = ($B278C165, $CC97D184);
  Key2: array [0 .. 15] of byte = ($52, $69, $F1, $49, $D4, $1B, $A0, $15, $24, $97, $57, $4D, $7F, $15, $31, $25);
  Plain2: array [0 .. 1] of UInt32 = ($B278C165, $CC97D184);
  Cipher2: array [0 .. 1] of UInt32 = ($15E444EB, $249831DA);
var
  Cipher: TncEnc_rc5;
  Data: array [0 .. 1] of UInt32;
begin
  Cipher := TncEnc_rc5.Create(nil);
  Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
  Cipher.EncryptECB(Plain1, Data);
  Result := Boolean(CompareMem(@Data, @Cipher1, Sizeof(Data)));
  Cipher.DecryptECB(Data, Data);
  Result := Result and Boolean(CompareMem(@Data, @Plain1, Sizeof(Data)));
  Cipher.Burn;
  Cipher.Init(Key2, Sizeof(Key2) * 8, nil);
  Cipher.EncryptECB(Plain2, Data);
  Result := Result and Boolean(CompareMem(@Data, @Cipher2, Sizeof(Data)));
  Cipher.DecryptECB(Data, Data);
  Result := Result and Boolean(CompareMem(@Data, @Plain2, Sizeof(Data)));
  Cipher.Burn;
  Cipher.Free;
end;

procedure TncEnc_rc5.InitKey(const Key; Size: longword);
var
  xKeyD: array [0 .. 63] of UInt32;
  i, j, k, xKeyLen: longword;
  a, b: UInt32;
begin
  FillChar(xKeyD, Sizeof(xKeyD), 0);
  Size := Size div 8;
  Move(Key, xKeyD, Size);
  xKeyLen := Size div 4;
  if (Size mod 4) <> 0 then
    Inc(xKeyLen);
  Move(sBox, KeyData, (NUMROUNDS + 1) * 8);
  i := 0;
  j := 0;
  a := 0;
  b := 0;
  if xKeyLen > ((NUMROUNDS + 1) * 2) then
    k := xKeyLen * 3
  else
    k := (NUMROUNDS + 1) * 6;
  for k := k downto 1 do
  begin
    a := LRot32(KeyData[i] + a + b, 3);
    KeyData[i] := a;
    b := LRot32(xKeyD[j] + a + b, a + b);
    xKeyD[j] := b;
    i := (i + 1) mod ((NUMROUNDS + 1) * 2);
    j := (j + 1) mod xKeyLen;
  end;
  FillChar(xKeyD, Sizeof(xKeyD), 0);
end;

procedure TncEnc_rc5.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), $FF);
  inherited Burn;
end;

procedure TncEnc_rc5.EncryptECB(const InData; var OutData);
var
  a, b: UInt32;
  i: longword;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  a := PUInt32(@InData)^ + KeyData[0];
  b := PUInt32(NativeUInt(@InData) + 4)^ + KeyData[1];
  for i := 1 to NUMROUNDS do
  begin
    a := a xor b;
    a := LRot32(a, b) + KeyData[2 * i];
    b := b xor a;
    b := LRot32(b, a) + KeyData[(2 * i) + 1];
  end;
  PUInt32(@OutData)^ := a;
  PUInt32(NativeUInt(@OutData) + 4)^ := b;
end;

procedure TncEnc_rc5.DecryptECB(const InData; var OutData);
var
  a, b: UInt32;
  i: longword;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  a := PUInt32(@InData)^;
  b := PUInt32(NativeUInt(@InData) + 4)^;
  for i := NUMROUNDS downto 1 do
  begin
    b := RRot32(b - KeyData[(2 * i) + 1], a);
    b := b xor a;
    a := RRot32(a - KeyData[2 * i], b);
    a := a xor b;
  end;
  PUInt32(@OutData)^ := a - KeyData[0];
  PUInt32(NativeUInt(@OutData) + 4)^ := b - KeyData[1];
end;

end.
