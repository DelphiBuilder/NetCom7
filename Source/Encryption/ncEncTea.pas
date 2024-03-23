{$R-}
{$Q-}
unit ncEncTea;

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

type
  TncEnc_tea = class(TncEnc_blockcipher64)
  protected
    KeyData: array [0 .. 3] of UInt32;
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
  Delta = $9E3779B9;
  Rounds = 32;

function SwapDword(const a: UInt32): UInt32; inline;
begin
  Result := ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

class function TncEnc_tea.GetAlgorithm: string;
begin
  Result := 'Tea';
end;

class function TncEnc_tea.GetMaxKeySize: Integer;
begin
  Result := 128;
end;

class function TncEnc_tea.SelfTest: Boolean;
const
  Key: array [0 .. 3] of UInt32 = ($12345678, $9ABCDEF0, $0FEDCBA9, $87654321);
  PT: array [0 .. 1] of UInt32 = ($12345678, $9ABCDEF0);
var
  Data: array [0 .. 1] of UInt32;
  Cipher: TncEnc_tea;
begin
  Cipher := TncEnc_tea.Create(nil);
  Cipher.Init(Key, Sizeof(Key) * 8, nil);
  Cipher.EncryptECB(PT, Data);
  Result := not CompareMem(@Data, @PT, Sizeof(PT));
  Cipher.DecryptECB(Data, Data);
  Result := Result and CompareMem(@Data, @PT, Sizeof(PT));
  Cipher.Burn;
  Cipher.Free;
end;

procedure TncEnc_tea.InitKey(const Key; Size: longword);
begin
  FillChar(KeyData, Sizeof(KeyData), 0);
  Move(Key, KeyData, Size div 8);
  KeyData[0] := SwapDword(KeyData[0]);
  KeyData[1] := SwapDword(KeyData[1]);
  KeyData[2] := SwapDword(KeyData[2]);
  KeyData[3] := SwapDword(KeyData[3]);
end;

procedure TncEnc_tea.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), 0);
  inherited Burn;
end;

procedure TncEnc_tea.EncryptECB(const InData; var OutData);
var
  a, b, c, d, x, y, n, sum: UInt32;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);

  x := SwapDword(PUInt32(@InData)^);
  y := SwapDword(PUInt32(NativeUInt(@InData) + 4)^);
  sum := 0;
  a := KeyData[0];
  b := KeyData[1];
  c := KeyData[2];
  d := KeyData[3];
  for n := 1 to Rounds do
  begin
    Inc(sum, Delta);
    Inc(x, (y shl 4) + (a xor y) + (sum xor (y shr 5)) + b);
    Inc(y, (x shl 4) + (c xor x) + (sum xor (x shr 5)) + d);
  end;
  PUInt32(@OutData)^ := SwapDword(x);
  PUInt32(NativeUInt(@OutData) + 4)^ := SwapDword(y);
end;

procedure TncEnc_tea.DecryptECB(const InData; var OutData);
var
  a, b, c, d, x, y, n, sum: UInt32;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);

  x := SwapDword(PUInt32(@InData)^);
  y := SwapDword(PUInt32(NativeUInt(@InData) + 4)^);
  sum := Delta shl 5;
  a := KeyData[0];
  b := KeyData[1];
  c := KeyData[2];
  d := KeyData[3];
  for n := 1 to Rounds do
  begin
    Dec(y, (x shl 4) + (c xor x) + (sum xor (x shr 5)) + d);
    Dec(x, (y shl 4) + (a xor y) + (sum xor (y shr 5)) + b);
    Dec(sum, Delta);
  end;
  PUInt32(@OutData)^ := SwapDword(x);
  PUInt32(NativeUInt(@OutData) + 4)^ := SwapDword(y);
end;

end.
