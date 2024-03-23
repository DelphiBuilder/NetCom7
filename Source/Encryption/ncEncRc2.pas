{$R-}
{$Q-}
unit ncEncRc2;

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
  Classes, Sysutils, ncEnccrypt2, ncEncblockciphers;

type
  TncEnc_rc2 = class(TncEnc_blockcipher64)
  protected
    KeyData: array [0 .. 63] of Word;
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
  sBox: array [0 .. 255] of byte = ($D9, $78, $F9, $C4, $19, $DD, $B5, $ED, $28, $E9, $FD, $79, $4A, $A0, $D8, $9D, $C6, $7E, $37, $83, $2B, $76, $53, $8E, $62, $4C, $64, $88, $44, $8B, $FB, $A2, $17, $9A, $59, $F5, $87, $B3, $4F, $13, $61, $45, $6D, $8D, $09, $81, $7D, $32, $BD, $8F, $40, $EB, $86, $B7, $7B, $0B, $F0,
    $95, $21, $22, $5C, $6B, $4E, $82, $54, $D6, $65, $93, $CE, $60, $B2, $1C, $73, $56, $C0, $14, $A7, $8C, $F1, $DC, $12, $75, $CA, $1F, $3B, $BE, $E4, $D1, $42, $3D, $D4, $30, $A3, $3C, $B6, $26, $6F, $BF, $0E, $DA, $46, $69, $07, $57, $27, $F2, $1D, $9B, $BC, $94, $43, $03, $F8, $11, $C7, $F6, $90, $EF, $3E, $E7,
    $06, $C3, $D5, $2F, $C8, $66, $1E, $D7, $08, $E8, $EA, $DE, $80, $52, $EE, $F7, $84, $AA, $72, $AC, $35, $4D, $6A, $2A, $96, $1A, $D2, $71, $5A, $15, $49, $74, $4B, $9F, $D0, $5E, $04, $18, $A4, $EC, $C2, $E0, $41, $6E, $0F, $51, $CB, $CC, $24, $91, $AF, $50, $A1, $F4, $70, $39, $99, $7C, $3A, $85, $23, $B8, $B4,
    $7A, $FC, $02, $36, $5B, $25, $55, $97, $31, $2D, $5D, $FA, $98, $E3, $8A, $92, $AE, $05, $DF, $29, $10, $67, $6C, $BA, $C9, $D3, $00, $E6, $CF, $E1, $9E, $A8, $2C, $63, $16, $01, $3F, $58, $E2, $89, $A9, $0D, $38, $34, $1B, $AB, $33, $FF, $B0, $BB, $48, $0C, $5F, $B9, $B1, $CD, $2E, $C5, $F3, $DB, $47, $E5, $A5,
    $9C, $77, $0A, $A6, $20, $68, $FE, $7F, $C1, $AD);

function LRot16(a, n: Word): Word;
begin
  Result := (a shl n) or (a shr (16 - n));
end;

function RRot16(a, n: Word): Word;
begin
  Result := (a shr n) or (a shl (16 - n));
end;

class function TncEnc_rc2.GetMaxKeySize: integer;
begin
  Result := 1024;
end;

class function TncEnc_rc2.GetAlgorithm: string;
begin
  Result := 'RC2';
end;

class function TncEnc_rc2.SelfTest: boolean;
const
  Key1: array [0 .. 15] of byte = ($00, $01, $02, $03, $04, $05, $06, $07, $08, $09, $0A, $0B, $0C, $0D, $0E, $0F);
  InData1: array [0 .. 7] of byte = ($00, $00, $00, $00, $00, $00, $00, $00);
  OutData1: array [0 .. 7] of byte = ($50, $DC, $01, $62, $BD, $75, $7F, $31);
  Key2: array [0 .. 15] of byte = ($00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01);
  InData2: array [0 .. 7] of byte = ($00, $00, $00, $00, $00, $00, $00, $00);
  OutData2: array [0 .. 7] of byte = ($21, $82, $9C, $78, $A9, $F9, $C0, $74);
var
  Cipher: TncEnc_rc2;
  Data: array [0 .. 7] of byte;
begin
  Cipher := TncEnc_rc2.Create(nil);
  Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
  Cipher.EncryptECB(InData1, Data);
  Result := boolean(CompareMem(@Data, @OutData1, Sizeof(Data)));
  Cipher.DecryptECB(Data, Data);
  Result := boolean(CompareMem(@Data, @InData1, Sizeof(Data))) and Result;
  Cipher.Burn;
  Cipher.Init(Key2, Sizeof(Key2) * 8, nil);
  Cipher.EncryptECB(InData2, Data);
  Result := boolean(CompareMem(@Data, @OutData2, Sizeof(Data))) and Result;
  Cipher.DecryptECB(Data, Data);
  Result := boolean(CompareMem(@Data, @InData2, Sizeof(Data))) and Result;
  Cipher.Burn;
  Cipher.Free;
end;

procedure TncEnc_rc2.InitKey(const Key; Size: longword);
var
  i: longword;
  KeyB: array [0 .. 127] of byte;
begin
  Move(Key, KeyB, Size div 8);
  for i := (Size div 8) to 127 do
    KeyB[i] := sBox[(KeyB[i - (Size div 8)] + KeyB[i - 1]) and $FF];
  KeyB[0] := sBox[KeyB[0]];
  Move(KeyB, KeyData, Sizeof(KeyData));
end;

procedure TncEnc_rc2.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), 0);
  inherited Burn;
end;

procedure TncEnc_rc2.EncryptECB(const InData; var OutData);
var
  i, j: longword;
  w: array [0 .. 3] of Word;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  PUInt32(@w[0])^ := PUInt32(@InData)^;
  PUInt32(@w[2])^ := PUInt32(NativeUInt(@InData) + 4)^;
  for i := 0 to 15 do
  begin
    j := i * 4;
    w[0] := LRot16((w[0] + (w[1] and (not w[3])) + (w[2] and w[3]) + KeyData[j + 0]), 1);
    w[1] := LRot16((w[1] + (w[2] and (not w[0])) + (w[3] and w[0]) + KeyData[j + 1]), 2);
    w[2] := LRot16((w[2] + (w[3] and (not w[1])) + (w[0] and w[1]) + KeyData[j + 2]), 3);
    w[3] := LRot16((w[3] + (w[0] and (not w[2])) + (w[1] and w[2]) + KeyData[j + 3]), 5);
    if (i = 4) or (i = 10) then
    begin
      w[0] := w[0] + KeyData[w[3] and 63];
      w[1] := w[1] + KeyData[w[0] and 63];
      w[2] := w[2] + KeyData[w[1] and 63];
      w[3] := w[3] + KeyData[w[2] and 63];
    end;
  end;
  PUInt32(@OutData)^ := PUInt32(@w[0])^;
  PUInt32(NativeUInt(@OutData) + 4)^ := PUInt32(@w[2])^;
end;

procedure TncEnc_rc2.DecryptECB(const InData; var OutData);
var
  i, j: longword;
  w: array [0 .. 3] of Word;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  PUInt32(@w[0])^ := PUInt32(@InData)^;
  PUInt32(@w[2])^ := PUInt32(NativeUInt(@InData) + 4)^;
  for i := 15 downto 0 do
  begin
    j := i * 4;
    w[3] := RRot16(w[3], 5) - (w[0] and (not w[2])) - (w[1] and w[2]) - KeyData[j + 3];
    w[2] := RRot16(w[2], 3) - (w[3] and (not w[1])) - (w[0] and w[1]) - KeyData[j + 2];
    w[1] := RRot16(w[1], 2) - (w[2] and (not w[0])) - (w[3] and w[0]) - KeyData[j + 1];
    w[0] := RRot16(w[0], 1) - (w[1] and (not w[3])) - (w[2] and w[3]) - KeyData[j + 0];
    if (i = 5) or (i = 11) then
    begin
      w[3] := w[3] - KeyData[w[2] and 63];
      w[2] := w[2] - KeyData[w[1] and 63];
      w[1] := w[1] - KeyData[w[0] and 63];
      w[0] := w[0] - KeyData[w[3] and 63];
    end;
  end;
  PUInt32(@OutData)^ := PUInt32(@w[0])^;
  PUInt32(NativeUInt(@OutData) + 4)^ := PUInt32(@w[2])^;
end;

end.
