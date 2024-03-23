{$R-}
{$Q-}
unit ncEncMisty1;

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
  System.Classes, System.Sysutils, ncEnccrypt2, ncEncblockciphers;

const
  NUMROUNDS = 8;

type
  TncEnc_misty1 = class(TncEnc_blockcipher64)
  protected
    KeyData: array [0 .. 31] of UInt32;
    function FI(const FI_IN, FI_KEY: UInt32): UInt32;
    function FO(const FO_IN: UInt32; const k: longword): UInt32; inline;
    function FL(const FL_IN: UInt32; const k: longword): UInt32; inline;
    function FLINV(const FL_IN: UInt32; const k: longword): UInt32; inline;
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
  S7TABLE: array [0 .. $7F] of Byte = ($1B, $32, $33, $5A, $3B, $10, $17, $54, $5B, $1A, $72, $73, $6B, $2C, $66, $49, $1F, $24, $13, $6C, $37, $2E, $3F, $4A, $5D, $0F, $40, $56, $25, $51, $1C, $04, $0B, $46, $20, $0D, $7B, $35, $44, $42, $2B, $1E, $41, $14, $4B, $79, $15, $6F, $0E, $55, $09, $36, $74, $0C, $67, $53,
    $28, $0A, $7E, $38, $02, $07, $60, $29, $19, $12, $65, $2F, $30, $39, $08, $68, $5F, $78, $2A, $4C, $64, $45, $75, $3D, $59, $48, $03, $57, $7C, $4F, $62, $3C, $1D, $21, $5E, $27, $6A, $70, $4D, $3A, $01, $6D, $6E, $63, $18, $77, $23, $05, $26, $76, $00, $31, $2D, $7A, $7F, $61, $50, $22, $11, $06, $47, $16, $52,
    $4E, $71, $3E, $69, $43, $34, $5C, $58, $7D);

  S9TABLE: array [0 .. $1FF] of UInt32 = ($1C3, $0CB, $153, $19F, $1E3, $0E9, $0FB, $035, $181, $0B9, $117, $1EB, $133, $009, $02D, $0D3, $0C7, $14A, $037, $07E, $0EB, $164, $193, $1D8, $0A3, $11E, $055, $02C, $01D, $1A2, $163, $118, $14B, $152, $1D2, $00F, $02B, $030, $13A, $0E5, $111, $138, $18E, $063, $0E3, $0C8,
    $1F4, $01B, $001, $09D, $0F8, $1A0, $16D, $1F3, $01C, $146, $07D, $0D1, $082, $1EA, $183, $12D, $0F4, $19E, $1D3, $0DD, $1E2, $128, $1E0, $0EC, $059, $091, $011, $12F, $026, $0DC, $0B0, $18C, $10F, $1F7, $0E7, $16C, $0B6, $0F9, $0D8, $151, $101, $14C, $103, $0B8, $154, $12B, $1AE, $017, $071, $00C, $047, $058,
    $07F, $1A4, $134, $129, $084, $15D, $19D, $1B2, $1A3, $048, $07C, $051, $1CA, $023, $13D, $1A7, $165, $03B, $042, $0DA, $192, $0CE, $0C1, $06B, $09F, $1F1, $12C, $184, $0FA, $196, $1E1, $169, $17D, $031, $180, $10A, $094, $1DA, $186, $13E, $11C, $060, $175, $1CF, $067, $119, $065, $068, $099, $150, $008, $007,
    $17C, $0B7, $024, $019, $0DE, $127, $0DB, $0E4, $1A9, $052, $109, $090, $19C, $1C1, $028, $1B3, $135, $16A, $176, $0DF, $1E5, $188, $0C5, $16E, $1DE, $1B1, $0C3, $1DF, $036, $0EE, $1EE, $0F0, $093, $049, $09A, $1B6, $069, $081, $125, $00B, $05E, $0B4, $149, $1C7, $174, $03E, $13B, $1B7, $08E, $1C6, $0AE, $010,
    $095, $1EF, $04E, $0F2, $1FD, $085, $0FD, $0F6, $0A0, $16F, $083, $08A, $156, $09B, $13C, $107, $167, $098, $1D0, $1E9, $003, $1FE, $0BD, $122, $089, $0D2, $18F, $012, $033, $06A, $142, $0ED, $170, $11B, $0E2, $14F, $158, $131, $147, $05D, $113, $1CD, $079, $161, $1A5, $179, $09E, $1B4, $0CC, $022, $132, $01A,
    $0E8, $004, $187, $1ED, $197, $039, $1BF, $1D7, $027, $18B, $0C6, $09C, $0D0, $14E, $06C, $034, $1F2, $06E, $0CA, $025, $0BA, $191, $0FE, $013, $106, $02F, $1AD, $172, $1DB, $0C0, $10B, $1D6, $0F5, $1EC, $10D, $076, $114, $1AB, $075, $10C, $1E4, $159, $054, $11F, $04B, $0C4, $1BE, $0F7, $029, $0A4, $00E, $1F0,
    $077, $04D, $17A, $086, $08B, $0B3, $171, $0BF, $10E, $104, $097, $15B, $160, $168, $0D7, $0BB, $066, $1CE, $0FC, $092, $1C5, $06F, $016, $04A, $0A1, $139, $0AF, $0F1, $190, $00A, $1AA, $143, $17B, $056, $18D, $166, $0D4, $1FB, $14D, $194, $19A, $087, $1F8, $123, $0A7, $1B8, $141, $03C, $1F9, $140, $02A, $155,
    $11A, $1A1, $198, $0D5, $126, $1AF, $061, $12E, $157, $1DC, $072, $18A, $0AA, $096, $115, $0EF, $045, $07B, $08D, $145, $053, $05F, $178, $0B2, $02E, $020, $1D5, $03F, $1C9, $1E7, $1AC, $044, $038, $014, $0B1, $16B, $0AB, $0B5, $05A, $182, $1C8, $1D4, $018, $177, $064, $0CF, $06D, $100, $199, $130, $15A, $005,
    $120, $1BB, $1BD, $0E0, $04F, $0D6, $13F, $1C4, $12A, $015, $006, $0FF, $19B, $0A6, $043, $088, $050, $15F, $1E8, $121, $073, $17E, $0BC, $0C2, $0C9, $173, $189, $1F5, $074, $1CC, $1E6, $1A8, $195, $01F, $041, $00D, $1BA, $032, $03D, $1D1, $080, $0A8, $057, $1B9, $162, $148, $0D9, $105, $062, $07A, $021, $1FF,
    $112, $108, $1C0, $0A9, $11D, $1B0, $1A6, $0CD, $0F3, $05C, $102, $05B, $1D9, $144, $1F6, $0AD, $0A5, $03A, $1CB, $136, $17F, $046, $0E1, $01E, $1DD, $0E6, $137, $1FA, $185, $08C, $08F, $040, $1B5, $0BE, $078, $000, $0AC, $110, $15E, $124, $002, $1BC, $0A2, $0EA, $070, $1FC, $116, $15C, $04C, $1C2);

function SwapUInt32(const a: UInt32): UInt32; inline;
begin
  Result := ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

class function TncEnc_misty1.GetAlgorithm: string;
begin
  Result := 'Misty1';
end;

class function TncEnc_misty1.GetMaxKeySize: Integer;
begin
  Result := 128;
end;

class function TncEnc_misty1.SelfTest: Boolean;
const
  Key: array [0 .. 15] of Byte = ($00, $11, $22, $33, $44, $55, $66, $77, $88, $99, $AA, $BB, $CC, $DD, $EE, $FF);
  Plain1: array [0 .. 7] of Byte = ($01, $23, $45, $67, $89, $AB, $CD, $EF);
  Plain2: array [0 .. 7] of Byte = ($FE, $DC, $BA, $98, $76, $54, $32, $10);
  Cipher1: array [0 .. 7] of Byte = ($8B, $1D, $A5, $F5, $6A, $B3, $D0, $7C);
  Cipher2: array [0 .. 7] of Byte = ($04, $B6, $82, $40, $B1, $3B, $E9, $5D);
var
  Cipher: TncEnc_misty1;
  Block: array [0 .. 7] of Byte;
begin
  Cipher := TncEnc_misty1.Create(nil);
  Cipher.Init(Key, Sizeof(Key) * 8, nil);
  Cipher.EncryptECB(Plain1, Block);
  Result := CompareMem(@Cipher1, @Block, Sizeof(Block));
  Cipher.DecryptECB(Block, Block);
  Result := Result and CompareMem(@Plain1, @Block, Sizeof(Block));
  Cipher.EncryptECB(Plain2, Block);
  Result := Result and CompareMem(@Cipher2, @Block, Sizeof(Block));
  Cipher.DecryptECB(Block, Block);
  Result := Result and CompareMem(@Plain2, @Block, Sizeof(Block));
  Cipher.Burn;
  Cipher.Free;
end;

function TncEnc_misty1.FI(const FI_IN, FI_KEY: UInt32): UInt32;
var
  d7, d9: UInt32;
begin
  d9 := (FI_IN shr 7) and $1FF;
  d7 := FI_IN and $7F;
  d9 := S9TABLE[d9] xor d7;
  d7 := (S7TABLE[d7] xor d9) and $7F;
  d7 := d7 xor ((FI_KEY shr 9) and $7F);
  d9 := d9 xor (FI_KEY and $1FF);
  d9 := S9TABLE[d9] xor d7;
  Result := (d7 shl 9) or d9;
end;

function TncEnc_misty1.FO(const FO_IN: UInt32; const k: longword): UInt32;
var
  t0, t1: UInt32;
begin
  t0 := FO_IN shr 16;
  t1 := FO_IN and $FFFF;
  t0 := t0 xor KeyData[k];
  t0 := FI(t0, KeyData[((k + 5) mod 8) + 8]);
  t0 := t0 xor t1;
  t1 := t1 xor KeyData[(k + 2) mod 8];
  t1 := FI(t1, KeyData[((k + 1) mod 8) + 8]);
  t1 := t1 xor t0;
  t0 := t0 xor KeyData[(k + 7) mod 8];
  t0 := FI(t0, KeyData[((k + 3) mod 8) + 8]);
  t0 := t0 xor t1;
  t1 := t1 xor KeyData[(k + 4) mod 8];
  Result := (t1 shl 16) or t0;
end;

function TncEnc_misty1.FL(const FL_IN: UInt32; const k: longword): UInt32;
var
  d0, d1: UInt32;
  t: Byte;
begin
  d0 := FL_IN shr 16;
  d1 := FL_IN and $FFFF;
  if (k mod 2) <> 0 then
  begin
    t := (k - 1) div 2;
    d1 := d1 xor (d0 and KeyData[((t + 2) mod 8) + 8]);
    d0 := d0 xor (d1 or KeyData[(t + 4) mod 8]);
  end
  else
  begin
    t := k div 2;
    d1 := d1 xor (d0 and KeyData[t]);
    d0 := d0 xor (d1 or KeyData[((t + 6) mod 8) + 8]);
  end;
  Result := (d0 shl 16) or d1;
end;

function TncEnc_misty1.FLINV(const FL_IN: UInt32; const k: longword): UInt32;
var
  d0, d1: UInt32;
  t: Byte;
begin
  d0 := FL_IN shr 16;
  d1 := FL_IN and $FFFF;
  if (k mod 2) <> 0 then
  begin
    t := (k - 1) div 2;
    d0 := d0 xor (d1 or KeyData[(t + 4) mod 8]);
    d1 := d1 xor (d0 and KeyData[((t + 2) mod 8) + 8]);
  end
  else
  begin
    t := k div 2;
    d0 := d0 xor (d1 or KeyData[((t + 6) mod 8) + 8]);
    d1 := d1 xor (d0 and KeyData[t]);
  end;
  Result := (d0 shl 16) or d1;
end;

procedure TncEnc_misty1.InitKey(const Key; Size: longword);
var
  KeyB: array [0 .. 15] of Byte;
  i: longword;
begin
  FillChar(KeyB, Sizeof(KeyB), 0);
  Move(Key, KeyB, Size div 8);
  for i := 0 to 7 do
    KeyData[i] := (KeyB[i * 2] * 256) + KeyB[i * 2 + 1];
  for i := 0 to 7 do
  begin
    KeyData[i + 8] := FI(KeyData[i], KeyData[(i + 1) mod 8]);
    KeyData[i + 16] := KeyData[i + 8] and $1FF;
    KeyData[i + 24] := KeyData[i + 8] shr 9;
  end;
end;

procedure TncEnc_misty1.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), 0);
  inherited Burn;
end;

procedure TncEnc_misty1.EncryptECB(const InData; var OutData);
var
  d0, d1: UInt32;
  i: longword;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  d0 := SwapUInt32(PUInt32(@InData)^);
  d1 := SwapUInt32(PUInt32(NativeUInt(@InData) + 4)^);
  for i := 0 to NUMROUNDS - 1 do
  begin
    if (i mod 2) = 0 then
    begin
      d0 := FL(d0, i);
      d1 := FL(d1, i + 1);
      d1 := d1 xor FO(d0, i);
    end
    else
      d0 := d0 xor FO(d1, i);
  end;
  d0 := FL(d0, NUMROUNDS);
  d1 := FL(d1, NUMROUNDS + 1);
  PUInt32(@OutData)^ := SwapUInt32(d1);
  PUInt32(NativeUInt(@OutData) + 4)^ := SwapUInt32(d0);
end;

procedure TncEnc_misty1.DecryptECB(const InData; var OutData);
var
  d0, d1: UInt32;
  i: longword;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  d1 := SwapUInt32(PUInt32(@InData)^);
  d0 := SwapUInt32(PUInt32(NativeUInt(@InData) + 4)^);
  d1 := FLINV(d1, NUMROUNDS + 1);
  d0 := FLINV(d0, NUMROUNDS);
  for i := NUMROUNDS - 1 downto 0 do
  begin
    if (i mod 2) = 0 then
    begin
      d1 := d1 xor FO(d0, i);
      d0 := FLINV(d0, i);
      d1 := FLINV(d1, i + 1);
    end
    else
      d0 := d0 xor FO(d1, i);
  end;
  PUInt32(@OutData)^ := SwapUInt32(d0);
  PUInt32(NativeUInt(@OutData) + 4)^ := SwapUInt32(d1);
end;

end.
