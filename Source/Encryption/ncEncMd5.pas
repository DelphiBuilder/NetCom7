{$R-}
{$Q-}
unit ncEncMd5;

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
  TncEnc_md5 = class(TncEncHash)
  protected
    LenHi, LenLo: UInt32;
    Index: UInt32;
    CurrentHash: array [0 .. 3] of UInt32;
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

function LRot32(const AVal: UInt32; AShift: Byte): UInt32; inline;
begin
  Result := (AVal shl AShift) or (AVal shr (32 - AShift));
end;

procedure TncEnc_md5.Compress;
var
  Data: array [0 .. 15] of UInt32;
  A, B, C, D: UInt32;
begin
  Move(HashBuffer, Data, Sizeof(Data));
  A := CurrentHash[0];
  B := CurrentHash[1];
  C := CurrentHash[2];
  D := CurrentHash[3];

  A := B + LRot32(A + (D xor (B and (C xor D))) + Data[0] + $D76AA478, 7);
  D := A + LRot32(D + (C xor (A and (B xor C))) + Data[1] + $E8C7B756, 12);
  C := D + LRot32(C + (B xor (D and (A xor B))) + Data[2] + $242070DB, 17);
  B := C + LRot32(B + (A xor (C and (D xor A))) + Data[3] + $C1BDCEEE, 22);
  A := B + LRot32(A + (D xor (B and (C xor D))) + Data[4] + $F57C0FAF, 7);
  D := A + LRot32(D + (C xor (A and (B xor C))) + Data[5] + $4787C62A, 12);
  C := D + LRot32(C + (B xor (D and (A xor B))) + Data[6] + $A8304613, 17);
  B := C + LRot32(B + (A xor (C and (D xor A))) + Data[7] + $FD469501, 22);
  A := B + LRot32(A + (D xor (B and (C xor D))) + Data[8] + $698098D8, 7);
  D := A + LRot32(D + (C xor (A and (B xor C))) + Data[9] + $8B44F7AF, 12);
  C := D + LRot32(C + (B xor (D and (A xor B))) + Data[10] + $FFFF5BB1, 17);
  B := C + LRot32(B + (A xor (C and (D xor A))) + Data[11] + $895CD7BE, 22);
  A := B + LRot32(A + (D xor (B and (C xor D))) + Data[12] + $6B901122, 7);
  D := A + LRot32(D + (C xor (A and (B xor C))) + Data[13] + $FD987193, 12);
  C := D + LRot32(C + (B xor (D and (A xor B))) + Data[14] + $A679438E, 17);
  B := C + LRot32(B + (A xor (C and (D xor A))) + Data[15] + $49B40821, 22);

  A := B + LRot32(A + (C xor (D and (B xor C))) + Data[1] + $F61E2562, 5);
  D := A + LRot32(D + (B xor (C and (A xor B))) + Data[6] + $C040B340, 9);
  C := D + LRot32(C + (A xor (B and (D xor A))) + Data[11] + $265E5A51, 14);
  B := C + LRot32(B + (D xor (A and (C xor D))) + Data[0] + $E9B6C7AA, 20);
  A := B + LRot32(A + (C xor (D and (B xor C))) + Data[5] + $D62F105D, 5);
  D := A + LRot32(D + (B xor (C and (A xor B))) + Data[10] + $02441453, 9);
  C := D + LRot32(C + (A xor (B and (D xor A))) + Data[15] + $D8A1E681, 14);
  B := C + LRot32(B + (D xor (A and (C xor D))) + Data[4] + $E7D3FBC8, 20);
  A := B + LRot32(A + (C xor (D and (B xor C))) + Data[9] + $21E1CDE6, 5);
  D := A + LRot32(D + (B xor (C and (A xor B))) + Data[14] + $C33707D6, 9);
  C := D + LRot32(C + (A xor (B and (D xor A))) + Data[3] + $F4D50D87, 14);
  B := C + LRot32(B + (D xor (A and (C xor D))) + Data[8] + $455A14ED, 20);
  A := B + LRot32(A + (C xor (D and (B xor C))) + Data[13] + $A9E3E905, 5);
  D := A + LRot32(D + (B xor (C and (A xor B))) + Data[2] + $FCEFA3F8, 9);
  C := D + LRot32(C + (A xor (B and (D xor A))) + Data[7] + $676F02D9, 14);
  B := C + LRot32(B + (D xor (A and (C xor D))) + Data[12] + $8D2A4C8A, 20);

  A := B + LRot32(A + (B xor C xor D) + Data[5] + $FFFA3942, 4);
  D := A + LRot32(D + (A xor B xor C) + Data[8] + $8771F681, 11);
  C := D + LRot32(C + (D xor A xor B) + Data[11] + $6D9D6122, 16);
  B := C + LRot32(B + (C xor D xor A) + Data[14] + $FDE5380C, 23);
  A := B + LRot32(A + (B xor C xor D) + Data[1] + $A4BEEA44, 4);
  D := A + LRot32(D + (A xor B xor C) + Data[4] + $4BDECFA9, 11);
  C := D + LRot32(C + (D xor A xor B) + Data[7] + $F6BB4B60, 16);
  B := C + LRot32(B + (C xor D xor A) + Data[10] + $BEBFBC70, 23);
  A := B + LRot32(A + (B xor C xor D) + Data[13] + $289B7EC6, 4);
  D := A + LRot32(D + (A xor B xor C) + Data[0] + $EAA127FA, 11);
  C := D + LRot32(C + (D xor A xor B) + Data[3] + $D4EF3085, 16);
  B := C + LRot32(B + (C xor D xor A) + Data[6] + $04881D05, 23);
  A := B + LRot32(A + (B xor C xor D) + Data[9] + $D9D4D039, 4);
  D := A + LRot32(D + (A xor B xor C) + Data[12] + $E6DB99E5, 11);
  C := D + LRot32(C + (D xor A xor B) + Data[15] + $1FA27CF8, 16);
  B := C + LRot32(B + (C xor D xor A) + Data[2] + $C4AC5665, 23);

  A := B + LRot32(A + (C xor (B or (not D))) + Data[0] + $F4292244, 6);
  D := A + LRot32(D + (B xor (A or (not C))) + Data[7] + $432AFF97, 10);
  C := D + LRot32(C + (A xor (D or (not B))) + Data[14] + $AB9423A7, 15);
  B := C + LRot32(B + (D xor (C or (not A))) + Data[5] + $FC93A039, 21);
  A := B + LRot32(A + (C xor (B or (not D))) + Data[12] + $655B59C3, 6);
  D := A + LRot32(D + (B xor (A or (not C))) + Data[3] + $8F0CCC92, 10);
  C := D + LRot32(C + (A xor (D or (not B))) + Data[10] + $FFEFF47D, 15);
  B := C + LRot32(B + (D xor (C or (not A))) + Data[1] + $85845DD1, 21);
  A := B + LRot32(A + (C xor (B or (not D))) + Data[8] + $6FA87E4F, 6);
  D := A + LRot32(D + (B xor (A or (not C))) + Data[15] + $FE2CE6E0, 10);
  C := D + LRot32(C + (A xor (D or (not B))) + Data[6] + $A3014314, 15);
  B := C + LRot32(B + (D xor (C or (not A))) + Data[13] + $4E0811A1, 21);
  A := B + LRot32(A + (C xor (B or (not D))) + Data[4] + $F7537E82, 6);
  D := A + LRot32(D + (B xor (A or (not C))) + Data[11] + $BD3AF235, 10);
  C := D + LRot32(C + (A xor (D or (not B))) + Data[2] + $2AD7D2BB, 15);
  B := C + LRot32(B + (D xor (C or (not A))) + Data[9] + $EB86D391, 21);

  Inc(CurrentHash[0], A);
  Inc(CurrentHash[1], B);
  Inc(CurrentHash[2], C);
  Inc(CurrentHash[3], D);
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
end;

class function TncEnc_md5.GetHashSize: Integer;
begin
  Result := 128;
end;

class function TncEnc_md5.GetAlgorithm: string;
begin
  Result := 'MD5';
end;

class function TncEnc_md5.SelfTest: Boolean;
const
  Test1Out: array [0 .. 15] of Byte = ($90, $01, $50, $98, $3C, $D2, $4F, $B0, $D6, $96, $3F, $7D, $28, $E1, $7F, $72);
  Test2Out: array [0 .. 15] of Byte = ($C3, $FC, $D3, $D7, $61, $92, $E4, $00, $7D, $FB, $49, $6C, $CA, $67, $E1, $3B);
var
  TestHash: TncEnc_md5;
  TestOut: array [0 .. 19] of Byte;
begin
  TestHash := TncEnc_md5.Create(nil);
  TestHash.Init;
  TestHash.UpdateStr('abc');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test1Out, Sizeof(Test1Out));
  TestHash.Init;
  TestHash.UpdateStr('abcdefghijklmnopqrstuvwxyz');
  TestHash.Final(TestOut);
  Result := CompareMem(@TestOut, @Test2Out, Sizeof(Test2Out)) and Result;
  TestHash.Free;
end;

procedure TncEnc_md5.Init;
begin
  Burn;
  CurrentHash[0] := $67452301;
  CurrentHash[1] := $EFCDAB89;
  CurrentHash[2] := $98BADCFE;
  CurrentHash[3] := $10325476;
  FInitialized := true;
end;

procedure TncEnc_md5.Burn;
begin
  LenHi := 0;
  LenLo := 0;
  Index := 0;
  FillChar(HashBuffer, Sizeof(HashBuffer), 0);
  FillChar(CurrentHash, Sizeof(CurrentHash), 0);
  FInitialized := false;
end;

procedure TncEnc_md5.Update(const Buffer; Size: NativeUInt);
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

procedure TncEnc_md5.Final(var Digest);
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
