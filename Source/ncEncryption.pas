{$R-}
{$O-}
unit ncEncryption;

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
  System.Classes,
  System.SysUtils,
  System.Math,
  ncEncCrypt2,
  // Ciphers:
  ncEncBlockciphers,
  ncEncRc2, ncEncRc4, ncEncRc5, ncEncRc6,
  ncEncBlowfish, ncEncTwofish,
  ncEncCast128, ncEncCast256,
  ncEncRijndael, ncEncMisty1, ncEncIdea, ncEncMars,
  ncEncIce, ncEncDes, ncEncTea, ncEncSerpent,
  // Hashers
  ncEncSha1, ncEncSha256, ncEncSha512,
  ncEncRipeMd128, ncEncRipeMd160,
  ncEncHaval, ncEncMd4, ncEncMd5, ncEncTiger;

type
  TEncryptorType = (etNoEncryption, etRc2, etRc4, etRc5, etRc6, etBlowfish, etTwoFish, etCast128, etCast256, etRijndael, etMisty1, etIdea, etMars, etIce, etThinIce, etIce2, etDES, et3DES, etTea, etSerpent);

  THasherType = (htNoDigesting, htSha1, htSha256, htSha384, htSha512, htRipeMd128, htRipeMd160, htHaval, htMd4, htMd5, htTiger);

  // Encode a AnsiString into Base64 format
  // (output is (4/3) times bigger than input)
function Base64EncodeBytes(const aBytes: TBytes): TBytes;
// Decode a Base64 format AnsiString
function Base64DecodeBytes(const aBytes: TBytes): TBytes;

// Hashing
function GetHash(const aBytes: TBytes; aHasherType: THasherType = htSha256; aBase64Encode: Boolean = True): TBytes;
function GetHashFromFile(const aFileName: string; aHasherType: THasherType = htSha256; aBase64Encode: Boolean = True): TBytes;

// Encryption
function EncryptBytes(const aBytes: TBytes; const aEncryptionKey: AnsiString = 'TheEncryptionKey'; aEncryptorType: TEncryptorType = etBlowfish; aEncryptOnHashedKey: Boolean = True; aBase64Encode: Boolean = True): TBytes;
function DecryptBytes(aBytes: TBytes; const aDecryptionKey: AnsiString = 'TheEncryptionKey'; aDecryptorType: TEncryptorType = etBlowfish; aDecryptOnHashedKey: Boolean = True; aBase64Encoded: Boolean = True): TBytes;

implementation

const
  B64: array [0 .. 63] of Byte = (65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47);

function Base64Encode(pInput: Pointer; pOutput: Pointer; Size: longint): longint;
var
  i, iptr, optr: Integer;
  Input, Output: PByteArray;
begin
  Input := PByteArray(pInput);
  Output := PByteArray(pOutput);
  iptr := 0;
  optr := 0;
  for i := 1 to (Size div 3) do
  begin
    Output^[optr + 0] := B64[Input^[iptr] shr 2];
    Output^[optr + 1] := B64[((Input^[iptr] and 3) shl 4) + (Input^[iptr + 1] shr 4)];
    Output^[optr + 2] := B64[((Input^[iptr + 1] and 15) shl 2) + (Input^[iptr + 2] shr 6)];
    Output^[optr + 3] := B64[Input^[iptr + 2] and 63];
    Inc(optr, 4);
    Inc(iptr, 3);
  end;
  case (Size mod 3) of
    1:
      begin
        Output^[optr + 0] := B64[Input^[iptr] shr 2];
        Output^[optr + 1] := B64[(Input^[iptr] and 3) shl 4];
        Output^[optr + 2] := Byte('=');
        Output^[optr + 3] := Byte('=');
      end;
    2:
      begin
        Output^[optr + 0] := B64[Input^[iptr] shr 2];
        Output^[optr + 1] := B64[((Input^[iptr] and 3) shl 4) + (Input^[iptr + 1] shr 4)];
        Output^[optr + 2] := B64[(Input^[iptr + 1] and 15) shl 2];
        Output^[optr + 3] := Byte('=');
      end;
  end;
  Result := ((Size + 2) div 3) * 4;
end;

function Base64EncodeBytes(const aBytes: TBytes): TBytes;
begin
  SetLength(Result, 0);

  SetLength(Result, ((Length(aBytes) + 2) div 3) * 4);
  Base64Encode(@aBytes[0], @Result[0], Length(aBytes));
end;

function Base64Decode(pInput: Pointer; pOutput: Pointer; Size: longint): longint;
var
  i, j, iptr, optr: Integer;
  Temp: array [0 .. 3] of Byte;
  Input, Output: PByteArray;
begin
  Input := PByteArray(pInput);
  Output := PByteArray(pOutput);
  iptr := 0;
  optr := 0;
  Result := 0;
  for i := 1 to (Size div 4) do
  begin
    for j := 0 to 3 do
    begin
      case Input^[iptr] of
        65 .. 90:
          Temp[j] := Input^[iptr] - Ord('A');
        97 .. 122:
          Temp[j] := Input^[iptr] - Ord('a') + 26;
        48 .. 57:
          Temp[j] := Input^[iptr] - Ord('0') + 52;
        43:
          Temp[j] := 62;
        47:
          Temp[j] := 63;
        61:
          Temp[j] := $FF;
      end;
      Inc(iptr);
    end;
    Output^[optr] := (Temp[0] shl 2) or (Temp[1] shr 4);
    Result := optr + 1;
    if (Temp[2] <> $FF) and (Temp[3] = $FF) then
    begin
      Output^[optr + 1] := (Temp[1] shl 4) or (Temp[2] shr 2);
      Result := optr + 2;
      Inc(optr);
    end
    else if (Temp[2] <> $FF) then
    begin
      Output^[optr + 1] := (Temp[1] shl 4) or (Temp[2] shr 2);
      Output^[optr + 2] := (Temp[2] shl 6) or Temp[3];
      Result := optr + 3;
      Inc(optr, 2);
    end;
    Inc(optr);
  end;
end;

function Base64DecodeBytes(const aBytes: TBytes): TBytes;
begin
  SetLength(Result, 0);

  SetLength(Result, (Length(aBytes) div 4) * 3);
  SetLength(Result, Base64Decode(@aBytes[0], @Result[0], Length(aBytes)));
end;

function GetHash(const aBytes: TBytes; aHasherType: THasherType = htSha256; aBase64Encode: Boolean = True): TBytes;
var
  Hash: TncEncHash;
  Digest: PByte;
begin
  // Create unique hash
  case aHasherType of
    htSha1:
      Hash := TncEnc_sha1.Create(nil);
    htSha256:
      Hash := TncEnc_sha256.Create(nil);
    htSha384:
      Hash := TncEnc_sha384.Create(nil);
    htSha512:
      Hash := TncEnc_sha512.Create(nil);
    htRipeMd128:
      Hash := TncEnc_RipeMd128.Create(nil);
    htRipeMd160:
      Hash := TncEnc_RipeMd160.Create(nil);
    htHaval:
      Hash := TncEnc_Haval.Create(nil);
    htMd4:
      Hash := TncEnc_Md4.Create(nil);
    htMd5:
      Hash := TncEnc_Md5.Create(nil);
    htTiger:
      Hash := TncEnc_Tiger.Create(nil);
  else
    Hash := nil;
  end;

  if Hash = nil then
    Result := aBytes
  else
    try
      Hash.Init;
      Hash.Update(aBytes[0], Length(aBytes));
      GetMem(Digest, Hash.HashSize div 8);
      try
        Hash.Final(Digest^);
        SetLength(Result, (Hash.HashSize div 8));
        move(Digest^, Result[0], Length(Result));

        if aBase64Encode then
          Result := Base64EncodeBytes(Result);
      finally
        FreeMem(Digest, Hash.HashSize div 8);
      end;
    finally
      Hash.Free;
    end;
end;

function GetHashFromFile(const aFileName: string; aHasherType: THasherType = htSha256; aBase64Encode: Boolean = True): TBytes;
var
  fs: TFileStream;
  FileBytes: TBytes;
begin
  fs := TFileStream.Create(aFileName, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(FileBytes, fs.Size);
    fs.Read(FileBytes[0], fs.Size);
  finally
    fs.Free;
  end;

  Result := GetHash(FileBytes, aHasherType, aBase64Encode);
end;

function EncryptBytes(const aBytes: TBytes; const aEncryptionKey: AnsiString = 'TheEncryptionKey'; aEncryptorType: TEncryptorType = etBlowfish; aEncryptOnHashedKey: Boolean = True; aBase64Encode: Boolean = True): TBytes;
var
  Encryptor: TncEncCipher;
begin
  case aEncryptorType of
    etRc2:
      Encryptor := TncEnc_Rc2.Create(nil);
    etRc4:
      Encryptor := TncEnc_Rc4.Create(nil);
    etRc5:
      Encryptor := TncEnc_Rc5.Create(nil);
    etRc6:
      Encryptor := TncEnc_Rc6.Create(nil);
    etBlowfish:
      Encryptor := TncEnc_blowfish.Create(nil);
    etTwoFish:
      Encryptor := TncEnc_TwoFish.Create(nil);
    etCast128:
      Encryptor := TncEnc_cast128.Create(nil);
    etCast256:
      Encryptor := TncEnc_cast256.Create(nil);
    etRijndael:
      Encryptor := TncEnc_Rijndael.Create(nil);
    etMisty1:
      Encryptor := TncEnc_Misty1.Create(nil);
    etIdea:
      Encryptor := TncEnc_Idea.Create(nil);
    etMars:
      Encryptor := TncEnc_Mars.Create(nil);
    etIce:
      Encryptor := TncEnc_Ice.Create(nil);
    etThinIce:
      Encryptor := TncEnc_ThinIce.Create(nil);
    etIce2:
      Encryptor := TncEnc_Ice2.Create(nil);
    etDES:
      Encryptor := TncEnc_DES.Create(nil);
    et3DES:
      Encryptor := TncEnc_3DES.Create(nil);
    etTea:
      Encryptor := TncEnc_Tea.Create(nil);
    etSerpent:
      Encryptor := TncEnc_Serpent.Create(nil);
  else
    Encryptor := nil;
  end;

  if Encryptor = nil then
    Result := aBytes
  else
    try
      if aEncryptOnHashedKey then
        Encryptor.InitStr(aEncryptionKey, TncEnc_sha256)
      else
        Encryptor.Init(aEncryptionKey[1], min(Length(aEncryptionKey) * 8, Encryptor.MaxKeySize), nil);

      SetLength(Result, Length(aBytes));
      Encryptor.Encrypt(aBytes[0], Result[0], Length(aBytes));

      if aBase64Encode then
        Result := Base64EncodeBytes(Result);

      Encryptor.Burn; // clear keying information
    finally
      Encryptor.Free;
    end;
end;

function DecryptBytes(aBytes: TBytes; const aDecryptionKey: AnsiString = 'TheEncryptionKey'; aDecryptorType: TEncryptorType = etBlowfish; aDecryptOnHashedKey: Boolean = True; aBase64Encoded: Boolean = True): TBytes;
var
  Decryptor: TncEncCipher;
begin
  case aDecryptorType of
    etRc2:
      Decryptor := TncEnc_Rc2.Create(nil);
    etRc4:
      Decryptor := TncEnc_Rc4.Create(nil);
    etRc5:
      Decryptor := TncEnc_Rc5.Create(nil);
    etRc6:
      Decryptor := TncEnc_Rc6.Create(nil);
    etBlowfish:
      Decryptor := TncEnc_blowfish.Create(nil);
    etTwoFish:
      Decryptor := TncEnc_TwoFish.Create(nil);
    etCast128:
      Decryptor := TncEnc_cast128.Create(nil);
    etCast256:
      Decryptor := TncEnc_cast256.Create(nil);
    etRijndael:
      Decryptor := TncEnc_Rijndael.Create(nil);
    etMisty1:
      Decryptor := TncEnc_Misty1.Create(nil);
    etIdea:
      Decryptor := TncEnc_Idea.Create(nil);
    etMars:
      Decryptor := TncEnc_Mars.Create(nil);
    etIce:
      Decryptor := TncEnc_Ice.Create(nil);
    etThinIce:
      Decryptor := TncEnc_ThinIce.Create(nil);
    etIce2:
      Decryptor := TncEnc_Ice2.Create(nil);
    etDES:
      Decryptor := TncEnc_DES.Create(nil);
    et3DES:
      Decryptor := TncEnc_3DES.Create(nil);
    etTea:
      Decryptor := TncEnc_Tea.Create(nil);
    etSerpent:
      Decryptor := TncEnc_Serpent.Create(nil);
  else
    Decryptor := nil;
  end;

  if Decryptor = nil then
    Result := aBytes
  else
    try
      if aDecryptOnHashedKey then
        Decryptor.InitStr(aDecryptionKey, TncEnc_sha256)
      else
        Decryptor.Init(aDecryptionKey[1], min(Length(aDecryptionKey) * 8, Decryptor.MaxKeySize), nil);

      if aBase64Encoded then
        aBytes := Base64DecodeBytes(aBytes);

      SetLength(Result, Length(aBytes));
      Decryptor.Decrypt(aBytes[0], Result[0], Length(aBytes));

      Decryptor.Burn; // clear keying information
    finally
      Decryptor.Free;
    end;
end;

end.
