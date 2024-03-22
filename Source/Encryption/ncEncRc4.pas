{$R-}
{$Q-}
unit ncEncRc4;

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
  TncEnc_rc4 = class(TncEncCipher)
  protected
    KeyData, KeyOrg: array [0 .. 255] of Byte;
  public
    class function GetAlgorithm: string; override;
    class function GetMaxKeySize: Integer; override;
    class function SelfTest: Boolean; override;
    procedure Init(const Key; Size: NativeUInt; InitVector: Pointer); override;
    procedure Reset; override;
    procedure Burn; override;
    procedure Encrypt(const InData; var OutData; Size: NativeUInt); override;
    procedure Decrypt(const InData; var OutData; Size: NativeUInt); override;
  end;

  { ****************************************************************************** }
  { ****************************************************************************** }
implementation

uses ncEncryption;

class function TncEnc_rc4.GetAlgorithm: string;
begin
  Result := 'RC4';
end;

class function TncEnc_rc4.GetMaxKeySize: Integer;
begin
  Result := 2048;
end;

class function TncEnc_rc4.SelfTest: Boolean;
const
  Key1: array [0 .. 4] of Byte = ($61, $8A, $63, $D2, $FB);
  InData1: array [0 .. 4] of Byte = ($DC, $EE, $4C, $F9, $2C);
  OutData1: array [0 .. 4] of Byte = ($F1, $38, $29, $C9, $DE);
var
  Cipher: TncEnc_rc4;
  Data: array [0 .. 4] of Byte;
begin
  Cipher := TncEnc_rc4.Create(nil);
  Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
  Cipher.Encrypt(InData1, Data, Sizeof(Data));
  Result := Boolean(CompareMem(@Data, @OutData1, Sizeof(Data)));
  Cipher.Reset;
  Cipher.Decrypt(Data, Data, Sizeof(Data));
  Result := Boolean(CompareMem(@Data, @InData1, Sizeof(Data))) and Result;
  Cipher.Burn;
  Cipher.Free;
end;

procedure TncEnc_rc4.Init(const Key; Size: NativeUInt; InitVector: Pointer);
var
  i, j, t: NativeUInt;
  xKey: array [0 .. 255] of Byte;
begin
  if FInitialized then
    Burn;
  inherited Init(Key, Size, nil);
  Size := Size div 8;
  i := 0;
  while i < 255 do
  begin
    KeyData[i] := i;
    xKey[i] := PByte(NativeUInt(@Key) + (i mod Size))^;
    KeyData[i + 1] := i + 1;
    xKey[i + 1] := PByte(NativeUInt(@Key) + ((i + 1) mod Size))^;
    KeyData[i + 2] := i + 2;
    xKey[i + 2] := PByte(NativeUInt(@Key) + ((i + 2) mod Size))^;
    KeyData[i + 3] := i + 3;
    xKey[i + 3] := PByte(NativeUInt(@Key) + ((i + 3) mod Size))^;
    KeyData[i + 4] := i + 4;
    xKey[i + 4] := PByte(NativeUInt(@Key) + ((i + 4) mod Size))^;
    KeyData[i + 5] := i + 5;
    xKey[i + 5] := PByte(NativeUInt(@Key) + ((i + 5) mod Size))^;
    KeyData[i + 6] := i + 6;
    xKey[i + 6] := PByte(NativeUInt(@Key) + ((i + 6) mod Size))^;
    KeyData[i + 7] := i + 7;
    xKey[i + 7] := PByte(NativeUInt(@Key) + ((i + 7) mod Size))^;
    Inc(i, 8);
  end;
  j := 0;
  i := 0;
  while i < 255 do
  begin
    j := (j + KeyData[i] + xKey[i]) and $FF;
    t := KeyData[i];
    KeyData[i] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 1] + xKey[i + 1]) and $FF;
    t := KeyData[i + 1];
    KeyData[i + 1] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 2] + xKey[i + 2]) and $FF;
    t := KeyData[i + 2];
    KeyData[i + 2] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 3] + xKey[i + 3]) and $FF;
    t := KeyData[i + 3];
    KeyData[i + 3] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 4] + xKey[i + 4]) and $FF;
    t := KeyData[i + 4];
    KeyData[i + 4] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 5] + xKey[i + 5]) and $FF;
    t := KeyData[i + 5];
    KeyData[i + 5] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 6] + xKey[i + 6]) and $FF;
    t := KeyData[i + 6];
    KeyData[i + 6] := KeyData[j];
    KeyData[j] := t;
    j := (j + KeyData[i + 7] + xKey[i + 7]) and $FF;
    t := KeyData[i + 7];
    KeyData[i + 7] := KeyData[j];
    KeyData[j] := t;
    Inc(i, 8);
  end;
  Move(KeyData, KeyOrg, Sizeof(KeyOrg));
end;

procedure TncEnc_rc4.Reset;
begin
  Move(KeyOrg, KeyData, Sizeof(KeyData));
end;

procedure TncEnc_rc4.Burn;
begin
  FillChar(KeyOrg, Sizeof(KeyOrg), $FF);
  FillChar(KeyData, Sizeof(KeyData), $FF);
  inherited Burn;
end;

procedure TncEnc_rc4.Encrypt(const InData; var OutData; Size: NativeUInt);
var
  i, j, t, k: longword;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  i := 0;
  j := 0;
  for k := 0 to Size - 1 do
  begin
    i := (i + 1) and $FF;
    t := KeyData[i];
    j := (j + t) and $FF;
    KeyData[i] := KeyData[j];
    KeyData[j] := t;
    t := (t + KeyData[i]) and $FF;
    Pbytearray(@OutData)^[k] := Pbytearray(@InData)^[k] xor KeyData[t];
  end;
end;

procedure TncEnc_rc4.Decrypt(const InData; var OutData; Size: NativeUInt);
var
  i, j, t, k: longword;
begin
  if not FInitialized then
    raise EEncBlockcipherException.Create(rsCipherNotInitialised);
  i := 0;
  j := 0;
  for k := 0 to Size - 1 do
  begin
    i := (i + 1) and $FF;
    t := KeyData[i];
    j := (j + t) and $FF;
    KeyData[i] := KeyData[j];
    KeyData[j] := t;
    t := (t + KeyData[i]) and $FF;
    Pbytearray(@OutData)^[k] := Pbytearray(@InData)^[k] xor KeyData[t];
  end;
end;

end.
