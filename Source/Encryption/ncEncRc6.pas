{$R-}
{$Q-}
unit ncEncRc6;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

  uses
    Classes, Sysutils, ncEnccrypt2, ncEncblockciphers;

  const
    NUMROUNDS = 20; { number of rounds must be between 16-24 }

  type
    TncEnc_rc6 = class(TncEnc_blockcipher128)
    protected
      KeyData: array [0 .. ((NUMROUNDS * 2) + 3)] of DWord;
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
    sBox: array [0 .. 51] of DWord = ($B7E15163, $5618CB1C, $F45044D5, $9287BE8E, $30BF3847, $CEF6B200, $6D2E2BB9, $0B65A572, $A99D1F2B, $47D498E4, $E60C129D,
      $84438C56, $227B060F, $C0B27FC8, $5EE9F981, $FD21733A, $9B58ECF3, $399066AC, $D7C7E065, $75FF5A1E, $1436D3D7, $B26E4D90, $50A5C749, $EEDD4102, $8D14BABB,
      $2B4C3474, $C983AE2D, $67BB27E6, $05F2A19F, $A42A1B58, $42619511, $E0990ECA, $7ED08883, $1D08023C, $BB3F7BF5, $5976F5AE, $F7AE6F67, $95E5E920, $341D62D9,
      $D254DC92, $708C564B, $0EC3D004, $ACFB49BD, $4B32C376, $E96A3D2F, $87A1B6E8, $25D930A1, $C410AA5A, $62482413, $007F9DCC, $9EB71785, $3CEE913E);

  function LRot32(X: DWord; c: longword): DWord;
  begin
    LRot32 := (X shl c) or (X shr (32 - c));
  end;

  function RRot32(X: DWord; c: longword): DWord;
  begin
    RRot32 := (X shr c) or (X shl (32 - c));
  end;

  class function TncEnc_rc6.GetAlgorithm: string;
  begin
    Result := 'RC6';
  end;

  class function TncEnc_rc6.GetMaxKeySize: integer;
  begin
    Result := 2048;
  end;

  class function TncEnc_rc6.SelfTest: boolean;
  const
    Key1: array [0 .. 15] of byte = ($01, $23, $45, $67, $89, $AB, $CD, $EF, $01, $12, $23, $34, $45, $56, $67, $78);
    Plain1: array [0 .. 15] of byte = ($02, $13, $24, $35, $46, $57, $68, $79, $8A, $9B, $AC, $BD, $CE, $DF, $E0, $F1);
    Cipher1: array [0 .. 15] of byte = ($52, $4E, $19, $2F, $47, $15, $C6, $23, $1F, $51, $F6, $36, $7E, $A4, $3F, $18);
    Key2: array [0 .. 31] of byte = ($01, $23, $45, $67, $89, $AB, $CD, $EF, $01, $12, $23, $34, $45, $56, $67, $78, $89, $9A, $AB, $BC, $CD, $DE, $EF, $F0,
      $10, $32, $54, $76, $98, $BA, $DC, $FE);
    Plain2: array [0 .. 15] of byte = ($02, $13, $24, $35, $46, $57, $68, $79, $8A, $9B, $AC, $BD, $CE, $DF, $E0, $F1);
    Cipher2: array [0 .. 15] of byte = ($C8, $24, $18, $16, $F0, $D7, $E4, $89, $20, $AD, $16, $A1, $67, $4E, $5D, $48);
  var
    Cipher: TncEnc_rc6;
    Data: array [0 .. 15] of byte;
  begin
    Cipher := TncEnc_rc6.Create(nil);
    Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
    Cipher.EncryptECB(Plain1, Data);
    Result := boolean(CompareMem(@Data, @Cipher1, Sizeof(Data)));
    Cipher.DecryptECB(Data, Data);
    Result := Result and boolean(CompareMem(@Data, @Plain1, Sizeof(Data)));
    Cipher.Burn;
    Cipher.Init(Key2, Sizeof(Key2) * 8, nil);
    Cipher.EncryptECB(Plain2, Data);
    Result := Result and boolean(CompareMem(@Data, @Cipher2, Sizeof(Data)));
    Cipher.DecryptECB(Data, Data);
    Result := Result and boolean(CompareMem(@Data, @Plain2, Sizeof(Data)));
    Cipher.Burn;
    Cipher.Free;
  end;

  procedure TncEnc_rc6.InitKey(const Key; Size: longword);
  var
    xKeyD: array [0 .. 63] of DWord;
    i, j, k, xKeyLen: longword;
    A, B: DWord;
  begin
    Size := Size div 8;
    FillChar(xKeyD, Sizeof(xKeyD), 0);
    Move(Key, xKeyD, Size);
    xKeyLen := Size div 4;
    if (Size mod 4) <> 0 then
      Inc(xKeyLen);
    Move(sBox, KeyData, ((NUMROUNDS * 2) + 4) * 4);
    i := 0;
    j := 0;
    A := 0;
    B := 0;
    if xKeyLen > ((NUMROUNDS * 2) + 4) then
      k := xKeyLen * 3
    else
      k := ((NUMROUNDS * 2) + 4) * 3;
    for k := 1 to k do
    begin
      A := LRot32(KeyData[i] + A + B, 3);
      KeyData[i] := A;
      B := LRot32(xKeyD[j] + A + B, A + B);
      xKeyD[j] := B;
      i := (i + 1) mod ((NUMROUNDS * 2) + 4);
      j := (j + 1) mod xKeyLen;
    end;
    FillChar(xKeyD, Sizeof(xKeyD), 0);
  end;

  procedure TncEnc_rc6.Burn;
  begin
    FillChar(KeyData, Sizeof(KeyData), $FF);
    inherited Burn;
  end;

  procedure TncEnc_rc6.EncryptECB(const InData; var OutData);
  var
    x0, x1, x2, x3: DWord;
    u, t: DWord;
    i: longword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');
    x0 := PDword(@InData)^;
    x1 := PDword(longword(@InData) + 4)^;
    x2 := PDword(longword(@InData) + 8)^;
    x3 := PDword(longword(@InData) + 12)^;
    x1 := x1 + KeyData[0];
    x3 := x3 + KeyData[1];
    for i := 1 to NUMROUNDS do
    begin
      t := LRot32(x1 * (2 * x1 + 1), 5);
      u := LRot32(x3 * (2 * x3 + 1), 5);
      x0 := LRot32(x0 xor t, u) + KeyData[2 * i];
      x2 := LRot32(x2 xor u, t) + KeyData[2 * i + 1];
      t := x0;
      x0 := x1;
      x1 := x2;
      x2 := x3;
      x3 := t;
    end;
    x0 := x0 + KeyData[(2 * NUMROUNDS) + 2];
    x2 := x2 + KeyData[(2 * NUMROUNDS) + 3];
    PDword(@OutData)^ := x0;
    PDword(longword(@OutData) + 4)^ := x1;
    PDword(longword(@OutData) + 8)^ := x2;
    PDword(longword(@OutData) + 12)^ := x3;
  end;

  procedure TncEnc_rc6.DecryptECB(const InData; var OutData);
  var
    x0, x1, x2, x3: DWord;
    u, t: DWord;
    i: longword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');
    x0 := PDword(@InData)^;
    x1 := PDword(longword(@InData) + 4)^;
    x2 := PDword(longword(@InData) + 8)^;
    x3 := PDword(longword(@InData) + 12)^;
    x2 := x2 - KeyData[(2 * NUMROUNDS) + 3];
    x0 := x0 - KeyData[(2 * NUMROUNDS) + 2];
    for i := NUMROUNDS downto 1 do
    begin
      t := x0;
      x0 := x3;
      x3 := x2;
      x2 := x1;
      x1 := t;
      u := LRot32(x3 * (2 * x3 + 1), 5);
      t := LRot32(x1 * (2 * x1 + 1), 5);
      x2 := RRot32(x2 - KeyData[2 * i + 1], t) xor u;
      x0 := RRot32(x0 - KeyData[2 * i], u) xor t;
    end;
    x3 := x3 - KeyData[1];
    x1 := x1 - KeyData[0];
    PDword(@OutData)^ := x0;
    PDword(longword(@OutData) + 4)^ := x1;
    PDword(longword(@OutData) + 8)^ := x2;
    PDword(longword(@OutData) + 12)^ := x3;
  end;

end.
