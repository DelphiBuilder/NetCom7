{$R-}
{$Q-}
unit ncEncRc5;

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
    NUMROUNDS = 12; { number of rounds must be between 12-16 }

  type
    TncEnc_rc5 = class(TncEnc_blockcipher64)
    protected
      KeyData: array [0 .. ((NUMROUNDS * 2) + 1)] of DWord;
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
    sBox: array [0 .. 33] of DWord = ($B7E15163, $5618CB1C, $F45044D5, $9287BE8E, $30BF3847, $CEF6B200, $6D2E2BB9, $0B65A572, $A99D1F2B, $47D498E4, $E60C129D,
      $84438C56, $227B060F, $C0B27FC8, $5EE9F981, $FD21733A, $9B58ECF3, $399066AC, $D7C7E065, $75FF5A1E, $1436D3D7, $B26E4D90, $50A5C749, $EEDD4102, $8D14BABB,
      $2B4C3474, $C983AE2D, $67BB27E6, $05F2A19F, $A42A1B58, $42619511, $E0990ECA, $7ED08883, $1D08023C);

  function LRot32(a, b: longword): longword;
  begin
    Result := (a shl b) or (a shr (32 - b));
  end;

  function RRot32(a, b: longword): longword;
  begin
    Result := (a shr b) or (a shl (32 - b));
  end;

  class function TncEnc_rc5.GetAlgorithm: string;
  begin
    Result := 'RC5';
  end;

  class function TncEnc_rc5.GetMaxKeySize: integer;
  begin
    Result := 2048;
  end;

  class function TncEnc_rc5.SelfTest: boolean;
  const
    Key1: array [0 .. 15] of byte = ($DC, $49, $DB, $13, $75, $A5, $58, $4F, $64, $85, $B4, $13, $B5, $F1, $2B, $AF);
    Plain1: array [0 .. 1] of DWord = ($B7B3422F, $92FC6903);
    Cipher1: array [0 .. 1] of DWord = ($B278C165, $CC97D184);
    Key2: array [0 .. 15] of byte = ($52, $69, $F1, $49, $D4, $1B, $A0, $15, $24, $97, $57, $4D, $7F, $15, $31, $25);
    Plain2: array [0 .. 1] of DWord = ($B278C165, $CC97D184);
    Cipher2: array [0 .. 1] of DWord = ($15E444EB, $249831DA);
  var
    Cipher: TncEnc_rc5;
    Data: array [0 .. 1] of DWord;
  begin
    Cipher := TncEnc_rc5.Create(nil);
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

  procedure TncEnc_rc5.InitKey(const Key; Size: longword);
  var
    xKeyD: array [0 .. 63] of DWord;
    i, j, k, xKeyLen: longword;
    a, b: DWord;
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
    a, b: DWord;
    i: longword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');
    a := PDword(@InData)^ + KeyData[0];
    b := PDword(longword(@InData) + 4)^ + KeyData[1];
    for i := 1 to NUMROUNDS do
    begin
      a := a xor b;
      a := LRot32(a, b) + KeyData[2 * i];
      b := b xor a;
      b := LRot32(b, a) + KeyData[(2 * i) + 1];
    end;
    PDword(@OutData)^ := a;
    PDword(longword(@OutData) + 4)^ := b;
  end;

  procedure TncEnc_rc5.DecryptECB(const InData; var OutData);
  var
    a, b: DWord;
    i: longword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');
    a := PDword(@InData)^;
    b := PDword(longword(@InData) + 4)^;
    for i := NUMROUNDS downto 1 do
    begin
      b := RRot32(b - KeyData[(2 * i) + 1], a);
      b := b xor a;
      a := RRot32(a - KeyData[2 * i], b);
      a := a xor b;
    end;
    PDword(@OutData)^ := a - KeyData[0];
    PDword(longword(@OutData) + 4)^ := b - KeyData[1];
  end;

end.
