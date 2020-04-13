{$R-}
{$Q-}
unit ncEncTea;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

  uses
    Classes, Sysutils, ncEnccrypt2, ncEncblockciphers;

  type
    TncEnc_tea = class(TncEnc_blockcipher64)
    protected
      KeyData: array [0 .. 3] of dword;
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
    Delta = $9E3779B9;
    Rounds = 32;

  function SwapDword(a: dword): dword;
  begin
    Result := ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
  end;

  class function TncEnc_tea.GetAlgorithm: string;
  begin
    Result := 'Tea';
  end;

  class function TncEnc_tea.GetMaxKeySize: integer;
  begin
    Result := 128;
  end;

  class function TncEnc_tea.SelfTest: boolean;
  const
    Key: array [0 .. 3] of dword = ($12345678, $9ABCDEF0, $0FEDCBA9, $87654321);
    PT: array [0 .. 1] of dword = ($12345678, $9ABCDEF0);
  var
    Data: array [0 .. 1] of dword;
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
    a, b, c, d, x, y, n, sum: dword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');

    x := SwapDword(pdword(@InData)^);
    y := SwapDword(pdword(longword(@InData) + 4)^);
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
    pdword(@OutData)^ := SwapDword(x);
    pdword(longword(@OutData) + 4)^ := SwapDword(y);
  end;

  procedure TncEnc_tea.DecryptECB(const InData; var OutData);
  var
    a, b, c, d, x, y, n, sum: dword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');

    x := SwapDword(pdword(@InData)^);
    y := SwapDword(pdword(longword(@InData) + 4)^);
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
    pdword(@OutData)^ := SwapDword(x);
    pdword(longword(@OutData) + 4)^ := SwapDword(y);
  end;

end.
