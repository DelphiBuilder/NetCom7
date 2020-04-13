{$R-}
{$Q-}
unit ncEncIce;

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
    TncEnc_customice = class(TncEnc_blockcipher64)
    protected
      rounds: dword;
      ik_keysched: array [0 .. 31, 0 .. 2] of dword;
      function f(p, sk: dword): dword;
      procedure key_sched_build(kb: pwordarray; n: dword; keyrot: pdwordarray);
      procedure InitIce(const Key; Size: longword; n: dword);
    public
      procedure Burn; override;
      procedure EncryptECB(const InData; var OutData); override;
      procedure DecryptECB(const InData; var OutData); override;
      constructor Create(AOwner: TComponent); override;
    end;

    TncEnc_ice = class(TncEnc_customice)
    protected
      procedure InitKey(const Key; Size: longword); override;
    public
      class function GetAlgorithm: string; override;
      class function GetMaxKeySize: integer; override;
      class function SelfTest: boolean; override;
    end;

    TncEnc_thinice = class(TncEnc_customice)
    protected
      procedure InitKey(const Key; Size: longword); override;
    public
      class function GetAlgorithm: string; override;
      class function GetMaxKeySize: integer; override;
      class function SelfTest: boolean; override;
    end;

    TncEnc_ice2 = class(TncEnc_customice)
    protected
      procedure InitKey(const Key; Size: longword); override;
    public
      class function GetAlgorithm: string; override;
      class function GetMaxKeySize: integer; override;
      class function SelfTest: boolean; override;
    end;

    { ****************************************************************************** }
    { ****************************************************************************** }
implementation

  uses ncEncryption;

  var
    ice_sbox: array [0 .. 3, 0 .. 1023] of dword;
    ice_sboxdone: boolean;

  const
    ice_smod: array [0 .. 3, 0 .. 3] of dword = ((333, 313, 505, 369), (379, 375, 319, 391), (361, 445, 451, 397), (397, 425, 395, 505));
    ice_sxor: array [0 .. 3, 0 .. 3] of dword = (($83, $85, $9B, $CD), ($CC, $A7, $AD, $41), ($4B, $2E, $D4, $33), ($EA, $CB, $2E, $04));
    ice_keyrot: array [0 .. 15] of dword = (0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2);
    ice_pbox: array [0 .. 31] of dword = ($00000001, $00000080, $00000400, $00002000, $00080000, $00200000, $01000000, $40000000, $00000008, $00000020,
      $00000100, $00004000, $00010000, $00800000, $04000000, $20000000, $00000004, $00000010, $00000200, $00008000, $00020000, $00400000, $08000000, $10000000,
      $00000002, $00000040, $00000800, $00001000, $00040000, $00100000, $02000000, $80000000);

  function SwapDword(a: dword): dword;
  begin
    Result := ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
  end;

  { ****************************************************************************** }
  function gf_mult(a, b, m: dword): dword;
  var
    res: dword;
  begin
    res := 0;
    while b <> 0 do
    begin
      if (b and 1) <> 0 then
        res := res xor a;
      a := a shl 1;
      b := b shr 1;
      if a >= 256 then
        a := a xor m;
    end;
    Result := res;
  end;

  function gf_exp7(b, m: dword): dword;
  var
    x: dword;
  begin
    if b = 0 then
      Result := 0
    else
    begin
      x := gf_mult(b, b, m);
      x := gf_mult(b, x, m);
      x := gf_mult(x, x, m);
      Result := gf_mult(b, x, m);
    end;
  end;

  function ice_perm32(x: dword): dword;
  var
    res: dword;
    pbox: pdword;
  begin
    res := 0;
    pbox := @ice_pbox;
    while x <> 0 do
    begin
      if (x and 1) <> 0 then
        res := res or pbox^;
      Inc(pbox);
      x := x shr 1;
    end;
    Result := res;
  end;

  procedure ice_sboxes_init;
  var
    i, col, row: dword;
    x: dword;
  begin
    for i := 0 to 1023 do
    begin
      col := (i shr 1) and $FF;
      row := (i and 1) or ((i and $200) shr 8);
      x := gf_exp7(col xor ice_sxor[0, row], ice_smod[0, row]) shl 24;
      ice_sbox[0, i] := ice_perm32(x);
      x := gf_exp7(col xor ice_sxor[1, row], ice_smod[1, row]) shl 16;
      ice_sbox[1, i] := ice_perm32(x);
      x := gf_exp7(col xor ice_sxor[2, row], ice_smod[2, row]) shl 8;
      ice_sbox[2, i] := ice_perm32(x);
      x := gf_exp7(col xor ice_sxor[3, row], ice_smod[3, row]);
      ice_sbox[3, i] := ice_perm32(x);
    end;
  end;

  function TncEnc_customice.f(p, sk: dword): dword;
  var
    tl, tr, al, ar: dword;
  begin
    tl := ((p shr 16) and $3FF) or (((p shr 14) or (p shl 18)) and $FFC00);
    tr := (p and $3FF) or ((p shl 2) and $FFC00);
    al := ik_keysched[sk, 2] and (tl xor tr);
    ar := al xor tr;
    al := al xor tl;
    al := al xor ik_keysched[sk, 0];
    ar := ar xor ik_keysched[sk, 1];
    Result := ice_sbox[0, al shr 10] or ice_sbox[1, al and $3FF] or ice_sbox[2, ar shr 10] or ice_sbox[3, ar and $3FF];
  end;

  procedure TncEnc_customice.key_sched_build(kb: pwordarray; n: dword; keyrot: pdwordarray);
  var
    i, j, k, kr: dword;
    keys: pdwordarray;
    currentsk: pdword;
    currentkb: pword;
    bit: dword;
  begin
    for i := 0 to 7 do
    begin
      kr := keyrot^[i];
      keys := @ik_keysched[n + i];
      for j := 0 to 2 do
        keys^[j] := 0;
      for j := 0 to 14 do
      begin
        currentsk := @keys^[j mod 3];
        for k := 0 to 3 do
        begin
          currentkb := @kb^[(kr + k) and 3];
          bit := currentkb^ and 1;
          currentsk^ := (currentsk^ shl 1) or bit;
          currentkb^ := (currentkb^ shr 1) or ((bit xor 1) shl 15);
        end;
      end;
    end;
  end;

  procedure TncEnc_customice.InitIce(const Key; Size: longword; n: dword);
  var
    i, j: dword;
    kb: array [0 .. 3] of word;
    keyb: array [0 .. 15] of byte;
  begin
    FillChar(keyb, Sizeof(keyb), 0);
    Move(Key, keyb, Size div 8);
    if n > 0 then
      rounds := 16 * n
    else
      rounds := 8;

    if rounds = 8 then
    begin
      for i := 0 to 4 do
        kb[3 - i] := (keyb[i * 2] shl 8) or keyb[i * 2 + 1];
      key_sched_build(@kb, 0, @ice_keyrot);
    end
    else
    begin
      for i := 0 to (n - 1) do
      begin
        for j := 0 to 3 do
          kb[3 - j] := (keyb[i * 8 + j * 2] shl 8) or keyb[i * 8 + j * 2 + 1];
        key_sched_build(@kb, i * 8, @ice_keyrot);
        key_sched_build(@kb, rounds - 8 - i * 8, @ice_keyrot[8]);
      end;
    end;
  end;

  procedure TncEnc_customice.Burn;
  begin
    FillChar(ik_keysched, Sizeof(ik_keysched), 0);
    rounds := 0;
    inherited Burn;
  end;

  procedure TncEnc_customice.EncryptECB(const InData; var OutData);
  var
    i, l, r: dword;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');
    l := SwapDword(pdword(@InData)^);
    r := SwapDword(pdword(longword(@InData) + 4)^);
    i := 0;
    while i < rounds do
    begin
      l := l xor f(r, i);
      r := r xor f(l, i + 1);
      Inc(i, 2);
    end;
    pdword(@OutData)^ := SwapDword(r);
    pdword(longword(@OutData) + 4)^ := SwapDword(l);
  end;

  procedure TncEnc_customice.DecryptECB(const InData; var OutData);
  var
    l, r: dword;
    i: integer;
  begin
    if not fInitialized then
      raise EncEnc_blockcipher.Create('Cipher not initialized');
    l := SwapDword(pdword(@InData)^);
    r := SwapDword(pdword(longword(@InData) + 4)^);
    i := rounds - 1;
    while i > 0 do
    begin
      l := l xor f(r, i);
      r := r xor f(l, i - 1);
      Dec(i, 2);
    end;
    pdword(@OutData)^ := SwapDword(r);
    pdword(longword(@OutData) + 4)^ := SwapDword(l);
  end;

  constructor TncEnc_customice.Create(AOwner: TComponent);
  begin
    inherited Create(AOwner);
    if not ice_sboxdone then
    begin
      ice_sboxes_init;
      ice_sboxdone := true;
    end;
  end;

  { ****************************************************************************** }
  class function TncEnc_ice.GetMaxKeySize: integer;
  begin
    Result := 64;
  end;

  class function TncEnc_ice.GetAlgorithm: string;
  begin
    Result := 'Ice';
  end;

  class function TncEnc_ice.SelfTest: boolean;
  const
    Key1: array [0 .. 7] of byte = ($DE, $AD, $BE, $EF, $01, $23, $45, $67);
    InData1: array [0 .. 7] of byte = ($FE, $DC, $BA, $98, $76, $54, $32, $10);
    OutData1: array [0 .. 7] of byte = ($7D, $6E, $F1, $EF, $30, $D4, $7A, $96);
  var
    Cipher: TncEnc_ice;
    Data: array [0 .. 7] of byte;
  begin
    Cipher := TncEnc_ice.Create(nil);
    Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
    Cipher.EncryptECB(InData1, Data);
    Result := boolean(CompareMem(@Data, @OutData1, Sizeof(Data)));
    Cipher.Reset;
    Cipher.DecryptECB(Data, Data);
    Result := boolean(CompareMem(@Data, @InData1, Sizeof(Data))) and Result;
    Cipher.Burn;
    Cipher.Free;
  end;

  procedure TncEnc_ice.InitKey(const Key; Size: longword);
  begin
    InitIce(Key, Size, 1);
  end;

  { ****************************************************************************** }
  class function TncEnc_thinice.GetMaxKeySize: integer;
  begin
    Result := 64;
  end;

  class function TncEnc_thinice.GetAlgorithm: string;
  begin
    Result := 'Thin Ice';
  end;

  class function TncEnc_thinice.SelfTest: boolean;
  const
    Key1: array [0 .. 7] of byte = ($DE, $AD, $BE, $EF, $01, $23, $45, $67);
    InData1: array [0 .. 7] of byte = ($FE, $DC, $BA, $98, $76, $54, $32, $10);
    OutData1: array [0 .. 7] of byte = ($DE, $24, $0D, $83, $A0, $0A, $9C, $C0);
  var
    Cipher: TncEnc_thinice;
    Data: array [0 .. 7] of byte;
  begin
    Cipher := TncEnc_thinice.Create(nil);
    Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
    Cipher.EncryptECB(InData1, Data);
    Result := boolean(CompareMem(@Data, @OutData1, Sizeof(Data)));
    Cipher.Reset;
    Cipher.DecryptECB(Data, Data);
    Result := boolean(CompareMem(@Data, @InData1, Sizeof(Data))) and Result;
    Cipher.Burn;
    Cipher.Free;
  end;

  procedure TncEnc_thinice.InitKey(const Key; Size: longword);
  begin
    InitIce(Key, Size, 0);
  end;

  { ****************************************************************************** }
  class function TncEnc_ice2.GetMaxKeySize: integer;
  begin
    Result := 128;
  end;

  class function TncEnc_ice2.GetAlgorithm: string;
  begin
    Result := 'Ice2';
  end;

  class function TncEnc_ice2.SelfTest: boolean;
  const
    Key1: array [0 .. 15] of byte = ($00, $11, $22, $33, $44, $55, $66, $77, $88, $99, $AA, $BB, $CC, $DD, $EE, $FF);
    InData1: array [0 .. 7] of byte = ($FE, $DC, $BA, $98, $76, $54, $32, $10);
    OutData1: array [0 .. 7] of byte = ($F9, $48, $40, $D8, $69, $72, $F2, $1C);
  var
    Cipher: TncEnc_ice2;
    Data: array [0 .. 7] of byte;
  begin
    Cipher := TncEnc_ice2.Create(nil);
    Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
    Cipher.EncryptECB(InData1, Data);
    Result := boolean(CompareMem(@Data, @OutData1, Sizeof(Data)));
    Cipher.Reset;
    Cipher.DecryptECB(Data, Data);
    Result := boolean(CompareMem(@Data, @InData1, Sizeof(Data))) and Result;
    Cipher.Burn;
    Cipher.Free;
  end;

  procedure TncEnc_ice2.InitKey(const Key; Size: longword);
  begin
    InitIce(Key, Size, 2);
  end;

initialization

  ice_sboxdone := false;

end.
