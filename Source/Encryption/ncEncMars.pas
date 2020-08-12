{$R-}
{$Q-}
unit ncEncMars;

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
  TncEnc_mars = class(TncEnc_blockcipher128)
  protected
    KeyData: array [0 .. 39] of DWord;
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
  S_Box: array [0 .. 511] of DWord = ($09D0C479, $28C8FFE0, $84AA6C39, $9DAD7287, $7DFF9BE3, $D4268361, $C96DA1D4, $7974CC93, $85D0582E, $2A4B5705, $1CA16A62,
    $C3BD279D, $0F1F25E5, $5160372F, $C695C1FB, $4D7FF1E4, $AE5F6BF4, $0D72EE46, $FF23DE8A, $B1CF8E83, $F14902E2, $3E981E42, $8BF53EB6, $7F4BF8AC, $83631F83,
    $25970205, $76AFE784, $3A7931D4, $4F846450, $5C64C3F6, $210A5F18, $C6986A26, $28F4E826, $3A60A81C, $D340A664, $7EA820C4, $526687C5, $7EDDD12B, $32A11D1D,
    $9C9EF086, $80F6E831, $AB6F04AD, $56FB9B53, $8B2E095C, $B68556AE, $D2250B0D, $294A7721, $E21FB253, $AE136749, $E82AAE86, $93365104, $99404A66, $78A784DC,
    $B69BA84B, $04046793, $23DB5C1E, $46CAE1D6, $2FE28134, $5A223942, $1863CD5B, $C190C6E3, $07DFB846, $6EB88816, $2D0DCC4A, $A4CCAE59, $3798670D, $CBFA9493,
    $4F481D45, $EAFC8CA8, $DB1129D6, $B0449E20, $0F5407FB, $6167D9A8, $D1F45763, $4DAA96C3, $3BEC5958, $ABABA014, $B6CCD201, $38D6279F, $02682215, $8F376CD5,
    $092C237E, $BFC56593, $32889D2C, $854B3E95, $05BB9B43, $7DCD5DCD, $A02E926C, $FAE527E5, $36A1C330, $3412E1AE, $F257F462, $3C4F1D71, $30A2E809, $68E5F551,
    $9C61BA44, $5DED0AB8, $75CE09C8, $9654F93E, $698C0CCA, $243CB3E4, $2B062B97, $0F3B8D9E, $00E050DF, $FC5D6166, $E35F9288, $C079550D, $0591AEE8, $8E531E74,
    $75FE3578, $2F6D829A, $F60B21AE, $95E8EB8D, $6699486B, $901D7D9B, $FD6D6E31, $1090ACEF, $E0670DD8, $DAB2E692, $CD6D4365, $E5393514, $3AF345F0, $6241FC4D,
    $460DA3A3, $7BCF3729, $8BF1D1E0, $14AAC070, $1587ED55, $3AFD7D3E, $D2F29E01, $29A9D1F6, $EFB10C53, $CF3B870F, $B414935C, $664465ED, $024ACAC7, $59A744C1,
    $1D2936A7, $DC580AA6, $CF574CA8, $040A7A10, $6CD81807, $8A98BE4C, $ACCEA063, $C33E92B5, $D1E0E03D, $B322517E, $2092BD13, $386B2C4A, $52E8DD58, $58656DFB,
    $50820371, $41811896, $E337EF7E, $D39FB119, $C97F0DF6, $68FEA01B, $A150A6E5, $55258962, $EB6FF41B, $D7C9CD7A, $A619CD9E, $BCF09576, $2672C073, $F003FB3C,
    $4AB7A50B, $1484126A, $487BA9B1, $A64FC9C6, $F6957D49, $38B06A75, $DD805FCD, $63D094CF, $F51C999E, $1AA4D343, $B8495294, $CE9F8E99, $BFFCD770, $C7C275CC,
    $378453A7, $7B21BE33, $397F41BD, $4E94D131, $92CC1F98, $5915EA51, $99F861B7, $C9980A88, $1D74FD5F, $B0A495F8, $614DEED0, $B5778EEA, $5941792D, $FA90C1F8,
    $33F824B4, $C4965372, $3FF6D550, $4CA5FEC0, $8630E964, $5B3FBBD6, $7DA26A48, $B203231A, $04297514, $2D639306, $2EB13149, $16A45272, $532459A0, $8E5F4872,
    $F966C7D9, $07128DC0, $0D44DB62, $AFC8D52D, $06316131, $D838E7CE, $1BC41D00, $3A2E8C0F, $EA83837E, $B984737D, $13BA4891, $C4F8B949, $A6D6ACB3, $A215CDCE,
    $8359838B, $6BD1AA31, $F579DD52, $21B93F93, $F5176781, $187DFDDE, $E94AEB76, $2B38FD54, $431DE1DA, $AB394825, $9AD3048F, $DFEA32AA, $659473E3, $623F7863,
    $F3346C59, $AB3AB685, $3346A90B, $6B56443E, $C6DE01F8, $8D421FC0, $9B0ED10C, $88F1A1E9, $54C1F029, $7DEAD57B, $8D7BA426, $4CF5178A, $551A7CCA, $1A9A5F08,
    $FCD651B9, $25605182, $E11FC6C3, $B6FD9676, $337B3027, $B7C8EB14, $9E5FD030, $6B57E354, $AD913CF7, $7E16688D, $58872A69, $2C2FC7DF, $E389CCC6, $30738DF1,
    $0824A734, $E1797A8B, $A4A8D57B, $5B5D193B, $C8A8309B, $73F9A978, $73398D32, $0F59573E, $E9DF2B03, $E8A5B6C8, $848D0704, $98DF93C2, $720A1DC3, $684F259A,
    $943BA848, $A6370152, $863B5EA3, $D17B978B, $6D9B58EF, $0A700DD4, $A73D36BF, $8E6A0829, $8695BC14, $E35B3447, $933AC568, $8894B022, $2F511C27, $DDFBCC3C,
    $006662B6, $117C83FE, $4E12B414, $C2BCA766, $3A2FEC10, $F4562420, $55792E2A, $46F5D857, $CEDA25CE, $C3601D3B, $6C00AB46, $EFAC9C28, $B3C35047, $611DFEE3,
    $257C3207, $FDD58482, $3B14D84F, $23BECB64, $A075F3A3, $088F8EAD, $07ADF158, $7796943C, $FACABF3D, $C09730CD, $F7679969, $DA44E9ED, $2C854C12, $35935FA3,
    $2F057D9F, $690624F8, $1CB0BAFD, $7B0DBDC6, $810F23BB, $FA929A1A, $6D969A17, $6742979B, $74AC7D05, $010E65C4, $86A3D963, $F907B5A0, $D0042BD3, $158D7D03,
    $287A8255, $BBA8366F, $096EDC33, $21916A7B, $77B56B86, $951622F9, $A6C5E650, $8CEA17D1, $CD8C62BC, $A3D63433, $358A68FD, $0F9B9D3C, $D6AA295B, $FE33384A,
    $C000738E, $CD67EB2F, $E2EB6DC2, $97338B02, $06C9F246, $419CF1AD, $2B83C045, $3723F18A, $CB5B3089, $160BEAD7, $5D494656, $35F8A74B, $1E4E6C9E, $000399BD,
    $67466880, $B4174831, $ACF423B2, $CA815AB3, $5A6395E7, $302A67C5, $8BDB446B, $108F8FA4, $10223EDA, $92B8B48B, $7F38D0EE, $AB2701D4, $0262D415, $AF224A30,
    $B3D88ABA, $F8B2C3AF, $DAF7EF70, $CC97D3B7, $E9614B6C, $2BAEBFF4, $70F687CF, $386C9156, $CE092EE5, $01E87DA6, $6CE91E6A, $BB7BCC84, $C7922C20, $9D3B71FD,
    $060E41C6, $D7590F15, $4E03BB47, $183C198E, $63EEB240, $2DDBF49A, $6D5CBA54, $923750AF, $F9E14236, $7838162B, $59726C72, $81B66760, $BB2926C1, $48A0CE0D,
    $A6C0496D, $AD43507B, $718D496A, $9DF057AF, $44B1BDE6, $054356DC, $DE7CED35, $D51A138B, $62088CC9, $35830311, $C96EFCA2, $686F86EC, $8E77CB68, $63E1D6B8,
    $C80F9778, $79C491FD, $1B4C67F2, $72698D7D, $5E368C31, $F7D95E2E, $A1D3493F, $DCD9433E, $896F1552, $4BC4CA7A, $A6D1BAF4, $A5A96DCC, $0BEF8B46, $A169FDA7,
    $74DF40B7, $4E208804, $9A756607, $038E87C8, $20211E44, $8B7AD4BF, $C6403F35, $1848E36D, $80BDB038, $1E62891C, $643D2107, $BF04D6F8, $21092C8C, $F644F389,
    $0778404E, $7B78ADB8, $A2C52D53, $42157ABE, $A2253E2E, $7BF3F4AE, $80F594F9, $953194E7, $77EB92ED, $B3816930, $DA8D9336, $BF447469, $F26D9483, $EE6FAED5,
    $71371235, $DE425F73, $B4E59F43, $7DBE2D4E, $2D37B185, $49DC9A63, $98C39D98, $1301C9A2, $389B1BBF, $0C18588D, $A421C1BA, $7AA3865C, $71E08558, $3C5CFCAA,
    $7D239CA4, $0297D9DD, $D7DC2830, $4B37802B, $7428AB54, $AEEE0347, $4B3FBB85, $692F2F08, $134E578E, $36D9E0BF, $AE8B5FCF, $EDB93ECF, $2B27248E, $170EB1EF,
    $7DC57FD6, $1E760F16, $B1136601, $864E1B9B, $D7EA7319, $3AB871BD, $CFA4D76F, $E31BD782, $0DBEB469, $ABB96061, $5370F85D, $FFB07E37, $DA30D0FB, $EBC977B6,
    $0B98B40F, $3A4D0FE6, $DF4FC26B, $159CF22A, $C298D6E2, $2B78EF6A, $61A94AC0, $AB561187, $14EEA0F0, $DF0D4164, $19AF70EE);

  vk: array [0 .. 6] of DWord = ($09D0C479, $28C8FFE0, $84AA6C39, $9DAD7287, $7DFF9BE3, $D4268361, $C96DA1D4);

function LRot32(X: DWord; c: longword): DWord;
begin
  LRot32 := (X shl c) or (X shr (32 - c));
end;

function RRot32(X: DWord; c: longword): DWord;
begin
  RRot32 := (X shr c) or (X shl (32 - c));
end;

class function TncEnc_mars.GetAlgorithm: string;
begin
  Result := 'Mars';
end;

class function TncEnc_mars.GetMaxKeySize: integer;
begin
  Result := 1248;
end;

class function TncEnc_mars.SelfTest: boolean;
const
  Key1: array [0 .. 3] of DWord = ($DEB35132, $83C296DE, $39069E6B, $994C2438);
  Key2: array [0 .. 5] of DWord = ($A5391779, $1A58048B, $A853A993, $1D41102C, $088658D1, $954D8738);
  Key3: array [0 .. 7] of DWord = ($9867A1FB, $22EF7A3E, $8CE27C31, $A3E1AA02, $3CCCE5E8, $2AA8BEED, $9AC3DB99, $27725ED6);
  Plain1: array [0 .. 3] of DWord = ($DEB35132, $83C296DE, $39069E6B, $994C2438);
  Plain2: array [0 .. 3] of DWord = ($2DC46167, $D242613E, $ADBF4FA8, $8F1583B3);
  Plain3: array [0 .. 3] of DWord = ($A4AB4413, $0847C4D3, $1621A7A8, $8493F4D4);
  Cipher1: array [0 .. 3] of DWord = ($A91245F9, $4E032DB4, $042279C4, $9BA608D7);
  Cipher2: array [0 .. 3] of DWord = ($260334CB, $6D587F45, $E0D2BD54, $BD191C57);
  Cipher3: array [0 .. 3] of DWord = ($67A1ACDD, $BE3163E3, $5F9F1C2C, $B8A48FE3);
var
  Cipher: TncEnc_mars;
  Block: array [0 .. 3] of DWord;
begin
  Cipher := TncEnc_mars.Create(nil);
  Cipher.Init(Key1, Sizeof(Key1) * 8, nil);
  Cipher.EncryptECB(Plain1, Block);
  Result := CompareMem(@Cipher1, @Block, Sizeof(Block));
  Cipher.DecryptECB(Block, Block);
  Result := Result and CompareMem(@Plain1, @Block, Sizeof(Block));
  Cipher.Burn;
  Cipher.Init(Key2, Sizeof(Key2) * 8, nil);
  Cipher.EncryptECB(Plain2, Block);
  Result := Result and CompareMem(@Cipher2, @Block, Sizeof(Block));
  Cipher.DecryptECB(Block, Block);
  Result := Result and CompareMem(@Plain2, @Block, Sizeof(Block));
  Cipher.Burn;
  Cipher.Init(Key3, Sizeof(Key3) * 8, nil);
  Cipher.EncryptECB(Plain3, Block);
  Result := Result and CompareMem(@Cipher3, @Block, Sizeof(Block));
  Cipher.DecryptECB(Block, Block);
  Result := Result and CompareMem(@Plain3, @Block, Sizeof(Block));
  Cipher.Burn;
  Cipher.Free;
end;

procedure gen_mask(var X, m: DWord);
var
  u: DWord;
begin
  u := X and (X shr 1);
  u := u and (u shr 2);
  u := u and (u shr 4);
  u := u and (u shr 1) and (u shr 2);
  m := u;
  u := (X xor $FFFFFFFF) and ((X xor $FFFFFFFF) shr 1);
  u := u and (u shr 2);
  u := u and (u shr 4);
  u := u and (u shr 1) and (u shr 2);
  u := u or m;
  m := (u shl 1) or (u shl 2) or (u shl 3) or (u shl 4) or (u shl 5) or (u shl 6) or (u shl 7) or (u shl 8);
  m := (m or u or (u shl 9)) and ((X xor $FFFFFFFF) xor (X shl 1)) and ((X xor $FFFFFFFF) xor (X shr 1));
  m := m and $FFFFFFFC;
end;

procedure TncEnc_mars.InitKey(const Key; Size: longword);
var
  i, j, m, u, w: DWord;
  t: array [-7 .. 39] of DWord;
  KeyB: array [0 .. 39] of DWord;
begin
  Size := Size div 8;
  FillChar(KeyB, Sizeof(KeyB), 0);
  Move(Key, KeyB, Size);
  Size := Size div 4;
  Move(vk, t, Sizeof(vk));
  for i := 0 to 38 do
  begin
    u := t[i - 7] xor t[i - 2];
    t[i] := LRot32(u, 3) xor KeyB[i mod DWord(Size)] xor i;
  end;
  t[39] := Size;
  for j := 0 to 6 do
  begin
    for i := 1 to 39 do
    begin
      u := t[i] + S_Box[t[i - 1] and $1FF];
      t[i] := LRot32(u, 9);
    end;
    u := t[0] + S_Box[t[39] and $1FF];
    t[0] := LRot32(u, 9);
  end;
  for i := 0 to 39 do
    KeyData[(7 * i) mod 40] := t[i];
  i := 5;
  repeat
    u := S_Box[265 + (KeyData[i] and $3)];
    j := KeyData[i + 3] and $1F;
    w := KeyData[i] or $3;
    gen_mask(w, m);
    KeyData[i] := w xor (LRot32(u, j) and m);
    Inc(i, 2);
  until i >= 37;
end;

procedure TncEnc_mars.Burn;
begin
  FillChar(KeyData, Sizeof(KeyData), $FF);
  inherited Burn;
end;

procedure TncEnc_mars.EncryptECB(const InData; var OutData);
var
  l, m, r, t: DWord;
  blk: array [0 .. 3] of DWord;
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  blk[0] := PDWord(@InData)^;
  blk[1] := PDWord(longword(@InData) + 4)^;
  blk[2] := PDWord(longword(@InData) + 8)^;
  blk[3] := PDWord(longword(@InData) + 12)^;

  blk[0] := blk[0] + KeyData[0];
  blk[1] := blk[1] + KeyData[1];
  blk[2] := blk[2] + KeyData[2];
  blk[3] := blk[3] + KeyData[3];
  blk[1] := blk[1] xor S_Box[blk[0] and $FF];
  blk[1] := blk[1] + S_Box[((blk[0] shr 8) and $FF) + 256];
  blk[2] := blk[2] + S_Box[(blk[0] shr 16) and $FF];
  blk[3] := blk[3] xor S_Box[((blk[0] shr 24) and $FF) + 256];
  blk[0] := RRot32(blk[0], 24);
  blk[0] := blk[0] + blk[3];
  blk[2] := blk[2] xor S_Box[blk[1] and $FF];
  blk[2] := blk[2] + S_Box[((blk[1] shr 8) and $FF) + 256];
  blk[3] := blk[3] + S_Box[(blk[1] shr 16) and $FF];
  blk[0] := blk[0] xor S_Box[((blk[1] shr 24) and $FF) + 256];
  blk[1] := RRot32(blk[1], 24);
  blk[1] := blk[1] + blk[2];
  blk[3] := blk[3] xor S_Box[blk[2] and $FF];
  blk[3] := blk[3] + S_Box[((blk[2] shr 8) and $FF) + 256];
  blk[0] := blk[0] + S_Box[(blk[2] shr 16) and $FF];
  blk[1] := blk[1] xor S_Box[((blk[2] shr 24) and $FF) + 256];
  blk[2] := RRot32(blk[2], 24);
  blk[0] := blk[0] xor S_Box[blk[3] and $FF];
  blk[0] := blk[0] + S_Box[((blk[3] shr 8) and $FF) + 256];
  blk[1] := blk[1] + S_Box[(blk[3] shr 16) and $FF];
  blk[2] := blk[2] xor S_Box[((blk[3] shr 24) and $FF) + 256];
  blk[3] := RRot32(blk[3], 24);
  blk[1] := blk[1] xor S_Box[blk[0] and $FF];
  blk[1] := blk[1] + S_Box[((blk[0] shr 8) and $FF) + 256];
  blk[2] := blk[2] + S_Box[(blk[0] shr 16) and $FF];
  blk[3] := blk[3] xor S_Box[((blk[0] shr 24) and $FF) + 256];
  blk[0] := RRot32(blk[0], 24);
  blk[0] := blk[0] + blk[3];
  blk[2] := blk[2] xor S_Box[blk[1] and $FF];
  blk[2] := blk[2] + S_Box[((blk[1] shr 8) and $FF) + 256];
  blk[3] := blk[3] + S_Box[(blk[1] shr 16) and $FF];
  blk[0] := blk[0] xor S_Box[((blk[1] shr 24) and $FF) + 256];
  blk[1] := RRot32(blk[1], 24);
  blk[1] := blk[1] + blk[2];
  blk[3] := blk[3] xor S_Box[blk[2] and $FF];
  blk[3] := blk[3] + S_Box[((blk[2] shr 8) and $FF) + 256];
  blk[0] := blk[0] + S_Box[(blk[2] shr 16) and $FF];
  blk[1] := blk[1] xor S_Box[((blk[2] shr 24) and $FF) + 256];
  blk[2] := RRot32(blk[2], 24);
  blk[0] := blk[0] xor S_Box[blk[3] and $FF];
  blk[0] := blk[0] + S_Box[((blk[3] shr 8) and $FF) + 256];
  blk[1] := blk[1] + S_Box[(blk[3] shr 16) and $FF];
  blk[2] := blk[2] xor S_Box[((blk[3] shr 24) and $FF) + 256];
  blk[3] := RRot32(blk[3], 24);
  m := blk[0] + KeyData[4];
  r := LRot32(blk[0], 13) * KeyData[5];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := LRot32(blk[0], 13);
  blk[1] := blk[1] + l;
  blk[2] := blk[2] + m;
  blk[3] := blk[3] xor r;
  m := blk[1] + KeyData[6];
  r := LRot32(blk[1], 13) * KeyData[7];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := LRot32(blk[1], 13);
  blk[2] := blk[2] + l;
  blk[3] := blk[3] + m;
  blk[0] := blk[0] xor r;
  m := blk[2] + KeyData[8];
  r := LRot32(blk[2], 13) * KeyData[9];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := LRot32(blk[2], 13);
  blk[3] := blk[3] + l;
  blk[0] := blk[0] + m;
  blk[1] := blk[1] xor r;
  m := blk[3] + KeyData[10];
  r := LRot32(blk[3], 13) * KeyData[11];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := LRot32(blk[3], 13);
  blk[0] := blk[0] + l;
  blk[1] := blk[1] + m;
  blk[2] := blk[2] xor r;
  m := blk[0] + KeyData[12];
  r := LRot32(blk[0], 13) * KeyData[13];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := LRot32(blk[0], 13);
  blk[1] := blk[1] + l;
  blk[2] := blk[2] + m;
  blk[3] := blk[3] xor r;
  m := blk[1] + KeyData[14];
  r := LRot32(blk[1], 13) * KeyData[15];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := LRot32(blk[1], 13);
  blk[2] := blk[2] + l;
  blk[3] := blk[3] + m;
  blk[0] := blk[0] xor r;
  m := blk[2] + KeyData[16];
  r := LRot32(blk[2], 13) * KeyData[17];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := LRot32(blk[2], 13);
  blk[3] := blk[3] + l;
  blk[0] := blk[0] + m;
  blk[1] := blk[1] xor r;
  m := blk[3] + KeyData[18];
  r := LRot32(blk[3], 13) * KeyData[19];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := LRot32(blk[3], 13);
  blk[0] := blk[0] + l;
  blk[1] := blk[1] + m;
  blk[2] := blk[2] xor r;
  m := blk[0] + KeyData[20];
  r := LRot32(blk[0], 13) * KeyData[21];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := LRot32(blk[0], 13);
  blk[3] := blk[3] + l;
  blk[2] := blk[2] + m;
  blk[1] := blk[1] xor r;
  m := blk[1] + KeyData[22];
  r := LRot32(blk[1], 13) * KeyData[23];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := LRot32(blk[1], 13);
  blk[0] := blk[0] + l;
  blk[3] := blk[3] + m;
  blk[2] := blk[2] xor r;
  m := blk[2] + KeyData[24];
  r := LRot32(blk[2], 13) * KeyData[25];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := LRot32(blk[2], 13);
  blk[1] := blk[1] + l;
  blk[0] := blk[0] + m;
  blk[3] := blk[3] xor r;
  m := blk[3] + KeyData[26];
  r := LRot32(blk[3], 13) * KeyData[27];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := LRot32(blk[3], 13);
  blk[2] := blk[2] + l;
  blk[1] := blk[1] + m;
  blk[0] := blk[0] xor r;
  m := blk[0] + KeyData[28];
  r := LRot32(blk[0], 13) * KeyData[29];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := LRot32(blk[0], 13);
  blk[3] := blk[3] + l;
  blk[2] := blk[2] + m;
  blk[1] := blk[1] xor r;
  m := blk[1] + KeyData[30];
  r := LRot32(blk[1], 13) * KeyData[31];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := LRot32(blk[1], 13);
  blk[0] := blk[0] + l;
  blk[3] := blk[3] + m;
  blk[2] := blk[2] xor r;
  m := blk[2] + KeyData[32];
  r := LRot32(blk[2], 13) * KeyData[33];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := LRot32(blk[2], 13);
  blk[1] := blk[1] + l;
  blk[0] := blk[0] + m;
  blk[3] := blk[3] xor r;
  m := blk[3] + KeyData[34];
  r := LRot32(blk[3], 13) * KeyData[35];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := LRot32(blk[3], 13);
  blk[2] := blk[2] + l;
  blk[1] := blk[1] + m;
  blk[0] := blk[0] xor r;
  blk[1] := blk[1] xor S_Box[(blk[0] and $FF) + 256];
  blk[2] := blk[2] - S_Box[(blk[0] shr 24) and $FF];
  blk[3] := blk[3] - S_Box[((blk[0] shr 16) and $FF) + 256];
  blk[3] := blk[3] xor S_Box[(blk[0] shr 8) and $FF];
  blk[0] := LRot32(blk[0], 24);
  blk[2] := blk[2] xor S_Box[(blk[1] and $FF) + 256];
  blk[3] := blk[3] - S_Box[(blk[1] shr 24) and $FF];
  blk[0] := blk[0] - S_Box[((blk[1] shr 16) and $FF) + 256];
  blk[0] := blk[0] xor S_Box[(blk[1] shr 8) and $FF];
  blk[1] := LRot32(blk[1], 24);
  blk[2] := blk[2] - blk[1];
  blk[3] := blk[3] xor S_Box[(blk[2] and $FF) + 256];
  blk[0] := blk[0] - S_Box[(blk[2] shr 24) and $FF];
  blk[1] := blk[1] - S_Box[((blk[2] shr 16) and $FF) + 256];
  blk[1] := blk[1] xor S_Box[(blk[2] shr 8) and $FF];
  blk[2] := LRot32(blk[2], 24);
  blk[3] := blk[3] - blk[0];
  blk[0] := blk[0] xor S_Box[(blk[3] and $FF) + 256];
  blk[1] := blk[1] - S_Box[(blk[3] shr 24) and $FF];
  blk[2] := blk[2] - S_Box[((blk[3] shr 16) and $FF) + 256];
  blk[2] := blk[2] xor S_Box[(blk[3] shr 8) and $FF];
  blk[3] := LRot32(blk[3], 24);
  blk[1] := blk[1] xor S_Box[(blk[0] and $FF) + 256];
  blk[2] := blk[2] - S_Box[(blk[0] shr 24) and $FF];
  blk[3] := blk[3] - S_Box[((blk[0] shr 16) and $FF) + 256];
  blk[3] := blk[3] xor S_Box[(blk[0] shr 8) and $FF];
  blk[0] := LRot32(blk[0], 24);
  blk[2] := blk[2] xor S_Box[(blk[1] and $FF) + 256];
  blk[3] := blk[3] - S_Box[(blk[1] shr 24) and $FF];
  blk[0] := blk[0] - S_Box[((blk[1] shr 16) and $FF) + 256];
  blk[0] := blk[0] xor S_Box[(blk[1] shr 8) and $FF];
  blk[1] := LRot32(blk[1], 24);
  blk[2] := blk[2] - blk[1];
  blk[3] := blk[3] xor S_Box[(blk[2] and $FF) + 256];
  blk[0] := blk[0] - S_Box[(blk[2] shr 24) and $FF];
  blk[1] := blk[1] - S_Box[((blk[2] shr 16) and $FF) + 256];
  blk[1] := blk[1] xor S_Box[(blk[2] shr 8) and $FF];
  blk[2] := LRot32(blk[2], 24);
  blk[3] := blk[3] - blk[0];
  blk[0] := blk[0] xor S_Box[(blk[3] and $FF) + 256];
  blk[1] := blk[1] - S_Box[(blk[3] shr 24) and $FF];
  blk[2] := blk[2] - S_Box[((blk[3] shr 16) and $FF) + 256];
  blk[2] := blk[2] xor S_Box[(blk[3] shr 8) and $FF];
  blk[3] := LRot32(blk[3], 24);
  blk[0] := blk[0] - KeyData[36];
  blk[1] := blk[1] - KeyData[37];
  blk[2] := blk[2] - KeyData[38];
  blk[3] := blk[3] - KeyData[39];

  PDWord(@OutData)^ := blk[0];
  PDWord(longword(@OutData) + 4)^ := blk[1];
  PDWord(longword(@OutData) + 8)^ := blk[2];
  PDWord(longword(@OutData) + 12)^ := blk[3];
end;

procedure TncEnc_mars.DecryptECB(const InData; var OutData);
var
  l, m, r, t: DWord;
  blk: array [0 .. 3] of DWord;
begin
  if not fInitialized then
    raise EncEnc_blockcipher.Create('Cipher not initialized');
  blk[0] := PDWord(@InData)^;
  blk[1] := PDWord(longword(@InData) + 4)^;
  blk[2] := PDWord(longword(@InData) + 8)^;
  blk[3] := PDWord(longword(@InData) + 12)^;

  blk[0] := blk[0] + KeyData[36];
  blk[1] := blk[1] + KeyData[37];
  blk[2] := blk[2] + KeyData[38];
  blk[3] := blk[3] + KeyData[39];
  blk[3] := RRot32(blk[3], 24);
  blk[2] := blk[2] xor S_Box[(blk[3] shr 8) and $FF];
  blk[2] := blk[2] + S_Box[((blk[3] shr 16) and $FF) + 256];
  blk[1] := blk[1] + S_Box[(blk[3] shr 24) and $FF];
  blk[0] := blk[0] xor S_Box[(blk[3] and $FF) + 256];
  blk[3] := blk[3] + blk[0];
  blk[2] := RRot32(blk[2], 24);
  blk[1] := blk[1] xor S_Box[(blk[2] shr 8) and $FF];
  blk[1] := blk[1] + S_Box[((blk[2] shr 16) and $FF) + 256];
  blk[0] := blk[0] + S_Box[(blk[2] shr 24) and $FF];
  blk[3] := blk[3] xor S_Box[(blk[2] and $FF) + 256];
  blk[2] := blk[2] + blk[1];
  blk[1] := RRot32(blk[1], 24);
  blk[0] := blk[0] xor S_Box[(blk[1] shr 8) and $FF];
  blk[0] := blk[0] + S_Box[((blk[1] shr 16) and $FF) + 256];
  blk[3] := blk[3] + S_Box[(blk[1] shr 24) and $FF];
  blk[2] := blk[2] xor S_Box[(blk[1] and $FF) + 256];
  blk[0] := RRot32(blk[0], 24);
  blk[3] := blk[3] xor S_Box[(blk[0] shr 8) and $FF];
  blk[3] := blk[3] + S_Box[((blk[0] shr 16) and $FF) + 256];
  blk[2] := blk[2] + S_Box[(blk[0] shr 24) and $FF];
  blk[1] := blk[1] xor S_Box[(blk[0] and $FF) + 256];
  blk[3] := RRot32(blk[3], 24);
  blk[2] := blk[2] xor S_Box[(blk[3] shr 8) and $FF];
  blk[2] := blk[2] + S_Box[((blk[3] shr 16) and $FF) + 256];
  blk[1] := blk[1] + S_Box[(blk[3] shr 24) and $FF];
  blk[0] := blk[0] xor S_Box[(blk[3] and $FF) + 256];
  blk[3] := blk[3] + blk[0];
  blk[2] := RRot32(blk[2], 24);
  blk[1] := blk[1] xor S_Box[(blk[2] shr 8) and $FF];
  blk[1] := blk[1] + S_Box[((blk[2] shr 16) and $FF) + 256];
  blk[0] := blk[0] + S_Box[(blk[2] shr 24) and $FF];
  blk[3] := blk[3] xor S_Box[(blk[2] and $FF) + 256];
  blk[2] := blk[2] + blk[1];
  blk[1] := RRot32(blk[1], 24);
  blk[0] := blk[0] xor S_Box[(blk[1] shr 8) and $FF];
  blk[0] := blk[0] + S_Box[((blk[1] shr 16) and $FF) + 256];
  blk[3] := blk[3] + S_Box[(blk[1] shr 24) and $FF];
  blk[2] := blk[2] xor S_Box[(blk[1] and $FF) + 256];
  blk[0] := RRot32(blk[0], 24);
  blk[3] := blk[3] xor S_Box[(blk[0] shr 8) and $FF];
  blk[3] := blk[3] + S_Box[((blk[0] shr 16) and $FF) + 256];
  blk[2] := blk[2] + S_Box[(blk[0] shr 24) and $FF];
  blk[1] := blk[1] xor S_Box[(blk[0] and $FF) + 256];
  blk[3] := RRot32(blk[3], 13);
  m := blk[3] + KeyData[34];
  r := LRot32(blk[3], 13) * KeyData[35];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := blk[2] - l;
  blk[1] := blk[1] - m;
  blk[0] := blk[0] xor r;
  blk[2] := RRot32(blk[2], 13);
  m := blk[2] + KeyData[32];
  r := LRot32(blk[2], 13) * KeyData[33];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := blk[1] - l;
  blk[0] := blk[0] - m;
  blk[3] := blk[3] xor r;
  blk[1] := RRot32(blk[1], 13);
  m := blk[1] + KeyData[30];
  r := LRot32(blk[1], 13) * KeyData[31];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := blk[0] - l;
  blk[3] := blk[3] - m;
  blk[2] := blk[2] xor r;
  blk[0] := RRot32(blk[0], 13);
  m := blk[0] + KeyData[28];
  r := LRot32(blk[0], 13) * KeyData[29];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := blk[3] - l;
  blk[2] := blk[2] - m;
  blk[1] := blk[1] xor r;
  blk[3] := RRot32(blk[3], 13);
  m := blk[3] + KeyData[26];
  r := LRot32(blk[3], 13) * KeyData[27];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := blk[2] - l;
  blk[1] := blk[1] - m;
  blk[0] := blk[0] xor r;
  blk[2] := RRot32(blk[2], 13);
  m := blk[2] + KeyData[24];
  r := LRot32(blk[2], 13) * KeyData[25];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := blk[1] - l;
  blk[0] := blk[0] - m;
  blk[3] := blk[3] xor r;
  blk[1] := RRot32(blk[1], 13);
  m := blk[1] + KeyData[22];
  r := LRot32(blk[1], 13) * KeyData[23];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := blk[0] - l;
  blk[3] := blk[3] - m;
  blk[2] := blk[2] xor r;
  blk[0] := RRot32(blk[0], 13);
  m := blk[0] + KeyData[20];
  r := LRot32(blk[0], 13) * KeyData[21];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := blk[3] - l;
  blk[2] := blk[2] - m;
  blk[1] := blk[1] xor r;
  blk[3] := RRot32(blk[3], 13);
  m := blk[3] + KeyData[18];
  r := LRot32(blk[3], 13) * KeyData[19];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := blk[0] - l;
  blk[1] := blk[1] - m;
  blk[2] := blk[2] xor r;
  blk[2] := RRot32(blk[2], 13);
  m := blk[2] + KeyData[16];
  r := LRot32(blk[2], 13) * KeyData[17];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := blk[3] - l;
  blk[0] := blk[0] - m;
  blk[1] := blk[1] xor r;
  blk[1] := RRot32(blk[1], 13);
  m := blk[1] + KeyData[14];
  r := LRot32(blk[1], 13) * KeyData[15];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := blk[2] - l;
  blk[3] := blk[3] - m;
  blk[0] := blk[0] xor r;
  blk[0] := RRot32(blk[0], 13);
  m := blk[0] + KeyData[12];
  r := LRot32(blk[0], 13) * KeyData[13];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := blk[1] - l;
  blk[2] := blk[2] - m;
  blk[3] := blk[3] xor r;
  blk[3] := RRot32(blk[3], 13);
  m := blk[3] + KeyData[10];
  r := LRot32(blk[3], 13) * KeyData[11];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[0] := blk[0] - l;
  blk[1] := blk[1] - m;
  blk[2] := blk[2] xor r;
  blk[2] := RRot32(blk[2], 13);
  m := blk[2] + KeyData[8];
  r := LRot32(blk[2], 13) * KeyData[9];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[3] := blk[3] - l;
  blk[0] := blk[0] - m;
  blk[1] := blk[1] xor r;
  blk[1] := RRot32(blk[1], 13);
  m := blk[1] + KeyData[6];
  r := LRot32(blk[1], 13) * KeyData[7];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[2] := blk[2] - l;
  blk[3] := blk[3] - m;
  blk[0] := blk[0] xor r;
  blk[0] := RRot32(blk[0], 13);
  m := blk[0] + KeyData[4];
  r := LRot32(blk[0], 13) * KeyData[5];
  l := S_Box[m and $1FF];
  r := LRot32(r, 5);
  t := r and $1F;
  m := LRot32(m, t);
  l := l xor r;
  r := LRot32(r, 5);
  l := l xor r;
  t := r and $1F;
  l := LRot32(l, t);
  blk[1] := blk[1] - l;
  blk[2] := blk[2] - m;
  blk[3] := blk[3] xor r;
  blk[3] := LRot32(blk[3], 24);
  blk[2] := blk[2] xor S_Box[((blk[3] shr 24) and $FF) + 256];
  blk[1] := blk[1] - S_Box[(blk[3] shr 16) and $FF];
  blk[0] := blk[0] - S_Box[((blk[3] shr 8) and $FF) + 256];
  blk[0] := blk[0] xor S_Box[blk[3] and $FF];
  blk[2] := LRot32(blk[2], 24);
  blk[1] := blk[1] xor S_Box[((blk[2] shr 24) and $FF) + 256];
  blk[0] := blk[0] - S_Box[(blk[2] shr 16) and $FF];
  blk[3] := blk[3] - S_Box[((blk[2] shr 8) and $FF) + 256];
  blk[3] := blk[3] xor S_Box[blk[2] and $FF];
  blk[1] := blk[1] - blk[2];
  blk[1] := LRot32(blk[1], 24);
  blk[0] := blk[0] xor S_Box[((blk[1] shr 24) and $FF) + 256];
  blk[3] := blk[3] - S_Box[(blk[1] shr 16) and $FF];
  blk[2] := blk[2] - S_Box[((blk[1] shr 8) and $FF) + 256];
  blk[2] := blk[2] xor S_Box[blk[1] and $FF];
  blk[0] := blk[0] - blk[3];
  blk[0] := LRot32(blk[0], 24);
  blk[3] := blk[3] xor S_Box[((blk[0] shr 24) and $FF) + 256];
  blk[2] := blk[2] - S_Box[(blk[0] shr 16) and $FF];
  blk[1] := blk[1] - S_Box[((blk[0] shr 8) and $FF) + 256];
  blk[1] := blk[1] xor S_Box[blk[0] and $FF];
  blk[3] := LRot32(blk[3], 24);
  blk[2] := blk[2] xor S_Box[((blk[3] shr 24) and $FF) + 256];
  blk[1] := blk[1] - S_Box[(blk[3] shr 16) and $FF];
  blk[0] := blk[0] - S_Box[((blk[3] shr 8) and $FF) + 256];
  blk[0] := blk[0] xor S_Box[blk[3] and $FF];
  blk[2] := LRot32(blk[2], 24);
  blk[1] := blk[1] xor S_Box[((blk[2] shr 24) and $FF) + 256];
  blk[0] := blk[0] - S_Box[(blk[2] shr 16) and $FF];
  blk[3] := blk[3] - S_Box[((blk[2] shr 8) and $FF) + 256];
  blk[3] := blk[3] xor S_Box[blk[2] and $FF];
  blk[1] := blk[1] - blk[2];
  blk[1] := LRot32(blk[1], 24);
  blk[0] := blk[0] xor S_Box[((blk[1] shr 24) and $FF) + 256];
  blk[3] := blk[3] - S_Box[(blk[1] shr 16) and $FF];
  blk[2] := blk[2] - S_Box[((blk[1] shr 8) and $FF) + 256];
  blk[2] := blk[2] xor S_Box[blk[1] and $FF];
  blk[0] := blk[0] - blk[3];
  blk[0] := LRot32(blk[0], 24);
  blk[3] := blk[3] xor S_Box[((blk[0] shr 24) and $FF) + 256];
  blk[2] := blk[2] - S_Box[(blk[0] shr 16) and $FF];
  blk[1] := blk[1] - S_Box[((blk[0] shr 8) and $FF) + 256];
  blk[1] := blk[1] xor S_Box[blk[0] and $FF];
  blk[0] := blk[0] - KeyData[0];
  blk[1] := blk[1] - KeyData[1];
  blk[2] := blk[2] - KeyData[2];
  blk[3] := blk[3] - KeyData[3];

  PDWord(@OutData)^ := blk[0];
  PDWord(longword(@OutData) + 4)^ := blk[1];
  PDWord(longword(@OutData) + 8)^ := blk[2];
  PDWord(longword(@OutData) + 12)^ := blk[3];
end;

end.
