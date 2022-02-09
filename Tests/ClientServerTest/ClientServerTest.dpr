program ClientServerTest;

uses
  Vcl.Forms,
  UClientServerTestForm in 'UClientServerTestForm.pas' {ClientServerTestForm},
  ncCommandHandlers in '..\..\Source\ncCommandHandlers.pas',
  ncCommandPacking in '..\..\Source\ncCommandPacking.pas',
  ncCompression in '..\..\Source\ncCompression.pas',
  ncEncryption in '..\..\Source\ncEncryption.pas',
  ncLines in '..\..\Source\ncLines.pas',
  ncPendingCommandsList in '..\..\Source\ncPendingCommandsList.pas',
  ncSerializeValue in '..\..\Source\ncSerializeValue.pas',
  ncSocketList in '..\..\Source\ncSocketList.pas',
  ncSockets in '..\..\Source\ncSockets.pas',
  ncSources in '..\..\Source\ncSources.pas',
  ncThreads in '..\..\Source\ncThreads.pas',
  ncEncBlockciphers in '..\..\Source\Encryption\ncEncBlockciphers.pas',
  ncEncBlowfish in '..\..\Source\Encryption\ncEncBlowfish.pas',
  ncEncCast128 in '..\..\Source\Encryption\ncEncCast128.pas',
  ncEncCast256 in '..\..\Source\Encryption\ncEncCast256.pas',
  ncEncCrypt2 in '..\..\Source\Encryption\ncEncCrypt2.pas',
  ncEncDes in '..\..\Source\Encryption\ncEncDes.pas',
  ncEncHaval in '..\..\Source\Encryption\ncEncHaval.pas',
  ncEncIce in '..\..\Source\Encryption\ncEncIce.pas',
  ncEncIdea in '..\..\Source\Encryption\ncEncIdea.pas',
  ncEncMars in '..\..\Source\Encryption\ncEncMars.pas',
  ncEncMd4 in '..\..\Source\Encryption\ncEncMd4.pas',
  ncEncMd5 in '..\..\Source\Encryption\ncEncMd5.pas',
  ncEncMisty1 in '..\..\Source\Encryption\ncEncMisty1.pas',
  ncEncRc2 in '..\..\Source\Encryption\ncEncRc2.pas',
  ncEncRc4 in '..\..\Source\Encryption\ncEncRc4.pas',
  ncEncRc5 in '..\..\Source\Encryption\ncEncRc5.pas',
  ncEncRc6 in '..\..\Source\Encryption\ncEncRc6.pas',
  ncEncRijndael in '..\..\Source\Encryption\ncEncRijndael.pas',
  ncEncRipemd128 in '..\..\Source\Encryption\ncEncRipemd128.pas',
  ncEncRipemd160 in '..\..\Source\Encryption\ncEncRipemd160.pas',
  ncEncSerpent in '..\..\Source\Encryption\ncEncSerpent.pas',
  ncEncSha1 in '..\..\Source\Encryption\ncEncSha1.pas',
  ncEncSha256 in '..\..\Source\Encryption\ncEncSha256.pas',
  ncEncSha512 in '..\..\Source\Encryption\ncEncSha512.pas',
  ncEncTea in '..\..\Source\Encryption\ncEncTea.pas',
  ncEncTiger in '..\..\Source\Encryption\ncEncTiger.pas',
  ncEncTwofish in '..\..\Source\Encryption\ncEncTwofish.pas';

{$R *.res}

var
  ClientServerTestForm: TClientServerTestForm;

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TClientServerTestForm, ClientServerTestForm);
  Application.Run;
end.
