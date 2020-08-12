program VideoChatClient;

uses
  System.StartUpCopy,
  FMX.Forms,
  FMX.Types,
  ufrmMain in 'ufrmMain.pas' {frmMain},
  CommonCommands in '..\Server\CommonCommands.pas';

{$R *.res}

begin
  {$IFDEF DEBUG}
  ReportMemoryLeaksOnShutdown := True;
  {$ENDIF}
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
