program DBServerApplication;

uses
  Forms,
  ufrmMain in 'ufrmMain.pas' { frmMain } ,
  uscvServiceCommands in '..\Service\uscvServiceCommands.pas',
  usvcMain in '..\Service\usvcMain.pas' { svcMain: TService } ;
{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;

  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.ShowMainForm := False;
  Service := TNetcomDataServer.Create(nil);
  try
    Application.Title := Service.DisplayName;
    Application.CreateForm(TfrmMain, frmMain);
    Application.Run;
  finally
    Service.Free;
  end;
end.
