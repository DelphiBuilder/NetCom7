program Client;

uses
  Vcl.Forms,
  uMainClient in 'uMainClient.pas' {Form1},
  Vcl.Themes,
  Vcl.Styles;

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TStyleManager.TrySetStyle('Carbon');
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
