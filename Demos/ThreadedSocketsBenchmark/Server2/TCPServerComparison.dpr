program TCPServerComparison;

uses
  Vcl.Forms,
  ufrmTCPServer in 'ufrmTCPServer.pas' {frmTCPServer};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmTCPServer, frmTCPServer);
  Application.Run;
end. 