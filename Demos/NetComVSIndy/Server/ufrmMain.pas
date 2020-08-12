unit ufrmMain;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Winapi.Winsock2,
  IdContext, IdBaseComponent, IdComponent, IdCustomTCPServer, IdTCPServer, IdGlobal,
  System.Diagnostics, ncLines, ncSockets, Vcl.StdCtrls;

type
  TfrmMain = class(TForm)
    ncServer: TncTCPServer;
    idServer: TIdTCPServer;
    Label1: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure ncServerReadData(Sender: TObject; aLine: TncLine;
      const aBuf: TArray<System.Byte>; aBufCount: Integer);
    procedure idServerExecute(AContext: TIdContext);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  ncServer.Active := True;
  idServer.Active := True;
end;

procedure TfrmMain.idServerExecute(AContext: TIdContext);
var
  Data: TIdBytes;
begin
  // Reply with data received
  if not aContext.Connection.IOHandler.InputBufferIsEmpty then
  begin
    aContext.Connection.IOHandler.InputBuffer.ExtractToBytes(Data);
    aContext.Binding.Send(Data);
  end;
end;

procedure TfrmMain.ncServerReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TArray<System.Byte>; aBufCount: Integer);
var
  Data: TBytes;
begin
  // Reply with data received
  Data := Copy (aBuf, 0, aBufCount);
  ncServer.Send(aLine, Data);
end;

end.
