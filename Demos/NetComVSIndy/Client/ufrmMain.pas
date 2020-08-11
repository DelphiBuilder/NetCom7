unit ufrmMain;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.Samples.Spin,
  IdTCPConnection, IdTCPClient, IdBaseComponent, IdComponent, IdCustomTCPServer,
  IdTCPServer, IdContext, IdGlobal,
  Winapi.Winsock2, System.Diagnostics, ncSockets, ncLines;

const
  // We are testing the socket mechanisms here and not how fast tcp/ip is,
  // therefore the buffer sent back and forth is kept at a fairly minimal size
  BuffSize = 256;

type
  TfrmMain = class(TForm)
    ncClient: TncTCPClient;
    idClient: TIdTCPClient;
    pnlToolbar: TPanel;
    memLog: TMemo;
    btnTestSpeed: TButton;
    edtIterations: TSpinEdit;
    Label1: TLabel;
    rbTestNetCom: TRadioButton;
    rbTestIndy: TRadioButton;
    procedure FormCreate(Sender: TObject);
    procedure btnTestSpeedClick(Sender: TObject);
  private
    BufferSend, BufferRead: TBytes;
    idBufferSend, idBufferRead: TidBytes;
  public
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  SetLength(BufferSend, BuffSize);
  SetLength(BufferRead, BuffSize);
  SetLength(idBufferSend, BuffSize);
  SetLength(idBufferRead, BuffSize);
end;

procedure TfrmMain.btnTestSpeedClick(Sender: TObject);
var
  i: Integer;
  TimeSt: Cardinal;
  TimeTaken: Cardinal;
begin
  if rbTestNetCom.Checked then
    ncClient.Active := True;
  if rbTestIndy.Checked then
    idClient.Connect;

  if rbTestNetCom.Checked then
  begin
    memLog.Lines.Add('Testing NetCom...');
    TimeSt := GetTickCount;
    for i := 1 to edtIterations.Value do
    begin
      ncClient.Send(BufferSend);
      ncClient.ReceiveRaw(BufferRead);
    end;
    TimeTaken := GetTickCount - TimeSt;
    memLog.Lines.Add('Time taken: ' + IntToStr(TimeTaken) + ' msec');
  end;

  if rbTestIndy.Checked then
  begin
    memLog.Lines.Add('Testing Indy...');
    TimeSt := GetTickCount;
    for i := 1 to edtIterations.Value do
    begin
      idClient.Socket.Write(idBufferSend);
      idClient.Socket.ReadBytes(idBufferRead, BuffSize, False);
    end;
    TimeTaken := GetTickCount - TimeSt;
    memLog.Lines.Add('Time taken: ' + IntToStr(TimeTaken) + ' msec');
  end;

  if rbTestNetCom.Checked then
    ncClient.Active := False;
  if rbTestIndy.Checked then
    idClient.Disconnect;
end;

end.
