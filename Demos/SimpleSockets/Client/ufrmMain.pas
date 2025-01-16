unit ufrmMain;

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows, WinApi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, Vcl.Forms, Vcl.Controls, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.Samples.Spin,
  System.Diagnostics, ncLines, ncSockets;

type
  TForm1 = class(TForm)
    memLog: TMemo;
    TCPClient: TncTCPClient;
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pnlAddress: TPanel;
    edtHost: TEdit;
    edtPort: TSpinEdit;
    Panel1: TPanel;
    btnSendData: TButton;
    Panel2: TPanel;
    edtDataToSend: TEdit;
    procedure btnActivateClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure TCPClientConnected(Sender: TObject; aLine: TncLine);
    procedure TCPClientDisconnected(Sender: TObject; aLine: TncLine);
    procedure TCPClientReconnected(Sender: TObject; aLine: TncLine);

    procedure edtHostChange(Sender: TObject);
    procedure edtPortChange(Sender: TObject);
    procedure btnSendDataClick(Sender: TObject);
    procedure edtDataToSendEnter(Sender: TObject);
    procedure edtDataToSendExit(Sender: TObject);
    procedure TCPClientReadData(Sender: TObject; aLine: TncLine;
      const aBuf: TBytes; aBufCount: Integer);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
  private
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormDestroy(Sender: TObject);
begin
  TCPClient.Active := False;
end;

procedure TForm1.edtHostChange(Sender: TObject);
begin
  try
    TCPClient.Host := edtHost.Text;
  except
    edtHost.OnChange := nil;
    try
      edtHost.Text := TCPClient.Host;
    finally
      edtHost.OnChange := edtHostChange;
    end;
    raise;
  end;
end;

procedure TForm1.edtPortChange(Sender: TObject);
begin
  try
    TCPClient.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := TCPClient.Port;
    finally
      edtPort.OnChange := edtPortChange;
    end;
    raise;
  end;
end;

procedure TForm1.btnActivateClick(Sender: TObject);
begin
  TCPClient.Active := not TCPClient.Active;
end;



procedure TForm1.edtDataToSendEnter(Sender: TObject);
begin
  btnSendData.Default := True;
end;

procedure TForm1.edtDataToSendExit(Sender: TObject);
begin
  btnSendData.Default := False;
end;

procedure TForm1.TCPClientConnected(Sender: TObject; aLine: TncLine);
begin
  Log('Connected');
  btnActivate.Caption := 'Deactivate';

end;

procedure TForm1.TCPClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Disconnected');
  btnActivate.Caption := 'Activate';
end;

procedure TForm1.TCPClientReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  BytesReceived: TBytes;
begin
  BytesReceived := Copy(aBuf, 0, aBufCount);

  Log('Received: ' + StringOf(BytesReceived));

end;

procedure TForm1.TCPClientReconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Reconnected');
end;

procedure TForm1.btnSendDataClick(Sender: TObject);
begin
  TCPClient.Send(edtDataToSend.Text);
end;

// *****************************************************************************
// Memo Log
// *****************************************************************************
procedure TForm1.Log(const AMessage: string);
begin
  TThread.Queue(nil,
    procedure
    begin
      try
        memLog.Lines.Add(Format('[%s] %s', [FormatDateTime('hh:nn:ss.zzz', Now),
          AMessage]));
      finally
      end;
    end);
end;

procedure TForm1.memLogKeyDown(Sender: TObject; var Key: Word;
Shift: TShiftState);
begin
  if (Shift = [ssCtrl]) and (Key = Ord('A')) then
    memLog.SelectAll
  else if (Shift = [ssCtrl]) and (Key = Ord('C')) then
    memLog.CopyToClipboard;
end;

end.
