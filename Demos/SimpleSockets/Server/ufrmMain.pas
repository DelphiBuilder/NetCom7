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
  System.Diagnostics, ncLines, ncSocketList, ncSockets;

type
  TForm1 = class(TForm)
    memLog: TMemo;
    TCPServer: TncTCPServer;
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pblPort: TPanel;
    edtPort: TSpinEdit;
    btnShutdownAllClients: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure TCPServerConnected(Sender: TObject; aLine: TncLine);
    procedure TCPServerDisconnected(Sender: TObject; aLine: TncLine);
    procedure btnActivateClick(Sender: TObject);
    procedure edtPortChange(Sender: TObject);
    procedure btnShutdownAllClientsClick(Sender: TObject);
    procedure TCPServerReadData(Sender: TObject; aLine: TncLine;
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

procedure TForm1.FormCreate(Sender: TObject);
begin
  try
    TCPServer.Active := True;
    Log('Server is active at port: ' + IntToStr(TCPServer.Port));
    btnActivate.Caption := 'Deactivate';
  except
    on e: Exception do
      Log('Server cannot activate. ' + e.Message);
  end;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  TCPServer.Active := False;
end;

procedure TForm1.btnActivateClick(Sender: TObject);
begin
  try
    TCPServer.Active := not TCPServer.Active;
  finally
    if TCPServer.Active then
    begin
      Log('Server is active at port: ' + IntToStr(TCPServer.Port));
      btnActivate.Caption := 'Deactivate';
    end
    else
    begin
      Log
      ('Server was deactivated');
      btnActivate.Caption := 'Activate';
    end;
  end;
end;

procedure TForm1.edtPortChange(Sender: TObject);
begin
  try
    TCPServer.Port := edtPort.Value;
  except
    // if it is active, it will not allow us to change the value,
    // revert the edtPort value to its original
    edtPort.Value := TCPServer.Port;
    raise; // Reraise the exception so as the user sees the error
  end;
end;

procedure TForm1.btnShutdownAllClientsClick(Sender: TObject);
var
  SocketList: TSocketList;
  i: Integer;
begin
  SocketList := TCPServer.Lines.LockList;
  try
    for i := 0 to SocketList.Count - 1 do
      TCPServer.ShutDownLine(SocketList.Lines[i]);
  finally
    TCPServer.Lines.UnlockList;
  end;
end;

procedure TForm1.TCPServerConnected(Sender: TObject; aLine: TncLine);
begin

  Log('Connected: ' + aLine.PeerIP);

  TCPServer.Send(aLine, BytesOf('Hello mr. ' + IntToStr(aLine.Handle)));
end;

procedure TForm1.TCPServerDisconnected(Sender: TObject; aLine: TncLine);
begin

  Log('Disconnected: ' + aLine.PeerIP);

end;

procedure TForm1.TCPServerReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  BytesReceived: TBytes;
begin
  BytesReceived := Copy(aBuf, 0, aBufCount);

  Log('Received: "' + StringOf(BytesReceived) + '" from: ' + aLine.PeerIP);

  // Send back the buffer received
  TCPServer.Send(aLine, BytesReceived);
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
