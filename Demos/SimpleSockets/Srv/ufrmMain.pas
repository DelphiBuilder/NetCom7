unit ufrmMain;

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows, WinApi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, Vcl.Forms, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.Samples.Spin,
  System.Diagnostics, ncLines, ncSocketList, ncSockets;

type
  TfrmMain = class(TForm)
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
    procedure TCPServerReadData(Sender: TObject; aLine: TncLine; const aBuf: TArray<System.Byte>; aBufCount: Integer);
    procedure btnActivateClick(Sender: TObject);
    procedure edtPortChange(Sender: TObject);
    procedure btnShutdownAllClientsClick(Sender: TObject);
  private
  public
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  try
    TCPServer.Active := True;
    memLog.Lines.Add('Server is active at port: ' + IntToStr(TCPServer.Port));
    btnActivate.Caption := 'Deactivate';
  except
    on e: Exception do
      memLog.Lines.Add('Server cannot activate. ' + e.Message);
  end;
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  TCPServer.Active := False;
end;

procedure TfrmMain.btnActivateClick(Sender: TObject);
begin
  try
    TCPServer.Active := not TCPServer.Active;
  finally
    if TCPServer.Active then
    begin
      memLog.Lines.Add('Server is active at port: ' + IntToStr(TCPServer.Port));
      btnActivate.Caption := 'Deactivate';
    end
    else
    begin
      memLog.Lines.Add('Server was deactivated');
      btnActivate.Caption := 'Activate';
    end;
  end;
end;

procedure TfrmMain.edtPortChange(Sender: TObject);
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

procedure TfrmMain.btnShutdownAllClientsClick(Sender: TObject);
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


procedure TfrmMain.TCPServerConnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      memLog.Lines.Add('Connected: ' + aLine.PeerIP);
    end);

  TCPServer.Send(aLine, BytesOf('Hello mr. ' + IntToStr(aLine.Handle)));
end;

procedure TfrmMain.TCPServerDisconnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      memLog.Lines.Add('Disconnected: ' + aLine.PeerIP);
    end);
end;

procedure TfrmMain.TCPServerReadData(Sender: TObject; aLine: TncLine; const aBuf: TArray<System.Byte>; aBufCount: Integer);
var
  BytesReceived: TBytes;
begin
  BytesReceived := Copy(aBuf, 0, aBufCount);

  TThread.Queue(nil,
    procedure
    begin
      memLog.Lines.Add('Received: "' + StringOf(BytesReceived) + '" from: ' + aLine.PeerIP);
    end);

  // Send back the buffer received
  TCPServer.Send(aLine, BytesReceived);
end;

end.
