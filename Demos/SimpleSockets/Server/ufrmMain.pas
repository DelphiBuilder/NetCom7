unit ufrmMain;

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows, WinApi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, Vcl.Forms, Vcl.Controls, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.Samples.Spin, Vcl.ComCtrls,
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
    StatusBar1: TStatusBar;
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
    FConnectionCount: Integer;
    procedure UpdateConnectionCount;
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
  FConnectionCount := 0;
  UpdateConnectionCount;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  TCPServer.Active := False;
end;

// *****************************************************************************
// Start/Stop Main Server
// *****************************************************************************
procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if TCPServer.Active then
  begin
    // Deactivate the TCP Server
    TCPServer.Active := False;
    btnActivate.Caption := 'Start TCP Server';
    Log('TCP Server Deactivated');
  end
  else
  begin
    try
      // Activate the TCP Server
      TCPServer.Port := edtPort.Value;
      TCPServer.Active := True;
      btnActivate.Caption := 'Stop TCP Server';
      Log('TCP Server Activated at port: ' + IntToStr(TCPServer.Port));

    except
      on E: Exception do
        Log('Failed to activate TCP Server: ' + E.Message);
    end;
  end;
end;

// *****************************************************************************
// Change Main Client port
// *****************************************************************************
procedure TForm1.edtPortChange(Sender: TObject);
begin
  try
    TCPServer.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := TCPServer.Port;
    finally
      edtPort.OnChange := edtPortChange;
    end;
    raise;
  end;
end;

// *****************************************************************************
// Shutdown all Clients
// *****************************************************************************
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

procedure TForm1.UpdateConnectionCount;
begin
  StatusBar1.Panels[0].Text := 'Connections: ' + IntToStr(FConnectionCount);
end;

// *****************************************************************************
// TCPServerConnected
// *****************************************************************************
procedure TForm1.TCPServerConnected(Sender: TObject; aLine: TncLine);
begin
  Inc(FConnectionCount);
  UpdateConnectionCount;

  Log('Connected: ' + aLine.PeerIP);

  TCPServer.Send(aLine, BytesOf('Hello mr. ' + IntToStr(aLine.Handle)));
end;

// *****************************************************************************
// TCPServerDisconnected
// *****************************************************************************
procedure TForm1.TCPServerDisconnected(Sender: TObject; aLine: TncLine);
begin
  Dec(FConnectionCount);
  UpdateConnectionCount;

  Log('Disconnected: ' + aLine.PeerIP);

end;

// *****************************************************************************
// Read Data
// *****************************************************************************
procedure TForm1.TCPServerReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  BytesReceived: TBytes;
begin
  BytesReceived := Copy(aBuf, 0, aBufCount);

  Log('Received: "' + StringOf(BytesReceived) + '" from: ' + aLine.PeerIP);

  // Send back the buffer received
  TCPServer.Send(aLine, BytesReceived);

  Log('Data sent: ' + StringOf(BytesReceived));

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
