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
  System.Diagnostics, ncLines, ncSocketList, ncSockets, ncTSockets;

type
  TForm1 = class(TForm)
    memLog: TMemo;
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pblPort: TPanel;
    edtPort: TSpinEdit;
    btnShutdownAllClients: TButton;
    StatusBar1: TStatusBar;
    ncServer1: TncServer;
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
  
  // Connect event handlers to component events
  ncServer1.OnConnected := TCPServerConnected;
  ncServer1.OnDisconnected := TCPServerDisconnected;
  ncServer1.OnReadData := TCPServerReadData;
  
  // Set default port
  edtPort.Value := 16233;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  ncServer1.Active := False;
end;

// *****************************************************************************
// Start/Stop Main Server
// *****************************************************************************
procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if ncServer1.Active then
  begin
    // Deactivate the TCP Server
    ncServer1.Active := False;
    btnActivate.Caption := 'Start TCP Server';
    Log('TCP Server Deactivated');
  end
  else
  begin
    try
      // Activate the TCP Server
      ncServer1.Port := edtPort.Value;
      ncServer1.Active := True;
      btnActivate.Caption := 'Stop TCP Server';
      Log('TCP Server Activated at port: ' + IntToStr(ncServer1.Port));
      Log('Using thread pool with ' + IntToStr(ncServer1.GetThreadPoolThreadCount) + ' processing threads');

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
    ncServer1.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := ncServer1.Port;
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
  SocketList := ncServer1.Lines.LockList;
  try
    for i := 0 to SocketList.Count - 1 do
      ncServer1.ShutDownLine(SocketList.Lines[i]);
  finally
    ncServer1.Lines.UnlockList;
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

  ncServer1.Send(aLine, BytesOf('Hello mr. ' + IntToStr(aLine.Handle)));
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
  ThreadID: TThreadID;
begin
  ThreadID := GetCurrentThreadId;
  BytesReceived := Copy(aBuf, 0, aBufCount);

  Log(Format('Received: "%s" from: %s [Thread: %d]', [StringOf(BytesReceived), aLine.PeerIP, ThreadID]));

  // Send back the buffer received (echo server)
  ncServer1.Send(aLine, BytesReceived);

  Log(Format('Echoed back: "%s" [Thread: %d]', [StringOf(BytesReceived), ThreadID]));
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
