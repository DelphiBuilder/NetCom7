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

function FileSize(const AFilename: string): Int64;
var
  FileStream: TFileStream;
begin
  Result := 0;
  if FileExists(AFilename) then
  try
    FileStream := TFileStream.Create(AFilename, fmOpenRead or fmShareDenyNone);
    try
      Result := FileStream.Size;
    finally
      FileStream.Free;
    end;
  except
    Result := 0;
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  CertPath: string;
begin
  FConnectionCount := 0;
  UpdateConnectionCount;
  
  // Configure TLS settings for the server
  ncServer1.UseTLS := True;                                                    // Enable TLS encryption
  ncServer1.TlsProvider := tpSChannel;                                         // Use Windows SChannel (Windows built-in TLS)
  
  // Verify certificate file exists
  CertPath := ExtractFilePath(Application.ExeName) + 'server.pfx';
  if FileExists(CertPath) then
  begin
    ncServer1.CertificateFile := CertPath;                                     // Certificate file path
    ncServer1.PrivateKeyPassword := 'test';                                    // Certificate password
    ncServer1.IgnoreCertificateErrors := True;                                 // For demo purposes
    
    Log('Certificate file found: ' + CertPath);
    Log('Certificate file size: ' + IntToStr(FileSize(CertPath)) + ' bytes');
  end
  else
  begin
    Log('ERROR: Certificate file not found: ' + CertPath);
    Log('Please ensure server.pfx is in the same directory as the executable');
    // Still configure TLS but it will fail
    ncServer1.CertificateFile := CertPath;
    ncServer1.PrivateKeyPassword := 'test';
    ncServer1.IgnoreCertificateErrors := False;
  end;
  
  // Set initial button caption
  btnActivate.Caption := 'Start TLS Server';
  
  Log('TLS Server configured with SChannel provider');
  Log('Note: Certificate errors are ignored for demo purposes');
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  ncServer1.Active := False;
  Log('TLS Server shutdown complete');
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
    btnActivate.Caption := 'Start TLS Server';
    Log('TLS Server Deactivated');
  end
  else
  begin
    try
      // Validate TLS configuration before starting
      if not FileExists(ncServer1.CertificateFile) then
      begin
        Log('ERROR: Certificate file not found: ' + ncServer1.CertificateFile);
        Log('Cannot start TLS server without valid certificate');
        Exit;
      end;
      
      Log('Starting TLS server with configuration:');
      Log('  UseTLS: ' + BoolToStr(ncServer1.UseTLS, True));
      Log('  TlsProvider: ' + IntToStr(Ord(ncServer1.TlsProvider)));
      Log('  Certificate: ' + ncServer1.CertificateFile);
      Log('  IgnoreCertErrors: ' + BoolToStr(ncServer1.IgnoreCertificateErrors, True));
      
      // Activate the TCP Server
      ncServer1.Port := edtPort.Value;
      ncServer1.Active := True;
      btnActivate.Caption := 'Stop TLS Server';
      Log('TLS Server Activated at port: ' + IntToStr(ncServer1.Port));
      Log('Server ready to accept TLS connections');

    except
      on E: Exception do
      begin
        Log('Failed to activate TLS Server: ' + E.Message);
        Log('Exception class: ' + E.ClassName);
      end;
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
    Log('Shutting down all TLS clients...');
    for i := 0 to SocketList.Count - 1 do
      ncServer1.ShutDownLine(SocketList.Lines[i]);
    Log('All TLS clients shutdown requested');
  finally
    ncServer1.Lines.UnlockList;
  end;
end;

procedure TForm1.UpdateConnectionCount;
begin
  StatusBar1.Panels[0].Text := 'TLS Connections: ' + IntToStr(FConnectionCount);
end;

// *****************************************************************************
// TCPServerConnected
// *****************************************************************************
procedure TForm1.TCPServerConnected(Sender: TObject; aLine: TncLine);
begin
  Inc(FConnectionCount);
  UpdateConnectionCount;

  Log('TLS Client Connected: ' + aLine.PeerIP + ' (Handle: ' + IntToStr(aLine.Handle) + ')');
  Log('Starting TLS handshake...');
  
  try
    // Send welcome message
    ncServer1.Send(aLine, BytesOf('Hello mr. ' + IntToStr(aLine.Handle) + ' - TLS connection established'));
    Log('Welcome message sent to: ' + aLine.PeerIP);
    Log('TLS handshake completed successfully');
  except
    on E: Exception do
    begin
      Log('ERROR during TLS handshake with ' + aLine.PeerIP + ': ' + E.Message);
      Log('Exception class: ' + E.ClassName);
      // Don't re-raise - let the connection continue to see what happens
    end;
  end;
end;

// *****************************************************************************
// TCPServerDisconnected
// *****************************************************************************
procedure TForm1.TCPServerDisconnected(Sender: TObject; aLine: TncLine);
begin
  Dec(FConnectionCount);
  UpdateConnectionCount;

  Log('TLS Client Disconnected: ' + aLine.PeerIP + ' (Handle: ' + IntToStr(aLine.Handle) + ')');
  Log('Connection duration: Client was connected');

end;

// *****************************************************************************
// Read Data
// *****************************************************************************
procedure TForm1.TCPServerReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  BytesReceived: TBytes;
  ReceivedText: string;
begin
  try
    BytesReceived := Copy(aBuf, 0, aBufCount);

    // Convert bytes to string using proper UTF-8 decoding
    ReceivedText := TEncoding.UTF8.GetString(BytesReceived);

    Log('Received via TLS: "' + ReceivedText + '" from: ' + aLine.PeerIP + ' (Handle: ' + IntToStr(aLine.Handle) + ')');

    // Send back the buffer received
    ncServer1.Send(aLine, BytesReceived);

    Log('Data sent via TLS: ' + ReceivedText + ' to: ' + aLine.PeerIP);
  except
    on E: Exception do
    begin
      Log('ERROR in TLS data handling with ' + aLine.PeerIP + ': ' + E.Message);
      Log('Exception class: ' + E.ClassName);
    end;
  end;
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
