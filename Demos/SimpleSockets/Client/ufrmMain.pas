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
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pnlAddress: TPanel;
    edtHost: TEdit;
    edtPort: TSpinEdit;
    Panel1: TPanel;
    btnSendData: TButton;
    Panel2: TPanel;
    edtDataToSend: TEdit;
    TCPClient: TncTCPClient;
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
    procedure FormCreate(Sender: TObject);
  private
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
//
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  TCPClient.Active := False;
end;

// *****************************************************************************
// Start/Stop Main CLient
// *****************************************************************************
procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if TCPClient.Active then
  begin
    // Deactivate the TCP client
    TCPClient.Active := False;
    btnActivate.Caption := 'Start TCP Client';
    Log('TCP Client Deactivated');
  end
  else
  begin
    // Check if the host field is blank
    if Trim(edtHost.Text) = '' then
    begin
      Log('Host field cannot be blank.');
      Exit; // Exit the procedure if the host field is blank
    end;

    try
      // Set the host from the text field
      TCPClient.Host := edtHost.Text;

      // Activate the TCP client
      TCPClient.Active := True;
      btnActivate.Caption := 'Stop TCP Client';
      Log('TCP Client Activated');
    except
      on E: Exception do
        Log('Failed to activate TCP Client: ' + E.Message);
    end;
  end;
end;

// *****************************************************************************
// Change host (server)
// *****************************************************************************
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

// *****************************************************************************
// Change Main Client port
// *****************************************************************************
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

// *****************************************************************************
// Data to send
// *****************************************************************************
procedure TForm1.edtDataToSendEnter(Sender: TObject);
begin
  btnSendData.Default := True;
end;

procedure TForm1.edtDataToSendExit(Sender: TObject);
begin
  btnSendData.Default := False;
end;

procedure TForm1.btnSendDataClick(Sender: TObject);
begin
  // Check if the data field is blank
  if Trim(edtDataToSend.Text) = '' then
  begin
    Log('Cannot send - Data field cannot be blank.');
    Exit; // Exit the procedure if the data field is blank
  end;

  try
    // Send the data
    TCPClient.Send(edtDataToSend.Text);
    Log('Data sent: ' + edtDataToSend.Text);
  except
    on E: Exception do
      Log('Failed to send data: ' + E.Message);
  end;
end;

// *****************************************************************************
// TCPClientConnected
// *****************************************************************************
procedure TForm1.TCPClientConnected(Sender: TObject; aLine: TncLine);
begin
  Log('Connected');
  btnActivate.Caption := 'Deactivate';
end;

// *****************************************************************************
// TCPClientDisconnected
// *****************************************************************************
procedure TForm1.TCPClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Disconnected');
  btnActivate.Caption := 'Activate';
end;

// *****************************************************************************
// TCPClientReconnected
// *****************************************************************************
procedure TForm1.TCPClientReconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Reconnected');
end;

// *****************************************************************************
// Read Data
// *****************************************************************************
procedure TForm1.TCPClientReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  BytesReceived: TBytes;
begin
  BytesReceived := Copy(aBuf, 0, aBufCount);

  Log('Received: ' + StringOf(BytesReceived));

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
