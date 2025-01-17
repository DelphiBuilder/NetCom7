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
  System.Diagnostics, ncLines, ncUDPSockets;

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
    UDPClient: TncUDPClient;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnActivateClick(Sender: TObject);
    procedure edtHostChange(Sender: TObject);
    procedure edtPortChange(Sender: TObject);
    procedure edtDataToSendEnter(Sender: TObject);
    procedure edtDataToSendExit(Sender: TObject);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure btnSendDataClick(Sender: TObject);
    procedure UDPClientReadDatagram(Sender: TObject; aLine: TncLine;
      const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddr);
  private
    { Private declarations }
  public
    { Public declarations }
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
  UDPClient.Active := False;
end;

// *****************************************************************************
// Start/Stop Main CLient
// *****************************************************************************
procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if UDPClient.Active then
  begin
    // Deactivate the UDP client
    UDPClient.Active := False;
    btnActivate.Caption := 'Start UDP Client';
    Form1.Log('UDP Client Deactivated');
  end
  else
  begin
    try
      // Activate the UDP client
      UDPClient.Active := True;
      btnActivate.Caption := 'Stop UDP Client';
      Form1.Log('UDP Client Activated');
    except
      on E: Exception do
        Form1.Log('Failed to activate UDP Client: ' + E.Message);
    end;
  end;
end;

// *****************************************************************************
// Change host (server)
// *****************************************************************************
procedure TForm1.edtHostChange(Sender: TObject);
begin
  try
    UDPClient.Host := edtHost.Text;
  except
    edtHost.OnChange := nil;
    try
      edtHost.Text := UDPClient.Host;
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
    UDPClient.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := UDPClient.Port;
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
  try
    // Ensure the client is active
    if not UDPClient.Active then
    begin
      Log('Cannot send - client not active');
      Exit;
    end;

    // Ensure the input field is not empty
    if Trim(edtHost.Text) = '' then
    begin
      Log('Cannot send - data field is blank');
      Exit;
    end;

    // Send the data if all conditions are met
    UDPClient.Send(edtDataToSend.Text);
    Log(Format('Data sent: %s', [edtDataToSend.Text]));
  except
    on E: Exception do
      Log('Error sending: ' + E.Message);
  end;
end;

// *****************************************************************************
// Read Data
// *****************************************************************************
procedure TForm1.UDPClientReadDatagram(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddr);
var
  SenderIP: string;
begin
  // Format the sender IP address
  SenderIP := Format('%d.%d.%d.%d', [Ord(SenderAddr.sa_data[2]),
    Ord(SenderAddr.sa_data[3]), Ord(SenderAddr.sa_data[4]),
    Ord(SenderAddr.sa_data[5])]);

  // Use the received buffer directly
  Form1.Log(Format('Received from %s: %s',
    [SenderIP, StringOf(Copy(aBuf, 0, aBufCount))]));
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
