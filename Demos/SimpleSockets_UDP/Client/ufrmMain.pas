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
  System.Diagnostics, ncLines, ncUDPSockets, ncIPUtils;

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
      const aBuf: TBytes; aBufCount: Integer;
      const SenderAddr: TSockAddrStorage);

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
    Log('UDP Client Deactivated');
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
      UDPClient.Host := edtHost.Text;

      // Activate the UDP client
      UDPClient.Active := True;
      btnActivate.Caption := 'Stop UDP Client';
      Log('UDP Client Activated');
    except
      on E: Exception do
        Log('Failed to activate UDP Client: ' + E.Message);
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
    if Trim(edtDataToSend.Text) = '' then
    begin
      Log('Cannot send - Data field cannot be blank.');
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
  const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddrStorage);
var
  ReceivedData: string;
  BytesReceived: TBytes;
  SenderIP: string;
begin
  // Convert received data to string
  ReceivedData := StringOf(Copy(aBuf, 0, aBufCount));

  // Get sender IP address using our utils
  try
    SenderIP := TncIPUtils.GetIPFromStorage(SenderAddr);
  except
    on E: EIPError do
      SenderIP := Format('Invalid Address: %s', [E.Message]);
  end;

  Form1.Log(Format('Received from %s: %s', [SenderIP, ReceivedData]));
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
