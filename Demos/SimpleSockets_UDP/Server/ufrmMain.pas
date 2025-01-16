unit ufrmMain;

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows, WinApi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, Vcl.Forms, Vcl.Controls, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.Samples.Spin, System.Diagnostics,
  ncLines, ncSocketList, ncUDPSockets;

type
  TForm1 = class(TForm)
    memLog: TMemo;
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pblPort: TPanel;
    edtPort: TSpinEdit;
    UDPServer: TncUDPServer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnActivateClick(Sender: TObject);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure edtPortChange(Sender: TObject);
    procedure SendToClient(const Data: string; const DestAddr: TSockAddr);
    procedure UDPServerReadDatagram(Sender: TObject; aLine: TncLine;
      const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddr);
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
  UDPServer.Active := False;
end;

// *****************************************************************************
// Start/Stop Main CLient
// *****************************************************************************
procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if UDPServer.Active then
  begin
    // Deactivate the UDP client
    UDPServer.Active := False;
    btnActivate.Caption := 'Start UDP Server';
    Form1.Log('UDP Server Deactivated');
  end
  else
  begin
    try
      // Activate the UDP client
      UDPServer.Active := True;
      btnActivate.Caption := 'Stop UDP Server';
      Form1.Log('UDP Server Activated');
    except
      on E: Exception do
        Form1.Log('Failed to activate UDP Server: ' + E.Message);
    end;
  end;
end;

// *****************************************************************************
// Change Main Server port
// *****************************************************************************
procedure TForm1.edtPortChange(Sender: TObject);
begin
  try
    UDPServer.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := UDPServer.Port;
    finally
      edtPort.OnChange := edtPortChange;
    end;
    raise;
  end;
end;

// *****************************************************************************
// SendToClient
// *****************************************************************************
procedure TForm1.SendToClient(const Data: string; const DestAddr: TSockAddr);
begin
  if UDPServer.Active then

  begin
    try
      UDPServer.SendTo(BytesOf(Data), DestAddr);
      Form1.Log(Format('Sent to %d.%d.%d.%d: %s',
        [Ord(DestAddr.sa_data[2]),
         Ord(DestAddr.sa_data[3]),
         Ord(DestAddr.sa_data[4]),
         Ord(DestAddr.sa_data[5]),
         Data]));
    except
      on E: Exception do
        Form1.Log('Error sending data: ' + E.Message);
    end;
  end;
end;

// *****************************************************************************
// Read Data
// *****************************************************************************
procedure TForm1.UDPServerReadDatagram(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddr);
var
  ReceivedData: string;
  SenderIP: string;
begin
  ReceivedData := StringOf(Copy(aBuf, 0, aBufCount));

  SenderIP := Format('%d.%d.%d.%d',
    [Ord(SenderAddr.sa_data[2]),
     Ord(SenderAddr.sa_data[3]),
     Ord(SenderAddr.sa_data[4]),
     Ord(SenderAddr.sa_data[5])]);

  Form1.Log(Format('Received from %s: %s', [SenderIP, ReceivedData]));

  // Echo back to the sender
  SendToClient('Echo: ' + ReceivedData, SenderAddr);

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

procedure TForm1.memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
begin
  if (Shift = [ssCtrl]) and (Key = Ord('A')) then
    memLog.SelectAll
  else if (Shift = [ssCtrl]) and (Key = Ord('C')) then
    memLog.CopyToClipboard;
end;

end.
