unit ufrmMain;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Edit, FMX.Layouts, FMX.Controls.Presentation, FMX.ScrollBox,
  FMX.Memo, System.SyncObjs, ncSources;

type
  TfrmMain = class(TForm)
    memLog: TMemo;
    ltMain: TLayout;
    edtText: TEdit;
    btnSend: TButton;
    Client: TncClientSource;
    tmrUpdateLog: TTimer;
    edtClientName: TEdit;
    ToolBar1: TToolBar;
    btnActivateClient: TButton;
    edtHost: TEdit;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnSendClick(Sender: TObject);
    procedure tmrUpdateLogTimer(Sender: TObject);
    function ClientHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer;
      const aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
    procedure edtTextEnter(Sender: TObject);
    procedure edtTextExit(Sender: TObject);
    procedure btnActivateClientClick(Sender: TObject);
    procedure ClientConnected(Sender: TObject; aLine: TncLine);
    procedure ClientDisconnected(Sender: TObject; aLine: TncLine);
    procedure ClientReconnected(Sender: TObject; aLine: TncLine);
    procedure edtHostChange(Sender: TObject);
  private
    LogLock: TCriticalSection;
    LogLines, LogLinesCopy: TStringList;
  public
    procedure Log(aStr: string);
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.fmx}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  LogLock := TCriticalSection.Create;
  LogLines := TStringList.Create;
  LogLinesCopy := TStringList.Create;
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  Client.Active := False;

  LogLinesCopy.Free;
  LogLines.Free;
  LogLock.Free;
end;

procedure TfrmMain.Log(aStr: string);
begin
  // This is thread safe
  LogLock.Acquire;
  try
    LogLines.Add (aStr);
  finally
    LogLock.Release;
  end;
end;

procedure TfrmMain.tmrUpdateLogTimer(Sender: TObject);
var
  i: Integer;
begin
  // Update the memLog from LogLines
  LogLock.Acquire;
  try
    LogLinesCopy.Assign(LogLines);
    LogLines.Clear;
  finally
    LogLock.Release;
  end;

  for i := 0 to LogLinesCopy.Count - 1 do
  begin
    memLog.Lines.Add(LogLinesCopy.Strings[i]);
    memLog.SelStart := Length(memLog.Text);
  end;
  LogLinesCopy.Clear;
end;

procedure TfrmMain.btnActivateClientClick(Sender: TObject);
begin
  Client.Active := not Client.Active;
end;

procedure TfrmMain.btnSendClick(Sender: TObject);
begin
  Client.ExecCommand(0, BytesOf (edtClientName.Text + ': ' + edtText.Text));
  edtText.Text := '';
end;

procedure TfrmMain.edtHostChange(Sender: TObject);
begin
  if not Client.Active then
    Client.Host := edtHost.Text;
end;

procedure TfrmMain.edtTextEnter(Sender: TObject);
begin
  btnSend.Default := True;
end;

procedure TfrmMain.edtTextExit(Sender: TObject);
begin
  btnSend.Default := False;
end;

procedure TfrmMain.ClientConnected(Sender: TObject; aLine: TncLine);
begin
  Log ('Client connected to peer: ' + aLine.PeerIP);
  TThread.Synchronize(nil,
  procedure
  begin
    btnActivateClient.Text := 'Deactivate client';
  end);
end;

procedure TfrmMain.ClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  Log ('Client disconnected from peer: ' + aLine.PeerIP);
  TThread.Synchronize(nil,
  procedure
  begin
    btnActivateClient.Text := 'Activate client';
  end);
end;

procedure TfrmMain.ClientReconnected(Sender: TObject; aLine: TncLine);
begin
  Log ('Client was reconnected to peer: ' + aLine.PeerIP);
end;

function TfrmMain.ClientHandleCommand(Sender: TObject; aLine: TncLine;
  aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
  const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
begin
  Log (Stringof (aData));
end;

end.
