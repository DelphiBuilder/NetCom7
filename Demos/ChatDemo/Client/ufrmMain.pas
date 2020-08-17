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
    edtClientName: TEdit;
    ToolBar1: TToolBar;
    btnActivateClient: TButton;
    edtHost: TEdit;
    procedure FormDestroy(Sender: TObject);
    procedure btnSendClick(Sender: TObject);
    function ClientHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
    procedure edtTextEnter(Sender: TObject);
    procedure edtTextExit(Sender: TObject);
    procedure btnActivateClientClick(Sender: TObject);
    procedure ClientConnected(Sender: TObject; aLine: TncLine);
    procedure ClientDisconnected(Sender: TObject; aLine: TncLine);
    procedure ClientReconnected(Sender: TObject; aLine: TncLine);
    procedure edtHostChange(Sender: TObject);
  private
  public
    procedure Log(aStr: string);
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.fmx}

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  Client.Active := False;
end;

procedure TfrmMain.Log(aStr: string);
begin
  // This is thread safe
  TThread.Queue(nil,
    procedure
    begin
      memLog.Lines.Add(aStr);
      memLog.ScrollBy(0, 100);
    end);
end;

procedure TfrmMain.btnActivateClientClick(Sender: TObject);
begin
  Client.Active := not Client.Active;
end;

procedure TfrmMain.btnSendClick(Sender: TObject);
begin
  Client.ExecCommand(0, BytesOf(edtClientName.Text + ': ' + edtText.Text));
  edtText.Text := '';
end;

procedure TfrmMain.edtHostChange(Sender: TObject);
begin
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
  Log('Client connected to peer: ' + aLine.PeerIP);
  TThread.Queue(nil,
    procedure
    begin
      btnActivateClient.Text := 'Deactivate client';
    end);
end;

procedure TfrmMain.ClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Client disconnected from peer: ' + aLine.PeerIP);
  TThread.Queue(nil,
    procedure
    begin
      btnActivateClient.Text := 'Activate client';
    end);
end;

procedure TfrmMain.ClientReconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Client was reconnected to peer: ' + aLine.PeerIP);
end;

function TfrmMain.ClientHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
begin
  Log(Stringof(aData));
end;

end.
