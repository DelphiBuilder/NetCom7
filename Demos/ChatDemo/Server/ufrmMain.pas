unit ufrmMain;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.StdCtrls, FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo,
  System.SyncObjs, ncSocketList, ncSources;

type
  TfrmMain = class(TForm)
    Server: TncServerSource;
    memLog: TMemo;
    ToolBar1: TToolBar;
    btnActivateServer: TButton;
    btnShutDownClients: TButton;
    procedure FormDestroy(Sender: TObject);
    function ServerHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
    procedure ServerConnected(Sender: TObject; aLine: TncLine);
    procedure ServerDisconnected(Sender: TObject; aLine: TncLine);
    procedure btnActivateServerClick(Sender: TObject);
    procedure btnShutDownClientsClick(Sender: TObject);
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
  Server.Active := False;
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

procedure TfrmMain.btnActivateServerClick(Sender: TObject);
begin
  try
    Server.Active := not Server.Active;
  finally
    if Server.Active then
    begin
      btnActivateServer.Text := 'Deactivate Server';
      Log('Server is activated');
    end
    else
    begin
      btnActivateServer.Text := 'Activate Server';
      Log('Server was deactivated');
    end;
  end;
end;

procedure TfrmMain.ServerConnected(Sender: TObject; aLine: TncLine);
begin
  Log('Client connected: ' + aLine.PeerIP);
end;

procedure TfrmMain.ServerDisconnected(Sender: TObject; aLine: TncLine);
begin
  Log('Client disconnected: ' + aLine.PeerIP);
end;

function TfrmMain.ServerHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
var
  Clients: TSocketList;
  i: Integer;
begin
  Log('Received: "' + StringOf(aData) + '" from peer: ' + aLine.PeerIP);

  // Now send this to all clients
  Clients := Server.Lines.LockList;
  try
    for i := 0 to Clients.Count - 1 do
      // if Clients.Lines[i] <> aLine then  // If you do not want to send text back to original client
      Server.ExecCommand(Clients.Lines[i], 0, aData, False);

    // You can shutdown a line here by calling Server.ShutdownLine,
    // see following procecure
  finally
    Server.Lines.UnlockList;
  end;
end;

procedure TfrmMain.btnShutDownClientsClick(Sender: TObject);
var
  Clients: TSocketList;
  i: Integer;
begin
  Clients := Server.Lines.LockList;
  try
    for i := 0 to Clients.Count - 1 do
      Server.ShutDownLine(Clients.Lines[i]);
  finally
    Server.Lines.UnlockList;
  end;

end;

end.
