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
    tmrUpdateLog: TTimer;
    ToolBar1: TToolBar;
    btnActivateServer: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure tmrUpdateLogTimer(Sender: TObject);
    function ServerHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
    procedure ServerConnected(Sender: TObject; aLine: TncLine);
    procedure ServerDisconnected(Sender: TObject; aLine: TncLine);
    procedure btnActivateServerClick(Sender: TObject);
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
  Server.Active := False;

  LogLinesCopy.Free;
  LogLines.Free;
  LogLock.Free;
end;

procedure TfrmMain.Log(aStr: string);
begin
  // This is thread safe
  LogLock.Acquire;
  try
    LogLines.Add(aStr);
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

    // Clear the log if its too big
    if memLog.Lines.Count > 10000 then
      memLog.Lines.Clear;
  end;
  LogLinesCopy.Clear;
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
      // if Clients.Objects[i] <> aLine then  // If you do not want to send text back to original client
      Server.ExecCommand(Clients.Lines[i], 0, aData, False);
  finally
    Server.Lines.UnlockList;
  end;
end;

end.
