unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ExtCtrls, StdCtrls, Registry, Menus, SyncObjs, ComCtrls, ADOConEd,
  Spin;

type
  TStringArray = array of string;
  TBooleanArray = array of Boolean;

  TfrmMain = class(TForm)
    pnlCaption: TPanel;
    memLog: TMemo;
    TrayIcon: TTrayIcon;
    popTray: TPopupMenu;
    miShowHideServer: TMenuItem;
    miN1: TMenuItem;
    miShutdown: TMenuItem;
    tmrUpdateLog: TTimer;
    CategoryPanelGroup1: TCategoryPanelGroup;
    CategoryPanel1: TCategoryPanel;
    cpConnection: TCategoryPanel;
    btnStartService: TButton;
    cbAutostartServer: TCheckBox;
    CategoryPanel3: TCategoryPanel;
    cbAutorunLogon: TCheckBox;
    Splitter1: TSplitter;
    GridPanel1: TGridPanel;
    Panel1: TPanel;
    edtConnectionString: TEdit;
    btnEditConnectionString: TButton;
    Panel2: TPanel;
    edtPort: TSpinEdit;
    lblPort: TLabel;
    Panel3: TPanel;
    cbEnableCachedResults: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure btnStartServiceClick(Sender: TObject);
    procedure cbAutostartServerClick(Sender: TObject);
    procedure cbAutorunLogonClick(Sender: TObject);
    procedure miShowHideServerClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure miShutdownClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure tmrUpdateLogTimer(Sender: TObject);
    procedure btnEditConnectionStringClick(Sender: TObject);
    procedure edtConnectionStringChange(Sender: TObject);
    procedure edtPortChange(Sender: TObject);
    procedure cbEnableCachedResultsClick(Sender: TObject);
  private
    svcStarted: Boolean;
    LogLock: TCriticalSection;
    LogStrs: TStringArray;
    LogErrs: TBooleanArray;
    btnStartServiceCaption: string;
    procedure RefreshGUI;
    procedure ServiceLogMessage(Sender: TObject; aMessage: string; aError: Boolean = False);
    procedure ApplicationException(Sender: TObject; E: Exception);
  public
    function IsAutoRun: Boolean;
    procedure SetAutoRun(aAutoRun: Boolean);
  end;

var
  frmMain: TfrmMain;

implementation

uses usvcMain;
{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  svcStarted := False;

  btnStartServiceCaption := btnStartService.Caption;

  LogLock := TCriticalSection.Create;
  SetLength(LogStrs, 0);
  SetLength(LogErrs, 0);

  Application.OnException := ApplicationException;
  Service.OnLogMessage := ServiceLogMessage;

  if Service.Settings.ValueExists('AppAutostart') then
    cbAutostartServer.Checked := Service.Settings.ReadBool('AppAutostart');
  cbAutorunLogon.Checked := IsAutoRun;

  edtConnectionString.Text := Service.DBConnectionString;
  edtPort.Value := Service.ServicePort;
  cbEnableCachedResults.Checked := Service.CacheResponses;

  RefreshGUI;

  if cbAutostartServer.Checked then
    btnStartService.Click;
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  LogLock.Free;
end;

procedure TfrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caNone;
  Visible := False;
end;

procedure TfrmMain.ApplicationException(Sender: TObject; E: Exception);
begin
  memLog.Lines.Add('*** APPLICATION EXCEPTION (' + E.ClassName + ')! ' + DateTimeToStr(Now) + ': ' + E.Message);
end;

procedure TfrmMain.ServiceLogMessage(Sender: TObject; aMessage: string; aError: Boolean = False);
begin
  // This must be thread safe, a log can be called all over the place

  LogLock.Acquire;
  try
    SetLength(LogStrs, Length(LogStrs) + 1);
    LogStrs[ High(LogStrs)] := aMessage;
    SetLength(LogErrs, Length(LogErrs) + 1);
    LogErrs[ High(LogErrs)] := aError;
  finally
    LogLock.Release;
  end;
end;

procedure TfrmMain.tmrUpdateLogTimer(Sender: TObject);
var
  Strs: TStringArray;
  Errs: TBooleanArray;

  MsgStr: string;
  i: Integer;
begin
  // Get thread critical data as fast as possible onto local copies
  LogLock.Acquire;
  try
    Strs := LogStrs;
    Errs := LogErrs;
    SetLength(LogStrs, 0);
    SetLength(LogErrs, 0);
  finally
    LogLock.Release;
  end;

  // And begin showing the messages/errors in the log area
  if Length(Strs) > 0 then
  begin
    memLog.Lines.BeginUpdate;
    try
      for i := 0 to High(Strs) do
      begin
        MsgStr := '';
        if Errs[i] then
        begin
          Visible := True;
          MsgStr := MsgStr + '*** Error! ';
        end;

        MsgStr := MsgStr + '[' + DateTimeToStr(Now) + ']: ' + Strs[i];
        if memLog.Lines.Count > 10000 then
          memLog.Lines.Text := 'Log cleared - reached 10000 lines';
        memLog.Lines.Add(MsgStr);
      end;
    finally
      memLog.Lines.EndUpdate;
    end;
  end;
end;

procedure TfrmMain.RefreshGUI;
var
  Caption: string;
begin
  Caption := Service.DisplayName;
  if svcStarted then
    Caption := Caption + ' - started'
  else
    Caption := Caption + ' - stopped';
  pnlCaption.Caption := Caption;
end;

procedure TfrmMain.btnStartServiceClick(Sender: TObject);
var
  svcStopped: Boolean;
begin
  if svcStarted then
  begin
    svcStarted := False;
    btnStartService.Caption := btnStartServiceCaption;
    cpConnection.Enabled := True;
    Service.ServiceStop(nil, svcStopped);
  end
  else
  begin
    svcStarted := True;
    try
      Service.ServiceStart(nil, svcStarted);
      if svcStarted then
      begin
        btnStartService.Caption := 'Stop service';
        cpConnection.Enabled := False;
      end;
    except
      svcStarted := False;
      raise ;
    end;
  end;
  RefreshGUI;
end;

procedure TfrmMain.cbAutostartServerClick(Sender: TObject);
begin
  Service.Settings.WriteBool('AppAutostart', cbAutostartServer.Checked);
end;

procedure TfrmMain.edtConnectionStringChange(Sender: TObject);
begin
  edtConnectionString.Hint := edtConnectionString.Text;
  Service.DBConnectionString := edtConnectionString.Text;
end;

procedure TfrmMain.edtPortChange(Sender: TObject);
begin
  Service.ServicePort := edtPort.Value;
end;

procedure TfrmMain.cbEnableCachedResultsClick(Sender: TObject);
begin
  Service.CacheResponses := cbEnableCachedResults.Checked;
end;

procedure TfrmMain.cbAutorunLogonClick(Sender: TObject);
begin
  if cbAutorunLogon.Checked then
    cbAutoStartServer.Checked := True;
  SetAutoRun(cbAutorunLogon.Checked);
end;

procedure TfrmMain.btnEditConnectionStringClick(Sender: TObject);
begin
  if EditConnectionString(Service.ADOConnection) then
  begin
    edtConnectionString.Text := Service.ADOConnection.ConnectionString;
  end;
end;

function TfrmMain.IsAutoRun: Boolean;
var
  Reg: TRegistry;
  AppName: string;
begin
  Result := False;

  Reg := TRegistry.Create;
  try
    Reg.RootKey := HKEY_LOCAL_MACHINE;
    if Reg.OpenKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', True) then
      try
        AppName := ExtractFileName(ParamStr(0));
        AppName := Copy(AppName, 1, Length(AppName) - Length(ExtractFileExt(AppName)));
        AppName := AppName + '.' + Service.Name;

        Result := SameText(Reg.ReadString(AppName), ParamStr(0));
      finally
        Reg.CloseKey;
      end;
  finally
    Reg.Free;
  end;
end;

procedure TfrmMain.SetAutoRun(aAutoRun: Boolean);
var
  Reg: TRegistry;
  AppName: string;
begin
  Reg := TRegistry.Create;
  try
    Reg.RootKey := HKEY_LOCAL_MACHINE;
    Reg.LazyWrite := False;
    if not Reg.OpenKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', True) then
      raise Exception.Create('Cannot open registry key.');
    try
      AppName := ExtractFileName(ParamStr(0));
      AppName := Copy(AppName, 1, Length(AppName) - Length(ExtractFileExt(AppName)));
      AppName := AppName + '.' + Service.Name;

      if cbAutorunLogon.Checked then
        Reg.WriteString(AppName, ParamStr(0))
      else
        Reg.DeleteValue(AppName);
    finally
      Reg.CloseKey;
    end;
  finally
    Reg.Free;
  end;
end;

procedure TfrmMain.miShowHideServerClick(Sender: TObject);
begin
  Application.BringToFront;
  frmMain.Visible := not frmMain.Visible;
end;

procedure TfrmMain.miShutdownClick(Sender: TObject);
begin
  Application.Terminate;
end;

end.
