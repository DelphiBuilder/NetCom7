unit usvcMain;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, SvcMgr, Dialogs,
  ncSources, ncSockets, Registry, DB, ADODB, ncCommandHandlers, ncDBSrv, ActiveX;

type
  TsvcOnLogMessage = procedure(Sender: TObject; aMessage: string; aError: Boolean = False) of object;

  // Name property is the name we are going to use to uniquelly identify our service
  TNetcomDataServer = class(TService)
    srvController: TncServerSource;
    DBServer: TncDBServer;
    ADOConnection: TADOConnection;
    procedure ServiceCreate(Sender: TObject);
    procedure ServiceDestroy(Sender: TObject);
    procedure ServiceStart(Sender: TService; var Started: Boolean);
    procedure ServiceStop(Sender: TService; var Stopped: Boolean);
    procedure ServiceShutdown(Sender: TService);
  private
    FOnLogMessage: TsvcOnLogMessage;
    function GetServicePort: Integer;
    procedure SetServicePort(const Value: Integer);
    function GetDBConnectionString: string;
    procedure SetDBConnectionString(const Value: string);
    procedure StopAndShutdown;
    function GetCacheResponses: Boolean;
    procedure SetCacheResponses(const Value: Boolean);
  public
    Settings: TRegistry;
    procedure Log(aStr: string; aError: Boolean = False);
    function GetServiceController: TServiceController; override;
    property OnLogMessage: TsvcOnLogMessage read FOnLogMessage write FOnLogMessage;
    property ServicePort: Integer read GetServicePort write SetServicePort;
    property DBConnectionString: string read GetDBConnectionString write SetDBConnectionString;
    property CacheResponses: Boolean read GetCacheResponses write SetCacheResponses;
  end;

var
  Service: TNetcomDataServer;

implementation

uses uscvServiceCommands;
{$R *.DFM}

procedure ServiceController(CtrlCode: DWord); stdcall;
begin
  Service.Controller(CtrlCode);
end;

function TNetcomDataServer.GetServiceController: TServiceController;
begin
  Result := ServiceController;
end;

procedure TNetcomDataServer.ServiceCreate(Sender: TObject);
begin
  FOnLogMessage := nil;
  Settings := TRegistry.Create(KEY_READ or KEY_WRITE);
  Settings.LazyWrite := False;
  Settings.RootKey := HKEY_CURRENT_USER;
  if not Settings.OpenKey('\HKEY_CURRENT_USER\Software\' + Name, True) then
    Log('Cannot open settings key: \HKEY_CURRENT_USER\Software\' + Name);
end;

procedure TNetcomDataServer.ServiceDestroy(Sender: TObject);
begin
  Settings.CloseKey;
  Settings.Free;
end;

procedure TNetcomDataServer.Log(aStr: string; aError: Boolean = False);
var
  ErrType: DWord;
begin
  if Assigned(FOnLogMessage) then
    // Call custom handler
    FOnLogMessage(Self, aStr, aError)
  else
  begin
    // Write to windows log system
    if aError then
      ErrType := EVENTLOG_AUDIT_FAILURE
    else
      ErrType := EVENTLOG_AUDIT_SUCCESS;
    Self.LogMessage(aStr, ErrType);
  end;
end;

procedure TNetcomDataServer.ServiceStart(Sender: TService; var Started: Boolean);
begin
  try
    CoInitialize(nil);
    // Put critical startup code here
    srvController.Port := ServicePort;
    ADOConnection.ConnectionString := DBConnectionString;
    DBServer.CacheResponses := CacheResponses;

    ADOConnection.Connected := True;
    srvController.Active := True;

    Log('"' + DisplayName + '" (' + Name + ') service started successfully, on port: ' + IntTostr(srvController.Port));
  except
    on E: Exception do
    begin
      Log('"' + DisplayName + '" (' + Name + ') service failed to start. ' + E.Message, True);
      Started := False;
    end;
  end;
end;

procedure TNetcomDataServer.ServiceStop(Sender: TService; var Stopped: Boolean);
begin
  StopAndShutdown;

  Log('"' + DisplayName + '" service stopped successfully');
end;

procedure TNetcomDataServer.ServiceShutdown(Sender: TService);
begin
  StopAndShutdown;

  Log('"' + DisplayName + '" service stopped successfully');
end;

procedure TNetcomDataServer.StopAndShutdown;
begin
  srvController.Active := False;
  ADOConnection.Connected := False;
  CoUninitialize;
end;

function TNetcomDataServer.GetServicePort: Integer;
begin
  try
    if not Settings.ValueExists('ServicePort') then
      Abort;
    Result := Settings.ReadInteger('ServicePort');
  except
    Result := srvController.Port;
  end;
end;

procedure TNetcomDataServer.SetServicePort(const Value: Integer);
begin
  Settings.WriteInteger('ServicePort', Value);
end;

function TNetcomDataServer.GetDBConnectionString: string;
begin
  try
    if not Settings.ValueExists('DBConnection') then
      Abort;
    Result := Settings.ReadString('DBConnection');
  except
    Result := ADOConnection.ConnectionString;
  end;
end;

procedure TNetcomDataServer.SetDBConnectionString(const Value: string);
begin
  Settings.WriteString('DBConnection', Value);
end;

function TNetcomDataServer.GetCacheResponses: Boolean;
begin
  try
    if not Settings.ValueExists('CacheResponses') then
      Abort;
    Result := Settings.ReadBool('CacheResponses');
  except
    Result := DBServer.CacheResponses;
  end;
end;

procedure TNetcomDataServer.SetCacheResponses(const Value: Boolean);
begin
  Settings.WriteBool('CacheResponses', Value);
end;

end.
