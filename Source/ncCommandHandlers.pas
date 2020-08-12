unit ncCommandHandlers;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  System.Classes, System.SysUtils, System.SyncObjs, System.Rtti, ncSources;

type
  TncCustomCommandHandler = class(TComponent, IncCommandHandler)
  private
    FSource: TncSourceBase;
    FPeerCommandHandler: string;
    FOnConnected: TncOnSourceConnectDisconnect;
    FOnDisconnected: TncOnSourceConnectDisconnect;
    FOnHandleCommand: TncOnSourceHandleCommand;
    FOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    procedure SetSource(const Value: TncSourceBase);
    function GetPeerCommandHandler: string;
    procedure SetPeerCommandHandler(const Value: string);
    function GetOnConnected: TncOnSourceConnectDisconnect;
    procedure SetOnConnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnDisconnected: TncOnSourceConnectDisconnect;
    procedure SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
    function GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    procedure SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
  protected
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
    function GetComponentName: string;

    property Source: TncSourceBase read FSource write SetSource;
    property PeerCommandHandler: string read GetPeerCommandHandler write SetPeerCommandHandler;
    property OnConnected: TncOnSourceConnectDisconnect read GetOnConnected write SetOnConnected;
    property OnDisconnected: TncOnSourceConnectDisconnect read GetOnDisconnected write SetOnDisconnected;
    property OnHandleCommand: TncOnSourceHandleCommand read GetOnHandleCommand write SetOnHandleCommand;
    property OnAsyncExecCommandResult: TncOnAsyncExecCommandResult read GetOnAsyncExecCommandResult write SetOnAsyncExecCommandResult;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function ExecCommand(aLine: TncSourceLine; const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True;
      aAsyncExecute: Boolean = False; const aPeerComponentHandler: string = ''): TBytes;
  published
  end;

  TncCommandHandler = class(TncCustomCommandHandler)
  published
    property Source;
    property PeerCommandHandler;

    property OnConnected;
    property OnDisconnected;
    property OnHandleCommand;
  end;

implementation

{ TncCustomCommandHandler }

constructor TncCustomCommandHandler.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FSource := nil;
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnHandleCommand := nil;
  FOnAsyncExecCommandResult := nil;
end;

destructor TncCustomCommandHandler.Destroy;
begin
  Source := nil;
  inherited Destroy;
end;

procedure TncCustomCommandHandler.Notification(AComponent: TComponent; Operation: TOperation);
begin
  inherited Notification(AComponent, Operation);

  if Operation = opRemove then
    if AComponent = FSource then
      SetSource(nil);

  if not(csLoading in ComponentState) then
  begin
    if Operation = opInsert then
      if not Assigned(FSource) then
        if AComponent is TncSourceBase then
          SetSource(TncSourceBase(AComponent));
  end;
end;

function TncCustomCommandHandler.ExecCommand(aLine: TncSourceLine; const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True;
  aAsyncExecute: Boolean = False; const aPeerComponentHandler: string = ''): TBytes;
begin
  if not Assigned(Source) then
    raise Exception.Create('Cannot execute with no source object');

  // If no override, we use the component's command handler (the property)
  if aPeerComponentHandler = '' then
    Result := Source.ExecCommand(aLine, aCmd, aData, aRequiresResult, aAsyncExecute, PeerCommandHandler)
  else
    Result := Source.ExecCommand(aLine, aCmd, aData, aRequiresResult, aAsyncExecute, aPeerComponentHandler);
end;

procedure TncCustomCommandHandler.SetSource(const Value: TncSourceBase);
begin
  if FSource <> Value then
  begin
    if Assigned(FSource) then
      FSource.RemoveCommandHandler(Self);

    FSource := Value;

    if Assigned(FSource) then
      FSource.AddCommandHandler(Self);
  end;
end;

function TncCustomCommandHandler.GetPeerCommandHandler: string;
begin
  Result := FPeerCommandHandler;
end;

procedure TncCustomCommandHandler.SetPeerCommandHandler(const Value: string);
begin
  FPeerCommandHandler := Value;
end;

function TncCustomCommandHandler.GetComponentName: string;
begin
  Result := Name;
end;

function TncCustomCommandHandler.GetOnConnected: TncOnSourceConnectDisconnect;
begin
  Result := FOnConnected;
end;

procedure TncCustomCommandHandler.SetOnConnected(const Value: TncOnSourceConnectDisconnect);
begin
  FOnConnected := Value;
end;

function TncCustomCommandHandler.GetOnDisconnected: TncOnSourceConnectDisconnect;
begin
  Result := FOnDisconnected;
end;

procedure TncCustomCommandHandler.SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
begin
  FOnDisconnected := Value;
end;

function TncCustomCommandHandler.GetOnHandleCommand: TncOnSourceHandleCommand;
begin
  Result := FOnHandleCommand;
end;

procedure TncCustomCommandHandler.SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
begin
  FOnHandleCommand := Value;
end;

function TncCustomCommandHandler.GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
begin
  Result := FOnAsyncExecCommandResult;
end;

procedure TncCustomCommandHandler.SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
begin
  FOnAsyncExecCommandResult := Value;
end;

end.
