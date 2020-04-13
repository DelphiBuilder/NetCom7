unit ncCommandHandlers;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

uses
  Windows, Classes, SysUtils, SyncObjs, Rtti, ncSources;

type
  TncCustomCommandHandler = class(TComponent, IncCommandHandler)
  private
    PropertyLock: TCriticalSection;
  private
    FSource: TncSourceBase;
    FOnConnected: TncOnSourceConnectDisconnect;
    FOnDisconnected: TncOnSourceConnectDisconnect;
    FOnHandleCommand: TncOnSourceHandleCommand;
    FPeerCommandHandler: string;
    procedure SetSource(const Value: TncSourceBase);
    function GetOnConnected: TncOnSourceConnectDisconnect;
    procedure SetOnConnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnDisconnected: TncOnSourceConnectDisconnect;
    procedure SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
    function GetPeerCommandHandler: string;
    procedure SetPeerCommandHandler(const Value: string);
  protected
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
    procedure Connected(aLine: TncSourceLine);
    procedure Disconnected(aLine: TncSourceLine);
    function GetComponentName: string;

    property Source: TncSourceBase read FSource write SetSource;
    property PeerCommandHandler: string read GetPeerCommandHandler write SetPeerCommandHandler;
    property OnConnected: TncOnSourceConnectDisconnect read GetOnConnected write SetOnConnected;
    property OnDisconnected: TncOnSourceConnectDisconnect read GetOnDisconnected write SetOnDisconnected;
    property OnHandleCommand: TncOnSourceHandleCommand read GetOnHandleCommand write SetOnHandleCommand;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function ExecCommand(aLine: TncSourceLine; const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True; aAsyncExecute: Boolean = False;
      const aPeerComponentHandler: string = ''): TBytes;
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
  PropertyLock := TCriticalSection.Create;
  FSource := nil;
  FOnConnected := nil;
  FOnDisconnected := nil;
  FOnHandleCommand := nil;
end;

destructor TncCustomCommandHandler.Destroy;
begin
  Source := nil;
  PropertyLock.Free;
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

procedure TncCustomCommandHandler.Connected(aLine: TncSourceLine);
begin
  if Assigned(OnConnected) then
    OnConnected(Self, aLine);
end;

procedure TncCustomCommandHandler.Disconnected(aLine: TncSourceLine);
begin
  if Assigned(OnDisconnected) then
    OnDisconnected(Self, aLine);
end;

function TncCustomCommandHandler.ExecCommand(aLine: TncSourceLine; const aCmd: Integer; const aData: TBytes = nil; const aRequiresResult: Boolean = True; aAsyncExecute: Boolean = False;
  const aPeerComponentHandler: string = ''): TBytes;
begin
  if not Assigned(Source) then
    raise Exception.Create('Cannot execute with no source object');

  // If no override, we use the component's command handler (the property)
  if aPeerComponentHandler = '' then
    Result := Source.ExecCommand(aLine, aCmd, aData, aRequiresResult, aAsyncExecute, PeerCommandHandler)
  else
    Result := Source.ExecCommand(aLine, aCmd, aData, aRequiresResult, aAsyncExecute, aPeerComponentHandler);
end;

function TncCustomCommandHandler.GetComponentName: string;
begin
  Result := Name;
end;

function TncCustomCommandHandler.GetOnConnected: TncOnSourceConnectDisconnect;
begin
  PropertyLock.Acquire;
  try
    Result := FOnConnected;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomCommandHandler.SetOnConnected(const Value: TncOnSourceConnectDisconnect);
begin
  PropertyLock.Acquire;
  try
    FOnConnected := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomCommandHandler.GetOnDisconnected: TncOnSourceConnectDisconnect;
begin
  PropertyLock.Acquire;
  try
    Result := FOnDisconnected;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomCommandHandler.SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
begin
  PropertyLock.Acquire;
  try
    FOnDisconnected := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomCommandHandler.GetOnHandleCommand: TncOnSourceHandleCommand;
begin
  PropertyLock.Acquire;
  try
    Result := FOnHandleCommand;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomCommandHandler.SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
begin
  PropertyLock.Acquire;
  try
    FOnHandleCommand := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncCustomCommandHandler.GetPeerCommandHandler: string;
begin
  PropertyLock.Acquire;
  try
    Result := FPeerCommandHandler;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncCustomCommandHandler.SetPeerCommandHandler(const Value: string);
begin
  PropertyLock.Acquire;
  try
    FPeerCommandHandler := Value;
  finally
    PropertyLock.Release;
  end;
end;

end.
