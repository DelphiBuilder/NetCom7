unit ncDBCnt;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  Windows, Classes, SysUtils, SyncObjs,
  Variants, ncSources, ncCommandHandlers, DB, ADOInt, ADODB, ActiveX, ncSerializeADO, ncDBCommands;

type
  TncDBDataset = class(TCustomADODataSet, IncCommandHandler)
  private
    WasActivated: Boolean;
    procedure UpdateSQLParams;
  private
    FSQL: TStrings;
    FSource: TncClientSource;
    FPeerCommandHandler: string;

    BeforeUpdatesRecordIndex: Integer;

    function GetSQL: TStrings;
    procedure SetSQL(const Value: TStrings);
    function GetPeerCommandHandler: string;
    procedure SetPeerCommandHandler(const Value: string);
    procedure SetSource(const Value: TncClientSource);

    function GetOnConnected: TncOnSourceConnectDisconnect;
    procedure SetOnConnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnDisconnected: TncOnSourceConnectDisconnect;
    procedure SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
    function GetOnHandleCommand: TncOnSourceHandleCommand;
    procedure SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
    function GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
    procedure SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
  protected
    WithinUpdates: Boolean;

    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
    procedure Loaded; override;

    procedure InitializeMasterFieldsNew;
    procedure RefreshParams;
    procedure MasterChanged(Sender: TObject); override;
    procedure SQLChanged(Sender: TObject);

    procedure OpenCursor(InfoQuery: Boolean); override;
    procedure InternalRefresh; override;

    procedure InternalApplyUpdates;

    procedure DoBeforeEdit; override;
    procedure DoBeforeInsert; override;
    procedure DoBeforeDelete; override;
    procedure DoAfterPost; override;
    procedure DoAfterDelete; override;

    function GetComponentName: string;
    property OnHandleCommand: TncOnSourceHandleCommand read GetOnHandleCommand write SetOnHandleCommand;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure FetchRemoteDataset;

    procedure Requery;
    function ExecSQL: Integer;

    procedure BeginUpdates;
    procedure ApplyUpdates;
    procedure CancelUpdates;

  published
    property Active; // : Boolean read GetActive write SetActive default False;
    property Source: TncClientSource read FSource write SetSource;
    property PeerCommandHandler: string read GetPeerCommandHandler write SetPeerCommandHandler;
    property SQL: TStrings read GetSQL write SetSQL;
    property DataSource;
    property IndexFieldNames;
    property Parameters;
  end;

implementation

{ TncDBDataset }

constructor TncDBDataset.Create(AOwner: TComponent);
begin
  inherited;

  WasActivated := False;

  FSQL := TStringList.Create;
  TStringList(FSQL).OnChange := SQLChanged;

  CursorLocation := clUseClient;
  LockType := ltBatchOptimistic;
  // This is the type also returned from BytesToRecordset used in this component
  // to stream back the contents from server
  CommandType := cmdFile;

  WithinUpdates := False;
end;

destructor TncDBDataset.Destroy;
begin
  Active := False;
  Source := nil;
  FSQL.Free;

  inherited;
end;

procedure TncDBDataset.SQLChanged(Sender: TObject);
begin
  if not(csLoading in ComponentState) then
    Active := False;
  UpdateSQLParams;
end;

procedure TncDBDataset.UpdateSQLParams;
begin
  Parameters.ParseSQL(FSQL.Text, True);
end;

function TncDBDataset.GetComponentName: string;
begin
  Result := Name;
end;

function TncDBDataset.GetOnConnected: TncOnSourceConnectDisconnect;
begin
  // Does nothing
end;

procedure TncDBDataset.SetOnConnected(const Value: TncOnSourceConnectDisconnect);
begin
  // Does nothing
end;

function TncDBDataset.GetOnDisconnected: TncOnSourceConnectDisconnect;
begin
  // Does nothing
end;

procedure TncDBDataset.SetOnDisconnected(const Value: TncOnSourceConnectDisconnect);
begin
  // Does nothing
end;

function TncDBDataset.GetOnHandleCommand: TncOnSourceHandleCommand;
begin
  // Does nothing
end;

procedure TncDBDataset.SetOnHandleCommand(const Value: TncOnSourceHandleCommand);
begin
  // Does nothing
end;

function TncDBDataset.GetOnAsyncExecCommandResult: TncOnAsyncExecCommandResult;
begin
  // Does nothing
end;

procedure TncDBDataset.SetOnAsyncExecCommandResult(const Value: TncOnAsyncExecCommandResult);
begin
  // Does nothing
end;

procedure TncDBDataset.Notification(AComponent: TComponent; Operation: TOperation);
begin
  inherited Notification(AComponent, Operation);

  if Operation = opRemove then
    if AComponent = FSource then
      SetSource(nil);

  if not(csLoading in ComponentState) then
  begin
    if Operation = opInsert then
      if not Assigned(FSource) then
        if AComponent is TncClientSource then
          SetSource(TncClientSource(AComponent));
  end;
end;

procedure TncDBDataset.Loaded;
begin
  inherited;

  if WasActivated then
    Active := True;
end;

procedure TncDBDataset.MasterChanged(Sender: TObject);
begin
  if not Active then
    Exit;
  if Parameters.Count = 0 then
  begin
    CheckBrowseMode;
    if SetDetailFilter then
      First;
  end
  else
    RefreshParams;
end;

procedure TncDBDataset.InitializeMasterFieldsNew;
var
  I: Integer;
  MasterFieldList: string;
begin
  { Assign MasterFields from parameters as needed by the MasterDataLink }
  if (Parameters.Count > 0) and Assigned(MasterDataLink.DataSource) and Assigned(MasterDataLink.DataSource.DataSet) then
  begin
    for I := 0 to Parameters.Count - 1 do
      if (Parameters[I].Direction in [pdInput, pdInputOutput]) and (MasterDataLink.DataSource.DataSet.FindField(Parameters[I].Name) <> nil) then
        MasterFieldList := MasterFieldList + Parameters[I].Name + ';';
    MasterFields := Copy(MasterFieldList, 1, Length(MasterFieldList) - 1);
    SetParamsFromCursor;
  end;
end;

procedure TncDBDataset.RefreshParams;
var
  DataSet: TDataSet;

  function FieldValueChanged(const V1, V2: Variant): Boolean;
  begin
    // RTL doesn't support comparison of VT_DECIMAL variants, so convert those to strings first.
    // Fixes QC# 50327.
    if (VarType(V1) = VT_DECIMAL) or (VarType(V2) = VT_DECIMAL) then
      Result := not SameStr(VarToStr(V1), VarToStr(V2))
    else
      Result := V1 <> V2;
  end;

  function MasterFieldsChanged: Boolean;
  var
    I: Integer;
    MasterField: TField;
  begin
    Result := False;
    if MasterDataLink.DataSource <> nil then
      for I := 0 to MasterDataLink.Fields.Count - 1 do
      begin
        MasterField := TField(MasterDataLink.Fields[I]);
        if FieldValueChanged(Parameters.ParamByName(MasterField.FieldName).Value, MasterField.Value) then
        begin
          Result := True;
          break;
        end;
      end;
  end;

begin
  DisableControls;
  try
    if MasterDataLink.DataSource <> nil then
    begin
      DataSet := MasterDataLink.DataSource.DataSet;
      if DataSet <> nil then
        if DataSet.Active and (DataSet.State <> dsSetKey) and MasterFieldsChanged then
        begin
          SetParamsFromCursor;
          Requery;
        end;
    end;
  finally
    EnableControls;
  end;
end;

procedure TncDBDataset.DoBeforeEdit;
begin
  BeforeUpdatesRecordIndex := RecNo;
  inherited;
end;

procedure TncDBDataset.DoBeforeInsert;
begin
  BeforeUpdatesRecordIndex := RecNo;
  inherited;
end;

procedure TncDBDataset.DoBeforeDelete;
begin
  BeforeUpdatesRecordIndex := RecNo;
  inherited;
end;

procedure TncDBDataset.DoAfterPost;
begin
  // If we are not within a transaction, apply commits on the fly
  if not WithinUpdates then
    try
      InternalApplyUpdates;
    except
      CancelUpdates;
      raise;
    end;

  inherited;
end;

procedure TncDBDataset.DoAfterDelete;
begin
  // If we are not within a transaction, delete commits on the fly
  if not WithinUpdates then
    try
      InternalApplyUpdates;
    except
      CancelUpdates;
      raise;
    end;

  inherited;
end;

procedure TncDBDataset.FetchRemoteDataset;
var
  CommandData: TDBDatasetData;
  Data: TBytes;
  // PrevBk: TBytes;
  // CurrRec: Integer;
begin
  // Make sure we establish the comms
  if not Assigned(Source) then
    raise Exception.Create('Source component not specified');
  if Trim(Name) = '' then
    raise Exception.Create('TncDBDataset cannot activate without component name');

  CommandData := TDBDatasetData.Create;
  try
    // Set the MasterFields property and also get the data for the parameter
    // from the DataSource's equivalent
    InitializeMasterFieldsNew;

    // Send the SQL and Parameters and retrieve the table back
    CommandData.SQL := SQL.Text;
    CommandData.Parameters := ParametersToBytes(Parameters);

    Data := Source.ExecCommand(ncDBOpenDataset, CommandData.ToBytes, True, False, PeerCommandHandler, Name);

  finally
    CommandData.Free;
  end;
  Recordset := BytesToRecordset(Data);
end;

procedure TncDBDataset.OpenCursor(InfoQuery: Boolean);
begin
  if not Assigned(Recordset) then
    FetchRemoteDataset
  else
    inherited OpenCursor(InfoQuery);
end;

// For close cursor we could have:
// if Source.Active then
// try
// Source.ExecCommand(ncDBCloseDataset, nil, True, PeerCommandHandler, Name);
// except
// end;

procedure TncDBDataset.InternalRefresh;
begin
  Requery;
  DestroyLookupCursor;
end;

procedure TncDBDataset.Requery;
var
  PrevRecNo: Integer;
begin
  PrevRecNo := RecNo;
  DisableControls;
  try
    FetchRemoteDataset;
    if (PrevRecNo > 0) and (PrevRecNo <= RecordCount) then
      RecNo := PrevRecNo;
  finally
    EnableControls;
  end;
end;

procedure TncDBDataset.BeginUpdates;
begin
  WithinUpdates := True;
  BeforeUpdatesRecordIndex := RecNo;
end;

procedure TncDBDataset.CancelUpdates;
begin
  // TODO: DisableControls
  Recordset.CancelBatch(adAffectAll);
  Resync([]);
  RecNo := BeforeUpdatesRecordIndex;

  WithinUpdates := False;
end;

procedure TncDBDataset.ApplyUpdates;
begin
  InternalApplyUpdates;

  WithinUpdates := False;
end;

procedure TncDBDataset.InternalApplyUpdates;
var
  UpdateData: TDBUpdateDatasetData;
  AppliedUpdatesRS: _Recordset;
  I: Integer;
  CannotUpdate: Boolean;
begin
  CheckBrowseMode;
  CannotUpdate := False;

  DisableControls;
  try
    Recordset.MarshalOptions := adMarshalModifiedOnly;
    Recordset.Filter := adFilterPendingRecords;
    try
      if Recordset.RecordCount > 0 then // there exist updates
      begin
        UpdateData := TDBUpdateDatasetData.Create;
        try
          UpdateData.SQL := SQL.Text;
          UpdateData.Parameters := ParametersToBytes(Parameters);
          UpdateData.RecordUpdates := Recordset;

          // Send the updates and get back the updated updates

          AppliedUpdatesRS := BytesToRecordset(Source.ExecCommand(ncDBUpdateDataset, UpdateData.ToBytes, True, False, PeerCommandHandler, Name), nil);
        finally
          UpdateData.Free;
        end;

        // Flatten local updates one by one, copying refreshed values from AppliedUpdates
        Recordset.MoveFirst;
        while not Recordset.EOF do
          try
            if Recordset.Status in [adRecNew, adRecModified] then
            begin
              // Copy field by field
              CannotUpdate := False;
              for I := 0 to Recordset.Fields.Count - 1 do
                try
                  Recordset.Fields.Item[I].Value := AppliedUpdatesRS.Fields.Item[I].Value;
                except
                  // We have tried to assign to a readonly field
                  // Silence off exception. This means a field could not be updated (SQL AutoInc)
                  // If Field is SQLServer & IDENTITY/AutoInc then should delete the field add it again as Integer.
                  // When this is fixed the CannotUpdate must be removed...

                  if Recordset.Fields.Item[I].Value <> AppliedUpdatesRS.Fields.Item[I].Value then
                    CannotUpdate := True;
                end;
              AppliedUpdatesRS.MoveNext;
            end;

            // Flatten local record with updated updates
            Recordset.UpdateBatch(adAffectCurrent);
          finally
            Recordset.MoveNext;
          end;
      end;
    finally
      Recordset.Filter := adFilterNone;
    end;

    // Refresh the displaying data
    UpdateCursorPos;
    DestroyLookupCursor;
    Resync([]);
  finally
    EnableControls;
  end;

  // Temporary (see ToDo comment on the middle of the function.) Just make sure that even if something fails, the data are correct/refresh from server
  if CannotUpdate then
    Refresh;
end;

function TncDBDataset.ExecSQL: Integer;
var
  CommandData: TDBDatasetData;
begin
  CommandData := TDBDatasetData.Create;
  try
    // Set the MasterFields property and also get the data for the parameter
    // from the DataSource's equivalent
    InitializeMasterFieldsNew;

    CommandData.SQL := SQL.Text;
    CommandData.Parameters := ParametersToBytes(Parameters);
    Result := StrToInt(StringOf(Source.ExecCommand(ncDBExecDataset, CommandData.ToBytes, True, False, PeerCommandHandler, Name)));
  finally
    CommandData.Free;
  end;
end;

function TncDBDataset.GetSQL: TStrings;
begin
  Result := FSQL;
end;

procedure TncDBDataset.SetSQL(const Value: TStrings);
begin
  FSQL.Assign(Value);
end;

procedure TncDBDataset.SetSource(const Value: TncClientSource);
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

function TncDBDataset.GetPeerCommandHandler: string;
begin
  Result := FPeerCommandHandler;
end;

procedure TncDBDataset.SetPeerCommandHandler(const Value: string);
begin
  FPeerCommandHandler := Value;
end;

end.
