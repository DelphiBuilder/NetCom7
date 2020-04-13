// This is the DB server part of netcom7
// Written by Demos Bill
//
// Date completed: 2011 / 5 / 5
//
// The TncDBServer is an object which serves recordsets to ncClientDatasets

// It holds every recordset open for its issued SQL. It maintains the recordset
// open for performance when requering.
// This is more performant even from stored procedures.
//
// It also cashes all responses depending on sql and params. The cache uses
// binary searching of issued sql to get the response, so this is extremely fast.
// Updating a recordset clears cache for the current updated recordset and all
// recordsets active in the list which contain a cached result and draw data
// from the same tables that were updated.

unit ncDBSrv;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

uses
  Windows, Classes, SysUtils, SyncObjs, ncSources, Variants, ncCommandHandlers, ADODB, ADOInt, ncDBCommands, ncSerializeADO;

type
  // Add an array of tables and if one of them is altered then void all the ReadyResults.
  TReadyQueryItem = class
  private
    FSerialiser: TCriticalSection;
    // Ready results holds a string list of Parameters, and the Objects are TBytes
    ReadyResults: TStringList;
  protected
    Tables: TStringList;
    procedure GetTablesForSQL;
  public
    ADOQuery: TADOQuery;

    constructor Create(aConnectionString, aSQL: string; aSerialiser: TCriticalSection);
    destructor Destroy; override;
    function GetResult(aParams: TBytes; aUseCache: Boolean): TBytes;
    function Update(aUpdates: _recordset): TBytes;
    procedure ClearCachedResults;
  end;

  TReadyQueryList = class
  private
    Serialiser: TCriticalSection;
    // A Sorted String List of SQL statements
    // The Data contains a TReadyQueryItem
    ReadyQueries: TStringList;
    FConnectionString: string;
  public
    // Returns the corresponding TReadyQueryItem (creates it if it does not exist).
    constructor Create;
    destructor Destroy; override;
    function GetQuery(aSQL: string): TReadyQueryItem;

    procedure SetConnectionString(aConnectionString: string);
  end;

  TncDBServer = class(TncCustomCommandHandler)
  private
    PropertyLock: TCriticalSection;
    ReadyQueryList: TReadyQueryList;
    FCacheResponses: Boolean;

    procedure DBServerConnected(Sender: TObject; aLine: TncSourceLine);
    procedure DBServerDisconnected(Sender: TObject; aLine: TncSourceLine);
    function DBServerHandleCommand(Sender: TObject; aLine: TncSourceLine; aCmd: Integer; aData: TBytes; aRequiresResult: Boolean; const aSenderComponent, aReceiverComponent: string): TBytes;
  private
    FADOConnection: TADOConnection;
    PrevADOConnectionString: string;
    procedure SetADOConnection(const Value: TADOConnection);
    function GetADOConnection: TADOConnection;
    function GetCacheResponses: Boolean;
    procedure SetCacheResponses(const Value: Boolean);
  protected
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    property ADOConnection: TADOConnection read GetADOConnection write SetADOConnection;
    property CacheResponses: Boolean read GetCacheResponses write SetCacheResponses default True;
    property Source;
  end;

implementation

{ TncDBServer }

constructor TncDBServer.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  PropertyLock := TCriticalSection.Create;
  ReadyQueryList := TReadyQueryList.Create;

  FCacheResponses := True;
  PrevADOConnectionString := '';

  FADOConnection := nil;
  OnHandleCommand := DBServerHandleCommand;
  OnConnected := DBServerConnected;
  OnDisconnected := DBServerDisconnected;
end;

destructor TncDBServer.Destroy;
begin
  ReadyQueryList.Free;
  PropertyLock.Free;
  inherited;
end;

procedure TncDBServer.DBServerConnected(Sender: TObject; aLine: TncSourceLine);
begin
  ReadyQueryList.SetConnectionString(ADOConnection.ConnectionString);
end;

procedure TncDBServer.DBServerDisconnected(Sender: TObject; aLine: TncSourceLine);
begin
  // Remove all items for the line that disconnected
  // RecordsetList.RemoveRecordsetItems(aLine);
end;

function TncDBServer.DBServerHandleCommand(Sender: TObject; aLine: TncSourceLine; aCmd: Integer; aData: TBytes; aRequiresResult: Boolean; const aSenderComponent, aReceiverComponent: string): TBytes;
var
  DatasetData: TDBDatasetData; // Command
  UpdateDatasetData: TDBUpdateDatasetData; // Command
  ReadyQry: TReadyQueryItem;
  ExecQry: TADOQuery;

  UpdatedTables: TStringList;
  rq: Integer;
  ListRQ: TReadyQueryItem;
  i: Integer;
begin

  PropertyLock.Acquire;
  try
    if Assigned (FADOConnection) then
    begin
      if FADOConnection.ConnectionString <> PrevADOConnectionString then
      begin
        PrevADOConnectionString := FADOConnection.ConnectionString;
        // Purge all cache
        for rq := 0 to ReadyQueryList.ReadyQueries.Count - 1 do
        begin
          ListRQ := TReadyQueryItem(ReadyQueryList.ReadyQueries.Objects[rq]);
          ListRQ.ClearCachedResults;
        end;
      end;
    end;
  finally
    PropertyLock.Release;
  end;

  case aCmd of
    ncDBOpenDataset:
      begin
        DatasetData := TDBDatasetData.Create;
        try
          // Deserialise aData to DatasetData
          DatasetData.FromBytes(aData);

          ReadyQry := ReadyQueryList.GetQuery(DatasetData.SQL);
          Result := ReadyQry.GetResult(DatasetData.Parameters, CacheResponses);
        finally
          DatasetData.Free;
        end;
      end;

    ncDBCloseDataset:
      begin
      end;

    ncDBUpdateDataset:
      begin
        UpdateDatasetData := TDBUpdateDatasetData.Create;
        try
          UpdateDatasetData.FromBytes(aData);

          ReadyQry := ReadyQueryList.GetQuery(UpdateDatasetData.SQL);
          Result := ReadyQry.Update(UpdateDatasetData.RecordUpdates);

          UpdatedTables := ReadyQry.Tables;
          // For each updated Table
          for i := 0 to UpdatedTables.Count - 1 do
            // Search all open queries
            for rq := 0 to ReadyQueryList.ReadyQueries.Count - 1 do
            begin
              ListRQ := TReadyQueryItem(ReadyQueryList.ReadyQueries.Objects[rq]);

              // If table exists on target
              if ListRQ.Tables.IndexOf(UpdatedTables.Strings[i]) > -1 then
                ListRQ.ClearCachedResults;
            end;

          // This would be to send back the complete table, but we don't do that
          // instead, we send back the updated updates (updates that were posted,
          // and returned back with the new autoinc fields for example.
          // Result := ReadyQry.GetResult(UpdateDatasetData.Parameters, CacheResponses);
        finally
          UpdateDatasetData.Free;
        end;
      end;
    ncDBExecDataset:
      begin
        DatasetData := TDBDatasetData.Create;
        try
          // Deserialise aData to DatasetData
          DatasetData.FromBytes(aData);

          ExecQry := TADOQuery.Create(nil);
          try
            ExecQry.SQL.Text := DatasetData.SQL;
            BytesToParameters(DatasetData.Parameters, ExecQry.Parameters);
            Result := BytesOf(IntToStr(ExecQry.ExecSQL));

            // Since a exec query can virtually do anything,
            // We are going to purge all cached responses
            for rq := 0 to ReadyQueryList.ReadyQueries.Count - 1 do
            begin
              ListRQ := TReadyQueryItem(ReadyQueryList.ReadyQueries.Objects[rq]);
              ListRQ.ClearCachedResults;
            end;
          finally
            ExecQry.Free;
          end;
        finally
          DatasetData.Free;
        end;
      end;

  end;

end;

procedure TncDBServer.Notification(AComponent: TComponent; Operation: TOperation);
begin
  inherited Notification(AComponent, Operation);

  if Operation = opRemove then
    if AComponent = FADOConnection then
      SetADOConnection(nil);

  if not(csLoading in ComponentState) then
  begin
    if Operation = opInsert then
      if not Assigned(FADOConnection) then
        if AComponent is TADOConnection then
          SetADOConnection(TADOConnection(AComponent));
  end;
end;

function TncDBServer.GetADOConnection: TADOConnection;
begin
  PropertyLock.Acquire;
  try
    Result := FADOConnection;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncDBServer.SetADOConnection(const Value: TADOConnection);
begin
  PropertyLock.Acquire;
  try
    FADOConnection := Value;
  finally
    PropertyLock.Release;
  end;
end;

function TncDBServer.GetCacheResponses: Boolean;
begin
  PropertyLock.Acquire;
  try
    Result := FCacheResponses;
  finally
    PropertyLock.Release;
  end;
end;

procedure TncDBServer.SetCacheResponses(const Value: Boolean);
begin
  PropertyLock.Acquire;
  try
    FCacheResponses := Value;
  finally
    PropertyLock.Release;
  end;
end;

{ TReadyQueryItem }

constructor TReadyQueryItem.Create(aConnectionString, aSQL: string; aSerialiser: TCriticalSection);
begin
  FSerialiser := aSerialiser;

  // Get the new query created
  ADOQuery := TADOQuery.Create(nil);
  // Setting ConnectionString reports to server as different session:
  // i.e: sees everything updated
  // Also ensures multithreading works (multithreaded queries are not allowed
  // to share a Connection.
  // ConnectionString must be specified
  ADOQuery.Connection := TADOConnection.Create(nil);
  ADOQuery.Connection.ConnectionString := aConnectionString;
  ADOQuery.SQL.Text := aSQL;
  // ADOQuery.LockType := ltBatchOptimistic;
  // ADOQuery.MarshalOptions := moMarshalModifiedOnly;

  // ADOQuery.CursorLocation := clUseClient;
  // ADOQuery.CursorType := ctOpenForwardOnly;

  // Get the cashed results list ready
  ReadyResults := TStringList.Create;
  ReadyResults.CaseSensitive := False;
  ReadyResults.Sorted := True;
  ReadyResults.Duplicates := dupIgnore;

  // Get the tables references list created
  Tables := TStringList.Create;
  Tables.CaseSensitive := False;
  Tables.Sorted := True;
  Tables.Duplicates := dupIgnore;
end;

destructor TReadyQueryItem.Destroy;
begin
  ClearCachedResults;

  Tables.Free;
  ReadyResults.Free;

  ADOQuery.Connection.Free;
  ADOQuery.Free;

  inherited;
end;

type
  TResObj = class
    Content: TBytes;
  end;

function TReadyQueryItem.GetResult(aParams: TBytes; aUseCache: Boolean): TBytes;
var
  strParams: string;
  Ndx: Integer;
  ResObj: TResObj;
begin
  FSerialiser.Acquire;
  try
    strParams := StringOf(aParams);

    if aUseCache then
      Ndx := ReadyResults.IndexOf(strParams)
    else
      Ndx := -1;

    if (Ndx < 0) then // Result not found
    begin
      BytesToParameters(aParams, ADOQuery.Parameters);

      if not ADOQuery.Active then
      begin
        ADOQuery.Active := True;
        GetTablesForSQL;
      end
      else
        ADOQuery.Requery;

      Result := RecordsetToBytes(ADOQuery.Recordset, pfADTG);

      if aUseCache and (Length(Result) > 0) then
      begin
        ResObj := TResObj.Create;
        ResObj.Content := Result;
        ReadyResults.AddObject(strParams, ResObj);
      end;
    end
    else
      Result := TResObj(ReadyResults.Objects[Ndx]).Content;

  finally
    FSerialiser.Release;
  end;
end;

procedure TReadyQueryItem.GetTablesForSQL;
var
  i: Integer;
begin
  Tables.Clear;
  // Get for every field the table it comes from
  for i := 0 to ADOQuery.Recordset.Fields.Count - 1 do
    if VarIsStr (ADOQuery.Recordset.Fields.Item[i].Properties.Item['BASETABLENAME'].Value) then
      Tables.Add(ADOQuery.Recordset.Fields.Item[i].Properties.Item['BASETABLENAME'].Value);
end;

function TReadyQueryItem.Update(aUpdates: _recordset): TBytes;
var
  tmpDS: TADODataSet;
begin
  FSerialiser.Acquire;
  try
    tmpDS := TADODataSet.Create(nil);
    try
      tmpDS.Recordset := aUpdates;
      tmpDS.Recordset.Set_ActiveConnection(ADOQuery.Connection.ConnectionObject);
      tmpDS.Recordset.UpdateBatch(adAffectAll);
      // tmpDS.Recordset.Filter := adFilterAffectedRecords;
      Result := RecordsetToBytes(tmpDS.Recordset, pfADTG);
    finally
      tmpDS.Free;
    end;
  finally
    FSerialiser.Release;
  end;
end;

procedure TReadyQueryItem.ClearCachedResults;
var
  i: Integer;
begin
  for i := 0 to ReadyResults.Count - 1 do
    ReadyResults.Objects[i].Free;

  ReadyResults.Clear;
end;

{ TReadyQueryList }

constructor TReadyQueryList.Create;
begin
  Serialiser := TCriticalSection.Create;
  ReadyQueries := TStringList.Create;
  ReadyQueries.CaseSensitive := False;
  ReadyQueries.Sorted := True;
  ReadyQueries.Duplicates := dupIgnore;
end;

destructor TReadyQueryList.Destroy;
var
  i: Integer;
begin
  for i := 0 to ReadyQueries.Count - 1 do
    TReadyQueryItem(ReadyQueries.Objects[i]).Free;

  ReadyQueries.Free;
  Serialiser.Free;

  inherited;
end;

function TReadyQueryList.GetQuery(aSQL: string): TReadyQueryItem;
var
  Ndx: Integer;
begin
  Serialiser.Acquire;
  try
    Ndx := ReadyQueries.IndexOf(aSQL);
    if (Ndx < 0) then // not found
    begin
      Result := TReadyQueryItem.Create(FConnectionString, aSQL, Serialiser);
      ReadyQueries.AddObject(aSQL, Result);
    end
    else
      Result := TReadyQueryItem(ReadyQueries.Objects[Ndx]);
  finally
    Serialiser.Release;
  end;
end;

procedure TReadyQueryList.SetConnectionString(aConnectionString: string);
begin
  Serialiser.Acquire;
  try
    FConnectionString := aConnectionString;
  finally
    Serialiser.Release;
  end;
end;

end.
