unit ncDBCommands;

interface

uses Classes, SysUtils, DB, ADODB, ADOInt, ncSources, ncSerializeADO;

const
  ncDBOpenDataset = 0; // uses TDBDatasetData as param
  ncDBCloseDataset = 1; // uses no params
  ncDBUpdateDataset = 2; // uses TDBUpdateDatasetData as param
  ncDBExecDataset = 3; // uses TDBDatasetData as param

type
  TDBDatasetData = class(TncCommandData)
  public
    SQL: string;
    Parameters: TBytes;

    constructor Create;
    destructor Destroy; override;

    function FromBytes(aBytes: TBytes): Integer; override;
    function ToBytes: TBytes; override;
  end;

  TDBUpdateDatasetData = class(TDBDatasetData)
  public
    RecordUpdates: _Recordset;

    constructor Create;
    destructor Destroy; override;

    function FromBytes(aBytes: TBytes): Integer; override;
    function ToBytes: TBytes; override;
  end;

implementation

{ TDBOpenDatasetData }

constructor TDBDatasetData.Create;
begin
  inherited Create;
  SetLength(Parameters, 0);
end;

destructor TDBDatasetData.Destroy;
begin
  inherited;
end;

function TDBDatasetData.FromBytes(aBytes: TBytes): Integer;
begin
  Result := inherited FromBytes(aBytes);

  SQL := ReadString(aBytes, Result);
  Parameters := ReadBytes(aBytes, Result);
end;

function TDBDatasetData.ToBytes: TBytes;
var
  BufLen: Integer;
begin
  // This is intended for the use of WriteMessageEmbeddedBufferLen
  Result := inherited ToBytes;
  BufLen := Length(Result);

  WriteString(SQL, Result, BufLen);
  WriteBytes(Parameters, Result, BufLen);
end;

{ TDBUpdateDatasetData }

constructor TDBUpdateDatasetData.Create;
begin
  inherited Create;
  RecordUpdates := nil;
end;

destructor TDBUpdateDatasetData.Destroy;
begin
  if Assigned(RecordUpdates) then
    RecordUpdates := nil;

  inherited;
end;

function TDBUpdateDatasetData.FromBytes(aBytes: TBytes): Integer;
begin
  Result := inherited FromBytes(aBytes);

  RecordUpdates := BytesToRecordset(ReadBytes(aBytes, Result));
end;

function TDBUpdateDatasetData.ToBytes: TBytes;
var
  BufLen: Integer;
begin
  Result := inherited ToBytes;
  BufLen := Length(Result);

  WriteBytes(RecordsetToBytes(RecordUpdates, pfADTG), Result, BufLen);
end;

end.
