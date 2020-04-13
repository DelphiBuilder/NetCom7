unit ncSerializeADO;

interface

uses SysUtils, Classes, Variants, DB, ADODB, ADOInt, ComObj, ActiveX, OleCtrls;

// SysUtils: Need TBytes
// Classes: Need TBytesStream
// ADODB: Need TPersistFormat
// ADOInt: Need function PersistFormatEnum
// ActiveX: Need IStream

function RecordsetToStream(const aRecordset: _Recordset; aFormat: TPersistFormat): TBytesStream;
function RecordsetToBytes(const aRecordset: _Recordset; aFormat: TPersistFormat = pfADTG): TBytes;

function StreamToRecordset(const aStream: TBytesStream; aConnection: TADOConnection = nil): _Recordset;
function BytesToRecordset(const aBytes: TBytes; aConnection: TADOConnection = nil): _Recordset;

function VariantToBytes(aVar: Variant): TBytes;
function BytesToVariant(aBytes: TBytes): Variant;

function ParametersToBytes(aParameters: TParameters): TBytes;
procedure BytesToParameters(aBytes: TBytes; aParameters: TParameters);

implementation

uses ncSources;

function VariantToBytes(aVar: Variant): TBytes;
var
  VariantType: TVarType;
  BufLen: Integer;
begin
  VariantType := FindVarData(aVar)^.VType;
  SetLength(Result, SizeOf(VariantType));
  move(VariantType, Result[0], SizeOf(VariantType));
  BufLen := Length(Result);
  if not(VariantType in [varEmpty, varNull]) then
  begin
    case VariantType of
      varByte, varSmallint, varShortInt, varInteger, varWord, varLongWord:
        WriteInteger(aVar, Result, BufLen);
      varSingle, varDouble:
        WriteDouble(aVar, Result, BufLen);
      varCurrency:
        WriteCurrency(aVar, Result, BufLen);
      varDate:
        WriteDate(aVar, Result, BufLen);
      varBoolean:
        WriteBool(aVar, Result, BufLen);
      varInt64, varUInt64:
        WriteInt64(aVar, Result, BufLen);
      varOleStr, varStrArg, varString, varUString:
        WriteString(aVar, Result, BufLen);
    else
      raise Exception.Create('Cannot pack specified parameter');
    end;
  end;

end;

function BytesToVariant(aBytes: TBytes): Variant;
var
  VariantType: TVarType;
  Ofs: Integer;
begin
  move(aBytes[0], VariantType, SizeOf(VariantType));
  Ofs := SizeOf(VariantType);

  if not(VariantType in [varEmpty, varNull]) then
  begin
    case VariantType of
      varEmpty:
        Result := Variants.Unassigned;
      varNull:
        Result := Variants.Null;
      varByte, varSmallint, varShortInt, varInteger, varWord, varLongWord:
        Result := ReadInteger(aBytes, Ofs);
      varSingle, varDouble:
        Result := ReadDouble(aBytes, Ofs);
      varCurrency:
        Result := ReadCurrency(aBytes, Ofs);
      varDate:
        Result := ReadDate(aBytes, Ofs);
      varBoolean:
        Result := ReadBool(aBytes, Ofs);
      varInt64, varUInt64:
        Result := ReadInt64(aBytes, Ofs);
      varOleStr, varStrArg, varString, varUString:
        Result := ReadString(aBytes, Ofs);
    else
      raise Exception.Create('Cannot pack specified parameter');
    end;
  end;

end;

function ParametersToBytes(aParameters: TParameters): TBytes;
var
  BufLen: Integer;
  i: Integer;
begin
  BufLen := 0;
  WriteInteger(aParameters.Count, Result, BufLen);
  for i := 0 to aParameters.Count - 1 do
    WriteBytes(VariantToBytes(aParameters.Items[i].Value), Result, BufLen);
end;

procedure BytesToParameters(aBytes: TBytes; aParameters: TParameters);
var
  ParameterCount: Integer;
  Ofs: Integer;
  i: Integer;
begin
  if Length(aBytes) > 0 then
  begin
    Ofs := 0;
    if not Assigned(aParameters) then
      raise Exception.Create('Parameters object not assigned');
    ParameterCount := ReadInteger(aBytes, Ofs);
    if ParameterCount <> aParameters.Count then
      raise Exception.Create('Bytes stream parameters differ from SQL Parameters');

    for i := 0 to ParameterCount - 1 do
      aParameters.Items[i].Value := BytesToVariant(ReadBytes(aBytes, Ofs));
  end;
end;

function RecordsetToStream(const aRecordset: _Recordset; aFormat: TPersistFormat): TBytesStream;
var
  ADOStream: IStream;
begin
  // Create a stream to hold the data
  Result := TBytesStream.Create;
  try
    // Since ADO can't write directly to a Delphi stream, we must wrap the Delphi stream
    ADOStream := TStreamAdapter.Create(Result, soReference) as IStream;
    try
      // Save the content of the recordset to the stream
      aRecordset.Save(ADOStream, PersistFormatEnum(aFormat));
    finally
      ADOStream := nil;
    end;

    // The Stream now contains the data
    // Position the stream at the start
    Result.Position := 0;
  except
    Result.Free;
    raise ;
  end;
end;

function RecordsetToBytes(const aRecordset: _Recordset; aFormat: TPersistFormat = pfADTG): TBytes;
var
  tmpSS: TBytesStream;
begin
  tmpSS := RecordsetToStream(aRecordset, aFormat);
  try
    Result := tmpSS.Bytes;
  finally
    tmpSS.Free;
  end;
end;


function StreamToRecordset(const aStream: TBytesStream; aConnection: TADOConnection = nil): _Recordset;
var
  ADOStream: IStream;
begin
  Result := CoRecordset.Create;
  try
    // Since ADO can't write directly to a Delphi stream, we must wrap the Delphi stream
    ADOStream := TStreamAdapter.Create(aStream, soReference) as IStream;
    try
      // Save the content of the stream to the recordset
      Result.Open(ADOStream, EmptyParam, adOpenKeyset, adLockBatchOptimistic, adCmdFile);

      // You need to Set_ActiveConnection in order to be able to update a recordset.
      if Assigned(aConnection) then
          Result.Set_ActiveConnection(aConnection.ConnectionObject);
    finally
      ADOStream := nil;
    end;
  except
    Result := nil;
    raise ;
  end;
end;

function BytesToRecordset(const aBytes: TBytes; aConnection: TADOConnection = nil): _Recordset;
var
  Stream: TBytesStream;
begin
  Stream := TBytesStream.Create(aBytes);
  try
    Stream.Position := 0;
    Result := StreamToRecordset(Stream, aConnection);
  finally
    Stream.Free;
  end;
end;


end.
