unit ncPendingCommandsList;

/// ////////////////////////////////////////////////////////////////////////////
//
// TPendingCommandsList
// Written by Demos Bill, Tue 11/08/2020
//
// PendingCommandsList, the equivalent of TStringList
// but for the type of TncCommandUniqueID
//
/// ////////////////////////////////////////////////////////////////////////////

interface

uses System.Classes, System.SysUtils, System.RTLConsts, System.SyncObjs, ncCommandPacking;

type
  TPendingCommandItem = record
    FUniqueID: TncCommandUniqueID;
    FReceivedResultEvent: TLightweightEvent;
    FResult: TncCommand;
  end;

  PPendingCommandItem = ^TPendingCommandItem;

  TPendingCommandItemsList = array of TPendingCommandItem;
  PPendingCommandItemsList = ^TPendingCommandItemsList;

  TPendingCommandsList = class(TPersistent)
  private
    FList: TPendingCommandItemsList;
    FCount: Integer;
    FCapacity: Integer;
    function GetUniqueIDs(Index: Integer): TncCommandUniqueID; register;
    function GetReceivedResultEvents(Index: Integer): TLightweightEvent; register;
    procedure PutReceivedResultEvents(Index: Integer; aReceivedResultEvent: TLightweightEvent);
    function GetResults(Index: Integer): TncCommand;
    procedure PutResults(Index: Integer; const aResult: TncCommand);
    procedure SetCapacity(aNewCapacity: Integer);
  protected
    procedure Insert(aIndex: Integer; const aUniqueID: TncCommandUniqueID; aReceivedResultEvent: TLightweightEvent);
    procedure Grow;
  public
    destructor Destroy; override;

    function Add(const aUniqueID: TncCommandUniqueID; aReceivedResultEvent: TLightweightEvent): Integer;
    procedure Clear;
    procedure Delete(aIndex: Integer); register;
    function Find(const aUniqueID: TncCommandUniqueID; var aIndex: Integer): Boolean; register;
    function IndexOf(const aUniqueID: TncCommandUniqueID): Integer; register;

    property Count: Integer read FCount;
    property UniqueIDs[index: Integer]: TncCommandUniqueID read GetUniqueIDs; default;
    property ReceivedResultEvents[index: Integer]: TLightweightEvent read GetReceivedResultEvents write PutReceivedResultEvents;
    property Results[index: Integer]: TncCommand read GetResults write PutResults;
  end;

implementation

resourcestring
  SDuplicateUniqueID = 'Command unique ID list does not allow duplicates';

  { TPendingCommandList }

destructor TPendingCommandsList.Destroy;
begin
  inherited Destroy;
  FCount := 0;
  SetCapacity(0);
end;

function TPendingCommandsList.Add(const aUniqueID: TncCommandUniqueID; aReceivedResultEvent: TLightweightEvent): Integer;
begin
  if Find(aUniqueID, Result) then
    raise Exception.Create(SDuplicateUniqueID);
  Insert(Result, aUniqueID, aReceivedResultEvent);
end;

procedure TPendingCommandsList.Clear;
begin
  if FCount <> 0 then
  begin
    FCount := 0;
    SetCapacity(0);
  end;
end;

procedure TPendingCommandsList.Delete(aIndex: Integer);
begin
  if (aIndex < 0) or (aIndex >= FCount) then
    raise Exception.Create(Format(SListIndexError, [aIndex]));

  Dec(FCount);
  if aIndex < FCount then
    System.Move(FList[aIndex + 1], FList[aIndex], (FCount - aIndex) * SizeOf(TPendingCommandItem));
end;

// Binary Searching

function TPendingCommandsList.Find(const aUniqueID: TncCommandUniqueID; var aIndex: Integer): Boolean;
var
  Low, High, Mid: Integer;
begin
  Result := False;
  Low := 0;
  High := FCount - 1;
  while Low <= High do
  begin
    Mid := (Low + High) shr 1;
    if aUniqueID > FList[Mid].FUniqueID then
      Low := Mid + 1
    else
    begin
      High := Mid - 1;
      if aUniqueID = FList[Mid].FUniqueID then
      begin
        Result := True;
        Low := Mid;
      end;
    end;
  end;
  aIndex := Low;
end;

procedure TPendingCommandsList.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else if FCapacity > 8 then
    Delta := 16
  else
    Delta := 4;
  SetCapacity(FCapacity + Delta);
end;

function TPendingCommandsList.IndexOf(const aUniqueID: TncCommandUniqueID): Integer;
begin
  if not Find(aUniqueID, Result) then
    Result := -1;
end;

procedure TPendingCommandsList.Insert(aIndex: Integer; const aUniqueID: TncCommandUniqueID; aReceivedResultEvent: TLightweightEvent);
begin
  if FCount = FCapacity then
    Grow;
  if aIndex < FCount then
    System.Move(FList[aIndex], FList[aIndex + 1], (FCount - aIndex) * SizeOf(TPendingCommandItem));
  with FList[aIndex] do
  begin
    FUniqueID := aUniqueID;
    FReceivedResultEvent := aReceivedResultEvent;
  end;
  Inc(FCount);
end;

function TPendingCommandsList.GetUniqueIDs(Index: Integer): TncCommandUniqueID;
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  Result := FList[index].FUniqueID;
end;

function TPendingCommandsList.GetReceivedResultEvents(Index: Integer): TLightweightEvent;
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  Result := FList[index].FReceivedResultEvent;
end;

procedure TPendingCommandsList.PutReceivedResultEvents(Index: Integer; aReceivedResultEvent: TLightweightEvent);
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  FList[index].FReceivedResultEvent := aReceivedResultEvent;
end;

function TPendingCommandsList.GetResults(Index: Integer): TncCommand;
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  Result := FList[index].FResult;
end;

procedure TPendingCommandsList.PutResults(Index: Integer; const aResult: TncCommand);
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  FList[index].FResult := aResult;
end;

procedure TPendingCommandsList.SetCapacity(aNewCapacity: Integer);
begin
  if aNewCapacity < FCount then
    raise Exception.Create(Format(SListCapacityError, [aNewCapacity]));
  if aNewCapacity <> FCapacity then
  begin
    SetLength(FList, aNewCapacity);
    FCapacity := aNewCapacity;
  end;
end;

end.
