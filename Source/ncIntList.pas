unit ncIntList;

/// ////////////////////////////////////////////////////////////////////////////
//
// TIntList
// Written by Demos Bill, Tue 21/10/2004
//
// IntList, the equivalent of TStringList
// but for the type of Int64
//

interface

uses Classes, SysUtils, RTLConsts;

type
  TCustomIntList = class;

  PIntItem = ^TIntItem;
  TIntItem = record
    FInteger: int64;
    FObject: TObject;
  end;

  PIntItemList = ^TIntItemList;
  TIntItemList = array of TIntItem;

  TCustomIntList = class(TPersistent)
  private
    FList: TIntItemList;
    FCount: Integer;
    FCapacity: Integer;
    FSorted: Boolean;
    FDuplicates: TDuplicates;
    procedure ExchangeItems(Index1, Index2: Integer);
    procedure Grow;
    procedure QuickSort(L, R: Integer);
    procedure SetSorted(Value: Boolean);
  protected
    function Get(Index: Integer): int64; register;
    function GetCapacity: Integer; register;
    function GetCount: Integer; register;
    function GetObject(Index: Integer): TObject; register;
    procedure Put(Index: Integer; const N: int64); register;
    procedure PutObject(Index: Integer; AObject: TObject);
    procedure SetCapacity(NewCapacity: Integer);
    function CompareNumbers(const N1, N2: int64): Integer; register;
    procedure InsertItem(Index: Integer; const N: int64; AObject: TObject);
  public
    function Add(const N: int64): Integer; register;
    function AddObject(const N: int64; AObject: TObject): Integer;
    procedure Clear;
    procedure Delete(Index: Integer); register;
    procedure Exchange(Index1, Index2: Integer);
    function Find(const N: int64; var Index: Integer): Boolean;
    function IndexOf(const N: int64): Integer;
    procedure Insert(Index: Integer; const N: int64); register;
    procedure InsertObject(Index: Integer; const N: int64; AObject: TObject);
    procedure Sort;

    property Duplicates: TDuplicates read FDuplicates write FDuplicates;
    property Items[index: Integer]: int64 read Get write Put; default;
    property Objects[index: Integer]: TObject read GetObject write PutObject;
    property Sorted: Boolean read FSorted write SetSorted;
  public
    destructor Destroy; override;
    property Count: Integer read FCount;
  end;

  TIntList = class(TCustomIntList)
  public
    property Items;
    property Objects;
  published
    property Count;
    property Duplicates;
    property Sorted;
  end;

implementation

resourcestring
  SDuplicateInteger = 'Integer list does not allow duplicates';

  { TCustomIntList }

destructor TCustomIntList.Destroy;
begin
  inherited Destroy;
  FCount := 0;
  SetCapacity(0);
end;

function TCustomIntList.Add(const N: int64): Integer;
begin
  Result := AddObject(N, nil);
end;

function TCustomIntList.AddObject(const N: int64; AObject: TObject): Integer;
begin
  if not Sorted then
    Result := FCount
  else if Find(N, Result) then
    case Duplicates of
      dupIgnore:
        Exit;
      dupError:
        raise Exception.Create(SDuplicateInteger);
    end;
  InsertItem(Result, N, AObject);
end;

procedure TCustomIntList.Clear;
begin
  if FCount <> 0 then
  begin
    FCount := 0;
    SetCapacity(0);
  end;
end;

procedure TCustomIntList.Delete(Index: Integer);
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));

  Dec(FCount);
  if index < FCount then
    System.Move(FList[index + 1], FList[index], (FCount - index) * SizeOf(TIntItem));
end;

procedure TCustomIntList.Exchange(Index1, Index2: Integer);
begin
  if (Index1 < 0) or (Index1 >= FCount) then
    raise Exception.Create(Format(SListIndexError, [Index1]));
  if (Index2 < 0) or (Index2 >= FCount) then
    raise Exception.Create(Format(SListIndexError, [Index2]));
  ExchangeItems(Index1, Index2);
end;

procedure TCustomIntList.ExchangeItems(Index1, Index2: Integer);
var
  Temp: int64;
  Item1, Item2: PIntItem;
begin
  Item1 := @FList[Index1];
  Item2 := @FList[Index2];
  Temp := Item1^.FInteger;
  Item1^.FInteger := Item2^.FInteger;
  Item2^.FInteger := Temp;
  Temp := Integer(Item1^.FObject);
  Integer(Item1^.FObject) := Integer(Item2^.FObject);
  Integer(Item2^.FObject) := Temp;
end;

// Bin Searching
function TCustomIntList.Find(const N: int64; var Index: Integer): Boolean;
var
  L, H, I, C: Integer;
begin
  Result := False;
  L := 0;
  H := FCount - 1;
  while L <= H do
  begin
    I := (L + H) shr 1;
    C := CompareNumbers(FList[I].FInteger, N);
    if C < 0 then
      L := I + 1
    else
    begin
      H := I - 1;
      if C = 0 then
      begin
        Result := True;
        if Duplicates <> dupAccept then
          L := I;
      end;
    end;
  end;
  index := L;
end;

function TCustomIntList.Get(Index: Integer): int64;
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  Result := FList[index].FInteger;
end;

function TCustomIntList.GetCapacity: Integer;
begin
  Result := FCapacity;
end;

function TCustomIntList.GetCount: Integer;
begin
  Result := FCount;
end;

function TCustomIntList.GetObject(Index: Integer): TObject;
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  Result := FList[index].FObject;
end;

procedure TCustomIntList.Grow;
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

function TCustomIntList.IndexOf(const N: int64): Integer;
begin
  if not Sorted then
  begin
    for Result := 0 to GetCount - 1 do
      if CompareNumbers(Get(Result), N) = 0 then
        Exit;
    Result := -1;
  end
  else if not Find(N, Result) then
    Result := -1;
end;

procedure TCustomIntList.Insert(Index: Integer; const N: int64);
begin
  InsertObject(index, N, nil);
end;

procedure TCustomIntList.InsertObject(Index: Integer; const N: int64; AObject: TObject);
begin
  if Sorted then
    raise Exception.Create(SSortedListError);
  if (index < 0) or (index > FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  InsertItem(index, N, AObject);
end;

procedure TCustomIntList.InsertItem(Index: Integer; const N: int64; AObject: TObject);
begin
  if FCount = FCapacity then
    Grow;
  if index < FCount then
    System.Move(FList[index], FList[index + 1], (FCount - index) * SizeOf(TIntItem));
  with FList[index] do
  begin
    FObject := AObject;
    FInteger := N;
  end;
  Inc(FCount);
end;

procedure TCustomIntList.Put(Index: Integer; const N: int64);
begin
  if Sorted then
    raise Exception.Create(SSortedListError);

  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  FList[index].FInteger := N;
end;

procedure TCustomIntList.PutObject(Index: Integer; AObject: TObject);
begin
  if (index < 0) or (index >= FCount) then
    raise Exception.Create(Format(SListIndexError, [index]));
  FList[index].FObject := AObject;
end;

procedure TCustomIntList.Sort;
begin
  if not Sorted and (FCount > 1) then
  begin
    QuickSort(0, FCount - 1);
  end;
end;

function IntegerListCompareStrings(aList: TCustomIntList; aIndex1, aIndex2: Integer): Integer;
begin
  Result := aList.CompareNumbers(aList.FList[aIndex1].FInteger, aList.FList[aIndex2].FInteger);
end;

function TCustomIntList.CompareNumbers(const N1, N2: int64): Integer;
begin
  Result := N1 - N2;
end;

procedure TCustomIntList.QuickSort(L, R: Integer);
var
  I, J, P: Integer;
begin
  repeat
    I := L;
    J := R;
    P := (L + R) shr 1;
    repeat
      while IntegerListCompareStrings(Self, I, P) < 0 do
        Inc(I);
      while IntegerListCompareStrings(Self, J, P) > 0 do
        Dec(J);
      if I <= J then
      begin
        ExchangeItems(I, J);
        if P = I then
          P := J
        else if P = J then
          P := I;
        Inc(I);
        Dec(J);
      end;
    until I > J;
    if L < J then
      QuickSort(L, J);
    L := I;
  until I >= R;
end;

procedure TCustomIntList.SetCapacity(NewCapacity: Integer);
begin
  if NewCapacity < FCount then
    raise Exception.Create (Format (SListCapacityError, [NewCapacity]));
  if NewCapacity <> FCapacity then
  begin
    SetLength(FList, NewCapacity);
    FCapacity := NewCapacity;
  end;
end;

procedure TCustomIntList.SetSorted(Value: Boolean);
begin
  if FSorted <> Value then
  begin
    if Value then
      Sort;
    FSorted := Value;
  end;
end;

end.
