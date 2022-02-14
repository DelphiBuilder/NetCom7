unit ncThreads;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
// Written by Demos Bill, 17 Nov 2009
//
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}
{$WARN SYMBOL_PLATFORM OFF}

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows,
  WinApi.ActiveX,
{$ENDIF}
  System.Classes,
  System.SyncObjs,
  System.SysUtils;

type
  TncThreadPriority =
  (
    ntpIdle,
    ntpLowest,
    ntpLower,
    ntpNormal,
    ntpHigher,
    ntpHighest,
    ntpTimeCritical
  );

  // The thread waits for the wakeup event to start processing
  // after the its ready event is set.
  // After processing is complete, it sets again the ready event and waits
  // again for the WakeUpEvent to be set.
  TncReadyThread = class(TThread)
  public
    WakeupEvent: TEvent;
    ReadyEvent: TEvent;

    constructor Create;
    destructor Destroy; override;

    procedure Execute; override;
    procedure ProcessEvent; virtual; abstract;

    function IsReady: Boolean;
    function WaitForReady(ATimeOut: Cardinal = Infinite): TWaitResult;

    procedure Run;
  end;

  TncReadyThreadClass = class of TncReadyThread;

  // TncThreadPool is a thread pool of TncCommandExecThread that manages
  // to assign a job with AddJob to a waiting thread.
  // This Thread pool works as:
  // Request a ready thread from it, with RequestReadyThread
  // Set its data (normally this thread is a descendant of TncReadyThread with appropriate data fields
  // Call RunRequestedThread to tell it to run its ProcessEvent

  TncThreadPool = class
  private
    FGrowUpto: Integer;

    function GetGrowUpto: Integer;
    procedure SetGrowUpto(const AValue: Integer);
  private
    ThreadClass: TncReadyThreadClass;

    procedure Shutdown;
  protected
    Threads: array of TncReadyThread;
  public
    Serialiser: TCriticalSection;

    constructor Create(AWorkerThreadClass: TncReadyThreadClass);
    destructor Destroy; override;

    function RequestReadyThread: TncReadyThread;
    procedure RunRequestedThread(ARequestedThread: TncReadyThread);

    procedure SetExecThreads(AThreadCount: Integer; AThreadPriority: TncThreadPriority);
    procedure SetThreadPriority(APriority: TncThreadPriority);

    property GrowUpto: Integer read GetGrowUpto write SetGrowUpto;
  end;

function GetNumberOfProcessors: Integer; inline;
{$IFDEF MSWINDOWS}
function FromNCThreadPriority(AncThreadPriority: TncThreadPriority): TThreadPriority; inline;
function ToNCThreadPriority(AThreadPriority: TThreadPriority): TncThreadPriority; inline;
{$ELSE}
function FromNCThreadPriority(AncThreadPriority: TncThreadPriority): Integer; inline;
function ToNCThreadPriority(AThreadPriority: Integer): TncThreadPriority; inline;
{$ENDIF}

implementation

// *****************************************************************************
// Helper functions
// *****************************************************************************

function GetNumberOfProcessors: Integer;
{$IFDEF MSWINDOWS}
var
  lpSystemInfo: TSystemInfo;
  i: Integer;
begin
  Result := 0;
  try
    GetSystemInfo(lpSystemInfo);

    for i := 0 to lpSystemInfo.dwNumberOfProcessors - 1 do
    begin
      if lpSystemInfo.dwActiveProcessorMask or (1 shl i) <> 0 then
      begin
        Result := Result + 1;
      end;
    end;
  finally
    if Result < 1 then
    begin
      Result := 1;
    end;
  end;
end;
{$ELSE}
begin
  Result := TThread.ProcessorCount;
end;
{$ENDIF}

{$IFDEF MSWINDOWS}
function FromNCThreadPriority(AncThreadPriority: TncThreadPriority): TThreadPriority;
begin
  case AncThreadPriority of
    ntpIdle:
      Result := tpIdle;
    ntpLowest:
      Result := tpLowest;
    ntpLower:
      Result := tpLower;
    ntpHigher:
      Result := tpHigher;
    ntpHighest:
      Result := tpHighest;
    ntpTimeCritical:
      Result := tpTimeCritical;
  else
    Result := tpNormal;
  end;
end;

function ToNCThreadPriority(AThreadPriority: TThreadPriority): TncThreadPriority;
begin
  case AThreadPriority of
    tpIdle:
      Result := ntpIdle;
    tpLowest:
      Result := ntpLowest;
    tpLower:
      Result := ntpLower;
    tpHigher:
      Result := ntpHigher;
    tpHighest:
      Result := ntpHighest;
    tpTimeCritical:
      Result := ntpTimeCritical;
  else
    Result := ntpNormal;
  end;
end;
{$ELSE}
function FromNCThreadPriority(AncThreadPriority: TncThreadPriority): Integer;
begin
  case AncThreadPriority of
    ntpIdle:
      Result := 19;
    ntpLowest:
      Result := 13;
    ntpLower:
      Result := 7;
    ntpHigher:
      Result := -7;
    ntpHighest:
      Result := -13;
    ntpTimeCritical:
      Result := -19;
  else
    Result := 0;
  end;
end;

function ToNCThreadPriority(AThreadPriority: Integer): TncThreadPriority;
begin
  case AThreadPriority of
    14 .. 19:
      Result := ntpIdle;
    8 .. 13:
      Result := ntpLowest;
    3 .. 7:
      Result := ntpLower;
    -7 .. -3:
      Result := ntpHigher;
    -13 .. -8:
      Result := ntpHighest;
    -19 .. -14:
      Result := ntpTimeCritical;
  else
    Result := ntpNormal;
  end;
end;
{$ENDIF}

// *****************************************************************************
{ TncReadyThread }
// *****************************************************************************

constructor TncReadyThread.Create;
begin
  WakeupEvent := TEvent.Create;
  ReadyEvent := TEvent.Create;

  inherited Create(False);
end;

destructor TncReadyThread.Destroy;
begin
  FreeAndNil(ReadyEvent);
  FreeAndNil(WakeupEvent);

  inherited Destroy;
end;

procedure TncReadyThread.Execute;
begin
{$IFDEF MSWINDOWS}
  CoInitialize(nil);
{$ENDIF}
  try
    while True do
    begin
      ReadyEvent.SetEvent;
      WakeupEvent.WaitFor(Infinite);
      ReadyEvent.ResetEvent;
      WakeupEvent.ResetEvent; // Next loop will wait again

      if Terminated then
      begin
        Break; // ==> Exit main loop
      end;
      
      try
        ProcessEvent;
      except
        // Ignore
      end;

      if Terminated then
      begin
        Break; // ==> Exit main loop
      end;
    end; // Exiting main loop terminates thread

    ReadyEvent.SetEvent;
  finally
{$IFDEF MSWINDOWS}
    CoUninitialize;
{$ENDIF}
  end;
end;

function TncReadyThread.IsReady: Boolean;
begin
  Result := ReadyEvent.WaitFor(0) = wrSignaled;
end;

function TncReadyThread.WaitForReady(ATimeOut: Cardinal = Infinite): TWaitResult;
begin
  Result := ReadyEvent.WaitFor(ATimeOut);
end;

procedure TncReadyThread.Run;
begin
  ReadyEvent.ResetEvent;
  WakeupEvent.SetEvent;
end;

// *****************************************************************************
{ TncThreadPool }
// *****************************************************************************

constructor TncThreadPool.Create(AWorkerThreadClass: TncReadyThreadClass);
begin
  inherited Create;

  Serialiser := TCriticalSection.Create;
  ThreadClass := AWorkerThreadClass;
  FGrowUpto := 500; // can reach up to 500 threads by default
end;

destructor TncThreadPool.Destroy;
begin
  Shutdown;
  FreeAndNil(Serialiser);

  inherited Destroy;
end;

function TncThreadPool.RequestReadyThread: TncReadyThread;
var
  i: Integer;
begin
  // Keep repeating until a ready thread is found
  repeat
    for i := Low(Threads) to High(Threads) do
    begin
      if Threads[i].ReadyEvent.WaitFor(0) = wrSignaled then
      begin
        Threads[i].ReadyEvent.ResetEvent;
        Result := Threads[i];

        Exit; // ==>
      end;
    end;

    // We will get here if no threads were ready
    if Length(Threads) < FGrowUpto then
    begin
      // Create a new thread to handle commands
      i := Length(Threads);

      SetLength(Threads, i + 1); // i now holds High(Threads)
      try
        Threads[i] := ThreadClass.Create;
      except
        // Cannot create any new thread
        // Set length back to what it was, and continue waiting until
        // any other thread is ready
        SetLength(Threads, i);
        Continue; // ==>
      end;
      
      Threads[i].Priority := Threads[0].Priority;

      if Threads[i].ReadyEvent.WaitFor(1000) = wrSignaled then
      begin
        Threads[i].ReadyEvent.ResetEvent;
        Result := Threads[i];

        Exit; // ==>
      end;
    end else
    begin
      TThread.Yield;
    end;
  until False;
end;

// Between requesting a ready thread and executing it, we normally fill in
// the thread's data (would be a descendant that we need to fill known data to work with)
procedure TncThreadPool.RunRequestedThread(ARequestedThread: TncReadyThread);
begin
  ARequestedThread.WakeupEvent.SetEvent;
end;

procedure TncThreadPool.SetExecThreads(AThreadCount: Integer; AThreadPriority: TncThreadPriority);
var
  i: Integer;
begin
  // Terminate any not needed threads
  if AThreadCount < Length(Threads) then
  begin
    for i := AThreadCount to High(Threads) do
    try
      Threads[i].Terminate;
      Threads[i].WakeupEvent.SetEvent;
    except
      // Ignore
    end;

    for i := AThreadCount to High(Threads) do
    try
      Threads[i].WaitFor;
      FreeAndNil(Threads[i]);
    except
      // Ignore
    end;
  end;

  // Reallocate thread count
  SetLength(Threads, AThreadCount);

  for i := Low(Threads) to High(Threads) do
  begin
    if Threads[i] = nil then
    begin
      Threads[i] := ThreadClass.Create;
      Threads[i].Priority := FromNCThreadPriority(AThreadPriority);
    end else
    begin
      Threads[i].Priority := FromNCThreadPriority(AThreadPriority);
    end;
  end;
end;

procedure TncThreadPool.SetThreadPriority(APriority: TncThreadPriority);
var
  i: Integer;
begin
  for i := Low(Threads) to High(Threads) do
  try
    Threads[i].Priority := FromNCThreadPriority(APriority);
  except
    // Sone android devices do not like this
  end;
end;

procedure TncThreadPool.Shutdown;
var
  i: Integer;
begin
  for i := Low(Threads) to High(Threads) do
  try
    Threads[i].Terminate;
    Threads[i].WakeupEvent.SetEvent;
  except
    // Ignore
  end;

  for i := Low(Threads) to High(Threads) do
  try
    Threads[i].WaitFor;
    FreeAndNil(Threads[i]);
  except
    // Ignore
  end;
end;

function TncThreadPool.GetGrowUpto: Integer;
begin
  Serialiser.Acquire;
  try
    Result := FGrowUpto;
  finally
    Serialiser.Release;
  end;
end;

procedure TncThreadPool.SetGrowUpto(const AValue: Integer);
begin
  Serialiser.Acquire;
  try
    FGrowUpto := AValue;
  finally
    Serialiser.Release;
  end;
end;

end.
