unit ncThreads;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
// Written by Demos Bill, 17 Nov 2009
//
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

{$WARN SYMBOL_PLATFORM OFF}
// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

{$IFDEF MSWINDOWS}
uses Windows, Classes, SyncObjs, ActiveX, ComObj;
{$ELSE}
//uses System.Win, System.Classes, System.SyncObjs, System.ActiveX, System.Win.ComObj;
uses System.SysUtils, System.Classes, System.SyncObjs;
{$ENDIF}

type
  // The thread waits for the wakeup event to start processing
  // after the its ready event is set.
  // After processing is complete, it sets again the ready event and waits
  // again for the WakeUpEvent to be set.
  TncReadyThread = class(TThread)
  public
    WakeupEvent, ReadyEvent: TEvent;
    constructor Create;
    destructor Destroy; override;
    procedure Execute; override;
    procedure ProcessEvent; virtual; abstract;

    function IsReady: Boolean;
    function WaitForReady(aTimeOut: Cardinal = Infinite): TWaitResult;
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
    procedure SetGrowUpto(const Value: Integer);
  private
    ThreadClass: TncReadyThreadClass;
    procedure ShutDown;
  protected
    Serialiser: TCriticalSection;
    Threads: array of TncReadyThread;
  public
    constructor Create(aWorkerThreadClass: TncReadyThreadClass);
    destructor Destroy; override;
    function RequestReadyThread: TncReadyThread;
    procedure RunRequestedThread(aRequestedThread: TncReadyThread);
{$IFDEF MSWINDOWS}
    procedure SetExecThreads(aThreadCount: Integer; aThreadPriority: TThreadPriority);
    procedure SetThreadPriority(aPriority: TThreadPriority);
{$ELSE}
    procedure SetExecThreads(aThreadCount: Integer; aThreadPriority: Integer);
    procedure SetThreadPriority(aPriority: integer);
{$ENDIF}
    property GrowUpto: Integer read GetGrowUpto write SetGrowUpto;
  end;

function GetNumberOfProcessors: Integer;

implementation

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
  ReadyEvent.Free;
  WakeupEvent.Free;
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
        Break; // Exit main loop
      try
        ProcessEvent;
      except
      end;
      if Terminated then
        Break; // Exit main loop
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

function TncReadyThread.WaitForReady(aTimeOut: Cardinal = Infinite): TWaitResult;
begin
  Result := ReadyEvent.WaitFor(aTimeOut);
end;

procedure TncReadyThread.Run;
begin
  ReadyEvent.ResetEvent;
  WakeupEvent.SetEvent;
end;

// *****************************************************************************
{ TncThreadPool }
// *****************************************************************************

constructor TncThreadPool.Create(aWorkerThreadClass: TncReadyThreadClass);
begin
  Serialiser := TCriticalSection.Create;
  ThreadClass := aWorkerThreadClass;
  FGrowUpto := 500; // can reach up to 500 threads by default
end;

destructor TncThreadPool.Destroy;
begin
  ShutDown;
  Serialiser.Free;
  inherited;
end;

function TncThreadPool.RequestReadyThread: TncReadyThread;
var
  i: Integer;
  Accepted: Boolean;
begin
  Result := nil;
  Accepted := False;

  Serialiser.Acquire;
  try
    while not Accepted do
    begin
      for i := 0 to High(Threads) do
      begin
        if Threads[i].ReadyEvent.WaitFor(0) = wrSignaled then
        begin
          Threads[i].ReadyEvent.ResetEvent;

          Result := Threads[i];

          Accepted := True;
          Break; // Break for
        end;
      end;
      if (not Accepted) then
        if (Length(Threads) < FGrowUpto) then
        begin
          // Create a new thread to handle commands
          SetLength(Threads, Length(Threads) + 1);
          Threads[ High(Threads)] := ThreadClass.Create;
          Threads[ High(Threads)].Priority := Threads[0].Priority;
          Threads[i].ReadyEvent.WaitFor(1000);
        end
        else
          Sleep(1);
    end;
  finally
    Serialiser.Release;
  end;
end;

// Between requesting a ready thread and executing it, we normally fill in
// the thread's data (would be a descendant that we need to fill known data to work with)
procedure TncThreadPool.RunRequestedThread(aRequestedThread: TncReadyThread);
begin
  aRequestedThread.WakeupEvent.SetEvent;
end;

{$IFDEF MSWINDOWS}
procedure TncThreadPool.SetExecThreads(aThreadCount: Integer; aThreadPriority: TThreadPriority);
{$ELSE}
procedure TncThreadPool.SetExecThreads(aThreadCount: Integer; aThreadPriority: Integer);
{$ENDIF}
var
  i: Integer;
begin
  // Terminate any not needed threads
  if aThreadCount < Length(Threads) then
  begin
    for i := aThreadCount to high(Threads) do
      try
        Threads[i].Terminate;
        Threads[i].WakeupEvent.SetEvent;
      except
      end;
    for i := aThreadCount to high(Threads) do
      try
        Threads[i].WaitFor;
        Threads[i].Free;
      except
      end;
  end;

  // Reallocate thread count
  SetLength(Threads, aThreadCount);

  for i := 0 to high(Threads) do
    if Threads[i] = nil then
    begin
      Threads[i] := ThreadClass.Create;
      Threads[i].Priority := aThreadPriority;
    end
    else
      Threads[i].Priority := aThreadPriority;
end;

{$IFDEF MSWINDOWS}
procedure TncThreadPool.SetThreadPriority(aPriority: TThreadPriority);
{$ELSE}
procedure TncThreadPool.SetThreadPriority(aPriority: Integer);
{$ENDIF}
var
  i: Integer;
begin
  for i := 0 to high(Threads) do
    Threads[i].Priority := aPriority;
end;

procedure TncThreadPool.ShutDown;
var
  i: Integer;
begin
  for i := 0 to high(Threads) do
    try
      Threads[i].Terminate;
      Threads[i].WakeupEvent.SetEvent;
    except
    end;

  for i := 0 to high(Threads) do
    try
      Threads[i].WaitFor;
      Threads[i].Free;
    except
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

procedure TncThreadPool.SetGrowUpto(const Value: Integer);
begin
  Serialiser.Acquire;
  try
    FGrowUpto := Value;
  finally
    Serialiser.Release;
  end;
end;

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
      if lpSystemInfo.dwActiveProcessorMask or (1 shl i) <> 0 then
        Result := Result + 1;
  finally
    if Result < 1 then
      Result := 1;
  end;
end;
{$ELSE}
begin
  Result := 2;
end;
{$ENDIF}

end.
