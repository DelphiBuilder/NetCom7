unit ufrmMain;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, System.StrUtils, System.DateUtils,
  System.Diagnostics, System.SyncObjs, System.Math,
  ncTSockets, ncLines, ncThreads;

type
  TfrmMain = class(TForm)
    Panel1: TPanel;
    btnStartStop: TButton;
    edtPort: TEdit;
    Label1: TLabel;
    Panel2: TPanel;
    memoLog: TMemo;
    Label2: TLabel;
    Panel3: TPanel;
    Label3: TLabel;
    lblConnections: TLabel;
    Label4: TLabel;
    lblThreadsPerCPU: TLabel;
    Label5: TLabel;
    lblMaxThreads: TLabel;
    Label6: TLabel;
    lblTotalRequests: TLabel;
    btnClearLog: TButton;
    Label7: TLabel;
    lblRequestsPerSecond: TLabel;
    Timer1: TTimer;
    Label8: TLabel;
    lblActiveThreads: TLabel;
    lblLastTestResults: TLabel;
    lblTestTotalRequests: TLabel;
    lblTestTotalRequestsValue: TLabel;
    lblTestPeakReqSec: TLabel;
    lblTestPeakReqSecValue: TLabel;
    lblTestDuration: TLabel;
    lblTestDurationValue: TLabel;
    lblTestAvgReqSec: TLabel;
    lblTestAvgReqSecValue: TLabel;
    btnResetStats: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnStartStopClick(Sender: TObject);
    procedure btnClearLogClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure btnResetStatsClick(Sender: TObject);
  private
    FServer: TncServer;
    FRequestCount: Integer;
    FLastRequestCount: Integer;
    FRequestCountLock: TCriticalSection;
    FConnectionCount: Integer;
    FConnectionCountLock: TCriticalSection;
    FMaxRequestsPerSecond: Integer;
    FTestStartTime: TDateTime;
    FTestStartRequestCount: Integer;
    FTestInProgress: Boolean;
    
    procedure ServerConnected(Sender: TObject; aLine: TncLine);
    procedure ServerDisconnected(Sender: TObject; aLine: TncLine);
    procedure ServerReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
    procedure LogMessage(const aMessage: string);
    procedure ProcessDataRequest(aLine: TncLine; const aRequest: string);
    procedure UpdateConnectionCount(aDelta: Integer);
    procedure UpdateRequestCount;
    procedure UpdateStatistics;
    procedure DisplayFinalTestResults(CurrentRequestCount: Integer);
  public
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  FRequestCount := 0;
  FLastRequestCount := 0;
  FConnectionCount := 0;
  FMaxRequestsPerSecond := 0;
  FTestStartTime := 0;
  FTestStartRequestCount := 0;
  FTestInProgress := False;
  FRequestCountLock := TCriticalSection.Create;
  FConnectionCountLock := TCriticalSection.Create;
  
  // Create TncServer with optimal thread pool settings
  FServer := TncServer.Create(Self);
  
  // Configure thread pool for demonstration
  FServer.DataProcessorThreadsPerCPU := 4;  // 4 threads per CPU core
  FServer.DataProcessorThreadsGrowUpto := 32; // Maximum 32 threads
  FServer.DataProcessorThreadPriority := ntpNormal;
  FServer.EventsUseMainThread := False; // Use thread pool for processing - UI updates handled separately
  
  // Configure socket properties
  FServer.NoDelay := True;
  FServer.KeepAlive := True;
  FServer.ReadBufferLen := 8192;
  
  // Set event handlers
  FServer.OnConnected := ServerConnected;
  FServer.OnDisconnected := ServerDisconnected;
  FServer.OnReadData := ServerReadData;
  
  // Initialize UI
  edtPort.Text := '8080';
  lblThreadsPerCPU.Caption := IntToStr(FServer.DataProcessorThreadsPerCPU);
  lblMaxThreads.Caption := IntToStr(FServer.DataProcessorThreadsGrowUpto);
  
  UpdateStatistics;
  
  LogMessage('Server initialized with thread pool configuration');
  LogMessage('Threads per CPU: ' + IntToStr(FServer.DataProcessorThreadsPerCPU));
  LogMessage('Max threads: ' + IntToStr(FServer.DataProcessorThreadsGrowUpto));
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  if Assigned(FServer) then
  begin
    FServer.Active := False;
    FServer.Free;
  end;
  
  FRequestCountLock.Free;
  FConnectionCountLock.Free;
end;

procedure TfrmMain.btnStartStopClick(Sender: TObject);
begin
  if FServer.Active then
  begin
    // Stop server
    FServer.Active := False;
    btnStartStop.Caption := 'Start Server';
    LogMessage('Server stopped');
  end
  else
  begin
    // Start server
    try
      FServer.Port := StrToInt(edtPort.Text);
      FServer.Active := True;
      btnStartStop.Caption := 'Stop Server';
      LogMessage('Server started on port ' + edtPort.Text);
      LogMessage('Ready to accept connections...');
    except
      on E: Exception do
      begin
        LogMessage('Error starting server: ' + E.Message);
        ShowMessage('Error starting server: ' + E.Message);
      end;
    end;
  end;
end;

procedure TfrmMain.btnClearLogClick(Sender: TObject);
begin
  memoLog.Clear;
end;

procedure TfrmMain.Timer1Timer(Sender: TObject);
begin
  UpdateStatistics;
end;

procedure TfrmMain.ServerConnected(Sender: TObject; aLine: TncLine);
begin
  UpdateConnectionCount(1);
  LogMessage('Client connected: ' + aLine.PeerIP);
end;

procedure TfrmMain.ServerDisconnected(Sender: TObject; aLine: TncLine);
begin
  UpdateConnectionCount(-1);
  LogMessage('Client disconnected: ' + aLine.PeerIP);
end;

// This runs in a processing thread from the thread pool
procedure TfrmMain.ServerReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
var
  Request: string;
  ThreadID: TThreadID;
begin
  try
    ThreadID := GetCurrentThreadId;
    
    // Convert received data to string
    Request := TEncoding.UTF8.GetString(aBuf, 0, aBufCount);
    Request := Trim(Request);
    
    if Request <> '' then
    begin
      UpdateRequestCount;
      
      // Only log occasionally to avoid UI bottleneck during stress tests
      if (ThreadID mod 7 = 0) then  // Log roughly 1 in 7 requests based on thread ID
      begin
        TThread.Synchronize(nil, procedure
        begin
          LogMessage(Format('Processing request from %s in thread %d: %s', 
            [aLine.PeerIP, ThreadID, Copy(Request, 1, 50)]));
        end);
      end;
      
      // Process the request (this can be CPU-intensive)
      ProcessDataRequest(aLine, Request);
    end;
    
  except
    on E: Exception do
    begin
      TThread.Synchronize(nil, procedure
      begin
        LogMessage('Error processing request: ' + E.Message);
      end);
    end;
  end;
end;

procedure TfrmMain.ProcessDataRequest(aLine: TncLine; const aRequest: string);
var
  Response: string;
  ResponseBytes: TBytes;
  ProcessingTime: Integer;
  StartTime: TStopwatch;
  ThreadID: TThreadID;
  Command, Data: string;
  Parts: TArray<string>;
begin
  ThreadID := GetCurrentThreadId;
  StartTime := TStopwatch.StartNew;
  
  try
    // Parse command from request
    Parts := aRequest.Split([' '], 2);
    Command := UpperCase(Parts[0]);
    
    if Length(Parts) > 1 then
      Data := Parts[1]
    else
      Data := '';
    
    // Process different commands
    case IndexText(Command, ['PING', 'ECHO', 'REVERSE', 'HASH', 'COMPUTE', 'TIME']) of
      0: // PING
        begin
          Response := 'PONG';
        end;
      1: // ECHO
        begin
          Response := 'ECHO: ' + Data;
        end;
      2: // REVERSE
        begin
          Response := 'REVERSED: ' + ReverseString(Data);
        end;
      3: // HASH
        begin
          // Simulate CPU-intensive hashing
          Sleep(100 + Random(200)); // Variable processing time
          Response := 'HASH: ' + IntToStr(Data.GetHashCode);
        end;
      4: // COMPUTE
        begin
          // Simulate heavy computation
          Sleep(500 + Random(1000)); // 0.5-1.5 seconds
          Response := 'COMPUTED: ' + IntToStr(Random(1000000));
        end;
      5: // TIME
        begin
          Response := 'TIME: ' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now);
        end;
    else
      Response := 'ERROR: Unknown command. Available: PING, ECHO <text>, REVERSE <text>, HASH <text>, COMPUTE, TIME';
    end;
    
    // Add thread and timing information
    ProcessingTime := StartTime.ElapsedMilliseconds;
    Response := Response + #13#10 + Format('Thread: %d, Processing time: %dms', [ThreadID, ProcessingTime]);
    
    // Send response
    ResponseBytes := TEncoding.UTF8.GetBytes(Response + #13#10);
    FServer.Send(aLine, ResponseBytes);
    
  except
    on E: Exception do
    begin
      Response := 'ERROR: ' + E.Message;
      ResponseBytes := TEncoding.UTF8.GetBytes(Response + #13#10);
      FServer.Send(aLine, ResponseBytes);
    end;
  end;
end;

procedure TfrmMain.LogMessage(const aMessage: string);
begin
  if memoLog.Lines.Count > 1000 then
    memoLog.Clear;
    
  memoLog.Lines.Add(FormatDateTime('hh:nn:ss.zzz', Now) + ' - ' + aMessage);
  
  // Auto-scroll to bottom
  SendMessage(memoLog.Handle, WM_VSCROLL, SB_BOTTOM, 0);
end;

procedure TfrmMain.UpdateConnectionCount(aDelta: Integer);
begin
  FConnectionCountLock.Acquire;
  try
    FConnectionCount := FConnectionCount + aDelta;
  finally
    FConnectionCountLock.Release;
  end;
end;

procedure TfrmMain.UpdateRequestCount;
begin
  FRequestCountLock.Acquire;
  try
    Inc(FRequestCount);
  finally
    FRequestCountLock.Release;
  end;
end;

procedure TfrmMain.UpdateStatistics;
var
  CurrentRequests: Integer;
  RequestsPerSecond: Integer;
begin
  // Update connection count
  FConnectionCountLock.Acquire;
  try
    lblConnections.Caption := IntToStr(FConnectionCount);
  finally
    FConnectionCountLock.Release;
  end;
  
  // Update request statistics
  FRequestCountLock.Acquire;
  try
    CurrentRequests := FRequestCount;
    lblTotalRequests.Caption := IntToStr(CurrentRequests);
    
    // Calculate requests per second
    RequestsPerSecond := CurrentRequests - FLastRequestCount;
    lblRequestsPerSecond.Caption := IntToStr(RequestsPerSecond);
    FLastRequestCount := CurrentRequests;
  finally
    FRequestCountLock.Release;
  end;
  
  // Detect test start (first time we see incoming requests)
  if not FTestInProgress and (RequestsPerSecond > 0) then
  begin
    FTestInProgress := True;
    FTestStartTime := Now;
    FTestStartRequestCount := CurrentRequests - RequestsPerSecond;
    FMaxRequestsPerSecond := RequestsPerSecond;
    LogMessage('Test started - tracking performance...');
  end;
  
  // Track peak performance during test
  if FTestInProgress and (RequestsPerSecond > FMaxRequestsPerSecond) then
  begin
    FMaxRequestsPerSecond := RequestsPerSecond;
  end;
  
  // Detect test end (no requests for 2 seconds after test was active)
  if FTestInProgress and (RequestsPerSecond = 0) then
  begin
    // Wait for a confirmation period (2 more timer ticks = 2 seconds)
    if Timer1.Tag = 0 then
      Timer1.Tag := GetTickCount;
    
    if (GetTickCount - Cardinal(Timer1.Tag)) >= 2000 then
    begin
      // Test ended - calculate final results
      FTestInProgress := False;
      Timer1.Tag := 0;
      DisplayFinalTestResults(CurrentRequests);
      LogMessage('Test completed - final results calculated');
    end;
  end
  else
  begin
    // Reset the end-test timer if we're still getting requests
    Timer1.Tag := 0;
  end;
  
  // Update active threads info - show thread pool threads (not connections)
  var ThreadPoolThreads := FServer.GetThreadPoolThreadCount;
  var ActiveProcessingThreads := FServer.GetThreadPoolActiveThreadCount;
  var ConnectionCount := FServer.Lines.LockList.Count;
  FServer.Lines.UnlockList;
  
  lblActiveThreads.Caption := Format('%d pool (%d active)', [ThreadPoolThreads, ActiveProcessingThreads]);
end;

procedure TfrmMain.DisplayFinalTestResults(CurrentRequestCount: Integer);
var
  TotalTestRequests: Integer;
  TestDuration: Double;
  AvgRequestsPerSecond: Double;
begin
  TotalTestRequests := CurrentRequestCount - FTestStartRequestCount;
  TestDuration := (Now - FTestStartTime) * 24 * 60 * 60; // Convert to seconds
  
  if TestDuration > 0 then
    AvgRequestsPerSecond := TotalTestRequests / TestDuration
  else
    AvgRequestsPerSecond := 0;
  
  // Display final test results
  lblTestTotalRequestsValue.Caption := Format('%d', [TotalTestRequests]);
  lblTestPeakReqSecValue.Caption := Format('%d', [FMaxRequestsPerSecond]);
  lblTestDurationValue.Caption := Format('%.1fs', [TestDuration]);
  lblTestAvgReqSecValue.Caption := Format('%.1f', [AvgRequestsPerSecond]);
  
  LogMessage(Format('Final Results: %d requests, %.1fs duration, %d peak req/sec, %.1f avg req/sec', 
    [TotalTestRequests, TestDuration, FMaxRequestsPerSecond, AvgRequestsPerSecond]));
end;

procedure TfrmMain.btnResetStatsClick(Sender: TObject);
begin
  // Reset final test results display
  lblTestTotalRequestsValue.Caption := '0';
  lblTestPeakReqSecValue.Caption := '0';
  lblTestDurationValue.Caption := '0s';
  lblTestAvgReqSecValue.Caption := '0';
  
  // Reset internal tracking variables
  FMaxRequestsPerSecond := 0;
  FTestStartTime := 0;
  FTestStartRequestCount := 0;
  FTestInProgress := False;
  Timer1.Tag := 0;
  
  LogMessage('Test statistics reset');
end;

end. 