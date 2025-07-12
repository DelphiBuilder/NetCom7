unit ufrmTCPServer;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, System.Math,
  System.Hash, System.DateUtils, System.Diagnostics, System.Types, System.SyncObjs, System.StrUtils,
  ncSockets, ncLines;

type
  TfrmTCPServer = class(TForm)
    pnlTop: TPanel;
    btnStartStop: TButton;
    edtPort: TEdit;
    lblPort: TLabel;
    memoLog: TMemo;
    lblLog: TLabel;
    pnlStats: TPanel;
    lblConnections: TLabel;
    lblRequests: TLabel;
    lblRequestsPerSec: TLabel;
    lblThreads: TLabel;
    lblConnectionsValue: TLabel;
    lblRequestsValue: TLabel;
    lblRequestsPerSecValue: TLabel;
    lblThreadsValue: TLabel;
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
    tmrStats: TTimer;
    procedure btnStartStopClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure tmrStatsTimer(Sender: TObject);
    procedure btnResetStatsClick(Sender: TObject);
  private
    FServer: TncTCPServer;
    FStartTime: TDateTime;
    FRequestCount: Integer;
    FLastRequestCount: Integer;
    FMaxRequestsPerSecond: Integer;
    FRequestCountLock: TCriticalSection;
    FTestStartTime: TDateTime;
    FTestStartRequestCount: Integer;
    FTestInProgress: Boolean;
    
    procedure ServerConnected(Sender: TObject; aLine: TncLine);
    procedure ServerDisconnected(Sender: TObject; aLine: TncLine);
    procedure ServerReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
    procedure ProcessCommandDirectly(aLine: TncLine; const aCommand: string);
    procedure LogMessage(const aMessage: string);
    procedure IncrementRequestCount;
    procedure DisplayFinalTestResults(CurrentRequestCount: Integer);
  public
    { Public declarations }
  end;

var
  frmTCPServer: TfrmTCPServer;

implementation

{$R *.dfm}

procedure TfrmTCPServer.FormCreate(Sender: TObject);
begin
  FRequestCountLock := TCriticalSection.Create;
  FRequestCount := 0;
  FLastRequestCount := 0;
  FMaxRequestsPerSecond := 0;
  FStartTime := Now;
  FTestStartTime := 0;
  FTestStartRequestCount := 0;
  FTestInProgress := False;
  
  // Create TncTCPServer (raw socket without any thread pool)
  FServer := TncTCPServer.Create(Self);
  FServer.Port := 8080;
  FServer.EventsUseMainThread := False; // Process in reader thread - no thread pool
  FServer.OnConnected := ServerConnected;
  FServer.OnDisconnected := ServerDisconnected;
  FServer.OnReadData := ServerReadData;
  
  edtPort.Text := '8080';
  
  LogMessage('TncTCPServer Demo - RAW Socket (No Thread Pool)');
  LogMessage('All processing happens directly in reader thread');
  LogMessage('Ready to start server...');
end;

procedure TfrmTCPServer.FormDestroy(Sender: TObject);
begin
  if Assigned(FServer) then
    FServer.Active := False;
  
  FRequestCountLock.Free;
end;

procedure TfrmTCPServer.btnStartStopClick(Sender: TObject);
begin
  if not FServer.Active then
  begin
    // Start server
    FServer.Port := StrToIntDef(edtPort.Text, 8080);
    FServer.Active := True;
    FStartTime := Now;
    FRequestCount := 0;
    FLastRequestCount := 0;
    
    btnStartStop.Caption := 'Stop Server';
    edtPort.Enabled := False;
    tmrStats.Enabled := True;
    
    LogMessage(Format('Server started on port %d', [FServer.Port]));
    LogMessage('Using TncTCPServer - RAW socket processing');
  end
  else
  begin
    // Stop server
    FServer.Active := False;
    
    btnStartStop.Caption := 'Start Server';
    edtPort.Enabled := True;
    tmrStats.Enabled := False;
    
    LogMessage('Server stopped');
  end;
end;

procedure TfrmTCPServer.ServerConnected(Sender: TObject; aLine: TncLine);
begin
  LogMessage(Format('Client connected: %s', [aLine.PeerIP]));
end;

procedure TfrmTCPServer.ServerDisconnected(Sender: TObject; aLine: TncLine);
begin
  LogMessage(Format('Client disconnected: %s', [aLine.PeerIP]));
end;

procedure TfrmTCPServer.ServerReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
var
  Command: string;
begin
  // This runs directly in the reader thread - NO thread pool involved
  try
    Command := TEncoding.UTF8.GetString(aBuf, 0, aBufCount).Trim;
    
    // Process command directly in reader thread (this is the RAW approach)
    ProcessCommandDirectly(aLine, Command);
  except
    on E: Exception do
      LogMessage(Format('Error processing data: %s', [E.Message]));
  end;
end;

procedure TfrmTCPServer.ProcessCommandDirectly(aLine: TncLine; const aCommand: string);
var
  Response: string;
  ThreadID: Cardinal;
begin
  // This runs directly in reader thread - no thread pool queuing
  ThreadID := GetCurrentThreadId;
  IncrementRequestCount;
  
  try
    if aCommand = 'PING' then
    begin
      Response := 'PONG';
    end
    else if aCommand = 'TIME' then
    begin
      Response := FormatDateTime('yyyy-mm-dd hh:nn:ss', Now);
    end
    else if StartsText('ECHO:', aCommand) then
    begin
      Response := Copy(aCommand, 6, Length(aCommand));
    end
    else if StartsText('REVERSE:', aCommand) then
    begin
      Response := ReverseString(Copy(aCommand, 9, Length(aCommand)));
    end
    else if StartsText('HASH:', aCommand) then
    begin
      Response := THashMD5.GetHashString(Copy(aCommand, 6, Length(aCommand)));
    end
    else if aCommand = 'COMPUTE' then
    begin
      // Simulate CPU-intensive work
      Sleep(Random(1000) + 500); // 0.5-1.5 seconds
      Response := Format('COMPUTED[%d]', [ThreadID]);
    end
    else
    begin
      Response := 'UNKNOWN_COMMAND';
    end;

    // Send response
    Response := Response + Format('[T:%d]', [ThreadID]);
    FServer.Send(aLine, TEncoding.UTF8.GetBytes(Response));
    
    // Log approximately 1 in 7 requests to avoid spam
    if (FRequestCount mod 7) = 0 then
      LogMessage(Format('Processed: %s -> %s', [aCommand, Response]));
  except
    on E: Exception do
    begin
      LogMessage(Format('Error processing command "%s": %s', [aCommand, E.Message]));
      try
        FServer.Send(aLine, TEncoding.UTF8.GetBytes('ERROR: ' + E.Message));
      except
        // Ignore send errors
      end;
    end;
  end;
end;

procedure TfrmTCPServer.LogMessage(const aMessage: string);
begin
  if memoLog.Lines.Count > 1000 then
    memoLog.Lines.Delete(0);
  memoLog.Lines.Add(Format('[%s] %s', [FormatDateTime('hh:nn:ss', Now), aMessage]));
end;

procedure TfrmTCPServer.IncrementRequestCount;
begin
  FRequestCountLock.Acquire;
  try
    Inc(FRequestCount);
  finally
    FRequestCountLock.Release;
  end;
end;

procedure TfrmTCPServer.tmrStatsTimer(Sender: TObject);
var
  CurrentRequestCount: Integer;
  RequestsPerSecond: Integer;
begin
  // Get current request count
  FRequestCountLock.Acquire;
  try
    CurrentRequestCount := FRequestCount;
  finally
    FRequestCountLock.Release;
  end;
  
  // Calculate requests per second (same method as thread pool demo)
  RequestsPerSecond := CurrentRequestCount - FLastRequestCount;
  FLastRequestCount := CurrentRequestCount;
  
  // Detect test start (first time we see incoming requests)
  if not FTestInProgress and (RequestsPerSecond > 0) then
  begin
    FTestInProgress := True;
    FTestStartTime := Now;
    FTestStartRequestCount := CurrentRequestCount - RequestsPerSecond;
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
    if tmrStats.Tag = 0 then
      tmrStats.Tag := GetTickCount;
    
    if (GetTickCount - Cardinal(tmrStats.Tag)) >= 2000 then
    begin
      // Test ended - calculate final results
      FTestInProgress := False;
      tmrStats.Tag := 0;
      DisplayFinalTestResults(CurrentRequestCount);
      LogMessage('Test completed - final results calculated');
    end;
  end
  else
  begin
    // Reset the end-test timer if we're still getting requests
    tmrStats.Tag := 0;
  end;
    
  // Get connection count safely with thread-safe locking
  var SocketList := FServer.Lines.LockList;
  try
    lblConnectionsValue.Caption := Format('%d', [SocketList.Count]);
  finally
    FServer.Lines.UnlockList;
  end;
  
  lblRequestsValue.Caption := Format('%d', [CurrentRequestCount]);
  lblRequestsPerSecValue.Caption := Format('%d', [RequestsPerSecond]);
  lblThreadsValue.Caption := '1 (Reader Only)'; // No thread pool - just reader thread
end;

procedure TfrmTCPServer.DisplayFinalTestResults(CurrentRequestCount: Integer);
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

procedure TfrmTCPServer.btnResetStatsClick(Sender: TObject);
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
  tmrStats.Tag := 0;
  
  LogMessage('Test statistics reset');
end;

end. 