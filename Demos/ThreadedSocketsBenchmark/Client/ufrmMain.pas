unit ufrmMain;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, System.DateUtils,
  System.Threading, System.SyncObjs, System.Diagnostics, System.Math,
  ncTSockets, ncLines, ncThreads;

type
  TfrmMain = class(TForm)
    Panel1: TPanel;
    btnConnect: TButton;
    edtHost: TEdit;
    edtPort: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Panel2: TPanel;
    memoLog: TMemo;
    Label3: TLabel;
    Panel3: TPanel;
    btnPing: TButton;
    edtEcho: TEdit;
    btnEcho: TButton;
    Label4: TLabel;
    edtReverse: TEdit;
    btnReverse: TButton;
    Label5: TLabel;
    edtHash: TEdit;
    btnHash: TButton;
    Label6: TLabel;
    btnCompute: TButton;
    btnTime: TButton;
    Panel4: TPanel;
    Label7: TLabel;
    lblStatus: TLabel;
    btnClearLog: TButton;
    Panel5: TPanel;
    Label8: TLabel;
    trackConcurrency: TTrackBar;
    lblConcurrency: TLabel;
    btnStressTest: TButton;
    progressStress: TProgressBar;
    lblStressStatus: TLabel;
    btnStopStress: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnConnectClick(Sender: TObject);
    procedure btnPingClick(Sender: TObject);
    procedure btnEchoClick(Sender: TObject);
    procedure btnReverseClick(Sender: TObject);
    procedure btnHashClick(Sender: TObject);
    procedure btnComputeClick(Sender: TObject);
    procedure btnTimeClick(Sender: TObject);
    procedure btnClearLogClick(Sender: TObject);
    procedure trackConcurrencyChange(Sender: TObject);
    procedure btnStressTestClick(Sender: TObject);
    procedure btnStopStressClick(Sender: TObject);
    procedure edtEchoKeyPress(Sender: TObject; var Key: Char);
    procedure edtReverseKeyPress(Sender: TObject; var Key: Char);
    procedure edtHashKeyPress(Sender: TObject; var Key: Char);
  private
    FClient: TncClient;
    FStressTestRunning: Boolean;
    FStressTestTask: ITask;
    FStressTestLock: TCriticalSection;
    FRequestCount: Integer;
    FResponseCount: Integer;
    FErrorCount: Integer;
    
    procedure ClientConnected(Sender: TObject; aLine: TncLine);
    procedure ClientDisconnected(Sender: TObject; aLine: TncLine);
    procedure ClientReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
    procedure LogMessage(const aMessage: string);
    procedure UpdateStatus;
    procedure SendCommand(const aCommand: string);
    procedure UpdateStressTestProgress(aProgress: Integer; const aStatus: string);
    procedure StressTestWorker;
    procedure EnableControls(aEnabled: Boolean);
  public
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  FStressTestRunning := False;
  FStressTestLock := TCriticalSection.Create;
  FRequestCount := 0;
  FResponseCount := 0;
  FErrorCount := 0;
  
  // Create TncClient
  FClient := TncClient.Create(Self);
  FClient.EventsUseMainThread := True;
  FClient.OnConnected := ClientConnected;
  FClient.OnDisconnected := ClientDisconnected;
  FClient.OnReadData := ClientReadData;
  
  // Initialize UI
  edtHost.Text := 'localhost';
  edtPort.Text := '8080';
  trackConcurrency.Position := 5;
  lblConcurrency.Caption := IntToStr(trackConcurrency.Position);
  
  UpdateStatus;
  LogMessage('Client initialized');
  LogMessage('Ready to connect to server...');
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  if FStressTestRunning then
  begin
    FStressTestRunning := False;
    if Assigned(FStressTestTask) then
      FStressTestTask.Wait;
  end;
  
  if Assigned(FClient) then
  begin
    FClient.Active := False;
    FClient.Free;
  end;
  
  FStressTestLock.Free;
end;

procedure TfrmMain.btnConnectClick(Sender: TObject);
begin
  if FClient.Active then
  begin
    // Disconnect
    FClient.Active := False;
    btnConnect.Caption := 'Connect';
    LogMessage('Disconnecting from server...');
  end
  else
  begin
    // Connect
    try
      FClient.Host := edtHost.Text;
      FClient.Port := StrToInt(edtPort.Text);
      FClient.Active := True;
      btnConnect.Caption := 'Disconnect';
      LogMessage('Connecting to ' + edtHost.Text + ':' + edtPort.Text + '...');
    except
      on E: Exception do
      begin
        LogMessage('Error connecting: ' + E.Message);
        ShowMessage('Error connecting: ' + E.Message);
      end;
    end;
  end;
end;

procedure TfrmMain.btnPingClick(Sender: TObject);
begin
  SendCommand('PING');
end;

procedure TfrmMain.btnEchoClick(Sender: TObject);
begin
  if Trim(edtEcho.Text) = '' then
  begin
    ShowMessage('Please enter text to echo');
    edtEcho.SetFocus;
    Exit;
  end;
  SendCommand('ECHO ' + edtEcho.Text);
end;

procedure TfrmMain.btnReverseClick(Sender: TObject);
begin
  if Trim(edtReverse.Text) = '' then
  begin
    ShowMessage('Please enter text to reverse');
    edtReverse.SetFocus;
    Exit;
  end;
  SendCommand('REVERSE ' + edtReverse.Text);
end;

procedure TfrmMain.btnHashClick(Sender: TObject);
begin
  if Trim(edtHash.Text) = '' then
  begin
    ShowMessage('Please enter text to hash');
    edtHash.SetFocus;
    Exit;
  end;
  SendCommand('HASH ' + edtHash.Text);
end;

procedure TfrmMain.btnComputeClick(Sender: TObject);
begin
  SendCommand('COMPUTE');
end;

procedure TfrmMain.btnTimeClick(Sender: TObject);
begin
  SendCommand('TIME');
end;

procedure TfrmMain.btnClearLogClick(Sender: TObject);
begin
  memoLog.Clear;
end;

procedure TfrmMain.trackConcurrencyChange(Sender: TObject);
begin
  lblConcurrency.Caption := IntToStr(trackConcurrency.Position);
end;

procedure TfrmMain.btnStressTestClick(Sender: TObject);
begin
  if not FClient.Active then
  begin
    ShowMessage('Please connect to server first');
    Exit;
  end;
  
  FStressTestRunning := True;
  FRequestCount := 0;
  FResponseCount := 0;
  FErrorCount := 0;
  
  EnableControls(False);
  btnStopStress.Enabled := True;
  progressStress.Position := 0;
  
  // Disable event synchronization for better performance during stress test
  FClient.EventsUseMainThread := False;
  
  LogMessage('Starting stress test with ' + IntToStr(trackConcurrency.Position) + ' concurrent tasks...');
  
  // Start stress test in background task
  FStressTestTask := TTask.Create(StressTestWorker);
  FStressTestTask.Start;
end;

procedure TfrmMain.btnStopStressClick(Sender: TObject);
begin
  FStressTestRunning := False;
  // Restore event synchronization
  FClient.EventsUseMainThread := True;
  LogMessage('Stopping stress test...');
end;

procedure TfrmMain.edtEchoKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then
  begin
    btnEchoClick(nil);
    Key := #0;
  end;
end;

procedure TfrmMain.edtReverseKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then
  begin
    btnReverseClick(nil);
    Key := #0;
  end;
end;

procedure TfrmMain.edtHashKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then
  begin
    btnHashClick(nil);
    Key := #0;
  end;
end;

procedure TfrmMain.ClientConnected(Sender: TObject; aLine: TncLine);
begin
  LogMessage('Connected to server at ' + aLine.PeerIP);
  UpdateStatus;
  EnableControls(True);
end;

procedure TfrmMain.ClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  LogMessage('Disconnected from server');
  UpdateStatus;
  EnableControls(False);
  btnConnect.Caption := 'Connect';
end;

procedure TfrmMain.ClientReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
var
  Response: string;
begin
  Response := TEncoding.UTF8.GetString(aBuf, 0, aBufCount);
  Response := Trim(Response);
  
  if Response <> '' then
  begin
    LogMessage('Response: ' + Response);
    
    // Update stress test counter
    if FStressTestRunning then
    begin
      FStressTestLock.Acquire;
      try
        Inc(FResponseCount);
      finally
        FStressTestLock.Release;
      end;
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

procedure TfrmMain.UpdateStatus;
begin
  if FClient.Active then
  begin
    lblStatus.Caption := 'Connected to ' + FClient.Host + ':' + IntToStr(FClient.Port);
    lblStatus.Font.Color := clGreen;
  end
  else
  begin
    lblStatus.Caption := 'Disconnected';
    lblStatus.Font.Color := clRed;
  end;
end;

procedure TfrmMain.SendCommand(const aCommand: string);
var
  CommandBytes: TBytes;
begin
  if not FClient.Active then
  begin
    ShowMessage('Not connected to server');
    Exit;
  end;
  
  try
    // Only log individual commands when not stress testing to avoid UI blocking
    if not FStressTestRunning then
      LogMessage('Sending: ' + aCommand);
      
    CommandBytes := TEncoding.UTF8.GetBytes(aCommand + #13#10);
    FClient.Send(CommandBytes);
    
    // Update stress test counter
    if FStressTestRunning then
    begin
      FStressTestLock.Acquire;
      try
        Inc(FRequestCount);
      finally
        FStressTestLock.Release;
      end;
    end;
    
  except
    on E: Exception do
    begin
      // Only log individual errors when not stress testing
      if not FStressTestRunning then
        LogMessage('Error sending command: ' + E.Message);
      
      // Update stress test error counter
      if FStressTestRunning then
      begin
        FStressTestLock.Acquire;
        try
          Inc(FErrorCount);
        finally
          FStressTestLock.Release;
        end;
      end;
    end;
  end;
end;

procedure TfrmMain.UpdateStressTestProgress(aProgress: Integer; const aStatus: string);
begin
  TThread.Synchronize(nil, procedure
  begin
    progressStress.Position := aProgress;
    lblStressStatus.Caption := aStatus;
  end);
end;

procedure TfrmMain.StressTestWorker;
var
  i, j: Integer;
  Tasks: array of ITask;
  Commands: array[0..5] of string;
  TotalRequests: Integer;
  StartTime: TStopwatch;
begin
  // Initialize the commands array
  Commands[0] := 'PING';
  Commands[1] := 'ECHO StressTest';
  Commands[2] := 'REVERSE Hello';
  Commands[3] := 'HASH TestData';
  Commands[4] := 'COMPUTE';
  Commands[5] := 'TIME';
  try
    TotalRequests := 100; // Total requests to send
    SetLength(Tasks, trackConcurrency.Position);
    StartTime := TStopwatch.StartNew;
    
    // Create concurrent tasks with shared counter approach
    for i := 0 to trackConcurrency.Position - 1 do
    begin
      Tasks[i] := TTask.Create(procedure
      var
        LocalRequestCount: Integer;
      begin
        LocalRequestCount := 0;
        
        // Keep sending until we reach total or test stops
        while FStressTestRunning and (LocalRequestCount < TotalRequests) do
        begin
          // Check if we should send another request
          FStressTestLock.Acquire;
          try
            if FRequestCount < TotalRequests then
            begin
              Inc(LocalRequestCount);
            end
            else
              Break; // Total reached, exit
          finally
            FStressTestLock.Release;
          end;
          
          // Send random command directly from background thread
          SendCommand(Commands[Random(Length(Commands))]);
          
          // Small delay to prevent overwhelming
          Sleep(50 + Random(100));
        end;
      end);
    end;
    
    // Start all tasks
    for i := 0 to High(Tasks) do
      Tasks[i].Start;
    
    // Monitor progress
    while FStressTestRunning do
    begin
      Sleep(100);
      
      FStressTestLock.Acquire;
      try
        if FRequestCount > 0 then
        begin
          UpdateStressTestProgress(
            Min(100, (FRequestCount * 100) div TotalRequests),
            Format('Requests: %d, Responses: %d, Errors: %d, Time: %ds', 
              [FRequestCount, FResponseCount, FErrorCount, StartTime.ElapsedMilliseconds div 1000])
          );
        end;
        
        // Check if all requests completed
        if FRequestCount >= TotalRequests then
          Break;
      finally
        FStressTestLock.Release;
      end;
    end;
    
    // Wait for all tasks to complete
    for i := 0 to High(Tasks) do
      Tasks[i].Wait;
    
    // Final update
    TThread.Synchronize(nil, procedure
    begin
      // Restore event synchronization
      FClient.EventsUseMainThread := True;
      
      UpdateStressTestProgress(100, 
        Format('Completed! Requests: %d, Responses: %d, Errors: %d, Time: %ds', 
          [FRequestCount, FResponseCount, FErrorCount, StartTime.ElapsedMilliseconds div 1000]));
      
      LogMessage('Stress test completed');
      LogMessage(Format('Total time: %d seconds', [StartTime.ElapsedMilliseconds div 1000]));
      LogMessage(Format('Requests per second: %.2f', [FRequestCount / (StartTime.ElapsedMilliseconds / 1000)]));
      
      EnableControls(True);
      btnStopStress.Enabled := False;
    end);
    
  except
    on E: Exception do
    begin
      TThread.Synchronize(nil, procedure
      begin
        // Restore event synchronization
        FClient.EventsUseMainThread := True;
        LogMessage('Stress test error: ' + E.Message);
        EnableControls(True);
        btnStopStress.Enabled := False;
      end);
    end;
  end;
  
  FStressTestRunning := False;
end;

procedure TfrmMain.EnableControls(aEnabled: Boolean);
begin
  btnPing.Enabled := aEnabled;
  btnEcho.Enabled := aEnabled;
  btnReverse.Enabled := aEnabled;
  btnHash.Enabled := aEnabled;
  btnCompute.Enabled := aEnabled;
  btnTime.Enabled := aEnabled;
  btnStressTest.Enabled := aEnabled;
  edtEcho.Enabled := aEnabled;
  edtReverse.Enabled := aEnabled;
  edtHash.Enabled := aEnabled;
  trackConcurrency.Enabled := aEnabled;
end;

end. 