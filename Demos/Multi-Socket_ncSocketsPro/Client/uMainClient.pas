unit uMainClient;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,System.Threading,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.Imaging.jpeg, ncSocketsPro,
  Vcl.ExtCtrls, System.SyncObjs, ncLines;

type
  TForm1 = class(TForm)
    ClientSocket: TncTCPProClient;
    Memo1: TMemo;
    Timer1: TTimer;
    procedure ClientSocketConnected(Sender: TObject; aLine: TncLine);
    procedure ClientSocketCommand(Sender: TObject; aLine: TncLine;
      aCmd: Integer; const aData: TBytes);
    procedure ClientSocketReadData(Sender: TObject; aLine: TncLine;
      const aBuf: TBytes; aBufCount: Integer);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure ClientSocketDisconnected(Sender: TObject; aLine: TncLine);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word;
    Shift: TShiftState);

  private
    FConnecting: Boolean;
    FCommandParser: TStringList; // Pre-allocated for command parsing
    FCommandLock: TCriticalSection; // Thread safety for command processing
    procedure ConnectToServer;
    procedure StartReconnectTimer;
    procedure StopReconnectTimer;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function CaptureScreenshot: TBytes;
var
  DC: HDC; // Device context for screen
  ScreenBMP: TBitmap; // Bitmap for screen capture
  jpgImage: TJPEGImage; // JPEG for compression
  MS: TMemoryStream; // Memory stream for processing
begin
  Result := nil;

  // Create required objects for screen capture
  ScreenBMP := TBitmap.Create;
  jpgImage := TJPEGImage.Create;
  MS := TMemoryStream.Create;
  try
    // Set bitmap dimensions to match screen resolution
    ScreenBMP.Width := Screen.Width;
    ScreenBMP.Height := Screen.Height;

    // Get device context for the entire screen (0 = desktop window)
    DC := GetDC(0);
    try
      // Copy screen pixels to bitmap using BitBlt
      // SRCCOPY = direct copy of source pixels
      BitBlt(ScreenBMP.Canvas.Handle, 0, 0, Screen.Width,
        Screen.Height, DC, 0, 0, SRCCOPY);
    finally
      // Always release the device context
      ReleaseDC(0, DC);
    end;

    // Convert to JPEG with 30% quality (already compressed)
    jpgImage.Assign(ScreenBMP);
    jpgImage.CompressionQuality := 30;
    jpgImage.SaveToStream(MS);

    // Return JPEG data directly (no additional compression needed)
    MS.Position := 0;
    SetLength(Result, MS.Size);
    if MS.Size > 0 then
      MS.ReadBuffer(Result[0], MS.Size);

  finally
    // Clean up resources
    ScreenBMP.Free;
    jpgImage.Free;
    MS.Free;
  end;
end;

procedure TForm1.ConnectToServer;
begin
  if FConnecting then
    Exit;

  FConnecting := True;
  StopReconnectTimer;

  if ClientSocket.Active then
    ClientSocket.Active := False;

  // Set connection parameters on main thread (these are just property assignments)
  ClientSocket.Host := '192.168.10.30';
  ClientSocket.Port := 3434;

  // Move the blocking call to background thread
  TTask.Run(procedure
  begin
    try
      ClientSocket.Active := True; // Now runs in background thread
    except
      on E: Exception do
      begin
        // Marshal back to main thread for UI updates
        TThread.Queue(nil, procedure
        begin
          FConnecting := False;
          Log('Connection failed: ' + E.Message);
          StartReconnectTimer;
        end);
      end;
    end;
  end);
end;

procedure TForm1.StartReconnectTimer;
begin
  if not Timer1.Enabled then
  begin
    Timer1.Interval := 3000;
    Timer1.Enabled := True;
  end;
end;

procedure TForm1.StopReconnectTimer;
begin
  Timer1.Enabled := False;
end;

procedure TForm1.Timer1Timer(Sender: TObject);
begin
  Timer1.Enabled := False;
  Log('Retrying connection...');
  ConnectToServer;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin

  // Configure TLS settings for the client
  ClientSocket.UseTLS := True;
  ClientSocket.TlsProvider := tpSChannel;
  ClientSocket.IgnoreCertificateErrors := True;

  // Initialize command parsing structures
  FCommandParser := TStringList.Create;
  FCommandParser.Delimiter := '|';
  FCommandParser.StrictDelimiter := True;
  FCommandLock := TCriticalSection.Create;

  // Set up events for dual protocol support
  ClientSocket.OnCommand := ClientSocketCommand; // Binary protocol handler
  ClientSocket.OnReadData := ClientSocketReadData; // Raw text protocol handler

  Log('Client starting......');

  ConnectToServer;

end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  StopReconnectTimer;
  if ClientSocket.Active then
    ClientSocket.Active := False;

  // Clean up command parsing structures (same pattern as server)
  if Assigned(FCommandParser) then
    FCommandParser.Free;

  if Assigned(FCommandLock) then
    FCommandLock.Free;
end;

procedure TForm1.ClientSocketConnected(Sender: TObject; aLine: TncLine);
var
 FClientName: String;
begin
  FConnecting := False;
  StopReconnectTimer;

  FClientName := 'Client' + IntToStr(GetTickCount);

  Log('Connected to server as: ' + FClientName);

  //send over nickname info and authentication command...
  self.ClientSocket.SendCommand(0,bytesof('NewAuth|' + FClientName));
end;

procedure TForm1.ClientSocketDisconnected(Sender: TObject; aLine: TncLine);
begin
  FConnecting := False;

  Log('Disconnected from server');

  // Only start auto-reconnection if we're not already trying to connect
  // This prevents rapid connect/disconnect cycles when server shuts down
  if not Timer1.Enabled then
    StartReconnectTimer;
end;

procedure TForm1.ClientSocketCommand(Sender: TObject; aLine: TncLine;
  aCmd: Integer; const aData: TBytes);
var
  dataReceived: String;
  CommandName: string;
begin
  // Convert bytes to string
  dataReceived := StringOf(aData);

  // Parse command first (no lock needed for parsing) - EXACT same logic as ncSources
  FCommandParser.Clear;
  FCommandParser.DelimitedText := dataReceived;

  if FCommandParser.Count > 0 then
  begin
    CommandName := FCommandParser[0];

    // Lock per command for better concurrency
    FCommandLock.Enter;
    try
////////////////////////////////////////////////////////////////////////////////
/// Handle command ScreenShot (server requesting screenshot)
////////////////////////////////////////////////////////////////////////////////
      if CommandName = 'ScreenShot' then
      begin
        TThread.Queue(nil,
          procedure
          var
            ScreenshotData: TBytes;
          begin
            // Capture screenshot
            ScreenshotData := CaptureScreenshot;

            try

              ClientSocket.SendCommand(0, BytesOf('ScreenShot|') + ScreenshotData);

            except
              on E: Exception do
                Log('Error sending screenshot: ' + E.Message);
            end;
          end);
      end
////////////////////////////////////////////////////////////////////////////////
/// Handle command TITLE (server setting window title)
////////////////////////////////////////////////////////////////////////////////
      else if CommandName = 'TITLE' then
      begin
        if FCommandParser.Count > 1 then
        begin
          TThread.Queue(nil,
            procedure
            begin
              Self.Caption := FCommandParser[1];
            end);
        end;
      end
////////////////////////////////////////////////////////////////////////////////
/// Handle unknown commands
////////////////////////////////////////////////////////////////////////////////
      else
      begin
        TThread.Queue(nil,
          procedure
          begin
            Log('Unknown command: ' + CommandName);
          end);
      end;
    finally
      FCommandLock.Leave;
    end;
  end
  else
  begin
    // Handle non-command data (direct message) - lock for consistency
    FCommandLock.Enter;
    try
      TThread.Queue(nil,
        procedure
        begin
          Log('Server: ' + dataReceived);
        end);
    finally
      FCommandLock.Leave;
    end;
  end;
end;

procedure TForm1.ClientSocketReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  dataReceived: String;
begin
  // Convert raw bytes to string
  dataReceived := StringOf(Copy(aBuf, 0, aBufCount));

  // Display received raw text data
  TThread.Queue(nil, procedure
  begin

    Log(Format('[%s] OnReadData fired: %d bytes', [TimeToStr(Now), aBufCount]));
    Log(Format('[%s] Raw text from server: %s', [TimeToStr(Now), dataReceived]));


    // Send response back to server
    try
      ClientSocket.Send(Format('CLIENT_RESPONSE: %s', [dataReceived]));
      Log(Format('[%s] Sent response back to server', [TimeToStr(Now)]));
    except
      on E: Exception do
        Log(Format('[%s] Error sending response: %s', [TimeToStr(Now), E.Message]));
    end;
  end);
end;

// *****************************************************************************
// Memo Log
// *****************************************************************************
procedure TForm1.Log(const AMessage: string);
begin
  TThread.Queue(nil,
    procedure
    begin
      try
        Memo1.Lines.Add(Format('[%s] %s', [FormatDateTime('hh:nn:ss.zzz', Now),
          AMessage]));
      finally
      end;
    end);
end;

procedure TForm1.memLogKeyDown(Sender: TObject; var Key: Word;
Shift: TShiftState);
begin
  if (Shift = [ssCtrl]) and (Key = Ord('A')) then
    Memo1.SelectAll
  else if (Shift = [ssCtrl]) and (Key = Ord('C')) then
    Memo1.CopyToClipboard;
end;

end.


