unit uMainServer;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes, Vcl.Forms,
  Vcl.ComCtrls, ncSocketsPro, Vcl.Controls, Vcl.Menus, Vcl.Graphics,
  Vcl.Imaging.jpeg, System.Generics.Collections, System.SyncObjs, Vcl.ExtCtrls,
  ncSocketList,Vcl.StdCtrls;

type
  TConnectedUserData = class
  private
    FLine: TncLine;
    FID: string;
    FConnectedAt: TDateTime;
  public
    constructor Create(ALine: TncLine; const AID: string);
    property Line: TncLine read FLine;
    property ID: string read FID;
    property ConnectedAt: TDateTime read FConnectedAt;
  end;

type
  TForm1 = class(TForm)
    StatusBar1: TStatusBar;
    ListView1: TListView;
    ServerSocket: TncTCPProServer;
    PopupMenu1: TPopupMenu;
    S1: TMenuItem;
    S2: TMenuItem;
    G1: TMenuItem;
    Memo1: TMemo;
    S3: TMenuItem;
    Image1: TImage;
    N1: TMenuItem;
    C1: TMenuItem;
    procedure FormCreate(Sender: TObject);
    procedure ServerSocketConnected(Sender: TObject; aLine: TncLine);
    procedure ServerSocketDisconnected(Sender: TObject; aLine: TncLine);
    procedure ServerSocketCommand(Sender: TObject; aLine: TncLine;
      aCmd: Integer; const aData: TBytes);
    procedure ServerSocketReadData(Sender: TObject; aLine: TncLine;
      const aBuf: TBytes; aBufCount: Integer);
    procedure S1Click(Sender: TObject);
    procedure S2Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure DisplayScreenShot(const aData: TBytes);
    procedure G1Click(Sender: TObject);
    procedure S3Click(Sender: TObject);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word;
Shift: TShiftState);
    procedure C1Click(Sender: TObject);
  private
    connectedclients: Integer; // Raw TCP connection count
    // New optimized data structures
    FClientsByLine: TDictionary<TncLine, TConnectedUserData>;
    FClientsByID: TDictionary<string, TConnectedUserData>;
    FCommandParser: TStringList; // Pre-allocated for command parsing
    FClientDataLock: TCriticalSection; // Thread safety for client data

    procedure UpdateClientCount;
    function GetClientCount: Integer;
    function GetAuthenticatedClientCount: Integer;
    function GetClientByID(const AID: string): TConnectedUserData;
    function GetClientByLine(aLine: TncLine): TConnectedUserData;
    procedure AddClientToUI(AUserData: TConnectedUserData);
    procedure RemoveClientFromUI(const ClientID: string);
    procedure SendToAllClients(const AMessage: string);
    procedure SendToSelectedClient(const AMessage: string);
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

{ TConnectedUserData }

constructor TConnectedUserData.Create(ALine: TncLine; const AID: string);
begin
  inherited Create;
  FLine := ALine;
  FID := AID;
  FConnectedAt := Now;
end;

{ TForm1 }

procedure TForm1.AddClientToUI(AUserData: TConnectedUserData);
var
  Item: TListItem;
begin
  TThread.Queue(nil,
    procedure
    begin
      Item := Form1.ListView1.Items.Add;
      Item.Caption := AUserData.Line.PeerIP;  // Column 1: IP Address
      Item.SubItems.Add(AUserData.ID);        // Column 2: NickName/ID
      Item.SubItems.Add('Connected');         // Column 3: Status
      Item.SubItems.Add(FormatDateTime('hh:nn:ss', AUserData.ConnectedAt)); // Column 4: Connected At
      Item.Data := AUserData;
    end);
end;

procedure TForm1.RemoveClientFromUI(const ClientID: string);
var
  I: Integer;
begin
  for I := ListView1.Items.Count - 1 downto 0 do
  begin
    if ListView1.Items[I].SubItems[0] = ClientID then
    begin
      ListView1.Items.Delete(I);
      Break;
    end;
  end;
end;

function TForm1.GetClientByID(const AID: string): TConnectedUserData;
begin
  FClientDataLock.Enter;
  try
    if not FClientsByID.TryGetValue(AID, Result) then
      Result := nil;
  finally
    FClientDataLock.Leave;
  end;
end;

procedure TForm1.SendToAllClients(const AMessage: string);
var
  SocketList: TSocketList;
  I: Integer;
begin
  // Use the optimized built-in broadcast mechanism (same as ncSources)
  SocketList := ServerSocket.Lines.LockList;
  try
    for I := 0 to SocketList.Count - 1 do
    begin
      ServerSocket.SendCommand(SocketList.Lines[I], 0, BytesOf(AMessage));
    end;
  finally
    ServerSocket.Lines.UnlockList;
  end;
end;

procedure TForm1.SendToSelectedClient(const AMessage: string);
var
  NickName: string;
  UserData: TConnectedUserData;
begin
  if Assigned(Form1.ListView1.Selected) then
  begin
    NickName := Form1.ListView1.Selected.SubItems[0];
    UserData := Form1.GetClientByID(NickName);

    if Assigned(UserData) then
    begin
      ServerSocket.SendCommand(UserData.Line, 0, BytesOf(AMessage));
    end;
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  CertPath: string;
begin
  // Initialize raw TCP connection counter
  connectedclients := 0;

  // Initialize optimized data structures
  FClientsByLine := TDictionary<TncLine, TConnectedUserData>.Create;
  FClientsByID := TDictionary<string, TConnectedUserData>.Create;
  FCommandParser := TStringList.Create;
  FCommandParser.Delimiter := '|';
  FCommandParser.StrictDelimiter := True;
  FClientDataLock := TCriticalSection.Create;

  // Configure TLS settings for the server
  ServerSocket.UseTLS := True;
  ServerSocket.TlsProvider := tpSChannel;
  CertPath := ExtractFilePath(Application.ExeName) + 'server.pfx';
  ServerSocket.CertificateFile := CertPath;
  ServerSocket.PrivateKeyPassword := 'test';
  ServerSocket.IgnoreCertificateErrors := True; // Changed to True for demo purposes

  // Start server with dual protocol support
  ServerSocket.Port := 3434;
  ServerSocket.OnCommand := ServerSocketCommand; // Binary protocol handler
  ServerSocket.OnReadData := ServerSocketReadData; // Raw text protocol handler
  ServerSocket.Active := True;
  StatusBar1.Panels[0].Text := 'Status: Active';

  Image1.Picture.Bitmap.SetSize(Image1.Width, Image1.Height);
  Image1.Picture.Bitmap.Canvas.Brush.Color := clBlack;
  Image1.Picture.Bitmap.Canvas.FillRect(Rect(0, 0, Image1.Width, Image1.Height));

end;

procedure TForm1.S1Click(Sender: TObject);
begin
  SendToAllClients('Hello ALL');
end;

procedure TForm1.S2Click(Sender: TObject);
begin
  SendToSelectedClient('MSG to you');
end;

procedure TForm1.S3Click(Sender: TObject);
var
  NickName: string;
  UserData: TConnectedUserData;
begin
  // Send raw text using regular Send method - triggers OnReadData event
  if Assigned(Form1.ListView1.Selected) then
  begin
    NickName := Form1.ListView1.Selected.SubItems[0];
    UserData := Form1.GetClientByID(NickName);

    if Assigned(UserData) then
    begin
      ServerSocket.Send(UserData.Line, 'RAW TEXT MESSAGE from server - This should trigger OnReadData!');
      Log(Format('[%s] Sent raw text to %s', [TimeToStr(Now), NickName]));
    end;
  end;
end;

procedure TForm1.G1Click(Sender: TObject);
begin
  SendToSelectedClient('ScreenShot');
end;

procedure TForm1.C1Click(Sender: TObject);
var
  NickName: string;
  UserData: TConnectedUserData;
begin
  if Assigned(Form1.ListView1.Selected) then
  begin
    NickName := Form1.ListView1.Selected.SubItems[0];
    UserData := Form1.GetClientByID(NickName);

    if Assigned(UserData) then
    begin
      ServerSocket.SendCommand(UserData.Line,0, BytesOf('TITLE|'+ 'THIS IS A NEW TITLE'));
    end;
  end;
end;

procedure TForm1.ServerSocketConnected(Sender: TObject; aLine: TncLine);
begin
  Inc(connectedclients);
  UpdateClientCount;
end;

procedure TForm1.ServerSocketDisconnected(Sender: TObject; aLine: TncLine);
var
  UserData: TConnectedUserData;
  ClientID: string;
begin
  // Decrement raw TCP connection counter
  Dec(connectedclients);

  FClientDataLock.Enter;
  try
    // O(1) lookup by line reference
    if FClientsByLine.TryGetValue(aLine, UserData) then
    begin
      ClientID := UserData.ID;

      // Remove from both dictionaries - O(1) operations
      FClientsByLine.Remove(aLine);
      FClientsByID.Remove(ClientID);

      // Clean up the user data object
      UserData.Free;
    end;
  finally
    FClientDataLock.Leave;
  end;

  // Update UI (outside of lock to avoid deadlock)
  if ClientID <> '' then
  begin
    RemoveClientFromUI(ClientID);
  end;

  UpdateClientCount;
end;

procedure TForm1.ServerSocketCommand(Sender: TObject; aLine: TncLine;
  aCmd: Integer; const aData: TBytes);
var
  datarecieved: String;
  ClientAdded: Boolean;
  CommandName: string;
  UserData: TConnectedUserData;
begin
  // Convert bytes to string - exact same as ncSources!
  datarecieved := StringOf(aData);
  ClientAdded := False;

  // Parse command first (no lock needed for parsing)
  FCommandParser.Clear;
  FCommandParser.DelimitedText := datarecieved;

  if FCommandParser.Count > 0 then
  begin
    CommandName := FCommandParser[0];

    Log(Format('[%s] Parsed command: %s', [TimeToStr(Now), CommandName]));

    // Lock per command for better concurrency
    FClientDataLock.Enter;
    try
////////////////////////////////////////////////////////////////////////////////
/// Handle command NewAuth - EXACT same logic as ncSources
////////////////////////////////////////////////////////////////////////////////
      if CommandName = 'NewAuth' then
      begin
        Log(Format('[%s] Processing NewAuth command', [TimeToStr(Now)]));

        // Check if we have a client ID
        if FCommandParser.Count > 1 then
        begin
          Log(Format('[%s] Client ID: %s', [TimeToStr(Now), FCommandParser[1]]));

          // Check if client ID already exists to prevent duplicates
          if not FClientsByID.ContainsKey(FCommandParser[1]) then
          begin
            UserData := TConnectedUserData.Create(aLine, FCommandParser[1]);

            // Add to both dictionaries for O(1) lookup
            FClientsByLine.Add(aLine, UserData);
            FClientsByID.Add(FCommandParser[1], UserData);
            ClientAdded := True;

            Log(Format('[%s] Client %s authenticated successfully', [TimeToStr(Now), FCommandParser[1]]));
          end
          else
          begin
            Log(Format('[%s] Client %s already exists', [TimeToStr(Now), FCommandParser[1]]));
          end;
        end
        else
        begin
          Log(Format('[%s] NewAuth command missing client ID', [TimeToStr(Now)]));
        end;
      end
////////////////////////////////////////////////////////////////////////////////
/// Handle command ScreenShot (server requesting screenshot)
////////////////////////////////////////////////////////////////////////////////
      else if CommandName = 'ScreenShot' then
      begin

        if FCommandParser.Count > 1 then
        begin

          TThread.Queue(nil,
            procedure
            var
              imageData: TBytes;
            begin
              try
                // Extract image data from command - skip "ScreenShot|" (10 bytes)
                // aData contains: "ScreenShot|" + JPEG binary data
                imageData := Copy(aData, 11, Length(aData));

                Form1.DisplayScreenShot(imageData);

              except
                on E: Exception do
                begin
                  Log(Format('[%s] Error processing screenshot: %s', [TimeToStr(Now), E.Message]));
                end;
              end;
            end);
        end
      end
////////////////////////////////////////////////////////////////////////////////
/// Handle unknown commands
////////////////////////////////////////////////////////////////////////////////
      else
      begin
        TThread.Queue(nil,
          procedure
          begin
            Log(Format('[%s] Unknown command received: %s', [TimeToStr(Now), CommandName]));
          end);
      end;
    finally
      FClientDataLock.Leave;
    end;
  end
  else
  begin
    Log(Format('[%s] Failed to parse command data', [TimeToStr(Now)]));
  end;

  // Update UI outside of lock to prevent deadlock
  if ClientAdded then
  begin
    FClientDataLock.Enter;
    try
      if FCommandParser.Count > 1 then
      begin
        if FClientsByID.TryGetValue(FCommandParser[1], UserData) then
          AddClientToUI(UserData);
      end;
    finally
      FClientDataLock.Leave;
    end;

    // Update status bar after authentication
    UpdateClientCount;
    Log(Format('[%s] UI updated - Auth count: %d', [TimeToStr(Now), GetAuthenticatedClientCount]));
  end;
end;

procedure TForm1.ServerSocketReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer);
var
  dataReceived: String;
  UserData: TConnectedUserData;
begin
  // Convert raw bytes to string
  dataReceived := StringOf(Copy(aBuf, 0, aBufCount));

  // Display received raw text data
  TThread.Queue(nil, procedure
  begin
    Log(Format('[%s] OnReadData fired: %d bytes', [TimeToStr(Now), aBufCount]));
    Log(Format('  Raw data: %s', [dataReceived]));

    // Find the user data for this line to get client info
    UserData := GetClientByLine(aLine);
    if Assigned(UserData) then
    begin
      Log(Format('[%s] Raw text received from %s', [TimeToStr(Now), UserData.ID]));
    end
    else
    begin
      Log(Format('[%s] Raw text received from unknown client', [TimeToStr(Now)]));
    end;
  end);
end;

procedure TForm1.UpdateClientCount;
begin
  FClientDataLock.Enter;
  try
    StatusBar1.Panels[1].Text := Format('Raw: %d | Auth: %d',
      [connectedclients, FClientsByID.Count]);
  finally
    FClientDataLock.Leave;
  end;
end;

function TForm1.GetClientCount: Integer;
begin
  Result := connectedclients;
end;

function TForm1.GetAuthenticatedClientCount: Integer;
begin
  FClientDataLock.Enter;
  try
    Result := FClientsByID.Count;
  finally
    FClientDataLock.Leave;
  end;
end;

function TForm1.GetClientByLine(aLine: TncLine): TConnectedUserData;
begin
  FClientDataLock.Enter;
  try
    if not FClientsByLine.TryGetValue(aLine, Result) then
      Result := nil;
  finally
    FClientDataLock.Leave;
  end;
end;

procedure TForm1.DisplayScreenShot(const aData: TBytes);
var
  MS: TMemoryStream;
  jpgImage: TJPEGImage;
begin
  // Create streams for JPEG loading
  MS := TMemoryStream.Create;
  jpgImage := TJPEGImage.Create;
  try
    // Load JPEG data directly into stream
    MS.WriteBuffer(aData[0], Length(aData));
    MS.Position := 0;

    // Load JPEG from data stream
    jpgImage.LoadFromStream(MS);

    // Display in TImage component
    if Assigned(Form1) and Assigned(Form1.Image1) then
    begin
      Form1.Image1.Picture.Assign(jpgImage);
      Form1.Image1.Stretch := True;
    end;

  finally
    MS.Free;
    jpgImage.Free;
  end;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  if ServerSocket.Active then
    ServerSocket.Active := False;

  FClientDataLock.Enter;
  try
    for var UserData in FClientsByLine.Values do
      UserData.Free;
    FClientsByLine.Free;
    FClientsByID.Free;
  finally
    FClientDataLock.Leave;
  end;

  FCommandParser.Free;
  FClientDataLock.Free;
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
