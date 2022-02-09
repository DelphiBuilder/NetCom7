unit UClientServerTestForm;

interface

// Written for Delphi 10.4.2 by Andreas Toth (andreas.toth@xtra.co.nz)

// WARNING: This test relies on the fact that all clients are created and
//          destroyed as LIFO by a single instance of this code!

// WARNING: Creating clients without the server will cause synchronisation
//          issues (and possibly AVs) once the server has been created!

uses
  Vcl.Forms,
  Vcl.Controls,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.Samples.Spin,
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  ncSockets,
  ncLines;

type
  TClientServerTestForm = class(TForm)
    btnToggleServer: TButton;
    pnlDivider0: TBevel;
    edtClientCount: TSpinEdit;
    btnAddClients: TButton;
    btnDeleteClients: TButton;
    btnDeleteAllClients: TButton;
    pnlDivider1: TBevel;
    bntSendToClients: TButton;
    btnSendFromClients: TButton;
    pnlDivider2: TBevel;
    btnReset: TButton;
    edtLog: TMemo;

    procedure btnToggleServerClick(Sender: TObject);
    procedure btnAddClientsClick(Sender: TObject);
    procedure btnDeleteClientsClick(Sender: TObject);
    procedure bntSendToClientsClick(Sender: TObject);
    procedure btnSendFromClientsClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
  private // Server
    const
      CServer = 'Server';
    type
      TServer = TncTCPServer;

      TServerClient = class
        Line: TncLine;
        ID: Integer;
      end;

      TServerClientList = System.Generics.Collections.TObjectList<TServerClient>;
    private
      FServer: TServer;
      FServerClients: TServerClientList;

      procedure HandleServerOnConnected(Sender: TObject; aLine: TncLine);
      procedure HandleServerOnDisconnected(Sender: TObject; aLine: TncLine);

      procedure HandleServerOnReadData(Sender: TObject; ALine: TncLine; const ABuff: TBytes; ABuffCount: Integer);

      function ServerSide_ClientName(const ALine: TncLine): string;
  private // Client
    const
      CClient = 'Client';
    type
      TClient = TncTCPClient;
      TClientList = System.Generics.Collections.TObjectList<TClient>;
    private
      FClients: TClientList;

      procedure HandleClientOnReadData(Sender: TObject; ALine: TncLine; const ABuff: TBytes; ABuffCount: Integer);

      function ClientSide_ClientName(const AID: Integer): string;
  private // Common
      function UnknownClientName: string;

      function WrapDataMessage(const ABy: string; const AFor: string; const AIndex: Integer): AnsiString;
      procedure UnwrapDataMessage(const ADataMessage: AnsiString; out AValid: Boolean; out ABy: string; out AFor: string; out AIndex: Integer);
  private // Log
    procedure Log(const AMessage: string);

    procedure LogCreated(const AName: string);
    procedure LogDestroyed(const AName: string);
    function FormatLogDestroyed(const AName: string): string;

    function FormatLogData(const AData: AnsiString): string;

    procedure LogDataSent(const ASource: string; const ADestination: string; const AData: AnsiString);
    procedure LogDataReceived(const ASource: string; const ADestination: string; const ABuffer: TBytes; const ACount: Integer);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

implementation

{$R *.dfm}

uses
  System.Types,
  System.StrUtils,
  System.Diagnostics,
  Winapi.Windows,
  Winapi.WinSock2,
  ncSocketList;

{ TClientServerTestForm }

constructor TClientServerTestForm.Create(AOwner: TComponent);
begin
  inherited;

  FServer := nil;
  FServerClients := nil;

  FClients := nil;
end;

destructor TClientServerTestForm.Destroy;
begin
  FreeAndNil(FClients);

  FreeAndNil(FServerClients);
  FreeAndNil(FServer);

  inherited;
end;

procedure TClientServerTestForm.Log(const AMessage: string);
begin
  edtLog.Lines.Add(AMessage);
end;

procedure TClientServerTestForm.LogCreated(const AName: string);
begin
  Log(AName + ' created');
end;

procedure TClientServerTestForm.LogDestroyed(const AName: string);
begin
  Log(FormatLogDestroyed(AName));
end;

function TClientServerTestForm.FormatLogDestroyed(const AName: string): string;
begin
  Result := AName + ' destroyed';
end;

function TClientServerTestForm.FormatLogData(const AData: AnsiString): string;
begin
  Result := '(Data = <' + string(AData) + '>)';
end;

procedure TClientServerTestForm.LogDataSent(const ASource: string; const ADestination: string; const AData: AnsiString);
begin
  Log(ASource + ' sent data to ' + ADestination + ' ' + FormatLogData(AData));
end;

procedure TClientServerTestForm.LogDataReceived(const ASource: string; const ADestination: string; const ABuffer: TBytes; const ACount: Integer);
begin
  var LData: AnsiString;
  SetLength(LData, ACount);
  Move(Pointer(ABuffer)^, Pointer(LData)^, ACount);

  var LMessage: string := ADestination + ' received data from ' + ASource + ' ' + FormatLogData(LData);

  var LValid: Boolean;
  var LBy: string;
  var LFor: string;
  var LIndex: Integer;

  UnwrapDataMessage(LData, LValid, LBy, LFor, LIndex);

  if not LValid then
  begin
    LMessage := LMessage + ' <<< CORRUPT >>>';
  end else
  begin
    LValid := (LBy = ASource) and (LFor = ADestination);

    if not LValid then
    begin
      LMessage := LMessage + ' <<< INVALID >>>';
    end;
  end;

  Log(LMessage);
end;

function TClientServerTestForm.ServerSide_ClientName(const ALine: TncLine): string;
begin
  for var LIndex: Integer := 0 to FServerClients.Count - 1 do
  begin
    var LClient: TServerClient := FServerClients[LIndex];

    if LClient.Line = ALine then
    begin
      Result := ClientSide_ClientName(LClient.ID);
      Exit; // ==>
    end;
  end;

  Result := UnknownClientName;
end;

function TClientServerTestForm.ClientSide_ClientName(const AID: Integer): string;
begin
  Result := CClient + IntToStr(AID);
end;

function TClientServerTestForm.UnknownClientName: string;
begin
  Result := CClient + '?';
end;

function TClientServerTestForm.WrapDataMessage(const ABy: string; const AFor: string; const AIndex: Integer): AnsiString;
begin
  Result := AnsiString('By = ' + ABy + '; For = ' + AFor + '; Message = ' + IntToStr(AIndex));
end;

procedure TClientServerTestForm.UnwrapDataMessage(const ADataMessage: AnsiString; out AValid: Boolean; out ABy: string; out AFor: string; out AIndex: Integer);
const
  CDelimiters = ' ;=';
  CByIndex = 3;
  CForIndex = 8;
  CMessageIndex = 13;
  CUnknownString = '<UNKNOWN>';
  CUnknownInteger = -1;
begin
  var LReferenceDataMessage: AnsiString := WrapDataMessage(CServer, ClientSide_ClientName(0), 0);
  var LReferenceStrings: TStringDynArray := SplitString(string(LReferenceDataMessage), CDelimiters);
  var LReferenceLength: Integer := Length(LReferenceStrings);

  var LStrings: TStringDynArray := SplitString(string(ADataMessage), CDelimiters);
  var LLength: Integer := Length(LStrings);

  AValid := LLength = LReferenceLength;

  if CByIndex < LLength then
  begin
    ABy := LStrings[CByIndex];
  end else
  begin
    AValid := False;
    ABy := CUnknownString;
  end;

  if CForIndex < LLength then
  begin
    AFor := LStrings[CForIndex];
  end else
  begin
    AValid := False;
    AFor := CUnknownString;
  end;

  if (CMessageIndex >= LLength) or (not TryStrToInt(LStrings[CMessageIndex], AIndex)) then
  begin
    AValid := False;
    AIndex := CUnknownInteger;
  end;
end;

procedure TClientServerTestForm.HandleServerOnConnected(Sender: TObject; aLine: TncLine);
begin
  if not Assigned(FServerClients) then
  begin
    FServerClients := TServerClientList.Create;
    FServerClients.OwnsObjects := True;
  end;

  var LClient := TServerClient.Create;
  LClient.Line := aLine;
  LClient.ID := FServerClients.Count;

  FServerClients.Add(LClient);

  LogCreated(CServer + ClientSide_ClientName(LClient.ID));
end;

procedure TClientServerTestForm.HandleServerOnDisconnected(Sender: TObject; aLine: TncLine);
begin
  var LClient: TServerClient := FServerClients[FServerClients.Count - 1];
  var LMessage: string := FormatLogDestroyed(CServer + ClientSide_ClientName(LClient.ID));

  Assert(LClient.Line = aLine);
  FServerClients.Delete(FServerClients.Count - 1);

  if FServerClients.Count = 0 then
  begin
    FreeAndNil(FServerClients);
  end;

  Log(LMessage);
end;

procedure TClientServerTestForm.HandleServerOnReadData(Sender: TObject; ALine: TncLine; const ABuff: TBytes; ABuffCount: Integer);
begin
  var LSource: string := CServer;
  var LDestination: string := UnknownClientName;

  var LSockets: TSocketList := FServer.Lines.LockList;
  try
    for var LIndex: Integer := 0 to LSockets.Count - 1 do
    begin
      if LSockets.Lines[LIndex] = ALine then
      begin
        LDestination := ServerSide_ClientName(ALine);
        LogDataReceived(LDestination, LSource, ABuff, ABuffCount);

        Exit; // ==>
      end;
    end;

    LogDataReceived(LDestination, LSource, ABuff, ABuffCount); // Should never happen!!!
  finally
    FServer.Lines.UnlockList;
  end;
end;

procedure TClientServerTestForm.HandleClientOnReadData(Sender: TObject; ALine: TncLine; const ABuff: TBytes; ABuffCount: Integer);
begin
  var LSource: string := UnknownClientName;
  var LDestination: string := CServer;

  for var LIndex: Integer := 0 to FClients.Count - 1 do
  begin
    var LClient: TClient := FClients[LIndex];

    if LClient = Sender then
    begin
      LSource := ClientSide_ClientName(LIndex);
      LogDataReceived(LDestination, LSource, ABuff, ABuffCount);

      Exit; // ==>
    end;
  end;

  LogDataReceived(LDestination, LSource, ABuff, ABuffCount); // Should never happen!!!
end;

procedure TClientServerTestForm.btnToggleServerClick(Sender: TObject);
begin
  if not Assigned(FServer) then
  begin
    FServer := TncTCPServer.Create(nil);
    FServer.OnReadData := HandleServerOnReadData;
    FServer.OnConnected := HandleServerOnConnected;
    FServer.OnDisconnected := HandleServerOnDisconnected;
    FServer.Active := True;

    LogCreated(CServer);
  end else
  begin
    FreeAndNil(FServer);
    FreeAndNil(FServerClients);

    LogDestroyed(CServer);
  end;
end;

procedure TClientServerTestForm.btnAddClientsClick(Sender: TObject);
begin
  if not Assigned(FClients) then
  begin
    FClients := TClientList.Create;
    FClients.OwnsObjects := True;
  end;

  var LCount: Integer := edtClientCount.Value;

  for var LIndex: Integer := 0 to LCount - 1 do
  begin
    var LClient: TClient := TClient.Create(nil);
    LClient.OnReadData := HandleClientOnReadData;
    FClients.Add(LClient);
    LClient.Active := True;

    LogCreated(ClientSide_ClientName(FClients.Count - 1));
  end;
end;

procedure TClientServerTestForm.btnDeleteClientsClick(Sender: TObject);
begin
  if not Assigned(FClients) then
  begin
    Exit; // ==>
  end;

  var LCount: Integer;

  if Sender = btnDeleteClients then
  begin
    LCount := edtClientCount.Value;
  end else
  begin
    Assert(Sender = btnDeleteAllClients);
    LCount := FClients.Count;
  end;

  for var LIndex: Integer := 0 to LCount - 1 do
  begin
    var LMessage: string := FormatLogDestroyed(ClientSide_ClientName(FClients.Count - 1));

    Assert(FClients.Count > 0);
    FClients.Delete(FClients.Count - 1);

    if FClients.Count = 0 then
    begin
      FreeAndNil(FClients);
    end;

    Log(LMessage);
  end;
end;

procedure TClientServerTestForm.bntSendToClientsClick(Sender: TObject);
begin
  if not Assigned(FServer) then
  begin
    Exit; // ==>
  end;

  var LSockets: TSocketList := FServer.Lines.LockList;
  try
    for var LIndex: Integer := 0 to LSockets.Count - 1 do
    begin
      var LClient: TncLine := LSockets.Lines[LIndex] as TncLine;
      var LSource: string := CServer;
      var LDestination: string := ServerSide_ClientName(LClient);
      var LData: AnsiString := WrapDataMessage(LSource, LDestination, LIndex);

      FServer.Send(LClient, string(LData));
      LogDataSent(LSource, LDestination, LData);
    end;
  finally
    FServer.Lines.UnlockList;
  end;
end;

procedure TClientServerTestForm.btnSendFromClientsClick(Sender: TObject);
begin
  if not Assigned(FClients) then
  begin
    Exit; // ==>
  end;

  for var LIndex: Integer := 0 to FClients.Count - 1 do
  begin
    var LClient: TClient := FClients[LIndex];
    var LSource: string := ClientSide_ClientName(LIndex);
    var LDestination: string := CServer;
    var LData: AnsiString := WrapDataMessage(LSource, LDestination, LIndex);

    LClient.Send(string(LData));
    LogDataSent(LSource, LDestination, LData);
  end;
end;

procedure TClientServerTestForm.btnResetClick(Sender: TObject);
begin
  FreeAndNil(FClients);

  FreeAndNil(FServerClients);
  FreeAndNil(FServer);

  Log('Reset');
end;

end.
