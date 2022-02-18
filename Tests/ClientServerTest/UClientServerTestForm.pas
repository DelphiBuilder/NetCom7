unit UClientServerTestForm;

interface

// Written for Delphi 10.4.2 by Andreas Toth (andreas.toth@xtra.co.nz)

// WARNING: Since, currently, there is no way of differentiating TCP clients
//          from each other, the TCP version of this test is limited to all
//          clients being created and destroyed by a single instance of this
//          code, something that is assumed(!) to be done in LIFO order!

// WARNING: Since UDP clients don't provide a reply server, nor communicate a
//          reply port, there's no way for the server to message clients!

// WARNING: Creating clients (UDP/TCP) without having first created the server
//          will cause synchronisation issues (and possibly AVs) once the
//          server has been created!

// WARNING: Toggling the socket type during a session can result in undefined
//          behaviour!

// WARNING: Data message strings are not escaped so be careful if you intend to
//          base code on this rather basic implementation.

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
    edtSocketTypeTCP: TRadioButton;
    edtSocketTypeUDP: TRadioButton;
    pnlDivider0: TBevel;
    btnToggleServer: TButton;
    pnlDivider1: TBevel;
    edtClientCount: TSpinEdit;
    btnAddClients: TButton;
    btnDeleteClients: TButton;
    btnDeleteAllClients: TButton;
    pnlDivider2: TBevel;
    bntSendToClients: TButton;
    btnSendFromClients: TButton;
    pnlDivider3: TBevel;
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
      TServer = TncCustomSocketServer;

      TServerClient = class
        Connection: TncLine; // TCP
        Host: string; // UDP
        Port: string; // UDP
        ID: Integer;
      end;

      TServerClientList = System.Generics.Collections.TObjectList<TServerClient>;
    private
      FServer: TServer;
      FServerClients: TServerClientList;

      procedure HandleTCPServerOnConnected(Sender: TObject; ALine: TncLine);
      procedure HandleTCPServerOnDisconnected(Sender: TObject; ALine: TncLine);

      procedure SendDataMessageToClient(const AIndex: Integer; const AData: string);

      procedure HandleTCPServerOnReadData(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer);
      procedure HandleUDPServerOnReadData(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer);

      function ServerName: string;
      function ServerSide_ClientName(const AClient: TServerClient): string;
  private // Client
    const
      CClient = 'Client';
    type
      TClient = TncCustomSocketClient;
      TClientList = System.Generics.Collections.TObjectList<TClient>;
    private
      FClients: TClientList;

      procedure SendDataMessageToServer(const AID: Integer; const AData: string);
      procedure HandleClientOnReadData(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer);

      function ClientSide_ClientName(const AType: TSocketType; const AID: Integer): string;
  private // Common
    const
      CNameDelimiter = '-';
      CUnexpectedDataMessageSuffix = ' <<< UNEXPECTED >>>';
      CUDPAddClient = 'AddClient';
      CUDPDeleteClient = 'DeleteClient';
    private
      function CurrentSocketType: TSocketType;

      function FormatTypedName(const AType: TSocketType; const AName: string): string;
      function UnknownClientName(const AType: TSocketType): string;

      function WrapDataMessage(const ABy: string; const AFor: string; const AData: string): AnsiString;
      procedure UnwrapDataMessage(const ADataMessage: AnsiString; out AValid: Boolean; out ABy: string; out AFor: string; out AData: string); overload;
      procedure UnwrapDataMessage(const ABuffer: TBytes; const ACount: Integer; out AValid: Boolean; out ABy: string; out AFor: string; out AData: string); overload;

      function IsValidDataMessageAddressing(const ASource: string; const ADestination: string; const ABy: string; const AFor: string): Boolean;
  private // Log
    procedure Log(const AMessage: string);

    procedure LogCreated(const AName: string);
    procedure LogDestroyed(const AName: string);
    function FormatLogDestroyed(const AName: string): string;

    function FormatLogDataMessage(const ADataMessage: AnsiString): string;

    procedure LogDataSent(const ASource: string; const ADestination: string; const AData: AnsiString);
    procedure LogDataReceived(const ASource: string; const ADestination: string; const ABuffer: TBytes; const ACount: Integer; const ASuffix: string = '');
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

type
  TncLineAccess = class(TncLine);

{ TClientServerTestForm }

constructor TClientServerTestForm.Create(AOwner: TComponent);
begin
  inherited;

  FServer := nil;
  FServerClients := nil;

  FClients := nil;

  case TncLineAccess.DefaultKind of
    stTCP: edtSocketTypeTCP.Checked := True;
    stUDP: edtSocketTypeUDP.Checked := True;
  else
    raise Exception.Create('Unhandled default socket type');
  end;
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

function TClientServerTestForm.FormatLogDataMessage(const ADataMessage: AnsiString): string;
begin
  Result := '(Message = <' + string(ADataMessage) + '>)';
end;

procedure TClientServerTestForm.LogDataSent(const ASource: string; const ADestination: string; const AData: AnsiString);
begin
  Log(ASource + ' sent data to ' + ADestination + ' ' + FormatLogDataMessage(AData));
end;

procedure TClientServerTestForm.LogDataReceived(const ASource: string; const ADestination: string; const ABuffer: TBytes; const ACount: Integer; const ASuffix: string);
begin
  var LValid: Boolean;
  var LBy: string;
  var LFor: string;
  begin
    var LData: string;
    UnwrapDataMessage(ABuffer, ACount, LValid, LBy, LFor, LData);
  end;

  var LSuffix: string := '';

  if not LValid then
  begin
    LSuffix := ' <<< CORRUPT >>>';
  end else
  begin
    LValid := IsValidDataMessageAddressing(ASource, ADestination, LBy, LFor);

    if not LValid then
    begin
      LSuffix := ' <<< INVALID >>>';
    end;
  end;

  LSuffix := LSuffix + ASuffix;

  var LData: AnsiString;
  SetLength(LData, ACount);
  Move(Pointer(ABuffer)^, Pointer(LData)^, ACount);
  Log(ADestination + ' received data from ' + ASource + ' ' + FormatLogDataMessage(LData) + LSuffix);
end;

function TClientServerTestForm.ServerName: string;
begin
  if Assigned(FServer) then
  begin
    Result := FormatTypedName(FServer.Kind, CServer);
  end else
  begin
    Result := FormatTypedName(CurrentSocketType, CServer);
  end;
end;

function TClientServerTestForm.ServerSide_ClientName(const AClient: TServerClient): string;
begin
  if Assigned(AClient) then
  begin
    var LKind: TSocketType;

    if Assigned(AClient.Connection) then
    begin
      LKind := AClient.Connection.Kind;
    end else
    begin
      LKind := stUDP;
    end;

    Result := ClientSide_ClientName(LKind, AClient.ID);
  end else
  begin
    Result := UnknownClientName(CurrentSocketType);
  end;
end;

function TClientServerTestForm.ClientSide_ClientName(const AType: TSocketType; const AID: Integer): string;
begin
  Result := FormatTypedName(AType, CClient + IntToStr(AID));
end;

function TClientServerTestForm.CurrentSocketType: TSocketType;
begin
  if edtSocketTypeTCP.Checked then
  begin
    Result := stTCP;
  end else if edtSocketTypeUDP.Checked then
  begin
    Result := stUDP;
  end else
  begin
    raise Exception.Create('Unhandled socket type');
  end;
end;

function TClientServerTestForm.FormatTypedName(const AType: TSocketType; const AName: string): string;
begin
  Result := CSocketTypeNames[AType] + CNameDelimiter + AName;
end;

function TClientServerTestForm.UnknownClientName(const AType: TSocketType): string;
begin
  Result := FormatTypedName(AType, CClient + '?');
end;

function TClientServerTestForm.WrapDataMessage(const ABy: string; const AFor: string; const AData: string): AnsiString;
begin
  Result := AnsiString('By = ' + ABy + '; For = ' + AFor + '; Data = ' + AData);
end;

procedure TClientServerTestForm.UnwrapDataMessage(const ADataMessage: AnsiString; out AValid: Boolean; out ABy: string; out AFor: string; out AData: string);
const
  CDelimiters = ' ;=';
  CByIndex = 3;
  CForIndex = 8;
  CMessageIndex = 13;
  CUnknownString = '<UNKNOWN>';
  CUnknownInteger = -1;
begin
  var LReferenceDataMessage: AnsiString := WrapDataMessage(ServerName, ClientSide_ClientName(CurrentSocketType, 0), '0'); // NOTE: Dummy names used
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

  if CMessageIndex < LLength then
  begin
    AData := LStrings[CMessageIndex];
  end else
  begin
    AValid := False;
    AFor := CUnknownString;
  end;
end;

procedure TClientServerTestForm.UnwrapDataMessage(const ABuffer: TBytes; const ACount: Integer; out AValid: Boolean; out ABy: string; out AFor: string; out AData: string);
begin
  var LData: AnsiString;
  SetLength(LData, ACount);
  Move(Pointer(ABuffer)^, Pointer(LData)^, ACount);

  UnwrapDataMessage(LData, AValid, ABy, AFor, AData);
end;

function TClientServerTestForm.IsValidDataMessageAddressing(const ASource: string; const ADestination: string; const ABy: string; const AFor: string): Boolean;
begin
  Result := (ABy = ASource) and (AFor = ADestination);
end;

procedure TClientServerTestForm.HandleTCPServerOnConnected(Sender: TObject; ALine: TncLine);
begin
  if not Assigned(FServerClients) then
  begin
    FServerClients := TServerClientList.Create;
    FServerClients.OwnsObjects := True;
  end;

  var LClient := TServerClient.Create;
  LClient.Connection := ALine;
  LClient.ID := FServerClients.Count;

  FServerClients.Add(LClient);

  LogCreated(ServerName + ServerSide_ClientName(LClient));
end;

procedure TClientServerTestForm.HandleTCPServerOnDisconnected(Sender: TObject; ALine: TncLine);
begin
  var LClient: TServerClient := FServerClients[FServerClients.Count - 1];
  var LMessage: string := FormatLogDestroyed(ServerName + ServerSide_ClientName(LClient));

  Assert(LClient.Connection = ALine);
  FServerClients.Delete(FServerClients.Count - 1);

  if FServerClients.Count = 0 then
  begin
    FreeAndNil(FServerClients);
  end;

  Log(LMessage);
end;

procedure TClientServerTestForm.SendDataMessageToClient(const AIndex: Integer; const AData: string);
begin
  var LClient: TServerClient := FServerClients[AIndex];
  var LSource: string := ServerSide_ClientName(LClient);
  var LDestination: string := ServerName;
  var LDataMessage: AnsiString := WrapDataMessage(LSource, LDestination, AData);

  if Assigned(LClient.Connection) then
  begin
    FServer.Send(LClient.Connection, string(LDataMessage));
  end else
  begin
    Exit; // ==> TODO: FServer.Send(LClient.Host, LClient.Port, string(LDataMessage));
  end;

  LogDataSent(LSource, LDestination, LDataMessage);
end;

procedure TClientServerTestForm.HandleTCPServerOnReadData(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer);
begin
  var LSource: string := UnknownClientName(ALine.Kind);
  var LDestination: string := ServerName;

  FServer.Lines.LockList;
  try
    if Assigned(FServerClients) then
    begin
      for var LIndex: Integer := 0 to FServerClients.Count - 1 do
      begin
        var LClient: TServerClient := FServerClients[LIndex];

        if LClient.Connection = ALine then
        begin
          LSource := ServerSide_ClientName(LClient);
          LogDataReceived(LSource, LDestination, ABuffer, ABufferSize);

          Exit; // ==>
        end;
      end;
    end;

    LogDataReceived(LSource, LDestination, ABuffer, ABufferSize, CUnexpectedDataMessageSuffix);
  finally
    FServer.Lines.UnlockList;
  end;
end;

procedure TClientServerTestForm.SendDataMessageToServer(const AID: Integer; const AData: string);
begin
  var LClient := FClients[AID];
  var LSource: string := ClientSide_ClientName(LClient.Line.Kind, AID);
  var LDestination: string := ServerName;
  var LDataMessage: AnsiString := WrapDataMessage(LSource, LDestination, AData);

  LClient.Send(string(LDataMessage));
  LogDataSent(LSource, LDestination, LDataMessage);
end;

procedure TClientServerTestForm.HandleUDPServerOnReadData(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer);
begin
  FServer.Lines.LockList;
  try
    var LSource: string := UnknownClientName(ALine.Kind);;
    var LDestination: string := ServerName;

    var LValid: Boolean;
    var LBy: string;
    var LFor: string;
    var LData: string;
    UnwrapDataMessage(ABuffer, ABufferSize, LValid, LBy, LFor, LData);

    var LClient: TServerClient := nil;

    if Assigned(FServerClients) then
    begin
      for var LIndex: Integer := 0 to FServerClients.Count - 1 do
      begin
        LClient := FServerClients[LIndex];

        if (LClient.Host = ALine.PeerIP) and (LClient.Port = LBy{LPort}) then
        begin
          Break; // ==>
        end;

        LClient := nil;
      end;
    end;

    var LExpected: Boolean := False;
    var LDeleteMessage: string := '';

    if not Assigned(LClient) then
    begin
      if LData = CUDPAddClient then
      begin
        LExpected := True;

        if LValid then
        begin
          if not Assigned(FServerClients) then
          begin
            FServerClients := TServerClientList.Create;
            FServerClients.OwnsObjects := True;
          end;

          LClient := TServerClient.Create;
          LClient.Connection := nil;
          LClient.Host := ALine.PeerIP;
          LClient.Port := LBy{LPort};
          LClient.ID := FServerClients.Count;

          FServerClients.Add(LClient);

          LogCreated(ServerName + ServerSide_ClientName(LClient));

          LSource := ServerSide_ClientName(LClient);
          LValid := LValid and IsValidDataMessageAddressing(LSource, LDestination, LBy, LFor);

          if not LValid then
          begin
            // Error!!!
          end;
        end;
      end;
    end else
    begin
      LSource := ServerSide_ClientName(LClient);
      LValid := LValid and IsValidDataMessageAddressing(LSource, LDestination, LBy, LFor);

      if LData <> CUDPAddClient then
      begin
        LExpected := True;

        if LValid and (LData = CUDPDeleteClient) then
        begin
          LDeleteMessage := FormatLogDestroyed(ServerName + ServerSide_ClientName(LClient));
          FServerClients.Delete(FServerClients.Count - 1);

          if FServerClients.Count = 0 then
          begin
            FreeAndNil(FServerClients);
          end;
        end;
      end;
    end;

    var LSuffix: string := '';;

    if not LExpected then
    begin
      LSuffix := CUnexpectedDataMessageSuffix;
    end;

    LogDataReceived(LSource, LDestination, ABuffer, ABufferSize, LSuffix);

    if LDeleteMessage <> '' then
    begin
      Log(LDeleteMessage);
    end;
  finally
    FServer.Lines.UnlockList;
  end;
end;

procedure TClientServerTestForm.HandleClientOnReadData(Sender: TObject; ALine: TncLine; const ABuffer: TBytes; ABufferSize: Integer);
begin
  var LSource: string := ServerName;
  var LDestination: string := UnknownClientName(ALine.Kind);

  for var LIndex: Integer := 0 to FClients.Count - 1 do
  begin
    var LClient: TClient := FClients[LIndex];

    if LClient = Sender then
    begin
      LDestination := ClientSide_ClientName(LClient.Line.Kind, LIndex);
      LogDataReceived(LDestination, LSource, ABuffer, ABufferSize);

      Exit; // ==>
    end;
  end;

  LogDataReceived(LDestination, LSource, ABuffer, ABufferSize, CUnexpectedDataMessageSuffix);
end;

procedure TClientServerTestForm.btnToggleServerClick(Sender: TObject);

  function SocketTypeToServerClass(const ASocketType: TSocketType): TncCustomSocketServerClass;
  begin
    case ASocketType of
      stTCP: Result := TncTCPServer;
      stUDP: Result := TncUDPServer;
    else
      Result := nil;
    end;
  end;

begin
  if not Assigned(FServer) then
  begin
    FServer := SocketTypeToServerClass(CurrentSocketType).Create(nil);

    case FServer.Kind of
      stTCP:
      begin
        FServer.OnReadData := HandleTCPServerOnReadData;
        FServer.OnConnected := HandleTCPServerOnConnected;
        FServer.OnDisconnected := HandleTCPServerOnDisconnected;
      end;
      stUDP:
      begin
        FServer.OnReadData := HandleUDPServerOnReadData;
      end;
    else
      // Do nothing
    end;

    FServer.EventsUseMainThread := True;
    FServer.Active := True;

    LogCreated(ServerName);
  end else
  begin
    var LName: string := ServerName;

    FreeAndNil(FServer);
    FreeAndNil(FServerClients);

    LogDestroyed(LName);
  end;
end;

procedure TClientServerTestForm.btnAddClientsClick(Sender: TObject);

  function SocketTypeToClientClass(const ASocketType: TSocketType): TncCustomSocketClientClass;
  begin
    case ASocketType of
      stTCP: Result := TncTCPClient;
      stUDP: Result := TncUDPClient;
    else
      Result := nil;
    end;
  end;

begin
  if not Assigned(FClients) then
  begin
    FClients := TClientList.Create;
    FClients.OwnsObjects := True;
  end;

  var LCount: Integer := edtClientCount.Value;
  var LClass: TncCustomSocketClientClass := SocketTypeToClientClass(CurrentSocketType);

  for var LIndex: Integer := 0 to LCount - 1 do
  begin
    var LClient: TncCustomSocketClient := LClass.Create(nil);
    LClient.OnReadData := HandleClientOnReadData;
    LClient.EventsUseMainThread := True;
    FClients.Add(LClient);
    LClient.Active := True;

    var LID: Integer := FClients.Count - 1;
    LogCreated(ClientSide_ClientName(LClient.Line.Kind, LID));

    if not LClient.IsConnectionBased then
    begin
      SendDataMessageToServer(LID, CUDPAddClient);
    end;
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
    var LID: Integer := FClients.Count - 1;
    var LClient := FClients[LID];

    var LMessage: string := FormatLogDestroyed(ClientSide_ClientName(LClient.Kind, LID));

    if not LClient.IsConnectionBased then
    begin
      SendDataMessageToServer(LID, CUDPDeleteClient);
    end;

    FClients.Delete(LID);

    if FClients.Count = 0 then
    begin
      FreeAndNil(FClients);
    end;

    Log(LMessage);

    if not Assigned(FClients) then
    begin
      Exit; // ==>
    end;
  end;
end;

procedure TClientServerTestForm.bntSendToClientsClick(Sender: TObject);
begin
  if not Assigned(FServer) then
  begin
    Exit; // ==>
  end;

  FServer.Lines.LockList;
  try
    if Assigned(FServerClients) then
    begin
      for var LIndex: Integer := 0 to FServerClients.Count - 1 do
      begin
        SendDataMessageToClient(LIndex, IntToStr(LIndex));
      end;
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
    SendDataMessageToServer(LIndex, IntToStr(LIndex));
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
