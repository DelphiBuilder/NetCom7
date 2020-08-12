unit ufrmMain;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  System.SyncObjs, ncSocketList, ncSources, CommonCommands,
  FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo;

type
  TConnectedUserData = class
    Line: TncLine;
    Image: TBitmap;
  end;

  TfrmMain = class(TForm)
    Server: TncServerSource;
    memLog: TMemo;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    function ServerHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
    procedure ServerDisconnected(Sender: TObject; aLine: TncLine);
    procedure ServerConnected(Sender: TObject; aLine: TncLine);
  private
    ConnectedUsersLock: TCriticalSection;
    ConnectedUsers: TStringList;
    procedure InformClientsOfLogins(aDontSendToLine: TncLine = nil);
  public
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.fmx}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  ConnectedUsersLock := TCriticalSection.Create;

  ConnectedUsers := TStringList.Create;
  ConnectedUsers.Sorted := True;
  ConnectedUsers.Duplicates := dupError;
  ConnectedUsers.CaseSensitive := False;

  try
    Server.Active := True;
    memLog.Lines.Add('Server started! Do not close this window');
  except
    on e: Exception do
      memLog.Lines.Add('Cannot start server: ' + e.Message);
  end;
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  Server.Active := False;
  ConnectedUsers.Free;
  ConnectedUsersLock.Free;
end;

procedure TfrmMain.ServerConnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      memLog.Lines.Add(aLine.PeerIP + ' Client connected');
      memLog.ScrollBy(0, 100);
    end);
end;

procedure TfrmMain.ServerDisconnected(Sender: TObject; aLine: TncLine);
var
  i: Integer;
  UserData: TConnectedUserData;
begin
  TThread.Synchronize(nil,
    procedure
    begin
      memLog.Lines.Add(aLine.PeerIP + ' Client disconnected');
      memLog.ScrollBy(0, 100);
    end);

  // Check Connected Users list to delete the entry
  ConnectedUsersLock.Acquire;
  try
    for i := 0 to ConnectedUsers.Count - 1 do
    begin
      UserData := TConnectedUserData(ConnectedUsers.Objects[i]);
      if UserData.Line = aLine then
      begin
        UserData.Image.Free;
        UserData.Free;
        ConnectedUsers.Delete(i);
        Break;
      end;
    end;
  finally
    ConnectedUsersLock.Release;
  end;

  // WARNING: You cannot ExecCommand in this event and in OnConnected
  // with aRequiresResult set to true while you have locked the lines list
  // InformClientsOfLogins does not requre a result from ExecCommand
  InformClientsOfLogins(aLine);
end;

// DontSendTo parameter is used by disconnect, so that we don't send the
// disconnected line the message
procedure TfrmMain.InformClientsOfLogins(aDontSendToLine: TncLine = nil);
var
  SocketList: TSocketList;
  i: Integer;
begin
  // Now inform all clients to update their user lists
  SocketList := Server.Lines.LockList;
  try
    for i := 0 to SocketList.Count - 1 do
      if SocketList.Lines[i] <> aDontSendToLine then
        Server.ExecCommand(SocketList.Lines[i], cmdSrvUpdateLoggedInUsers, BytesOf(ConnectedUsers.CommaText), False);
  finally
    Server.Lines.UnlockList;
  end;
end;

function TfrmMain.ServerHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
var
  UserData: TConnectedUserData;
  i, j: Integer;
  BytesStream: TBytesStream;
  DataToSend: TBytes;
  SocketList: TSocketList;
begin
  case aCmd of
    cmdCntUserLogin:
      begin
        // When the user logs in, he/she sends a name which is held in aData
        ConnectedUsersLock.Acquire;
        try
          // If a username already exists, the ConnectedUsers will raise an exception
          // as it has Duplicates set to dupError
          // This exception will travel back to the client. Since we want a custom
          // message, we trap the exception and change its message
          UserData := TConnectedUserData.Create;
          UserData.Line := aLine;
          UserData.Image := TBitmap.Create;
          try
            ConnectedUsers.AddObject(StringOf(aData), UserData);
          except
            UserData.Image.Free;
            UserData.Free;
            raise Exception.Create('Cannot login with this name, another user has already taken it');
          end;

          // Inform all connected clients of the new data
          InformClientsOfLogins;
        finally
          ConnectedUsersLock.Release;
        end;
      end;
    cmdCntCameraImage:
      begin
        // The client is sending us a video image, update our list
        ConnectedUsersLock.Acquire;
        try
          for i := 0 to ConnectedUsers.Count - 1 do
          begin
            UserData := TConnectedUserData(ConnectedUsers.Objects[i]);
            if UserData.Line = aLine then
            begin
              BytesStream := TBytesStream.Create(aData);
              try
                UserData.Image.LoadFromStream(BytesStream);
              finally
                BytesStream.Free;
              end;

              // Send the image to everyone
              DataToSend := BytesOf(ConnectedUsers.Strings[i]) + BytesOf(#13#10) + aData;
              SocketList := Server.Lines.LockList;
              try
                for j := 0 to SocketList.Count - 1 do
                  Server.ExecCommand(SocketList.Lines[j], cmdSrvUpdateImage, DataToSend, False);
              finally
                Server.Lines.UnlockList;
              end;

              Break;
            end;
          end;

        finally
          ConnectedUsersLock.Release;
        end;
      end;
    cmdCntGetText:
      begin
        // Send the text to all users
        SocketList := Server.Lines.LockList;
        try
          for j := 0 to SocketList.Count - 1 do
            Server.ExecCommand(SocketList.Lines[j], cmdSrvGetText, aData, False);
        finally
          Server.Lines.UnlockList;
        end;
      end;
  end;
end;

end.
