unit ufrmMain;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.ListView.Types, FMX.ListView.Appearances, FMX.ListView.Adapters.Base,
  FMX.Layouts, ncSources, FMX.Edit, FMX.StdCtrls, FMX.ListView,
  FMX.Controls.Presentation, FMX.Objects, FMX.ScrollBox, FMX.Memo, FMX.MultiView,
  FMX.ListBox, CommonCommands, FMX.Media;

type
  TfrmMain = class(TForm)
    ToolBar: TToolBar;
    btnConnect: TButton;
    edtUsername: TEdit;
    ltContent: TLayout;
    Client: TncClientSource;
    ltCameras: TGridPanelLayout;
    ltSendText: TLayout;
    imgUserVideo: TImage;
    imgPeerUserVideo: TImage;
    edtTextToSend: TEdit;
    btnSendText: TButton;
    ltMessages: TLayout;
    memMessages: TMemo;
    Splitter: TSplitter;
    btnMasterView: TButton;
    MultiView: TMultiView;
    lbUsers: TListBox;
    CameraComponent: TCameraComponent;
    procedure edtUsernameEnter(Sender: TObject);
    procedure edtUsernameExit(Sender: TObject);
    procedure edtTextToSendEnter(Sender: TObject);
    procedure edtTextToSendExit(Sender: TObject);
    procedure btnConnectClick(Sender: TObject);
    procedure ClientConnected(Sender: TObject; aLine: TncLine);
    procedure ClientDisconnected(Sender: TObject; aLine: TncLine);
    function ClientHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
    procedure btnSendTextClick(Sender: TObject);
    procedure CameraComponentSampleBufferReady(Sender: TObject; const ATime: TMediaTime);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormPaint(Sender: TObject; Canvas: TCanvas; const ARect: TRectF);
  private
    ConnectErrorMsg: string;
  public
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.fmx}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  //
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  Client.Active := False;
end;

procedure TfrmMain.FormPaint(Sender: TObject; Canvas: TCanvas;
  const ARect: TRectF);
begin
  // We set the camera on when the form has fully loaded, as in some phones,
  // we may not get the permission to use the camera. In such a case, if we
  // had enabled the camera at creation time, the application would terminate...
  OnPaint := nil;
  CameraComponent.Active := True;
end;

procedure TfrmMain.ClientConnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      btnConnect.Text := 'Disconnect';
      if edtUsername.Text = '' then
        edtUsername.Text := 'Anonymous'; // Although Eponymous
      edtUsername.Enabled := False;
    end);

  try
    Client.ExecCommand(cmdCntUserLogin, BytesOf(edtUsername.Text), True);
  except
    on e: exception do
    begin
      // We do not want to show exceptions here, as this might be a reconnect
      // attempt, we will show the exception only when the user presses the button
      // in btnConnectClick
      ConnectErrorMsg := e.Message;
      Client.Active := False;
    end;
  end;
end;

procedure TfrmMain.ClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      btnConnect.Text := 'Connect';
      edtUsername.Enabled := True;
      lbUsers.Clear;
    end);
end;

procedure TfrmMain.btnConnectClick(Sender: TObject);
begin
  if Client.Active then
  begin
    Client.Active := False;
  end
  else
  begin
    Client.Active := True;
    if not Client.Active then
      raise Exception.Create(ConnectErrorMsg);
  end;
end;

function TfrmMain.ClientHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
begin
  SetLength(Result, 0);

  TThread.Synchronize(nil,

    procedure
    var
      i: Integer;
      Username: string;
      BytesStream: TBytesStream;
      lbIndex: Integer;
      PrevUser: string;
    begin
      // This is called from the server to update information
      case aCmd of
        cmdSrvUpdateLoggedInUsers:
          begin
            // Save the user we are on
            lbUsers.BeginUpdate;
            try
              if lbUsers.ItemIndex <> -1 then
                PrevUser := lbUsers.Items.Strings[lbUsers.ItemIndex]
              else
                PrevUser := '';

              lbUsers.Items.CommaText := StringOf(aData);

              if PrevUser <> '' then
                lbUsers.ItemIndex := lbUsers.Items.IndexOf(PrevUser);
            finally
              lbUsers.EndUpdate;
            end;
          end;
        cmdSrvUpdateImage:
          begin
            // Extract the #13#10 from the aData
            for i := 0 to High(aData) - 1 do
              if (aData[i] = 13) and (aData[i + 1] = 10) then
              begin
                Username := StringOf(Copy(aData, 0, i));

                BytesStream := TBytesStream.Create(Copy(aData, i + 2));
                try
                  lbIndex := lbUsers.Items.IndexOf(Username);
                  lbUsers.ItemByIndex(lbIndex).ItemData.Bitmap.LoadFromStream(BytesStream);
                  lbUsers.ItemByIndex(lbIndex).StyleLookup := 'listboxitemleftdetail';

                  if lbUsers.ItemIndex = lbIndex then
                    imgPeerUserVideo.Bitmap.LoadFromStream(BytesStream);
                finally
                  BytesStream.Free;
                end;

                Break;
              end;
          end;
        cmdSrvGetText:
          begin
            memMessages.Lines.Add(StringOf(aData));
            memMessages.ScrollBy(0, 100);
          end;
      end;
    end);
end;

procedure TfrmMain.CameraComponentSampleBufferReady(Sender: TObject; const ATime: TMediaTime);
var
  BytesStream: TBytesStream;
begin
  // We got a new image from the camera
  // Assign it first to our own imgUserVideo component
  CameraComponent.SampleBufferToBitmap(imgUserVideo.Bitmap, True);

  // This try is because the CameraComponent OnSampleBufferReady cannot cope
  // with thrown exceptions
  try
    if Client.Active then
    begin
      // If we are logged in, send the picture to the server
      // (SaveToStream will save it as png format)
      BytesStream := TBytesStream.Create;
      try
        imgUserVideo.Bitmap.SaveToStream(BytesStream);
        Client.ExecCommand(cmdCntCameraImage, BytesStream.Bytes, False);
      finally
        BytesStream.Free;
      end;
    end;
  except
  end;
end;

procedure TfrmMain.btnSendTextClick(Sender: TObject);
begin
  Client.ExecCommand(cmdCntGetText, BytesOf(edtUsername.Text + ': ' + edtTextToSend.Text), False);
  edtTextToSend.Text := '';
end;

procedure TfrmMain.edtUsernameEnter(Sender: TObject);
begin
  btnConnect.Default := True;
end;

procedure TfrmMain.edtUsernameExit(Sender: TObject);
begin
  btnConnect.Default := False;
end;

procedure TfrmMain.edtTextToSendEnter(Sender: TObject);
begin
  btnSendText.Default := True;
end;

procedure TfrmMain.edtTextToSendExit(Sender: TObject);
begin
  btnSendText.Default := False;
end;

end.
