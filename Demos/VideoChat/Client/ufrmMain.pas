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
    StyleBook: TStyleBook;
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
    procedure FormShow(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.fmx}

procedure TfrmMain.FormShow(Sender: TObject);
begin
  CameraComponent.Active := True;
end;

procedure TfrmMain.ClientConnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      btnConnect.Text := 'Disconnect';
    end);
end;

procedure TfrmMain.ClientDisconnected(Sender: TObject; aLine: TncLine);
begin
  TThread.Synchronize(nil,
    procedure
    begin
      btnConnect.Text := 'Connect';
      lbUsers.Clear;
    end);
end;

function TfrmMain.ClientHandleCommand(Sender: TObject; aLine: TncLine; aCmd: Integer; const aData: TArray<System.Byte>; aRequiresResult: Boolean;
const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
begin
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

procedure TfrmMain.btnConnectClick(Sender: TObject);
begin
  if Client.Active then
  begin
    Client.Active := False;
    edtUsername.Enabled := True;
  end
  else
  begin
    if edtUsername.Text = '' then
      edtUsername.Text := 'Anonymous'; // Although Eponymous

    edtUsername.Enabled := False;
    Client.Active := True;
    try
      Client.ExecCommand(cmdCntUserLogin, BytesOf(edtUsername.Text));
    except
      Client.Active := False;
      edtUsername.Enabled := True;

      raise; // reraise the exception so that user gets informed
    end;
  end;
end;

procedure TfrmMain.CameraComponentSampleBufferReady(Sender: TObject; const ATime: TMediaTime);
var
  BytesStream: TBytesStream;
begin
  // We got a new image from the camera
  // Assign it first to our own imgUserVideo component
  CameraComponent.SampleBufferToBitmap(imgUserVideo.Bitmap, True);

  // If we are logged in, send the picture to the server
  if Client.Active then
  begin
    BytesStream := TBytesStream.Create;
    try
      imgUserVideo.Bitmap.SaveToStream(BytesStream);
      Client.ExecCommand(cmdCntCameraImage, BytesStream.Bytes, False);
    finally
      BytesStream.Free;
    end;
  end;
end;

procedure TfrmMain.btnSendTextClick(Sender: TObject);
begin
  Client.ExecCommand(cmdCntGetText, BytesOf(edtTextToSend.Text), False);
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
