unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ncSources, StdCtrls;

type
  TForm1 = class(TForm)
    ncClientSource: TncClientSource;
    Button1: TButton;
    Memo1: TMemo;
    Button2: TButton;
    Button3: TButton;
    procedure ncClientSourceConnected(Sender: TObject; aLine: TncSourceLine);
    procedure ncClientSourceDisconnected(Sender: TObject; aLine: TncSourceLine);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.Button1Click(Sender: TObject);
begin
  ncClientSource.Active := not ncClientSource.Active;
end;

procedure TForm1.Button2Click(Sender: TObject);
var
  Response: TBytes;
  TimeNow: Cardinal;
begin
  Memo1.Lines.Add('Executing command...');
  TimeNow := GetTickCount;
  Response := ncClientSource.ExecCommand(0, BytesOf('Hello'));

  Memo1.Lines.Add('Response: ' + StringOf(Response) + ', Time: ' + IntToStr(GetTickCount - TimeNow));
end;

procedure TForm1.Button3Click(Sender: TObject);
var
  Response: TBytes;
  TimeNow: Cardinal;
  i: Integer;
begin
  Memo1.Lines.Add('Executing 1000 commands...');
  TimeNow := GetTickCount;
  for i := 0 to 999 do
    Response := ncClientSource.ExecCommand(0, BytesOf('Hello'));
  Memo1.Lines.Add('Response: ' + StringOf(Response) + ', Time: ' + IntToStr(GetTickCount - TimeNow));
end;

procedure TForm1.ncClientSourceConnected(Sender: TObject; aLine: TncSourceLine);
begin
  Memo1.Lines.Add('Connected');
end;

procedure TForm1.ncClientSourceDisconnected(Sender: TObject; aLine: TncSourceLine);
begin
  Memo1.Lines.Add('Disconnected');
end;

end.
