unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ncSockets, ncSources, StdCtrls;

type
  TForm1 = class(TForm)
    ncServerSource: TncServerSource;
    Memo1: TMemo;
    procedure FormCreate(Sender: TObject);
    procedure ncServerSourceConnected(Sender: TObject; aLine: TncSourceLine);
    procedure ncServerSourceDisconnected(Sender: TObject; aLine: TncSourceLine);
    function ncServerSourceHandleCommand(Sender: TObject; aLine: TncSourceLine;
      aCmd: Integer; aData: TArray<System.Byte>; aRequiresResult: Boolean;
      const aSenderComponent, aReceiverComponent: string): TArray<System.Byte>;
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
  ncServerSource.Active := True;
end;

procedure TForm1.ncServerSourceConnected(Sender: TObject; aLine: TncSourceLine);
begin
  Memo1.Lines.Add('Connected peer');
end;

procedure TForm1.ncServerSourceDisconnected(Sender: TObject;
  aLine: TncSourceLine);
begin
  Memo1.Lines.Add('Disconnected peer');
end;

function TForm1.ncServerSourceHandleCommand(Sender: TObject;
  aLine: TncSourceLine; aCmd: Integer; aData: TArray<System.Byte>;
  aRequiresResult: Boolean; const aSenderComponent,
  aReceiverComponent: string): TArray<System.Byte>;
begin
  // Comment out the following line if you want to test the server's real response speed
  Memo1.Lines.Add('Given response for data: ' + StringOf (aData));
  Result := aData;
end;

end.
