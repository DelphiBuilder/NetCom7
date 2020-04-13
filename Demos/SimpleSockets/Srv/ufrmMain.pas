unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ncSockets, StdCtrls;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    ncTCPServer1: TncTCPServer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure ncTCPServer1Connected(Sender: TObject; aLine: TncLine);
    procedure ncTCPServer1Disconnected(Sender: TObject; aLine: TncLine);
    procedure ncTCPServer1ReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
  private
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
  ncTCPServer1.Active := True;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  ncTCPServer1.Active := False;
end;

procedure TForm1.ncTCPServer1Connected(Sender: TObject; aLine: TncLine);
begin
  if ncTCPServer1.ReaderUseMainThread then
    Memo1.Lines.Add('Connected');
  ncTCPServer1.Send(aLine, BytesOf('Hello mr. ' + IntToStr(aLine.Handle)));

end;

procedure TForm1.ncTCPServer1Disconnected(Sender: TObject; aLine: TncLine);
begin
  if ncTCPServer1.ReaderUseMainThread then
    Memo1.Lines.Add('Disconnected');

end;

procedure TForm1.ncTCPServer1ReadData(Sender: TObject; aLine: TncLine; const aBuf: TBytes; aBufCount: Integer);
begin
  if ncTCPServer1.ReaderUseMainThread then
    Memo1.Lines.Add(StringOf(aBuf));
  ncTCPServer1.Send(aLine, aBuf);
end;

end.
