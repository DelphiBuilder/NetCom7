unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ncSockets, StdCtrls, ncSources;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    ncTCPClient1: TncTCPClient;
    procedure Button1Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure ncTCPClient1Connected(Sender: TObject; aLine: TncLine);
    procedure ncTCPClient1Disconnected(Sender: TObject; aLine: TncLine);
    procedure ncTCPClient1Reconnected(Sender: TObject; aLine: TncLine);
    procedure ncTCPClient1ReadData(Sender: TObject; aLine: TncLine;
      const aBuf: TArray<System.Byte>; aBufCount: Integer);
  private
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.Button1Click(Sender: TObject);
//var
//  i: Integer;
begin
  ncTCPClient1.Active := True;

//  i := 0;
//  while not Application.Terminated do
//  begin
//    i := i + 1;
//    ncTCPClient1.Send(BytesOf (WideString ('Hello man!' + IntToStr (i))));
//    Application.ProcessMessages;
//    Sleep (100);
//  end;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  ncTCPClient1.Active := False;
end;

procedure TForm1.ncTCPClient1Connected(Sender: TObject; aLine: TncLine);
begin
  if ncTCPClient1.ReaderUseMainThread then
    Memo1.Lines.Add ('Connected');
end;

procedure TForm1.ncTCPClient1Disconnected(Sender: TObject; aLine: TncLine);
begin
  if ncTCPClient1.ReaderUseMainThread then
    Memo1.Lines.Add ('Disconnected');
end;

procedure TForm1.ncTCPClient1ReadData(Sender: TObject; aLine: TncLine;
  const aBuf: TArray<System.Byte>; aBufCount: Integer);
begin
  if ncTCPClient1.ReaderUseMainThread then
    Memo1.Lines.Add ('Received: ' + StringOf (aBuf));
  // ncTCPClient1.Send(aBuf);
end;

procedure TForm1.ncTCPClient1Reconnected(Sender: TObject; aLine: TncLine);
begin
  if ncTCPClient1.ReaderUseMainThread then
    Memo1.Lines.Add ('Reconnected');
end;

end.
