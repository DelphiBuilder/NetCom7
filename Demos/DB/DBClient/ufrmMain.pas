unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, udmMain, DBCtrls, ExtCtrls, Grids, DBGrids, StdCtrls, ncSockets, ncDBCnt,
  ComCtrls, ADOInt, ADODB, Data.DB;

type
  TfrmMain = class(TForm)
    StatusBar: TStatusBar;
    Panel1: TPanel;
    Panel2: TPanel;
    dbGrid1: TDBGrid;
    DBNavigator1: TDBNavigator;
    DBGrid2: TDBGrid;
    DBNavigator2: TDBNavigator;
    Button1: TButton;
    Button2: TButton;
    cbShowOpenClose: TCheckBox;
    Button4: TButton;
    edtHost: TEdit;
    btnHostByName: TButton;
    btnApplyUpdates: TButton;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure edtHostChange(Sender: TObject);
    procedure btnHostByNameClick(Sender: TObject);
    procedure btnApplyUpdatesClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

var
  InButton1: Boolean = False;
  PrevBtn1Cap: string;

procedure TfrmMain.btnHostByNameClick(Sender: TObject);
begin
  btnHostByName.Caption := IntToStr(Ord(HostByName(edtHost.Text).S_un_b.s_b1)) + '.' + IntToStr(Ord(HostByName(edtHost.Text).S_un_b.s_b2)) + '.' +
    IntToStr(Ord(HostByName(edtHost.Text).S_un_b.s_b3)) + '.' + IntToStr(Ord(HostByName(edtHost.Text).S_un_b.s_b4));
end;

procedure TfrmMain.Button1Click(Sender: TObject);
var
  TimeStart, TimeEnd: Int64;

  Freq: Int64;
  i: Integer;
begin
  if InButton1 then
  begin
    Button1.Caption := PrevBtn1Cap;

    InButton1 := False;
    Exit;
  end;

  // Test n alive queries
  InButton1 := True;
  try
    PrevBtn1Cap := Button1.Caption;
    Button1.Caption := 'Stop';

    if not cbShowOpenClose.Checked then
    begin
      dmMain.DataSource1.DataSet := nil;
      dmMain.DataSource2.DataSet := nil;
    end;
    try
      QueryPerformanceFrequency(Freq);
      QueryPerformanceCounter(TimeStart);
      i := 0;
      while InButton1 and not Application.Terminated do
      begin
        i := i + 1;
        if i mod 100 = 0 then
        begin
          StatusBar.SimpleText := Format('Iteration: %4.4d, Mean Open/Close Time: %f (ms)', [i, 1000 * (TimeEnd - TimeStart) / (i * Freq)]);
          Application.ProcessMessages;
        end;
        // Test open/close time
        dmMain.ncDBDataset1.Active := False;
        dmMain.ncDBDataset1.Active := True;
        // Test ExecSQL time
        // dmMain.ncDBDataset1.SQL.Text := 'UPDATE Customers SET CustomerName = ''Bill'' where ID = 1';
        // dmMain.ncDBDataset1.ExecSQL;
        QueryPerformanceCounter(TimeEnd);
      end;
    finally
      if dmMain.DataSource1.DataSet = nil then
      begin
        dmMain.DataSource1.DataSet := dmMain.ncDBDataset1;
        dmMain.DataSource2.DataSet := dmMain.ncDBDataset2;
      end;
    end;
  finally
    InButton1 := False;
  end;
end;

procedure TfrmMain.Button2Click(Sender: TObject);
begin
  dmMain.ncDBDataset2.Requery;
end;

var
  InButton3: Boolean = False;
  PrevBtn3Cap: string;

procedure TfrmMain.Button4Click(Sender: TObject);
begin
  dmMain.ncDBDataset1.FilterGroup := fgPendingRecords;
  dmMain.ncDBDataset1.Filtered := not dmMain.ncDBDataset1.Filtered;

  { with dmMain.ncDBDataset1.Recordset do
    begin
    if Filter = adFilterNone then
    begin
    Filter := adFilterPendingRecords;
    MarshalOptions := adMarshalModifiedOnly;
    end
    else
    begin
    Filter := adFilterNone;
    end;
    end;
  }
end;

procedure TfrmMain.btnApplyUpdatesClick(Sender: TObject);
begin
  dmMain.ncDBDataset1.ApplyUpdates;
  dmMain.ncDBDataset2.ApplyUpdates;
end;

procedure TfrmMain.edtHostChange(Sender: TObject);
begin
  dmMain.ncClientSource1.Active := False;
  dmMain.ncClientSource1.Host := edtHost.Text;
end;

end.
