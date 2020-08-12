unit udmMain;

interface

uses
  System.Classes, System.SysUtils, Data.DB, Data.Win.ADODB, ncSockets, ncSources, ncDBCnt;

type
  TdmMain = class(TDataModule)
    ncClientSource: TncClientSource;
    ncDBDataset1: TncDBDataset;
    DataSource1: TDataSource;
    ncDBDataset2: TncDBDataset;
    DataSource2: TDataSource;
    ADOQuery1: TADOQuery;
    procedure DataModuleCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  dmMain: TdmMain;

implementation

uses ufrmMain;

{$R *.dfm}

procedure TdmMain.DataModuleCreate(Sender: TObject);
begin
  ncDBDataset1.Active := True;
  ncDBDataset2.Active := True;
end;

end.
