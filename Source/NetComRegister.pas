unit NetComRegister;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
// 13 Dec 2010
// Written by Demos Bill
// BDemos@simetron.gr
// www.simetron.gr
//
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

interface

uses
  Classes, SysUtils, DesignIntf, DesignEditors, ncSockets, ncSources, ncCommandHandlers, ncDBSrv, ncDBCnt;

type
  TncTCPSocketDefaultEditor = class(TDefaultEditor)
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

  TncSourceDefaultEditor = class(TDefaultEditor)
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

procedure Register;

implementation

{ TncTCPSocketDefaultEditor }

procedure TncTCPSocketDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if CompareText(Prop.GetName, 'ONREADDATA') = 0 then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

{ TncCustomPeerSourceDefaultEditor }

procedure TncSourceDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if CompareText(Prop.GetName, 'ONHANDLECOMMAND') = 0 then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

procedure Register;
begin
  RegisterComponents('NetCom7', [TncTCPServer, TncTCPClient, TncServerSource, TncClientSource, TncCommandHandler, TncDBServer, TncDBDataset]);

  RegisterComponentEditor(TncTCPServer, TncTCPSocketDefaultEditor);
  RegisterComponentEditor(TncTCPClient, TncTCPSocketDefaultEditor);
  RegisterComponentEditor(TncServerSource, TncSourceDefaultEditor);
  RegisterComponentEditor(TncClientSource, TncSourceDefaultEditor);

  UnlistPublishedProperty(TncDBDataset, 'Connection');
  UnlistPublishedProperty(TncDBDataset, 'ConnectionString');
  // RegisterPropertyEditor(TypeInfo(string), TncDBDataset, 'ConnectionString', nil);
end;

end.
