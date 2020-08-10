unit NetComRegister;

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
// 13 Dec 2010
// Written by Demos Bill
// VasDemos@yahoo.co.uk
//
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

interface

uses
  WinApi.Windows, System.Classes, System.SysUtils, ToolsAPI, DesignIntf, DesignEditors,

  ncSockets, ncSources, ncCommandHandlers, ncDBSrv, ncDBCnt;

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

  ForceDemandLoadState(dlDisable);
end;

function GetVersion(aMinor: Boolean = True; aRelease: Boolean = True; aBuild: Boolean = True): string;
var
  VerInfoSize: DWORD;
  VerInfo: Pointer;
  VerValueSize: DWORD;
  VerValue: PVSFixedFileInfo;
  Dummy: DWORD;
  strBuffer: array [0 .. MAX_PATH] of Char;
begin
  GetModuleFileName(hInstance, strBuffer, MAX_PATH);
  VerInfoSize := GetFileVersionInfoSize(strBuffer, Dummy);
  if VerInfoSize <> 0 then
  begin
    GetMem(VerInfo, VerInfoSize);
    try
      GetFileVersionInfo(strBuffer, 0, VerInfoSize, VerInfo);
      VerQueryValue(VerInfo, '\', Pointer(VerValue), VerValueSize);
      with VerValue^ do
      begin
        Result := IntToStr(dwFileVersionMS shr 16); // Major always there
        if aMinor then
          Result := Result + '.' + IntToStr(dwFileVersionMS and $FFFF);
        if aRelease then
          Result := Result + '.' + IntToStr(dwFileVersionLS shr 16);
        if aBuild then
          Result := Result + '.' + IntToStr(dwFileVersionLS and $FFFF);
      end;
    finally
      FreeMem(VerInfo, VerInfoSize);
    end;
  end;
end;

const
  ICON_SPLASH = 'TNCICON';
  ICON_ABOUT = 'TNCICON';

var
  AboutBoxServices: IOTAAboutBoxServices = nil;
  AboutBoxIndex: Integer = 0;

resourcestring
  resPackageName = 'NetCom7 Network Communications Framework';
  resLicence = 'Full Edition for RAD Studio';
  resAboutCopyright = 'Copyright © 2020 Bill Demos (VasDemos@yahoo.co.uk)';
  resAboutTitle = 'NetCom7 Network Communications Framework';
  resAboutDescription =
    'Netcom7 Communicatios Framework enables you to use communication components with the ease of use of the Delphi programming language. Create and handle client/server sockets, sources and DB elements with no single line of API calls.';

procedure RegisterSplashScreen;
var
  SplashScreenHandle: HBitmap;
begin
  SplashScreenHandle := LoadBitmap(hInstance, ICON_SPLASH);
  try
    SplashScreenServices.AddPluginBitmap(resPackageName + GetVersion, SplashScreenHandle, False, resLicence);
  finally
    DeleteObject(SplashScreenHandle);
  end;
end;

procedure RegisterAboutBox;
var
  ProductImage: HBitmap;
begin
  Supports(BorlandIDEServices, IOTAAboutBoxServices, AboutBoxServices);
  ProductImage := LoadBitmap(FindResourceHInstance(hInstance), ICON_ABOUT);
  AboutBoxIndex := AboutBoxServices.AddPluginInfo(resPackageName + GetVersion,
    resAboutCopyright + #13#10 + resAboutDescription, ProductImage, False, resLicence);
end;

procedure UnregisterAboutBox;
begin
  if (AboutBoxIndex <> 0) and Assigned(AboutBoxServices) then
  begin
    AboutBoxServices.RemovePluginInfo(AboutBoxIndex);
    AboutBoxIndex := 0;
    AboutBoxServices := nil;
  end;
end;

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

initialization

RegisterSplashScreen;
RegisterAboutBox;

finalization

UnregisterAboutBox;

end.
