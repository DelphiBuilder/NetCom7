object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'NetCom VS Indy Server'
  ClientHeight = 57
  ClientWidth = 601
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 24
    Top = 24
    Width = 555
    Height = 13
    Caption = 
      'Servers activate on creation (except if there was an error). You' +
      ' can now run the client while this program is running'
  end
  object ncServer: TncTCPServer
    NoDelay = True
    OnReadData = ncServerReadData
    Left = 456
    Top = 8
  end
  object idServer: TIdTCPServer
    Bindings = <>
    DefaultPort = 16234
    OnExecute = idServerExecute
    Left = 504
    Top = 8
  end
end
