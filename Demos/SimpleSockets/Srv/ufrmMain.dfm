object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Form1'
  ClientHeight = 243
  ClientWidth = 527
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object Button1: TButton
    Left = 16
    Top = 16
    Width = 75
    Height = 25
    Caption = 'Deactivate'
    TabOrder = 0
  end
  object Memo1: TMemo
    Left = 0
    Top = 0
    Width = 527
    Height = 243
    Align = alClient
    Lines.Strings = (
      'Memo1')
    TabOrder = 1
  end
  object ncTCPServer1: TncTCPServer
    ReaderUseMainThread = True
    OnConnected = ncTCPServer1Connected
    OnDisconnected = ncTCPServer1Disconnected
    OnReadData = ncTCPServer1ReadData
    Left = 92
    Top = 52
  end
end
