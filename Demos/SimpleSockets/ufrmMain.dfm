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
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
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
  object Button1: TButton
    Left = 236
    Top = 128
    Width = 75
    Height = 25
    Caption = 'Button1'
    TabOrder = 0
    OnClick = Button1Click
  end
  object ncTCPClient1: TncTCPClient
    Host = 'localhost'
    ReaderUseMainThread = True
    OnConnected = ncTCPClient1Connected
    OnDisconnected = ncTCPClient1Disconnected
    OnReadData = ncTCPClient1ReadData
    OnReconnected = ncTCPClient1Reconnected
    Left = 92
    Top = 52
  end
end
