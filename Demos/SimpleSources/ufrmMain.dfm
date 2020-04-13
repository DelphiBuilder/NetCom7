object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Form1'
  ClientHeight = 300
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Memo1: TMemo
    Left = 0
    Top = 0
    Width = 635
    Height = 300
    Align = alClient
    Lines.Strings = (
      'Memo1')
    TabOrder = 1
  end
  object Button1: TButton
    Left = 344
    Top = 12
    Width = 265
    Height = 25
    Caption = 'Connect/Disconnect'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Button2: TButton
    Left = 344
    Top = 43
    Width = 265
    Height = 25
    Caption = 'Exec Command'
    TabOrder = 2
    OnClick = Button2Click
  end
  object Button3: TButton
    Left = 344
    Top = 74
    Width = 265
    Height = 25
    Caption = 'Exec 1000 Commands'
    TabOrder = 3
    OnClick = Button3Click
  end
  object ncClientSource: TncClientSource
    ReaderUseMainThread = True
    CommandProcessorType = cpReaderContextOnly
    EncryptionKey = 'SetEncryptionKey'
    OnConnected = ncClientSourceConnected
    OnDisconnected = ncClientSourceDisconnected
    Host = 'localhost'
    Left = 36
    Top = 32
  end
end
