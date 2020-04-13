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
  OnCreate = FormCreate
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
    TabOrder = 0
  end
  object ncServerSource: TncServerSource
    ReaderUseMainThread = True
    CommandProcessorType = cpReaderContextOnly
    EncryptionKey = 'SetEncryptionKey'
    OnConnected = ncServerSourceConnected
    OnDisconnected = ncServerSourceDisconnected
    OnHandleCommand = ncServerSourceHandleCommand
    Left = 60
    Top = 32
  end
end
