object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Client - ncSocketsPro Demo'
  ClientHeight = 203
  ClientWidth = 489
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poMainFormCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object Memo1: TMemo
    Left = 0
    Top = 0
    Width = 489
    Height = 203
    Align = alClient
    Lines.Strings = (
      '')
    TabOrder = 0
  end
  object ClientSocket: TncTCPProClient
    Host = 'LocalHost'
    Reconnect = False
    OnConnected = ClientSocketConnected
    OnDisconnected = ClientSocketDisconnected
    OnCommand = ClientSocketCommand
    Left = 144
    Top = 72
  end
  object Timer1: TTimer
    Enabled = False
    OnTimer = Timer1Timer
    Left = 248
    Top = 72
  end
end
