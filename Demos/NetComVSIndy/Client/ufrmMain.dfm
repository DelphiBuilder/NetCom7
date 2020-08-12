object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'NetCom vs Indy speed testing'
  ClientHeight = 358
  ClientWidth = 802
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
  object pnlToolbar: TPanel
    Left = 0
    Top = 0
    Width = 802
    Height = 41
    Align = alTop
    BevelOuter = bvNone
    FullRepaint = False
    TabOrder = 0
    object Label1: TLabel
      Left = 328
      Top = 14
      Width = 51
      Height = 13
      Caption = 'Iterations:'
    end
    object btnTestSpeed: TButton
      Left = 0
      Top = 0
      Width = 121
      Height = 41
      Align = alLeft
      Caption = 'Test Speed'
      TabOrder = 0
      OnClick = btnTestSpeedClick
    end
    object edtIterations: TSpinEdit
      Left = 385
      Top = 11
      Width = 81
      Height = 22
      MaxValue = 0
      MinValue = 0
      TabOrder = 1
      Value = 10000
    end
    object rbTestNetCom: TRadioButton
      Left = 145
      Top = 12
      Width = 80
      Height = 17
      Caption = 'Test NetCom'
      Checked = True
      TabOrder = 2
      TabStop = True
    end
    object rbTestIndy: TRadioButton
      Left = 231
      Top = 12
      Width = 82
      Height = 17
      Caption = 'Test Indy'
      TabOrder = 3
    end
  end
  object memLog: TMemo
    Left = 0
    Top = 41
    Width = 802
    Height = 317
    Align = alClient
    TabOrder = 1
  end
  object ncClient: TncTCPClient
    Host = 'LocalHost'
    UseReaderThread = False
    NoDelay = True
    KeepAlive = False
    Reconnect = False
    Left = 304
    Top = 32
  end
  object idClient: TIdTCPClient
    ConnectTimeout = 0
    Host = 'LocalHost'
    IPVersion = Id_IPv4
    Port = 16234
    ReadTimeout = -1
    Left = 304
    Top = 88
  end
end
