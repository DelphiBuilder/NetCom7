object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'NetCom7 Threaded Client Demo'
  ClientHeight = 700
  ClientWidth = 900
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    900
    700)
  PixelsPerInch = 96
  TextHeight = 13
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 900
    Height = 89
    Align = alTop
    TabOrder = 0
    object Label1: TLabel
      Left = 16
      Top = 16
      Width = 25
      Height = 13
      Caption = 'Host:'
    end
    object Label2: TLabel
      Left = 16
      Top = 48
      Width = 24
      Height = 13
      Caption = 'Port:'
    end
    object btnConnect: TButton
      Left = 256
      Top = 16
      Width = 121
      Height = 25
      Caption = 'Connect'
      TabOrder = 0
      OnClick = btnConnectClick
    end
    object edtHost: TEdit
      Left = 47
      Top = 13
      Width = 121
      Height = 21
      TabOrder = 1
      Text = 'localhost'
    end
    object edtPort: TEdit
      Left = 47
      Top = 45
      Width = 121
      Height = 21
      TabOrder = 2
      Text = '8080'
    end
    object btnClearLog: TButton
      Left = 400
      Top = 16
      Width = 75
      Height = 25
      Caption = 'Clear Log'
      TabOrder = 3
      OnClick = btnClearLogClick
    end
  end
  object Panel2: TPanel
    Left = 0
    Top = 89
    Width = 900
    Height = 320
    Align = alClient
    TabOrder = 1
    object Label3: TLabel
      Left = 16
      Top = 8
      Width = 49
      Height = 13
      Caption = 'Client Log'
    end
    object memoLog: TMemo
      Left = 16
      Top = 27
      Width = 867
      Height = 281
      Anchors = [akLeft, akTop, akRight, akBottom]
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
      ReadOnly = True
      ScrollBars = ssVertical
      TabOrder = 0
    end
  end
  object Panel3: TPanel
    Left = 0
    Top = 409
    Width = 900
    Height = 145
    Align = alBottom
    TabOrder = 2
    object Label4: TLabel
      Left = 16
      Top = 16
      Width = 26
      Height = 13
      Caption = 'Echo:'
    end
    object Label5: TLabel
      Left = 16
      Top = 48
      Width = 41
      Height = 13
      Caption = 'Reverse:'
    end
    object Label6: TLabel
      Left = 16
      Top = 80
      Width = 26
      Height = 13
      Caption = 'Hash:'
    end
    object btnPing: TButton
      Left = 16
      Top = 112
      Width = 75
      Height = 25
      Caption = 'PING'
      TabOrder = 0
      OnClick = btnPingClick
    end
    object edtEcho: TEdit
      Left = 63
      Top = 13
      Width = 121
      Height = 21
      TabOrder = 1
      Text = 'Hello World'
      OnKeyPress = edtEchoKeyPress
    end
    object btnEcho: TButton
      Left = 200
      Top = 13
      Width = 75
      Height = 25
      Caption = 'ECHO'
      TabOrder = 2
      OnClick = btnEchoClick
    end
    object edtReverse: TEdit
      Left = 63
      Top = 45
      Width = 121
      Height = 21
      TabOrder = 3
      Text = 'Hello World'
      OnKeyPress = edtReverseKeyPress
    end
    object btnReverse: TButton
      Left = 200
      Top = 45
      Width = 75
      Height = 25
      Caption = 'REVERSE'
      TabOrder = 4
      OnClick = btnReverseClick
    end
    object edtHash: TEdit
      Left = 63
      Top = 77
      Width = 121
      Height = 21
      TabOrder = 5
      Text = 'TestData'
      OnKeyPress = edtHashKeyPress
    end
    object btnHash: TButton
      Left = 200
      Top = 77
      Width = 75
      Height = 25
      Caption = 'HASH'
      TabOrder = 6
      OnClick = btnHashClick
    end
    object btnCompute: TButton
      Left = 97
      Top = 112
      Width = 75
      Height = 25
      Caption = 'COMPUTE'
      TabOrder = 7
      OnClick = btnComputeClick
    end
    object btnTime: TButton
      Left = 178
      Top = 112
      Width = 75
      Height = 25
      Caption = 'TIME'
      TabOrder = 8
      OnClick = btnTimeClick
    end
  end
  object Panel4: TPanel
    Left = 0
    Top = 554
    Width = 900
    Height = 41
    Align = alBottom
    TabOrder = 3
    object Label7: TLabel
      Left = 16
      Top = 16
      Width = 33
      Height = 13
      Caption = 'Status:'
    end
    object lblStatus: TLabel
      Left = 55
      Top = 16
      Width = 62
      Height = 13
      Caption = 'Disconnected'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clRed
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
  end
  object Panel5: TPanel
    Left = 0
    Top = 595
    Width = 900
    Height = 105
    Align = alBottom
    TabOrder = 4
    object Label8: TLabel
      Left = 16
      Top = 16
      Width = 96
      Height = 13
      Caption = 'Stress Test Settings'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblConcurrency: TLabel
      Left = 200
      Top = 40
      Width = 6
      Height = 13
      Caption = '5'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlue
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblStressStatus: TLabel
      Left = 400
      Top = 72
      Width = 3
      Height = 13
    end
    object trackConcurrency: TTrackBar
      Left = 16
      Top = 35
      Width = 177
      Height = 33
      Max = 20
      Min = 1
      Position = 5
      TabOrder = 0
      OnChange = trackConcurrencyChange
    end
    object btnStressTest: TButton
      Left = 256
      Top = 35
      Width = 121
      Height = 25
      Caption = 'Start Stress Test'
      TabOrder = 1
      OnClick = btnStressTestClick
    end
    object progressStress: TProgressBar
      Left = 400
      Top = 35
      Width = 350
      Height = 25
      TabOrder = 2
    end
    object btnStopStress: TButton
      Left = 256
      Top = 67
      Width = 121
      Height = 25
      Caption = 'Stop Stress Test'
      Enabled = False
      TabOrder = 3
      OnClick = btnStopStressClick
    end
  end
end 