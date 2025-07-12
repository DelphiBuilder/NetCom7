object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'NetCom7 Threaded Server Demo'
  ClientHeight = 600
  ClientWidth = 800
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 13
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 800
    Height = 89
    Align = alTop
    TabOrder = 0
    ExplicitWidth = 798
    object Label1: TLabel
      Left = 16
      Top = 16
      Width = 24
      Height = 13
      Caption = 'Port:'
    end
    object btnStartStop: TButton
      Left = 16
      Top = 48
      Width = 121
      Height = 25
      Caption = 'Start Server'
      TabOrder = 0
      OnClick = btnStartStopClick
    end
    object edtPort: TEdit
      Left = 46
      Top = 13
      Width = 91
      Height = 21
      TabOrder = 1
      Text = '8080'
    end
    object btnClearLog: TButton
      Left = 168
      Top = 48
      Width = 75
      Height = 25
      Caption = 'Clear Log'
      TabOrder = 2
      OnClick = btnClearLogClick
    end
  end
  object Panel2: TPanel
    Left = 0
    Top = 89
    Width = 800
    Height = 320
    Align = alClient
    TabOrder = 1
    ExplicitWidth = 798
    ExplicitHeight = 312
    DesignSize = (
      800
      320)
    object Label2: TLabel
      Left = 16
      Top = 8
      Width = 52
      Height = 13
      Caption = 'Server Log'
    end
    object memoLog: TMemo
      Left = 16
      Top = 27
      Width = 769
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
      ExplicitWidth = 767
      ExplicitHeight = 273
    end
  end
  object Panel3: TPanel
    Left = 0
    Top = 409
    Width = 800
    Height = 191
    Align = alBottom
    TabOrder = 2
    ExplicitTop = 401
    ExplicitWidth = 798
    object Label3: TLabel
      Left = 16
      Top = 16
      Width = 63
      Height = 13
      Caption = 'Connections:'
    end
    object lblConnections: TLabel
      Left = 86
      Top = 16
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlue
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object Label4: TLabel
      Left = 16
      Top = 40
      Width = 85
      Height = 13
      Caption = 'Threads per CPU:'
    end
    object lblThreadsPerCPU: TLabel
      Left = 105
      Top = 40
      Width = 7
      Height = 13
      Caption = '4'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlue
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object Label5: TLabel
      Left = 16
      Top = 64
      Width = 66
      Height = 13
      Caption = 'Max Threads:'
    end
    object lblMaxThreads: TLabel
      Left = 89
      Top = 64
      Width = 14
      Height = 13
      Caption = '32'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlue
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object Label6: TLabel
      Left = 200
      Top = 16
      Width = 76
      Height = 13
      Caption = 'Total Requests:'
    end
    object lblTotalRequests: TLabel
      Left = 283
      Top = 16
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGreen
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object Label7: TLabel
      Left = 200
      Top = 40
      Width = 88
      Height = 13
      Caption = 'Requests/Second:'
    end
    object lblRequestsPerSecond: TLabel
      Left = 288
      Top = 40
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGreen
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object Label8: TLabel
      Left = 200
      Top = 64
      Width = 76
      Height = 13
      Caption = 'Active Threads:'
    end
    object lblActiveThreads: TLabel
      Left = 283
      Top = 64
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clMaroon
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblLastTestResults: TLabel
      Left = 400
      Top = 16
      Width = 89
      Height = 13
      Caption = 'Last Test Results:'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clNavy
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblTestTotalRequests: TLabel
      Left = 400
      Top = 40
      Width = 76
      Height = 13
      Caption = 'Total Requests:'
    end
    object lblTestTotalRequestsValue: TLabel
      Left = 490
      Top = 40
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGreen
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblTestPeakReqSec: TLabel
      Left = 400
      Top = 64
      Width = 65
      Height = 13
      Caption = 'Peak Req/Sec:'
    end
    object lblTestPeakReqSecValue: TLabel
      Left = 490
      Top = 64
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGreen
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblTestDuration: TLabel
      Left = 400
      Top = 88
      Width = 67
      Height = 13
      Caption = 'Test Duration:'
    end
    object lblTestDurationValue: TLabel
      Left = 490
      Top = 88
      Width = 15
      Height = 13
      Caption = '0s'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGreen
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblTestAvgReqSec: TLabel
      Left = 400
      Top = 112
      Width = 62
      Height = 13
      Caption = 'Avg Req/Sec:'
    end
    object lblTestAvgReqSecValue: TLabel
      Left = 490
      Top = 112
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGreen
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object btnResetStats: TButton
      Left = 400
      Top = 144
      Width = 75
      Height = 25
      Caption = 'Reset Stats'
      TabOrder = 0
      OnClick = btnResetStatsClick
    end
  end
  object Timer1: TTimer
    OnTimer = Timer1Timer
    Left = 720
    Top = 48
  end
end
