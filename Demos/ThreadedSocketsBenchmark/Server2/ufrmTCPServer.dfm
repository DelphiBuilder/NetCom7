object frmTCPServer: TfrmTCPServer
  Left = 0
  Top = 0
  Caption = 'NetCom7 TncTCPServer Demo - Raw Socket (No Thread Pool)'
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
  object pnlTop: TPanel
    Left = 0
    Top = 0
    Width = 800
    Height = 89
    Align = alTop
    TabOrder = 0
    object lblPort: TLabel
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
  end
  object memoLog: TMemo
    Left = 0
    Top = 89
    Width = 800
    Height = 320
    Align = alClient
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Consolas'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 1
  end
  object pnlStats: TPanel
    Left = 0
    Top = 409
    Width = 800
    Height = 191
    Align = alBottom
    TabOrder = 2
    object lblConnections: TLabel
      Left = 16
      Top = 16
      Width = 63
      Height = 13
      Caption = 'Connections:'
    end
    object lblRequests: TLabel
      Left = 16
      Top = 40
      Width = 76
      Height = 13
      Caption = 'Total Requests:'
    end
    object lblRequestsPerSec: TLabel
      Left = 16
      Top = 64
      Width = 88
      Height = 13
      Caption = 'Requests/Second:'
    end
    object lblThreads: TLabel
      Left = 16
      Top = 88
      Width = 76
      Height = 13
      Caption = 'Active Threads:'
    end
    object lblConnectionsValue: TLabel
      Left = 120
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
    object lblRequestsValue: TLabel
      Left = 120
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
    object lblRequestsPerSecValue: TLabel
      Left = 120
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
    object lblThreadsValue: TLabel
      Left = 120
      Top = 88
      Width = 7
      Height = 13
      Caption = '0'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clRed
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object lblLastTestResults: TLabel
      Left = 400
      Top = 16
      Width = 100
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
      Width = 70
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
      Width = 69
      Height = 13
      Caption = 'Test Duration:'
    end
    object lblTestDurationValue: TLabel
      Left = 490
      Top = 88
      Width = 13
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
      Width = 66
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
    object lblLog: TLabel
      Left = 16
      Top = 152
      Width = 161
      Height = 21
      Caption = 'Raw Socket - No Thread Pool'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clMaroon
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
  object tmrStats: TTimer
    OnTimer = tmrStatsTimer
    Left = 720
    Top = 48
  end
end
