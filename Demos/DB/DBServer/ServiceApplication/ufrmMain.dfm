object frmMain: TfrmMain
  Left = 0
  Top = 0
  ActiveControl = memLog
  Caption = 'Netcom7 Database Server Management'
  ClientHeight = 388
  ClientWidth = 1030
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  ScreenSnap = True
  ShowHint = True
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object Splitter1: TSplitter
    Left = 257
    Top = 50
    Height = 338
    ExplicitLeft = 308
    ExplicitTop = 276
    ExplicitHeight = 100
  end
  object pnlCaption: TPanel
    Left = 0
    Top = 0
    Width = 1030
    Height = 50
    Align = alTop
    BevelOuter = bvNone
    Caption = 'In-memory service - stopped'
    Color = clBlack
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWhite
    Font.Height = -27
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentBackground = False
    ParentFont = False
    TabOrder = 0
  end
  object memLog: TMemo
    Left = 260
    Top = 50
    Width = 770
    Height = 338
    Align = alClient
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 2
    WordWrap = False
  end
  object CategoryPanelGroup1: TCategoryPanelGroup
    Left = 0
    Top = 50
    Width = 257
    Height = 338
    VertScrollBar.Tracking = True
    BevelInner = bvNone
    BevelOuter = bvNone
    ChevronAlignment = taRightJustify
    Color = clGradientActiveCaption
    HeaderAlignment = taRightJustify
    HeaderFont.Charset = DEFAULT_CHARSET
    HeaderFont.Color = clWindowText
    HeaderFont.Height = -11
    HeaderFont.Name = 'Tahoma'
    HeaderFont.Style = []
    Padding.Left = 3
    Padding.Top = 3
    Padding.Right = 3
    Padding.Bottom = 3
    TabOrder = 1
    object CategoryPanel3: TCategoryPanel
      AlignWithMargins = True
      Top = 204
      Height = 65
      Caption = 'Startup'
      TabOrder = 2
      object cbAutorunLogon: TCheckBox
        AlignWithMargins = True
        Left = 7
        Top = 3
        Width = 163
        Height = 33
        Hint = 
          'Check this if you want to run this program instead of the servic' +
          'e for testing over time. This application will launch with windo' +
          'ws logon.'
        Margins.Left = 7
        Margins.Right = 7
        Align = alLeft
        Caption = 'Autorun with Windows logon'
        TabOrder = 0
        OnClick = cbAutorunLogonClick
      end
    end
    object cpConnection: TCategoryPanel
      AlignWithMargins = True
      Top = 77
      Height = 121
      Caption = 'Engine Settings'
      TabOrder = 1
      object GridPanel1: TGridPanel
        AlignWithMargins = True
        Left = 7
        Top = 7
        Width = 227
        Height = 81
        Margins.Left = 7
        Margins.Top = 7
        Margins.Right = 7
        Margins.Bottom = 7
        Align = alClient
        BevelOuter = bvNone
        ColumnCollection = <
          item
            Value = 100.000000000000000000
          end>
        ControlCollection = <
          item
            Column = 0
            Control = Panel1
            Row = 0
          end
          item
            Column = 0
            Control = Panel2
            Row = 1
          end
          item
            Column = 0
            Control = Panel3
            Row = 2
          end>
        RowCollection = <
          item
            Value = 33.333333333333330000
          end
          item
            Value = 33.333333333333330000
          end
          item
            Value = 33.333333333333330000
          end>
        TabOrder = 0
        object Panel1: TPanel
          Left = 0
          Top = 0
          Width = 227
          Height = 26
          Align = alClient
          BevelOuter = bvNone
          Caption = 'Panel1'
          TabOrder = 0
          object edtConnectionString: TEdit
            AlignWithMargins = True
            Left = 0
            Top = 2
            Width = 202
            Height = 22
            Margins.Left = 0
            Margins.Top = 2
            Margins.Right = 1
            Margins.Bottom = 2
            Align = alClient
            TabOrder = 0
            TextHint = 'ADO Connection String'
            OnChange = edtConnectionStringChange
            ExplicitHeight = 21
          end
          object btnEditConnectionString: TButton
            AlignWithMargins = True
            Left = 204
            Top = 2
            Width = 23
            Height = 22
            Hint = 'Edit connection string...'
            Margins.Left = 1
            Margins.Top = 2
            Margins.Right = 0
            Margins.Bottom = 2
            Align = alRight
            Caption = '...'
            TabOrder = 1
            OnClick = btnEditConnectionStringClick
          end
        end
        object Panel2: TPanel
          Left = 0
          Top = 26
          Width = 227
          Height = 26
          Align = alClient
          BevelOuter = bvNone
          TabOrder = 1
          object lblPort: TLabel
            Left = 71
            Top = 5
            Width = 64
            Height = 13
            Caption = '(TCP/IP Port)'
          end
          object edtPort: TSpinEdit
            Left = 0
            Top = 2
            Width = 65
            Height = 22
            MaxValue = 0
            MinValue = 0
            TabOrder = 0
            Value = 0
            OnChange = edtPortChange
          end
        end
        object Panel3: TPanel
          Left = 0
          Top = 52
          Width = 227
          Height = 29
          Align = alClient
          BevelOuter = bvNone
          TabOrder = 2
          object cbEnableCachedResults: TCheckBox
            Left = 0
            Top = 0
            Width = 227
            Height = 29
            Align = alClient
            Caption = 'Enable cached query responses'
            Checked = True
            Color = clWindow
            ParentColor = False
            State = cbChecked
            TabOrder = 0
            OnClick = cbEnableCachedResultsClick
          end
        end
      end
    end
    object CategoryPanel1: TCategoryPanel
      AlignWithMargins = True
      Top = 6
      Height = 65
      Caption = 'In-memory Server Activation'
      TabOrder = 0
      object btnStartService: TButton
        AlignWithMargins = True
        Left = 7
        Top = 7
        Width = 102
        Height = 25
        Margins.Left = 7
        Margins.Top = 7
        Margins.Bottom = 7
        Align = alLeft
        Caption = 'Start Engine'
        TabOrder = 0
        OnClick = btnStartServiceClick
      end
      object cbAutostartServer: TCheckBox
        AlignWithMargins = True
        Left = 168
        Top = 3
        Width = 66
        Height = 33
        Hint = 'Start Engine when this program starts'
        Margins.Right = 7
        Align = alRight
        Caption = 'Autostart'
        TabOrder = 1
        OnClick = cbAutostartServerClick
      end
    end
  end
  object TrayIcon: TTrayIcon
    PopupMenu = popTray
    Visible = True
    OnClick = miShowHideServerClick
    Left = 316
    Top = 68
  end
  object popTray: TPopupMenu
    Left = 368
    Top = 68
    object miShowHideServer: TMenuItem
      Caption = 'Show/Hide Server'
      OnClick = miShowHideServerClick
    end
    object miN1: TMenuItem
      Caption = '-'
    end
    object miShutdown: TMenuItem
      Caption = 'Shutdown'
      OnClick = miShutdownClick
    end
  end
  object tmrUpdateLog: TTimer
    Interval = 10
    OnTimer = tmrUpdateLogTimer
    Left = 316
    Top = 116
  end
end
