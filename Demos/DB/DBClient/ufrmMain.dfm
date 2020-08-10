object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'Client DB Tester'
  ClientHeight = 392
  ClientWidth = 945
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Panel2: TPanel
    Left = 245
    Top = 0
    Width = 700
    Height = 373
    Align = alClient
    TabOrder = 2
    object dbGrid1: TDBGrid
      AlignWithMargins = True
      Left = 4
      Top = 4
      Width = 692
      Height = 150
      Align = alTop
      DataSource = dmMain.DataSource1
      TabOrder = 0
      TitleFont.Charset = DEFAULT_CHARSET
      TitleFont.Color = clWindowText
      TitleFont.Height = -11
      TitleFont.Name = 'Tahoma'
      TitleFont.Style = []
    end
    object DBNavigator1: TDBNavigator
      AlignWithMargins = True
      Left = 4
      Top = 160
      Width = 692
      Height = 35
      DataSource = dmMain.DataSource1
      Align = alTop
      TabOrder = 1
    end
    object DBGrid2: TDBGrid
      AlignWithMargins = True
      Left = 4
      Top = 201
      Width = 692
      Height = 130
      Align = alClient
      DataSource = dmMain.DataSource2
      TabOrder = 2
      TitleFont.Charset = DEFAULT_CHARSET
      TitleFont.Color = clWindowText
      TitleFont.Height = -11
      TitleFont.Name = 'Tahoma'
      TitleFont.Style = []
    end
    object DBNavigator2: TDBNavigator
      AlignWithMargins = True
      Left = 4
      Top = 337
      Width = 692
      Height = 32
      DataSource = dmMain.DataSource2
      Align = alBottom
      TabOrder = 3
    end
  end
  object StatusBar: TStatusBar
    Left = 0
    Top = 373
    Width = 945
    Height = 19
    Panels = <>
    SimplePanel = True
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 245
    Height = 373
    Align = alLeft
    TabOrder = 0
    object Button1: TButton
      Left = 6
      Top = 52
      Width = 219
      Height = 25
      Caption = 'Test Activate/Deactivate Recordset Cycle'
      TabOrder = 0
      OnClick = Button1Click
    end
    object Button2: TButton
      Left = 6
      Top = 111
      Width = 219
      Height = 25
      Caption = 'Test Requery'
      TabOrder = 1
      OnClick = Button2Click
    end
    object cbShowOpenClose: TCheckBox
      Left = 12
      Top = 83
      Width = 213
      Height = 17
      Caption = 'Show Open/Close'
      TabOrder = 2
    end
    object Button4: TButton
      Left = 6
      Top = 230
      Width = 161
      Height = 45
      Caption = 'Filter Pending'
      TabOrder = 3
      OnClick = Button4Click
    end
    object edtHost: TEdit
      Left = 6
      Top = 10
      Width = 121
      Height = 21
      TabOrder = 4
      Text = 'LocalHost'
      TextHint = 'Host'
      OnChange = edtHostChange
    end
    object btnApplyUpdates: TButton
      Left = 6
      Top = 281
      Width = 161
      Height = 45
      Caption = 'Apply Updates'
      TabOrder = 5
      OnClick = btnApplyUpdatesClick
    end
  end
end
