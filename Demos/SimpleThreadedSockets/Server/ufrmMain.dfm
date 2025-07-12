object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'TCPServer'
  ClientHeight = 243
  ClientWidth = 527
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
  object memLog: TMemo
    AlignWithMargins = True
    Left = 5
    Top = 37
    Width = 517
    Height = 182
    Margins.Left = 5
    Margins.Top = 0
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 0
    OnKeyDown = memLogKeyDown
  end
  object pnlToolbar: TPanel
    Left = 0
    Top = 0
    Width = 527
    Height = 37
    Align = alTop
    BevelOuter = bvNone
    FullRepaint = False
    TabOrder = 1
    object btnActivate: TButton
      AlignWithMargins = True
      Left = 5
      Top = 5
      Width = 105
      Height = 27
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Align = alLeft
      Caption = 'Activate'
      TabOrder = 0
      OnClick = btnActivateClick
    end
    object pblPort: TPanel
      AlignWithMargins = True
      Left = 115
      Top = 3
      Width = 412
      Height = 31
      Margins.Left = 0
      Margins.Right = 0
      Align = alClient
      BevelOuter = bvNone
      FullRepaint = False
      TabOrder = 1
      object edtPort: TSpinEdit
        AlignWithMargins = True
        Left = 0
        Top = 5
        Width = 121
        Height = 22
        Margins.Left = 0
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Align = alLeft
        MaxValue = 0
        MinValue = 0
        TabOrder = 0
        Value = 16233
        OnChange = edtPortChange
      end
      object btnShutdownAllClients: TButton
        AlignWithMargins = True
        Left = 256
        Top = 5
        Width = 151
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Align = alRight
        Caption = 'Shutdown all clients'
        TabOrder = 1
        OnClick = btnShutdownAllClientsClick
      end
    end
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 224
    Width = 527
    Height = 19
    Panels = <
      item
        Text = 'Connections: 0'
        Width = 150
      end>
  end
  object ncServer1: TncServer
    OnConnected = TCPServerConnected
    OnDisconnected = TCPServerDisconnected
    OnReadData = TCPServerReadData
    Left = 160
    Top = 56
  end
end
