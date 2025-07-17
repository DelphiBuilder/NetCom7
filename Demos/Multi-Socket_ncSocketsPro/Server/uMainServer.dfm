object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Server - ncSocketsPro Demo'
  ClientHeight = 283
  ClientWidth = 780
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poDesktopCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object Image1: TImage
    Left = 578
    Top = 8
    Width = 192
    Height = 145
  end
  object ListView1: TListView
    Left = 8
    Top = 8
    Width = 564
    Height = 145
    Columns = <
      item
        Caption = 'IP Address'
        Width = 150
      end
      item
        AutoSize = True
        Caption = 'NickName'
      end
      item
        AutoSize = True
        Caption = 'Status'
      end
      item
        AutoSize = True
        Caption = 'Connected At'
      end>
    ReadOnly = True
    RowSelect = True
    PopupMenu = PopupMenu1
    TabOrder = 0
    ViewStyle = vsReport
  end
  object Memo1: TMemo
    Left = 8
    Top = 159
    Width = 762
    Height = 90
    Lines.Strings = (
      '')
    TabOrder = 1
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 264
    Width = 780
    Height = 19
    Panels = <
      item
        Text = 'Status: Offline!'
        Width = 150
      end
      item
        Text = 'Clients Connected: 0'
        Width = 150
      end>
  end
  object PopupMenu1: TPopupMenu
    Left = 96
    Top = 64
    object S1: TMenuItem
      Caption = 'Send To All'
      OnClick = S1Click
    end
    object S2: TMenuItem
      Caption = 'Send To Selected'
      OnClick = S2Click
    end
    object S3: TMenuItem
      Caption = 'Send Raw To Selected'
      OnClick = S3Click
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object G1: TMenuItem
      Caption = 'GetScreenShot'
      OnClick = G1Click
    end
    object C1: TMenuItem
      Caption = 'Change Window Title'
      OnClick = C1Click
    end
  end
  object ServerSocket: TncTCPProServer
    OnConnected = ServerSocketConnected
    OnDisconnected = ServerSocketDisconnected
    OnCommand = ServerSocketCommand
    Left = 208
    Top = 64
  end
end
