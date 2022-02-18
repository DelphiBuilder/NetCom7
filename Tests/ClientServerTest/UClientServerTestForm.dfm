object ClientServerTestForm: TClientServerTestForm
  Left = 0
  Top = 0
  Caption = 'Client/Server Test'
  ClientHeight = 352
  ClientWidth = 855
  Color = clBtnFace
  Constraints.MinHeight = 389
  Constraints.MinWidth = 773
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  DesignSize = (
    855
    352)
  PixelsPerInch = 96
  TextHeight = 13
  object pnlDivider1: TBevel
    Left = 193
    Top = 8
    Width = 1
    Height = 25
    Shape = bsLeftLine
  end
  object pnlDivider2: TBevel
    Left = 537
    Top = 8
    Width = 4
    Height = 25
    Shape = bsLeftLine
  end
  object pnlDivider3: TBevel
    Left = 762
    Top = 8
    Width = 4
    Height = 25
    Shape = bsLeftLine
  end
  object pnlDivider0: TBevel
    Left = 100
    Top = 8
    Width = 1
    Height = 25
    Shape = bsLeftLine
  end
  object edtLog: TMemo
    Left = 8
    Top = 39
    Width = 839
    Height = 305
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssBoth
    TabOrder = 10
  end
  object btnToggleServer: TButton
    Left = 107
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Toggle server'
    TabOrder = 2
    OnClick = btnToggleServerClick
  end
  object btnAddClients: TButton
    Left = 260
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Add clients'
    TabOrder = 4
    OnClick = btnAddClientsClick
  end
  object btnDeleteClients: TButton
    Left = 344
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Delete clients'
    TabOrder = 5
    OnClick = btnDeleteClientsClick
  end
  object bntSendToClients: TButton
    Left = 543
    Top = 8
    Width = 104
    Height = 25
    Caption = 'Send to clients'
    TabOrder = 7
    OnClick = bntSendToClientsClick
  end
  object btnSendFromClients: TButton
    Left = 652
    Top = 8
    Width = 104
    Height = 25
    Caption = 'Send from clients'
    TabOrder = 8
    OnClick = btnSendFromClientsClick
  end
  object edtClientCount: TSpinEdit
    Left = 201
    Top = 9
    Width = 54
    Height = 22
    MaxValue = 4096
    MinValue = 1
    TabOrder = 3
    Value = 1
  end
  object btnDeleteAllClients: TButton
    Left = 428
    Top = 8
    Width = 104
    Height = 25
    Caption = 'Delete all clients'
    TabOrder = 6
    OnClick = btnDeleteClientsClick
  end
  object btnReset: TButton
    Left = 768
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Reset'
    TabOrder = 9
    OnClick = btnResetClick
  end
  object edtSocketTypeTCP: TRadioButton
    Left = 8
    Top = 11
    Width = 40
    Height = 17
    Caption = 'TCP'
    TabOrder = 0
  end
  object edtSocketTypeUDP: TRadioButton
    Left = 54
    Top = 11
    Width = 40
    Height = 17
    Caption = 'UDP'
    TabOrder = 1
  end
end
