object ClientServerTestForm: TClientServerTestForm
  Left = 0
  Top = 0
  Caption = 'Client/Server Test'
  ClientHeight = 350
  ClientWidth = 757
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
    757
    350)
  PixelsPerInch = 96
  TextHeight = 13
  object pnlDivider0: TBevel
    Left = 94
    Top = 8
    Width = 1
    Height = 25
    Shape = bsLeftLine
  end
  object pnlDivider1: TBevel
    Left = 438
    Top = 8
    Width = 4
    Height = 25
    Shape = bsLeftLine
  end
  object pnlDivider2: TBevel
    Left = 663
    Top = 8
    Width = 4
    Height = 25
    Shape = bsLeftLine
  end
  object edtLog: TMemo
    Left = 8
    Top = 39
    Width = 741
    Height = 303
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssBoth
    TabOrder = 8
  end
  object btnToggleServer: TButton
    Left = 8
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Toggle server'
    TabOrder = 0
    OnClick = btnToggleServerClick
  end
  object btnAddClients: TButton
    Left = 161
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Add clients'
    TabOrder = 2
    OnClick = btnAddClientsClick
  end
  object btnDeleteClients: TButton
    Left = 245
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Delete clients'
    TabOrder = 3
    OnClick = btnDeleteClientsClick
  end
  object bntSendToClients: TButton
    Left = 444
    Top = 8
    Width = 104
    Height = 25
    Caption = 'Send to clients'
    TabOrder = 5
    OnClick = bntSendToClientsClick
  end
  object btnSendFromClients: TButton
    Left = 553
    Top = 8
    Width = 104
    Height = 25
    Caption = 'Send from clients'
    TabOrder = 6
    OnClick = btnSendFromClientsClick
  end
  object edtClientCount: TSpinEdit
    Left = 102
    Top = 9
    Width = 54
    Height = 23
    MaxValue = 4096
    MinValue = 1
    TabOrder = 1
    Value = 1
  end
  object btnDeleteAllClients: TButton
    Left = 329
    Top = 8
    Width = 104
    Height = 25
    Caption = 'Delete all clients'
    TabOrder = 4
    OnClick = btnDeleteClientsClick
  end
  object btnReset: TButton
    Left = 669
    Top = 8
    Width = 80
    Height = 25
    Caption = 'Reset'
    TabOrder = 7
    OnClick = btnResetClick
  end
end
