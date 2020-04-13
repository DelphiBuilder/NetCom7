object dmMain: TdmMain
  OldCreateOrder = False
  OnCreate = DataModuleCreate
  Height = 351
  Width = 376
  object ncClientSource1: TncClientSource
    Port = 18753
    EncryptionKey = 'SetEncryptionKey'
    Host = 'localhost'
    Left = 56
    Top = 36
  end
  object ncDBDataset1: TncDBDataset
    CursorType = ctStatic
    LockType = ltBatchOptimistic
    Source = ncClientSource1
    PeerCommandHandler = 'DBServer'
    SQL.Strings = (
      'select * from Customers')
    Parameters = <>
    Left = 112
    Top = 116
  end
  object DataSource1: TDataSource
    DataSet = ncDBDataset1
    Left = 196
    Top = 116
  end
  object ncDBDataset2: TncDBDataset
    CursorType = ctStatic
    LockType = ltBatchOptimistic
    Source = ncClientSource1
    PeerCommandHandler = 'DBServer'
    SQL.Strings = (
      'select * from Orders'
      'where FKCustomersID=:ID')
    DataSource = DataSource1
    IndexFieldNames = 'FKCustomersID'
    Parameters = <
      item
        Name = 'ID'
        Size = -1
        Value = Null
      end>
    Left = 112
    Top = 184
  end
  object DataSource2: TDataSource
    DataSet = ncDBDataset2
    Left = 196
    Top = 184
  end
  object ADOQuery1: TADOQuery
    Parameters = <>
    Left = 56
    Top = 276
  end
end
