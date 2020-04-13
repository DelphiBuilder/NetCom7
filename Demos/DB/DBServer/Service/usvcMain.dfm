object NetcomDataServer: TNetcomDataServer
  OldCreateOrder = False
  OnCreate = ServiceCreate
  OnDestroy = ServiceDestroy
  DisplayName = 'Netcom7 Database Server'
  OnShutdown = ServiceShutdown
  OnStart = ServiceStart
  OnStop = ServiceStop
  Height = 254
  Width = 270
  object srvController: TncServerSource
    Port = 18753
    EncryptionKey = 'SetEncryptionKey'
    Left = 40
    Top = 32
  end
  object DBServer: TncDBServer
    ADOConnection = ADOConnection
    Source = srvController
    Left = 40
    Top = 92
  end
  object ADOConnection: TADOConnection
    ConnectionString = 
      'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=.\..\TestData\Custo' +
      'mers.mdb;Persist Security Info=False;'
    LoginPrompt = False
    Mode = cmShareDenyNone
    Provider = 'Microsoft.Jet.OLEDB.4.0'
    Left = 128
    Top = 92
  end
end
