unit FileLogger;

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs;

type
  TFileLogger = class
  private
    class var FCriticalSection: TCriticalSection;
    class var FLogFileName: string;
  public
    class procedure Initialize;
    class procedure Finalize;
    class procedure Log(const AMessage: string);
  end;

implementation

class procedure TFileLogger.Initialize;
begin
  FCriticalSection := TCriticalSection.Create;
  FLogFileName := ChangeFileExt(ParamStr(0), '.log');
end;

class procedure TFileLogger.Finalize;
begin
  FCriticalSection.Free;
end;

class procedure TFileLogger.Log(const AMessage: string);
var
  LogFile: TextFile;
  TimeStamp: string;
begin
  FCriticalSection.Enter;
  try
    TimeStamp := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now);
    AssignFile(LogFile, FLogFileName);
    if FileExists(FLogFileName) then
      Append(LogFile)
    else
      Rewrite(LogFile);
    try
      WriteLn(LogFile, Format('[%s] %s', [TimeStamp, AMessage]));
    finally
      CloseFile(LogFile);
    end;
  finally
    FCriticalSection.Leave;
  end;
end;

initialization
  TFileLogger.Initialize;

finalization
  TFileLogger.Finalize;

end.