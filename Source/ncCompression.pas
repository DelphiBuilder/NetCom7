unit ncCompression;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0 }
{$WEAKLINKRTTI ON }
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([]) }
{$IFEND }

interface

  uses ZLib, Classes, SysUtils, Windows {ToDo: Remove Windows Reference} ;

  type
    TncCompressionLevel = TZCompressionLevel;

  function CompressBytes(const aBytes: TBytes; aCompressionLevel: TncCompressionLevel = zcDefault): TBytes;

  function DecompressBytes(const aBytes: TBytes): TBytes;

implementation

  function CompressBytes(const aBytes: TBytes; aCompressionLevel: TncCompressionLevel = zcDefault): TBytes;
  var
    Buffer: Pointer;
    Size: Integer; // In bytes
  begin
    SetLength(Result, 0);

    if Length(aBytes) > 0 then
    begin
      ZCompress(@aBytes[0], Length(aBytes), Buffer, Size, aCompressionLevel);
      try
        if Size > 0 then
        begin
          SetLength(Result, Size);
          Move(Buffer^, Result[0], Size);
        end;
      finally
        FreeMem(Buffer);
      end;
    end;
  end;

  function DecompressBytes(const aBytes: TBytes): TBytes;
  var
    Buffer: Pointer;
    Size: Integer;
  begin
    try
      SetLength(Result, 0);

      if Length(aBytes) > 0 then
      begin
        ZDecompress(@aBytes[0], Length(aBytes), Buffer, Size);
        try
          if Size > 0 then
          begin
            SetLength(Result, Size);
            Move(Buffer^, Result[0], Size);
          end;
        finally
          FreeMem(Buffer);
        end;
      end;
    except
      on E: Exception do
        OutputDebugString(PWideChar('Decompression Failed: ' + E.Message));
    end;
  end;

end.
