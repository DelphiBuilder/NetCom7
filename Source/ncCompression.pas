unit ncCompression;

// To disable as much of RTTI as possible (Delphi 2009/2010),
// Note: There is a bug if $RTTI is used before the "unit <unitname>;" section of a unit, hence the position
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses System.ZLib, System.Classes, System.SysUtils;

type
  TncCompressionLevel = TZCompressionLevel;

function CompressBytes(const aBytes: TBytes; aCompressionLevel: TncCompressionLevel = zcDefault): TBytes;
function DecompressBytes(const aBytes: TBytes): TBytes;

implementation

function CompressBytes(const aBytes: TBytes; aCompressionLevel: TncCompressionLevel = zcDefault): TBytes;
begin
  if Length(aBytes) > 0 then
    ZCompress(aBytes, Result, aCompressionLevel)
  else
    SetLength(Result, 0);
end;

function DecompressBytes(const aBytes: TBytes): TBytes;
begin
  if Length(aBytes) > 0 then
    ZDecompress(aBytes, Result)
  else
    SetLength(Result, 0);
end;

end.
