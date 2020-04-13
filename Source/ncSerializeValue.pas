unit ncSerializeValue;

interface

uses Rtti;

implementation
  var
    RttiContext: TRttiContext;

    { Value ToBytes:
    if Data.IsEmpty then
      WriteString('nil')
    else
    begin
      // Write Data (TncValue) string name

      WriteString(RttiContext.GetType(Data.TypeInfo).QualifiedName);

      // Append Data (TncValue) contents
      Len := Length(Result);
      SetLength(Result, Len + Data.DataSize);
      Data.ExtractRawData(@Result[Len]);
    end;

    Value FromBytes:
    // Read Data (TncValue) string name
    TypeName := ReadString;

    // Read Data (TncValue) contents
    if TypeName = 'nil' then
      Data := nil
    else
      TValue.Make(@aBytes[Ofs], RttiContext.FindType(TypeName).Handle, Data);

    }

initialization

  RttiContext := TRttiContext.Create;

finalization

  RttiContext.Free;

end.
