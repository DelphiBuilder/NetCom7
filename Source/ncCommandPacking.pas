unit ncCommandPacking;

/// ////////////////////////////////////////////////////////////////////////////
//
// TSocketList
//
// This unit declares a TncCommand which is used by ncSources to pass
// information from peer to peer.
// The TncCommand can be packed and unnpacked into and from a TBytes array
//
// This unit has been optimised to perform at maximum speed by checking the
// assembly the compiler generates.
//
// Written by Demos Bill
// 7/8/2020
//  - Optimised code by checking assembly. The performance of executing 100000
//    times a command with data: 'Hello from Client', and compression on, was
//    before optimisation: 57532 msec
//    after optimisation: 19383 msec
//    performance gain: 2,97 times faster.
//    With compression off we can execute 100000 command executions
//    in 5438 msec
//    This performance testing was made before ncSources were re-engineered.
//    Please check ncSources to see what the new performance is after
//    latest re-engineering.
//  - Initial Creation: Ported code from ncSources
//
/// ////////////////////////////////////////////////////////////////////////////

interface

uses SysUtils;

type
  ENetComImproperMessageEncoding = class(Exception);

  TncCommandType = (ctInitiator, ctResponse);
  PncCommandType = ^TncCommandType;

  TncCommandUniqueID = UInt32;
  PncCommandUniqueID = ^TncCommandUniqueID;

  TncCommandCmd = UInt32;
  PncCommandCmd = ^TncCommandCmd;

  TncCommand = record
  public
    CommandType: TncCommandType;
    UniqueID: TncCommandUniqueID;
    Cmd: TncCommandCmd;
    Data: TBytes;
    RequiresResult: Boolean;
    AsyncExecute: Boolean;
    ResultIsErrorString: Boolean;
    SourceComponentHandler: string;
    PeerComponentHandler: string;

    procedure FromBytes(const aBytes: TBytes);
    function ToBytes: TBytes;
  end;

resourcestring
  ENetComImproperMessageEncodingMessage = 'Improper message encoding';

implementation

// /////////////////////////////////////////////////////////////////////////////
{ TncCommand }
// /////////////////////////////////////////////////////////////////////////////

procedure TncCommand.FromBytes(const aBytes: TBytes);
type
  PBool = ^Boolean;
  PInt32 = ^Int32;
  PUInt64 = ^UInt64;

const
  SigLen = SizeOf(Byte);
  BytesLen = SizeOf(UInt64);

  CommandTypeLen = SizeOf(TncCommandType);
  UniqueIDLen = SizeOf(TncCommandUniqueID);
  CmdLen = SizeOf(TncCommandCmd);
  AsyncExecuteLen = SizeOf(Boolean);
  RequiresResultLen = SizeOf(Boolean);
  ResultIsErrorStringLen = SizeOf(Boolean);

var
  AddrPtr: PByte;
  DataBytesLen, SourceComponentBytesLen, PeerComponentBytesLen: UInt64;
  StrBytes: TBytes;

begin
  // Point to beginning of aBytes
  AddrPtr := @aBytes[0];

  // Read command type
  CommandType := PncCommandType(AddrPtr)^;
  inc(AddrPtr, CommandTypeLen);
  // Read UniqueID
  UniqueID := PncCommandUniqueID(AddrPtr)^;
  inc(AddrPtr, UniqueIDLen);
  // Read Cmd
  Cmd := PncCommandCmd(AddrPtr)^;
  inc(AddrPtr, CmdLen);
  // Read AsyncExecute
  AsyncExecute := PBool(AddrPtr)^;
  inc(AddrPtr, AsyncExecuteLen);
  // Read RequiresResult
  RequiresResult := PBool(AddrPtr)^;
  inc(AddrPtr, RequiresResultLen);
  // Read ResultIsErrorString
  ResultIsErrorString := PBool(AddrPtr)^;
  inc(AddrPtr, ResultIsErrorStringLen);

  // Read Signature
  if PByte(AddrPtr)^ <> $AA then // 10101010 bin
    raise ENetComImproperMessageEncoding.Create(ENetComImproperMessageEncodingMessage);
  inc(AddrPtr, SigLen);
  // Read DataLen
  DataBytesLen := PUInt64(AddrPtr)^;
  inc(AddrPtr, BytesLen);

  // Read Signature
  if PByte(AddrPtr)^ <> $AA then // 10101010 bin
    raise ENetComImproperMessageEncoding.Create(ENetComImproperMessageEncodingMessage);
  inc(AddrPtr, SigLen);
  // Read SourceComponentHandlerBytesLen
  SourceComponentBytesLen := PUInt64(AddrPtr)^;
  inc(AddrPtr, BytesLen);

  // Read Signature
  if PByte(AddrPtr)^ <> $AA then // 10101010 bin
    raise ENetComImproperMessageEncoding.Create(ENetComImproperMessageEncodingMessage);
  inc(AddrPtr, SigLen);
  // Read PeerComponentHandlerBytesLen
  PeerComponentBytesLen := PUInt64(AddrPtr)^;
  inc(AddrPtr, BytesLen);

  // Read Data
  if DataBytesLen > 0 then
  begin
    SetLength(Data, DataBytesLen);
    move(AddrPtr^, Data[0], DataBytesLen);
    inc(AddrPtr, DataBytesLen);
  end;
  // Read SourceComponentHandlerBytes
  if SourceComponentBytesLen > 0 then
  begin
    SetLength(StrBytes, SourceComponentBytesLen);
    move(AddrPtr^, StrBytes[0], SourceComponentBytesLen);
    SourceComponentHandler := StringOf(StrBytes);
    inc(AddrPtr, SourceComponentBytesLen);
  end;
  // Read PeerComponentHandlerBytes
  if PeerComponentBytesLen > 0 then
  begin
    SetLength(StrBytes, PeerComponentBytesLen);
    move(AddrPtr^, StrBytes[0], PeerComponentBytesLen);
    PeerComponentHandler := StringOf(StrBytes);
  end;
end;

function TncCommand.ToBytes: TBytes;
type
  PBool = ^Boolean;
  PInt32 = ^Int32;
  PUInt64 = ^UInt64;

const
  SigLen = SizeOf(Byte);
  BytesLen = SizeOf(UInt64);

  CommandTypeLen = SizeOf(TncCommandType);
  UniqueIDLen = SizeOf(TncCommandUniqueID);
  CmdLen = SizeOf(TncCommandCmd);
  AsyncExecuteLen = SizeOf(Boolean);
  RequiresResultLen = SizeOf(Boolean);
  ResultIsErrorStringLen = SizeOf(Boolean);

  StaticBufferLen =

    UInt64(CommandTypeLen + UniqueIDLen + CmdLen + AsyncExecuteLen + RequiresResultLen + ResultIsErrorStringLen +

    SigLen + BytesLen + SigLen + BytesLen + SigLen + BytesLen);

var
  AddrPtr: PByte;
  DataBytesLen, SourceComponentBytesLen, PeerComponentBytesLen: UInt64;
  SourceComponentHandlerBytes, PeerComponentHandlerBytes: TBytes;

begin
  SourceComponentHandlerBytes := BytesOf(SourceComponentHandler);
  PeerComponentHandlerBytes := BytesOf(PeerComponentHandler);

  DataBytesLen := Length(Data);
  SourceComponentBytesLen := Length(SourceComponentHandlerBytes);
  PeerComponentBytesLen := Length(PeerComponentHandlerBytes);

  SetLength(Result, StaticBufferLen + DataBytesLen + SourceComponentBytesLen + PeerComponentBytesLen);

  // Point to beginning of result buffer
  AddrPtr := @Result[0];

  // Write command type
  PncCommandType(AddrPtr)^ := CommandType;
  inc(AddrPtr, CommandTypeLen);
  // Write UniqueID
  PncCommandUniqueID(AddrPtr)^ := UniqueID;
  inc(AddrPtr, UniqueIDLen);
  // Write Cmd
  PncCommandCmd(AddrPtr)^ := Cmd;
  inc(AddrPtr, CmdLen);
  // Write AnyncExecute
  PBool(AddrPtr)^ := AsyncExecute;
  inc(AddrPtr, AsyncExecuteLen);
  // Write RequiresResult
  PBool(AddrPtr)^ := RequiresResult;
  inc(AddrPtr, RequiresResultLen);
  // Write ResultIsErrorString
  PBool(AddrPtr)^ := ResultIsErrorString;
  inc(AddrPtr, ResultIsErrorStringLen);

  // Write Signature
  PByte(AddrPtr)^ := $AA; // 10101010 bin
  inc(AddrPtr, SigLen);
  // Write DataLen
  PUInt64(AddrPtr)^ := DataBytesLen;
  inc(AddrPtr, BytesLen);

  // Write Signature
  PByte(AddrPtr)^ := $AA; // 10101010 bin
  inc(AddrPtr, SigLen);
  // Write SourceComponentHandlerBytesLen
  PUInt64(AddrPtr)^ := SourceComponentBytesLen;
  inc(AddrPtr, BytesLen);

  // Write Signature
  PByte(AddrPtr)^ := $AA; // 10101010 bin
  inc(AddrPtr, SigLen);
  // Write PeerComponentHandlerBytesLen
  PUInt64(AddrPtr)^ := PeerComponentBytesLen;
  inc(AddrPtr, BytesLen);

  // Write Data
  if DataBytesLen > 0 then
  begin
    move(Data[0], AddrPtr^, DataBytesLen);
    inc(AddrPtr, DataBytesLen);
  end;
  // Write SourceComponentHandlerBytes
  if SourceComponentBytesLen > 0 then
  begin
    move(SourceComponentHandlerBytes[0], AddrPtr^, SourceComponentBytesLen);
    inc(AddrPtr, SourceComponentBytesLen);
  end;
  // Write PeerComponentHandlerBytes
  if PeerComponentBytesLen > 0 then
    move(PeerComponentHandlerBytes[0], AddrPtr^, PeerComponentBytesLen);
end;

end.
