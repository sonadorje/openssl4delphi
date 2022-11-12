unit openssl3.tsan_assist;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses  {$IFDEF  MSWINDOWS}
        Windows,
      {$ENDIF} OpenSSL.Api;

procedure tsan_store(ptr: PUINT32; val: UINT32);overload;
function tsan_load(ptr: PInt32): Integer;
procedure tsan_store(ptr: PInt32; val: Integer);overload;
function tsan_add(ptr: Pointer; n, sz: Int): int64;
function tsan_counter(ptr: Pointer; sz: int): int64;


implementation



function tsan_counter(ptr: Pointer; sz: int): int64;
begin
   Result := tsan_add(ptr, 1, sz);

end;


function tsan_add(ptr: Pointer; n, sz: Int): int64;
begin
{$ifdef WIN64}
    if sz = 8 then
       Result := InterlockedExchangeAdd64(Pint64(ptr)^, n)
    else
       Result := InterlockedExchangeAdd(PInt32(ptr)^, n);
{$else}
    Result := InterlockedExchangeAdd(PInt32(ptr)^, n);
{$endif}
end;




procedure tsan_store(ptr: PUINT32; val: UINT32);
begin
   ptr^ := val;
end;

procedure tsan_store(ptr: PInt32; val: Integer);
begin
   ptr^ := val;
end;

function tsan_load(ptr: PInt32): Integer;
begin
  Result := ptr^;
end;

end.
