unit openssl3.test.testutil.random;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api;

function test_random:uint32;
procedure test_random_seed( sd : uint32);

var

  test_random_state : array[0..30] of uint32;
  pos: UInt32 = 3;

implementation

{$Q-}
function test_random:uint32;
begin
    if pos = 31 then
       pos := 0;
    test_random_state[pos]  := test_random_state[pos] + (test_random_state[(pos + 28) mod 31]);
    Result := test_random_state[PostInc(pos)] div 2;
end;
{$Q+}

procedure test_random_seed( sd : uint32);
var
  i, s : integer;
const
  _mod : uint32 = (UINT32(1) shl 31) - 1;
begin
    test_random_state[0] := sd;
    for i := 1 to 30 do
    begin
        s := int32(test_random_state[i - 1]);
        test_random_state[i] := uint32((16807 * int64(s)) mod _mod);
    end;
    for i := 34 to 343 do
        test_random;
end;


end.
