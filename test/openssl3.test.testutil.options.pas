unit openssl3.test.testutil.options;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api, SysUtils;

{$POINTERMATH ON}
var
  used: array[0..100-1] of int;

procedure opt_check_usage;
function opt_printf_stderr( fmt : PUTF8Char; ap: array of const):integer;

implementation
uses app.lib.opt,                openssl3.test.testutil.output,
     openssl3.test.testutil.basic_output;


function opt_printf_stderr( fmt : PUTF8Char; ap: array of const):integer;
begin
    Result := test_vprintf_stderr(fmt, ap);
end;

procedure opt_check_usage;
var
  i         : integer;
  argv      : PPUTF8Char;
  n,
  arg_count : integer;
begin
    argv := opt_rest;
    arg_count := opt_num_rest;
    if arg_count > Length(used) then
        n := Length(used)
    else
        n := arg_count;
    for i := 0 to n-1 do
    begin
        if used[i] = 0 then
        test_printf_stderr('Warning ignored command-line argument %d: %s'#10,
                               [i, argv[i]]);
    end;
    if i < arg_count then
        test_printf_stderr('Warning arguments %d and later unchecked'#10, [i]);
end;

initialization
  FillChar(used, 100, 0);
end.
