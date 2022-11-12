unit openssl3.test.testutil.output;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api;

function test_printf_stdout( fmt : PUTF8Char; ap: array of const):integer;
function test_printf_stderr( fmt : PUTF8Char; ap: array of const):integer;
function test_printf_tapout( fmt : PUTF8Char; ap: array of const):integer;
function test_printf_taperr( fmt : PUTF8Char; ap: array of const):integer;

implementation
uses openssl3.test.testutil.basic_output;

function test_printf_stdout( fmt : PUTF8Char; ap: array of const):integer;
begin
    Result := test_vprintf_stdout(fmt, ap);
end;


function test_printf_stderr( fmt : PUTF8Char; ap: array of const):integer;
var
  ret : integer;
begin
    ret := test_vprintf_stderr(fmt, ap);
    Result := ret;
end;


function test_printf_tapout( fmt : PUTF8Char; ap: array of const):integer;
var
  ret : integer;
begin
    ret := test_vprintf_tapout(fmt, ap);
    Result := ret;
end;


function test_printf_taperr( fmt : PUTF8Char; ap: array of const):integer;
var
  ret : integer;
begin
    ret := test_vprintf_taperr(fmt, ap);
    Result := ret;
end;

end.
