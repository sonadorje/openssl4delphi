unit output;

interface

function test_printf_stdout( fmt : &string):integer;
  function test_printf_stderr( fmt : &string):integer;
  function test_printf_tapout( fmt : &string):integer;
  function test_printf_taperr( fmt : &string):integer;

implementation
uses bioprinttest;

function test_printf_stdout( fmt : &string):integer;
var
  ret : integer;
begin
    ret := test_vprintf_stdout(fmt);
    Result := ret;
end;


function test_printf_stderr( fmt : &string):integer;
var
  ret : integer;
begin

    ret := test_vprintf_stderr(fmt);
    Result := ret;
end;


function test_printf_tapout( fmt : &string):integer;
var
  ret : integer;
begin
    ret := test_vprintf_tapout(fmt);
    Result := ret;
end;


function test_printf_taperr( fmt : &string):integer;
var
  ret : integer;
begin
    ret := test_vprintf_taperr(fmt);
    Result := ret;
end;

end.
