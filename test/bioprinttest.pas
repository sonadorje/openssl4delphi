unit bioprinttest;

interface
uses OpenSSL.api, System.SysUtils;

function test_vprintf_stdout( fmt : PUTF8Char):integer;
  function test_vprintf_stderr( fmt : PUTF8Char):integer;
  function test_flush_stdout:integer;
  function test_flush_stderr:integer;
  function test_vprintf_tapout( fmt : PUTF8Char):integer;
  function test_vprintf_taperr( fmt : PUTF8Char):integer;
  function test_flush_tapout:integer;
  function test_flush_taperr:integer;

var
  tap_level: integer = 0;
  bio_err: PBIO  = nil;

implementation


function test_vprintf_stdout( fmt : PUTF8Char):integer;
var
  s :string;
begin
    s := Format('%*s# ', [tap_level, '']) + fmt;
    Write(s);
    Result := Length(s);
end;


function test_vprintf_stderr( fmt : PUTF8Char):integer;
var
  s :string;
begin
    s := Format('%*s# ', [tap_level, '']) + fmt;
    Write(s);
    Result := Length(s);
end;


function test_flush_stdout:integer;
begin
    Result := 1;//fflush(stdout);
end;


function test_flush_stderr:integer;
begin
    Result := 1;//fflush(stderr);
end;


function test_vprintf_tapout( fmt : PUTF8Char):integer;
var
  s :string;
begin
    s := Format('%*s', [tap_level, '']) + fmt;
    Write(s);
    Result := Length(s);
end;



function test_vprintf_taperr( fmt : PUTF8Char):integer;
var
  s :string;
begin
    s := Format('%*s', [tap_level, '']) + fmt;
    Write(s);
    Result := Length(s);
end;


function test_flush_tapout:integer;
begin
    Result := 1;//fflush(stdout);
end;


function test_flush_taperr:integer;
begin
    Result := 1;//fflush(stderr);
end;


end.
