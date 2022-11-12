program buildtest_rand_status;

{$APPTYPE CONSOLE}
uses
  SysUtils,
  openssl3.test.testutil.basic_output in 'test\openssl3.test.testutil.basic_output.pas',
  openssl3.test.testutil.driver in 'test\openssl3.test.testutil.driver.pas',
  openssl3.test.testutil.format_output in 'test\openssl3.test.testutil.format_output.pas',
  openssl3.test.testutil.options in 'test\openssl3.test.testutil.options.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  openssl3.test.testutil.random in 'test\openssl3.test.testutil.random.pas',
  openssl3.test.testutil.tests in 'test\openssl3.test.testutil.tests.pas',
  openssl3.test.testutil.testutil_init in 'test\openssl3.test.testutil.testutil_init.pas',
  app.lib.opt in 'app\app.lib.opt.pas',
  openssl3.test.testutil.test_options in 'test\openssl3.test.testutil.test_options.pas',
  rand_status_test in 'test\rand_status_test.pas';

function main:integer;
var
  ret, I, len : integer;
  _argv: array[0..9] of PAnsiChar;
  str: Ansistring;
  label _end;
begin
{$POINTERMATH ON}
   {F := @System.Output;
   Writeln(F^, 'I''m System.Output');

   F := @System.ErrOutput;
   Writeln(F^, 'I''m System.ErrOutput');
   CloseFile(F^);

    AssignFile(F^, 'test.txt');
    Rewrite(F^);
    Writeln(F^, 'Hello');
    CloseFile(F^);
   }
    ret := 1;//EXIT_FAILURE;
    test_open_streams;
    if 0 >= global_init() then
    begin
        test_printf_stderr('Global init failed - aborting'#10,[]);
        Exit(ret);
    end;
    FillChar(_argv, Sizeof(_argv), #0);
    //if ParamCount > 0 then
    begin

       for i := 0 to System.ParamCount do
       begin
           Str := ParamStr(I);
           _argv[I] := StrNew(PAnsiChar(Str));
       end;
    end;
    argv := @_argv;
    if 0>=setup_test_framework(ParamCount, argv) then
        goto _end;
    if setup_tests > 0 then
    begin
        ret := run_tests(argv[0]);
        //cleanup_tests;
        opt_check_usage;
    end
    else
    begin
        opt_help(test_get_options);
    end;

_end:
    for i := 0 to System.ParamCount do
        StrDispose( _argv[I]);

    ret := pulldown_test_framework(ret);
    test_close_streams;
    Result := ret;

{$POINTERMATH OFF}
end;


begin
  try
    main;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.





