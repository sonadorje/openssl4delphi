program buildtest_drbg;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  {$IFDEF EurekaLog}
  EMemLeaks,
  EResLeaks,
  EDebugExports,
  EDebugJCL,
  EFixSafeCallException,
  EMapWin32,
  EAppConsole,
  EDialogConsole,
  ExceptionLog7,
  {$ENDIF EurekaLog}
  SysUtils,
  openssl3.crypto.params,
  openssl3.crypto.evp.pmeth_lib,
  openssl3.crypto.evp.p_lib,
  openssl3.crypto.evp.pmeth_gn,
  openssl3.crypto.bn.bn_lib,
  OpenSSL3.crypto.err.err_prn,
  openssl3.crypto.bio.bio_dump,
  openssl3.crypto.provider,
  openssl3.crypto.provider_core,
  openssl3.crypto.evp.evp_fetch,
  openssl3.providers.fips.fips_entry,
  OpenSSL.Api,
  libc.error in 'libc\libc.error.pas',
  openssl3.crypto.conf.conf_def in 'openssl3.crypto.conf.conf_def.pas',
  openssl3.test.testutil.random in 'test\openssl3.test.testutil.random.pas',
  app.lib.opt in 'app\app.lib.opt.pas',
  app.lib.win32_init in 'app\app.lib.win32_init.pas',
  test_options in 'test\test_options.pas',
  openssl3.test.testutil.testutil_init in 'test\openssl3.test.testutil.testutil_init.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  openssl3.test.testutil.options in 'test\openssl3.test.testutil.options.pas',
  openssl3.test.testutil.driver in 'test\openssl3.test.testutil.driver.pas',
  openssl3.test.testutil.tests in 'test\openssl3.test.testutil.tests.pas',
  openssl3.test.testutil.basic_output in 'test\openssl3.test.testutil.basic_output.pas',
  drbgtest in 'test\drbgtest.pas';

type
  PTextFile = ^TextFile;

var
  F: PTextFile;

{$POINTERMATH ON}
function main:integer;
var
  ret, I, len : integer;
  _argv: array[0..9] of PAnsiChar;
  str: Ansistring;
  label _end;
begin
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
end;


begin
  try
    main;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.


begin
  try
    main;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

