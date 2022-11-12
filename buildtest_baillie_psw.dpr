program buildtest_baillie_psw;

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
  openssl3.test.testutil.random in 'test\openssl3.test.testutil.random.pas',
  app.lib.opt in 'app\app.lib.opt.pas',
  app.lib.win32_init in 'app\app.lib.win32_init.pas',
  openssl3.test.testutil.testutil_init in 'test\openssl3.test.testutil.testutil_init.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  openssl3.test.testutil.driver in 'test\openssl3.test.testutil.driver.pas',
  openssl3.test.testutil.tests in 'test\openssl3.test.testutil.tests.pas',
  openssl3.test.testutil.basic_output in 'test\openssl3.test.testutil.basic_output.pas',
  openssl3.test.testutil.test_options in 'test\openssl3.test.testutil.test_options.pas',
  openssl3.test.testutil.options in 'test\openssl3.test.testutil.options.pas',
  openssl3.crypto.stack in 'openssl3.crypto.stack.pas',
  openssl3.crypto.bio.bss_file in 'openssl3.crypto.bio.bss_file.pas',
  baillie_psw in 'test\baillie_psw.pas',
  crypto_utils in 'test\crypto_utils.pas',
  bpsw_test in 'test\bpsw_test.pas';


{$POINTERMATH ON}
function main:integer;
begin
   (* test suite *)
    bpsw_tests();
    Result := 0;
end;


begin
  try
    main;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.



