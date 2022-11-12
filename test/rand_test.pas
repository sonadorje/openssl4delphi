unit rand_test;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api;

function setup_tests:integer;
implementation
uses openssl3.crypto.params,           openssl3.crypto.rand.rand_lib,
     openssl3.test.testutil.tests,     openssl3.crypto.evp.evp_rand,
     openssl3.test.testutil.driver;

function test_rand:integer;
var
    privctx  : PEVP_RAND_CTX;
    outbuf   : array[0..2] of Byte;
    params   : array[0..1] of TOSSL_PARAM;
    p : POSSL_PARAM;
const
  entropy1 : array[0..5] of Byte = ($00, $01, $02, $03, $04, $05);
  entropy2 : array[0..2] of Byte = ($ff, $fe, $fd);
begin
{$POINTERMATH ON}
    p := @params;
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                             @entropy1, sizeof(entropy1));
    p^ := OSSL_PARAM_construct_end;
    privctx := RAND_get0_private(nil);
    if (0>=TEST_ptr('privctx = RAND_get0_private(nil)', privctx))
       or  (0>=TEST_true('EVP_RAND_CTX_set_params(privctx, params)', EVP_RAND_CTX_set_params(privctx, @params)))
       or  (0>=TEST_int_gt('RAND_priv_bytes(outbuf, sizeof(outbuf))', '0', RAND_priv_bytes(@outbuf, sizeof(outbuf)), 0))
       or  (0>=TEST_mem_eq('outbuf', 'sizeof(outbuf)', @outbuf, sizeof(outbuf), @entropy1, sizeof(outbuf)))
       or  (0>=TEST_int_le('RAND_priv_bytes(outbuf, sizeof(outbuf) + 1)', '0', RAND_priv_bytes(@outbuf, sizeof(outbuf) + 1), 0))
       or  (0>=TEST_int_gt('RAND_priv_bytes(outbuf, sizeof(outbuf))', '0', RAND_priv_bytes(@outbuf, sizeof(outbuf)), 0))
       or  (0>=TEST_mem_eq('outbuf', 'sizeof(outbuf)', @outbuf, sizeof(outbuf),
                      PByte(@entropy1) + sizeof(outbuf), sizeof(outbuf))) then
        Exit(0);

    params[0] := OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                                @entropy2, sizeof(entropy2));
    if (0>=TEST_true('EVP_RAND_CTX_set_params(privctx, params)', EVP_RAND_CTX_set_params(privctx, @params)))
       or  (0>=TEST_int_gt('RAND_priv_bytes(outbuf, sizeof(outbuf))', '0', RAND_priv_bytes(@outbuf, sizeof(outbuf)), 0))
       or  (0>=TEST_mem_eq('outbuf', 'sizeof(outbuf)', @outbuf, sizeof(outbuf), @entropy2, sizeof(outbuf))) then
        Exit(0);
    Result := 1;
{$POINTERMATH OFF}
end;


function setup_tests:integer;
begin
    if 0>=TEST_true('RAND_set_DRBG_type(nil, "TEST-RAND", nil, nil, nil)',
                   RAND_set_DRBG_type(nil, 'TEST-RAND', nil, nil, nil))  then
        Exit(0);
    ADD_TEST('test_rand', test_rand);
    Result := 1;
end;

end.
