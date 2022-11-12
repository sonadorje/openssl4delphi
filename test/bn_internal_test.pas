unit bn_internal_test;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api;

function test_is_prime_enhanced:integer;
function test_is_composite_enhanced( id : integer):integer;
function test_bn_small_factors:integer;
function setup_tests:integer;
procedure cleanup_tests;

var
  composites : array[0..4] of integer = (9, 21, 77, 81, 265);
  ctx        : PBN_CTX;

implementation
uses openssl3.test.testutil.Tests,    openssl3.crypto.rsa.rsa_lib,
     OpenSSL3.crypto.rsa.rsa_crpt,    openssl3.crypto.bn.bn_lib,
     openssl3.test.testutil.driver,   openssl3.crypto.bn.bn_prime,
     openssl3.crypto.bn.bn_word,      openssl3.crypto.bn.bn_ctx;

function test_is_prime_enhanced:integer;
var
  ret: Boolean;
  status : integer;
  bn : PBIGNUM;
begin
    status := 0;
    bn := nil;
    bn := BN_new();
    ret :=(TEST_ptr('bn = BN_new', bn) > 0)
          { test passing a prime returns the correct status }
           and  (TEST_true('BN_set_word(bn, 11)', BN_set_word(bn, 11)) > 0)
          { return extra parameters related to composite }
           and  (TEST_true('ossl_bn_miller_rabin_is_prime', ossl_bn_miller_rabin_is_prime(bn, 10, ctx, nil, 1, status)) > 0)
           and  (TEST_int_eq('status', 'BN_PRIMETEST_PROBABLY_PRIME', status, BN_PRIMETEST_PROBABLY_PRIME) > 0);
    BN_free(bn);
    Result := Int(ret);
end;


function test_is_composite_enhanced( id : integer):integer;
var
  ret: Boolean;
  status : integer;
  bn : PBIGNUM;
begin
    status := 0;
    bn := nil;
    bn := BN_new();
    ret := (TEST_ptr('bn = BN_new', bn) > 0)
          { negative tests for different composite numbers }
           and  (TEST_true('BN_set_word', BN_set_word(bn, composites[id])) > 0)
           and  (TEST_true('ossl_bn_miller_rabin_is_prime',ossl_bn_miller_rabin_is_prime(bn, 10, ctx, nil, 1,
                                                     &status)) > 0)
           and  (TEST_int_ne('status', 'BN_PRIMETEST_PROBABLY_PRIME', status, BN_PRIMETEST_PROBABLY_PRIME) > 0);
    BN_free(bn);
    Result := Int(ret);
end;


function test_bn_small_factors:integer;
var
  ret,
  i : integer;
  b : PBIGNUM;
  p : prime_t;
  label _err;
begin
    ret := 0;
    b := BN_new();
    if not ( (TEST_ptr('b = BN_new', b) > 0)  and  (TEST_true('BN_set_word', BN_set_word(b, 3)) > 0) ) then
        goto _err;
    for i := 1 to NUMPRIMES-1 do
    begin
        p := primes[i];
        if (p > 3)  and  (p <= 751)  and  (0>=BN_mul_word(b, p)) then
            goto _err;
        if p > 751 then break;
    end;
    ret := TEST_BN_eq('ossl_bn_get0_small_factors', 'b', ossl_bn_get0_small_factors, b);
_err:
    BN_free(b);
    Result := ret;
end;


function setup_tests:integer;
begin
    ctx := BN_CTX_new();
    if 0>=TEST_ptr('ctx = BN_CTX_new', ctx) then
        Exit(0);
    ADD_TEST('test_is_prime_enhanced', test_is_prime_enhanced);
    ADD_ALL_TESTS('test_is_composite_enhanced', test_is_composite_enhanced, Length(composites), 1);
    ADD_TEST('test_bn_small_factors', test_bn_small_factors);
    Result := 1;
end;


procedure cleanup_tests;
begin
    BN_CTX_free(ctx);
end;




end.

