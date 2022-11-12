unit drbgtest;

{$I config.inc}
interface
uses openssl.api, SysUtils, DateUtils;

function setup_tests:integer;

implementation
uses openssl3.test.testutil.Tests,    openssl3.crypto.rsa.rsa_lib,
     OpenSSL3.crypto.rsa.rsa_crpt,    openssl3.crypto.bn.bn_lib,
     openssl3.test.testutil.driver,   openssl3.crypto.rand.rand_lib,
     openssl3.crypto.rand.rand_meth,  openssl3.crypto.evp.evp_rand,
     openssl3.crypto.params,          openssl3.crypto.initthread,
     OpenSSL3.providers.implementations.rands.drbg,
     {$if defined(MSWINDOWS)} windows, {$ENDIF} OpenSSL3.Err,
     OpenSSL3.providers.implementations.rands.drbg_hash ;

{static}function gen_bytes( drbg : PEVP_RAND_CTX; buf : PByte; num : integer):integer;
var
  meth : PRAND_METHOD ;
begin
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    meth := RAND_get_rand_method;
    if (meth <> nil)  and  (meth <> RAND_OpenSSL()) then
    begin
        if Assigned(meth.bytes) then
            Exit(meth.bytes(buf, num));
        Exit(-1);
    end;
{$ENDIF}
    if drbg <> nil then
       Exit(EVP_RAND_generate(drbg, buf, num, 0, 0, nil, 0));
    Result := 0;
end;


{static}function rand_bytes( buf : PByte; num : integer):integer;
begin
    Result := gen_bytes(RAND_get0_public(nil), buf, num);
end;


{static}function rand_priv_bytes( buf : PByte; num : integer):integer;
begin
    Result := gen_bytes(RAND_get0_private(nil), buf, num);
end;


{static}function state( drbg : PEVP_RAND_CTX):integer;
begin
    Result := EVP_RAND_get_state(drbg);
end;


{static}function query_rand_uint(drbg : PEVP_RAND_CTX;const name : PUTF8Char):uint32;
var
  params : array[0..1] of TOSSL_PARAM;
  n : uint32;
begin
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END ;

    params[0] := OSSL_PARAM_construct_uint(name, @n);
    if EVP_RAND_CTX_get_params(drbg, @params) > 0 then
        Exit(n);
    Result := 0;
end;

function prov_rand( drbg : PEVP_RAND_CTX):PPROV_DRBG;
begin
    Result := PPROV_DRBG(drbg.algctx);
end;

procedure set_reseed_counter( drbg : PEVP_RAND_CTX; n : uint32);
var
  p : PPROV_DRBG;
begin
    p := prov_rand(drbg);
    p.reseed_counter := n;
end;

function reseed_counter( drbg : PEVP_RAND_CTX):uint32;
begin
   Result := query_rand_uint(drbg, 'reseed_counter');
end;

procedure inc_reseed_counter( drbg : PEVP_RAND_CTX);
begin
    set_reseed_counter(drbg, reseed_counter(drbg) + 1);
end;


function reseed_time( drbg : PEVP_RAND_CTX):time_t;
var
  params : array[0..1] of TOSSL_PARAM;
  t : time_t;
begin
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;

    params[0] := OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME, @t);
    if EVP_RAND_CTX_get_params(drbg, @params) > 0 then
        Exit(t);
    Result := 0;
end;

(*
 * When building the FIPS module, it isn't possible to disable the continuous
 * RNG tests.  Tests that require this are skipped.
 *)
function crngt_skip:integer;
begin
{$IFDEF FIPS_MODULE}
    Exit(1);
{$ELSE}
    Exit(0);
{$ENDIF}
end;

(*
 * Disable CRNG testing if it is enabled.
 * This stub remains to indicate the calling locations where it is necessary.
 * Once the RNG infrastructure is able to disable these tests, it should be
 * reconstituted.
 *)
function disable_crngt( drbg : PEVP_RAND_CTX):integer;
begin
    Result := 1;
end;

const RANDOM_SIZE = 16;
(*
 * Generates random output using rand_bytes() and rand_priv_bytes()
 * and checks whether the three shared DRBGs were reseeded as
 * expected.
 *
 * |expect_success|: expected outcome (as reported by RAND_status())
 * |primary|, |public|, |private|: pointers to the three shared DRBGs
 * |public_random|, |private_random|: generated random output
 * |expect_xxx_reseed| =
 *       1:  it is expected that the specified DRBG is reseeded
 *       0:  it is expected that the specified DRBG is not reseeded
 *      -1:  don't check whether the specified DRBG was reseeded or not
 * |reseed_when|: if nonzero, used instead of time(NULL) to set the
 *                |before_reseed| time.
 *)
function test_drbg_reseed( expect_success : integer; primary, _public, _private : PEVP_RAND_CTX; public_random, private_random : PByte; expect_primary_reseed, expect_public_reseed, expect_private_reseed : integer; reseed_when : time_t):integer;
var
  before_reseed,
  after_reseed   : time_t;
  expected_state : integer;
  primary_reseed,
  public_reseed,
  private_reseed : uint32;
  dummy          : array[0..(RANDOM_SIZE)-1] of Byte;
begin
    expected_state := get_result(expect_success > 0, Int(DRBG_READY) , Int(DRBG_ERROR));
    if public_random = nil then
       public_random := @dummy;
    if private_random = nil then
       private_random := @dummy;
    {
     * step 1: check preconditions
     }
    { Test whether seed propagation is enabled }
    primary_reseed := reseed_counter(primary);
    public_reseed := reseed_counter(_public);
    private_reseed := reseed_counter(_private);
    if (0>=TEST_int_ne('primary_reseed = reseed_counter(primary)' , '0', primary_reseed, 0))
         or  (0>=TEST_int_ne('public_reseed = reseed_counter(public)', '0', public_reseed, 0))
         or  (0>=TEST_int_ne('private_reseed = reseed_counter(private)', '0', private_reseed, 0)) then
        Exit(0);
    {
     * step 2: generate random output
     }
    if reseed_when = 0 then
       reseed_when := DateTimeToUnix(Now);
    { Generate random output from the public and private DRBG }
    before_reseed := get_result(expect_primary_reseed = 1 , reseed_when , 0);
    if (0>=TEST_int_eq('rand_bytes(public_random, RANDOM_SIZE)', 'expect_success',
                       rand_bytes(public_random, RANDOM_SIZE), expect_success))
         or  (0>=TEST_int_eq('rand_priv_bytes(private_random, RANDOM_SIZE)', 'expect_success',
                              rand_priv_bytes(private_random, RANDOM_SIZE), expect_success)) then
        Exit(0);
    after_reseed := DateTimeToUnix(Now);
    {
     * step 3: check postconditions
     }
    { Test whether reseeding succeeded as expected }
    if (0>=TEST_int_eq('state(primary)' , 'expected_state', state(primary) , expected_state))
         or  (0>=TEST_int_eq('state(public)', 'expected_state', state(_public), expected_state))
         or  (0>=TEST_int_eq('state(private)', 'expected_state', state(_private), expected_state)) then
        Exit(0);
    if expect_primary_reseed >= 0 then begin
        { Test whether primary DRBG was reseeded as expected }
        if 0>=TEST_int_ge('reseed_counter(primary)', 'primary_reseed',reseed_counter(primary), primary_reseed) then
            Exit(0);
    end;
    if expect_public_reseed >= 0 then begin
        { Test whether public DRBG was reseeded as expected }
        if (0>=TEST_int_ge('reseed_counter(public)', 'public_reseed', reseed_counter(_public), public_reseed))
           or  (0>=TEST_uint_ge('reseed_counter(public)', 'reseed_counter(primary)',
                                 reseed_counter(_public), reseed_counter(primary))) then
            Exit(0);
    end;
    if expect_private_reseed >= 0 then begin
        { Test whether public DRBG was reseeded as expected }
        if (0>=TEST_int_ge('reseed_counter(private)', 'private_reseed', reseed_counter(_private), private_reseed))
           or  (0>=TEST_uint_ge('reseed_counter(_private)', 'reseed_counter(primary)',
                                reseed_counter(_private), reseed_counter(primary))) then
            Exit(0);
    end;
    if expect_success = 1 then begin
        { Test whether reseed time of primary DRBG is set correctly }
        if (0>=TEST_time_t_le('before_reseed', 'reseed_time(primary)', before_reseed, reseed_time(primary)))
             or  (0>=TEST_time_t_le('reseed_time(primary)', 'after_reseed',reseed_time(primary), after_reseed)) then
            Exit(0);
        { Test whether reseed times of child DRBGs are synchronized with primary }
        if (0>=TEST_time_t_ge('reseed_time(public)' , 'reseed_time(primary)',
                     reseed_time(_public) , reseed_time(primary)))   or
           (0>=TEST_time_t_ge('reseed_time(private)', 'reseed_time(primary)',
                   reseed_time(_private), reseed_time(primary))) then
            Exit(0);
    end
    else begin
        ERR_clear_error;
    end;
    Result := 1;
end;

function test_rand_reseed:integer;
var
  primary,
  _public,
  _private       : PEVP_RAND_CTX;
  rand_add_buf  : array[0..255] of Byte;
  rv            : integer;
  before_reseed : time_t;
  label _error;
begin
    rv := 0;
    if crngt_skip > 0 then
       Exit(TEST_skip('CRNGT cannot be disabled', []));
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    { Check whether RAND_OpenSSL is the default method }
    if 0>=TEST_ptr_eq('RAND_get_rand_method', 'RAND_OpenSSL', RAND_get_rand_method, RAND_OpenSSL) then
        Exit(0);
{$ENDIF}
    { All three DRBGs should be non-null }
    primary := RAND_get0_primary(nil);
    _public := RAND_get0_public(nil);
    _private := RAND_get0_private(nil);
    if (0>=TEST_ptr('primary = RAND_get0_primary(nil)', primary))
         or  (0>=TEST_ptr('public = RAND_get0_public(nil)', _public))
         or  (0>=TEST_ptr('private = RAND_get0_private(nil)', _private)) then
        Exit(0);
    { There should be three distinct DRBGs, two of them chained to primary }
    if (0>=TEST_ptr_ne('public', 'private', _public, _private))  or
       (0>=TEST_ptr_ne('public', 'primary', _public, primary))
         or  (0>=TEST_ptr_ne('private', 'primary', _private, primary))
         or  (0>=TEST_ptr_eq('prov_rand(public).parent', 'prov_rand(primary)', prov_rand(_public).parent, prov_rand(primary)))
         or  (0>=TEST_ptr_eq('prov_rand(private).parent', 'prov_rand(primary)', prov_rand(_private).parent, prov_rand(primary))) then
        Exit(0);
    { Disable CRNG testing for the primary DRBG }
    if 0>=TEST_true('disable_crngt(primary)', disable_crngt(primary))then
        Exit(0);
    { uninstantiate the three global DRBGs }
    EVP_RAND_uninstantiate(primary);
    EVP_RAND_uninstantiate(_private);
    EVP_RAND_uninstantiate(_public);
    {
     * Test initial seeding of shared DRBGs
     }
    if 0>=TEST_true('test_drbg_reseed', test_drbg_reseed(1,
                                    primary, _public, _private,
                                    nil, nil,
                                    1, 1, 1, 0)) then
        goto _error;
    {
     * Test initial state of shared DRBGs
     }
    if 0>=TEST_true('test_drbg_reseed', test_drbg_reseed(1,
                                    primary, _public, _private,
                                    nil, nil,
                                    0, 0, 0, 0) ) then
        goto _error;
    {
     * Test whether the public and private DRBG are both reseeded when their
     * reseed counters differ from the primary's reseed counter.
     }
    inc_reseed_counter(primary);
    if 0>=TEST_true('test_drbg_reseed', test_drbg_reseed(1,
                                    primary, _public, _private,
                                    nil, nil,
                                    0, 1, 1, 0)) then
        goto _error;
    {
     * Test whether the public DRBG is reseeded when its reseed counter differs
     * from the primary's reseed counter.
     }
    inc_reseed_counter(primary);
    inc_reseed_counter(_private);
    if 0>=TEST_true('test_drbg_reseed', test_drbg_reseed(1,
                                    primary, _public, _private,
                                    nil, nil,
                                    0, 1, 0, 0 ))then
        goto _error;
    {
     * Test whether the private DRBG is reseeded when its reseed counter differs
     * from the primary's reseed counter.
     }
    inc_reseed_counter(primary);
    inc_reseed_counter(_public);
    if 0>=TEST_true('test_drbg_reseed', test_drbg_reseed(1,
                                    primary, _public, _private,
                                    nil, nil,
                                    0, 0, 1, 0)) then
        goto _error;
    { fill 'randomness' buffer with some arbitrary data }
    memset(@rand_add_buf, Ord('r'), sizeof(rand_add_buf));
{$IFNDEF FIPS_MODULE}
    {
     * Test whether all three DRBGs are reseeded by RAND_add.
     * The before_reseed time has to be measured here and passed into the
     * test_drbg_reseed test, because the primary DRBG gets already reseeded
     * in RAND_add, whence the check for the condition
     * before_reseed <= reseed_time(primary) will fail if the time value happens
     * to increase between the RAND_add and the test_drbg_reseed call.
     }
    before_reseed := datetimetounix(Now);
    RAND_add(@rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if 0>=TEST_true('test_drbg_reseed', test_drbg_reseed(1,
                                    primary, _public, _private,
                                    nil, nil,
                                    1, 1, 1,
                                    before_reseed)) then
        goto _error;
{$ELSE} { FIPS_MODULE }
    {
     * In FIPS mode, random data provided by the application via RAND_add
     * is not considered a trusted entropy source. It is only treated as
     * additional_data and no reseeding is forced. This test assures that
     * no reseeding occurs.
     }
    before_reseed := time(nil);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if 0>=TEST_true(test_drbg_reseed(1,
                                    primary, public, private,
                                    nil, nil,
                                    0, 0, 0,
                                    before_reseed then ))
        goto _error;
{$ENDIF}
    rv := 1;

_error:
   Result := rv;
end;

{$if defined(OPENSSL_THREADS)}
var
 multi_thread_rand_bytes_succeeded: int = 1;
 multi_thread_rand_priv_bytes_succeeded: int = 1;

function set_reseed_time_interval( drbg : PEVP_RAND_CTX; t : integer):integer;
var
  params : array[0..1] of TOSSL_PARAM;
begin
    params[0] := OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, @t);
    params[1] := OSSL_PARAM_construct_end;
    Result := EVP_RAND_CTX_set_params(drbg, @params);
end;


procedure run_multi_thread_test;
var
  buf : array[0..255] of Byte;
  start : time_t;
  _public, _private : PEVP_RAND_CTX;
begin
    start := DateTimeToUnix(Now);
    _public := nil; _private := nil;
    _public := RAND_get0_public(nil);
    _private := RAND_get0_private(nil);
    if (0>=TEST_ptr('public = RAND_get0_public(nil)', _public))
       or  (0>=TEST_ptr('private = RAND_get0_private(nil)', _private))
       or  (0>=TEST_true('set_reseed_time_interval(_private, 1)', set_reseed_time_interval(_private, 1)))
       or  (0>=TEST_true('set_reseed_time_interval(_public, 1)', set_reseed_time_interval(_public, 1))) then
    begin
        multi_thread_rand_bytes_succeeded := 0;
        exit;
    end;
    repeat
        if rand_bytes(@buf, sizeof(buf)) <= 0  then
            multi_thread_rand_bytes_succeeded := 0;
        if rand_priv_bytes(@buf, sizeof(buf)) <= 0  then
            multi_thread_rand_priv_bytes_succeeded := 0;
    until not (DatetimeToUnix(Now) - start < 5) ;
end;

{$if defined(MSWINDOWS)}
type  thread_t = THandle;
      Pthread_t = ^thread_t;

function thread_run( arg : LPVOID):DWORD; stdcall;
begin
    run_multi_thread_test;
    {
     * Because we're linking with a   library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     }
    OPENSSL_thread_stop;
    Result := 0;
end;

function run_thread(t : Pthread_t):integer;
var
  p : TFNThreadStartRoutine;
  threadid: uint32;
begin
    t^ := CreateThread(nil, 0, @thread_run, nil, 0, threadid);
    Result := Int(t^ <> 0);
end;

function wait_for_thread( thread : thread_t):integer;
begin
    Result := Int(WaitForSingleObject(thread, INFINITE) = 0);
end;
{$ELSE}

function thread_run( arg : Pointer):Pointer;
begin
    run_multi_thread_test;
    {
     * Because we're linking with a   library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     }
    OPENSSL_thread_stop;
    Result := nil;
end;


function run_thread(var t : thread_t):integer;
begin
    Result := pthread_create(t, nil, thread_run, nil) = 0;
end;


function wait_for_thread( thread : thread_t):integer;
begin
    Result := pthread_join(thread, nil) = 0;
end;
{$endif}

(*
 * The main thread will also run the test, so we'll have THREADS+1 parallel
 * tests running
 *)
const THREADS = 1;

function test_multi_thread:integer;
var
  t : array[0..(THREADS)-1] of thread_t;
  i : integer;
begin
    for i := 0 to THREADS-1 do
        run_thread(@t[i]);
    run_multi_thread_test;
    for i := 0 to THREADS-1 do
       wait_for_thread(t[i]);
    if 0>=TEST_true('multi_thread_rand_bytes_succeeded', multi_thread_rand_bytes_succeeded) then
        Exit(0);
    if 0>=TEST_true('multi_thread_rand_priv_bytes_succeeded', multi_thread_rand_priv_bytes_succeeded) then
        Exit(0);
    Result := 1;
end;
{$ENDIF}

function new_drbg( parent : PEVP_RAND_CTX):PEVP_RAND_CTX;
var
  params : array[0..1] of TOSSL_PARAM;
  rand : PEVP_RAND;
  drbg : PEVP_RAND_CTX;
begin
    rand := nil;
    drbg := nil;
    params[0] := OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                 'AES-256-CTR', 0);
    params[1] := OSSL_PARAM_construct_end;
    rand := EVP_RAND_fetch(nil, 'CTR-DRBG', nil);
    drbg := EVP_RAND_CTX_new(rand, parent);
    if (0>=TEST_ptr('rand = EVP_RAND_fetch(nil, ''CTR-DRBG'', nil', rand))
       or  (0>=TEST_ptr('drbg = EVP_RAND_CTX_new(rand, parent)', drbg))
       or  (0>=TEST_true('EVP_RAND_CTX_set_params(drbg, params)', EVP_RAND_CTX_set_params(drbg, @params))) then
    begin
        EVP_RAND_CTX_free(drbg);
        drbg := nil;
    end;
    EVP_RAND_free(rand);
    Result := drbg;
end;

function test_rand_prediction_resistance:integer;
var
  x, y, z : PEVP_RAND_CTX;
  buf1, buf2 : array[0..50] of Byte;
  ret, xreseed, yreseed, zreseed : integer;
  label _err;
begin
    x := nil; y := nil; z := nil;
    ret := 0;
    if crngt_skip > 0 then
       Exit(TEST_skip('CRNGT cannot be disabled', []));
    { Initialise a three long DRBG chain }
    x := new_drbg(nil);
    y := new_drbg(x);
    z := new_drbg(y);
    if (0>=TEST_ptr('x = new_drbg(nil)', x))
         or  (0>=TEST_true('disable_crngt(x)', disable_crngt(x)))
         or  (0>=TEST_true('EVP_RAND_instantiate(x, 0, 0, nil, 0, nil)', EVP_RAND_instantiate(x, 0, 0, nil, 0, nil)))
         or  (0>=TEST_ptr('y = new_drbg(x)', y))
         or  (0>=TEST_true('EVP_RAND_instantiate(y, 0, 0, nil, 0, nil)', EVP_RAND_instantiate(y, 0, 0, nil, 0, nil)))
         or  (0>=TEST_ptr('z = new_drbg(y)', z))
         or  (0>=TEST_true('EVP_RAND_instantiate(z, 0, 0, nil, 0, nil)', EVP_RAND_instantiate(z, 0, 0, nil, 0, nil))) then
        goto _err;
    {
     * During a normal reseed, only the last DRBG in the chain should
     * be reseeded.
     }
    inc_reseed_counter(y);
    xreseed := reseed_counter(x);
    yreseed := reseed_counter(y);
    zreseed := reseed_counter(z);
    if (0>=TEST_true('EVP_RAND_reseed(z, 0, nil, 0, nil, 0', EVP_RAND_reseed(z, 0, nil, 0, nil, 0)))
         or  (0>=TEST_int_eq('reseed_counter(x)', 'xreseed', reseed_counter(x), xreseed))
         or  (0>=TEST_int_eq('reseed_counter(y)', 'yreseed', reseed_counter(y), yreseed))
         or  (0>=TEST_int_gt('reseed_counter(z)', 'zreseed)',reseed_counter(z), zreseed)) then
        goto _err;
    {
     * When prediction resistance is requested, the request should be
     * propagated to the primary, so that the entire DRBG chain reseeds.
     }
    zreseed := reseed_counter(z);
    if (0>=TEST_true('EVP_RAND_reseed(z, 1, nil, 0, nil, 0', EVP_RAND_reseed(z, 1, nil, 0, nil, 0) ))
         or  (0>=TEST_int_gt('reseed_counter(x)', 'xreseed', reseed_counter(x), xreseed))
         or  (0>=TEST_int_gt('reseed_counter(y)', 'yreseed', reseed_counter(y), yreseed))
         or  (0>=TEST_int_gt('reseed_counter(z)', 'zreseed', reseed_counter(z), zreseed)) then
        goto _err;
    {
     * During a normal generate, only the last DRBG should be reseed }
    inc_reseed_counter(y);
    xreseed := reseed_counter(x);
    yreseed := reseed_counter(y);
    zreseed := reseed_counter(z);
    if (0>=TEST_true('EVP_RAND_generate(z, @buf1, sizeof(buf1) , 0, 0, nil, 0)', EVP_RAND_generate(z, @buf1, sizeof(buf1) , 0, 0, nil, 0)))
         or  (0>=TEST_int_eq('reseed_counter(x)', 'xreseed', reseed_counter(x), xreseed))
         or  (0>=TEST_int_eq('reseed_counter(y)', 'yreseed', reseed_counter(y), yreseed))
         or  (0>=TEST_int_gt('reseed_counter(z)', 'zreseed', reseed_counter(z), zreseed)) then
        goto _err;
    {
     * When a prediction resistant generate is requested, the request
     * should be propagated to the primary, reseeding the entire DRBG chain.
     }
    zreseed := reseed_counter(z);
    if (0>=TEST_true('EVP_RAND_generate(z, buf2, sizeof(buf2) , 0, 1, nil, 0)', EVP_RAND_generate(z, @buf2, sizeof(buf2) , 0, 1, nil, 0)))
         or  (0>=TEST_int_gt('reseed_counter(x)', 'xreseed', reseed_counter(x), xreseed))
         or  (0>=TEST_int_gt('reseed_counter(y)', 'yreseed', reseed_counter(y), yreseed))
         or  (0>=TEST_int_gt('reseed_counter(z)', 'zreseed', reseed_counter(z), zreseed))
         or  (0>=TEST_mem_ne('buf1', 'sizeof(buf1)', @buf1, sizeof(buf1), @buf2, sizeof(buf2))) then
        goto _err;
    { Verify that a normal reseed still only reseeds the last DRBG }
    inc_reseed_counter(y);
    xreseed := reseed_counter(x);
    yreseed := reseed_counter(y);
    zreseed := reseed_counter(z);
    if (0>=TEST_true('EVP_RAND_reseed(z, 0, nil, 0, nil, 0 )', EVP_RAND_reseed(z, 0, nil, 0, nil, 0)) )
         or  (0>=TEST_int_eq('reseed_counter(x)', 'xreseed', reseed_counter(x), xreseed))
         or  (0>=TEST_int_eq('reseed_counter(y)', 'yreseed', reseed_counter(y), yreseed))
         or  (0>=TEST_int_gt('reseed_counter(z)', 'zreseed', reseed_counter(z), zreseed)) then
        goto _err;
    ret := 1;

_err:
    EVP_RAND_CTX_free(z);
    EVP_RAND_CTX_free(y);
    EVP_RAND_CTX_free(x);
    Result := ret;
end;


function setup_tests:integer;
begin
    ADD_TEST('test_rand_reseed', test_rand_reseed);
{$IF defined(OPENSSL_SYS_UNIX)}
    ADD_ALL_TESTS(test_rand_fork_safety, RANDOM_SIZE);
{$ENDIF}
    ADD_TEST('test_rand_prediction_resistance', test_rand_prediction_resistance);
{$IF defined(OPENSSL_THREADS)}
    //ADD_TEST('test_multi_thread', test_multi_thread);
{$ENDIF}
    Result := 1;
end;

end.
