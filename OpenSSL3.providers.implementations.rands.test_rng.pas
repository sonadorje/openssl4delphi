unit OpenSSL3.providers.implementations.rands.test_rng;

interface
uses  OpenSSL.Api, DateUtils, SysUtils,
      OpenSSL3.providers.implementations.rands.drbg;

function test_rng_new(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
procedure test_rng_free( vtest : Pointer);
 function test_rng_instantiate(vtest : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
 function test_rng_uninstantiate( vtest : Pointer):integer;
function test_rng_generate(vtest : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
function test_rng_reseed(vtest : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
function test_rng_nonce( vtest : Pointer; _out : PByte; strength : uint32; min_noncelen, max_noncelen : size_t):size_t;
function test_rng_enable_locking( vtest : Pointer):integer;
function test_rng_lock( vtest : Pointer):integer;
procedure test_rng_unlock( vtest : Pointer);
function test_rng_settable_ctx_params( vtest, provctx : Pointer):POSSL_PARAM;
function test_rng_set_ctx_params(vtest : Pointer;const params : POSSL_PARAM):integer;
function test_rng_gettable_ctx_params( vtest, provctx : Pointer):POSSL_PARAM;
function test_rng_get_ctx_params( vtest : Pointer; params : POSSL_PARAM):integer;
function test_rng_verify_zeroization( vtest : Pointer):integer;
function test_rng_get_seed(vtest : Pointer; pout : PPByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer;const adin : PByte; adin_len : size_t):size_t;


const ossl_test_rng_functions: array[0..16] of TOSSL_DISPATCH  = (
    ( function_id: OSSL_FUNC_RAND_NEWCTX; method:(code:@test_rng_new ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_FREECTX; method:(code:@test_rng_free ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_INSTANTIATE; method:(code:@test_rng_instantiate ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNINSTANTIATE; method:(code:@test_rng_uninstantiate ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GENERATE; method:(code:@test_rng_generate ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_RESEED; method:(code:@test_rng_reseed ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_NONCE; method:(code:@test_rng_nonce ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_ENABLE_LOCKING; method:(code:@test_rng_enable_locking ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_LOCK; method:(code:@test_rng_lock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNLOCK; method:(code:@test_rng_unlock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS; method:(code:@test_rng_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS; method:(code:@test_rng_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS; method:(code:@test_rng_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS; method:(code:@test_rng_get_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION; method:(code:@test_rng_verify_zeroization ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_SEED; method:(code:@test_rng_get_seed ;data:nil)),
    ( function_id: 0;  method:(code:nil ;data:nil))
);

implementation
uses OpenSSL3.Err, openssl3.crypto.mem,  openssl3.providers.fips.self_test,
     openssl3.crypto.mem_sec,            openssl3.providers.common.provider_ctx,
     openssl3.crypto.context,            openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,               OpenSSL3.providers.implementations.rands.crngt,
     OpenSSL3.openssl.params,            openssl3.crypto.params,
     OpenSSL3.threads_none,              OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.rand.rand_pool,     OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib,        openssl3.crypto.evp.mac_lib,
     OpenSSL3.providers.implementations.rands.seeding.rand_win;


var // 1d arrays
  known_settable_ctx_params : array[0..4] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..3] of TOSSL_PARAM;


function test_rng_get_seed(vtest : Pointer; pout : PPByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer;const adin : PByte; adin_len : size_t):size_t;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    pout^ := t.entropy;
    Result := get_result(t.entropy_len > max_len , max_len , t.entropy_len);
end;

function test_rng_verify_zeroization( vtest : Pointer):integer;
begin
    Result := 1;
end;

function test_rng_get_ctx_params( vtest : Pointer; params : POSSL_PARAM):integer;
var
  t : PPROV_TEST_RNG;
  p : POSSL_PARAM;
begin
    t := PPROV_TEST_RNG ( vtest);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, t.state )) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, t.strength) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, t.max_request) ) then
        Exit(0);
    Result := 1;
end;

function test_rng_gettable_ctx_params( vtest, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nil);
    known_gettable_ctx_params[1] := _OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nil);
    known_gettable_ctx_params[2] := _OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nil);
    known_gettable_ctx_params[3] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;

function test_rng_set_ctx_params(vtest : Pointer;const params : POSSL_PARAM):integer;
var
  t : PPROV_TEST_RNG;
  p : POSSL_PARAM;
  ptr : Pointer;
  size : size_t;
begin
    t := PPROV_TEST_RNG ( vtest);
    ptr := nil;
    size := 0;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_uint(p, @t.strength) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_ENTROPY);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_octet_string(p, @ptr, 0, @size) then
            Exit(0);
        OPENSSL_free(t.entropy);
        t.entropy := ptr;
        t.entropy_len := size;
        t.entropy_pos := 0;
        ptr := nil;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_NONCE);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_octet_string(p, ptr, 0, @size) then
            Exit(0);
        OPENSSL_free(t.nonce);
        t.nonce := ptr;
        t.nonce_len := size;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p <> nil)   and  (0>= OSSL_PARAM_get_size_t(p, @t.max_request) ) then
        Exit(0);
    Result := 1;
end;

function test_rng_settable_ctx_params( vtest, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nil);
    known_settable_ctx_params[3] := _OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nil);
    known_settable_ctx_params[4] := OSSL_PARAM_END ;

    Result := @known_settable_ctx_params;
end;

procedure test_rng_unlock( vtest : Pointer);
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    if (t <> nil)  and  (t.lock <> nil) then
       CRYPTO_THREAD_unlock(t.lock);
end;

function test_rng_lock( vtest : Pointer):integer;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    if (t = nil)  or  (t.lock = nil) then Exit(1);
    Result := CRYPTO_THREAD_write_lock(t.lock);
end;

function test_rng_enable_locking( vtest : Pointer):integer;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG (vtest);
    if (t <> nil)  and  (t.lock = nil) then
    begin
        t.lock := CRYPTO_THREAD_lock_new();
        if t.lock = nil then
        begin
            ERR_raise(ERR_LIB_PROV, RAND_R_FAILED_TO_CREATE_LOCK);
            Exit(0);
        end;
    end;
    Result := 1;
end;

function test_rng_nonce( vtest : Pointer; _out : PByte; strength : uint32; min_noncelen, max_noncelen : size_t):size_t;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    if (t.nonce = nil)  or  (strength > t.strength) then Exit(0);
    if _out <> nil then
       memcpy(_out, t.nonce, t.nonce_len);
    Result := t.nonce_len;
end;

function test_rng_reseed(vtest : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
begin
    Result := 1;
end;

function test_rng_generate(vtest : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    if (strength > t.strength) or (t.entropy_len - t.entropy_pos < outlen) then
       Exit(0);
    memcpy(_out, t.entropy + t.entropy_pos, outlen);
    t.entropy_pos  := t.entropy_pos + outlen;
    Result := 1;
end;

function test_rng_uninstantiate( vtest : Pointer):integer;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    t.entropy_pos := 0;
    t.state := EVP_RAND_STATE_UNINITIALISED;
    Result := 1;
end;

function test_rng_instantiate(vtest : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    if (0>= test_rng_set_ctx_params(t, params))   or  (strength > t.strength) then
        Exit(0);
    t.state := EVP_RAND_STATE_READY;
    t.entropy_pos := 0;
    Result := 1;
end;

procedure test_rng_free( vtest : Pointer);
var
  t : PPROV_TEST_RNG;
begin
    t := PPROV_TEST_RNG ( vtest);
    if t = nil then exit;
    OPENSSL_free(t.entropy);
    OPENSSL_free(t.nonce);
    CRYPTO_THREAD_lock_free(t.lock);
    OPENSSL_free(t);
end;

function test_rng_new(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
var
  t : PPROV_TEST_RNG;
begin
    t := OPENSSL_zalloc(sizeof( t^));
    if t = nil then Exit(nil);
    t.max_request := INT_MAX;
    t.provctx := provctx;
    t.state := EVP_RAND_STATE_UNINITIALISED;
    Result := t;
end;

end.
