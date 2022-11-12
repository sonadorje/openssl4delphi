unit OpenSSL3.providers.implementations.rands.seed_src;

interface
uses  OpenSSL.Api, DateUtils, SysUtils,
    OpenSSL3.providers.implementations.rands.drbg;

function seed_src_new(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
procedure seed_src_free( vseed : Pointer);
function seed_src_instantiate(vseed : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
function seed_src_uninstantiate( vseed : Pointer):integer;
function seed_src_generate(vseed : Pointer; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
function seed_src_reseed(vseed : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
function seed_src_enable_locking( vseed : Pointer):integer;
function seed_src_lock( vctx : Pointer):integer;
procedure seed_src_unlock( vctx : Pointer);
function seed_src_gettable_ctx_params( vseed, provctx : Pointer):POSSL_PARAM;
function seed_src_get_ctx_params( vseed : Pointer; params : POSSL_PARAM):integer;
function seed_src_verify_zeroization( vseed : Pointer):integer;
function seed_get_seed(vseed : Pointer;out pout : PByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer;const adin : PByte; adin_len : size_t):size_t;
procedure seed_clear_seed( vdrbg : Pointer; _out : PByte; outlen : size_t);


const  ossl_seed_src_functions: array[0..14] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_RAND_NEWCTX; method:(code:@seed_src_new ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_FREECTX; method:(code:@seed_src_free ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_INSTANTIATE;  method:(code:@seed_src_instantiate ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNINSTANTIATE; method:(code:@seed_src_uninstantiate ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GENERATE; method:(code:@seed_src_generate ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_RESEED; method:(code:@seed_src_reseed ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_ENABLE_LOCKING; method:(code:@seed_src_enable_locking ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_LOCK; method:(code:@seed_src_lock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNLOCK; method:(code:@seed_src_unlock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS; method:(code:@seed_src_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS; method:(code:@seed_src_get_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION; method:(code:@seed_src_verify_zeroization ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_SEED; method:(code:@seed_get_seed ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_CLEAR_SEED; method:(code:@seed_clear_seed ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil))
);

implementation
uses openssl3.crypto.mem_sec,           openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.crypto.mem, openssl3.providers.common.provider_ctx,
     openssl3.crypto.context,           openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,              openssl3.crypto.rand.rand_pool,
     OpenSSL3.openssl.params,           openssl3.crypto.params,
     OpenSSL3.threads_none,             OpenSSL3.openssl.core_dispatch,
     OpenSSL3.providers.common.provider_util,
     OpenSSL3.providers.implementations.rands.crngt,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib,
     OpenSSL3.providers.implementations.rands.seeding.rand_win;


var // 1d arrays
  known_settable_ctx_params : array[0..5] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..3] of TOSSL_PARAM;


procedure seed_clear_seed( vdrbg : Pointer; _out : PByte; outlen : size_t);
begin
    //OPENSSL_secure_clear_free(_out, outlen);
    if Length(TBytes(_out)) = outlen then
       SetLength(TBytes(_out), 0);
end;

function seed_get_seed(vseed : Pointer;out pout : PByte; entropy : integer;
                       min_len, max_len : size_t; prediction_resistance : integer;
                       const adin : PByte; adin_len : size_t):size_t;
var
    bytes_needed : size_t;
    //p            : TBytes;
begin
    {
     * Figure out how many bytes we need.
     * This assumes that the seed sources provide eight bits of entropy
     * per byte.  For lower quality sources, the formula will need to be
     * different.
     }
    bytes_needed := get_result( entropy >= 0 , (entropy + 7) div 8 , 0);
    if bytes_needed < min_len then bytes_needed := min_len;
    if bytes_needed > max_len then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK);
        Exit(0);
    end;
    //p := OPENSSL_secure_malloc(bytes_needed);
    SetLength(TBytes(pout),bytes_needed);
    if pout = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if seed_src_generate(vseed, @pout[0], bytes_needed, 0, prediction_resistance,
                          adin, adin_len) <> 0 then
    begin
        //pout := Pbyte(p);
        Exit(bytes_needed);
    end;
    OPENSSL_secure_clear_free(pout, bytes_needed);

    Result := 0;
end;

function seed_src_verify_zeroization( vseed : Pointer):integer;
begin
    Result := 1;
end;

function seed_src_get_ctx_params( vseed : Pointer; params : POSSL_PARAM):integer;
var
  s : PPROV_SEED_SRC;
  p : POSSL_PARAM;
begin
    s := PPROV_SEED_SRC ( vseed);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, s.state) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, 1024) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, 128) ) then
        Exit(0);
    Result := 1;
end;

function seed_src_gettable_ctx_params( vseed, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nil);
    known_gettable_ctx_params[1] := _OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nil);
    known_gettable_ctx_params[2] := _OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nil) ;
    known_gettable_ctx_params[3] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;

procedure seed_src_unlock( vctx : Pointer);
begin
    //TODO
end;

function seed_src_lock( vctx : Pointer):integer;
begin
    Result := 1;
end;

function seed_src_enable_locking( vseed : Pointer):integer;
begin
    Result := 1;
end;

function seed_src_reseed(vseed : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
var
  s : PPROV_SEED_SRC;
begin
    s := PPROV_SEED_SRC ( vseed);
    if s.state <> EVP_RAND_STATE_READY then
    begin
        ERR_raise(ERR_LIB_PROV,
                 get_result(s.state = EVP_RAND_STATE_ERROR, PROV_R_IN_ERROR_STATE
                                                   , PROV_R_NOT_INSTANTIATED));
        Exit(0);
    end;
    Result := 1;
end;


//参数adin, adin_len无用
function seed_src_generate(vseed : Pointer; _out : PByte; outlen : size_t;
                           strength : uint32; prediction_resistance : integer;
                           const adin : PByte; adin_len : size_t):integer;
var
    src               : PPROV_SEED_SRC;
    entropy_available : size_t;
    pool              : PRAND_POOL;
begin
    src := PPROV_SEED_SRC(vseed);
    if src.state <> EVP_RAND_STATE_READY then
    begin
        ERR_raise(ERR_LIB_PROV,
                  get_result(src.state = EVP_RAND_STATE_ERROR , PROV_R_IN_ERROR_STATE
                                                   , PROV_R_NOT_INSTANTIATED));
        Exit(0);
    end;
    pool := ossl_rand_pool_new(strength, 1, outlen, outlen);
    if pool = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    { Get entropy by polling system entropy sources. }
    entropy_available := ossl_pool_acquire_entropy(pool);
    if entropy_available > 0 then
       memcpy(_out, ossl_rand_pool_buffer(pool), ossl_rand_pool_length(pool));
    ossl_rand_pool_free(pool);
    Result := Int(entropy_available > 0);
end;

function seed_src_uninstantiate( vseed : Pointer):integer;
var
  s : PPROV_SEED_SRC;
begin
    s := PPROV_SEED_SRC ( vseed);
    s.state := EVP_RAND_STATE_UNINITIALISED;
    Result := 1;
end;

function seed_src_instantiate(vseed : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
var
  src : PPROV_SEED_SRC;
begin
    src := PPROV_SEED_SRC ( vseed);
    src.state := EVP_RAND_STATE_READY;
    Result := 1;
end;

procedure seed_src_free( vseed : Pointer);
begin
    OPENSSL_free(vseed);
end;

function seed_src_new(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
var
  seed : PPROV_SEED_SRC;
begin
    if parent <> nil then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
        Exit(nil);
    end;
    seed := OPENSSL_zalloc(sizeof( seed^));
    if seed = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    seed.provctx := provctx;
    seed.state := EVP_RAND_STATE_UNINITIALISED;
    Result := seed;
end;

end.
