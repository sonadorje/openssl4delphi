unit openssl3.crypto.evp.evp_rand;

interface
uses OpenSSL.Api;

procedure EVP_RAND_CTX_free( ctx : PEVP_RAND_CTX);
procedure EVP_RAND_free(rand : PEVP_RAND);
function EVP_RAND_fetch(libctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_RAND;
function evp_rand_from_algorithm( name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_rand_new:Pointer;
function evp_rand_up_ref( vrand : Pointer):integer;
function EVP_RAND_CTX_new( rand : PEVP_RAND; parent : PEVP_RAND_CTX):PEVP_RAND_CTX;
function evp_rand_ctx_up_ref( ctx : PEVP_RAND_CTX):integer;
function EVP_RAND_instantiate(ctx : PEVP_RAND_CTX; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
function evp_rand_lock( rand : PEVP_RAND_CTX):integer;
function evp_rand_instantiate_locked(ctx : PEVP_RAND_CTX; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
procedure evp_rand_unlock( rand : PEVP_RAND_CTX);
function EVP_RAND_CTX_settable_params( ctx : PEVP_RAND_CTX):POSSL_PARAM;
function EVP_RAND_get0_provider(const rand : PEVP_RAND):POSSL_PROVIDER;
function EVP_RAND_enable_locking( rand : PEVP_RAND_CTX):integer;
function EVP_RAND_generate(ctx : PEVP_RAND_CTX; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const addin : PByte; addin_len : size_t):integer;
function evp_rand_generate_locked(ctx : PEVP_RAND_CTX; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const addin : PByte; addin_len : size_t):integer;
function evp_rand_get_ctx_params_locked( ctx : PEVP_RAND_CTX; params : POSSL_PARAM):integer;
function EVP_RAND_get_state( ctx : PEVP_RAND_CTX):integer;
function EVP_RAND_CTX_get_params( ctx : PEVP_RAND_CTX; params : POSSL_PARAM):integer;
function EVP_RAND_reseed(ctx : PEVP_RAND_CTX; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const addin : PByte; addin_len : size_t):integer;
function evp_rand_reseed_locked(ctx : PEVP_RAND_CTX; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const addin : PByte; addin_len : size_t):integer;
function EVP_RAND_CTX_set_params(ctx : PEVP_RAND_CTX;const params : POSSL_PARAM):integer;
function evp_rand_set_ctx_params_locked(ctx : PEVP_RAND_CTX;const params : POSSL_PARAM):integer;
function EVP_RAND_get_strength( ctx : PEVP_RAND_CTX):uint32;
function evp_rand_strength_locked( ctx : PEVP_RAND_CTX):uint32;
function EVP_RAND_uninstantiate( ctx : PEVP_RAND_CTX):integer;
function evp_rand_uninstantiate_locked( ctx : PEVP_RAND_CTX):integer;
function evp_rand_verify_zeroization_locked( ctx : PEVP_RAND_CTX):integer;
function EVP_RAND_verify_zeroization( ctx : PEVP_RAND_CTX):integer;
procedure _evp_rand_free( vrand : Pointer);

implementation

uses openssl3.include.internal.refcount, openssl3.crypto.mem, OpenSSL3.Err,
     openssl3.crypto.evp.evp_fetch,      openssl3.crypto.core_algorithm,
     OpenSSL3.threads_none,              OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.provider_core,      openssl3.crypto.evp.keymgmt_meth,
     OpenSSL3.openssl.params,            openssl3.crypto.params;


procedure _evp_rand_free( vrand : Pointer);
var
  rand : PEVP_RAND;
  ref : integer;
begin
    rand := PEVP_RAND (vrand);
    ref := 0;
    if rand = nil then exit;
    CRYPTO_DOWN_REF(rand.refcnt, ref, rand.refcnt_lock);
    if ref > 0 then exit;
    OPENSSL_free(rand.type_name);
    ossl_provider_free(rand.prov);
    CRYPTO_THREAD_lock_free(rand.refcnt_lock);
    OPENSSL_free(rand);
end;

function evp_rand_verify_zeroization_locked( ctx : PEVP_RAND_CTX):integer;
begin
    if Assigned(ctx.meth.verify_zeroization) then
       Exit(ctx.meth.verify_zeroization(ctx.algctx));
    Result := 0;
end;


function EVP_RAND_verify_zeroization( ctx : PEVP_RAND_CTX):integer;
var
  res : integer;
begin
    if 0>=evp_rand_lock(ctx) then
        Exit(0);
    res := evp_rand_verify_zeroization_locked(ctx);
    evp_rand_unlock(ctx);
    Result := res;
end;



function evp_rand_uninstantiate_locked( ctx : PEVP_RAND_CTX):integer;
begin
    Result := ctx.meth.uninstantiate(ctx.algctx);
end;


function EVP_RAND_uninstantiate( ctx : PEVP_RAND_CTX):integer;
var
  res : integer;
begin
    if 0>=evp_rand_lock(ctx) then
        Exit(0);
    res := evp_rand_uninstantiate_locked(ctx);
    evp_rand_unlock(ctx);
    Result := res;
end;

function evp_rand_strength_locked( ctx : PEVP_RAND_CTX):uint32;
var
    params   : array of TOSSL_PARAM;
    strength : uint32;
begin
    params := [OSSL_PARAM_END, OSSL_PARAM_END];
    strength := 0;
    params[0] := OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, @strength);
    if 0>=evp_rand_get_ctx_params_locked(ctx, @params[0]) then
        Exit(0);
    Result := strength;
end;


function EVP_RAND_get_strength( ctx : PEVP_RAND_CTX):uint32;
var
  res : uint32;
begin
    if 0>=evp_rand_lock(ctx) then
        Exit(0);
    res := evp_rand_strength_locked(ctx);
    evp_rand_unlock(ctx);
    Result := res;
end;

function evp_rand_set_ctx_params_locked(ctx : PEVP_RAND_CTX;const params : POSSL_PARAM):integer;
begin
    if Assigned(ctx.meth.set_ctx_params) then
       Exit(ctx.meth.set_ctx_params(ctx.algctx, params));
    Result := 1;
end;

function EVP_RAND_CTX_set_params(ctx : PEVP_RAND_CTX;const params : POSSL_PARAM):integer;
var
  res : integer;
begin
    if 0>=evp_rand_lock(ctx ) then
        Exit(0);
    res := evp_rand_set_ctx_params_locked(ctx, params);
    evp_rand_unlock(ctx);
    Result := res;
end;

function evp_rand_reseed_locked(ctx : PEVP_RAND_CTX; prediction_resistance : integer;
                                const ent : PByte; ent_len : size_t;
                                const addin : PByte; addin_len : size_t):integer;
begin
    if Assigned(ctx.meth.reseed) then
       Exit(ctx.meth.reseed(ctx.algctx, prediction_resistance,
                                 ent, ent_len, addin, addin_len));
    Result := 1;
end;

function EVP_RAND_reseed(ctx : PEVP_RAND_CTX; prediction_resistance : integer;
                         const ent : PByte; ent_len : size_t;
                         const addin : PByte; addin_len : size_t):integer;
var
  res : integer;
begin
    if 0>=evp_rand_lock(ctx) then
        Exit(0);
    res := evp_rand_reseed_locked(ctx, prediction_resistance,
                                 ent, ent_len, addin, addin_len);
    evp_rand_unlock(ctx);
    Result := res;
end;

function EVP_RAND_CTX_get_params( ctx : PEVP_RAND_CTX; params : POSSL_PARAM):integer;
var
  res : integer;
begin
    if 0>=evp_rand_lock(ctx) then
        Exit(0);
    res := evp_rand_get_ctx_params_locked(ctx, params);
    evp_rand_unlock(ctx);
    Result := res;
end;

function EVP_RAND_get_state( ctx : PEVP_RAND_CTX):integer;
var
  params : array of TOSSL_PARAM;
  state : integer;
begin
    params := [  OSSL_PARAM_END, OSSL_PARAM_END ];
    params[0] := OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, @state);
    if 0>=EVP_RAND_CTX_get_params(ctx, @params[0]) then
        state := EVP_RAND_STATE_ERROR;
    Result := state;
end;

function evp_rand_get_ctx_params_locked( ctx : PEVP_RAND_CTX; params : POSSL_PARAM):integer;
begin
    Result := ctx.meth.get_ctx_params(ctx.algctx, params);
end;

function evp_rand_generate_locked(ctx : PEVP_RAND_CTX; _out : PByte; outlen : size_t;
                                  strength : uint32; prediction_resistance : integer;
                                  const addin : PByte; addin_len : size_t):integer;
var
  chunk,
  max_request : size_t;
  params      : array[0..1] of TOSSL_PARAM;
begin
    max_request := 0;
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;

    params[0] := OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, @max_request);
    if (0>= evp_rand_get_ctx_params_locked(ctx, @params)) or (max_request = 0) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE);
        Exit(0);
    end;

    while outlen > 0 do
    begin
        chunk := get_result(outlen > max_request , max_request , outlen);
        if  0>= ctx.meth.generate(ctx.algctx, _out, chunk, strength,
                                 prediction_resistance, addin, addin_len) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_GENERATE_ERROR);
            Exit(0);

        end;
        {
         * Prediction resistance is only relevant the first time around,
         * subsequently, the DRBG has already been properly reseeded.
         }
        prediction_resistance := 0;
        outlen := outlen - chunk;
        _out := _out + chunk
    end;
    Result := 1;
end;

function EVP_RAND_generate(ctx : PEVP_RAND_CTX; _out : PByte; outlen : size_t;
                           strength : uint32; prediction_resistance : integer;
                           const addin : PByte; addin_len : size_t):integer;
var
  res : integer;
begin
    if  0>= evp_rand_lock(ctx ) then
        Exit(0);
    res := evp_rand_generate_locked(ctx, _out, outlen, strength,
                                   prediction_resistance, addin, addin_len);
    evp_rand_unlock(ctx);
    Result := res;
end;

function EVP_RAND_enable_locking( rand : PEVP_RAND_CTX):integer;
begin
    if Assigned(rand.meth.enable_locking ) then
       Exit(rand.meth.enable_locking(rand.algctx));
    ERR_raise(ERR_LIB_EVP, EVP_R_LOCKING_NOT_SUPPORTED);
    Result := 0;
end;

function EVP_RAND_get0_provider(const rand : PEVP_RAND):POSSL_PROVIDER;
begin
    Result := rand.prov;
end;

function EVP_RAND_CTX_settable_params( ctx : PEVP_RAND_CTX):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if not Assigned(ctx.meth.settable_ctx_params) then
       Exit(nil);
    provctx := ossl_provider_ctx(EVP_RAND_get0_provider(ctx.meth));
    Result := ctx.meth.settable_ctx_params(ctx.algctx, provctx);
end;

procedure evp_rand_unlock( rand : PEVP_RAND_CTX);
begin
    if Assigned(rand.meth.unlock ) then
       rand.meth.unlock(rand.algctx);
end;

function evp_rand_instantiate_locked(ctx : PEVP_RAND_CTX; strength : uint32;
                                     prediction_resistance : integer;
                                     const pstr : PByte; pstr_len : size_t;
                                     const params : POSSL_PARAM):integer;
begin
    Result := ctx.meth.instantiate(ctx.algctx, strength, prediction_resistance,
                                  pstr, pstr_len, params);
end;

function evp_rand_lock( rand : PEVP_RAND_CTX):integer;
begin
    if Assigned(rand.meth.lock) then
       Exit(rand.meth.lock(rand.algctx));
    Result := 1;
end;

function EVP_RAND_instantiate(ctx : PEVP_RAND_CTX; strength : uint32;
                              prediction_resistance : integer;const pstr : PByte;
                              pstr_len : size_t;const params : POSSL_PARAM):integer;
var
  res : integer;
begin
    if  0>= evp_rand_lock(ctx) then
        Exit(0);
    res := evp_rand_instantiate_locked(ctx, strength, prediction_resistance,
                                      pstr, pstr_len, params);
    evp_rand_unlock(ctx);
    Result := res;
end;

function evp_rand_ctx_up_ref( ctx : PEVP_RAND_CTX):integer;
var
  ref : integer;
begin
    ref := 0;
    Result := CRYPTO_UP_REF(ctx.refcnt, ref, ctx.refcnt_lock);
end;

function EVP_RAND_CTX_new( rand : PEVP_RAND; parent : PEVP_RAND_CTX):PEVP_RAND_CTX;
var
    ctx             : PEVP_RAND_CTX;
    parent_ctx, p   : Pointer;
    parent_dispatch : POSSL_DISPATCH;
begin
    parent_ctx := nil;
    parent_dispatch := nil;
    if rand = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM);
        Exit(nil);
    end;
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    ctx.refcnt_lock := CRYPTO_THREAD_lock_new();
    if (ctx = nil)  or  (ctx.refcnt_lock = nil)  then
    begin
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if parent <> nil then
    begin
        if  0>= evp_rand_ctx_up_ref(parent) then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            CRYPTO_THREAD_lock_free(ctx.refcnt_lock);
            OPENSSL_free(ctx);
            Exit(nil);
        end;
        parent_ctx := parent.algctx;
        parent_dispatch := parent.meth.dispatch;
    end;
    p := ossl_provider_ctx(rand.prov);
    ctx.algctx := rand.newctx(p, parent_ctx, parent_dispatch);
    if (ctx.algctx = nil ) or (0>= EVP_RAND_up_ref(rand))  then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        rand.freectx(ctx.algctx);
        CRYPTO_THREAD_lock_free(ctx.refcnt_lock);
        OPENSSL_free(ctx);
        EVP_RAND_CTX_free(parent);
        Exit(nil);
    end;
    ctx.meth := rand;
    ctx.parent := parent;
    ctx.refcnt := 1;
    Result := ctx;
end;

function evp_rand_up_ref( vrand : Pointer):integer;
var
  rand : PEVP_RAND;
  ref : integer;
begin
    rand := PEVP_RAND(vrand);
    ref := 0;
    if rand <> nil then
       Exit(CRYPTO_UP_REF(rand.refcnt, ref, rand.refcnt_lock));
    Result := 1;
end;

function evp_rand_new:Pointer;
var
  rand : PEVP_RAND;
begin
    rand := OPENSSL_zalloc(sizeof( rand^));
    rand.refcnt_lock := CRYPTO_THREAD_lock_new();
    if (rand = nil)
             or  (rand.refcnt_lock = nil) then
    begin
        OPENSSL_free(rand);
        Exit(nil);
    end;
    rand.refcnt := 1;
    Result := rand;
end;


//evp_generic_fetch  ÀïÃæµÄ new_method : Tevp_fetch_new_method
function evp_rand_from_algorithm( name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  fns             : POSSL_DISPATCH;
  rand            : PEVP_RAND;
  fnrandcnt,
  fnctxcnt,
  fnlockcnt,
  fnenablelockcnt,
  fnzeroizecnt    : integer;
begin
    fns := algodef._implementation;
    rand := nil;
    fnrandcnt := 0;
    fnctxcnt := 0;
    fnlockcnt := 0;
    fnenablelockcnt := 0;
{$IFDEF FIPS_MODULE}
    fnzeroizecnt := 0;
{$ENDIF}
    rand := evp_rand_new( );
    if rand = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    rand.name_id := name_id;
    rand.type_name := ossl_algorithm_get1_first_name(algodef);
    if rand.type_name =  nil then
    begin
        _evp_rand_free(rand);
        Exit(nil);
    end;
    rand.description := algodef.algorithm_description;
    rand.dispatch := fns;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_RAND_NEWCTX:
        begin
            if Assigned(rand.newctx ) then break;
            rand.newctx := _OSSL_FUNC_rand_newctx(fns);
            PostInc(fnctxcnt);
        end;
        OSSL_FUNC_RAND_FREECTX:
        begin
            if Assigned(rand.freectx ) then break;
            rand.freectx := _OSSL_FUNC_rand_freectx(fns);
            PostInc(fnctxcnt);
        end;
        OSSL_FUNC_RAND_INSTANTIATE:
        begin
            if Assigned(rand.instantiate ) then break;
            rand.instantiate := _OSSL_FUNC_rand_instantiate(fns);
            PostInc(fnrandcnt);
        end;
        OSSL_FUNC_RAND_UNINSTANTIATE:
        begin
             if Assigned(rand.uninstantiate ) then break;
            rand.uninstantiate := _OSSL_FUNC_rand_uninstantiate(fns);
            PostInc(fnrandcnt);
        end;
        OSSL_FUNC_RAND_GENERATE:
        begin
            if Assigned(rand.generate ) then break;
            rand.generate := _OSSL_FUNC_rand_generate(fns);
            PostInc(fnrandcnt);
        end;
        OSSL_FUNC_RAND_RESEED:
        begin
            if Assigned(rand.reseed ) then break;
            rand.reseed := _OSSL_FUNC_rand_reseed(fns);
        end;
        OSSL_FUNC_RAND_NONCE:
        begin
            if Assigned(rand.nonce ) then break;
            rand.nonce := _OSSL_FUNC_rand_nonce(fns);
        end;
        OSSL_FUNC_RAND_ENABLE_LOCKING:
        begin
            if Assigned(rand.enable_locking ) then break;
            rand.enable_locking := _OSSL_FUNC_rand_enable_locking(fns);
            PostInc(fnenablelockcnt);
        end;
        OSSL_FUNC_RAND_LOCK:
        begin
            if Assigned(rand.lock ) then break;
            rand.lock := _OSSL_FUNC_rand_lock(fns);
            PostInc(fnlockcnt);
        end;
        OSSL_FUNC_RAND_UNLOCK:
        begin
            if Assigned(rand.unlock ) then break;
            rand.unlock := _OSSL_FUNC_rand_unlock(fns);
            PostInc(fnlockcnt);
        end;
        OSSL_FUNC_RAND_GETTABLE_PARAMS:
        begin
            if Assigned(rand.gettable_params ) then break;
            rand.gettable_params := _OSSL_FUNC_rand_gettable_params(fns);
        end;
        OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS:
        begin
            if Assigned(rand.gettable_ctx_params ) then break;
            rand.gettable_ctx_params := _OSSL_FUNC_rand_gettable_ctx_params(fns);
        end;
        OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS:
        begin
            if Assigned(rand.settable_ctx_params ) then break;
            rand.settable_ctx_params := _OSSL_FUNC_rand_settable_ctx_params(fns);
        end;
        OSSL_FUNC_RAND_GET_PARAMS:
        begin
            if Assigned(rand.get_params ) then break;
            rand.get_params := _OSSL_FUNC_rand_get_params(fns);
        end;
        OSSL_FUNC_RAND_GET_CTX_PARAMS:
        begin
            if Assigned(rand.get_ctx_params ) then break;
            rand.get_ctx_params := _OSSL_FUNC_rand_get_ctx_params(fns);
            PostInc(fnctxcnt);
        end;
        OSSL_FUNC_RAND_SET_CTX_PARAMS:
        begin
            if Assigned(rand.set_ctx_params ) then break;
            rand.set_ctx_params := _OSSL_FUNC_rand_set_ctx_params(fns);
        end;
        OSSL_FUNC_RAND_VERIFY_ZEROIZATION:
        begin
            if Assigned(rand.verify_zeroization ) then break;
            rand.verify_zeroization := _OSSL_FUNC_rand_verify_zeroization(fns);
{$IFDEF FIPS_MODULE}
            PostInc(fnzeroizecnt);
{$ENDIF}
        end;
        end;
        Inc(fns);
    end;
    {
     * In order to be a consistent set of functions we must have at least
     * a complete set of 'rand' functions and a complete set of context
     * management functions.  In FIPS mode, we also require the zeroization
     * verification function.
     *
     * In addition, if locking can be enabled, we need a complete set of
     * locking functions.
     }
    if (fnrandcnt <> 3)
             or  (fnctxcnt <> 3)
             or  ( (fnenablelockcnt <> 0)  and  (fnenablelockcnt <> 1) )
             or  ( (fnlockcnt <> 0)  and  (fnlockcnt <> 2) )
{$IFDEF FIPS_MODULE}
             or  (fnzeroizecnt <> 1)
{$ENDIF}
           then
    begin
        _evp_rand_free(rand);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    if (prov <> nil)  and   (0>= ossl_provider_up_ref(prov) )  then
    begin
        _evp_rand_free(rand);
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    rand.prov := prov;
    Result := rand;
end;

function EVP_RAND_fetch(libctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_RAND;
begin
    Exit(evp_generic_fetch(libctx, OSSL_OP_RAND, algorithm, properties,
                           evp_rand_from_algorithm, evp_rand_up_ref,
                           _evp_rand_free));
end;

procedure EVP_RAND_free(rand : PEVP_RAND);
begin
    _evp_rand_free(rand);
end;

procedure EVP_RAND_CTX_free( ctx : PEVP_RAND_CTX);
var
  ref : integer;
  parent : PEVP_RAND_CTX;
begin
    ref := 0;
    if ctx = nil then exit;
    CRYPTO_DOWN_REF(ctx.refcnt, ref, ctx.refcnt_lock);
    if ref > 0 then exit;
    parent := ctx.parent;
    ctx.meth.freectx(ctx.algctx);
    ctx.algctx := nil;
    EVP_RAND_free(ctx.meth);
    CRYPTO_THREAD_lock_free(ctx.refcnt_lock);
    OPENSSL_free(ctx);
    EVP_RAND_CTX_free(parent);
end;

end.
