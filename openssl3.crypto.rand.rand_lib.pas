unit openssl3.crypto.rand.rand_lib;

interface
uses OpenSSL.Api, SysUtils;

function RAND_bytes_ex( ctx : POSSL_LIB_CTX; buf : PByte; num : size_t; strength : uint32):integer;
function RAND_get0_public( ctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
function RAND_get0_private( ctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
function RAND_priv_bytes_ex( ctx : POSSL_LIB_CTX; buf : PByte; num : size_t; strength : uint32):integer;
function RAND_get_rand_method:PRAND_METHOD;
function RAND_bytes( buf : PByte; num : integer):integer;
function RAND_get0_primary( ctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
procedure do_rand_init_ossl_;
function do_rand_init:integer;
procedure ossl_rand_cleanup_int;
function RAND_set_rand_method(const meth : PRAND_METHOD):integer;
function RAND_priv_bytes( buf : PByte; num : integer):integer;
procedure ossl_random_add_conf_module;
function RAND_pseudo_bytes( buf : PByte; num : integer):integer;
function RAND_set_DRBG_type(ctx : POSSL_LIB_CTX;const drbg, propq, cipher, digest : PUTF8Char):integer;
procedure RAND_add(const buf : Pointer; num : integer; randomness : Double);
function RAND_status:integer;

implementation

uses
   OpenSSL3.Err, openssl3.crypto.context,   openssl3.crypto.evp.evp_rand,
   {$IFDEF MSWINDOWS}
   OpenSSL3.providers.implementations.rands.seeding.rand_win,
   {$ENDIF}
   openssl3.crypto.mem,                     openssl3.crypto.params,
   openssl3.crypto.rand.rand_meth,          openssl3.providers.fips.fipsprov,
   openssl3.crypto.engine.tb_rand,          openssl3.crypto.engine.eng_init,
   openssl3.crypto.init,                    openssl3.crypto.conf.conf_lib,
   openssl3.crypto.conf.conf_mod,           OpenSSL3.openssl.conf,
   openssl3.crypto.o_str,                   OpenSSL3.threads_none,
   openssl3.crypto.initthread;


var
{$ifndef OPENSSL_NO_ENGINE}
(* non-NULL if default_RAND_meth is ENGINE-provided *)
  rand_engine_lock: PCRYPTO_RWLOCK ;
  funct_ref: PENGINE ;
{$ENDIF}
{$ifndef OPENSSL_NO_DEPRECATED_3_0}
   rand_meth_lock: PCRYPTO_RWLOCK ;
   default_RAND_meth: PRAND_METHOD ;
{$ENDIF}

   rand_init: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
   do_rand_init_ossl_ret_: int  = 0;
   rand_inited: int = 0;

{static}function rand_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
var
  dgbl : PRAND_GLOBAL;
  label _err1, _err2;
begin
    dgbl := OPENSSL_zalloc(sizeof( dgbl^));
    if dgbl = nil then Exit(nil);
{$IFNDEF FIPS_MODULE}
    {
     * We need to ensure that base libcrypto thread handling has been
     * initialised.
     }
     OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, nil);
{$ENDIF}
    dgbl.lock := CRYPTO_THREAD_lock_new();
    if dgbl.lock = nil then goto _err1;
    if  0>= CRYPTO_THREAD_init_local(@dgbl.&private, nil)  then
        goto _err1;
    if  0>= CRYPTO_THREAD_init_local(@dgbl.&public, nil)   then
        goto _err2;
    Exit(dgbl);
 _err2:
    CRYPTO_THREAD_cleanup_local(@dgbl.private);
 _err1:
    CRYPTO_THREAD_lock_free(dgbl.lock);
    OPENSSL_free(dgbl);
    Result := nil;
end;

{static}procedure rand_ossl_ctx_free( vdgbl : Pointer);
var
  dgbl : PRAND_GLOBAL;
begin
    dgbl := vdgbl;
    if dgbl = nil then exit;
    CRYPTO_THREAD_lock_free(dgbl.lock);
    CRYPTO_THREAD_cleanup_local(@dgbl.private);
    CRYPTO_THREAD_cleanup_local(@dgbl.public);
    EVP_RAND_CTX_free(dgbl.primary);
    EVP_RAND_CTX_free(dgbl.seed);
    OPENSSL_free(dgbl.rng_name);
    OPENSSL_free(dgbl.rng_cipher);
    OPENSSL_free(dgbl.rng_digest);
    OPENSSL_free(dgbl.rng_propq);
    OPENSSL_free(dgbl.seed_name);
    OPENSSL_free(dgbl.seed_propq);
    OPENSSL_free(dgbl);
end;

const  rand_drbg_ossl_ctx_method: TOSSL_LIB_CTX_METHOD = (
    priority :OSSL_LIB_CTX_METHOD_PRIORITY_2;
    new_func: rand_ossl_ctx_new;
    free_func: rand_ossl_ctx_free;
);

function rand_get_global( libctx : POSSL_LIB_CTX):PRAND_GLOBAL;
begin
    Result := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_DRBG_INDEX, @rand_drbg_ossl_ctx_method);
end;

function RAND_status:integer;
var
  rand : PEVP_RAND_CTX;
  meth : PRAND_METHOD;
begin
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    meth := RAND_get_rand_method;
    if (meth <> nil)  and  (meth <> RAND_OpenSSL) then
       Exit(get_result(Assigned(meth.status) , meth.status , 0));
{$ENDIF}
    rand := RAND_get0_primary(nil);
    if Rand = nil then
        Exit(0);
    Result := Int(EVP_RAND_get_state(rand) = EVP_RAND_STATE_READY);
end;

procedure RAND_add(const buf : Pointer; num : integer; randomness : Double);
var
  drbg : PEVP_RAND_CTX;
  meth : PRAND_METHOD;
begin
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
   meth := RAND_get_rand_method;
    if (meth <> nil)  and  (Assigned(meth.add)) then begin
        meth.add(buf, num, randomness);
        exit;
    end;
{$ENDIF}
    drbg := RAND_get0_primary(nil);
    if (drbg <> nil)  and  (num > 0) then
       EVP_RAND_reseed(drbg, 0, nil, 0, buf, num);
end;

{$ifndef FIPS_MODULE}
{static}function random_set_string(var p : PUTF8Char;const s : PUTF8Char):integer;
var
  d : PUTF8Char;
begin
    d := nil;
    if s <> nil then begin
        OPENSSL_strdup(d, s);
        if d = nil then begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    OPENSSL_free( p);
    p := d;
    Result := 1;
end;
{$ENDIF}

function RAND_set_DRBG_type(ctx : POSSL_LIB_CTX;const drbg, propq, cipher, digest : PUTF8Char):integer;
var
  dgbl : PRAND_GLOBAL;
begin
    dgbl := rand_get_global(ctx);
    if dgbl = nil then Exit(0);
    if dgbl.primary <> nil then begin
        ERR_raise(ERR_LIB_CRYPTO, RAND_R_ALREADY_INSTANTIATED);
        Exit(0);
    end;
    Result := Int( (random_set_string(dgbl.rng_name, drbg) > 0)
               and (random_set_string(dgbl.rng_propq, propq) > 0)
               and (random_set_string(dgbl.rng_cipher, cipher) > 0)
               and (random_set_string(dgbl.rng_digest, digest) > 0) );
end;

function RAND_pseudo_bytes( buf : PByte; num : integer):integer;
var
  meth : PRAND_METHOD;
begin
     meth := RAND_get_rand_method;
    if (meth <> nil)  and  (Assigned(meth.pseudorand)) then
       Exit(meth.pseudorand(buf, num));
    ERR_raise(ERR_LIB_RAND, RAND_R_FUNC_NOT_IMPLEMENTED);
    Result := -1;
end;


{static}function random_conf_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
  elist : Pstack_st_CONF_VALUE;
  cval : PCONF_VALUE;
  dgbl : PRAND_GLOBAL;
  i, r : integer;
begin
    dgbl := rand_get_global(NCONF_get0_libctx(PCONF (cnf)));
    r := 1;
    //OSSL_TRACE1(CONF, 'Loading random module: section %s\n',
      //          CONF_imodule_get_value(md));
    { Value is a section containing RANDOM configuration }
    elist := NCONF_get_section(cnf, CONF_imodule_get_value(md));
    if elist = nil then begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_RANDOM_SECTION_ERROR);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(elist)-1 do
    begin
        cval := sk_CONF_VALUE_value(elist, i);
        if strcasecmp(cval.name, 'random' ) = 0 then
        begin
            if 0>=random_set_string(dgbl.rng_name, cval.value) then
                Exit(0);
        end
        else if (strcasecmp(cval.name, 'cipher') = 0) then
        begin
            if 0>=random_set_string(dgbl.rng_cipher, cval.value ) then
                Exit(0);
        end
        else if (strcasecmp(cval.name, 'digest') = 0) then begin
            if 0>=random_set_string(dgbl.rng_digest, cval.value) then
                Exit(0);
        end
        else if (strcasecmp(cval.name, 'properties') = 0) then begin
            if 0>=random_set_string(dgbl.rng_propq, cval.value) then
                Exit(0);
        end
        else if (strcasecmp(cval.name, 'seed') = 0) then begin
            if 0>=random_set_string(dgbl.seed_name, cval.value) then
                Exit(0);
        end
        else if (strcasecmp(cval.name, 'seed_properties') = 0) then begin
            if 0>=random_set_string(dgbl.seed_propq, cval.value) then
                Exit(0);
        end
        else
        begin
            ERR_raise_data(ERR_LIB_CRYPTO,
                           CRYPTO_R_UNKNOWN_NAME_IN_RANDOM_SECTION,
                          Format( 'name=%s, value=%s', [cval.name, cval.value]));
            r := 0;
        end;
    end;
    Result := r;
end;


{static}procedure random_conf_deinit( md : PCONF_IMODULE);
begin
    //OSSL_TRACE(CONF, 'Cleaned up random\n');
end;



procedure ossl_random_add_conf_module;
begin
    //OSSL_TRACE(CONF, 'Adding config module 'random'\n');
    CONF_module_add('random', random_conf_init, random_conf_deinit);
end;


function RAND_priv_bytes( buf : PByte; num : integer):integer;
begin
    if num < 0 then Exit(0);
    Result := RAND_priv_bytes_ex(nil, buf, size_t(num), 0);
end;


function rand_set_rand_method_internal(const meth : PRAND_METHOD; e : PENGINE):integer;
begin
    if 0>= get_result(CRYPTO_THREAD_run_once(@rand_init, do_rand_init_ossl_) > 0,
                       do_rand_init_ossl_ret_ , 0) then

        Exit(0);
    if 0>=CRYPTO_THREAD_write_lock(rand_meth_lock) then
        Exit(0);
{$IFNDEF OPENSSL_NO_ENGINE}
    ENGINE_finish(funct_ref);
    funct_ref := e;
{$ENDIF}
    default_RAND_meth := meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    Result := 1;
end;



function RAND_set_rand_method(const meth : PRAND_METHOD):integer;
begin
    Result := rand_set_rand_method_internal(meth, nil);
end;

procedure ossl_rand_cleanup_int;
var
  meth : PRAND_METHOD;
begin
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    meth := default_RAND_meth;
    if  0>= rand_inited then exit;
    if (meth <> nil)  and  (Assigned(meth.cleanup)) then meth.cleanup();
    RAND_set_rand_method(nil);
{$ENDIF}
    ossl_rand_pool_cleanup();
{$IFNDEF OPENSSL_NO_ENGINE}
    CRYPTO_THREAD_lock_free(rand_engine_lock);
    rand_engine_lock := nil;
{$ENDIF}
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    CRYPTO_THREAD_lock_free(rand_meth_lock);
    rand_meth_lock := nil;
{$ENDIF}
    rand_inited := 0;
end;

function do_rand_init:integer;
label _err;
begin
    rand_engine_lock := CRYPTO_THREAD_lock_new;
    if rand_engine_lock = Pointer(0) then
        Exit(0);
    rand_meth_lock := CRYPTO_THREAD_lock_new;
    if rand_meth_lock = Pointer(0) then
        goto _err;
    if 0>=ossl_rand_pool_init then goto _err;
    rand_inited := 1;
    Exit(1);
 _err:
    CRYPTO_THREAD_lock_free(rand_meth_lock);
    rand_meth_lock := Pointer(0) ;
    CRYPTO_THREAD_lock_free(rand_engine_lock);
    rand_engine_lock := Pointer(0) ;
    Result := 0;
end;

procedure do_rand_init_ossl_;
begin
   do_rand_init_ossl_ret_ := do_rand_init();
end;

function RAND_bytes( buf : PByte; num : integer):integer;
begin
    if num < 0 then Exit(0);
    Result := RAND_bytes_ex(nil, buf, size_t( num), 0);
end;

function RAND_get_rand_method:PRAND_METHOD;
var
    tmp_meth : PRAND_METHOD;
    e        : PENGINE;
begin
    tmp_meth := nil;
    if 0>= get_result( CRYPTO_THREAD_run_once(@rand_init, do_rand_init_ossl_) >0,
                do_rand_init_ossl_ret_ , 0) then
        Exit(nil);
    if 0>= CRYPTO_THREAD_write_lock(rand_meth_lock) then
        Exit(nil);
    if default_RAND_meth = nil then
    begin
{$IFNDEF OPENSSL_NO_ENGINE}
        { If we have an engine that can do RAND, use it. }
        e := ENGINE_get_default_RAND();
        if (e <> nil) then
        begin
            tmp_meth := ENGINE_get_RAND(e);
            if (tmp_meth <> nil) then
            begin
               funct_ref := e;
               default_RAND_meth := tmp_meth;
            end;
        end
        else
        begin
            ENGINE_finish(e);
            default_RAND_meth := @ossl_rand_meth;
        end;
{$ELSE}
    default_RAND_meth = &ossl_rand_meth;
{$ENDIF}
    end;
    tmp_meth := default_RAND_meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    Result := tmp_meth;
end;

function RAND_priv_bytes_ex( ctx : POSSL_LIB_CTX; buf : PByte; num : size_t; strength : uint32):integer;
var
  rand : PEVP_RAND_CTX;
  meth : PRAND_METHOD;
begin
{$IF not defined(OPENSSL_NO_DEPRECATED_3_0)  and  not defined(FIPS_MODULE)}
     meth := RAND_get_rand_method();
    if (meth <> nil)  and  (meth <> RAND_OpenSSL) then
    begin
        if Assigned(meth.bytes) then
            Exit(meth.bytes(buf, num));
        ERR_raise(ERR_LIB_RAND, RAND_R_FUNC_NOT_IMPLEMENTED);
        Exit(-1);
    end;
{$IFEND}
    rand := RAND_get0_private(ctx);
    if rand <> nil then
       Exit(EVP_RAND_generate(rand, buf, num, strength, 0, nil{addin}, 0{addin_len}));
    Result := 0;
end;

procedure rand_delete_thread_state( arg : Pointer);
var
  ctx : POSSL_LIB_CTX;
  dgbl : PRAND_GLOBAL;
  rand : PEVP_RAND_CTX;
begin
    ctx := arg;
    dgbl := rand_get_global(ctx);
    if dgbl = nil then exit;
    rand := CRYPTO_THREAD_get_local(@dgbl.public);
    CRYPTO_THREAD_set_local(@dgbl.public, nil);
    EVP_RAND_CTX_free(rand);
    rand := CRYPTO_THREAD_get_local(@dgbl.private);
    CRYPTO_THREAD_set_local(@dgbl.private, nil);
    EVP_RAND_CTX_free(rand);
end;

{static}function rand_new_drbg( libctx : POSSL_LIB_CTX; parent : PEVP_RAND_CTX;
                        reseed_interval : uint32;
                        reseed_time_interval : time_t; use_df : integer):PEVP_RAND_CTX;
var
    rand      : PEVP_RAND;
    dgbl      : PRAND_GLOBAL;
    ctx       : PEVP_RAND_CTX;
    params    : array[0..7] of TOSSL_PARAM;
    p, settables : POSSL_PARAM;
    name,
    cipher    : PUTF8Char;
    i: int;
begin
    dgbl := rand_get_global(libctx);
    {$IFNDEF FPC}
    for I := 0 to 7 do
       params[i] := default(TOSSL_PARAM);
    {$ENDIF}

    p := @params;
    if dgbl.rng_name <> nil then
       name := dgbl.rng_name
    else
       name := 'CTR-DRBG';
    rand := EVP_RAND_fetch(libctx, name, dgbl.rng_propq);
    if rand = nil then
    begin
        ERR_raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_FETCH_DRBG);
        Exit(nil);
    end;
    ctx := EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_CREATE_DRBG);
        Exit(nil);
    end;
    settables := EVP_RAND_CTX_settable_params(ctx);
    if OSSL_PARAM_locate_const(settables, OSSL_DRBG_PARAM_CIPHER) <> nil then
    begin
        if dgbl.rng_cipher <> nil then
           cipher :=  dgbl.rng_cipher
        else
           cipher := 'AES-256-CTR';
        p^ := OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, cipher, 0);
        Inc(p);
    end;
    if (dgbl.rng_digest <> nil) and
       (nil <> OSSL_PARAM_locate_const(settables, OSSL_DRBG_PARAM_DIGEST) ) then
    begin
       p^ := OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
                                                dgbl.rng_digest, 0);
       Inc(p);
    end;
    if dgbl.rng_propq <> nil then
    begin
       p^ := OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_PROPERTIES,
                                                dgbl.rng_propq, 0);
       Inc(p);
    end;
    if OSSL_PARAM_locate_const(settables, OSSL_ALG_PARAM_MAC) <> nil  then
    begin
        p^ := (OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_MAC, 'HMAC', 0));
        Inc(p);
    end;
    if OSSL_PARAM_locate_const(settables, OSSL_DRBG_PARAM_USE_DF )<>nil  then
    begin
        p^ := (OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, @use_df));
        Inc(p);
    end;
    p^ := OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, @reseed_interval);
    Inc(p);
    p^ := OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, @reseed_time_interval);
    Inc(p);
    p^ := OSSL_PARAM_construct_end();
    if  0>= EVP_RAND_instantiate(ctx, 0, 0, nil, 0, @params) then
    begin
        ERR_raise(ERR_LIB_RAND, RAND_R_ERROR_INSTANTIATING_DRBG);
        EVP_RAND_CTX_free(ctx);
        Exit(nil);
    end;
    Result := ctx;
end;

function RAND_get0_private( ctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
var
  dgbl : PRAND_GLOBAL;
  rand, primary : PEVP_RAND_CTX;
begin
    dgbl := rand_get_global(ctx);
    if dgbl = nil then Exit(nil);
    rand := CRYPTO_THREAD_get_local(@dgbl.private);
    if rand = nil then
    begin
        primary := RAND_get0_primary(ctx);
        if primary = nil then Exit(nil);
        ctx := ossl_lib_ctx_get_concrete(ctx);
        {
         * If the public is also nil then this is the first time we've
         * used this thread.
         }
        if (CRYPTO_THREAD_get_local(@dgbl.public) = nil ) and
           (0 >= ossl_init_thread_start(nil, ctx, rand_delete_thread_state)) then
            Exit(nil);
        rand := rand_new_drbg(ctx, primary, SECONDARY_RESEED_INTERVAL, SECONDARY_RESEED_TIME_INTERVAL, 0);
        CRYPTO_THREAD_set_local(@dgbl.private, rand);
    end;
    Result := rand;
end;




{$ifndef FIPS_MODULE}
function rand_new_seed( libctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
var
  rand : PEVP_RAND;
  dgbl : PRAND_GLOBAL;
  ctx : PEVP_RAND_CTX;
  name : PUTF8Char;
begin
    dgbl := rand_get_global(libctx);
    if dgbl.seed_name <> nil then
       name :=  dgbl.seed_name
    else
       name := 'SEED-SRC';
    rand := EVP_RAND_fetch(libctx, name, dgbl.seed_propq);
    if rand = nil then
    begin
        ERR_raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_FETCH_DRBG);
        Exit(nil);
    end;
    ctx := EVP_RAND_CTX_new(rand, nil);
    EVP_RAND_free(rand);
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_CREATE_DRBG);
        Exit(nil);
    end;
    if  0>= EVP_RAND_instantiate(ctx, 0, 0, nil, 0, nil) then
    begin
        ERR_raise(ERR_LIB_RAND, RAND_R_ERROR_INSTANTIATING_DRBG);
        EVP_RAND_CTX_free(ctx);
        Exit(nil);
    end;
    Result := ctx;
end;
{$ENDIF}

function RAND_get0_primary( ctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
var
  dgbl : PRAND_GLOBAL;
  ret : PEVP_RAND_CTX;
begin
    dgbl := rand_get_global(ctx);
    if dgbl = nil then Exit(nil);
    if  (0>= CRYPTO_THREAD_read_lock(dgbl.lock )) then
        Exit(nil);
    ret := dgbl.primary;
    CRYPTO_THREAD_unlock(dgbl.lock);
    if ret <> nil then Exit(ret);
    if  (0>= CRYPTO_THREAD_write_lock(dgbl.lock )) then
        Exit(nil);
    ret := dgbl.primary;
    if ret <> nil then begin
        CRYPTO_THREAD_unlock(dgbl.lock);
        Exit(ret);
    end;
{$IFNDEF FIPS_MODULE}
    if dgbl.seed = nil then
    begin
        ERR_set_mark();
        dgbl.seed := rand_new_seed(ctx);
        ERR_pop_to_mark();
    end;
{$ENDIF}
    dgbl.primary := rand_new_drbg(ctx, dgbl.seed,
                                  PRIMARY_RESEED_INTERVAL,
                                  PRIMARY_RESEED_TIME_INTERVAL, 1);
    ret := dgbl.primary;
    {
    * The primary DRBG may be shared between multiple threads so we must
    * enable locking.
    }
    if (ret <> nil)  and   (0>= EVP_RAND_enable_locking(ret )) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNABLE_TO_ENABLE_LOCKING);
        EVP_RAND_CTX_free(ret);
        ret := nil;
        dgbl.primary := nil;
    end;
    CRYPTO_THREAD_unlock(dgbl.lock);
    Result := ret;
end;

function RAND_get0_public( ctx : POSSL_LIB_CTX):PEVP_RAND_CTX;
var
  dgbl : PRAND_GLOBAL;
  rand, primary : PEVP_RAND_CTX;
begin
    dgbl := rand_get_global(ctx);
    if dgbl = nil then Exit(nil);
    rand := CRYPTO_THREAD_get_local(@dgbl.public);
    if rand = nil then
    begin
        primary := RAND_get0_primary(ctx);
        if primary = nil then Exit(nil);
        ctx := ossl_lib_ctx_get_concrete(ctx);
        {
         * If the private is also nil then this is the first time we've
         * used this thread.
         }
        if (CRYPTO_THREAD_get_local(@dgbl.private) = nil)
                 and   (0>= ossl_init_thread_start(nil, ctx, rand_delete_thread_state))  then
            Exit(nil);
        rand := rand_new_drbg(ctx, primary, SECONDARY_RESEED_INTERVAL,
                             SECONDARY_RESEED_TIME_INTERVAL, 0);
        CRYPTO_THREAD_set_local(@dgbl.public, rand);
    end;
    Result := rand;
end;

function RAND_bytes_ex( ctx : POSSL_LIB_CTX; buf : PByte; num : size_t; strength : uint32):integer;
var
  rand : PEVP_RAND_CTX;
  meth : PRAND_METHOD;
begin
{$IF not defined(OPENSSL_NO_DEPRECATED_3_0)  and   not defined(FIPS_MODULE)}
     meth := RAND_get_rand_method();
    if (meth <> nil)  and  (meth <> RAND_OpenSSL() ) then
    begin
        if Assigned(meth.bytes) then
            Exit(meth.bytes(buf, num));
        ERR_raise(ERR_LIB_RAND, RAND_R_FUNC_NOT_IMPLEMENTED);
        Exit(-1);
    end;
{$IFEND}
    rand := RAND_get0_public(ctx);
    if rand <> nil then
       Exit(EVP_RAND_generate(rand, buf, num, strength, 0, nil, 0));
    Result := 0;
end;

end.
