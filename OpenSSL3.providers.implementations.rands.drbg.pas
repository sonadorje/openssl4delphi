unit OpenSSL3.providers.implementations.rands.drbg;

interface
uses  OpenSSL.Api, {$IFDEF MSWINDOWS}windows, {$ENDIF} DateUtils, SysUtils;

type
  Tdnew_func = function(ctx: PPROV_DRBG): Integer;
  Tinstantiate_func = function(drbg: PPROV_DRBG; const entropy: PByte; entropylen: size_t; const nonce: PByte; noncelen: size_t; const pers: PByte; perslen: size_t): Integer;
  Tuninstantiate_func = function(ctx: PPROV_DRBG): Integer;
  Treseed_func = function(drbg: PPROV_DRBG; const ent: PByte; ent_len: size_t; const adin: PByte; adin_len: size_t): Integer;
  Tgenerate_func = function(p1: PPROV_DRBG; &out: PByte; outlen: size_t; const adin: PByte; adin_len: size_t): Integer;


 function ossl_drbg_enable_locking( vctx : Pointer):integer;
procedure ossl_drbg_unlock( vctx : Pointer);
function ossl_drbg_lock( vctx : Pointer):integer;
function ossl_drbg_get_seed(vdrbg : Pointer;out pout : PByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer;const adin : PByte; adin_len : size_t):size_t;
procedure ossl_drbg_clear_seed( vdrbg : Pointer; _out : PByte; outlen : size_t);
function ossl_prov_drbg_generate(drbg : PPROV_DRBG; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer; adin : PByte; adinlen : size_t):integer;
function rand_drbg_restart( drbg : PPROV_DRBG):Boolean;
function ossl_prov_drbg_instantiate(drbg : PPROV_DRBG; strength : uint32; prediction_resistance : integer; pers : PByte; perslen : size_t):integer;
function prov_drbg_get_nonce( drbg : PPROV_DRBG; pout : PPByte; min_len, max_len : size_t):size_t;
function prov_drbg_nonce_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
procedure prov_drbg_nonce_ossl_ctx_free( vdngbl : Pointer);
function get_entropy( drbg : PPROV_DRBG;out pout : PByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer):size_t;
function get_parent_strength( drbg : PPROV_DRBG; str : Puint32):integer;
function ossl_drbg_lock_parent( drbg : PPROV_DRBG):integer;
procedure ossl_drbg_unlock_parent( drbg : PPROV_DRBG);
procedure cleanup_entropy( drbg : PPROV_DRBG; &out : PByte; outlen : size_t);
function get_parent_reseed_count( drbg : PPROV_DRBG):uint32;
function ossl_prov_drbg_reseed(drbg : PPROV_DRBG; prediction_resistance : integer;const ent : PByte; ent_len : size_t; adin : PByte; adinlen : size_t):integer;
function ossl_drbg_get_ctx_params( drbg : PPROV_DRBG; params : POSSL_PARAM):integer;
function ossl_drbg_set_ctx_params(drbg : PPROV_DRBG;const params : POSSL_PARAM):integer;
function ossl_prov_drbg_uninstantiate( drbg : PPROV_DRBG):integer;
procedure ossl_rand_drbg_free( drbg : PPROV_DRBG);
function ossl_rand_drbg_new(provctx, parent : Pointer;const p_dispatch : POSSL_DISPATCH; dnew : Tdnew_func; instantiate : Tinstantiate_func; uninstantiate : Tuninstantiate_func; reseed : Treseed_func; generate : Tgenerate_func):PPROV_DRBG;
function find_call( dispatch : POSSL_DISPATCH; &function : integer):POSSL_DISPATCH;
function PROV_DRBG_VERYIFY_ZEROIZATION( v : PByte):integer;

const
   ossl_pers_string: PUTF8Char = 'OpenSSL NIST SP 800-90A DRBG';
   drbg_nonce_ossl_ctx_method: TOSSL_LIB_CTX_METHOD  = (
    priority:OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
    new_func:prov_drbg_nonce_ossl_ctx_new;
    free_func:prov_drbg_nonce_ossl_ctx_free
);

var
  {$IFNDEF FPC}[volatile]{$ENDIF} reseed_counter: UInt32;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem,           openssl3.crypto.mem_sec,
     openssl3.providers.prov_running,             OpenSSL3.providers.common.provider_ctx,
     openssl3.crypto.context,                     openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,                        OpenSSL3.providers.implementations.rands.crngt,
     OpenSSL3.openssl.params,                     openssl3.crypto.params,
     OpenSSL3.threads_none,                       OpenSSL3.openssl.core_dispatch;

function PROV_DRBG_VERYIFY_ZEROIZATION( v : PByte):integer;
var
  i : size_t;
begin
  for i := 0 to SizeOf(v)-1 do
      if v[i] <> 0 then Exit(0);
end;


function find_call( dispatch : POSSL_DISPATCH; &function : integer):POSSL_DISPATCH;
begin
    if dispatch <> nil then
    while (dispatch.function_id <> 0) do
    begin
        if dispatch.function_id = &function then
            Exit(dispatch);
        Inc(dispatch);
    end;
    Result := nil;
end;


function ossl_rand_drbg_new(provctx, parent : Pointer;const p_dispatch : POSSL_DISPATCH; dnew : Tdnew_func; instantiate : Tinstantiate_func; uninstantiate : Tuninstantiate_func; reseed : Treseed_func; generate : Tgenerate_func):PPROV_DRBG;
var
  drbg : PPROV_DRBG;
  pfunc : POSSL_DISPATCH;
  p_str : uint32;
  label _err;
begin
    if  not ossl_prov_is_running( ) then
        Exit(nil);
    drbg := OPENSSL_zalloc(sizeof( drbg^));
    if drbg = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    drbg.provctx := provctx;
    drbg.instantiate := instantiate;
    drbg.uninstantiate := uninstantiate;
    drbg.reseed := reseed;
    drbg.generate := generate;
    drbg.fork_id := openssl_get_fork_id();
    { Extract parent's functions }
    drbg.parent := parent;
    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_ENABLE_LOCKING );
    if pfunc <> nil then
        drbg.parent_enable_locking := _OSSL_FUNC_rand_enable_locking(pfunc);

    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_LOCK);
    if pfunc <> nil then
        drbg.parent_lock := _OSSL_FUNC_rand_lock(pfunc);

    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_UNLOCK);
    if pfunc <> nil then
        drbg.parent_unlock := _OSSL_FUNC_rand_unlock(pfunc);

    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_GET_CTX_PARAMS);
    if pfunc <> nil then
        drbg.parent_get_ctx_params := _OSSL_FUNC_rand_get_ctx_params(pfunc);

    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_NONCE);
    if pfunc <> nil then
        drbg.parent_nonce := _OSSL_FUNC_rand_nonce(pfunc);

    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_GET_SEED);
    if pfunc <> nil then
        drbg.parent_get_seed := _OSSL_FUNC_rand_get_seed(pfunc);

    pfunc := find_call(p_dispatch, OSSL_FUNC_RAND_CLEAR_SEED);
    if pfunc <> nil then
        drbg.parent_clear_seed := _OSSL_FUNC_rand_clear_seed(pfunc);
    { Set some default maximums up }
    drbg.max_entropylen := DRBG_MAX_LENGTH;
    drbg.max_noncelen := DRBG_MAX_LENGTH;
    drbg.max_perslen := DRBG_MAX_LENGTH;
    drbg.max_adinlen := DRBG_MAX_LENGTH;
    drbg.generate_counter := 1;
    drbg.reseed_counter := 1;
    drbg.reseed_interval := RESEED_INTERVAL;
    drbg.reseed_time_interval := TIME_INTERVAL;
    if  0>= dnew(drbg )  then
        goto _err ;
    if parent <> nil then
    begin
        if  0>= get_parent_strength(drbg, @p_str) then
            goto _err ;
        if drbg.strength > p_str then
        begin
            {
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             }
            ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_STRENGTH_TOO_WEAK);
            goto _err ;
        end;
    end;
{$IFDEF TSAN_REQUIRES_LOCKING}
    if  not ossl_drbg_enable_locking(drbg then )
        goto_err ;
{$ENDIF}
    Exit(drbg);
 _err:
    ossl_rand_drbg_free(drbg);
    Result := nil;
end;



procedure ossl_rand_drbg_free( drbg : PPROV_DRBG);
begin
    if drbg = nil then exit;
    CRYPTO_THREAD_lock_free(drbg.lock);
    OPENSSL_free(drbg);
end;

function ossl_prov_drbg_uninstantiate( drbg : PPROV_DRBG):integer;
begin
    Int(drbg.state) := EVP_RAND_STATE_UNINITIALISED;
    Result := 1;
end;



function ossl_drbg_set_ctx_params(drbg : PPROV_DRBG;const params : POSSL_PARAM):integer;
var
  p: POSSL_PARAM;
begin
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p <> nil)  and
       (0>= OSSL_PARAM_get_uint(p, @drbg.reseed_interval)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p <> nil)  and
       (0>= OSSL_PARAM_get_time_t(p, @drbg.reseed_time_interval) ) then
        Exit(0);
    Result := 1;
end;

function ossl_drbg_get_ctx_params( drbg : PPROV_DRBG; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, Int(drbg.state)) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, drbg.strength )) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.max_request) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.min_entropylen) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.max_entropylen) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_NONCELEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.min_noncelen) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_NONCELEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.max_noncelen) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_PERSLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.max_perslen) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ADINLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, drbg.max_adinlen) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_uint(p, drbg.reseed_interval) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_time_t(p, drbg.reseed_time) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_time_t(p, drbg.reseed_time_interval) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_COUNTER);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_uint(p, tsan_load(@drbg.reseed_counter)) ) then
        Exit(0);
    Result := 1;
end;


function ossl_prov_drbg_reseed(drbg : PPROV_DRBG; prediction_resistance : integer;const ent : PByte; ent_len : size_t; adin : PByte; adinlen : size_t):integer;
var
    entropy    : PByte;
    entropylen : size_t;
    label _end;
begin
    entropy := nil;
    entropylen := 0;
    if not ossl_prov_is_running()  then
        Exit(0);
    if Int(drbg.state) <> EVP_RAND_STATE_READY then
    begin
        { try to recover from previous errors }
        rand_drbg_restart(drbg);
        if Int(drbg.state) = EVP_RAND_STATE_ERROR then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
            Exit(0);
        end;
        if Int(drbg.state) = EVP_RAND_STATE_UNINITIALISED then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
            Exit(0);
        end;
    end;
    if ent <> nil then
    begin
        if ent_len < drbg.min_entropylen then
        begin
            ERR_raise(ERR_LIB_RAND, RAND_R_ENTROPY_OUT_OF_RANGE);
            Int(drbg.state) := EVP_RAND_STATE_ERROR;
            Exit(0);
        end;
        if ent_len > drbg.max_entropylen then
        begin
            ERR_raise(ERR_LIB_RAND, RAND_R_ENTROPY_INPUT_TOO_LONG);
            Int(drbg.state) := EVP_RAND_STATE_ERROR;
            Exit(0);
        end;
    end;
    if adin = nil then
    begin
        adinlen := 0;
    end
    else
    if (adinlen > drbg.max_adinlen) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_ADDITIONAL_INPUT_TOO_LONG);
        Exit(0);
    end;

    Int(drbg.state) := EVP_RAND_STATE_ERROR;
    drbg.reseed_next_counter := tsan_load(@drbg.reseed_counter);
    if drbg.reseed_next_counter > 0 then
    begin
        Inc(drbg.reseed_next_counter);
        if 0>= drbg.reseed_next_counter then
           drbg.reseed_next_counter := 1;
    end;

    if ent <> nil then
    begin
{$IFDEF FIPS_MODULE}
        {
         * NIST SP-800-90A mandates that entropy *shall not* be provided
         * by the consuming application. Instead the data is added as additional
         * input.
         *
         * (NIST SP-800-90Ar1, Sections 9.1 and 9.2)
         }
        if 0>= drbg.reseed(drbg, nil, 0, ent, ent_len) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_RESEED);
            Exit(0);
        end;
{$ELSE} if 0>= drbg.reseed(drbg, ent, ent_len, adin, adinlen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_RESEED);
            Exit(0);
        end;
        { There isn't much point adding the same additional input twice }
        adin := nil;
        adinlen := 0;
{$ENDIF}
    end;
    { Reseed using our sources in addition }
    entropylen := get_entropy(drbg, entropy, drbg.strength,
                             drbg.min_entropylen, drbg.max_entropylen,
                             prediction_resistance);
    if (entropylen < drbg.min_entropylen)   or
       (entropylen > drbg.max_entropylen) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_ENTROPY);
        goto _end ;
    end;
    if 0>= drbg.reseed(drbg, entropy, entropylen, adin, adinlen) then
        goto _end ;
    Int(drbg.state) := EVP_RAND_STATE_READY;
    drbg.generate_counter := 1;
    drbg.reseed_time := _time(nil);
    tsan_store(@drbg.reseed_counter, drbg.reseed_next_counter);
    if drbg.parent <> nil then
       drbg.parent_reseed_counter := get_parent_reseed_count(drbg);
 _end:
    cleanup_entropy(drbg, entropy, entropylen);
    //SetLength(TBytes(entropy), 0);
    if Int(drbg.state) = EVP_RAND_STATE_READY then
       Exit(1);
    Result := 0;
end;

function get_parent_reseed_count( drbg : PPROV_DRBG):uint32;
var
  params : array of TOSSL_PARAM;
  parent : Pointer;
  r : uint32;
  label _err;
begin
{$POINTERMATH ON}
    SetLength(params, 2);
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END ;
    parent := drbg.parent;
    r := 0;
    params[0] := OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, @r);
    if  0>= ossl_drbg_lock_parent(drbg) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOCK_PARENT);
        goto _err ;
    end;
    if  0>= drbg.parent_get_ctx_params(parent, @params[0])  then
        r := 0;
    ossl_drbg_unlock_parent(drbg);
    SetLength(params, 0);
    Exit(r);

 _err:
    r := tsan_load(@drbg.reseed_counter) - 2;
    if r = 0 then
       r := UINT_MAX;
    Result := r;
 {$POINTERMATH OFF}
end;

procedure cleanup_entropy( drbg : PPROV_DRBG; &out : PByte; outlen : size_t);
begin
    if drbg.parent = nil then
    begin
{$IFDEF FIPS_MODULE}
        ossl_crngt_cleanup_entropy(drbg, out, outlen);
{$ELSE ossl_prov_cleanup_entropy(drbg.provctx, out, outlen);}
{$ENDIF}
    end
    else
    if Assigned(drbg.parent_clear_seed) then
    begin
        if  0>= ossl_drbg_lock_parent(drbg  )   then
            exit;
        drbg.parent_clear_seed(drbg, &out, outlen);
        ossl_drbg_unlock_parent(drbg);
    end;
end;

procedure ossl_drbg_unlock_parent( drbg : PPROV_DRBG);
var
  parent : Pointer;
begin
    parent := drbg.parent;
    if (parent <> nil)  and  (Assigned(drbg.parent_unlock)) then
       drbg.parent_unlock(parent);
end;

function ossl_drbg_lock_parent( drbg : PPROV_DRBG):integer;
var
  parent : Pointer;
begin
    parent := drbg.parent;
    if (parent <> nil)
             and  (Assigned(drbg.parent_lock) )
             and  (0>= drbg.parent_lock(parent) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
        Exit(0);
    end;
    Result := 1;
end;

function get_parent_strength( drbg : PPROV_DRBG; str : Puint32):integer;
var
  params : array of TOSSL_PARAM;
  parent : Pointer;
  res : integer;
begin
{$POINTERMATH ON}
    SetLength(params, 2);
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END ;
    parent := drbg.parent;
    if not Assigned(drbg.parent_get_ctx_params) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PARENT_STRENGTH);
        Exit(0);
    end;
    params[0] := OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, str);
    if  0>= ossl_drbg_lock_parent(drbg)  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOCK_PARENT);
        Exit(0);
    end;
    res := drbg.parent_get_ctx_params(parent, @params[0]);
    ossl_drbg_unlock_parent(drbg);
    if  0>= res then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PARENT_STRENGTH);
        Exit(0);
    end;
    SetLength(params, 0);
    Result := 1;
{$POINTERMATH OFF}
end;

function get_entropy( drbg : PPROV_DRBG;out pout : PByte; entropy : integer;
                      min_len, max_len : size_t; prediction_resistance : integer):size_t;
var
  bytes : size_t;
  p_str : uint32;
begin
    if drbg.parent = nil then
{$ifdef FIPS_MODULE}
      Exit(ossl_crngt_get_entropy(drbg, pout, entropy, min_len, max_len,
                                      prediction_resistance);
{$ELSE}
      Exit(ossl_prov_get_entropy(drbg.provctx, pout, entropy, min_len,
                                     max_len));
{$ENDIF}
    if not Assigned(drbg.parent_get_seed) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_CANNOT_SUPPLY_ENTROPY_SEED);
        Exit(0);
    end;
    if  0 >= get_parent_strength(drbg, @p_str)  then
        Exit(0);
    if drbg.strength > p_str then
    begin
        {
         * We currently don't support the algorithm from NIST SP 800-90C
         * 10.1.2 to use a weaker DRBG as source
         }
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_STRENGTH_TOO_WEAK);
        Exit(0);
    end;
    {
     * Our lock is already held, but we need to lock our parent before
     * generating bits from it.  Note: taking the lock will be a no-op
     * if locking is0>= required (while drbg.parent.lock = nil).
     }
    if  0>= ossl_drbg_lock_parent(drbg)   then
        Exit(0);
    {
     * Get random data from parent.  Include our DRBG address as
     * additional input, in order to provide a distinction between
     * different DRBG child instances.
     *
     * Note: using the sizeof() operator on a pointer triggers
     *       a warning in some static code analyzers, but it's
     *       intentional and correct here.
     }
    bytes := drbg.parent_get_seed(drbg.parent, pout, drbg.strength,
                                  min_len, max_len, prediction_resistance,
                                  PByte(@drbg), sizeof(drbg));
    ossl_drbg_unlock_parent(drbg);
    Result := bytes;
end;

function prov_drbg_nonce_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
var
  dngbl : PPROV_DRBG_NONCE_GLOBAL;
begin
    dngbl := OPENSSL_zalloc(sizeof( dngbl^));
    if dngbl = nil then Exit(nil);
    dngbl.rand_nonce_lock := CRYPTO_THREAD_lock_new();
    if dngbl.rand_nonce_lock = nil then
    begin
        OPENSSL_free(dngbl);
        Exit(nil);
    end;
    Result := dngbl;
end;


procedure prov_drbg_nonce_ossl_ctx_free( vdngbl : Pointer);
var
  dngbl : PPROV_DRBG_NONCE_GLOBAL;
begin
    dngbl := vdngbl;
    if dngbl = nil then exit;
    CRYPTO_THREAD_lock_free(dngbl.rand_nonce_lock);
    OPENSSL_free(dngbl);
end;

function prov_drbg_get_nonce( drbg : PPROV_DRBG; pout : PPByte; min_len, max_len : size_t):size_t;
type
  data_st = record
     drbg: Pointer;
     count: int ;
  end;
var
  data: data_st;
  ret ,n: size_t;
  buf : PByte;
  libctx : POSSL_LIB_CTX;
  dngbl : PPROV_DRBG_NONCE_GLOBAL;
  count : integer;
begin
    ret := 0;
    buf := nil;
    libctx := ossl_prov_ctx_get0_libctx(drbg.provctx);
    dngbl := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_DRBG_NONCE_INDEX,
                                @drbg_nonce_ossl_ctx_method);

    if dngbl = nil then Exit(0);
    if (drbg.parent <> nil)  and  ( Assigned(drbg.parent_nonce) ) then
    begin
        n := drbg.parent_nonce(drbg.parent, nil, 0, drbg.min_noncelen,
                               drbg.max_noncelen);
        buf := OPENSSL_malloc(n);
        if (n > 0)  and  (buf <> nil) then
        begin
            ret := drbg.parent_nonce(drbg.parent, buf, 0,
                                     drbg.min_noncelen, drbg.max_noncelen);
            if ret = n then
            begin
                pout^ := buf;
                Exit(ret);
            end;
            OPENSSL_free(buf);
        end;
    end;
    { Use the built in nonce source plus some of our specifics }
    memset(@data, 0, sizeof(data));
    data.drbg := drbg;
    CRYPTO_atomic_add(@dngbl.rand_nonce_count, 1, @data.count,
                      dngbl.rand_nonce_lock);
    Exit(ossl_prov_get_nonce(drbg.provctx, pout, min_len, max_len,
                               @data, sizeof(data)));
end;

function ossl_prov_drbg_instantiate(drbg : PPROV_DRBG; strength : uint32; prediction_resistance : integer; pers : PByte; perslen : size_t):integer;
var
  nonce,entropy  : PByte;
  noncelen, entropylen,
  min_entropy,
  min_entropylen,
  max_entropylen : size_t;
  label _end;
begin
    nonce := nil; entropy := nil;
    noncelen := 0; entropylen := 0;
    if strength > drbg.strength then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH);
        goto _end ;
    end;
    min_entropy := drbg.strength;
    min_entropylen := drbg.min_entropylen;
    max_entropylen := drbg.max_entropylen;
    if pers = nil then
    begin
        pers := PByte(ossl_pers_string);
        perslen := sizeof(ossl_pers_string);
    end;
    if perslen > drbg.max_perslen then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_PERSONALISATION_STRING_TOO_LONG);
        goto _end ;
    end;
    if Int(drbg.state) <> EVP_RAND_STATE_UNINITIALISED then
    begin
        if Int(drbg.state) = EVP_RAND_STATE_ERROR then
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE)
        else
            ERR_raise(ERR_LIB_PROV, PROV_R_ALREADY_INSTANTIATED);
        goto _end ;
    end;
    Int(drbg.state) := EVP_RAND_STATE_ERROR;
    if drbg.min_noncelen > 0 then
    begin
        if Assigned(drbg.parent_nonce ) then
        begin
            noncelen := drbg.parent_nonce(drbg.parent, nil, drbg.strength,
                                          drbg.min_noncelen,
                                          drbg.max_noncelen);
            if noncelen = 0 then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto _end ;
            end;
            nonce := OPENSSL_malloc(noncelen);
            if nonce = nil then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto _end ;
            end;
            if noncelen <> drbg.parent_nonce(drbg.parent, nonce,
                                               drbg.strength,
                                               drbg.min_noncelen,
                                               drbg.max_noncelen) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto _end ;
            end;
{$IFNDEF PROV_RAND_GET_RANDOM_NONCE}
        end
        else
        if (drbg.parent <> nil) then
        begin
{$ENDIF}
            {
             * NIST SP800-90Ar1 section 9.1 says you can combine getting
             * the entropy and nonce in 1 call by increasing the entropy
             * with 50% and increasing the minimum length to accommodate
             * the length of the nonce. We do this in case a nonce is
             * required and there is no parental nonce capability.
             }
            min_entropy  := min_entropy + (drbg.strength div 2);
            min_entropylen  := min_entropylen + drbg.min_noncelen;
            max_entropylen  := max_entropylen + drbg.max_noncelen;
        end
{$IFNDEF PROV_RAND_GET_RANDOM_NONCE}
        else
        begin  { parent = nil }
            noncelen := prov_drbg_get_nonce(drbg, @nonce, drbg.min_noncelen,
                                           drbg.max_noncelen);
            if (noncelen < drbg.min_noncelen)
                     or  (noncelen > drbg.max_noncelen) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto _end ;
            end;
        end;
{$ENDIF}
    end;
    drbg.reseed_next_counter := tsan_load(@drbg.reseed_counter);
    if drbg.reseed_next_counter>0 then
    begin
        Inc(drbg.reseed_next_counter);
        if  0>= drbg.reseed_next_counter then
           drbg.reseed_next_counter := 1;
    end;
    entropylen := get_entropy(drbg, entropy, min_entropy,
                             min_entropylen, max_entropylen,
                             prediction_resistance);
    if (entropylen < min_entropylen) or  (entropylen > max_entropylen) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_ENTROPY);
        goto _end ;
    end;
    if  0>= drbg.instantiate(drbg, entropy, entropylen, nonce, noncelen,
                           pers, perslen )then
    begin
        cleanup_entropy(drbg, entropy, entropylen);
        ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_INSTANTIATING_DRBG);
        goto _end ;
    end;
    cleanup_entropy(drbg, entropy, entropylen);
    //SetLength(TBytes(entropy), 0);
    Int(drbg.state) := EVP_RAND_STATE_READY;
    drbg.generate_counter := 1;
    drbg.reseed_time := _time(nil);
    tsan_store(@drbg.reseed_counter, drbg.reseed_next_counter);

 _end:
    if nonce <> nil then
       ossl_prov_cleanup_nonce(drbg.provctx, nonce, noncelen);
    if Int(drbg.state) = EVP_RAND_STATE_READY then
       Exit(1);
    Result := 0;
end;



function rand_drbg_restart( drbg : PPROV_DRBG):Boolean;
begin
    { repair error state }
    if Int(drbg.state) = EVP_RAND_STATE_ERROR then
       drbg.uninstantiate(drbg);
    { repair uninitialized state }
    if Int(drbg.state) = EVP_RAND_STATE_UNINITIALISED then { reinstantiate drbg }
        ossl_prov_drbg_instantiate(drbg, drbg.strength, 0, nil, 0);
    Result := Int(drbg.state) = EVP_RAND_STATE_READY;
end;

function ossl_prov_drbg_generate(drbg : PPROV_DRBG; _out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;adin : PByte; adinlen : size_t):integer;
var
  fork_id,
  reseed_required : integer;
  _now            : time_t;
begin
    reseed_required := 0;
    if  not ossl_prov_is_running()  then
        Exit(0);
    if Int(drbg.state) <> EVP_RAND_STATE_READY then
    begin
        { try to recover from previous errors }
        rand_drbg_restart(drbg);
        if Int(drbg.state) = EVP_RAND_STATE_ERROR then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
            Exit(0);
        end;
        if Int(drbg.state) = EVP_RAND_STATE_UNINITIALISED then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
            Exit(0);
        end;
    end;
    if strength > drbg.strength then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH);
        Exit(0);
    end;
    if outlen > drbg.max_request then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_REQUEST_TOO_LARGE_FOR_DRBG);
        Exit(0);
    end;
    if adinlen > drbg.max_adinlen then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_ADDITIONAL_INPUT_TOO_LONG);
        Exit(0);
    end;
    fork_id := openssl_get_fork_id();
    if drbg.fork_id <> fork_id then begin
        drbg.fork_id := fork_id;
        reseed_required := 1;
    end;
    if drbg.reseed_interval > 0 then begin
        if drbg.generate_counter >= drbg.reseed_interval then
            reseed_required := 1;
    end;

    if drbg.reseed_time_interval > 0 then
    begin
        _now := _time(nil);
        if (_now < drbg.reseed_time)  or
           (_now - drbg.reseed_time >= drbg.reseed_time_interval) then
             reseed_required := 1;
    end;

    if (drbg.parent <> nil) and
       (get_parent_reseed_count(drbg) <> drbg.parent_reseed_counter)  then
        reseed_required := 1;

    if (reseed_required>0)  or  (prediction_resistance>0) then
    begin
        if ( 0>= ossl_prov_drbg_reseed(drbg, prediction_resistance, nil, 0,
                                   adin, adinlen)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_RESEED_ERROR);
            Exit(0);
        end;
        adin := nil;
        adinlen := 0;
    end;
    //OpenSSL3.providers.implementations.rands.drbg_ctr: function drbg_ctr_generate
    if 0>= drbg.generate(drbg, _out, outlen, adin, adinlen) then
    begin
        Int(drbg.state) := EVP_RAND_STATE_ERROR;
        ERR_raise(ERR_LIB_PROV, PROV_R_GENERATE_ERROR);
        Exit(0);
    end;
    Inc(drbg.generate_counter);
    Result := 1;
end;

procedure ossl_drbg_clear_seed( vdrbg : Pointer; _out : PByte; outlen : size_t);
begin
    //OPENSSL_secure_clear_free(&out, outlen);
    if Length(TBytes(_out)) = outlen then
       SetLength(TBytes(_out), 0);
end;

function ossl_drbg_get_seed(vdrbg : Pointer;out pout : PByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer;const adin : PByte; adin_len : size_t):size_t;
var
    drbg         : PPROV_DRBG;
    bytes_needed : size_t;
begin
    drbg := PPROV_DRBG ( vdrbg);
    { Figure out how many bytes we need }
    bytes_needed := get_result(entropy >= 0 , (entropy + 7) div 8 , 0);
    if bytes_needed < min_len then
       bytes_needed := min_len;
    if bytes_needed > max_len then
       bytes_needed := max_len;
    { Allocate storage }
    pout := OPENSSL_secure_malloc(bytes_needed);
    //原本为nil的pout在此处被分配内存
    //SetLength(TBytes(pout), bytes_needed);
    if pout = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    {
     * Get random data.  Include our DRBG address as
     * additional input, in order to provide a distinction between
     * different DRBG child instances.
     *
     * Note: using the sizeof() operator on a pointer triggers
     *       a warning in some static code analyzers, but it's
     *       intentional and correct here.
     }
    //pout的成员被赋值
    if 0 >= ossl_prov_drbg_generate(drbg, pout, bytes_needed,
                                 drbg.strength, prediction_resistance,
                                 PByte(@drbg), sizeof(drbg)) then
    begin
        OPENSSL_secure_clear_free(pout, bytes_needed);
        ERR_raise(ERR_LIB_PROV, PROV_R_GENERATE_ERROR);
        Exit(0);
    end;
    Result := bytes_needed;
end;

procedure ossl_drbg_unlock( vctx : Pointer);
var
  drbg : PPROV_DRBG;
begin
    drbg := vctx;
    if (drbg <> nil)  and  (drbg.lock <> nil) then
       CRYPTO_THREAD_unlock(drbg.lock);
end;

function ossl_drbg_lock( vctx : Pointer):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := vctx;
    if (drbg = nil)  or  (drbg.lock = nil) then Exit(1);
    Result := CRYPTO_THREAD_write_lock(drbg.lock);
end;

function ossl_drbg_enable_locking( vctx : Pointer):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := vctx;
    if (drbg <> nil)  and  (drbg.lock = nil) then
    begin
        if Assigned(drbg.parent_enable_locking ) then
            if ( 0>= drbg.parent_enable_locking(drbg.parent)) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
                Exit(0);
            end;
        drbg.lock := CRYPTO_THREAD_lock_new();
        if drbg.lock = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_CREATE_LOCK);
            Exit(0);
        end;
    end;
    Result := 1;
end;


end.
