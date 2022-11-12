unit OpenSSL3.providers.implementations.rands.drbg_hmac;

interface
uses  OpenSSL.Api, DateUtils, SysUtils,
    OpenSSL3.providers.implementations.rands.drbg;

function drbg_hmac_new_wrapper(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
procedure drbg_hmac_free( vdrbg : Pointer);
function drbg_hmac_instantiate_wrapper(vdrbg : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
function drbg_hmac_uninstantiate_wrapper( vdrbg : Pointer):integer;
function drbg_hmac_generate_wrapper(vdrbg : Pointer; &out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
 function drbg_hmac_reseed_wrapper(vdrbg : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
function drbg_hmac_settable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
function drbg_hmac_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function drbg_hmac_gettable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
function drbg_hmac_get_ctx_params( vdrbg : Pointer; params : POSSL_PARAM):integer;
function drbg_hmac_verify_zeroization( vdrbg : Pointer):integer;

const ossl_drbg_ossl_hmac_functions: array[0..16] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_RAND_NEWCTX; method:(code:@drbg_hmac_new_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_FREECTX; method:(code:@drbg_hmac_free ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_INSTANTIATE;
      method:(code:@drbg_hmac_instantiate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNINSTANTIATE;
      method:(code:@drbg_hmac_uninstantiate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GENERATE; method:(code:@drbg_hmac_generate_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_RESEED; method:(code:@drbg_hmac_reseed_wrapper ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_ENABLE_LOCKING; method:(code:@ossl_drbg_enable_locking ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_LOCK; method:(code:@ossl_drbg_lock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_UNLOCK; method:(code:@ossl_drbg_unlock ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS;
      method:(code:@drbg_hmac_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_SET_CTX_PARAMS; method:(code:@drbg_hmac_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS;
      method:(code:@drbg_hmac_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_CTX_PARAMS; method:(code:@drbg_hmac_get_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_VERIFY_ZEROIZATION;
      method:(code:@drbg_hmac_verify_zeroization ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_GET_SEED; method:(code:@ossl_drbg_get_seed ;data:nil)),
    ( function_id: OSSL_FUNC_RAND_CLEAR_SEED; method:(code:@ossl_drbg_clear_seed ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil))
);

function drbg_hmac_uninstantiate( drbg : PPROV_DRBG):integer;
function drbg_hmac_new( drbg : PPROV_DRBG):integer;
function drbg_hmac_instantiate(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const nonce : PByte; nonce_len : size_t;const pstr : PByte; pstr_len : size_t):integer;
function drbg_hmac_update(drbg : PPROV_DRBG;const in1 : PByte; in1len : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
function do_hmac(hmac : PPROV_DRBG_HMAC; inbyte : Byte;const in1 : PByte; in1len : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
 function drbg_hmac_reseed(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
 function drbg_hmac_generate(drbg : PPROV_DRBG; &out : PByte; outlen : size_t;const adin : PByte; adin_len : size_t):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem_sec, openssl3.providers.fips.self_test,
     openssl3.crypto.mem, openssl3.providers.common.provider_ctx,
     openssl3.crypto.context, openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,OpenSSL3.providers.implementations.rands.crngt,
     OpenSSL3.openssl.params, openssl3.crypto.params,
     OpenSSL3.threads_none, OpenSSL3.openssl.core_dispatch,
     OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib;


var // 1d arrays
  known_settable_ctx_params : array[0..5] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..15] of TOSSL_PARAM;





function drbg_hmac_generate(drbg : PPROV_DRBG; &out : PByte; outlen : size_t;const adin : PByte; adin_len : size_t):integer;
var
  hmac : PPROV_DRBG_HMAC;

  ctx : PEVP_MAC_CTX;

  temp : PByte;
begin
    hmac := PPROV_DRBG_HMAC ( drbg.data);
    ctx := hmac.ctx;
    temp := @hmac.V;
    { (Step 2) if adin <> nil then (K,V) = HMAC_DRBG_Update(adin, K, V) }
    if (adin <> nil)
             and  (adin_len > 0)
             and  (0>= drbg_hmac_update(drbg, adin, adin_len, nil, 0, nil, 0) )then
        Exit(0);
    (*
     * (Steps 3-5) temp = nil
     *             while (len(temp) < outlen) {
     *                 V = HMAC(K, V)
     *                 temp = temp  or  V
     *             }
     *)
    while True do
    begin
        if (0>= EVP_MAC_init(ctx, @hmac.K, hmac.blocklen, nil ) )or
           (0>= EVP_MAC_update(ctx, temp, hmac.blocklen)) then
            Exit(0);
        if outlen > hmac.blocklen then
        begin
            if 0>= EVP_MAC_final(ctx, &out, nil, outlen) then
                Exit(0);
            temp := out;
        end
        else
        begin
            if 0>= EVP_MAC_final(ctx, @hmac.V, nil, sizeof(hmac.V))  then
                Exit(0);
            memcpy(&out, @hmac.V, outlen);
            break;
        end;
        &out  := &out + hmac.blocklen;
        outlen  := outlen - hmac.blocklen;
    end;
    { (Step 6) (K,V) = HMAC_DRBG_Update(adin, K, V) }
    if 0>= drbg_hmac_update(drbg, adin, adin_len, nil, 0, nil, 0)  then
        Exit(0);
    Result := 1;
end;





function drbg_hmac_reseed(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
begin
    { (Step 2) (K,V) = HMAC_DRBG_Update(entropy or additional_input, K, V) }
    Result := drbg_hmac_update(drbg, ent, ent_len, adin, adin_len, nil, 0);
end;





function do_hmac(hmac : PPROV_DRBG_HMAC; inbyte : Byte;const in1 : PByte; in1len : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
var
  ctx : PEVP_MAC_CTX;
begin
    ctx := hmac.ctx;
    if  (0>= EVP_MAC_init(ctx, @hmac.K, hmac.blocklen, nil)) { K = HMAC(K, V  or  inbyte  or  [in1]  or  [in2]  or  [in3]) }
             or  (0>= EVP_MAC_update(ctx, @hmac.V, hmac.blocklen))
             or  (0>= EVP_MAC_update(ctx, @inbyte, 1))
             or  not ( (in1 = nil)  or  (in1len = 0)  or  (EVP_MAC_update(ctx, in1, in1len)>0) )
             or  not ( (in2 = nil)  or  (in2len = 0)  or  (EVP_MAC_update(ctx, in2, in2len)>0) )
             or  not ( (in3 = nil)  or  (in3len = 0)  or  (EVP_MAC_update(ctx, in3, in3len)>0) )
             or  (0>= EVP_MAC_final(ctx, @hmac.K, nil, sizeof(hmac.K))) then
        Exit(0);
   { V = HMAC(K, V) }
    Result := Int( (EVP_MAC_init(ctx, @hmac.K, hmac.blocklen, nil)>0)
            and  (EVP_MAC_update(ctx, @hmac.V, hmac.blocklen)>0)
            and  (EVP_MAC_final(ctx, @hmac.V, nil, sizeof(hmac.V))>0) );
end;




function drbg_hmac_update(drbg : PPROV_DRBG;const in1 : PByte; in1len : size_t;const in2 : PByte; in2len : size_t;const in3 : PByte; in3len : size_t):integer;
var
  hmac : PPROV_DRBG_HMAC;
begin
    hmac := PPROV_DRBG_HMAC ( drbg.data);
    { (Steps 1-2) K = HMAC(K, V or $00 or provided_data). V = HMAC(K,V) }
    if  0>= do_hmac(hmac, $00, in1, in1len, in2, in2len, in3, in3len)  then
        Exit(0);
    { (Step 3) If provided_data = nil then return (K,V) }
    if (in1len = 0)  and  (in2len = 0)  and  (in3len = 0) then Exit(1);
    { (Steps 4-5) K = HMAC(K, V or $01 or provided_data). V = HMAC(K,V) }
    Result := do_hmac(hmac, $01, in1, in1len, in2, in2len, in3, in3len);
end;




function drbg_hmac_instantiate(drbg : PPROV_DRBG;const ent : PByte; ent_len : size_t;const nonce : PByte; nonce_len : size_t;const pstr : PByte; pstr_len : size_t):integer;
var
  hmac : PPROV_DRBG_HMAC;
begin
    hmac := PPROV_DRBG_HMAC ( drbg.data);
    if hmac.ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MAC);
        Exit(0);
    end;
    { (Step 2) Key = $00 00...00 }
    memset(@hmac.K, $00, hmac.blocklen);
    { (Step 3) V = $01 01...01 }
    memset(@hmac.V, $01, hmac.blocklen);
    { (Step 4) (K,V) = HMAC_DRBG_Update(entropy or nonce or pers string, K, V) }
    Exit(drbg_hmac_update(drbg, ent, ent_len, nonce, nonce_len, pstr,
                            pstr_len));
end;

function drbg_hmac_new( drbg : PPROV_DRBG):integer;
var
  hmac : PPROV_DRBG_HMAC;
begin
    hmac := OPENSSL_secure_zalloc(sizeof( hmac^));
    if hmac = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    drbg.data := hmac;
    { See SP800-57 Part1 Rev4 5.6.1 Table 3 }
    drbg.max_entropylen := DRBG_MAX_LENGTH;
    drbg.max_noncelen := DRBG_MAX_LENGTH;
    drbg.max_perslen := DRBG_MAX_LENGTH;
    drbg.max_adinlen := DRBG_MAX_LENGTH;
    { Maximum number of bits per request = 2^19  = 2^16 bytes }
    drbg.max_request := 1  shl  16;
    Result := 1;
end;



function drbg_hmac_uninstantiate( drbg : PPROV_DRBG):integer;
var
  hmac : PPROV_DRBG_HMAC;
begin
    hmac := PPROV_DRBG_HMAC ( drbg.data);
    OPENSSL_cleanse(@hmac.K, sizeof(hmac.K));
    OPENSSL_cleanse(@hmac.V, sizeof(hmac.V));
    Result := ossl_prov_drbg_uninstantiate(drbg);
end;




function drbg_hmac_verify_zeroization( vdrbg : Pointer):integer;
var
  drbg : PPROV_DRBG;

  hmac : PPROV_DRBG_HMAC;
begin
    drbg := PPROV_DRBG ( vdrbg);
    hmac := PPROV_DRBG_HMAC(drbg.data);
    PROV_DRBG_VERYIFY_ZEROIZATION(@hmac.K);
    PROV_DRBG_VERYIFY_ZEROIZATION(@hmac.V);
    Result := 1;
end;

function drbg_hmac_get_ctx_params( vdrbg : Pointer; params : POSSL_PARAM):integer;
var
  drbg : PPROV_DRBG;
  hmac : PPROV_DRBG_HMAC;
  name : PUTF8Char;
  md : PEVP_MD;
  p : POSSL_PARAM;
begin
    drbg := PPROV_DRBG ( vdrbg);
    hmac := (PPROV_DRBG_HMAC  (drbg.data));
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAC);
    if p <> nil then begin
        if hmac.ctx = nil then
            Exit(0);
        name := EVP_MAC_get0_name(EVP_MAC_CTX_get0_mac(hmac.ctx));
        if  0>= OSSL_PARAM_set_utf8_string(p, name)  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_DIGEST);
    if p <> nil then
    begin
        md := ossl_prov_digest_md(@hmac.digest);
        if (md = nil)  or
           (0>= OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(md)) )  then
            Exit(0);
    end;
    Result := ossl_drbg_get_ctx_params(drbg, params);
end;

function drbg_hmac_gettable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_MAC, nil, 0);
    known_gettable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, nil, 0);
    known_gettable_ctx_params[2] := _OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nil);
    known_gettable_ctx_params[3] := _OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nil);
    known_gettable_ctx_params[4] := _OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nil);
    known_gettable_ctx_params[5] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, nil);
    known_gettable_ctx_params[6] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, nil);
    known_gettable_ctx_params[7] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN, nil);
    known_gettable_ctx_params[8] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN, nil);
    known_gettable_ctx_params[9] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN, nil);
    known_gettable_ctx_params[10] := _OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN, nil);
    known_gettable_ctx_params[11] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, nil);
    known_gettable_ctx_params[12] := _OSSL_PARAM_time_t(OSSL_DRBG_PARAM_RESEED_TIME, nil);
    known_gettable_ctx_params[13] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, nil);
    known_gettable_ctx_params[14] := _OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, nil);
    known_gettable_ctx_params[15] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;



function drbg_hmac_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_DRBG;

  hmac : PPROV_DRBG_HMAC;

  libctx : POSSL_LIB_CTX;

  md : PEVP_MD;
begin
    ctx := PPROV_DRBG ( vctx);
    hmac := (PPROV_DRBG_HMAC(ctx.data));
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if  0>= ossl_prov_digest_load_from_params(@hmac.digest, params, libctx) then
        Exit(0);
    {
     * Confirm digest is allowed. We allow all digests that are not XOF
     * (such as SHAKE).  In FIPS mode, the fetch will fail for non-approved
     * digests.
     }
    md := ossl_prov_digest_md(@hmac.digest);
    if (md <> nil)  and
       ( (EVP_MD_get_flags(md) and EVP_MD_FLAG_XOF) <> 0) then
       begin
        ERR_raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED);
        Exit(0);
    end;
    if  0>= ossl_prov_macctx_load_from_params(@hmac.ctx, params,
                                           nil, nil, nil, libctx)  then
        Exit(0);
    if hmac.ctx <> nil then
    begin
        { These are taken from SP 800-90 10.1 Table 2 }
        hmac.blocklen := EVP_MD_get_size(md);
        { See SP800-57 Part1 Rev4 5.6.1 Table 3 }
        ctx.strength := 64 * int(hmac.blocklen  shr  3);
        if ctx.strength > 256 then
           ctx.strength := 256;
        ctx.seedlen := hmac.blocklen;
        ctx.min_entropylen := ctx.strength div 8;
        ctx.min_noncelen := ctx.min_entropylen div 2;
    end;
    Result := ossl_drbg_set_ctx_params(ctx, params);
end;

function drbg_hmac_settable_ctx_params( vctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_MAC, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, nil);
    known_settable_ctx_params[4] := _OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, nil);
    known_settable_ctx_params[5] := OSSL_PARAM_END ;

    Result := @known_settable_ctx_params;
end;




function drbg_hmac_reseed_wrapper(vdrbg : Pointer; prediction_resistance : integer;const ent : PByte; ent_len : size_t;const adin : PByte; adin_len : size_t):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG ( vdrbg);
    Exit(ossl_prov_drbg_reseed(drbg, prediction_resistance, ent, ent_len,
                                 adin, adin_len));
end;




function drbg_hmac_generate_wrapper(vdrbg : Pointer; &out : PByte; outlen : size_t; strength : uint32; prediction_resistance : integer;const adin : PByte; adin_len : size_t):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG ( vdrbg);
    Exit(ossl_prov_drbg_generate(drbg, &out, outlen, strength,
                                   prediction_resistance, adin, adin_len));
end;



function drbg_hmac_uninstantiate_wrapper( vdrbg : Pointer):integer;
begin
    Result := drbg_hmac_uninstantiate(PPROV_DRBG ( vdrbg));
end;

function drbg_hmac_instantiate_wrapper(vdrbg : Pointer; strength : uint32; prediction_resistance : integer;const pstr : PByte; pstr_len : size_t;const params : POSSL_PARAM):integer;
var
  drbg : PPROV_DRBG;
begin
    drbg := PPROV_DRBG ( vdrbg);
    if  (not ossl_prov_is_running)  or
        (0>= drbg_hmac_set_ctx_params(drbg, params)) then
        Exit(0);
    Exit(ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance,
                                      pstr, pstr_len));
end;

procedure drbg_hmac_free( vdrbg : Pointer);
var
  drbg : PPROV_DRBG;

  hmac : PPROV_DRBG_HMAC;
begin
    drbg := PPROV_DRBG ( vdrbg);
    hmac := PPROV_DRBG_HMAC( drbg.data);
    if (drbg <> nil)  and  (hmac <> nil)   then
    begin
        EVP_MAC_CTX_free(hmac.ctx);
        ossl_prov_digest_reset(@hmac.digest);
        OPENSSL_secure_clear_free(hmac, sizeof( hmac^));
    end;
    ossl_rand_drbg_free(drbg);
end;




function drbg_hmac_new_wrapper(provctx, parent : Pointer;const parent_dispatch : POSSL_DISPATCH):Pointer;
begin
    Exit(ossl_rand_drbg_new(provctx, parent, parent_dispatch, @drbg_hmac_new,
                              @drbg_hmac_instantiate, @drbg_hmac_uninstantiate,
                              @drbg_hmac_reseed, @drbg_hmac_generate));
end;


end.
