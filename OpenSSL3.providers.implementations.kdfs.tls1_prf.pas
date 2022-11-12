unit OpenSSL3.providers.implementations.kdfs.tls1_prf;

interface
uses OpenSSL.Api;

function kdf_tls1_prf_new( provctx : Pointer):Pointer;
procedure kdf_tls1_prf_free( vctx : Pointer);
 procedure kdf_tls1_prf_reset( vctx : Pointer);
function kdf_tls1_prf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function kdf_tls1_prf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_tls1_prf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function kdf_tls1_prf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_tls1_prf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function tls1_prf_alg(mdctx, sha1ctx : PEVP_MAC_CTX;const sec : PByte; slen : size_t;const seed : PByte; seed_len : size_t; &out : PByte; olen : size_t):integer;
function tls1_prf_P_hash(ctx_init : PEVP_MAC_CTX;const sec : PByte; sec_len : size_t;const seed : PByte; seed_len : size_t; &out : PByte; olen : size_t):integer;

const
    TLS1_PRF_MAXBUF = 1024;

    ossl_kdf_tls1_prf_functions: array[0..8] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_KDF_NEWCTX;              method:(code:@kdf_tls1_prf_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX;             method:(code:@kdf_tls1_prf_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET;               method:(code:@kdf_tls1_prf_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE;              method:(code:@kdf_tls1_prf_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS; method:(code:@kdf_tls1_prf_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS;      method:(code:@kdf_tls1_prf_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS; method:(code:@kdf_tls1_prf_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS;      method:(code:@kdf_tls1_prf_get_ctx_params ;data:nil)),
    ( function_id: 0;                                 method:(code:nil ;data:nil) ));



var // 1d arrays
  known_settable_ctx_params : array[0..4] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;


implementation
uses OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,openssl3.crypto.evp.evp_lib,
     openssl3.crypto.evp.mac_lib;




function tls1_prf_P_hash(ctx_init : PEVP_MAC_CTX;const sec : PByte; sec_len : size_t;const seed : PByte; seed_len : size_t; &out : PByte; olen : size_t):integer;
var
  chunk : size_t;

  ctx,ctx_Ai : PEVP_MAC_CTX;

  Ai : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  Ai_len : size_t;

  ret : integer;
  label _err;
begin
    ctx := nil; ctx_Ai := nil;
    ret := 0;
    if 0>= EVP_MAC_init(ctx_init, sec, sec_len, nil) then
        goto _err ;
    chunk := EVP_MAC_CTX_get_mac_size(ctx_init);
    if chunk = 0 then goto _err ;
    { A(0) = seed }
    ctx_Ai := EVP_MAC_CTX_dup(ctx_init);
    if ctx_Ai = nil then goto _err ;
    if (seed <> nil)  and  (0>= EVP_MAC_update(ctx_Ai, seed, seed_len)) then
        goto _err ;
    while True do
    begin
        { calc: A(i) = HMAC_<hash>(secret, A(i-1)) }
        if 0>= EVP_MAC_final(ctx_Ai, @Ai, @Ai_len, sizeof(Ai)) then
            goto _err ;
        EVP_MAC_CTX_free(ctx_Ai);
        ctx_Ai := nil;
        { calc next chunk: HMAC_<hash>(secret, A(i) + seed) }
        ctx := EVP_MAC_CTX_dup(ctx_init);
        if ctx = nil then goto _err ;
        if 0>= EVP_MAC_update(ctx, @Ai, Ai_len) then
            goto _err ;
        { save state for calculating next A(i) value }
        if olen > chunk then
        begin
            ctx_Ai := EVP_MAC_CTX_dup(ctx);
            if ctx_Ai = nil then goto _err ;
        end;
        if (seed <> nil)  and  (0>= EVP_MAC_update(ctx, seed, seed_len)) then
            goto _err ;
        if olen <= chunk then
        begin
            { last chunk - use Ai as temp bounce buffer }
            if 0>= EVP_MAC_final(ctx, @Ai, @Ai_len, sizeof(Ai)) then
                goto _err ;
            memcpy(&out, @Ai, olen);
            break;
        end;
        if 0>= EVP_MAC_final(ctx, out, nil, olen) then
            goto _err ;
        EVP_MAC_CTX_free(ctx);
        ctx := nil;
        &out  := &out + chunk;
        olen  := olen - chunk;
    end;
    ret := 1;
 _err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(ctx_Ai);
    OPENSSL_cleanse(@Ai, sizeof(Ai));
    Result := ret;
end;



function tls1_prf_alg(mdctx, sha1ctx : PEVP_MAC_CTX;const sec : PByte; slen : size_t;const seed : PByte; seed_len : size_t; &out : PByte; olen : size_t):integer;
var
  i : size_t;

  tmp : PByte;

  L_S1, L_S2 : size_t;
begin
    if sha1ctx <> nil then begin
        { TLS v1.0 and TLS v1.1 }
        { calc: L_S1 = L_S2 = ceil(L_S / 2) }
        L_S1 := (slen + 1) div 2;
        L_S2 := L_S1;
        if  0>= tls1_prf_P_hash(mdctx, sec, L_S1,
                             seed, seed_len, out, olen)  then
            Exit(0);
        tmp := OPENSSL_malloc(olen);
        if tmp = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        if  0>= tls1_prf_P_hash(sha1ctx, sec + slen - L_S2, L_S2,
                             seed, seed_len, tmp, olen) then begin
            OPENSSL_clear_free(Pointer(tmp), olen);
            Exit(0);
        end;
        for i := 0 to olen-1 do
            out[i]  := out[i] xor (tmp[i]);
        OPENSSL_clear_free(Pointer(tmp), olen);
        Exit(1);
    end;
    { TLS v1.2 }
    if  0>= tls1_prf_P_hash(mdctx, sec, slen, seed, seed_len, out, olen) then
        Exit(0);
    Result := 1;
end;


function kdf_tls1_prf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, SIZE_MAX));
    Result := -2;
end;


function kdf_tls1_prf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[0] := OSSL_PARAM_END;
    Result := @known_gettable_ctx_params;
end;



function kdf_tls1_prf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;

  ctx : PTLS1_PRF;

  libctx : POSSL_LIB_CTX;

  q : Pointer;

  sz : size_t;
begin
    ctx := vctx;
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST );
    if p <> nil then
    begin
        if strcasecmp(p.data, SN_md5_sha1) = 0 then
        begin
            if (0>= ossl_prov_macctx_load_from_params(@ctx.P_hash, params,
                                                   OSSL_MAC_NAME_HMAC,
                                                   nil, SN_md5, libctx))
                 or  (0>= ossl_prov_macctx_load_from_params(@ctx.P_sha1, params,
                                                      OSSL_MAC_NAME_HMAC,
                                                      nil, SN_sha1, libctx)) then
                Exit(0);
        end
        else
        begin
            EVP_MAC_CTX_free(ctx.P_sha1);
            if 0>= ossl_prov_macctx_load_from_params(@ctx.P_hash, params,
                                                   OSSL_MAC_NAME_HMAC,
                                                   nil, nil, libctx ) then
                Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET );
    if p  <> nil then
    begin
        OPENSSL_clear_free(Pointer(ctx.sec), ctx.seclen);
        ctx.sec := nil;
        if 0>= OSSL_PARAM_get_octet_string(p, Pointer(ctx.sec), 0, @ctx.seclen) then
            Exit(0);
    end;
    { The seed fields concatenate, so process them all }
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED );
    if p <> nil then
    begin
        while p <> nil do
        begin
            q := PByte(@ctx.seed) + ctx.seedlen;
            sz := 0;
            if (p.data_size <> 0 )
                 and  (p.data <> nil )
                 and  (0>= OSSL_PARAM_get_octet_string(p, q,
                                                TLS1_PRF_MAXBUF - ctx.seedlen,
                                                @sz)) then
                Exit(0);
            ctx.seedlen  := ctx.seedlen + sz;
            inc(p);
            p := OSSL_PARAM_locate_const(p, OSSL_KDF_PARAM_SEED);
        end;
    end;
    Result := 1;
end;



function kdf_tls1_prf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, nil, 0);
    known_settable_ctx_params[4] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;


function kdf_tls1_prf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PTLS1_PRF;
begin
    ctx := (PTLS1_PRF  (vctx));
    if (not ossl_prov_is_running)  or
       (0>= kdf_tls1_prf_set_ctx_params(ctx, params)) then
        Exit(0);
    if ctx.P_hash = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    if ctx.sec = nil then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        Exit(0);
    end;
    if ctx.seedlen = 0 then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        Exit(0);
    end;
    if keylen = 0 then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    Exit(tls1_prf_alg(ctx.P_hash, ctx.P_sha1,
                        ctx.sec, ctx.seclen,
                        @ctx.seed, ctx.seedlen,
                        key, keylen));
end;



procedure kdf_tls1_prf_reset( vctx : Pointer);
var
  ctx : PTLS1_PRF;

  provctx : Pointer;
begin
    ctx := (PTLS1_PRF (vctx));
    provctx := ctx.provctx;
    EVP_MAC_CTX_free(ctx.P_hash);
    EVP_MAC_CTX_free(ctx.P_sha1);
    OPENSSL_clear_free(Pointer(ctx.sec), ctx.seclen);
    OPENSSL_cleanse(@ctx.seed, ctx.seedlen);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
end;



procedure kdf_tls1_prf_free( vctx : Pointer);
var
  ctx : PTLS1_PRF;
begin
    ctx := (PTLS1_PRF  (vctx));
    if ctx <> nil then
    begin
        kdf_tls1_prf_reset(ctx);
        OPENSSL_free(Pointer(ctx));
    end;
end;


function kdf_tls1_prf_new( provctx : Pointer):Pointer;
var
  ctx : PTLS1_PRF;
begin
    if not ossl_prov_is_running() then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^) );
    if ctx = nil then
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    ctx.provctx := provctx;
    Result := ctx;
end;


end.
