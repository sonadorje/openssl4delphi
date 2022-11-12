unit OpenSSL3.providers.implementations.asymciphers.sm2_enc;

interface
uses OpenSSL.Api, SysUtils;

  function sm2_newctx( provctx : Pointer):Pointer;
  function sm2_init(vpsm2ctx, vkey : Pointer;const params : POSSL_PARAM):integer;
  function sm2_get_md( psm2ctx : PPROV_SM2_CTX2):PEVP_MD;
  function sm2_asym_encrypt(vpsm2ctx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
  function sm2_asym_decrypt(vpsm2ctx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
  procedure sm2_freectx( vpsm2ctx : Pointer);
  function sm2_dupctx( vpsm2ctx : Pointer):Pointer;
  function sm2_get_ctx_params( vpsm2ctx : Pointer; params : POSSL_PARAM):integer;
  function sm2_gettable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
  function sm2_set_ctx_params(vpsm2ctx : Pointer;const params : POSSL_PARAM):integer;
  function sm2_settable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;

const
ossl_sm2_asym_cipher_functions: array[0..11] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_ASYM_CIPHER_NEWCTX; method:(code:@sm2_newctx; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT; method:(code:@sm2_init; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_ENCRYPT; method:(code:@sm2_asym_encrypt; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT; method:(code:@sm2_init; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_DECRYPT; method:(code:@sm2_asym_decrypt; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_FREECTX; method:(code:@sm2_freectx; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_DUPCTX; method:(code:@sm2_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS;
      method:(code:@sm2_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@sm2_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS;
      method:(code:@sm2_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS;
      method:(code:@sm2_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);




implementation
uses  OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.providers.fips.self_test, OpenSSL3.openssl.params,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.sm2.sm2_crypt,
     OpenSSL3.providers.common.securitycheck_default,
     openssl3.crypto.ec.ec_key,  openssl3.internal.constant_time;

var
  known_gettable_ctx_params: array[0..1] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..3] of TOSSL_PARAM ;








function sm2_newctx( provctx : Pointer):Pointer;
var
  psm2ctx : PPROV_SM2_CTX2;
begin
    psm2ctx := OPENSSL_zalloc(sizeof(TPROV_SM2_CTX2));
    if psm2ctx = nil then Exit(nil);
    psm2ctx.libctx := PROV_LIBCTX_OF(provctx);
    Result := psm2ctx;
end;


function sm2_init(vpsm2ctx, vkey : Pointer;const params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX2;
begin
    psm2ctx := PPROV_SM2_CTX2 ( vpsm2ctx);
    if (psm2ctx = nil)  or  (vkey = nil)  or  (0>= EC_KEY_up_ref(vkey)) then
        Exit(0);
    EC_KEY_free(psm2ctx.key);
    psm2ctx.key := vkey;
    Result := sm2_set_ctx_params(psm2ctx, params);
end;


function sm2_get_md( psm2ctx : PPROV_SM2_CTX2):PEVP_MD;
var
  md : PEVP_MD;
begin
    md := ossl_prov_digest_md(@psm2ctx.md);
    if md = nil then
       md := ossl_prov_digest_fetch(@psm2ctx.md, psm2ctx.libctx, 'SM3', nil);
    Result := md;
end;


function sm2_asym_encrypt(vpsm2ctx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
var
  psm2ctx : PPROV_SM2_CTX2;

  md : PEVP_MD;
begin
    psm2ctx := PPROV_SM2_CTX2 ( vpsm2ctx);
    md := sm2_get_md(psm2ctx);
    if md = nil then Exit(0);
    if out = nil then
    begin
        if 0>= ossl_sm2_ciphertext_size(psm2ctx.key, md, inlen, outlen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            Exit(0);
        end;
        Exit(1);
    end;
    Result := ossl_sm2_encrypt(psm2ctx.key, md, &in, inlen, out, outlen);
end;


function sm2_asym_decrypt(vpsm2ctx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
var
  psm2ctx : PPROV_SM2_CTX2;

  md : PEVP_MD;
begin
   psm2ctx := PPROV_SM2_CTX2 ( vpsm2ctx);
   md := sm2_get_md(psm2ctx);
    if md = nil then Exit(0);
    if out = nil then
    begin
        if 0>= ossl_sm2_plaintext_size(&in, inlen, outlen) then
            Exit(0);
        Exit(1);
    end;
    Result := ossl_sm2_decrypt(psm2ctx.key, md, &in, inlen, out, outlen);
end;


procedure sm2_freectx( vpsm2ctx : Pointer);
var
  psm2ctx : PPROV_SM2_CTX2;
begin
    psm2ctx := PPROV_SM2_CTX2 ( vpsm2ctx);
    EC_KEY_free(psm2ctx.key);
    ossl_prov_digest_reset(@psm2ctx.md);
    OPENSSL_free(Pointer(psm2ctx));
end;


function sm2_dupctx( vpsm2ctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_SM2_CTX2;
begin
    srcctx := PPROV_SM2_CTX2 ( vpsm2ctx);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    if (dstctx.key <> nil)  and  (0>= EC_KEY_up_ref(dstctx.key)) then
    begin
        OPENSSL_free(Pointer(dstctx));
        Exit(nil);
    end;
    if 0>= ossl_prov_digest_copy(@dstctx.md, @srcctx.md) then
    begin
        sm2_freectx(dstctx);
        Exit(nil);
    end;
    Result := dstctx;
end;


function sm2_get_ctx_params( vpsm2ctx : Pointer; params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX2;

  p : POSSL_PARAM;

  md : PEVP_MD;
begin
    psm2ctx := PPROV_SM2_CTX2 ( vpsm2ctx);
    if vpsm2ctx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
    if p <> nil then begin
        md := ossl_prov_digest_md(@psm2ctx.md);
        if 0>= OSSL_PARAM_set_utf8_string(p, get_result(md = nil , ''
                                             , EVP_MD_get0_name(md)) )then
            Exit(0);
    end;
    Result := 1;
end;


function sm2_gettable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function sm2_set_ctx_params(vpsm2ctx : Pointer;const params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX2;
begin
    psm2ctx := PPROV_SM2_CTX2 ( vpsm2ctx);
    if psm2ctx = nil then Exit(0);
    if params = nil then Exit(1);
    if 0>= ossl_prov_digest_load_from_params(@psm2ctx.md, params,
                                           psm2ctx.libctx) then
        Exit(0);
    Result := 1;
end;


function sm2_settable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;

initialization

    known_gettable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, nil, 0);
    known_gettable_ctx_params[1] := OSSL_PARAM_END;
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_ENGINE, nil, 0);
    known_settable_ctx_params[3] := OSSL_PARAM_END;

end.
