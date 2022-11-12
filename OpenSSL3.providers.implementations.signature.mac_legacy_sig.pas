unit OpenSSL3.providers.implementations.signature.mac_legacy_sig;

interface
uses OpenSSL.api;

type
  TPROV_MAC_CTX = record
    libctx : POSSL_LIB_CTX;
    propq : PUTF8Char;
    key : PMAC_KEY;
    macctx : PEVP_MAC_CTX;
  end;
  PPROV_MAC_CTX = ^TPROV_MAC_CTX;

  function mac_newctx(provctx : Pointer;const propq, macname : PUTF8Char):Pointer;
  function mac_digest_sign_init(vpmacctx : Pointer;const mdname : PUTF8Char; vkey : Pointer;const params : POSSL_PARAM):integer;
  function mac_digest_sign_update(vpmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function mac_digest_sign_final( vpmacctx : Pointer; mac : PByte; maclen : Psize_t; macsize : size_t):integer;
  procedure mac_freectx( vpmacctx : Pointer);
  function mac_dupctx( vpmacctx : Pointer):Pointer;
  function mac_set_ctx_params(vpmacctx : Pointer;const params : POSSL_PARAM):integer;
  function mac_settable_ctx_params(ctx, provctx : Pointer;const macname : PUTF8Char):POSSL_PARAM;

  function mac_hmac_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
  function mac_siphash_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
  function mac_poly1305_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
  function mac_cmac_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;

  function mac_hmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function mac_siphash_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function mac_poly1305_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function mac_cmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;

const  ossl_mac_legacy_hmac_signature_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@mac_hmac_newctx; data:nil)),
(function_id:  8; method:(code:@mac_digest_sign_init; data:nil)),
(function_id:  9; method:(code:@mac_digest_sign_update; data:nil)),
(function_id:  10; method:(code:@mac_digest_sign_final; data:nil)),
(function_id:  16; method:(code:@mac_freectx; data:nil)),
(function_id:  17; method:(code:@mac_dupctx; data:nil)),
(function_id:  20; method:(code:@mac_set_ctx_params; data:nil)),
(function_id:  21; method:(code:@mac_hmac_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_mac_legacy_siphash_signature_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@mac_siphash_newctx; data:nil)),
(function_id:  8; method:(code:@mac_digest_sign_init; data:nil)),
(function_id:  9; method:(code:@mac_digest_sign_update; data:nil)),
(function_id:  10; method:(code:@mac_digest_sign_final; data:nil)),
(function_id:  16; method:(code:@mac_freectx; data:nil)),
(function_id:  17; method:(code:@mac_dupctx; data:nil)),
(function_id:  20; method:(code:@mac_set_ctx_params; data:nil)),
(function_id:  21; method:(code:@mac_siphash_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_mac_legacy_poly1305_signature_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@mac_poly1305_newctx; data:nil)),
(function_id:  8; method:(code:@mac_digest_sign_init; data:nil)),
(function_id:  9; method:(code:@mac_digest_sign_update; data:nil)),
(function_id:  10; method:(code:@mac_digest_sign_final; data:nil)),
(function_id:  16; method:(code:@mac_freectx; data:nil)),
(function_id:  17; method:(code:@mac_dupctx; data:nil)),
(function_id:  20; method:(code:@mac_set_ctx_params; data:nil)),
(function_id:  21; method:(code:@mac_poly1305_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_mac_legacy_cmac_signature_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@mac_cmac_newctx; data:nil)),
(function_id:  8; method:(code:@mac_digest_sign_init; data:nil)),
(function_id:  9; method:(code:@mac_digest_sign_update; data:nil)),
(function_id:  10; method:(code:@mac_digest_sign_final; data:nil)),
(function_id:  16; method:(code:@mac_freectx; data:nil)),
(function_id:  17; method:(code:@mac_dupctx; data:nil)),
(function_id:  20; method:(code:@mac_set_ctx_params; data:nil)),
(function_id:  21; method:(code:@mac_cmac_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses openssl3.providers.fips.self_test,            openssl3.crypto.mem,
     OpenSSL3.Err,                                 openssl3.crypto.evp.mac_lib,
     openssl3.crypto.evp.mac_meth,                 openssl3.crypto.evp.evp_lib,
     OpenSSL3.providers.implementations.mac_legacy_kmgmt,
     openssl3.crypto.engine.eng_lib,               OpenSSL3.providers.common.provider_util,
     openssl3.providers.common.provider_ctx,       openssl3.crypto.o_str;





function mac_hmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
  Result := mac_settable_ctx_params(ctx, provctx, 'HMAC');
end;


function mac_siphash_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
  Result :=  mac_settable_ctx_params(ctx, provctx, 'SIPHASH');
end;


function mac_poly1305_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
  Result :=  mac_settable_ctx_params(ctx, provctx, 'POLY1305');
end;


function mac_cmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
  Result :=  mac_settable_ctx_params(ctx, provctx, 'CMAC');
end;

function mac_hmac_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
begin
  Result :=  mac_newctx(provctx, propq, 'HMAC');
end;


function mac_siphash_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
begin
  Result :=  mac_newctx(provctx, propq, 'SIPHASH');
end;


function mac_poly1305_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
begin
  Result :=  mac_newctx(provctx, propq, 'POLY1305');
end;


function mac_cmac_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
begin
  Result :=  mac_newctx(provctx, propq, 'CMAC');
end;


function mac_newctx(provctx : Pointer;const propq, macname : PUTF8Char):Pointer;
var
  pmacctx : PPROV_MAC_CTX;
  mac : PEVP_MAC;
  label _err;
begin
    mac := nil;
    if not ossl_prov_is_running then
       Exit(nil);
    pmacctx := OPENSSL_zalloc(sizeof(TPROV_MAC_CTX));
    if pmacctx = nil then
       Exit(nil);
    pmacctx.libctx := ossl_prov_ctx_get0_libctx((provctx));
    OPENSSL_strdup(pmacctx.propq, propq);
    if (propq <> nil)  and  (pmacctx.propq = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    mac := EVP_MAC_fetch(pmacctx.libctx, macname, propq);
    if mac = nil then goto _err;
    pmacctx.macctx := EVP_MAC_CTX_new(mac);
    if pmacctx.macctx = nil then goto _err;
    EVP_MAC_free(mac);
    Exit(pmacctx);
 _err:
    OPENSSL_free(Pointer(pmacctx.propq));
    OPENSSL_free(Pointer(pmacctx));
    EVP_MAC_free(mac);
    Result := nil;
end;


function mac_digest_sign_init(vpmacctx : Pointer;const mdname : PUTF8Char; vkey : Pointer;const params : POSSL_PARAM):integer;
var
    pmacctx    : PPROV_MAC_CTX;
    ciphername, engine : PUTF8Char;
begin
    pmacctx := PPROV_MAC_CTX(vpmacctx);
    ciphername := nil; engine := nil;
    if (not ossl_prov_is_running) or  (pmacctx = nil) then
        Exit(0);
    if (pmacctx.key = nil)  and  (vkey = nil) then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if vkey <> nil then
    begin
        if 0>=ossl_mac_key_up_ref(vkey) then
            Exit(0);
        ossl_mac_key_free(pmacctx.key);
        pmacctx.key := vkey;
    end;
    if pmacctx.key.cipher.cipher <> nil then
       ciphername := PUTF8Char( EVP_CIPHER_get0_name(pmacctx.key.cipher.cipher));
{$IF not defined(OPENSSL_NO_ENGINE)  and not defined(FIPS_MODULE)}
    if pmacctx.key.cipher.engine <> nil then
       engine := PUTF8Char( ENGINE_get_id(pmacctx.key.cipher.engine));
{$ENDIF}
    if 0>=ossl_prov_set_macctx(pmacctx.macctx, nil,
                              PUTF8Char( ciphername),
                              PUTF8Char( mdname),
                              PUTF8Char( engine),
                              pmacctx.key.properties,
                              nil, 0) then
        Exit(0);
    if 0>=EVP_MAC_init(pmacctx.macctx, pmacctx.key.priv_key,
                      pmacctx.key.priv_key_len, params ) then
        Exit(0);
    Result := 1;
end;


function mac_digest_sign_update(vpmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  pmacctx : PPROV_MAC_CTX;
begin
    pmacctx := PPROV_MAC_CTX(vpmacctx);
    if (pmacctx = nil)  or  (pmacctx.macctx = nil) then
       Exit(0);
    Result := EVP_MAC_update(pmacctx.macctx, data, datalen);
end;


function mac_digest_sign_final( vpmacctx : Pointer; mac : PByte; maclen : Psize_t; macsize : size_t):integer;
var
  pmacctx : PPROV_MAC_CTX;
begin
    pmacctx := PPROV_MAC_CTX(vpmacctx);
    if (not ossl_prov_is_running)  or  (pmacctx = nil)  or  (pmacctx.macctx = nil) then
       Exit(0);
    Result := EVP_MAC_final(pmacctx.macctx, mac, maclen, macsize);
end;


procedure mac_freectx( vpmacctx : Pointer);
var
  ctx : PPROV_MAC_CTX;
begin
    ctx := PPROV_MAC_CTX(vpmacctx);
    OPENSSL_free(ctx.propq);
    EVP_MAC_CTX_free(ctx.macctx);
    ossl_mac_key_free(ctx.key);
    OPENSSL_free(ctx);
end;


function mac_dupctx( vpmacctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_MAC_CTX;
  label _err;
begin
    srcctx := PPROV_MAC_CTX(vpmacctx);
    if not ossl_prov_is_running then Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    dstctx.propq := nil;
    dstctx.key := nil;
    dstctx.macctx := nil;
    OPENSSL_strdup(dstctx.propq, srcctx.propq);
    if (srcctx.propq <> nil)  and  (dstctx.propq = nil) then
        goto _err;
    if (srcctx.key <> nil)  and  (0>=ossl_mac_key_up_ref(srcctx.key)) then
        goto _err;
    dstctx.key := srcctx.key;
    if srcctx.macctx <> nil then
    begin
        dstctx.macctx := EVP_MAC_CTX_dup(srcctx.macctx);
        if dstctx.macctx = nil then
           goto _err;
    end;
    Exit(dstctx);
 _err:
    mac_freectx(dstctx);
    Result := nil;
end;


function mac_set_ctx_params(vpmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_MAC_CTX;
begin
    ctx := PPROV_MAC_CTX(vpmacctx);
    Result := EVP_MAC_CTX_set_params(ctx.macctx, params);
end;


function mac_settable_ctx_params(ctx, provctx : Pointer;const macname : PUTF8Char):POSSL_PARAM;
var
  mac : PEVP_MAC;
  params : POSSL_PARAM;
begin
    mac := EVP_MAC_fetch(PROV_LIBCTX_OF(provctx), macname, nil);
    if mac = nil then Exit(nil);
    params := EVP_MAC_settable_ctx_params(mac);
    EVP_MAC_free(mac);
    Result := params;
end;


end.
