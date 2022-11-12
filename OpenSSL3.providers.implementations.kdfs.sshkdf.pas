unit OpenSSL3.providers.implementations.kdfs.sshkdf;

interface
uses OpenSSL.Api;

function kdf_sshkdf_new( provctx : Pointer):Pointer;
procedure kdf_sshkdf_free( vctx : Pointer);
procedure kdf_sshkdf_reset( vctx : Pointer);
function kdf_sshkdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function kdf_sshkdf_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
function kdf_sshkdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function kdf_sshkdf_gettable_ctx_params(ctx, p_ctx : Pointer):POSSL_PARAM;
function kdf_sshkdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function sshkdf_set_membuf(var dst : PByte; dst_len : Psize_t;const p : POSSL_PARAM):integer;
function SSHKDF(const evp_md : PEVP_MD; key : PByte; key_len : size_t;const xcghash : PByte; xcghash_len : size_t;const session_id : PByte; session_id_len : size_t; &type : UTF8Char; okey : PByte; okey_len : size_t):integer;

const  ossl_kdf_sshkdf_functions: array[0..8] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_KDF_NEWCTX; method:(code:@kdf_sshkdf_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX; method:(code:@kdf_sshkdf_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET; method:(code:@kdf_sshkdf_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE; method:(code:@kdf_sshkdf_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;  method:(code:@kdf_sshkdf_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@kdf_sshkdf_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS; method:(code:@kdf_sshkdf_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@kdf_sshkdf_get_ctx_params ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil) )
);



var // 1d arrays
  known_settable_ctx_params : array[0..18] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;


implementation
uses OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     openssl3.crypto.evp.digest,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,openssl3.crypto.evp.evp_lib;


function SSHKDF(const evp_md : PEVP_MD; key : PByte; key_len : size_t;const xcghash : PByte; xcghash_len : size_t;const session_id : PByte; session_id_len : size_t; &type : UTF8Char; okey : PByte; okey_len : size_t):integer;
var
  md : PEVP_MD_CTX;
  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  dsize : uint32;
  cursize : size_t;
  ret : integer;
  label _out;
begin
    md := nil;
    dsize := 0;
    cursize := 0;
    ret := 0;
    md := EVP_MD_CTX_new();
    if md = nil then Exit(0);
    if 0>= EVP_DigestInit_ex(md, evp_md, nil ) then
        goto _out ;
    if 0>= EVP_DigestUpdate(md, key, key_len ) then
        goto _out ;
    if 0>= EVP_DigestUpdate(md, xcghash, xcghash_len ) then
        goto _out ;
    if 0>= EVP_DigestUpdate(md, @&type, 1 ) then
        goto _out ;
    if 0>= EVP_DigestUpdate(md, session_id, session_id_len ) then
        goto _out ;
    if 0>= EVP_DigestFinal_ex(md, @digest, @dsize ) then
        goto _out ;
    if okey_len < dsize then
    begin
        memcpy(okey, @digest, okey_len);
        ret := 1;
        goto _out ;
    end;
    memcpy(okey, @digest, dsize);
    cursize := dsize;
    while ( cursize < okey_len )do
    begin
        if 0>= EVP_DigestInit_ex(md, evp_md, nil ) then
            goto _out ;
        if 0>= EVP_DigestUpdate(md, key, key_len ) then
            goto _out ;
        if 0>= EVP_DigestUpdate(md, xcghash, xcghash_len ) then
            goto _out ;
        if 0>= EVP_DigestUpdate(md, okey, cursize ) then
            goto _out ;
        if 0>= EVP_DigestFinal_ex(md, @digest, @dsize ) then
            goto _out ;
        if okey_len < cursize + dsize then
        begin
            memcpy(okey + cursize, @digest, okey_len - cursize);
            ret := 1;
            goto _out ;
        end;
        memcpy(okey + cursize, @digest, dsize);
        cursize := cursize+dsize;
    end;
    ret := 1;
_out:
    EVP_MD_CTX_free(md);
    OPENSSL_cleanse(@digest, EVP_MAX_MD_SIZE);
    Result := ret;
end;



function sshkdf_set_membuf(var dst : PByte; dst_len : Psize_t;const p : POSSL_PARAM):integer;
begin
    OPENSSL_clear_free( Pointer(dst), dst_len^);
    dst := nil;
    dst_len^ := 0;
    Result := OSSL_PARAM_get_octet_string(p, Pointer(dst), 0, dst_len);
end;

function kdf_sshkdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, SIZE_MAX));
    Result := -2;
end;


function kdf_sshkdf_gettable_ctx_params(ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := OSSL_PARAM_END;
    Result := @known_gettable_ctx_params;
end;



function kdf_sshkdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
  kdftype: PUTF8Char;
  ctx : PKDF_SSHKDF;

  provctx : POSSL_LIB_CTX;
begin
    ctx := vctx;
    provctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    if  0>=  ossl_prov_digest_load_from_params(@ctx.digest, params, provctx  ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if p <> nil then
        if ( 0>=  sshkdf_set_membuf(ctx.key, @ctx.key_len, p)) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SSHKDF_XCGHASH );
    if p <> nil  then
        if  0>=  sshkdf_set_membuf(ctx.xcghash, @ctx.xcghash_len, p) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SSHKDF_SESSION_ID);
    if p <> nil then
        if  0>=  sshkdf_set_membuf(ctx.session_id, @ctx.session_id_len, p) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SSHKDF_TYPE );
    if   P  <> nil then
    begin
        if  0>=  OSSL_PARAM_get_utf8_string_ptr(p, @kdftype) then
            Exit(0);
        { Expect one character (byte in this case) }
        if (kdftype = nil)  or  (p.data_size <> 1) then Exit(0);
        if (Ord(kdftype[0]) < 65)  or  (Ord(kdftype[0]) > 70) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_VALUE_ERROR);
            Exit(0);
        end;
        ctx.&type := kdftype[0];
    end;
    Result := 1;
end;



function kdf_sshkdf_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH, nil, 0);
    known_settable_ctx_params[4] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID, nil, 0);
    known_settable_ctx_params[5] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, nil, 0);
    known_settable_ctx_params[6] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;






function kdf_sshkdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_SSHKDF;

  md : PEVP_MD;
begin
    ctx := PKDF_SSHKDF  (vctx);
    if  (not  ossl_prov_is_running) or
        (0>=  kdf_sshkdf_set_ctx_params(ctx, params)) then
        Exit(0);
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    if ctx.key = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        Exit(0);
    end;
    if ctx.xcghash = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_XCGHASH);
        Exit(0);
    end;
    if ctx.session_id = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SESSION_ID);
        Exit(0);
    end;
    if Ord(ctx.&type) = 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_TYPE);
        Exit(0);
    end;
    Exit(SSHKDF(md, ctx.key, ctx.key_len,
                  ctx.xcghash, ctx.xcghash_len,
                  ctx.session_id, ctx.session_id_len,
                  ctx.&type, key, keylen));
end;



procedure kdf_sshkdf_reset( vctx : Pointer);
var
  ctx : PKDF_SSHKDF;

  provctx : Pointer;
begin
    ctx := PKDF_SSHKDF  (vctx);
    provctx := ctx.provctx;
    ossl_prov_digest_reset(@ctx.digest);
    OPENSSL_clear_free(Pointer(ctx.key), ctx.key_len);
    OPENSSL_clear_free(Pointer(ctx.xcghash), ctx.xcghash_len);
    OPENSSL_clear_free(Pointer(ctx.session_id), ctx.session_id_len);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
end;




procedure kdf_sshkdf_free( vctx : Pointer);
var
  ctx : PKDF_SSHKDF;
begin
    ctx := (PKDF_SSHKDF  (vctx));
    if ctx <> nil then begin
        kdf_sshkdf_reset(ctx);
        OPENSSL_free(Pointer(ctx));
    end;
end;


function kdf_sshkdf_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_SSHKDF;
begin
    if  not  ossl_prov_is_running( ) then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^ ));
    if ctx = nil then
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    ctx.provctx := provctx;
    Result := ctx;
end;
end.
