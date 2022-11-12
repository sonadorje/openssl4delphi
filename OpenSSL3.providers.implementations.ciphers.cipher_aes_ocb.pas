unit OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

const
  OCB_MAX_TAG_LEN = AES_BLOCK_SIZE;
  OCB_MAX_DATA_LEN = AES_BLOCK_SIZE;
  OCB_MAX_AAD_LEN = AES_BLOCK_SIZE;
  OCB_DEFAULT_IV_LEN  = 12;
  OCB_DEFAULT_TAG_LEN = 16;
  OCB_MIN_IV_LEN      = 1;
  OCB_MAX_IV_LEN      = 15;

  function aes_256_ocb_get_params( params : POSSL_PARAM):integer;
  function aes_256_ocb_newctx( provctx : Pointer):Pointer;
  function aes_ocb_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_ocb_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_ocb_block_update_internal( ctx : PPROV_AES_OCB_CTX; buf : PByte; bufsz : Psize_t; _out : PByte; outl : Psize_t; outsize : size_t; _in : PByte; inl : size_t; ciph : TOSSL_ocb_cipher_fn):integer;
  function aes_ocb_block_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function aes_ocb_block_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
  function aes_ocb_cipher(vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  procedure aes_ocb_freectx( vctx : Pointer);
  function aes_ocb_dupctx( vctx : Pointer):Pointer;
  function aes_ocb_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function aes_ocb_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function cipher_ocb_gettable_ctx_params( cctx, p_ctx : Pointer):POSSL_PARAM;
  function cipher_ocb_settable_ctx_params( cctx, p_ctx : Pointer):POSSL_PARAM;
  function aes_192_ocb_get_params( params : POSSL_PARAM):integer;
  function aes_192_ocb_newctx( provctx : Pointer):Pointer;
   function aes_ocb_newctx( provctx : Pointer; kbits, blkbits, ivbits : size_t; mode : uint32; flags : uint64):Pointer;
  function aes_128_ocb_get_params( params : POSSL_PARAM):integer;
  function aes_128_ocb_newctx( provctx : Pointer):Pointer;

 //IMPLEMENT_cipher(ocb, OCB, AES_OCB_FLAGS, 256, 128, OCB_DEFAULT_IV_LEN * 8);
const  ossl_aes256ocb_functions: array[0..14] of TOSSL_DISPATCH= (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;     method:(code:@aes_256_ocb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@aes_ocb_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@aes_ocb_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@aes_ocb_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@aes_ocb_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@aes_ocb_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_ocb_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@aes_ocb_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;    method:(code:@aes_256_ocb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;  method:(code:@aes_ocb_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;  method:(code:@aes_ocb_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;  method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;   method:(code:@cipher_ocb_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;   method:(code:@cipher_ocb_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

//IMPLEMENT_cipher(ocb, OCB, AES_OCB_FLAGS, 192, 128, OCB_DEFAULT_IV_LEN * 8);
const ossl_aes192ocb_functions:array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
        method:(code:@aes_192_ocb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@aes_ocb_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@aes_ocb_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@aes_ocb_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@aes_ocb_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@aes_ocb_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_ocb_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@aes_ocb_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
        method:(code:@aes_192_ocb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
        method:(code:@aes_ocb_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
        method:(code:@aes_ocb_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
        method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
        method:(code:@cipher_ocb_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
        method:(code:@cipher_ocb_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

//IMPLEMENT_cipher(ocb, OCB, AES_OCB_FLAGS, 128, 128, OCB_DEFAULT_IV_LEN * 8);
const ossl_aes128ocb_functions:array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
        method:(code:@aes_128_ocb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@aes_ocb_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@aes_ocb_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@aes_ocb_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@aes_ocb_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@aes_ocb_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_ocb_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@aes_ocb_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
        method:(code:@aes_128_ocb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
        method:(code:@aes_ocb_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
        method:(code:@aes_ocb_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
        method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
        method:(code:@cipher_ocb_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
        method:(code:@cipher_ocb_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

function aes_generic_ocb_copy_ctx( dst, src : PPROV_AES_OCB_CTX):integer;
procedure aes_generic_ocb_cleanup( ctx : PPROV_AES_OCB_CTX);
function aes_generic_ocb_cipher(ctx : PPROV_AES_OCB_CTX;const _in : PByte; _out : PByte; len : size_t):integer;
function update_iv( ctx : PPROV_AES_OCB_CTX):integer;
function aes_generic_ocb_setiv(ctx : PPROV_AES_OCB_CTX;const iv : PByte; ivlen, taglen : size_t):integer;
function aes_generic_ocb_setaad(ctx : PPROV_AES_OCB_CTX;const aad : PByte; alen : size_t):integer;
function aes_generic_ocb_gettag( ctx : PPROV_AES_OCB_CTX; tag : PByte; tlen : size_t):integer;
function aes_generic_ocb_final( ctx : PPROV_AES_OCB_CTX):integer;
function cipher_updateaad(ctx : PPROV_AES_OCB_CTX;const &in : PByte; &out : PByte; len : size_t):integer;
function aes_ocb_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
function CRYPTO_ocb128_copy_ctx( dest, src : POCB128_CONTEXT; keyenc, keydec : Pointer):integer;

var
  cipher_ocb_known_settable_ctx_params,
  cipher_ocb_known_gettable_ctx_params: array of TOSSL_PARAM ;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_hw,
     openssl3.crypto.aes.aes_core, openssl3.crypto.aes.aes_cbc,
     openssl3.crypto.modes.ocb128,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb_hw,
     openssl3.crypto.evp.ctrl_params_translate,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_block;

function CRYPTO_ocb128_copy_ctx( dest, src : POCB128_CONTEXT; keyenc, keydec : Pointer):integer;
begin
    memcpy(dest, src, sizeof(TOCB128_CONTEXT));
    if keyenc <> nil then dest.keyenc := keyenc;
    if keydec <> nil then dest.keydec := keydec;
    if src.l <> nil then
    begin
        dest.l := OPENSSL_malloc(src.max_l_index * 16);
        if (dest.l = nil) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(dest.l, src.l, (src.l_index + 1) * 16);
    end;
    Result := 1;
end;




function aes_128_ocb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params, EVP_CIPH_OCB_MODE,
                                          AES_OCB_FLAGS, 128, 128, OCB_DEFAULT_IV_LEN * 8);
end;


function aes_128_ocb_newctx( provctx : Pointer):Pointer;
begin
    result := aes_ocb_newctx(provctx, 128, 128, OCB_DEFAULT_IV_LEN * 8,
                               EVP_CIPH_OCB_MODE, AES_OCB_FLAGS);
end;

function aes_ocb_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
  ctx : PPROV_AES_OCB_CTX;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
    if not ossl_prov_is_running then
        Exit(0);
    ctx.aad_buf_len := 0;
    ctx.data_buf_len := 0;
    ctx.base.enc := enc;
    if iv <> nil then
    begin
        if ivlen <> ctx.base.ivlen then
        begin
            { IV len must be 1 to 15 }
            if (ivlen < OCB_MIN_IV_LEN)  or  (ivlen > OCB_MAX_IV_LEN) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                Exit(0);
            end;
            ctx.base.ivlen := ivlen;
        end;
        if 0>= ossl_cipher_generic_initiv(@ctx.base, iv, ivlen )then
            Exit(0);
        ctx.iv_state := IV_STATE_BUFFERED;
    end;
    if key <> nil then begin
        if keylen <> ctx.base.keylen then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>= ctx.base.hw.init(@ctx.base, key, keylen ) then
            Exit(0);
    end;
    Result := aes_ocb_set_ctx_params(ctx, params);
end;

function cipher_updateaad(ctx : PPROV_AES_OCB_CTX;const &in : PByte; &out : PByte; len : size_t):integer;
begin
    Result := aes_generic_ocb_setaad(ctx, &in, len);
end;

function aes_generic_ocb_final( ctx : PPROV_AES_OCB_CTX):integer;
begin
    Result := int(CRYPTO_ocb128_finish(@ctx.ocb, @ctx.tag, ctx.taglen) = 0);
end;




function aes_generic_ocb_gettag( ctx : PPROV_AES_OCB_CTX; tag : PByte; tlen : size_t):integer;
begin
    Result := Int(CRYPTO_ocb128_tag(@ctx.ocb, tag, tlen) > 0);
end;

function aes_generic_ocb_setaad(ctx : PPROV_AES_OCB_CTX;const aad : PByte; alen : size_t):integer;
begin
    Result := Int(CRYPTO_ocb128_aad(@ctx.ocb, aad, alen) = 1);
end;

function aes_generic_ocb_setiv(ctx : PPROV_AES_OCB_CTX;const iv : PByte; ivlen, taglen : size_t):integer;
begin
    Result := int(CRYPTO_ocb128_setiv(@ctx.ocb, iv, ivlen, taglen) = 1);
end;

function update_iv( ctx : PPROV_AES_OCB_CTX):integer;
begin
    if (ctx.iv_state = IV_STATE_FINISHED )
         or  (ctx.iv_state = IV_STATE_UNINITIALISED) then
         Exit(0);
    if ctx.iv_state = IV_STATE_BUFFERED then
    begin
        if (0>= aes_generic_ocb_setiv(ctx, @ctx.base.iv, ctx.base.ivlen,
                                   ctx.taglen)) then
            Exit(0);
        ctx.iv_state := IV_STATE_COPIED;
    end;
    Result := 1;
end;




function aes_generic_ocb_cipher(ctx : PPROV_AES_OCB_CTX;const _in : PByte; _out : PByte; len : size_t):integer;
begin
    if ctx.base.enc>0 then
    begin
        if 0>= CRYPTO_ocb128_encrypt(@ctx.ocb, _in, _out, len) then
            Exit(0);
    end
    else
    begin
        if 0>= CRYPTO_ocb128_decrypt(@ctx.ocb, _in, _out, len) then
            Exit(0);
    end;
    Result := 1;
end;

procedure aes_generic_ocb_cleanup( ctx : PPROV_AES_OCB_CTX);
begin
    CRYPTO_ocb128_cleanup(@ctx.ocb);
end;


function aes_generic_ocb_copy_ctx( dst, src : PPROV_AES_OCB_CTX):integer;
begin
    Exit(CRYPTO_ocb128_copy_ctx(@dst.ocb, @src.ocb,
                                  @dst.ksenc.ks, @dst.ksdec.ks));
end;


function aes_ocb_newctx( provctx : Pointer; kbits, blkbits, ivbits : size_t; mode : uint32; flags : uint64):Pointer;
var
  ctx : PPROV_AES_OCB_CTX;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
    begin
        ossl_cipher_generic_initkey(ctx, kbits, blkbits, ivbits, mode, flags,
                                    ossl_prov_cipher_hw_aes_ocb(kbits), nil);
        ctx.taglen := OCB_DEFAULT_TAG_LEN;
    end;
    Result := ctx;
end;


function aes_192_ocb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params, EVP_CIPH_OCB_MODE,
                                          AES_OCB_FLAGS, 192, 128, OCB_DEFAULT_IV_LEN * 8);
end;


function aes_192_ocb_newctx( provctx : Pointer):Pointer;
begin
    result := aes_ocb_newctx(provctx, 192, 128, OCB_DEFAULT_IV_LEN * 8,
                               EVP_CIPH_OCB_MODE, AES_OCB_FLAGS);
end;

function cipher_ocb_settable_ctx_params( cctx, p_ctx : Pointer):POSSL_PARAM;
begin
    Result := @cipher_ocb_known_settable_ctx_params[0];
end;



function cipher_ocb_gettable_ctx_params( cctx, p_ctx : Pointer):POSSL_PARAM;
begin
    Result := @cipher_ocb_known_gettable_ctx_params[0];
end;



function aes_ocb_dupctx( vctx : Pointer):Pointer;
var
  _in, ret : PPROV_AES_OCB_CTX;
begin
    _in := PPROV_AES_OCB_CTX ( vctx);
    if not ossl_prov_is_running then
        Exit(nil);
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret^ := _in^;
    if 0>= aes_generic_ocb_copy_ctx(ret, _in ) then
    begin
        OPENSSL_free(ret);
        ret := nil;
    end;
    Result := ret;
end;


function aes_ocb_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_AES_OCB_CTX;
  p : POSSL_PARAM;
  sz, keylen : size_t;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if p.data = nil then begin
            { Tag len must be 0 to 16 }
            if p.data_size > OCB_MAX_TAG_LEN then
                Exit(0);
            ctx.taglen := p.data_size;
        end
        else
        begin
            if (p.data_size <> ctx.taglen)  or  (ctx.base.enc>0) then
               Exit(0);
            memcpy(@ctx.tag, p.data, p.data_size);
        end;
     end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_size_t(p, @sz) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        { IV len must be 1 to 15 }
        if (sz < OCB_MIN_IV_LEN)  or  (sz > OCB_MAX_IV_LEN) then
           Exit(0);
        ctx.base.ivlen := sz;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if p <> nil then begin
        if 0>= OSSL_PARAM_get_size_t(p, @keylen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if ctx.base.keylen <> keylen then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
    end;
    Result := 1;
end;


function aes_ocb_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_AES_OCB_CTX;
  p : POSSL_PARAM;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, ctx.base.ivlen) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, ctx.base.keylen) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_set_size_t(p, ctx.taglen) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if p <> nil then
    begin
        if ctx.base.ivlen > p.data_size then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        if (0>= OSSL_PARAM_set_octet_string(p, @ctx.base.oiv, ctx.base.ivlen))  and
           (0>= OSSL_PARAM_set_octet_ptr(p, @ctx.base.oiv, ctx.base.ivlen)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if p <> nil then begin
        if ctx.base.ivlen > p.data_size then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        if (0>= OSSL_PARAM_set_octet_string(p, @ctx.base.iv, ctx.base.ivlen))  and
           (0>= OSSL_PARAM_set_octet_ptr(p, @ctx.base.iv, ctx.base.ivlen)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if (0>= ctx.base.enc)  or  (p.data_size <> ctx.taglen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            Exit(0);
        end;
        memcpy(p.data, @ctx.tag, ctx.taglen);
    end;
    Result := 1;
end;

procedure aes_ocb_freectx( vctx : Pointer);
var
  ctx : PPROV_AES_OCB_CTX;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
    if ctx <> nil then
    begin
        aes_generic_ocb_cleanup(ctx);
        ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX ( vctx));
        OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
    end;
end;

function aes_ocb_cipher(vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_AES_OCB_CTX;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
    if not ossl_prov_is_running then
        Exit(0);
    if outsize < inl then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>= aes_generic_ocb_cipher(ctx, _in, &out, inl ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    outl^ := inl;
    Result := 1;
end;

function aes_ocb_block_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : PPROV_AES_OCB_CTX;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
    if not ossl_prov_is_running then
        Exit(0);
    { If no block_update has run then the iv still needs to be set }
    if (0>= ctx.key_set)  or  (0>= update_iv(ctx )) then
        Exit(0);
    {
     * Empty the buffer of any partial block that we might have been provided,
     * both for data and AAD
     }
    outl^ := 0;
    if ctx.data_buf_len > 0 then
    begin
        if 0>= aes_generic_ocb_cipher(ctx, @ctx.data_buf, _out, ctx.data_buf_len) then
            Exit(0);
        outl^ := ctx.data_buf_len;
        ctx.data_buf_len := 0;
    end;
    if ctx.aad_buf_len > 0 then
    begin
        if 0>= aes_generic_ocb_setaad(ctx, @ctx.aad_buf, ctx.aad_buf_len) then
            Exit(0);
        ctx.aad_buf_len := 0;
    end;
    if ctx.base.enc >0 then
    begin
        { If encrypting then just get the tag }
        if 0>= aes_generic_ocb_gettag(ctx, @ctx.tag, ctx.taglen) then
            Exit(0);
    end
    else
    begin
        { If decrypting then verify }
        if ctx.taglen = 0 then Exit(0);
        if 0>= aes_generic_ocb_final(ctx) then
            Exit(0);
    end;
    { Don't reuse the IV }
    ctx.iv_state := IV_STATE_FINISHED;
    Result := 1;
end;


function aes_ocb_block_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_AES_OCB_CTX;
  buf : PByte;
  buflen : Psize_t;
  fn : TOSSL_ocb_cipher_fn;
begin
    ctx := PPROV_AES_OCB_CTX  (vctx);
    if (0>= ctx.key_set)  or  (0>= update_iv(ctx)) then
        Exit(0);
    if inl = 0 then
    begin
        outl^ := 0;
        Exit(1);
    end;
    { Are we dealing with AAD or normal data here? }
    if _out = nil then
    begin
        buf := @ctx.aad_buf;
        buflen := @ctx.aad_buf_len;
        fn := cipher_updateaad;
    end
    else
    begin
        buf := @ctx.data_buf;
        buflen := @ctx.data_buf_len;
        fn := aes_generic_ocb_cipher;
    end;
    Exit(aes_ocb_block_update_internal(ctx, buf, buflen, _out, outl, outsize,
                                         _in, inl, fn));
end;


function aes_ocb_block_update_internal(ctx : PPROV_AES_OCB_CTX; buf : PByte; bufsz : Psize_t; _out : PByte; outl : Psize_t; outsize : size_t; _in : PByte; inl : size_t; ciph : TOSSL_ocb_cipher_fn):integer;
var
  nextblocks,
  outlint    : size_t;
begin
    outlint := 0;
    if (bufsz^ <> 0 ) then
       nextblocks := ossl_cipher_fillblock(buf, bufsz, AES_BLOCK_SIZE, @_in, @inl)
    else
        nextblocks := inl and not (AES_BLOCK_SIZE-1);
    if bufsz^ = AES_BLOCK_SIZE then
    begin
        if outsize < AES_BLOCK_SIZE then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            Exit(0);
        end;
        if 0>= ciph(ctx, buf, _out, AES_BLOCK_SIZE ) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        bufsz^ := 0;
        outlint := AES_BLOCK_SIZE;
        if _out <> nil then
           _out  := _out + AES_BLOCK_SIZE;
    end;
    if nextblocks > 0 then
    begin
        outlint  := outlint + nextblocks;
        if outsize < outlint then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            Exit(0);
        end;
        if 0>= ciph(ctx, _in, _out, nextblocks) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        _in  := _in + nextblocks;
        inl  := inl - nextblocks;
    end;
    if (inl <> 0)
         and  (0>= ossl_cipher_trailingdata(buf, bufsz, AES_BLOCK_SIZE, @_in, @inl ))then
    begin
        { PROVerr already called }
        Exit(0);
    end;
    outl^ := outlint;
    Result := 0; inl := 0;
end;




function aes_ocb_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := aes_ocb_init(vctx, key, keylen, iv, ivlen, params, 1);
end;


function aes_ocb_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := aes_ocb_init(vctx, key, keylen, iv, ivlen, params, 0);
end;

function aes_256_ocb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params, EVP_CIPH_OCB_MODE,
                                          AES_OCB_FLAGS, 256, 128, OCB_DEFAULT_IV_LEN * 8);
end;


function aes_256_ocb_newctx( provctx : Pointer):Pointer;
begin
    result := aes_ocb_newctx(provctx, 256, 128, OCB_DEFAULT_IV_LEN * 8,
                               EVP_CIPH_OCB_MODE, AES_OCB_FLAGS);
end;

initialization
  cipher_ocb_known_settable_ctx_params  := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, nil, 0),
    OSSL_PARAM_END
];

  cipher_ocb_known_gettable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, nil, 0),
    OSSL_PARAM_END
];
end.
