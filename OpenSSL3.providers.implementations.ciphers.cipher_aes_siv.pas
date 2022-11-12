unit OpenSSL3.providers.implementations.ciphers.cipher_aes_siv;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

const
  SIV_FLAGS = AEAD_FLAGS;

  function aes128_siv_get_params( params : POSSL_PARAM):integer;
  function aes128_siv_newctx( provctx : Pointer):Pointer;
  procedure aes_siv_freectx( vctx : Pointer);
  function siv_dupctx( vctx : Pointer):Pointer;
  function siv_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
  function siv_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function siv_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function siv_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function siv_stream_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function aes_siv_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
   function aes_siv_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function aes_siv_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function aes_siv_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function aes_192_siv_get_params( params : POSSL_PARAM):integer;
  function aes192siv_newctx( provctx : Pointer):Pointer;
  function aes_256_siv_get_params( params : POSSL_PARAM):integer;
  function aes256siv_newctx( provctx : Pointer):Pointer;

  function siv_stream_update(vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t;const &in : PByte; inl : size_t):integer ;

//IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 128, 8, 0)
const  ossl_aes128siv_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX; method:(code:@aes128_siv_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_siv_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@siv_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@siv_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@siv_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@siv_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@siv_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@siv_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes128_siv_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ aes_siv_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@aes_siv_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@aes_siv_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
      method:(code:@aes_siv_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

//IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 192, 8, 0)
const ossl_aes192siv_functions: array[0..14] of TOSSL_DISPATCH =(
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX; method:(code:@aes192siv_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_siv_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@ siv_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@ siv_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@ siv_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@ siv_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@ siv_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@ siv_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_siv_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ aes_siv_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ aes_siv_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ aes_siv_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
      method:(code:@ aes_siv_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

//IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 256, 8, 0)
const ossl_aes256siv_functions: array[0..14] of TOSSL_DISPATCH =(
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX; method:(code:@aes256siv_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_siv_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@ siv_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@ siv_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@ siv_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@ siv_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@ siv_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@ siv_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_256_siv_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ aes_siv_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ aes_siv_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ aes_siv_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
      method:(code:@ aes_siv_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

function aes_siv_newctx( provctx : Pointer; keybits : size_t; mode : uint32; flags : uint64):Pointer;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err,
     openssl3.crypto.params_from_text,openssl3.providers.common.provider_ctx,
     openssl3.crypto.aes.aes_core, openssl3.crypto.aes.aes_cbc,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb_hw,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw,
     openssl3.crypto.evp.ctrl_params_translate,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_siv_hw;


var
   aes_siv_known_settable_ctx_params,
   aes_siv_known_gettable_ctx_params : array of TOSSL_PARAM;





function aes_256_siv_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params, EVP_CIPH_SIV_MODE, SIV_FLAGS, 2*256, 8, 0);
end;


function aes256siv_newctx( provctx : Pointer):Pointer;
begin
    result := aes_siv_newctx(provctx, 2*256, EVP_CIPH_SIV_MODE, SIV_FLAGS);
end;






function aes_192_siv_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params, EVP_CIPH_SIV_MODE, SIV_FLAGS, 2*192, 8, 0);
end;


function aes192siv_newctx( provctx : Pointer):Pointer;
begin
    result := aes_siv_newctx(provctx, 2*192, EVP_CIPH_SIV_MODE, SIV_FLAGS);
end;



function aes_siv_newctx( provctx : Pointer; keybits : size_t; mode : uint32; flags : uint64):Pointer;
var
  ctx : PPROV_AES_SIV_CTX;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
    begin
        ctx.taglen := SIV_LEN;
        ctx.mode := mode;
        ctx.keylen := keybits div 8;
        ctx.hw := ossl_prov_cipher_hw_aes_siv(keybits);
        ctx.libctx := PROV_LIBCTX_OF(provctx);
    end;
    Result := ctx;
end;

function aes_siv_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @aes_siv_known_settable_ctx_params[0];
end;



function aes_siv_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_AES_SIV_CTX;

  speed : uint32;
  p : POSSL_PARAM;
  keylen : size_t;
begin
    ctx := PPROV_AES_SIV_CTX ( vctx);
    speed := 0;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then
    begin
        if ctx.enc>0 then
            Exit(1);
        if (p.data_type <> OSSL_PARAM_OCTET_STRING)
             or  (0>= ctx.hw.settag(ctx, p.data, p.data_size)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_SPEED);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @speed) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        ctx.hw.setspeed(ctx, int (speed));
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_size_t(p, @keylen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        { The key length can not be modified }
        if keylen <> ctx.keylen then
           Exit(0);
    end;
    Result := 1;
end;

function aes_siv_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @aes_siv_known_gettable_ctx_params[0];
end;

function siv_stream_update(vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t;const &in : PByte; inl : size_t):integer;
begin
  Result := siv_cipher(vctx,&out, outl, outsize, &in, inl);
end;

procedure aes_siv_freectx( vctx : Pointer);
var
  ctx : PPROV_AES_SIV_CTX;
begin
    ctx := PPROV_AES_SIV_CTX (vctx);
    if ctx <> nil then
    begin
        ctx.hw.cleanup(ctx);
        OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
    end;
end;


function siv_dupctx( vctx : Pointer):Pointer;
var
  _in : PPROV_AES_SIV_CTX;

  ret : PPROV_AES_SIV_CTX;
begin
    _in := PPROV_AES_SIV_CTX (vctx);
    if not ossl_prov_is_running then
        Exit(nil);
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>= _in.hw.dupctx(_in, ret) then
    begin
        OPENSSL_free(ret);
        ret := nil;
    end;
    Result := ret;
end;


function siv_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
  ctx : PPROV_AES_SIV_CTX;
begin
    ctx := PPROV_AES_SIV_CTX (vctx);
    if not ossl_prov_is_running then
        Exit(0);
    ctx.enc := enc;
    if key <> nil then
    begin
        if keylen <> ctx.keylen then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>= ctx.hw.initkey(ctx, key, ctx.keylen ) then
            Exit(0);
    end;
    Result := aes_siv_set_ctx_params(ctx, params);
end;


function siv_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := siv_init(vctx, key, keylen, iv, ivlen, params, 1);
end;


function siv_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := siv_init(vctx, key, keylen, iv, ivlen, params, 0);
end;


function siv_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_AES_SIV_CTX;
begin
    ctx := PPROV_AES_SIV_CTX (vctx);
    if not ossl_prov_is_running then
        Exit(0);
    if inl = 0 then
    begin
        outl^ := 0;
        Exit(1);
    end;
    if outsize < inl then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if ctx.hw.cipher(ctx, _out, _in, inl ) <= 0 then
        Exit(0);
    if outl <> nil then outl^ := inl;
    Result := 1;
end;


function siv_stream_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : PPROV_AES_SIV_CTX;
begin
    ctx := PPROV_AES_SIV_CTX (vctx);
    if not ossl_prov_is_running then
        Exit(0);
    if 0>= ctx.hw.cipher(vctx, out, nil, 0 )then
        Exit(0);
    if outl <> nil then outl^ := 0;
    Result := 1;
end;


function aes_siv_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_AES_SIV_CTX;

  sctx : PSIV128_CONTEXT;

  p : POSSL_PARAM;
begin
    ctx := PPROV_AES_SIV_CTX (vctx);
    sctx := @ctx.siv;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p <> nil)  and  (p.data_type = OSSL_PARAM_OCTET_STRING) then
    begin
        if (0>= ctx.enc)
             or  (p.data_size <> ctx.taglen)
             or  (0>= OSSL_PARAM_set_octet_string(p, @sctx.tag.byte, ctx.taglen)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, ctx.taglen) )then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, ctx.keylen) )then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;



function aes128_siv_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params, EVP_CIPH_SIV_MODE, SIV_FLAGS, 2*128, 8, 0);
end;


function aes128_siv_newctx( provctx : Pointer):Pointer;
begin
    result := aes_siv_newctx(provctx, 2*128, EVP_CIPH_SIV_MODE, SIV_FLAGS);
end;

initialization
   aes_siv_known_settable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_SPEED, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, nil, 0),
    OSSL_PARAM_END
];
  aes_siv_known_gettable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, nil, 0),
    OSSL_PARAM_END
];
end.
