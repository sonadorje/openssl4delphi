unit OpenSSL3.providers.implementations.ciphers.cipher_aes_cts;

interface
 uses OpenSSL.Api;

//extract from cipher_cts.h macro
  function aes_cts_128_cbc_get_params( params : POSSL_PARAM):integer;
  function aes_cbc_cts_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function aes_cbc_cts_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function aes_128_cbc_get_params( params : POSSL_PARAM):integer;
  function aes_cbc_cts_einit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_cbc_cts_dinit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_cbc_cts_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function aes_cbc_cts_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function aes_cts_192_cbc_get_params( params : POSSL_PARAM):integer;
  function aes_cts_256_cbc_get_params( params : POSSL_PARAM):integer;

var
  aes_cbc_cts_known_gettable_ctx_params : array of TOSSL_PARAM;
  aes_cbc_cts_known_settable_ctx_params : array of TOSSL_PARAM;

implementation

uses
     OpenSSL3.crypto.params, OpenSSL3.Err,  OpenSSL3.openssl.params,
     OpenSSL3.providers.implementations.ciphers.ciphercommon,
     OpenSSL3.providers.implementations.ciphers.cipher_cts,
     OpenSSL3.providers.implementations.ciphers.cipher_aes;



function aes_cts_256_cbc_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params, EVP_CIPH_CBC_MODE,
                                          CTS_FLAGS, 256, 128, 128));
end;

function aes_cts_192_cbc_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params, EVP_CIPH_CBC_MODE,
                                          CTS_FLAGS, 192, 128, 128));
end;

function aes_cbc_cts_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p    : POSSL_PARAM;
  id : integer;
  label _err;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            goto _err ;
        id := ossl_cipher_cbc_cts_mode_name2id(p.data);
        if id < 0 then goto _err ;
        ctx.cts_mode := uint32( id);
    end;
    Exit(ossl_cipher_generic_set_ctx_params(vctx, params));
_err:
    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
    Result := 0;
end;

(* ossl_aes128cbc_cts_functions */
IMPLEMENT_cts_cipher(aes, AES, cbc, CBC, CTS_FLAGS, 128, 128, 128, block)*)
function aes_cts_128_cbc_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params, EVP_CIPH_CBC_MODE,
                                          CTS_FLAGS, 128, 128, 128));
end;

function aes_cbc_cts_einit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    if 0>= ossl_cipher_generic_einit(ctx, key, keylen, iv, ivlen, nil )then
        Exit(0);
    Result := aes_cbc_cts_set_ctx_params(ctx, params);
end;


function aes_cbc_cts_dinit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    if 0>= ossl_cipher_generic_dinit(ctx, key, keylen, iv, ivlen, nil) then
        Exit(0);
    Result := aes_cbc_cts_set_ctx_params(ctx, params);
end;


function aes_cbc_cts_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;

  p : POSSL_PARAM;

  name : PUTF8Char;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE);
    if p <> nil then
    begin
       name := ossl_cipher_cbc_cts_mode_id2name(ctx.cts_mode);
        if (name = nil)  or  (0>= OSSL_PARAM_set_utf8_string(p, name)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    Result := ossl_cipher_generic_get_ctx_params(vctx, params);
end;

(* cipher_aes_cts.inc
   ossl_aes128cbc_cts_functions
IMPLEMENT_cts_cipher(aes, AES, cbc, CBC, CTS_FLAGS, 128, 128, 128, block)*)
function aes_128_cbc_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params,EVP_CIPH_CBC_MODE,
                                          0,128,128,128));
end;

(*
  CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(aes_cbc_cts)
  OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
  CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(aes_cbc_cts)
*)

function aes_cbc_cts_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    aes_cbc_cts_known_gettable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, nil, 0),
    OSSL_PARAM_END
    ];
  result := @aes_cbc_cts_known_gettable_ctx_params[0];
end;

(*
  CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(aes_cbc_cts)
  OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
  CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(aes_cbc_cts)
*)
function aes_cbc_cts_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    aes_cbc_cts_known_settable_ctx_params := [
      _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
      _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
      _OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, nil, 0),
      OSSL_PARAM_END
    ];
   result := @aes_cbc_cts_known_settable_ctx_params[0];
end;


end.
