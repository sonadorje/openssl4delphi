unit OpenSSL3.providers.implementations.ciphers.cipher_null;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

type

  prov_cipher_null_ctx_st = record
  var
      enc        : integer;
      tlsmacsize : size_t;
      tlsmac     : Pbyte;
  end;
  TPROV_CIPHER_NULL_CTX = prov_cipher_null_ctx_st;
  PPROV_CIPHER_NULL_CTX = ^TPROV_CIPHER_NULL_CTX;

function null_newctx( provctx : Pointer):Pointer;
  procedure null_freectx( vctx : Pointer);
  function null_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function null_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function null_cipher(vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t;const &in : PByte; inl : size_t):integer;
  function null_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function null_get_params( params : POSSL_PARAM):integer;
  function null_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function null_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function null_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function null_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;

const  ossl_null_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ null_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@ null_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@ null_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@null_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@null_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@null_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@null_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@null_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS; method:(code:@ null_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
        method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS; method:(code:@null_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@null_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS; method:(code:@null_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
      method:(code:@null_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

var
  null_known_gettable_ctx_params:array[0..3] of TOSSL_PARAM ;
  null_known_settable_ctx_params:array[0..1] of TOSSL_PARAM ;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err;

function null_newctx( provctx : Pointer):Pointer;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    Result := OPENSSL_zalloc(sizeof(TPROV_CIPHER_NULL_CTX));
end;


procedure null_freectx( vctx : Pointer);
begin
    OPENSSL_free(vctx);
end;


function null_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_NULL_CTX;
begin
    ctx := PPROV_CIPHER_NULL_CTX (vctx);
    if not ossl_prov_is_running then
        Exit(0);
    ctx.enc := 1;
    Result := 1;
end;


function null_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running then
        Exit(0);
    Result := 1;
end;


function null_cipher(vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t;const &in : PByte; inl : size_t):integer;
var
  ctx : PPROV_CIPHER_NULL_CTX;
begin
    ctx := PPROV_CIPHER_NULL_CTX (vctx);
    if not ossl_prov_is_running then
        Exit(0);
    if (0>= ctx.enc)  and  (ctx.tlsmacsize > 0) then
    begin
        {
         * TLS nil cipher as per:
         * https://tools.ietf.org/html/rfc5246#section-6.2.3.1
         }
        if inl < ctx.tlsmacsize then
            Exit(0);
        ctx.tlsmac := &in + inl - ctx.tlsmacsize;
        inl  := inl - ctx.tlsmacsize;
    end;
    if outsize < inl then Exit(0);
    if &in <> &out then
       memcpy(&out, &in, inl);
    outl^ := inl;
    Result := 1;
end;


function null_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
begin
    if not ossl_prov_is_running then
        Exit(0);
    outl^ := 0;
    Result := 1;
end;


function null_get_params( params : POSSL_PARAM):integer;
begin
    Result := ossl_cipher_generic_get_params(params, 0, 0, 0, 8, 0);
end;


function null_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @null_known_gettable_ctx_params;
end;


function null_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_NULL_CTX;

  p : POSSL_PARAM;
begin
    ctx := PPROV_CIPHER_NULL_CTX (vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, 0)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, 0)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_octet_ptr(p, ctx.tlsmac, ctx.tlsmacsize))  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;


function null_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @null_known_settable_ctx_params;
end;


function null_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_NULL_CTX;
  p   : POSSL_PARAM;
begin
    ctx := PPROV_CIPHER_NULL_CTX (vctx);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_size_t(p, @ctx.tlsmacsize) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
    end;
    Result := 1;
end;

initialization
  null_known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil);
  null_known_gettable_ctx_params[1] := _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil);
  null_known_gettable_ctx_params[2].key := OSSL_CIPHER_PARAM_TLS_MAC;
  null_known_gettable_ctx_params[2].data_type := OSSL_PARAM_OCTET_PTR;
  null_known_gettable_ctx_params[2].data := nil;
  null_known_gettable_ctx_params[2].data_size := 0;
  null_known_gettable_ctx_params[2].return_size := OSSL_PARAM_UNMODIFIED ;
  null_known_gettable_ctx_params[3] := OSSL_PARAM_END ;

  null_known_settable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, nil);
  null_known_settable_ctx_params[1] := OSSL_PARAM_END;

end.
