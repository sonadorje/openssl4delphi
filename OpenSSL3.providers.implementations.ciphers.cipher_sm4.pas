unit OpenSSL3.providers.implementations.ciphers.cipher_sm4;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

  procedure sm4_freectx( vctx : Pointer);
  function sm4_dupctx( ctx : Pointer):Pointer;
  function sm4_128_ecb_get_params( params : POSSL_PARAM):integer;
  function sm4_128_ecb_newctx( provctx : Pointer):Pointer;
  function sm4_128_cbc_get_params( params : POSSL_PARAM):integer;
  function sm4_128_cbc_newctx( provctx : Pointer):Pointer;
  function sm4_128_ctr_get_params( params : POSSL_PARAM):integer;
  function sm4_128_ctr_newctx( provctx : Pointer):Pointer;
  function sm4_128_ofb128_get_params( params : POSSL_PARAM):integer;
  function sm4_128_ofb128_newctx( provctx : Pointer):Pointer;
  function sm4_128_cfb128_get_params( params : POSSL_PARAM):integer;
  function sm4_128_cfb128_newctx( provctx : Pointer):Pointer;

const  ossl_sm4128ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ sm4_128_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ sm4_freectx; data:nil)),
(function_id:  8; method:(code:@ sm4_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ sm4_128_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_sm4128cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ sm4_128_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ sm4_freectx; data:nil)),
(function_id:  8; method:(code:@ sm4_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ sm4_128_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_sm4128ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ sm4_128_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ sm4_freectx; data:nil)),
(function_id:  8; method:(code:@ sm4_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ sm4_128_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_sm4128ofb128_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ sm4_128_ofb128_newctx; data:nil)),
(function_id:  7; method:(code:@ sm4_freectx; data:nil)),
(function_id:  8; method:(code:@ sm4_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ sm4_128_ofb128_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_sm4128cfb128_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ sm4_128_cfb128_newctx; data:nil)),
(function_id:  7; method:(code:@ sm4_freectx; data:nil)),
(function_id:  8; method:(code:@ sm4_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ sm4_128_cfb128_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem, OpenSSL3.Err,
     OpenSSL3.providers.implementations.ciphers.cipher_sm4_hw;


function sm4_128_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 128, 128, 0));
end;


function sm4_128_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_SM4_CTX;
begin
   if ossl_prov_is_running then
      ctx := CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;
   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 128, 0, $1, 0, ossl_prov_cipher_hw_sm4_ecb(128), provctx);
   end;
   Exit(ctx);
end;


function sm4_128_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 128, 128, 128));
end;


function sm4_128_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_SM4_CTX;
begin
    if ossl_prov_is_running then
      ctx := CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;
   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 128, 128, $2, 0, ossl_prov_cipher_hw_sm4_cbc(128), provctx);
   end;
 Exit(ctx);
end;


function sm4_128_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 128, 8, 128));
end;


function sm4_128_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_SM4_CTX;
begin
    if ossl_prov_is_running then
      ctx := CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;
   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $5, 0, ossl_prov_cipher_hw_sm4_ctr(128), provctx);
   end;
 Exit(ctx);
end;


function sm4_128_ofb128_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 128, 8, 128));
end;


function sm4_128_ofb128_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_SM4_CTX;
begin
  if ossl_prov_is_running then
      ctx := CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;
   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $4, 0, ossl_prov_cipher_hw_sm4_ofb128(128), provctx);
   end;
 Exit(ctx);
end;


function sm4_128_cfb128_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function sm4_128_cfb128_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_SM4_CTX;
begin
    if ossl_prov_is_running then
      ctx := CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;
   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_sm4_cfb128(128), provctx);
   end;
 Exit(ctx);
end;

procedure sm4_freectx( vctx : Pointer);
var
  ctx : PPROV_SM4_CTX;
begin
    ctx := PPROV_SM4_CTX(vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX (vctx));
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sm4_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PPROV_SM4_CTX;
begin
    _in := PPROV_SM4_CTX(ctx);
    if not ossl_prov_is_running then Exit(nil);
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    _in.base.hw.copyctx(@ret.base, @_in.base);
    Result := ret;
end;


end.
