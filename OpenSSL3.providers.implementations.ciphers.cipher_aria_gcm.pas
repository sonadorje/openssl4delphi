unit OpenSSL3.providers.implementations.ciphers.cipher_aria_gcm;

interface
uses OpenSSL.Api,
     OpenSSL3.providers.implementations.ciphers.ciphercommon,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm;

 function aria_gcm_newctx( provctx : Pointer; keybits : size_t):Pointer;
 procedure aria_gcm_freectx( vctx : Pointer);

 function aria_128_gcm_get_params( params : POSSL_PARAM):integer;
  function aria128gcm_newctx( provctx : Pointer):Pointer;
  function aria_192_gcm_get_params( params : POSSL_PARAM):integer;
  function aria192gcm_newctx( provctx : Pointer):Pointer;
  function aria_256_gcm_get_params( params : POSSL_PARAM):integer;
  function aria256gcm_newctx( provctx : Pointer):Pointer;

 const  ossl_aria128gcm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aria128gcm_newctx; data:nil)),
(function_id:  7; method:(code:@aria_gcm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_gcm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_gcm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_gcm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_gcm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_gcm_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_gcm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_gcm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_gcm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aria192gcm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aria192gcm_newctx; data:nil)),
(function_id:  7; method:(code:@aria_gcm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_gcm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_gcm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_gcm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_gcm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_gcm_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_gcm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_gcm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_gcm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256gcm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aria256gcm_newctx; data:nil)),
(function_id:  7; method:(code:@aria_gcm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_gcm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_gcm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_gcm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_gcm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_gcm_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_gcm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_gcm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_gcm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.providers.implementations.ciphers.cipher_aria_gcm_hw;







function aria_128_gcm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $6, ($0001 or $0002), 128, 8, 96));
end;


function aria128gcm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aria_gcm_newctx(provctx, 128));
end;


function aria_192_gcm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $6, ($0001 or $0002), 192, 8, 96));
end;


function aria192gcm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aria_gcm_newctx(provctx, 192));
end;


function aria_256_gcm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $6, ($0001 or $0002), 256, 8, 96));
end;


function aria256gcm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aria_gcm_newctx(provctx, 256));
end;

function aria_gcm_newctx( provctx : Pointer; keybits : size_t):Pointer;
var
  ctx : PPROV_ARIA_GCM_CTX;
begin
    if not ossl_prov_is_running then Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
       ossl_gcm_initctx(provctx, @ctx.base, keybits, ossl_prov_aria_hw_gcm(keybits));
    Result := ctx;
end;


procedure aria_gcm_freectx( vctx : Pointer);
var
  ctx : PPROV_ARIA_GCM_CTX;
begin
    ctx := PPROV_ARIA_GCM_CTX(vctx);
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


end.
