unit OpenSSL3.providers.implementations.ciphers.cipher_aria_ccm;

interface
uses OpenSSL.Api,

     OpenSSL3.providers.implementations.ciphers.ciphercommon,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_ccm;

 function aria_ccm_newctx( provctx : Pointer; keybits : size_t):Pointer;
  procedure aria_ccm_freectx( vctx : Pointer);
function aria_128_ccm_get_params( params : POSSL_PARAM):integer;
  function aria128ccm_newctx( provctx : Pointer):Pointer;
  function aria_192_ccm_get_params( params : POSSL_PARAM):integer;
  function aria192ccm_newctx( provctx : Pointer):Pointer;
  function aria_256_ccm_get_params( params : POSSL_PARAM):integer;
  function aria256ccm_newctx( provctx : Pointer):Pointer;

  const  ossl_aria128ccm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aria128ccm_newctx; data:nil)),
(function_id:  7; method:(code:@aria_ccm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_ccm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_ccm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_ccm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_ccm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_ccm_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_ccm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_ccm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_ccm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria192ccm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aria192ccm_newctx; data:nil)),
(function_id:  7; method:(code:@aria_ccm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_ccm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_ccm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_ccm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_ccm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_ccm_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_ccm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_ccm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_ccm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256ccm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aria256ccm_newctx; data:nil)),
(function_id:  7; method:(code:@aria_ccm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_ccm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_ccm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_ccm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_ccm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_ccm_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_ccm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_ccm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_ccm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.providers.implementations.ciphers.cipher_aria_ccm_hw;







function aria_128_ccm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $7, ($0001 or $0002), 128, 8, 96));
end;


function aria128ccm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aria_ccm_newctx(provctx, 128));
end;


function aria_192_ccm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $7, ($0001 or $0002), 192, 8, 96));
end;


function aria192ccm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aria_ccm_newctx(provctx, 192));
end;


function aria_256_ccm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $7, ($0001 or $0002), 256, 8, 96));
end;


function aria256ccm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aria_ccm_newctx(provctx, 256));
end;

function aria_ccm_newctx( provctx : Pointer; keybits : size_t):Pointer;
var
  ctx : PPROV_ARIA_CCM_CTX;
begin
    if not ossl_prov_is_running then Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
       ossl_ccm_initctx(@ctx.base, keybits, ossl_prov_aria_hw_ccm(keybits));
    Result := ctx;
end;


procedure aria_ccm_freectx( vctx : Pointer);
var
  ctx : PPROV_ARIA_CCM_CTX;
begin
    ctx := PPROV_ARIA_CCM_CTX(vctx);
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


end.
