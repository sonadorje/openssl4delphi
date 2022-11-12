unit OpenSSL3.providers.implementations.ciphers.cipher_aes_gcm;

interface
uses OpenSSL.Api, openssl3.crypto.modes.gcm128,
     OpenSSL3.providers.implementations.ciphers.ciphercommon,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm;

 function aes_gcm_newctx( provctx : Pointer; keybits : size_t):Pointer;

 procedure aes_gcm_freectx( vctx : Pointer);
 function aes_256_gcm_get_params( params : POSSL_PARAM):integer;
 function aes256gcm_newctx( provctx : Pointer):Pointer;



 const ossl_aes256gcm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes256gcm_newctx; data:nil)),
(function_id:  7; method:(code:@aes_gcm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_gcm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_gcm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_gcm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_gcm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_gcm_cipher; data:nil)),
(function_id:  9; method:(code:@aes_256_gcm_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_gcm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_gcm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function aes_128_gcm_get_params( params : POSSL_PARAM):integer;
  function aes128gcm_newctx( provctx : Pointer):Pointer;
  function aes_192_gcm_get_params( params : POSSL_PARAM):integer;
  function aes192gcm_newctx( provctx : Pointer):Pointer;


const  ossl_aes128gcm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes128gcm_newctx; data:nil)),
(function_id:  7; method:(code:@aes_gcm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_gcm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_gcm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_gcm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_gcm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_gcm_cipher; data:nil)),
(function_id:  9; method:(code:@ aes_128_gcm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_gcm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_gcm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes192gcm_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes192gcm_newctx; data:nil)),
(function_id:  7; method:(code:@aes_gcm_freectx; data:nil)),
(function_id:  2; method:(code:@ossl_gcm_einit; data:nil)),
(function_id:  3; method:(code:@ossl_gcm_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_gcm_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_gcm_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_gcm_cipher; data:nil)),
(function_id:  9; method:(code:@ aes_192_gcm_get_params; data:nil)),
(function_id:  10; method:(code:@ ossl_gcm_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ ossl_gcm_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_aead_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_aead_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation

uses openssl3.providers.prov_running, OpenSSL3.Err, openssl3.crypto.mem,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_gcm_hw;




function aes_128_gcm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $6, ($0001 or $0002), 128, 8, 96));
end;


function aes128gcm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_gcm_newctx(provctx, 128));
end;


function aes_192_gcm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $6, ($0001 or $0002), 192, 8, 96));
end;


function aes192gcm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_gcm_newctx(provctx, 192));
end;

function aes_256_gcm_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $6, ($0001 or $0002), 256, 8, 96));
end;


function aes256gcm_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_gcm_newctx(provctx, 256));
end;



procedure aes_gcm_freectx( vctx : Pointer);
var
  ctx : PPROV_AES_GCM_CTX;
begin
    ctx := PPROV_AES_GCM_CTX (vctx);
    if ctx = nil then exit;
    ctx^ := default(TPROV_AES_GCM_CTX);
    ctx := nil;
    Freemem(ctx);
    //OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;

function aes_gcm_newctx( provctx : Pointer; keybits : size_t):Pointer;
var
  ctx : PPROV_AES_GCM_CTX;
begin
    if not ossl_prov_is_running then Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
       ossl_gcm_initctx(provctx, @ctx.base, keybits,
                         ossl_prov_aes_hw_gcm(keybits));
    Result := ctx;
end;


end.
