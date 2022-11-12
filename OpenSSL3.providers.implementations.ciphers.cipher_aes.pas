unit OpenSSL3.providers.implementations.ciphers.cipher_aes;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.cipher_cts,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cts,
     OpenSSL3.providers.implementations.ciphers.ciphercommon;




function aes_192_cfb1_get_params( params : POSSL_PARAM):integer;
function aes_192_cfb1_newctx( provctx : Pointer):Pointer;
procedure aes_freectx( vctx : Pointer);
function aes_dupctx( ctx : Pointer):Pointer;

function aes_256_ecb_get_params( params : POSSL_PARAM):integer;
 function aes_256_ecb_newctx( provctx : Pointer):Pointer;
function aes_192_ecb_get_params( params : POSSL_PARAM):integer;
  function aes_192_ecb_newctx( provctx : Pointer):Pointer;
function aes_128_ecb_get_params( params : POSSL_PARAM):integer;
  function aes_128_ecb_newctx( provctx : Pointer):Pointer;

  function aes_256_cbc_get_params( params : POSSL_PARAM):integer;
  function aes_256_cbc_newctx( provctx : Pointer):Pointer;
  function aes_192_cbc_get_params( params : POSSL_PARAM):integer;
  function aes_192_cbc_newctx( provctx : Pointer):Pointer;
  function aes_128_cbc_newctx( provctx : Pointer):Pointer;

  function aes_256_ofb_get_params( params : POSSL_PARAM):integer;
  function aes_256_ofb_newctx( provctx : Pointer):Pointer;

  function aes_192_ofb_get_params( params : POSSL_PARAM):integer;
  function aes_192_ofb_newctx( provctx : Pointer):Pointer;

  function aes_128_ofb_get_params( params : POSSL_PARAM):integer;
  function aes_128_ofb_newctx( provctx : Pointer):Pointer;

  function aes_256_cfb_get_params( params : POSSL_PARAM):integer;
  function aes_256_cfb_newctx( provctx : Pointer):Pointer;

  function aes_192_cfb_get_params( params : POSSL_PARAM):integer;
  function aes_192_cfb_newctx( provctx : Pointer):Pointer;

  function aes_128_cfb_get_params( params : POSSL_PARAM):integer;
  function aes_128_cfb_newctx( provctx : Pointer):Pointer;

  function aes_256_cfb1_get_params( params : POSSL_PARAM):integer;
  function aes_256_cfb1_newctx( provctx : Pointer):Pointer;

  function aes_128_cfb1_get_params( params : POSSL_PARAM):integer;
  function aes_128_cfb1_newctx( provctx : Pointer):Pointer;

  function aes_256_cfb8_get_params( params : POSSL_PARAM):integer;
  function aes_256_cfb8_newctx( provctx : Pointer):Pointer;

  function aes_192_cfb8_get_params( params : POSSL_PARAM):integer;
  function aes_192_cfb8_newctx( provctx : Pointer):Pointer;

  function aes_128_cfb8_get_params( params : POSSL_PARAM):integer;
  function aes_128_cfb8_newctx( provctx : Pointer):Pointer;

  function aes_256_ctr_get_params( params : POSSL_PARAM):integer;
  function aes_256_ctr_newctx( provctx : Pointer):Pointer;

   function aes_192_ctr_get_params( params : POSSL_PARAM):integer;
  function aes_192_ctr_newctx( provctx : Pointer):Pointer;

  function aes_128_ctr_get_params( params : POSSL_PARAM):integer;
  function aes_128_ctr_newctx( provctx : Pointer):Pointer;

(* ossl_aes256ecb_functions
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 256, 128, 0, block)
 *)
const ossl_aes256ecb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_256_ecb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_256_ecb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192cfb1_functions
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)
*)

const ossl_aeskbitscfb1_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_192_cfb1_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_cfb1_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

(* ossl_aes192ecb_functions
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 192, 128, 0, block) *)
const  ossl_aes192ecb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_192_ecb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_ecb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes128ecb_functions
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 128, 128, 0, block)*)
const ossl_aes128ecb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_128_ecb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_128_ecb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes256cbc_functions
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 256, 128, 128, block)*)
const  ossl_aes256cbc_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_256_cbc_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_256_cbc_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192cbc_functions
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 192, 128, 128, block)*)
const ossl_aes192cbc_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_192_cbc_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_cbc_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes128cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 128, 128, 128, block)*)
const  ossl_aes128cbc_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_128_cbc_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_128_cbc_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* cipher_aes_cts.inc
   ossl_aes128cbc_cts_functions
IMPLEMENT_cts_cipher(aes, AES, cbc, CBC, CTS_FLAGS, 128, 128, 128, block)*)

const  ossl_aes128cbc_cts_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_128_cbc_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@aes_cbc_cts_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@aes_cbc_cts_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;
      method:(code:@ossl_cipher_cbc_cts_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;
      method:(code:@ossl_cipher_cbc_cts_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_cts_128_cbc_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@aes_cbc_cts_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@aes_cbc_cts_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@aes_cbc_cts_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@aes_cbc_cts_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

(* ossl_aes192cbc_cts_functions
IMPLEMENT_cts_cipher(aes, AES, cbc, CBC, CTS_FLAGS, 192, 128, 128, block)*)
const ossl_aes192cbc_cts_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_192_cbc_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@aes_cbc_cts_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@aes_cbc_cts_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;
      method:(code:@ossl_cipher_cbc_cts_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;
      method:(code:@ossl_cipher_cbc_cts_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_cts_192_cbc_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@aes_cbc_cts_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@aes_cbc_cts_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@aes_cbc_cts_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@aes_cbc_cts_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

(* ossl_aes256cbc_cts_functions
IMPLEMENT_cts_cipher(aes, AES, cbc, CBC, CTS_FLAGS, 256, 128, 128, block)*)
const ossl_aes256cbc_cts_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_256_cbc_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX; method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX; method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT; method:(code:@aes_cbc_cts_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT; method:(code:@aes_cbc_cts_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;
      method:(code:@ossl_cipher_cbc_cts_block_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;
      method:(code:@ossl_cipher_cbc_cts_block_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER; method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_cts_256_cbc_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@aes_cbc_cts_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@aes_cbc_cts_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@aes_cbc_cts_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@aes_cbc_cts_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

(* ossl_aes256ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)*)
const  ossl_aes256ofb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_256_ofb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_256_ofb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192ofb_functions
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)*)
const  ossl_aes192ofb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_192_ofb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_192_ofb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes128ofb_functions
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)*)
const  ossl_aes128ofb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_128_ofb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_128_ofb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes256cfb_functions
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 256, 8, 128, stream)*)
const  ossl_aes256cfb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_256_cfb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_256_cfb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 192, 8, 128, stream)*)
const  ossl_aes192cfb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_192_cfb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@aes_192_cfb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes128cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 128, 8, 128, stream)*)
const  ossl_aes128cfb_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@aes_128_cfb_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_128_cfb_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes256cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 256, 8, 128, stream)*)
const  ossl_aes256cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_256_cfb1_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_256_cfb1_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)*)
const  ossl_aes192cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_192_cfb1_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_cfb1_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

const  ossl_aes128cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_128_cfb1_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_128_cfb1_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes256cfb8_functions
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 256, 8, 128, stream)*)
const  ossl_aes256cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_256_cfb8_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_256_cfb8_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192cfb8_functions
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 192, 8, 128, stream)*)
const  ossl_aes192cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_192_cfb8_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_cfb8_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes128cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 128, 8, 128, stream)*)
const  ossl_aes128cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_128_cfb8_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_128_cfb8_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes256ctr_functions
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)*)
const  ossl_aes256ctr_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_256_ctr_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_256_ctr_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes192ctr_functions
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)*)
const  ossl_aes192ctr_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_192_ctr_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_192_ctr_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

(* ossl_aes128ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)*)
const  ossl_aes128ctr_functions: array[0..14] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CIPHER_NEWCTX;
      method:(code:@ aes_128_ctr_newctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FREECTX;method:(code:@ aes_freectx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DUPCTX;method:(code:@ aes_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_ENCRYPT_INIT;method:(code:@ossl_cipher_generic_einit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_DECRYPT_INIT;method:(code:@ossl_cipher_generic_dinit; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_UPDATE;method:(code:@ossl_cipher_generic_stream_update; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_FINAL;method:(code:@ossl_cipher_generic_stream_final; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_CIPHER;method:(code:@ossl_cipher_generic_cipher; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_PARAMS;
      method:(code:@ aes_128_ctr_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SET_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS;
     method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
    (function_id:  0;method:(code:nil; data:nil) )
);

implementation
uses openssl3.providers.prov_running, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_hw,
     OpenSSL3.common, openssl3.crypto.param_build_set,
     openssl3.crypto.evp.ctrl_params_translate ;

function aes_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PPROV_AES_CTX;
begin
    _in := PPROV_AES_CTX ( ctx);
    if not ossl_prov_is_running then
        Exit(nil);
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    _in.base.hw.copyctx(@ret.base, @_in.base);
    Result := ret;
end;



function aes_128_ctr_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CTR_MODE, 0,128,8,128);
end;


function aes_128_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,128,8,128,
                                     EVP_CIPH_CTR_MODE,0,
                                     ossl_prov_cipher_hw_aes_ctr(128),
                                     provctx);
     end;
     exit(ctx);
end;



function aes_192_ctr_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CTR_MODE, 0,192,8,128);
end;


function aes_192_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,192,8,128,
                                     EVP_CIPH_CTR_MODE,0,
                                     ossl_prov_cipher_hw_aes_ctr(192),
                                     provctx);
     end;
     exit(ctx);
end;


function aes_256_ctr_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CTR_MODE, 0,256,8,128);
end;


function aes_256_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,256,8,128,
                                     EVP_CIPH_CTR_MODE,0,
                                     ossl_prov_cipher_hw_aes_ctr(256),
                                     provctx);
     end;
     exit(ctx);
end;




function aes_128_cfb8_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,128,8,128);
end;


function aes_128_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,128,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb8(128),
                                     provctx);
     end;
     exit(ctx);
end;





function aes_256_cfb8_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,256,8,128);
end;


function aes_256_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,256,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb8(256),
                                     provctx);
     end;
     exit(ctx);
end;





function aes_192_cfb8_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,192,8,128);
end;


function aes_192_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,192,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb8(192),
                                     provctx);
     end;
     exit(ctx);
end;





function aes_128_cfb1_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,128,8,128);
end;


function aes_128_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,128,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb1(128),
                                     provctx);
     end;
     exit(ctx);
end;





function aes_192_cfb1_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,192,8,128);
end;


function aes_192_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,192,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb1(192),
                                     provctx);
     end;
     exit(ctx);
end;







function aes_256_cfb1_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,256,8,128);
end;


function aes_256_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,256,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb1(256),
                                     provctx);
     end;
     exit(ctx);
end;



function aes_128_cfb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,128,8,128);
end;


function aes_128_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,128,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb128(128),
                                     provctx);
     end;
     exit(ctx);
end;





function aes_192_cfb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,192,8,128);
end;


function aes_192_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,192,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb128(192),
                                     provctx);
     end;
     exit(ctx);
end;



function aes_256_cfb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_CFB_MODE, 0,256,8,128);
end;


function aes_256_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,256,8,128,
                                     EVP_CIPH_CFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_cfb128(256),
                                     provctx);
     end;
     exit(ctx);
end;

function aes_128_ofb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_OFB_MODE, 0,128,8,128);
end;


function aes_128_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,128,8,128,
                                     EVP_CIPH_OFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_ofb128(128),
                                     provctx);
     end;
     exit(ctx);
end;




function aes_192_ofb_get_params( params : POSSL_PARAM):integer;
begin
    result := ossl_cipher_generic_get_params(params,EVP_CIPH_OFB_MODE, 0,192,8,128);
end;


function aes_192_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,192,8,128,
                                     EVP_CIPH_OFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_ofb128(192),
                                     provctx);
     end;
     exit(ctx);
end;




function aes_256_ofb_get_params( params : POSSL_PARAM):integer;
begin
    Result := ossl_cipher_generic_get_params(params,EVP_CIPH_OFB_MODE, 0,256,8,128);
end;


function aes_256_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then begin
         ossl_cipher_generic_initkey(ctx,256,8,128,
                                     EVP_CIPH_OFB_MODE,0,
                                     ossl_prov_cipher_hw_aes_ofb128(256),
                                     provctx);
     end;
     exit(ctx);
end;

function aes_128_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
   if ossl_prov_is_running() then
        ctx := OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,128,128,128,
                                     EVP_CIPH_CBC_MODE,0,
                                     ossl_prov_cipher_hw_aes_cbc(128),
                                     provctx);
     end;
     exit(ctx);
end;




function aes_192_cbc_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params,EVP_CIPH_CBC_MODE,
                                          0,192,128,128));
end;


function aes_192_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
     if ossl_prov_is_running() then
        ctx :=  OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;

     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,192,128,128,
                                     EVP_CIPH_CBC_MODE,0,
                                     ossl_prov_cipher_hw_aes_cbc(192),
                                     provctx);
     end;
     Result := ctx;
end;




function aes_256_cbc_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params,EVP_CIPH_CBC_MODE,
                                          0,256,128,128));
end;


function aes_256_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
     if ossl_prov_is_running() then
        ctx :=  OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,256,128,128,
                                     EVP_CIPH_CBC_MODE,0,
                                     ossl_prov_cipher_hw_aes_cbc(256),
                                     provctx);
     end;
     Result := ctx;
end;




function aes_128_ecb_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params,EVP_CIPH_ECB_MODE,
                                          0,128,128,0));
end;


function aes_128_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
     if ossl_prov_is_running() then
        ctx :=  OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,128,128,0,
                                     EVP_CIPH_ECB_MODE,0,
                                     ossl_prov_cipher_hw_aes_ecb(128),
                                     provctx);
     end;
     Result := ctx;
end;





function aes_192_ecb_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params,EVP_CIPH_ECB_MODE,
                                          0,192,128,0));
end;


function aes_192_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
     if ossl_prov_is_running() then
        ctx :=  OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,192,128,0,
                                     EVP_CIPH_ECB_MODE,0,
                                     ossl_prov_cipher_hw_aes_ecb(192),
                                     provctx);
     end;
     Exit(ctx);
end;


function aes_256_ecb_get_params( params : POSSL_PARAM):integer;
begin
    Exit(ossl_cipher_generic_get_params(params,EVP_CIPH_ECB_MODE,
                                          0,256,128,0));
end;



function aes_256_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_AES_CTX;
begin
     if ossl_prov_is_running() then
        ctx :=  OPENSSL_zalloc(sizeof( ctx^))
     else
        ctx := nil;
     if ctx <> nil then
     begin
         ossl_cipher_generic_initkey(ctx,256,128,0,
                                     EVP_CIPH_ECB_MODE,0,
                                     ossl_prov_cipher_hw_aes_ecb(256),
                                     provctx);
     end;
     Result := ctx;
end;





procedure aes_freectx( vctx : Pointer);
var
  ctx : PPROV_AES_CTX;
begin
    ctx := PPROV_AES_CTX ( vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX ( vctx));
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;




end.
