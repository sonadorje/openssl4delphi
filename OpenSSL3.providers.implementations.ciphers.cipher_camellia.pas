unit OpenSSL3.providers.implementations.ciphers.cipher_camellia;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon,
    OpenSSL3.providers.implementations.ciphers.cipher_cts;

procedure camellia_freectx( vctx : Pointer);
  function camellia_dupctx( ctx : Pointer):Pointer;
function camellia_256_ecb_get_params( params : POSSL_PARAM):integer;
  function camellia_256_ecb_newctx( provctx : Pointer):Pointer;
  function camellia_192_ecb_get_params( params : POSSL_PARAM):integer;
  function camellia_192_ecb_newctx( provctx : Pointer):Pointer;
  function camellia_128_ecb_get_params( params : POSSL_PARAM):integer;
  function camellia_128_ecb_newctx( provctx : Pointer):Pointer;
  function camellia_256_cbc_get_params( params : POSSL_PARAM):integer;
  function camellia_256_cbc_newctx( provctx : Pointer):Pointer;
  function camellia_192_cbc_get_params( params : POSSL_PARAM):integer;
  function camellia_192_cbc_newctx( provctx : Pointer):Pointer;
  function camellia_128_cbc_get_params( params : POSSL_PARAM):integer;
  function camellia_128_cbc_newctx( provctx : Pointer):Pointer;
  function camellia_256_ofb_get_params( params : POSSL_PARAM):integer;
  function camellia_256_ofb_newctx( provctx : Pointer):Pointer;
  function camellia_192_ofb_get_params( params : POSSL_PARAM):integer;
  function camellia_192_ofb_newctx( provctx : Pointer):Pointer;
  function camellia_128_ofb_get_params( params : POSSL_PARAM):integer;
  function camellia_128_ofb_newctx( provctx : Pointer):Pointer;
  function camellia_256_cfb_get_params( params : POSSL_PARAM):integer;
  function camellia_256_cfb_newctx( provctx : Pointer):Pointer;
  function camellia_192_cfb_get_params( params : POSSL_PARAM):integer;
  function camellia_192_cfb_newctx( provctx : Pointer):Pointer;
  function camellia_128_cfb_get_params( params : POSSL_PARAM):integer;
  function camellia_128_cfb_newctx( provctx : Pointer):Pointer;
  function camellia_256_cfb1_get_params( params : POSSL_PARAM):integer;
  function camellia_256_cfb1_newctx( provctx : Pointer):Pointer;
  function camellia_192_cfb1_get_params( params : POSSL_PARAM):integer;
  function camellia_192_cfb1_newctx( provctx : Pointer):Pointer;
  function camellia_128_cfb1_get_params( params : POSSL_PARAM):integer;
  function camellia_128_cfb1_newctx( provctx : Pointer):Pointer;
  function camellia_256_cfb8_get_params( params : POSSL_PARAM):integer;
  function camellia_256_cfb8_newctx( provctx : Pointer):Pointer;
  function camellia_192_cfb8_get_params( params : POSSL_PARAM):integer;
  function camellia_192_cfb8_newctx( provctx : Pointer):Pointer;
  function camellia_128_cfb8_get_params( params : POSSL_PARAM):integer;
  function camellia_128_cfb8_newctx( provctx : Pointer):Pointer;
  function camellia_256_ctr_get_params( params : POSSL_PARAM):integer;
  function camellia_256_ctr_newctx( provctx : Pointer):Pointer;
  function camellia_192_ctr_get_params( params : POSSL_PARAM):integer;
  function camellia_192_ctr_newctx( provctx : Pointer):Pointer;
  function camellia_128_ctr_get_params( params : POSSL_PARAM):integer;
  function camellia_128_ctr_newctx( provctx : Pointer):Pointer;

  const  ossl_camellia256ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );


const  ossl_camellia192ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia128ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia256cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia192cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia128cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia256ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_ofb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_ofb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia192ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_ofb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_ofb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia128ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_ofb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_ofb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia256cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_cfb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_cfb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia192cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_cfb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_cfb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia128cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_cfb_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_cfb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia256cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_cfb1_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_cfb1_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia192cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_cfb1_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_cfb1_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia128cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_cfb1_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_cfb1_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia256cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_cfb8_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_cfb8_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia192cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_cfb8_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_cfb8_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia128cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_cfb8_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_cfb8_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia256ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_256_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia192ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_192_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia128ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_128_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

  function camellia_cts_256_cbc_get_params( params : POSSL_PARAM):integer;
  function camellia_cts_192_cbc_get_params( params : POSSL_PARAM):integer;
  function camellia_cts_128_cbc_get_params( params : POSSL_PARAM):integer;
  function camellia_cbc_cts_einit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function camellia_cbc_cts_dinit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function camellia_cbc_cts_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function camellia_cbc_cts_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function camellia_cbc_cts_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function camellia_cbc_cts_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;

const  ossl_camellia256cbc_cts_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_256_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ camellia_cbc_cts_einit; data:nil)),
(function_id:  3; method:(code:@ camellia_cbc_cts_dinit; data:nil)),
(function_id:  4; method:(code:@ ossl_cipher_cbc_cts_block_update; data:nil)),
(function_id:  5; method:(code:@ ossl_cipher_cbc_cts_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_cts_256_cbc_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ camellia_cbc_cts_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ camellia_cbc_cts_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ camellia_cbc_cts_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ camellia_cbc_cts_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_camellia192cbc_cts_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_192_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ camellia_cbc_cts_einit; data:nil)),
(function_id:  3; method:(code:@ camellia_cbc_cts_dinit; data:nil)),
(function_id:  4; method:(code:@ ossl_cipher_cbc_cts_block_update; data:nil)),
(function_id:  5; method:(code:@ ossl_cipher_cbc_cts_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_cts_192_cbc_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ camellia_cbc_cts_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ camellia_cbc_cts_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ camellia_cbc_cts_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ camellia_cbc_cts_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_camellia128cbc_cts_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ camellia_128_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ camellia_freectx; data:nil)),
(function_id:  8; method:(code:@ camellia_dupctx; data:nil)),
(function_id:  2; method:(code:@ camellia_cbc_cts_einit; data:nil)),
(function_id:  3; method:(code:@ camellia_cbc_cts_dinit; data:nil)),
(function_id:  4; method:(code:@ ossl_cipher_cbc_cts_block_update; data:nil)),
(function_id:  5; method:(code:@ ossl_cipher_cbc_cts_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ camellia_cts_128_cbc_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ camellia_cbc_cts_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ camellia_cbc_cts_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ camellia_cbc_cts_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ camellia_cbc_cts_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );




var
   camellia_cbc_cts_known_gettable_ctx_params,
   camellia_cbc_cts_known_settable_ctx_params: array of TOSSL_PARAM;

implementation
uses openssl3.crypto.mem, openssl3.providers.fips.self_test, OpenSSL3.Err,
     openssl3.crypto.params,       OpenSSL3.openssl.params,
     OpenSSL3.providers.implementations.ciphers.cipher_camellia_hw,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw;





function camellia_cbc_cts_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
   Result := @camellia_cbc_cts_known_settable_ctx_params[0];
end;



function camellia_cbc_cts_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
   Result := @camellia_cbc_cts_known_gettable_ctx_params[0];
end;


function camellia_cbc_cts_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p : POSSL_PARAM;
  id : integer;
  label _err;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE{'cts_mode'});
    if p <> Pointer(0) then
    begin
        if p.data_type <> 4 then
            goto _err;
        id := ossl_cipher_cbc_cts_mode_name2id(p.data);
        if id < 0 then goto _err;
        ctx.cts_mode := uint32(id);
    end;
    Exit(ossl_cipher_generic_set_ctx_params(vctx, params));
_err:
    ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
    Result := 0;
end;

function camellia_cbc_cts_einit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    if 0>=ossl_cipher_generic_einit(ctx, key, keylen, iv, ivlen, nil) then
        Exit(0);
    Result := camellia_cbc_cts_set_ctx_params(ctx, params);
end;


function camellia_cbc_cts_dinit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    if 0>=ossl_cipher_generic_dinit(ctx, key, keylen, iv, ivlen, nil) then
        Exit(0);
    Result := camellia_cbc_cts_set_ctx_params(ctx, params);
end;


function camellia_cbc_cts_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p : POSSL_PARAM;
  name : PUTF8Char;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE{'cts_mode'});
    if p <> nil then
    begin
        name := ossl_cipher_cbc_cts_mode_id2name(ctx.cts_mode);
        if (name = nil)  or  (0>=OSSL_PARAM_set_utf8_string(p, name)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    Result := ossl_cipher_generic_get_ctx_params(vctx, params);
end;



function camellia_cts_256_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, $0004, 256, 128, 128));
end;


function camellia_cts_192_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, $0004, 192, 128, 128));
end;


function camellia_cts_128_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, $0004, 128, 128, 128));
end;


function camellia_256_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 256, 128, 0));
end;


function camellia_256_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
  if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
      ossl_cipher_generic_initkey(ctx, 256, 128, 0, $1, 0, ossl_prov_cipher_hw_camellia_ecb(256), provctx);
   end;
 Exit(ctx);
end;


function camellia_192_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 192, 128, 0));
end;


function camellia_192_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 128, 0, $1, 0, ossl_prov_cipher_hw_camellia_ecb(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 128, 128, 0));
end;


function camellia_128_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 128, 0, $1, 0, ossl_prov_cipher_hw_camellia_ecb(128), provctx);
   end;
 Exit(ctx);
end;


function camellia_256_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 256, 128, 128));
end;


function camellia_256_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 256, 128, 128, $2, 0, ossl_prov_cipher_hw_camellia_cbc(256), provctx);
   end;
   Exit(ctx);
end;


function camellia_192_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 192, 128, 128));
end;


function camellia_192_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 192, 128, 128, $2, 0, ossl_prov_cipher_hw_camellia_cbc(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 128, 128, 128));
end;


function camellia_128_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 128, 128, 128, $2, 0, ossl_prov_cipher_hw_camellia_cbc(128), provctx);
 end;
 Exit(ctx);
end;


function camellia_256_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 256, 8, 128));
end;


function camellia_256_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin ossl_cipher_generic_initkey(ctx, 256, 8, 128, $4, 0, ossl_prov_cipher_hw_camellia_ofb128(256), provctx);
 end;
 Exit(ctx);
end;


function camellia_192_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 192, 8, 128));
end;


function camellia_192_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 8, 128, $4, 0, ossl_prov_cipher_hw_camellia_ofb128(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 128, 8, 128));
end;


function camellia_128_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 128, 8, 128, $4, 0, ossl_prov_cipher_hw_camellia_ofb128(128), provctx);
 end;
 Exit(ctx);
end;


function camellia_256_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 256, 8, 128));
end;


function camellia_256_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 256, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb128(256), provctx);
 end;
 Exit(ctx);
end;


function camellia_192_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 192, 8, 128));
end;


function camellia_192_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb128(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function camellia_128_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb128(128), provctx);
 end;
 Exit(ctx);
end;


function camellia_256_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 256, 8, 128));
end;


function camellia_256_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 256, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb1(256), provctx);
 end;
 Exit(ctx);
end;


function camellia_192_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 192, 8, 128));
end;


function camellia_192_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb1(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function camellia_128_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb1(128), provctx);
 end;
 Exit(ctx);
end;


function camellia_256_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 256, 8, 128));
end;


function camellia_256_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 256, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb8(256), provctx);
 end;
 Exit(ctx);
end;


function camellia_192_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 192, 8, 128));
end;


function camellia_192_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb8(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function camellia_128_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
    ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_camellia_cfb8(128), provctx);
 end;
 Exit(ctx);
end;


function camellia_256_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 256, 8, 128));
end;


function camellia_256_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 256, 8, 128, $5, 0, ossl_prov_cipher_hw_camellia_ctr(256), provctx);
 end;
 Exit(ctx);
end;


function camellia_192_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 192, 8, 128));
end;


function camellia_192_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
    ossl_cipher_generic_initkey(ctx, 192, 8, 128, $5, 0, ossl_prov_cipher_hw_camellia_ctr(192), provctx);
 end;
 Exit(ctx);
end;


function camellia_128_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 128, 8, 128));
end;


function camellia_128_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_CAMELLIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $5, 0, ossl_prov_cipher_hw_camellia_ctr(128), provctx);
 end;
 Exit(ctx);
end;

procedure camellia_freectx( vctx : Pointer);
var
  ctx : PPROV_CAMELLIA_CTX;
begin
    ctx := PPROV_CAMELLIA_CTX(vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX (vctx));
    OPENSSL_clear_free(Pointer(ctx),  sizeof(ctx^));
end;


function camellia_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PPROV_CAMELLIA_CTX;
begin
    _in := PPROV_CAMELLIA_CTX(ctx);
    if not ossl_prov_is_running then Exit(nil);
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    _in.base.hw.copyctx(@ret.base, @_in.base);
    Result := ret;
end;

initialization
   camellia_cbc_cts_known_gettable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, nil, 0),
    OSSL_PARAM_END
  ];

  camellia_cbc_cts_known_settable_ctx_params := [
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
    _OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, nil, 0),
    OSSL_PARAM_END
  ];
end.
