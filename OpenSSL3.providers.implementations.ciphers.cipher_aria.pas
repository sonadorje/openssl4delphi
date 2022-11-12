unit OpenSSL3.providers.implementations.ciphers.cipher_aria;

interface
uses OpenSSL.Api,
     OpenSSL3.providers.implementations.ciphers.ciphercommon;

  procedure aria_freectx( vctx : Pointer);
  function aria_dupctx( ctx : Pointer):Pointer;
  function aria_256_ecb_get_params( params : POSSL_PARAM):integer;
  function aria_256_ecb_newctx( provctx : Pointer):Pointer;
  function aria_192_ecb_get_params( params : POSSL_PARAM):integer;
  function aria_192_ecb_newctx( provctx : Pointer):Pointer;
  function aria_128_ecb_get_params( params : POSSL_PARAM):integer;
  function aria_128_ecb_newctx( provctx : Pointer):Pointer;
  function aria_256_cbc_get_params( params : POSSL_PARAM):integer;
  function aria_256_cbc_newctx( provctx : Pointer):Pointer;
  function aria_192_cbc_get_params( params : POSSL_PARAM):integer;
  function aria_192_cbc_newctx( provctx : Pointer):Pointer;
  function aria_128_cbc_get_params( params : POSSL_PARAM):integer;
  function aria_128_cbc_newctx( provctx : Pointer):Pointer;
  function aria_256_ofb_get_params( params : POSSL_PARAM):integer;
  function aria_256_ofb_newctx( provctx : Pointer):Pointer;
  function aria_192_ofb_get_params( params : POSSL_PARAM):integer;
  function aria_192_ofb_newctx( provctx : Pointer):Pointer;
  function aria_128_ofb_get_params( params : POSSL_PARAM):integer;
  function aria_128_ofb_newctx( provctx : Pointer):Pointer;
  function aria_256_cfb_get_params( params : POSSL_PARAM):integer;
  function aria_256_cfb_newctx( provctx : Pointer):Pointer;
  function aria_192_cfb_get_params( params : POSSL_PARAM):integer;
  function aria_192_cfb_newctx( provctx : Pointer):Pointer;
  function aria_128_cfb_get_params( params : POSSL_PARAM):integer;
  function aria_128_cfb_newctx( provctx : Pointer):Pointer;
  function aria_256_cfb1_get_params( params : POSSL_PARAM):integer;
  function aria_256_cfb1_newctx( provctx : Pointer):Pointer;
  function aria_192_cfb1_get_params( params : POSSL_PARAM):integer;
  function aria_192_cfb1_newctx( provctx : Pointer):Pointer;
  function aria_128_cfb1_get_params( params : POSSL_PARAM):integer;
  function aria_128_cfb1_newctx( provctx : Pointer):Pointer;
  function aria_256_cfb8_get_params( params : POSSL_PARAM):integer;
  function aria_256_cfb8_newctx( provctx : Pointer):Pointer;
  function aria_192_cfb8_get_params( params : POSSL_PARAM):integer;
  function aria_192_cfb8_newctx( provctx : Pointer):Pointer;
  function aria_128_cfb8_get_params( params : POSSL_PARAM):integer;
  function aria_128_cfb8_newctx( provctx : Pointer):Pointer;
  function aria_256_ctr_get_params( params : POSSL_PARAM):integer;
  function aria_256_ctr_newctx( provctx : Pointer):Pointer;
  function aria_192_ctr_get_params( params : POSSL_PARAM):integer;
  function aria_192_ctr_newctx( provctx : Pointer):Pointer;
  function aria_128_ctr_get_params( params : POSSL_PARAM):integer;
  function aria_128_ctr_newctx( provctx : Pointer):Pointer;


  const  ossl_aria256ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aria192ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria128ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_ecb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_ecb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria192cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aria128cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_cbc_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_cbc_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_ofb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_ofb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria192ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_ofb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_ofb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria128ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_ofb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_ofb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_cfb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_cfb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria192cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_cfb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_cfb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria128cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_cfb_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_cfb_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_cfb1_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_cfb1_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria192cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_cfb1_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_cfb1_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria128cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_cfb1_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_cfb1_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_cfb8_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_cfb8_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria192cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_cfb8_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_cfb8_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aria128cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_cfb8_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_cfb8_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria256ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_256_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_256_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aria192ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_192_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_192_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aria128ctr_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@ aria_128_ctr_newctx; data:nil)),
(function_id:  7; method:(code:@ aria_freectx; data:nil)),
(function_id:  8; method:(code:@ aria_dupctx; data:nil)),
(function_id:  2; method:(code:@ossl_cipher_generic_einit; data:nil)),
(function_id:  3; method:(code:@ossl_cipher_generic_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  9; method:(code:@ aria_128_ctr_get_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

function ossl_prov_cipher_hw_aria_cbc( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_aria_ecb( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_aria_ofb128( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_aria_cfb128( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_aria_cfb1( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_aria_cfb8( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_aria_ctr( keybits : size_t):PPROV_CIPHER_HW;


implementation

uses openssl3.providers.fips.self_test, openssl3.crypto.mem, OpenSSL3.Err,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw,
     OpenSSL3.providers.implementations.ciphers.cipher_aria_hw;


var
  aria_cbc: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_chunked_cbc;copyctx: cipher_hw_aria_copyctx );
aria_ecb: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_generic_ecb;copyctx: cipher_hw_aria_copyctx );
aria_ofb128: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_chunked_ofb128;copyctx: cipher_hw_aria_copyctx );
aria_cfb128: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_chunked_cfb128;copyctx: cipher_hw_aria_copyctx );
aria_cfb1: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_generic_cfb1;copyctx: cipher_hw_aria_copyctx );
aria_cfb8: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_chunked_cfb8;copyctx: cipher_hw_aria_copyctx );
aria_ctr: TPROV_CIPHER_HW =
( init: cipher_hw_aria_initkey;cipher: ossl_cipher_hw_generic_ctr;copyctx: cipher_hw_aria_copyctx );


function ossl_prov_cipher_hw_aria_cbc( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_cbc);
end;


function ossl_prov_cipher_hw_aria_ecb( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_ecb);
end;


function ossl_prov_cipher_hw_aria_ofb128( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_ofb128);
end;


function ossl_prov_cipher_hw_aria_cfb128( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_cfb128);
end;


function ossl_prov_cipher_hw_aria_cfb1( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_cfb1);
end;


function ossl_prov_cipher_hw_aria_cfb8( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_cfb8);
end;


function ossl_prov_cipher_hw_aria_ctr( keybits : size_t):PPROV_CIPHER_HW;
begin
 Exit(@aria_ctr);
end;




function aria_256_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 256, 128, 0));
end;


function aria_256_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
      ossl_cipher_generic_initkey(ctx, 256, 128, 0, $1, 0, ossl_prov_cipher_hw_aria_ecb(256), provctx);
   end;
   Exit(ctx);
end;


function aria_192_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 192, 128, 0));
end;


function aria_192_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
  if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 128, 0, $1, 0, ossl_prov_cipher_hw_aria_ecb(192), provctx);
   end;
 Exit(ctx);
end;


function aria_128_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, 0, 128, 128, 0));
end;


function aria_128_ecb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
 if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 128, 0, $1, 0, ossl_prov_cipher_hw_aria_ecb(128), provctx);
   end;
 Exit(ctx);
end;


function aria_256_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 256, 128, 128));
end;


function aria_256_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
 if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 256, 128, 128, $2, 0, ossl_prov_cipher_hw_aria_cbc(256), provctx);
   end;
 Exit(ctx);
end;


function aria_192_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 192, 128, 128));
end;


function aria_192_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
  if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
    ossl_cipher_generic_initkey(ctx, 192, 128, 128, $2, 0, ossl_prov_cipher_hw_aria_cbc(192), provctx);
   end;
 Exit(ctx);
end;


function aria_128_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, 0, 128, 128, 128));
end;


function aria_128_cbc_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
 if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
    ossl_cipher_generic_initkey(ctx, 128, 128, 128, $2, 0, ossl_prov_cipher_hw_aria_cbc(128), provctx);
   end;
 Exit(ctx);
end;


function aria_256_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 256, 8, 128));
end;


function aria_256_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
      ossl_cipher_generic_initkey(ctx, 256, 8, 128, $4, 0, ossl_prov_cipher_hw_aria_ofb128(256), provctx);
   end;
 Exit(ctx);
end;


function aria_192_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 192, 8, 128));
end;


function aria_192_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
      ossl_cipher_generic_initkey(ctx, 192, 8, 128, $4, 0, ossl_prov_cipher_hw_aria_ofb128(192), provctx);
   end;
 Exit(ctx);
end;


function aria_128_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, 0, 128, 8, 128));
end;


function aria_128_ofb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
    ossl_cipher_generic_initkey(ctx, 128, 8, 128, $4, 0, ossl_prov_cipher_hw_aria_ofb128(128), provctx);
   end;
 Exit(ctx);
end;


function aria_256_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 256, 8, 128));
end;


function aria_256_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
    ossl_cipher_generic_initkey(ctx, 256, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb128(256), provctx);
   end;
 Exit(ctx);
end;


function aria_192_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 192, 8, 128));
end;


function aria_192_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 192, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb128(192), provctx);
   end;
 Exit(ctx);
end;


function aria_128_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function aria_128_cfb_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
 if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin
     ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb128(128), provctx);
 end;
 Exit(ctx);
end;


function aria_256_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 256, 8, 128));
end;


function aria_256_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
 if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 256, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb1(256), provctx);
 end;
 Exit(ctx);
end;


function aria_192_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 192, 8, 128));
end;


function aria_192_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 192, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb1(192), provctx);
 end;
 Exit(ctx);
end;


function aria_128_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function aria_128_cfb1_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb1(128), provctx);
 end;
 Exit(ctx);
end;


function aria_256_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 256, 8, 128));
end;


function aria_256_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 256, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb8(256), provctx);
 end;
 Exit(ctx);
end;


function aria_192_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 192, 8, 128));
end;


function aria_192_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 192, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb8(192), provctx);
 end;
 Exit(ctx);
end;


function aria_128_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, 0, 128, 8, 128));
end;


function aria_128_cfb8_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin   ossl_cipher_generic_initkey(ctx, 128, 8, 128, $3, 0, ossl_prov_cipher_hw_aria_cfb8(128), provctx);
 end;
 Exit(ctx);
end;


function aria_256_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 256, 8, 128));
end;


function aria_256_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 256, 8, 128, $5, 0, ossl_prov_cipher_hw_aria_ctr(256), provctx);
 end;
 Exit(ctx);
end;


function aria_192_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 192, 8, 128));
end;


function aria_192_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 192, 8, 128, $5, 0, ossl_prov_cipher_hw_aria_ctr(192), provctx);
 end;
 Exit(ctx);
end;


function aria_128_ctr_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $5, 0, 128, 8, 128));
end;


function aria_128_ctr_newctx( provctx : Pointer):Pointer;
var
  ctx : PPROV_ARIA_CTX;
begin
   if ossl_prov_is_running then
      ctx :=  CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := nil;

   if ctx <> nil then
   begin  ossl_cipher_generic_initkey(ctx, 128, 8, 128, $5, 0, ossl_prov_cipher_hw_aria_ctr(128), provctx);
 end;
 Exit(ctx);
end;

procedure aria_freectx( vctx : Pointer);
var
  ctx : PPROV_ARIA_CTX;
begin
    ctx := PPROV_ARIA_CTX(vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX (vctx));
    OPENSSL_clear_free(Pointer(ctx),  sizeof(ctx^));
end;


function aria_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PPROV_ARIA_CTX;
begin
    _in := PPROV_ARIA_CTX(ctx);
    if not ossl_prov_is_running then Exit(nil);
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    _in.base.hw.copyctx(@ret.base, @_in.base);
    Result := ret;
end;



end.
