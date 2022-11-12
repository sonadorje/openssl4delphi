unit OpenSSL3.providers.implementations.ciphers.cipher_tdes_default;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.cipher_tdes_common,
     OpenSSL3.providers.implementations.ciphers.ciphercommon;


  function tdes_ede3_ofb_newctx( provctx : Pointer):Pointer;
  function tdes_ede3_ofb_get_params( params : POSSL_PARAM):integer;
  function tdes_ede3_cfb_newctx( provctx : Pointer):Pointer;
  function tdes_ede3_cfb_get_params( params : POSSL_PARAM):integer;
  function tdes_ede3_cfb1_newctx( provctx : Pointer):Pointer;
  function tdes_ede3_cfb1_get_params( params : POSSL_PARAM):integer;
  function tdes_ede3_cfb8_newctx( provctx : Pointer):Pointer;
  function tdes_ede3_cfb8_get_params( params : POSSL_PARAM):integer;
  function tdes_ede2_ecb_newctx( provctx : Pointer):Pointer;
  function tdes_ede2_ecb_get_params( params : POSSL_PARAM):integer;
  function tdes_ede2_cbc_newctx( provctx : Pointer):Pointer;
  function tdes_ede2_cbc_get_params( params : POSSL_PARAM):integer;
  function tdes_ede2_ofb_newctx( provctx : Pointer):Pointer;
  function tdes_ede2_ofb_get_params( params : POSSL_PARAM):integer;
  function tdes_ede2_cfb_newctx( provctx : Pointer):Pointer;
  function tdes_ede2_cfb_get_params( params : POSSL_PARAM):integer;

const  ossl_tdes_ede3_ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede3_ofb_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede3_ofb_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede3_cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede3_cfb_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede3_cfb_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede3_cfb1_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede3_cfb1_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede3_cfb1_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede3_cfb8_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede3_cfb8_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede3_cfb8_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede2_ecb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede2_ecb_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede2_ecb_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede2_cbc_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_block_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_block_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede2_cbc_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede2_cbc_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede2_ofb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede2_ofb_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede2_ofb_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_tdes_ede2_cfb_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ossl_tdes_dinit; data:nil)),
(function_id:  4; method:(code:@ossl_cipher_generic_stream_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  6; method:(code:@ossl_cipher_generic_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_ede2_cfb_newctx; data:nil)),
(function_id:  8; method:(code:@ossl_tdes_dupctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  9; method:(code:@tdes_ede2_cfb_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses OpenSSL3.providers.implementations.ciphers.cipher_tdes_default_hw;


function tdes_ede3_ofb_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $4, 64*3, 8, 64, $0010, ossl_prov_cipher_hw_tdes_ede3_ofb));
end;


function tdes_ede3_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, $0010, 64*3, 8, 64));
end;


function tdes_ede3_cfb_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $3, 64*3, 8, 64, $0010, ossl_prov_cipher_hw_tdes_ede3_cfb));
end;


function tdes_ede3_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, $0010, 64*3, 8, 64));
end;


function tdes_ede3_cfb1_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $3, 64*3, 8, 64, $0010, ossl_prov_cipher_hw_tdes_ede3_cfb1));
end;


function tdes_ede3_cfb1_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, $0010, 64*3, 8, 64));
end;


function tdes_ede3_cfb8_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $3, 64*3, 8, 64, $0010, ossl_prov_cipher_hw_tdes_ede3_cfb8));
end;


function tdes_ede3_cfb8_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, $0010, 64*3, 8, 64));
end;


function tdes_ede2_ecb_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $1, 64*2, 64, 0, $0010, ossl_prov_cipher_hw_tdes_ede2_ecb));
end;


function tdes_ede2_ecb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $1, $0010, 64*2, 64, 0));
end;


function tdes_ede2_cbc_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $2, 64*2, 64, 64, $0010, ossl_prov_cipher_hw_tdes_ede2_cbc));
end;


function tdes_ede2_cbc_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $2, $0010, 64*2, 64, 64));
end;


function tdes_ede2_ofb_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $4, 64*2, 8, 64, $0010, ossl_prov_cipher_hw_tdes_ede2_ofb));
end;


function tdes_ede2_ofb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $4, $0010, 64*2, 8, 64));
end;


function tdes_ede2_cfb_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $3, 64*2, 8, 64, $0010, ossl_prov_cipher_hw_tdes_ede2_cfb));
end;


function tdes_ede2_cfb_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $3, $0010, 64*2, 8, 64));
end;

end.
