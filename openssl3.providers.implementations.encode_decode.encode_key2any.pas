unit openssl3.providers.implementations.encode_decode.encode_key2any;

interface
uses OpenSSL.Api;

  function rsa_to_type_specific_keypair_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_type_specific_keypair_der_free_object( key : Pointer);
  function rsa_to_type_specific_keypair_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_type_specific_keypair_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function key2any_newctx( provctx : Pointer):Pointer;
  procedure key2any_freectx( vctx : Pointer);
  function key2any_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function key2any_check_selection( selection, selection_mask : integer):integer;
  function key2any_encode(ctx : Pkey2any_ctx_st; cout : POSSL_CORE_BIO;const key : Pointer; &type : integer;const pemname : PUTF8Char;checker : Tcheck_key_type_fn; writer : Tkey_to_der_fn; pwcb : TOSSL_PASSPHRASE_CALLBACK; pwcbarg : Pointer; key2paramstring : Tkey_to_paramstring_fn; key2der : Ti2d_of_void):integer;
  function key2any_settable_ctx_params( provctx : Pointer):POSSL_PARAM;

const ossl_rsa_to_type_specific_keypair_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_type_specific_keypair_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_type_specific_keypair_der_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_type_specific_keypair_der_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_type_specific_keypair_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

function rsa_check_key_type(const rsa : Pointer; expected_type : integer):integer;
function key_to_type_specific_der_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char;p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
function prepare_rsa_params(const rsa : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;

 function rsa_to_type_specific_keypair_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_type_specific_keypair_pem_free_object( key : Pointer);
  function rsa_to_type_specific_keypair_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_type_specific_keypair_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_rsa_to_type_specific_keypair_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_type_specific_keypair_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_type_specific_keypair_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_type_specific_keypair_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_type_specific_keypair_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

  function dh_to_type_specific_params_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_type_specific_params_der_free_object( key : Pointer);
  function dh_to_type_specific_params_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_type_specific_params_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_dh_to_type_specific_params_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@dh_to_type_specific_params_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@dh_to_type_specific_params_der_import_object; data:nil)),
 (function_id:  21; method:(code:@dh_to_type_specific_params_der_free_object; data:nil)),
 (function_id:  11; method:(code:@dh_to_type_specific_params_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function dh_to_type_specific_params_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_type_specific_params_pem_free_object( key : Pointer);
  function dh_to_type_specific_params_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_type_specific_params_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dh_to_type_specific_params_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@dh_to_type_specific_params_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@dh_to_type_specific_params_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@dh_to_type_specific_params_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@dh_to_type_specific_params_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function dhx_to_type_specific_params_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_type_specific_params_der_free_object( key : Pointer);
  function dhx_to_type_specific_params_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_type_specific_params_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dhx_to_type_specific_params_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@dhx_to_type_specific_params_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@dhx_to_type_specific_params_der_import_object; data:nil)),
 (function_id:  21; method:(code:@dhx_to_type_specific_params_der_free_object; data:nil)),
 (function_id:  11; method:(code:@dhx_to_type_specific_params_der_encode; data:nil)),
 (function_id:  0;  method:(code:nil; data:nil)) );

 function dhx_to_type_specific_params_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_type_specific_params_pem_free_object( key : Pointer);
  function dhx_to_type_specific_params_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_type_specific_params_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_dhx_to_type_specific_params_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@dhx_to_type_specific_params_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@dhx_to_type_specific_params_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@dhx_to_type_specific_params_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@dhx_to_type_specific_params_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function dsa_to_type_specific_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_type_specific_der_free_object( key : Pointer);
  function dsa_to_type_specific_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_type_specific_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_dsa_to_type_specific_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@dsa_to_type_specific_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@dsa_to_type_specific_der_import_object; data:nil)),
 (function_id:  21; method:(code:@dsa_to_type_specific_der_free_object; data:nil)),
 (function_id:  11; method:(code:@dsa_to_type_specific_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

  function dsa_to_type_specific_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_type_specific_pem_free_object( key : Pointer);
  function dsa_to_type_specific_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_type_specific_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_dsa_to_type_specific_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@dsa_to_type_specific_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@dsa_to_type_specific_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@dsa_to_type_specific_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@dsa_to_type_specific_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function ec_to_type_specific_no_pub_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_type_specific_no_pub_der_free_object( key : Pointer);
  function ec_to_type_specific_no_pub_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_type_specific_no_pub_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_ec_to_type_specific_no_pub_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@ec_to_type_specific_no_pub_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@ec_to_type_specific_no_pub_der_import_object; data:nil)),
 (function_id:  21; method:(code:@ec_to_type_specific_no_pub_der_free_object; data:nil)),
 (function_id:  11; method:(code:@ec_to_type_specific_no_pub_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function ec_to_type_specific_no_pub_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_type_specific_no_pub_pem_free_object( key : Pointer);
  function ec_to_type_specific_no_pub_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_type_specific_no_pub_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_ec_to_type_specific_no_pub_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@ec_to_type_specific_no_pub_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@ec_to_type_specific_no_pub_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@ec_to_type_specific_no_pub_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@ec_to_type_specific_no_pub_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function sm2_to_type_specific_no_pub_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_type_specific_no_pub_der_free_object( key : Pointer);
  function sm2_to_type_specific_no_pub_der_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_type_specific_no_pub_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_sm2_to_type_specific_no_pub_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@sm2_to_type_specific_no_pub_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@sm2_to_type_specific_no_pub_der_import_object; data:nil)),
 (function_id:  21; method:(code:@sm2_to_type_specific_no_pub_der_free_object; data:nil)),
 (function_id:  11; method:(code:@sm2_to_type_specific_no_pub_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function sm2_to_type_specific_no_pub_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_type_specific_no_pub_pem_free_object( key : Pointer);
  function sm2_to_type_specific_no_pub_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_type_specific_no_pub_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_sm2_to_type_specific_no_pub_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@sm2_to_type_specific_no_pub_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@sm2_to_type_specific_no_pub_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@sm2_to_type_specific_no_pub_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@sm2_to_type_specific_no_pub_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function rsa_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : pOSSL_PARAM):Pointer;
  procedure rsa_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function rsa_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : pOSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_rsa_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
 (function_id:  0;  method:(code:nil; data:nil)) );

 function rsa_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function rsa_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


 const ossl_rsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function rsa_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function rsa_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_rsa_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_PrivateKeyInfo_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_PrivateKeyInfo_der_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_PrivateKeyInfo_der_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_PrivateKeyInfo_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function rsa_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function rsa_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_rsa_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_PrivateKeyInfo_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_PrivateKeyInfo_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_PrivateKeyInfo_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_PrivateKeyInfo_pem_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function rsa_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function rsa_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_rsa_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_SubjectPublicKeyInfo_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function rsa_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function rsa_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_rsa_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsa_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
 (function_id:  0;  method:(code:nil; data:nil)) );

 function rsapss_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function rsapss_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_rsapss_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2any_newctx; data:nil)),
 (function_id:  2; method:(code:@key2any_freectx; data:nil)),
 (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
 (function_id:  21; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
 (function_id:  11; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function key_to_type_specific_pem_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char;p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
 function key_to_type_specific_pem_bio_cb(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st;cb : Tpem_password_cb; cbarg : Pointer):integer;
 function key_to_type_specific_pem_pub_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
 function dh_check_key_type(const dh : Pointer; expected_type : integer):integer;
 function dh_type_specific_params_to_der(const dh : Pointer; pder : PPByte):integer;
 function key_to_type_specific_pem_param_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
 function prepare_dsa_params(const dsa : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
 function encode_dsa_params(const dsa : Pointer; nid : integer; pstr : PPointer; pstrtype : PInteger):integer;
 function prepare_ec_params(const eckey : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
 function prepare_ec_explicit_params(const eckey : Pointer; pstr : PPointer; pstrtype : PInteger):integer;
 function key_to_epki_der_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
 function key_to_encp8(const key : Pointer; key_nid : integer; params : Pointer; params_type : integer; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):PX509_SIG;
 function key_to_p8info(const key : Pointer; key_nid : integer; params : Pointer; params_type : integer; k2d : Ti2d_of_void):PPKCS8_PRIV_KEY_INFO;
 procedure free_asn1_data( &type : integer; data : Pointer);
 function p8info_to_encp8( p8info : PPKCS8_PRIV_KEY_INFO; ctx : Pkey2any_ctx_st):PX509_SIG;
 function key_to_epki_pem_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
  function key_to_pki_der_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
  function key_to_pki_pem_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
 function key_to_spki_der_pub_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
  function key_to_pubkey(const key : Pointer; key_nid : integer; params : Pointer; params_type : integer; k2d : Ti2d_of_void):PX509_PUBKEY;
  function key_to_spki_pem_pub_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;

 function rsapss_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
 function rsapss_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
 function rsapss_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
 procedure rsapss_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);

 const ossl_rsapss_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (

  (function_id: 1; method:(code:@key2any_newctx; data:nil)),
  (function_id: 2; method:(code:@key2any_freectx; data:nil)),
  (function_id: 6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id: 5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id: 10; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id: 20; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id: 21; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id: 11; method:(code:@rsapss_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id: 0;method:(code:nil; data:nil)) );

  function rsapss_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function rsapss_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_rsapss_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH =(
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@rsapss_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@rsapss_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@rsapss_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@rsapss_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

 function rsapss_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function rsapss_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_rsapss_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@rsapss_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@rsapss_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@rsapss_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@rsapss_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function rsapss_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function rsapss_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_rsapss_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@rsapss_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@rsapss_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@rsapss_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@rsapss_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function rsapss_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function rsapss_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_rsapss_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@rsapss_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@rsapss_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@rsapss_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@rsapss_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

   function dh_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function dh_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
   function dh_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;

  const  ossl_dh_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dh_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dh_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dh_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dh_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function prepare_dh_params(const dh : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
  function dh_pki_priv_to_der(const dh : Pointer; pder : PPByte):integer;

  function dh_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function dh_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dh_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH =(
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dh_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dh_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dh_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dh_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dh_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function dh_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dh_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dh_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dh_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dh_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dh_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dh_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function dh_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dh_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dh_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dh_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dh_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dh_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dh_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function dh_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dh_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dh_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dh_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dh_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dh_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dh_spki_pub_to_der(const dh : Pointer; pder : PPByte):integer;
  function dh_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function dh_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dh_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dh_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dh_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dh_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dh_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dhx_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function dhx_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dhx_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dhx_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dhx_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dhx_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dhx_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dhx_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function dhx_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dhx_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dhx_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dhx_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dhx_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dhx_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dhx_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function dhx_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dhx_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dhx_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dhx_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dhx_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dhx_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dhx_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function dhx_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dhx_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dhx_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dhx_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dhx_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dhx_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dhx_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function dhx_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dhx_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dhx_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dhx_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dhx_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dhx_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dhx_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function dhx_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_dhx_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dhx_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dhx_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dhx_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dhx_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

   function dsa_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function dsa_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dsa_pki_priv_to_der(const dsa : Pointer; pder : PPByte):integer;

  const ossl_dsa_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dsa_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dsa_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dsa_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dsa_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dsa_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function dsa_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dsa_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dsa_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dsa_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dsa_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

   function dsa_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function dsa_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dsa_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dsa_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dsa_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dsa_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dsa_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dsa_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function dsa_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_dsa_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dsa_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dsa_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dsa_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dsa_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dsa_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function dsa_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

   const ossl_dsa_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dsa_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@dsa_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@dsa_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@dsa_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function dsa_spki_pub_to_der(const dsa : Pointer; pder : PPByte):integer;
   function dsa_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function dsa_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


  const  ossl_dsa_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@dsa_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@dsa_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@dsa_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@dsa_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

   function ec_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function ec_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_ec_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ec_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ec_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ec_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ec_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );
  function ec_pki_priv_to_der(const veckey : Pointer; pder : PPByte):integer;

  function ec_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function ec_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ec_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ec_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ec_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ec_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ec_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ec_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function ec_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_ec_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ec_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ec_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ec_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ec_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ec_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function ec_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_ec_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ec_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ec_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ec_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ec_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ec_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function ec_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ec_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ec_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ec_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ec_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ec_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );
  function ec_spki_pub_to_der(const eckey : Pointer; pder : PPByte):integer;
  function ec_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function ec_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ec_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ec_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ec_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ec_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ec_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );
  function sm2_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function sm2_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_sm2_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@sm2_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@sm2_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@sm2_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@sm2_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function sm2_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function sm2_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_sm2_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@sm2_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@sm2_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@sm2_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@sm2_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function sm2_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function sm2_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_sm2_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@sm2_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@sm2_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@sm2_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@sm2_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function sm2_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function sm2_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_sm2_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@sm2_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@sm2_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@sm2_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@sm2_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

   function sm2_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function sm2_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_sm2_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@sm2_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@sm2_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@sm2_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@sm2_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function sm2_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function sm2_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_sm2_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@sm2_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@sm2_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@sm2_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@sm2_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ed25519_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed25519_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function ed25519_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ed25519_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_ed25519_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );
  function ecx_pki_priv_to_der(const vecxkey : Pointer; pder : PPByte):integer;

  function ed25519_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed25519_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function ed25519_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ed25519_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_ed25519_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ed25519_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0;method:(code:nil; data:nil)) );

  function ed25519_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed25519_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function ed25519_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ed25519_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_ed25519_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed25519_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed25519_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ed25519_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ed25519_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ed25519_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed25519_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function ed25519_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ed25519_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed25519_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed25519_to_PrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed25519_to_PrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ed25519_to_PrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ed25519_to_PrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );


  function ed25519_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed25519_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function ed25519_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ed25519_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed25519_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed25519_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed25519_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ed25519_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ed25519_to_SubjectPublicKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ecx_spki_pub_to_der(const vecxkey : Pointer; pder : PPByte):integer;
  function ed25519_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed25519_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function ed25519_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ed25519_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed25519_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed25519_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed25519_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ed25519_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ed25519_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ed448_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed448_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function ed448_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ed448_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed448_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed448_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed448_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ed448_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ed448_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ed448_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed448_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function ed448_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ed448_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed448_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed448_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed448_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
  (function_id:  21; method:(code:@ed448_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
  (function_id:  11; method:(code:@ed448_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ed448_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed448_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function ed448_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ed448_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed448_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@key2any_newctx; data:nil)),
  (function_id:  2; method:(code:@key2any_freectx; data:nil)),
  (function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
  (function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
  (function_id:  10; method:(code:@ed448_to_PrivateKeyInfo_der_does_selection; data:nil)),
  (function_id:  20; method:(code:@ed448_to_PrivateKeyInfo_der_import_object; data:nil)),
  (function_id:  21; method:(code:@ed448_to_PrivateKeyInfo_der_free_object; data:nil)),
  (function_id:  11; method:(code:@ed448_to_PrivateKeyInfo_der_encode; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function ed448_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed448_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function ed448_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ed448_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const  ossl_ed448_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ed448_to_PrivateKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@ed448_to_PrivateKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@ed448_to_PrivateKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@ed448_to_PrivateKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 function ed448_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed448_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function ed448_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ed448_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_ed448_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ed448_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@ed448_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@ed448_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@ed448_to_SubjectPublicKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 function ed448_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed448_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function ed448_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ed448_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_ed448_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ed448_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@ed448_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@ed448_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@ed448_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x25519_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x25519_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function x25519_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function x25519_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


const ossl_x25519_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x25519_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@x25519_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@x25519_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@x25519_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x25519_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x25519_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function x25519_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function x25519_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_x25519_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x25519_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@x25519_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@x25519_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@x25519_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)));

function x25519_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x25519_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function x25519_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function x25519_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_x25519_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x25519_to_PrivateKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@x25519_to_PrivateKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@x25519_to_PrivateKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@x25519_to_PrivateKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x25519_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x25519_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function x25519_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function x25519_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_x25519_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x25519_to_PrivateKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@x25519_to_PrivateKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@x25519_to_PrivateKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@x25519_to_PrivateKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

 function x25519_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x25519_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function x25519_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function x25519_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_x25519_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x25519_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@x25519_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@x25519_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@x25519_to_SubjectPublicKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

function x25519_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x25519_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function x25519_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function x25519_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_x25519_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x25519_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@x25519_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@x25519_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@x25519_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x448_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x448_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
  function x448_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function x448_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_x448_to_EncryptedPrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x448_to_EncryptedPrivateKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@x448_to_EncryptedPrivateKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@x448_to_EncryptedPrivateKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@x448_to_EncryptedPrivateKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x448_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x448_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
  function x448_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function x448_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


const ossl_x448_to_EncryptedPrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x448_to_EncryptedPrivateKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@x448_to_EncryptedPrivateKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@x448_to_EncryptedPrivateKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@x448_to_EncryptedPrivateKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 function x448_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x448_to_PrivateKeyInfo_der_free_object( key : Pointer);
  function x448_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function x448_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_x448_to_PrivateKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x448_to_PrivateKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@x448_to_PrivateKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@x448_to_PrivateKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@x448_to_PrivateKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x448_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x448_to_PrivateKeyInfo_pem_free_object( key : Pointer);
  function x448_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function x448_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_x448_to_PrivateKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x448_to_PrivateKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@x448_to_PrivateKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@x448_to_PrivateKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@x448_to_PrivateKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x448_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x448_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
  function x448_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
  function x448_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


const  ossl_x448_to_SubjectPublicKeyInfo_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x448_to_SubjectPublicKeyInfo_der_does_selection; data:nil)),
(function_id:  20; method:(code:@x448_to_SubjectPublicKeyInfo_der_import_object; data:nil)),
(function_id:  21; method:(code:@x448_to_SubjectPublicKeyInfo_der_free_object; data:nil)),
(function_id:  11; method:(code:@x448_to_SubjectPublicKeyInfo_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function x448_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x448_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
  function x448_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function x448_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_x448_to_SubjectPublicKeyInfo_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@x448_to_SubjectPublicKeyInfo_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@x448_to_SubjectPublicKeyInfo_pem_import_object; data:nil)),
(function_id:  21; method:(code:@x448_to_SubjectPublicKeyInfo_pem_free_object; data:nil)),
(function_id:  11; method:(code:@x448_to_SubjectPublicKeyInfo_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function rsa_to_RSA_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_RSA_der_free_object( key : Pointer);
  function rsa_to_RSA_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_RSA_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_rsa_to_RSA_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@rsa_to_RSA_der_does_selection; data:nil)),
(function_id:  20; method:(code:@rsa_to_RSA_der_import_object; data:nil)),
(function_id:  21; method:(code:@rsa_to_RSA_der_free_object; data:nil)),
(function_id:  11; method:(code:@rsa_to_RSA_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function rsa_to_RSA_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_RSA_pem_free_object( key : Pointer);
  function rsa_to_RSA_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_RSA_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_rsa_to_RSA_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@rsa_to_RSA_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@rsa_to_RSA_pem_import_object; data:nil)),
(function_id:  21; method:(code:@rsa_to_RSA_pem_free_object; data:nil)),
(function_id:  11; method:(code:@rsa_to_RSA_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function dh_to_DH_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_DH_der_free_object( key : Pointer);
  function dh_to_DH_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_DH_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


const  ossl_dh_to_DH_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dh_to_DH_der_does_selection; data:nil)),
(function_id:  20; method:(code:@dh_to_DH_der_import_object; data:nil)),
(function_id:  21; method:(code:@dh_to_DH_der_free_object; data:nil)),
(function_id:  11; method:(code:@dh_to_DH_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

function dh_to_DH_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_DH_pem_free_object( key : Pointer);
  function dh_to_DH_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_DH_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_dh_to_DH_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dh_to_DH_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@dh_to_DH_pem_import_object; data:nil)),
(function_id:  21; method:(code:@dh_to_DH_pem_free_object; data:nil)),
(function_id:  11; method:(code:@dh_to_DH_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function dhx_to_DHX_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_DHX_der_free_object( key : Pointer);
  function dhx_to_DHX_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_DHX_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dhx_to_DHX_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_DHX_pem_free_object( key : Pointer);
  function dhx_to_DHX_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_DHX_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


const  ossl_dhx_to_DHX_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dhx_to_DHX_der_does_selection; data:nil)),
(function_id:  20; method:(code:@dhx_to_DHX_der_import_object; data:nil)),
(function_id:  21; method:(code:@dhx_to_DHX_der_free_object; data:nil)),
(function_id:  11; method:(code:@dhx_to_DHX_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_dhx_to_DHX_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dhx_to_DHX_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@dhx_to_DHX_pem_import_object; data:nil)),
(function_id:  21; method:(code:@dhx_to_DHX_pem_free_object; data:nil)),
(function_id:  11; method:(code:@dhx_to_DHX_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );


function dsa_to_DSA_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_DSA_der_free_object( key : Pointer);
  function dsa_to_DSA_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_DSA_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dsa_to_DSA_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa_to_DSA_pem_free_object( key : Pointer);
  function dsa_to_DSA_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dsa_to_DSA_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function ec_to_EC_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_EC_der_free_object( key : Pointer);
  function ec_to_EC_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_EC_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function ec_to_EC_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_EC_pem_free_object( key : Pointer);
  function ec_to_EC_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_EC_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function sm2_to_SM2_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_SM2_der_free_object( key : Pointer);
  function sm2_to_SM2_der_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_SM2_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function sm2_to_SM2_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm2_to_SM2_pem_free_object( key : Pointer);
  function sm2_to_SM2_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function sm2_to_SM2_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;


const  ossl_dsa_to_DSA_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dsa_to_DSA_der_does_selection; data:nil)),
(function_id:  20; method:(code:@dsa_to_DSA_der_import_object; data:nil)),
(function_id:  21; method:(code:@dsa_to_DSA_der_free_object; data:nil)),
(function_id:  11; method:(code:@dsa_to_DSA_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 const  ossl_ec_to_EC_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ec_to_EC_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@ec_to_EC_pem_import_object; data:nil)),
(function_id:  21; method:(code:@ec_to_EC_pem_free_object; data:nil)),
(function_id:  11; method:(code:@ec_to_EC_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_ec_to_EC_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ec_to_EC_der_does_selection; data:nil)),
(function_id:  20; method:(code:@ec_to_EC_der_import_object; data:nil)),
(function_id:  21; method:(code:@ec_to_EC_der_free_object; data:nil)),
(function_id:  11; method:(code:@ec_to_EC_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_dsa_to_DSA_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dsa_to_DSA_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@dsa_to_DSA_pem_import_object; data:nil)),
(function_id:  21; method:(code:@dsa_to_DSA_pem_free_object; data:nil)),
(function_id:  11; method:(code:@dsa_to_DSA_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_sm2_to_SM2_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@sm2_to_SM2_der_does_selection; data:nil)),
(function_id:  20; method:(code:@sm2_to_SM2_der_import_object; data:nil)),
(function_id:  21; method:(code:@sm2_to_SM2_der_free_object; data:nil)),
(function_id:  11; method:(code:@sm2_to_SM2_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_sm2_to_SM2_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@sm2_to_SM2_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@sm2_to_SM2_pem_import_object; data:nil)),
(function_id:  21; method:(code:@sm2_to_SM2_pem_free_object; data:nil)),
(function_id:  11; method:(code:@sm2_to_SM2_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function rsa_to_PKCS1_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_PKCS1_der_free_object( key : Pointer);
  function rsa_to_PKCS1_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_PKCS1_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function rsa_to_PKCS1_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa_to_PKCS1_pem_free_object( key : Pointer);
  function rsa_to_PKCS1_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsa_to_PKCS1_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function rsapss_to_PKCS1_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_PKCS1_der_free_object( key : Pointer);
  function rsapss_to_PKCS1_der_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_PKCS1_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function rsapss_to_PKCS1_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss_to_PKCS1_pem_free_object( key : Pointer);
  function rsapss_to_PKCS1_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function rsapss_to_PKCS1_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_rsa_to_PKCS1_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@rsa_to_PKCS1_der_does_selection; data:nil)),
(function_id:  20; method:(code:@rsa_to_PKCS1_der_import_object; data:nil)),
(function_id:  21; method:(code:@rsa_to_PKCS1_der_free_object; data:nil)),
(function_id:  11; method:(code:@rsa_to_PKCS1_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_rsapss_to_PKCS1_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@rsapss_to_PKCS1_der_does_selection; data:nil)),
(function_id:  20; method:(code:@rsapss_to_PKCS1_der_import_object; data:nil)),
(function_id:  21; method:(code:@rsapss_to_PKCS1_der_free_object; data:nil)),
(function_id:  11; method:(code:@rsapss_to_PKCS1_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_rsa_to_PKCS1_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@rsa_to_PKCS1_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@rsa_to_PKCS1_pem_import_object; data:nil)),
(function_id:  21; method:(code:@rsa_to_PKCS1_pem_free_object; data:nil)),
(function_id:  11; method:(code:@rsa_to_PKCS1_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_rsapss_to_PKCS1_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@rsapss_to_PKCS1_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@rsapss_to_PKCS1_pem_import_object; data:nil)),
(function_id:  21; method:(code:@rsapss_to_PKCS1_pem_free_object; data:nil)),
(function_id:  11; method:(code:@rsapss_to_PKCS1_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function dh_to_PKCS3_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_PKCS3_der_free_object( key : Pointer);
  function dh_to_PKCS3_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_PKCS3_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dh_to_PKCS3_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh_to_PKCS3_pem_free_object( key : Pointer);
  function dh_to_PKCS3_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dh_to_PKCS3_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dhx_to_X9_42_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_X9_42_der_free_object( key : Pointer);
  function dhx_to_X9_42_der_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_X9_42_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dhx_to_X9_42_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx_to_X9_42_pem_free_object( key : Pointer);
  function dhx_to_X9_42_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function dhx_to_X9_42_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function ec_to_X9_62_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_X9_62_der_free_object( key : Pointer);
  function ec_to_X9_62_der_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_X9_62_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function ec_to_X9_62_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec_to_X9_62_pem_free_object( key : Pointer);
  function ec_to_X9_62_pem_does_selection( ctx : Pointer; selection : integer):integer;
  function ec_to_X9_62_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;



const  ossl_dh_to_PKCS3_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dh_to_PKCS3_der_does_selection; data:nil)),
(function_id:  20; method:(code:@dh_to_PKCS3_der_import_object; data:nil)),
(function_id:  21; method:(code:@dh_to_PKCS3_der_free_object; data:nil)),
(function_id:  11; method:(code:@dh_to_PKCS3_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_dh_to_PKCS3_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dh_to_PKCS3_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@dh_to_PKCS3_pem_import_object; data:nil)),
(function_id:  21; method:(code:@dh_to_PKCS3_pem_free_object; data:nil)),
(function_id:  11; method:(code:@dh_to_PKCS3_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_dhx_to_X9_42_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dhx_to_X9_42_der_does_selection; data:nil)),
(function_id:  20; method:(code:@dhx_to_X9_42_der_import_object; data:nil)),
(function_id:  21; method:(code:@dhx_to_X9_42_der_free_object; data:nil)),
(function_id:  11; method:(code:@dhx_to_X9_42_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_dhx_to_X9_42_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@dhx_to_X9_42_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@dhx_to_X9_42_pem_import_object; data:nil)),
(function_id:  21; method:(code:@dhx_to_X9_42_pem_free_object; data:nil)),
(function_id:  11; method:(code:@dhx_to_X9_42_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_ec_to_X9_62_der_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ec_to_X9_62_der_does_selection; data:nil)),
(function_id:  20; method:(code:@ec_to_X9_62_der_import_object; data:nil)),
(function_id:  21; method:(code:@ec_to_X9_62_der_free_object; data:nil)),
(function_id:  11; method:(code:@ec_to_X9_62_der_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_ec_to_X9_62_pem_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@key2any_newctx; data:nil)),
(function_id:  2; method:(code:@key2any_freectx; data:nil)),
(function_id:  6; method:(code:@key2any_settable_ctx_params; data:nil)),
(function_id:  5; method:(code:@key2any_set_ctx_params; data:nil)),
(function_id:  10; method:(code:@ec_to_X9_62_pem_does_selection; data:nil)),
(function_id:  20; method:(code:@ec_to_X9_62_pem_import_object; data:nil)),
(function_id:  21; method:(code:@ec_to_X9_62_pem_free_object; data:nil)),
(function_id:  11; method:(code:@ec_to_X9_62_pem_encode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const
  key_to_type_specific_der_priv_bio: function (&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char;p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer = key_to_type_specific_der_bio;
  key_to_type_specific_der_pub_bio : function (&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char;p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer =  key_to_type_specific_der_bio;
  key_to_type_specific_der_param_bio: function (&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char;p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer =  key_to_type_specific_der_bio ;
var // 1d arrays
  settables : array[0..2] of TOSSL_PARAM;

implementation

uses openssl3.crypto.mem, openssl3.crypto.passphrase,
     openssl3.crypto.evp.evp_enc,  openssl3.crypto.ec.ec_key,
     openssl3.providers.common.provider_ctx, openssl3.crypto.params,
     OpenSSL3.Err, openssl3.crypto.bio.bio_prov,
     openssl3.providers.implementations.encode_decode.endecoder_common,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     openssl3.crypto.bio.bio_print, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.rsa.rsa_pss,   openssl3.crypto.packet,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ecx_kmgmt,
     OpenSSL3.providers.common.der.der_rsa_key,
     openssl3.crypto.dsa.dsa_asn1, openssl3.crypto.ec.ec_asn1,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.x509.x_all,
     openssl3.openssl.params,          OpenSSL3.crypto.rsa.rsa_asn1,
     openssl3.crypto.ec.ec_curve,      openssl3.crypto.ec.ec_lib,
     openssl3.crypto.asn1.a_object,    openssl3.crypto.dsa.dsa_lib,
     openssl3.crypto.x509.x_pubkey, openssl3.crypto.pem.pem_all,
     openssl3.crypto.pem.pem_lib,   openssl3.crypto.pem.pem_pk8,
     openssl3.crypto.asn1.p8_pkey,  openssl3.crypto.asn1.x_sig,
     openssl3.crypto.dh.dh_lib,     openssl3.crypto.dh.dh_asn1,
     openssl3.crypto.bio.bio_lib,   openssl3.crypto.asn1.a_int,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.o_str,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.pkcs12.p12_p8e;



function dh_to_PKCS3_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_PKCS3_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_PKCS3_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dh_to_PKCS3_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function dh_to_PKCS3_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_PKCS3_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_PKCS3_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dh_to_PKCS3_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function dhx_to_X9_42_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_X9_42_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_X9_42_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dhx_to_X9_42_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function dhx_to_X9_42_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_X9_42_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_X9_42_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dhx_to_X9_42_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function ec_to_X9_62_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_X9_62_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_X9_62_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function ec_to_X9_62_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg, prepare_ec_params, {Ti2d_of_void }i2d_ECPrivateKey));
 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_ECParameters));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function ec_to_X9_62_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_X9_62_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_X9_62_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function ec_to_X9_62_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_ec_params, {Ti2d_of_void }i2d_ECPrivateKey));
 if selection and ( $04 or $80  ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_ECParameters));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function rsa_to_PKCS1_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_PKCS1_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_PKCS1_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsa_to_PKCS1_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type, key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
 if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type, key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function rsa_to_PKCS1_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_PKCS1_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_PKCS1_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsa_to_PKCS1_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type, key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
 if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type, key_to_type_specific_pem_pub_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function rsapss_to_PKCS1_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_PKCS1_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_PKCS1_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsapss_to_PKCS1_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PRIVATE KEY', rsa_check_key_type, key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
 if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PUBLIC KEY', rsa_check_key_type, key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function rsapss_to_PKCS1_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_PKCS1_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_PKCS1_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsapss_to_PKCS1_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PRIVATE KEY', rsa_check_key_type, key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
 if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PUBLIC KEY', rsa_check_key_type, key_to_type_specific_pem_pub_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;

function dsa_to_DSA_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_DSA_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_DSA_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( ( $01 or $02 ) or ( $04 or $80) )));
end;


function dsa_to_DSA_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
 if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg, prepare_dsa_params, {Ti2d_of_void }i2d_DSAPrivateKey));
   if selection and $02 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PUBLIC KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg, prepare_dsa_params, {Ti2d_of_void }i2d_DSAPublicKey));
   if selection and ( $04 or $80 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_DSAparams));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function dsa_to_DSA_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_DSA_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_DSA_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( ( $01 or $02 ) or ( $04 or $80) )));
end;


function dsa_to_DSA_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_dsa_params, {Ti2d_of_void }i2d_DSAPrivateKey));
   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PUBLIC KEY', Pointer(0) , key_to_type_specific_pem_pub_bio, cb, cbarg, prepare_dsa_params, {Ti2d_of_void }i2d_DSAPublicKey));
   if selection and ( $04 or $80 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_DSAparams));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function ec_to_EC_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_EC_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_EC_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function ec_to_EC_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg, prepare_ec_params, {Ti2d_of_void }i2d_ECPrivateKey));
 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_ECParameters));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function ec_to_EC_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_EC_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_EC_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function ec_to_EC_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_ec_params, {Ti2d_of_void }i2d_ECPrivateKey));
 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_ECParameters));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function sm2_to_SM2_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_SM2_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_SM2_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function sm2_to_SM2_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg, prepare_ec_params, {Ti2d_of_void }i2d_ECPrivateKey));
 if selection and ( $04 or $80 ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_ECParameters));

  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function sm2_to_SM2_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_SM2_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_SM2_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function sm2_to_SM2_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_ec_params, {Ti2d_of_void }i2d_ECPrivateKey));
 if selection and ( $04 or $80) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , {Ti2d_of_void }i2d_ECParameters));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function dhx_to_DHX_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_DHX_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_DHX_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dhx_to_DHX_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


   if selection and ( $04 or $80 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function dhx_to_DHX_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_DHX_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_DHX_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dhx_to_DHX_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


   if selection and ( $04 or $80 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function dh_to_DH_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_DH_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_DH_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dh_to_DH_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


  if selection and ( $04 or $80 ) <> 0 then
     Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function dh_to_DH_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_DH_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_DH_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dh_to_DH_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


  if selection and ( $04 or $80 ) <> 0 then
     Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function rsa_to_RSA_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_RSA_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_RSA_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsa_to_RSA_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type, key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type, key_to_type_specific_pem_pub_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function rsa_to_RSA_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_RSA_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_RSA_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsa_to_RSA_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
 if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


 if selection and $01 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type, key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
 if selection and $02 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type, key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function x448_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x448_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x448_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function x448_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1035, 'X448'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function x448_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x448_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x448_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function x448_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1035, 'X448'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;





function x448_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x448_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x448_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x448_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1035, 'X448'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function x448_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x448_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x448_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x448_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1035, 'X448'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function x448_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x448_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x448_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x448_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1035, 'X448'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function x448_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x448_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x448_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x448_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1035, 'X448'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function x25519_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x25519_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x25519_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function x25519_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1034, 'X25519'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function x25519_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x25519_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x25519_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function x25519_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1034, 'X25519'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function x25519_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x25519_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x25519_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x25519_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1034, 'X25519'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function x25519_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x25519_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x25519_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x25519_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1034, 'X25519'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function x25519_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x25519_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x25519_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x25519_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1034, 'X25519'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function x25519_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure x25519_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x25519_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function x25519_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1034, 'X25519'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed448_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed448_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed448_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function ed448_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1088, 'ED448'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function ed448_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed448_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed448_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function ed448_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1088, 'ED448'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed448_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed448_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed448_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed448_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1088, 'ED448'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;


function ed448_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed448_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed448_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed448_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1088, 'ED448'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;



function ed448_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed448_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed448_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed448_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1088, 'ED448'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed448_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed448_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed448_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed448_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

  if selection and $01 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1088, 'ED448'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed25519_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed25519_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed25519_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function ed25519_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1087, 'ED25519'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed25519_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed25519_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed25519_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function ecx_spki_pub_to_der(const vecxkey : Pointer; pder : PPByte):integer;
var
  ecxkey : PECX_KEY;
  keyblob : PByte;
begin
     ecxkey := vecxkey;
    if ecxkey = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    keyblob := OPENSSL_memdup(@ecxkey.pubkey, ecxkey.keylen);
    if keyblob = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    pder^ := keyblob;
    Result := ecxkey.keylen;
end;

function ed25519_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

  if selection and $02  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1087, 'ED25519'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, Pointer(0) , ecx_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed25519_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed25519_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed25519_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed25519_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


  if selection and $01 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1087, 'ED25519'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed25519_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed25519_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed25519_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed25519_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1087, 'ED25519'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0)
end;




function ed25519_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed25519_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed25519_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ed25519_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;


  if selection and $01  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1087, 'ED25519'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
     ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function ed25519_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ed25519_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed25519_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;





function ecx_pki_priv_to_der(const vecxkey : Pointer; pder : PPByte):integer;
var
    ecxkey     : PECX_KEY;
    oct        : TASN1_OCTET_STRING;
    keybloblen : integer;
begin
     ecxkey := vecxkey;
    if (ecxkey = nil)  or  (ecxkey.privkey = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    oct.data := ecxkey.privkey;
    oct.length := ecxkey.keylen;
    oct.flags := 0;
    keybloblen := i2d_ASN1_OCTET_STRING(@oct, pder);
    if keybloblen < 0 then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := keybloblen;
end;

function ed25519_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 1087, 'ED25519'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, Pointer(0) , ecx_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function sm2_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function sm2_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

  if selection and $02  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, prepare_ec_params, ec_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function sm2_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function sm2_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $02 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, prepare_ec_params, ec_spki_pub_to_der));
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function sm2_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function sm2_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;
function sm2_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function sm2_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function sm2_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function sm2_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;

function sm2_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function sm2_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $01  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function ec_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function ec_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $02  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, prepare_ec_params, ec_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;





function ec_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function ec_spki_pub_to_der(const eckey : Pointer; pder : PPByte):integer;
begin
    if EC_KEY_get0_public_key(eckey) = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        Exit(0);
    end;
    Result := i2o_ECPublicKey(eckey, pder);
end;

function ec_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $02 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, prepare_ec_params, ec_spki_pub_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function ec_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ec_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function ec_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ec_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function ec_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function ec_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $01  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function ec_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;



function ec_pki_priv_to_der(const veckey : Pointer; pder : PPByte):integer;
var
    eckey     : PEC_KEY;
    old_flags : uint32;
    ret       : integer;
begin
    eckey := PEC_KEY (veckey);
    ret := 0;
    {
     * For PKCS8 the curve name appears in the PKCS8_PRIV_KEY_INFO object
     * as the pkeyalg.parameter field. (For a named curve this is an OID)
     * The pkey field is an octet string that holds the encoded
     * ECPrivateKey SEQUENCE with the optional parameters field omitted.
     * We omit this by setting the EC_PKEY_NO_PARAMETERS flag.
     }
    old_flags := EC_KEY_get_enc_flags(eckey); { save old flags }
    EC_KEY_set_enc_flags(eckey, old_flags or EC_PKEY_NO_PARAMETERS);
    ret := i2d_ECPrivateKey(eckey, pder);
    EC_KEY_set_enc_flags(eckey, old_flags); { restore old flags }
    Exit(ret); { return the length of the der encoded data }
end;

function ec_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
 if selection and $01 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, prepare_ec_params, ec_pki_priv_to_der));
 ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function dsa_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function dsa_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $02  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_pem_pub_bio, cb, cbarg, prepare_dsa_params, dsa_spki_pub_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dsa_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
   Exit(key2any_check_selection(selection, $02));
end;


function dsa_spki_pub_to_der(const dsa : Pointer; pder : PPByte):integer;
var
  bn : PBIGNUM;
  pub_key : PASN1_INTEGER;
  ret : integer;
begin
    bn := nil;
    pub_key := nil;
    bn := DSA_get0_pub_key(dsa);
    if bn = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        Exit(0);
    end;
    pub_key := BN_to_ASN1_INTEGER(bn, nil);
    if pub_key = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        Exit(0);
    end;
    ret := i2d_ASN1_INTEGER(pub_key, pder);
    ASN1_STRING_clear_free(pub_key);
    Result := ret;
end;

function dsa_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $02 <> 0 then
     Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PUBLIC KEY', Pointer(0) , key_to_spki_der_pub_bio, cb, cbarg, prepare_dsa_params, dsa_spki_pub_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function dsa_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dsa_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_pem_priv_bio, cb, cbarg, prepare_dsa_params, dsa_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function dsa_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
   ctx := vctx;
   Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dsa_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_pki_der_priv_bio, cb, cbarg, prepare_dsa_params, dsa_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function dsa_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dsa_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_pem_priv_bio, cb, cbarg, prepare_dsa_params, dsa_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dsa_pki_priv_to_der(const dsa : Pointer; pder : PPByte):integer;
var
    bn       : PBIGNUM;
    priv_key : PASN1_INTEGER;
    ret      : integer;
begin
    bn := nil;
    priv_key := nil;
    bn := DSA_get0_priv_key(dsa);
    if bn = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        Exit(0);
    end;
    priv_key := BN_to_ASN1_INTEGER(bn, nil);
    if priv_key = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        Exit(0);
    end;
    ret := i2d_ASN1_INTEGER(priv_key, pder);
    ASN1_STRING_clear_free(priv_key);
    Result := ret;
end;




function dsa_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
   ctx := vctx;
   Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
   Exit(key2any_check_selection(selection, $01));
end;


function dsa_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;
  if selection and $01  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_epki_der_priv_bio, cb, cbarg, prepare_dsa_params, dsa_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dhx_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function dhx_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
 if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PUBLIC KEY', dh_check_key_type, key_to_spki_pem_pub_bio, cb, cbarg, prepare_dh_params, dh_spki_pub_to_der));
 ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dhx_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function dhx_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $02 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PUBLIC KEY', dh_check_key_type, key_to_spki_der_pub_bio, cb, cbarg, prepare_dh_params, dh_spki_pub_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dhx_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dhx_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_pki_pem_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dhx_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dhx_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
 if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_pki_der_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
 ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dhx_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dhx_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_epki_pem_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dhx_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dhx_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_epki_der_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function dh_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function dh_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
 if selection and $02 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PUBLIC KEY', dh_check_key_type, key_to_spki_pem_pub_bio, cb, cbarg, prepare_dh_params, dh_spki_pub_to_der));
 ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dh_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function dh_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;

  if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PUBLIC KEY', dh_check_key_type, key_to_spki_der_pub_bio, cb, cbarg, prepare_dh_params, dh_spki_pub_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dh_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
   ctx := vctx;
   Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dh_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $01  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_pki_pem_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dh_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dh_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $01  <> 0 then
     Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_pki_der_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dh_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function dh_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if selection and $01 <> 0 then
    Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_epki_pem_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;





function dh_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;



function dh_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;

  if ((selection and $01) <> 0) then
     Exit(key2any_encode(ctx, cout, key, 28, 'DH'+ ' PRIVATE KEY', dh_check_key_type, key_to_epki_der_priv_bio, cb, cbarg, prepare_dh_params, dh_pki_priv_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;





function rsapss_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function rsapss_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;

  if selection and $02  <> 0 then
    Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PUBLIC KEY', rsa_check_key_type, key_to_spki_pem_pub_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function rsapss_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function rsapss_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
  end;
  if ((selection and $02) <> 0) then
     Exit( key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PUBLIC KEY', rsa_check_key_type, key_to_spki_der_pub_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPublicKey));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function rsapss_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsapss_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if selection and $01  <> 0 then
       Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PRIVATE KEY', rsa_check_key_type, key_to_pki_pem_priv_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function rsapss_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsapss_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if selection and $01 <> 0 then
      Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PRIVATE KEY', rsa_check_key_type, key_to_pki_der_priv_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;

procedure rsapss_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;




function rsapss_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> Pointer(0) then
   begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
   end;

   if selection and $01  <> 0 then
      Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PRIVATE KEY', rsa_check_key_type, key_to_epki_pem_priv_bio, cb, cbarg, prepare_rsa_params, {Ti2d_of_void }i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function rsapss_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;



function rsapss_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsapss_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
   ctx := vctx;
   Exit(ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsapss_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;


function rsapss_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsapss_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
  if ((selection and $01) <> 0)  then
    Exit(key2any_encode(ctx, cout, key, 912, 'RSA-PSS'+ ' PRIVATE KEY', rsa_check_key_type, key_to_epki_der_priv_bio, cb, cbarg,
               prepare_rsa_params, i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function dh_pki_priv_to_der(const dh : Pointer; pder : PPByte):integer;
var
    bn       : PBIGNUM;
    priv_key : PASN1_INTEGER;
    ret      : integer;
begin
    bn := nil;
    priv_key := nil;
    bn := DH_get0_priv_key(dh);
    if bn = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        Exit(0);
    end;
    priv_key := BN_to_ASN1_INTEGER(bn, nil);
    if priv_key  = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        Exit(0);
    end;
    ret := i2d_ASN1_INTEGER(priv_key, pder);
    ASN1_STRING_clear_free(priv_key);
    Result := ret;
end;


function dh_spki_pub_to_der(const dh : Pointer; pder : PPByte):integer;
var
  bn : PBIGNUM;
  pub_key : PASN1_INTEGER;
  ret : integer;
begin
   bn := nil;
    pub_key := nil;
    bn := DH_get0_pub_key(dh);
    if bn = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        Exit(0);
    end;
    pub_key := BN_to_ASN1_INTEGER(bn, nil);
    if pub_key = nil then  begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        Exit(0);
    end;
    ret := i2d_ASN1_INTEGER(pub_key, pder);
    ASN1_STRING_clear_free(pub_key);
    Result := ret;
end;

function prepare_dh_params(const dh : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
var
  params : PASN1_STRING;
begin
    params := ASN1_STRING_new;
    if params = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if nid = EVP_PKEY_DHX then
       params.length := i2d_DHxparams(dh, @params.data)
    else
        params.length := i2d_DHparams(dh, @params.data);
    if params.length <= 0 then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        Exit(0);
    end;
    params.&type := V_ASN1_SEQUENCE;
    pstr^ := params;
    pstrtype^ := V_ASN1_SEQUENCE;
    Result := 1;
end;

function key_to_spki_pem_pub_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  ret : integer;
  str : Pointer;
  strtype : integer;
  xpk : PX509_PUBKEY;
begin
    ret := 0;
    str := nil;
    strtype := V_ASN1_UNDEF;
    xpk := nil;
    if (Assigned(p2s))  and  (0>= p2s(key, key_nid, ctx.save_parameters,
                            @str, @strtype)) then
        Exit(0);
    xpk := key_to_pubkey(key, key_nid, str, strtype, k2d);
    if xpk <> nil then
       ret := PEM_write_bio_X509_PUBKEY(&out, xpk)
    else
        free_asn1_data(strtype, str);
    { Also frees |str| }
    X509_PUBKEY_free(xpk);
    Result := ret;
end;

function rsa_to_SubjectPublicKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
  ctx := vctx;
  Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_SubjectPublicKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_SubjectPublicKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function rsa_to_SubjectPublicKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if ((selection and $02) <> 0) then
      Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type, key_to_spki_pem_pub_bio,
          cb, cbarg, prepare_rsa_params, i2d_RSAPublicKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function key_to_pubkey(const key : Pointer; key_nid : integer; params : Pointer; params_type : integer; k2d : Ti2d_of_void):PX509_PUBKEY;
var
  der : PByte;
  derlen : integer;
  xpk : PX509_PUBKEY;
begin
    { der, derlen store the key DER output and its length }
    der := nil;
    { The final PX509_PUBKEY  }
    xpk := nil;
    xpk := X509_PUBKEY_new();
    derlen := k2d(key, @der);
    if (xpk  = nil)
         or  (derlen <= 0 )
         or  (0>= X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(key_nid),
                                   params_type, params, der, derlen))  then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        xpk := nil;
    end;
    Result := xpk;
end;


function key_to_spki_der_pub_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  ret : integer;

  str : Pointer;

  strtype : integer;

  xpk : PX509_PUBKEY;
begin
    ret := 0;
    str := nil;
    strtype := V_ASN1_UNDEF;
    xpk := nil;
    if (Assigned(p2s))  and  (0>= p2s(key, key_nid, ctx.save_parameters,
                               @str, @strtype)) then
        Exit(0);
    xpk := key_to_pubkey(key, key_nid, str, strtype, k2d);
    if xpk <> nil then
       ret := i2d_X509_PUBKEY_bio(&out, xpk);
    { Also frees |str| }
    X509_PUBKEY_free(xpk);
    Result := ret;
end;




function rsa_to_SubjectPublicKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_SubjectPublicKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_SubjectPublicKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $02));
end;


function rsa_to_SubjectPublicKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if ((selection and $02) <> 0) then
   Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type, key_to_spki_der_pub_bio, cb, cbarg,
                prepare_rsa_params, i2d_RSAPublicKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;

function key_to_pki_pem_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  ret : integer;
  str : Pointer;
  strtype : integer;
  p8info : PPKCS8_PRIV_KEY_INFO;
begin
    ret := 0;
    str := nil;
    strtype := V_ASN1_UNDEF;
    if ctx.cipher_intent > 0 then
       Exit(key_to_epki_pem_priv_bio(out, key, key_nid, pemname,
                                        p2s, k2d, ctx));
    if (Assigned(p2s))  and  (0>= p2s(key, key_nid, ctx.save_parameters,
                            @str, @strtype)) then
        Exit(0);
    p8info := key_to_p8info(key, key_nid, str, strtype, k2d);
    if (p8info <> nil) then
       ret := PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info)
    else
        free_asn1_data(strtype, str);
    PKCS8_PRIV_KEY_INFO_free(p8info);
    Result := ret;
end;




function rsa_to_PrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_PrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_PrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsa_to_PrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if ((selection and $01) <> 0) then
      Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type, key_to_pki_pem_priv_bio,
                cb, cbarg, prepare_rsa_params, i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;

function key_to_pki_der_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  ret : integer;

  str : Pointer;

  strtype : integer;

  p8info : PPKCS8_PRIV_KEY_INFO;
begin
    ret := 0;
    str := nil;
    strtype := V_ASN1_UNDEF;
    if ctx.cipher_intent>0 then
       Exit(key_to_epki_der_priv_bio(&out, key, key_nid, pemname,
                                        p2s, k2d, ctx));
    if (Assigned(p2s))  and  (0>= p2s(key, key_nid, ctx.save_parameters,
                            @str, @strtype ))then
        Exit(0);
    p8info := key_to_p8info(key, key_nid, str, strtype, k2d);
    if p8info <> nil then
       ret := i2d_PKCS8_PRIV_KEY_INFO_bio(&out, p8info)
    else
        free_asn1_data(strtype, str);
    PKCS8_PRIV_KEY_INFO_free(p8info);
    Result := ret;
end;

function rsa_to_PrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
  ctx := vctx;
  Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_PrivateKeyInfo_der_free_object( key : Pointer);
begin
  ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_PrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
  Exit(key2any_check_selection(selection, $01));
end;


function rsa_to_PrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if (selection and $01 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type, key_to_pki_der_priv_bio, cb, cbarg,
            prepare_rsa_params, i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function key_to_epki_pem_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  ret : integer;
  str : Pointer;
  strtype : integer;
  p8 : PX509_SIG;
begin
    ret := 0;
    str := nil;
    strtype := V_ASN1_UNDEF;
    if 0>= ctx.cipher_intent then Exit(0);
    if (Assigned(p2s))  and  (0>= p2s(key, key_nid, ctx.save_parameters,
                            @str, @strtype)) then
        Exit(0);
    p8 := key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
    if p8 <> nil then
       ret := PEM_write_bio_PKCS8(out, p8);
    X509_SIG_free(p8);
    Result := ret;
end;


function rsa_to_EncryptedPrivateKeyInfo_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
  ctx := vctx;
  Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_EncryptedPrivateKeyInfo_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_EncryptedPrivateKeyInfo_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsa_to_EncryptedPrivateKeyInfo_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
  if ((selection and $01) <> 0) then
     Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type,
           key_to_epki_pem_priv_bio, cb, cbarg, prepare_rsa_params,
           i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function p8info_to_encp8( p8info : PPKCS8_PRIV_KEY_INFO; ctx : Pkey2any_ctx_st):PX509_SIG;
var
  p8 : PX509_SIG;

  kstr : array[0..(PEM_BUFSIZE)-1] of UTF8Char;

  klen : size_t;

  libctx : POSSL_LIB_CTX;
begin
    p8 := nil;
    klen := 0;
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if ctx.cipher = nil then Exit(nil);
    if 0>= ossl_pw_get_passphrase(@kstr, sizeof(kstr) , @klen, nil, 1,
                                @ctx.pwdata)  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PASSPHRASE);
        Exit(nil);
    end;
    { First argument = -1 means 'standard' }
    p8 := PKCS8_encrypt_ex(-1, ctx.cipher, kstr, klen, nil, 0, 0, p8info, libctx, nil);
    OPENSSL_cleanse(@kstr, klen);
    Result := p8;
end;



procedure free_asn1_data( &type : integer; data : Pointer);
begin
    case &type of
    V_ASN1_OBJECT:
        ASN1_OBJECT_free(data);
        //break;
    V_ASN1_SEQUENCE:
        ASN1_STRING_free(data);
        //break;
    end;
end;

function key_to_p8info(const key : Pointer; key_nid : integer; params : Pointer; params_type : integer; k2d : Ti2d_of_void):PPKCS8_PRIV_KEY_INFO;
var
  der : PByte;
  derlen : integer;
  p8info : PPKCS8_PRIV_KEY_INFO;
begin
    { der, derlen store the key DER output and its length }
    der := nil;
    { The final PKCS#8 info }
    p8info := nil;
    p8info := PKCS8_PRIV_KEY_INFO_new();
    derlen := k2d(key, @der);
    if (p8info = nil)
         or  (derlen  <= 0 )
         or  (0>= PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,
                            params_type, params, der, derlen)) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        PKCS8_PRIV_KEY_INFO_free(p8info);
        OPENSSL_free(der);
        p8info := nil;
    end;
    Result := p8info;
end;




function key_to_encp8(const key : Pointer; key_nid : integer; params : Pointer; params_type : integer; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):PX509_SIG;
var
  p8info : PPKCS8_PRIV_KEY_INFO;

  p8 : PX509_SIG;
begin
    p8info := key_to_p8info(key, key_nid, params, params_type, k2d);
    p8 := nil;
    if p8info = nil then
    begin
        free_asn1_data(params_type, params);
    end
    else
    begin
        p8 := p8info_to_encp8(p8info, ctx);
        PKCS8_PRIV_KEY_INFO_free(p8info);
    end;
    Result := p8;
end;

function key_to_epki_der_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  ret : integer;
  str : Pointer;
  strtype : integer;
  p8 : PX509_SIG;
begin
    ret := 0;
    str := nil;
    strtype := V_ASN1_UNDEF;
    if 0>= ctx.cipher_intent then
       Exit(0);
    if (Assigned(p2s))  and  (0>= p2s(key, key_nid, ctx.save_parameters,
                            @str, @strtype)) then
        Exit(0);
    p8 := key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
    if p8 <> nil then
       ret := i2d_PKCS8_bio(out, p8);
    X509_SIG_free(p8);
    Result := ret;
end;



function rsa_to_EncryptedPrivateKeyInfo_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_EncryptedPrivateKeyInfo_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_EncryptedPrivateKeyInfo_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, $01));
end;


function rsa_to_EncryptedPrivateKeyInfo_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
  if ((selection and $01) <> 0) then
     Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type,
           key_to_epki_der_priv_bio, cb, cbarg, prepare_rsa_params, i2d_RSAPrivateKey));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function sm2_to_type_specific_no_pub_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
  ctx := vctx;
  Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_type_specific_no_pub_pem_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_type_specific_no_pub_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
   Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function sm2_to_type_specific_no_pub_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if (selection and $01) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg,
            prepare_ec_params, i2d_ECPrivateKey));
   if (selection and ( $04 or $80) ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) ,
           Pointer(0) , Pointer(0) , i2d_ECParameters));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function sm2_to_type_specific_no_pub_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
    ctx := vctx;
    Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure sm2_to_type_specific_no_pub_der_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm2_to_type_specific_no_pub_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
   Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function sm2_to_type_specific_no_pub_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if (selection and $01 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg,
            prepare_ec_params, i2d_ECPrivateKey));
   if (selection and ( $04 or $80) ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 1172, 'SM2'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_der_bio, Pointer(0) ,
               Pointer(0) , Pointer(0) , i2d_ECParameters));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function ec_to_type_specific_no_pub_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
  ctx := vctx;
  Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_type_specific_no_pub_pem_free_object( key : Pointer);
begin
  ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_type_specific_no_pub_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function ec_to_type_specific_no_pub_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if (selection and $01) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg,
             prepare_ec_params, i2d_ECPrivateKey));
   if (selection and ( $04 or $80) ) <> 0 then
    Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) ,
         Pointer(0) , i2d_ECParameters));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function prepare_ec_explicit_params(const eckey : Pointer; pstr : PPointer; pstrtype : PInteger):integer;
var
  params : PASN1_STRING;
begin
    params := ASN1_STRING_new();
    if params = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    params.length := i2d_ECParameters(eckey, @params.data);
    if params.length <= 0 then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        Exit(0);
    end;
    pstrtype^ := V_ASN1_SEQUENCE;
    pstr^ := params;
    Result := 1;
end;




function prepare_ec_params(const eckey : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
var
    curve_nid : integer;
    group     : PEC_GROUP;
    params    : PASN1_OBJECT;
begin
    group := EC_KEY_get0_group(eckey);
    params := nil;
    if group = nil then
      Exit(0);
    curve_nid := EC_GROUP_get_curve_name(group);
    if curve_nid <> NID_undef then
    begin
        params := OBJ_nid2obj(curve_nid);
        if params = nil then Exit(0);
    end;
    if (curve_nid <> NID_undef)
         and  ( (EC_GROUP_get_asn1_flag(group) and OPENSSL_EC_NAMED_CURVE)>0)  then
    begin
        { The CHOICE came to namedCurve }
        if OBJ_length(params) = 0 then
        begin
            { Some curves might not have an associated OID }
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_OID);
            ASN1_OBJECT_free(params);
            Exit(0);
        end;
        pstr^ := params;
        pstrtype^ := V_ASN1_OBJECT;
        Exit(1);
    end
    else
    begin
        { The CHOICE came to ecParameters }
        Exit(prepare_ec_explicit_params(eckey, pstr, pstrtype));
    end;
end;



function ec_to_type_specific_no_pub_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure ec_to_type_specific_no_pub_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec_to_type_specific_no_pub_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or ( $04 or $80))));
end;


function ec_to_type_specific_no_pub_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if ((selection and $01) <> 0) then
      Exit( key2any_encode(ctx, cout, key, 408, 'EC'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb,
            cbarg, prepare_ec_params, i2d_ECPrivateKey));
   if (selection and ( $04 or $80) ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 408, 'EC'+ ' PARAMETERS', Pointer(0) ,
         key_to_type_specific_der_bio, Pointer(0) , Pointer(0) , Pointer(0) , i2d_ECParameters));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function dsa_to_type_specific_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_type_specific_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_type_specific_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( ( $01 or $02 ) or ( $04 or $80) )));
end;


function dsa_to_type_specific_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   if ((selection and $01) <> 0) then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_pem_priv_bio, cb, cbarg,
             prepare_dsa_params, i2d_DSAPrivateKey));
   if (selection and $02 ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PUBLIC KEY', Pointer(0) , key_to_type_specific_pem_pub_bio, cb, cbarg,
              prepare_dsa_params, i2d_DSAPublicKey));
   if (selection and ( $04 or $80) ) <> 0 then
      Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_pem_param_bio, Pointer(0) ,
           Pointer(0) , Pointer(0) , i2d_DSAparams));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;





function encode_dsa_params(const dsa : Pointer; nid : integer; pstr : PPointer; pstrtype : PInteger):integer;
var
  params : PASN1_STRING;
begin
    params := ASN1_STRING_new();
    if params = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    params.length := i2d_DSAparams(dsa, @params.data);
    if params.length <= 0 then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        Exit(0);
    end;
    pstrtype^ := V_ASN1_SEQUENCE;
    pstr^ := params;
    Result := 1;
end;



function prepare_dsa_params(const dsa : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
var
  p, q, g : PBIGNUM;
begin
     p := DSA_get0_p(dsa);
     q := DSA_get0_q(dsa);
     g := DSA_get0_g(dsa);
    if (save>0)  and  (p <> nil)  and  (q <> nil)  and  (g <> nil) then
       Exit(encode_dsa_params(dsa, nid, pstr, pstrtype));
    pstr^ := nil;
    pstrtype^ := V_ASN1_UNDEF;
    Result := 1;
end;

function dsa_to_type_specific_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dsa_to_type_specific_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa_to_type_specific_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( ( $01 or $02 ) or ( $04 or $80) )));
end;


function dsa_to_type_specific_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
  if ((selection and $01) <> 0) then
     Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PRIVATE KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg,
             prepare_dsa_params, i2d_DSAPrivateKey));
  if (selection and $02 ) <> 0 then
     Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PUBLIC KEY', Pointer(0) , key_to_type_specific_der_bio, cb, cbarg,
           prepare_dsa_params, i2d_DSAPublicKey));
  if (selection and ( $04 or $80) ) <> 0 then
     Exit(key2any_encode(ctx, cout, key, 116, 'DSA'+ ' PARAMETERS', Pointer(0) , key_to_type_specific_der_bio, Pointer(0) ,
          Pointer(0), Pointer(0) , i2d_DSAparams));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;



function dhx_to_type_specific_params_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_type_specific_params_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_type_specific_params_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dhx_to_type_specific_params_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
  if ((selection and ( $04 or $80)) <> 0) then
    Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PARAMETERS', dh_check_key_type,
                key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
  ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
  Exit(0);
end;





function dhx_to_type_specific_params_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dhx_to_type_specific_params_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx_to_type_specific_params_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dhx_to_type_specific_params_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil  then
     begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
     end;
  if ((selection and ( $04 or $80)) <> 0) then
     Exit(key2any_encode(ctx, cout, key, 920, 'X9.42 DH'+ ' PARAMETERS', dh_check_key_type, key_to_type_specific_der_bio,
                     Pointer(0), Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


{$ifndef OPENSSL_NO_KEYPARAMS}
function key_to_type_specific_pem_param_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
begin
    Exit(key_to_type_specific_pem_bio_cb(&out, key, key_nid, pemname,
                                           p2s, k2d, ctx, nil, nil));
end;
{$ENDIF}


function dh_to_type_specific_params_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_type_specific_params_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_type_specific_params_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dh_to_type_specific_params_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
     begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
     end;
   if ((selection and ( $04 or $80)) <> 0) then
      Exit( key2any_encode(ctx, cout, key, 28, 'DH'+ ' PARAMETERS', dh_check_key_type,
          key_to_type_specific_pem_param_bio, Pointer(0) , Pointer(0) , Pointer(0) , dh_type_specific_params_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;


function dh_type_specific_params_to_der(const dh : Pointer; pder : PPByte):integer;
begin
    if DH_test_flags(dh, DH_FLAG_TYPE_DHX)>0 then
        Exit(i2d_DHxparams(dh, pder));
    Result := i2d_DHparams(dh, pder);
end;




function dh_check_key_type(const dh : Pointer; expected_type : integer):integer;
var
  &type : integer;
begin
    &type := get_result( DH_test_flags(dh, DH_FLAG_TYPE_DHX) >0, EVP_PKEY_DHX , EVP_PKEY_DH);
    Result := int(&type = expected_type);

end;



function dh_to_type_specific_params_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure dh_to_type_specific_params_der_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh_to_type_specific_params_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $04 or $80)));
end;


function dh_to_type_specific_params_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
     begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
     end;
   if ((selection and ( $04 or $80)) <> 0) then
       exit( key2any_encode(ctx, cout, key, 28, 'DH'+ ' PARAMETERS', dh_check_key_type,
              key_to_type_specific_der_bio, Pointer( 0), Pointer( 0), Pointer( 0), dh_type_specific_params_to_der));
   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
   Exit(0);
end;




function key_to_type_specific_pem_pub_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
begin
    Exit(key_to_type_specific_pem_bio_cb(out, key, key_nid, pemname,
                                           p2s, k2d, ctx, nil, nil));
end;


function key_to_type_specific_pem_bio_cb(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st; cb : Tpem_password_cb; cbarg : Pointer):integer;
begin
    result := int(PEM_ASN1_write_bio(k2d, pemname, out, key, ctx.cipher,
                           nil, 0, cb, cbarg) > 0);
end;




function key_to_type_specific_pem_priv_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char; p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
begin
    Exit(key_to_type_specific_pem_bio_cb(&out, key, key_nid, pemname,
                                           p2s, k2d, ctx,
                                           ossl_pw_pem_password, @ctx.pwdata));
end;




function rsa_to_type_specific_keypair_pem_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
 ctx := vctx;
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_type_specific_keypair_pem_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_type_specific_keypair_pem_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsa_to_type_specific_keypair_pem_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil  then
     begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
     end;
   if ((selection and $01) <> 0) then
       Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type,
                          key_to_type_specific_pem_priv_bio, cb, cbarg, prepare_rsa_params, i2d_RSAPrivateKey));

   if (selection and $02 ) <> 0 then
       Exit(key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type,
                  key_to_type_specific_pem_pub_bio, cb, cbarg, prepare_rsa_params, i2d_RSAPublicKey));

   ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    Exit(0);
end;



function prepare_rsa_params(const rsa : Pointer; nid, save : integer; pstr : PPointer; pstrtype : PInteger):integer;
var
  pss : PRSA_PSS_PARAMS_30;

  astr : PASN1_STRING;

  pkt : TWPACKET;

  str : PByte;

  str_sz : size_t;

  i : integer;
  label _err;
begin
     pss := ossl_rsa_get0_pss_params_30(PRSA(rsa));
    pstr := nil;
    case (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) of
        RSA_FLAG_TYPE_RSA:
        begin
            { If plain RSA, the parameters shall be nil }
            pstrtype^ := V_ASN1_NULL;
            Exit(1);
        end;
        RSA_FLAG_TYPE_RSASSAPSS:
        begin
            if ossl_rsa_pss_params_30_is_unrestricted(pss) >0 then
            begin
                pstrtype^ := V_ASN1_UNDEF;
                Exit(1);
            end
            else
            begin
                astr := nil;
                str := nil;
                str_sz := 0;
                for i := 0 to 1 do
                begin
                    case i of
                    0:
                    begin
                        if 0>= WPACKET_init_null_der(@pkt) then
                            goto _err ;
                    end;
                    1:
                    begin
                        str := OPENSSL_malloc(str_sz);
                        if (str  = nil )
                             or  (0>= WPACKET_init_der(@pkt, str, str_sz)) then
                        begin
                            goto _err ;
                        end;
                    end;
                    end;
                    if (0>= ossl_DER_w_RSASSA_PSS_params(@pkt, -1, pss))  or
                       (0>= WPACKET_finish(@pkt))
                         or  (0>= WPACKET_get_total_written(@pkt, @str_sz))  then
                        goto _err ;
                    WPACKET_cleanup(@pkt);
                    {
                     * If no PSS parameters are going to be written, there's no
                     * point going for another iteration.
                     * This saves us from getting |str| allocated just to have it
                     * immediately de-allocated.
                     }
                    if str_sz = 0 then
                       break;
                end;
                astr := ASN1_STRING_new( );
                if astr = nil then
                    goto _err ;
                pstrtype^ := V_ASN1_SEQUENCE;
                ASN1_STRING_set0(astr, str, int(str_sz) );
                pstr^ := astr;
                Exit(1);
             _err:
                OPENSSL_free(str);
                Exit(0);
            end;
        end;
    end;
    { Currently unsupported RSA key type }
    Result := 0;
end;


function key_to_type_specific_der_bio(&out : PBIO;const key : Pointer; key_nid : integer;const pemname : PUTF8Char;p2s : Tkey_to_paramstring_fn; k2d : Ti2d_of_void; ctx : Pkey2any_ctx_st):integer;
var
  der : PByte;
  derlen, ret : integer;
begin
    der := nil;
    derlen := k2d(key, @der);
    if derlen <= 0 then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ret := BIO_write(&out, der, derlen);
    OPENSSL_free(der);
    Result := Int(ret > 0);
end;


function rsa_check_key_type(const rsa : Pointer; expected_type : integer):integer;
begin
    case (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) of
    RSA_FLAG_TYPE_RSA:
        Exit(Int(expected_type = EVP_PKEY_RSA));
    RSA_FLAG_TYPE_RSASSAPSS:
        Exit(Int(expected_type = EVP_PKEY_RSA_PSS));
    end;
    { Currently unsupported RSA key type }
    Result := EVP_PKEY_NONE;
end;



function key2any_settable_ctx_params( provctx : Pointer):POSSL_PARAM;
begin
   Result := @settables;
end;

function key2any_newctx( provctx : Pointer):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
    begin
        ctx.provctx := provctx;
        ctx.save_parameters := 1;
    end;
    Result := ctx;
end;


procedure key2any_freectx( vctx : Pointer);
var
  ctx : Pkey2any_ctx_st;
begin
    ctx := vctx;
    ossl_pw_clear_passphrase_data(@ctx.pwdata);
    EVP_CIPHER_free(ctx.cipher);
    OPENSSL_free(ctx);
end;


function key2any_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
    ctx          : Pkey2any_ctx_st;

    libctx       : POSSL_LIB_CTX;

  cipherp,
propsp,
  save_paramsp : POSSL_PARAM;

  ciphername,
  props        : PUTF8Char;
begin
    ctx := vctx;
    libctx := ossl_prov_ctx_get0_libctx(ctx.provctx);
    cipherp      := OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    propsp       := OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
    save_paramsp := OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_SAVE_PARAMETERS);
    if cipherp <> nil then
    begin
        ciphername := nil;
        props := nil;
        if 0>= OSSL_PARAM_get_utf8_string_ptr(cipherp, @ciphername) then
            Exit(0);
        if (propsp <> nil)  and  (0>= OSSL_PARAM_get_utf8_string_ptr(propsp, @props)) then
            Exit(0);
        EVP_CIPHER_free(ctx.cipher);
        ctx.cipher := nil;
        ctx.cipher_intent := Int( ciphername <> nil);
        ctx.cipher := EVP_CIPHER_fetch(libctx, ciphername, props) ;
        if (ciphername <> nil)
             and  ((ctx.cipher = nil))  then
            Exit(0);
    end;
    if save_paramsp <> nil then
    begin
        if 0>= OSSL_PARAM_get_int(save_paramsp, @ctx.save_parameters) then
            Exit(0);
    end;
    Result := 1;
end;


function key2any_check_selection( selection, selection_mask : integer):integer;
var
  checks : array of integer;

  i : size_t;

  check1, check2 : integer;
begin
    {
     * The selections are kinda sorta 'levels', i.e. each selection given
     * here is assumed to include those following.
     }
    checks := [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    ];

    { The decoder implementations made here support guessing }
    if selection = 0 then Exit(1);
    for i := 0 to Length(checks)-1 do
    begin
        check1 := Int((selection and checks[i]) <> 0);
        check2 := Int((selection_mask and checks[i]) <> 0);
        {
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         }
        if check1>0 then Exit(check2);
    end;
    { This should be dead code, but just to be safe... }
    Result := 0;
end;


function key2any_encode(ctx : Pkey2any_ctx_st; cout : POSSL_CORE_BIO;const key : Pointer; &type : integer;const pemname : PUTF8Char;checker : Tcheck_key_type_fn; writer : Tkey_to_der_fn; pwcb : TOSSL_PASSPHRASE_CALLBACK; pwcbarg : Pointer; key2paramstring : Tkey_to_paramstring_fn; key2der : Ti2d_of_void):integer;
var
  ret : integer;

  _out : PBIO;
begin
    ret := 0;
    if key = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    end
    else
    if ( Assigned(writer))
                and  ( (Assigned(checker))  or  (checker(key, &type)>0)) then
    begin
        _out := ossl_bio_new_from_core_bio(ctx.provctx, cout);
        if (_out <> nil)
             and ( (not Assigned(pwcb))
                 or  (ossl_pw_set_ossl_passphrase_cb(@ctx.pwdata, pwcb, pwcbarg) > 0) ) then
            ret := writer(_out, key, &type, pemname, key2paramstring, key2der, ctx);
        BIO_free(_out);
    end
    else
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    end;
    Result := ret;
end;



function rsa_to_type_specific_keypair_der_import_object(vctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  ctx : Pkey2any_ctx_st;
begin
  ctx := vctx;
  Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx.provctx, selection, params));
end;


procedure rsa_to_type_specific_keypair_der_free_object( key : Pointer);
begin
  ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa_to_type_specific_keypair_der_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2any_check_selection(selection, ( $01 or $02 )));
end;


function rsa_to_type_specific_keypair_der_encode(ctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
     if key_abstract <> nil  then
     begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
     end;

     if ((selection and $01) <> 0) then
        Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PRIVATE KEY', rsa_check_key_type,
                              key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, i2d_RSAPrivateKey));

     if (selection and $02 ) <> 0 then
        Exit( key2any_encode(ctx, cout, key, 6, 'RSA'+ ' PUBLIC KEY', rsa_check_key_type,
                            key_to_type_specific_der_bio, cb, cbarg, prepare_rsa_params, i2d_RSAPublicKey));

    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    Exit(0);
end;

 initialization

    settables[0] := _OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, nil, 0);
    settables[1] := _OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, nil, 0);
    settables[2] := OSSL_PARAM_END ;
end.
