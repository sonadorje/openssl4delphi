unit openssl3.providers.implementations.encode_decode.decode_der2key;

interface
uses OpenSSL.Api;

type
  Pkeytype_desc_st = ^keytype_desc_st;
  der2key_ctx_st = record
    provctx: PPROV_CTX;
    desc: Pkeytype_desc_st;
    selection: Integer;
    flag_fatal: Cardinal;
  end;

  Pder2key_ctx_st = ^der2key_ctx_st;
  Tcheck_key_fn = function(p1: Pointer; ctx: Pder2key_ctx_st): Integer;
  Tadjust_key_fn = procedure(p1: Pointer; ctx: Pder2key_ctx_st);
  Tfree_key_fn = procedure(p1: Pointer);

  Td2i_PKCS8_fn = function(p1: PPointer; const p2: PPByte; p3: Integer; p4: Pder2key_ctx_st): Pointer;

  keytype_desc_st = record
    keytype_name: PUTF8Char;
    fns: POSSL_DISPATCH;
    structure_name: PUTF8Char;
    evp_type: Integer;
    selection_mask: Integer;
    d2i_private_key: Td2i_of_void;
    d2i_public_key: Td2i_of_void;
    d2i_key_params: Td2i_of_void;
    d2i_PKCS8: Td2i_PKCS8_fn;
    d2i_PUBKEY: Td2i_of_void;
    check_key: Tcheck_key_fn;
    adjust_key: Tadjust_key_fn;
    free_key: Tfree_key_fn;
  end;
  
  Tkey_from_pkcs8_t = function(const p8inf: PPKCS8_PRIV_KEY_INFO; libctx: POSSL_LIB_CTX; const propq: PUTF8Char): Pointer;
  Pkey_from_pkcs8_t = ^Tkey_from_pkcs8_t ;

  function der2key_decode_p8(const input_der : PPByte; input_der_len : long; ctx : Pder2key_ctx_st; key_from_pkcs8 : Tkey_from_pkcs8_t):Pointer;
  function der2key_newctx(provctx : Pointer;const desc : Pkeytype_desc_st):Pder2key_ctx_st;
  procedure der2key_freectx( vctx : Pointer);
  function der2key_check_selection(selection : integer;const desc : Pkeytype_desc_st):integer;
  function der2key_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
  function der2key_export_object(vctx : Pointer;const reference : Pointer; reference_sz : size_t; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;

  function dh_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
  procedure dh_adjust( key : Pointer; ctx : Pder2key_ctx_st);
  function dsa_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
  procedure dsa_adjust( key : Pointer; ctx : Pder2key_ctx_st);
  function ec_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
  function ec_check( key : Pointer; ctx : Pder2key_ctx_st):integer;
  procedure ec_adjust( key : Pointer; ctx : Pder2key_ctx_st);
  function ecx_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
  procedure ecx_key_adjust( key : Pointer; ctx : Pder2key_ctx_st);
  function sm2_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
  function rsa_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
  function rsa_check( key : Pointer; ctx : Pder2key_ctx_st):integer;
  procedure rsa_adjust( key : Pointer; ctx : Pder2key_ctx_st);

  function PrivateKeyInfo_der2dh_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2dh_does_selection( provctx : Pointer; selection : integer):integer;


  const ossl_PrivateKeyInfo_der_to_dh_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
  (function_id:  1; method:(code:@PrivateKeyInfo_der2dh_newctx; data:nil)),
  (function_id:  2; method:(code:@der2key_freectx; data:nil)),
  (function_id:  10; method:(code:@PrivateKeyInfo_der2dh_does_selection; data:nil)),
  (function_id:  11; method:(code:@der2key_decode; data:nil)),
  (function_id:  20; method:(code:@der2key_export_object; data:nil)),
  (function_id:  0; method:(code:nil; data:nil)) );

  function SubjectPublicKeyInfo_der2dh_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2dh_does_selection( provctx : Pointer; selection : integer):integer;

const ossl_SubjectPublicKeyInfo_der_to_dh_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2dh_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2dh_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

 function type_specific_params_der2dh_newctx( provctx : Pointer):Pointer;
 function type_specific_params_der2dh_does_selection( provctx : Pointer; selection : integer):integer;

 const ossl_type_specific_params_der_to_dh_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@type_specific_params_der2dh_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@type_specific_params_der2dh_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

 function DH_der2dh_newctx( provctx : Pointer):Pointer;
 function DH_der2dh_does_selection( provctx : Pointer; selection : integer):integer;

const ossl_DH_der_to_dh_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@DH_der2dh_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@DH_der2dh_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function PrivateKeyInfo_der2dhx_newctx( provctx : Pointer):Pointer;
function PrivateKeyInfo_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;

const ossl_PrivateKeyInfo_der_to_dhx_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2dhx_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2dhx_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function SubjectPublicKeyInfo_der2dhx_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;

const ossl_SubjectPublicKeyInfo_der_to_dhx_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2dhx_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2dhx_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function type_specific_params_der2dhx_newctx( provctx : Pointer):Pointer;
  function type_specific_params_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;

const ossl_type_specific_params_der_to_dhx_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@type_specific_params_der2dhx_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@type_specific_params_der2dhx_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function DHX_der2dhx_newctx( provctx : Pointer):Pointer;
  function DHX_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;


const  ossl_DHX_der_to_dhx_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@DHX_der2dhx_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@DHX_der2dhx_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function PrivateKeyInfo_der2dsa_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2dsa_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
  function type_specific_der2dsa_newctx( provctx : Pointer):Pointer;
  function type_specific_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
  function DSA_der2dsa_newctx( provctx : Pointer):Pointer;
  function DSA_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;


const  ossl_PrivateKeyInfo_der_to_dsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2dsa_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2dsa_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_dsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2dsa_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2dsa_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_type_specific_der_to_dsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@type_specific_der2dsa_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@type_specific_der2dsa_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_DSA_der_to_dsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@DSA_der2dsa_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@DSA_der2dsa_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function PrivateKeyInfo_der2ec_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2ec_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
  function type_specific_no_pub_der2ec_newctx( provctx : Pointer):Pointer;
  function type_specific_no_pub_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
  function EC_der2ec_newctx( provctx : Pointer):Pointer;
  function EC_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
  function PrivateKeyInfo_der2x25519_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2x25519_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2x25519_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2x25519_does_selection( provctx : Pointer; selection : integer):integer;
  function PrivateKeyInfo_der2x448_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2x448_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2x448_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2x448_does_selection( provctx : Pointer; selection : integer):integer;
  function PrivateKeyInfo_der2ed25519_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2ed25519_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2ed25519_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2ed25519_does_selection( provctx : Pointer; selection : integer):integer;
  function PrivateKeyInfo_der2ed448_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2ed448_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2ed448_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2ed448_does_selection( provctx : Pointer; selection : integer):integer;


const  ossl_PrivateKeyInfo_der_to_ec_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2ec_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2ec_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_ec_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2ec_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2ec_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_type_specific_no_pub_der_to_ec_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@type_specific_no_pub_der2ec_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@type_specific_no_pub_der2ec_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_EC_der_to_ec_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@EC_der2ec_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@EC_der2ec_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_PrivateKeyInfo_der_to_x25519_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2x25519_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2x25519_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_x25519_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2x25519_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2x25519_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_PrivateKeyInfo_der_to_x448_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2x448_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2x448_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_x448_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2x448_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2x448_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_PrivateKeyInfo_der_to_ed25519_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2ed25519_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2ed25519_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_ed25519_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2ed25519_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2ed25519_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_PrivateKeyInfo_der_to_ed448_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@PrivateKeyInfo_der2ed448_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@PrivateKeyInfo_der2ed448_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_ed448_decoder_functions: array[0..5] of TOSSL_DISPATCH = ( 
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2ed448_newctx; data:nil)), 
(function_id:  2; method:(code:@der2key_freectx; data:nil)), 
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2ed448_does_selection; data:nil)), 
(function_id:  11; method:(code:@der2key_decode; data:nil)), 
(function_id:  20; method:(code:@der2key_export_object; data:nil)), 
(function_id:  0; method:(code:nil; data:nil)) );

function PrivateKeyInfo_der2sm2_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2sm2_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2sm2_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2sm2_does_selection( provctx : Pointer; selection : integer):integer;

const  ossl_PrivateKeyInfo_der_to_sm2_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@PrivateKeyInfo_der2sm2_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@PrivateKeyInfo_der2sm2_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_sm2_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2sm2_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2sm2_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

function PrivateKeyInfo_der2rsa_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2rsa_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
  function type_specific_keypair_der2rsa_newctx( provctx : Pointer):Pointer;
  function type_specific_keypair_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
  function RSA_der2rsa_newctx( provctx : Pointer):Pointer;
  function RSA_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
  function PrivateKeyInfo_der2rsapss_newctx( provctx : Pointer):Pointer;
  function PrivateKeyInfo_der2rsapss_does_selection( provctx : Pointer; selection : integer):integer;
  function SubjectPublicKeyInfo_der2rsapss_newctx( provctx : Pointer):Pointer;
  function SubjectPublicKeyInfo_der2rsapss_does_selection( provctx : Pointer; selection : integer):integer;


const  ossl_PrivateKeyInfo_der_to_rsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@PrivateKeyInfo_der2rsa_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@PrivateKeyInfo_der2rsa_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_type_specific_keypair_der_to_rsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@type_specific_keypair_der2rsa_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@type_specific_keypair_der2rsa_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_RSA_der_to_rsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@RSA_der2rsa_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@RSA_der2rsa_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_PrivateKeyInfo_der_to_rsapss_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@PrivateKeyInfo_der2rsapss_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@PrivateKeyInfo_der2rsapss_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_rsapss_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2rsapss_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2rsapss_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_SubjectPublicKeyInfo_der_to_rsa_decoder_functions: array[0..5] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@SubjectPublicKeyInfo_der2rsa_newctx; data:nil)),
(function_id:  2; method:(code:@der2key_freectx; data:nil)),
(function_id:  10; method:(code:@SubjectPublicKeyInfo_der2rsa_does_selection; data:nil)),
(function_id:  11; method:(code:@der2key_decode; data:nil)),
(function_id:  20; method:(code:@der2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

var PrivateKeyInfo_dh_desc, SubjectPublicKeyInfo_dh_desc,
    PrivateKeyInfo_dhx_desc, SubjectPublicKeyInfo_dhx_desc,
    type_specific_params_dhx_desc, DHX_dhx_desc,
    PrivateKeyInfo_dsa_desc,SubjectPublicKeyInfo_dsa_desc,
    type_specific_dsa_desc, DSA_dsa_desc,
    PrivateKeyInfo_ec_desc,SubjectPublicKeyInfo_ec_desc,
    type_specific_no_pub_ec_desc,EC_ec_desc,
    PrivateKeyInfo_x25519_desc,SubjectPublicKeyInfo_x25519_desc,
    PrivateKeyInfo_x448_desc,SubjectPublicKeyInfo_x448_desc,
    PrivateKeyInfo_ed25519_desc,SubjectPublicKeyInfo_ed25519_desc,
    PrivateKeyInfo_ed448_desc,SubjectPublicKeyInfo_ed448_desc,
    PrivateKeyInfo_sm2_desc,  SubjectPublicKeyInfo_sm2_desc,
    PrivateKeyInfo_rsa_desc,  SubjectPublicKeyInfo_rsa_desc,
    type_specific_keypair_rsa_desc,RSA_rsa_desc,
    PrivateKeyInfo_rsapss_desc,  SubjectPublicKeyInfo_rsapss_desc,
    type_specific_params_dh_desc, DH_dh_desc: keytype_desc_st;

implementation
uses openssl3.crypto.dh.dh_backend,    openssl3.crypto.dh.dh_lib,
     OpenSSL3.crypto.dsa.dsa_backend,  openssl3.crypto.dsa.dsa_lib,
     openssl3.crypto.ec.ec_backend,    openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ecx_backend,   openssl3.crypto.ec.ecx_key,
     OpenSSL3.crypto.rsa.rsa_backend,  openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.mem,              OpenSSL3.Err,
     openssl3.providers.fips.fipsprov, openssl3.crypto.params,
     openssl3.crypto.asn1.p8_pkey,     openssl3.crypto.objects.obj_dat,
     openssl3.crypto.x509.x_pubkey,    openssl3.crypto.dh.dh_asn1,
     openssl3.crypto.dsa.dsa_asn1,     openssl3.crypto.ec.ec_asn1,
     OpenSSL3.crypto.rsa.rsa_asn1,
     openssl3.providers.implementations.encode_decode.endecoder_common,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ecx_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     OpenSSL3.providers.common.provider_ctx;




function PrivateKeyInfo_der2rsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_rsa_desc));
end;


function PrivateKeyInfo_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_rsa_desc));
end;


function SubjectPublicKeyInfo_der2rsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_rsa_desc));
end;


function SubjectPublicKeyInfo_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_rsa_desc));
end;


function type_specific_keypair_der2rsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @type_specific_keypair_rsa_desc));
end;


function type_specific_keypair_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @type_specific_keypair_rsa_desc));
end;


function RSA_der2rsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @RSA_rsa_desc));
end;


function RSA_der2rsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @RSA_rsa_desc));
end;


function PrivateKeyInfo_der2rsapss_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_rsapss_desc));
end;


function PrivateKeyInfo_der2rsapss_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_rsapss_desc));
end;


function SubjectPublicKeyInfo_der2rsapss_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_rsapss_desc));
end;


function SubjectPublicKeyInfo_der2rsapss_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_rsapss_desc));
end;



function PrivateKeyInfo_der2sm2_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_sm2_desc));
end;


function PrivateKeyInfo_der2sm2_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_sm2_desc));
end;


function SubjectPublicKeyInfo_der2sm2_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_sm2_desc));
end;


function SubjectPublicKeyInfo_der2sm2_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_sm2_desc));
end;

function PrivateKeyInfo_der2ec_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_ec_desc));
end;


function PrivateKeyInfo_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_ec_desc));
end;


function SubjectPublicKeyInfo_der2ec_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_ec_desc));
end;


function SubjectPublicKeyInfo_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_ec_desc));
end;


function type_specific_no_pub_der2ec_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @type_specific_no_pub_ec_desc));
end;


function type_specific_no_pub_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @type_specific_no_pub_ec_desc));
end;


function EC_der2ec_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @EC_ec_desc));
end;


function EC_der2ec_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @EC_ec_desc));
end;


function PrivateKeyInfo_der2x25519_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_x25519_desc));
end;


function PrivateKeyInfo_der2x25519_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_x25519_desc));
end;


function SubjectPublicKeyInfo_der2x25519_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_x25519_desc));
end;


function SubjectPublicKeyInfo_der2x25519_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_x25519_desc));
end;


function PrivateKeyInfo_der2x448_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_x448_desc));
end;


function PrivateKeyInfo_der2x448_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_x448_desc));
end;


function SubjectPublicKeyInfo_der2x448_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_x448_desc));
end;


function SubjectPublicKeyInfo_der2x448_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_x448_desc));
end;


function PrivateKeyInfo_der2ed25519_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_ed25519_desc));
end;


function PrivateKeyInfo_der2ed25519_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_ed25519_desc));
end;


function SubjectPublicKeyInfo_der2ed25519_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_ed25519_desc));
end;


function SubjectPublicKeyInfo_der2ed25519_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_ed25519_desc));
end;


function PrivateKeyInfo_der2ed448_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_ed448_desc));
end;


function PrivateKeyInfo_der2ed448_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_ed448_desc));
end;


function SubjectPublicKeyInfo_der2ed448_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_ed448_desc));
end;


function SubjectPublicKeyInfo_der2ed448_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_ed448_desc));
end;



function PrivateKeyInfo_der2dsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_dsa_desc));
end;


function PrivateKeyInfo_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_dsa_desc));
end;


function SubjectPublicKeyInfo_der2dsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_dsa_desc));
end;


function SubjectPublicKeyInfo_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_dsa_desc));
end;


function type_specific_der2dsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @type_specific_dsa_desc));
end;


function type_specific_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @type_specific_dsa_desc));
end;


function DSA_der2dsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @DSA_dsa_desc));
end;


function DSA_der2dsa_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @DSA_dsa_desc));
end;


function DHX_der2dhx_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @DHX_dhx_desc));
end;


function DHX_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @DHX_dhx_desc));
end;
 


function type_specific_params_der2dhx_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @type_specific_params_dhx_desc));
end;


function type_specific_params_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @type_specific_params_dhx_desc));
end;



function SubjectPublicKeyInfo_der2dhx_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_dhx_desc));
end;


function SubjectPublicKeyInfo_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_dhx_desc));
end;



function PrivateKeyInfo_der2dhx_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_dhx_desc));
end;


function PrivateKeyInfo_der2dhx_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_dhx_desc));
end;


function DH_der2dh_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @DH_dh_desc));
end;


function DH_der2dh_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @DH_dh_desc));
end;




function type_specific_params_der2dh_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @type_specific_params_dh_desc));
end;


function type_specific_params_der2dh_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @type_specific_params_dh_desc));
end;
 


function SubjectPublicKeyInfo_der2dh_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @SubjectPublicKeyInfo_dh_desc));
end;


function SubjectPublicKeyInfo_der2dh_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @SubjectPublicKeyInfo_dh_desc));
end;


function get_keytype_desc_st
  (  keytype_name: PUTF8Char;
    fns: POSSL_DISPATCH;
    structure_name: PUTF8Char;
    evp_type: Integer;
    selection_mask: Integer;
    d2i_private_key: Td2i_of_void;
    d2i_public_key: Td2i_of_void;
    d2i_key_params: Td2i_of_void;
    d2i_PKCS8: Td2i_PKCS8_fn;
    d2i_PUBKEY: Td2i_of_void;
    check_key: Tcheck_key_fn;
    adjust_key: Tadjust_key_fn;
    free_key: Tfree_key_fn): keytype_desc_st;
begin
    Result.keytype_name := keytype_name;
    Result.fns:= fns;
    Result.structure_name:=structure_name;
    Result.evp_type:=evp_type;
    Result.selection_mask:=selection_mask;
    Result.d2i_private_key:=d2i_private_key;
    Result.d2i_public_key:=d2i_public_key;
    Result.d2i_key_params:=d2i_key_params;
    Result.d2i_PKCS8:=d2i_PKCS8;
    Result.d2i_PUBKEY:=d2i_PUBKEY;
    Result.check_key:=check_key;
    Result.adjust_key:=adjust_key;
    Result.free_key:=free_key;
end;

function PrivateKeyInfo_der2dh_newctx( provctx : Pointer):Pointer;
begin
 Exit(der2key_newctx(provctx, @PrivateKeyInfo_dh_desc));
end;


function PrivateKeyInfo_der2dh_does_selection( provctx : Pointer; selection : integer):integer;
begin
 Exit(der2key_check_selection(selection, @PrivateKeyInfo_dh_desc));
end;


function dh_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
begin
    Exit(der2key_decode_p8(der, der_len, ctx,
                             Pkey_from_pkcs8_t(@ossl_dh_key_from_pkcs8)^));
end;


procedure dh_adjust( key : Pointer; ctx : Pder2key_ctx_st);
begin
    ossl_dh_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;


function dsa_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
begin
    Exit(der2key_decode_p8(der, der_len, ctx,
                             Pkey_from_pkcs8_t(@ossl_dsa_key_from_pkcs8)^));
end;


procedure dsa_adjust( key : Pointer; ctx : Pder2key_ctx_st);
begin
    ossl_dsa_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;


function ec_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
begin
    Exit(der2key_decode_p8(der, der_len, ctx,
                             Pkey_from_pkcs8_t(@ossl_ec_key_from_pkcs8)^));
end;


function ec_check( key : Pointer; ctx : Pder2key_ctx_st):integer;
var
  sm2, ok : integer;
begin
    { We're trying to be clever by comparing two truths }
    sm2 := Int( (EC_KEY_get_flags(key) and EC_FLAG_SM2_RANGE) <> 0);
    ok  := Int(ctx.desc.evp_type = EVP_PKEY_SM2);
    Result := Int(sm2 = ok);
end;


procedure ec_adjust( key : Pointer; ctx : Pder2key_ctx_st);
begin
    ossl_ec_key_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;


function ecx_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
begin
    Exit(der2key_decode_p8(der, der_len, ctx,
                             Pkey_from_pkcs8_t(@ossl_ecx_key_from_pkcs8)^));
end;


procedure ecx_key_adjust( key : Pointer; ctx : Pder2key_ctx_st);
begin
    ossl_ecx_key_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;


function sm2_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
begin
    Exit(der2key_decode_p8(der, der_len, ctx,
                             Pkey_from_pkcs8_t(@ossl_ec_key_from_pkcs8)^));
end;


function rsa_d2i_PKCS8(key : PPointer;const der : PPByte; der_len : long; ctx : Pder2key_ctx_st):Pointer;
begin
    Exit(der2key_decode_p8(der, der_len, ctx,
                             Pkey_from_pkcs8_t(@ossl_rsa_key_from_pkcs8)^));
end;


function rsa_check( key : Pointer; ctx : Pder2key_ctx_st):integer;
begin
    case (RSA_test_flags(key, RSA_FLAG_TYPE_MASK)) of
    RSA_FLAG_TYPE_RSA:
        Exit(Int(ctx.desc.evp_type = EVP_PKEY_RSA));
    RSA_FLAG_TYPE_RSASSAPSS:
        Exit(Int(ctx.desc.evp_type = EVP_PKEY_RSA_PSS));
    end;
    { Currently unsupported RSA key type }
    Result := 0;
end;


procedure rsa_adjust( key : Pointer; ctx : Pder2key_ctx_st);
begin
    ossl_rsa_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;



function der2key_newctx(provctx : Pointer;const desc : Pkeytype_desc_st):Pder2key_ctx_st;
var
  ctx : Pder2key_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then begin
        ctx.provctx := provctx;
        ctx.desc := desc;
    end;
    Result := ctx;
end;


procedure der2key_freectx( vctx : Pointer);
var
  ctx : Pder2key_ctx_st;
begin
    ctx := vctx;
    OPENSSL_free(ctx);
end;


function der2key_check_selection(selection : integer;const desc : Pkeytype_desc_st):integer;
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
    for i := 0 to Length(checks)-1 do begin
        check1 := Int((selection and checks[i]) <> 0);
        check2 := Int((desc.selection_mask and checks[i]) <> 0);
        {
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         }
        if check1 > 0 then Exit(check2);
    end;
    { This should be dead code, but just to be safe... }
    Result := 0;
end;


function der2key_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
    ctx         : Pder2key_ctx_st;
    der, derp   : PByte;
    der_len     : long;
    key         : Pointer;
    ok          : integer;
    params      : array[0..3] of TOSSL_PARAM;
    object_type : integer;
    label _next, _end ;
begin
    ctx := vctx;
    der := nil;
    der_len := 0;
    key := nil;
    ok := 0;
    ctx.selection := selection;
    {
     * The caller is allowed to specify 0 as a selection mark, to have the
     * structure and key type guessed.  For type-specific structures, this
     * is not recommended, as some structures are very similar.
     * Note that 0 isn't the same as OSSL_KEYMGMT_SELECT_ALL, as the latter
     * signifies a private key structure, where everything else is assumed
     * to be present as well.
     }
    if selection = 0 then selection := ctx.desc.selection_mask;
    if selection and ctx.desc.selection_mask = 0 then  begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    ok := ossl_read_der(ctx.provctx, cin, @der, @der_len);
    if 0>=ok then goto _next;
    ok := 0; { Assume that we fail }
    ERR_set_mark;
    if selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY <> 0 then
    begin
        derp := der;
        if Assigned(ctx.desc.d2i_PKCS8) then
        begin
            key := ctx.desc.d2i_PKCS8(nil, @derp, der_len, ctx);
            if ctx.flag_fatal > 0 then
            begin
                ERR_clear_last_mark;
                goto _end;
            end;
        end
        else if Assigned(ctx.desc.d2i_private_key) then
        begin
            key := ctx.desc.d2i_private_key(nil, @derp, der_len);
        end;
        if (key = nil)  and  (ctx.selection <> 0) then begin
            ERR_clear_last_mark;
            goto _next;
        end;
    end;
    if (key = nil)  and  (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY <> 0)  then
    begin
        derp := der;
        if Assigned(ctx.desc.d2i_PUBKEY) then
           key := ctx.desc.d2i_PUBKEY(nil, @derp, der_len)
        else
            key := ctx.desc.d2i_public_key(nil, @derp, der_len);
        if (key = nil)  and  (ctx.selection <> 0) then begin
            ERR_clear_last_mark;
            goto _next;
        end;
    end;
    if (key = nil)  and  (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS  <> 0) then
    begin
        derp := der;
        if Assigned(ctx.desc.d2i_key_params) then
           key := ctx.desc.d2i_key_params(nil, @derp, der_len);
        if (key = nil)  and  (ctx.selection <> 0) then begin
            ERR_clear_last_mark;
            goto _next;
        end;
    end;
    if key = nil then
       ERR_clear_last_mark
    else
        ERR_pop_to_mark;
    {
     * Last minute check to see if this was the correct type of key.  This
     * should never lead to a fatal error, i.e. the decoding itself was
     * correct, it was just an unexpected key type.  This is generally for
     * classes of key types that have subtle variants, like RSA-PSS keys as
     * opposed to plain RSA keys.
     }
    if (key <> nil)
         and  (Assigned(ctx.desc.check_key))
         and  (0>=ctx.desc.check_key(key, ctx))  then
    begin
        ctx.desc.free_key(key);
        key := nil;
    end;
    if (key <> nil)  and  (Assigned(ctx.desc.adjust_key)) then
       ctx.desc.adjust_key(key, ctx);
 _next:
    {
     * Indicated that we successfully decoded something, or not at all.
     * Ending up 'empty handed' is not an error.
     }
    ok := 1;
    {
     * We free memory here so it's not held up during the callback, because
     * we know the process is recursive and the allocated chunks of memory
     * add up.
     }
    OPENSSL_free(der);
    der := nil;
    if key <> nil then begin
        object_type := OSSL_OBJECT_PKEY;
        params[0] := OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @object_type);
        params[1] := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             PUTF8Char( ctx.desc.keytype_name),
                                             0);
        { The address of the key becomes the octet string }
        params[2] := OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &key, sizeof(key));
        params[3] := OSSL_PARAM_construct_end;
        ok := data_cb(@params, data_cbarg);
    end;

 _end:
    ctx.desc.free_key(key);
    OPENSSL_free(der);
    Result := ok;
end;


function der2key_export_object(vctx : Pointer;const reference : Pointer; reference_sz : size_t; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;
var
  ctx : Pder2key_ctx_st;
  _export : TOSSL_FUNC_keymgmt_export_fn;
  keydata : Pointer;
begin
    ctx := vctx;
    _export := ossl_prov_get_keymgmt_export(ctx.desc.fns);
    if (reference_sz = sizeof(keydata)) and  (Assigned(_export))  then
    begin
        { The contents of the reference is the address to our object }
        keydata := PPointer(reference)^;
        Exit(_export(keydata, ctx.selection, export_cb, export_cbarg));
    end;
    Result := 0;
end;



function der2key_decode_p8(const input_der : PPByte; input_der_len : long; ctx : Pder2key_ctx_st; key_from_pkcs8 : Tkey_from_pkcs8_t):Pointer;
var
  p8inf : PPKCS8_PRIV_KEY_INFO;
  alg : PX509_ALGOR;
  key : Pointer;
begin
    p8inf := nil;
     alg := nil;
    key := nil;
    p8inf := d2i_PKCS8_PRIV_KEY_INFO(nil, input_der, input_der_len);
    if (p8inf   <> nil)
         and  (PKCS8_pkey_get0(nil, nil, nil, @alg, p8inf) > 0)
         and  (OBJ_obj2nid(alg.algorithm) = ctx.desc.evp_type) then
        key := key_from_pkcs8(p8inf, PROV_LIBCTX_OF(ctx.provctx), nil);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    Result := key;
end;

initialization
  PrivateKeyInfo_dh_desc:= get_keytype_desc_st
  ( 'DH',
    @ossl_dh_keymgmt_functions,
    'PrivateKeyInfo',
    28,
    $01 ,
    nil,
    nil,
    nil,
    dh_d2i_PKCS8,
    nil,
    nil,
    dh_adjust,
    @DH_free);

    SubjectPublicKeyInfo_dh_desc := get_keytype_desc_st 
      ( 'DH', @ossl_dh_keymgmt_functions, 'SubjectPublicKeyInfo', 28,  $02, 
      Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) , 
      @ossl_d2i_DH_PUBKEY, Pointer(0) , dh_adjust, @DH_free) ;

    type_specific_params_dh_desc := get_keytype_desc_st
      ( 'DH', @ossl_dh_keymgmt_functions, 'type-specific', 28, ( ( $04 or $80) ), 
      Pointer(0) , Pointer(0) , @d2i_DHparams, Pointer(0) ,
      Pointer(0) , Pointer(0) , dh_adjust, @DH_free);

     DH_dh_desc := get_keytype_desc_st
       ( 'DH', @ossl_dh_keymgmt_functions, 'DH', 28, ( ( $04 or $80) ),
       Pointer(0) , Pointer(0) , @d2i_DHparams, Pointer(0) ,
       Pointer(0) , Pointer(0) , dh_adjust, @DH_free);

     PrivateKeyInfo_dhx_desc := get_keytype_desc_st
       ( 'DHX', @ossl_dhx_keymgmt_functions, 'PrivateKeyInfo', 920, ( $01 ), 
       Pointer(0) , Pointer(0) , Pointer(0) , dh_d2i_PKCS8, Pointer(0) , 
       Pointer(0) , dh_adjust, @DH_free);

    SubjectPublicKeyInfo_dhx_desc := get_keytype_desc_st
       ( 'DHX', @ossl_dhx_keymgmt_functions, 'SubjectPublicKeyInfo', 920, ( $02 ),
       Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) ,
       @ossl_d2i_DHx_PUBKEY, Pointer(0) , dh_adjust, @DH_free);

    type_specific_params_dhx_desc := get_keytype_desc_st
       ( 'DHX', @ossl_dhx_keymgmt_functions, 'type-specific', 920, ( ( $04 or $80) ), 
       Pointer(0) , Pointer(0) , @d2i_DHxparams, Pointer(0) ,
       Pointer(0) , Pointer(0) , dh_adjust, @DH_free);

    DHX_dhx_desc := get_keytype_desc_st
       ( 'DHX', @ossl_dhx_keymgmt_functions, 'DHX', 920, ( ( $04 or $80) ),
       Pointer(0) , Pointer(0) , @d2i_DHxparams, Pointer(0) ,
       Pointer(0) , Pointer(0) , dh_adjust, @DH_free);

    PrivateKeyInfo_dsa_desc := get_keytype_desc_st 
       ( 'DSA', @ossl_dsa_keymgmt_functions, 'PrivateKeyInfo', 116, ( $01 ), 
       Pointer(0) , Pointer(0) , Pointer(0) , dsa_d2i_PKCS8, Pointer(0) , 
       Pointer(0) , dsa_adjust, @DH_free);


    SubjectPublicKeyInfo_dsa_desc := get_keytype_desc_st
       ( 'DSA', @ossl_dsa_keymgmt_functions, 'SubjectPublicKeyInfo', 116, ( $02 ),
       Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) ,
       @d2i_DSA_PUBKEY, Pointer(0) , dsa_adjust, @DH_free);


    type_specific_dsa_desc := get_keytype_desc_st
       ('DSA', @ossl_dsa_keymgmt_functions, 'type-specific', 116, 
       ( ( ( $01 or $02 ) or ( $04 or $80) ) ), @d2i_DSAPrivateKey,
       @d2i_DSAPublicKey, @d2i_DSAparams, Pointer(0) ,
       Pointer(0) , Pointer(0) , dsa_adjust, @DH_free);

    DSA_dsa_desc := get_keytype_desc_st
         ( 'DSA', @ossl_dsa_keymgmt_functions, 'DSA', 116,
         ( ( ( $01 or $02 ) or ( $04 or $80) ) ), (@d2i_DSAPrivateKey),
         (@d2i_DSAPublicKey), (@d2i_DSAparams), Pointer(0) ,
         Pointer(0) , Pointer(0) , dsa_adjust, @DH_free);

    PrivateKeyInfo_ec_desc := get_keytype_desc_st 
            ( 'EC', @ossl_ec_keymgmt_functions, 'PrivateKeyInfo', 408, ( $01 ), 
            Pointer(0) , Pointer(0) , Pointer(0) , ec_d2i_PKCS8, Pointer(0) , 
            ec_check, ec_adjust, @EC_KEY_free);


    SubjectPublicKeyInfo_ec_desc := get_keytype_desc_st
    ( 'EC', @ossl_ec_keymgmt_functions, 'SubjectPublicKeyInfo', 408, ( $02 ),
     Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) ,
     (@d2i_EC_PUBKEY), ec_check, ec_adjust, @EC_KEY_free )    ;


    type_specific_no_pub_ec_desc := get_keytype_desc_st 
    ( 'EC', @ossl_ec_keymgmt_functions, 'type-specific', 408, ( $01 or ( $04 or $80) ), 
       (@d2i_ECPrivateKey), Pointer(0) , (@d2i_ECParameters),
       Pointer(0) , Pointer(0) , ec_check, ec_adjust, @EC_KEY_free ) ;

    EC_ec_desc := get_keytype_desc_st 
    ( 'EC', @ossl_ec_keymgmt_functions, 'EC', 408, ( $01 or ( $04 or $80) ), 
       (@d2i_ECPrivateKey), Pointer(0) , (@d2i_ECParameters),
       Pointer(0) , Pointer(0) , ec_check, ec_adjust, @EC_KEY_free ) ;

    PrivateKeyInfo_x25519_desc := get_keytype_desc_st 
    ( 'X25519', @ossl_x25519_keymgmt_functions, 'PrivateKeyInfo', 1034, ( $01 ), 
       Pointer(0) , Pointer(0) , Pointer(0) , ecx_d2i_PKCS8, Pointer(0) , 
       Pointer(0) , ecx_key_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_x25519_desc := get_keytype_desc_st 
    ( 'X25519', @ossl_x25519_keymgmt_functions, 'SubjectPublicKeyInfo', 1034, 
      ( $02 ), Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) , 
      (@ossl_d2i_X25519_PUBKEY), Pointer(0) , ecx_key_adjust,
      @EC_KEY_free ) ;

    PrivateKeyInfo_x448_desc := get_keytype_desc_st 
    ( 'X448', @ossl_x448_keymgmt_functions, 'PrivateKeyInfo', 1035, ( $01 ), 
       Pointer(0) , Pointer(0) , Pointer(0) , ecx_d2i_PKCS8, Pointer(0) , 
       Pointer(0) , ecx_key_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_x448_desc := get_keytype_desc_st 
    ( 'X448', @ossl_x448_keymgmt_functions, 'SubjectPublicKeyInfo', 1035, ( $02 ), 
      Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) , 
      (@ossl_d2i_X448_PUBKEY), Pointer(0) , ecx_key_adjust,
      @EC_KEY_free ) ;


    PrivateKeyInfo_ed25519_desc := get_keytype_desc_st 
    ( 'ED25519', @ossl_ed25519_keymgmt_functions, 'PrivateKeyInfo', 1087, ( $01 ), 
       Pointer(0) , Pointer(0) , Pointer(0) , ecx_d2i_PKCS8, Pointer(0) , Pointer(0) , 
       ecx_key_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_ed25519_desc := get_keytype_desc_st 
    ( 'ED25519', @ossl_ed25519_keymgmt_functions, 'SubjectPublicKeyInfo', 1087, 
       ( $02 ), Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) , 
       (@ossl_d2i_ED25519_PUBKEY), Pointer(0) , ecx_key_adjust,
       @EC_KEY_free ) ;


    PrivateKeyInfo_ed448_desc := get_keytype_desc_st 
    ( 'ED448', @ossl_ed448_keymgmt_functions, 'PrivateKeyInfo', 1088, ( $01 ), 
       Pointer(0) , Pointer(0) , Pointer(0) , ecx_d2i_PKCS8, Pointer(0) , 
       Pointer(0) , ecx_key_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_ed448_desc := get_keytype_desc_st
    ( 'ED448', @ossl_ed448_keymgmt_functions, 'SubjectPublicKeyInfo', 1088, 
      ( $02 ), Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) , 
      (@ossl_d2i_ED448_PUBKEY), Pointer(0) , ecx_key_adjust,
      @EC_KEY_free ) ;

    PrivateKeyInfo_sm2_desc := get_keytype_desc_st
    ( 'SM2', @ossl_sm2_keymgmt_functions, 'PrivateKeyInfo', 1172, ( $01 ),
       Pointer(0) , Pointer(0) , Pointer(0) , sm2_d2i_PKCS8, Pointer(0) ,
       ec_check, ec_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_sm2_desc := get_keytype_desc_st
     ( 'SM2', @ossl_sm2_keymgmt_functions, 'SubjectPublicKeyInfo', 1172, ( $02 ),
        Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) ,
        (@d2i_EC_PUBKEY), ec_check, ec_adjust, @EC_KEY_free ) ;

    PrivateKeyInfo_rsa_desc := get_keytype_desc_st
     ( 'RSA', @ossl_rsa_keymgmt_functions, 'PrivateKeyInfo', 6, ( $01 ),
        Pointer(0) , Pointer(0) , Pointer(0) , rsa_d2i_PKCS8, Pointer(0) ,
        rsa_check, rsa_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_rsa_desc := get_keytype_desc_st
    ( 'RSA', @ossl_rsa_keymgmt_functions, 'SubjectPublicKeyInfo', 6, ( $02 ),
       Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) ,
       (@d2i_RSA_PUBKEY), rsa_check, rsa_adjust, @EC_KEY_free ) ;

    type_specific_keypair_rsa_desc := get_keytype_desc_st
    ( 'RSA', @ossl_rsa_keymgmt_functions, 'type-specific', 6, ( ( $01 or $02 ) ),
      (@d2i_RSAPrivateKey), (@d2i_RSAPublicKey),
      Pointer(0) , Pointer(0) , Pointer(0) , rsa_check, rsa_adjust, @EC_KEY_free ) ;

    RSA_rsa_desc := get_keytype_desc_st
    ( 'RSA', @ossl_rsa_keymgmt_functions, 'RSA', 6, ( ( $01 or $02 ) ),
      (@d2i_RSAPrivateKey), (@d2i_RSAPublicKey),
      Pointer(0) , Pointer(0) , Pointer(0) , rsa_check, rsa_adjust, @EC_KEY_free ) ;

    PrivateKeyInfo_rsapss_desc := get_keytype_desc_st
    ( 'RSA-PSS', @ossl_rsapss_keymgmt_functions, 'PrivateKeyInfo', 912, ( $01 ),
      Pointer(0) , Pointer(0) , Pointer(0) , rsa_d2i_PKCS8, Pointer(0) ,
      rsa_check, rsa_adjust, @EC_KEY_free ) ;

    SubjectPublicKeyInfo_rsapss_desc := get_keytype_desc_st
    ( 'RSA-PSS', @ossl_rsapss_keymgmt_functions, 'SubjectPublicKeyInfo', 912,
      ( $02 ), Pointer(0) , Pointer(0) , Pointer(0) , Pointer(0) ,
      (@d2i_RSA_PUBKEY), rsa_check, rsa_adjust, @EC_KEY_free ) ;

end.
