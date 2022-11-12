unit openssl3.crypto.evp.ctrl_params_translate;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

type
  Tstate = (
    PKEY,
    PRE_CTRL_TO_PARAMS, POST_CTRL_TO_PARAMS, CLEANUP_CTRL_TO_PARAMS,
    PRE_CTRL_STR_TO_PARAMS, POST_CTRL_STR_TO_PARAMS, CLEANUP_CTRL_STR_TO_PARAMS,
    PRE_PARAMS_TO_CTRL, POST_PARAMS_TO_CTRL, CLEANUP_PARAMS_TO_CTRL
  );

  Taction = (
    NONE = 0, GET = 1, _SET = 2
   );
 Ptranslation_st = ^translation_st;
 Ptranslation_ctx_st = ^translation_ctx_st;
 Tfixup_args_fn = function(state: Tstate; const translation: Ptranslation_st; ctx: Ptranslation_ctx_st): Integer;
 Tcleanup_args_fn = function(state: Tstate; const translation: Ptranslation_st; ctx: Ptranslation_ctx_st): Integer;

 Tget_name_func = function( algo : Pointer):PUTF8Char;
 Tget_algo_by_name_func = function(libctx : POSSL_LIB_CTX;const name : PUTF8Char):Pointer;

 translation_ctx_st = record
    pctx: PEVP_PKEY_CTX;
    action_type: Taction;
    ctrl_cmd: Integer;
    ctrl_str: PUTF8Char;
    ishex: Integer;
    p1: Integer;
    p2: Pointer;
    sz: NativeUInt;
    params: POSSL_PARAM;
    orig_p2: Pointer;
    name_buf: array [0..49] of UTF8Char;
    allocated_buf: Pointer;
    bufp: Pointer;
    buflen: NativeUInt;
  end;

  translation_st = record
    action_type: Taction;
    keytype1: Integer;
    keytype2: Integer;
    optype: Integer;
    ctrl_num: Integer;
    ctrl_str: PUTF8Char;
    ctrl_hexstr: PUTF8Char;
    param_key: PUTF8Char;
    param_data_type: Cardinal;
    fixup_args: Tfixup_args_fn;
  end;

  kdf_type_map_st = record
    kdf_type_num: Integer;
    kdf_type_str: PUTF8Char;
  end;
  Pkdf_type_map_st = ^kdf_type_map_st;

function fix_dh_kdf_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function fix_kdf_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; kdf_type_map : Pkdf_type_map_st):integer;
function fix_md(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function fix_cipher_md(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; get_name : Tget_name_func; get_algo_by_name : Tget_algo_by_name_func):integer;
function get_md_name( md : Pointer):PUTF8Char;
function get_md_by_name(libctx : POSSL_LIB_CTX;const name : PUTF8Char):Pointer;
function fix_oid(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_dh_paramgen_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_dh_nid(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;

function get_payload_group_name(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_payload_private_key(state : Tstate;const translation : Ptranslation_st; ctx: Ptranslation_ctx_st):integer;
function get_payload_public_key(state : Tstate;const translation : Ptranslation_st;ctx: Ptranslation_ctx_st):integer;
function get_dh_dsa_payload_p(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_dh_dsa_payload_q(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_dh_dsa_payload_g(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_n(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_d(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f1(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e1(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f2(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e2(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f3(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e3(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f4(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e4(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f5(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e5(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f6(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e6(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f7(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e7(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f8(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e8(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f9(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e9(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_f10(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_e10(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c1(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c2(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c3(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c4(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c5(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c6(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c7(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c8(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_rsa_payload_c9(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function get_ec_decoded_from_explicit_params(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function fix_distid_len(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;

const
  evp_pkey_translations: array[0..38] of translation_st = (
    (*
     * The following contain no ctrls; they are exclusively here to extract
     * key payloads from legacy keys; using OSSL_PARAMs; and rely entirely
     * on |fixup_args| to pass the actual data.  The |fixup_args| should
     * expect to get the EVP_PKEY pointer through |ctx->p2|.
     *)

    (* DH; DSA & EC *)
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_GROUP_NAME; param_data_type:OSSL_PARAM_UTF8_STRING;
      fixup_args:get_payload_group_name ),

    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_PRIV_KEY; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_payload_private_key ),

    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_PUB_KEY;
      param_data_type:0; (* no data type; let fixup_args:get_payload_public_key() handle that *)
      fixup_args:get_payload_public_key ),

    (* DH and DSA *)
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_FFC_P; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_dh_dsa_payload_p ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_FFC_G; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_dh_dsa_payload_g ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_FFC_Q; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_dh_dsa_payload_q ),

    (* RSA *)
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_N; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_n ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_E; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_D; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_d ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR1; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f1 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR2; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f2 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR3; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f3 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR4; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f4 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR5; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f5 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR6; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f6 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR7; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f7 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR8; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f8 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR9; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f9 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_FACTOR10; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_f10 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT1; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e1 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT2; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e2 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT3; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e3 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT4; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e4 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT5; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e5 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT6; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e6 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT7; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e7 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT8; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e8 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT9; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e9 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_EXPONENT10; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_e10 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT1; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c1 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT2; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c2 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT3; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c3 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT4; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c4 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT5; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c5 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT6; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c6 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT7; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c7 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT8; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c8 ),
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_RSA_COEFFICIENT9; param_data_type:OSSL_PARAM_UNSIGNED_INTEGER;
      fixup_args:get_rsa_payload_c9 ),

    (* EC *)
    ( action_type:GET; keytype1:-1; keytype2:-1; optype:-1; ctrl_num:0; ctrl_str:nil; ctrl_hexstr:nil;
      param_key:OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS; param_data_type:OSSL_PARAM_INTEGER;
      fixup_args:get_ec_decoded_from_explicit_params )
);


function evp_pkey_get_params_to_ctrl(const pkey : PEVP_PKEY; params : POSSL_PARAM):integer;
function evp_pkey_setget_params_to_ctrl(const pkey : PEVP_PKEY; action_type : Taction; params : POSSL_PARAM):integer;
function default_fixup_args(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function default_check(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
function OSSL_PARAM_get_uint(const p : POSSL_PARAM; val : Puint32):integer;
function OSSL_PARAM_get_uint64(const p : POSSL_PARAM; val : Puint64_t):integer;
function OSSL_PARAM_get_octet_string(const p : POSSL_PARAM;var val : Pointer; max_len : size_t; used_len : Psize_t):integer;
function OSSL_PARAM_set_octet_string(p : POSSL_PARAM;const val : Pointer; len : size_t):integer;
function lookup_evp_pkey_translation( tmpl : Ptranslation_st):Ptranslation_st;
function lookup_translation(tmpl : Ptranslation_st;const translations : Ptranslation_st; translations_num : size_t):Ptranslation_st;
//function get_ec_decoded_from_explicit_params(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function get_payload_int(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st;const val : integer):integer;
 function get_rsa_payload_coefficient(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; coefficientnum : size_t):integer;
 function get_payload_bn(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st;bn : PBIGNUM):integer;
 function get_rsa_payload_factor(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; factornum : size_t):integer;
 function get_rsa_payload_exponent(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; exponentnum : size_t):integer;
 function cleanup_translation_ctx(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function evp_pkey_ctx_set_params_to_ctrl(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
 function evp_pkey_ctx_setget_params_to_ctrl( pctx : PEVP_PKEY_CTX; action_type: Taction; params : POSSL_PARAM):integer;
 function lookup_evp_pkey_ctx_translation( tmpl : Ptranslation_st):Ptranslation_st;
 function fix_dh_nid5114(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_ec_param_enc(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_ec_paramgen_curve_nid(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_ecdh_cofactor(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_ec_kdf_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_rsa_padding_mode(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_rsa_pss_saltlen(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_hkdf_mode(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function fix_cipher(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
 function get_cipher_name( cipher : Pointer):PUTF8Char;
 function get_cipher_by_name(libctx : POSSL_LIB_CTX;const name : PUTF8Char):Pointer;
 function evp_pkey_ctx_ctrl_to_param( pctx : PEVP_PKEY_CTX; keytype, optype, cmd, p1 : integer; p2 : Pointer):integer;
  function evp_pkey_ctx_get_params_to_ctrl( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
function evp_pkey_ctx_ctrl_str_to_param(pctx : PEVP_PKEY_CTX;const name, value : PUTF8Char):integer;



var
  evp_pkey_ctx_translations: array of translation_st;

implementation


uses
   OpenSSL3.common, OpenSSL3.Err, openssl3.crypto.evp, openssl3.crypto.params,
   openssl3.crypto.bn.bn_lib, openssl3.crypto.mem, openssl3.crypto.o_str,
   openssl3.crypto.evp.pmeth_lib, openssl3.crypto.params_from_text,
   openssl3.crypto.ec.ec_key, openssl3.crypto.evp.p_lib, openssl3.crypto.dh.dh_key,
   openssl3.crypto.bn.bn_ctx, openssl3.crypto.ffc.ffc_dh,
   openssl3.crypto.rsa.rsa_lib, openssl3.crypto.dh.dh_lib,
   openssl3.crypto.dh.dh_group_params , openssl3.crypto.ec.ec_lib,
   openssl3.crypto.dsa.dsa_lib, openssl3.crypto.ec.ec_oct,
   openssl3.crypto.evp.names,  openssl3.crypto.dh.dh_support,
   openssl3.crypto.bio.bio_print,
   openssl3.crypto.objects.obj_dat, openssl3.crypto.evp.evp_lib,
   openssl3.crypto.ec.ec_support, openssl3.crypto.evp.p_legacy;

function evp_pkey_ctx_ctrl_str_to_param(pctx : PEVP_PKEY_CTX;const name, value : PUTF8Char):integer;
var
    ctx         : translation_ctx_st;
    tmpl        : translation_st;
    translation : Ptranslation_st;
    params      : array[0..1] of TOSSL_PARAM;
    keytype,
    optype,
    ret         : integer;
    fixup       : Tfixup_args_fn;
    label _break;
begin
    FillChar(ctx, SizeOf(translation_ctx_st), 0);
    FillChar(tmpl, SizeOf(translation_st), 0);
    translation := nil;
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;

    keytype := pctx.legacy_keytype;
    optype := get_result(pctx.operation = 0 , -1 , pctx.operation);
    fixup := default_fixup_args;
    tmpl.action_type := _SET;
    tmpl.keytype1 := keytype; tmpl.keytype2 := keytype;
    tmpl.optype := optype;
    tmpl.ctrl_str := name;
    tmpl.ctrl_hexstr := name;
    translation := lookup_evp_pkey_ctx_translation(@tmpl);
    if translation <> nil then begin
        if Assigned(translation.fixup_args) then
            fixup := translation.fixup_args;
        ctx.action_type := translation.action_type;
        ctx.ishex := int(tmpl.ctrl_hexstr <> nil);
    end
    else begin
        { String controls really only support setting }
        ctx.action_type := _SET;
    end;
    ctx.ctrl_str := name;
    ctx.p1 := int(Length(value));
    ctx.p2 := PUTF8Char( value);
    ctx.pctx := pctx;
    ctx.params := @params;
    ret := fixup(PRE_CTRL_STR_TO_PARAMS, translation, @ctx);
    if ret > 0 then begin
        case ctx.action_type of

        GET:
            {
             * this is dead code, but must be present, or some compilers
             * will complain
             }
            goto _break;
        _SET:
            ret := evp_pkey_ctx_set_params_strict(pctx, ctx.params);
            //break;
        else
            { fixup_args is expected to make sure this is dead code }
            goto _break;
        end;
    end;
_break:
    if ret > 0 then
       ret := fixup(POST_CTRL_STR_TO_PARAMS, translation, @ctx);
    cleanup_translation_ctx(CLEANUP_CTRL_STR_TO_PARAMS, translation, @ctx);
    Result := ret;
end;



function evp_pkey_ctx_get_params_to_ctrl( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
begin
    Result := evp_pkey_ctx_setget_params_to_ctrl(ctx, GET, params);
end;

function evp_pkey_ctx_ctrl_to_param( pctx : PEVP_PKEY_CTX; keytype, optype, cmd, p1 : integer; p2 : Pointer):integer;
var
    ctx         : translation_ctx_st;
    tmpl        : translation_st;
    translation : Ptranslation_st;
    params      : array[0..1] of TOSSL_PARAM;
    ret         : integer;
    fixup       : Tfixup_args_fn;
begin
    FillChar(ctx, SizeOf(ctx), 0);
    FillChar(tmpl, SizeOf(tmpl), 0);
    translation := nil;
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;
    fixup := default_fixup_args;
    if keytype = -1 then
       keytype := pctx.legacy_keytype;
    tmpl.ctrl_num := cmd;
    tmpl.keytype1 := keytype; tmpl.keytype2 := keytype;
    tmpl.optype := optype;
    translation := lookup_evp_pkey_ctx_translation(@tmpl);
    if translation = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        Exit(-2);
    end;
    if (pctx.pmeth <> nil)
         and  (pctx.pmeth.pkey_id <> translation.keytype1)
         and  (pctx.pmeth.pkey_id <> translation.keytype2) then
         Exit(-1);
    if Assigned(translation.fixup_args) then
       fixup := translation.fixup_args;
    ctx.action_type := translation.action_type;
    ctx.ctrl_cmd := cmd;
    ctx.p1 := p1;
    ctx.p2 := p2;
    ctx.pctx := pctx;
    ctx.params := @params;
    ret := fixup(PRE_CTRL_TO_PARAMS, translation, @ctx);
    if ret > 0 then
    begin
        case ctx.action_type of

        GET:
            ret := evp_pkey_ctx_get_params_strict(pctx, ctx.params);

        _SET:
            ret := evp_pkey_ctx_set_params_strict(pctx, ctx.params);
            //break;
        else
            { fixup_args is expected to make sure this is dead code }
            begin
               // break;
            end;
        end;
    end;
    {
     * In POST, we pass the return value as p1, allowing the fixup_args
     * function to affect it by changing its value.
     }
    if ret > 0 then
    begin
        ctx.p1 := ret;
        fixup(POST_CTRL_TO_PARAMS, translation, @ctx);
        ret := ctx.p1;
    end;
    cleanup_translation_ctx(POST_CTRL_TO_PARAMS, translation, @ctx);
    Result := ret;
end;

function get_cipher_by_name(libctx : POSSL_LIB_CTX;const name : PUTF8Char):Pointer;
begin
    Result := evp_get_cipherbyname_ex(libctx, name);
end;




function get_cipher_name( cipher : Pointer):PUTF8Char;
begin
    Result := EVP_CIPHER_get0_name(cipher);
end;


function fix_cipher(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
    Exit(fix_cipher_md(state, translation, ctx,
                         get_cipher_name, get_cipher_by_name));
end;


function fix_hkdf_mode(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
const // 1d arrays
  str_value_map : array[0..2] of TOSSL_ITEM = (
    (id: EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND; ptr: 'EXTRACT_AND_EXPAND'),
    (id: EVP_KDF_HKDF_MODE_EXTRACT_ONLY;       ptr: 'EXTRACT_ONLY'),
    (id: EVP_KDF_HKDF_MODE_EXPAND_ONLY;        ptr: 'EXPAND_ONLY')
  );
var
  ret : integer;
  i : size_t;
begin
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if ( (ctx.action_type = _SET)  and  (state = PRE_CTRL_TO_PARAMS) )  or
       ( (ctx.action_type = GET )  and  (state = POST_PARAMS_TO_CTRL) ) then
    begin
        for i := 0 to Length(str_value_map)-1 do
        begin
            if ctx.p1 = int (str_value_map[i].id) then
                break;
        end;
        if i = Length(str_value_map) then
            Exit(0);
        ctx.p2 := str_value_map[i].ptr;
        ctx.p1 := StrLen(PUTF8Char(ctx.p2));
    end;
    ret := default_fixup_args(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if ( (ctx.action_type = _SET)  and  (state = PRE_PARAMS_TO_CTRL) )  or
       ( (ctx.action_type = GET )  and  (state = POST_CTRL_TO_PARAMS) ) then
    begin
        for i := 0 to Length(str_value_map)-1 do
        begin
            if strcmp(ctx.p2, str_value_map[i].ptr) = 0 then
                break;
        end;
        if i = Length(str_value_map) then
            Exit(0);
        if state = POST_CTRL_TO_PARAMS then
           ret := str_value_map[i].id
        else
            ctx.p1 := str_value_map[i].id;
        ctx.p2 := nil;
    end;
    Result := 1;
end;




function fix_rsa_pss_saltlen(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
const // 1d arrays
  str_value_map : array[0..2] of TOSSL_ITEM = (
    (id: uint32(RSA_PSS_SALTLEN_DIGEST); ptr: 'digest'),
    (id: uint32(RSA_PSS_SALTLEN_MAX)   ; ptr: 'max'),
    (id: uint32(RSA_PSS_SALTLEN_AUTO)  ; ptr: 'auto')
  );
var
  ret : integer;
  i, sz : size_t;
  val : integer;
begin
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = GET) then
    begin
        {
         * EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN returns the saltlen by filling
         * in the int pointed at by p2.  This is potentially as weird as
         * the way EVP_PKEY_CTRL_GET_RSA_PADDING works, except that saltlen
         * might be a negative value, so it wouldn't work as a legitimate
         * return value.
         * In any case, we must therefore remember |ctx.p2|, then make
         * |ctx.p2| point at a buffer to be filled in with the name, and
         * |ctx.p1| with its size.  default_fixup_args() will take care
         * of the rest for us, along with the POST_CTRL_TO_PARAMS  and  GET
         * code section further down.
         }
        ctx.orig_p2 := ctx.p2;
        ctx.p2 := @ctx.name_buf;
        ctx.p1 := sizeof(ctx.name_buf);
    end
    else
    if ( (ctx.action_type = _SET)  and  (state = PRE_CTRL_TO_PARAMS) )  or
       ( (ctx.action_type = GET )  and  (state = POST_PARAMS_TO_CTRL) ) then
    begin
        for i := 0 to Length(str_value_map)-1 do
        begin
            if ctx.p1 = int (str_value_map[i].id) then
               break;
        end;
        if i = Length(str_value_map) then
        begin
            BIO_snprintf(ctx.name_buf, sizeof(ctx.name_buf), '%d', [ctx.p1]);
        end
        else
        begin
            { This won't truncate but it will quiet static analysers }
            strncpy(ctx.name_buf, str_value_map[i].ptr, sizeof(ctx.name_buf) - 1);
            sz := sizeof(ctx.name_buf);
            ctx.name_buf[sz - 1] := #0;
        end;
        ctx.p2 := @ctx.name_buf;
        ctx.p1 := StrLen(PUTF8Char(ctx.p2));
    end;
    ret := default_fixup_args(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if ( (ctx.action_type = _SET)  and  (state = PRE_PARAMS_TO_CTRL)) or
       ( (ctx.action_type = GET )  and  (state = POST_CTRL_TO_PARAMS) )then
    begin
        for i := 0 to Length(str_value_map)-1 do
        begin
            if strcmp(ctx.p2, str_value_map[i].ptr) = 0 then
                break;
        end;
        i := get_result(Length(str_value_map)>0 , StrToInt(PUTF8Char(ctx.p2))
                                             , int (str_value_map[i].id));
        val := i;
        if state = POST_CTRL_TO_PARAMS then
        begin
            {
             * EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN weirdness explained further
             * up
             }
            PInteger(ctx.orig_p2)^ := val;
        end
        else
        begin
            ctx.p1 := val;
        end;
        ctx.p2 := nil;
    end;
    Result := ret;
end;




function fix_rsa_padding_mode(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
const // 1d arrays
  str_value_map : array[0..6] of TOSSL_ITEM = (
    (id :  RSA_PKCS1_PADDING;      ptr:'pkcs1'  ),
    (id :  RSA_NO_PADDING;         ptr:'none'   ),
    (id :  RSA_PKCS1_OAEP_PADDING; ptr:'oaep'   ),
    (id :  RSA_PKCS1_OAEP_PADDING; ptr:'oeap'   ),
    (id :  RSA_X931_PADDING;       ptr:'x931'   ),
    (id :  RSA_PKCS1_PSS_PADDING;  ptr:'pss'    ),
    (* Special case; will pass directly as an integer *)
    (id :  RSA_PKCS1_WITH_TLS_PADDING;   ptr: nil)
);

var
  ret : integer;
  i : size_t;
begin
{$POINTERMATH ON}
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = GET) then
    begin
        {
         * EVP_PKEY_CTRL_GET_RSA_PADDING returns the padding mode in the
         * weirdest way for a ctrl.  Instead of doing like all other ctrls
         * that return a simple, i.e. just have that as a return value,
         * this particular ctrl treats p2 as the address for the int to be
         * returned.  We must therefore remember |ctx.p2|, then make
         * |ctx.p2| point at a buffer to be filled in with the name, and
         * |ctx.p1| with its size.  default_fixup_args() will take care
         * of the rest for us, along with the POST_CTRL_TO_PARAMS  and  GET
         * code section further down.
         }
        ctx.orig_p2 := ctx.p2;
        ctx.p2 := @ctx.name_buf;
        ctx.p1 := sizeof(ctx.name_buf);
    end
    else
    if (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = _SET) then
    begin
        {
         * Ideally, we should use utf8 strings for the diverse padding modes.
         * We only came here because someone called EVP_PKEY_CTX_ctrl(),
         * though, and since that can reasonably be seen as legacy code
         * that uses the diverse RSA macros for the padding mode, and we
         * know that at least our providers can handle the numeric modes,
         * we take the cheap route for now.
         *
         * The other solution would be to match |ctx.p1| against entries
         * in str_value_map and pass the corresponding string.  However,
         * since we don't have a string for RSA_PKCS1_WITH_TLS_PADDING,
         * we have to do this same hack at least for that one.
         *
         * Since the 'official' data type for the RSA padding mode is utf8
         * string, we cannot count on default_fixup_args().  Instead, we
         * build the OSSL_PARAM item ourselves and return immediately.
         }
        ctx.params[0] := OSSL_PARAM_construct_int(translation.param_key,
                                                  @ctx.p1);
        Exit(1);
    end
    else
    if (state = POST_PARAMS_TO_CTRL)  and  (ctx.action_type = GET) then
    begin
        {
         * The EVP_PKEY_CTX_get_params() caller may have asked for a utf8
         * string, or may have asked for an integer of some sort.  If they
         * ask for an integer, we respond directly.  If not, we translate
         * the response from the ctrl function into a string.
         }
        case ctx.params.data_type of
        OSSL_PARAM_INTEGER:
            Exit(OSSL_PARAM_get_int(ctx.params, @ctx.p1));
        OSSL_PARAM_UNSIGNED_INTEGER:
            Exit(OSSL_PARAM_get_uint(ctx.params, Puint32(@ctx.p1)));
        else
            begin
              //
            end;
        end;
        for i := 0 to Length(str_value_map)-1 do
        begin
            if ctx.p1 = int (str_value_map[i].id) then
               break;
        end;
        if i = Length(str_value_map ) then
        begin
            ERR_raise_data(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE,
                          Format('[action:%d, state:%d] padding number %d',
                           [Int(ctx.action_type), Int(state), ctx.p1]));
            Exit(-2);
        end;
        {
         * If we don't have a string, we can't do anything.  The caller
         * should have asked for a number...
         }
        if str_value_map[i].ptr = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
            Exit(-2);
        end;
        ctx.p2 := str_value_map[i].ptr;
        ctx.p1 := StrLen(PUTF8Char(ctx.p2));
    end;
    ret := default_fixup_args(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if ( (ctx.action_type = _SET)  and  (state = PRE_PARAMS_TO_CTRL))  or
       ( (ctx.action_type = GET )  and  (state = POST_CTRL_TO_PARAMS)) then
    begin
        for i := 0 to Length(str_value_map)-1 do
        begin
            if strcmp(ctx.p2, str_value_map[i].ptr) = 0 then
                break;
        end;
        if i = Length(str_value_map ) then
        begin
            ERR_raise_data(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE,
                          Format('[action:%d, state:%d] padding name %s',
                           [Int(ctx.action_type), Int(state), ctx.p1]));
            ctx.p1 := -2; ret := -2;
        end
        else
        if (state = POST_CTRL_TO_PARAMS) then
        begin
            { EVP_PKEY_CTRL_GET_RSA_PADDING weirdness explained further up }
            PInteger(ctx.orig_p2)^ := str_value_map[i].id;
        end
        else
        begin
            ctx.p1 := str_value_map[i].id;
        end;
        ctx.p2 := nil;
    end;
    Result := ret;
 {$POINTERMATH OFF}
end;






function fix_ec_kdf_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
const // 1d arrays
  kdf_type_map : array[0..2] of kdf_type_map_st = (
    (kdf_type_num: EVP_PKEY_ECDH_KDF_NONE;  kdf_type_str: ''),
    (kdf_type_num: EVP_PKEY_ECDH_KDF_X9_63; kdf_type_str: OSSL_KDF_NAME_X963KDF),
    (kdf_type_num: 0;                       kdf_type_str: nil)
  );
begin
    Result := fix_kdf_type(state, translation, ctx, @kdf_type_map);
end;

function fix_ecdh_cofactor(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    {
     * The EVP_PKEY_CTRL_EC_ECDH_COFACTOR ctrl command is a bit special, in
     * that it's used both for setting a value, and for getting it, all
     * depending on the value if |ctx.p1|; if |ctx.p1| is -2, the backend is
     * supposed to place the current cofactor mode in |ctx.p2|, and if not,
     * |ctx.p1| is interpreted as the new cofactor mode.
     }
    ret := 0;
    if state = PRE_CTRL_TO_PARAMS then
    begin
        {
         * The initial value for |ctx.action_type| must be zero.
         * evp_pkey_ctrl_to_params() takes it from the translation item.
         }
        if not ossl_assert(ctx.action_type = NONE) then
            Exit(0);
        { The action type depends on the value of ctx.p1 }
        if ctx.p1 = -2 then
           ctx.action_type := GET
        else
            ctx.action_type := _SET;
    end
    else
    if (state = PRE_CTRL_STR_TO_PARAMS) then
    begin
        ctx.action_type := _SET;
    end
    else
    if (state = PRE_PARAMS_TO_CTRL) then
    begin
        { The initial value for |ctx.action_type| must not be zero. }
        if not ossl_assert(ctx.action_type <> NONE) then
            Exit(0);
    end;
    ret := default_check(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = _SET) then
    begin
        if (ctx.p1 < -1)  or  (ctx.p1 > 1) then
        begin
            { Uses the same return value of pkey_ec_ctrl() }
            Exit(-2);
        end;
    end;
    ret := default_fixup_args(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if (state = POST_CTRL_TO_PARAMS)  and  (ctx.action_type = GET) then
    begin
        if (ctx.p1 < 0)  or  (ctx.p1 > 1) then
        begin
            {
             * The provider should return either 0 or 1, any other value is a
             * provider error.
             }
            ctx.p1 := -1; ret := -1;
        end;
    end
    else
    if (state = PRE_PARAMS_TO_CTRL)  and  (ctx.action_type = GET) then
    begin
        ctx.p1 := -2;
    end;
    Result := ret;
end;



function fix_ec_paramgen_curve_nid(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    { This is currently only settable }
    if ctx.action_type <> _SET then
       Exit(0);
    if state = PRE_CTRL_TO_PARAMS then
    begin
        ctx.p2 := PUTF8Char(  OBJ_nid2sn(ctx.p1));
        ctx.p1 := 0;
    end;
    ret := default_fixup_args(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if state = PRE_PARAMS_TO_CTRL then
    begin
        ctx.p1 := OBJ_sn2nid(ctx.p2);
        ctx.p2 := nil;
    end;
    Result := ret;
end;




function fix_ec_param_enc(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
  label _end;
begin
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    { This is currently only settable }
    if ctx.action_type <> _SET then
       Exit(0);
    if state = PRE_CTRL_TO_PARAMS then
    begin
        case ctx.p1 of
            OPENSSL_EC_EXPLICIT_CURVE:
                PUTF8Char(ctx.p2) := OSSL_PKEY_EC_ENCODING_EXPLICIT;
                //break;
            OPENSSL_EC_NAMED_CURVE:
                PUTF8Char(ctx.p2) := OSSL_PKEY_EC_ENCODING_GROUP;
                //break;
            else
            begin
                ret := -2;
                goto _end ;
            end;
        end;
        ctx.p1 := 0;
    end;
    ret := default_fixup_args(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if state = PRE_PARAMS_TO_CTRL then
    begin
        if strcmp(ctx.p2, OSSL_PKEY_EC_ENCODING_EXPLICIT) = 0 then
            ctx.p1 := OPENSSL_EC_EXPLICIT_CURVE
        else if (strcmp(ctx.p2, OSSL_PKEY_EC_ENCODING_GROUP) = 0) then
            ctx.p1 := OPENSSL_EC_NAMED_CURVE
        else
            ctx.p1 := -2; ret := -2;
        ctx.p2 := nil;
    end;
 _end:
    if ret = -2 then
       ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
    Result := ret;
end;




function fix_dh_nid(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    { This is only settable }
    if ctx.action_type <> _SET then Exit(0);
    if state = PRE_CTRL_TO_PARAMS then
    begin
        ctx.p2 := PUTF8Char(ossl_ffc_named_group_get_name
                          (ossl_ffc_uid_to_dh_named_group(ctx.p1)));
        if (ctx.p2 = nil) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE);
            Exit(0);
        end;
        ctx.p1 := 0;
    end;
    Result := default_fixup_args(state, translation, ctx);
end;




function fix_dh_nid5114(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    { This is only settable }
    if ctx.action_type <> _SET then
       Exit(0);
    case state of
        PRE_CTRL_TO_PARAMS:
        begin
            ctx.p2 := PUTF8Char(ossl_ffc_named_group_get_name
                            (ossl_ffc_uid_to_dh_named_group(ctx.p1)));
            if ctx.p2 = nil  then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE);
                Exit(0);
            end;
            ctx.p1 := 0;
        end;
        PRE_CTRL_STR_TO_PARAMS:
        begin
            if ctx.p2 = nil then Exit(0);
            ctx.p2 := PUTF8Char(ossl_ffc_named_group_get_name
                             (ossl_ffc_uid_to_dh_named_group(StrToInt(PUTF8Char(ctx.p2)))));
            if (ctx.p2 = nil)  then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE);
                Exit(0);
            end;
            ctx.p1 := 0;
        end;
        else
        begin
          //
        end;
    end;
    Result := default_fixup_args(state, translation, ctx);
end;




function fix_dh_paramgen_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    ret := default_check(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    { This is only settable }
    if ctx.action_type <> _SET then
       Exit(0);
    if state = PRE_CTRL_STR_TO_PARAMS then
    begin
        ctx.p2 := ossl_dh_gen_type_id2name(StrToInt(PUTF8Char(ctx.p2)));
        ctx.p1 := StrLen(PUTF8Char(ctx.p2));
    end;
    Result := default_fixup_args(state, translation, ctx);
end;




function fix_oid(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    ret := default_check(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if ( (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = _SET) )  or
       ( (state = POST_PARAMS_TO_CTRL)  and (ctx.action_type = GET) ) then
    begin
        {
         * We're translating from ctrl to params and setting the OID, or
         * we're translating from params to ctrl and getting the OID.
         * Either way, |ctx.p2| points at an ASN1_OBJECT, and needs to have
         * that replaced with the corresponding name.
         * default_fixup_args() will then be able to convert that to the
         * corresponding OSSL_PARAM.
         }
        OBJ_obj2txt(ctx.name_buf, sizeof(ctx.name_buf), ctx.p2, 0);
        ctx.p2 := PUTF8Char(@ctx.name_buf);
        ctx.p1 := 0; { let default_fixup_args() figure out the length }
    end;
    ret := default_fixup_args(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if ( (state = PRE_PARAMS_TO_CTRL)  and  (ctx.action_type = _SET) )   or
       ( (state = POST_CTRL_TO_PARAMS)  and (ctx.action_type = GET) ) then
    begin
        {
         * We're translating from ctrl to params and setting the OID name,
         * or we're translating from params to ctrl and getting the OID
         * name.  Either way, default_fixup_args() has placed the OID name
         * in |ctx.p2|, all we need to do now is to replace that with the
         * corresponding ASN1_OBJECT.
         }
        ctx.p2 := PASN1_OBJECT(OBJ_txt2obj(ctx.p2, 0));
    end;
    Result := ret;
end;




function get_md_by_name(libctx : POSSL_LIB_CTX;const name : PUTF8Char):Pointer;
begin
    Result := evp_get_digestbyname_ex(libctx, name);
end;



function get_md_name( md : Pointer):PUTF8Char;
begin
    Result := EVP_MD_get0_name(md);
end;




function fix_cipher_md(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; get_name : Tget_name_func; get_algo_by_name : Tget_algo_by_name_func):integer;
var
  ret : integer;
begin
    ret := 1;
    ret := default_check(state, translation, ctx);
    if ret  <= 0 then
        Exit(ret);
    if (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = GET) then
    begin
        {
         * |ctx.p2| contains the address to an EVP_CIPHER or EVP_MD pointer
         * to be filled in.  We need to remember it, then make |ctx.p2|
         * point at a buffer to be filled in with the name, and |ctx.p1|
         * with its size.  default_fixup_args() will take care of the rest
         * for us.
         }
        ctx.orig_p2 := ctx.p2;
        ctx.p2 := @ctx.name_buf;
        ctx.p1 := sizeof(ctx.name_buf);
    end
    else
    if (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = _SET) then
    begin
        {
         * In different parts of OpenSSL, this ctrl command is used
         * differently.  Some calls pass a NID as p1, others pass an
         * EVP_CIPHER pointer as p2...
         }
        if (ctx.p2 = nil) then
          ctx.p2 := PUTF8Char(OBJ_nid2sn(ctx.p1))
        else
          ctx.p2 := PUTF8Char(get_name(ctx.p2));
        ctx.p1 := StrLen(PUTF8Char(ctx.p2));
    end
    else
    if (state = POST_PARAMS_TO_CTRL)  and  (ctx.action_type = GET) then
    begin
        if ctx.p2 = nil then
           ctx.p2 := PUTF8Char('')
        else
           ctx.p2 := PUTF8Char(get_name(ctx.p2));
        ctx.p1 := StrLen(PUTF8Char(ctx.p2));
    end;
    ret := default_fixup_args(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if (state = POST_CTRL_TO_PARAMS)  and  (ctx.action_type = GET) then
    begin
        {
         * Here's how we re-use |ctx.orig_p2| that was set in the
         * PRE_CTRL_TO_PARAMS state above.
         }
        PPointer( ctx.orig_p2)^ := Pointer(get_algo_by_name(ctx.pctx.libctx, ctx.p2));
        ctx.p1 := 1;
    end
    else
    if (state = PRE_PARAMS_TO_CTRL)  and  (ctx.action_type = _SET) then
    begin
        ctx.p2 := Pointer( get_algo_by_name(ctx.pctx.libctx, ctx.p2));
        ctx.p1 := 0;
    end;
    Result := ret;
end;




function fix_md(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
    Exit(fix_cipher_md(state, translation, ctx,
                         get_md_name, get_md_by_name));
end;


function fix_kdf_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; kdf_type_map : Pkdf_type_map_st):integer;
var
  ret : integer;
  label _end;
begin
    {
     * The EVP_PKEY_CTRL_DH_KDF_TYPE ctrl command is a bit special, in
     * that it's used both for setting a value, and for getting it, all
     * depending on the value if |p1|; if |p1| is -2, the backend is
     * supposed to place the current kdf type in |p2|, and if not, |p1|
     * is interpreted as the new kdf type.
     }
    ret := 0;
    ret := default_check(state, translation, ctx );
    if ret <= 0 then
        Exit(ret);
    if state = PRE_CTRL_TO_PARAMS then
    begin
        {
         * In |translations|, the initial value for |ctx.action_type| must
         * be NONE.
         }
        if not ossl_assert(ctx.action_type = NONE) then
            Exit(0);
        { The action type depends on the value of *p1 }
        if ctx.p1 = -2 then begin
            {
             * The OSSL_PARAMS getter needs space to store a copy of the kdf
             * type string.  We use |ctx.name_buf|, which has enough space
             * allocated.
             *
             * (this wouldn't be needed if the OSSL_xxx_PARAM_KDF_TYPE
             * had the data type OSSL_PARAM_UTF8_PTR)
             }
            ctx.p2 := @ctx.name_buf;
            ctx.p1 := sizeof(ctx.name_buf);
            ctx.action_type := GET;
        end
        else
        begin
            ctx.action_type := _SET;
        end;
    end;
    ret := default_check(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if ( (state = PRE_CTRL_TO_PARAMS)  and  (ctx.action_type = _SET) )  or
       ( (state = POST_PARAMS_TO_CTRL)  and (ctx.action_type = GET) ) then
    begin
        ret := -2;
        { Convert KDF type numbers to strings }
        while kdf_type_map.kdf_type_str <> nil do
        begin
            if ctx.p1 = kdf_type_map.kdf_type_num then
            begin
                ctx.p2 := PUTF8Char(  kdf_type_map.kdf_type_str);
                ret := 1;
                break;
            end;
            Inc(kdf_type_map);
        end;
        if ret <= 0 then goto _end ;
        ctx.p1 := strlen(PUTF8Char(ctx.p2));
    end;
    ret := default_fixup_args(state, translation, ctx);
    if ret <= 0 then
        Exit(ret);
    if ( (state = POST_CTRL_TO_PARAMS)  and  (ctx.action_type = GET) ) or
       ( (state = PRE_PARAMS_TO_CTRL )  and  (ctx.action_type = _SET) ) then
    begin
        ctx.p1 := -1; ret := -1;
        { Convert KDF type strings to numbers }
        while kdf_type_map.kdf_type_str <> nil do
        begin
            if strcasecmp(ctx.p2, kdf_type_map.kdf_type_str) = 0 then
            begin
                ctx.p1 := kdf_type_map.kdf_type_num;
                ret := 1;
                break;
            end;
            Inc(kdf_type_map);
        end;
        ctx.p2 := nil;
    end
    else
    if (state = PRE_PARAMS_TO_CTRL)  and  (ctx.action_type = GET)then
    begin
        ctx.p1 := -2;
    end;
 _end:
    Result := ret;
end;




function fix_dh_kdf_type(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
const // 1d arrays
  kdf_type_map : array[0..2] of kdf_type_map_st = (
    (kdf_type_num: EVP_PKEY_DH_KDF_NONE;  kdf_type_str: ''),
    (kdf_type_num: EVP_PKEY_DH_KDF_X9_42; kdf_type_str: OSSL_KDF_NAME_X942KDF_ASN1),
    (kdf_type_num: 0;                     kdf_type_str: nil)
  );
begin
    Result := fix_kdf_type(state, translation, ctx, @kdf_type_map);
end;



function fix_distid_len(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  ret : integer;
begin
    ret := default_fixup_args(state, translation, ctx);
    if ret > 0 then
    begin
        ret := 0;
        if (state = POST_CTRL_TO_PARAMS)     or
           (state = POST_CTRL_STR_TO_PARAMS) and  (ctx.action_type = GET)  then
        begin
            Psize_t (ctx.p2)^ := ctx.sz;
            ret := 1;
        end;
    end;
    Result := ret;
end;

function get_translation_st(
    action_type: Taction;
    keytype1: Integer;
    keytype2: Integer;
    optype: Integer;
    ctrl_num: Integer;
    ctrl_str: PUTF8Char;
    ctrl_hexstr: PUTF8Char;
    param_key: PUTF8Char;
    param_data_type: Cardinal;
    fixup_args: Tfixup_args_fn
  ): translation_st;
begin
    Result.action_type     := action_type;
    Result.keytype1        :=  keytype1;
    Result.keytype2        :=  keytype2;
    Result.optype          :=  optype;
    Result.ctrl_num        :=  ctrl_num;
    Result.ctrl_str        :=  ctrl_str;
    Result.ctrl_hexstr     :=  ctrl_hexstr;
    Result.param_key       :=  param_key;
    Result.param_data_type :=  param_data_type;
    Result.fixup_args      :=  fixup_args;
end;




function lookup_evp_pkey_ctx_translation( tmpl : Ptranslation_st):Ptranslation_st;
begin
    Exit(lookup_translation(tmpl, @evp_pkey_ctx_translations,
                              Length(evp_pkey_ctx_translations)));
end;




function evp_pkey_ctx_setget_params_to_ctrl( pctx : PEVP_PKEY_CTX; action_type: Taction; params : POSSL_PARAM):integer;
var
  keytype,
  optype      : integer;
  ctx         : translation_ctx_st;
  tmpl        : translation_st;
  translation : Ptranslation_st;
  fixup       : Tfixup_args_fn;
  ret         : integer;
begin
    keytype := pctx.legacy_keytype;
    optype := get_result(pctx.operation = 0 , -1 , pctx.operation);
    while (params <> nil)  and  (params.key <> nil) do
    begin
        FillChar(ctx, SizeOf(ctx), 0);
        FillChar(tmpl, SizeOf(tmpl), 0);
        translation := nil;
        fixup := default_fixup_args;
        tmpl.action_type := action_type;
        tmpl.keytype1 := keytype; tmpl.keytype2 := keytype;
        tmpl.optype := optype;
        tmpl.param_key := params.key;
        translation := lookup_evp_pkey_ctx_translation(@tmpl);
        if translation <> nil then
        begin
            if Assigned(translation.fixup_args) then
                fixup := translation.fixup_args;
            ctx.action_type := translation.action_type;
        end;
        ctx.pctx := pctx;
        ctx.params := params;
        ret := fixup(PRE_PARAMS_TO_CTRL, translation, @ctx);
        if (ret > 0)  and  (action_type <> NONE) then
            ret := EVP_PKEY_CTX_ctrl(pctx, keytype, optype,
                                    ctx.ctrl_cmd, ctx.p1, ctx.p2);
        {
         * In POST, we pass the return value as p1, allowing the fixup_args
         * function to put it to good use, or maybe affect it.
         }
        if ret > 0 then
        begin
            ctx.p1 := ret;
            fixup(POST_PARAMS_TO_CTRL, translation, @ctx);
            ret := ctx.p1;
        end;
        cleanup_translation_ctx(CLEANUP_PARAMS_TO_CTRL, translation, @ctx);
        if ret <= 0 then Exit(0);
        Inc(params);
    end;
    Result := 1;
end;

function evp_pkey_ctx_set_params_to_ctrl(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
begin
    Result := evp_pkey_ctx_setget_params_to_ctrl(ctx, _SET, POSSL_PARAM(params));
end;






function cleanup_translation_ctx(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
    if ctx.allocated_buf <> nil then OPENSSL_free(ctx.allocated_buf);
    ctx.allocated_buf := nil;
    Result := 1;
end;

function get_rsa_payload_exponent(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; exponentnum : size_t):integer;
var
  r : PRSA;
  bn : PBIGNUM;
  pnum : size_t;
  exps, coeffs : array[0..9] of PBIGNUM;
begin
    r := EVP_PKEY_get0_RSA(ctx.p2);
    bn := nil;
    case exponentnum of
        0:
            bn := RSA_get0_dmp1(r);
        1:
            bn := RSA_get0_dmq1(r);
        else
        begin
            pnum := RSA_get_multi_prime_extra_count(r);
            if (exponentnum - 2 < pnum )    and
               (RSA_get0_multi_prime_crt_params(r, @exps, @coeffs)>0) then
                bn := exps[exponentnum - 2];
        end;

    end;
    Result := get_payload_bn(state, translation, ctx, bn);
end;



function get_rsa_payload_factor(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; factornum : size_t):integer;
var
  r : PRSA;
  bn : PBIGNUM;
  pnum : size_t;
  factors : array[0..9] of PBIGNUM;
begin
    r := EVP_PKEY_get0_RSA(ctx.p2);
    bn := nil;
    case factornum of
      0:
          bn := RSA_get0_p(r);

      1:
          bn := RSA_get0_q(r);

      else
      begin
          pnum := RSA_get_multi_prime_extra_count(r);
          if (factornum - 2 < pnum) and
             (RSA_get0_multi_prime_factors(r, @factors)>0) then
              bn := factors[factornum - 2];
      end;

    end;
    Result := get_payload_bn(state, translation, ctx, bn);
end;



function get_payload_bn(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st;bn : PBIGNUM):integer;
begin
    if bn = nil then
       Exit(0);
    if ctx.params.data_type <> OSSL_PARAM_UNSIGNED_INTEGER then
       Exit(0);
    ctx.p2 := PBIGNUM (bn);
    Result := default_fixup_args(state, translation, ctx);
end;



function get_rsa_payload_coefficient(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st; coefficientnum : size_t):integer;
var
  r : PRSA;
  bn : PBIGNUM;
  pnum : size_t;
  exps, coeffs : array[0..9] of PBIGNUM;
begin
    r := EVP_PKEY_get0_RSA(ctx.p2);
    bn := nil;
    case coefficientnum of
        0:
            bn := RSA_get0_iqmp(r);

        else
        begin
            pnum := RSA_get_multi_prime_extra_count(r);

            if (coefficientnum - 1 < pnum)  and
                ( RSA_get0_multi_prime_crt_params(r, @exps, @coeffs)>0) then
                bn := coeffs[coefficientnum - 1];
        end;

    end;
    Result := get_payload_bn(state, translation, ctx, bn);
end;




function get_payload_int(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st;const val : integer):integer;
begin
    if ctx.params.data_type <> OSSL_PARAM_INTEGER then Exit(0);
    ctx.p1 := val;
    ctx.p2 := nil;
    Result := default_fixup_args(state, translation, ctx);
end;


function get_ec_decoded_from_explicit_params(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  val : integer;

  pkey : PEVP_PKEY;
begin
    val := 0;
    pkey := ctx.p2;
    case (EVP_PKEY_base_id(pkey)) of
{$IFNDEF OPENSSL_NO_EC}
        EVP_PKEY_EC:
        begin
            val := EC_KEY_decoded_from_explicit_params(EVP_PKEY_get0_EC_KEY(pkey));
            if val < 0 then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
                Exit(0);
            end;
        end;
{$ENDIF}
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE);
            Exit(0);
        end;
    end;
    Result := get_payload_int(state, translation, ctx, val);
end;


function get_rsa_payload_c9(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  9 - 1));
end;


function get_rsa_payload_c8(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  8 - 1));
end;


function get_rsa_payload_c7(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  7 - 1));
end;

function get_rsa_payload_c6(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  6 - 1));
end;


function get_rsa_payload_c5(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  5 - 1));
end;



function get_rsa_payload_c4(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  4 - 1));
end;

function get_rsa_payload_c3(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  3 - 1));
end;

function get_rsa_payload_c2(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  2 - 1));
end;


function get_rsa_payload_c1(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
	   Exit(0);
	Exit(get_rsa_payload_coefficient(state, translation, ctx,  1 - 1));
end;


function get_rsa_payload_f10(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 10 - 1);
end;


function get_rsa_payload_e10(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        10 - 1);
end;


function get_rsa_payload_f9(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 9 - 1);
end;


function get_rsa_payload_e9(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        9 - 1);
end;
function get_rsa_payload_f8(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 8 - 1);
end;


function get_rsa_payload_e8(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        8 - 1);
end;


function get_rsa_payload_f7(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 7 - 1);
end;


function get_rsa_payload_e7(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        7 - 1);
end;


function get_rsa_payload_f6(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 6 - 1);
end;


function get_rsa_payload_e6(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        6 - 1);
end;


function get_rsa_payload_f5(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 5 - 1);
end;


function get_rsa_payload_e5(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        5 - 1);
end;


function get_rsa_payload_f4(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 4 - 1);
end;


function get_rsa_payload_e4(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        4 - 1);
end;


function get_rsa_payload_f3(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 3 - 1);
end;


function get_rsa_payload_e3(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        3 - 1);
end;


function get_rsa_payload_f2(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 2 - 1);
end;


function get_rsa_payload_e2(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        2 - 1);
end;


function get_rsa_payload_f1(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
	if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then Exit(0);
	result := get_rsa_payload_factor(state, translation, ctx, 1 - 1);
end;


function get_rsa_payload_e1(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
   if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA then
      Exit(0);
   result := get_rsa_payload_exponent(state, translation, ctx,
                                        1 - 1);
end;


function get_rsa_payload_n(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  bn : PBIGNUM;
begin
    bn := nil;
    if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA  then
        Exit(0);
    bn := RSA_get0_n(EVP_PKEY_get0_RSA(ctx.p2));
    Result := get_payload_bn(state, translation, ctx, bn);
end;


function get_rsa_payload_e(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  bn : PBIGNUM;
begin
    bn := nil;
    if EVP_PKEY_get_base_id(ctx.p2)  <> EVP_PKEY_RSA then
        Exit(0);
    bn := RSA_get0_e(EVP_PKEY_get0_RSA(ctx.p2));
    Result := get_payload_bn(state, translation, ctx, bn);
end;


function get_rsa_payload_d(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  bn : PBIGNUM;
begin
    bn := nil;
    if EVP_PKEY_get_base_id(ctx.p2) <> EVP_PKEY_RSA  then
        Exit(0);
    bn := RSA_get0_d(EVP_PKEY_get0_RSA(ctx.p2));
    Result := get_payload_bn(state, translation, ctx, bn);
end;


function get_dh_dsa_payload_p(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  bn : PBIGNUM;

  pkey : PEVP_PKEY;
begin
    bn := nil;
    pkey := ctx.p2;
    case (EVP_PKEY_get_base_id(pkey)) of
{$IFNDEF OPENSSL_NO_DH}
    EVP_PKEY_DH:
        bn := DH_get0_p(EVP_PKEY_get0_DH(pkey));

{$ENDIF}
{$IFNDEF OPENSSL_NO_DSA}
    EVP_PKEY_DSA:
        bn := DSA_get0_p(EVP_PKEY_get0_DSA(pkey));

{$ENDIF}
    else
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE);
    end;
    Result := get_payload_bn(state, translation, ctx, bn);
end;


function get_dh_dsa_payload_q(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  bn : PBIGNUM;
begin
    bn := nil;
    case (EVP_PKEY_get_base_id(ctx.p2)) of
{$IFNDEF OPENSSL_NO_DH}
    EVP_PKEY_DH:
        bn := DH_get0_q(EVP_PKEY_get0_DH(ctx.p2));

{$ENDIF}
{$IFNDEF OPENSSL_NO_DSA}
    EVP_PKEY_DSA:
        bn := DSA_get0_q(EVP_PKEY_get0_DSA(ctx.p2));

{$ENDIF}
    end;
    Result := get_payload_bn(state, translation, ctx, bn);
end;


function get_dh_dsa_payload_g(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
  bn : PBIGNUM;
begin
    bn := nil;
    case (EVP_PKEY_get_base_id(ctx.p2)) of
{$IFNDEF OPENSSL_NO_DH}
    EVP_PKEY_DH:
        bn := DH_get0_g(EVP_PKEY_get0_DH(ctx.p2));

{$ENDIF}
{$IFNDEF OPENSSL_NO_DSA}
    EVP_PKEY_DSA:
        bn := DSA_get0_g(EVP_PKEY_get0_DSA(ctx.p2));

{$ENDIF}
    end;
    Result := get_payload_bn(state, translation, ctx, bn);
end;

function get_payload_private_key(state : Tstate;const translation : Ptranslation_st; ctx: Ptranslation_ctx_st):integer;
var
  pkey : PEVP_PKEY;

  dh : PDH;

  ec : PEC_KEY;
begin
    pkey := ctx.p2;
    ctx.p2 := nil;
    if ctx.params.data_type <> OSSL_PARAM_UNSIGNED_INTEGER then Exit(0);
    case (EVP_PKEY_get_base_id(pkey)) of
{$IFNDEF OPENSSL_NO_DH}
      EVP_PKEY_DH:
      begin
          dh := EVP_PKEY_get0_DH(pkey);
          ctx.p2 := PBIGNUM (DH_get0_priv_key(dh));
      end;

  {$ENDIF}
  {$IFNDEF OPENSSL_NO_EC}
      EVP_PKEY_EC:
      begin
          ec := EVP_PKEY_get0_EC_KEY(pkey);
          ctx.p2 := PBIGNUM (EC_KEY_get0_private_key(ec));
      end;

  {$ENDIF}
      else
      begin
          ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE);
          Exit(0);
      end;
    end;
    Result := default_fixup_args(state, translation, ctx);
end;


function get_payload_public_key(state : Tstate;const translation : Ptranslation_st;ctx: Ptranslation_ctx_st):integer;
var
  pkey : PEVP_PKEY;

  buf : PByte;

  ret : integer;

  eckey : PEC_KEY;

  bnctx : PBN_CTX;

  ecg : PEC_GROUP;

  point : PEC_POINT;
begin
    pkey := ctx.p2;
    buf := nil;
    ctx.p2 := nil;
    case (EVP_PKEY_get_base_id(pkey)) of
{$IFNDEF OPENSSL_NO_DH}
    EVP_PKEY_DHX,
    EVP_PKEY_DH:
    begin
        case ctx.params.data_type of
          OSSL_PARAM_OCTET_STRING:
          begin
              ctx.sz := ossl_dh_key2buf(EVP_PKEY_get0_DH(pkey), @buf, 0, 1);
              ctx.p2 := buf;
          end;
          OSSL_PARAM_UNSIGNED_INTEGER:
              ctx.p2 := Pointer(DH_get0_pub_key(EVP_PKEY_get0_DH(pkey)));

          else
              Exit(0);
        end;
    end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_DSA}
    EVP_PKEY_DSA:
    begin
        if ctx.params.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
        begin
            ctx.p2 := Pointer(DSA_get0_pub_key(EVP_PKEY_get0_DSA(pkey)));
            //break;
        end;
        Exit(0);
    end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
    EVP_PKEY_EC:
    begin
        if ctx.params.data_type = OSSL_PARAM_OCTET_STRING then
        begin
            eckey := EVP_PKEY_get0_EC_KEY(pkey);
            bnctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(eckey));
            ecg := EC_KEY_get0_group(eckey);
            point := EC_KEY_get0_public_key(eckey);
            if bnctx = nil then Exit(0);
            ctx.sz := EC_POINT_point2buf(ecg, point,
                                         POINT_CONVERSION_COMPRESSED,
                                         @buf, bnctx);
            ctx.p2 := buf;
            BN_CTX_free(bnctx);

        end;
        Exit(0);
    end;
{$ENDIF}
    else
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE);
        Exit(0);
    end;
    end;
    ret := default_fixup_args(state, translation, ctx);
    OPENSSL_free(buf);
    Result := ret;
end;

function get_payload_group_name(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
    pkey     : PEVP_PKEY;

    dh       : PDH;

    uid      : integer;

    dh_group : PDH_NAMED_GROUP;

    grp      : PEC_GROUP;

    nid      : integer;
begin
    pkey := ctx.p2;
    ctx.p2 := nil;
    case (EVP_PKEY_get_base_id(pkey)) of
{$IFNDEF OPENSSL_NO_DH}
    EVP_PKEY_DH:
    begin
        dh := EVP_PKEY_get0_DH(pkey);
        uid := DH_get_nid(dh);
        if uid <> NID_undef then
        begin
            dh_group := ossl_ffc_uid_to_dh_named_group(uid);
            ctx.p2 := PUTF8Char (ossl_ffc_named_group_get_name(dh_group));
        end;
    end;

{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
    EVP_PKEY_EC:
    begin
        grp := EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey));
        nid := NID_undef;
        if grp <> nil then
           nid := EC_GROUP_get_curve_name(grp);
        if nid <> NID_undef then
           ctx.p2 := PUTF8Char (OSSL_EC_curve_nid2name(nid));
    end;

{$ENDIF}
    else
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE);
        Exit(0);
    end;
    end;
    {
     * Quietly ignoring unknown groups matches the behaviour on the provider
     * side.
     }
    if ctx.p2 = nil then Exit(1);
    ctx.p1 := strlen(PUTF8Char(ctx.p2));
    Result := default_fixup_args(state, translation, ctx);
end;

function lookup_translation(tmpl : Ptranslation_st;const translations : Ptranslation_st; translations_num : size_t):Ptranslation_st;
var
    i           : size_t;
    item        : Ptranslation_st ;
    ctrl_str    ,
    ctrl_hexstr : PUTF8Char ;
begin
{$POINTERMATH ON}
   item  := @translations[i];
   ctrl_str    := nil;
   ctrl_hexstr := nil;
    for i := 0 to translations_num-1 do
    begin
        {
         * Sanity check the translation table item.
         *
         * 1.  Either both keytypes are -1, or neither of them are.
         * 2.  TBA...
         }
        if  not ossl_assert( (item.keytype1 = -1) and (item.keytype2 = -1) ) then
            continue;
        {
         * Base search criteria: check that the optype and keytypes match,
         * if relevant.  All callers must synthesise these bits somehow.
         }
        if (item.optype <> -1)  and  ((tmpl.optype and item.optype) = 0)  then
            continue;
        {
         * This expression is stunningly simple thanks to the sanity check
         * above.
         }
        if (item.keytype1 <> -1) and  (tmpl.keytype1 <> item.keytype1)
             and  (tmpl.keytype2 <> item.keytype2) then
             continue;
        {
         * Done with the base search criteria, now we check the criteria for
         * the individual types of translations:
         * ctrl.params, ctrl_str.params, and params.ctrl
         }
        if tmpl.ctrl_num <> 0 then
        begin
            if tmpl.ctrl_num <> item.ctrl_num then
                continue;
        end
        else
        if (tmpl.ctrl_str <> nil) then
        begin
            {
             * Search criteria that originates from a ctrl_str is only used
             * for setting, never for getting.  Therefore, we only look at
             * the setter items.
             }
            if (item.action_type <> NONE)
                 and  (item.action_type <> _SET) then
                 continue;
            {
             * At least one of the ctrl cmd names must be match the ctrl
             * cmd name in the template.
             }
            if (item.ctrl_str <> nil)
                 and  (strcasecmp(tmpl.ctrl_str, item.ctrl_str)  = 0) then
                ctrl_str := tmpl.ctrl_str
            else
            if (item.ctrl_hexstr <> nil)
                      and  (strcasecmp(tmpl.ctrl_hexstr, item.ctrl_hexstr) = 0) then
                ctrl_hexstr := tmpl.ctrl_hexstr
            else
                continue;
            { Modify the template to signal which string matched }
            tmpl.ctrl_str := ctrl_str;
            tmpl.ctrl_hexstr := ctrl_hexstr;
        end
        else
        if (tmpl.param_key <> nil) then
        begin
            {
             * Search criteria that originates from a OSSL_PARAM setter or
             * getter.
             *
             * Ctrls were fundamentally bidirectional, with only the ctrl
             * command macro name implying direction (if you're lucky).
             * A few ctrl commands were even taking advantage of the
             * bidirectional nature, making the direction depend in the
             * value of the numeric argument.
             *
             * OSSL_PARAM functions are fundamentally different, in that
             * setters and getters are separated, so the data direction is
             * implied by the function that's used.  The same OSSL_PARAM
             * key name can therefore be used in both directions.  We must
             * therefore take the action type into account in this case.
             }
            if ( (item.action_type <> NONE) and  (tmpl.action_type <> item.action_type))   or
               ( (item.param_key <> nil)  and  (strcasecmp(tmpl.param_key, item.param_key) <> 0) ) then
                continue;
        end
        else
        begin
            Exit(nil);
        end;
        Exit(item);
    end;
    Result := nil;
 {$POINTERMATH OFF}
end;



function lookup_evp_pkey_translation( tmpl : Ptranslation_st):Ptranslation_st;
begin
    Exit(lookup_translation(tmpl, @evp_pkey_translations,
                              Length(evp_pkey_translations)));
end;

function OSSL_PARAM_set_octet_string(p : POSSL_PARAM;const val : Pointer; len : size_t):integer;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if val = nil then begin
        err_null_argument;
        Exit(0);
    end;
    Result := set_string_internal(p, val, len, OSSL_PARAM_OCTET_STRING);
end;


function OSSL_PARAM_get_octet_string(const p : POSSL_PARAM;var val : Pointer; max_len : size_t; used_len : Psize_t):integer;
begin
    Exit(get_string_internal(p, val, @max_len, used_len,
                               OSSL_PARAM_OCTET_STRING));
end;

function OSSL_PARAM_get_uint64(const p : POSSL_PARAM; val : Puint64_t):integer;
var
  d : Double;

  i32 : integer;

  i64 : int64;
begin
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
          sizeof(uint32_t):
          begin
              val^ := Pint32_t(p.data)^;
              Exit(1);
          end;
          sizeof(uint64_t):
          begin
              val^ := Pint64_t(p.data)^;
              Exit(1);
          end;
        end;
{$ENDIF}
        Exit(general_get_uint(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
            sizeof(int32_t):
            begin
                i32 := Pint32_t(p.data)^;
                if i32 >= 0 then
                begin
                    val^ := uint64_t(i32);
                    Exit(1);
                end;
                err_unsigned_negative;
                Exit(0);
            end;
            sizeof(int64_t):
            begin
                i64 := Pint64_t(p.data)^;
                if i64 >= 0 then
                begin
                    val^ := uint64_t(i64);
                    Exit(1);
                end;
                err_unsigned_negative;
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_get_uint(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        case p.data_size of
            sizeof(double):
            begin
                d := Pdouble (p.data)^;
                if (d >= 0)
                        {
                         * By subtracting 65535 (2^16-1 then we cancel the low order
                         * 15 bits of UINT64_MAX to avoid using imprecise floating
                         * point values.
                         }
                         and  (d < (UINT64_MAX - 65535) + 65536.0)
                         and  (d = round(d)) then
                begin
                    val^ := round(d);
                    Exit(1);
                end;
                err_inexact;
                Exit(0);
            end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;



function OSSL_PARAM_get_uint(const p : POSSL_PARAM; val : Puint32):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(uint32)) of
    sizeof(uint32_t):
        Exit(OSSL_PARAM_get_uint32(p, Puint32_t (val)));
    sizeof(uint64_t):
        Exit(OSSL_PARAM_get_uint64(p, Puint64_t (val)));
    end;
{$ENDIF}
    Result := general_get_uint(p, val, sizeof( val^));
end;




function default_check(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
begin
    case state of

      PRE_CTRL_TO_PARAMS:
      begin
          if  not ossl_assert(translation <> nil) then
          begin
              ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
              Exit(-2);
          end;
          if  (not ossl_assert(translation.param_key <> nil) )  or
              (not ossl_assert(translation.param_data_type <> 0)) then
          begin
              ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
              Exit(-1);
          end;
      end;
      PRE_CTRL_STR_TO_PARAMS:
      begin    {
           * For ctrl_str to params translation, we allow direct use of
           * OSSL_PARAM keys as ctrl_str keys.  Therefore, it's possible that
           * we end up with |translation = nil|, which is fine.  The fixup
           * function will have to deal with it carefully.
           }
          if translation <> nil then
          begin
              if  not ossl_assert(translation.action_type <> GET) then
              begin
                  ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
                  Exit(-2);
              end;
              if  (not ossl_assert(translation.param_key <> nil)) or
                  (not ossl_assert(translation.param_data_type <> 0)) then
              begin
                  ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
                  Exit(0);
              end;
          end;
      end;
      PRE_PARAMS_TO_CTRL,
      POST_PARAMS_TO_CTRL:
      begin
          if  not ossl_assert(translation <> nil ) then
          begin
              ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
              Exit(-2);
          end;
          if  (not ossl_assert(translation.ctrl_num <> 0))  or
              (not ossl_assert(translation.param_data_type <> 0))then
          begin
              ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
              Exit(-1);
          end;
      end;
      else
       begin
         //
       end;
    end;
    { Nothing else to check }
    Result := 1;
end;


function default_fixup_args(state : Tstate;const translation : Ptranslation_st; ctx : Ptranslation_ctx_st):integer;
var
    ret             : integer;
    tmp_ctrl_str,
    orig_ctrl_str,
    orig_value, pc      : PUTF8Char;
    settable        : POSSL_PARAM;
    exists          : integer;
    param_data_type : uint32;
    size            : size_t;
    s: string;
begin
{$POINTERMATH ON}
    ret := default_check(state, translation, ctx );
    if ret < 0 then
        Exit(ret);
  case state of

    {
     * PRE_CTRL_TO_PARAMS and POST_CTRL_TO_PARAMS handle ctrl to params
     * translations.  PRE_CTRL_TO_PARAMS is responsible for preparing
     * |*params|, and POST_CTRL_TO_PARAMS is responsible for bringing the
     * result back to |*p2| and the return value.
     }
    PRE_CTRL_TO_PARAMS:
    begin    { This is ctrl to params translation, so we need an OSSL_PARAM key }
        if ctx.action_type = NONE then
        begin
            {
             * No action type is an error here.  That's a case for a
             * special fixup function.
             }
            s := Format('[action:%d, state:%d]', [int(ctx.action_type), int(state)]);
            ERR_raise_data(ERR_LIB_EVP, ERR_R_UNSUPPORTED, s);
            Exit(0);
        end;
        if translation.optype <> 0 then
        begin
            if (  (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx.pctx))
                  and  (ctx.pctx.op.sig.algctx = nil) )
                 or ( (EVP_PKEY_CTX_IS_DERIVE_OP(ctx.pctx))
                     and  (ctx.pctx.op.kex.algctx = nil))
                 or ( (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx.pctx))
                     and  (ctx.pctx.op.ciph.algctx = nil))
                 or ( (EVP_PKEY_CTX_IS_KEM_OP(ctx.pctx))
                     and  (ctx.pctx.op.encap.algctx = nil))
                {
                 * The following may be unnecessary, but we have them
                 * for good measure...
                 }
                 or  ( (EVP_PKEY_CTX_IS_GEN_OP(ctx.pctx))
                     and  (ctx.pctx.op.keymgmt.genctx = nil))
                 or ( (EVP_PKEY_CTX_IS_FROMDATA_OP(ctx.pctx))
                     and  (ctx.pctx.op.keymgmt.genctx = nil)) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
                { Uses the same return values as EVP_PKEY_CTX_ctrl }
                Exit(-2);
            end;
        end;
        {
         * OSSL_PARAM_construct_TYPE() works equally well for both SET and GET.
         }
        case translation.param_data_type of
        OSSL_PARAM_INTEGER:
            ctx.params^ := OSSL_PARAM_construct_int(translation.param_key,
                                                    @ctx.p1);
            //break;
        OSSL_PARAM_UNSIGNED_INTEGER:
        begin    {
             * BIGNUMs are passed via |p2|.  For all ctrl's that just want
             * to pass a simple integer via |p1|, |p2| is expected to be
             * nil.
             *
             * Note that this allocates a buffer, which the cleanup function
             * must deallocate.
             }
            if ctx.p2 <> nil then
            begin
                if ctx.action_type = _SET then
                begin
                    ctx.buflen := BN_num_bytes(ctx.p2);
                    ctx.allocated_buf :=  OPENSSL_malloc(ctx.buflen);
                    if (ctx.allocated_buf = nil) then
                    begin
                        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                        Exit(0);
                    end;
                    if BN_bn2nativepad(ctx.p2,
                                         ctx.allocated_buf, ctx.buflen)  < 0 then
                    begin
                        OPENSSL_free(ctx.allocated_buf);
                        ctx.allocated_buf := nil;
                        Exit(0);
                    end;
                    ctx.params^ := OSSL_PARAM_construct_BN(translation.param_key,
                                                ctx.allocated_buf,
                                                ctx.buflen);
                end
                else
                begin
                    {
                     * No support for getting a BIGNUM by ctrl, this needs
                     * fixup_args function support.
                     }
                    ERR_raise_data(ERR_LIB_EVP, ERR_R_UNSUPPORTED,
                                   Format('[action:%d, state:%d] trying to get a '+
                                   'BIGNUM via ctrl call',
                                   [int(ctx.action_type), Int(state)]));
                    Exit(0);
                end;
            end
            else
            begin
                ctx.params^ :=
                    OSSL_PARAM_construct_uint(translation.param_key,
                                              Puint32(@ctx.p1));
            end;
        end;
        OSSL_PARAM_UTF8_STRING:
            ctx.params^ :=
                OSSL_PARAM_construct_utf8_string(translation.param_key,
                                                 ctx.p2, size_t(ctx.p1));
            //break;
        OSSL_PARAM_UTF8_PTR:
            ctx.params^ :=
                OSSL_PARAM_construct_utf8_ptr(translation.param_key,
                                              ctx.p2, size_t(ctx.p1));
            //break;
        OSSL_PARAM_OCTET_STRING:
            ctx.params^ :=
                OSSL_PARAM_construct_octet_string(translation.param_key,
                                                  ctx.p2, size_t(ctx.p1));
            //break;
        OSSL_PARAM_OCTET_PTR:
            ctx.params^ :=
                OSSL_PARAM_construct_octet_ptr(translation.param_key,
                                               ctx.p2, size_t(ctx.p1));
            //break;
        end;
    end;
    POST_CTRL_TO_PARAMS:
        {
         * Because EVP_PKEY_CTX_ctrl() returns the length of certain objects
         * as its return value, we need to ensure that we do it here as well,
         * for the OSSL_PARAM data types where this makes sense.
         }
        if ctx.action_type = GET then
        begin
            case translation.param_data_type of
              OSSL_PARAM_UTF8_STRING,
              OSSL_PARAM_UTF8_PTR,
              OSSL_PARAM_OCTET_STRING,
              OSSL_PARAM_OCTET_PTR:
                  ctx.p1 := int(ctx.params[0].return_size);

            end;
        end;
        //break;
    {
     * PRE_CTRL_STR_TO_PARAMS and POST_CTRL_STR_TO_PARAMS handle ctrl_str to
     * params translations.  PRE_CTRL_TO_PARAMS is responsible for preparing
     * |*params|, and POST_CTRL_TO_PARAMS currently has nothing to do, since
     * there's no support for getting data via ctrl_str calls.
     }
    PRE_CTRL_STR_TO_PARAMS:
    begin
        { This is ctrl_str to params translation }
        tmp_ctrl_str := ctx.ctrl_str;
        orig_ctrl_str := ctx.ctrl_str;
        orig_value := ctx.p2;
        settable := nil;
        exists := 0;
        { Only setting is supported here }
        if ctx.action_type <> _SET then
        begin
            ERR_raise_data(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED,
                               Format('[action:%d, state:%d] only setting allowed',
                               [Int(ctx.action_type), Int(state)]));
            Exit(0);
        end;
        {
         * If no translation exists, we simply pass the control string
         * unmodified.
         }
        if translation <> nil then
        begin
            tmp_ctrl_str := translation.param_key;
            ctx.ctrl_str := translation.param_key;
            if ctx.ishex>0 then
            begin
                ctx.name_buf := 'hex';
                pc := @ctx.name_buf;
                if OPENSSL_strlcat(pc, tmp_ctrl_str,
                                    sizeof(ctx.name_buf)) <= 3 then
                begin
                    ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
                    Exit(-1);
                end;
                tmp_ctrl_str := ctx.name_buf;
            end;
        end;
        settable := EVP_PKEY_CTX_settable_params(ctx.pctx);
        if  0>=OSSL_PARAM_allocate_from_text(ctx.params, settable,
                                           tmp_ctrl_str,
                                           ctx.p2, StrLen(PUTF8Char(ctx.p2)) ,
                                           @exists) then
        begin
            if  0>= exists then
            begin
                ERR_raise_data(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED,
                               Format('[action:%d, state:%d] name=%s, value=%s',
                               [Int(ctx.action_type), Int(state),
                               orig_ctrl_str, orig_value]));
                Exit(-2);
            end;
            Exit(0);
        end;
        ctx.allocated_buf := ctx.params.data;
        ctx.buflen := ctx.params.data_size;
    end;
        //break;
    POST_CTRL_STR_TO_PARAMS:
        { Nothing to be done }
    begin
      //
    end;
    {
     * PRE_PARAMS_TO_CTRL and POST_PARAMS_TO_CTRL handle params to ctrl
     * translations.  PRE_PARAMS_TO_CTRL is responsible for preparing
     * |p1| and |p2|, and POST_PARAMS_TO_CTRL is responsible for bringing
     * the EVP_PKEY_CTX_ctrl() return value (passed as |p1|) and |p2| back
     * to |*params|.
     *
     * PKEY is treated just like POST_PARAMS_TO_CTRL, making it easy
     * for the related fixup_args functions to just set |p1| and |p2|
     * appropriately and leave it to this section of code to fix up
     * |ctx.params| accordingly.
     }
    PKEY,
    POST_PARAMS_TO_CTRL:
        ret := ctx.p1;
        { FALLTHRU }
    PRE_PARAMS_TO_CTRL:
    begin
        { This is params to ctrl translation }
        if (state = PRE_PARAMS_TO_CTRL)  and  (ctx.action_type = _SET) then
        begin
            { For the PRE state, only setting needs some work to be done }
            { When setting, we populate |p1| and |p2| from |*params| }
          case translation.param_data_type of
            OSSL_PARAM_INTEGER:
                Exit(OSSL_PARAM_get_int(ctx.params, @ctx.p1));
            OSSL_PARAM_UNSIGNED_INTEGER:
            begin
                if ctx.p2 <> nil then
                begin
                    { BIGNUM passed down with p2 }
                    if  0>= OSSL_PARAM_get_BN(ctx.params, ctx.p2) then
                        Exit(0);
                end
                else
                begin
                    { Normal C unsigned int passed down }
                    if  0>= OSSL_PARAM_get_uint(ctx.params,
                                             Puint32(@ctx.p1))  then
                        Exit(0);
                end;
                Exit(1);
            end;
            OSSL_PARAM_UTF8_STRING:
                Exit(OSSL_PARAM_get_utf8_string(ctx.params,
                                                  PPUTF8Char(ctx.p2), ctx.sz));
            OSSL_PARAM_OCTET_STRING:
                Exit(OSSL_PARAM_get_octet_string(ctx.params,
                                                   ctx.p2, ctx.sz,
                                                   @ctx.sz));
            OSSL_PARAM_OCTET_PTR:
                Exit(OSSL_PARAM_get_octet_ptr(ctx.params,
                                                ctx.p2, @ctx.sz));
            else
            begin
                ERR_raise_data(ERR_LIB_EVP, ERR_R_UNSUPPORTED,
                              Format( '[action:%d, state:%d] '+
                               'unknown OSSL_PARAM data type %d',
                               [Int(ctx.action_type), Int(state),
                               translation.param_data_type]));
                Exit(0);
            end;
          end;
        end
        else
        if ( (state = POST_PARAMS_TO_CTRL)  or  (state = PKEY) )
                    and  (ctx.action_type = GET) then
        begin
            { For the POST state, only getting needs some work to be done }
            param_data_type := translation.param_data_type;
            size := size_t(ctx.p1);
            if state = PKEY then
               size := ctx.sz;
            if param_data_type = 0 then
            begin
                { we must have a fixup_args function to work }
                if  not ossl_assert(Assigned(translation.fixup_args)) then
                begin
                    ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
                    Exit(0);
                end;
                param_data_type := ctx.params.data_type;
            end;
            { When getting, we populate |*params| from |p1| and |p2| }
            case param_data_type of
                OSSL_PARAM_INTEGER:
                    Exit(OSSL_PARAM_set_int(ctx.params, ctx.p1));
                OSSL_PARAM_UNSIGNED_INTEGER:
                begin
                    if ctx.p2 <> nil then
                    begin
                        { BIGNUM passed back }
                        Exit(OSSL_PARAM_set_BN(ctx.params, ctx.p2));
                    end
                    else
                    begin
                        { Normal C unsigned int passed back }
                        Exit(OSSL_PARAM_set_uint(ctx.params,
                                                   uint32(ctx.p1)));
                    end;
                    Exit(0);
                end;
                OSSL_PARAM_UTF8_STRING:
                    Exit(OSSL_PARAM_set_utf8_string(ctx.params, ctx.p2));
                OSSL_PARAM_OCTET_STRING:
                    Exit(OSSL_PARAM_set_octet_string(ctx.params, ctx.p2,
                                                       size));
                OSSL_PARAM_OCTET_PTR:
                    Exit(OSSL_PARAM_set_octet_ptr(ctx.params, ctx.p2,
                                                    size));
                else
                begin
                    ERR_raise_data(ERR_LIB_EVP, ERR_R_UNSUPPORTED,
                                  Format('[action:%d, state:%d] '+
                                   'unsupported OSSL_PARAM data type %d',
                                   [Integer(ctx.action_type), Integer(state),
                                   translation.param_data_type]));
                    Exit(0);
                end;
            end;
        end;
    end;
    { Any other combination is simply pass-through }
    //break;
    else
    begin
      { For states this function should never have been called with }
      ERR_raise_data(ERR_LIB_EVP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                     Format('[action:%d, state:%d]',
                            [Int(ctx.action_type), Int(state)]));
      Exit(0);
    end;
  end; (*case state*)
    Result := ret;
{$POINTERMATH OFF}
end;



function evp_pkey_setget_params_to_ctrl(const pkey : PEVP_PKEY; action_type : Taction; params : POSSL_PARAM):integer;
var
    ret         : integer;
    ctx         : translation_ctx_st;
    tmpl        : translation_st;
    translation : Ptranslation_st;
    fixup       : Tfixup_args_fn;
begin
    ret := 1;
    while (params <> nil)  and  (params.key <> nil) do
    begin
         FillChar(ctx,0,SizeOf(ctx));
         FillChar(tmpl,0,SizeOf(ctx));
        translation := nil;
        fixup := default_fixup_args;
        tmpl.action_type := action_type;
        tmpl.param_key := params.key;
        translation := lookup_evp_pkey_translation(@tmpl);
        if translation <> nil then
        begin
            if Assigned(translation.fixup_args) then
                fixup := translation.fixup_args;
            ctx.action_type := translation.action_type;
        end;
        ctx.p2 := Pointer(pkey);
        ctx.params := params;
        {
         * EVP_PKEY doesn't have any ctrl function, so we rely completely
         * on fixup_args to do the whole work.  Also, we currently only
         * support getting.
         }
        if  (not ossl_assert(translation <> nil) ) or
            (not ossl_assert(translation.action_type = GET) )  or
            (not ossl_assert( Assigned(translation.fixup_args)) ) then
        begin
            Exit(-2);
        end;
        ret := fixup(Tstate(PKEY), translation, @ctx);
        cleanup_translation_ctx(Tstate(PKEY), translation, @ctx);
        Inc(params);
    end;
    Result := ret;
end;



function evp_pkey_get_params_to_ctrl(const pkey : PEVP_PKEY; params : POSSL_PARAM):integer;
begin
    Result := evp_pkey_setget_params_to_ctrl(pkey, GET, params);
end;

initialization
  evp_pkey_ctx_translations := [
    (*
     * DistID: we pass it to the backend as an octet string,
     * but get it back as a pointer to an octet string.
     *
     * Note that the EVP_PKEY_CTRL_GET1_ID_LEN is purely for legacy purposes
     * that has no separate counterpart in OSSL_PARAM terms, since we get
     * the length of the DistID automatically when getting the DistID itself.
     *)
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_SET1_ID, 'distid', 'hexdistid',
      OSSL_PKEY_PARAM_DIST_ID, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( GET, -1, -1, -1,
      EVP_PKEY_CTRL_GET1_ID, 'distid', 'hexdistid',
      OSSL_PKEY_PARAM_DIST_ID, OSSL_PARAM_OCTET_PTR, nil ),
    get_translation_st( GET, -1, -1, -1,
      EVP_PKEY_CTRL_GET1_ID_LEN, nil, nil,
      OSSL_PKEY_PARAM_DIST_ID, OSSL_PARAM_OCTET_PTR, fix_distid_len ),

    (*-
     * DH & DHX
     * ========
     *)

    (*
     * EVP_PKEY_CTRL_DH_KDF_TYPE is used both for setting and getting.  The
     * fixup function has to handle this...
     *)
    get_translation_st( NONE, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_DH_KDF_TYPE, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_PARAM_UTF8_STRING,
      fix_dh_kdf_type ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_DH_KDF_MD, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( GET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_DH_KDF_MD, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_DH_KDF_OUTLEN, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( GET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_DH_KDF_UKM, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( GET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_DH_KDF_UKM, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, nil ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_DH_KDF_OID, nil, nil,
      OSSL_KDF_PARAM_CEK_ALG, OSSL_PARAM_UTF8_STRING, fix_oid ),
    get_translation_st( GET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_DH_KDF_OID, nil, nil,
      OSSL_KDF_PARAM_CEK_ALG, OSSL_PARAM_UTF8_STRING, fix_oid ),

    (* DHX Keygen Parameters that are shared with DH *)
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, 'dh_paramgen_type', nil,
      OSSL_PKEY_PARAM_FFC_TYPE, OSSL_PARAM_UTF8_STRING, fix_dh_paramgen_type ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 'dh_paramgen_prime_len', nil,
      OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_PARAMGEN  or EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_DH_NID, 'dh_param', nil,
      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, nil ),
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_PARAMGEN  or EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_DH_RFC5114, 'dh_rfc5114', nil,
      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, fix_dh_nid5114 ),

    (* DH Keygen Parameters that are shared with DHX *)
    get_translation_st( _SET, EVP_PKEY_DH, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, 'dh_paramgen_type', nil,
      OSSL_PKEY_PARAM_FFC_TYPE, OSSL_PARAM_UTF8_STRING, fix_dh_paramgen_type ),
    get_translation_st( _SET, EVP_PKEY_DH, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 'dh_paramgen_prime_len', nil,
      OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_DH, 0, EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_DH_NID, 'dh_param', nil,
      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, fix_dh_nid ),
    get_translation_st( _SET, EVP_PKEY_DH, 0, EVP_PKEY_OP_PARAMGEN  or EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_DH_RFC5114, 'dh_rfc5114', nil,
      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, fix_dh_nid5114 ),

    (* DH specific Keygen Parameters *)
    get_translation_st( _SET, EVP_PKEY_DH, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, 'dh_paramgen_generator', nil,
      OSSL_PKEY_PARAM_DH_GENERATOR, OSSL_PARAM_INTEGER, nil ),

    (* DHX specific Keygen Parameters *)
    get_translation_st( _SET, EVP_PKEY_DHX, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, 'dh_paramgen_subprime_len', nil,
      OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PARAM_UNSIGNED_INTEGER, nil ),

    get_translation_st( _SET, EVP_PKEY_DH, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_DH_PAD, 'dh_pad', nil,
      OSSL_EXCHANGE_PARAM_PAD, OSSL_PARAM_UNSIGNED_INTEGER, nil ),

    (*-
     * DSA
     * ===
     *)
    get_translation_st( _SET, EVP_PKEY_DSA, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, 'dsa_paramgen_bits', nil,
      OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_DSA, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, 'dsa_paramgen_q_bits', nil,
      OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_DSA, 0, EVP_PKEY_OP_PARAMGEN,
      EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 'dsa_paramgen_md', nil,
      OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),

    (*-
     * EC
     * ==
     *)
    get_translation_st( _SET, EVP_PKEY_EC, 0, EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_EC_PARAM_ENC, 'ec_param_enc', nil,
      OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PARAM_UTF8_STRING, fix_ec_param_enc ),
    get_translation_st( _SET, EVP_PKEY_EC, 0, EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, 'ec_paramgen_curve', nil,
      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING,
      fix_ec_paramgen_curve_nid ),
    (*
     * EVP_PKEY_CTRL_EC_ECDH_COFACTOR and EVP_PKEY_CTRL_EC_KDF_TYPE are used
     * both for setting and getting.  The fixup function has to handle this...
     *)
    get_translation_st( NONE, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_EC_ECDH_COFACTOR, 'ecdh_cofactor_mode', nil,
      OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, OSSL_PARAM_INTEGER,
      fix_ecdh_cofactor ),
    get_translation_st( NONE, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_EC_KDF_TYPE, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_PARAM_UTF8_STRING, fix_ec_kdf_type ),
    get_translation_st( _SET, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_EC_KDF_MD, 'ecdh_kdf_md', nil,
      OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( GET, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_EC_KDF_MD, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( _SET, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_EC_KDF_OUTLEN, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( GET, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_EC_KDF_UKM, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( GET, EVP_PKEY_EC, 0, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_GET_EC_KDF_UKM, nil, nil,
      OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, nil ),

    (*-
     * RSA
     * ===
     *)

    (*
     * RSA padding modes are numeric with ctrls, strings with ctrl_strs,
     * and can be both with OSSL_PARAM.  We standardise on strings here,
     * fix_rsa_padding_mode() does the work when the caller has a different
     * idea.
     *)
    get_translation_st( _SET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
      EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_RSA_PADDING, 'rsa_padding_mode', nil,
      OSSL_PKEY_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, fix_rsa_padding_mode ),
    get_translation_st( GET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
      EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_GET_RSA_PADDING, nil, nil,
      OSSL_PKEY_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, fix_rsa_padding_mode ),

    get_translation_st( _SET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
      EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_RSA_MGF1_MD, 'rsa_mgf1_md', nil,
      OSSL_PKEY_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( GET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
      EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_GET_RSA_MGF1_MD, nil, nil,
      OSSL_PKEY_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),

    (*
     * RSA-PSS saltlen is essentially numeric, but certain values can be
     * expressed as keywords (strings) with ctrl_str.  The corresponding
     * OSSL_PARAM allows both forms.
     * fix_rsa_pss_saltlen() takes care of the distinction.
     *)
    get_translation_st( _SET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_RSA_PSS_SALTLEN, 'rsa_pss_saltlen', nil,
      OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING,
      fix_rsa_pss_saltlen ),
    get_translation_st( GET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, nil, nil,
      OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING,
      fix_rsa_pss_saltlen ),

    get_translation_st( _SET, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT,
      EVP_PKEY_CTRL_RSA_OAEP_MD, 'rsa_oaep_md', nil,
      OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( GET, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT,
      EVP_PKEY_CTRL_GET_RSA_OAEP_MD, nil, nil,
      OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    (*
     * The 'rsa_oaep_label' ctrl_str expects the value to always be hex.
     * This is accommodated by default_fixup_args() above, which mimics that
     * expectation for any translation item where |ctrl_str| is nil and
     * |ctrl_hexstr| is non-nil.
     *)
    get_translation_st( _SET, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT,
      EVP_PKEY_CTRL_RSA_OAEP_LABEL, nil, 'rsa_oaep_label',
      OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( GET, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT,
      EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, nil, nil,
      OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_STRING, nil ),

    get_translation_st( _SET, EVP_PKEY_RSA_PSS, 0, EVP_PKEY_OP_TYPE_GEN,
      EVP_PKEY_CTRL_MD, 'rsa_pss_keygen_md', nil,
      OSSL_ALG_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( _SET, EVP_PKEY_RSA_PSS, 0, EVP_PKEY_OP_TYPE_GEN,
      EVP_PKEY_CTRL_RSA_MGF1_MD, 'rsa_pss_keygen_mgf1_md', nil,
      OSSL_PKEY_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( _SET, EVP_PKEY_RSA_PSS, 0, EVP_PKEY_OP_TYPE_GEN,
      EVP_PKEY_CTRL_RSA_PSS_SALTLEN, 'rsa_pss_keygen_saltlen', nil,
      OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_RSA_KEYGEN_BITS, 'rsa_keygen_bits', nil,
      OSSL_PKEY_PARAM_RSA_BITS, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_RSA, 0, EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 'rsa_keygen_pubexp', nil,
      OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, EVP_PKEY_RSA, 0, EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, 'rsa_keygen_primes', nil,
      OSSL_PKEY_PARAM_RSA_PRIMES, OSSL_PARAM_UNSIGNED_INTEGER, nil ),

    (*-
     * SipHash
     * ======
     *)
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_SET_DIGEST_SIZE, 'digestsize', nil,
      OSSL_MAC_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, nil ),

    (*-
     * TLS1-PRF
     * ========
     *)
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_TLS_MD, 'md', nil,
      OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_TLS_SECRET, 'secret', 'hexsecret',
      OSSL_KDF_PARAM_SECRET, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_TLS_SEED, 'seed', 'hexseed',
      OSSL_KDF_PARAM_SEED, OSSL_PARAM_OCTET_STRING, nil ),

    (*-
     * HKDF
     * ====
     *)
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_HKDF_MD, 'md', nil,
      OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_HKDF_SALT, 'salt', 'hexsalt',
      OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_HKDF_KEY, 'key', 'hexkey',
      OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_HKDF_INFO, 'info', 'hexinfo',
      OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_HKDF_MODE, 'mode', nil,
      OSSL_KDF_PARAM_MODE, OSSL_PARAM_INTEGER, fix_hkdf_mode ),

    (*-
     * Scrypt
     * ======
     *)
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_PASS, 'pass', 'hexpass',
      OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_SCRYPT_SALT, 'salt', 'hexsalt',
      OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_SCRYPT_N, 'N', nil,
      OSSL_KDF_PARAM_SCRYPT_N, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_SCRYPT_R, 'r', nil,
      OSSL_KDF_PARAM_SCRYPT_R, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_SCRYPT_P, 'p', nil,
      OSSL_KDF_PARAM_SCRYPT_P, OSSL_PARAM_UNSIGNED_INTEGER, nil ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_DERIVE,
      EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, 'maxmem_bytes', nil,
      OSSL_KDF_PARAM_SCRYPT_MAXMEM, OSSL_PARAM_UNSIGNED_INTEGER, nil ),

    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_KEYGEN or EVP_PKEY_OP_TYPE_CRYPT,
      EVP_PKEY_CTRL_CIPHER, nil, nil,
      OSSL_PKEY_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING, fix_cipher ),
    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_KEYGEN,
      EVP_PKEY_CTRL_SET_MAC_KEY, 'key', 'hexkey',
      OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, nil ),

    get_translation_st( _SET, -1, -1, EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_MD, nil, nil,
      OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md ),
    get_translation_st( GET, -1, -1, EVP_PKEY_OP_TYPE_SIG,
      EVP_PKEY_CTRL_GET_MD, nil, nil,
      OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, fix_md )
];

  


end.
