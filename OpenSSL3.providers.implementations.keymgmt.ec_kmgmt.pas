unit OpenSSL3.providers.implementations.keymgmt.ec_kmgmt;

interface
uses OpenSSL.Api;

function sm2_validate(const keydata : Pointer; selection, checktype : integer):integer;
function sm2_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
 function sm2_query_operation_name( operation_id : integer):PUTF8Char;
function sm2_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
function sm2_load(const reference : Pointer; reference_sz : size_t):Pointer;
function sm2_get_params( key : Pointer; params : POSSL_PARAM):integer;
function sm2_gettable_params( provctx : Pointer):POSSL_PARAM;
function  sm2_settable_params(provctx: Pointer):POSSL_PARAM;
function ec_newdata( provctx : Pointer):Pointer;
function ec_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function ec_gen_set_template( genctx, templ : Pointer):integer;
function ec_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
function ec_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
function ec_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
procedure ec_gen_cleanup( genctx : Pointer);
procedure ec_freedata( keydata : Pointer);
function ec_has(const keydata : Pointer; selection : integer):integer;
function ec_get_params( key : Pointer; params : POSSL_PARAM):integer;
function ec_gettable_params( provctx : Pointer):POSSL_PARAM;
function ec_set_params(key : Pointer;const params : POSSL_PARAM):integer;
function ec_settable_params( provctx : Pointer):POSSL_PARAM;
function ec_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
function ec_validate(const keydata : Pointer; selection, checktype : integer):integer;
function ec_load(const reference : Pointer; reference_sz : size_t):Pointer;
function ec_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
function ec_import_types( selection : integer):POSSL_PARAM;
function ec_export_types( selection : integer):POSSL_PARAM;
function ec_get_ecm_params(const group : PEC_GROUP; params : POSSL_PARAM):integer;
function ec_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
function ec_query_operation_name( operation_id : integer):PUTF8Char;
function ec_dup(const keydata_from : Pointer; selection : integer):Pointer;
function key_to_params(const eckey : PEC_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM; include_private : integer; pub_key : PPByte):integer;
function otherparams_to_params(const ec : PEC_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
function ec_imexport_types( selection : integer):POSSL_PARAM;
function common_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM; sm2_wanted : integer):integer;
function sm2_newdata( provctx : Pointer):Pointer;
function sm2_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;

const  ossl_ec_keymgmt_functions: array[0..22] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_KEYMGMT_NEW;                  method:(code:@ec_newdata ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_INIT;             method:(code:@ec_gen_init ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE;     method:(code:@ec_gen_set_template ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS;       method:(code:@ec_gen_set_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS;  method:(code:@ec_gen_settable_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN;                  method:(code:@ec_gen ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_CLEANUP;          method:(code:@ec_gen_cleanup ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_LOAD;                 method:(code:@ec_load ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_FREE;                 method:(code:@ec_freedata ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GET_PARAMS;           method:(code:@ec_get_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS;      method:(code:@ec_gettable_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_SET_PARAMS;           method:(code:@ec_set_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS;      method:(code:@ec_settable_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_HAS;                  method:(code:@ec_has ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_MATCH;                method:(code:@ec_match ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_VALIDATE;             method:(code:@ec_validate ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_IMPORT;               method:(code:@ec_import ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_IMPORT_TYPES;         method:(code:@ec_import_types ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_EXPORT;               method:(code:@ec_export ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_EXPORT_TYPES;         method:(code:@ec_export_types ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME; method:(code:@ec_query_operation_name ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_DUP;                  method:(code:@ec_dup ;data:nil)),
    (function_id:  0;                                      method:(code:nil ;data:nil))
);
 ossl_sm2_keymgmt_functions: array[0..22] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW;                 method:(code:@sm2_newdata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_INIT;            method:(code:@sm2_gen_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE;    method:(code:@ec_gen_set_template ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS;      method:(code:@ec_gen_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS; method:(code:@ec_gen_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN;                 method:(code:@sm2_gen ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP;         method:(code:@ec_gen_cleanup ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_LOAD;                method:(code:@sm2_load ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE;                method:(code:@ec_freedata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS;          method:(code:@sm2_get_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS;     method:(code:@sm2_gettable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS;          method:(code:@ec_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS;     method:(code:@sm2_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS;                 method:(code:@ec_has ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_MATCH;               method:(code:@ec_match ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_VALIDATE;            method:(code:@sm2_validate ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT;              method:(code:@sm2_import ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES;        method:(code:@ec_import_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT;              method:(code:@ec_export ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES;        method:(code:@ec_export_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME;method:(code:@sm2_query_operation_name ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_DUP;                 method:(code:@ec_dup ;data:nil)),
    (function_id: 0;                                     method:(code:nil ;data:nil))
);
var
  ec_private_key_types,
  ec_public_key_types,
  ec_key_types,
  ec_dom_parameters_types,
  ec_5_types,
  ec_6_types,
  ec_key_domp_types,
  ec_other_parameters_types,
  ec_9_types,
  ec_10_types,
  ec_11_types,
  ec_all_parameters_types,
  ec_13_types,
  ec_14_types,
  ec_all_types,
  ec_known_settable_params,
  ec_known_gettable_params,
  sm2_known_settable_params,
  sm2_known_gettable_params: array of TOSSL_PARAM ;

  ec_types: array of POSSL_PARAM;

const
  EC_DEFAULT_MD = 'SHA256';
  SM2_DEFAULT_MD = 'SM3';

function common_check_sm2(const ec : PEC_KEY; sm2_wanted : integer):integer;

function common_get_params( key : Pointer; params : POSSL_PARAM; sm2 : integer):integer;
function common_load(const reference : Pointer; reference_sz : size_t; sm2_wanted : integer):Pointer;
function ec_gen_set_group_from_params( gctx : Pec_gen_ctx):integer;
function ec_gen_assign_group( ec : PEC_KEY; group : PEC_GROUP):Boolean;
function ec_gen_set_group(genctx : Pointer;const src : PEC_GROUP):integer;

implementation

uses openssl3.providers.fips.self_test,openssl3.crypto.ffc.ffc_params,
     openssl3.crypto.param_build,  OpenSSL3.openssl.params,
     openssl3.crypto.param_build_set, OpenSSL3.crypto.rsa.rsa_backend,
     openssl3.crypto.params_dup,openssl3.crypto.bn.bn_lib,
     openssl3.crypto.params, openssl3.crypto.mem,
     OpenSSL3.Err, openssl3.crypto.o_str, openssl3.crypto.ec.ec_backend,
     openssl3.providers.common.provider_ctx, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.ec.ec_key, openssl3.crypto.ec.ec_lib,
     openssl3.crypto.ec.ec_asn1,  openssl3.crypto.ec.ec_oct,
     OpenSSL3.crypto.ec.ec_check, openssl3.crypto.sm.sm2_key;

function sm2_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
begin
    Result := common_import(keydata, selection, params, 1);
end;

function sm2_query_operation_name( operation_id : integer):PUTF8Char;
begin
    case operation_id of
    OSSL_OP_SIGNATURE:
        Exit('SM2');
    end;
    Result := nil;
end;

function sm2_validate(const keydata : Pointer; selection, checktype : integer):integer;
var
  eck : PEC_KEY;

  ok : Boolean;

  ctx : PBN_CTX;
begin
     eck := keydata;
    ok := Boolean(1);
    ctx := nil;
    if  not ossl_prov_is_running() then
        Exit(0);
    if (selection and EC_POSSIBLE_SELECTIONS ) = 0 then
       Exit(1); { nothing to validate }
    ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(eck));
    if ctx = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        ok := (ok)  and  (EC_GROUP_check(EC_KEY_get0_group(eck), ctx)>0);
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
    begin
        if checktype = OSSL_KEYMGMT_VALIDATE_QUICK_CHECK then
            ok := (ok)  and  (ossl_ec_key_public_check_quick(eck, ctx)>0)
        else
            ok := (ok)  and  (ossl_ec_key_public_check(eck, ctx)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        ok := (ok)  and  (ossl_sm2_key_private_check(eck)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = OSSL_KEYMGMT_SELECT_KEYPAIR then
        ok := (ok)  and  (ossl_ec_key_pairwise_check(eck, ctx)>0);
    BN_CTX_free(ctx);
    Result := Int(ok);
end;

function  sm2_settable_params(provctx: Pointer):POSSL_PARAM;
begin
    result := @sm2_known_settable_params[0];
end;

function sm2_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @sm2_known_gettable_params[0];
end;



function sm2_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    Result := common_get_params(key, params, 1);
end;


function sm2_load(const reference : Pointer; reference_sz : size_t):Pointer;
begin
    Result := common_load(reference, reference_sz, 1);
end;


function sm2_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pec_gen_ctx;

  ec : PEC_KEY;

  ret: Boolean;
  flags, format : integer;
  label _err;
begin
    gctx := genctx;
    ec := nil;
    ret := Boolean(1);
    ec := EC_KEY_new_ex(gctx.libctx, nil);
    if (gctx = nil)
         or  (ec = nil)  then
        Exit(nil);
    if gctx.gen_group = nil then
    begin
        if  0>= ec_gen_set_group_from_params(gctx) then
            goto _err ;
    end
    else
    begin
        if Assigned(gctx.encoding) then
        begin
            flags := ossl_ec_encoding_name2id(gctx.encoding);
            if flags < 0 then goto _err ;
            EC_GROUP_set_asn1_flag(gctx.gen_group, flags);
        end;
        if gctx.pt_format <> nil then
        begin
            format := ossl_ec_pt_format_name2id(gctx.pt_format);
            if format < 0 then goto _err ;
            EC_GROUP_set_point_conversion_form(gctx.gen_group, point_conversion_form_t(format));
        end;
    end;
    { We must always assign a group, no matter what }
    ret := ec_gen_assign_group(ec, gctx.gen_group);
    { Whether you want it or not, you get a keypair, not just one half }
    if (gctx.selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ret := (ret)  and  (EC_KEY_generate_key(ec)>0);
    if ret then Exit(ec);
_err:
    { Something went wrong, throw the key away }
    EC_KEY_free(ec);
    Result := nil;
end;




function sm2_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  gctx : Pec_gen_ctx;
begin
    gctx := ec_gen_init(provctx, selection, params);
    if gctx <> nil then
    begin
        if gctx.group_name <> nil then
            Exit(gctx);
        OPENSSL_strdup(gctx.group_name ,'sm2');
        if gctx.group_name <> nil then
            Exit(gctx);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ec_gen_cleanup(gctx);
    end;
    Result := nil;
end;




function sm2_newdata( provctx : Pointer):Pointer;
begin
    if  not ossl_prov_is_running() then
        Exit(nil);
    Result := EC_KEY_new_by_curve_name_ex(PROV_LIBCTX_OF(provctx), nil, NID_sm2);
end;




function ec_gen_set_group(genctx : Pointer;const src : PEC_GROUP):integer;
var
  gctx : Pec_gen_ctx;

  group : PEC_GROUP;
begin
    gctx := genctx;
    group := EC_GROUP_dup(src);
    if group = nil then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        Exit(0);
    end;
    EC_GROUP_free(gctx.gen_group);
    gctx.gen_group := group;
    Result := 1;
end;


function ec_gen_assign_group( ec : PEC_KEY; group : PEC_GROUP):Boolean;
begin
    if group = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        Exit(False);
    end;
    Result := (EC_KEY_set_group(ec, group) > 0);
end;

function ec_gen_set_group_from_params( gctx : Pec_gen_ctx):integer;
var
  ret : integer;
  bld : POSSL_PARAM_BLD;
  params : POSSL_PARAM;
  group : PEC_GROUP;
  label _err, _build;
begin
    ret := 0;
    params := nil;
    group := nil;
    bld := OSSL_PARAM_BLD_new();
    if bld = nil then Exit(0);
    if (gctx.encoding <> nil)
         and (0>= OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING,
                                            gctx.encoding, 0))  then
        goto _err ;
    if (gctx.pt_format <> nil)
         and (0>= OSSL_PARAM_BLD_push_utf8_string(bld,
                                            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                            gctx.pt_format, 0) )  then
        goto _err ;
    if gctx.group_name <> nil then
    begin
        if ( 0>= OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                             gctx.group_name, 0)) then
            goto _err ;
        { Ignore any other parameters if there is a group name }
        goto _build ;
    end
    else
    if (gctx.field_type <> nil) then
    begin
        if  0>= OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                             gctx.field_type, 0)  then
            goto _err ;
    end
    else
    begin
        goto _err ;
    end;
    if (gctx.p = nil)
         or  (gctx.a = nil)
         or  (gctx.b = nil)
         or  (gctx.order = nil)
         or  (0>= OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, gctx.p))  or
             (0>= OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, gctx.a))
         or   (0>= OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, gctx.b))
         or   (0>= OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER, gctx.order)) then
        goto _err ;
    if (gctx.cofactor <> nil)
         and   (0>= OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR,
                                   gctx.cofactor) )  then
        goto _err ;
    if (gctx.seed <> nil)
         and   (0>= OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED,
                                             gctx.seed, gctx.seed_len)) then
        goto _err ;
    if (gctx.gen = nil)
         or   (0>= OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR,
                                             gctx.gen, gctx.gen_len)) then
        goto _err ;
_build:
    params := OSSL_PARAM_BLD_to_param(bld);
    if params = nil then goto _err ;
    group := EC_GROUP_new_from_params(params, gctx.libctx, nil);
    if group = nil then goto _err ;
    EC_GROUP_free(gctx.gen_group);
    gctx.gen_group := group;
    ret := 1;
_err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    Result := ret;
end;



function common_load(const reference : Pointer; reference_sz : size_t; sm2_wanted : integer):Pointer;
var
  ec : PEC_KEY;
begin
    ec := nil;
    if (ossl_prov_is_running)  and  (reference_sz = sizeof(ec)) then
    begin
        { The contents of the reference is the address to our object }
        ec := PPEC_KEY ( reference)^;
        if  0>= common_check_sm2(ec, sm2_wanted) then
            Exit(nil);
        { We grabbed, so we detach it }
        PPEC_KEY ( reference)^ := nil;
        Exit(ec);
    end;
    Result := nil;
end;


function common_get_params( key : Pointer; params : POSSL_PARAM; sm2 : integer):integer;
var
  ret                : Boolean;
  eck                : PEC_KEY;
  ecg                : PEC_GROUP;
  p                  : POSSL_PARAM;
  pub_key ,genbuf    : PByte;
  libctx             : POSSL_LIB_CTX;
  propq              : PUTF8Char;
  bnctx              : PBN_CTX;
  ecbits,
  sec_bits,
  explicitparams,
  ecdh_cofactor_mode : integer;
  label _err;
begin
    ret := Boolean(0);
    eck := key;
    ecg := nil;
    pub_key := nil; genbuf := nil;
    bnctx := nil;
    ecg := EC_KEY_get0_group(eck);
    if ecg = nil then Exit(0);
    libctx := ossl_ec_key_get_libctx(eck);
    propq := ossl_ec_key_get0_propq(eck);
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then Exit(0);
    BN_CTX_start(bnctx);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE );
    if (p  <> nil )
         and   (0>= OSSL_PARAM_set_int(p, ECDSA_size(eck))) then
        goto _err ;
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p  <> nil)
         and (0>= OSSL_PARAM_set_int(p, EC_GROUP_order_bits(ecg))) then
        goto _err ;
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS );
    if (p <> nil) then
    begin
        ecbits := EC_GROUP_order_bits(ecg);
        {
         * The following estimates are based on the values published
         * in Table 2 of 'NIST Special Publication 800-57 Part 1 Revision 4'
         * at http://dx.doi.org/10.6028/NIST.SP.800-57pt1r4 .
         *
         * Note that the above reference explicitly categorizes algorithms in a
         * discrete set of values 80, 112, 128, 192, 256, and that it is
         * relevant only for NIST approved Elliptic Curves, while OpenSSL
         * applies the same logic also to other curves.
         *
         * Classifications produced by other standardazing bodies might differ,
         * so the results provided for 'bits of security' by this provider are
         * to be considered merely indicative, and it is the users'
         * responsibility to compare these values against the normative
         * references that may be relevant for their intent and purposes.
         }
        if ecbits >= 512 then
           sec_bits := 256
        else if (ecbits >= 384) then
            sec_bits := 192
        else if (ecbits >= 256) then
            sec_bits := 128
        else if (ecbits >= 224) then
            sec_bits := 112
        else if (ecbits >= 160) then
            sec_bits := 80
        else
            sec_bits := ecbits div 2;
        if  0>= OSSL_PARAM_set_int(p, sec_bits) then
            goto _err ;
    end;
    p := OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS);
    if (p <> nil)  then
    begin
        explicitparams := EC_KEY_decoded_from_explicit_params(eck);
        if (explicitparams < 0)
              or  (0>= OSSL_PARAM_set_int(p, explicitparams))  then
            goto _err ;
    end;
    if  0>= sm2 then
    begin
        p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
        if (p  <> nil)
                 and (0>= OSSL_PARAM_set_utf8_string(p, EC_DEFAULT_MD)) then
            goto _err ;
    end
    else
    begin
       p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
       if (p  <> nil)
                 and (0>= OSSL_PARAM_set_utf8_string(p, SM2_DEFAULT_MD)) then
            goto _err ;
    end;
    { SM2 doesn't support this PARAM }
    if  0>= sm2 then
    begin
        p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
        if p <> nil then
        begin
            ecdh_cofactor_mode := 0;
            ecdh_cofactor_mode := get_result( (EC_KEY_get_flags(eck) and EC_FLAG_COFACTOR_ECDH)>0 , 1 , 0);
            if  0>= OSSL_PARAM_set_int(p, ecdh_cofactor_mode ) then
                goto _err ;
        end;
    end;
    p := OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p <> nil)  then
    begin
        p.return_size := EC_POINT_point2oct(EC_KEY_get0_group(key),
                                            EC_KEY_get0_public_key(key),
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            p.data, p.return_size, bnctx);
        if p.return_size = 0 then goto _err ;
    end;
    ret := (ec_get_ecm_params(ecg, params)>0)
           and  (ossl_ec_group_todata(ecg, nil, params, libctx, propq, bnctx,
                                  @genbuf)>0)
           and  (key_to_params(eck, nil, params, 1, @pub_key)>0)
           and  (otherparams_to_params(eck, nil, params)>0);
_err:
    OPENSSL_free(Pointer(genbuf));
    OPENSSL_free(Pointer(pub_key));
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    Result := Int(ret);
end;





function common_check_sm2(const ec : PEC_KEY; sm2_wanted : integer):integer;
var
  ecg : PEC_GROUP;
  ok: Boolean;
begin
    ecg := nil;
    {
     * sm2_wanted: import the keys or domparams only on SM2 Curve
     * !sm2_wanted: import the keys or domparams only not on SM2 Curve
     }
    ecg := EC_KEY_get0_group(ec);
    ok := (EC_GROUP_get_curve_name(ecg) = NID_sm2);
    if (ecg  = nil)
         or  ( (sm2_wanted  xor  Int(ok)) >0 )    then
        Exit(0);
    Result := 1;
end;




function common_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM; sm2_wanted : integer):integer;
var
    ec              : PEC_KEY;

  ok: Boolean;
  include_private : integer;
begin
    ec := keydata;
    ok := Boolean(1);
    if  (not ossl_prov_is_running)  or  (ec = nil)  then
        Exit(0);
    {
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters (+optional other params)
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated domain parameters and optional public key
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters are always optional
     }
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) = 0 then
        Exit(0);
    ok := (ok)  and  (ossl_ec_group_fromdata(ec, params)>0);
    if  0>= common_check_sm2(ec, sm2_wanted) then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) <> 0 then
    begin
        include_private := get_result(
            (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY )>0, 1 , 0);
        ok := (ok)  and  (ossl_ec_key_fromdata(ec, params, include_private)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) <> 0 then
        ok := (ok)  and  (ossl_ec_key_otherparams_fromdata(ec, params)>0);
    Result := Int(ok);
end;

function ec_imexport_types( selection : integer):POSSL_PARAM;
var
    type_select : integer;

begin
    type_select := 0;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        type_select  := type_select + 1;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        type_select  := type_select + 2;
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        type_select  := type_select + 4;
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) <> 0 then
        type_select  := type_select + 8;
    Result := ec_types[type_select];
end;


function otherparams_to_params(const ec : PEC_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
    ecdh_cofactor_mode,
    group_check : integer;
    name               : PUTF8Char;
    format             : point_conversion_form_t;
begin
    ecdh_cofactor_mode := 0; group_check := 0;
    name := nil;
    if ec = nil then Exit(0);
    format := EC_KEY_get_conv_form(ec);
    name := ossl_ec_pt_format_id2name(int(format));
    if (name <> nil )
         and (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                             name)) then
        Exit(0);
    group_check := EC_KEY_get_flags(ec) and EC_FLAG_CHECK_NAMED_GROUP_MASK;
    name := ossl_ec_check_group_type_id2name(group_check);
    if (name <> nil)
         and (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
                                             name) ) then
        Exit(0);
    if ( (EC_KEY_get_enc_flags(ec) and EC_PKEY_NO_PUBKEY) <> 0)
             and (0>= ossl_param_build_set_int(tmpl, params,
                                         OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0))  then
        Exit(0);
    ecdh_cofactor_mode := get_result( (EC_KEY_get_flags(ec) and EC_FLAG_COFACTOR_ECDH) >0, 1 , 0);
    Exit(ossl_param_build_set_int(tmpl, params,
                                    OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                    ecdh_cofactor_mode));
end;

function key_to_params(const eckey : PEC_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM; include_private : integer; pub_key : PPByte):integer;
var
  sz : size_t;

  ecbits : integer;

  x, y,
  priv_key    : PBIGNUM;

    pub_point   : PEC_POINT;

    ecg         : PEC_GROUP;

    pub_key_len : size_t;

    ret         : integer;

    bnctx       : PBN_CTX;

    p, px, py  : POSSL_PARAM;
    label _err;
begin
    x := nil; y := nil;
    priv_key := nil;
    pub_point := nil;
     ecg := nil;
    pub_key_len := 0;
    ret := 0;
    bnctx := nil;
    ecg := EC_KEY_get0_group(eckey);
    if (eckey = nil) or  (ecg = nil) then
        Exit(0);
    priv_key := EC_KEY_get0_private_key(eckey);
    pub_point := EC_KEY_get0_public_key(eckey);
    if pub_point <> nil then
    begin
        p := nil; px := nil; py := nil;
        {
         * EC_POINT_point2buf() can generate random numbers in some
         * implementations so we need to ensure we use the correct libctx.
         }
        bnctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(eckey));
        if bnctx = nil then goto _err ;
        { If we are doing a get then check first before decoding the poPInteger }
        if tmpl = nil then
        begin
            p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
            px := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
            py := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
        end;
        if (p <> nil)  or  (tmpl <> nil) then
        begin
            { convert pub_point to a octet string according to the SECG standard }
            pub_key_len := EC_POINT_point2buf(ecg, pub_point,
                                                  POINT_CONVERSION_COMPRESSED,
                                                  pub_key, bnctx);
            if (pub_key_len = 0 )
                 or (0>= ossl_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PUB_KEY,
                                                      pub_key^, pub_key_len)) then
                goto _err ;
        end;
        if (px <> nil)  or  (py <> nil) then
        begin
            if px <> nil then
                x := BN_CTX_get(bnctx);
            if py <> nil then
                y := BN_CTX_get(bnctx);
            if  0>= EC_POINT_get_affine_coordinates(ecg, pub_point, x, y, bnctx) then
                goto _err ;
            if (px <> nil)
                 and   (0>= ossl_param_build_set_bn(tmpl, px,
                                            OSSL_PKEY_PARAM_EC_PUB_X, x ))then
                goto _err ;
            if (py <> nil)
                 and  (0>= ossl_param_build_set_bn(tmpl, py,
                                            OSSL_PKEY_PARAM_EC_PUB_Y, y ) )then
                goto _err ;
        end;
   end;
   if (priv_key <> nil)  and  (include_private >0)then
   begin
        ecbits := EC_GROUP_order_bits(ecg);
        if ecbits <= 0 then goto _err ;
        sz := (ecbits + 7) div 8;
        if 0>= ossl_param_build_set_bn_pad(tmpl, params,
                                         OSSL_PKEY_PARAM_PRIV_KEY,
                                         priv_key, sz ) then
            goto _err ;
    end;
    ret := 1;
 _err:
    BN_CTX_free(bnctx);
    Result := ret;
end;

function ec_dup(const keydata_from : Pointer; selection : integer):Pointer;
begin
    if ossl_prov_is_running( ) then
        Exit(ossl_ec_key_dup(keydata_from, selection));
    Result := nil;
end;


function ec_query_operation_name( operation_id : integer):PUTF8Char;
begin
    case operation_id of
    OSSL_OP_KEYEXCH:
        Exit('ECDH');
    OSSL_OP_SIGNATURE:
        Exit('ECDSA');
    end;
    Result := nil;
end;

function ec_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
    ec              : PEC_KEY;

    tmpl            : POSSL_PARAM_BLD;

    params          : POSSL_PARAM;

    pub_key ,genbuf        : PByte;

    bnctx           : PBN_CTX;

  ok: Boolean;
  include_private : integer;
  label _end;
begin
    ec := keydata;
    tmpl := nil;
    params := nil;
    pub_key := nil; genbuf := nil;
    bnctx := nil;
    ok := Boolean(1);
    if  (not ossl_prov_is_running) or  (ec = nil) then
        Exit(0);
    {
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters (+optional other params)
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated public key and domain parameters
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters are always optional
     }
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)= 0 then
        Exit(0);
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)
             and ( (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) = 0) then
        Exit(0);
    if ( (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) <> 0 )
             and ( (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) = 0)  then
        Exit(0);
    tmpl := OSSL_PARAM_BLD_new();
    if tmpl = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
    begin
        bnctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
        if bnctx = nil then
        begin
            ok := False;
            goto _end ;
        end;
        BN_CTX_start(bnctx);
        ok := (ok)  and  (ossl_ec_group_todata(EC_KEY_get0_group(ec), tmpl, nil,
                                        ossl_ec_key_get_libctx(ec),
                                        ossl_ec_key_get0_propq(ec),
                                        bnctx, @genbuf)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        include_private := get_result(
            (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY)>0 , 1 , 0);
        ok := (ok)  and  (key_to_params(ec, tmpl, nil, include_private, @pub_key)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) <> 0 then
        ok := (ok)  and  (otherparams_to_params(ec, tmpl, nil)>0);
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if (ok)  and  (params <> nil) then
        ok := Boolean(param_cb(params, cbarg));
_end:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_free(Pointer(pub_key));
    OPENSSL_free(Pointer(genbuf));
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    Result := Int(ok);
end;




function ec_import_types( selection : integer):POSSL_PARAM;
begin
    Result := ec_imexport_types(selection);
end;


function ec_export_types( selection : integer):POSSL_PARAM;
begin
    Result := ec_imexport_types(selection);
end;


function ec_get_ecm_params(const group : PEC_GROUP; params : POSSL_PARAM):integer;
var
    ret,m      : integer;
    k1,k2,k3   : uint32;
    basis_nid  : integer;
    basis_name : PUTF8Char;
    fid        : integer;
    label _err;
begin
{$IFDEF OPENSSL_NO_EC2M}
    Exit(1);
{$ELSE} ret := 0;
    k1 := 0; k2 := 0; k3 := 0;
    basis_name := nil;
    fid := EC_GROUP_get_field_type(group);
    if fid <> NID_X9_62_characteristic_two_field then Exit(1);
    basis_nid := EC_GROUP_get_basis_type(group);
    if basis_nid = NID_X9_62_tpBasis then
       basis_name := SN_X9_62_tpBasis
    else
    if (basis_nid = NID_X9_62_ppBasis) then
        basis_name := SN_X9_62_ppBasis
    else
        goto _err ;
    m := EC_GROUP_get_degree(group);
    if  (0>= ossl_param_build_set_int(nil, params, OSSL_PKEY_PARAM_EC_CHAR2_M, m) )
      or(0>= ossl_param_build_set_utf8_string(nil, params,
                                             OSSL_PKEY_PARAM_EC_CHAR2_TYPE,
                                             basis_name)) then
        goto _err ;
    if basis_nid = NID_X9_62_tpBasis then
    begin
        if  (0>= EC_GROUP_get_trinomial_basis(group, @k1))
             or  (0>= ossl_param_build_set_int(nil, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS,
                                         int(k1))) then
            goto _err ;
    end
    else
    begin
        if (0>= EC_GROUP_get_pentanomial_basis(group, @k1, @k2, @k3 ))  or
           (0>= ossl_param_build_set_int(nil, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, int(k1)))
             or  (0>= ossl_param_build_set_int(nil, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_PP_K2, int(k2)))
             or  (0>= ossl_param_build_set_int(nil, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, int(k3)))then
            goto _err ;
    end;
    ret := 1;
_err:
    Exit(ret);
{$endif} { OPENSSL_NO_EC2M }
end;



function ec_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
begin
    Result := common_import(keydata, selection, params, 0);
end;




function ec_validate(const keydata : Pointer; selection, checktype : integer):integer;
var
  eck : PEC_KEY;

  ok : Boolean;

  ctx : PBN_CTX;

  flags : integer;
begin
   eck := keydata;
    ok := Boolean(1);
    ctx := nil;
    if  not ossl_prov_is_running()  then
        Exit(0);
    if (selection and EC_POSSIBLE_SELECTIONS ) = 0 then
       Exit(1); { nothing to validate }
    ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(eck));
    if ctx = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
    begin
        flags := EC_KEY_get_flags(eck);
        if  (flags and EC_FLAG_CHECK_NAMED_GROUP ) <> 0 then
            ok := (ok)  and  (EC_GROUP_check_named_curve(EC_KEY_get0_group(eck),
                              int( (flags and EC_FLAG_CHECK_NAMED_GROUP_NIST) <> 0), ctx) > 0)
        else
            ok := (ok)  and  (EC_GROUP_check(EC_KEY_get0_group(eck), ctx)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
    begin
        if checktype = OSSL_KEYMGMT_VALIDATE_QUICK_CHECK then
            ok := (ok)  and  (ossl_ec_key_public_check_quick(eck, ctx)>0)
        else
            ok := (ok)  and  (ossl_ec_key_public_check(eck, ctx)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        ok := (ok)  and ( ossl_ec_key_private_check(eck)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = OSSL_KEYMGMT_SELECT_KEYPAIR then
        ok := (ok)  and  (ossl_ec_key_pairwise_check(eck, ctx)>0);
    BN_CTX_free(ctx);
    Result := Int(ok);
end;

function ec_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
var
  ec1,
  ec2         : PEC_KEY;
  group_a,
  group_b     : PEC_GROUP;
  ctx         : PBN_CTX;

  ok          : Boolean;
  key_checked : integer;

  pa1,
  pb1          : PEC_POINT;
  pa2,
  pb2          : PBIGNUM;
begin
    ec1 := keydata1;
    ec2 := keydata2;
    group_a := EC_KEY_get0_group(ec1);
    group_b := EC_KEY_get0_group(ec2);
    ctx := nil;
    ok := Boolean(1);
    if  not ossl_prov_is_running() then
        Exit(0);
    ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(ec1));
    if ctx = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        ok := (ok)  and  (group_a <> nil)  and  (group_b <> nil)
             and  (EC_GROUP_cmp(group_a, group_b, ctx) = 0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        key_checked := 0;
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 then
        begin
             pa1 := EC_KEY_get0_public_key(ec1);
             pb1 := EC_KEY_get0_public_key(ec2);
            if (pa1 <> nil)  and  (pb1 <> nil) then
            begin
                ok := (ok)  and  (EC_POINT_cmp(group_b, pa1, pb1, ctx) = 0);
                key_checked := 1;
            end;
        end;
        if  (0>= key_checked)
             and ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)  then
        begin
             pa2 := EC_KEY_get0_private_key(ec1);
             pb2 := EC_KEY_get0_private_key(ec2);
            if (pa2 <> nil)  and  (pb2 <> nil) then
            begin
                ok := (ok)  and  (BN_cmp(pa2, pb2) = 0);
                key_checked := 1;
            end;
        end;
        ok := (ok)  and  (key_checked>0);
    end;
    BN_CTX_free(ctx);
    Result := Int(ok);
end;

function ec_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ec_known_settable_params[0];
end;

function ec_set_params(key : Pointer;const params : POSSL_PARAM):integer;
var
  eck : PEC_KEY;
  ctx : PBN_CTX;
  p   : POSSL_PARAM;
  ret : integer;
begin
   eck := key;
    if key = nil then Exit(0);
    if params = nil then Exit(1);
    if  0>= ossl_ec_group_set_params(PEC_GROUP(EC_KEY_get0_group(key)), params)   then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if p <> nil then
    begin
        ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
        ret := 1;
        if (ctx = nil)
                 or ( p.data_type <> OSSL_PARAM_OCTET_STRING)
                 or (0>= EC_KEY_oct2key(key, p.data, p.data_size, ctx))  then
            ret := 0;
        BN_CTX_free(ctx);
        if  0>= ret then
           Exit(0);
    end;
    Result := ossl_ec_key_otherparams_fromdata(eck, params);
end;



function ec_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ec_known_gettable_params[0];
end;


function ec_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    Result := common_get_params(key, params, 0);
end;

procedure ec_freedata( keydata : Pointer);
begin
    EC_KEY_free(keydata);
end;


function ec_has(const keydata : Pointer; selection : integer):integer;
var
  ec : PEC_KEY;

  ok : Boolean;
begin
    ec := keydata;
    ok := Boolean(1);
    if ( not ossl_prov_is_running)  or  (ec = nil)  then
        Exit(0);
    if (selection and EC_POSSIBLE_SELECTIONS ) = 0 then Exit(1); { the selection is not missing }
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := (ok)  and  (EC_KEY_get0_public_key(ec) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        ok := (ok)  and  (EC_KEY_get0_private_key(ec) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0 then
        ok := ok  and  (EC_KEY_get0_group(ec) <> nil);
    {
     * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be
     * available, so no extra check is needed other than the previous one
     * against EC_POSSIBLE_SELECTIONS.
     }
    Result := Int(ok);
end;

function ec_load(const reference : Pointer; reference_sz : size_t):Pointer;
begin
    Result := common_load(reference, reference_sz, 0);
end;

procedure ec_gen_cleanup( genctx : Pointer);
var
  gctx : Pec_gen_ctx;
begin
    gctx := genctx;
    if gctx = nil then exit;
    EC_GROUP_free(gctx.gen_group);
    BN_free(gctx.p);
    BN_free(gctx.a);
    BN_free(gctx.b);
    BN_free(gctx.order);
    BN_free(gctx.cofactor);
    OPENSSL_free(Pointer(gctx.group_name));
    OPENSSL_free(Pointer(gctx.field_type));
    OPENSSL_free(Pointer(gctx.pt_format));
    OPENSSL_free(Pointer(gctx.encoding));
    OPENSSL_free(Pointer(gctx.seed));
    OPENSSL_free(Pointer(gctx.gen));
    OPENSSL_free(Pointer(gctx));
end;



function ec_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pec_gen_ctx;
  ec : PEC_KEY;
  ret: Boolean;
  flags, format : integer;
  label _err;
begin
   gctx := genctx;
   ec := nil;
    ret := Boolean(0);
    ec := EC_KEY_new_ex(gctx.libctx, nil);
    if  (not ossl_prov_is_running)  or  (gctx = nil)
         or  (ec = nil)  then
        Exit(nil);
    if gctx.gen_group = nil then
    begin
        if  0>= ec_gen_set_group_from_params(gctx) then
            goto _err ;
    end
    else
    begin
        if gctx.encoding <> nil then
        begin
            flags := ossl_ec_encoding_name2id(gctx.encoding);
            if flags < 0 then goto _err ;
            EC_GROUP_set_asn1_flag(gctx.gen_group, flags);
        end;
        if gctx.pt_format <> nil then
        begin
            format := ossl_ec_pt_format_name2id(gctx.pt_format);
            if format < 0 then
               goto _err ;
            EC_GROUP_set_point_conversion_form(gctx.gen_group,
                       point_conversion_form_t(format));
        end;
    end;
    { We must always assign a group, no matter what }
    ret := ec_gen_assign_group(ec, gctx.gen_group);
    { Whether you want it or not, you get a keypair, not just one half }
    if (gctx.selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ret := (ret)  and  (EC_KEY_generate_key(ec)>0);
    if gctx.ecdh_mode <> -1 then
       ret := (ret)  and  (ossl_ec_set_ecdh_cofactor_mode(ec, gctx.ecdh_mode)>0);
    if gctx.group_check <> nil then
       ret := (ret)  and  (ossl_ec_set_check_group_type_from_name(ec, gctx.group_check)>0);
    if ret then
       Exit(ec);
_err:
    { Something went wrong, throw the key away }
    EC_KEY_free(ec);
    Result := nil;
end;

var
  settable : array[0..12] of TOSSL_PARAM;
function ec_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    settable[0] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
    settable[1] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil);
    settable[2] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0);
    settable[3] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0);
    settable[4] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0);
    settable[5] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0);
    settable[6] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0);
    settable[7] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0);
    settable[8] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0);
    settable[9] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0);
    settable[10] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0);
    settable[11] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0);
    settable[12] := OSSL_PARAM_END;
    Result := @settable;
end;

function ec_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  ret : integer;
  gctx : Pec_gen_ctx;
  p : POSSL_PARAM;
  group : PEC_GROUP;
  label _err;

  function COPY_INT_PARAM(const params : POSSL_PARAM; const key: PUTF8Char; val: int): Boolean;
  begin
    Result := True;
    p := OSSL_PARAM_locate_const(params, key);
    if (p <> nil) and (0>= OSSL_PARAM_get_int(p, @val)) then
       Result := False;
  end;

  function COPY_OCTET_PARAM(const params : POSSL_PARAM; const key: PUTF8Char; val: Pointer; len: int): Boolean;
  begin
      Result := True;
      p := OSSL_PARAM_locate_const(params, key);
      if p <> nil then
      begin
          if p.data_type <> OSSL_PARAM_OCTET_STRING then
             OPENSSL_free(val);
          len := p.data_size;
          val := OPENSSL_memdup(p.data, p.data_size);
          if val = nil then
             Result := False;
      end;
  end;

  function COPY_UTF8_PARAM(const params : POSSL_PARAM; const key: PUTF8Char; val: Pointer): Boolean;
  begin

    Result := True;
    p := OSSL_PARAM_locate_const(params, key);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
        OPENSSL_free(val);
        OPENSSL_strdup(PUTF8Char(val) ,p.data);
        if val = nil then
           Result := False;
    end;

  end;

  function COPY_BN_PARAM(const params : POSSL_PARAM; const key: PUTF8Char; bn: PBIGNUM): Boolean;
  begin
     Result := True;
     p := OSSL_PARAM_locate_const(params, key);
    if p <> nil then
    begin
        if bn = nil then
            bn := BN_new();
        if (bn = nil)  or   (0>= OSSL_PARAM_get_BN(p, @bn)) then
           Result := False;
    end;
  end;
begin
    ret := 0;
    gctx := genctx;
    group := nil;
    if not COPY_INT_PARAM(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, gctx.ecdh_mode) then
        goto _err;
    if not COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_GROUP_NAME, gctx.group_name) then
        goto _err;
    if not COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE, gctx.field_type) then
        goto _err;
    if not COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_ENCODING, gctx.encoding) then
        goto _err;
    if not COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, gctx.pt_format)then
        goto _err;
    if not COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, gctx.group_check) then
        goto _err;
    if not COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_P, gctx.p) then
        goto _err;
    if not COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_A, gctx.a) then
         goto _err;
    if not COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_B, gctx.b) then
        goto _err;
    if not COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_ORDER, gctx.order) then
        goto _err;
    if not COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_COFACTOR, gctx.cofactor) then
        goto _err;
    if not COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_EC_SEED, gctx.seed, gctx.seed_len) then
        goto _err;
    if not COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_EC_GENERATOR, gctx.gen,
                     gctx.gen_len) then
         goto _err;
    ret := 1;

_err:
    EC_GROUP_free(group);
    Result := ret;
end;

function ec_gen_set_template( genctx, templ : Pointer):integer;
var
  gctx : Pec_gen_ctx;
  ec_group: PEC_GROUP ;
  ec : PEC_KEY;
begin
    gctx := genctx;
    ec := templ;
    if  (not ossl_prov_is_running) or  (gctx = nil)  or  (ec = nil) then
        Exit(0);
    ec_group := EC_KEY_get0_group(ec );
    if ec_group = nil then
        Exit(0);
    Result := ec_gen_set_group(gctx, ec_group);
end;

function ec_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  libctx : POSSL_LIB_CTX;
  gctx : Pec_gen_ctx;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    gctx := nil;
    if  (not ossl_prov_is_running)  or ( (selection and (EC_POSSIBLE_SELECTIONS)) = 0) then
        Exit(nil);
    gctx := OPENSSL_zalloc(sizeof( gctx^));
    if gctx <> nil then
    begin
        gctx.libctx := libctx;
        gctx.selection := selection;
        gctx.ecdh_mode := 0;
    end;
    if  0>= ec_gen_set_params(gctx, params) then
    begin
        OPENSSL_free(Pointer(gctx));
        gctx := nil;
    end;
    Result := gctx;
end;

function ec_newdata( provctx : Pointer):Pointer;
begin
    if  not ossl_prov_is_running() then
        Exit(nil);
    Result := EC_KEY_new_ex(PROV_LIBCTX_OF(provctx), nil);
end;

initialization
  ec_private_key_types := [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    OSSL_PARAM_END
];
  ec_public_key_types :=  [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    OSSL_PARAM_END
];
ec_key_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    OSSL_PARAM_END
];
ec_dom_parameters_types :=  [
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    OSSL_PARAM_END
];
ec_5_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    OSSL_PARAM_END
];
ec_6_types :=  [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    OSSL_PARAM_END
];
ec_key_domp_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    OSSL_PARAM_END
];
ec_other_parameters_types :=  [
     _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_9_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
     _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_10_types :=  [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
     _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_11_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
     _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_all_parameters_types :=  [
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
     _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_13_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
     _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_14_types :=  [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];
ec_all_types :=  [
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];

 ec_known_settable_params := [
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, nil, 0),
    OSSL_PARAM_END
];

ec_known_gettable_params := [
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, nil),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_M, nil),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_CHAR2_TYPE, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K2, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, nil),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, nil),
    OSSL_PARAM_END
];

 sm2_known_settable_params := [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0),
    OSSL_PARAM_END
];
 sm2_known_gettable_params := [
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0),
    _OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, nil),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_PUB_X, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_PUB_Y, nil, 0),
    _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    OSSL_PARAM_END
];

ec_types := [
    nil,
    @ec_private_key_types[0],
    @ec_public_key_types[0],
    @ec_key_types[0],
    @ec_dom_parameters_types[0],
    @ec_5_types[0],
    @ec_6_types[0],
    @ec_key_domp_types[0],
    @ec_other_parameters_types[0],
    @ec_9_types[0],
    @ec_10_types[0],
    @ec_11_types[0],
    @ec_all_parameters_types[0],
    @ec_13_types[0],
    @ec_14_types[0],
    @ec_all_types[0]
];

end.
