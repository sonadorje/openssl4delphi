unit OpenSSL3.providers.implementations.keymgmt.dh_kmgmt;

interface
uses OpenSSL.Api;

function dh_newdata( provctx : Pointer):Pointer;
function dh_gen_set_template( genctx, templ : Pointer):integer;
function dh_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
function dh_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
function dh_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function dh_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
procedure dh_gen_cleanup( genctx : Pointer);
function dh_load(const reference : Pointer; reference_sz : size_t):Pointer;
procedure dh_freedata( keydata : Pointer);
function dh_get_params( key : Pointer; params : POSSL_PARAM):integer;
function dh_gettable_params( provctx : Pointer):POSSL_PARAM;
function dh_set_params(key : Pointer;const params : POSSL_PARAM):integer;
function dh_settable_params( provctx : Pointer):POSSL_PARAM;
function dh_has(const keydata : Pointer; selection : integer):integer;
function dh_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
function dh_validate(const keydata : Pointer; selection, checktype : integer):integer;
function dh_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
function dh_import_types( selection : integer):POSSL_PARAM;
function dh_export_types( selection : integer):POSSL_PARAM;
function dh_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
function dh_dup(const keydata_from : Pointer; selection : integer):Pointer;
function dhx_newdata( provctx : Pointer):Pointer;
function dhx_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function dhx_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
function dhx_query_operation_name( operation_id : integer):PUTF8Char;
function dhx_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;

const

   ossl_dhx_keymgmt_functions: array[0..22] of TOSSL_DISPATCH  = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW; method:(code:@dhx_newdata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_INIT; method:(code:@dhx_gen_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE; method:(code:@dh_gen_set_template ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS; method:(code:@dhx_gen_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS; method:(code:@dhx_gen_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN; method:(code:@dh_gen ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP; method:(code:@dh_gen_cleanup ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_LOAD; method:(code:@dh_load ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE; method:(code:@dh_freedata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS; method:(code:@dh_get_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS; method:(code:@dh_gettable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS; method:(code:@dh_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS; method:(code:@dh_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS; method:(code:@dh_has ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_MATCH; method:(code:@dh_match ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_VALIDATE; method:(code:@dh_validate ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT; method:(code:@dh_import ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES; method:(code:@dh_import_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT; method:(code:@dh_export ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES; method:(code:@dh_export_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME; method:(code:@dhx_query_operation_name ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_DUP; method:(code:@dh_dup ;data:nil)),
    (function_id: 0;  method:(code:nil ;data:nil))
);


   ossl_dh_keymgmt_functions: array[0..21] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_KEYMGMT_NEW;                 method:(code:@dh_newdata ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GEN_INIT;            method:(code:@dh_gen_init ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE;    method:(code:@dh_gen_set_template ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS;      method:(code:@dh_gen_set_params ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS; method:(code:@dh_gen_settable_params ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GEN;                 method:(code:@dh_gen ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP;         method:(code:@dh_gen_cleanup ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_LOAD;                method:(code:@dh_load ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_FREE;                method:(code:@dh_freedata ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS;          method:(code:@dh_get_params ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS;     method:(code:@dh_gettable_params ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS;          method:(code:@dh_set_params ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS;     method:(code:@dh_settable_params ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_HAS;                 method:(code:@dh_has ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_MATCH;               method:(code:@dh_match ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_VALIDATE;            method:(code:@dh_validate ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_IMPORT;              method:(code:@dh_import ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES;        method:(code:@dh_import_types ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_EXPORT;              method:(code:@dh_export ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES;        method:(code:@dh_export_types ;data:nil)),
    ( function_id: OSSL_FUNC_KEYMGMT_DUP;                 method:(code:@dh_dup ;data:nil)),
    ( function_id: 0;                                     method:(code:nil ;data:nil))
);

var// 1d arrays
  dh_gen_settable    : array[0..5]  of TOSSL_PARAM ;
  dh_key_types       : array[0..2]  of TOSSL_PARAM ;
  dh_parameter_types : array[0..10] of TOSSL_PARAM ;
  dh_all_types       : array[0..12] of TOSSL_PARAM ;
  dh_known_settable_params: array[0..1] of TOSSL_PARAM ;
  dh_params: array[0..16] of TOSSL_PARAM ;
  dhx_gen_settable : array[0..11] of TOSSL_PARAM;

const
  dh_types: array[0..3] of POSSL_PARAM  = (
    nil,                        // Index 0 = none of them
    @dh_parameter_types,          // Index 1 = parameter types
    @dh_key_types,                // Index 2 = key types
    @dh_all_types                 // Index 3 = 1 + 2
);



function dh_imexport_types( selection : integer):POSSL_PARAM;
function dh_validate_public(const dh : PDH; checktype : integer):integer;
function dh_validate_private(const dh : PDH):integer;
function dh_gencb( p, n : integer; cb : PBN_GENCB):integer;
function dh_gen_common_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
function dh_gen_type_name2id_w_default(const name : PUTF8Char; &type : integer):integer;
function dh_gen_init_base(provctx : Pointer; selection : integer;const params : POSSL_PARAM; &type : integer):Pointer;
function dh_set_gen_seed( gctx : Pdh_gen_ctx; seed : PByte; seedlen : size_t):integer;

implementation
uses openssl3.crypto.mem_sec,               openssl3.providers.fips.self_test,
     openssl3.crypto.mem,                   openssl3.providers.common.provider_ctx,
     openssl3.crypto.context,               openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,                  OpenSSL3.providers.implementations.rands.crngt,
     OpenSSL3.openssl.params,               openssl3.crypto.params,
     OpenSSL3.threads_none,                 OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.rand.rand_pool,        OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib,           openssl3.crypto.evp.mac_lib,
     openssl3.crypto.dh.dh_backend,         openssl3.crypto.param_build,
     openssl3.crypto.params_dup,            openssl3.crypto.dh.dh_group_params,
     openssl3.crypto.dh.dh_check,           openssl3.crypto.dh.dh_lib,
     openssl3.crypto.ffc.ffc_params,        openssl3.crypto.dh.dh_key,
     openssl3.crypto.dh.dh_gen,             openssl3.crypto.bn.bn_lib,
     openssl3.crypto.dh.dh_support,         openssl3.crypto.ffc.ffc_dh,
     openssl3.crypto.o_str,                 OpenSSL3.Err,
     OpenSSL3.providers.implementations.rands.seeding.rand_win;


function dhx_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Result := dh_gen_init_base(provctx, selection, params, DH_FLAG_TYPE_DHX);
end;

function dh_set_gen_seed( gctx : Pdh_gen_ctx; seed : PByte; seedlen : size_t):integer;
begin
    OPENSSL_clear_free(Pointer(gctx.seed), gctx.seedlen);
    gctx.seed := nil;
    gctx.seedlen := 0;
    if (seed <> nil)  and  (seedlen > 0) then
    begin
        gctx.seed := OPENSSL_memdup(seed, seedlen);
        if gctx.seed = nil then Exit(0);
        gctx.seedlen := seedlen;
    end;
    Result := 1;
end;


function dhx_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    dhx_gen_settable[0] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, nil, 0);
    dhx_gen_settable[1] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
    dhx_gen_settable[2] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, nil);
    dhx_gen_settable[3] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, nil);
    dhx_gen_settable[4] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_QBITS, nil);
    dhx_gen_settable[5] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, nil, 0);
    dhx_gen_settable[6] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, nil, 0);
    dhx_gen_settable[7] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
    dhx_gen_settable[8] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
    dhx_gen_settable[9] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
    dhx_gen_settable[10] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
    dhx_gen_settable[11] := OSSL_PARAM_END;

    Result := @dhx_gen_settable;
end;

function dhx_query_operation_name( operation_id : integer):PUTF8Char;
begin
    Result := 'DH';
end;

function dhx_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  gctx : Pdh_gen_ctx;
  p : POSSL_PARAM;
begin
    gctx := genctx;
    if 0>= dh_gen_common_set_params(genctx, params) then
        Exit(0);
    { Parameters related to fips186-4 and fips186-2 }
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @gctx.gindex) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @gctx.pcounter) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @gctx.hindex) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
    if (p <> nil)
         and ( (p.data_type <> OSSL_PARAM_OCTET_STRING)  or
               (0>= dh_set_gen_seed(gctx, p.data, p.data_size)) ) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS) ;
    if (p <> nil)
         and  (0>= OSSL_PARAM_get_size_t(p, @gctx.qbits))  then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
    if p <> nil then begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        OPENSSL_free(Pointer(gctx.mdname));
        OPENSSL_strdup(gctx.mdname ,p.data);
        if gctx.mdname = nil then Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
    if p <> nil then begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        OPENSSL_free(Pointer(gctx.mdprops));
        OPENSSL_strdup(gctx.mdprops ,p.data);
        if gctx.mdprops = nil then Exit(0);
    end;
    { Parameters that are(0>= allowed for DHX }
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
    if p <> nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        Exit(0);
    end;
    Result := 1;
end;

(******************************************************************************)

function dhx_newdata( provctx : Pointer):Pointer;
var
  dh : PDH;
begin
    dh := nil;
    dh := ossl_dh_new_ex(PROV_LIBCTX_OF(provctx));
    if dh <> nil then begin
        DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
        DH_set_flags(dh, DH_FLAG_TYPE_DHX);
    end;
    Result := dh;
end;



function dh_gen_init_base(provctx : Pointer; selection : integer;const params : POSSL_PARAM; &type : integer):Pointer;
var
  libctx : POSSL_LIB_CTX;
  gctx : Pdh_gen_ctx;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    gctx := nil;
    if  not ossl_prov_is_running()  then
        Exit(nil);
    if  (selection>0) and ((OSSL_KEYMGMT_SELECT_KEYPAIR
                      or OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) = 0)  then
        Exit(nil);
    gctx := OPENSSL_zalloc(sizeof(gctx^ ));
    if gctx <> nil then
    begin
        gctx.selection := selection;
        gctx.libctx := libctx;
        gctx.pbits := 2048;
        gctx.qbits := 224;
        gctx.mdname := nil;
{$IFDEF FIPS_MODULE}
        gctx.gen_type := (type = DH_FLAG_TYPE_DHX)
                         ? DH_PARAMGEN_TYPE_FIPS_186_4
                         : DH_PARAMGEN_TYPE_GROUP;
{$ELSE} gctx.gen_type := get_result (&type = DH_FLAG_TYPE_DHX
                         , DH_PARAMGEN_TYPE_FIPS_186_2
                         , DH_PARAMGEN_TYPE_GENERATOR);
{$ENDIF}
        gctx.gindex := -1;
        gctx.hindex := 0;
        gctx.pcounter := -1;
        gctx.generator := DH_GENERATOR_2;
        gctx.dh_type := &type;
    end;
    if  0>= dh_gen_set_params(gctx, params) then
    begin
        OPENSSL_free(Pointer(gctx));
        gctx := nil;
    end;
    Result := gctx;
end;



function dh_gen_type_name2id_w_default(const name : PUTF8Char; &type : integer):integer;
begin
    if strcmp(name, 'default')= 0 then
    begin
{$IFDEF FIPS_MODULE}
        if &type = DH_FLAG_TYPE_DHX then
            Exit(DH_PARAMGEN_TYPE_FIPS_186_4);
        Exit(DH_PARAMGEN_TYPE_GROUP);
{$ELSE if type = DH_FLAG_TYPE_DHX then Exit(DH_PARAMGEN_TYPE_FIPS_186_2);}
        Exit(DH_PARAMGEN_TYPE_GENERATOR);
{$ENDIF}
    end;
    Result := ossl_dh_gen_type_name2id(name, &type);
end;

function dh_gen_common_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  gctx : Pdh_gen_ctx;
  p : POSSL_PARAM;
  group : PDH_NAMED_GROUP;
begin
    gctx := genctx;
    if gctx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
    if p <> nil then
    begin
       gctx.gen_type := dh_gen_type_name2id_w_default(p.data, gctx.dh_type);
        if (p.data_type <> OSSL_PARAM_UTF8_STRING)
             or  (gctx.gen_type = -1) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if p <> nil then
    begin
        group := nil;
        group := ossl_ffc_name_to_dh_named_group(p.data);
        gctx.group_nid := ossl_ffc_named_group_get_uid(group);
        if (p.data_type <> OSSL_PARAM_UTF8_STRING)
             or  (p.data = nil)
             or  (group = nil)
             or  (gctx.group_nid = NID_undef) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS) ;
    if (p <> nil)
         and (0>= OSSL_PARAM_get_size_t(p, @gctx.pbits))   then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
    if (p <> nil)  and   (0>= OSSL_PARAM_get_int(p, @gctx.priv_len) )then
        Exit(0);
    Result := 1;
end;




function dh_gencb( p, n : integer; cb : PBN_GENCB):integer;
var
  gctx : Pdh_gen_ctx;

  params : array[0..2] of TOSSL_PARAM;
begin
    gctx := BN_GENCB_get_arg(cb);
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;
    params[2] := OSSL_PARAM_END;

    params[0] := OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, @p);
    params[1] := OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, @n);
    Result := gctx.cb(@params, gctx.cbarg);
end;

function dh_validate_private(const dh : PDH):integer;
var
    status   : integer;

    priv_key : PBIGNUM;
begin
    status := 0;
    priv_key := nil;
    DH_get0_key(dh, nil, @priv_key);
    if priv_key = nil then Exit(0);
    Result := ossl_dh_check_priv_key(dh, priv_key, @status);
end;




function dh_validate_public(const dh : PDH; checktype : integer):integer;
var
  pub_key : PBIGNUM;

  res : integer;
begin
    pub_key := nil;
    res := 0;
    DH_get0_key(dh, @pub_key, nil);
    if pub_key = nil then Exit(0);
    { The partial test is only valid for named group's with q = (p - 1) / 2 }
    if (checktype = OSSL_KEYMGMT_VALIDATE_QUICK_CHECK)
         and  (ossl_dh_is_named_safe_prime_group(dh)>0)  then
        Exit(ossl_dh_check_pub_key_partial(dh, pub_key, @res));
    Result := DH_check_pub_key(dh, pub_key, @res);
end;


function dh_imexport_types( selection : integer):POSSL_PARAM;
var
    type_select : integer;
begin
    type_select := 0;
    if (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ) <> 0 then
        type_select  := type_select + 1;
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        type_select  := type_select + 2;
    Result := dh_types[type_select];
end;

function dh_dup(const keydata_from : Pointer; selection : integer):Pointer;
begin
    if ossl_prov_is_running() then
        Exit(ossl_dh_dup(keydata_from, selection));
    Result := nil;
end;


function dh_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
  dh : PDH;
  tmpl : POSSL_PARAM_BLD;
  params : POSSL_PARAM;
  ok : Boolean;
  label _err;
begin
    dh := keydata;
    tmpl := nil;
    params := nil;
    ok := Boolean(1);
    if (not ossl_prov_is_running)  or  (dh = nil)  then
        Exit(0);
    tmpl := OSSL_PARAM_BLD_new();
    if tmpl = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ) <> 0 then
        ok := (ok)  and  (ossl_dh_params_todata(dh, tmpl, nil)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (ossl_dh_key_todata(dh, tmpl, nil)>0);
    params := OSSL_PARAM_BLD_to_param(tmpl );
    if not( ok) or  (params = nil)then
    begin
        ok := Boolean(0);
        goto _err ;
    end;
    ok := Boolean(param_cb(params, cbarg));
    OSSL_PARAM_free(params);
_err:
    OSSL_PARAM_BLD_free(tmpl);
    Result := Int(ok);
end;



function dh_import_types( selection : integer):POSSL_PARAM;
begin
    Result := dh_imexport_types(selection);
end;


function dh_export_types( selection : integer):POSSL_PARAM;
begin
    Result := dh_imexport_types(selection);
end;


function dh_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
var
  dh : PDH;
  ok : Boolean;
begin
    dh := keydata;
    ok := Boolean(1);
    if (not ossl_prov_is_running) or  (dh = nil)  then
        Exit(0);
    if (selection and DH_POSSIBLE_SELECTIONS ) = 0 then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ) <> 0 then
        ok := (ok)  and  (ossl_dh_params_fromdata(dh, params)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (ossl_dh_key_fromdata(dh, params)>0);
    Result := Int(ok);
end;



function dh_validate(const keydata : Pointer; selection, checktype : integer):integer;
var
  dh : PDH;
  ok : Boolean;
begin
     dh := keydata;
    ok := Boolean(1);
    if not ossl_prov_is_running( ) then
        Exit(0);
    if (selection and DH_POSSIBLE_SELECTIONS ) = 0 then Exit(1); { nothing to validate }
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
    begin
        {
         * Both of these functions check parameters. DH_check_params_ex()
         * performs a lightweight check (e.g. it does0>= check that p is a
         * safe prime)
         }
        if checktype = OSSL_KEYMGMT_VALIDATE_QUICK_CHECK then
            ok := (ok)  and  (DH_check_params_ex(dh)>0)
        else
            ok := (ok)  and  (DH_check_ex(dh)>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := (ok)  and  (dh_validate_public(dh, checktype)>0);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        ok := (ok)  and  (dh_validate_private(dh)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = OSSL_KEYMGMT_SELECT_KEYPAIR then
        ok := (ok)  and  (ossl_dh_check_pairwise(dh)>0);
    Result := Int(ok);
end;



function dh_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
var
  dh1,
  dh2         : PDH;
  ok          : Boolean;
  key_checked : integer;
  pa,
  pb          : PBIGNUM;
  dhparams1,
  dhparams2   : PFFC_PARAMS;
begin
     dh1 := keydata1;
     dh2 := keydata2;
    ok := Boolean(1);
    if not ossl_prov_is_running( ) then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        key_checked := 0;
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 then
        begin
            pa := DH_get0_pub_key(dh1);
            pb := DH_get0_pub_key(dh2);
            if (pa <> nil)  and  (pb <> nil) then
            begin
                ok := Boolean(ok)  and  (BN_cmp(pa, pb) = 0);
                key_checked := 1;
            end;
        end;
        if (0>= key_checked)
             and ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)  then
        begin
            pa := DH_get0_priv_key(dh1);
            pb := DH_get0_priv_key(dh2);
            if (pa <> nil)  and  (pb <> nil) then
            begin
                ok := (ok)  and  (BN_cmp(pa, pb) = 0);
                key_checked := 1;
            end;
        end;
        ok := (ok)  and  (key_checked>0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0 then
    begin
        dhparams1 := ossl_dh_get0_params(PDH(dh1));
        dhparams2 := ossl_dh_get0_params(PDH(dh2));
        ok := (ok)  and  (ossl_ffc_params_cmp(dhparams1, dhparams2, 1)>0);
    end;
    Result := Int(ok);
end;



function dh_has(const keydata : Pointer; selection : integer):integer;
var
  dh : PDH;

  ok : Boolean;
begin
     dh := keydata;
    ok := Boolean(1);
    if (not ossl_prov_is_running) or  (dh = nil)  then
        Exit(0);
    if (selection and DH_POSSIBLE_SELECTIONS ) = 0 then
        Exit(1); { the selection is0>= missing }
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := (ok)  and  (DH_get0_pub_key(dh) <> nil) ;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        ok := ok  and  (DH_get0_priv_key(dh) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        ok := ok  and  ( (DH_get0_p(dh) <> nil)  and  (DH_get0_g(dh) <> nil) );
    Result := int(ok);
end;



function dh_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @dh_known_settable_params;
end;

function dh_set_params(key : Pointer;const params : POSSL_PARAM):integer;
var
  dh : PDH;
  p : POSSL_PARAM;
begin
    dh := key;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p <> nil)
             and  ( (p.data_type <> OSSL_PARAM_OCTET_STRING)
                 or (0>= ossl_dh_buf2key(dh, p.data, p.data_size)) ) then
        Exit(0);
    Result := 1;
end;

function dh_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @dh_params;
end;

function dh_get_params( key : Pointer; params : POSSL_PARAM):integer;
var
  dh : PDH;
  p : POSSL_PARAM;
begin
    dh := key;
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS );
    if (p  <> nil)
         and  (0>= OSSL_PARAM_set_int(p, _DH_bits(dh))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS );
    if (p  <> nil)
         and  (0>= OSSL_PARAM_set_int(p, _DH_security_bits(dh))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE );
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_int(p, DH_size(dh))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY );
    if (p <> nil) then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
            Exit(0);
        p.return_size := ossl_dh_key2buf(dh, PPByte (@p.data),
                                         p.data_size, 0);
        if p.return_size = 0 then Exit(0);
    end;
    Result := int( (ossl_dh_params_todata(dh, nil, params)>0)
                and(ossl_dh_key_todata(dh, nil, params)>0) );
end;



procedure dh_freedata( keydata : Pointer);
begin
    DH_free(keydata);
end;


function dh_load(const reference : Pointer; reference_sz : size_t):Pointer;
var
  dh : PDH;
begin
    dh := nil;
    if (ossl_prov_is_running) and  (reference_sz = sizeof(dh)) then
    begin
        { The contents of the reference is the address to our object }
        dh := PPDH(reference)^;
        { We grabbed, so we detach it }
        PPDH(reference)^ := nil;
        Exit(dh);
    end;
    Result := nil;
end;


procedure dh_gen_cleanup( genctx : Pointer);
var
  gctx: Pdh_gen_ctx;
begin
    gctx := genctx;
    if gctx = nil then exit;
    OPENSSL_free(Pointer(gctx.mdname));
    OPENSSL_free(Pointer(gctx.mdprops));
    OPENSSL_clear_free(Pointer(gctx.seed), gctx.seedlen);
    OPENSSL_free(Pointer(gctx));
end;



function dh_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  ret : integer;
  dh : PDH;
  gencb : PBN_GENCB;
  gctx: Pdh_gen_ctx;
  ffc : PFFC_PARAMS;
  label _end;
begin
    ret := 0;
    gctx := genctx;
    dh := nil;
    gencb := nil;
    if (not ossl_prov_is_running)  or  (gctx = nil) then
        Exit(nil);
    {
     * If a group name is selected then the type is group regardless of what the
     * the user selected. This overrides rather than errors for backwards
     * compatibility.
     }
    if gctx.group_nid <> NID_undef then
       gctx.gen_type := DH_PARAMGEN_TYPE_GROUP;
    { For parameter generation - If there is a group name just create it }
    if (gctx.gen_type = DH_PARAMGEN_TYPE_GROUP)
             and  (gctx.ffc_params = nil) then
    begin
        { Select a named group if there is0>= one already }
        if gctx.group_nid = NID_undef then
           gctx.group_nid := ossl_dh_get_named_group_uid_from_size(gctx.pbits);
        if gctx.group_nid = NID_undef then Exit(nil);
        dh := ossl_dh_new_by_nid_ex(gctx.libctx, gctx.group_nid);
        if dh = nil then
           Exit(nil);
        ffc := ossl_dh_get0_params(dh);
    end
    else
    begin
        dh := ossl_dh_new_ex(gctx.libctx);
        if dh = nil then Exit(nil);
        ffc := ossl_dh_get0_params(dh);
        { Copy the template value if one was passed }
        if (gctx.ffc_params <> nil)
             and  (0>= ossl_ffc_params_copy(ffc, gctx.ffc_params) ) then
            goto _end ;
        if (0>= ossl_ffc_params_set_seed(ffc, gctx.seed, gctx.seedlen) ) then
            goto _end ;
        if gctx.gindex <> -1 then
        begin
            ossl_ffc_params_set_gindex(ffc, gctx.gindex);
            if gctx.pcounter <> -1 then
               ossl_ffc_params_set_pcounter(ffc, gctx.pcounter);
        end
        else
        if (gctx.hindex <> 0) then
        begin
            ossl_ffc_params_set_h(ffc, gctx.hindex);
        end;
        if gctx.mdname <> nil then
        begin
            if 0>= ossl_ffc_set_digest(ffc, gctx.mdname, gctx.mdprops) then
                goto _end ;
        end;
        gctx.cb := osslcb;
        gctx.cbarg := cbarg;
        gencb := BN_GENCB_new();
        if gencb <> nil then
           BN_GENCB_set(gencb, dh_gencb, genctx);
        if (gctx.selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0 then  begin
            {
             * NOTE: The old safe prime generator code is0>= used in fips mode,
             * (i.e internally it ignores the generator and chooses a named
             * group based on pbits.
             }
            if gctx.gen_type = DH_PARAMGEN_TYPE_GENERATOR then
                ret := DH_generate_parameters_ex(dh, gctx.pbits,
                                                gctx.generator, gencb)
            else
                ret := ossl_dh_generate_ffc_parameters(dh, gctx.gen_type,
                                                      gctx.pbits, gctx.qbits,
                                                      gencb);
            if ret <= 0 then
               goto _end ;
        end;
    end;
    if (gctx.selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        if (ffc.p = nil)  or  (ffc.g = nil) then
            goto _end ;
        if gctx.priv_len > 0 then
           DH_set_length(dh, long(gctx.priv_len) );
        ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY,
                           Int(gctx.gen_type = DH_PARAMGEN_TYPE_FIPS_186_2));
        if DH_generate_key(dh) <= 0   then
            goto _end ;
    end;
    DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
    DH_set_flags(dh, gctx.dh_type);
    ret := 1;
_end:
    if ret <= 0 then
    begin
        DH_free(dh);
        dh := nil;
    end;
    BN_GENCB_free(gencb);
    Result := dh;
end;



function dh_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    dh_gen_settable[0] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, nil, 0);
    dh_gen_settable[1] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
    dh_gen_settable[2] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, nil);
    dh_gen_settable[3] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, nil);
    dh_gen_settable[4] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_GENERATOR, nil);
    dh_gen_settable[5] := OSSL_PARAM_END;

    Result := @dh_gen_settable;
end;



function dh_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
  gctx: Pdh_gen_ctx  ;
begin
    gctx := genctx;
    if 0>= dh_gen_common_set_params(genctx, params ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @gctx.generator) ) then
        Exit(0);
    { Parameters that are0>= allowed for PDH  }
    if ( OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX) <> nil)
         or  (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER) <> nil)
         or  (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H) <> nil)
         or  (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED) <> nil)
         or  (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS) <> nil)
         or  (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST) <> nil)
         or  (OSSL_PARAM_locate_const(params,
                                   OSSL_PKEY_PARAM_FFC_DIGEST_PROPS) <> nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := 1;
end;

function dh_gen_set_template( genctx, templ : Pointer):integer;
var
  dh : PDH;
  gctx: Pdh_gen_ctx ;
begin
    gctx := genctx;
    dh := templ;
    if (not ossl_prov_is_running) or  (gctx = nil)  or  (dh = nil)  then
        Exit(0);
    gctx.ffc_params := ossl_dh_get0_params(dh);
    Result := 1;
end;


function dh_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := dh_gen_init_base(provctx, selection, params, DH_FLAG_TYPE_DH);
end;

function dh_newdata( provctx : Pointer):Pointer;
var
  dh : PDH;
begin
    dh := nil;
    if ossl_prov_is_running then
    begin
        dh := ossl_dh_new_ex(PROV_LIBCTX_OF(provctx));
        if dh <> nil then
        begin
            DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
            DH_set_flags(dh, DH_FLAG_TYPE_DH);
        end;
    end;
    Result := dh;
end;

initialization
  dh_key_types[0] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
  dh_key_types[1] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
  dh_key_types[2] := OSSL_PARAM_END;

  dh_parameter_types[0] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, nil, 0);
  dh_parameter_types[1] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, nil, 0);
  dh_parameter_types[2] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, nil, 0);
  dh_parameter_types[3] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, nil, 0);
  dh_parameter_types[4] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
  dh_parameter_types[5] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
  dh_parameter_types[6] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
  dh_parameter_types[7] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, nil);
  dh_parameter_types[8] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
  dh_parameter_types[9] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
  dh_parameter_types[10] := OSSL_PARAM_END;

  dh_all_types[0] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, nil, 0);
  dh_all_types[1] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, nil, 0);
  dh_all_types[2] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, nil, 0);
  dh_all_types[3] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, nil, 0);
  dh_all_types[4] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
  dh_all_types[5] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
  dh_all_types[6] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
  dh_all_types[7] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, nil);
  dh_all_types[8] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
  dh_all_types[9] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
  dh_all_types[10] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
  dh_all_types[11] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
  dh_all_types[12] := OSSL_PARAM_END;

  dh_known_settable_params[0] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0);
  dh_known_settable_params[1] := OSSL_PARAM_END;
  dh_params[0] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, Nil);
  dh_params[1] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil);
  dh_params[2] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil);
  dh_params[3] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0);
  dh_params[4] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, nil, 0);
  dh_params[5] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, nil, 0);
  dh_params[6] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, nil, 0);
  dh_params[7] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, nil, 0);
  dh_params[8] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
  dh_params[9] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
  dh_params[10] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
  dh_params[11] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, nil);
  dh_params[12] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
  dh_params[13] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
  dh_params[14] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
  dh_params[15] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
  dh_params[16] := OSSL_PARAM_END;


end.
