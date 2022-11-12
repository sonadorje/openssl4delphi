unit OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt;

interface
uses OpenSSL.Api;

function dsa_newdata( provctx : Pointer):Pointer;
 function dsa_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
 function dsa_gen_set_template( genctx, templ : Pointer):integer;
 function dsa_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
 function dsa_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
 function dsa_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
  procedure dsa_gen_cleanup( genctx : Pointer);
 function dsa_load(const reference : Pointer; reference_sz : size_t):Pointer;
 procedure dsa_freedata( keydata : Pointer);
 function dsa_get_params( key : Pointer; params : POSSL_PARAM):integer;
 function dsa_gettable_params( provctx : Pointer):POSSL_PARAM;
 function dsa_has(const keydata : Pointer; selection : integer):integer;
 function dsa_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
  function dsa_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
 function dsa_import_types( selection : integer):POSSL_PARAM;
 function dsa_export_types( selection : integer):POSSL_PARAM;
 function dsa_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
 function dsa_dup(const keydata_from : Pointer; selection : integer):Pointer;
 function dsa_key_todata( dsa : PDSA; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
 function dsa_imexport_types( selection : integer):POSSL_PARAM;
function dsa_validate(const keydata : Pointer; selection, checktype : integer):integer;
function dsa_validate_domparams(const dsa : PDSA; checktype : integer):integer;
function dsa_validate_public(const dsa : PDSA):integer;
function dsa_validate_private(const dsa : PDSA):integer;
function dsa_gencb( p, n : integer; cb : PBN_GENCB):integer;
function dsa_gen_type_name2id(const name : PUTF8Char):integer;
function dsa_set_gen_seed( gctx : Pdsa_gen_ctx; seed : PByte; seedlen : size_t):integer;

const DSA_DEFAULT_MD = 'SHA256';
    ossl_dsa_keymgmt_functions: array[0..19] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW; method:(code:@dsa_newdata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_INIT; method:(code:@dsa_gen_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE; method:(code:@dsa_gen_set_template ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS; method:(code:@dsa_gen_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS;
      method:(code:@dsa_gen_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN; method:(code:@dsa_gen ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP; method:(code:@dsa_gen_cleanup ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_LOAD; method:(code:@dsa_load ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE; method:(code:@dsa_freedata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS; method:(code:@dsa_get_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS; method:(code:@dsa_gettable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS; method:(code:@dsa_has ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_MATCH; method:(code:@dsa_match ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_VALIDATE; method:(code:@dsa_validate ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT; method:(code:@dsa_import ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES; method:(code:@dsa_import_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT; method:(code:@dsa_export ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES; method:(code:@dsa_export_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_DUP; method:(code:@dsa_dup ;data:nil)),
    (function_id: 0; method:(code:nil ;data:nil))
);

implementation
uses openssl3.providers.fips.self_test,openssl3.crypto.ffc.ffc_params,
     OpenSSL3.crypto.dsa.dsa_backend, openssl3.crypto.param_build,
     openssl3.crypto.dsa.dsa_sign, openssl3.crypto.dsa.dsa_key,
     openssl3.crypto.dsa.dsa_lib, openssl3.crypto.param_build_set,
     openssl3.crypto.params_dup, OpenSSL3.crypto.dsa.dsa_check,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.params, openssl3.crypto.mem,
     openssl3.crypto.dsa_gen, OpenSSL3.openssl.params,
     OpenSSL3.Err, openssl3.crypto.o_str, openssl3.providers.common.provider_ctx;

const
  dsatype2id:array[0..2] of TDSA_GENTYPE_NAME2ID =
(
{$ifdef FIPS_MODULE}
    (name:'default'; id:DSA_PARAMGEN_TYPE_FIPS_186_4 ),
{$else}
    (name:'default'; id:DSA_PARAMGEN_TYPE_FIPS_DEFAULT ),
{$endif}
    (name:'fips186_4'; id:DSA_PARAMGEN_TYPE_FIPS_186_4 ),
    (name:'fips186_2'; id:DSA_PARAMGEN_TYPE_FIPS_186_2 )
);


var // 1d arrays
  settable : array[0..9] of TOSSL_PARAM ;
  dsa_parameter_types: array[0..8] of TOSSL_PARAM;
  dsa_key_types: array[0..2] of TOSSL_PARAM;
  dsa_all_types: array[0..10] of TOSSL_PARAM;
  dsa_params: array[0..14] of TOSSL_PARAM ;

const dsa_types: array[0..3] of POSSL_PARAM = (
    nil,                        // Index 0 = none of them
    @dsa_parameter_types,          // Index 1 = parameter types
    @dsa_key_types,                // Index 2 = key types
    @dsa_all_types                 // Index 3 = 1 + 2
);


function dsa_set_gen_seed( gctx : Pdsa_gen_ctx; seed : PByte; seedlen : size_t):integer;
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

function dsa_gen_type_name2id(const name : PUTF8Char):integer;
var
    i          : size_t;

begin
    for i := 0 to Length(dsatype2id)-1 do
    begin
        if strcasecmp(dsatype2id[i].name, name) = 0 then
            Exit(dsatype2id[i].id);
    end;
    Result := -1;
end;


function dsa_gencb( p, n : integer; cb : PBN_GENCB):integer;
var
  gctx : Pdsa_gen_ctx;

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

function dsa_validate_private(const dsa : PDSA):integer;
var
    status   : integer;

    priv_key : PBIGNUM;
begin
    status := 0;
    priv_key := nil;
    DSA_get0_key(dsa, nil, @priv_key);
    if priv_key = nil then Exit(0);
    Result := ossl_dsa_check_priv_key(dsa, priv_key, @status);
end;

function dsa_validate_public(const dsa : PDSA):integer;
var
  status : integer;

  pub_key : PBIGNUM;
begin
    status := 0;
     pub_key := nil;
    DSA_get0_key(dsa, @pub_key, nil);
    if pub_key = nil then Exit(0);
    Result := ossl_dsa_check_pub_key(dsa, pub_key, @status);
end;

function dsa_validate_domparams(const dsa : PDSA; checktype : integer):integer;
var
  status : integer;
begin
    status := 0;
    Result := ossl_dsa_check_params(dsa, checktype, @status);
end;

function dsa_imexport_types( selection : integer):POSSL_PARAM;
var
    type_select : integer;

begin
    type_select := 0;
    if (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ) <> 0 then
        type_select  := type_select + 1;
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        type_select  := type_select + 2;
    Result := dsa_types[type_select];
end;

function dsa_key_todata( dsa : PDSA; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
  priv, pub : PBIGNUM;
begin
     priv := nil;
     pub := nil;
    if dsa = nil then Exit(0);
    DSA_get0_key(dsa, @pub, @priv);
    if (priv <> nil)
         and (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv))  then
        Exit(0);
    if (pub <> nil)
         and (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub))  then
        Exit(0);
    Result := 1;
end;

function dsa_dup(const keydata_from : Pointer; selection : integer):Pointer;
begin
    if ossl_prov_is_running()  then
       Exit(ossl_dsa_dup(keydata_from, selection));
    Result := nil;
end;


function dsa_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
  dsa : PDSA;

  tmpl : POSSL_PARAM_BLD;

  params : POSSL_PARAM;

  ok : Boolean;
  label _err;
begin
    dsa := keydata;
    params := nil;
    ok := Boolean(1);
    if  (not ossl_prov_is_running) or  (dsa = nil)  then
        Exit(0);
    tmpl := OSSL_PARAM_BLD_new();
    if tmpl = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) <> 0 then
        ok := (ok)  and  (ossl_ffc_params_todata(ossl_dsa_get0_params(dsa), tmpl, nil)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (dsa_key_todata(dsa, tmpl, nil)>0);
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if  (not ok) or  (params = nil) then
        goto _err ;
    ok := Boolean(param_cb(params, cbarg));
    OSSL_PARAM_free(params);
_err:
    OSSL_PARAM_BLD_free(tmpl);
    Result := Int(ok);
end;

function dsa_export_types( selection : integer):POSSL_PARAM;
begin
    Result := dsa_imexport_types(selection);
end;



function dsa_import_types( selection : integer):POSSL_PARAM;
begin
    Result := dsa_imexport_types(selection);
end;



function dsa_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
var
  dsa : PDSA;

  ok : Boolean;
begin
    dsa := keydata;
    ok := Boolean(1);
    if  (not ossl_prov_is_running) or  (dsa = nil)  then
        Exit(0);
    if (selection and DSA_POSSIBLE_SELECTIONS) = 0 then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ) <> 0 then
        ok := (ok)  and  (ossl_dsa_ffc_params_fromdata(dsa, params)>0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (ossl_dsa_key_fromdata(dsa, params)>0);
    Result := Int(ok);
end;




function dsa_validate(const keydata : Pointer; selection, checktype : integer):integer;
var
  dsa : PDSA;

  ok : Boolean;
begin
    dsa := keydata;
    ok := Boolean(1);
    if  not ossl_prov_is_running( ) then
        Exit(0);
    if (selection and DSA_POSSIBLE_SELECTIONS) = 0 then Exit(1); { nothing to validate }
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        ok := (ok)  and  (dsa_validate_domparams(dsa, checktype)>0);
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := (ok)  and  (dsa_validate_public(dsa)>0);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        ok := (ok)  and  (dsa_validate_private(dsa)>0);
    { If the whole key is selected, we do a pairwise validation }
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = OSSL_KEYMGMT_SELECT_KEYPAIR then
        ok := (ok)  and  (ossl_dsa_check_pairwise(dsa)>0);
    Result := Int(ok);
end;


function dsa_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
var
  dsa1,
  dsa2        : PDSA;
  ok          : Boolean;
  key_checked : integer;
  pa,
  pb          : PBIGNUM;

  dsaparams1,
  dsaparams2  : PFFC_PARAMS;
begin
     dsa1 := keydata1;
     dsa2 := keydata2;
    ok := Boolean(1);
    if  not ossl_prov_is_running()   then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) <> 0 then
    begin
        key_checked := 0;
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 then
        begin
             pa := DSA_get0_pub_key(dsa1);
             pb := DSA_get0_pub_key(dsa2);
            if (pa <> nil)  and  (pb <> nil) then
            begin
                ok := (ok)  and  (BN_cmp(pa, pb) = 0);
                key_checked := 1;
            end;
        end;
        if  (0>= key_checked )
             and ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0) then
        begin
           pa := DSA_get0_priv_key(dsa1);
           pb := DSA_get0_priv_key(dsa2);
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
        dsaparams1 := ossl_dsa_get0_params(PDSA(dsa1));
        dsaparams2 := ossl_dsa_get0_params(PDSA(dsa2));
        ok := (ok)  and  (ossl_ffc_params_cmp(dsaparams1, dsaparams2, 1)>0);
    end;
    Result := Int(ok);
end;



function dsa_has(const keydata : Pointer; selection : integer):integer;
var
  dsa : PDSA;

  ok : Boolean;
begin
    dsa := keydata;
    ok := Boolean(1);
    if  (not ossl_prov_is_running) or  (dsa = nil)  then
        Exit(0);
    if (selection and DSA_POSSIBLE_SELECTIONS) = 0 then Exit(1); { the selection is not missing }
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := ok  and  (DSA_get0_pub_key(dsa) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        ok := ok  and  (DSA_get0_priv_key(dsa) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        ok := ok  and
             ( (DSA_get0_p(dsa) <> nil ) and (DSA_get0_g(dsa) <> nil) );
    Result := Int(ok);
end;

function dsa_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @dsa_params;
end;

function dsa_get_params( key : Pointer; params : POSSL_PARAM):integer;
var
  dsa : PDSA;

  p : POSSL_PARAM;
begin
    dsa := key;
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS );
    if (p   <> nil )
         and   (0>= OSSL_PARAM_set_int(p, _DSA_bits(dsa))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p <> nil)
         and   (0>= OSSL_PARAM_set_int(p, _DSA_security_bits(dsa)))   then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE );
    if (p  <> nil )
         and   (0>= OSSL_PARAM_set_int(p, DSA_size(dsa)))   then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST );
    if (p <> nil)
         and   (0>= OSSL_PARAM_set_utf8_string(p, DSA_DEFAULT_MD))   then
        Exit(0);
    Result := int( (ossl_ffc_params_todata(ossl_dsa_get0_params(dsa), nil, params)>0)
               and (dsa_key_todata(dsa, nil, params)>0) );
end;



procedure dsa_freedata( keydata : Pointer);
begin
    DSA_free(keydata);
end;

function dsa_load(const reference : Pointer; reference_sz : size_t):Pointer;
var
  dsa : PDSA;
begin
    dsa := nil;
    if (ossl_prov_is_running) and  (reference_sz = sizeof(dsa)) then
    begin
        { The contents of the reference is the address to our object }
        dsa := PPDSA(reference)^;
        { We grabbed, so we detach it }
        PPDSA(reference)^ := nil;
        Exit(dsa);
    end;
    Result := nil;
end;





procedure dsa_gen_cleanup( genctx : Pointer);
var
  gctx : Pdsa_gen_ctx;
begin
    gctx := genctx;
    if gctx = nil then exit;
    OPENSSL_free(Pointer(gctx.mdname));
    OPENSSL_free(Pointer(gctx.mdprops));
    OPENSSL_clear_free(Pointer(gctx.seed), gctx.seedlen);
    OPENSSL_free(Pointer(gctx));
end;

function dsa_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pdsa_gen_ctx;

  dsa : PDSA;

  gencb : PBN_GENCB;

  ret : integer;

  ffc : PFFC_PARAMS;
  label _end;
begin
    gctx := genctx;
    dsa := nil;
    gencb := nil;
    ret := 0;
    if  (not ossl_prov_is_running) or  (gctx = nil) then
        Exit(nil);
    dsa := ossl_dsa_new(gctx.libctx);
    if dsa = nil then Exit(nil);
    if (gctx.gen_type = DSA_PARAMGEN_TYPE_FIPS_DEFAULT) then
        gctx.gen_type := get_result(gctx.pbits >= 2048 , DSA_PARAMGEN_TYPE_FIPS_186_4 ,
                                                DSA_PARAMGEN_TYPE_FIPS_186_2);
    gctx.cb := osslcb;
    gctx.cbarg := cbarg;
    gencb := BN_GENCB_new();
    if gencb <> nil then
       BN_GENCB_set(gencb, dsa_gencb, genctx);
    ffc := ossl_dsa_get0_params(dsa);
    { Copy the template value if one was passed }
    if (gctx.ffc_params <> nil)
         and   (0>= ossl_ffc_params_copy(ffc, gctx.ffc_params)) then
        goto _end ;
    if (gctx.seed <> nil)
         and   (0>= ossl_ffc_params_set_seed(ffc, gctx.seed, gctx.seedlen) )then
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
        if  0>= ossl_ffc_set_digest(ffc, gctx.mdname, gctx.mdprops) then
            goto _end ;
    end;
    if (gctx.selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0 then
    begin
         if (ossl_dsa_generate_ffc_parameters(dsa, gctx.gen_type,
                                              gctx.pbits, gctx.qbits,
                                              gencb) <= 0) then
             goto _end ;
    end;
    ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY,
                                 Int(gctx.gen_type = DSA_PARAMGEN_TYPE_FIPS_186_2) );
    if (gctx.selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        if (ffc.p = nil)
             or  (ffc.q = nil)
             or  (ffc.g = nil) then
            goto _end ;
        if DSA_generate_key(dsa) <= 0  then
            goto _end ;
    end;
    ret := 1;
_end:
    if ret <= 0 then
    begin
        DSA_free(dsa);
        dsa := nil;
    end;
    BN_GENCB_free(gencb);
    Result := dsa;
end;



function dsa_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    settable[0] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, nil, 0);
    settable[1] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, nil);
    settable[2] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_QBITS, nil);
    settable[3] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, nil, 0);
    settable[4] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, nil, 0);
    settable[5] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
    settable[6] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
    settable[7] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
    settable[8] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
    settable[9] := OSSL_PARAM_END;
    Result := @settable;
end;




function dsa_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  gctx : Pdsa_gen_ctx;

  p : POSSL_PARAM;
begin
    gctx := genctx;
    if gctx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
    if p <> nil then
    begin
        gctx.gen_type := dsa_gen_type_name2id(p.data);
        if (p.data_type <> OSSL_PARAM_UTF8_STRING)
             or  (gctx.gen_type = -1) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
    if (p <> nil)
         and  (0>= OSSL_PARAM_get_int(p, @gctx.gindex) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
    if (p <> nil)
         and  (0>= OSSL_PARAM_get_int(p, @gctx.pcounter) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
    if (p <> nil)
         and  (0>= OSSL_PARAM_get_int(p, @gctx.hindex) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
    if (p <> nil)
         and  ( (p.data_type <> OSSL_PARAM_OCTET_STRING)
             or  (0>= dsa_set_gen_seed(gctx, p.data, p.data_size)) ) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS);
    if  (p  <> nil)
         and  (0>= OSSL_PARAM_get_size_t(p, @gctx.pbits)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS );
    if (P <> nil)
         and  (0>= OSSL_PARAM_get_size_t(p, @gctx.qbits))  then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
    if (p <> nil) then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        OPENSSL_free(Pointer(gctx.mdname));
        OPENSSL_strdup(gctx.mdname, p.data);
        if gctx.mdname = nil then Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
    if (p <> nil) then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        OPENSSL_free(Pointer(gctx.mdprops));
        OPENSSL_strdup(gctx.mdprops, p.data);
        if gctx.mdprops = nil then Exit(0);
    end;
    Result := 1;
end;



function dsa_gen_set_template( genctx, templ : Pointer):integer;
var
  gctx : Pdsa_gen_ctx;

  dsa : PDSA;
begin
    gctx := genctx;
    dsa := templ;
    if  (not ossl_prov_is_running)  or  (gctx = nil)  or  (dsa = nil) then
        Exit(0);
    gctx.ffc_params := ossl_dsa_get0_params(dsa);
    Result := 1;
end;

function dsa_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  libctx : POSSL_LIB_CTX;

  gctx : Pdsa_gen_ctx;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    gctx := nil;
    if  (not ossl_prov_is_running)  or
        ( (selection and DSA_POSSIBLE_SELECTIONS) = 0) then
        Exit(nil);
    gctx := OPENSSL_zalloc(sizeof( gctx^));
    if gctx <> nil then
    begin
        gctx.selection := selection;
        gctx.libctx := libctx;
        gctx.pbits := 2048;
        gctx.qbits := 224;
{$IFDEF FIPS_MODULE}
        gctx.gen_type := DSA_PARAMGEN_TYPE_FIPS_186_4;
{$ELSE} gctx.gen_type := DSA_PARAMGEN_TYPE_FIPS_DEFAULT;
{$ENDIF}
        gctx.gindex := -1;
        gctx.pcounter := -1;
        gctx.hindex := 0;
    end;
    if  0>= dsa_gen_set_params(gctx, params)  then
    begin
        OPENSSL_free(Pointer(gctx));
        gctx := nil;
    end;
    Result := gctx;
end;



function dsa_newdata( provctx : Pointer):Pointer;
begin
    if  not ossl_prov_is_running()  then
        Exit(nil);
    Result := ossl_dsa_new(PROV_LIBCTX_OF(provctx));
end;

initialization
   dsa_parameter_types[0] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, nil, 0);
   dsa_parameter_types[1] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, nil, 0);
   dsa_parameter_types[2] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, nil, 0);
   dsa_parameter_types[3] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, nil, 0);
   dsa_parameter_types[4] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
   dsa_parameter_types[5] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
   dsa_parameter_types[6] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
   dsa_parameter_types[7] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
   dsa_parameter_types[8] := OSSL_PARAM_END ;

   dsa_key_types[0] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
   dsa_key_types[1] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
   dsa_key_types[2] := OSSL_PARAM_END;
   dsa_all_types[0] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, nil, 0);
   dsa_all_types[1] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, nil, 0);
   dsa_all_types[2] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, nil, 0);
   dsa_all_types[3] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, nil, 0);
   dsa_all_types[4] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
   dsa_all_types[5] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
   dsa_all_types[6] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
   dsa_all_types[7] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
   dsa_all_types[8] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
   dsa_all_types[9] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
   dsa_all_types[10] := OSSL_PARAM_END;

    dsa_params[0] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nil);
    dsa_params[1] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil);
    dsa_params[2] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil);
    dsa_params[3] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nil, 0);
    dsa_params[4] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, nil, 0);
    dsa_params[5] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, nil, 0);
    dsa_params[6] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, nil, 0);
    dsa_params[7] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, nil, 0);
    dsa_params[8] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, nil);
    dsa_params[9] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, nil);
    dsa_params[10] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, nil);
    dsa_params[11] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, nil, 0);
    dsa_params[12] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
    dsa_params[13] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
    dsa_params[14] := OSSL_PARAM_END;
end.
