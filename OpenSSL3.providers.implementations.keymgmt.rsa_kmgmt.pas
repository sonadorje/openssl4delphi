unit OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt;

interface
uses OpenSSL.Api;

function rsa_newdata( provctx : Pointer):Pointer;
function rsa_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function rsa_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
function rsa_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
procedure rsa_gen_cleanup( genctx : Pointer);
function rsa_load(const reference : Pointer; reference_sz : size_t):Pointer;
procedure rsa_freedata( keydata : Pointer);
function rsa_get_params( key : Pointer; params : POSSL_PARAM):Boolean;
function rsa_gettable_params( provctx : Pointer):POSSL_PARAM;
function rsa_has(const keydata : Pointer; selection : integer):Boolean;
function rsa_validate(const keydata : Pointer; selection, checktype : integer):integer;
function rsa_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
function rsa_import_types( selection : integer):POSSL_PARAM;
function rsa_export_types( selection : integer):POSSL_PARAM;
function rsa_export( keydata : Pointer; selection : integer; param_callback : POSSL_CALLBACK; cbarg : Pointer):integer;
function rsa_dup(const keydata_from : Pointer; selection : integer):Pointer;
function rsapss_load(const reference : Pointer; reference_sz : size_t):Pointer;

function rsa_match(const keydata1, keydata2 : Pointer; selection : integer):Boolean;
function rsa_imexport_types( selection : integer):POSSL_PARAM;
function pss_params_fromdata(pss_params : PRSA_PSS_PARAMS_30; defaults_set : PInteger;const params : POSSL_PARAM; rsa_type : integer; libctx : POSSL_LIB_CTX):integer;
function common_load(const reference : Pointer; reference_sz : size_t; expected_rsa_type : integer):Pointer;
function rsa_gencb( p, n : integer; cb : PBN_GENCB):integer;
function gen_init(provctx : Pointer; selection, rsa_type : integer;const params : POSSL_PARAM):Pointer;
function rsapss_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function rsapss_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
function rsa_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
function rsapss_newdata( provctx : Pointer):Pointer;
function rsa_query_operation_name( operation_id : integer):PUTF8Char;

const  ossl_rsapss_keymgmt_functions: array[0..19] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_KEYMGMT_NEW;                   method:(code:@rsapss_newdata ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_INIT;              method:(code:@rsapss_gen_init ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS;        method:(code:@rsa_gen_set_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS;   method:(code:@rsapss_gen_settable_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN;                   method:(code:@rsa_gen ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GEN_CLEANUP;           method:(code:@rsa_gen_cleanup ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_LOAD;                  method:(code:@rsapss_load ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_FREE;                  method:(code:@rsa_freedata ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GET_PARAMS;            method:(code:@rsa_get_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS;       method:(code:@rsa_gettable_params ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_HAS;                   method:(code:@rsa_has ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_MATCH;                 method:(code:@rsa_match ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_VALIDATE;              method:(code:@rsa_validate ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_IMPORT;                method:(code:@rsa_import ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_IMPORT_TYPES;          method:(code:@rsa_import_types ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_EXPORT;                method:(code:@rsa_export ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_EXPORT_TYPES;          method:(code:@rsa_export_types ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME;  method:(code:@rsa_query_operation_name ;data:nil)),
    (function_id:  OSSL_FUNC_KEYMGMT_DUP;                   method:(code:@rsa_dup ;data:nil)),
    (function_id:  0;                                       method:(code:nil; data:nil))
);
const ossl_rsa_keymgmt_functions: array[0..18] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW;                 method:(code:@rsa_newdata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_INIT;            method:(code:@rsa_gen_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS;      method:(code:@rsa_gen_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS; method:(code:@rsa_gen_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN;                 method:(code:@rsa_gen ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP;         method:(code:@rsa_gen_cleanup ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_LOAD;                method:(code:@rsa_load ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE;                method:(code:@rsa_freedata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS;          method:(code:@rsa_get_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS;     method:(code:@rsa_gettable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS;                 method:(code:@rsa_has ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_MATCH;               method:(code:@rsa_match ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_VALIDATE;            method:(code:@rsa_validate ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT;              method:(code:@rsa_import ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES;        method:(code:@rsa_import_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT;              method:(code:@rsa_export ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES;        method:(code:@rsa_export_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_DUP;                 method:(code:@rsa_dup ;data:nil)),
    (function_id: 0;                                     method:(code:nil ;data:nil))
);
 RSA_DEFAULT_MD = 'SHA256';

var // 1d arrays

  rsa_key_types, rsa_params :array of TOSSL_PARAM;

implementation

uses openssl3.crypto.ffc.ffc_params,  OpenSSL3.Err,
     openssl3.crypto.param_build,     OpenSSL3.openssl.params,
     openssl3.crypto.param_build_set, OpenSSL3.crypto.rsa.rsa_backend,
     openssl3.crypto.params_dup,      openssl3.crypto.bn.bn_lib,
     openssl3.crypto.params,          openssl3.crypto.mem,
     OpenSSL3.crypto.rsa.rsa_crpt,    OpenSSL3.crypto.rsa.rsa_gen,
     openssl3.crypto.rsa.rsa_lib,     openssl3.crypto.rsa.rsa_pss,
     openssl3.crypto.o_str,           openssl3.crypto.rsa.rsa_chk,
     openssl3.providers.prov_running, openssl3.crypto.rsa_schemes,
     openssl3.providers.common.provider_ctx;

function rsa_query_operation_name( operation_id : integer):PUTF8Char;
begin
    Result := 'RSA';
end;

function rsapss_load(const reference : Pointer; reference_sz : size_t):Pointer;
begin
    Result := common_load(reference, reference_sz, RSA_FLAG_TYPE_RSASSAPSS);
end;

var // 1d arrays
  settable : array[0..9] of TOSSL_PARAM;
function rsapss_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    settable[0] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, nil);
    settable[1] := _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, nil);
    settable[2] := _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nil, 0);
    settable[3] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, nil, 0);
    settable[4] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, nil, 0);
    settable[5] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, nil, 0);
    settable[6] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, nil, 0);
    settable[7] := _OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, nil);
    settable[9] := OSSL_PARAM_END;
    Result := @settable;
end;

function rsapss_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := gen_init(provctx, selection, RSA_FLAG_TYPE_RSASSAPSS, params);
end;

function rsapss_newdata( provctx : Pointer):Pointer;
var
  libctx : POSSL_LIB_CTX;
  rsa : PRSA;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    if  not ossl_prov_is_running( )then
        Exit(nil);
    rsa := ossl_rsa_new_with_ctx(libctx);
    if rsa <> nil then
    begin
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS);
    end;
    Result := rsa;
end;

function gen_init(provctx : Pointer; selection, rsa_type : integer;const params : POSSL_PARAM):Pointer;
var
  libctx : POSSL_LIB_CTX;
  gctx : Prsa_gen_ctx;
  label _err;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    gctx := nil;
    if  not ossl_prov_is_running() then
        Exit(nil);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) = 0 then
        Exit(nil);
    gctx := OPENSSL_zalloc(sizeof( gctx^));
    if gctx <> nil then
    begin
        gctx.libctx := libctx;
        gctx.pub_exp := BN_new( );
        if (gctx.pub_exp = nil )
             or  (0>= BN_set_word(gctx.pub_exp, RSA_F4))  then
        begin
            goto _err ;
        end;
        gctx.nbits := 2048;
        gctx.primes := RSA_DEFAULT_PRIME_NUM;
        gctx.rsa_type := rsa_type;
    end
    else
    begin
        goto _err ;
    end;
    if  0>= rsa_gen_set_params(gctx, params) then
        goto _err ;
    Exit(gctx);
_err:
    if gctx <> nil then BN_free(gctx.pub_exp);
    OPENSSL_free(gctx);
    Result := nil;
end;

function rsa_gencb( p, n : integer; cb : PBN_GENCB):integer;
var
  gctx : Prsa_gen_ctx;
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

function common_load(const reference : Pointer; reference_sz : size_t; expected_rsa_type : integer):Pointer;
var
  rsa : PRSA;
begin
    rsa := nil;
    if (ossl_prov_is_running)  and  (reference_sz = sizeof(rsa)) then
    begin
        { The contents of the reference is the address to our object }
        rsa := PPRSA ( reference)^;
        if RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) <> expected_rsa_type then
            Exit(nil);
        { We grabbed, so we detach it }
        PPRSA ( reference)^ := nil;
        Exit(rsa);
    end;
    Result := nil;
end;

function pss_params_fromdata(pss_params : PRSA_PSS_PARAMS_30; defaults_set : PInteger;const params : POSSL_PARAM; rsa_type : integer; libctx : POSSL_LIB_CTX):integer;
begin
    if  0>= ossl_rsa_pss_params_30_fromdata(pss_params, defaults_set,
                                         params, libctx ) then
        Exit(0);
    { If not a PSS type RSA, sending us PSS parameters is wrong }
    if (rsa_type <> RSA_FLAG_TYPE_RSASSAPSS)
         and   (0>= ossl_rsa_pss_params_30_is_unrestricted(pss_params))  then
        Exit(0);
    Result := 1;
end;

function rsa_imexport_types( selection : integer):POSSL_PARAM;
begin
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        Exit(@rsa_key_types[0]);
    Result := nil;
end;


function rsa_dup(const keydata_from : Pointer; selection : integer):Pointer;
begin
    if (ossl_prov_is_running) { do not allow creating empty keys by duplication }
         and ( (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) <> 0) then
        Exit(ossl_rsa_dup(keydata_from, selection));
    Result := nil;
end;

function rsa_export( keydata : Pointer; selection : integer; param_callback : POSSL_CALLBACK; cbarg : Pointer):integer;
var
    rsa        : PRSA;
    pss_params : PRSA_PSS_PARAMS_30;
    tmpl       : POSSL_PARAM_BLD;
    params     : POSSL_PARAM;
    ok         : Boolean;
    label _err;
begin
    rsa := keydata;
   pss_params := ossl_rsa_get0_pss_params_30(rsa);
    params := nil;
    ok := Boolean(1);
    if  (not ossl_prov_is_running)   or  (rsa = nil) then
        Exit(0);
    if (selection and RSA_POSSIBLE_SELECTIONS ) = 0 then
        Exit(0);
    tmpl := OSSL_PARAM_BLD_new();
    if tmpl = nil then Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) <> 0 then
        ok := (ok)  and  ( (ossl_rsa_pss_params_30_is_unrestricted(pss_params)>0)
                     or    (ossl_rsa_pss_params_30_todata(pss_params, tmpl, nil)>0) );
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (ossl_rsa_todata(rsa, tmpl, nil)>0);
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if  (not ok)
         or  (params = nil) then
        goto _err ;
    ok := Boolean(param_callback(params, cbarg));
    OSSL_PARAM_free(params);

_err:
    OSSL_PARAM_BLD_free(tmpl);
    Result := Int(ok);
end;

function rsa_import_types( selection : integer):POSSL_PARAM;
begin
    Result := rsa_imexport_types(selection);
end;


function rsa_export_types( selection : integer):POSSL_PARAM;
begin
    Result := rsa_imexport_types(selection);
end;

function rsa_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
var
  rsa              : PRSA;
  ok: Boolean;
  rsa_type,
  pss_defaults_set : integer;
begin
    rsa := keydata;
    ok := Boolean(1);
    pss_defaults_set := 0;
    if  (not ossl_prov_is_running)  or  (rsa = nil)  then
        Exit(0);
    if (selection and RSA_POSSIBLE_SELECTIONS) = 0 then
        Exit(0);
    rsa_type := RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) <> 0 then
        ok := (ok)  and  (pss_params_fromdata(ossl_rsa_get0_pss_params_30(rsa),
                                       @pss_defaults_set,
                                       params, rsa_type,
                                       ossl_rsa_get0_libctx(rsa)) >0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (ossl_rsa_fromdata(rsa, params)>0);
    Result := Int(ok);
end;

function rsa_validate(const keydata : Pointer; selection, checktype : integer):integer;
var
  rsa : PRSA;
  ok : Boolean;
begin
    rsa := keydata;
    ok := Boolean(1);
    if  not ossl_prov_is_running()   then
        Exit(0);
    if (selection and RSA_POSSIBLE_SELECTIONS) = 0 then Exit(1); { nothing to validate }
    { If the whole key is selected, we do a pairwise validation }
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = OSSL_KEYMGMT_SELECT_KEYPAIR then
    begin
        ok := (ok)  and (ossl_rsa_validate_pairwise(rsa)>0);
    end
    else
    begin
        if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
            ok := (ok)  and  (ossl_rsa_validate_private(rsa) > 0);
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
            ok := (ok)  and  (ossl_rsa_validate_public(rsa)>0);
    end;
    Result := Int(ok);
end;


function rsa_match(const keydata1, keydata2 : Pointer; selection : integer):Boolean;
var
  rsa1,
  rsa2        : PRSA;
  ok          : Boolean;
  key_checked : integer;
  pa,
  pb          : PBIGNUM;
begin
    rsa1 := keydata1;
    rsa2 := keydata2;
    ok := Boolean(1);
    if  not ossl_prov_is_running()  then
        Exit(False);
    { There is always an |e| }
    ok := (ok)  and  (BN_cmp(RSA_get0_e(rsa1), RSA_get0_e(rsa2)) = 0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        key_checked := 0;
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        begin
             pa := RSA_get0_n(rsa1);
            pb := RSA_get0_n(rsa2);
            if (pa <> nil)  and  (pb <> nil) then
            begin
                ok := (ok)  and  (BN_cmp(pa, pb) = 0);
                key_checked := 1;
            end;
        end;
        if  (0>= key_checked )
             and ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0) then
        begin
            pa := RSA_get0_d(rsa1);
            pb := RSA_get0_d(rsa2);
            if (pa <> nil)  and  (pb <> nil) then
            begin
                ok := (ok)  and  (BN_cmp(pa, pb) = 0);
                key_checked := 1;
            end;
        end;
        ok := (ok)  and  (key_checked>0);
    end;
    Result := ok;
end;

function rsa_has(const keydata : Pointer; selection : integer):Boolean;
var
  rsa : PRSA;
  ok : Boolean;
begin
    rsa := keydata;
    ok := true;
    if (rsa = nil)  or   (not ossl_prov_is_running) then
        Exit(False);
    if (selection and RSA_POSSIBLE_SELECTIONS)  = 0 then Exit(true); { the selection is not missing }
    { OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty }
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
        ok := (ok)  and  (RSA_get0_e(rsa) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := (ok)  and  (RSA_get0_n(rsa) <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        ok := ok  and  (RSA_get0_d(rsa) <> nil);
    Result := ok;
end;

function rsa_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @rsa_params[0];
end;

function rsa_get_params( key : Pointer; params : POSSL_PARAM):Boolean;
var
    rsa        : PRSA;
    pss_params : PRSA_PSS_PARAMS_30;
    rsa_type   : integer;
    p          : POSSL_PARAM;
    empty      : Boolean;
    mdname     : PUTF8Char;
begin
    rsa := key;
    pss_params := ossl_rsa_get0_pss_params_30(rsa);
    rsa_type := RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);
    empty := RSA_get0_n(rsa) = nil;
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p <> nil)
         and  ( (empty)  or   (0>= OSSL_PARAM_set_int(p, _RSA_bits(rsa)) )) then
        Exit(False);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p  <> nil)
         and  ( (empty)  or (0>= OSSL_PARAM_set_int(p, _RSA_security_bits(rsa)))) then
        Exit(False);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE );
    if (p  <> nil)
         and  ( (empty)  or  (0>= OSSL_PARAM_set_int(p, RSA_size(rsa)))) then
        Exit(False);
    {
     * For restricted RSA-PSS keys, we ignore the default digest request.
     * With RSA-OAEP keys, this may need to be amended.
     }
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST );
    if (p  <> nil)
         and  ( (rsa_type <> RSA_FLAG_TYPE_RSASSAPSS)
             or (ossl_rsa_pss_params_30_is_unrestricted(pss_params)>0)) then
    begin
        if  0>= OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD) then
            Exit(False);
    end;
    {
     * For non-RSA-PSS keys, we ignore the mandatory digest request.
     * With RSA-OAEP keys, this may need to be amended.
     }
    p := OSSL_PARAM_locate(params,OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (P <> nil)
         and  (rsa_type = RSA_FLAG_TYPE_RSASSAPSS)
         and  (0>= ossl_rsa_pss_params_30_is_unrestricted(pss_params)) then
    begin
        mdname := ossl_rsa_oaeppss_nid2name(ossl_rsa_pss_params_30_hashalg(pss_params));
        if (mdname = nil)  or (0>= OSSL_PARAM_set_utf8_string(p, mdname) ) then
            Exit(False);
    end;
    Result := (rsa_type <> RSA_FLAG_TYPE_RSASSAPSS)
             or  (ossl_rsa_pss_params_30_todata(pss_params, nil, params)>0)
         and  (ossl_rsa_todata(rsa, nil, params)>0);
end;

procedure rsa_freedata( keydata : Pointer);
begin
    RSA_free(keydata);
end;

function rsa_load(const reference : Pointer; reference_sz : size_t):Pointer;
begin
    Result := common_load(reference, reference_sz, RSA_FLAG_TYPE_RSA);
end;

procedure rsa_gen_cleanup( genctx : Pointer);
var
  gctx : Prsa_gen_ctx;
begin
    gctx := genctx;
    if gctx = nil then exit;
{$IF defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ACVP_TESTS)}
    ossl_rsa_acvp_test_gen_params_free(gctx.acvp_test_params);
    gctx.acvp_test_params := nil;
{$ENDIF}
    BN_clear_free(gctx.pub_exp);
    OPENSSL_free(gctx);
end;

function rsa_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Prsa_gen_ctx;
  rsa, rsa_tmp : PRSA;
  gencb : PBN_GENCB;
  label _err;
begin
    gctx := genctx;
    rsa := nil;
    rsa_tmp := nil;
    gencb := nil;
    if  (not ossl_prov_is_running) or  (gctx = nil)  then
        Exit(nil);
    case gctx.rsa_type of
        RSA_FLAG_TYPE_RSA:
          { For plain RSA keys, PSS parameters must not be set }
          if  0>= ossl_rsa_pss_params_30_is_unrestricted(@gctx.pss_params)  then
              goto _err ;

        RSA_FLAG_TYPE_RSASSAPSS:
        begin
        {
         * For plain RSA-PSS keys, PSS parameters may be set but don't have
         * to, so not check.
         }

          //break;
        end;
    else
        { Unsupported RSA key sub-type... }
        Exit(nil);
    end;
    rsa_tmp := ossl_rsa_new_with_ctx(gctx.libctx);
    if rsa_tmp  = nil then
        Exit(nil);
    gctx.cb := osslcb;
    gctx.cbarg := cbarg;
    gencb := BN_GENCB_new();
    if gencb <> nil then
       BN_GENCB_set(gencb, rsa_gencb, genctx);
{$IF defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ACVP_TESTS)}
    if gctx.acvp_test_params <> nil then
    begin
        if  not ossl_rsa_acvp_test_set_params(rsa_tmp, gctx.acvp_test_params) then
            goto_err ;
    end;
{$ENDIF}
    if  0>= RSA_generate_multi_prime_key(rsa_tmp, int(gctx.nbits), int(gctx.primes),
                                      gctx.pub_exp, gencb)  then
        goto _err ;
    if  0>= ossl_rsa_pss_params_30_copy(ossl_rsa_get0_pss_params_30(rsa_tmp) ,
                                     @gctx.pss_params) then
        goto _err ;
    RSA_clear_flags(rsa_tmp, RSA_FLAG_TYPE_MASK);
    RSA_set_flags(rsa_tmp, gctx.rsa_type);
    rsa := rsa_tmp;
    rsa_tmp := nil;

 _err:
    BN_GENCB_free(gencb);
    RSA_free(rsa_tmp);
    Result := rsa;
end;


var
  settable2: array[0..3] of TOSSL_PARAM;
function rsa_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    settable2[0] :=  _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, nil);
    settable2[1] :=  _OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, nil);
    settable2[2] :=  _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nil, 0);
    settable2[3] :=  OSSL_PARAM_END;
    Result := @settable2;
end;

function rsa_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  gctx : Prsa_gen_ctx;
  p : POSSL_PARAM;
begin
    gctx := genctx;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS );
    if p <> nil then
    begin
        if  0>= OSSL_PARAM_get_size_t(p, @gctx.nbits) then
            Exit(0);
        if gctx.nbits < RSA_MIN_MODULUS_BITS then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            Exit(0);
        end;
    end;
     p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES );
    if  (p  <> nil)
         and   (0>= OSSL_PARAM_get_size_t(p, @gctx.primes)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E );
    if (p <> nil)
         and   (0>= OSSL_PARAM_get_BN(p, @gctx.pub_exp))   then
        Exit(0);
    { Only attempt to get PSS parameters when generating an RSA-PSS key }
    if (gctx.rsa_type = RSA_FLAG_TYPE_RSASSAPSS)
         and   (0>= pss_params_fromdata(@gctx.pss_params, @gctx.pss_defaults_set, params,
                                gctx.rsa_type, gctx.libctx) ) then
        Exit(0);
{$IF defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ACVP_TESTS)}
    { Any ACVP test related parameters are copied into a params[] }
    if  0>= ossl_rsa_acvp_test_gen_params_new(@gctx.acvp_test_params, params ) then
        Exit(0);
{$ENDIF}
    Result := 1;
end;

function rsa_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := gen_init(provctx, selection, RSA_FLAG_TYPE_RSA, params);
end;

function rsa_newdata( provctx : Pointer):Pointer;
var
  libctx : POSSL_LIB_CTX;
  rsa : PRSA;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    if  not ossl_prov_is_running( )then
        Exit(nil);
    rsa := ossl_rsa_new_with_ctx(libctx);
    if rsa <> nil then
    begin
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA);
    end;
    Result := rsa;
end;

initialization
  rsa_key_types := [
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR3, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR4, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR5, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR6, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR7, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR8, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR9, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR10, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT3, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT4, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT5, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT6, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT7, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT8, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT9, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT10, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT2, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT3, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT4, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT5, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT6, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT7, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT8, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT9, nil, 0),
      OSSL_PARAM_END];

  rsa_params := [
      _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nil),
      _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil),
      _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil),
      _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR3, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR4, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR5, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR6, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR7, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR8, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR9, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR10, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT3, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT4, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT5, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT6, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT7, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT8, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT9, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT10, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT2, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT3, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT4, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT5, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT6, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT7, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT8, nil, 0),
      _OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT9, nil, 0),
      OSSL_PARAM_END
   ]
end.
