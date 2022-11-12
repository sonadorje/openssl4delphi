unit OpenSSL3.providers.implementations.mac_legacy_kmgmt;

interface
uses  OpenSSL.Api;

function ossl_mac_key_new( libctx : POSSL_LIB_CTX; cmac : integer):PMAC_KEY;
  procedure ossl_mac_key_free( mackey : PMAC_KEY);
  function ossl_mac_key_up_ref( mackey : PMAC_KEY):integer;
  function mac_new( provctx : Pointer):Pointer;
  function mac_new_cmac( provctx : Pointer):Pointer;
  procedure mac_free( mackey : Pointer);
  function mac_has(const keydata : Pointer; selection : integer):integer;
  function mac_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
  function mac_key_fromdata(key : PMAC_KEY;const params : POSSL_PARAM):integer;
  function mac_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
  function key_to_params( key : PMAC_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
  function mac_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
  function mac_imexport_types( selection : integer):POSSL_PARAM;
  function cmac_imexport_types( selection : integer):POSSL_PARAM;
  function mac_get_params( key : Pointer; params : POSSL_PARAM):integer;
  function mac_gettable_params( provctx : Pointer):POSSL_PARAM;
  function cmac_gettable_params( provctx : Pointer):POSSL_PARAM;
  function mac_set_params(keydata : Pointer;const params : POSSL_PARAM):integer;
  function mac_settable_params( provctx : Pointer):POSSL_PARAM;
  function mac_gen_init_common( provctx : Pointer; selection : integer):Pointer;
  function mac_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  function cmac_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  function mac_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
  function cmac_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
  function mac_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
  function cmac_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
  function mac_gen( genctx : Pointer; cb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
  procedure mac_gen_cleanup( genctx : Pointer);

const ossl_mac_legacy_keymgmt_functions: array[0..17] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW; method:(code:@mac_new ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE; method:(code:@mac_free ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS; method:(code:@mac_get_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS; method:(code:@mac_gettable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS; method:(code:@mac_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS; method:(code:@mac_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS; method:(code:@mac_has ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_MATCH; method:(code:@mac_match ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT; method:(code:@mac_import ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES; method:(code:@mac_imexport_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT; method:(code:@mac_export ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES; method:(code:@mac_imexport_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_INIT; method:(code:@mac_gen_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS; method:(code:@mac_gen_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS;
        method:(code:@mac_gen_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN; method:(code:@mac_gen ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP; method:(code:@mac_gen_cleanup ;data:nil)),
    (function_id: 0; method:(code:nil ;data:nil))
);
ossl_cmac_legacy_keymgmt_functions: array[0..17] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW; method:(code:@mac_new_cmac ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE; method:(code:@mac_free ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS; method:(code:@mac_get_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS; method:(code:@cmac_gettable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS; method:(code:@mac_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS; method:(code:@mac_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS; method:(code:@mac_has ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_MATCH; method:(code:@mac_match ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT; method:(code:@mac_import ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES; method:(code:@cmac_imexport_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT; method:(code:@mac_export ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES; method:(code:@cmac_imexport_types ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_INIT; method:(code:@cmac_gen_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS; method:(code:@cmac_gen_set_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS;
        method:(code:@cmac_gen_settable_params ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN; method:(code:@mac_gen ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP; method:(code:@mac_gen_cleanup ;data:nil)),
    (function_id: 0; method:(code:nil ;data:nil))
);

var mac_key_types,
    cmac_key_types: array of TOSSL_PARAM ;

implementation
uses openssl3.include.internal.refcount, openssl3.crypto.mem, openssl3.crypto.params,
     openssl3.providers.fips.self_test, openssl3.providers.common.provider_ctx,
     openssl3.crypto.mem_sec,           OpenSSL3.providers.common.provider_util,
     OpenSSL3.threads_none,            openssl3.crypto.uid,
     openssl3.crypto.evp.keymgmt_meth, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.cpuid,
     OpenSSL3.Err, openssl3.crypto.o_str,openssl3.crypto.param_build_set,
     openssl3.crypto.engine.eng_lib, openssl3.crypto.param_build,
     openssl3.crypto.params_dup, OpenSSL3.openssl.params;

function ossl_mac_key_new( libctx : POSSL_LIB_CTX; cmac : integer):PMAC_KEY;
var
  mackey : PMAC_KEY;
begin
    if  not ossl_prov_is_running( ) then
        Exit(nil);
    mackey := OPENSSL_zalloc(sizeof( mackey^));
    if mackey = nil then Exit(nil);
    mackey.lock := CRYPTO_THREAD_lock_new();
    if mackey.lock = nil then
    begin
        OPENSSL_free(Pointer(mackey));
        Exit(nil);
    end;
    mackey.libctx := libctx;
    mackey.refcnt := 1;
    mackey.cmac := cmac;
    Result := mackey;
end;


procedure ossl_mac_key_free( mackey : PMAC_KEY);
var
  ref : integer;
begin
    ref := 0;
    if mackey = nil then exit;
    CRYPTO_DOWN_REF(mackey.refcnt, ref, mackey.lock);
    if ref > 0 then exit;
    OPENSSL_secure_clear_free(mackey.priv_key, mackey.priv_key_len);
    OPENSSL_free(Pointer(mackey.properties));
    ossl_prov_cipher_reset(@mackey.cipher);
    CRYPTO_THREAD_lock_free(mackey.lock);
    OPENSSL_free(Pointer(mackey));
end;


function ossl_mac_key_up_ref( mackey : PMAC_KEY):integer;
var
  ref : integer;
begin
    ref := 0;
    { This is effectively doing a new operation on the MAC_KEY and should be
     * adequately guarded again modules' error states.  However, both current
     * calls here are guarded properly in signature/mac_legacy.c.  Thus, it
     * could be removed here.  The concern is that something in the future
     * might call this function without adequate guards.  It's a cheap call,
     * it seems best to leave it even though it is currently redundant.
     }
    if  not ossl_prov_is_running()  then
        Exit(0);
    CRYPTO_UP_REF(mackey.refcnt, ref, mackey.lock);
    Result := 1;
end;


function mac_new( provctx : Pointer):Pointer;
begin
    Result := ossl_mac_key_new(PROV_LIBCTX_OF(provctx), 0);
end;


function mac_new_cmac( provctx : Pointer):Pointer;
begin
    Result := ossl_mac_key_new(PROV_LIBCTX_OF(provctx), 1);
end;


procedure mac_free( mackey : Pointer);
begin
    ossl_mac_key_free(mackey);
end;


function mac_has(const keydata : Pointer; selection : integer):integer;
var
  key : PMAC_KEY;
  ok : integer;
begin
     key := keydata;
    ok := 0;
    if (ossl_prov_is_running) and  (key <> nil)  then
    begin
        {
         * MAC keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         * Similarly for public keys.
         }
        ok := 1;
        if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
            ok := Int(key.priv_key <> nil);
    end;
    Result := ok;
end;


function mac_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
var
  key1, key2 : PMAC_KEY;
  ok : Boolean;
begin
    key1 := keydata1;
    key2 := keydata2;
    ok := Boolean(1);
    if  not ossl_prov_is_running()   then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        if ( (key1.priv_key = nil)  and  (key2.priv_key <> nil) )
                 or ( (key1.priv_key <> nil)  and  (key2.priv_key = nil) )
                 or  (key1.priv_key_len <> key2.priv_key_len)
                 or ( (key1.cipher.cipher = nil)  and  (key2.cipher.cipher <> nil) )
                 or ( (key1.cipher.cipher <> nil)  and  (key2.cipher.cipher = nil) )  then
            ok := Boolean(0)
        else
            ok := (ok)  and ( (key1.priv_key = nil) { implies key2.privkey = nil }
                         or  (CRYPTO_memcmp(key1.priv_key, key2.priv_key,
                                         key1.priv_key_len) = 0) );
        if key1.cipher.cipher <> nil then
           ok := (ok)  and  (EVP_CIPHER_is_a(key1.cipher.cipher,
                                       EVP_CIPHER_get0_name(key2.cipher.cipher)));
    end;
    Result := Int(ok);
end;


function mac_key_fromdata(key : PMAC_KEY;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
        OPENSSL_secure_clear_free(key.priv_key, key.priv_key_len);
        { allocate at least one byte to distinguish empty key from no key set }
        key.priv_key := OPENSSL_secure_malloc(get_result(p.data_size > 0 , p.data_size , 1));
        if key.priv_key = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(key.priv_key, p.data, p.data_size);
        key.priv_key_len := p.data_size;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
        OPENSSL_free(Pointer(key.properties));
        OPENSSL_strdup(key.properties ,p.data);
        if key.properties = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    if (key.cmac>0)  and  (0>= ossl_prov_cipher_load_from_params(@key.cipher, params,
                                                        key.libctx)) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    if key.priv_key <> nil then Exit(1);
    Result := 0;
end;


function mac_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
var
  key : PMAC_KEY;
begin
    key := keydata;
    if  (not ossl_prov_is_running) or  (key = nil)  then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) = 0 then
        Exit(0);
    Result := mac_key_fromdata(key, params);
end;


function key_to_params( key : PMAC_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
begin
    if key = nil then Exit(0);
    if (key.priv_key <> nil)
         and  (0>= ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key.priv_key, key.priv_key_len)) then
        Exit(0);
    if (key.cipher.cipher <> nil)
         and  (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_CIPHER,
                                             EVP_CIPHER_get0_name(key.cipher.cipher))  )then
        Exit(0);
{$IF not defined(OPENSSL_NO_ENGINE)  and  (not defined(FIPS_MODULE))}
    if (key.cipher.engine <> nil)
         and  (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_ENGINE,
                                             ENGINE_get_id(key.cipher.engine)))  then
        Exit(0);
{$ENDIF}
    Result := 1;
end;


function mac_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
  key : PMAC_KEY;
  tmpl : POSSL_PARAM_BLD;
  params : POSSL_PARAM;
  ret : integer;
  label _err;
begin
    key := keydata;
    params := nil;
    ret := 0;
    if  (not ossl_prov_is_running) or  (key = nil) then
        Exit(0);
    tmpl := OSSL_PARAM_BLD_new();
    if tmpl = nil then Exit(0);
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)
          and  (0>= key_to_params(key, tmpl, nil))  then
        goto _err ;
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if params = nil then
       goto _err ;
    ret := param_cb(params, cbarg);
    OSSL_PARAM_free(params);
_err:
    OSSL_PARAM_BLD_free(tmpl);
    Result := ret;
end;


function mac_imexport_types( selection : integer):POSSL_PARAM;
begin
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        Exit(@mac_key_types[0]);
    Result := nil;
end;


function cmac_imexport_types( selection : integer):POSSL_PARAM;
begin
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        Exit(@cmac_key_types[0]);
    Result := nil;
end;


function mac_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    Result := key_to_params(key, nil, params);
end;

var
  gettable_params1 : array of TOSSL_PARAM;
function mac_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
     gettable_params1 := [
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
        OSSL_PARAM_END
   ];
    Result := @gettable_params1[0];
end;

var
  gettable_params2 : array of TOSSL_PARAM;
function cmac_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    gettable_params2 := [
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
        _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, nil, 0),
        _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_ENGINE, nil, 0),
        OSSL_PARAM_END
   ];
    Result := @gettable_params2[0];
end;


function mac_set_params(keydata : Pointer;const params : POSSL_PARAM):integer;
var
  key : PMAC_KEY;
  p : POSSL_PARAM;
begin
    key := keydata;
    if key = nil then Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if p <> nil then Exit(mac_key_fromdata(key, params));
    Result := 1;
end;

var
  settable_params : array of TOSSL_PARAM;
function mac_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    settable_params := [
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
        OSSL_PARAM_END
    ];
    Result := @settable_params[0];
end;


function mac_gen_init_common( provctx : Pointer; selection : integer):Pointer;
var
  libctx : POSSL_LIB_CTX;
  gctx : Pmac_gen_ctx;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    gctx := nil;
    if  not ossl_prov_is_running()  then
        Exit(nil);
    gctx := OPENSSL_zalloc(sizeof(gctx^ ));
    if gctx <> nil then
    begin
        gctx.libctx := libctx;
        gctx.selection := selection;
    end;
    Result := gctx;
end;


function mac_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  gctx : Pmac_gen_ctx;
begin
    gctx := mac_gen_init_common(provctx, selection);
    if (gctx <> nil)  and  (0>= mac_gen_set_params(gctx, params) ) then
    begin
        OPENSSL_free(Pointer(gctx));
        gctx := nil;
    end;
    Result := gctx;
end;


function cmac_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
  gctx : Pmac_gen_ctx;
begin
    gctx := mac_gen_init_common(provctx, selection);
    if (gctx <> nil)  and  (0>= cmac_gen_set_params(gctx, params)) then
    begin
        OPENSSL_free(Pointer(gctx));
        gctx := nil;
    end;
    Result := gctx;
end;


function mac_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  gctx : Pmac_gen_ctx;
  p : POSSL_PARAM;
begin
    gctx := genctx;
    if gctx = nil then Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if p <> nil then begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then  begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
        gctx.priv_key := OPENSSL_secure_malloc(p.data_size);
        if gctx.priv_key = nil then begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(gctx.priv_key, p.data, p.data_size);
        gctx.priv_key_len := p.data_size;
    end;
    Result := 1;
end;


function cmac_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
  gctx : Pmac_gen_ctx;
begin
    gctx := genctx;
    if  0>= mac_gen_set_params(genctx, params) then
        Exit(0);
    if  0>= ossl_prov_cipher_load_from_params(@gctx.cipher, params,
                                           gctx.libctx ) then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := 1;
end;

var
  settable1 : array of TOSSL_PARAM;
function mac_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
     settable1 := [
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
        OSSL_PARAM_END
   ];
    Result := @settable1[0];
end;

var
  settable2 : array of TOSSL_PARAM;
function cmac_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin
    settable2 := [
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
        _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, nil, 0),
        OSSL_PARAM_END
   ];
    Result := @settable2[0];
end;


function mac_gen( genctx : Pointer; cb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pmac_gen_ctx;
  key : PMAC_KEY;
begin
    gctx := genctx;
    if  (not ossl_prov_is_running) or  (gctx = nil) then
        Exit(nil);
    key := ossl_mac_key_new(gctx.libctx, 0 );
    if key  = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    { If we're doing parameter generation then we just return a blank key }
    if (gctx.selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = 0 then
        Exit(key);
    if gctx.priv_key = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        ossl_mac_key_free(key);
        Exit(nil);
    end;
    {
     * This is horrible but required for backwards compatibility. We don't
     * actually do real key generation at all. We simply copy the key that was
     * previously set in the gctx. Hopefully at some point in the future all
     * of this can be removed and we will only support the EVP_KDF APIs.
     }
    if  0>= ossl_prov_cipher_copy(@key.cipher, @gctx.cipher) then
    begin
        ossl_mac_key_free(key);
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    ossl_prov_cipher_reset(@gctx.cipher);
    key.priv_key := gctx.priv_key;
    key.priv_key_len := gctx.priv_key_len;
    gctx.priv_key_len := 0;
    gctx.priv_key := nil;
    Result := key;
end;


procedure mac_gen_cleanup( genctx : Pointer);
var
  gctx : Pmac_gen_ctx;
begin
    gctx := genctx;
    OPENSSL_secure_clear_free(gctx.priv_key, gctx.priv_key_len);
    ossl_prov_cipher_reset(@gctx.cipher);
    OPENSSL_free(Pointer(gctx));
end;

initialization
  mac_key_types := [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, nil, 0),
    OSSL_PARAM_END
];

 cmac_key_types := [
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_ENGINE, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, nil, 0),
    OSSL_PARAM_END
];


end.
