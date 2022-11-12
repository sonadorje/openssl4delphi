unit OpenSSL3.providers.implementations.keymgmt.ecx_kmgmt;

interface
uses OpenSSL.Api, openssl3.crypto.ec.ecx_key;

const
   ECX_POSSIBLE_SELECTIONS = (OSSL_KEYMGMT_SELECT_KEYPAIR);

  function x25519_new_key( provctx : Pointer):Pointer;
  function x448_new_key( provctx : Pointer):Pointer;
  function ed25519_new_key( provctx : Pointer):Pointer;
  function ed448_new_key( provctx : Pointer):Pointer;
  function ecx_has(const keydata : Pointer; selection : integer):integer;
  function ecx_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
  function ecx_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
  function key_to_params( key : PECX_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
  function ecx_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
  function ecx_get_params( key : Pointer; params : POSSL_PARAM; bits, secbits, size : integer):integer;
  function ed_get_params( key : Pointer; params : POSSL_PARAM):integer;
  function x25519_get_params( key : Pointer; params : POSSL_PARAM):integer;
  function x448_get_params( key : Pointer; params : POSSL_PARAM):integer;
  function ed25519_get_params( key : Pointer; params : POSSL_PARAM):integer;
  function ed448_get_params( key : Pointer; params : POSSL_PARAM):integer;
  function x25519_gettable_params( provctx : Pointer):POSSL_PARAM;
  function x25519_set_params(key : Pointer;const params : POSSL_PARAM):integer;
  function x25519_settable_params( provctx : Pointer):POSSL_PARAM;
  function x25519_validate(const keydata : Pointer; selection, checktype : integer):integer;
  function ecx_imexport_types( selection : integer):POSSL_PARAM;
  function x25519_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  function ecx_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
  function ecx_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
  function ecx_gen( gctx : Pecx_gen_ctx):Pointer;
  function x25519_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
  procedure ecx_gen_cleanup( genctx : Pointer);
  function ecx_load(const reference : Pointer; reference_sz : size_t):Pointer;
  function ecx_dup(const keydata_from : Pointer; selection : integer):Pointer;

const  ossl_x25519_keymgmt_functions: array[0..20] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@x25519_new_key; data:nil)),
(function_id:  10; method:(code:@ossl_ecx_key_free; data:nil)),
(function_id:  11;  method:(code:@x25519_get_params; data:nil)),
(function_id:  12;  method:(code:@x25519_gettable_params; data:nil)),
(function_id:  13;  method:(code:@x25519_set_params; data:nil)),
(function_id:  14;  method:(code:@x25519_settable_params; data:nil)),
(function_id:  21; method:(code:@ecx_has; data:nil)),
(function_id:  23; method:(code:@ecx_match; data:nil)),
(function_id:  22; method:(code:@x25519_validate; data:nil)),
(function_id:  40; method:(code:@ecx_import; data:nil)),
(function_id:  41; method:(code:@ecx_imexport_types; data:nil)),
(function_id:  42; method:(code:@ecx_export; data:nil)),
(function_id:  43; method:(code:@ecx_imexport_types; data:nil)),
(function_id:  2; method:(code:@x25519_gen_init; data:nil)),
(function_id:  4; method:(code:@ecx_gen_set_params; data:nil)),
(function_id:  5; method:(code:@ecx_gen_settable_params; data:nil)),
(function_id:  6; method:(code:@x25519_gen; data:nil)),
(function_id:  7; method:(code:@ecx_gen_cleanup; data:nil)),
(function_id:  8; method:(code:@ecx_load; data:nil)),
(function_id:  44; method:(code:@ecx_dup; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

function ed25519_gettable_params( provctx : Pointer):POSSL_PARAM;
function ed25519_set_params(key : Pointer;const params : POSSL_PARAM):integer;
 function ed25519_settable_params( provctx : Pointer):POSSL_PARAM;
 function ed25519_validate(const keydata : Pointer; selection, checktype : integer):integer;
 function ed25519_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function ed25519_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;


const ossl_ed25519_keymgmt_functions: array[0..20] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@ed25519_new_key; data:nil)),
 (function_id:  10; method:(code:@ossl_ecx_key_free; data:nil)),
 (function_id:  11; method:(code:@ed25519_get_params; data:nil)),
 (function_id:  12; method:(code:@ed25519_gettable_params; data:nil)),
 (function_id:  13; method:(code:@ed25519_set_params; data:nil)),
 (function_id:  14; method:(code:@ed25519_settable_params; data:nil)),
 (function_id:  21; method:(code:@ecx_has; data:nil)),
 (function_id:  23; method:(code:@ecx_match; data:nil)),
 (function_id:  22; method:(code:@ed25519_validate; data:nil)),
 (function_id:  40; method:(code:@ecx_import; data:nil)),
 (function_id:  41; method:(code:@ecx_imexport_types; data:nil)),
 (function_id:  42; method:(code:@ecx_export; data:nil)),
 (function_id:  43; method:(code:@ecx_imexport_types; data:nil)),
 (function_id:  2; method:(code:@ed25519_gen_init; data:nil)),
 (function_id:  4; method:(code:@ecx_gen_set_params; data:nil)),
 (function_id:  5; method:(code:@ecx_gen_settable_params; data:nil)),
 (function_id:  6; method:(code:@ed25519_gen; data:nil)),
 (function_id:  7; method:(code:@ecx_gen_cleanup; data:nil)),
 (function_id:  8; method:(code:@ecx_load; data:nil)),
 (function_id:  44; method:(code:@ecx_dup; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function ed448_gettable_params( provctx : Pointer):POSSL_PARAM;
 function ed448_set_params(key : Pointer;const params : POSSL_PARAM):integer;
 function ed448_settable_params( provctx : Pointer):POSSL_PARAM;
 function ed448_validate(const keydata : Pointer; selection, checktype : integer):integer;
 function ed448_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
 function ed448_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;

const ossl_ed448_keymgmt_functions: array[0..20] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@ed448_new_key; data:nil)),
 (function_id:  10; method:(code:@ossl_ecx_key_free; data:nil)),
 (function_id:  11; method:(code:@ed448_get_params; data:nil)),
 (function_id:  12;method:(code:@ed448_gettable_params; data:nil)),
 (function_id:  13; method:(code:@ed448_set_params; data:nil)),
 (function_id:  14;method:(code:@ed448_settable_params; data:nil)),
 (function_id:  21; method:(code:@ecx_has; data:nil)),
 (function_id:  23; method:(code:@ecx_match; data:nil)),
 (function_id:  22; method:(code:@ed448_validate; data:nil)),
 (function_id:  40; method:(code:@ecx_import; data:nil)),
 (function_id:  41; method:(code:@ecx_imexport_types; data:nil)),
 (function_id:  42; method:(code:@ecx_export; data:nil)),
 (function_id:  43; method:(code:@ecx_imexport_types; data:nil)),
 (function_id:  2; method:(code:@ed448_gen_init; data:nil)),
 (function_id:  4; method:(code:@ecx_gen_set_params; data:nil)),
 (function_id:  5; method:(code:@ecx_gen_settable_params; data:nil)),
 (function_id:  6; method:(code:@ed448_gen; data:nil)),
 (function_id:  7; method:(code:@ecx_gen_cleanup; data:nil)),
 (function_id:  8; method:(code:@ecx_load; data:nil)),
 (function_id:  44; method:(code:@ecx_dup; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

function x448_gettable_params( provctx : Pointer):POSSL_PARAM;
function x448_set_params(key : Pointer;const params : POSSL_PARAM):integer;
function x448_settable_params( provctx : Pointer):POSSL_PARAM;
function x448_validate(const keydata : Pointer; selection, checktype : integer):integer;
 function x448_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
 function x448_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;

const ossl_x448_keymgmt_functions: array[0..20] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@x448_new_key; data:nil)),
 (function_id:  10; method:(code:@ossl_ecx_key_free; data:nil)),
 (function_id:  11; method:(code:@x448_get_params; data:nil)),
 (function_id:  12; method:(code:@x448_gettable_params; data:nil)),
 (function_id:  13; method:(code:@x448_set_params; data:nil)),
 (function_id:  14; method:(code:@x448_settable_params; data:nil)),
 (function_id:  21; method:(code:@ecx_has; data:nil)),
 (function_id:  23; method:(code:@ecx_match; data:nil)),
 (function_id:  22; method:(code:@x448_validate; data:nil)),
 (function_id:  40; method:(code:@ecx_import; data:nil)),
 (function_id:  41; method:(code:@ecx_imexport_types; data:nil)),
 (function_id:  42; method:(code:@ecx_export; data:nil)),
 (function_id:  43; method:(code:@ecx_imexport_types; data:nil)),
 (function_id:  2; method:(code:@x448_gen_init; data:nil)),
 (function_id:  4; method:(code:@ecx_gen_set_params; data:nil)),
 (function_id:  5; method:(code:@ecx_gen_settable_params; data:nil)),
 (function_id:  6; method:(code:@x448_gen; data:nil)),
 (function_id:  7; method:(code:@ecx_gen_cleanup; data:nil)),
 (function_id:  8; method:(code:@ecx_load; data:nil)),
 (function_id:  44; method:(code:@ecx_dup; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );


function ecx_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM; &type : TECX_KEY_TYPE):Pointer;
function ecx_validate(const keydata : Pointer; selection, &type : integer; keylen : size_t):integer;
function ecx_key_pairwise_check(const ecx : PECX_KEY; &type : integer):integer;
function ecx_set_params(key : Pointer;const params : POSSL_PARAM):integer;
function set_property_query(ecxkey : PECX_KEY;const propq : PUTF8Char):integer;


implementation
uses OpenSSL3.Err, openssl3.crypto.mem_sec, openssl3.providers.fips.self_test,
     openssl3.crypto.mem, openssl3.providers.common.provider_ctx,
     openssl3.crypto.context, openssl3.crypto.provider.provider_seeding,
     openssl3.tsan_assist,OpenSSL3.providers.implementations.rands.crngt,
     OpenSSL3.openssl.params, openssl3.crypto.params,
     OpenSSL3.threads_none, OpenSSL3.openssl.core_dispatch,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.rand.rand_pool,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib,
     OpenSSL3.providers.implementations.rands.seeding.rand_win,
     openssl3.crypto.dh.dh_backend, openssl3.crypto.param_build,
     openssl3.crypto.params_dup, openssl3.crypto.dh.dh_group_params,
     openssl3.crypto.dh.dh_check, openssl3.crypto.dh.dh_lib,
     openssl3.crypto.ffc.ffc_params, openssl3.crypto.dh.dh_key,
     openssl3.crypto.dh.dh_gen, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.dh.dh_support, openssl3.crypto.ffc.ffc_dh,
     openssl3.crypto.o_str, openssl3.crypto.ec.ecx_backend,
     openssl3.crypto.bn.bn_rand, openssl3.crypto.ec.curve25519,
     openssl3.crypto.cpuid,      openssl3.crypto.rand.rand_lib,
     openssl3.crypto.param_build_set, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.crypto.ec.curve448, openssl3.crypto.ec.curve25519.eddsa;



var// 1d arrays
  settable : array[0..2] of TOSSL_PARAM;
  ecx_key_types, ecx_settable_params: array[0..2] of TOSSL_PARAM;
  ecx_gettable_params, ed_settable_params,
  ed_gettable_params:  array of TOSSL_PARAM;





function x448_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pecx_gen_ctx;
begin
    gctx := genctx;
    if not ossl_prov_is_running then
        Exit(0);
    Result := ecx_gen(gctx);
end;





function x448_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X448);
end;




function x448_validate(const keydata : Pointer; selection, checktype : integer):integer;
begin
    Result := ecx_validate(keydata, selection, Int(ECX_KEY_TYPE_X448), X448_KEYLEN);
end;





function x448_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ecx_settable_params;
end;




function x448_set_params(key : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := ecx_set_params(key, params);
end;



function x448_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ecx_gettable_params[0];
end;



function ed448_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pecx_gen_ctx;
begin
    gctx := genctx;
    if not ossl_prov_is_running then
        Exit(0);
    Result := ecx_gen(gctx);
end;





function ed448_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_ED448);
end;




function ed448_validate(const keydata : Pointer; selection, checktype : integer):integer;
begin
    Result := ecx_validate(keydata, selection, Int(ECX_KEY_TYPE_ED448), ED448_KEYLEN);
end;

function ed448_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ed_settable_params[0];
end;


function ed448_set_params(key : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := 1;
end;

function ed448_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ed_gettable_params[0];
end;

function ed25519_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pecx_gen_ctx;
begin
    gctx := genctx;
    if not ossl_prov_is_running then
        Exit(0);
{$IFDEF S390X_EC_ASM}
    if OPENSSL_s39$cap_P.pcc[1] and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_ED25519 then  and  OPENSSL_s39$cap_P.kdsa[0] and S390X_CAPBIT(S390X_EDDSA_SIGN_ED25519)
         and  OPENSSL_s39$cap_P.kdsa[0]
            and S390X_CAPBIT(S390X_EDDSA_VERIFY_ED25519))
        Exit(s390x_ecd_keygen25519(gctx));
{$ENDIF}
    Result := ecx_gen(gctx);
end;

function ed25519_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_ED25519);
end;

function ed25519_validate(const keydata : Pointer; selection, checktype : integer):integer;
begin
    Result := ecx_validate(keydata, selection, Int(ECX_KEY_TYPE_ED25519), ED25519_KEYLEN);
end;

function ed25519_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ed_settable_params[0];
end;


function ed25519_set_params(key : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := 1;
end;

function ed25519_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ed_gettable_params[0];
end;

function set_property_query(ecxkey : PECX_KEY;const propq : PUTF8Char):integer;
begin
    OPENSSL_free(Pointer(ecxkey.propq));
    ecxkey.propq := nil;
    if propq <> nil then
    begin
        OPENSSL_strdup(ecxkey.propq, propq);
        if ecxkey.propq = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    Result := 1;
end;




function ecx_set_params(key : Pointer;const params : POSSL_PARAM):integer;
var
  ecxkey : PECX_KEY;
  p : POSSL_PARAM;
  buf : Pointer;
begin
    ecxkey := key;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if p <> nil then
    begin
        buf := @ecxkey.pubkey;
        if (p.data_size <> ecxkey.keylen)
                 or  (0>= OSSL_PARAM_get_octet_string(p, buf, sizeof(ecxkey.pubkey) ,
                                                nil))  then
            Exit(0);
        OPENSSL_clear_free(Pointer(ecxkey.privkey), ecxkey.keylen);
        ecxkey.privkey := nil;
        ecxkey.haspubkey := 1;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if p <> nil then
    begin
        if (p.data_type <> OSSL_PARAM_UTF8_STRING)
             or  (0>= set_property_query(ecxkey, p.data)) then
            Exit(0);
    end;
    Result := 1;
end;



function ecx_key_pairwise_check(const ecx : PECX_KEY; &type : integer):integer;
var
  pub : array[0..63] of byte;
begin
    case &type of
    Int(ECX_KEY_TYPE_X25519):
        ossl_x25519_public_from_private(@pub, ecx.privkey);
        //break;
    Int(ECX_KEY_TYPE_X448):
        ossl_x448_public_from_private(@pub, ecx.privkey);
        //break;
    Int(ECX_KEY_TYPE_ED25519):
        if 0>= ossl_ed25519_public_from_private(ecx.libctx, @pub, ecx.privkey,
                                              ecx.propq) then
            Exit(0);
        //break;
    Int(ECX_KEY_TYPE_ED448):
        if 0>= ossl_ed448_public_from_private(ecx.libctx, @pub, ecx.privkey,
                                            ecx.propq  ) then
            Exit(0);
        //break;
    else
        Exit(0);
    end;
    Result := Int(CRYPTO_memcmp(@ecx.pubkey, @pub, ecx.keylen) = 0);
end;

function ecx_validate(const keydata : Pointer; selection, &type : integer; keylen : size_t):integer;
var
  ecx : PECX_KEY;
  ok : Boolean;
begin
     ecx := keydata;
    ok := keylen = ecx.keylen;
    if not ossl_prov_is_running then
        Exit(0);
    if (selection and ECX_POSSIBLE_SELECTIONS )= 0 then
       Exit(1); { nothing to validate }
    if not ok then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        Exit(0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        ok := (ok)  and  (ecx.haspubkey>0);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        ok := (ok)  and  (ecx.privkey <> nil);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) = OSSL_KEYMGMT_SELECT_KEYPAIR then
        ok := (ok)  and  (ecx_key_pairwise_check(ecx, &type)>0);
    Result := Int(ok);
end;


function ecx_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM; &type : TECX_KEY_TYPE):Pointer;
var
  libctx : POSSL_LIB_CTX;

  gctx : Pecx_gen_ctx;
begin
    libctx := PROV_LIBCTX_OF(provctx);
    gctx := nil;
    if not ossl_prov_is_running then
        Exit(nil);
    gctx := OPENSSL_zalloc(sizeof( gctx^));
    if gctx <> nil then
    begin
        gctx.libctx := libctx;
        gctx.&type := &type;
        gctx.selection := selection;
    end;
    if 0>= ecx_gen_set_params(gctx, params)  then
    begin
        OPENSSL_free(Pointer(gctx));
        gctx := nil;
    end;
    Result := gctx;
end;


function ecx_load(const reference : Pointer; reference_sz : size_t):Pointer;
var
  key : PECX_KEY;
begin
    key := nil;
    if (ossl_prov_is_running)  and  (reference_sz = sizeof(key))  then
    begin
        { The contents of the reference is the address to our object }
        key := PPECX_KEY(reference)^;
        { We grabbed, so we detach it }
        PPECX_KEY(reference)^ := nil;
        Exit(key);
    end;
    Result := nil;
end;


function ecx_dup(const keydata_from : Pointer; selection : integer):Pointer;
begin
    if ossl_prov_is_running() then
        Exit(ossl_ecx_key_dup(keydata_from, selection));
    Result := nil;
end;




procedure ecx_gen_cleanup( genctx : Pointer);
var
  gctx : Pecx_gen_ctx;
begin
    gctx := genctx;
    OPENSSL_free(gctx.propq);
    OPENSSL_free(gctx);
end;





function x25519_gen( genctx : Pointer; osslcb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  gctx : Pecx_gen_ctx;
begin
    gctx := genctx;
    if not ossl_prov_is_running then
        Exit(0);
{$IFDEF S390X_EC_ASM}
    if OPENSSL_s39$cap_P.pcc[1] and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X25519 then )
        Exit(s390x_ecx_keygen25519(gctx));
{$ENDIF}
    Result := ecx_gen(gctx);
end;


function ecx_gen( gctx : Pecx_gen_ctx):Pointer;
var
  key : PECX_KEY;

  privkey : PByte;
  label _err;
begin
    if gctx = nil then Exit(nil);
    key := ossl_ecx_key_new(gctx.libctx, gctx.&type, 0,
                                gctx.propq);
    if (key = nil)  then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    { If we're doing parameter generation then we just return a blank key }
    if (gctx.selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) = 0 then
        Exit(key);
    privkey := ossl_ecx_key_allocate_privkey(key );
    if privkey = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if RAND_priv_bytes_ex(gctx.libctx, privkey, key.keylen, 0 ) <= 0 then
        goto _err ;
    case gctx.&type of
      ECX_KEY_TYPE_X25519:
      begin
          privkey[0] := privkey[0] and 248;
          privkey[X25519_KEYLEN - 1] := privkey[X25519_KEYLEN - 1] and 127;
          privkey[X25519_KEYLEN - 1]  := privkey[X25519_KEYLEN - 1]  or 64;
          ossl_x25519_public_from_private(@key.pubkey, privkey);
      end;
      ECX_KEY_TYPE_X448:
      begin
          privkey[0] := privkey[0] and 252;
          privkey[X448_KEYLEN - 1]  := privkey[X448_KEYLEN - 1]  or 128;
          ossl_x448_public_from_private(@key.pubkey, privkey);
      end;
      ECX_KEY_TYPE_ED25519:
      begin
          if 0>= ossl_ed25519_public_from_private(gctx.libctx, @key.pubkey, privkey,
                                                gctx.propq) then
              goto _err ;
      end;
      ECX_KEY_TYPE_ED448:
      begin
          if 0>= ossl_ed448_public_from_private(gctx.libctx, @key.pubkey, privkey,
                                              gctx.propq) then
              goto _err ;
      end;
    end;
    key.haspubkey := 1;
    Exit(key);
_err:
    ossl_ecx_key_free(key);
    Result := nil;
end;



function ecx_gen_settable_params( genctx, provctx : Pointer):POSSL_PARAM;
begin

   settable[0] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nil, 0);
   settable[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
   settable[2] := OSSL_PARAM_END;

    Result := @settable;
end;



function ecx_gen_set_params(genctx : Pointer;const params : POSSL_PARAM):integer;
var
    gctx      : Pecx_gen_ctx;

    p         : POSSL_PARAM;

    groupname : PUTF8Char;
begin
    gctx := genctx;
    if gctx = nil then Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if p <> nil then begin
        groupname := nil;
        {
         * We optionally allow setting a group name - but each algorithm only
         * support one such name, so all we do is verify that it is the one we
         * expected.
         }
        case gctx.&type of
            ECX_KEY_TYPE_X25519:
                groupname := 'x25519';
                //break;
            ECX_KEY_TYPE_X448:
                groupname := 'x448';
                //break;
            else
                { We only support this for key exchange at the moment }
                begin
                  //
                end;  ;
        end;
        if (p.data_type <> OSSL_PARAM_UTF8_STRING)
                 or  (groupname = nil)
                 or  (strcasecmp(p.data, groupname) <> 0)  then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        OPENSSL_free(gctx.propq);
        OPENSSL_strdup(gctx.propq ,p.data);
        if gctx.propq = nil then Exit(0);
    end;
    Result := 1;
end;





function x25519_gen_init(provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
    Result := ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X25519);
end;



function ecx_imexport_types( selection : integer):POSSL_PARAM;
begin
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) <> 0 then
        Exit(@ecx_key_types);
    Result := nil;
end;




function x25519_validate(const keydata : Pointer; selection, checktype : integer):integer;
begin
    Result := ecx_validate(keydata, selection, Int(ECX_KEY_TYPE_X25519), X25519_KEYLEN);
end;




function x25519_settable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ecx_settable_params;
end;




function x25519_set_params(key : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := ecx_set_params(key, params);
end;





function x25519_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @ecx_gettable_params[0];
end;



function x25519_new_key( provctx : Pointer):Pointer;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    result := ossl_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_X25519, 0,
                            nil);
end;


function x448_new_key( provctx : Pointer):Pointer;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    result := ossl_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_X448, 0,
                            nil);
end;


function ed25519_new_key( provctx : Pointer):Pointer;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    result := ossl_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_ED25519, 0,
                            nil);
end;


function ed448_new_key( provctx : Pointer):Pointer;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    result := ossl_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_ED448, 0,
                            nil);
end;


function ecx_has(const keydata : Pointer; selection : integer):integer;
var
  key : PECX_KEY;

  ok : Boolean;
begin
    key := keydata;
    ok := Boolean(0);
    if (ossl_prov_is_running)  and ( key <> nil)  then
    begin
        {
         * ECX keys always have all the parameters they need (i.e. none).
         * Therefore we always result = with 1, if asked about parameters.
         }
        ok := Boolean(1);
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 then
            ok := (ok)  and  (key.haspubkey>0);
        if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
            ok := (ok)  and  (key.privkey <> nil);
    end;
    result := Int(ok);
end;


function ecx_match(const keydata1, keydata2 : Pointer; selection : integer):integer;
var
  key1,
  key2        : PECX_KEY;

  ok: Boolean;
  key_checked : integer;

  pa,
  pb          : PByte;

  pal,
  pbl         : size_t;


begin
    key1 := keydata1;
    key2 := keydata2;
    ok := Boolean(1);
    if not ossl_prov_is_running then
        Exit(0);
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
        ok := (ok)  and  (key1.&type = key2.&type);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 then
    begin
        key_checked := 0;
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
        begin
             pa := get_result(key1.haspubkey>0 , PByte(@key1.pubkey) , nil);
             pb := get_result(key2.haspubkey>0 , PByte(@key2.pubkey) , nil);
            pal := key1.keylen;
            pbl := key2.keylen;
            if (pa <> nil)  and  (pb <> nil) then
            begin
                ok := (ok)
                     and  (key1.&type = key2.&type)
                     and  (pal = pbl)
                     and  (CRYPTO_memcmp(pa, pb, pal) = 0);
                key_checked := 1;
            end;
        end;
        if (0>= key_checked)
             and ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)  then
        begin
            pa := key1.privkey;
            pb := key2.privkey;
            pal := key1.keylen;
            pbl := key2.keylen;
            if (pa <> nil)  and ( pb <> nil) then
            begin
                ok := (ok)
                     and  (key1.&type = key2.&type)
                     and  (pal = pbl)
                     and  (CRYPTO_memcmp(pa, pb, pal) = 0);
                key_checked := 1;
            end;
        end;
        ok := (ok)  and  (key_checked>0);
    end;
    result := Int( ok);
end;


function ecx_import(keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
var
    key             : PECX_KEY;

  ok: Boolean;
  include_private : integer;
begin
    key := keydata;
    ok := Boolean(1);
    include_private := 0;
    if (not ossl_prov_is_running)  or ( key = nil)  then
        Exit( 0);
    if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) = 0 then
         Exit( 0);
    include_private := int((selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0);
    ok := (ok)  and  (ossl_ecx_key_fromdata(key, params, include_private)>0);
    result := Int(ok);
end;


function key_to_params( key : PECX_KEY; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
begin
    if key = nil then Exit(0);
    if 0>= ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_PUB_KEY,
                                           @key.pubkey, key.keylen) then
        Exit(0);
    if (key.privkey <> nil)
         and  (0>= ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key.privkey, key.keylen) )then
        Exit(0);
    result := 1;
end;


function ecx_export( keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
  key : PECX_KEY;

  tmpl : POSSL_PARAM_BLD;

  params : POSSL_PARAM;

  ret : integer;
  label _err;
begin
    key := keydata;
    params := nil;
    ret := 0;
    if (not ossl_prov_is_running)  or  (key = nil)  then
       Exit(0);
    tmpl := OSSL_PARAM_BLD_new();
    if tmpl = nil then Exit(0);
    if ((selection and OSSL_KEYMGMT_SELECT_KEYPAIR ) <> 0 )
          and  (0>= key_to_params(key, tmpl, nil)) then
        goto _err ;
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if params = nil then goto _err ;
    ret := param_cb(params, cbarg);
    OSSL_PARAM_free(params);
_err:
    OSSL_PARAM_BLD_free(tmpl);
    result := ret;
end;


function ecx_get_params( key : Pointer; params : POSSL_PARAM; bits, secbits, size : integer):integer;
var
  ecx : PECX_KEY;

  p : POSSL_PARAM;
begin
    ecx := key;
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p  <> nil )
         and  (0>= OSSL_PARAM_set_int(p, bits)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS );
    if (p  <> nil)
         and  (0>= OSSL_PARAM_set_int(p, secbits)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE );
    if (p  <> nil)
         and  (0>= OSSL_PARAM_set_int(p, size)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY );
    if (p  <> nil)
             and ( (ecx.&type = ECX_KEY_TYPE_X25519)
                 or ( ecx.&type = ECX_KEY_TYPE_X448)) then
    begin
        if 0>= OSSL_PARAM_set_octet_string(p, @ecx.pubkey, ecx.keylen) then
           Exit(0);
    end;
    result := key_to_params(ecx, nil, params);
end;


function ed_get_params( key : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_utf8_string(p, '')) then
        Exit(0);
    result := 1;
end;


function x25519_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    result := ecx_get_params(key, params, X25519_BITS, X25519_SECURITY_BITS,
                          X25519_KEYLEN);
end;


function x448_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    result := ecx_get_params(key, params, X448_BITS, X448_SECURITY_BITS,
                          X448_KEYLEN);
end;


function ed25519_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    result := ecx_get_params(key, params, ED25519_BITS, ED25519_SECURITY_BITS, ED25519_SIGSIZE)
              and  ed_get_params(key, params);
end;


function ed448_get_params( key : Pointer; params : POSSL_PARAM):integer;
begin
    result := ecx_get_params(key, params, ED448_BITS, ED448_SECURITY_BITS, ED448_SIGSIZE)
              and  ed_get_params(key, params);
end;

initialization
    ecx_key_types[0] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0);
    ecx_key_types[1] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0);
    ecx_key_types[2] := OSSL_PARAM_END;


    ecx_settable_params[0] := _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0);
    ecx_settable_params[1] := _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, nil, 0);
    ecx_settable_params[2] := OSSL_PARAM_END;

    ecx_gettable_params := [
      _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nil),
      _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil),
      _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil),
      _OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, nil, 0),
      _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nil, 0),
      _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
      _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
      OSSL_PARAM_END
    ];

     ed_settable_params := [ OSSL_PARAM_END] ;

     ed_gettable_params := [
        _OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nil),
        _OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nil),
        _OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nil),
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nil, 0),
        _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, nil, 0),
        OSSL_PARAM_END
    ];
end.
