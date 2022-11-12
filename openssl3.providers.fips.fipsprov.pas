unit openssl3.providers.fips.fipsprov;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils, OpenSSL3.openssl.core_dispatch;

type
    fips_global_st = record
        handle                     : POSSL_CORE_HANDLE;
        selftest_params            : TSELF_TEST_POST_PARAMS;
        fips_security_checks       : integer;
        fips_security_check_option : PUTF8Char;
    end;
    TFIPS_GLOBAL = fips_global_st;
    PFIPS_GLOBAL = ^TFIPS_GLOBAL;

procedure ERR_new();
procedure ERR_set_debug(const func : PUTF8Char);
procedure ERR_set_error(lib, reason : integer;const fmt : string);
function ERR_PACK( lib : integer; func : PUTF8Char; reason : integer):uint32;
function ERR_set_mark:integer;
function ERR_pop_to_mark:integer;
function ERR_clear_last_mark:integer;
procedure ERR_vset_error(lib, reason : integer;const fmt : string);



 function OSSL_provider_init_int(const handle : POSSL_CORE_HANDLE;{const} _in : POSSL_DISPATCH; _out : PPOSSL_DISPATCH;var provctx : Pointer):integer;
 function _OSSL_FUNC_core_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_gettable_params_fn;
  function _OSSL_FUNC_core_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_params_fn;
  function _OSSL_FUNC_core_thread_start(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_thread_start_fn;
  function _OSSL_FUNC_core_get_libctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_libctx_fn;
  function _OSSL_FUNC_core_new_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_new_error_fn;
  function _OSSL_FUNC_core_set_error_debug(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_set_error_debug_fn;
  function _OSSL_FUNC_core_vset_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_vset_error_fn;
  function _OSSL_FUNC_core_set_error_mark(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_set_error_mark_fn;
  function _OSSL_FUNC_core_clear_last_error_mark(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_clear_last_error_mark_fn;
  function _OSSL_FUNC_core_pop_error_to_mark(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_pop_error_to_mark_fn;

  function _OSSL_FUNC_CRYPTO_malloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_malloc_fn;
  function _OSSL_FUNC_CRYPTO_zalloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_zalloc_fn;
  function _OSSL_FUNC_CRYPTO_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_free_fn;
  function _OSSL_FUNC_CRYPTO_clear_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_clear_free_fn;
  function _OSSL_FUNC_CRYPTO_realloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_realloc_fn;
  function _OSSL_FUNC_CRYPTO_clear_realloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_clear_realloc_fn;
  function _OSSL_FUNC_CRYPTO_secure_malloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_malloc_fn;
  function _OSSL_FUNC_CRYPTO_secure_zalloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_zalloc_fn;
  function _OSSL_FUNC_CRYPTO_secure_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_free_fn;
  function _OSSL_FUNC_CRYPTO_secure_clear_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_clear_free_fn;
  function _OSSL_FUNC_CRYPTO_secure_allocated(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_allocated_fn;
  function _OSSL_FUNC_OPENSSL_cleanse(const opf : POSSL_DISPATCH):TOSSL_FUNC_OPENSSL_cleanse_fn;

  function _OSSL_FUNC_BIO_new_file(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_file_fn;
  function _OSSL_FUNC_BIO_new_membuf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_membuf_fn;
  function _OSSL_FUNC_BIO_read_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_read_ex_fn;
  function _OSSL_FUNC_BIO_write_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_write_ex_fn;
  function _OSSL_FUNC_BIO_gets(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_gets_fn;
  function _OSSL_FUNC_BIO_puts(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_puts_fn;
  function _OSSL_FUNC_BIO_up_ref(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_up_ref_fn;
  function _OSSL_FUNC_BIO_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_free_fn;
  function _OSSL_FUNC_BIO_vprintf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_vprintf_fn;
  function _OSSL_FUNC_BIO_vsnprintf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_vsnprintf_fn;
  function _OSSL_FUNC_BIO_ctrl(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_ctrl_fn;
  function _OSSL_FUNC_self_test_cb(const opf : POSSL_DISPATCH):TOSSL_FUNC_self_test_cb_fn;
  function fips_prov_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
  procedure fips_prov_ossl_ctx_free(fgbl: Pointer);
  procedure set_self_test_cb( fgbl : PFIPS_GLOBAL);
  function FIPS_get_core_handle( libctx : POSSL_LIB_CTX):POSSL_CORE_HANDLE;



 var
  c_new_error: TOSSL_FUNC_core_new_error_fn ;
  c_set_error_debug: TOSSL_FUNC_core_set_error_debug_fn ;
  c_vset_error: TOSSL_FUNC_core_vset_error_fn ;
  c_set_error_mark: TOSSL_FUNC_core_set_error_mark_fn ;
  c_pop_error_to_mark: TOSSL_FUNC_core_pop_error_to_mark_fn ;
  c_clear_last_error_mark: TOSSL_FUNC_core_clear_last_error_mark_fn ;
  c_get_libctx: TOSSL_FUNC_core_get_libctx_fn ;
  c_gettable_params: TOSSL_FUNC_core_gettable_params_fn ;
  c_get_params: TOSSL_FUNC_core_get_params_fn ;
  c_thread_start: TOSSL_FUNC_core_thread_start_fn;
  c_CRYPTO_malloc: TOSSL_FUNC_CRYPTO_malloc_fn ;
  c_CRYPTO_zalloc: TOSSL_FUNC_CRYPTO_zalloc_fn;
  c_CRYPTO_free: TOSSL_FUNC_CRYPTO_free_fn ;
  c_CRYPTO_clear_free: TOSSL_FUNC_CRYPTO_clear_free_fn ;
  c_CRYPTO_realloc: TOSSL_FUNC_CRYPTO_realloc_fn ;
  c_CRYPTO_clear_realloc     : TOSSL_FUNC_CRYPTO_clear_realloc_fn;
  c_CRYPTO_secure_malloc     : TOSSL_FUNC_CRYPTO_secure_malloc_fn;
  c_CRYPTO_secure_zalloc     : TOSSL_FUNC_CRYPTO_secure_zalloc_fn;
  c_CRYPTO_secure_free       : TOSSL_FUNC_CRYPTO_secure_free_fn;
  c_CRYPTO_secure_clear_free : TOSSL_FUNC_CRYPTO_secure_clear_free_fn;
  c_CRYPTO_secure_allocated  : TOSSL_FUNC_CRYPTO_secure_allocated_fn;
  c_BIO_vsnprintf : TOSSL_FUNC_BIO_vsnprintf_fn;
  c_stcbfn        : TOSSL_FUNC_self_test_cb_fn;

   fips_ciphers: array of TOSSL_ALGORITHM_CAPABLE;
   exported_fips_ciphers: array[0..50] of TOSSL_ALGORITHM ;
   fips_digests, fips_macs, fips_kdfs, fips_rands,
   fips_keymgmt, fips_keyexch, fips_signature,
   fips_asym_cipher, fips_asym_kem : array of TOSSL_ALGORITHM ;
   fips_param_types: array of TOSSL_PARAM;

   procedure fips_teardown( provctx : Pointer);
   function fips_gettable_params( provctx : Pointer):POSSL_PARAM;
   function fips_get_params_from_core( fgbl : PFIPS_GLOBAL):integer;
   function fips_get_params( provctx : Pointer; params : POSSL_PARAM):integer;
   function fips_query( provctx : Pointer; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;
   function fips_self_test( provctx : Pointer):integer;


const
    FIPS_DEFAULT_PROPERTIES:    PUTF8Char = 'provider=fips,fips=yes';
    FIPS_UNAPPROVED_PROPERTIES: PUTF8Char = 'provider=fips,fips=no';

    fips_prov_ossl_ctx_method :TOSSL_LIB_CTX_METHOD = (
    priority : OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
    new_func : fips_prov_ossl_ctx_new;
    free_func: fips_prov_ossl_ctx_free);
 



implementation
uses openssl3.crypto.context,                 openssl3.crypto.params,
     openssl3.crypto.mem,  OpenSSL3.Err,      OpenSSL3.openssl.params,
     openssl3.providers.fips.self_test,       openssl3.crypto.provider.provider_seeding,
     OpenSSL3.providers.common.capabilities,  OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_xts,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_gcm,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ccm,
     OpenSSL3.providers.implementations.rands.drbg_ctr,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.kem.rsa_kem,
     openssl3.providers.implementations.macs.cmac_prov,
     OpenSSL3.providers.implementations.signature.eddsa_sig,
     OpenSSL3.providers.implementations.asymciphers.rsa_enc,
     OpenSSL3.providers.implementations.signature.ecdsa_sig,
     OpenSSL3.providers.implementations.signature.rsa_sig,
     OpenSSL3.providers.implementations.signature.dsa_sig,
     OpenSSL3.providers.implementations.exchange.ecx_exch,
     OpenSSL3.providers.implementations.exchange.kdf_exch,
     OpenSSL3.providers.implementations.exchange.dh_exch,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.implementations.exchange.ecdh_exch,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.mac_legacy_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ecx_kmgmt,
     OpenSSL3.providers.implementations.kdf_legacy_kmgmt,
     OpenSSL3.providers.implementations.rands.drbg_hash,
     OpenSSL3.providers.implementations.rands.drbg_hmac,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_wrp,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha1_hw,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha256_hw ,
     openssl3.providers.implementations.digests.sha2_prov,
     openssl3.providers.implementations.digests.sha3_prov,
     openssl3.providers.implementations.macs.gmac_prov,
     OpenSSL3.providers.implementations.kdfs.kbkdf,
     OpenSSL3.providers.implementations.rands.test_rng,
     openssl3.providers.implementations.macs.hmac_prov,
     OpenSSL3.providers.implementations.kdfs.hkdf,
     OpenSSL3.providers.implementations.kdfs.pbkdf2,
     OpenSSL3.providers.implementations.kdfs.sskdf,
     openssl3.providers.implementations.macs.kmac_prov,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes,
     OpenSSL3.providers.implementations.kdfs.sshkdf,
     OpenSSL3.providers.implementations.kdfs.x942kdf,
     OpenSSL3.providers.implementations.kdfs.tls1_prf,
     OpenSSL3.providers.implementations.ciphers.cipher_aes;

const fips_dispatch_table: array[0..6] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_PROVIDER_TEARDOWN; method:(code:@fips_teardown; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GETTABLE_PARAMS; method:(code:@fips_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GET_PARAMS; method:(code:@fips_get_params; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_QUERY_OPERATION; method:(code:@fips_query; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GET_CAPABILITIES; method:(code:@ossl_prov_get_capabilities; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_SELF_TEST; method:(code:@fips_self_test; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) ));




function fips_self_test( provctx : Pointer):integer;
var
  fgbl : PFIPS_GLOBAL;
  ctx:  POSSL_LIB_CTX;
begin
    ctx := ossl_prov_ctx_get0_libctx(provctx);
    fgbl := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_FIPS_PROV_INDEX,
                                  @fips_prov_ossl_ctx_method);
    set_self_test_cb(fgbl);
    Result := get_result(SELF_TEST_post(@fgbl.selftest_params, 1) > 0, 1 , 0);
end;

function fips_query( provctx : Pointer; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;
begin
    no_cache^ := 0;
    if not ossl_prov_is_running then Exit(nil);
    case operation_id of
        OSSL_OP_DIGEST:
            Exit(@fips_digests[0]);
        OSSL_OP_CIPHER:
            Exit(@exported_fips_ciphers);
        OSSL_OP_MAC:
            Exit(@fips_macs[0]);
        OSSL_OP_KDF:
            Exit(@fips_kdfs[0]);
        OSSL_OP_RAND:
            Exit(@fips_rands[0]);
        OSSL_OP_KEYMGMT:
            Exit(@fips_keymgmt[0]);
        OSSL_OP_KEYEXCH:
            Exit(@fips_keyexch[0]);
        OSSL_OP_SIGNATURE:
            Exit(@fips_signature[0]);
        OSSL_OP_ASYM_CIPHER:
            Exit(@fips_asym_cipher[0]);
        OSSL_OP_KEM:
            Exit(@fips_asym_kem[0]);
    end;
    Result := nil;
end;


function fips_get_params( provctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
  fgbl : PFIPS_GLOBAL;
  ctx: POSSL_LIB_CTX;
begin
    ctx := ossl_prov_ctx_get0_libctx(provctx);
    fgbl := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_FIPS_PROV_INDEX,
                                  @fips_prov_ossl_ctx_method);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, 'OpenSSL FIPS Provider')) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_int(p, Int(ossl_prov_is_running))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_SECURITY_CHECKS);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_int(p, fgbl.fips_security_checks)) then
        Exit(0);
    Result := 1;
end;



function fips_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @fips_param_types[0];
end;




procedure fips_teardown( provctx : Pointer);
begin
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
end;



function fips_get_params_from_core( fgbl : PFIPS_GLOBAL):integer;
var
    core_params : array[0..7] of TOSSL_PARAM;
    p: POSSL_PARAM;
begin
    {
    * Parameters to retrieve from the core provider - required for self testing.
    * NOTE: inside core_get_params these will be loaded from config items
    * stored inside prov.parameters (except for
    * OSSL_PROV_PARAM_CORE_MODULE_FILENAME).
    * OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS is not a self test parameter.
    }
    // p := @core_params;
    core_params[0] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_PARAM_CORE_MODULE_FILENAME,
            PPUTF8Char(@fgbl.selftest_params.module_filename),
            sizeof(fgbl.selftest_params.module_filename));
    core_params[1] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_FIPS_PARAM_MODULE_MAC,
            PPUTF8Char(@fgbl.selftest_params.module_checksum_data),
            sizeof(fgbl.selftest_params.module_checksum_data));
    core_params[2] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
            PPUTF8Char(@fgbl.selftest_params.indicator_checksum_data),
            sizeof(fgbl.selftest_params.indicator_checksum_data));
    core_params[3] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
            PPUTF8Char(@fgbl.selftest_params.indicator_data),
            sizeof(fgbl.selftest_params.indicator_data));
    core_params[4] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
            PPUTF8Char(@fgbl.selftest_params.indicator_version),
            sizeof(fgbl.selftest_params.indicator_version));
    core_params[5] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS,
            PPUTF8Char(@fgbl.selftest_params.conditional_error_check),
            sizeof(fgbl.selftest_params.conditional_error_check));
    core_params[6] := OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS,
            PPUTF8Char(@fgbl.fips_security_check_option),
            sizeof(fgbl.fips_security_check_option));
    core_params[7] := OSSL_PARAM_construct_end;
    p := @core_params;
    if 0>=c_get_params(fgbl.handle, p) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;


function FIPS_get_core_handle( libctx : POSSL_LIB_CTX):POSSL_CORE_HANDLE;
var
  fgbl : PFIPS_GLOBAL;
begin
    fgbl := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_FIPS_PROV_INDEX,
                                              @fips_prov_ossl_ctx_method);
    if fgbl = nil then Exit(nil);
    Result := fgbl.handle;
end;

procedure set_self_test_cb( fgbl : PFIPS_GLOBAL);
var
  handle : POSSL_CORE_HANDLE;
begin
    handle := FIPS_get_core_handle(fgbl.selftest_params.libctx);
    if Assigned(c_stcbfn)  and  Assigned(c_get_libctx) then
    begin
        c_stcbfn(c_get_libctx(handle), @fgbl.selftest_params.cb,
                              @fgbl.selftest_params.cb_arg);
    end
    else
    begin
        fgbl.selftest_params.cb := nil;
        fgbl.selftest_params.cb_arg := nil;
    end;
end;

procedure fips_prov_ossl_ctx_free(fgbl: Pointer);
begin
    OPENSSL_free(fgbl);
end;


function fips_prov_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
var
  fgbl : PFIPS_GLOBAL;
begin
    fgbl := OPENSSL_zalloc(sizeof( fgbl^));
    if fgbl = nil then Exit(nil);
    fgbl.fips_security_checks := 1;
    fgbl.fips_security_check_option := '1';
    Result := fgbl;
end;


function _OSSL_FUNC_self_test_cb(const opf : POSSL_DISPATCH):TOSSL_FUNC_self_test_cb_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_self_test_cb_fn *)opf.function;
end;



function _OSSL_FUNC_BIO_new_file(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_file_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_new_file_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_new_membuf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_membuf_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_new_membuf_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_read_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_read_ex_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_read_ex_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_write_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_write_ex_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_write_ex_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_gets(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_gets_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_gets_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_puts(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_puts_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_puts_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_up_ref(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_up_ref_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_up_ref_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_free_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_free_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_vprintf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_vprintf_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_vprintf_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_vsnprintf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_vsnprintf_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_vsnprintf_fn *)opf.function;
end;


function _OSSL_FUNC_BIO_ctrl(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_ctrl_fn;
begin
Result := opf.method.Code; // OSSL_FUNC_BIO_ctrl_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_malloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_malloc_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_malloc_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_zalloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_zalloc_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_zalloc_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_free_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_free_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_clear_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_clear_free_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_clear_free_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_realloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_realloc_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_realloc_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_clear_realloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_clear_realloc_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_clear_realloc_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_secure_malloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_malloc_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_secure_malloc_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_secure_zalloc(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_zalloc_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_secure_zalloc_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_secure_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_free_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_secure_free_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_secure_clear_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_clear_free_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_secure_clear_free_fn *)opf.function;
end;


function _OSSL_FUNC_CRYPTO_secure_allocated(const opf : POSSL_DISPATCH):TOSSL_FUNC_CRYPTO_secure_allocated_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_CRYPTO_secure_allocated_fn *)opf.function;
end;


function _OSSL_FUNC_OPENSSL_cleanse(const opf : POSSL_DISPATCH):TOSSL_FUNC_OPENSSL_cleanse_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_OPENSSL_cleanse_fn *)opf.function;
end;

function _OSSL_FUNC_core_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_gettable_params_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_core_gettable_params_fn *)opf.function;
end;


function _OSSL_FUNC_core_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_params_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_core_get_params_fn *)opf.function;
end;


function _OSSL_FUNC_core_thread_start(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_thread_start_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_core_thread_start_fn *)opf.function;
end;


function _OSSL_FUNC_core_get_libctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_libctx_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_core_get_libctx_fn *)opf.function;
end;


function _OSSL_FUNC_core_new_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_new_error_fn;
begin
   Result := opf.method.Code; // OSSL_FUNC_core_new_error_fn *)opf.function;
end;


function _OSSL_FUNC_core_set_error_debug(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_set_error_debug_fn;
begin
   Result := opf.method.Code; // OSSL_FUNC_core_set_error_debug_fn *)opf.function;
end;


function _OSSL_FUNC_core_vset_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_vset_error_fn;
begin
   Result := opf.method.Code; // OSSL_FUNC_core_vset_error_fn *)opf.function;
end;


function _OSSL_FUNC_core_set_error_mark(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_set_error_mark_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_core_set_error_mark_fn *)opf.function;
end;


function _OSSL_FUNC_core_clear_last_error_mark(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_clear_last_error_mark_fn;
begin
   Result := opf.method.Code; // OSSL_FUNC_core_clear_last_error_mark_fn *)opf.function;
end;


function _OSSL_FUNC_core_pop_error_to_mark(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_pop_error_to_mark_fn;
begin
   Result := opf.method.Code; // OSSL_FUNC_core_pop_error_to_mark_fn *)opf.function;
end;

function OSSL_provider_init_int(const handle : POSSL_CORE_HANDLE;{const} _in : POSSL_DISPATCH; _out : PPOSSL_DISPATCH;var provctx : Pointer):integer;
var
    fgbl            : PFIPS_GLOBAL;
    libctx          : POSSL_LIB_CTX;
    selftest_params : TSELF_TEST_POST_PARAMS;
    p: Pointer;
    label _err;
begin
    libctx := nil;
    FillChar(selftest_params, sizeof(selftest_params), 0);
    if 0>=ossl_prov_seeding_from_dispatch(_in) then
        Exit(0);
    while _in.function_id <> 0 do
    begin
        {
         * We do not support the scenario of an application linked against
         * multiple versions of libcrypto (e.g. one   and one dynamic), but
         * sharing a single fips.so. We do a simple sanity check here.
         }
        case _in.function_id of
            OSSL_FUNC_CORE_GET_LIBCTX:
            begin
               if not Assigned(c_get_libctx) then
                  c_get_libctx := _OSSL_FUNC_core_get_libctx(_in)
               else
               if @c_get_libctx <> @_OSSL_FUNC_core_get_libctx(_in) then
                  Exit(0);
            end;
            OSSL_FUNC_CORE_GETTABLE_PARAMS:
            begin
                if not Assigned(c_gettable_params) then
                   c_gettable_params := _OSSL_FUNC_core_gettable_params(_in)
                else
                if @c_gettable_params <> @_OSSL_FUNC_core_gettable_params(_in) then
                   Exit(0);
            end;
            OSSL_FUNC_CORE_GET_PARAMS:
            begin
                if not Assigned(c_get_params) then
                   c_get_params := _OSSL_FUNC_core_get_params(_in)
                else
                if @c_get_params <> @_OSSL_FUNC_core_get_params(_in) then
                   Exit(0)
            end;
            OSSL_FUNC_CORE_THREAD_START:
            begin
                if not Assigned(c_thread_start) then
                   c_thread_start := _OSSL_FUNC_core_thread_start(_in)
                else
                if @c_thread_start <> @_OSSL_FUNC_core_thread_start(_in) then
                   Exit(0);
            end;
            5://OSSL_FUNC_CORE_NEW_ERROR:
            begin
                if not Assigned(c_new_error) then
                   c_new_error := _OSSL_FUNC_core_new_error(_in)
                else
                if @c_new_error <> @_OSSL_FUNC_core_new_error(_in) then
                   Exit(0)
            end;
            6://OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            begin
                if not Assigned(c_set_error_debug) then
                   c_set_error_debug := _OSSL_FUNC_core_set_error_debug(_in)
                else
                if @c_set_error_debug <> @_OSSL_FUNC_core_set_error_debug(_in) then
                   Exit(0)
            end;
            7: //OSSL_FUNC_CORE_VSET_ERROR:
            begin
                if not Assigned(c_vset_error) then
                   c_vset_error := _OSSL_FUNC_core_vset_error(_in)
                else
                if @c_vset_error <> @_OSSL_FUNC_core_vset_error(_in) then
                   Exit(0)
            end;
            8: //OSSL_FUNC_CORE_SET_ERROR_MARK:
            begin
                if not Assigned(c_set_error_mark) then
                   c_set_error_mark := _OSSL_FUNC_core_set_error_mark(_in)
                else
                if @c_set_error_mark <> @_OSSL_FUNC_core_set_error_mark(_in) then
                   Exit(0)
            end;
            OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            begin
                if not Assigned(c_clear_last_error_mark) then
                   c_clear_last_error_mark := _OSSL_FUNC_core_clear_last_error_mark(_in)
                else
                if @c_clear_last_error_mark <> @_OSSL_FUNC_core_clear_last_error_mark(_in) then
                   Exit(0)


            end;
            OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            begin
                if not Assigned(c_pop_error_to_mark) then
                   c_pop_error_to_mark := _OSSL_FUNC_core_pop_error_to_mark(_in)
                else
                if @c_pop_error_to_mark <> @_OSSL_FUNC_core_pop_error_to_mark(_in) then
                   Exit(0)


            end;
            OSSL_FUNC_CRYPTO_MALLOC:
            begin
                if not Assigned(c_CRYPTO_malloc) then
                   c_CRYPTO_malloc := _OSSL_FUNC_CRYPTO_malloc(_in)
                else
                if @c_CRYPTO_malloc <> @_OSSL_FUNC_CRYPTO_malloc(_in) then
                   Exit(0)
            end;
            OSSL_FUNC_CRYPTO_ZALLOC:
            begin
                if not Assigned(c_CRYPTO_zalloc ) then
                   c_CRYPTO_zalloc := _OSSL_FUNC_CRYPTO_zalloc(_in)
                else
                if @c_CRYPTO_zalloc <> @_OSSL_FUNC_CRYPTO_zalloc(_in) then Exit(0)
            end;
            OSSL_FUNC_CRYPTO_FREE:
            begin
                if not Assigned(c_CRYPTO_free) then
                   c_CRYPTO_free := _OSSL_FUNC_CRYPTO_free(_in)
                else
                if @c_CRYPTO_free <> @_OSSL_FUNC_CRYPTO_free(_in) then Exit(0)
            end;

            OSSL_FUNC_CRYPTO_CLEAR_FREE:
            begin
                if not Assigned(c_CRYPTO_clear_free) then
                   c_CRYPTO_clear_free := _OSSL_FUNC_CRYPTO_clear_free(_in)
                else
                if @c_CRYPTO_clear_free <> @_OSSL_FUNC_CRYPTO_clear_free(_in) then Exit(0)


            end;
            OSSL_FUNC_CRYPTO_REALLOC:
            begin
                if not Assigned(c_CRYPTO_realloc ) then
                   c_CRYPTO_realloc := _OSSL_FUNC_CRYPTO_realloc(_in)
                else
                if @c_CRYPTO_realloc <> @_OSSL_FUNC_CRYPTO_realloc(_in) then
                   Exit(0)
            end;
            OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            begin
                if not Assigned(c_CRYPTO_clear_realloc ) then
                   c_CRYPTO_clear_realloc := _OSSL_FUNC_CRYPTO_clear_realloc(_in)
                else
                if @c_CRYPTO_clear_realloc <> @_OSSL_FUNC_CRYPTO_clear_realloc(_in) then Exit(0)


            end;
            OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            begin
                if not Assigned(c_CRYPTO_secure_malloc ) then
                   c_CRYPTO_secure_malloc := _OSSL_FUNC_CRYPTO_secure_malloc(_in)
                else
                if @c_CRYPTO_secure_malloc <> @_OSSL_FUNC_CRYPTO_secure_malloc(_in) then Exit(0)
            end;
            OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            begin
                if not Assigned(c_CRYPTO_secure_zalloc ) then
                   c_CRYPTO_secure_zalloc := _OSSL_FUNC_CRYPTO_secure_zalloc(_in)
                else
                if @c_CRYPTO_secure_zalloc <> @_OSSL_FUNC_CRYPTO_secure_zalloc(_in) then Exit(0)


            end;
            OSSL_FUNC_CRYPTO_SECURE_FREE:
           begin
                if not Assigned(c_CRYPTO_secure_free ) then
                   c_CRYPTO_secure_free := _OSSL_FUNC_CRYPTO_secure_free(_in)
                else
                if @c_CRYPTO_secure_free <> @_OSSL_FUNC_CRYPTO_secure_free(_in) then Exit(0)
           end;
            OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            begin
                if not Assigned(c_CRYPTO_secure_clear_free ) then
                   c_CRYPTO_secure_clear_free := _OSSL_FUNC_CRYPTO_secure_clear_free(_in)
                else
                if @c_CRYPTO_secure_clear_free <> @_OSSL_FUNC_CRYPTO_secure_clear_free(_in) then Exit(0)


            end;
            OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            begin
                if not Assigned(c_CRYPTO_secure_allocated ) then
                   c_CRYPTO_secure_allocated := _OSSL_FUNC_CRYPTO_secure_allocated(_in)
                else
                if @c_CRYPTO_secure_allocated <> @_OSSL_FUNC_CRYPTO_secure_allocated(_in) then Exit(0)
            end;
            OSSL_FUNC_BIO_NEW_FILE:
            begin
                if not Assigned(selftest_params.bio_new_file_cb ) then
                   selftest_params.bio_new_file_cb := _OSSL_FUNC_BIO_new_file(_in)
                else
                if @selftest_params.bio_new_file_cb <> @_OSSL_FUNC_BIO_new_file(_in) then Exit(0)


            end;
            OSSL_FUNC_BIO_NEW_MEMBUF:
            begin
                if not Assigned(selftest_params.bio_new_buffer_cb ) then
                   selftest_params.bio_new_buffer_cb := _OSSL_FUNC_BIO_new_membuf(_in)
                else
                if @selftest_params.bio_new_buffer_cb <> @_OSSL_FUNC_BIO_new_membuf(_in) then Exit(0)


            end;
            OSSL_FUNC_BIO_READ_EX:
            begin
                if not Assigned(selftest_params.bio_read_ex_cb ) then
                   selftest_params.bio_read_ex_cb := _OSSL_FUNC_BIO_read_ex(_in)
                else
                if @selftest_params.bio_read_ex_cb <> @_OSSL_FUNC_BIO_read_ex(_in) then Exit(0)


            end;
            OSSL_FUNC_BIO_FREE:
            begin
                if not Assigned(selftest_params.bio_free_cb ) then
                   selftest_params.bio_free_cb := _OSSL_FUNC_BIO_free(_in)
                else
                if @selftest_params.bio_free_cb <> @_OSSL_FUNC_BIO_free(_in) then Exit(0)


            end;
            OSSL_FUNC_BIO_VSNPRINTF:
            begin
                if not Assigned(c_BIO_vsnprintf ) then
                   c_BIO_vsnprintf := _OSSL_FUNC_BIO_vsnprintf(_in)
                else
                if @c_BIO_vsnprintf <> @_OSSL_FUNC_BIO_vsnprintf(_in) then Exit(0)


            end;
            OSSL_FUNC_SELF_TEST_CB:
            begin
                if not Assigned(c_stcbfn ) then
                   c_stcbfn := _OSSL_FUNC_self_test_cb(_in)
                else
                if @c_stcbfn <> @_OSSL_FUNC_self_test_cb(_in) then Exit(0)


            end;
            else
                { Just ignore anything we don't understand }
                break;
        end;
        Inc(_in);
    end;
    {  Create a context. }

    provctx := ossl_prov_ctx_new();
    libctx := OSSL_LIB_CTX_new();
    if ( provctx = nil) or  (libctx = nil) then
    begin
        {
         * We free libctx separately here and only here because it hasn't
         * been attached to *provctx.  All other error paths below rely
         * solely on fips_teardown.
         }
        OSSL_LIB_CTX_free(libctx);
        goto _err;
    end;
    fgbl := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_FIPS_PROV_INDEX,
                                      @fips_prov_ossl_ctx_method );
    if (fgbl = nil) then
        goto _err;
    fgbl.handle := handle;
    {
     * We did initial set up of selftest_params in a local copy, because we
     * could not create fgbl until c_CRYPTO_zalloc was defined in the loop
     * above.
     }
    fgbl.selftest_params := selftest_params;
    fgbl.selftest_params.libctx := libctx;
    set_self_test_cb(fgbl);
    if 0>=fips_get_params_from_core(fgbl) then
    begin
        { Error already raised }
        goto _err;
    end;
    {
     * Disable the conditional error check if it's disabled in the fips config
     * file.
     }
    if (fgbl.selftest_params.conditional_error_check <> nil)
         and  (strcmp(fgbl.selftest_params.conditional_error_check, '0') = 0) then
        SELF_TEST_disable_conditional_error_state;
    { Disable the security check if it's disabled in the fips config file. }
    if (fgbl.fips_security_check_option <> nil )
         and  (strcmp(fgbl.fips_security_check_option, '0') = 0) then
        fgbl.fips_security_checks := 0;
    ossl_prov_cache_exported_algorithms(@fips_ciphers[0], @exported_fips_ciphers);
    if 0>=SELF_TEST_post(@fgbl.selftest_params, 0 ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
        goto _err;
    end;
    ossl_prov_ctx_set0_libctx( provctx, libctx);
    ossl_prov_ctx_set0_handle( provctx, handle);
    _out^ := @fips_dispatch_table;
    Exit(1);
 _err:
    fips_teardown( provctx);
    OSSL_LIB_CTX_free(libctx);
    provctx := nil;
    Result := 0;
end;


procedure ERR_vset_error(lib, reason : integer;const fmt : string);
begin
    c_vset_error(nil, ERR_PACK(lib, 0, reason), fmt);
end;



function ERR_clear_last_mark:integer;
begin
    if Assigned(c_clear_last_error_mark) then
       Result := c_clear_last_error_mark(nil);
end;



function ERR_pop_to_mark:integer;
begin
    if Assigned(c_pop_error_to_mark) then
       Result := c_pop_error_to_mark(nil);
end;

function ERR_set_mark:integer;
begin
   if Assigned(c_set_error_mark) then
      Result := c_set_error_mark(nil);
end;



function ERR_PACK( lib : integer; func : PUTF8Char; reason : integer):uint32;
begin
   result :=  ((uint32(lib)    and ERR_LIB_MASK   )  shl  ERR_LIB_OFFSET) or ((uint32(reason) and ERR_REASON_MASK))
end;



procedure ERR_set_error(lib, reason : integer;const fmt : string);
begin
    if Assigned(c_vset_error) then
       c_vset_error(nil, ERR_PACK(lib, 0, reason), fmt);
end;

procedure ERR_set_debug(const func : PUTF8Char);
begin
    if Assigned(c_set_error_debug) then
       c_set_error_debug(nil, func);
end;

procedure ERR_new();
begin
   if Assigned(c_new_error) then
      c_new_error(nil);
end;

function ALGC(NAMES: PUTF8Char; FUNC: POSSL_DISPATCH; CHECK: Tcapable_func):TOSSL_ALGORITHM_CAPABLE;
begin
  Result.alg.algorithm_names := NAMES;
  Result.alg.property_definition := FIPS_DEFAULT_PROPERTIES;
  Result.alg._implementation := FUNC ;
  Result.capable := CHECK ;
end;

function ALG(NAMES: PUTF8Char; FUNC: POSSL_DISPATCH): TOSSL_ALGORITHM_CAPABLE;
begin
  Result := ALGC(NAMES, FUNC, nil)
end;

function ALG2(NAMES, DEFINE: PUTF8Char; FUNC: POSSL_DISPATCH; CHECK: Tcapable_func):TOSSL_ALGORITHM_CAPABLE;
begin
  Result.alg.algorithm_names := NAMES;
  Result.alg.property_definition := DEFINE;
  Result.alg._implementation := FUNC ;
  Result.capable := CHECK ;
end;

initialization
  fips_ciphers := [
    (* Our primary name[:ASN.1 OID name][:our older names] *)
    ALG(PROV_NAMES_AES_256_ECB, @ossl_aes256ecb_functions),
    ALG(PROV_NAMES_AES_192_ECB, @ossl_aes192ecb_functions),
    ALG(PROV_NAMES_AES_128_ECB, @ossl_aes128ecb_functions),
    ALG(PROV_NAMES_AES_256_CBC, @ossl_aes256cbc_functions),
    ALG(PROV_NAMES_AES_192_CBC, @ossl_aes192cbc_functions),
    ALG(PROV_NAMES_AES_128_CBC, @ossl_aes128cbc_functions),
    ALG(PROV_NAMES_AES_256_CBC_CTS, @ossl_aes256cbc_cts_functions),
    ALG(PROV_NAMES_AES_192_CBC_CTS, @ossl_aes192cbc_cts_functions),
    ALG(PROV_NAMES_AES_128_CBC_CTS, @ossl_aes128cbc_cts_functions),
    ALG(PROV_NAMES_AES_256_OFB, @ossl_aes256ofb_functions),
    ALG(PROV_NAMES_AES_192_OFB, @ossl_aes192ofb_functions),
    ALG(PROV_NAMES_AES_128_OFB, @ossl_aes128ofb_functions),
    ALG(PROV_NAMES_AES_256_CFB, @ossl_aes256cfb_functions),
    ALG(PROV_NAMES_AES_192_CFB, @ossl_aes192cfb_functions),
    ALG(PROV_NAMES_AES_128_CFB, @ossl_aes128cfb_functions),
    ALG(PROV_NAMES_AES_256_CFB1, @ossl_aes256cfb1_functions),
    ALG(PROV_NAMES_AES_192_CFB1, @ossl_aes192cfb1_functions),
    ALG(PROV_NAMES_AES_128_CFB1, @ossl_aes128cfb1_functions),
    ALG(PROV_NAMES_AES_256_CFB8, @ossl_aes256cfb8_functions),
    ALG(PROV_NAMES_AES_192_CFB8, @ossl_aes192cfb8_functions),
    ALG(PROV_NAMES_AES_128_CFB8, @ossl_aes128cfb8_functions),
    ALG(PROV_NAMES_AES_256_CTR, @ossl_aes256ctr_functions),
    ALG(PROV_NAMES_AES_192_CTR, @ossl_aes192ctr_functions),
    ALG(PROV_NAMES_AES_128_CTR, @ossl_aes128ctr_functions),
    ALG(PROV_NAMES_AES_256_XTS, @ossl_aes256xts_functions),
    ALG(PROV_NAMES_AES_128_XTS, @ossl_aes128xts_functions),
    ALG(PROV_NAMES_AES_256_GCM, @ossl_aes256gcm_functions),
    ALG(PROV_NAMES_AES_192_GCM, @ossl_aes192gcm_functions),
    ALG(PROV_NAMES_AES_128_GCM, @ossl_aes128gcm_functions),
    ALG(PROV_NAMES_AES_256_CCM, @ossl_aes256ccm_functions),
    ALG(PROV_NAMES_AES_192_CCM, @ossl_aes192ccm_functions),
    ALG(PROV_NAMES_AES_128_CCM, @ossl_aes128ccm_functions),
    ALG(PROV_NAMES_AES_256_WRAP, @ossl_aes256wrap_functions),
    ALG(PROV_NAMES_AES_192_WRAP, @ossl_aes192wrap_functions),
    ALG(PROV_NAMES_AES_128_WRAP, @ossl_aes128wrap_functions),
    ALG(PROV_NAMES_AES_256_WRAP_PAD, @ossl_aes256wrappad_functions),
    ALG(PROV_NAMES_AES_192_WRAP_PAD, @ossl_aes192wrappad_functions),
    ALG(PROV_NAMES_AES_128_WRAP_PAD, @ossl_aes128wrappad_functions),
    ALG(PROV_NAMES_AES_256_WRAP_INV, @ossl_aes256wrapinv_functions),
    ALG(PROV_NAMES_AES_192_WRAP_INV, @ossl_aes192wrapinv_functions),
    ALG(PROV_NAMES_AES_128_WRAP_INV, @ossl_aes128wrapinv_functions),
    ALG(PROV_NAMES_AES_256_WRAP_PAD_INV, @ossl_aes256wrappadinv_functions),
    ALG(PROV_NAMES_AES_192_WRAP_PAD_INV, @ossl_aes192wrappadinv_functions),
    ALG(PROV_NAMES_AES_128_WRAP_PAD_INV, @ossl_aes128wrappadinv_functions),
    ALGC(PROV_NAMES_AES_128_CBC_HMAC_SHA1, @ossl_aes128cbc_hmac_sha1_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha1),
    ALGC(PROV_NAMES_AES_256_CBC_HMAC_SHA1, @ossl_aes256cbc_hmac_sha1_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha1),
    ALGC(PROV_NAMES_AES_128_CBC_HMAC_SHA256, @ossl_aes128cbc_hmac_sha256_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha256),
    ALGC(PROV_NAMES_AES_256_CBC_HMAC_SHA256, @ossl_aes256cbc_hmac_sha256_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha256),
{$ifndef OPENSSL_NO_DES}
    ALG(PROV_NAMES_DES_EDE3_ECB, @ossl_tdes_ede3_ecb_functions),
    ALG(PROV_NAMES_DES_EDE3_CBC, @ossl_tdes_ede3_cbc_functions),
{$endif}  (* OPENSSL_NO_DES *)
    ALG2(nil, nil, nil, nil)
];
    fips_digests := [
    (* Our primary name:NiST name[:our older names] *)
    get_ALGORITHM( PROV_NAMES_SHA1, @FIPS_DEFAULT_PROPERTIES, @ossl_sha1_functions ),
    get_ALGORITHM( PROV_NAMES_SHA2_224, @FIPS_DEFAULT_PROPERTIES, @ossl_sha224_functions ),
    get_ALGORITHM( PROV_NAMES_SHA2_256, @FIPS_DEFAULT_PROPERTIES, @ossl_sha256_functions ),
    get_ALGORITHM( PROV_NAMES_SHA2_384, @FIPS_DEFAULT_PROPERTIES, @ossl_sha384_functions ),
    get_ALGORITHM( PROV_NAMES_SHA2_512, @FIPS_DEFAULT_PROPERTIES, @ossl_sha512_functions ),
    get_ALGORITHM( PROV_NAMES_SHA2_512_224, @FIPS_DEFAULT_PROPERTIES, @ossl_sha512_224_functions ),
    get_ALGORITHM( PROV_NAMES_SHA2_512_256, @FIPS_DEFAULT_PROPERTIES, @ossl_sha512_256_functions ),

    (* We agree with NIST here, @so one name only *)
    get_ALGORITHM( PROV_NAMES_SHA3_224, @FIPS_DEFAULT_PROPERTIES, @ossl_sha3_224_functions ),
    get_ALGORITHM( PROV_NAMES_SHA3_256, @FIPS_DEFAULT_PROPERTIES, @ossl_sha3_256_functions ),
    get_ALGORITHM( PROV_NAMES_SHA3_384, @FIPS_DEFAULT_PROPERTIES, @ossl_sha3_384_functions ),
    get_ALGORITHM( PROV_NAMES_SHA3_512, @FIPS_DEFAULT_PROPERTIES, @ossl_sha3_512_functions ),

    get_ALGORITHM( PROV_NAMES_SHAKE_128, @FIPS_DEFAULT_PROPERTIES, @ossl_shake_128_functions ),
    get_ALGORITHM( PROV_NAMES_SHAKE_256, @FIPS_DEFAULT_PROPERTIES, @ossl_shake_256_functions ),

    (*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     *)
    get_ALGORITHM( PROV_NAMES_KECCAK_KMAC_128, @FIPS_DEFAULT_PROPERTIES, @ossl_keccak_kmac_128_functions ),
    get_ALGORITHM( PROV_NAMES_KECCAK_KMAC_256, @FIPS_DEFAULT_PROPERTIES, @ossl_keccak_kmac_256_functions ),
    get_ALGORITHM( nil, nil, nil )
  ];

  fips_macs := [
{$ifndef OPENSSL_NO_CMAC}
    get_ALGORITHM( PROV_NAMES_CMAC, @FIPS_DEFAULT_PROPERTIES, @ossl_cmac_functions ),
{$endif}
    get_ALGORITHM( PROV_NAMES_GMAC, @FIPS_DEFAULT_PROPERTIES, @ossl_gmac_functions ),
    get_ALGORITHM( PROV_NAMES_HMAC, @FIPS_DEFAULT_PROPERTIES, @ossl_hmac_functions ),
    get_ALGORITHM( PROV_NAMES_KMAC_128, @FIPS_DEFAULT_PROPERTIES, @ossl_kmac128_functions ),
    get_ALGORITHM( PROV_NAMES_KMAC_256, @FIPS_DEFAULT_PROPERTIES, @ossl_kmac256_functions ),
    get_ALGORITHM( nil, nil, nil )
];

fips_kdfs := [
    get_ALGORITHM( PROV_NAMES_HKDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_hkdf_functions ),
    get_ALGORITHM( PROV_NAMES_TLS1_3_KDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_tls1_3_kdf_functions ),
    get_ALGORITHM( PROV_NAMES_SSKDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_sskdf_functions ),
    get_ALGORITHM( PROV_NAMES_PBKDF2, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_pbkdf2_functions ),
    get_ALGORITHM( PROV_NAMES_SSHKDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_sshkdf_functions ),
    get_ALGORITHM( PROV_NAMES_X963KDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_x963_kdf_functions ),
    get_ALGORITHM( PROV_NAMES_X942KDF_ASN1, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_x942_kdf_functions ),
    get_ALGORITHM( PROV_NAMES_TLS1_PRF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_tls1_prf_functions ),
    get_ALGORITHM( PROV_NAMES_KBKDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_kbkdf_functions ),
    get_ALGORITHM( nil,nil,nil )
];

fips_rands := [
    get_ALGORITHM( PROV_NAMES_CTR_DRBG, @FIPS_DEFAULT_PROPERTIES, @ossl_drbg_ctr_functions ),
    get_ALGORITHM( PROV_NAMES_HASH_DRBG, @FIPS_DEFAULT_PROPERTIES, @ossl_drbg_hash_functions ),
    get_ALGORITHM( PROV_NAMES_HMAC_DRBG, @FIPS_DEFAULT_PROPERTIES, @ossl_drbg_ossl_hmac_functions ),
    get_ALGORITHM( PROV_NAMES_TEST_RAND, @FIPS_UNAPPROVED_PROPERTIES, @ossl_test_rng_functions ),
    get_ALGORITHM( nil,nil,nil  )
];

fips_keymgmt := [
{$ifndef OPENSSL_NO_DH}
    get_ALGORITHM( PROV_NAMES_DH, @FIPS_DEFAULT_PROPERTIES, @ossl_dh_keymgmt_functions,
      PROV_DESCS_DH ),
    get_ALGORITHM( PROV_NAMES_DHX, @FIPS_DEFAULT_PROPERTIES, @ossl_dhx_keymgmt_functions,
      PROV_DESCS_DHX ),
{$endif}
{$ifndef OPENSSL_NO_DSA}
    get_ALGORITHM( PROV_NAMES_DSA, @FIPS_DEFAULT_PROPERTIES, @ossl_dsa_keymgmt_functions,
      PROV_DESCS_DSA ),
{$endif}
    get_ALGORITHM( PROV_NAMES_RSA, @FIPS_DEFAULT_PROPERTIES, @ossl_rsa_keymgmt_functions,
      PROV_DESCS_RSA ),
    get_ALGORITHM( PROV_NAMES_RSA_PSS, @FIPS_DEFAULT_PROPERTIES,
      @ossl_rsapss_keymgmt_functions, PROV_DESCS_RSA_PSS ),
{$ifndef OPENSSL_NO_EC}
    get_ALGORITHM( PROV_NAMES_EC, @FIPS_DEFAULT_PROPERTIES, @ossl_ec_keymgmt_functions,
      PROV_DESCS_EC ),
    get_ALGORITHM( PROV_NAMES_X25519, @FIPS_DEFAULT_PROPERTIES, @ossl_x25519_keymgmt_functions,
      PROV_DESCS_X25519 ),
    get_ALGORITHM( PROV_NAMES_X448, @FIPS_DEFAULT_PROPERTIES, @ossl_x448_keymgmt_functions,
      PROV_DESCS_X448 ),
    get_ALGORITHM( PROV_NAMES_ED25519, @FIPS_DEFAULT_PROPERTIES, @ossl_ed25519_keymgmt_functions,
      PROV_DESCS_ED25519 ),
    get_ALGORITHM( PROV_NAMES_ED448, @FIPS_DEFAULT_PROPERTIES, @ossl_ed448_keymgmt_functions,
      PROV_DESCS_ED448 ),
{$endif}
    get_ALGORITHM( PROV_NAMES_TLS1_PRF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_keymgmt_functions,
      PROV_DESCS_TLS1_PRF_SIGN ),
    get_ALGORITHM( PROV_NAMES_HKDF, @FIPS_DEFAULT_PROPERTIES, @ossl_kdf_keymgmt_functions,
      PROV_DESCS_HKDF_SIGN ),
    get_ALGORITHM( PROV_NAMES_HMAC, @FIPS_DEFAULT_PROPERTIES, @ossl_mac_legacy_keymgmt_functions,
      PROV_DESCS_HMAC_SIGN ),
{$ifndef OPENSSL_NO_CMAC}
    get_ALGORITHM( PROV_NAMES_CMAC, @FIPS_DEFAULT_PROPERTIES,
      @ossl_cmac_legacy_keymgmt_functions, PROV_DESCS_CMAC_SIGN ),
{$endif}
    get_ALGORITHM( nil,nil,nil  )
];

  fips_keyexch := [
{$ifndef OPENSSL_NO_DH}
    get_ALGORITHM( PROV_NAMES_DH, @FIPS_DEFAULT_PROPERTIES, @ossl_dh_keyexch_functions ),
{$endif}
{$ifndef OPENSSL_NO_EC}
    get_ALGORITHM( PROV_NAMES_ECDH, FIPS_DEFAULT_PROPERTIES, @ossl_ecdh_keyexch_functions ),
    get_ALGORITHM( PROV_NAMES_X25519, FIPS_DEFAULT_PROPERTIES, @ossl_x25519_keyexch_functions ),
    get_ALGORITHM( PROV_NAMES_X448, FIPS_DEFAULT_PROPERTIES, @ossl_x448_keyexch_functions ),
{$endif}
    get_ALGORITHM( PROV_NAMES_TLS1_PRF, FIPS_DEFAULT_PROPERTIES, @ossl_kdf_tls1_prf_keyexch_functions ),
    get_ALGORITHM( PROV_NAMES_HKDF, FIPS_DEFAULT_PROPERTIES, @ossl_kdf_hkdf_keyexch_functions ),
    get_ALGORITHM( nil,nil,nil  )
];

  fips_signature := [
{$ifndef OPENSSL_NO_DSA}
    get_ALGORITHM( PROV_NAMES_DSA, FIPS_DEFAULT_PROPERTIES, @ossl_dsa_signature_functions ),
{$endif}
    get_ALGORITHM( PROV_NAMES_RSA, FIPS_DEFAULT_PROPERTIES, @ossl_rsa_signature_functions ),
{$ifndef OPENSSL_NO_EC}
    get_ALGORITHM( PROV_NAMES_ED25519, FIPS_DEFAULT_PROPERTIES, @ossl_ed25519_signature_functions ),
    get_ALGORITHM( PROV_NAMES_ED448, FIPS_DEFAULT_PROPERTIES, @ossl_ed448_signature_functions ),
    get_ALGORITHM( PROV_NAMES_ECDSA, FIPS_DEFAULT_PROPERTIES, @ossl_ecdsa_signature_functions ),
{$endif}
    //get_ALGORITHM( PROV_NAMES_HMAC, FIPS_DEFAULT_PROPERTIES,  @ossl_mac_legacy_hmac_signature_functions ),
{$ifndef OPENSSL_NO_CMAC}
    //get_ALGORITHM( PROV_NAMES_CMAC, FIPS_DEFAULT_PROPERTIES,  @ossl_mac_legacy_cmac_signature_functions ),
{$endif}
    get_ALGORITHM( nil,nil,nil  )
];

  fips_asym_cipher := [
    get_ALGORITHM( PROV_NAMES_RSA, FIPS_DEFAULT_PROPERTIES, @ossl_rsa_asym_cipher_functions ),
    get_ALGORITHM( nil,nil,nil  )
];

fips_asym_kem := [
    get_ALGORITHM( PROV_NAMES_RSA, FIPS_DEFAULT_PROPERTIES, @ossl_rsa_asym_kem_functions ),
    get_ALGORITHM( nil,nil,nil  )
];

fips_param_types := [
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_SECURITY_CHECKS, OSSL_PARAM_INTEGER, nil, 0),
    OSSL_PARAM_END
];
end.
