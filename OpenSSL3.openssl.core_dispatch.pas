unit OpenSSL3.openssl.core_dispatch;

interface
uses  OpenSSL.Api;

function _OSSL_FUNC_BIO_new_file(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_file_fn;

function _OSSL_FUNC_BIO_new_membuf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_membuf_fn;

function _OSSL_FUNC_BIO_read_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_read_ex_fn;

function _OSSL_FUNC_BIO_write_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_write_ex_fn;

function _OSSL_FUNC_BIO_gets(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_gets_fn;

function _OSSL_FUNC_BIO_puts(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_puts_fn;

function _OSSL_FUNC_BIO_ctrl(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_ctrl_fn;

function _OSSL_FUNC_BIO_up_ref(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_up_ref_fn;

function _OSSL_FUNC_BIO_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_free_fn;

function _OSSL_FUNC_BIO_vprintf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_vprintf_fn;

function _OSSL_FUNC_get_entropy(const opf : POSSL_DISPATCH):TOSSL_FUNC_get_entropy_fn;

function _OSSL_FUNC_cleanup_entropy(const opf : POSSL_DISPATCH):TOSSL_FUNC_cleanup_entropy_fn;

function _OSSL_FUNC_get_nonce(const opf : POSSL_DISPATCH):TOSSL_FUNC_get_nonce_fn;

function _OSSL_FUNC_cleanup_nonce(const opf : POSSL_DISPATCH):TOSSL_FUNC_cleanup_nonce_fn;

function _OSSL_FUNC_core_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_gettable_params_fn;

function _OSSL_FUNC_core_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_params_fn;

function _OSSL_FUNC_core_get_libctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_libctx_fn;

function _OSSL_FUNC_digest_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_newctx_fn;

 function _OSSL_FUNC_digest_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_init_fn;

 function _OSSL_FUNC_digest_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_update_fn;

 function _OSSL_FUNC_digest_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_final_fn;

 function _OSSL_FUNC_digest_digest(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_digest_fn;

 function _OSSL_FUNC_digest_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_freectx_fn;

 function _OSSL_FUNC_digest_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_dupctx_fn;

 function _OSSL_FUNC_digest_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_get_params_fn;

 function _OSSL_FUNC_digest_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_set_ctx_params_fn;

 function _OSSL_FUNC_digest_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_get_ctx_params_fn;

 function _OSSL_FUNC_digest_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_gettable_params_fn;

 function _OSSL_FUNC_digest_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_settable_ctx_params_fn;

 function _OSSL_FUNC_digest_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_gettable_ctx_params_fn;

 function _OSSL_FUNC_mac_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_newctx_fn;

 function _OSSL_FUNC_mac_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_dupctx_fn;

 function _OSSL_FUNC_mac_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_freectx_fn;

 function _OSSL_FUNC_mac_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_init_fn;

 function _OSSL_FUNC_mac_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_update_fn;

 function _OSSL_FUNC_mac_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_final_fn;

 function _OSSL_FUNC_mac_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_gettable_params_fn;

 function _OSSL_FUNC_mac_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_gettable_ctx_params_fn;

 function _OSSL_FUNC_mac_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_settable_ctx_params_fn;

 function _OSSL_FUNC_mac_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_get_params_fn;

 function _OSSL_FUNC_mac_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_get_ctx_params_fn;

 function _OSSL_FUNC_mac_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_set_ctx_params_fn;

function _OSSL_FUNC_cipher_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_newctx_fn;

function _OSSL_FUNC_cipher_encrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_encrypt_init_fn;

function _OSSL_FUNC_cipher_decrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_decrypt_init_fn;

function _OSSL_FUNC_cipher_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_update_fn;

function _OSSL_FUNC_cipher_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_final_fn;

function _OSSL_FUNC_cipher_cipher(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_cipher_fn;

function _OSSL_FUNC_cipher_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_freectx_fn;

function _OSSL_FUNC_cipher_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_dupctx_fn;

function _OSSL_FUNC_cipher_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_get_params_fn;

function _OSSL_FUNC_cipher_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_get_ctx_params_fn;

function _OSSL_FUNC_cipher_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_set_ctx_params_fn;

function _OSSL_FUNC_cipher_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_gettable_params_fn;

function _OSSL_FUNC_cipher_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_gettable_ctx_params_fn;

function _OSSL_FUNC_cipher_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_settable_ctx_params_fn;

 function _OSSL_FUNC_kdf_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_newctx_fn;

 function _OSSL_FUNC_kdf_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_dupctx_fn;

 function _OSSL_FUNC_kdf_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_freectx_fn;

 function _OSSL_FUNC_kdf_reset(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_reset_fn;

 function _OSSL_FUNC_kdf_derive(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_derive_fn;

 function _OSSL_FUNC_kdf_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_gettable_params_fn;

 function _OSSL_FUNC_kdf_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_gettable_ctx_params_fn;

 function _OSSL_FUNC_kdf_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_settable_ctx_params_fn;

 function _OSSL_FUNC_kdf_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_get_params_fn;

 function _OSSL_FUNC_kdf_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_get_ctx_params_fn;

 function _OSSL_FUNC_kdf_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_set_ctx_params_fn;

function _OSSL_FUNC_rand_enable_locking(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_enable_locking_fn;

function _OSSL_FUNC_rand_lock(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_lock_fn;

function _OSSL_FUNC_rand_unlock(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_unlock_fn;

function _OSSL_FUNC_rand_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_get_ctx_params_fn;

function _OSSL_FUNC_rand_nonce(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_nonce_fn;

function _OSSL_FUNC_rand_get_seed(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_get_seed_fn;

function _OSSL_FUNC_rand_clear_seed(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_clear_seed_fn;

 function _OSSL_FUNC_signature_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_newctx_fn;
  function _OSSL_FUNC_signature_sign_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_sign_init_fn;
  function _OSSL_FUNC_signature_sign(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_sign_fn;
  function _OSSL_FUNC_signature_verify_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_init_fn;
  function _OSSL_FUNC_signature_verify(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_fn;
  function _OSSL_FUNC_signature_verify_recover_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_recover_init_fn;
  function _OSSL_FUNC_signature_verify_recover(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_recover_fn;
  function _OSSL_FUNC_signature_digest_sign_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_init_fn;
  function _OSSL_FUNC_signature_digest_sign_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_update_fn;
  function _OSSL_FUNC_signature_digest_sign_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_final_fn;
  function _OSSL_FUNC_signature_digest_sign(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_fn;
  function _OSSL_FUNC_signature_digest_verify_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_init_fn;
  function _OSSL_FUNC_signature_digest_verify_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_update_fn;
  function _OSSL_FUNC_signature_digest_verify_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_final_fn;
  function _OSSL_FUNC_signature_digest_verify(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_fn;
  function _OSSL_FUNC_signature_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_freectx_fn;
  function _OSSL_FUNC_signature_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_dupctx_fn;
  function _OSSL_FUNC_signature_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_get_ctx_params_fn;
  function _OSSL_FUNC_signature_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_gettable_ctx_params_fn;
  function _OSSL_FUNC_signature_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_set_ctx_params_fn;
  function _OSSL_FUNC_signature_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_settable_ctx_params_fn;
  function _OSSL_FUNC_signature_get_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_get_ctx_md_params_fn;
  function _OSSL_FUNC_signature_gettable_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_gettable_ctx_md_params_fn;
  function _OSSL_FUNC_signature_set_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_set_ctx_md_params_fn;
  function _OSSL_FUNC_signature_settable_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_settable_ctx_md_params_fn;

  function _OSSL_FUNC_rand_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_newctx_fn;
function _OSSL_FUNC_rand_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_freectx_fn;
function _OSSL_FUNC_rand_instantiate(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_instantiate_fn;
function _OSSL_FUNC_rand_uninstantiate(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_uninstantiate_fn;
function _OSSL_FUNC_rand_generate(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_generate_fn;
function _OSSL_FUNC_rand_reseed(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_reseed_fn;

function _OSSL_FUNC_rand_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_gettable_params_fn;
function _OSSL_FUNC_rand_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_gettable_ctx_params_fn;
function _OSSL_FUNC_rand_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_settable_ctx_params_fn;
function _OSSL_FUNC_rand_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_get_params_fn;
function _OSSL_FUNC_rand_verify_zeroization(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_verify_zeroization_fn;
function _OSSL_FUNC_rand_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_set_ctx_params_fn;

 function _OSSL_FUNC_provider_teardown(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_teardown_fn;

 function _OSSL_FUNC_provider_gettable_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_provider_gettable_params_fn;

 function _OSSL_FUNC_provider_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_get_params_fn;

function _OSSL_FUNC_provider_self_test(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_self_test_fn;

function _OSSL_FUNC_provider_get_capabilities(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_get_capabilities_fn;

function _OSSL_FUNC_provider_query_operation(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_query_operation_fn;

function _OSSL_FUNC_provider_unquery_operation(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_unquery_operation_fn;

function _OSSL_FUNC_provider_get_reason_strings(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_get_reason_strings_fn;
function _OSSL_FUNC_keymgmt_export(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;

implementation

function _OSSL_FUNC_keymgmt_export(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_keymgmt_export_fn *)opf.function;
end;

function _OSSL_FUNC_provider_get_reason_strings(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_get_reason_strings_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_provider_get_reason_strings_fn(opf._function);
end;



function _OSSL_FUNC_provider_unquery_operation(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_unquery_operation_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_provider_unquery_operation_fn(opf._function);
end;


function _OSSL_FUNC_provider_query_operation(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_query_operation_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_provider_query_operation_fn(opf._function);
end;



function _OSSL_FUNC_provider_get_capabilities(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_get_capabilities_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_provider_get_capabilities_fn(opf._function);
end;



function _OSSL_FUNC_provider_self_test(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_self_test_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_provider_self_test_fn (opf._function);
end;



function _OSSL_FUNC_provider_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_provider_get_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_provider_get_params_fn(opf._function);
end;



function _OSSL_FUNC_provider_gettable_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_provider_gettable_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_provider_gettable_params_fn(opf._function);
end;



function _OSSL_FUNC_provider_teardown(const opf : POSSL_DISPATCH): TOSSL_FUNC_provider_teardown_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_provider_teardown_fn (opf._function);
end;


function _OSSL_FUNC_rand_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_set_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_set_ctx_params_fn (opf._function);
end;



function _OSSL_FUNC_rand_verify_zeroization(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_verify_zeroization_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_verify_zeroization_fn (opf._function);
end;



function _OSSL_FUNC_rand_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_get_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_get_params_fn (opf._function);
end;


function _OSSL_FUNC_rand_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_settable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_settable_ctx_params_fn (opf._function);
end;

function _OSSL_FUNC_rand_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_gettable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_gettable_ctx_params_fn (opf._function);
end;

function _OSSL_FUNC_rand_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_gettable_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_gettable_params_fn (opf._function);
end;


function _OSSL_FUNC_rand_reseed(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_reseed_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_reseed_fn (opf._function);
end;



function _OSSL_FUNC_rand_generate(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_generate_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_generate_fn (opf._function);
end;



function _OSSL_FUNC_rand_uninstantiate(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_uninstantiate_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_uninstantiate_fn (opf._function);
end;



function _OSSL_FUNC_rand_instantiate(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_instantiate_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_instantiate_fn (opf._function);
end;



function _OSSL_FUNC_rand_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_freectx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_freectx_fn (opf._function);
end;



function _OSSL_FUNC_rand_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_newctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_newctx_fn (opf._function);
end;

function _OSSL_FUNC_signature_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_newctx_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_newctx_fn (opf._function);
end;


function _OSSL_FUNC_signature_sign_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_sign_init_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_sign_init_fn (opf._function);
end;


function _OSSL_FUNC_signature_sign(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_sign_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_sign_fn (opf._function);
end;


function _OSSL_FUNC_signature_verify_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_init_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_verify_init_fn (opf._function);
end;


function _OSSL_FUNC_signature_verify(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_verify_fn (opf._function);
end;


function _OSSL_FUNC_signature_verify_recover_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_recover_init_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_verify_recover_init_fn (opf._function);
end;


function _OSSL_FUNC_signature_verify_recover(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_verify_recover_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_verify_recover_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_sign_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_init_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_sign_init_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_sign_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_update_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_sign_update_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_sign_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_final_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_sign_final_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_sign(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_sign_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_sign_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_verify_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_init_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_verify_init_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_verify_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_update_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_verify_update_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_verify_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_final_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_verify_final_fn (opf._function);
end;


function _OSSL_FUNC_signature_digest_verify(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_digest_verify_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_digest_verify_fn (opf._function);
end;


function _OSSL_FUNC_signature_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_freectx_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_freectx_fn (opf._function);
end;


function _OSSL_FUNC_signature_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_dupctx_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_dupctx_fn (opf._function);
end;


function _OSSL_FUNC_signature_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_get_ctx_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_get_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_gettable_ctx_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_gettable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_set_ctx_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_set_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_settable_ctx_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_settable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_get_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_get_ctx_md_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_get_ctx_md_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_gettable_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_gettable_ctx_md_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_gettable_ctx_md_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_set_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_set_ctx_md_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_set_ctx_md_params_fn (opf._function);
end;


function _OSSL_FUNC_signature_settable_ctx_md_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_signature_settable_ctx_md_params_fn;
begin
 Result := opf.method.Code; //TOSSL_FUNC_signature_settable_ctx_md_params_fn (opf._function);
end;



function _OSSL_FUNC_rand_clear_seed(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_clear_seed_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_clear_seed_fn (opf._function);
end;


function _OSSL_FUNC_rand_get_seed(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_get_seed_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_get_seed_fn (opf._function);
end;


function _OSSL_FUNC_rand_nonce(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_nonce_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_nonce_fn (opf._function);
end;


function _OSSL_FUNC_rand_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_get_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_get_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_rand_unlock(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_unlock_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_unlock_fn (opf._function);
end;


function _OSSL_FUNC_rand_lock(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_lock_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_lock_fn (opf._function);
end;


function _OSSL_FUNC_rand_enable_locking(const opf : POSSL_DISPATCH):TOSSL_FUNC_rand_enable_locking_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_rand_enable_locking_fn (opf._function);
end;


function _OSSL_FUNC_kdf_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_set_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_set_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_kdf_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_get_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_get_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_kdf_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_get_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_get_params_fn (opf._function);
end;


function _OSSL_FUNC_kdf_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_settable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_settable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_kdf_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_gettable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_gettable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_kdf_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_gettable_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_gettable_params_fn (opf._function);
end;


function _OSSL_FUNC_kdf_derive(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_derive_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_derive_fn (opf._function);
end;


function _OSSL_FUNC_kdf_reset(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_reset_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_reset_fn (opf._function);
end;


function _OSSL_FUNC_kdf_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_freectx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_freectx_fn (opf._function);
end;


function _OSSL_FUNC_kdf_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_dupctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_dupctx_fn (opf._function);
end;


function _OSSL_FUNC_kdf_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_kdf_newctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_kdf_newctx_fn (opf._function);
end;


function _OSSL_FUNC_cipher_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_settable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_settable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_cipher_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_gettable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_gettable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_cipher_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_gettable_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_gettable_params_fn (opf._function);
end;


function _OSSL_FUNC_cipher_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_set_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_set_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_cipher_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_get_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_get_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_cipher_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_get_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_get_params_fn (opf._function);
end;


function _OSSL_FUNC_cipher_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_dupctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_dupctx_fn (opf._function);
end;


function _OSSL_FUNC_cipher_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_freectx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_freectx_fn (opf._function);
end;


function _OSSL_FUNC_cipher_cipher(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_cipher_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_cipher_fn (opf._function);
end;


function _OSSL_FUNC_cipher_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_final_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_final_fn (opf._function);
end;


function _OSSL_FUNC_cipher_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_update_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_update_fn (opf._function);
end;


function _OSSL_FUNC_cipher_decrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_decrypt_init_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_decrypt_init_fn (opf._function);
end;


function _OSSL_FUNC_cipher_encrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_encrypt_init_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_encrypt_init_fn (opf._function);
end;


function _OSSL_FUNC_cipher_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_cipher_newctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_cipher_newctx_fn (opf._function);
end;


function _OSSL_FUNC_mac_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_set_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_set_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_mac_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_get_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_get_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_mac_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_get_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_get_params_fn (opf._function);
end;


function _OSSL_FUNC_mac_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_settable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_settable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_mac_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_gettable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_gettable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_mac_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_gettable_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_gettable_params_fn (opf._function);
end;


function _OSSL_FUNC_mac_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_final_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_final_fn (opf._function);
end;


function _OSSL_FUNC_mac_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_update_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_update_fn (opf._function);
end;


function _OSSL_FUNC_mac_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_init_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_init_fn (opf._function);
end;


function _OSSL_FUNC_mac_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_freectx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_freectx_fn (opf._function);
end;


function _OSSL_FUNC_mac_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_dupctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_dupctx_fn (opf._function);
end;


function _OSSL_FUNC_mac_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_mac_newctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_mac_newctx_fn (opf._function);
end;


function _OSSL_FUNC_digest_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_gettable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_gettable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_digest_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_settable_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_settable_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_digest_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_gettable_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_gettable_params_fn (opf._function);
end;


function _OSSL_FUNC_digest_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_get_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_get_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_digest_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_set_ctx_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_set_ctx_params_fn (opf._function);
end;


function _OSSL_FUNC_digest_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_get_params_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_get_params_fn (opf._function);
end;


function _OSSL_FUNC_digest_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_dupctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_dupctx_fn (opf._function);
end;

function _OSSL_FUNC_digest_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_freectx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_freectx_fn (opf._function);
end;


function _OSSL_FUNC_digest_digest(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_digest_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_digest_fn (opf._function);
end;


function _OSSL_FUNC_digest_final(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_final_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_final_fn (opf._function);
end;


function _OSSL_FUNC_digest_update(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_update_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_update_fn (opf._function);
end;


function _OSSL_FUNC_digest_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_init_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_init_fn (opf._function);
end;


function _OSSL_FUNC_digest_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_digest_newctx_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_digest_newctx_fn (opf._function);
end;


function _OSSL_FUNC_core_get_libctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_libctx_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_core_get_libctx_fn (opf._function);
end;


function _OSSL_FUNC_core_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_get_params_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_core_get_params_fn (opf._function);
end;


function _OSSL_FUNC_core_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_gettable_params_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_core_gettable_params_fn (opf._function);
end;


function _OSSL_FUNC_cleanup_nonce(const opf : POSSL_DISPATCH):TOSSL_FUNC_cleanup_nonce_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_cleanup_nonce_fn (opf._function);
end;


function _OSSL_FUNC_get_nonce(const opf : POSSL_DISPATCH):TOSSL_FUNC_get_nonce_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_get_nonce_fn (opf._function);
end;


function _OSSL_FUNC_cleanup_entropy(const opf : POSSL_DISPATCH):TOSSL_FUNC_cleanup_entropy_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_cleanup_entropy_fn (opf._function);
end;


function _OSSL_FUNC_get_entropy(const opf : POSSL_DISPATCH):TOSSL_FUNC_get_entropy_fn;
begin
  Result := opf.method.Code; //TOSSL_FUNC_get_entropy_fn (opf._function);
end;



function _OSSL_FUNC_BIO_vprintf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_vprintf_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_vprintf_fn (opf._function);
end;


function _OSSL_FUNC_BIO_free(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_free_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_free_fn (opf._function);
end;


function _OSSL_FUNC_BIO_up_ref(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_up_ref_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_up_ref_fn (opf._function);
end;


function _OSSL_FUNC_BIO_ctrl(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_ctrl_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_ctrl_fn (opf._function);
end;


function _OSSL_FUNC_BIO_puts(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_puts_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_puts_fn (opf._function);
end;


function _OSSL_FUNC_BIO_gets(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_gets_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_gets_fn (opf._function);
end;


function _OSSL_FUNC_BIO_write_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_write_ex_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_write_ex_fn (opf._function);
end;


function _OSSL_FUNC_BIO_read_ex(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_read_ex_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_read_ex_fn (opf._function);
end;


function _OSSL_FUNC_BIO_new_membuf(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_membuf_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_new_membuf_fn (opf._function);
end;


function _OSSL_FUNC_BIO_new_file(const opf : POSSL_DISPATCH):TOSSL_FUNC_BIO_new_file_fn;
begin
   Result := opf.method.Code; //TOSSL_FUNC_BIO_new_file_fn (opf._function);
end;


end.
