unit openssl3.crypto.provider_core;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$I config.inc}

interface
uses OpenSSL.Api, SysUtils,
     openssl3.crypto.context, OpenSSL3.Err,  openssl3.crypto.mem,
     openssl3.crypto.stack, OpenSSL3.common, openssl3.crypto.provider_child,
     openssl3.crypto.evp.evp_fetch,          openssl3.include.internal.refcount,
     openssl3.crypto.initthread,             openssl3.crypto.dso.dso_lib,
     OpenSSL3.threads_none,                  openssl3.crypto.o_str,
     openssl3.crypto.provider,               openssl3.providers.fips.fipsprov,
     openssl3.crypto.bio.bio_print,          openssl3.crypto.self_test_core,
     openssl3.crypto.rand.prov_seed,         openssl3.crypto.mem_sec,
     openssl3.crypto.params,                 OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.objects.obj_dat,        openssl3.crypto.objects.obj_xref,
     openssl3.crypto.init,                   OpenSSL3.openssl.params,
     openssl3.crypto.getenv,                 openssl3.crypto.bio.ossl_core_bio,
     openssl3.crypto.provider.provider_predefined;

type
  Tcb_func = function( provider : POSSL_PROVIDER; cbdata : Pointer):integer;
  sk_OSSL_PROVIDER_compfunc = function (const  a, b: PPOSSL_PROVIDER):integer;
  sk_OSSL_PROVIDER_freefunc = procedure(a: POSSL_PROVIDER);
  sk_OSSL_PROVIDER_copyfunc = function(const a: POSSL_PROVIDER): POSSL_PROVIDER;

  sk_OSSL_PROVIDER_CHILD_CB_compfunc = function (const  a, b: POSSL_PROVIDER_CHILD_CB):integer;
  sk_OSSL_PROVIDER_CHILD_CB_freefunc = procedure(a: POSSL_PROVIDER_CHILD_CB);
  sk_OSSL_PROVIDER_CHILD_CB_copyfunc = function(const a: POSSL_PROVIDER_CHILD_CB): POSSL_PROVIDER_CHILD_CB;

  sk_INFOPAIR_compfunc = function (const  a, b: PINFOPAIR):integer;
  sk_INFOPAIR_freefunc = procedure(a: PINFOPAIR);
  sk_INFOPAIR_copyfunc = function(const a: PINFOPAIR): PINFOPAIR;

  Tcreate_cb = function (const provider : POSSL_CORE_HANDLE; cbdata : Pointer):integer;
  Tremove_cb = function (const provider : POSSL_CORE_HANDLE; cbdata : Pointer):integer;
  Tglobal_props_cb = function (const props : PUTF8Char; cbdata : Pointer):integer;

  function sk_OSSL_PROVIDER_num( sk : Pointer):integer;
  function sk_OSSL_PROVIDER_value( sk : Pointer;idx: integer):POSSL_PROVIDER;
  function sk_OSSL_PROVIDER_new( cmp : sk_OSSL_PROVIDER_compfunc):PSTACK_st_OSSL_PROVIDER;
  function sk_OSSL_PROVIDER_new_null:PSTACK_st_OSSL_PROVIDER;
  function sk_OSSL_PROVIDER_new_reserve( cmp : sk_OSSL_PROVIDER_compfunc; n : integer):PSTACK_st_OSSL_PROVIDER;
  function sk_OSSL_PROVIDER_reserve( sk : Pointer; n : integer):integer;
  procedure sk_OSSL_PROVIDER_free( sk : Pointer);
  procedure sk_OSSL_PROVIDER_zero( sk : Pointer);
  function sk_OSSL_PROVIDER_delete( sk : Pointer; i : integer):POSSL_PROVIDER;
  function sk_OSSL_PROVIDER_delete_ptr( sk, ptr : Pointer):POSSL_PROVIDER;
  function sk_OSSL_PROVIDER_push( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_unshift( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_pop( sk : Pointer):POSSL_PROVIDER;
  function sk_OSSL_PROVIDER_shift( sk : Pointer):POSSL_PROVIDER;
  procedure sk_OSSL_PROVIDER_pop_free( sk : Pointer; freefunc : sk_OSSL_PROVIDER_freefunc);
  function sk_OSSL_PROVIDER_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_OSSL_PROVIDER_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PROVIDER;
  function sk_OSSL_PROVIDER_find( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_find_ex( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_OSSL_PROVIDER_sort( sk : Pointer);
  function sk_OSSL_PROVIDER_is_sorted( sk : Pointer):integer;
  function sk_OSSL_PROVIDER_dup( sk : Pointer):PSTACK_st_OSSL_PROVIDER;
  function sk_OSSL_PROVIDER_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PROVIDER_copyfunc; freefunc : sk_OSSL_PROVIDER_freefunc):PSTACK_st_OSSL_PROVIDER;
  function sk_OSSL_PROVIDER_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PROVIDER_compfunc):sk_OSSL_PROVIDER_compfunc;

  function sk_OSSL_PROVIDER_CHILD_CB_num( sk : Pointer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_value( sk : Pointer;idx: integer):POSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_new( cmp : sk_OSSL_PROVIDER_CHILD_CB_compfunc):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_new_null:PSTACK_st_OSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_new_reserve( cmp : sk_OSSL_PROVIDER_CHILD_CB_compfunc; n : integer):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_reserve( sk : Pointer; n : integer):integer;
  procedure sk_OSSL_PROVIDER_CHILD_CB_free( sk : Pointer);
  procedure sk_OSSL_PROVIDER_CHILD_CB_zero( sk : Pointer);
  function sk_OSSL_PROVIDER_CHILD_CB_delete( sk : Pointer; i : integer):POSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_delete_ptr( sk, ptr : Pointer):POSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_push( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_unshift( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_pop( sk : Pointer):POSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_shift( sk : Pointer):POSSL_PROVIDER_CHILD_CB;
  procedure sk_OSSL_PROVIDER_CHILD_CB_pop_free( sk : Pointer; freefunc : sk_OSSL_PROVIDER_CHILD_CB_freefunc);
  function sk_OSSL_PROVIDER_CHILD_CB_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_find( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_find_ex( sk, ptr : Pointer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_OSSL_PROVIDER_CHILD_CB_sort( sk : Pointer);
  function sk_OSSL_PROVIDER_CHILD_CB_is_sorted( sk : Pointer):integer;
  function sk_OSSL_PROVIDER_CHILD_CB_dup( sk : Pointer):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PROVIDER_CHILD_CB_copyfunc; freefunc : sk_OSSL_PROVIDER_CHILD_CB_freefunc):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
  function sk_OSSL_PROVIDER_CHILD_CB_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PROVIDER_CHILD_CB_compfunc):sk_OSSL_PROVIDER_CHILD_CB_compfunc;

  function sk_INFOPAIR_num( sk : Pointer):integer;
  function sk_INFOPAIR_value( sk : Pointer;idx: integer):PINFOPAIR;
  function sk_INFOPAIR_new( cmp : sk_INFOPAIR_compfunc):PSTACK_st_INFOPAIR;
  function sk_INFOPAIR_new_null:PSTACK_st_INFOPAIR;
  function sk_INFOPAIR_new_reserve( cmp : sk_INFOPAIR_compfunc; n : integer):PSTACK_st_INFOPAIR;
  function sk_INFOPAIR_reserve( sk : Pointer; n : integer):integer;
  procedure sk_INFOPAIR_free( sk : Pointer);
  procedure sk_INFOPAIR_zero( sk : Pointer);
  function sk_INFOPAIR_delete( sk : Pointer; i : integer):PINFOPAIR;
  function sk_INFOPAIR_delete_ptr( sk, ptr : Pointer):PINFOPAIR;
  function sk_INFOPAIR_push( sk, ptr : Pointer):integer;
  function sk_INFOPAIR_unshift( sk, ptr : Pointer):integer;
  function sk_INFOPAIR_pop( sk : Pointer):PINFOPAIR;
  function sk_INFOPAIR_shift( sk : Pointer):PINFOPAIR;
  procedure sk_INFOPAIR_pop_free( sk : Pointer; freefunc : sk_INFOPAIR_freefunc);
  function sk_INFOPAIR_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_INFOPAIR_set( sk : Pointer; idx : integer; ptr : Pointer):PINFOPAIR;
  function sk_INFOPAIR_find( sk, ptr : Pointer):integer;
  function sk_INFOPAIR_find_ex( sk, ptr : Pointer):integer;
  function sk_INFOPAIR_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_INFOPAIR_sort( sk : Pointer);
  function sk_INFOPAIR_is_sorted( sk : Pointer):integer;
  function sk_INFOPAIR_dup( sk : Pointer):PSTACK_st_INFOPAIR;
  function sk_INFOPAIR_deep_copy( sk : Pointer; copyfunc : sk_INFOPAIR_copyfunc; freefunc : sk_INFOPAIR_freefunc):PSTACK_st_INFOPAIR;
  function sk_INFOPAIR_set_cmp_func( sk : Pointer; cmp : sk_INFOPAIR_compfunc):sk_INFOPAIR_compfunc;

function ossl_provider_libctx(const prov : POSSL_PROVIDER):POSSL_LIB_CTX;
 procedure provider_store_free( vstore : Pointer);
function ossl_provider_ctx(const prov : POSSL_PROVIDER):Pointer;
function provider_store_new( ctx : POSSL_LIB_CTX):Pointer;
function ossl_provider_clear_all_operation_bits( libctx : POSSL_LIB_CTX):integer;
function get_provider_store( libctx : POSSL_LIB_CTX):Pprovider_store_st;
 procedure provider_deactivate_free( prov : POSSL_PROVIDER);
 function ossl_provider_deactivate( prov : POSSL_PROVIDER; removechildren : integer):integer;
 function provider_deactivate( prov : POSSL_PROVIDER; upcalls, removechildren : integer):integer;
function ossl_provider_get_parent( prov : POSSL_PROVIDER):POSSL_CORE_HANDLE;
function provider_flush_store_cache(const prov : POSSL_PROVIDER):integer;
procedure ossl_provider_free( prov : POSSL_PROVIDER);
procedure ossl_provider_teardown(const prov : POSSL_PROVIDER);
procedure infopair_free( pair : PINFOPAIR);
 procedure ossl_provider_child_cb_free( cb : POSSL_PROVIDER_CHILD_CB);
procedure ossl_provider_info_clear( info : POSSL_PROVIDER_INFO);
function ossl_provider_cmp(const a, b : PPOSSL_PROVIDER):integer;
function ossl_provider_doall_activated( ctx : POSSL_LIB_CTX; cb : Tcb_func; cbdata : Pointer):integer;
function provider_activate_fallbacks( store : Pprovider_store_st):integer;
function ossl_provider_query_operation(const prov : POSSL_PROVIDER; operation_id : integer;var no_cache : Integer):POSSL_ALGORITHM;
 procedure ossl_provider_unquery_operation(const prov : POSSL_PROVIDER; operation_id : integer;const algs : POSSL_ALGORITHM);
function ossl_provider_up_ref( prov : POSSL_PROVIDER):integer;
function ossl_provider_find(libctx : POSSL_LIB_CTX;const name : PUTF8Char; noconfig : integer):POSSL_PROVIDER;
function ossl_provider_new(libctx : POSSL_LIB_CTX;const name : PUTF8Char;init_function : TOSSL_provider_init_fn; noconfig : integer):POSSL_PROVIDER;
function provider_init( prov : POSSL_PROVIDER):integer;
function provider_activate( prov : POSSL_PROVIDER; lock, upcalls : integer):integer;
 function ossl_provider_add_to_store( prov : POSSL_PROVIDER; actualprov : PPOSSL_PROVIDER; retain_fallbacks : integer):integer;
 function ossl_provider_disable_fallback_loading( libctx : POSSL_LIB_CTX):integer;
 function ossl_provider_prov_ctx(const prov : POSSL_PROVIDER):Pointer;
 function ossl_provider_info_add_to_store(libctx : POSSL_LIB_CTX;entry : POSSL_PROVIDER_INFO):integer;
 function ossl_provider_name(const prov : POSSL_PROVIDER):PUTF8Char;
 function ossl_provider_test_operation_bit( provider : POSSL_PROVIDER; bitnum : size_t; _result : PInteger):integer;
 function ossl_provider_set_operation_bit( provider : POSSL_PROVIDER; bitnum : size_t):integer;

var
 ossl_default_provider_init: TOSSL_provider_init_fn = nil;
 ossl_base_provider_init,
 ossl_null_provider_init,
 ossl_fips_intern_provider_init: TOSSL_provider_init_fn;

const
  provider_store_method: OSSL_LIB_CTX_METHOD  = (
    (* Needs to be freed before the child provider data is freed *)
    priority :OSSL_LIB_CTX_METHOD_PRIORITY_1;
    new_func: provider_store_new;
    free_func: provider_store_free
  );




function create_provider_children( prov : POSSL_PROVIDER):integer;
 function core_gettable_params(const handle : POSSL_CORE_HANDLE):POSSL_PARAM;

function core_get_params(const handle : POSSL_CORE_HANDLE; params : POSSL_PARAM):integer;
  function core_get_libctx(const handle : POSSL_CORE_HANDLE): POPENSSL_CORE_CTX;

function core_thread_start(const handle : POSSL_CORE_HANDLE; handfn : TOSSL_thread_stop_handler_fn; arg : Pointer):integer;
 procedure core_new_error(const handle : POSSL_CORE_HANDLE);
  procedure core_set_error_debug(const handle : POSSL_CORE_HANDLE; &file : PUTF8Char; line : integer;const func : PUTF8Char);
  procedure core_vset_error(const handle : POSSL_CORE_HANDLE; reason : uint32;const fmt :string);
  function core_set_error_mark(const handle : POSSL_CORE_HANDLE):integer;
  function core_clear_last_error_mark(const handle : POSSL_CORE_HANDLE):integer;
  function core_pop_error_to_mark(const handle : POSSL_CORE_HANDLE):integer;
  function core_obj_add_sigid(const prov : POSSL_CORE_HANDLE; sign_name, digest_name, pkey_name : PUTF8Char):integer;
  function core_obj_create(const prov : POSSL_CORE_HANDLE; oid, sn, ln : PUTF8Char):integer;
  function ossl_provider_register_child_cb(const handle : POSSL_CORE_HANDLE; create_cb : Tcreate_cb; remove_cb : Tremove_cb; global_props_cb : Tglobal_props_cb; cbdata : Pointer):integer;
  procedure ossl_provider_deregister_child_cb(const handle : POSSL_CORE_HANDLE);
  function provider_up_ref_intern( prov : POSSL_PROVIDER; activate : integer):integer;
  function provider_free_intern( prov : POSSL_PROVIDER; deactivate : integer):integer;
function ossl_provider_module_path(const prov : POSSL_PROVIDER):PUTF8Char;

var
   param_types: array of TOSSL_PARAM;

function provider_new(const name : PUTF8Char;init_function : TOSSL_provider_init_fn;parameters: Pstack_st_INFOPAIR):POSSL_PROVIDER;
function infopair_copy(const src : PINFOPAIR):PINFOPAIR;
function ossl_provider_add_parameter(prov : POSSL_PROVIDER;const name, value : PUTF8Char):integer;
function ossl_provider_info_add_parameter(provinfo : POSSL_PROVIDER_INFO;const name, value : PUTF8Char):integer;
function ossl_provider_set_module_path(prov : POSSL_PROVIDER;const module_path : PUTF8Char):integer;

function ossl_provider_default_props_update(libctx : POSSL_LIB_CTX;const props : PUTF8Char):integer;
function infopair_add( infopairsk : PPstack_st_INFOPAIR;const name, value : PUTF8Char):integer;

const BUILTINS_BLOCK_SIZE  =   10;

const core_dispatch_: array[0..47] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_CORE_GETTABLE_PARAMS; method:(code:@core_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_CORE_GET_PARAMS; method:(code:@core_get_params; data:nil)),
    (function_id:  OSSL_FUNC_CORE_GET_LIBCTX; method:(code:@core_get_libctx; data:nil)),
    (function_id:  OSSL_FUNC_CORE_THREAD_START; method:(code:@core_thread_start; data:nil)),
{$ifndef FIPS_MODULE}
    (function_id:  OSSL_FUNC_CORE_NEW_ERROR; method:(code:@core_new_error; data:nil)),
    (function_id:  OSSL_FUNC_CORE_SET_ERROR_DEBUG; method:(code:@core_set_error_debug; data:nil)),
    (function_id:  OSSL_FUNC_CORE_VSET_ERROR; method:(code:@core_vset_error; data:nil)),
    (function_id:  OSSL_FUNC_CORE_SET_ERROR_MARK; method:(code:@core_set_error_mark; data:nil)),
    (function_id:  OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK;
      method:(code:@core_clear_last_error_mark; data:nil)),
    (function_id:  OSSL_FUNC_CORE_POP_ERROR_TO_MARK; method:(code:@core_pop_error_to_mark; data:nil)),
    (function_id:  OSSL_FUNC_BIO_NEW_FILE; method:(code:@ossl_core_bio_new_file; data:nil)),
    (function_id:  OSSL_FUNC_BIO_NEW_MEMBUF; method:(code:@ossl_core_bio_new_mem_buf; data:nil)),
    (function_id:  OSSL_FUNC_BIO_READ_EX; method:(code:@ossl_core_bio_read_ex; data:nil)),
    (function_id:  OSSL_FUNC_BIO_WRITE_EX; method:(code:@ossl_core_bio_write_ex; data:nil)),
    (function_id:  OSSL_FUNC_BIO_GETS; method:(code:@ossl_core_bio_gets; data:nil)),
    (function_id:  OSSL_FUNC_BIO_PUTS; method:(code:@ossl_core_bio_puts; data:nil)),
    (function_id:  OSSL_FUNC_BIO_CTRL; method:(code:@ossl_core_bio_ctrl; data:nil)),
    (function_id:  OSSL_FUNC_BIO_UP_REF; method:(code:@ossl_core_bio_up_ref; data:nil)),
    (function_id:  OSSL_FUNC_BIO_FREE; method:(code:@ossl_core_bio_free; data:nil)),
    (function_id:  OSSL_FUNC_BIO_VPRINTF; method:(code:@ossl_core_bio_vprintf; data:nil)),
    (function_id:  OSSL_FUNC_BIO_VSNPRINTF; method:(code:@BIO_vsnprintf; data:nil)),
    (function_id:  OSSL_FUNC_SELF_TEST_CB; method:(code:@OSSL_SELF_TEST_get_callback; data:nil)),
    (function_id:  OSSL_FUNC_GET_ENTROPY; method:(code:@ossl_rand_get_entropy; data:nil)),
    (function_id:  OSSL_FUNC_CLEANUP_ENTROPY; method:(code:@ossl_rand_cleanup_entropy; data:nil)),
    (function_id:  OSSL_FUNC_GET_NONCE; method:(code:@ossl_rand_get_nonce; data:nil)),
    (function_id:  OSSL_FUNC_CLEANUP_NONCE; method:(code:@ossl_rand_cleanup_nonce; data:nil)),
{$endif}
    (function_id:  OSSL_FUNC_CRYPTO_MALLOC; method:(code:@CRYPTO_malloc; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_ZALLOC; method:(code:@CRYPTO_zalloc; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_FREE; method:(code:@CRYPTO_free; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_CLEAR_FREE; method:(code:@CRYPTO_clear_free; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_REALLOC; method:(code:@CRYPTO_realloc; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_CLEAR_REALLOC; method:(code:@CRYPTO_clear_realloc; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_SECURE_MALLOC; method:(code:@CRYPTO_secure_malloc; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_SECURE_ZALLOC; method:(code:@CRYPTO_secure_zalloc; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_SECURE_FREE; method:(code:@CRYPTO_secure_free; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE;
        method:(code:@CRYPTO_secure_clear_free; data:nil)),
    (function_id:  OSSL_FUNC_CRYPTO_SECURE_ALLOCATED;
        method:(code:@CRYPTO_secure_allocated; data:nil)),
    (function_id:  OSSL_FUNC_OPENSSL_CLEANSE; method:(code:@OPENSSL_cleanse; data:nil)),
{$ifndef FIPS_MODULE}
    (function_id:  OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB;
        method:(code:@ossl_provider_register_child_cb; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB;
        method:(code:@ossl_provider_deregister_child_cb; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_NAME;
        method:(code:@OSSL_PROVIDER_get0_name; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX;
        method:(code:@OSSL_PROVIDER_get0_provider_ctx; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GET0_DISPATCH;
        method:(code:@OSSL_PROVIDER_get0_dispatch; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_UP_REF;
        method:(code:@provider_up_ref_intern; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_FREE;
        method:(code:@provider_free_intern; data:nil)),
    (function_id:  OSSL_FUNC_CORE_OBJ_ADD_SIGID; method:(code:@core_obj_add_sigid; data:nil)),
    (function_id:  OSSL_FUNC_CORE_OBJ_CREATE; method:(code:@core_obj_create; data:nil)),
{$endif}
    (function_id:  0; method:(code:nil; data:nil) ));

var core_dispatch: POSSL_DISPATCH  = @core_dispatch_;

implementation

function infopair_add( infopairsk : PPstack_st_INFOPAIR;const name, value : PUTF8Char):integer;
var
  pair : PINFOPAIR;
  function get_infopairsk: Boolean;
  begin
     infopairsk^ := sk_INFOPAIR_new_null;
     Result := infopairsk^ <> nil;
  end;
begin
    pair := nil;
    pair := OPENSSL_zalloc(sizeof(pair^));
    OPENSSL_strdup(pair.name ,name);
    OPENSSL_strdup(pair.value ,value);
    if (pair <> nil)
         and  ( (infopairsk^ <> nil)
             or  ( get_infopairsk) )
         and  (pair.name <> nil)
         and  (pair.value <> nil)
         and  (sk_INFOPAIR_push( infopairsk^, pair) > 0) then
        Exit(1);
    if pair <> nil then begin
        OPENSSL_free(pair.name);
        OPENSSL_free(pair.value);
        OPENSSL_free(pair);
    end;
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
    Result := 0;
end;



function ossl_provider_default_props_update(libctx : POSSL_LIB_CTX;const props : PUTF8Char):integer;
var
  store    : Pprovider_store_st;
  i,
  max      : integer;
  child_cb : POSSL_PROVIDER_CHILD_CB;
begin
{$IFNDEF FIPS_MODULE}
    store := nil;
    store := get_provider_store(libctx);
    if store = nil then
        Exit(0);
    if 0>=CRYPTO_THREAD_read_lock(store.lock ) then
        Exit(0);
    max := sk_OSSL_PROVIDER_CHILD_CB_num(store.child_cbs);
    for i := 0 to max-1 do
    begin
        child_cb := sk_OSSL_PROVIDER_CHILD_CB_value(store.child_cbs, i);
        child_cb.global_props_cb(props, child_cb.cbdata);
    end;
    CRYPTO_THREAD_unlock(store.lock);
{$ENDIF}
    Result := 1;
end;

function ossl_provider_set_module_path(prov : POSSL_PROVIDER;const module_path : PUTF8Char):integer;
begin
    OPENSSL_free(prov.path);
    prov.path := nil;
    if module_path = nil then Exit(1);
     OPENSSL_strdup(prov.path ,module_path);
    if prov.path <> nil then
        Exit(1);
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
    Result := 0;
end;



function ossl_provider_info_add_parameter(provinfo : POSSL_PROVIDER_INFO;const name, value : PUTF8Char):integer;
begin
    Result := infopair_add(&provinfo.parameters, name, value);
end;




function ossl_provider_add_parameter(prov : POSSL_PROVIDER;const name, value : PUTF8Char):integer;
begin
    Result := infopair_add(&prov.parameters, name, value);
end;



function infopair_copy(const src : PINFOPAIR):PINFOPAIR;
var
  dest : PINFOPAIR;
  label _err;
begin
    dest := OPENSSL_zalloc(sizeof( dest^));
    if dest = nil then Exit(nil);
    if src.name <> nil then begin
         OPENSSL_strdup(dest.name, src.name);
        if dest.name = nil then goto _err;
    end;
    if src.value <> nil then begin
        OPENSSL_strdup(dest.value ,src.value);
        if dest.value = nil then goto _err;
    end;
    Exit(dest);
 _err:
    OPENSSL_free(dest.name);
    OPENSSL_free(dest);
    Result := nil;
end;


function provider_new(const name : PUTF8Char;init_function : TOSSL_provider_init_fn;parameters: Pstack_st_INFOPAIR):POSSL_PROVIDER;
begin
    Result := nil;
    Result := OPENSSL_zalloc(sizeof( Result^));
    Result.opbits_lock := CRYPTO_THREAD_lock_new;
    Result.flag_lock := CRYPTO_THREAD_lock_new;
    OPENSSL_strdup(Result.name ,name);
    Result.parameters := sk_INFOPAIR_deep_copy(parameters,
                                                     infopair_copy,
                                                     infopair_free);
    if (Result = nil)
{$IFNDEF HAVE_ATOMICS}
         or  (Result.refcnt_lock = CRYPTO_THREAD_lock_new) = nil
{$ENDIF}
         or  (Result.opbits_lock = nil)
         or  (Result.flag_lock = nil)
         or  (Result.name =  nil)
         or  (Result.parameters = nil) then
    begin
        ossl_provider_free(Result);
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    Result.refcnt := 1; { 1 One reference to be returned }
    Result.init_function := init_function;

end;


function ossl_provider_module_path(const prov : POSSL_PROVIDER):PUTF8Char;
begin
{$IFDEF FIPS_MODULE}
    Exit(nil);
{$ELSE} { FIXME: Ensure it's a full path }
    Result := DSO_get_filename(prov.module);
{$ENDIF}
end;


function provider_up_ref_intern( prov : POSSL_PROVIDER; activate : integer):integer;
begin
    if activate > 0 then Exit(ossl_provider_activate(prov, 1, 0));
    Result := ossl_provider_up_ref(prov);
end;


function provider_free_intern( prov : POSSL_PROVIDER; deactivate : integer):integer;
begin
    if deactivate > 0 then Exit(ossl_provider_deactivate(prov, 1));
    ossl_provider_free(prov);
    Result := 1;
end;



procedure ossl_provider_deregister_child_cb(const handle : POSSL_CORE_HANDLE);
var
    thisprov : POSSL_PROVIDER;
    libctx   : POSSL_LIB_CTX;
    store    : Pprovider_store_st;
    i,
    max      : integer;
    child_cb : POSSL_PROVIDER_CHILD_CB;
begin
    {
     * This is really an OSSL_PROVIDER that we created and cast to
     * OSSL_CORE_HANDLE originally. Therefore it is safe to cast it back.
     }
    thisprov := POSSL_PROVIDER (handle);
    libctx := thisprov.libctx;
    store := nil;
    store := get_provider_store(libctx);
    if store = nil then
        exit;
    if 0>=CRYPTO_THREAD_write_lock(store.lock) then
        exit;
    max := sk_OSSL_PROVIDER_CHILD_CB_num(store.child_cbs);
    for i := 0 to max-1 do
    begin
        child_cb := sk_OSSL_PROVIDER_CHILD_CB_value(store.child_cbs, i);
        if child_cb.prov = thisprov then begin
            { Found an entry }
            sk_OSSL_PROVIDER_CHILD_CB_delete(store.child_cbs, i);
            OPENSSL_free(child_cb);
            break;
        end;
    end;
    CRYPTO_THREAD_unlock(store.lock);
end;


function ossl_provider_register_child_cb(const handle : POSSL_CORE_HANDLE; create_cb : Tcreate_cb; remove_cb : Tremove_cb; global_props_cb : Tglobal_props_cb; cbdata : Pointer):integer;
var
  thisprov,
  prov      : POSSL_PROVIDER;
  libctx    : POSSL_LIB_CTX;
  store     : Pprovider_store_st;
  ret, i, max       : integer;
  child_cb  : POSSL_PROVIDER_CHILD_CB;
  propsstr  : PUTF8Char;
  activated : integer;
begin
    {
     * This is really an OSSL_PROVIDER that we created and cast to
     * OSSL_CORE_HANDLE originally. Therefore it is safe to cast it back.
     }
    thisprov := POSSL_PROVIDER (handle);
    libctx := thisprov.libctx;
    store := nil;
    ret := 0;
    propsstr := nil;
    store := get_provider_store(libctx);
    if store = nil then
        Exit(0);
    child_cb := OPENSSL_malloc(sizeof( child_cb^));
    if child_cb = nil then Exit(0);
    child_cb.prov := thisprov;
    child_cb.create_cb := create_cb;
    child_cb.remove_cb := remove_cb;
    child_cb.global_props_cb := global_props_cb;
    child_cb.cbdata := cbdata;
    if 0>=CRYPTO_THREAD_write_lock(store.lock) then
    begin
        OPENSSL_free(child_cb);
        Exit(0);
    end;
    propsstr := evp_get_global_properties_str(libctx, 0);
    if propsstr <> nil then begin
        global_props_cb(propsstr, cbdata);
        OPENSSL_free(propsstr);
    end;
    max := sk_OSSL_PROVIDER_num(store.providers);
    for i := 0 to max-1 do
    begin
        prov := sk_OSSL_PROVIDER_value(store.providers, i);
        if 0>=CRYPTO_THREAD_read_lock(prov.flag_lock) then
            break;
        activated := prov.flag_activated;
        CRYPTO_THREAD_unlock(prov.flag_lock);
        {
         * We hold the store lock while calling the user callback. This means
         * that the user callback must be short and simple and not do anything
         * likely to cause a deadlock. We don't hold the flag_lock during this
         * call. In theory this means that another thread could deactivate it
         * while we are calling create. This is ok because the other thread
         * will also call remove_cb, but won't be able to do so until we release
         * the store lock.
         }
        if (activated > 0) and  (0>=create_cb(POSSL_CORE_HANDLE(prov), cbdata)) then
            break;
    end;
    if i = max then begin
        { Success }
        ret := sk_OSSL_PROVIDER_CHILD_CB_push(store.child_cbs, child_cb);
    end;
    if (i <> max)  or  (ret <= 0) then
    begin
        { Failed during creation. Remove everything we just added }
        while i >= 0 do
        begin
            prov := sk_OSSL_PROVIDER_value(store.providers, i);
            remove_cb(POSSL_CORE_HANDLE (prov), cbdata);
            Dec(i);
        end;
        OPENSSL_free(child_cb);
        ret := 0;
    end;
    CRYPTO_THREAD_unlock(store.lock);
    Result := ret;
end;



procedure core_new_error(const handle : POSSL_CORE_HANDLE);
begin
    ERR_new;
end;


procedure core_set_error_debug(const handle : POSSL_CORE_HANDLE; &file : PUTF8Char; line : integer;const func : PUTF8Char);
begin
    ERR_set_debug({file, line,} func);
end;


procedure core_vset_error(const handle : POSSL_CORE_HANDLE; reason : uint32;const fmt :string);
var
  prov : POSSL_PROVIDER;
begin
    {
     * We created this object originally and we know it is actually an
     * POSSL_PROVIDER , so the cast is safe
     }
    prov := POSSL_PROVIDER (handle);
    {
     * If the uppermost 8 bits are non-zero, it's an OpenSSL library
     * error and will be treated as such.  Otherwise, it's a new style
     * provider error and will be treated as such.
     }
    if ERR_GET_LIB(reason) <> 0  then
    begin
        ERR_vset_error(ERR_GET_LIB(reason), ERR_GET_REASON(reason), fmt);
    end
    else begin
        ERR_vset_error(prov.error_lib, int(reason), fmt);
    end;
end;


function core_set_error_mark(const handle : POSSL_CORE_HANDLE):integer;
begin
    Result := ERR_set_mark;
end;


function core_clear_last_error_mark(const handle : POSSL_CORE_HANDLE):integer;
begin
    Result := ERR_clear_last_mark;
end;


function core_pop_error_to_mark(const handle : POSSL_CORE_HANDLE):integer;
begin
    Result := ERR_pop_to_mark;
end;


function core_obj_add_sigid(const prov : POSSL_CORE_HANDLE; sign_name, digest_name, pkey_name : PUTF8Char):integer;
var
  sign_nid,
  digest_nid,
  pkey_nid   : integer;
begin
    sign_nid := OBJ_txt2nid(sign_name);
    digest_nid := NID_undef;
    pkey_nid := OBJ_txt2nid(pkey_name);
    digest_nid := OBJ_txt2nid(digest_name);
    if (digest_name <> nil)  and  (digest_name[0] <> #0)
         and  (digest_nid = NID_undef) then
            Exit(0);
    if sign_nid = NID_undef then Exit(0);
    {
     * Check if it already exists. This is a success if so (even if we don't
     * have nids for the digest/pkey)
     }
    if OBJ_find_sigid_algs(sign_nid, nil, nil) > 0 then
        Exit(1);
    if pkey_nid = NID_undef then Exit(0);
    Result := OBJ_add_sigid(sign_nid, digest_nid, pkey_nid);
end;


function core_obj_create(const prov : POSSL_CORE_HANDLE; oid, sn, ln : PUTF8Char):integer;
begin
    { Check if it already exists and create it if not }
    Result := Int( (OBJ_txt2nid(oid) <> NID_undef)
            or     (OBJ_create(oid, sn, ln) <> NID_undef) );
end;


function core_thread_start(const handle : POSSL_CORE_HANDLE; handfn : TOSSL_thread_stop_handler_fn; arg : Pointer):integer;
var
  prov : POSSL_PROVIDER;
begin
    {
     * We created this object originally and we know it is actually an
     * POSSL_PROVIDER , so the cast is safe
     }
    prov := POSSL_PROVIDER (handle);
    Result := ossl_init_thread_start(prov, arg, handfn);
end;




function core_get_params(const handle : POSSL_CORE_HANDLE; params : POSSL_PARAM):integer;
var
  i : integer;
  p : POSSL_PARAM;
  prov : POSSL_PROVIDER;
  pair : PINFOPAIR;
begin
    {
     * We created this object originally and we know it is actually an
     * POSSL_PROVIDER , so the cast is safe
     }
    prov := POSSL_PROVIDER (handle);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_VERSION);
    if p <> nil then
        OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_PROV_NAME);
    if p <> nil then
        OSSL_PARAM_set_utf8_ptr(p, prov.name);
{$IFNDEF FIPS_MODULE}
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_MODULE_FILENAME );
    if (p <> nil) then
        OSSL_PARAM_set_utf8_ptr(p, ossl_provider_module_path(prov));
{$ENDIF}
    if prov.parameters = nil then Exit(1);
    for i := 0 to sk_INFOPAIR_num(prov.parameters)-1 do
    begin
        pair := sk_INFOPAIR_value(prov.parameters, i);
        p := OSSL_PARAM_locate(params, pair.name);
        if p <> nil then
            OSSL_PARAM_set_utf8_ptr(p, pair.value);
    end;
    Result := 1;
end;


function core_get_libctx(const handle : POSSL_CORE_HANDLE): POPENSSL_CORE_CTX;
var
  prov : POSSL_PROVIDER;
begin
    {
     * We created this object originally and we know it is actually an
     * POSSL_PROVIDER , so the cast is safe
     }
    prov := POSSL_PROVIDER (handle);
    {
     * Using ossl_provider_libctx would be wrong as that returns
     * nil for |prov| = nil and nil libctx has a special meaning
     * that does not apply here. Here |prov| = nil can happen only in
     * case of a coding error.
     }
    assert(prov <> nil);
    Result := POPENSSL_CORE_CTX (prov.libctx);
end;


function core_gettable_params(const handle : POSSL_CORE_HANDLE):POSSL_PARAM;
begin
    Result := @param_types[0];
end;

function create_provider_children( prov : POSSL_PROVIDER):integer;
var
  ret      : integer;
  child_cb : POSSL_PROVIDER_CHILD_CB;
  store: Pprovider_store_st;
  i, max      : integer;
begin
    ret := 1;
{$IFNDEF FIPS_MODULE}
    store := prov.store;
    max := sk_OSSL_PROVIDER_CHILD_CB_num(store.child_cbs);
    for i := 0 to max-1 do begin
        {
         * This is newly activated (activatecnt = 1), so we need to
         * create child providers as necessary.
         }
        child_cb := sk_OSSL_PROVIDER_CHILD_CB_value(store.child_cbs, i);
        ret := ret and child_cb.create_cb(POSSL_CORE_HANDLE (prov), child_cb.cbdata);
    end;
{$ENDIF}
    Result := ret;
end;

function ossl_provider_set_operation_bit( provider : POSSL_PROVIDER; bitnum : size_t):integer;
var
  _byte : size_t;
  bit : Byte;
  tmp : PByte;
begin
    _byte := bitnum div 8;
    bit := (1  shl  (bitnum mod 8)) and $FF;
    if 0>= CRYPTO_THREAD_write_lock(provider.opbits_lock) then
        Exit(0);
    if provider.operation_bits_sz <= _byte then
    begin
        tmp := OPENSSL_realloc(provider.operation_bits,
                                             _byte + 1);
        if tmp = nil then
        begin
            CRYPTO_THREAD_unlock(provider.opbits_lock);
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        provider.operation_bits := tmp;
        memset(provider.operation_bits + provider.operation_bits_sz,
               Ord(#0), _byte + 1 - provider.operation_bits_sz);
        provider.operation_bits_sz := _byte + 1;
    end;
    provider.operation_bits[_byte]  := provider.operation_bits[_byte]  or bit;
    CRYPTO_THREAD_unlock(provider.opbits_lock);
    Result := 1;
end;

function ossl_provider_test_operation_bit( provider : POSSL_PROVIDER; bitnum : size_t; _result : PInteger):integer;
var
  _byte : size_t;
  bit : Byte;
begin
    _byte := bitnum div 8;
    bit := (1  shl  (bitnum mod 8)) and $FF;
    if not ossl_assert(_result <> nil) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    _result^ := 0;
    if 0>= CRYPTO_THREAD_read_lock(provider.opbits_lock) then
        Exit(0);
    if provider.operation_bits_sz > _byte then
       _result^ := int((provider.operation_bits[_byte] and bit) <> 0);
    CRYPTO_THREAD_unlock(provider.opbits_lock);
    Result := 1;
end;

function ossl_provider_name(const prov : POSSL_PROVIDER):PUTF8Char;
begin
    Result := prov.name;
end;

function ossl_provider_info_add_to_store(libctx : POSSL_LIB_CTX;entry : POSSL_PROVIDER_INFO):integer;
var
    store       : Pprovider_store_st;
    ret         : integer;
    tmpbuiltins : POSSL_PROVIDER_INFO;
    newsz       : size_t;
    label _err;
begin
{$POINTERMATH ON}
    store := get_provider_store(libctx);
    ret := 0;
    if entry.name = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if store = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    if 0>= CRYPTO_THREAD_write_lock(store.lock) then
        Exit(0);
    if store.provinfosz = 0 then
    begin
        store.provinfo := OPENSSL_zalloc(sizeof(store.provinfo^)
                                         * BUILTINS_BLOCK_SIZE);
        if store.provinfo = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        store.provinfosz := BUILTINS_BLOCK_SIZE;
    end
    else
    if (store.numprovinfo = store.provinfosz) then
    begin
        newsz := store.provinfosz + BUILTINS_BLOCK_SIZE;
        tmpbuiltins := OPENSSL_realloc(store.provinfo,
                                      sizeof(store.provinfo^) * newsz);
        if tmpbuiltins = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        store.provinfo := tmpbuiltins;
        store.provinfosz := newsz;
    end;
    store.provinfo[store.numprovinfo] := entry^;
    Inc(store.numprovinfo);
    ret := 1;
 _err:
    CRYPTO_THREAD_unlock(store.lock);
    Result := ret;
 {$POINTERMATH OFF}
end;



function ossl_provider_prov_ctx(const prov : POSSL_PROVIDER):Pointer;
begin
    if prov <> nil then
       Exit(prov.provctx);
    Result := nil;
end;




function ossl_provider_disable_fallback_loading( libctx : POSSL_LIB_CTX):integer;
var
  store : Pprovider_store_st;
begin
    store := get_provider_store(libctx);
    if store  <> nil then
    begin
        if 0>= CRYPTO_THREAD_write_lock(store.lock) then
            Exit(0);
        store.use_fallbacks := 0;
        CRYPTO_THREAD_unlock(store.lock);
        Exit(1);
    end;
    Result := 0;
end;


function ossl_provider_add_to_store( prov : POSSL_PROVIDER; actualprov : PPOSSL_PROVIDER; retain_fallbacks : integer):integer;
var
    store     : Pprovider_store_st;
    idx       : integer;
    tmpl      : TOSSL_PROVIDER;
    actualtmp : POSSL_PROVIDER;
    label _err;
begin
    FillChar(tmpl, SizeOf(TOSSL_PROVIDER), 0);
    actualtmp := nil;
    if actualprov <> nil then actualprov^ := nil;
    store := get_provider_store(prov.libctx);
    if store = nil then
        Exit(0);
    if 0>= CRYPTO_THREAD_write_lock(store.lock) then
        Exit(0);
    tmpl.name := PUTF8Char(  prov.name);
    idx := sk_OSSL_PROVIDER_find(store.providers, @tmpl);
    if idx = -1 then
       actualtmp := prov
    else
        actualtmp := sk_OSSL_PROVIDER_value(store.providers, idx);
    if idx = -1 then
    begin
        if sk_OSSL_PROVIDER_push(store.providers, prov) = 0 then
            goto _err ;
        prov.store := store;
        if 0>= create_provider_children(prov) then
        begin
            sk_OSSL_PROVIDER_delete_ptr(store.providers, prov);
            goto _err ;
        end;
        if 0>= retain_fallbacks then
           store.use_fallbacks := 0;
    end;
    CRYPTO_THREAD_unlock(store.lock);
    if actualprov <> nil then
    begin
        if 0>= ossl_provider_up_ref(actualtmp) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            actualtmp := nil;
            goto _err ;
        end;
        actualprov^ := actualtmp;
    end;
    if idx >= 0 then
    begin
        {
         * The provider is already in the store. Probably two threads
         * independently initialised their own provider objects with the same
         * name and raced to put them in the store. This thread lost. We
         * deactivate the one we just created and use the one that already
         * exists instead.
         * If we get here then we know we did not create provider children
         * above, so we inform ossl_provider_deactivate not to attempt to remove
         * any.
         }
        ossl_provider_deactivate(prov, 0);
        ossl_provider_free(prov);
    end;
    Exit(1);
 _err:
    CRYPTO_THREAD_unlock(store.lock);
    if actualprov <> nil then
       ossl_provider_free( actualprov^);
    Result := 0;
end;

function provider_activate( prov : POSSL_PROVIDER; lock, upcalls : integer):integer;
var
  count : integer;
  store : Pprovider_store_st;
  ret : integer;
begin
    count := -1;
    ret := 1;
    store := prov.store;
    {
    * If the provider hasn't been added to the store, then we don't need
    * any locks because we've not shared it with other threads.
    }
    if store = nil then
    begin
        lock := 0;
        if 0>= provider_init(prov) then
            Exit(-1);
    end;
{$IFNDEF FIPS_MODULE}
    if (prov.ischild>0)  and  (upcalls>0)  and  (0>= ossl_provider_up_ref_parent(prov, 1)) then
        Exit(-1);
{$ENDIF}
    if (lock > 0)  and  (0>= CRYPTO_THREAD_read_lock(store.lock)) then
    begin
{$IFNDEF FIPS_MODULE}
        if (prov.ischild>0)  and  (upcalls>0) then
            ossl_provider_free_parent(prov, 1);
{$ENDIF}
        Exit(-1);
    end;
    if (lock > 0)  and  (0>= CRYPTO_THREAD_write_lock(prov.flag_lock)) then
    begin
        CRYPTO_THREAD_unlock(store.lock);
{$IFNDEF FIPS_MODULE}
        if (prov.ischild > 0)  and  (upcalls > 0) then
           ossl_provider_free_parent(prov, 1);
{$ENDIF}
        Exit(-1);
    end;
    count := PreInc(prov.activatecnt);
    prov.flag_activated := 1;
    if (prov.activatecnt = 1)  and  (store <> nil) then
    begin
        ret := create_provider_children(prov);
    end;
    if lock > 0 then
    begin
        CRYPTO_THREAD_unlock(prov.flag_lock);
        CRYPTO_THREAD_unlock(store.lock);
    end;
    if 0>= ret then
       Exit(-1);
    Result := count;
end;

function provider_init( prov : POSSL_PROVIDER):integer;
var
    provider_dispatch    : POSSL_DISPATCH;
    tmp_provctx          : Pointer;
    p_get_reason_strings : TOSSL_FUNC_provider_get_reason_strings_fn;
    ok                   : integer;
    allocated_path,
    module_path,
    merged_path,
    load_dir,
    allocated_load_dir   : PUTF8Char;
    store                : Pprovider_store_st;
    reasonstrings        : POSSL_ITEM;
    cnt,
    cnt2                 : size_t;
    label _end;
begin
{$POINTERMATH ON}
    provider_dispatch := nil;
    tmp_provctx := nil;
{$IFNDEF OPENSSL_NO_ERR}
{$IFNDEF FIPS_MODULE}
    p_get_reason_strings := nil;
{$ENDIF}
{$ENDIF}
    ok := 0;
    if not ossl_assert(0>= prov.flag_initialized) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto _end ;
    end;
    {
     * If the init function isn't set, it indicates that this provider is
     * a loadable module.
     }
    if not Assigned(prov.init_function) then
    begin
{$IFDEF FIPS_MODULE}
        goto _end ;
{$ELSE} if prov.module = nil then
        begin
            allocated_path := nil;
            module_path := nil;
            merged_path := nil;
            load_dir := nil;
            allocated_load_dir := nil;
            prov.module := DSO_new();
            if prov.module = nil then
            begin
                { DSO_new() generates an error already }
                goto _end ;
            end;
            store := get_provider_store(prov.libctx);
            if (store = nil)
                     or  (0>= CRYPTO_THREAD_read_lock(store.default_path_lock)) then
                goto _end ;
            if store.default_path <> nil then
            begin
                OPENSSL_strdup(allocated_load_dir ,store.default_path);
                CRYPTO_THREAD_unlock(store.default_path_lock);
                if allocated_load_dir = nil then begin
                    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
                    goto _end ;
                end;
                load_dir := allocated_load_dir;
            end
            else
            begin
                CRYPTO_THREAD_unlock(store.default_path_lock);
            end;
            if load_dir = nil then
            begin
                load_dir := ossl_safe_getenv('OPENSSL_MODULES');
                if load_dir = nil then
                   load_dir := MODULESDIR;
            end;
            DSO_ctrl(prov.module, DSO_CTRL_SET_FLAGS,
                     DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, nil);
            module_path := prov.path;
            if module_path = nil then
            begin
              allocated_path := DSO_convert_filename(prov.module, prov.name);
              module_path := allocated_path;
            end;
            if module_path <> nil then
               merged_path := DSO_merge(prov.module, module_path, load_dir);
            if (merged_path = nil)
                 or  (DSO_load(prov.module, merged_path, nil, 0) = nil) then
            begin
                DSO_free(prov.module);
                prov.module := nil;
            end;
            OPENSSL_free(merged_path);
            OPENSSL_free(allocated_path);
            OPENSSL_free(allocated_load_dir);
        end;
        if prov.module <> nil then
           prov.init_function := POSSL_provider_init_fn(
                @DSO_bind_func(prov.module, 'OSSL_provider_init'))^;
{$ENDIF}
    end;
    { Call the initialise function for the provider. }
    if (not Assigned(prov.init_function))  or
       (0 >= prov.init_function(POSSL_CORE_HANDLE(prov), core_dispatch,
                                provider_dispatch, @tmp_provctx)) then
    begin
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL, Format('name=%s', [prov.name]));
        goto _end ;
    end;
    prov.provctx := tmp_provctx;
    prov.dispatch := provider_dispatch;
    while provider_dispatch.function_id <> 0 do
    begin
        case provider_dispatch.function_id of
        OSSL_FUNC_PROVIDER_TEARDOWN:
            prov.teardown := _OSSL_FUNC_provider_teardown(provider_dispatch);
            //break;
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS:
            prov.gettable_params := _OSSL_FUNC_provider_gettable_params(provider_dispatch);
            //break;
        OSSL_FUNC_PROVIDER_GET_PARAMS:
            prov.get_params := _OSSL_FUNC_provider_get_params(provider_dispatch);
            //break;
        OSSL_FUNC_PROVIDER_SELF_TEST:
            prov.self_test := _OSSL_FUNC_provider_self_test(provider_dispatch);
            //break;
        OSSL_FUNC_PROVIDER_GET_CAPABILITIES:
            prov.get_capabilities := _OSSL_FUNC_provider_get_capabilities(provider_dispatch);
            //break;
        OSSL_FUNC_PROVIDER_QUERY_OPERATION:
            prov.query_operation := _OSSL_FUNC_provider_query_operation(provider_dispatch);
            //break;
        OSSL_FUNC_PROVIDER_UNQUERY_OPERATION:
            prov.unquery_operation := _OSSL_FUNC_provider_unquery_operation(provider_dispatch);
            //break;
{$IFNDEF OPENSSL_NO_ERR}
{$IFNDEF FIPS_MODULE}
        OSSL_FUNC_PROVIDER_GET_REASON_STRINGS:
            p_get_reason_strings := _OSSL_FUNC_provider_get_reason_strings(provider_dispatch);
            //break;
{$ENDIF}
{$ENDIF}
        end;
        Inc(provider_dispatch);
    end;
{$IFNDEF OPENSSL_NO_ERR}
{$IFNDEF FIPS_MODULE}
    if Assigned(p_get_reason_strings) then
    begin
        reasonstrings := p_get_reason_strings(prov.provctx);
        {
         * ERR_load_strings() handles ERR_STRING_DATA rather than OSSL_ITEM,
         * although they are essentially the same type.
         * Furthermore, ERR_load_strings() patches the array's error number
         * with the error library number, so we need to make a copy of that
         * array either way.
         }
        cnt := 0;
        while reasonstrings[cnt].id <> 0 do
        begin
            if ERR_GET_LIB(reasonstrings[cnt].id) <> 0  then
                goto _end ;
            PostInc(cnt);
        end;
        PostInc(cnt);                   { One for the terminating item }
        { Allocate one extra item for the 'library' name }
        prov.error_strings := OPENSSL_zalloc(sizeof(TERR_STRING_DATA) * (cnt + 1));
        if prov.error_strings = nil then goto _end ;
        {
         * Set the 'library' name.
         }
        prov.error_strings[0].error := ERR_PACK(prov.error_lib, 0, 0);
        prov.error_strings[0]._string := prov.name;
        {
         * Copy reasonstrings item 0..cnt-1 to prov.error_trings positions
         * 1..cnt.
         }
        for cnt2 := 1 to cnt do begin
            prov.error_strings[cnt2].error := int (reasonstrings[cnt2-1].id);
            prov.error_strings[cnt2]._string := reasonstrings[cnt2-1].ptr;
        end;
        _ERR_load_strings(prov.error_lib, prov.error_strings);
    end;
{$ENDIF}
{$ENDIF}
    { With this flag set, this provider has become fully 'loaded'. }
    prov.flag_initialized := 1;
    ok := 1;
 _end:
    Result := ok;
 {$POINTERMATH OFF}
end;



function ossl_provider_new(libctx : POSSL_LIB_CTX;const name : PUTF8Char;init_function : TOSSL_provider_init_fn; noconfig : integer):POSSL_PROVIDER;
var
    store    : Pprovider_store_st;
    template : TOSSL_PROVIDER_INFO;
    i        : size_t;
    p: POSSL_PROVIDER_INFO;
begin
    store := nil;
    Result := nil;
    store := get_provider_store(libctx);
    if store = nil then
        Exit(nil);
    //memset(@template, 0, sizeof(template));
    FillChar(template, sizeof(template), 0);
    if not Assigned(init_function) then
    begin
        { Check if this is a predefined builtin provider }
        p := @ossl_predefined_providers;
        while p.name <> nil do
        begin
            if strcmp(p.name, name) = 0  then
            begin
                template := p^;
                break;
            end;
            Inc(p);
        end;
        if p.name = nil then begin
            { Check if this is a user added builtin provider }
            if 0>= CRYPTO_THREAD_read_lock(store.lock) then
                Exit(nil);
            i := 0; p := store.provinfo;
            while i < store.numprovinfo do
            begin
                if strcmp(p.name, name) = 0  then
                begin
                    template := p^;
                    break;
                end;
                 Inc(p); PostInc(i);
            end;
            CRYPTO_THREAD_unlock(store.lock);
        end;
    end
    else begin
        template.init := init_function;
    end;
    { provider_new() generates an error, so no need here }
    Result := provider_new(name, template.init, template.parameters);
    if Result = nil then
        Exit(nil);
    Result.libctx := libctx;
{$IFNDEF FIPS_MODULE}
    Result.error_lib := ERR_get_next_error_library();
{$ENDIF}
    {
     * At this point, the provider is only partially 'loaded'.  To be
     * fully 'loaded', ossl_provider_activate() must also be called and it must
     * then be added to the provider store.
     }

end;

function ossl_provider_find(libctx : POSSL_LIB_CTX;const name : PUTF8Char; noconfig : integer):POSSL_PROVIDER;
var
  store : Pprovider_store_st;
  prov : POSSL_PROVIDER;
  tmpl : TOSSL_PROVIDER;
  i : integer;
begin
    store := nil;
    prov := nil;
    store := get_provider_store(libctx);
    if store  <> nil then
    begin
        tmpl := default(TOSSL_PROVIDER);
{$IFNDEF FIPS_MODULE}
        {
         * Make sure any providers are loaded from config before we try to find
         * them.
         }
        if 0>= noconfig then
        begin
            if ossl_lib_ctx_is_default(libctx) > 0 then
                OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil);
        end;
{$ENDIF}
        tmpl.name := name;
        {
         * A 'find' operation can sort the stack, and therefore a write lock is
         * required.
         }
        if 0>= CRYPTO_THREAD_write_lock(store.lock) then
            Exit(nil);
        i := sk_OSSL_PROVIDER_find(store.providers, @tmpl);
        if i <> -1 then
            prov := sk_OSSL_PROVIDER_value(store.providers, i);
        CRYPTO_THREAD_unlock(store.lock);
        if (prov <> nil)  and  (0>= ossl_provider_up_ref(prov)) then
            prov := nil;
    end;
    Result := prov;
end;

function ossl_provider_up_ref( prov : POSSL_PROVIDER):integer;
var
  ref : integer;
begin
    ref := 0;
    if CRYPTO_UP_REF(prov.refcnt, ref, prov.refcnt_lock) <= 0   then
        Exit(0);
{$IFNDEF FIPS_MODULE}
    if prov.ischild > 0 then
    begin
        if  0>= ossl_provider_up_ref_parent(prov, 0) then  begin
            ossl_provider_free(prov);
            Exit(0);
        end;
    end;
{$ENDIF}
    Result := ref;
end;



procedure ossl_provider_unquery_operation(const prov : POSSL_PROVIDER; operation_id : integer;const algs : POSSL_ALGORITHM);
begin
    if Assigned(prov.unquery_operation) then
       prov.unquery_operation(prov.provctx, operation_id, algs);
end;

function ossl_provider_query_operation(const prov : POSSL_PROVIDER; operation_id : integer;var no_cache : Integer):POSSL_ALGORITHM;
begin
    if not Assigned(prov.query_operation) then
       Exit(nil);
    Result := prov.query_operation(prov.provctx, operation_id, no_cache); //openssl3.crypto.provider.defltprov.deflt_query
{$IF defined(OPENSSL_NO_CACHED_FETCH)}
    { Forcing the non-caching of queries }
    if no_cache <> nil then *no_cache = 1;
{$ENDIF}

end;

function provider_activate_fallbacks( store : Pprovider_store_st):integer;
var
  use_fallbacks,
  activated_fallback_count,
  ret                      : integer;
  prov                     : POSSL_PROVIDER;
  p: POSSL_PROVIDER_INFO;
  label err;

begin
    activated_fallback_count := 0;
    ret := 0;
    if  0>= CRYPTO_THREAD_read_lock(store.lock) then
        Exit(0);
    use_fallbacks := store.use_fallbacks;
    CRYPTO_THREAD_unlock(store.lock);
    if  0>= use_fallbacks then Exit(1);
    if  0>= CRYPTO_THREAD_write_lock(store.lock) then
        Exit(0);
    { Check again, just in case another thread changed it }
    use_fallbacks := store.use_fallbacks;
    if 0>= use_fallbacks then
    begin
        CRYPTO_THREAD_unlock(store.lock);
        Exit(1);
    end;

    p := @ossl_predefined_providers;
    while ( p.name <> nil) do
    begin
        prov := nil;
        if  0>=p.is_fallback then
        begin
           Inc(p);
           continue;
        end;
        {
         * We use the internal constructor directly here,
         * otherwise we get a call loop
         }
        prov := provider_new(p.name, p.init, nil);
        if prov = nil then
           goto err;
        prov.libctx := store.libctx;
{$IFNDEF FIPS_MODULE}
        prov.error_lib := ERR_get_next_error_library();
{$ENDIF}
        {
         * We are calling provider_activate while holding the store lock. This
         * means the init function will be called while holding a lock. Normally
         * we try to avoid calling a user callback while holding a lock.
         * However, fallbacks are never third party providers so we accept this.
         }
        if provider_activate(prov, 0, 0) < 0then
        begin
            ossl_provider_free(prov);
            goto err;
        end;
        prov.store := store;
        if sk_OSSL_PROVIDER_push(store.providers, prov)= 0 then
        begin
            ossl_provider_free(prov);
            goto err;
        end;
        Inc(activated_fallback_count);
        Inc(p);
    end;
    if activated_fallback_count > 0 then
    begin
        store.use_fallbacks := 0;
        ret := 1;
    end;
 err:
    CRYPTO_THREAD_unlock(store.lock);
    Result := ret;
end;

function ossl_provider_doall_activated( ctx : POSSL_LIB_CTX; cb : Tcb_func; cbdata : Pointer):integer;
var
    ret,
    curr, max, ref        : integer;
    store      : Pprovider_store_st;
    prov       : POSSL_PROVIDER;
    provs     : Pstack_st_OSSL_PROVIDER;
    label  _err_unlock, _finish;
begin
    ret := 0; ref := 0;
    store := get_provider_store(ctx);
    provs := nil;
{$IFNDEF FIPS_MODULE}
    {
     * Make sure any providers are loaded from config before we try to use
     * them.
     }
    if ossl_lib_ctx_is_default(ctx ) >0 then
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil);
{$ENDIF}
    if store = nil then Exit(1);
    if  0 >=provider_activate_fallbacks(store)   then
        Exit(0);
    {
     * Under lock, grab a copy of the provider list and up_ref each
     * provider so that they don't disappear underneath us.
     }
    if  0>= CRYPTO_THREAD_read_lock(store.lock)  then
        Exit(0);
    provs := sk_OSSL_PROVIDER_dup(store.providers);
    if provs = nil then
    begin
        CRYPTO_THREAD_unlock(store.lock);
        Exit(0);
    end;
    max := sk_OSSL_PROVIDER_num(provs);
    {
     * We work backwards through the stack so that we can safely delete items
     * as we go.
     }
    for curr := max - 1 downto 0 do
    begin
        prov := sk_OSSL_PROVIDER_value(provs, curr);
        if  0>= CRYPTO_THREAD_write_lock(prov.flag_lock) then
             goto _err_unlock;
        if prov.flag_activated > 0 then
        begin
            {
             * We call CRYPTO_UP_REF directly rather than ossl_provider_up_ref
             * to avoid upping the ref count on the parent provider, which we
             * must not do while holding locks.
             }
            if CRYPTO_UP_REF(prov.refcnt, ref, prov.refcnt_lock) <= 0 then
            begin
                CRYPTO_THREAD_unlock(prov.flag_lock);
                goto _err_unlock;
            end;
            {
             * It's already activated, but we up the activated count to ensure
             * it remains activated until after we've called the user callback.
             * We do this with no locking (because we already hold the locks)
             * and no upcalls (which must not be called when locks are held). In
             * theory this could mean the parent provider goes inactive, whilst
             * still activated in the child for a short period. That's ok.
             }
            if provider_activate(prov, 0, 0) < 0  then
            begin
                CRYPTO_DOWN_REF(prov.refcnt, ref, prov.refcnt_lock);
                CRYPTO_THREAD_unlock(prov.flag_lock);
                goto _err_unlock;
            end;
        end
        else
        begin
            sk_OSSL_PROVIDER_delete(provs, curr);
            Dec(max);
        end;
        CRYPTO_THREAD_unlock(prov.flag_lock);
    end;
    CRYPTO_THREAD_unlock(store.lock);
    {
     * Now, we sweep through all providers not under lock
     }
    for curr := 0 to max-1 do
    begin
        prov := sk_OSSL_PROVIDER_value(provs, curr);
        //openssl3.crypto.core_algorithm.algorithm_do_this
        if  0>= cb(prov, cbdata) then
            goto _finish;
    end;
    curr := -1;
    ret := 1;
    goto _finish;

 _err_unlock:
    CRYPTO_THREAD_unlock(store.lock);

 _finish:
    {
     * The pop_free call doesn't do what we want on an error condition. We
     * either start from the first item in the stack, or part way through if
     * we only processed some of the items.
     }
    Inc(curr);
    while curr < max do
    begin
        prov := sk_OSSL_PROVIDER_value(provs, curr);
        provider_deactivate(prov, 0, 1);
        {
         * As above where we did the up-ref, we don't call ossl_provider_free
         * to avoid making upcalls. There should always be at least one ref
         * to the provider in the store, so this should never drop to 0.
         }
        CRYPTO_DOWN_REF(prov.refcnt, ref, prov.refcnt_lock);
        {
         * Not much we can do if this assert ever fails. So we don't use
         * ossl_assert here.
         }
        assert(ref > 0);
        Inc(curr);
    end;
    sk_OSSL_PROVIDER_free(provs);
    Result := ret;
end;

function ossl_provider_cmp(const a, b : PPOSSL_PROVIDER):integer;
begin
    Result := strcmp(( a^).name, ( b^).name);
end;

procedure ossl_provider_info_clear( info : POSSL_PROVIDER_INFO);
begin
    if info = nil then
       Exit;
    OPENSSL_free(info.name);
    OPENSSL_free(info.path);
    sk_INFOPAIR_pop_free(info.parameters, infopair_free);
end;

procedure ossl_provider_child_cb_free( cb : POSSL_PROVIDER_CHILD_CB);
begin
    OPENSSL_free(cb);
end;

procedure infopair_free( pair : PINFOPAIR);
begin
    OPENSSL_free(pair.name);
    OPENSSL_free(pair.value);
    OPENSSL_free(pair);
end;
function sk_INFOPAIR_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_INFOPAIR_value( sk : Pointer; idx: integer):PINFOPAIR;
begin
   Result := PINFOPAIR(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_INFOPAIR_new( cmp : sk_INFOPAIR_compfunc):PSTACK_st_INFOPAIR;
begin
   Result := PSTACK_st_INFOPAIR (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_INFOPAIR_new_null:PSTACK_st_INFOPAIR;
begin
   Result := PSTACK_st_INFOPAIR (OPENSSL_sk_new_null())
end;


function sk_INFOPAIR_new_reserve( cmp : sk_INFOPAIR_compfunc; n : integer):PSTACK_st_INFOPAIR;
begin
   Result := PSTACK_st_INFOPAIR (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_INFOPAIR_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_INFOPAIR_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_INFOPAIR_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_INFOPAIR_delete( sk : Pointer; i : integer):PINFOPAIR;
begin
   Result := PINFOPAIR(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_INFOPAIR_delete_ptr( sk, ptr : Pointer):PINFOPAIR;
begin
   Result := PINFOPAIR(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_INFOPAIR_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_INFOPAIR_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_INFOPAIR_pop( sk : Pointer):PINFOPAIR;
begin
   Result := PINFOPAIR(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_INFOPAIR_shift( sk : Pointer):PINFOPAIR;
begin
   Result := PINFOPAIR(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_INFOPAIR_pop_free( sk : Pointer; freefunc : sk_INFOPAIR_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_INFOPAIR_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_INFOPAIR_set( sk : Pointer; idx : integer; ptr : Pointer):PINFOPAIR;
begin
   Result := PINFOPAIR(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_INFOPAIR_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_INFOPAIR_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_INFOPAIR_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_INFOPAIR_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_INFOPAIR_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_INFOPAIR_dup( sk : Pointer):PSTACK_st_INFOPAIR;
begin
   Result := PSTACK_st_INFOPAIR (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_INFOPAIR_deep_copy( sk : Pointer; copyfunc : sk_INFOPAIR_copyfunc; freefunc : sk_INFOPAIR_freefunc):PSTACK_st_INFOPAIR;
begin
   Result := (OPENSSL_sk_deep_copy(sk, OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_INFOPAIR_set_cmp_func( sk : Pointer; cmp : sk_INFOPAIR_compfunc):sk_INFOPAIR_compfunc;
begin
   Result := sk_INFOPAIR_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;
procedure ossl_provider_teardown(const prov : POSSL_PROVIDER);
begin
    if ( Assigned(prov.teardown) )
{$IFNDEF FIPS_MODULE}
             and   (0>= prov.ischild)
{$ENDIF}
        then prov.teardown(prov.provctx);
end;

procedure ossl_provider_free( prov : POSSL_PROVIDER);
var
  ref : integer;
begin
    if prov <> nil then
    begin
        ref := 0;
        CRYPTO_DOWN_REF(prov.refcnt, ref, prov.refcnt_lock);
        {
         * When the refcount drops to zero, we clean up the provider.
         * Note that this also does teardown, which may seem late,
         * considering that init happens on first activation.  However,
         * there may be other structures hanging on to the provider after
         * the last deactivation and may therefore need full access to the
         * provider's services.  Therefore, we deinit late.
         }
        if ref = 0 then
        begin
            if prov.flag_initialized >0 then
            begin
                ossl_provider_teardown(prov);
{$IFNDEF OPENSSL_NO_ERR}
{$ifndef FIPS_MODULE}
                if prov.error_strings <> nil then
                begin
                    ERR_unload_strings(prov.error_lib, prov.error_strings);
                    OPENSSL_free(prov.error_strings);
                    prov.error_strings := nil;
                end;
{$endif}
{$ENDIF}
                OPENSSL_free(prov.operation_bits);
                prov.operation_bits := nil;
                prov.operation_bits_sz := 0;
                prov.flag_initialized := 0;
            end;
{$IFNDEF FIPS_MODULE}
            {
             * We deregister thread handling whether or not the provider was
             * initialized. If init was attempted but was not successful then
             * the provider may still have registered a thread handler.
             }
            ossl_init_thread_deregister(prov);
            DSO_free(prov.module);
{$ENDIF}
            OPENSSL_free(prov.name);
            OPENSSL_free(prov.path);
            sk_INFOPAIR_pop_free(prov.parameters, infopair_free);
            CRYPTO_THREAD_lock_free(prov.opbits_lock);
            CRYPTO_THREAD_lock_free(prov.flag_lock);
{$IFNDEF HAVE_ATOMICS}
            CRYPTO_THREAD_lock_free(prov.refcnt_lock);
{$ENDIF}
            OPENSSL_free(prov);
        end
{$IFNDEF FIPS_MODULE}
        else
        if (prov.ischild>0) then
        begin
            ossl_provider_free_parent(prov, 0);
        end;
{$ENDIF}
    end;
end;

function provider_flush_store_cache(const prov : POSSL_PROVIDER):integer;
var
  store : Pprovider_store_st;
  freeing : integer;
begin
    store := get_provider_store(prov.libctx );
    if store  = nil then
        Exit(0);
    if  0>= CRYPTO_THREAD_read_lock(store.lock) then
        Exit(0);
    freeing := store.freeing;
    CRYPTO_THREAD_unlock(store.lock);
    if 0>= freeing then
       Exit(evp_method_store_flush(prov.libctx));
    Result := 1;
end;

function ossl_provider_get_parent( prov : POSSL_PROVIDER):POSSL_CORE_HANDLE;
begin
    Result := prov.handle;
end;

function sk_OSSL_PROVIDER_CHILD_CB_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_CHILD_CB_value( sk : Pointer; idx: integer):POSSL_PROVIDER_CHILD_CB;
begin
   Result := POSSL_PROVIDER_CHILD_CB(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_new( cmp : sk_OSSL_PROVIDER_CHILD_CB_compfunc):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
begin
   Result := PSTACK_st_OSSL_PROVIDER_CHILD_CB (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_new_null:PSTACK_st_OSSL_PROVIDER_CHILD_CB;
begin
   Result := PSTACK_st_OSSL_PROVIDER_CHILD_CB (OPENSSL_sk_new_null())
end;


function sk_OSSL_PROVIDER_CHILD_CB_new_reserve( cmp : sk_OSSL_PROVIDER_CHILD_CB_compfunc; n : integer):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
begin
   Result := PSTACK_st_OSSL_PROVIDER_CHILD_CB (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_OSSL_PROVIDER_CHILD_CB_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_OSSL_PROVIDER_CHILD_CB_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_CHILD_CB_delete( sk : Pointer; i : integer):POSSL_PROVIDER_CHILD_CB;
begin
   Result := POSSL_PROVIDER_CHILD_CB(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_delete_ptr( sk, ptr : Pointer):POSSL_PROVIDER_CHILD_CB;
begin
   Result := POSSL_PROVIDER_CHILD_CB(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_CHILD_CB_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_CHILD_CB_pop( sk : Pointer):POSSL_PROVIDER_CHILD_CB;
begin
   Result := POSSL_PROVIDER_CHILD_CB(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_shift( sk : Pointer):POSSL_PROVIDER_CHILD_CB;
begin
   Result := POSSL_PROVIDER_CHILD_CB(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_OSSL_PROVIDER_CHILD_CB_pop_free( sk : Pointer; freefunc : sk_OSSL_PROVIDER_CHILD_CB_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_OSSL_PROVIDER_CHILD_CB_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_OSSL_PROVIDER_CHILD_CB_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PROVIDER_CHILD_CB;
begin
   Result := POSSL_PROVIDER_CHILD_CB(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_CHILD_CB_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_CHILD_CB_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_OSSL_PROVIDER_CHILD_CB_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_CHILD_CB_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_CHILD_CB_dup( sk : Pointer):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
begin
   Result := PSTACK_st_OSSL_PROVIDER_CHILD_CB (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PROVIDER_CHILD_CB_copyfunc; freefunc : sk_OSSL_PROVIDER_CHILD_CB_freefunc):PSTACK_st_OSSL_PROVIDER_CHILD_CB;
begin
   Result := PSTACK_st_OSSL_PROVIDER_CHILD_CB (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_OSSL_PROVIDER_CHILD_CB_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PROVIDER_CHILD_CB_compfunc):sk_OSSL_PROVIDER_CHILD_CB_compfunc;
begin
   Result := sk_OSSL_PROVIDER_CHILD_CB_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;
function provider_deactivate( prov : POSSL_PROVIDER; upcalls, removechildren : integer):integer;
var
  count      : integer;
  store      : Pprovider_store_st;
  freeparent,
  lock,
  i,
  max        : integer;
  child_cb   : POSSL_PROVIDER_CHILD_CB;
begin
{$IFNDEF FIPS_MODULE}
    freeparent := 0;
{$ENDIF}
    lock := 1;
    if  not ossl_assert(prov <> nil ) then
        Exit(-1);
    {
     * No need to lock if we've got no store because we've not been shared with
     * other threads.
     }
    store := get_provider_store(prov.libctx);
    if store = nil then lock := 0;
    if (lock >0) and   (0>= CRYPTO_THREAD_read_lock(store.lock)) then
        Exit(-1);
    if (lock>0)  and   (0>= CRYPTO_THREAD_write_lock(prov.flag_lock)) then
    begin
        CRYPTO_THREAD_unlock(store.lock);
        Exit(-1);
    end;
{$IFNDEF FIPS_MODULE}
    if (prov.activatecnt >= 2)  and  (prov.ischild > 0)  and  (upcalls > 0) then
    begin
        {
         * We have had a direct activation in this child libctx so we need to
         * now down the ref count in the parent provider. We do the actual down
         * ref outside of the flag_lock, since it could involve getting other
         * locks.
         }
        freeparent := 1;
    end;
{$ENDIF}
    count := PreDec(prov.activatecnt);
    if count < 1 then
        prov.flag_activated := 0
{$IFNDEF FIPS_MODULE}
    else
        removechildren := 0;
{$ENDIF}
{$IFNDEF FIPS_MODULE}
    if (removechildren>0)  and  (store <> nil) then
    begin
        max := sk_OSSL_PROVIDER_CHILD_CB_num(store.child_cbs);
        for i := 0 to max-1 do
        begin
            child_cb := sk_OSSL_PROVIDER_CHILD_CB_value(store.child_cbs, i);
            child_cb.remove_cb(POSSL_CORE_HANDLE (prov), child_cb.cbdata);
        end;
    end;
{$ENDIF}
    if lock>0 then
    begin
        CRYPTO_THREAD_unlock(prov.flag_lock);
        CRYPTO_THREAD_unlock(store.lock);
    end;
{$IFNDEF FIPS_MODULE}
    if freeparent>0 then
       ossl_provider_free_parent(prov, 1);
{$ENDIF}
    { We don't deinit here, that's done in ossl_provider_free() }
    Result := count;
end;




function ossl_provider_deactivate( prov : POSSL_PROVIDER; removechildren : integer):integer;
var
  count : integer;
begin
    count := provider_deactivate(prov, 1, removechildren);
    if (prov = nil)
             or  ( count < 0) then
        Exit(0);
    Result := get_result(count = 0 , provider_flush_store_cache(prov) , 1);
end;

procedure provider_deactivate_free( prov : POSSL_PROVIDER);
begin
    if prov.flag_activated > 0then
       ossl_provider_deactivate(prov, 1);
    ossl_provider_free(prov);
end;

function sk_OSSL_PROVIDER_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_value( sk : Pointer; idx: integer):POSSL_PROVIDER;
begin
   Result := POSSL_PROVIDER(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_OSSL_PROVIDER_new( cmp : sk_OSSL_PROVIDER_compfunc):PSTACK_st_OSSL_PROVIDER;
begin
   Result := PSTACK_st_OSSL_PROVIDER (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_OSSL_PROVIDER_new_null:PSTACK_st_OSSL_PROVIDER;
begin
   Result := PSTACK_st_OSSL_PROVIDER (OPENSSL_sk_new_null())
end;


function sk_OSSL_PROVIDER_new_reserve( cmp : sk_OSSL_PROVIDER_compfunc; n : integer):PSTACK_st_OSSL_PROVIDER;
begin
   Result := PSTACK_st_OSSL_PROVIDER (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_OSSL_PROVIDER_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_OSSL_PROVIDER_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_OSSL_PROVIDER_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_delete( sk : Pointer; i : integer):POSSL_PROVIDER;
begin
   Result := POSSL_PROVIDER(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_OSSL_PROVIDER_delete_ptr( sk, ptr : Pointer):POSSL_PROVIDER;
begin
   Result := POSSL_PROVIDER(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_OSSL_PROVIDER_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_pop( sk : Pointer):POSSL_PROVIDER;
begin
   Result := POSSL_PROVIDER(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PROVIDER_shift( sk : Pointer):POSSL_PROVIDER;
begin
   Result := POSSL_PROVIDER(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_OSSL_PROVIDER_pop_free( sk : Pointer; freefunc : sk_OSSL_PROVIDER_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_OSSL_PROVIDER_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_OSSL_PROVIDER_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PROVIDER;
begin
   Result := POSSL_PROVIDER(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_OSSL_PROVIDER_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROVIDER_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_OSSL_PROVIDER_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROVIDER_dup( sk : Pointer):PSTACK_st_OSSL_PROVIDER;
begin
   Result := PSTACK_st_OSSL_PROVIDER (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PROVIDER_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PROVIDER_copyfunc; freefunc : sk_OSSL_PROVIDER_freefunc):PSTACK_st_OSSL_PROVIDER;
begin
   Result := PSTACK_st_OSSL_PROVIDER (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_OSSL_PROVIDER_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PROVIDER_compfunc):sk_OSSL_PROVIDER_compfunc;
begin
   Result := sk_OSSL_PROVIDER_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;

procedure provider_store_free( vstore : Pointer);
var
  store : Pprovider_store_st;
  i : size_t;
begin
{$POINTERMATH ON}
    store := vstore;
    if store = nil then exit;
    store.freeing := 1;
    OPENSSL_free(store.default_path);
    sk_OSSL_PROVIDER_pop_free(store.providers, provider_deactivate_free);
{$IFNDEF FIPS_MODULE}
    sk_OSSL_PROVIDER_CHILD_CB_pop_free(store.child_cbs,
                                       ossl_provider_child_cb_free);
{$ENDIF}
    CRYPTO_THREAD_lock_free(store.default_path_lock);
    CRYPTO_THREAD_lock_free(store.lock);
    if store.numprovinfo > 0 then
       for i := 0 to store.numprovinfo-1 do
          ossl_provider_info_clear(@store.provinfo[i]);
    OPENSSL_free(store.provinfo);
    OPENSSL_free(store);
{$POINTERMATH OFF}
end;

function provider_store_new( ctx : POSSL_LIB_CTX):Pointer;
var
  store : Pprovider_store_st;
begin
    store := OPENSSL_zalloc(sizeof( store^));
    store.providers := sk_OSSL_PROVIDER_new(ossl_provider_cmp);
    store.default_path_lock := CRYPTO_THREAD_lock_new();
    store.child_cbs := sk_OSSL_PROVIDER_CHILD_CB_new_null();
    store.lock := CRYPTO_THREAD_lock_new();
    if (store = nil)
         or  (store.providers = nil )
         or  (store.default_path_lock = nil )
{$IFNDEF FIPS_MODULE}
         or  (store.child_cbs =  nil )
{$ENDIF}
         or  (store.lock = nil) then
    begin
        provider_store_free(store);
        Exit(nil);
    end;
    store.libctx := ctx;
    store.use_fallbacks := 1;
    Result := store;
end;


function get_provider_store( libctx : POSSL_LIB_CTX):Pprovider_store_st;
var
  store : Pprovider_store_st;
begin
    store := nil;
    store := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_PROVIDER_STORE_INDEX,
                                  @provider_store_method);
    if store = nil then ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    Result := store;
end;

function ossl_provider_clear_all_operation_bits( libctx : POSSL_LIB_CTX):integer;
var
  store    : Pprovider_store_st;
  provider : POSSL_PROVIDER;
  i,
  num,
  res      : integer;
begin
    res := 1;
    store := get_provider_store(libctx );
    if store  <> nil then
    begin
        if  0>= CRYPTO_THREAD_read_lock(store.lock) then
            Exit(0);
        num := sk_OSSL_PROVIDER_num(store.providers);
        for i := 0 to num-1 do begin
            provider := sk_OSSL_PROVIDER_value(store.providers, i);
            if  0>= CRYPTO_THREAD_write_lock(provider.opbits_lock) then
            begin
                res := 0;
                continue;
            end;
            if provider.operation_bits <> nil then
               memset(provider.operation_bits, 0, provider.operation_bits_sz);
            CRYPTO_THREAD_unlock(provider.opbits_lock);
        end;
        CRYPTO_THREAD_unlock(store.lock);
        Exit(res);
    end;
    Result := 0;
end;


function ossl_provider_ctx(const prov : POSSL_PROVIDER):Pointer;
begin
    Result := prov.provctx;
end;



function ossl_provider_libctx(const prov : POSSL_PROVIDER):POSSL_LIB_CTX;
begin
  if prov <> nil then
     Result :=  prov.libctx
  else
     Result := nil;
end;

initialization
  param_types := [
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_CORE_VERSION, OSSL_PARAM_UTF8_PTR, Nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_CORE_PROV_NAME, OSSL_PARAM_UTF8_PTR, nil, 0),
{$ifndef FIPS_MODULE}
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_CORE_MODULE_FILENAME, OSSL_PARAM_UTF8_PTR, nil, 0),
{$endif}
    OSSL_PARAM_END
];
end.
