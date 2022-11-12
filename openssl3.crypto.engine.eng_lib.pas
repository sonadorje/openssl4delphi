unit openssl3.crypto.engine.eng_lib;

interface
uses OpenSSL.Api;

procedure do_engine_lock_init_ossl_;
function do_engine_lock_init:integer;
function ENGINE_new:PENGINE;
function ENGINE_free( e : PENGINE):integer;
function engine_free_util( e : PENGINE; not_locked : integer):integer;
function ENGINE_get_id(const e : PENGINE):PUTF8Char;
procedure ENGINE_REF_PRINT(e: PENGINE; isfunct, diff: int);

 function sk_ENGINE_num(const sk : Pstack_st_ENGINE):integer;
  function sk_ENGINE_value(const sk : Pstack_st_ENGINE; idx : integer):PENGINE;
  function sk_ENGINE_new( compare : sk_ENGINE_compfunc):Pstack_st_ENGINE;
  function sk_ENGINE_new_null:Pstack_st_ENGINE;
  function sk_ENGINE_new_reserve( compare : sk_ENGINE_compfunc; n : integer):Pstack_st_ENGINE;
  function sk_ENGINE_reserve( sk : Pstack_st_ENGINE; n : integer):integer;
  procedure sk_ENGINE_free( sk : Pstack_st_ENGINE);
  procedure sk_ENGINE_zero( sk : Pstack_st_ENGINE);
  function sk_ENGINE_delete( sk : Pstack_st_ENGINE; i : integer):PENGINE;
  function sk_ENGINE_delete_ptr( sk : Pstack_st_ENGINE; ptr : PENGINE):PENGINE;
  function sk_ENGINE_push( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
  function sk_ENGINE_unshift( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
  function sk_ENGINE_pop( sk : Pstack_st_ENGINE):PENGINE;
  function sk_ENGINE_shift( sk : Pstack_st_ENGINE):PENGINE;
  procedure sk_ENGINE_pop_free( sk : Pstack_st_ENGINE; freefunc : sk_ENGINE_freefunc);
  function sk_ENGINE_insert( sk : Pstack_st_ENGINE; ptr : PENGINE; idx : integer):integer;
  function sk_ENGINE_set( sk : Pstack_st_ENGINE; idx : integer; ptr : PENGINE):PENGINE;
  function sk_ENGINE_find( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
  function sk_ENGINE_find_ex( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
  function sk_ENGINE_find_all( sk : Pstack_st_ENGINE; ptr : PENGINE; pnum : PInteger):integer;
  procedure sk_ENGINE_sort( sk : Pstack_st_ENGINE);
  function sk_ENGINE_is_sorted(const sk : Pstack_st_ENGINE):integer;
  function sk_ENGINE_dup(const sk : Pstack_st_ENGINE):Pstack_st_ENGINE;
  function sk_ENGINE_deep_copy(const sk : Pstack_st_ENGINE; copyfunc : sk_ENGINE_copyfunc; freefunc : sk_ENGINE_freefunc):Pstack_st_ENGINE;
  function sk_ENGINE_set_cmp_func( sk : Pstack_st_ENGINE; compare : sk_ENGINE_compfunc):sk_ENGINE_compfunc;
  procedure engine_cleanup_add_first( cb : TENGINE_CLEANUP_CB);
  function int_cleanup_check( create : integer):integer;

  function sk_ENGINE_CLEANUP_ITEM_num(const sk : Pstack_st_ENGINE_CLEANUP_ITEM):integer;
  function sk_ENGINE_CLEANUP_ITEM_value(const sk : Pstack_st_ENGINE_CLEANUP_ITEM; idx : integer):PENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_new( compare : sk_ENGINE_CLEANUP_ITEM_compfunc):Pstack_st_ENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_new_null:Pstack_st_ENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_new_reserve( compare : sk_ENGINE_CLEANUP_ITEM_compfunc; n : integer):Pstack_st_ENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_reserve( sk : Pstack_st_ENGINE_CLEANUP_ITEM; n : integer):integer;
  procedure sk_ENGINE_CLEANUP_ITEM_free( sk : Pstack_st_ENGINE_CLEANUP_ITEM);
  procedure sk_ENGINE_CLEANUP_ITEM_zero( sk : Pstack_st_ENGINE_CLEANUP_ITEM);
  function sk_ENGINE_CLEANUP_ITEM_delete( sk : Pstack_st_ENGINE_CLEANUP_ITEM; i : integer):PENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_delete_ptr( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_push( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
  function sk_ENGINE_CLEANUP_ITEM_unshift( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
  function sk_ENGINE_CLEANUP_ITEM_pop( sk : Pstack_st_ENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_shift( sk : Pstack_st_ENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
  procedure sk_ENGINE_CLEANUP_ITEM_pop_free( sk : Pstack_st_ENGINE_CLEANUP_ITEM; freefunc : sk_ENGINE_CLEANUP_ITEM_freefunc);
  function sk_ENGINE_CLEANUP_ITEM_insert( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM; idx : integer):integer;
  function sk_ENGINE_CLEANUP_ITEM_set( sk : Pstack_st_ENGINE_CLEANUP_ITEM; idx : integer; ptr : PENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_find( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
  function sk_ENGINE_CLEANUP_ITEM_find_ex( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
  function sk_ENGINE_CLEANUP_ITEM_find_all( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM; pnum : PInteger):integer;
  procedure sk_ENGINE_CLEANUP_ITEM_sort( sk : Pstack_st_ENGINE_CLEANUP_ITEM);
  function sk_ENGINE_CLEANUP_ITEM_is_sorted(const sk : Pstack_st_ENGINE_CLEANUP_ITEM):integer;
  function sk_ENGINE_CLEANUP_ITEM_dup(const sk : Pstack_st_ENGINE_CLEANUP_ITEM):Pstack_st_ENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_deep_copy(const sk : Pstack_st_ENGINE_CLEANUP_ITEM; copyfunc : sk_ENGINE_CLEANUP_ITEM_copyfunc; freefunc : sk_ENGINE_CLEANUP_ITEM_freefunc):Pstack_st_ENGINE_CLEANUP_ITEM;
  function sk_ENGINE_CLEANUP_ITEM_set_cmp_func( sk : Pstack_st_ENGINE_CLEANUP_ITEM; compare : sk_ENGINE_CLEANUP_ITEM_compfunc):sk_ENGINE_CLEANUP_ITEM_compfunc;
  function int_cleanup_item( cb : TENGINE_CLEANUP_CB):PENGINE_CLEANUP_ITEM;
   procedure ENGINE_load_builtin_engines;

var
   do_engine_lock_init_ossl_ret_: int = 0;
   engine_lock_init: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
   global_engine_lock: PCRYPTO_RWLOCK ;
   cleanup_stack: Pstack_st_ENGINE_CLEANUP_ITEM = nil;

procedure engine_cleanup_int;
procedure engine_cleanup_cb_free( item : PENGINE_CLEANUP_ITEM);


function ENGINE_set_id(e : PENGINE;const id : PUTF8Char):integer;
function ENGINE_set_name(e : PENGINE;const name : PUTF8Char):integer;
function ENGINE_set_destroy_function( e : PENGINE; destroy_f : TENGINE_GEN_INT_FUNC_PTR):integer;
procedure engine_cleanup_add_last( cb : TENGINE_CLEANUP_CB);
function ENGINE_set_init_function( e : PENGINE; init_f : TENGINE_GEN_INT_FUNC_PTR):integer;
function ENGINE_set_finish_function( e : PENGINE; finish_f : TENGINE_GEN_INT_FUNC_PTR):integer;
function ENGINE_set_ctrl_function( e : PENGINE; ctrl_f : TENGINE_CTRL_FUNC_PTR):integer;
function ENGINE_get_ex_data(const e : PENGINE; idx : integer):Pointer;
function ENGINE_set_ex_data( e : PENGINE; idx : integer; arg : Pointer):integer;
procedure engine_set_all_null( e : PENGINE);
function ENGINE_set_flags( e : PENGINE; flags : integer):integer;
function ENGINE_set_cmd_defns(e : PENGINE;const defns : PENGINE_CMD_DEFN):integer;

implementation




uses  openssl3.err,openssl3.crypto.mem, OpenSSL3.threads_none,
      openssl3.crypto.ex_data,  openssl3.crypto.stack,
      openssl3.crypto.init,
      openssl3.include.internal.refcount, openssl3.crypto.engine.tb_pkmeth,
      openssl3.crypto.engine.tb_asnmth, openssl3.crypto.engine.eng_list;




function ENGINE_set_cmd_defns(e : PENGINE;const defns : PENGINE_CMD_DEFN):integer;
begin
    e.cmd_defns := defns;
    Result := 1;
end;



function ENGINE_set_flags( e : PENGINE; flags : integer):integer;
begin
    e.flags := flags;
    Result := 1;
end;


procedure engine_set_all_null( e : PENGINE);
begin
    e.id := nil;
    e.name := nil;
    e.rsa_meth := nil;
    e.dsa_meth := nil;
    e.dh_meth := nil;
    e.rand_meth := nil;
    e.ciphers := nil;
    e.digests := nil;
    e.destroy := nil;
    e.init := nil;
    e.finish := nil;
    e.ctrl := nil;
    e.load_privkey := nil;
    e.load_pubkey := nil;
    e.cmd_defns := nil;
    e.flags := 0;
    e.dynamic_id := nil;
end;

function ENGINE_set_ex_data( e : PENGINE; idx : integer; arg : Pointer):integer;
begin
    Result := CRYPTO_set_ex_data(@e.ex_data, idx, arg);
end;



function ENGINE_get_ex_data(const e : PENGINE; idx : integer):Pointer;
begin
    Result := CRYPTO_get_ex_data(@e.ex_data, idx);
end;



function ENGINE_set_ctrl_function( e : PENGINE; ctrl_f : TENGINE_CTRL_FUNC_PTR):integer;
begin
    e.ctrl := ctrl_f;
    Result := 1;
end;




function ENGINE_set_finish_function( e : PENGINE; finish_f : TENGINE_GEN_INT_FUNC_PTR):integer;
begin
    e.finish := finish_f;
    Result := 1;
end;

function ENGINE_set_init_function( e : PENGINE; init_f : TENGINE_GEN_INT_FUNC_PTR):integer;
begin
    e.init := init_f;
    Result := 1;
end;


procedure engine_cleanup_add_last( cb : TENGINE_CLEANUP_CB);
var
  item : PENGINE_CLEANUP_ITEM;
begin
    if 0>=int_cleanup_check(1) then
        Exit;
    item := int_cleanup_item(cb);
    if item <> nil then begin
        if sk_ENGINE_CLEANUP_ITEM_push(cleanup_stack, item) <= 0 then
            OPENSSL_free(item);
    end;
end;



function ENGINE_set_destroy_function( e : PENGINE; destroy_f : TENGINE_GEN_INT_FUNC_PTR):integer;
begin
    e.destroy := destroy_f;
    Result := 1;
end;

function ENGINE_set_name(e : PENGINE;const name : PUTF8Char):integer;
begin
    if name = nil then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    e.name := name;
    Result := 1;
end;



function ENGINE_set_id(e : PENGINE;const id : PUTF8Char):integer;
begin
    if id = nil then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    e.id := id;
    Result := 1;
end;

procedure engine_cleanup_cb_free( item : PENGINE_CLEANUP_ITEM);
begin
    item^.cb() ;
    OPENSSL_free(item);
end;


procedure engine_cleanup_int;
begin
    if int_cleanup_check(0 )>0 then
    begin
        sk_ENGINE_CLEANUP_ITEM_pop_free(cleanup_stack,
                                        engine_cleanup_cb_free);
        cleanup_stack := nil;
    end;
    CRYPTO_THREAD_lock_free(global_engine_lock);
    global_engine_lock := nil;
end;




//位于eng_all.c 仅此函数，故合并于此文件
procedure ENGINE_load_builtin_engines;
begin
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN, nil);
end;



function int_cleanup_item( cb : TENGINE_CLEANUP_CB):PENGINE_CLEANUP_ITEM;
var
  item : PENGINE_CLEANUP_ITEM;
begin
    item := OPENSSL_malloc(sizeof(item^));
    if item = nil then  begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    item.cb := cb;
    Result := item;
end;

function sk_ENGINE_CLEANUP_ITEM_num(const sk : Pstack_st_ENGINE_CLEANUP_ITEM):integer;
begin
   Exit(OPENSSL_sk_num(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_CLEANUP_ITEM_value(const sk : Pstack_st_ENGINE_CLEANUP_ITEM; idx : integer):PENGINE_CLEANUP_ITEM;
begin
 Result := PENGINE_CLEANUP_ITEM (OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;


function sk_ENGINE_CLEANUP_ITEM_new( compare : sk_ENGINE_CLEANUP_ITEM_compfunc):Pstack_st_ENGINE_CLEANUP_ITEM;
begin
 Result := Pstack_st_ENGINE_CLEANUP_ITEM (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_ENGINE_CLEANUP_ITEM_new_null:Pstack_st_ENGINE_CLEANUP_ITEM;
begin
 Result := Pstack_st_ENGINE_CLEANUP_ITEM (OPENSSL_sk_new_null);
end;


function sk_ENGINE_CLEANUP_ITEM_new_reserve( compare : sk_ENGINE_CLEANUP_ITEM_compfunc; n : integer):Pstack_st_ENGINE_CLEANUP_ITEM;
begin
 Result := Pstack_st_ENGINE_CLEANUP_ITEM (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_ENGINE_CLEANUP_ITEM_reserve( sk : Pstack_st_ENGINE_CLEANUP_ITEM; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK(sk), n));
end;


procedure sk_ENGINE_CLEANUP_ITEM_free( sk : Pstack_st_ENGINE_CLEANUP_ITEM);
begin
 OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_ENGINE_CLEANUP_ITEM_zero( sk : Pstack_st_ENGINE_CLEANUP_ITEM);
begin
 OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;


function sk_ENGINE_CLEANUP_ITEM_delete( sk : Pstack_st_ENGINE_CLEANUP_ITEM; i : integer):PENGINE_CLEANUP_ITEM;
begin
 Result := PENGINE_CLEANUP_ITEM (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_ENGINE_CLEANUP_ITEM_delete_ptr( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
begin
 Result := PENGINE_CLEANUP_ITEM (OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_CLEANUP_ITEM_push( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_CLEANUP_ITEM_unshift( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_CLEANUP_ITEM_pop( sk : Pstack_st_ENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
begin
 Result := PENGINE_CLEANUP_ITEM (OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_CLEANUP_ITEM_shift( sk : Pstack_st_ENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
begin
 Result := PENGINE_CLEANUP_ITEM (OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;


procedure sk_ENGINE_CLEANUP_ITEM_pop_free( sk : Pstack_st_ENGINE_CLEANUP_ITEM; freefunc : sk_ENGINE_CLEANUP_ITEM_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_ENGINE_CLEANUP_ITEM_insert( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer(ptr), idx));
end;


function sk_ENGINE_CLEANUP_ITEM_set( sk : Pstack_st_ENGINE_CLEANUP_ITEM; idx : integer; ptr : PENGINE_CLEANUP_ITEM):PENGINE_CLEANUP_ITEM;
begin
 Result := PENGINE_CLEANUP_ITEM (OPENSSL_sk_set(POPENSSL_STACK(sk), idx, Pointer(ptr)));
end;


function sk_ENGINE_CLEANUP_ITEM_find( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_CLEANUP_ITEM_find_ex( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_CLEANUP_ITEM_find_all( sk : Pstack_st_ENGINE_CLEANUP_ITEM; ptr : PENGINE_CLEANUP_ITEM; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK(sk), Pointer(ptr), pnum));
end;


procedure sk_ENGINE_CLEANUP_ITEM_sort( sk : Pstack_st_ENGINE_CLEANUP_ITEM);
begin
 OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_ENGINE_CLEANUP_ITEM_is_sorted(const sk : Pstack_st_ENGINE_CLEANUP_ITEM):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_CLEANUP_ITEM_dup(const sk : Pstack_st_ENGINE_CLEANUP_ITEM):Pstack_st_ENGINE_CLEANUP_ITEM;
begin
 Result := Pstack_st_ENGINE_CLEANUP_ITEM (OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_CLEANUP_ITEM_deep_copy(const sk : Pstack_st_ENGINE_CLEANUP_ITEM; copyfunc : sk_ENGINE_CLEANUP_ITEM_copyfunc; freefunc : sk_ENGINE_CLEANUP_ITEM_freefunc):Pstack_st_ENGINE_CLEANUP_ITEM;
begin
 Result := Pstack_st_ENGINE_CLEANUP_ITEM (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
          OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)));
end;


function sk_ENGINE_CLEANUP_ITEM_set_cmp_func( sk : Pstack_st_ENGINE_CLEANUP_ITEM; compare : sk_ENGINE_CLEANUP_ITEM_compfunc):sk_ENGINE_CLEANUP_ITEM_compfunc;
begin
 Result := sk_ENGINE_CLEANUP_ITEM_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
                OPENSSL_sk_compfunc(compare)));
end;


function int_cleanup_check( create : integer):integer;
begin
    if cleanup_stack <> nil then Exit(1);
    if 0>=create then Exit(0);
    cleanup_stack := sk_ENGINE_CLEANUP_ITEM_new_null;
    Result := get_result(cleanup_stack <> nil , 1 , 0);
end;

procedure engine_cleanup_add_first( cb : TENGINE_CLEANUP_CB);
var
  item : PENGINE_CLEANUP_ITEM;
begin
    if 0>=int_cleanup_check(1) then
        exit;
    item := int_cleanup_item(cb);
    if item <> nil then
       sk_ENGINE_CLEANUP_ITEM_insert(cleanup_stack, item, 0);
end;

function sk_ENGINE_num(const sk : Pstack_st_ENGINE):integer;
begin
   Exit(OPENSSL_sk_num(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_value(const sk : Pstack_st_ENGINE; idx : integer):PENGINE;
begin
 Result := PENGINE(OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;


function sk_ENGINE_new( compare : sk_ENGINE_compfunc):Pstack_st_ENGINE;
begin
 Result := Pstack_st_ENGINE (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_ENGINE_new_null:Pstack_st_ENGINE;
begin
 Result := Pstack_st_ENGINE (OPENSSL_sk_new_null);
end;


function sk_ENGINE_new_reserve( compare : sk_ENGINE_compfunc; n : integer):Pstack_st_ENGINE;
begin
 Result := Pstack_st_ENGINE (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_ENGINE_reserve( sk : Pstack_st_ENGINE; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK(sk), n));
end;


procedure sk_ENGINE_free( sk : Pstack_st_ENGINE);
begin
 OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_ENGINE_zero( sk : Pstack_st_ENGINE);
begin
 OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;


function sk_ENGINE_delete( sk : Pstack_st_ENGINE; i : integer):PENGINE;
begin
 Result := PENGINE  (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_ENGINE_delete_ptr( sk : Pstack_st_ENGINE; ptr : PENGINE):PENGINE;
begin
 Result := PENGINE  (OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_push( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_unshift( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_pop( sk : Pstack_st_ENGINE):PENGINE;
begin
 Result := PENGINE  (OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_shift( sk : Pstack_st_ENGINE):PENGINE;
begin
 Result := PENGINE  (OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;


procedure sk_ENGINE_pop_free( sk : Pstack_st_ENGINE; freefunc : sk_ENGINE_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_ENGINE_insert( sk : Pstack_st_ENGINE; ptr : PENGINE; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer(ptr), idx));
end;


function sk_ENGINE_set( sk : Pstack_st_ENGINE; idx : integer; ptr : PENGINE):PENGINE;
begin
 Result := PENGINE(OPENSSL_sk_set(POPENSSL_STACK(sk), idx, Pointer(ptr)));
end;


function sk_ENGINE_find( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_find_ex( sk : Pstack_st_ENGINE; ptr : PENGINE):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_ENGINE_find_all( sk : Pstack_st_ENGINE; ptr : PENGINE; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK(sk), Pointer(ptr), pnum));
end;


procedure sk_ENGINE_sort( sk : Pstack_st_ENGINE);
begin
 OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_ENGINE_is_sorted(const sk : Pstack_st_ENGINE):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_dup(const sk : Pstack_st_ENGINE):Pstack_st_ENGINE;
begin
 Result := Pstack_st_ENGINE (OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;


function sk_ENGINE_deep_copy(const sk : Pstack_st_ENGINE; copyfunc : sk_ENGINE_copyfunc; freefunc : sk_ENGINE_freefunc):Pstack_st_ENGINE;
begin
 Result := Pstack_st_ENGINE (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
              OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)));
end;


function sk_ENGINE_set_cmp_func( sk : Pstack_st_ENGINE; compare : sk_ENGINE_compfunc):sk_ENGINE_compfunc;
begin
 Result := sk_ENGINE_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
                OPENSSL_sk_compfunc(compare)));
end;

procedure ENGINE_REF_PRINT(e: PENGINE; isfunct, diff: int);
begin
    {OSSL_TRACE6(ENGINE_REF_COUNT,
               'engine: %p %s from %d to %d (%s:%d)n',
               (void *)e, (isfunct ? 'funct' : 'struct'),
               ((isfunct)
                ? (e.funct_ref - (diff))
                : (e.struct_ref - (diff))),
               ((isfunct) ? e.funct_ref : e.struct_ref),
               (OPENSSL_FILE), (OPENSSL_LINE)) }
end;

function ENGINE_get_id(const e : PENGINE):PUTF8Char;
begin
    Result := e.id;
end;



function engine_free_util( e : PENGINE; not_locked : integer):integer;
var
  i : integer;
begin
    if e = nil then Exit(1);
    if not_locked > 0 then
       CRYPTO_DOWN_REF(e.struct_ref, i, global_engine_lock)
    else
    begin
        Dec(e.struct_ref);
        i := (e.struct_ref);
    end;
    //ENGINE_REF_PRINT(e, 0, -1);
    if i > 0 then Exit(1);
    REF_ASSERT_ISNT(i < 0);
    { Free up any dynamically allocated public key methods }
    engine_pkey_meths_free(e);
    engine_pkey_asn1_meths_free(e);
    {
     * Give the ENGINE a chance to do any structural cleanup corresponding to
     * allocation it did in its constructor (eg. unload error strings)
     }
    if Assigned(e.destroy) then e.destroy(e);
    engine_remove_dynamic_id(e, not_locked);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ENGINE, e, @e.ex_data);
    OPENSSL_free(e);
    Result := 1;
end;

function ENGINE_free( e : PENGINE):integer;
begin
    Result := engine_free_util(e, 1);
end;

function ENGINE_new:PENGINE;
var
  ret : PENGINE;
  ok: int;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    ok := get_result(CRYPTO_THREAD_run_once(@engine_lock_init, do_engine_lock_init_ossl_) >0, do_engine_lock_init_ossl_ret_ , 0);
    if (0>= ok) or  (ret = nil) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.struct_ref := 1;
    //ENGINE_REF_PRINT(ret, 0, 1);
    if  0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ENGINE, ret, @ret.ex_data) then
    begin
        OPENSSL_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;


procedure do_engine_lock_init_ossl_;
begin
   do_engine_lock_init_ossl_ret_ := do_engine_lock_init();
end;


function do_engine_lock_init:integer;
begin
    global_engine_lock := CRYPTO_THREAD_lock_new();
    Result := Int(global_engine_lock <> nil);
end;

end.
