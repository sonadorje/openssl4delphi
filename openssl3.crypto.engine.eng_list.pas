unit openssl3.crypto.engine.eng_list;

interface
uses OpenSSL.Api, SysUtils;

procedure engine_remove_dynamic_id( e : PENGINE; not_locked : integer);
function ENGINE_get_first:PENGINE;
 function ENGINE_get_next( e : PENGINE):PENGINE;
function ENGINE_by_id(const id : PUTF8Char):PENGINE;
procedure engine_cpy(dest : PENGINE;const src : PENGINE);
function engine_add_dynamic_id( e : PENGINE; dynamic_id : TENGINE_DYNAMIC_ID; not_locked : integer):integer;
function ENGINE_add( e : PENGINE):integer;
function engine_list_add( e : PENGINE):integer;
procedure engine_list_cleanup;
function ENGINE_remove( e : PENGINE):integer;
function engine_list_remove( e : PENGINE):integer;

var
   engine_dyn_list_head :PENGINE = nil;
   engine_dyn_list_tail :PENGINE = nil;

   engine_list_head: PENGINE  = nil;
   engine_list_tail: PENGINE  = nil;

implementation
uses OpenSSL3.Err,
     openssl3.crypto.engine.eng_lib,     OpenSSL3.threads_none,
     openssl3.crypto.getenv,             openssl3.crypto.engine.eng_ctrl;




function engine_list_remove( e : PENGINE):integer;
var
  iterator : PENGINE;
begin
    if e = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { We need to check that e is in our linked list! }
    iterator := engine_list_head;
    while (iterator <> nil) and  (iterator <> e) do
        iterator := iterator.next;
    if iterator = nil then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ENGINE_IS_NOT_IN_LIST);
        Exit(0);
    end;
    { un-link e from the chain. }
    if e.next <> nil then e.next.prev := e.prev;
    if e.prev <> nil then e.prev.next := e.next;
    { Correct our head/tail if necessary. }
    if engine_list_head = e then engine_list_head := e.next;
    if engine_list_tail = e then engine_list_tail := e.prev;
    engine_free_util(e, 0);
    Result := 1;
end;


function ENGINE_remove( e : PENGINE):integer;
var
  to_return : integer;
begin
    to_return := 1;
    if e = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        Exit(0);
    if 0>=engine_list_remove(e) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
        to_return := 0;
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
    Result := to_return;
end;


procedure engine_list_cleanup;
var
  iterator : PENGINE;
begin
    iterator := engine_list_head;
    while iterator <> nil do
    begin
        ENGINE_remove(iterator);
        iterator := engine_list_head;
    end;
    exit;
end;



function engine_list_add( e : PENGINE):integer;
var
    conflict : integer;
    iterator : PENGINE;
begin
    conflict := 0;
    iterator := nil;
    if e = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    iterator := engine_list_head;
    while (iterator <> nil)  and  (0>=conflict) do
    begin
        conflict := int(strcmp(iterator.id, e.id) = 0);
        iterator := iterator.next;
    end;
    if conflict > 0 then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_CONFLICTING_ENGINE_ID);
        Exit(0);
    end;
    if engine_list_head = nil then
    begin
        { We are adding to an empty list. }
        if engine_list_tail <> nil then
        begin
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
            Exit(0);
        end;
        engine_list_head := e;
        e.prev := nil;
        {
         * The first time the list allocates, we should register the cleanup.
         }
        engine_cleanup_add_last(engine_list_cleanup);
    end
    else
    begin
        { We are adding to the tail of an existing list. }
        if (engine_list_tail = nil) or  (engine_list_tail.next <> nil) then
        begin
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
            Exit(0);
        end;
        engine_list_tail.next := e;
        e.prev := engine_list_tail;
    end;
    {
     * Having the engine in the list assumes a structural reference.
     }
    Inc(e.struct_ref);
    ENGINE_REF_PRINT(e, 0, 1);
    { However it came to be, e is the last item in the list. }
    engine_list_tail := e;
    e.next := nil;
    Result := 1;
end;



function ENGINE_add( e : PENGINE):integer;
var
  to_return : integer;
begin
    to_return := 1;
    if e = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (e.id = nil) or  (e.name = nil) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ID_OR_NAME_MISSING);
        Exit(0);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        Exit(0);
    if 0>=engine_list_add(e) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
        to_return := 0;
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
    Result := to_return;
end;

function engine_add_dynamic_id( e : PENGINE; dynamic_id : TENGINE_DYNAMIC_ID; not_locked : integer):integer;
var
    //result   : integer;
    iterator : PENGINE;
    label _err;
begin
    result := 0;
    iterator := nil;
    if e = nil then Exit(0);
    if (not Assigned(e.dynamic_id))  and  (not Assigned(dynamic_id)) then Exit(0);
    if (not_locked > 0) and  (0>=CRYPTO_THREAD_write_lock(global_engine_lock)) then
        Exit(0);
    if Assigned(dynamic_id) then begin
        iterator := engine_dyn_list_head;
        while iterator <> nil do  begin
            if @iterator.dynamic_id = @dynamic_id then goto _err;
            iterator := iterator.next;
        end;
        if Assigned(e.dynamic_id) then goto _err;
        e.dynamic_id := dynamic_id;
    end;
    if engine_dyn_list_head = nil then begin
        { We are adding to an empty list. }
        if engine_dyn_list_tail <> nil then
            goto _err;
        engine_dyn_list_head := e;
        e.prev_dyn := nil;
    end
    else
    begin
        { We are adding to the tail of an existing list. }
        if (engine_dyn_list_tail = nil)
             or  (engine_dyn_list_tail.next_dyn <> nil) then goto _err;
        engine_dyn_list_tail.next_dyn := e;
        e.prev_dyn := engine_dyn_list_tail;
    end;
    engine_dyn_list_tail := e;
    e.next_dyn := nil;
    result := 1;
 _err:
    if not_locked > 0 then
       CRYPTO_THREAD_unlock(global_engine_lock);
    Exit(result);
end;



procedure engine_cpy(dest : PENGINE;const src : PENGINE);
begin
    dest.id := src.id;
    dest.name := src.name;
    dest.rsa_meth := src.rsa_meth;
{$IFNDEF OPENSSL_NO_DSA}
    dest.dsa_meth := src.dsa_meth;
{$ENDIF}
{$IFNDEF OPENSSL_NO_DH}
    dest.dh_meth := src.dh_meth;
{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
    dest.ec_meth := src.ec_meth;
{$ENDIF}
    dest.rand_meth := src.rand_meth;
    dest.ciphers := src.ciphers;
    dest.digests := src.digests;
    dest.pkey_meths := src.pkey_meths;
    dest.destroy := src.destroy;
    dest.init := src.init;
    dest.finish := src.finish;
    dest.ctrl := src.ctrl;
    dest.load_privkey := src.load_privkey;
    dest.load_pubkey := src.load_pubkey;
    dest.cmd_defns := src.cmd_defns;
    dest.flags := src.flags;
    dest.dynamic_id := src.dynamic_id;
    engine_add_dynamic_id(dest, nil, 0);
end;

function ENGINE_by_id(const id : PUTF8Char):PENGINE;
var
    iterator : PENGINE;
    load_dir : PUTF8Char;
    cp       : PENGINE;
    label _notfound;
begin
    load_dir := nil;
    if id = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    ENGINE_load_builtin_engines;
    if 0 >= get_result(CRYPTO_THREAD_run_once(@engine_lock_init, do_engine_lock_init_ossl_) > 0,
                        do_engine_lock_init_ossl_ret_ , 0) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock ) then
        Exit(nil);
    iterator := engine_list_head;
    while (iterator <> nil) and  (strcmp(id, iterator.id) <> 0) do
        iterator := iterator.next;
    if iterator <> nil then begin
        {
         * We need to return a structural reference. If this is an ENGINE
         * type that returns copies, make a duplicate - otherwise increment
         * the existing ENGINE's reference count.
         }
        if iterator.flags and ENGINE_FLAGS_BY_ID_COPY > 0 then
        begin
            cp := ENGINE_new;
            if cp = nil then
               iterator := nil
            else begin
                engine_cpy(cp, iterator);
                iterator := cp;
            end;
        end
        else begin
            PostInc(iterator.struct_ref);
            ENGINE_REF_PRINT(iterator, 0, 1);
        end;
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
    if iterator <> nil then Exit(iterator);
    {
     * Prevent infinite recursion if we're looking for the dynamic engine.
     }
    if strcmp(id, 'dynamic') > 0 then
    begin
        load_dir := ossl_safe_getenv('OPENSSL_ENGINES');
        if (load_dir =  nil) then
            load_dir := ENGINESDIR;
        iterator := ENGINE_by_id('dynamic');
        if (nil =iterator)  or  (0>=ENGINE_ctrl_cmd_string(iterator, 'ID', id, 0))  or
           (0 >= ENGINE_ctrl_cmd_string(iterator, 'DIR_LOAD', '2', 0) )  or
           (0 >= ENGINE_ctrl_cmd_string(iterator, 'DIR_ADD', load_dir, 0) )  or
           (0 >= ENGINE_ctrl_cmd_string(iterator, 'LIST_ADD', '1', 0) )  or
           (0 >= ENGINE_ctrl_cmd_string(iterator, 'LOAD', nil, 0))  then
            goto _notfound;
        Exit(iterator);
    end;
 _notfound:
    ENGINE_free(iterator);
    ERR_raise_data(ERR_LIB_ENGINE, ENGINE_R_NO_SUCH_ENGINE, Format('id=%s', [id]));
    Exit(nil);
    { EEK! Experimental code ends }
end;

function ENGINE_get_next( e : PENGINE):PENGINE;
var
  ret : PENGINE;
begin
    ret := nil;
    if e = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        Exit(nil);
    ret := e.next;
    if ret <> nil then
    begin
        { Return a valid structural reference to the next PENGINE  }
        PostInc(ret.struct_ref);
        ENGINE_REF_PRINT(ret, 0, 1);
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
    { Release the structural reference to the previous PENGINE  }
    ENGINE_free(e);
    Result := ret;
end;


function ENGINE_get_first:PENGINE;
var
  ret : PENGINE;
begin
    if 0 >= get_result(CRYPTO_THREAD_run_once(@engine_lock_init, do_engine_lock_init_ossl_) > 0,
                        do_engine_lock_init_ossl_ret_ , 0) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock ) then
        Exit(nil);
    ret := engine_list_head;
    if ret <> nil then
    begin
        PostInc(ret.struct_ref);
        ENGINE_REF_PRINT(ret, 0, 1);
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
    Result := ret;
end;

procedure engine_remove_dynamic_id( e : PENGINE; not_locked : integer);
begin
    if (e = nil)  or  ( not Assigned(e.dynamic_id) ) then exit;
    if (not_locked>0)  and
       (0>= CRYPTO_THREAD_write_lock(global_engine_lock))  then
        exit;
    e.dynamic_id := nil;
    { un-link e from the chain. }
    if e.next_dyn <> nil then e.next_dyn.prev_dyn := e.prev_dyn;
    if e.prev_dyn <> nil then e.prev_dyn.next_dyn := e.next_dyn;
    { Correct our head/tail if necessary. }
    if engine_dyn_list_head = e then engine_dyn_list_head := e.next_dyn;
    if engine_dyn_list_tail = e then engine_dyn_list_tail := e.prev_dyn;
    if not_locked > 0 then
       CRYPTO_THREAD_unlock(global_engine_lock);
end;




end.
