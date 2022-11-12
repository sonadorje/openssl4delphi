unit openssl3.crypto.initthread;

interface
uses {$IFDEF MSWINDOWS} Windows, {$ENDIF}  OpenSSL.Api;

type

  PTHREAD_EVENT_HANDLER = ^THREAD_EVENT_HANDLER;
  PPTHREAD_EVENT_HANDLER = ^PTHREAD_EVENT_HANDLER;
  PPPTHREAD_EVENT_HANDLER = ^PPTHREAD_EVENT_HANDLER;

  Tdestructor_key = record
    case Integer of
    0: (sane: long );
    1: (value: CRYPTO_THREAD_LOCAL);
  end;

  thread_event_handler_st = record
    index: Pointer;
    arg: Pointer;
    handfn: TOSSL_thread_stop_handler_fn;
    next: PTHREAD_EVENT_HANDLER;
  end;
  THREAD_EVENT_HANDLER = thread_event_handler_st;


  PGLOBAL_TEVENT_REGISTER = ^TGLOBAL_TEVENT_REGISTER;
  Pstack_st_THREAD_EVENT_HANDLER_PTR = Pointer;
  PPstack_st_THREAD_EVENT_HANDLER_PTR = ^Pstack_st_THREAD_EVENT_HANDLER_PTR;
  global_tevent_register_st = record
    skhands: Pstack_st_THREAD_EVENT_HANDLER_PTR;
    lock: PCRYPTO_RWLOCK;
  end;
  TGLOBAL_TEVENT_REGISTER = global_tevent_register_st;

  sk_THREAD_EVENT_HANDLER_PTR_compfunc = function(const a, b: PPTHREAD_EVENT_HANDLER): integer;
  sk_THREAD_EVENT_HANDLER_PTR_freefunc = procedure(a: PTHREAD_EVENT_HANDLER);
  sk_THREAD_EVENT_HANDLER_PTR_copyfunc = function(const a: PTHREAD_EVENT_HANDLER): PTHREAD_EVENT_HANDLER ;

procedure sk_THREAD_EVENT_HANDLER_PTR_free( sk : Pointer);
procedure sk_THREAD_EVENT_HANDLER_PTR_zero( sk : Pointer);
procedure sk_THREAD_EVENT_HANDLER_PTR_pop_free( sk : Pointer; freefunc : sk_THREAD_EVENT_HANDLER_PTR_freefunc);
procedure sk_THREAD_EVENT_HANDLER_PTR_sort( sk : Pointer);

function sk_THREAD_EVENT_HANDLER_PTR_num( sk : Pointer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_reserve( sk : Pointer; n: Integer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_delete( sk : Pointer; i : integer):PTHREAD_EVENT_HANDLER;
function sk_THREAD_EVENT_HANDLER_PTR_delete_ptr( sk, ptr : Pointer):PTHREAD_EVENT_HANDLER;
function sk_THREAD_EVENT_HANDLER_PTR_push( sk, ptr : Pointer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_unshift( sk, ptr : Pointer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_pop( sk : Pointer):PTHREAD_EVENT_HANDLER;
function sk_THREAD_EVENT_HANDLER_PTR_shift( sk : Pointer):PTHREAD_EVENT_HANDLER;
function sk_THREAD_EVENT_HANDLER_PTR_insert( sk, ptr : Pointer; idx : integer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_set( sk : Pointer; idx : integer; ptr : Pointer):PTHREAD_EVENT_HANDLER;
function sk_THREAD_EVENT_HANDLER_PTR_find( sk, ptr : Pointer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_find_ex( sk, ptr : Pointer):integer;

function sk_THREAD_EVENT_HANDLER_PTR_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
function sk_THREAD_EVENT_HANDLER_PTR_is_sorted( sk : Pointer):integer;
function sk_THREAD_EVENT_HANDLER_PTR_dup( sk : Pointer):PSTACK_st_THREAD_EVENT_HANDLER_PTR;
function sk_THREAD_EVENT_HANDLER_PTR_deep_copy( sk : Pointer; copyfunc : sk_THREAD_EVENT_HANDLER_PTR_copyfunc; freefunc : sk_THREAD_EVENT_HANDLER_PTR_freefunc):PSTACK_st_THREAD_EVENT_HANDLER_PTR;
function sk_THREAD_EVENT_HANDLER_PTR_set_cmp_func( sk : Pointer; cmp : sk_THREAD_EVENT_HANDLER_PTR_compfunc):sk_THREAD_EVENT_HANDLER_PTR_compfunc;
function sk_THREAD_EVENT_HANDLER_PTR_value(sk: Pointer; idx: integer): PPTHREAD_EVENT_HANDLER;
function sk_THREAD_EVENT_HANDLER_PTR_new_null(): PSTACK_st_THREAD_EVENT_HANDLER_PTR;
function sk_THREAD_EVENT_HANDLER_PTR_new(cmp:sk_THREAD_EVENT_HANDLER_PTR_compfunc) : PSTACK_st_THREAD_EVENT_HANDLER_PTR;

function create_global_tevent_register:integer;
function ossl_init_thread_start(const index : Pointer; arg : Pointer; handfn : TOSSL_thread_stop_handler_fn):integer;
function ossl_init_thread_deregister( index : Pointer):integer;
function init_thread_deregister( index : Pointer; all : integer):integer;
function get_global_tevent_register:PGLOBAL_TEVENT_REGISTER;
function ossl_init_thread:integer;
function init_get_thread_local( local : PCRYPTO_THREAD_LOCAL; alloc, keep : integer):PPTHREAD_EVENT_HANDLER;
function init_thread_push_handlers( hands : PPTHREAD_EVENT_HANDLER):integer;

procedure OPENSSL_thread_stop;
procedure ossl_ctx_thread_stop( ctx : POSSL_LIB_CTX);
procedure ossl_cleanup_thread;
procedure init_thread_destructor( hands : Pointer);
procedure init_thread_stop( arg : Pointer; hands : PPTHREAD_EVENT_HANDLER);
procedure init_thread_remove_handlers( handsin : PPTHREAD_EVENT_HANDLER);

var
  create_global_tevent_register_ossl_ret_ : integer = 0;
  tevent_register_runonce:CRYPTO_ONCE               = CRYPTO_ONCE_STATIC_INIT;
  destructor_key: Tdestructor_key;
  glob_tevent_reg: PGLOBAL_TEVENT_REGISTER;
  dh: THandle;

implementation

uses
   openssl3.crypto.mem, OpenSSL3.threads_none, openssl3.crypto.stack;


function create_global_tevent_register_ossl_: integer;
begin
   create_global_tevent_register_ossl_ret_ := create_global_tevent_register();
end;

procedure ossl_cleanup_thread;
begin
    init_thread_deregister(nil, 1);
    CRYPTO_THREAD_cleanup_local(@destructor_key.value);
    destructor_key.sane := -1;
end;


procedure ossl_ctx_thread_stop( ctx : POSSL_LIB_CTX);
var
  hands : PPTHREAD_EVENT_HANDLER;
begin
    if destructor_key.sane <> -1 then
    begin
         hands := init_get_thread_local(@destructor_key.value, 0, 1);
        init_thread_stop(ctx, hands);
    end;
end;

procedure OPENSSL_thread_stop;
var
  hands : PPTHREAD_EVENT_HANDLER;
begin
    if destructor_key.sane <> -1 then
    begin
        hands := init_get_thread_local(@destructor_key.value, 0, 0);
        init_thread_stop(nil, hands);
        init_thread_remove_handlers(hands);
        OPENSSL_free(Pointer(hands));
    end;
end;


procedure init_thread_remove_handlers( handsin : PPTHREAD_EVENT_HANDLER);
var
  gtr : PGLOBAL_TEVENT_REGISTER;
  i : integer;
  hands : PPTHREAD_EVENT_HANDLER;
begin
    gtr := get_global_tevent_register();
    if gtr = nil then exit;
    if 0>= CRYPTO_THREAD_write_lock(gtr.lock) then
        exit;
    for i := 0 to sk_THREAD_EVENT_HANDLER_PTR_num(gtr.skhands)-1 do
    begin
        hands := sk_THREAD_EVENT_HANDLER_PTR_value(gtr.skhands, i);
        if hands = handsin then
        begin
            sk_THREAD_EVENT_HANDLER_PTR_delete(gtr.skhands, i);
            CRYPTO_THREAD_unlock(gtr.lock);
            exit;
        end;
    end;
    CRYPTO_THREAD_unlock(gtr.lock);
    exit;
end;

procedure init_thread_stop( arg : Pointer; hands : PPTHREAD_EVENT_HANDLER);
var
  curr, prev, tmp : PTHREAD_EVENT_HANDLER;
  gtr : PGLOBAL_TEVENT_REGISTER;
begin
    prev := nil;
    { Can't do much about this }
    if hands = nil then Exit;
{$IFNDEF FIPS_MODULE}
    gtr := get_global_tevent_register();
    if (gtr = nil) then
        exit;
    if 0>= CRYPTO_THREAD_write_lock(gtr.lock) then
       Exit;
{$ENDIF}
    curr := hands^;
    while curr <> nil do
    begin
        if (arg <> nil)  and  (curr.arg <> arg) then
        begin
            prev := curr;
            curr := curr.next;
            continue;
        end;
        curr.handfn(curr.arg);
        if prev = nil then
           hands^ := curr.next
        else
            prev.next := curr.next;
        tmp := curr;
        curr := curr.next;
        OPENSSL_free(Pointer(tmp));
    end;
{$IFNDEF FIPS_MODULE}
    CRYPTO_THREAD_unlock(gtr.lock);
{$ENDIF}
end;


procedure init_thread_destructor( hands : Pointer);
begin
    init_thread_stop(nil, PPTHREAD_EVENT_HANDLER (hands));
    init_thread_remove_handlers(hands);
    OPENSSL_free(hands);
end;

function ossl_init_thread:integer;
begin
    if 0>= CRYPTO_THREAD_init_local(@destructor_key.value,
                                  init_thread_destructor) then
        Exit(0);
    Result := 1;
end;

function init_thread_deregister( index : Pointer; all : integer):integer;
var
  gtr : PGLOBAL_TEVENT_REGISTER;
  i : integer;
  hands : PPTHREAD_EVENT_HANDLER;
  curr, prev, tmp : PTHREAD_EVENT_HANDLER;
begin
    gtr := get_global_tevent_register();
    if gtr = nil then Exit(0);
    if  0>= all then
    begin
        if  0>= CRYPTO_THREAD_write_lock(gtr.lock) then
            Exit(0);
    end
    else
    begin
        glob_tevent_reg :=  nil;
    end;
    for i := 0 to sk_THREAD_EVENT_HANDLER_PTR_num(gtr.skhands)-1 do
    begin
        hands := sk_THREAD_EVENT_HANDLER_PTR_value(gtr.skhands, i);
        curr := nil;
        prev := nil;
        if hands = nil then
        begin
            if  0>= all then
                CRYPTO_THREAD_unlock(gtr.lock);
            Exit(0);
        end;
        curr := hands^;
        while curr <> nil do
        begin
            if (all>0)  or ( curr.index = index) then
            begin
                if prev <> nil then
                    prev.next := curr.next
                else
                    hands^ := curr.next;
                tmp := curr;
                curr := curr.next;
                OPENSSL_free(Pointer(tmp));
                continue;
            end;
            prev := curr;
            curr := curr.next;
        end;
        if all>0 then
           OPENSSL_free(Pointer(hands));
    end;
    if all>0 then
    begin
        CRYPTO_THREAD_lock_free(gtr.lock);
        sk_THREAD_EVENT_HANDLER_PTR_free(gtr.skhands);
        OPENSSL_free(Pointer(gtr));
    end
    else
    begin
        CRYPTO_THREAD_unlock(gtr.lock);
    end;
    Result := 1;
end;



function ossl_init_thread_deregister( index : Pointer):integer;
begin
    Result := init_thread_deregister(index, 0);
end;



function create_global_tevent_register:integer;
begin
    //dh := GlobalAlloc(GMEM_FIXED or GMEM_ZEROINIT, sizeof(TGLOBAL_TEVENT_REGISTER));
    glob_tevent_reg := OPENSSL_zalloc(sizeof(TGLOBAL_TEVENT_REGISTER));
    if glob_tevent_reg = nil then
       Exit(0);
    glob_tevent_reg.skhands := sk_THREAD_EVENT_HANDLER_PTR_new_null();
    glob_tevent_reg.lock := CRYPTO_THREAD_lock_new();
    if (glob_tevent_reg.skhands = nil)  or  (glob_tevent_reg.lock = nil) then
    begin
        sk_THREAD_EVENT_HANDLER_PTR_free(glob_tevent_reg.skhands);
        CRYPTO_THREAD_lock_free(glob_tevent_reg.lock);
        OPENSSL_free(Pointer(glob_tevent_reg));
        glob_tevent_reg := nil;
        Exit(0);
    end;
    Result := 1;
end;

function get_global_tevent_register:PGLOBAL_TEVENT_REGISTER;
begin
    if  0>= get_result(CRYPTO_THREAD_run_once(@tevent_register_runonce,
                       create_global_tevent_register_ossl_) >0,
                        create_global_tevent_register_ossl_ret_ , 0) then
        Exit(nil)
    else
       Exit(glob_tevent_reg);
end;

function init_thread_push_handlers( hands : PPTHREAD_EVENT_HANDLER):integer;
var
  ret : integer;
  gtr : PGLOBAL_TEVENT_REGISTER;
begin
    gtr := get_global_tevent_register();
    if gtr = nil then Exit(0);
    if  0>= CRYPTO_THREAD_write_lock(gtr.lock) then
        Exit(0);
    ret := int(sk_THREAD_EVENT_HANDLER_PTR_push(gtr.skhands, hands) <> 0);
    CRYPTO_THREAD_unlock(gtr.lock);
    Result := ret;
end;

function init_get_thread_local( local : PCRYPTO_THREAD_LOCAL; alloc, keep : integer):PPTHREAD_EVENT_HANDLER;
begin
    Result := CRYPTO_THREAD_get_local(local);
    if alloc > 0 then
    begin
        if Result = nil then
        begin
            Result := OPENSSL_zalloc(sizeof( Result^));
            if (Result = nil) then
                Exit(nil);
            if  0>= CRYPTO_THREAD_set_local(local, Result) then
            begin
                OPENSSL_free(Pointer(Result));
                Exit(nil);
            end;
{$IFNDEF FIPS_MODULE}
            if  0>= init_thread_push_handlers(Result) then
            begin
                CRYPTO_THREAD_set_local(local, nil);
                OPENSSL_free(Pointer(Result));
                Exit(nil);
            end;
{$ENDIF}
        end;
    end
    else
    if ( 0>= keep) then
    begin
        CRYPTO_THREAD_set_local(local, nil);
    end;

end;

function ossl_init_thread_start(const index : Pointer; arg : Pointer; handfn : TOSSL_thread_stop_handler_fn):integer;
var
  hands : PPTHREAD_EVENT_HANDLER;
  hand : PTHREAD_EVENT_HANDLER;
  ctx : POSSL_LIB_CTX;
  local : PCRYPTO_THREAD_LOCAL;
begin
{$IFDEF FIPS_MODULE}
    ctx := arg;
    {
     * In FIPS mode the list of THREAD_EVENT_HANDLERs is unique per combination
     * of OSSL_LIB_CTX and thread. This is because in FIPS mode each
     * OSSL_LIB_CTX gets informed about thread stop events individually.
     }
    PCRYPTO_THREAD_LOCAL local
        = ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_THREAD_EVENT_HANDLER_INDEX,
                                &thread_event_ossl_ctx_method);
{$ELSE}
     (* Outside of FIPS mode the list of THREAD_EVENT_HANDLERs is unique per
     * thread, but may hold multiple OSSL_LIB_CTXs. We only get told about
     * thread stop events globally, so we have to ensure all affected
     * OSSL_LIB_CTXs are informed.
     *)
    local := @destructor_key.value;
{$ENDIF}
    hands := init_get_thread_local(local, 1, 0);
    if hands = nil then Exit(0);
{$IFDEF FIPS_MODULE}
    if hands^ = nil then
    begin
        {
         * We've not yet registered any handlers for this thread. We need to get
         * libcrypto to tell us about later thread stop events. c_thread_start
         * is a callback to libcrypto defined in fipsprov.c
         }
        if  not c_thread_start(FIPS_get_core_handle(ctx then , ossl_arg_thread_stop,
                            ctx))
            Exit(0);
    end;
{$ENDIF}
    hand := OPENSSL_malloc(sizeof( hand^));
    if hand = nil then
       Exit(0);
    hand.handfn := handfn;
    hand.arg := arg;
{$IFNDEF FIPS_MODULE}
    hand.index := index;
{$ENDIF}
    hand.next := hands^;
    hands^ := hand;
    Result := 1;
end;

function sk_THREAD_EVENT_HANDLER_PTR_new(cmp:sk_THREAD_EVENT_HANDLER_PTR_compfunc): PSTACK_st_THREAD_EVENT_HANDLER_PTR;
begin
   Result := OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp));
end;

function sk_THREAD_EVENT_HANDLER_PTR_new_null(): PSTACK_st_THREAD_EVENT_HANDLER_PTR;
begin
   Result := OPENSSL_sk_new_null();
end;

function sk_THREAD_EVENT_HANDLER_PTR_value(sk: Pointer; idx: integer): PPTHREAD_EVENT_HANDLER;
begin
   Result := PPTHREAD_EVENT_HANDLER (OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;

function sk_THREAD_EVENT_HANDLER_PTR_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;


function sk_THREAD_EVENT_HANDLER_PTR_reserve( sk : Pointer; n: integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), n);
end;


procedure sk_THREAD_EVENT_HANDLER_PTR_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_THREAD_EVENT_HANDLER_PTR_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_THREAD_EVENT_HANDLER_PTR_delete( sk : Pointer; i : integer): PTHREAD_EVENT_HANDLER;
begin
  Result := PTHREAD_EVENT_HANDLER (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_THREAD_EVENT_HANDLER_PTR_delete_ptr( sk, ptr : Pointer):PTHREAD_EVENT_HANDLER;
begin
  Result := PTHREAD_EVENT_HANDLER(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), ptr));
end;


function sk_THREAD_EVENT_HANDLER_PTR_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), ptr)
end;


function sk_THREAD_EVENT_HANDLER_PTR_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), ptr)
end;


function sk_THREAD_EVENT_HANDLER_PTR_pop( sk : Pointer):PTHREAD_EVENT_HANDLER;
begin
   Result := PTHREAD_EVENT_HANDLER(OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_THREAD_EVENT_HANDLER_PTR_shift( sk : Pointer):PTHREAD_EVENT_HANDLER;
begin
  Result := PTHREAD_EVENT_HANDLER(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_THREAD_EVENT_HANDLER_PTR_pop_free( sk : Pointer; freefunc : sk_THREAD_EVENT_HANDLER_PTR_freefunc);
begin
  OPENSSL_sk_pop_free(POPENSSL_STACK(sk),  OPENSSL_sk_freefunc(freefunc)) ;
end;


function sk_THREAD_EVENT_HANDLER_PTR_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), ptr, idx)
end;


function sk_THREAD_EVENT_HANDLER_PTR_set( sk : Pointer; idx : integer; ptr : Pointer):PTHREAD_EVENT_HANDLER;
begin
  Result := PTHREAD_EVENT_HANDLER (OPENSSL_sk_set(POPENSSL_STACK(sk), idx, ptr))
end;


function sk_THREAD_EVENT_HANDLER_PTR_find( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find(POPENSSL_STACK(sk), ptr)
end;


function sk_THREAD_EVENT_HANDLER_PTR_find_ex( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), ptr)
end;


function sk_THREAD_EVENT_HANDLER_PTR_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), ptr, pnum);
end;


procedure sk_THREAD_EVENT_HANDLER_PTR_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_THREAD_EVENT_HANDLER_PTR_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk));
end;


function sk_THREAD_EVENT_HANDLER_PTR_dup( sk : Pointer):PSTACK_st_THREAD_EVENT_HANDLER_PTR;
begin
   Result := OPENSSL_sk_dup(POPENSSL_STACK(sk));
end;


function sk_THREAD_EVENT_HANDLER_PTR_deep_copy( sk : Pointer; copyfunc : sk_THREAD_EVENT_HANDLER_PTR_copyfunc; freefunc : sk_THREAD_EVENT_HANDLER_PTR_freefunc):PSTACK_st_THREAD_EVENT_HANDLER_PTR;
begin
  Result := OPENSSL_sk_deep_copy( POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc),
                                  OPENSSL_sk_freefunc(freefunc));
end;


function sk_THREAD_EVENT_HANDLER_PTR_set_cmp_func( sk : Pointer; cmp : sk_THREAD_EVENT_HANDLER_PTR_compfunc):sk_THREAD_EVENT_HANDLER_PTR_compfunc;
begin
   Result := sk_THREAD_EVENT_HANDLER_PTR_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
                                                  OPENSSL_sk_compfunc(cmp)));
end;

initialization
  destructor_key.sane := -1;
end.
