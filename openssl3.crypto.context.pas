unit openssl3.crypto.context;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_lib_ctx_get_data(ctx : POSSL_LIB_CTX; index : integer;const meth : POSSL_LIB_CTX_METHOD):Pointer;
function ossl_lib_ctx_get_concrete( ctx : POSSL_LIB_CTX):POSSL_LIB_CTX;
function get_default_context:POSSL_LIB_CTX;
function get_thread_default_context:POSSL_LIB_CTX;
function context_init( ctx : POSSL_LIB_CTX):integer;
function ossl_lib_ctx_get_ex_data_global( ctx : POSSL_LIB_CTX):POSSL_EX_DATA_GLOBAL;
function ossl_lib_ctx_init_index(ctx : POSSL_LIB_CTX; static_index : integer;const meth : POSSL_LIB_CTX_METHOD):integer;

procedure ossl_lib_ctx_generic_new( parent_ign, ptr_ign : Pointer; ad : PCRYPTO_EX_DATA; index : integer; argl_ign : long; argp : Pointer);
procedure ossl_lib_ctx_generic_free( parent_ign, ptr : Pointer; ad : PCRYPTO_EX_DATA; index : integer; argl_ign : long; argp : Pointer);
function ossl_crypto_alloc_ex_data_intern( class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA; idx : integer):integer;
function ossl_lib_ctx_read_lock( ctx : POSSL_LIB_CTX):integer;
function ossl_lib_ctx_write_lock( ctx : POSSL_LIB_CTX):integer;
function ossl_lib_ctx_is_default( ctx : POSSL_LIB_CTX):integer;
function ossl_lib_ctx_get_descriptor( libctx : POSSL_LIB_CTX):PUTF8Char;
function ossl_lib_ctx_is_global_default( ctx : POSSL_LIB_CTX):integer;
procedure ossl_lib_ctx_default_deinit;
function context_deinit( ctx : POSSL_LIB_CTX):integer;
function OSSL_LIB_CTX_new:POSSL_LIB_CTX;
procedure OSSL_LIB_CTX_free( ctx : POSSL_LIB_CTX);
procedure default_context_do_init_ossl_;
function default_context_do_init:integer;



implementation


uses
   OpenSSL3.threads_none,
   openssl3.crypto.stack,                  openssl3.crypto.initthread,
   openssl3.crypto.provider_child,         openssl3.crypto.ex_data,
   openssl3.crypto.property_parse,         OpenSSL3.Err, openssl3.crypto.mem;

var
  default_context_init: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
  default_context_do_init_ossl_ret_ :int = 0;
  default_context_thread_local: CRYPTO_THREAD_LOCAL;
  default_context_int: TOSSL_LIB_CTX;

procedure default_context_do_init_ossl_;
begin
  default_context_do_init_ossl_ret_ := default_context_do_init();
end;


function default_context_do_init():integer;
begin
    Result := Int( (CRYPTO_THREAD_init_local(@default_context_thread_local, nil ) > 0)
                   and (context_init(@default_context_int) > 0) );
end;


procedure OSSL_LIB_CTX_free( ctx : POSSL_LIB_CTX);
begin
    if ossl_lib_ctx_is_default(ctx) > 0 then
        Exit;
{$IFNDEF FIPS_MODULE}
    if ctx.ischild > 0 then
       ossl_provider_deinit_child(ctx);
{$ENDIF}
    context_deinit(ctx);
    OPENSSL_free(ctx);
end;

function OSSL_LIB_CTX_new:POSSL_LIB_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(Result^));
    if (Result <> nil)  and  (0>=context_init(Result)) then
    begin
        OPENSSL_free(Result);
        Result := nil;
    end;

end;

function context_deinit( ctx : POSSL_LIB_CTX):integer;
var
  tmp, onfree : Possl_lib_ctx_onfree_list_st;
  i : integer;
begin
    if ctx = nil then Exit(1);
    ossl_ctx_thread_stop(ctx);
    onfree := ctx.onfreelist;
    while onfree <> nil do
    begin
        onfree.fn(ctx);
        tmp := onfree;
        onfree := onfree.next;
        OPENSSL_free(tmp);
    end;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_OSSL_LIB_CTX, nil, @ctx.data);
    ossl_crypto_cleanup_all_ex_data_int(ctx);
    for i := 0 to OSSL_LIB_CTX_MAX_INDEXES-1 do
        CRYPTO_THREAD_lock_free(ctx.index_locks[i]);
    CRYPTO_THREAD_lock_free(ctx.oncelock);
    CRYPTO_THREAD_lock_free(ctx.lock);
    ctx.lock := nil;
    Result := 1;
end;


procedure ossl_lib_ctx_default_deinit;
begin
    context_deinit(@default_context_int);
end;

function ossl_lib_ctx_is_global_default( ctx : POSSL_LIB_CTX):integer;
begin
{$IFNDEF FIPS_MODULE}
    if ossl_lib_ctx_get_concrete(ctx) = @default_context_int  then
        Exit(1);
{$ENDIF}
    Result := 0;
end;

function ossl_lib_ctx_get_descriptor( libctx : POSSL_LIB_CTX):PUTF8Char;
begin
{$IFDEF FIPS_MODULE}
    Exit('FIPS internal library context');
{$ELSE}
    if ossl_lib_ctx_is_global_default(libctx) > 0 then
        Exit('Global default library context');
    if ossl_lib_ctx_is_default(libctx) > 0 then
        Exit('Thread-local default library context');
    Exit('Non-default library context');
{$ENDIF}
end;

function ossl_lib_ctx_is_default( ctx : POSSL_LIB_CTX):integer;
begin
{$IFNDEF FIPS_MODULE}
    if (ctx = nil)  or  (ctx = get_default_context() )  then
        Exit(1);
{$ENDIF}
    Result := 0;
end;

function ossl_lib_ctx_write_lock( ctx : POSSL_LIB_CTX):integer;
begin
    Result := CRYPTO_THREAD_write_lock(ossl_lib_ctx_get_concrete(ctx).lock);
end;

function ossl_lib_ctx_read_lock( ctx : POSSL_LIB_CTX):integer;
begin
    Result := CRYPTO_THREAD_read_lock(ossl_lib_ctx_get_concrete(ctx).lock);
end;

function ossl_crypto_alloc_ex_data_intern( class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA; idx : integer):integer;
var
  f : PEX_CALLBACK;
  ip : PEX_CALLBACKS;
  global : POSSL_EX_DATA_GLOBAL;
begin
    global := ossl_lib_ctx_get_ex_data_global(ad.ctx);
    if global = nil then Exit(0);
    ip := get_and_lock(global, class_index);
    if ip = nil then Exit(0);
    f := sk_EX_CALLBACK_value(ip.meth, idx);
    CRYPTO_THREAD_unlock(global.ex_data_lock);
    {
     * This should end up calling CRYPTO_set_ex_data(), which allocates
     * everything necessary to support placing the new data in the right spot.
     }
    if not Assigned(f.new_func) then
       Exit(0);
    f.new_func(obj, nil, ad, idx, f.argl, f.argp);
    Result := 1;
end;

procedure ossl_lib_ctx_generic_free( parent_ign, ptr : Pointer; ad : PCRYPTO_EX_DATA; index : integer; argl_ign : long; argp : Pointer);
var
  meth : POSSL_LIB_CTX_METHOD;
begin
    meth := argp;
    meth.free_func(ptr);
end;

procedure ossl_lib_ctx_generic_new( parent_ign, ptr_ign : Pointer; ad : PCRYPTO_EX_DATA; index : integer; argl_ign : long; argp : Pointer);
var
  meth : POSSL_LIB_CTX_METHOD;
  ctx : POSSL_LIB_CTX;
  ptr : Pointer;
begin
    meth := argp;
    ctx := ossl_crypto_ex_data_get_ossl_lib_ctx(ad);
    ptr := meth.new_func(ctx);
    if ptr <> nil then
    begin
        if  0>= CRYPTO_THREAD_write_lock(ctx.lock) then
            {
             * Can't return something, so best to hope that something will
             * fail later. :(
             }
            exit;
        CRYPTO_set_ex_data(ad, index, ptr);
        CRYPTO_THREAD_unlock(ctx.lock);
    end;
end;



function ossl_lib_ctx_init_index(ctx : POSSL_LIB_CTX; static_index : integer;const meth : POSSL_LIB_CTX_METHOD):integer;
var
  idx : integer;
begin
    ctx := ossl_lib_ctx_get_concrete(ctx);
    if ctx = nil then Exit(0);
    idx := ossl_crypto_get_ex_new_index_ex(ctx, CRYPTO_EX_INDEX_OSSL_LIB_CTX, 0,
                                          meth, ossl_lib_ctx_generic_new,
                                          nil, ossl_lib_ctx_generic_free,
                                          meth.priority);
    if idx < 0 then Exit(0);
    ctx.dyn_indexes[static_index] := idx;
    Result := 1;
end;

function ossl_lib_ctx_get_ex_data_global( ctx : POSSL_LIB_CTX):POSSL_EX_DATA_GLOBAL;
begin
    ctx := ossl_lib_ctx_get_concrete(ctx);
    if ctx = nil then
       Exit(nil);
    Result := @ctx.global;
end;


function context_init( ctx : POSSL_LIB_CTX):integer;
var
  i           : size_t;
  exdata_done : integer;

  label _err;
begin
    exdata_done := 0;
    ctx.lock := CRYPTO_THREAD_lock_new();
    if ctx.lock = nil then
       Exit(0);
    ctx.oncelock := CRYPTO_THREAD_lock_new();
    if ctx.oncelock = nil then
       goto _err;

     for i := 0 to OSSL_LIB_CTX_MAX_INDEXES-1 do
     begin
        ctx.index_locks[i] := CRYPTO_THREAD_lock_new();
        ctx.dyn_indexes[i] := -1;
        if ctx.index_locks[i] = nil then
           goto _err;
     end;
    { OSSL_LIB_CTX is built on top of ex_data so we initialise that directly }
    if  0>= ossl_do_ex_data_init(ctx) then
        goto _err;
    exdata_done := 1;
    if  0>= ossl_crypto_new_ex_data_ex(ctx, CRYPTO_EX_INDEX_OSSL_LIB_CTX, nil,
                                    @ctx.data  )  then   //ctx.data.sk 在函数中设置为nil
        goto _err;
    { Everything depends on properties, so we also pre-initialise that }
    if  0>= ossl_property_parse_init(ctx) then
        goto _err;


    Exit(1);

 _err:
    if exdata_done > 0 then
       ossl_crypto_cleanup_all_ex_data_int(ctx);
    for i := 0 to OSSL_LIB_CTX_MAX_INDEXES-1 do
        CRYPTO_THREAD_lock_free(ctx.index_locks[i]);

    CRYPTO_THREAD_lock_free(ctx.oncelock);
    CRYPTO_THREAD_lock_free(ctx.lock);
    memset(ctx, 0, sizeof( ctx^));
    Result := 0;
end;


function get_thread_default_context:POSSL_LIB_CTX;
var
   ret: int;
begin
    if CRYPTO_THREAD_run_once(@default_context_init, default_context_do_init_ossl_) > 0 then
       ret := default_context_do_init_ossl_ret_
    else
       ret := 0;
    if 0 >= ret then
       Exit(nil);
    Result := CRYPTO_THREAD_get_local(@default_context_thread_local);
end;


function get_default_context:POSSL_LIB_CTX;
begin
    Result := get_thread_default_context();
    if Result = nil then
       Result := @default_context_int;
end;

function ossl_lib_ctx_get_concrete( ctx : POSSL_LIB_CTX):POSSL_LIB_CTX;
begin
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
       Exit(get_default_context());
{$ENDIF}
    Result := ctx;
end;


function ossl_lib_ctx_get_data(ctx : POSSL_LIB_CTX; index : integer;const meth : POSSL_LIB_CTX_METHOD):Pointer;
var
  dynidx, idx : integer;
  label _end ;
begin
    Result := nil;
    ctx := ossl_lib_ctx_get_concrete(ctx);
    if ctx = nil then
       Exit(nil);
    if  0>= CRYPTO_THREAD_read_lock(ctx.lock)  then
        Exit(nil);
    dynidx := ctx.dyn_indexes[index];
    CRYPTO_THREAD_unlock(ctx.lock);
    if dynidx <> -1 then
    begin
        if  0>= CRYPTO_THREAD_read_lock(ctx.index_locks[index]) then
            Exit(nil);
        if  0>= CRYPTO_THREAD_read_lock(ctx.lock) then
        begin
            CRYPTO_THREAD_unlock(ctx.index_locks[index]);
            Exit(nil);
        end;
        Result := CRYPTO_get_ex_data(@ctx.data, dynidx);
        CRYPTO_THREAD_unlock(ctx.lock);
        CRYPTO_THREAD_unlock(ctx.index_locks[index]);
        Exit;
    end;
    if  0>= CRYPTO_THREAD_write_lock(ctx.index_locks[index])  then
        Exit(nil);
    if  0>= CRYPTO_THREAD_write_lock(ctx.lock ) then  begin
        CRYPTO_THREAD_unlock(ctx.index_locks[index]);
        Exit(nil);
    end;

    dynidx := ctx.dyn_indexes[index];
    if dynidx <> -1 then
    begin
        Result := CRYPTO_get_ex_data(@ctx.data, dynidx);
        CRYPTO_THREAD_unlock(ctx.lock);
        CRYPTO_THREAD_unlock(ctx.index_locks[index]);
        Exit;
    end;
    if  0>= ossl_lib_ctx_init_index(ctx, index, meth ) then
    begin
        CRYPTO_THREAD_unlock(ctx.lock);
        CRYPTO_THREAD_unlock(ctx.index_locks[index]);
        Exit(nil);
    end;
    CRYPTO_THREAD_unlock(ctx.lock);
    {
     * The alloc call ensures there's a value there. We release the ctx.lock
     * for this, because the allocation itself may recursively call
     * ossl_lib_ctx_get_data for other indexes (never this one). The allocation
     * will itself acquire the ctx.lock when it actually comes to store the
     * allocated data (see ossl_lib_ctx_generic_new() above). We call
     * ossl_crypto_alloc_ex_data_intern() here instead of CRYPTO_alloc_ex_data().
     * They do the same thing except that the latter calls CRYPTO_get_ex_data()
     * as well - which we must not do without holding the ctx.lock.
     }

    dynidx := ctx.dyn_indexes[index];
    if ossl_crypto_alloc_ex_data_intern(CRYPTO_EX_INDEX_OSSL_LIB_CTX, nil,
                                         @ctx.data, dynidx) > 0 then
    begin
        if  0>= CRYPTO_THREAD_read_lock(ctx.lock) then
           goto _end;
        Result := CRYPTO_get_ex_data(@ctx.data, ctx.dyn_indexes[index]);
        CRYPTO_THREAD_unlock(ctx.lock);
    end;

_end:
    CRYPTO_THREAD_unlock(ctx.index_locks[index]);

end;

end.
