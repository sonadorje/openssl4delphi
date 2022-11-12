unit openssl3.crypto.ex_data;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
    Tex_callback_entry = record
      excb : PEX_CALLBACK;
      index : integer;
    end;
    Pex_callback_entry = ^Tex_callback_entry;
    Tex_callback_entrys = array of Tex_callback_entry;

function ossl_do_ex_data_init( ctx : POSSL_LIB_CTX):integer;
function ossl_crypto_new_ex_data_ex( ctx : POSSL_LIB_CTX; class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA):integer;
function get_and_lock( global : POSSL_EX_DATA_GLOBAL; class_index : integer):PEX_CALLBACKS;
procedure ossl_crypto_cleanup_all_ex_data_int( ctx : POSSL_LIB_CTX);
function ossl_crypto_ex_data_get_ossl_lib_ctx(const ad : PCRYPTO_EX_DATA):POSSL_LIB_CTX;
function CRYPTO_get_ex_data(const ad : PCRYPTO_EX_DATA; idx : integer):Pointer;
function CRYPTO_set_ex_data( ad : PCRYPTO_EX_DATA; idx : integer; val : Pointer):integer;
function CRYPTO_new_ex_data( class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA):integer;
procedure CRYPTO_free_ex_data( class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA);
function ex_callback_compare(const a, b : Pex_callback_entry):longint;
function CRYPTO_dup_ex_data(class_index : integer; _to : PCRYPTO_EX_DATA;const from : PCRYPTO_EX_DATA):integer;
function CRYPTO_get_ex_new_index(class_index : integer; argl : long; argp : Pointer;new_func : TCRYPTO_EX_new; dup_func : TCRYPTO_EX_dup; free_func : TCRYPTO_EX_free):integer;
function ossl_crypto_get_ex_new_index_ex( ctx : POSSL_LIB_CTX; class_index : integer; argl : long; argp : Pointer; new_func : TCRYPTO_EX_new; dup_func : TCRYPTO_EX_dup; free_func : TCRYPTO_EX_free; priority : integer):integer;


implementation
uses
     openssl3.crypto.context, OpenSSL3.Err,  OpenSSL3.threads_none,
     openssl3.include.openssl.crypto,        openssl3.crypto.cryptlib,
     openssl3.crypto.mem,                    openssl3.crypto.stack,
     {$IFDEF MSWINDOWS}libc.win {$ENDIF}, QuickSORT;


function ossl_crypto_get_ex_new_index_ex( ctx : POSSL_LIB_CTX; class_index : integer; argl : long; argp : Pointer; new_func : TCRYPTO_EX_new; dup_func : TCRYPTO_EX_dup; free_func : TCRYPTO_EX_free; priority : integer):integer;
var
  toret, ret : integer;
  a : PEX_CALLBACK;
  ip : PEX_CALLBACKS;
  global : POSSL_EX_DATA_GLOBAL;
  label err;
begin
    toret := -1;
    global := ossl_lib_ctx_get_ex_data_global(ctx);
    if global = nil then Exit(-1);
    ip := get_and_lock(global, class_index);
    if ip = nil then Exit(-1);
    if ip.meth = nil then
    begin
        ip.meth := sk_EX_CALLBACK_new_null();
        { We push an initial value on the stack because the SSL
         * 'app_data' routines use ex_data index zero.  See RT 3710. }

        if (ip.meth = nil) or (0>=sk_EX_CALLBACK_push(ip.meth, nil) )  then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            goto err;
        end;
    end;
    a := OPENSSL_malloc(sizeof( a^));
    if a = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        goto err;
    end;
    a.argl := argl;
    a.argp := argp;
    a.new_func := new_func;
    a.dup_func := dup_func;
    a.free_func := free_func;
    a.priority := priority;
    if  0>= sk_EX_CALLBACK_push(POPENSSL_STACK(ip.meth), nil ) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(Pointer(a));
        goto err;
    end;
    toret := sk_EX_CALLBACK_num(ip.meth) - 1;
    sk_EX_CALLBACK_set(ip.meth, toret, a);
 err:
    CRYPTO_THREAD_unlock(global.ex_data_lock);
    Result := toret;
end;

function CRYPTO_get_ex_new_index(class_index : integer; argl : long; argp : Pointer;new_func : TCRYPTO_EX_new; dup_func : TCRYPTO_EX_dup; free_func : TCRYPTO_EX_free):integer;
begin
    Result := ossl_crypto_get_ex_new_index_ex(nil, class_index, argl, argp,
                                           new_func, dup_func, free_func, 0);
end;




function CRYPTO_dup_ex_data(class_index : integer; _to : PCRYPTO_EX_DATA;const from : PCRYPTO_EX_DATA):integer;
var
  mx, j, i : integer;
  ptr : Pointer;
  stack : array[0..9] of PEX_CALLBACK;
  storage : PPEX_CALLBACK;
  ip : PEX_CALLBACKS;
  toret : integer;
  global : POSSL_EX_DATA_GLOBAL;
  label _err;
begin
{$POINTERMATH ON}
    storage := nil;
    toret := 0;
    _to.ctx := from.ctx;
    if from.sk = nil then { Nothing to copy over }
        Exit(1);
    global := ossl_lib_ctx_get_ex_data_global(from.ctx);
    if global = nil then Exit(0);
    ip := get_and_lock(global, class_index);
    if ip = nil then Exit(0);
    mx := sk_EX_CALLBACK_num(ip.meth);
    j := sk_void_num(from.sk);
    if j < mx then mx := j;
    if mx > 0 then
    begin
        if mx < int(Length(stack)) then
            storage := @stack
        else
            storage := OPENSSL_malloc(sizeof( storage^) * mx);
        if storage <> nil then
           for i := 0 to mx-1 do
               storage[i] := sk_EX_CALLBACK_value(ip.meth, i);
    end;
    CRYPTO_THREAD_unlock(global.ex_data_lock);
    if mx = 0 then Exit(1);
    if storage = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    {
     * Make sure the ex_data stack is at least |mx| elements long to avoid
     * (if it does not exist CRYPTO_get_ex_data() returns nil), and assign
     * to itself. This is normally a no-op; but ensures the stack is the
     * proper size
     }
    if 0>= CRYPTO_set_ex_data(_to, mx - 1, CRYPTO_get_ex_data(_to, mx - 1 ))  then
        goto _err ;
    for i := 0 to mx-1 do
    begin
        ptr := CRYPTO_get_ex_data(from, i);
        if (storage[i] <> nil)  and  (Assigned(storage[i].dup_func)) then
           if (0>= storage[i].dup_func(_to, from, &ptr, i,
                                      storage[i].argl, storage[i].argp))then
                goto _err ;
        CRYPTO_set_ex_data(_to, i, ptr);
    end;
    toret := 1;
 _err:
    if storage <> @stack then
       OPENSSL_free(Pointer(storage));
    Result := toret;
 {$POINTERMATH OFF}
end;


function ex_callback_compare(const a, b : Pex_callback_entry):longint;
var
  ap, bp : Pex_callback_entry;
begin
    ap := Pex_callback_entry(a);
    bp := Pex_callback_entry(b);
    if ap.excb = bp.excb then Exit(0);
    if ap.excb = nil then Exit(1);
    if bp.excb = nil then Exit(-1);
    if ap.excb.priority = bp.excb.priority then Exit(0);
    Result := get_result( ap.excb.priority > bp.excb.priority , -1 , 1);
end;

type
      TCompareFunc = function(const a,b: Pex_callback_entry): Integer;

procedure qsort(var A: Pex_callback_entry; num: int; comp: TCompareFunc);
  procedure Sort(L, R: Integer);
  var
    I, J: Integer;
    Y, X: Tex_callback_entry;
  begin
  {$POINTERMATH ON}
    I:= L; J:= R; X:= A[(L+R) DIV 2];
    repeat
      while comp(@A[I], @X) < 0 do
         inc(I);

      while Comp(@X, @A[J]) < 0 do
         dec(J);

      if I <= J then
      begin
        Y:= A[I];
        A[I]:= A[J];
        A[J]:= Y;
        inc(I); dec(J);
      end;
    until I > J;
    if L < J then Sort(L,J);
    if I < R then Sort(I,R);
  {$POINTERMATH OFF}
  end;
begin
  if num <2 then
     exit;
  Sort(0, num-1);
end;

procedure CRYPTO_free_ex_data( class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA);
var
  mx, i : int;
  ip : PEX_CALLBACKS;
  ptr : Pointer;
  f : PEX_CALLBACK;
  stack : array[0..9] of Tex_callback_entry;
  storage : Pex_callback_entry;
  global : POSSL_EX_DATA_GLOBAL;
  label _err;
begin
{$POINTERMATH ON}
    storage := nil;
    for I := Low(stack) to High(stack) do
       stack[I] := default(Tex_callback_entry);

    global := ossl_lib_ctx_get_ex_data_global(ad.ctx);
    if global = nil then
       goto _err ;
    ip := get_and_lock(global, class_index);
    if ip = nil then goto _err ;
    mx := sk_EX_CALLBACK_num(ip.meth);
    if mx > 0 then
    begin
        if mx < int( Length(stack)) then
            storage := @stack
        else
            storage := OPENSSL_malloc(sizeof(storage^) * mx);
        if storage <> nil then
        for i := 0 to mx-1 do
        begin
            storage[i].excb := sk_EX_CALLBACK_value(ip.meth, i);
            storage[i].index := i;
        end;
    end;
    CRYPTO_THREAD_unlock(global.ex_data_lock);
    if storage <> nil then
    begin
        { Sort according to priority. High priority first }

        qsort(storage, mx, {sizeof( storage^),} ex_callback_compare);
        for i := 0 to mx-1 do
        begin
            f := storage[i].excb;
            if (f <> nil)  and  (Assigned(f.free_func)) then
            begin
                ptr := CRYPTO_get_ex_data(ad, storage[i].index);
                f.free_func(obj, ptr, ad, storage[i].index, f.argl, f.argp);
            end;
        end;
    end;
    if storage <> @stack then
       OPENSSL_free(storage);

 _err:
    sk_void_free(ad.sk);
    ad.sk := nil;
    ad.ctx := nil;
 {$POINTERMATH OFF}
end;


function CRYPTO_new_ex_data( class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA):integer;
begin
    Result := ossl_crypto_new_ex_data_ex(nil, class_index, obj, ad);
end;

function CRYPTO_set_ex_data( ad : PCRYPTO_EX_DATA; idx : integer; val : Pointer):integer;
var
  i : integer;
begin
    if ad.sk = nil then
    begin
        ad.sk := sk_void_new_null();
        if ad.sk = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    for i := sk_void_num(ad.sk) to idx do
    begin
        if 0>= sk_void_push(ad.sk, nil) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    if sk_void_set(ad.sk, idx, val) <> val  then
    begin
        { Probably the index is out of bounds }
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := 1;
end;

function CRYPTO_get_ex_data(const ad : PCRYPTO_EX_DATA; idx : integer):Pointer;
begin
    if (ad.sk = nil)  or  (idx >= sk_void_num(ad.sk)) then
        Exit(nil);
    Result := sk_void_value(ad.sk, idx);
end;

function ossl_crypto_ex_data_get_ossl_lib_ctx(const ad : PCRYPTO_EX_DATA):POSSL_LIB_CTX;
begin
    Result := ad.ctx;
end;

procedure cleanup_cb( funcs : PEX_CALLBACK);
begin
    OPENSSL_free(funcs);
end;

procedure ossl_crypto_cleanup_all_ex_data_int( ctx : POSSL_LIB_CTX);
var
  i : integer;
  global : POSSL_EX_DATA_GLOBAL;
  ip : PEX_CALLBACKS;
begin
    global := ossl_lib_ctx_get_ex_data_global(ctx);
    if global = nil then exit;
    for i := 0 to CRYPTO_EX_INDEX__COUNT -1 do
    begin
        ip := @global.ex_data[i];
        sk_EX_CALLBACK_pop_free(ip.meth, cleanup_cb);
        ip.meth := nil;
    end;
    CRYPTO_THREAD_lock_free(global.ex_data_lock);
    global.ex_data_lock := nil;
end;


function get_and_lock( global : POSSL_EX_DATA_GLOBAL; class_index : integer):PEX_CALLBACKS;
var
  ip : PEX_CALLBACKS;
begin
    if (class_index < 0)  or  (class_index >= CRYPTO_EX_INDEX__COUNT) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(nil);
    end;
    if global.ex_data_lock = nil then
    begin
        {
         * If we get here, someone (who?) cleaned up the lock, so just
         * treat it as an error.
         }
         Exit(nil);
    end;
    if  0>= CRYPTO_THREAD_write_lock(global.ex_data_lock )  then
        Exit(nil);
    ip := @global.ex_data[class_index];
    Result := ip;
end;

function ossl_crypto_new_ex_data_ex( ctx : POSSL_LIB_CTX; class_index : integer; obj : Pointer; ad : PCRYPTO_EX_DATA):integer;
var
  mx, i : integer;
  ptr : Pointer;
  storage : PPEX_CALLBACK;
  stack : array[0..9] of PEX_CALLBACK;
  ip : PEX_CALLBACKS;
  global : POSSL_EX_DATA_GLOBAL;
begin
{$POINTERMATH ON}
    storage := nil;
    global := ossl_lib_ctx_get_ex_data_global(ctx);
    if global = nil then
       Exit(0);
    ip := get_and_lock(global, class_index);
    if ip = nil then
       Exit(0);
    ad.ctx := ctx;
    ad.sk := nil;
    mx := sk_EX_CALLBACK_num(ip.meth);
    if mx > 0 then
    begin
        if mx < Length(stack) then
            storage := @stack
        else
            storage := OPENSSL_malloc(sizeof( storage^) * mx);
        if storage <> nil then
           for i := 0 to mx-1 do
                storage[i] := sk_EX_CALLBACK_value(ip.meth, i);
    end;
    CRYPTO_THREAD_unlock(global.ex_data_lock);
    if (mx > 0)  and  (storage = nil) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    for i := 0 to mx-1 do
    begin
        if (storage[i] <> nil)  and  Assigned(storage[i].new_func) then
        begin
            ptr := CRYPTO_get_ex_data(ad, i);
            storage[i].new_func(obj, ptr, ad, i, storage[i].argl, storage[i].argp);
        end;
    end;
    if storage <> @stack then
       OPENSSL_free(storage);
    Result := 1;
{$POINTERMATH OFF}
end;

function ossl_do_ex_data_init( ctx : POSSL_LIB_CTX):integer;
var
  global : POSSL_EX_DATA_GLOBAL;
begin
    global := ossl_lib_ctx_get_ex_data_global(ctx);
    if global = nil then
       Exit(0);
    global.ex_data_lock := CRYPTO_THREAD_lock_new();
    Result := Int(global.ex_data_lock <> nil);
end;




end.
