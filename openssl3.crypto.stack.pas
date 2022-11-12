unit openssl3.crypto.stack;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, Math;

type
  Tfunc = procedure ( p1: Pointer );

const min_nodes = 4;
//safestack.h SKM_DEFINE_STACK_OF_INTERNAL(OPENSSL_CSTRING, const char, char)



function OPENSSL_sk_num(const st: POPENSSL_STACK): Integer;
function OPENSSL_sk_find_all(st : POPENSSL_STACK;const data : Pointer; pnum : Pinteger):integer;
function sk_EX_CALLBACK_num(const sk : PSTACK_st_EX_CALLBACK):integer;
function sk_EX_CALLBACK_value(const sk : PSTACK_st_EX_CALLBACK; idx : integer):PEX_CALLBACK;
function sk_EX_CALLBACK_new( compare : sk_EX_CALLBACK_compfunc):PSTACK_st_EX_CALLBACK;
function sk_EX_CALLBACK_new_null:POPENSSL_STACK;//PSTACK_st_EX_CALLBACK;
function sk_EX_CALLBACK_new_reserve( compare : sk_EX_CALLBACK_compfunc; n : integer):PSTACK_st_EX_CALLBACK;
function sk_EX_CALLBACK_reserve( sk : PSTACK_st_EX_CALLBACK; n : integer):integer;
procedure sk_EX_CALLBACK_free( sk : PSTACK_st_EX_CALLBACK);
procedure sk_EX_CALLBACK_zero( sk : PSTACK_st_EX_CALLBACK);
function sk_EX_CALLBACK_delete( sk : PSTACK_st_EX_CALLBACK; i : integer):PEX_CALLBACK;
function sk_EX_CALLBACK_delete_ptr( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK):PEX_CALLBACK;
function sk_EX_CALLBACK_push( sk :POPENSSL_STACK{PSTACK_st_EX_CALLBACK}; ptr : PEX_CALLBACK):integer;
function sk_EX_CALLBACK_unshift( sk : POPENSSL_STACK; ptr : PEX_CALLBACK):integer;
function sk_EX_CALLBACK_pop( sk : PSTACK_st_EX_CALLBACK):PEX_CALLBACK;
function sk_EX_CALLBACK_shift( sk : PSTACK_st_EX_CALLBACK):PEX_CALLBACK;
procedure sk_EX_CALLBACK_pop_free( sk : PSTACK_st_EX_CALLBACK; freefunc : sk_EX_CALLBACK_freefunc);
function sk_EX_CALLBACK_insert( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK; idx : integer):integer;
function sk_EX_CALLBACK_set( sk : PSTACK_st_EX_CALLBACK; idx : integer; ptr : PEX_CALLBACK):PEX_CALLBACK;
function sk_EX_CALLBACK_find( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK):integer;
function sk_EX_CALLBACK_find_ex( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK):integer;
function sk_EX_CALLBACK_find_all(sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK; pnum : Pinteger):integer;
procedure sk_EX_CALLBACK_sort( sk : PSTACK_st_EX_CALLBACK);
function sk_EX_CALLBACK_is_sorted(const sk : PSTACK_st_EX_CALLBACK):integer;
function sk_EX_CALLBACK_dup(const sk : PSTACK_st_EX_CALLBACK):PSTACK_st_EX_CALLBACK;
function sk_EX_CALLBACK_deep_copy(const sk : PSTACK_st_EX_CALLBACK; copyfunc : sk_EX_CALLBACK_copyfunc; freefunc : sk_EX_CALLBACK_freefunc):PSTACK_st_EX_CALLBACK;
function sk_EX_CALLBACK_set_cmp_func( sk : PSTACK_st_EX_CALLBACK; compare : sk_EX_CALLBACK_compfunc):sk_EX_CALLBACK_compfunc;
function internal_find(st : POPENSSL_STACK;const data : Pointer; ret_val_options : integer; pnum : Pinteger):integer;



//function OPENSSL_sk_find_all(st : POPENSSL_STACK;const data : Pointer; pnum : Pinteger):integer;
function ossl_check_OPENSSL_STRING_type( ptr : PUTF8Char):PUTF8Char;
function ossl_check_OPENSSL_STRING_sk_type( sk : PSTACK_st_OPENSSL_STRING):POPENSSL_STACK;
function ossl_check_OPENSSL_STRING_compfunc_type( cmp : sk_OPENSSL_STRING_compfunc):OPENSSL_sk_compfunc;
function ossl_check_OPENSSL_STRING_copyfunc_type( cpy : sk_OPENSSL_STRING_copyfunc):OPENSSL_sk_copyfunc;
function ossl_check_OPENSSL_STRING_freefunc_type( fr : sk_OPENSSL_STRING_freefunc):OPENSSL_sk_freefunc;

function sk_OPENSSL_STRING_num( sk : Pointer):integer;
function sk_OPENSSL_STRING_value( sk : Pointer;idx: integer):PUTF8Char;
function sk_OPENSSL_STRING_new( cmp : sk_OPENSSL_STRING_compfunc):PSTACK_st_OPENSSL_STRING;
function sk_OPENSSL_STRING_new_null:PSTACK_st_OPENSSL_STRING;
function sk_OPENSSL_STRING_new_reserve( cmp : sk_OPENSSL_STRING_compfunc; n : integer):PSTACK_st_OPENSSL_STRING;
function sk_OPENSSL_STRING_reserve( sk : Pointer; n : integer):integer;
procedure sk_OPENSSL_STRING_free( sk : Pointer);
procedure sk_OPENSSL_STRING_zero( sk : Pointer);
function sk_OPENSSL_STRING_delete( sk : Pointer; i : integer):PUTF8Char;
function sk_OPENSSL_STRING_delete_ptr( sk, ptr : Pointer):PUTF8Char;
function sk_OPENSSL_STRING_push( sk, ptr : Pointer):integer;
function sk_OPENSSL_STRING_unshift( sk, ptr : Pointer):integer;
function sk_OPENSSL_STRING_pop( sk : Pointer):PUTF8Char;
function sk_OPENSSL_STRING_shift( sk : Pointer):PUTF8Char;
procedure sk_OPENSSL_STRING_pop_free( sk : Pointer; freefunc : sk_OPENSSL_STRING_freefunc);
function sk_OPENSSL_STRING_insert( sk, ptr : Pointer;idx: integer):integer;
function sk_OPENSSL_STRING_set( sk : Pointer; idx : integer; ptr : Pointer):PUTF8Char;
function sk_OPENSSL_STRING_find( sk, ptr : Pointer):integer;
function sk_OPENSSL_STRING_find_ex( sk, ptr : Pointer):integer;
function sk_OPENSSL_STRING_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
procedure sk_OPENSSL_STRING_sort( sk : Pointer);
function sk_OPENSSL_STRING_is_sorted( sk : Pointer):integer;
function sk_OPENSSL_STRING_dup( sk : Pointer):PSTACK_st_OPENSSL_STRING;
function sk_OPENSSL_STRING_deep_copy( sk : Pointer; copyfunc : sk_OPENSSL_STRING_copyfunc; freefunc : sk_OPENSSL_STRING_freefunc):PSTACK_st_OPENSSL_STRING;
function sk_OPENSSL_STRING_set_cmp_func( sk : Pointer; cmp : sk_OPENSSL_STRING_compfunc):sk_OPENSSL_STRING_compfunc;
function OPENSSL_sk_find(st : POPENSSL_STACK;const data : Pointer):integer;
function OPENSSL_sk_find_ex(st : POPENSSL_STACK;const data : Pointer):integer;
function OPENSSL_sk_value(const st : POPENSSL_STACK; i : integer):Pointer;
function OPENSSL_sk_new_null:POPENSSL_STACK;
function OPENSSL_sk_new( cmp : OPENSSL_sk_compfunc):POPENSSL_STACK;
function OPENSSL_sk_new_reserve( c : OPENSSL_sk_compfunc; n : integer):POPENSSL_STACK;
function sk_reserve( st : POPENSSL_STACK; n, exact : integer):integer;
function compute_growth(target, current : integer):integer;
function safe_muldiv_int( a, b, c : integer; err : PInteger):integer;
function safe_mul_int(a, b : integer;err : Pinteger):integer;
function safe_div_int( a, b : integer; err : PInteger):integer;
function safe_mod_int( a, b : integer; err : PInteger):integer;
function safe_add_int( a, b : integer; err : PInteger):integer;
procedure OPENSSL_sk_free( st : POPENSSL_STACK);
function OPENSSL_sk_reserve( st : POPENSSL_STACK; n : integer):integer;
function OPENSSL_sk_set(st : POPENSSL_STACK; i : integer;const data : Pointer):Pointer;
procedure OPENSSL_sk_zero( st : POPENSSL_STACK);
function OPENSSL_sk_delete_ptr(st : POPENSSL_STACK;const p : Pointer):Pointer;
function internal_delete( st : POPENSSL_STACK; loc : integer):Pointer;
function OPENSSL_sk_delete( st : POPENSSL_STACK; loc : integer):Pointer;
function OPENSSL_sk_push(st : POPENSSL_STACK;const data : Pointer):integer;
function OPENSSL_sk_insert(st : POPENSSL_STACK;const data : Pointer; loc : integer):integer;
function OPENSSL_sk_unshift(st : POPENSSL_STACK;const data : Pointer):integer;
function OPENSSL_sk_pop( st : POPENSSL_STACK):Pointer;
function OPENSSL_sk_shift( st : POPENSSL_STACK):Pointer;
procedure OPENSSL_sk_pop_free( st : POPENSSL_STACK; freefunc : OPENSSL_sk_freefunc);
procedure OPENSSL_sk_sort( st : POPENSSL_STACK);
function OPENSSL_sk_is_sorted(const st : POPENSSL_STACK):integer;
function OPENSSL_sk_dup(const sk : POPENSSL_STACK):POPENSSL_STACK;
function OPENSSL_sk_deep_copy(const sk : POPENSSL_STACK; copy_func : OPENSSL_sk_copyfunc; free_func : OPENSSL_sk_freefunc):POPENSSL_STACK;
function OPENSSL_sk_set_cmp_func( sk : POPENSSL_STACK; c : OPENSSL_sk_compfunc):OPENSSL_sk_compfunc;


var
  max_nodes: int;



implementation

uses openssl3.crypto.mem, OpenSSL3.Err,    openssl3.crypto.bsearch,
     {$IFDEF MSWINDOWS}libc.win, {$ENDIF} QuickSORT,
     openssl3.crypto.cryptlib;

const
{$IFNDEF FPC}
  {((int)1 << (sizeof(int) * 8 - 1)) = -2147483648}
  _INT_MIN = (int(1) shl (sizeof(int) * 8 - 1)) ;
  _INT_MAX = not _INT_MIN;
{$ELSE}
  _INT_MAX = 2147483647;
  _INT_MIN = (-INT_MAX - 1);

{$ENDIF}
(*您可能希望通过两种方式比较方法指针。方法指针由两个指针组成，一个代码指针和一个对象指针。
Delphi 比较方法指针的本机方式只比较代码指针，它看起来像这样：
 if @EditorWindowMethod = @TEditForm.GetFrameWindow then
  EditorWindowMethod := nil;

  To really check whether the variable is set to a specific event handler you
  will need to compare both elements in the TMethod record. Something like:
  *)
//https://stackoverflow.com/questions/1026513/comparing-a-pointer-to-functions-value-in-delphi

function OPENSSL_sk_num(const st: POPENSSL_STACK): Integer;
begin
   if st = Nil  then
      Result :=  -1
   else
     Result :=   st.num;
end;

function OPENSSL_sk_set_cmp_func( sk : POPENSSL_STACK; c : OPENSSL_sk_compfunc):OPENSSL_sk_compfunc;
var
  old : OPENSSL_sk_compfunc;
begin
    old := sk.comp;
    if @sk.comp <> @c then
       sk.sorted := 0;
    sk.comp := c;
    Result := old;
end;

function OPENSSL_sk_deep_copy(const sk : POPENSSL_STACK; copy_func : OPENSSL_sk_copyfunc; free_func : OPENSSL_sk_freefunc):POPENSSL_STACK;
var
  i, j : integer;
  label _err;
begin
{$POINTERMATH ON}
    Result := OPENSSL_malloc(sizeof(Result^ ));
    if Result = nil then
        goto _err ;
    if sk = nil then
    begin
        Result.num := 0;
        Result.sorted := 0;
        Result.comp := nil;
    end
    else
    begin
        { direct structure assignment }
        Result^ := sk^;
    end;
    if (sk = nil)  or  (sk.num = 0) then
    begin
        { postpone |Result| data allocation }
        Result.data := nil;
        Result.num_alloc := 0;
        Exit(Result);
    end;
    Result.num_alloc := get_result(sk.num > min_nodes , sk.num , min_nodes);
    //Result.data := OPENSSL_zalloc(sizeof( Result.data^) * Result.num_alloc);
    SetLength(Result.buffer, Result.num_alloc);
    Result.data := @Result.Buffer[0];
    if Result.data = nil then
       goto _err ;

    for i := 0 to Result.num - 1 do
    begin
        if nil = (sk.buffer[i]) then
           continue;
        Result.buffer[i] := copy_func(sk.buffer[i]);
        if Result.buffer[i] = nil then
        begin
            j := i;
            while PreDec(j) >= 0 do
            begin
                if Result.buffer[j] <> nil then
                    free_func(Result.buffer[j]);
            end;
            goto _err ;
        end;

    end;
    Exit(Result);

 _err:
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
    OPENSSL_sk_free(Result);
    Result := nil;
 {$POINTERMATH OFF}
end;

function OPENSSL_sk_dup(const sk : POPENSSL_STACK):POPENSSL_STACK;
var
  I: int;
  label _err;
begin
    Result := OPENSSL_malloc(sizeof( Result^));
    if Result = nil then
        goto _err ;
    if sk = nil then
    begin
        Result.num := 0;
        Result.sorted := 0;
        Result.comp := nil;
    end
    else
    begin
        { direct structure assignment }
        Result^ := sk^;
    end;
    if (sk = nil)  or  (sk.num = 0) then
    begin
        { postpone |Result.data| allocation }
        Result.data := nil;
        Result.num_alloc := 0;
        Exit(Result);
    end;
    { duplicate |sk.data| content }
    //Result.data := OPENSSL_malloc(sizeof(Result.Data^) * sk.num_alloc);
    SetLength(Result.buffer, sk.num_alloc);
    Result.data := @Result.Buffer[0];
    if Result.data = nil then
        goto _err ;
    for I := 0 to sk.num - 1 do
       Move(sk.buffer[I]^, Result.buffer[I]^, sizeof(Pointer));
    //memcpy(Result.data, sk.data, sizeof(Pointer)  * sk.num);
    Exit(Result);

 _err:
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
    OPENSSL_sk_free(Result);
    Result := nil;
end;



function OPENSSL_sk_is_sorted(const st : POPENSSL_STACK):integer;
begin
    Result := get_result( st = nil , 1 , st.sorted);
end;


procedure OPENSSL_sk_sort( st : POPENSSL_STACK);
begin
{$POINTERMATH ON}
    if (st <> nil)  and ( (0>= st.sorted)  and  (Assigned(st.comp)) ) then
    begin
        if st.num > 1 then
            TQuickSort<Pointer>.qsort(st.buffer, st.num, st.comp);
        st.sorted := 1; { empty or single-element stack is considered sorted }
    end;
{$POINTERMATH OFF}
end;

procedure OPENSSL_sk_pop_free( st : POPENSSL_STACK; freefunc : OPENSSL_sk_freefunc);
var
  i : integer;
begin
{$POINTERMATH ON}
    if (st = nil) or (st.num_alloc <=0) then
       EXIT;
    for i := 0 to st.num-1 do
        if st.buffer[i] <> nil then
           freefunc(st.buffer[i]);
    OPENSSL_sk_free(st);
{$POINTERMATH OFF}
end;

function OPENSSL_sk_shift( st : POPENSSL_STACK):Pointer;
begin
    if (st = nil)  or  (st.num = 0) then
        Exit(nil);
    Result := internal_delete(st, 0);
end;


function OPENSSL_sk_pop( st : POPENSSL_STACK):Pointer;
begin
    if (st = nil)  or  (st.num = 0) then
       Exit(nil);
    Result := internal_delete(st, st.num - 1);
end;


function OPENSSL_sk_unshift(st : POPENSSL_STACK;const data : Pointer):integer;
begin
    Result := OPENSSL_sk_insert(st, data, 0);
end;

function OPENSSL_sk_insert(st : POPENSSL_STACK;const data : Pointer; loc : integer):integer;
begin
{$POINTERMATH ON}
    if (st = nil)  or  (st.num = max_nodes) then
       Exit(0);
    if 0>= sk_reserve(st, 1, 0) then
        Exit(0);
    if (loc >= st.num ) or  (loc < 0) then
    begin
        st.buffer[st.num] := data;
    end
    else
    begin
        memmove(@st.buffer[loc + 1], @st.buffer[loc],  sizeof(st.Buffer) * (st.num - loc));
        st.buffer[loc] := data;
    end;
    Inc(st.num);
    st.sorted := 0;
    st.data := @st.Buffer;
    Result := st.num;
{$POINTERMATH OFF}
end;

function OPENSSL_sk_push(st : POPENSSL_STACK;const data : Pointer):integer;
begin
    if st = nil then Exit(-1);
    Result := OPENSSL_sk_insert(st, data, st.num);
end;

function OPENSSL_sk_delete( st : POPENSSL_STACK; loc : integer):Pointer;
begin
    if (st = nil)  or  (loc < 0)  or  (loc >= st.num) then
        Exit(nil);
    Result := internal_delete(st, loc);
end;

function internal_delete( st : POPENSSL_STACK; loc : integer):Pointer;
var
  ret : Pointer;
begin
{$POINTERMATH ON}
    Result := st.buffer[loc];
    if loc <> st.num - 1 then
        memmove(@st.buffer[loc], @st.buffer[loc + 1], sizeof(st.Buffer) * (st.num - loc - 1));
    Dec(st.num);

{$POINTERMATH OFF}
end;

function OPENSSL_sk_delete_ptr(st : POPENSSL_STACK;const p : Pointer):Pointer;
var
  i : integer;
begin
{$POINTERMATH ON}
    for i := 0 to st.num-1 do
        if st.buffer[i] = p then
           Exit(internal_delete(st, i));
    Result := nil;
{$POINTERMATH OFF}
end;

procedure OPENSSL_sk_zero( st : POPENSSL_STACK);
begin
    if (st = nil)  or  (st.num = 0) then
       EXIT;
    //memset(@st.buffer, 0, sizeof(Pointer) * st.num);
    st^ := default(TOPENSSL_STACK);
    st.num := 0;
end;

function OPENSSL_sk_set(st : POPENSSL_STACK; i : integer;const data : Pointer):Pointer;
begin
{$POINTERMATH ON}
    if (st = nil)  or  (i < 0)  or  (i >= st.num) then
        Exit(nil);
    st.buffer[i] := data;
    st.sorted := 0;
    Result := st.buffer[i];
{$POINTERMATH OFF}
end;


function OPENSSL_sk_reserve( st : POPENSSL_STACK; n : integer):integer;
begin
    if st = nil then Exit(0);
    if n < 0 then Exit(1);
    Result := sk_reserve(st, n, 1);
end;

procedure OPENSSL_sk_free( st : POPENSSL_STACK);
begin
    if st = nil then
       exit;
    //OPENSSL_free(Pointer(st.data));
    SetLength(st.buffer, 0);
    st.data := nil;
    //st^ := default(TOPENSSL_STACK);
    st := nil;
    OPENSSL_free(st);

end;

function safe_add_int( a, b : integer; err : PInteger):integer;
begin
   if ( Int(a < 0) xor  int(b < 0) >0 )  or
      ( (a > 0)  and  (b <= _INT_MAX - a) )  or
      ( (a < 0)  and  (b >= _INT_MIN - a) )  or  (a = 0) then
     Exit(a + b);
   err^  := err^  or 1;
   Result := get_result(a < 0 , _INT_MIN , _INT_MAX);
end;


function safe_neg_int( a : integer; err : PInteger):integer;
begin
   if a <> _INT_MIN then Exit(-a);
   err^  := err^  or 1;
   Exit(_INT_MIN);
end;


function safe_abs_int( a : integer; err : PInteger):integer;
begin
   if a <> _INT_MIN then
   Exit( get_result(a < 0 , -a , a));
   err^  := err^  or 1;
   Exit(_INT_MIN);
end;


function safe_sub_int( a, b : integer; err : PInteger):integer;
begin
   if (0 >= int(a < 0)  xor  int(b < 0))  or
      ( (b > 0)  and  (a >= _INT_MIN + b) )  or
      ( (b < 0)  and  (a <= _INT_MAX + b) )  or  (b = 0) then
       Exit(a - b);
   err^  := err^  or 1;
   Result := get_result(a < 0 , _INT_MIN , not _INT_MAX);
end;


function safe_mul_int( a, b : integer; err : PInteger):integer;
var
  x, y: int;
begin
   if (a = 0)  or  (b = 0) then
      Exit(0);
   if a = 1 then Exit(b);
   if b = 1 then Exit(a);
   if (a <> _INT_MIN)  and  (b <> _INT_MIN) then
   begin
       x := get_result(a < 0, -a , a);
       y := get_result(b < 0, -b , b);
       if x <= _INT_MAX div y then
          Exit(a * b);
   end;
   err^  := err^  or 1;
   Result := get_result( Int(a < 0)  xor  int(b < 0) >0, _INT_MIN , _INT_MAX);
end;


function safe_div_int( a, b : integer; err : PInteger):integer;
begin
   if b = 0 then
   begin
      err^  := err^  or 1;
      Exit(get_result(a < 0 , _INT_MIN , _INT_MAX));
   end;
   if (b = -1)  and  (a = _INT_MIN) then
   begin
     err^  :=  err^  or 1;
     Exit(_INT_MAX);
   end;
   Exit(a div b);
end;


function safe_mod_int( a, b : integer; err : PInteger):integer;
begin
   if b = 0 then
   begin
     err^  :=  err^  or 1;
     Exit(0);
   end;
   if (b = -1)  and  (a = _INT_MIN) then
   begin
     err^  :=  err^  or 1;
     exit(_INT_MAX);
   end;
   Exit(a mod b);
end;


function safe_muldiv_int( a, b, c : integer; err : PInteger):integer;
var
  e2, q, r, x, y : integer;
begin
    e2 := 0;
    if c = 0 then
    begin
        err^  := err^  or 1;
        Exit(get_result( (a = 0)  or  (b = 0), 0 , _INT_MAX));
    end;
    x := safe_mul_int(a, b, @e2);
    if 0>= e2 then
       Exit(safe_div_int(x, c, err));
    if b > a then
    begin
        x := b;
        b := a;
        a := x;
    end;
    q := safe_div_int(a, c, err);
    r := safe_mod_int(a, c, err);
    x := safe_mul_int(r, b, err);
    y := safe_mul_int(q, b, err);
    q := safe_div_int(x, c, err);
    Result := safe_add_int(y, q, err);
end;

function compute_growth(target, current : integer):integer;
var
  err : integer;
begin
    err := 0;
    while current < target do
    begin
        if current >= max_nodes then Exit(0);
        current := safe_muldiv_int(current, 8, 5, @err);
        if err>0 then Exit(0);
        if current >= max_nodes then
           current := max_nodes;
    end;
    Result := current;
end;


function sk_reserve( st : POPENSSL_STACK; n, exact : integer):integer;
var
  num_alloc : integer;
begin
    { Check to see the reservation isn't exceeding the hard limit }
    if n > max_nodes - st.num then Exit(0);
    { Figure out the new size }
    num_alloc := st.num + n;
    if num_alloc < min_nodes then
       num_alloc := min_nodes;
    { If |st.data| allocation was postponed }
    if st.data = nil then
    begin
        {
         * At this point, |st.num_alloc| and |st.num| are 0;
         * so |num_alloc| value is |n| or |min_nodes| if greater than |n|.
         }
        //分配这个指针数组
        //st.data := OPENSSL_zalloc(sizeof(Pointer) * num_alloc);
        SetLength(st.buffer, num_alloc);
        st.data := @st.Buffer[0];
        if st.data = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        st.num_alloc := num_alloc;
        Exit(1);
    end;
    if  0>= exact then
    begin
        if num_alloc <= st.num_alloc then
            Exit(1);
        num_alloc := compute_growth(num_alloc, st.num_alloc);
        if num_alloc = 0 then Exit(0);
    end
    else
    if (num_alloc = st.num_alloc) then
    begin
        Exit(1);
    end;
    
    // 重新分配这个指针数组
    //st.data := OPENSSL_realloc(st.data, sizeof(Pointer ) * num_alloc);
    SetLength(st.buffer, num_alloc);
    st.data := @st.Buffer[0];
    if st.data = nil then Exit(0);

    st.num_alloc := num_alloc;
    Result := 1;
end;

function OPENSSL_sk_new_reserve( c : OPENSSL_sk_compfunc; n : integer):POPENSSL_STACK;
var
  st: POPENSSL_STACK;
begin
    st := OPENSSL_zalloc(sizeof(st^));
    if st = nil then Exit(nil);
    st.comp := c;
    if n <= 0 then
       Exit(st);
    if 0>= sk_reserve(st, n, 1) then
    begin
        OPENSSL_sk_free(st);
        Exit(nil);
    end;
    Result := st;
end;

function OPENSSL_sk_new_null:POPENSSL_STACK;
begin
    Result := OPENSSL_sk_new_reserve(nil, 0);
end;


function OPENSSL_sk_new( cmp : OPENSSL_sk_compfunc):POPENSSL_STACK;
begin
    Result := OPENSSL_sk_new_reserve(cmp, 0);
end;

function OPENSSL_sk_value(const st : POPENSSL_STACK; i : integer):Pointer;
begin
{$POINTERMATH ON}
    if (st = nil)  or  (i < 0)  or  (i >= st.num) then
        Exit(nil);
    Result := st.buffer[i];
{$POINTERMATH OFF}
end;

function OPENSSL_sk_find_ex(st : POPENSSL_STACK;const data : Pointer):integer;
begin
    Result := internal_find(st, data, OSSL_BSEARCH_VALUE_ON_NOMATCH, nil);
end;

function OPENSSL_sk_find(st : POPENSSL_STACK;const data : Pointer):integer;
begin
    Result := internal_find(st, data, OSSL_BSEARCH_FIRST_VALUE_ON_MATCH, nil);
end;

function sk_OPENSSL_STRING_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_OPENSSL_STRING_sk_type(sk))
end;


function sk_OPENSSL_STRING_value( sk : Pointer; idx: integer):PUTF8Char;
begin
   Result := PUTF8Char (OPENSSL_sk_value(ossl_check_OPENSSL_STRING_sk_type(sk), (idx)))
end;


function sk_OPENSSL_STRING_new( cmp : sk_OPENSSL_STRING_compfunc):PSTACK_st_OPENSSL_STRING;
begin
   Result := PSTACK_st_OPENSSL_STRING (OPENSSL_sk_new(ossl_check_OPENSSL_STRING_compfunc_type(cmp)))
end;


function sk_OPENSSL_STRING_new_null:PSTACK_st_OPENSSL_STRING;
begin
   Result := PSTACK_st_OPENSSL_STRING (OPENSSL_sk_new_null())
end;


function sk_OPENSSL_STRING_new_reserve( cmp : sk_OPENSSL_STRING_compfunc; n : integer):PSTACK_st_OPENSSL_STRING;
begin
   Result := PSTACK_st_OPENSSL_STRING (OPENSSL_sk_new_reserve(ossl_check_OPENSSL_STRING_compfunc_type(cmp), (n)))
end;


function sk_OPENSSL_STRING_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_OPENSSL_STRING_sk_type(sk), (n))
end;


procedure sk_OPENSSL_STRING_free( sk : Pointer);
begin
   OPENSSL_sk_free(ossl_check_OPENSSL_STRING_sk_type(sk))
end;


procedure sk_OPENSSL_STRING_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(ossl_check_OPENSSL_STRING_sk_type(sk))
end;


function sk_OPENSSL_STRING_delete( sk : Pointer; i : integer):PUTF8Char;
begin
   Result := PUTF8Char (OPENSSL_sk_delete(ossl_check_OPENSSL_STRING_sk_type(sk), (i)))
end;


function sk_OPENSSL_STRING_delete_ptr( sk, ptr : Pointer):PUTF8Char;
begin
   Result := PUTF8Char (OPENSSL_sk_delete_ptr(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr)))
end;


function sk_OPENSSL_STRING_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr))
end;


function sk_OPENSSL_STRING_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr))
end;


function sk_OPENSSL_STRING_pop( sk : Pointer):PUTF8Char;
begin
   Result := PUTF8Char (OPENSSL_sk_pop(ossl_check_OPENSSL_STRING_sk_type(sk)))
end;


function sk_OPENSSL_STRING_shift( sk : Pointer):PUTF8Char;
begin
   Result := PUTF8Char (OPENSSL_sk_shift(ossl_check_OPENSSL_STRING_sk_type(sk)))
end;


procedure sk_OPENSSL_STRING_pop_free( sk : Pointer; freefunc : sk_OPENSSL_STRING_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_OPENSSL_STRING_sk_type(sk),ossl_check_OPENSSL_STRING_freefunc_type(freefunc))
end;


function sk_OPENSSL_STRING_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr), (idx))
end;


function sk_OPENSSL_STRING_set( sk : Pointer; idx : integer; ptr : Pointer):PUTF8Char;
begin
   Result := PUTF8Char (OPENSSL_sk_set(ossl_check_OPENSSL_STRING_sk_type(sk), (idx), ossl_check_OPENSSL_STRING_type(ptr)))
end;


function sk_OPENSSL_STRING_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr))
end;


function sk_OPENSSL_STRING_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr))
end;


function sk_OPENSSL_STRING_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_type(ptr), pnum)
end;


procedure sk_OPENSSL_STRING_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_OPENSSL_STRING_sk_type(sk))
end;


function sk_OPENSSL_STRING_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_OPENSSL_STRING_sk_type(sk))
end;


function sk_OPENSSL_STRING_dup( sk : Pointer):PSTACK_st_OPENSSL_STRING;
begin
   Result := PSTACK_st_OPENSSL_STRING (OPENSSL_sk_dup(ossl_check_OPENSSL_STRING_sk_type(sk)))
end;


function sk_OPENSSL_STRING_deep_copy( sk : Pointer; copyfunc : sk_OPENSSL_STRING_copyfunc; freefunc : sk_OPENSSL_STRING_freefunc):PSTACK_st_OPENSSL_STRING;
begin
   Result := PSTACK_st_OPENSSL_STRING (OPENSSL_sk_deep_copy(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_copyfunc_type(copyfunc), ossl_check_OPENSSL_STRING_freefunc_type(freefunc)))
end;


function sk_OPENSSL_STRING_set_cmp_func( sk : Pointer; cmp : sk_OPENSSL_STRING_compfunc):sk_OPENSSL_STRING_compfunc;
begin
   Result := sk_OPENSSL_STRING_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_OPENSSL_STRING_sk_type(sk), ossl_check_OPENSSL_STRING_compfunc_type(cmp)))
end;

function ossl_check_OPENSSL_STRING_type( ptr : PUTF8Char):PUTF8Char;
begin
  Result := ptr;
end;


function ossl_check_OPENSSL_STRING_sk_type( sk : PSTACK_st_OPENSSL_STRING):POPENSSL_STACK;
begin
  Result := POPENSSL_STACK (sk);
end;


function ossl_check_OPENSSL_STRING_compfunc_type( cmp : sk_OPENSSL_STRING_compfunc):OPENSSL_sk_compfunc;
begin
  Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_OPENSSL_STRING_copyfunc_type( cpy : sk_OPENSSL_STRING_copyfunc):OPENSSL_sk_copyfunc;
begin
  Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_OPENSSL_STRING_freefunc_type( fr : sk_OPENSSL_STRING_freefunc):OPENSSL_sk_freefunc;
begin
  Result := OPENSSL_sk_freefunc(fr);
end;

function OPENSSL_sk_find_all(st : POPENSSL_STACK;const data : Pointer; pnum : Pinteger):integer;
begin
    Result := internal_find(st, data, OSSL_BSEARCH_FIRST_VALUE_ON_MATCH, pnum);
end;



function internal_find(st : POPENSSL_STACK;const data : Pointer; ret_val_options : integer; pnum : Pinteger):integer;
var
  r : Pointer;
  i : integer;
  p, pp : PPointer;
begin
{$POINTERMATH ON}
    if (st = nil)  or  (st.num = 0) then
       Exit(-1);
    if not Assigned(st.comp ) then
    begin
        for i := 0 to st.num-1 do
            if st.buffer[i] = data then
            begin
                if pnum <> nil then
                    pnum^ := 1;
                Exit(i);
            end;
        if pnum <> nil then
           pnum^ := 0;
        Exit(-1);
    end;
    if  not Boolean(st.sorted) then
    begin
        if st.num > 1 then
           TQuickSort<Pointer>.qsort(st.buffer, st.num, st.comp);
        st.sorted := 1;
    end;
    if data = nil then
       Exit(-1);
    if pnum <> nil then
       ret_val_options  := ret_val_options  or OSSL_BSEARCH_FIRST_VALUE_ON_MATCH;
    r := ossl_bsearch(@data, st.data, st.num, sizeof(Pointer), st.comp,  ret_val_options);
    if pnum <> nil then
    begin
        pnum^ := 0;
        if r <> nil then
        begin
            p := @r;
            while p < st.data + st.num do
            begin
                if st.comp(@data, p) <> 0 then
                    break;
                Inc(pnum^);
                Inc(p);
            end;
        end;
    end;
    if r = nil  then
       Result :=  -1
    else
    begin
       pp := @r;
       Result := int(pp - st.data);
    end;
{$POINTERMATH OFF}
end;

function sk_EX_CALLBACK_num(const sk : PSTACK_st_EX_CALLBACK):integer;
begin
    Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;


function sk_EX_CALLBACK_value(const sk : PSTACK_st_EX_CALLBACK; idx : integer):PEX_CALLBACK;
begin
    Result := PEX_CALLBACK (OPENSSL_sk_value(POPENSSL_STACK (sk), idx));
end;


function sk_EX_CALLBACK_new( compare : sk_EX_CALLBACK_compfunc):PSTACK_st_EX_CALLBACK;
begin
    Result := PSTACK_st_EX_CALLBACK (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)) );
end;


function sk_EX_CALLBACK_new_null:POPENSSL_STACK;//PSTACK_st_EX_CALLBACK;
begin
    Result := OPENSSL_sk_new_null;
end;


function sk_EX_CALLBACK_new_reserve( compare : sk_EX_CALLBACK_compfunc; n : integer):PSTACK_st_EX_CALLBACK;
begin
    Result := (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n) );
end;


function sk_EX_CALLBACK_reserve( sk : PSTACK_st_EX_CALLBACK; n : integer):integer;
begin
    Result := OPENSSL_sk_reserve(POPENSSL_STACK (sk), n) ;
end;


procedure sk_EX_CALLBACK_free( sk : PSTACK_st_EX_CALLBACK);
begin
    OPENSSL_sk_free(POPENSSL_STACK (sk));
end;


procedure sk_EX_CALLBACK_zero( sk : PSTACK_st_EX_CALLBACK);
begin
    OPENSSL_sk_zero(POPENSSL_STACK (sk));
end;


function sk_EX_CALLBACK_delete( sk : PSTACK_st_EX_CALLBACK; i : integer):PEX_CALLBACK;
begin
    Result := PEX_CALLBACK (OPENSSL_sk_delete(POPENSSL_STACK (sk), i));
end;


function sk_EX_CALLBACK_delete_ptr( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK):PEX_CALLBACK;
begin
   Result := PEX_CALLBACK (OPENSSL_sk_delete_ptr(POPENSSL_STACK (sk), Pointer(ptr) ));
end;


function sk_EX_CALLBACK_push( sk :POPENSSL_STACK{PSTACK_st_EX_CALLBACK}; ptr : PEX_CALLBACK):integer;
begin
    Result := OPENSSL_sk_push({POPENSSL_STACK}(sk), ptr);
end;


function sk_EX_CALLBACK_unshift( sk : POPENSSL_STACK; ptr : PEX_CALLBACK):integer;
begin
    Result := OPENSSL_sk_unshift(POPENSSL_STACK (sk), ptr);
end;


function sk_EX_CALLBACK_pop( sk : PSTACK_st_EX_CALLBACK):PEX_CALLBACK;
begin
    Result := PEX_CALLBACK (OPENSSL_sk_pop(POPENSSL_STACK (sk)));
end;


function sk_EX_CALLBACK_shift( sk : PSTACK_st_EX_CALLBACK):PEX_CALLBACK;
begin
    Result := PEX_CALLBACK (OPENSSL_sk_shift(POPENSSL_STACK (sk)));
end;


procedure sk_EX_CALLBACK_pop_free( sk : PSTACK_st_EX_CALLBACK; freefunc : sk_EX_CALLBACK_freefunc);
begin
        OPENSSL_sk_pop_free(POPENSSL_STACK (sk), OPENSSL_sk_freefunc(freefunc) );
end;


function sk_EX_CALLBACK_insert( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK; idx : integer):integer;
begin
    Result := OPENSSL_sk_insert(POPENSSL_STACK (sk), Pointer(ptr), idx);
end;


function sk_EX_CALLBACK_set( sk : PSTACK_st_EX_CALLBACK; idx : integer; ptr : PEX_CALLBACK):PEX_CALLBACK;
begin
    Result := PEX_CALLBACK (OPENSSL_sk_set(POPENSSL_STACK (sk), idx, Pointer(ptr)));
end;


function sk_EX_CALLBACK_find( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK):integer;
begin
    Result := OPENSSL_sk_find(POPENSSL_STACK (sk), Pointer(ptr));
end;


function sk_EX_CALLBACK_find_ex( sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK):integer;
begin
    Result := OPENSSL_sk_find_ex(POPENSSL_STACK (sk), Pointer(ptr));
end;

function sk_EX_CALLBACK_find_all(sk : PSTACK_st_EX_CALLBACK; ptr : PEX_CALLBACK;pnum : Pinteger):integer;
begin
    Result := OPENSSL_sk_find_all(POPENSSL_STACK (sk), Pointer(ptr), pnum);
end;


procedure sk_EX_CALLBACK_sort( sk : PSTACK_st_EX_CALLBACK);
begin
   OPENSSL_sk_sort(POPENSSL_STACK (sk));
end;


function sk_EX_CALLBACK_is_sorted(const sk : PSTACK_st_EX_CALLBACK):integer;
begin
    Result := OPENSSL_sk_is_sorted(POPENSSL_STACK (sk));
end;


function sk_EX_CALLBACK_dup(const sk : PSTACK_st_EX_CALLBACK):PSTACK_st_EX_CALLBACK;
begin
    Result := PSTACK_st_EX_CALLBACK (OPENSSL_sk_dup(POPENSSL_STACK (sk)));
end;


function sk_EX_CALLBACK_deep_copy(const sk : PSTACK_st_EX_CALLBACK; copyfunc : sk_EX_CALLBACK_copyfunc; freefunc : sk_EX_CALLBACK_freefunc):PSTACK_st_EX_CALLBACK;
begin
   Result := PSTACK_st_EX_CALLBACK (OPENSSL_sk_deep_copy(POPENSSL_STACK (sk),
                                               OPENSSL_sk_copyfunc(copyfunc),
                                            OPENSSL_sk_freefunc(freefunc)));
end;


function sk_EX_CALLBACK_set_cmp_func( sk : PSTACK_st_EX_CALLBACK; compare : sk_EX_CALLBACK_compfunc):sk_EX_CALLBACK_compfunc;
begin
    Result := sk_EX_CALLBACK_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK (sk),
                                          OPENSSL_sk_compfunc(compare)));
end;

{$IFDEF FPC}
   const SIZE_MAX = 18446744073709551615;
{$ENDIF}
initialization
   max_nodes:= get_result( SIZE_MAX div sizeof(Pointer) < INT_MAX,
                             int(SIZE_MAX div sizeof(Pointer) )
                             , INT_MAX);
end.
