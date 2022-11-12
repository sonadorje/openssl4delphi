unit openssl3.crypto.x509;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;




function ossl_check_X509_type( ptr : PX509):PX509;
  function ossl_check_X509_sk_type( sk : PSTACK_st_X509):POPENSSL_STACK;
  function ossl_check_X509_compfunc_type( cmp : sk_X509_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_copyfunc_type( cpy : sk_X509_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_freefunc_type( fr : sk_X509_freefunc):OPENSSL_sk_freefunc;

  function sk_X509_num( sk : Pointer):integer;
  function sk_X509_value( sk : Pointer; idx : integer):PX509;
  function sk_X509_new( cmp : sk_X509_compfunc):PSTACK_st_X509;
  function sk_X509_new_null:PSTACK_st_X509;
  function sk_X509_new_reserve( cmp : sk_X509_compfunc; n : integer):PSTACK_st_X509;
  function sk_X509_reserve( sk : Pointer; n : integer):integer;
  procedure sk_X509_free( sk : Pointer);
  procedure sk_X509_zero( sk : Pointer);
  function sk_X509_delete( sk : Pointer; i : integer):PX509;
  function sk_X509_delete_ptr( sk, ptr : Pointer):PX509;
  function sk_X509_push( sk, ptr : Pointer):integer;
  function sk_X509_unshift( sk, ptr : Pointer):integer;
  function sk_X509_pop( sk : Pointer):PX509;
  function sk_X509_shift( sk : Pointer):PX509;
  procedure sk_X509_pop_free( sk : Pointer; freefunc : sk_X509_freefunc);
  function sk_X509_insert( sk, ptr : Pointer; idx : integer):integer;
  function sk_X509_set( sk: Pointer; idx: Integer; ptr : Pointer):PX509;
  function sk_X509_find( sk, ptr : Pointer):integer;
  function sk_X509_find_ex( sk, ptr : Pointer):integer;
  function sk_X509_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
  procedure sk_X509_sort( sk : Pointer);
  function sk_X509_is_sorted( sk : Pointer):integer;
  function sk_X509_dup( sk : Pointer):PSTACK_st_X509;
  function sk_X509_deep_copy( sk : Pointer; copyfunc : sk_X509_copyfunc; freefunc : sk_X509_freefunc):PSTACK_st_X509;

  function ossl_check_X509_EXTENSION_type( ptr : PX509_EXTENSION):PX509_EXTENSION;
  function ossl_check_X509_EXTENSION_sk_type( sk : PSTACK_st_X509_EXTENSION):POPENSSL_STACK;
  function ossl_check_X509_EXTENSION_compfunc_type( cmp : sk_X509_EXTENSION_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_EXTENSION_copyfunc_type( cpy : sk_X509_EXTENSION_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_EXTENSION_freefunc_type( fr : sk_X509_EXTENSION_freefunc):OPENSSL_sk_freefunc;

  function sk_X509_EXTENSION_num( sk : Pointer):integer;
  function sk_X509_EXTENSION_value( sk : Pointer; idx : integer):PX509_EXTENSION;
  function sk_X509_EXTENSION_new( cmp : sk_X509_EXTENSION_compfunc):PSTACK_st_X509_EXTENSION;
  function sk_X509_EXTENSION_new_null:PSTACK_st_X509_EXTENSION ;
  function sk_X509_EXTENSION_new_reserve( cmp : sk_X509_EXTENSION_compfunc;n: Integer):PSTACK_st_X509_EXTENSION ;
  function sk_X509_EXTENSION_reserve( sk : Pointer; n : integer):integer;
  procedure sk_X509_EXTENSION_free( sk : Pointer);
  procedure sk_X509_EXTENSION_zero( sk : Pointer);
  function sk_X509_EXTENSION_delete( sk : Pointer; i : integer):PX509_EXTENSION;
  function sk_X509_EXTENSION_delete_ptr( sk, ptr : Pointer):PX509_EXTENSION;
  function sk_X509_EXTENSION_push( sk, ptr : Pointer):integer;
  function sk_X509_EXTENSION_unshift( sk, ptr : Pointer):integer;
  function sk_X509_EXTENSION_pop( sk : Pointer):PX509_EXTENSION;
  function sk_X509_EXTENSION_shift( sk : Pointer):PX509_EXTENSION;
  procedure sk_X509_EXTENSION_pop_free( sk : Pointer; freefunc : sk_X509_EXTENSION_freefunc);
  function sk_X509_EXTENSION_insert( sk, ptr : Pointer; idx : integer):integer;
  function sk_X509_EXTENSION_set( sk : Pointer; idx : integer; ptr : Pointer):PX509_EXTENSION;
  function sk_X509_EXTENSION_find( sk, ptr : Pointer):integer;
  function sk_X509_EXTENSION_find_ex( sk, ptr : Pointer):integer;
  function sk_X509_EXTENSION_find_all( sk, ptr : Pointer; pnum : PInteger):integer;
  procedure sk_X509_EXTENSION_sort( sk : Pointer);
  function sk_X509_EXTENSION_is_sorted( sk : Pointer):integer;
  function sk_X509_EXTENSION_dup( sk : Pointer):PSTACK_st_X509_EXTENSION;
  function sk_X509_EXTENSION_deep_copy( sk : Pointer; copyfunc : sk_X509_EXTENSION_copyfunc; freefunc : sk_X509_EXTENSION_freefunc):PSTACK_st_X509_EXTENSION;
  function sk_X509_EXTENSION_set_cmp_func( sk : Pointer; cmp : sk_X509_EXTENSION_compfunc):sk_X509_EXTENSION_compfunc;

  function ossl_check_X509_CRL_type( ptr : PX509_CRL):PX509_CRL;
  function ossl_check_X509_CRL_sk_type( sk : PSTACK_st_X509_CRL):POPENSSL_STACK;
  function ossl_check_X509_CRL_compfunc_type( cmp : sk_X509_CRL_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_CRL_copyfunc_type( cpy : sk_X509_CRL_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_CRL_freefunc_type( fr : sk_X509_CRL_freefunc):OPENSSL_sk_freefunc;


  function sk_X509_CRL_num( sk : Pointer):integer;
  function sk_X509_CRL_value( sk : Pointer;idx: integer):PX509_CRL;
  function sk_X509_CRL_new( cmp : sk_X509_CRL_compfunc):PSTACK_st_X509_CRL;
  function sk_X509_CRL_new_null:PSTACK_st_X509_CRL;
  function sk_X509_CRL_new_reserve( cmp : sk_X509_CRL_compfunc; n : integer):PSTACK_st_X509_CRL;
  function sk_X509_CRL_reserve( sk : Pointer; n : integer):integer;
  procedure sk_X509_CRL_free( sk : Pointer);
  procedure sk_X509_CRL_zero( sk : Pointer);
  function sk_X509_CRL_delete( sk : Pointer; i : integer):PX509_CRL;
  function sk_X509_CRL_delete_ptr( sk, ptr : Pointer):PX509_CRL;
  function sk_X509_CRL_push( sk, ptr : Pointer):integer;
  function sk_X509_CRL_unshift( sk, ptr : Pointer):integer;
  function sk_X509_CRL_pop( sk : Pointer):PX509_CRL;
  function sk_X509_CRL_shift( sk : Pointer):PX509_CRL;
  procedure sk_X509_CRL_pop_free( sk : Pointer; freefunc : sk_X509_CRL_freefunc);
  function sk_X509_CRL_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_X509_CRL_set( sk : Pointer; idx : integer; ptr : Pointer):PX509_CRL;
  function sk_X509_CRL_find( sk, ptr : Pointer):integer;
  function sk_X509_CRL_find_ex( sk, ptr : Pointer):integer;
  function sk_X509_CRL_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_X509_CRL_sort( sk : Pointer);
  function sk_X509_CRL_is_sorted( sk : Pointer):integer;
  function sk_X509_CRL_dup( sk : Pointer):PSTACK_st_X509_CRL;
  function sk_X509_CRL_deep_copy( sk : Pointer; copyfunc : sk_X509_CRL_copyfunc; freefunc : sk_X509_CRL_freefunc):PSTACK_st_X509_CRL;
  function sk_X509_CRL_set_cmp_func( sk : Pointer; cmp : sk_X509_CRL_compfunc):sk_X509_CRL_compfunc;

  function ossl_check_X509_REVOKED_type( ptr : PX509_REVOKED):PX509_REVOKED;
  function ossl_check_X509_REVOKED_sk_type( sk : PSTACK_st_X509_REVOKED):POPENSSL_STACK;
  function ossl_check_X509_REVOKED_compfunc_type( cmp : sk_X509_REVOKED_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_REVOKED_copyfunc_type( cpy : sk_X509_REVOKED_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_REVOKED_freefunc_type( fr : sk_X509_REVOKED_freefunc):OPENSSL_sk_freefunc;


  function sk_X509_REVOKED_num( sk : Pointer):integer;
  function sk_X509_REVOKED_value( sk : Pointer;idx: integer):PX509_REVOKED;
  function sk_X509_REVOKED_new( cmp : sk_X509_REVOKED_compfunc):PSTACK_st_X509_REVOKED;
  function sk_X509_REVOKED_new_null:PSTACK_st_X509_REVOKED;
  function sk_X509_REVOKED_new_reserve( cmp : sk_X509_REVOKED_compfunc; n : integer):PSTACK_st_X509_REVOKED;
  function sk_X509_REVOKED_reserve( sk : Pointer; n : integer):integer;
  procedure sk_X509_REVOKED_free( sk : Pointer);
  procedure sk_X509_REVOKED_zero( sk : Pointer);
  function sk_X509_REVOKED_delete( sk : Pointer; i : integer):PX509_REVOKED;
  function sk_X509_REVOKED_delete_ptr( sk, ptr : Pointer):PX509_REVOKED;
  function sk_X509_REVOKED_push( sk, ptr : Pointer):integer;
  function sk_X509_REVOKED_unshift( sk, ptr : Pointer):integer;
  function sk_X509_REVOKED_pop( sk : Pointer):PX509_REVOKED;
  function sk_X509_REVOKED_shift( sk : Pointer):PX509_REVOKED;
  procedure sk_X509_REVOKED_pop_free( sk : Pointer; freefunc : sk_X509_REVOKED_freefunc);
  function sk_X509_REVOKED_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_X509_REVOKED_set( sk : Pointer; idx : integer; ptr : Pointer):PX509_REVOKED;
  function sk_X509_REVOKED_find( sk, ptr : Pointer):integer;
  function sk_X509_REVOKED_find_ex( sk, ptr : Pointer):integer;
  function sk_X509_REVOKED_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_X509_REVOKED_sort( sk : Pointer);
  function sk_X509_REVOKED_is_sorted( sk : Pointer):integer;
  function sk_X509_REVOKED_dup( sk : Pointer):PSTACK_st_X509_REVOKED;
  function sk_X509_REVOKED_deep_copy( sk : Pointer; copyfunc : sk_X509_REVOKED_copyfunc; freefunc : sk_X509_REVOKED_freefunc):PSTACK_st_X509_REVOKED;
  function sk_X509_REVOKED_set_cmp_func( sk : Pointer; cmp : sk_X509_REVOKED_compfunc):sk_X509_REVOKED_compfunc;
  function sk_X509_ATTRIBUTE_new_null: Pstack_st_X509_ATTRIBUTE;
  function sk_X509_ATTRIBUTE_dup(sk: Pointer): Pstack_st_X509_ATTRIBUTE;
  function ossl_check_const_X509_ATTRIBUTE_sk_type(const sk: Pstack_st_X509_ATTRIBUTE):POPENSSL_STACK;
  function sk_X509_ATTRIBUTE_push(sk, ptr: Pointer): int;
  function ossl_check_X509_ATTRIBUTE_sk_type( sk : Pstack_st_X509_ATTRIBUTE):POPENSSL_STACK;
  function ossl_check_X509_ATTRIBUTE_type( ptr : PX509_ATTRIBUTE):PX509_ATTRIBUTE;
  procedure sk_X509_ATTRIBUTE_free(sk: Pointer);
  function sk_X509_NAME_ENTRY_new_null:Pstack_st_X509_NAME_ENTRY;
  procedure sk_X509_NAME_ENTRY_free(sk: Pointer);
  function ossl_check_X509_NAME_ENTRY_sk_type(sk: Pstack_st_X509_NAME_ENTRY):POPENSSL_STACK;
  procedure sk_X509_NAME_ENTRY_pop_free(sk: Pointer; freefunc: sk_X509_NAME_ENTRY_freefunc);
  function ossl_check_X509_NAME_ENTRY_freefunc_type( fr : sk_X509_NAME_ENTRY_freefunc):OPENSSL_sk_freefunc;
  function sk_X509_NAME_ENTRY_num(sk: Pointer): int;
   function ossl_check_const_X509_NAME_ENTRY_sk_type(const sk: Pstack_st_X509_NAME_ENTRY):POPENSSL_STACK;
  function sk_X509_NAME_ENTRY_value(sk: Pointer; idx: int):PX509_NAME_ENTRY;
  function sk_X509_NAME_ENTRY_push(sk, ptr: Pointer): int;
  function ossl_check_X509_NAME_ENTRY_type( ptr : PX509_NAME_ENTRY):PX509_NAME_ENTRY;
  function sk_X509_NAME_ENTRY_set(sk: Pointer; idx: int; ptr: Pointer): PX509_NAME_ENTRY;
  function sk_X509_NAME_ENTRY_insert(sk, ptr: Pointer; idx: int): int;
  procedure sk_X509_ATTRIBUTE_pop_free(sk: Pointer; freefunc: sk_X509_ATTRIBUTE_freefunc);
  function ossl_check_X509_ATTRIBUTE_freefunc_type( fr : sk_X509_ATTRIBUTE_freefunc):OPENSSL_sk_freefunc;
  function sk_X509_NAME_ENTRY_delete(sk: Pointer; i:int): PX509_NAME_ENTRY;

implementation

uses openssl3.crypto.stack;

function sk_X509_NAME_ENTRY_delete(sk: Pointer; i:int): PX509_NAME_ENTRY;
begin
   Result := PX509_NAME_ENTRY(OPENSSL_sk_delete(ossl_check_X509_NAME_ENTRY_sk_type(sk), i))
end;

function ossl_check_X509_ATTRIBUTE_freefunc_type( fr : sk_X509_ATTRIBUTE_freefunc):OPENSSL_sk_freefunc;
begin
   result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_X509_ATTRIBUTE_pop_free(sk: Pointer; freefunc: sk_X509_ATTRIBUTE_freefunc);
begin
  OPENSSL_sk_pop_free(ossl_check_X509_ATTRIBUTE_sk_type(sk),
                      ossl_check_X509_ATTRIBUTE_freefunc_type(freefunc))
end;

function sk_X509_NAME_ENTRY_insert(sk, ptr: Pointer; idx: int): int;
begin
   Result := OPENSSL_sk_insert(ossl_check_X509_NAME_ENTRY_sk_type(sk),
              ossl_check_X509_NAME_ENTRY_type(ptr), (idx))
end;

function sk_X509_NAME_ENTRY_set(sk: Pointer; idx: int; ptr: Pointer): PX509_NAME_ENTRY;
begin
   Result := PX509_NAME_ENTRY(OPENSSL_sk_set(
                   ossl_check_X509_NAME_ENTRY_sk_type(sk), idx,
                   ossl_check_X509_NAME_ENTRY_type(ptr)))
end;




function ossl_check_X509_NAME_ENTRY_type( ptr : PX509_NAME_ENTRY):PX509_NAME_ENTRY;
begin
   result := ptr;
end;

function sk_X509_NAME_ENTRY_push(sk, ptr: Pointer): int;
begin
    OPENSSL_sk_push(ossl_check_X509_NAME_ENTRY_sk_type(sk),
                    ossl_check_X509_NAME_ENTRY_type(ptr))
end;

function sk_X509_NAME_ENTRY_value(sk: Pointer; idx: int):PX509_NAME_ENTRY;
begin
   Result := PX509_NAME_ENTRY(OPENSSL_sk_value(
               ossl_check_const_X509_NAME_ENTRY_sk_type(sk), idx))
end;




function ossl_check_const_X509_NAME_ENTRY_sk_type(const sk: Pstack_st_X509_NAME_ENTRY):POPENSSL_STACK;
begin
   result := POPENSSL_STACK( sk);
end;

function sk_X509_NAME_ENTRY_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_X509_NAME_ENTRY_sk_type(sk))
end;

function ossl_check_X509_NAME_ENTRY_freefunc_type( fr : sk_X509_NAME_ENTRY_freefunc):OPENSSL_sk_freefunc;
begin
   result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_X509_NAME_ENTRY_pop_free(sk: Pointer; freefunc: sk_X509_NAME_ENTRY_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_X509_NAME_ENTRY_sk_type(sk),
                 ossl_check_X509_NAME_ENTRY_freefunc_type(freefunc))
end;


function ossl_check_X509_NAME_ENTRY_sk_type(sk: Pstack_st_X509_NAME_ENTRY):POPENSSL_STACK;
begin
   result := POPENSSL_STACK(sk);
end;


procedure sk_X509_NAME_ENTRY_free(sk: Pointer);
begin
   OPENSSL_sk_free(ossl_check_X509_NAME_ENTRY_sk_type(sk))
end;

function sk_X509_NAME_ENTRY_new_null:Pstack_st_X509_NAME_ENTRY;
begin
   Result := Pstack_st_X509_NAME_ENTRY(OPENSSL_sk_new_null)
end;

procedure sk_X509_ATTRIBUTE_free(sk: Pointer);
begin
    OPENSSL_sk_free(ossl_check_X509_ATTRIBUTE_sk_type(sk))
end;

function ossl_check_X509_ATTRIBUTE_type( ptr : PX509_ATTRIBUTE):PX509_ATTRIBUTE;
begin
   result := ptr;
end;




function ossl_check_X509_ATTRIBUTE_sk_type( sk : Pstack_st_X509_ATTRIBUTE):POPENSSL_STACK;
begin
   result := POPENSSL_STACK( sk);
end;

function sk_X509_ATTRIBUTE_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_X509_ATTRIBUTE_sk_type(sk),
                             ossl_check_X509_ATTRIBUTE_type(ptr))
end;

function ossl_check_const_X509_ATTRIBUTE_sk_type(const sk :Pstack_st_X509_ATTRIBUTE):POPENSSL_STACK;
begin
   result := POPENSSL_STACK( sk);
end;

function sk_X509_ATTRIBUTE_dup(sk: Pointer): Pstack_st_X509_ATTRIBUTE;
begin
   Result := Pstack_st_X509_ATTRIBUTE(OPENSSL_sk_dup(ossl_check_const_X509_ATTRIBUTE_sk_type(sk)))
end;

function sk_X509_ATTRIBUTE_new_null: Pstack_st_X509_ATTRIBUTE;
begin
    Result := Pstack_st_X509_ATTRIBUTE(OPENSSL_sk_new_null)
end;

(************************************X509_REVOKED******************************)
function ossl_check_X509_REVOKED_type( ptr : PX509_REVOKED):PX509_REVOKED;
begin
  Result := ptr;
end;


function ossl_check_X509_REVOKED_sk_type( sk : PSTACK_st_X509_REVOKED):POPENSSL_STACK;
begin
  Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_REVOKED_compfunc_type( cmp : sk_X509_REVOKED_compfunc):OPENSSL_sk_compfunc;
begin
  Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_REVOKED_copyfunc_type( cpy : sk_X509_REVOKED_copyfunc):OPENSSL_sk_copyfunc;
begin
  Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_REVOKED_freefunc_type( fr : sk_X509_REVOKED_freefunc):OPENSSL_sk_freefunc;
begin
  Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509_REVOKED_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_X509_REVOKED_sk_type(sk))
end;


function sk_X509_REVOKED_value( sk : Pointer; idx: integer):PX509_REVOKED;
begin
   Result := PX509_REVOKED(OPENSSL_sk_value(ossl_check_X509_REVOKED_sk_type(sk), (idx)))
end;


function sk_X509_REVOKED_new( cmp : sk_X509_REVOKED_compfunc):PSTACK_st_X509_REVOKED;
begin
   Result := PSTACK_st_X509_REVOKED (OPENSSL_sk_new(ossl_check_X509_REVOKED_compfunc_type(cmp)))
end;


function sk_X509_REVOKED_new_null:PSTACK_st_X509_REVOKED;
begin
   Result := PSTACK_st_X509_REVOKED (OPENSSL_sk_new_null())
end;


function sk_X509_REVOKED_new_reserve( cmp : sk_X509_REVOKED_compfunc; n : integer):PSTACK_st_X509_REVOKED;
begin
   Result := PSTACK_st_X509_REVOKED (OPENSSL_sk_new_reserve(ossl_check_X509_REVOKED_compfunc_type(cmp), (n)))
end;


function sk_X509_REVOKED_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_X509_REVOKED_sk_type(sk), (n))
end;


procedure sk_X509_REVOKED_free( sk : Pointer);
begin
   OPENSSL_sk_free(ossl_check_X509_REVOKED_sk_type(sk))
end;


procedure sk_X509_REVOKED_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(ossl_check_X509_REVOKED_sk_type(sk))
end;


function sk_X509_REVOKED_delete( sk : Pointer; i : integer):PX509_REVOKED;
begin
   Result := PX509_REVOKED(OPENSSL_sk_delete(ossl_check_X509_REVOKED_sk_type(sk), (i)))
end;


function sk_X509_REVOKED_delete_ptr( sk, ptr : Pointer):PX509_REVOKED;
begin
   Result := PX509_REVOKED(OPENSSL_sk_delete_ptr(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr)))
end;


function sk_X509_REVOKED_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
end;


function sk_X509_REVOKED_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
end;


function sk_X509_REVOKED_pop( sk : Pointer):PX509_REVOKED;
begin
   Result := PX509_REVOKED(OPENSSL_sk_pop(ossl_check_X509_REVOKED_sk_type(sk)))
end;


function sk_X509_REVOKED_shift( sk : Pointer):PX509_REVOKED;
begin
   Result := PX509_REVOKED(OPENSSL_sk_shift(ossl_check_X509_REVOKED_sk_type(sk)))
end;


procedure sk_X509_REVOKED_pop_free( sk : Pointer; freefunc : sk_X509_REVOKED_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_X509_REVOKED_sk_type(sk),ossl_check_X509_REVOKED_freefunc_type(freefunc))
end;


function sk_X509_REVOKED_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr), (idx))
end;


function sk_X509_REVOKED_set( sk : Pointer; idx : integer; ptr : Pointer):PX509_REVOKED;
begin
   Result := PX509_REVOKED(OPENSSL_sk_set(ossl_check_X509_REVOKED_sk_type(sk), (idx), ossl_check_X509_REVOKED_type(ptr)))
end;


function sk_X509_REVOKED_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
end;


function sk_X509_REVOKED_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
end;


function sk_X509_REVOKED_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr), pnum)
end;


procedure sk_X509_REVOKED_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_X509_REVOKED_sk_type(sk))
end;


function sk_X509_REVOKED_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_X509_REVOKED_sk_type(sk))
end;


function sk_X509_REVOKED_dup( sk : Pointer):PSTACK_st_X509_REVOKED;
begin
   Result := PSTACK_st_X509_REVOKED (OPENSSL_sk_dup(ossl_check_X509_REVOKED_sk_type(sk)))
end;


function sk_X509_REVOKED_deep_copy( sk : Pointer; copyfunc : sk_X509_REVOKED_copyfunc; freefunc : sk_X509_REVOKED_freefunc):PSTACK_st_X509_REVOKED;
begin
   Result := PSTACK_st_X509_REVOKED (OPENSSL_sk_deep_copy(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_copyfunc_type(copyfunc), ossl_check_X509_REVOKED_freefunc_type(freefunc)))
end;


function sk_X509_REVOKED_set_cmp_func( sk : Pointer; cmp : sk_X509_REVOKED_compfunc):sk_X509_REVOKED_compfunc;
begin
   Result := sk_X509_REVOKED_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_compfunc_type(cmp)))
end;

(*****************************X509_CRL*****************************************)
function ossl_check_X509_CRL_type( ptr : PX509_CRL):PX509_CRL;
begin
  Result := ptr;
end;


function ossl_check_X509_CRL_sk_type( sk : PSTACK_st_X509_CRL):POPENSSL_STACK;
begin
  Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_CRL_compfunc_type( cmp : sk_X509_CRL_compfunc):OPENSSL_sk_compfunc;
begin
  Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_CRL_copyfunc_type( cpy : sk_X509_CRL_copyfunc):OPENSSL_sk_copyfunc;
begin
  Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_CRL_freefunc_type( fr : sk_X509_CRL_freefunc):OPENSSL_sk_freefunc;
begin
  Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509_CRL_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_X509_CRL_sk_type(sk))
end;


function sk_X509_CRL_value( sk : Pointer; idx: integer):PX509_CRL;
begin
   Result := PX509_CRL(OPENSSL_sk_value(ossl_check_X509_CRL_sk_type(sk), (idx)))
end;


function sk_X509_CRL_new( cmp : sk_X509_CRL_compfunc):PSTACK_st_X509_CRL;
begin
   Result := PSTACK_st_X509_CRL (OPENSSL_sk_new(ossl_check_X509_CRL_compfunc_type(cmp)))
end;


function sk_X509_CRL_new_null:PSTACK_st_X509_CRL;
begin
   Result := PSTACK_st_X509_CRL (OPENSSL_sk_new_null())
end;


function sk_X509_CRL_new_reserve( cmp : sk_X509_CRL_compfunc; n : integer):PSTACK_st_X509_CRL;
begin
   Result := PSTACK_st_X509_CRL (OPENSSL_sk_new_reserve(ossl_check_X509_CRL_compfunc_type(cmp), (n)))
end;


function sk_X509_CRL_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_X509_CRL_sk_type(sk), (n))
end;


procedure sk_X509_CRL_free( sk : Pointer);
begin
   OPENSSL_sk_free(ossl_check_X509_CRL_sk_type(sk))
end;


procedure sk_X509_CRL_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(ossl_check_X509_CRL_sk_type(sk))
end;


function sk_X509_CRL_delete( sk : Pointer; i : integer):PX509_CRL;
begin
   Result := PX509_CRL(OPENSSL_sk_delete(ossl_check_X509_CRL_sk_type(sk), (i)))
end;


function sk_X509_CRL_delete_ptr( sk, ptr : Pointer):PX509_CRL;
begin
   Result := PX509_CRL(OPENSSL_sk_delete_ptr(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr)))
end;


function sk_X509_CRL_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
end;


function sk_X509_CRL_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
end;


function sk_X509_CRL_pop( sk : Pointer):PX509_CRL;
begin
   Result := PX509_CRL(OPENSSL_sk_pop(ossl_check_X509_CRL_sk_type(sk)))
end;


function sk_X509_CRL_shift( sk : Pointer):PX509_CRL;
begin
   Result := PX509_CRL(OPENSSL_sk_shift(ossl_check_X509_CRL_sk_type(sk)))
end;


procedure sk_X509_CRL_pop_free( sk : Pointer; freefunc : sk_X509_CRL_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_X509_CRL_sk_type(sk),ossl_check_X509_CRL_freefunc_type(freefunc))
end;


function sk_X509_CRL_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr), (idx))
end;


function sk_X509_CRL_set( sk : Pointer; idx : integer; ptr : Pointer):PX509_CRL;
begin
   Result := PX509_CRL(OPENSSL_sk_set(ossl_check_X509_CRL_sk_type(sk), (idx), ossl_check_X509_CRL_type(ptr)))
end;


function sk_X509_CRL_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
end;


function sk_X509_CRL_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
end;


function sk_X509_CRL_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr), pnum)
end;


procedure sk_X509_CRL_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_X509_CRL_sk_type(sk))
end;


function sk_X509_CRL_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_X509_CRL_sk_type(sk))
end;


function sk_X509_CRL_dup( sk : Pointer):PSTACK_st_X509_CRL;
begin
   Result := PSTACK_st_X509_CRL (OPENSSL_sk_dup(ossl_check_X509_CRL_sk_type(sk)))
end;


function sk_X509_CRL_deep_copy( sk : Pointer; copyfunc : sk_X509_CRL_copyfunc; freefunc : sk_X509_CRL_freefunc):PSTACK_st_X509_CRL;
begin
   Result := PSTACK_st_X509_CRL (OPENSSL_sk_deep_copy(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_copyfunc_type(copyfunc), ossl_check_X509_CRL_freefunc_type(freefunc)))
end;


function sk_X509_CRL_set_cmp_func( sk : Pointer; cmp : sk_X509_CRL_compfunc):sk_X509_CRL_compfunc;
begin
   Result := sk_X509_CRL_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_compfunc_type(cmp)))
end;

(*******************************X509_EXTENTION*********************************)
function ossl_check_X509_EXTENSION_type( ptr : PX509_EXTENSION):PX509_EXTENSION;
begin
   RESULT := ptr;
end;


function sk_X509_EXTENSION_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_X509_EXTENSION_sk_type(sk));
end;


function sk_X509_EXTENSION_value( sk : Pointer; idx : integer):PX509_EXTENSION;
begin
   Result := PX509_EXTENSION(OPENSSL_sk_value(ossl_check_X509_EXTENSION_sk_type(sk), idx));
end;


function sk_X509_EXTENSION_new( cmp : sk_X509_EXTENSION_compfunc):PSTACK_st_X509_EXTENSION;
begin
   Result := PSTACK_st_X509_EXTENSION (OPENSSL_sk_new(ossl_check_X509_EXTENSION_compfunc_type(cmp)));
end;


function sk_X509_EXTENSION_new_null:PSTACK_st_X509_EXTENSION ;
begin
   Result := PSTACK_st_X509_EXTENSION (OPENSSL_sk_new_null());
end;


function sk_X509_EXTENSION_new_reserve( cmp : sk_X509_EXTENSION_compfunc; n: Integer):PSTACK_st_X509_EXTENSION ;
begin
   Result := PSTACK_st_X509_EXTENSION (OPENSSL_sk_new_reserve(ossl_check_X509_EXTENSION_compfunc_type(cmp), (n)))
end;


function sk_X509_EXTENSION_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_X509_EXTENSION_sk_type(sk), n);
end;


procedure sk_X509_EXTENSION_free( sk : Pointer);
begin
   OPENSSL_sk_free(ossl_check_X509_EXTENSION_sk_type(sk));
end;


procedure sk_X509_EXTENSION_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(ossl_check_X509_EXTENSION_sk_type(sk))
end;


function sk_X509_EXTENSION_delete( sk : Pointer; i : integer):PX509_EXTENSION;
begin
   Result := PX509_EXTENSION(OPENSSL_sk_delete(ossl_check_X509_EXTENSION_sk_type(sk), (i)))
end;


function sk_X509_EXTENSION_delete_ptr( sk, ptr : Pointer):PX509_EXTENSION;
begin
   Result := PX509_EXTENSION(OPENSSL_sk_delete_ptr(ossl_check_X509_EXTENSION_sk_type(sk),
                 ossl_check_X509_EXTENSION_type(ptr)))
end;


function sk_X509_EXTENSION_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
end;


function sk_X509_EXTENSION_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
end;


function sk_X509_EXTENSION_pop( sk : Pointer):PX509_EXTENSION;
begin
   Result := PX509_EXTENSION(OPENSSL_sk_pop(ossl_check_X509_EXTENSION_sk_type(sk)))
end;


function sk_X509_EXTENSION_shift( sk : Pointer):PX509_EXTENSION;
begin
   Result := PX509_EXTENSION(OPENSSL_sk_shift(ossl_check_X509_EXTENSION_sk_type(sk)))
end;


procedure sk_X509_EXTENSION_pop_free( sk : Pointer; freefunc : sk_X509_EXTENSION_freefunc);
begin
    OPENSSL_sk_pop_free(ossl_check_X509_EXTENSION_sk_type(sk),ossl_check_X509_EXTENSION_freefunc_type(freefunc))
end;


function sk_X509_EXTENSION_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr), (idx))
end;


function sk_X509_EXTENSION_set( sk : Pointer; idx : integer; ptr : Pointer):PX509_EXTENSION;
begin
   Result := PX509_EXTENSION(OPENSSL_sk_set(ossl_check_X509_EXTENSION_sk_type(sk), (idx), ossl_check_X509_EXTENSION_type(ptr)))
end;


function sk_X509_EXTENSION_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
end;


function sk_X509_EXTENSION_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
end;


function sk_X509_EXTENSION_find_all( sk, ptr : Pointer; pnum : PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr), pnum)
end;


procedure sk_X509_EXTENSION_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_X509_EXTENSION_sk_type(sk))
end;


function sk_X509_EXTENSION_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_X509_EXTENSION_sk_type(sk))
end;


function sk_X509_EXTENSION_dup( sk : Pointer):PSTACK_st_X509_EXTENSION;
begin
   Result := PSTACK_st_X509_EXTENSION (OPENSSL_sk_dup(ossl_check_X509_EXTENSION_sk_type(sk)))
end;


function sk_X509_EXTENSION_deep_copy( sk : Pointer; copyfunc : sk_X509_EXTENSION_copyfunc; freefunc : sk_X509_EXTENSION_freefunc):PSTACK_st_X509_EXTENSION;
begin
   Result := PSTACK_st_X509_EXTENSION (OPENSSL_sk_deep_copy(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_copyfunc_type(copyfunc), ossl_check_X509_EXTENSION_freefunc_type(freefunc)))
end;


function sk_X509_EXTENSION_set_cmp_func( sk : Pointer; cmp : sk_X509_EXTENSION_compfunc):sk_X509_EXTENSION_compfunc;
begin
   Result := sk_X509_EXTENSION_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_compfunc_type(cmp)))
end;

(*********************************X509_EXTENSION*******************************)
function ossl_check_X509_EXTENSION_sk_type( sk : PSTACK_st_X509_EXTENSION):POPENSSL_STACK;
begin
   Result :=POPENSSL_STACK (sk);
end;


function ossl_check_X509_EXTENSION_compfunc_type( cmp : sk_X509_EXTENSION_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_EXTENSION_copyfunc_type( cpy : sk_X509_EXTENSION_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result :=OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_EXTENSION_freefunc_type( fr : sk_X509_EXTENSION_freefunc):OPENSSL_sk_freefunc;
begin
   Result :=OPENSSL_sk_freefunc(fr);
end;


(********************************x509******************************************)
function ossl_check_const_X509_sk_type(const sk: PSTACK_st_X509): POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;

function sk_X509_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_const_X509_sk_type(sk))
end;


function sk_X509_value( sk : Pointer; idx : integer):PX509;
begin
   Result := PX509 (OPENSSL_sk_value(ossl_check_const_X509_sk_type(sk), (idx)));
end;


function sk_X509_new( cmp : sk_X509_compfunc):PSTACK_st_X509;
begin
   Result := PSTACK_st_X509(OPENSSL_sk_new(ossl_check_X509_compfunc_type(cmp)));
end;


function sk_X509_new_null:PSTACK_st_X509;
begin
   Result := PSTACK_st_X509(OPENSSL_sk_new_null());
end;


function sk_X509_new_reserve( cmp : sk_X509_compfunc; n : integer):PSTACK_st_X509;
begin
   Result := PSTACK_st_X509(OPENSSL_sk_new_reserve(
                             ossl_check_X509_compfunc_type(cmp), n));
end;


function sk_X509_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_X509_sk_type(sk), (n))
end;


procedure sk_X509_free( sk : Pointer);
begin
   OPENSSL_sk_free(ossl_check_X509_sk_type(sk));
end;


procedure sk_X509_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(ossl_check_X509_sk_type(sk));
end;


function sk_X509_delete( sk : Pointer; i : integer):PX509;
begin
   Result := PX509 (OPENSSL_sk_delete(ossl_check_X509_sk_type(sk), i));
end;


function sk_X509_delete_ptr( sk, ptr : Pointer):PX509;
begin
   Result := PX509 (OPENSSL_sk_delete_ptr(ossl_check_X509_sk_type(sk),
                                       ossl_check_X509_type(ptr)));
end;


function sk_X509_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
end;


function sk_X509_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
end;


function sk_X509_pop( sk : Pointer):PX509;
begin
   Result := PX509 (OPENSSL_sk_pop(ossl_check_X509_sk_type(sk)));
end;


function sk_X509_shift( sk : Pointer):PX509;
begin
   Result := PX509 (OPENSSL_sk_shift(ossl_check_X509_sk_type(sk)));
end;


procedure sk_X509_pop_free( sk : Pointer; freefunc : sk_X509_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_X509_sk_type(sk),
                           ossl_check_X509_freefunc_type(freefunc));
end;


function sk_X509_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr), (idx))
end;


function sk_X509_set( sk: Pointer; idx: Integer; ptr : Pointer):PX509;
begin
   Result := PX509 (OPENSSL_sk_set(ossl_check_X509_sk_type(sk),
                      idx, ossl_check_X509_type(ptr)))
end;


function sk_X509_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
end;


function sk_X509_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
end;


function sk_X509_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_X509_sk_type(sk),
            ossl_check_X509_type(ptr), pnum) ;
end;


procedure sk_X509_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_X509_sk_type(sk));
end;


function sk_X509_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_const_X509_sk_type(sk))
end;


function sk_X509_dup( sk : Pointer):PSTACK_st_X509;
begin
   Result := PSTACK_st_X509(OPENSSL_sk_dup(ossl_check_const_X509_sk_type(sk)));
end;


function sk_X509_deep_copy( sk : Pointer; copyfunc : sk_X509_copyfunc; freefunc : sk_X509_freefunc):PSTACK_st_X509;
begin
   Result := PSTACK_st_X509(OPENSSL_sk_deep_copy(ossl_check_const_X509_sk_type(sk),
      ossl_check_X509_copyfunc_type(copyfunc), ossl_check_X509_freefunc_type(freefunc)));
end;


function ossl_check_X509_type( ptr : PX509):PX509;
begin
   Result := ptr;
end;


function ossl_check_X509_sk_type( sk : PSTACK_st_X509):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_compfunc_type( cmp : sk_X509_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_copyfunc_type( cpy : sk_X509_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_freefunc_type( fr : sk_X509_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

end.
