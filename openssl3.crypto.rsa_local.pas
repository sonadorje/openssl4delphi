unit openssl3.crypto.rsa_local;

interface
uses OpenSSL.Api;

type
  sk_RSA_PRIME_INFO_compfunc = function (const  a, b: PRSA_PRIME_INFO):integer;
  sk_RSA_PRIME_INFO_freefunc = procedure(a: PRSA_PRIME_INFO);
  sk_RSA_PRIME_INFO_copyfunc = function(const a: PRSA_PRIME_INFO): PRSA_PRIME_INFO;




  function sk_RSA_PRIME_INFO_num( sk : Pointer):integer;
  function sk_RSA_PRIME_INFO_value( sk : Pointer;idx: integer):PRSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_new( cmp : sk_RSA_PRIME_INFO_compfunc):PSTACK_st_RSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_new_null:PSTACK_st_RSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_new_reserve( cmp : sk_RSA_PRIME_INFO_compfunc; n : integer):PSTACK_st_RSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_reserve( sk : Pointer; n : integer):integer;
  procedure sk_RSA_PRIME_INFO_free( sk : Pointer);
  procedure sk_RSA_PRIME_INFO_zero( sk : Pointer);
  function sk_RSA_PRIME_INFO_delete( sk : Pointer; i : integer):PRSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_delete_ptr( sk, ptr : Pointer):PRSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_push( sk, ptr : Pointer):integer;
  function sk_RSA_PRIME_INFO_unshift( sk, ptr : Pointer):integer;
  function sk_RSA_PRIME_INFO_pop( sk : Pointer):PRSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_shift( sk : Pointer):PRSA_PRIME_INFO;
  procedure sk_RSA_PRIME_INFO_pop_free( sk : Pointer; freefunc : sk_RSA_PRIME_INFO_freefunc);
  function sk_RSA_PRIME_INFO_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_RSA_PRIME_INFO_set( sk : Pointer; idx : integer; ptr : Pointer):PRSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_find( sk, ptr : Pointer):integer;
  function sk_RSA_PRIME_INFO_find_ex( sk, ptr : Pointer):integer;
  function sk_RSA_PRIME_INFO_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_RSA_PRIME_INFO_sort( sk : Pointer);
  function sk_RSA_PRIME_INFO_is_sorted( sk : Pointer):integer;
  function sk_RSA_PRIME_INFO_dup( sk : Pointer):PSTACK_st_RSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_deep_copy( sk : Pointer; copyfunc : sk_RSA_PRIME_INFO_copyfunc; freefunc : sk_RSA_PRIME_INFO_freefunc):PSTACK_st_RSA_PRIME_INFO;
  function sk_RSA_PRIME_INFO_set_cmp_func( sk : Pointer; cmp : sk_RSA_PRIME_INFO_compfunc):sk_RSA_PRIME_INFO_compfunc;

implementation
uses openssl3.crypto.stack;

function sk_RSA_PRIME_INFO_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_RSA_PRIME_INFO_value( sk : Pointer; idx: integer):PRSA_PRIME_INFO;
begin
   Result := PRSA_PRIME_INFO(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_RSA_PRIME_INFO_new( cmp : sk_RSA_PRIME_INFO_compfunc):PSTACK_st_RSA_PRIME_INFO;
begin
   Result := PSTACK_st_RSA_PRIME_INFO (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_RSA_PRIME_INFO_new_null:PSTACK_st_RSA_PRIME_INFO;
begin
   Result := PSTACK_st_RSA_PRIME_INFO (OPENSSL_sk_new_null())
end;


function sk_RSA_PRIME_INFO_new_reserve( cmp : sk_RSA_PRIME_INFO_compfunc; n : integer):PSTACK_st_RSA_PRIME_INFO;
begin
   Result := PSTACK_st_RSA_PRIME_INFO (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_RSA_PRIME_INFO_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_RSA_PRIME_INFO_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_RSA_PRIME_INFO_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_RSA_PRIME_INFO_delete( sk : Pointer; i : integer):PRSA_PRIME_INFO;
begin
   Result := PRSA_PRIME_INFO(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_RSA_PRIME_INFO_delete_ptr( sk, ptr : Pointer):PRSA_PRIME_INFO;
begin
   Result := PRSA_PRIME_INFO(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_RSA_PRIME_INFO_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_RSA_PRIME_INFO_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_RSA_PRIME_INFO_pop( sk : Pointer):PRSA_PRIME_INFO;
begin
   Result := PRSA_PRIME_INFO(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_RSA_PRIME_INFO_shift( sk : Pointer):PRSA_PRIME_INFO;
begin
   Result := PRSA_PRIME_INFO(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_RSA_PRIME_INFO_pop_free( sk : Pointer; freefunc : sk_RSA_PRIME_INFO_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_RSA_PRIME_INFO_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_RSA_PRIME_INFO_set( sk : Pointer; idx : integer; ptr : Pointer):PRSA_PRIME_INFO;
begin
   Result := PRSA_PRIME_INFO(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_RSA_PRIME_INFO_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_RSA_PRIME_INFO_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_RSA_PRIME_INFO_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_RSA_PRIME_INFO_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_RSA_PRIME_INFO_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_RSA_PRIME_INFO_dup( sk : Pointer):PSTACK_st_RSA_PRIME_INFO;
begin
   Result := PSTACK_st_RSA_PRIME_INFO (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_RSA_PRIME_INFO_deep_copy( sk : Pointer; copyfunc : sk_RSA_PRIME_INFO_copyfunc; freefunc : sk_RSA_PRIME_INFO_freefunc):PSTACK_st_RSA_PRIME_INFO;
begin
   Result := PSTACK_st_RSA_PRIME_INFO (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_RSA_PRIME_INFO_set_cmp_func( sk : Pointer; cmp : sk_RSA_PRIME_INFO_compfunc):sk_RSA_PRIME_INFO_compfunc;
begin
   Result := sk_RSA_PRIME_INFO_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;

end.
