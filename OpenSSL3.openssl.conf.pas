unit OpenSSL3.openssl.conf;

interface
uses OpenSSL.Api;



function ossl_check_CONF_VALUE_type( ptr : PCONF_VALUE):PCONF_VALUE;
function ossl_check_CONF_VALUE_sk_type( sk : PSTACK_st_CONF_VALUE):POPENSSL_STACK;
function ossl_check_CONF_VALUE_compfunc_type( cmp : sk_CONF_VALUE_compfunc):OPENSSL_sk_compfunc;
function ossl_check_CONF_VALUE_copyfunc_type( cpy : sk_CONF_VALUE_copyfunc):OPENSSL_sk_copyfunc;
function ossl_check_CONF_VALUE_freefunc_type( fr : sk_CONF_VALUE_freefunc):OPENSSL_sk_freefunc;

function sk_CONF_VALUE_num( sk : Pointer):integer;
function sk_CONF_VALUE_reserve( sk : Pointer; n: Integer):integer;
function sk_CONF_VALUE_free( sk : Pointer):integer;
function sk_CONF_VALUE_zero( sk : Pointer):integer;
function sk_CONF_VALUE_delete( sk : Pointer; i : integer):PCONF_VALUE;
function sk_CONF_VALUE_delete_ptr( sk, ptr : Pointer):PCONF_VALUE;
function sk_CONF_VALUE_push( sk, ptr : Pointer):integer;
function sk_CONF_VALUE_unshift( sk, ptr : Pointer):integer;
function sk_CONF_VALUE_pop( sk : Pointer):PCONF_VALUE;
function sk_CONF_VALUE_shift( sk : Pointer):PCONF_VALUE;
procedure sk_CONF_VALUE_pop_free( sk : Pointer; freefunc : sk_CONF_VALUE_freefunc);
function sk_CONF_VALUE_insert( sk, ptr : Pointer; idx : integer):integer;
function sk_CONF_VALUE_set( sk : Pointer; idx : integer; ptr : Pointer):PCONF_VALUE;
function sk_CONF_VALUE_find( sk, ptr : Pointer):integer;
function sk_CONF_VALUE_find_ex( sk, ptr : Pointer):integer;
function sk_CONF_VALUE_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
procedure sk_CONF_VALUE_sort( sk : Pointer);
function sk_CONF_VALUE_is_sorted( sk : Pointer):integer;
function sk_CONF_VALUE_dup( sk : Pointer):PSTACK_st_CONF_VALUE;
function sk_CONF_VALUE_deep_copy( sk : Pointer; copyfunc : sk_CONF_VALUE_copyfunc; freefunc : sk_CONF_VALUE_freefunc):PSTACK_st_CONF_VALUE;
function sk_CONF_VALUE_set_cmp_func( sk : Pointer; cmp : sk_CONF_VALUE_compfunc):sk_CONF_VALUE_compfunc;
function sk_CONF_VALUE_value(sk: Pointer; idx: integer): PCONF_VALUE;
function sk_CONF_VALUE_new_null(): PSTACK_st_CONF_VALUE;
function sk_CONF_VALUE_new(cmp:sk_CONF_VALUE_compfunc) : PSTACK_st_CONF_VALUE;
function lh_CONF_VALUE_retrieve(lh: Pointer; ptr: PCONF_VALUE):PCONF_VALUE;

function ossl_check_CONF_VALUE_lh_plain_type( ptr : PCONF_VALUE):PCONF_VALUE;
  function ossl_check_const_CONF_VALUE_lh_plain_type(const ptr : PCONF_VALUE):PCONF_VALUE;
  function ossl_check_const_CONF_VALUE_lh_type(const lh : Plhash_st_CONF_VALUE):POPENSSL_LHASH;
  function ossl_check_CONF_VALUE_lh_type( lh : Plhash_st_CONF_VALUE):POPENSSL_LHASH;
  function ossl_check_CONF_VALUE_lh_compfunc_type( cmp : lh_CONF_VALUE_compfunc):TOPENSSL_LH_COMPFUNC;
  function ossl_check_CONF_VALUE_lh_hashfunc_type( hfn : lh_CONF_VALUE_hashfunc):TOPENSSL_LH_HASHFUNC;
  function ossl_check_CONF_VALUE_lh_doallfunc_type( dfn : lh_CONF_VALUE_doallfunc):TOPENSSL_LH_DOALL_FUNC;
  function lh_CONF_VALUE_new(hfn: lh_CONF_VALUE_hashfunc; cmp: lh_CONF_VALUE_compfunc): Plhash_st_CONF_VALUE;
  function lh_CONF_VALUE_insert(lh: Plhash_st_CONF_VALUE; ptr: Pointer): PCONF_VALUE;
  function lh_CONF_VALUE_error(lh: Plhash_st_CONF_VALUE): int;
  procedure lh_CONF_VALUE_set_down_load(lh: Plhash_st_CONF_VALUE; dl: uint32);
  function lh_CONF_VALUE_delete(lh: Plhash_st_CONF_VALUE; ptr: Pointer): PCONF_VALUE;
  procedure lh_CONF_VALUE_doall(lh: Plhash_st_CONF_VALUE; dfn: lh_CONF_VALUE_doallfunc);
  procedure lh_CONF_VALUE_free(lh: Plhash_st_CONF_VALUE);

implementation
uses openssl3.crypto.stack, openssl3.crypto.lhash;

procedure lh_CONF_VALUE_free(lh: Plhash_st_CONF_VALUE);
begin
   OPENSSL_LH_free(ossl_check_CONF_VALUE_lh_type(lh))
end;

procedure lh_CONF_VALUE_doall(lh: Plhash_st_CONF_VALUE; dfn: lh_CONF_VALUE_doallfunc);
begin
    OPENSSL_LH_doall(ossl_check_CONF_VALUE_lh_type(lh),
                     ossl_check_CONF_VALUE_lh_doallfunc_type(dfn))
end;

function lh_CONF_VALUE_delete(lh: Plhash_st_CONF_VALUE; ptr: Pointer): PCONF_VALUE;
begin
   Result := PCONF_VALUE(OPENSSL_LH_delete(ossl_check_CONF_VALUE_lh_type(lh),
                               ossl_check_const_CONF_VALUE_lh_plain_type(ptr)))
end;

procedure lh_CONF_VALUE_set_down_load(lh: Plhash_st_CONF_VALUE; dl: uint32);
begin
   OPENSSL_LH_set_down_load(ossl_check_CONF_VALUE_lh_type(lh), dl)
end;

function lh_CONF_VALUE_error(lh: Plhash_st_CONF_VALUE): int;
begin
   Result :=  OPENSSL_LH_error(ossl_check_CONF_VALUE_lh_type(lh))
end;

function lh_CONF_VALUE_insert(lh: Plhash_st_CONF_VALUE; ptr: Pointer): PCONF_VALUE;
begin
   Result := OPENSSL_LH_insert(POPENSSL_LHASH(lh), ptr);
end;

function lh_CONF_VALUE_new(hfn: lh_CONF_VALUE_hashfunc; cmp: lh_CONF_VALUE_compfunc): Plhash_st_CONF_VALUE;
begin
   Result := Plhash_st_CONF_VALUE(OPENSSL_LH_new(ossl_check_CONF_VALUE_lh_hashfunc_type(hfn),
                                                 ossl_check_CONF_VALUE_lh_compfunc_type(cmp)))
end;



function ossl_check_CONF_VALUE_lh_plain_type( ptr : PCONF_VALUE):PCONF_VALUE;
begin
 Exit(ptr);
end;


function ossl_check_const_CONF_VALUE_lh_plain_type(const ptr : PCONF_VALUE):PCONF_VALUE;
begin
 Exit(ptr);
end;


function ossl_check_const_CONF_VALUE_lh_type(const lh : Plhash_st_CONF_VALUE):POPENSSL_LHASH;
begin
 Result := POPENSSL_LHASH(lh);
end;


function ossl_check_CONF_VALUE_lh_type( lh : Plhash_st_CONF_VALUE):POPENSSL_LHASH;
begin
 Result := POPENSSL_LHASH(lh);
end;


function ossl_check_CONF_VALUE_lh_compfunc_type( cmp : lh_CONF_VALUE_compfunc):TOPENSSL_LH_COMPFUNC;
begin
 Result := TOPENSSL_LH_COMPFUNC(cmp);
end;


function ossl_check_CONF_VALUE_lh_hashfunc_type( hfn : lh_CONF_VALUE_hashfunc):TOPENSSL_LH_HASHFUNC;
begin
 Result := TOPENSSL_LH_HASHFUNC(hfn);
end;


function ossl_check_CONF_VALUE_lh_doallfunc_type( dfn : lh_CONF_VALUE_doallfunc):TOPENSSL_LH_DOALL_FUNC;
begin
 Result := TOPENSSL_LH_DOALL_FUNC(dfn);
end;

function lh_CONF_VALUE_retrieve(lh: Pointer; ptr: PCONF_VALUE):PCONF_VALUE;
begin
    Result := OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), ptr)
end;

function sk_CONF_VALUE_new(cmp:sk_CONF_VALUE_compfunc) : PSTACK_st_CONF_VALUE;
begin
   Result := PSTACK_st_CONF_VALUE(OPENSSL_sk_new(ossl_check_CONF_VALUE_compfunc_type(cmp)));
end;

function sk_CONF_VALUE_new_null(): PSTACK_st_CONF_VALUE;
begin
   Result := OPENSSL_sk_new_null;
end;

function sk_CONF_VALUE_value(sk: Pointer; idx: integer): PCONF_VALUE;
begin
   Result := PCONF_VALUE (OPENSSL_sk_value(ossl_check_CONF_VALUE_sk_type(sk), idx));
end;

function sk_CONF_VALUE_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_CONF_VALUE_sk_type(sk));
end;


function sk_CONF_VALUE_reserve( sk : Pointer; n: integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_CONF_VALUE_sk_type(sk), n);
end;


function sk_CONF_VALUE_free( sk : Pointer):integer;
begin
   OPENSSL_sk_free(sk)
end;


function sk_CONF_VALUE_zero( sk : Pointer):integer;
begin
   OPENSSL_sk_zero(ossl_check_CONF_VALUE_sk_type(sk))
end;


function sk_CONF_VALUE_delete( sk : Pointer; i : integer): PCONF_VALUE;
begin
  Result := PCONF_VALUE (OPENSSL_sk_delete(ossl_check_CONF_VALUE_sk_type(sk), i));
end;


function sk_CONF_VALUE_delete_ptr( sk, ptr : Pointer):PCONF_VALUE;
begin
  Result := OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), ptr);
end;


function sk_CONF_VALUE_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), ptr)
end;


function sk_CONF_VALUE_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_type(ptr))
end;


function sk_CONF_VALUE_pop( sk : Pointer):PCONF_VALUE;
begin
   Result := PCONF_VALUE (OPENSSL_sk_pop(ossl_check_CONF_VALUE_sk_type(sk)));
end;


function sk_CONF_VALUE_shift( sk : Pointer):PCONF_VALUE;
begin
  Result := PCONF_VALUE (OPENSSL_sk_shift(ossl_check_CONF_VALUE_sk_type(sk)))
end;


procedure sk_CONF_VALUE_pop_free( sk : Pointer; freefunc : sk_CONF_VALUE_freefunc);
begin
  OPENSSL_sk_pop_free(ossl_check_CONF_VALUE_sk_type(sk),
             ossl_check_CONF_VALUE_freefunc_type(freefunc)) ;
end;


function sk_CONF_VALUE_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_type(ptr), (idx))
end;


function sk_CONF_VALUE_set( sk : Pointer; idx : integer; ptr : Pointer):PCONF_VALUE;
begin
  Result := PCONF_VALUE (OPENSSL_sk_set(ossl_check_CONF_VALUE_sk_type(sk), (idx), ossl_check_CONF_VALUE_type(ptr)))
end;


function sk_CONF_VALUE_find( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_type(ptr))
end;


function sk_CONF_VALUE_find_ex( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find_ex(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_type(ptr))
end;


function sk_CONF_VALUE_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_type(ptr), pnum);
end;


procedure sk_CONF_VALUE_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_CONF_VALUE_sk_type(sk));
end;


function sk_CONF_VALUE_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_CONF_VALUE_sk_type(sk));
end;


function sk_CONF_VALUE_dup( sk : Pointer):PSTACK_st_CONF_VALUE;
begin
   Result := PSTACK_st_CONF_VALUE(OPENSSL_sk_dup(ossl_check_CONF_VALUE_sk_type(sk)))
end;


function sk_CONF_VALUE_deep_copy( sk : Pointer; copyfunc : sk_CONF_VALUE_copyfunc; freefunc : sk_CONF_VALUE_freefunc):PSTACK_st_CONF_VALUE;
begin
   Result := PSTACK_st_CONF_VALUE(OPENSSL_sk_deep_copy(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_copyfunc_type(copyfunc), ossl_check_CONF_VALUE_freefunc_type(freefunc)))
end;


function sk_CONF_VALUE_set_cmp_func( sk : Pointer; cmp : sk_CONF_VALUE_compfunc):sk_CONF_VALUE_compfunc;
begin
   Result := sk_CONF_VALUE_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_CONF_VALUE_sk_type(sk), ossl_check_CONF_VALUE_compfunc_type(cmp)))
end;

function ossl_check_CONF_VALUE_type( ptr : PCONF_VALUE):PCONF_VALUE;
begin
   Result := ptr;
end;


function ossl_check_CONF_VALUE_sk_type( sk : PSTACK_st_CONF_VALUE):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_CONF_VALUE_compfunc_type( cmp : sk_CONF_VALUE_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_CONF_VALUE_copyfunc_type( cpy : sk_CONF_VALUE_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_CONF_VALUE_freefunc_type( fr : sk_CONF_VALUE_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

end.
