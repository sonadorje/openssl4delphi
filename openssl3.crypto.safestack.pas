unit openssl3.crypto.safestack;

interface
uses  OpenSSL.Api;

 function sk_OPENSSL_CSTRING_new_null(): POPENSSL_STACK;
 function sk_OPENSSL_CSTRING_push(sk, ptr: Pointer): Integer ;
 function sk_OPENSSL_CSTRING_pop(sk: Pointer): PUTF8Char ;
 procedure sk_OPENSSL_CSTRING_free(sk: pointer) ;
 function ossl_check_OPENSSL_CSTRING_type(const ptr : PUTF8Char):PUTF8Char;
 function ossl_check_const_OPENSSL_CSTRING_sk_type(const sk : Pstack_st_OPENSSL_CSTRING):POPENSSL_STACK;
  function ossl_check_OPENSSL_CSTRING_sk_type( sk : Pstack_st_OPENSSL_CSTRING):POPENSSL_STACK;
  function ossl_check_OPENSSL_CSTRING_compfunc_type( cmp : sk_OPENSSL_CSTRING_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_OPENSSL_CSTRING_copyfunc_type( cpy : sk_OPENSSL_CSTRING_copyfunc):OPENSSL_sk_copyfunc;


  function sk_OPENSSL_CSTRING_num(sk: Pointer): int;
  function sk_OPENSSL_CSTRING_value(sk: Pointer; idx: int): PUTF8Char;

implementation
uses openssl3.crypto.stack;

function sk_OPENSSL_CSTRING_value(sk: Pointer; idx: int): PUTF8Char;
begin
   Result := PUTF8Char(OPENSSL_sk_value(ossl_check_const_OPENSSL_CSTRING_sk_type(sk), idx))
end;

function sk_OPENSSL_CSTRING_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_OPENSSL_CSTRING_sk_type(sk))
end;

function sk_OPENSSL_CSTRING_pop(sk: Pointer): PUTF8Char ;
begin
  Result := PUTF8Char(OPENSSL_sk_pop(ossl_check_OPENSSL_CSTRING_sk_type(sk)));
end;

function sk_OPENSSL_CSTRING_push(sk, ptr: Pointer): Integer ;
begin
  Result := OPENSSL_sk_push(POPENSSL_STACK(sk), ptr);
end;

function sk_OPENSSL_CSTRING_new_null(): POPENSSL_STACK;
begin
  Result := PSTACK_st_OPENSSL_CSTRING(OPENSSL_sk_new_null());
end;

function ossl_check_OPENSSL_CSTRING_type(const ptr : PUTF8Char):PUTF8Char;
begin
    Result := ptr;
end;


function ossl_check_const_OPENSSL_CSTRING_sk_type(const sk : Pstack_st_OPENSSL_CSTRING):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_OPENSSL_CSTRING_sk_type( sk : Pstack_st_OPENSSL_CSTRING):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_OPENSSL_CSTRING_compfunc_type( cmp : sk_OPENSSL_CSTRING_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_OPENSSL_CSTRING_copyfunc_type( cpy : sk_OPENSSL_CSTRING_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;

procedure sk_OPENSSL_CSTRING_free(sk: pointer) ;
begin
  OPENSSL_sk_free(ossl_check_OPENSSL_CSTRING_sk_type(sk));
end;
end.
