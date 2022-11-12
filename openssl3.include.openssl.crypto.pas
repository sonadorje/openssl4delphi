unit openssl3.include.openssl.crypto;

interface
uses OpenSSL.Api, openssl3.crypto.mem_sec;

type
   sk_void_compfunc =function(const a, b: PPointer): int;
   sk_void_freefunc= procedure(a: Pointer);
   sk_void_copyfunc = function(const a: Pointer): Pointer;

  procedure sk_void_free(sk: Pointer);
  function ossl_check_void_type( ptr : Pointer):Pointer;
  function ossl_check_void_sk_type(sk: Pointer):POPENSSL_STACK;
  function ossl_check_void_compfunc_type( cmp : sk_void_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_void_copyfunc_type( cpy : sk_void_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_void_freefunc_type( fr : sk_void_freefunc):OPENSSL_sk_freefunc;
  function sk_void_num(const sk : POPENSSL_STACK):int;
  function sk_void_value(sk : POPENSSL_STACK; idx: int): Pointer;
  function sk_void_new_null():PSTACK_st_void;
  function sk_void_push(sk: POPENSSL_STACK; ptr: Pointer): int;
  function sk_void_set(sk: POPENSSL_STACK; idx: int; ptr: Pointer): Pointer;
  function sk_void_pop(sk: Pointer): Pointer;

  const
    OPENSSL_secure_clear_free: procedure(ptr : Pointer; num : size_t) = CRYPTO_secure_clear_free;

implementation

uses openssl3.crypto.stack, openssl3.crypto.cryptlib;

function sk_void_pop(sk: Pointer): Pointer;
begin
   Result := Pointer(OPENSSL_sk_pop(ossl_check_void_sk_type(sk)))
end;

function sk_void_set(sk: POPENSSL_STACK; idx: int; ptr: Pointer): Pointer;
begin
  Result := OPENSSL_sk_set(sk, idx, ptr);//ossl_check_void_sk_type(sk), idx, ossl_check_void_type(ptr)))
end;

function sk_void_push(sk: POPENSSL_STACK; ptr: Pointer): int;
begin
    result := OPENSSL_sk_push(sk, ptr)
end;

function sk_void_new_null:PSTACK_st_void;
begin
    result := OPENSSL_sk_new_null();
end;

function sk_void_value(sk : POPENSSL_STACK; idx: int): Pointer;
begin
    Result := OPENSSL_sk_value(sk, idx);
end;

function sk_void_num(const sk : POPENSSL_STACK):int;
begin
   Result := OPENSSL_sk_num(sk)
end;



function ossl_check_void_type( ptr : Pointer):Pointer;
begin
  Result :=  ptr;
end;


function ossl_check_void_sk_type(sk: Pointer):POPENSSL_STACK;
begin
  Result :=  POPENSSL_STACK (sk);
end;


function ossl_check_void_compfunc_type( cmp : sk_void_compfunc):OPENSSL_sk_compfunc;
begin
  Result :=  OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_void_copyfunc_type( cpy : sk_void_copyfunc):OPENSSL_sk_copyfunc;
begin
  Result :=  OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_void_freefunc_type( fr : sk_void_freefunc):OPENSSL_sk_freefunc;
begin
  Result :=  OPENSSL_sk_freefunc(fr);
end;

procedure sk_void_free(sk: Pointer);
begin
   OPENSSL_sk_free(ossl_check_void_sk_type(sk))
end;

end.
