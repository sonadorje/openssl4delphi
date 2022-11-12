unit openssl3.openssl.crypto;

interface
uses OpenSSL.Api;

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

implementation

uses openssl3.crypto.stack;





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
