unit OpenSSL3.include.openssl.asn1;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

type
    Ti2d_X509_PUBKEY_func = function(const a : PX509_PUBKEY; &out : PPByte):integer;

function sk_ASN1_OBJECT_num(sk: Pstack_st_ASN1_OBJECT): UInt32; inline;
function sk_ASN1_OBJECT_value(sk: Pointer; idx: Integer): PASN1_OBJECT; inline;
function ossl_check_const_ASN1_OBJECT_sk_type(const sk: Pstack_st_ASN1_OBJECT): POPENSSL_STACK; inline;
function ossl_check_ASN1_OBJECT_sk_type(sk: Pstack_st_ASN1_OBJECT) : POPENSSL_STACK;inline;
function ossl_check_ASN1_OBJECT_freefunc_type(fr: sk_ASN1_OBJECT_freefunc): OPENSSL_sk_freefunc;inline;
procedure sk_ASN1_OBJECT_pop_free(sk: Pointer; freefunc: sk_ASN1_OBJECT_freefunc);
function sk_ASN1_TYPE_push(sk: POPENSSL_STACK ; ptr: Pointer): int;
function ossl_check_ASN1_TYPE_type( ptr : PASN1_TYPE):PASN1_TYPE;
 function ossl_check_const_ASN1_TYPE_sk_type(const sk : Pstack_st_ASN1_TYPE):POPENSSL_STACK;
 function ossl_check_ASN1_TYPE_sk_type( sk : Pstack_st_ASN1_TYPE):POPENSSL_STACK;
 function sk_ASN1_STRING_TABLE_find(sk, ptr: Pointer): int;
 function ossl_check_ASN1_STRING_TABLE_sk_type(sk: Pstack_st_PASN1_STRING_TABLE):POPENSSL_STACK;
 function ossl_check_ASN1_STRING_TABLE_type( ptr : PASN1_STRING_TABLE):PASN1_STRING_TABLE;
 function ossl_check_const_ASN1_STRING_TABLE_sk_type(const sk: Pstack_st_PASN1_STRING_TABLE):POPENSSL_STACK;
 function sk_ASN1_STRING_TABLE_value(sk:Pointer; idx: int): PASN1_STRING_TABLE;
 function sk_ASN1_STRING_TABLE_new(cmp: sk_ASN1_STRING_TABLE_compfunc):Pstack_st_ASN1_STRING_TABLE;
 function ossl_check_ASN1_STRING_TABLE_compfunc_type( cmp : sk_ASN1_STRING_TABLE_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ASN1_STRING_TABLE_copyfunc_type( cpy : sk_ASN1_STRING_TABLE_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_ASN1_STRING_TABLE_freefunc_type( fr : sk_ASN1_STRING_TABLE_freefunc):OPENSSL_sk_freefunc;
  function sk_ASN1_STRING_TABLE_push(sk, ptr: Pointer): int;
  procedure sk_ASN1_STRING_TABLE_pop_free(sk:Pointer; freefunc: sk_ASN1_STRING_TABLE_freefunc);
  function sk_ASN1_TYPE_num(sk: Pointer): Integer;
  function sk_ASN1_TYPE_value(sk: Pointer; idx: int): PASN1_TYPE;
  function sk_ASN1_OBJECT_new_null: PSTACK_st_ASN1_OBJECT;
  function sk_ASN1_OBJECT_push(sk, ptr: Pointer): int;
  function ossl_check_ASN1_OBJECT_type( ptr : PASN1_OBJECT):PASN1_OBJECT;
  function sk_ASN1_TYPE_new_null: Pstack_st_ASN1_TYPE;
  procedure sk_ASN1_TYPE_pop_free(sk: Pointer; freefunc: sk_ASN1_TYPE_freefunc);
  function ossl_check_ASN1_TYPE_freefunc_type( fr : sk_ASN1_TYPE_freefunc):OPENSSL_sk_freefunc;
  function sk_ASN1_INTEGER_num(sk: Pointer): int;
   function ossl_check_const_ASN1_INTEGER_sk_type(const sk: Pstack_st_ASN1_INTEGER):POPENSSL_STACK;
  function sk_ASN1_INTEGER_value(sk: Pointer; idx: int):PASN1_INTEGER;
  function sk_ASN1_INTEGER_push(sk, ptr: Pointer): int;
  function sk_ASN1_OBJECT_new_reserve(cmp: sk_ASN1_OBJECT_compfunc; n: int): Pstack_st_ASN1_OBJECT;

  function ossl_check_ASN1_INTEGER_sk_type( sk : Pstack_st_ASN1_INTEGER):POPENSSL_STACK;
  function ossl_check_ASN1_INTEGER_type( ptr : PASN1_INTEGER):PASN1_INTEGER;
  function ossl_check_ASN1_INTEGER_compfunc_type( cmp : sk_ASN1_INTEGER_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ASN1_INTEGER_copyfunc_type( cpy : sk_ASN1_INTEGER_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_ASN1_INTEGER_freefunc_type( fr : sk_ASN1_INTEGER_freefunc):OPENSSL_sk_freefunc;
  function sk_ASN1_INTEGER_new_null: Pstack_st_ASN1_INTEGER;


  function ossl_check_ASN1_OBJECT_compfunc_type( cmp : sk_ASN1_OBJECT_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ASN1_OBJECT_copyfunc_type( cpy : sk_ASN1_OBJECT_copyfunc):OPENSSL_sk_copyfunc;
  procedure sk_ASN1_OBJECT_free(sk: Pointer);
  procedure sk_ASN1_INTEGER_pop_free(sk: Pointer; freefunc: sk_ASN1_INTEGER_freefunc);

implementation

uses
  openssl3.crypto.stack;




procedure sk_ASN1_INTEGER_pop_free(sk: Pointer; freefunc: sk_ASN1_INTEGER_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_ASN1_INTEGER_sk_type(sk),
                       ossl_check_ASN1_INTEGER_freefunc_type(freefunc))
end;

function sk_ASN1_INTEGER_new_null: Pstack_st_ASN1_INTEGER;
begin
   Result := Pstack_st_ASN1_INTEGER(OPENSSL_sk_new_null)
end;

procedure sk_ASN1_OBJECT_free(sk: Pointer);
begin
   OPENSSL_sk_free(ossl_check_ASN1_OBJECT_sk_type(sk))
end;

function ossl_check_ASN1_OBJECT_compfunc_type( cmp : sk_ASN1_OBJECT_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ASN1_OBJECT_copyfunc_type( cpy : sk_ASN1_OBJECT_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result :=  OPENSSL_sk_copyfunc(cpy);
end;


function sk_ASN1_OBJECT_new_reserve(cmp: sk_ASN1_OBJECT_compfunc; n: int): Pstack_st_ASN1_OBJECT;
begin
   Result := Pstack_st_ASN1_OBJECT(
         OPENSSL_sk_new_reserve(ossl_check_ASN1_OBJECT_compfunc_type(cmp), (n)))
end;


function ossl_check_ASN1_INTEGER_sk_type( sk : Pstack_st_ASN1_INTEGER):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK( sk);
end;



function ossl_check_ASN1_INTEGER_type( ptr : PASN1_INTEGER):PASN1_INTEGER;
begin
 Exit(ptr);
end;


function ossl_check_ASN1_INTEGER_compfunc_type( cmp : sk_ASN1_INTEGER_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ASN1_INTEGER_copyfunc_type( cpy : sk_ASN1_INTEGER_copyfunc):OPENSSL_sk_copyfunc;
begin
  Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_ASN1_INTEGER_freefunc_type( fr : sk_ASN1_INTEGER_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;


function sk_ASN1_INTEGER_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_ASN1_INTEGER_sk_type(sk),
                             ossl_check_ASN1_INTEGER_type(ptr))
end;

function sk_ASN1_INTEGER_value(sk: Pointer; idx: int):PASN1_INTEGER;
begin
    Result := PASN1_INTEGER( OPENSSL_sk_value(ossl_check_const_ASN1_INTEGER_sk_type(sk), (idx)))
end;



function ossl_check_const_ASN1_INTEGER_sk_type(const sk: Pstack_st_ASN1_INTEGER):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK( sk);
end;

function sk_ASN1_INTEGER_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_ASN1_INTEGER_sk_type(sk))
end;


function ossl_check_ASN1_TYPE_freefunc_type( fr : sk_ASN1_TYPE_freefunc):OPENSSL_sk_freefunc;
begin
   result := OPENSSL_sk_freefunc(fr);
end;


procedure sk_ASN1_TYPE_pop_free(sk: Pointer; freefunc: sk_ASN1_TYPE_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_ASN1_TYPE_sk_type(sk),
                       ossl_check_ASN1_TYPE_freefunc_type(freefunc))
end;

function sk_ASN1_TYPE_new_null: Pstack_st_ASN1_TYPE;
begin
    Result := Pstack_st_ASN1_TYPE(OPENSSL_sk_new_null)
end;

function ossl_check_ASN1_OBJECT_type( ptr : PASN1_OBJECT):PASN1_OBJECT;
begin
   Result := ptr;
end;

function sk_ASN1_OBJECT_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_ASN1_OBJECT_sk_type(sk),
                   ossl_check_ASN1_OBJECT_type(ptr))
end;

function sk_ASN1_OBJECT_new_null: PSTACK_st_ASN1_OBJECT;
begin
   Result := PSTACK_st_ASN1_OBJECT(OPENSSL_sk_new_null);
end;

function sk_ASN1_TYPE_value(sk: Pointer; idx: int): PASN1_TYPE;
begin
   Result := PASN1_TYPE(OPENSSL_sk_value(ossl_check_const_ASN1_TYPE_sk_type(sk), idx))
end;

function sk_ASN1_TYPE_num(sk: Pointer): Integer;
begin
   result := OPENSSL_sk_num(ossl_check_const_ASN1_TYPE_sk_type(sk))
end;

procedure sk_ASN1_STRING_TABLE_pop_free(sk:Pointer; freefunc: sk_ASN1_STRING_TABLE_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_ASN1_STRING_TABLE_sk_type(sk),
                       ossl_check_ASN1_STRING_TABLE_freefunc_type(freefunc))
end;

function sk_ASN1_STRING_TABLE_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_ASN1_STRING_TABLE_sk_type(sk),
           ossl_check_ASN1_STRING_TABLE_type(ptr))
end;

function ossl_check_ASN1_STRING_TABLE_compfunc_type( cmp : sk_ASN1_STRING_TABLE_compfunc):OPENSSL_sk_compfunc;
begin
   result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ASN1_STRING_TABLE_copyfunc_type( cpy : sk_ASN1_STRING_TABLE_copyfunc):OPENSSL_sk_copyfunc;
begin
   result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_ASN1_STRING_TABLE_freefunc_type( fr : sk_ASN1_STRING_TABLE_freefunc):OPENSSL_sk_freefunc;
begin
   result := OPENSSL_sk_freefunc(fr);
end;

function sk_ASN1_STRING_TABLE_new(cmp: sk_ASN1_STRING_TABLE_compfunc):Pstack_st_ASN1_STRING_TABLE;
begin
   Result := Pstack_st_ASN1_STRING_TABLE(OPENSSL_sk_new(
                 ossl_check_ASN1_STRING_TABLE_compfunc_type(cmp)))
end;


function ossl_check_const_ASN1_STRING_TABLE_sk_type(const sk: Pstack_st_PASN1_STRING_TABLE):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK( sk);
end;

function sk_ASN1_STRING_TABLE_value(sk:Pointer; idx: int): PASN1_STRING_TABLE;
begin
  Result := PASN1_STRING_TABLE(OPENSSL_sk_value(
          ossl_check_const_ASN1_STRING_TABLE_sk_type(sk), idx))
end;

function ossl_check_ASN1_STRING_TABLE_type( ptr : PASN1_STRING_TABLE):PASN1_STRING_TABLE;
begin
   result := ptr;
end;




function ossl_check_ASN1_STRING_TABLE_sk_type(sk: Pstack_st_PASN1_STRING_TABLE):POPENSSL_STACK;
begin
   result := POPENSSL_STACK(sk);
end;

function sk_ASN1_STRING_TABLE_find(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_find(ossl_check_ASN1_STRING_TABLE_sk_type(sk),
              ossl_check_ASN1_STRING_TABLE_type(ptr))
end;

function ossl_check_ASN1_TYPE_sk_type( sk : Pstack_st_ASN1_TYPE):POPENSSL_STACK;
begin
   result := POPENSSL_STACK( sk);
end;




function ossl_check_const_ASN1_TYPE_sk_type(const sk : Pstack_st_ASN1_TYPE):POPENSSL_STACK;
begin
   result := POPENSSL_STACK( sk);
end;




function ossl_check_ASN1_TYPE_type( ptr : PASN1_TYPE):PASN1_TYPE;
begin
   result := ptr;
end;

function sk_ASN1_TYPE_push(sk: POPENSSL_STACK ; ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr))
end;

function ossl_check_ASN1_OBJECT_freefunc_type(fr: sk_ASN1_OBJECT_freefunc): OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function ossl_check_ASN1_OBJECT_sk_type(sk: Pstack_st_ASN1_OBJECT) : POPENSSL_STACK;
begin
   Result := POPENSSL_STACK(sk);
end;

procedure sk_ASN1_OBJECT_pop_free(sk: Pointer; freefunc: sk_ASN1_OBJECT_freefunc);
begin
  OPENSSL_sk_pop_free(ossl_check_ASN1_OBJECT_sk_type(sk),ossl_check_ASN1_OBJECT_freefunc_type(freefunc))
end;

function ossl_check_const_ASN1_OBJECT_sk_type(const sk: Pstack_st_ASN1_OBJECT): POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;

function sk_ASN1_OBJECT_num(sk: Pstack_st_ASN1_OBJECT): UInt32;
begin
   Result := OPENSSL_sk_num(ossl_check_const_ASN1_OBJECT_sk_type(sk))
end;

function sk_ASN1_OBJECT_value(sk: Pointer; idx: Integer): PASN1_OBJECT;
begin
  Result := PASN1_OBJECT (OPENSSL_sk_value(ossl_check_const_ASN1_OBJECT_sk_type(sk), idx))
end;

end.
