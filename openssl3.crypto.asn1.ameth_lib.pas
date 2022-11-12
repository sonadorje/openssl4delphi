unit openssl3.crypto.asn1.ameth_lib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

 function EVP_PKEY_asn1_get0_info(ppkey_id, ppkey_base_id, ppkey_flags : PInteger;const pinfo, ppem_str : PPUTF8Char; ameth : PEVP_PKEY_ASN1_METHOD):integer;
 function EVP_PKEY_asn1_get_count:integer;
 procedure EVP_PKEY_asn1_free( ameth : PEVP_PKEY_ASN1_METHOD);
 function EVP_PKEY_asn1_find( pe : PPENGINE; _type : integer):PEVP_PKEY_ASN1_METHOD;
 function EVP_PKEY_asn1_get0( idx : integer):PEVP_PKEY_ASN1_METHOD;
 function EVP_PKEY_asn1_find_str(pe : PPENGINE;const str : PUTF8Char; len : integer):PEVP_PKEY_ASN1_METHOD;
 function EVP_PKEY_get0_asn1(const pkey : PEVP_PKEY):PEVP_PKEY_ASN1_METHOD;

 function sk_EVP_PKEY_ASN1_METHOD_num(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD):integer;
  function sk_EVP_PKEY_ASN1_METHOD_value(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD; idx : integer):PEVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_new( compare : sk_EVP_PKEY_ASN1_METHOD_compfunc):Pstack_st_EVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_new_null:Pstack_st_EVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_new_reserve( compare : sk_EVP_PKEY_ASN1_METHOD_compfunc; n : integer):Pstack_st_EVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_reserve( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; n : integer):integer;
  procedure sk_EVP_PKEY_ASN1_METHOD_free( sk : Pstack_st_EVP_PKEY_ASN1_METHOD);
  procedure sk_EVP_PKEY_ASN1_METHOD_zero( sk : Pstack_st_EVP_PKEY_ASN1_METHOD);
  function sk_EVP_PKEY_ASN1_METHOD_delete( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; i : integer):PEVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_delete_ptr(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr: PEVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_push(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
  function sk_EVP_PKEY_ASN1_METHOD_unshift(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
  function sk_EVP_PKEY_ASN1_METHOD_pop( sk : Pstack_st_EVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_shift( sk : Pstack_st_EVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
  procedure sk_EVP_PKEY_ASN1_METHOD_pop_free( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; freefunc : sk_EVP_PKEY_ASN1_METHOD_freefunc);
  function sk_EVP_PKEY_ASN1_METHOD_insert(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD; idx : integer):integer;
  function sk_EVP_PKEY_ASN1_METHOD_set(sk : Pstack_st_EVP_PKEY_ASN1_METHOD; idx : integer;const ptr: PEVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_find(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
  function sk_EVP_PKEY_ASN1_METHOD_find_ex(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
  function sk_EVP_PKEY_ASN1_METHOD_find_all(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD; pnum : PInteger):integer;
  procedure sk_EVP_PKEY_ASN1_METHOD_sort( sk : Pstack_st_EVP_PKEY_ASN1_METHOD);
  function sk_EVP_PKEY_ASN1_METHOD_is_sorted(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD):integer;
  function sk_EVP_PKEY_ASN1_METHOD_dup(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD):Pstack_st_EVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_deep_copy(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD; copyfunc : sk_EVP_PKEY_ASN1_METHOD_copyfunc; freefunc : sk_EVP_PKEY_ASN1_METHOD_freefunc):Pstack_st_EVP_PKEY_ASN1_METHOD;
  function sk_EVP_PKEY_ASN1_METHOD_set_cmp_func( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; compare : sk_EVP_PKEY_ASN1_METHOD_compfunc):sk_EVP_PKEY_ASN1_METHOD_compfunc;
  function pkey_asn1_find( _type : integer):PEVP_PKEY_ASN1_METHOD;
  function ameth_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_ameth(const key, base : PPEVP_PKEY_ASN1_METHOD; num : integer):PPEVP_PKEY_ASN1_METHOD;
  function ameth_cmp(const a, b : PPEVP_PKEY_ASN1_METHOD):integer;

var
  app_methods: PEVP_PKEY_ASN1_METHOD  = nil;

implementation

uses openssl3.crypto.asn1.standard_methods, openssl3.crypto.engine.tb_asnmth,
     openssl3.crypto.engine.eng_init, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.mem,
     openssl3.crypto.stack, openssl3.crypto.objects.obj_dat;





function ameth_cmp(const a, b : PPEVP_PKEY_ASN1_METHOD):integer;
begin
    Result := (a^).pkey_id - (b^).pkey_id;
end;

function ameth_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : PPEVP_PKEY_ASN1_METHOD;
begin
  a := a_;
  b := b_;
  Result := ameth_cmp(a,b);
end;


function OBJ_bsearch_ameth(const key, base : PPEVP_PKEY_ASN1_METHOD; num : integer):PPEVP_PKEY_ASN1_METHOD;
begin
   Result := PPEVP_PKEY_ASN1_METHOD (OBJ_bsearch_(key, base, num,
                         sizeof(PEVP_PKEY_ASN1_METHOD ), ameth_cmp_BSEARCH_CMP_FN));
end;

function pkey_asn1_find( _type : integer):PEVP_PKEY_ASN1_METHOD;
var
  tmp : TEVP_PKEY_ASN1_METHOD;
  t : PEVP_PKEY_ASN1_METHOD;
  ret : PPEVP_PKEY_ASN1_METHOD;
  idx : integer;
begin
    t := @tmp;
    tmp.pkey_id := _type;
    if app_methods <> nil then
    begin
        idx := sk_EVP_PKEY_ASN1_METHOD_find(app_methods, @tmp);
        if idx >= 0 then
           Exit(sk_EVP_PKEY_ASN1_METHOD_value(app_methods, idx));
    end;
    ret := OBJ_bsearch_ameth(@t, @standard_methods, Length(standard_methods));
    if (ret = nil)  or  (ret^ = nil) then Exit(nil);
    Result := ret^;
end;

function sk_EVP_PKEY_ASN1_METHOD_num(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD):integer;
begin
 Exit(OPENSSL_sk_num(POPENSSL_STACK(sk)));
end;


function sk_EVP_PKEY_ASN1_METHOD_value(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD; idx : integer):PEVP_PKEY_ASN1_METHOD;
begin
 Result := PEVP_PKEY_ASN1_METHOD(OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;


function sk_EVP_PKEY_ASN1_METHOD_new( compare : sk_EVP_PKEY_ASN1_METHOD_compfunc):Pstack_st_EVP_PKEY_ASN1_METHOD;
begin
 Result := Pstack_st_EVP_PKEY_ASN1_METHOD (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_EVP_PKEY_ASN1_METHOD_new_null:Pstack_st_EVP_PKEY_ASN1_METHOD;
begin
 Result := Pstack_st_EVP_PKEY_ASN1_METHOD (OPENSSL_sk_new_null);
end;


function sk_EVP_PKEY_ASN1_METHOD_new_reserve( compare : sk_EVP_PKEY_ASN1_METHOD_compfunc; n : integer):Pstack_st_EVP_PKEY_ASN1_METHOD;
begin
 Result := Pstack_st_EVP_PKEY_ASN1_METHOD (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_EVP_PKEY_ASN1_METHOD_reserve( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK(sk), n));
end;


procedure sk_EVP_PKEY_ASN1_METHOD_free( sk : Pstack_st_EVP_PKEY_ASN1_METHOD);
begin
 OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_EVP_PKEY_ASN1_METHOD_zero( sk : Pstack_st_EVP_PKEY_ASN1_METHOD);
begin
 OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;


function sk_EVP_PKEY_ASN1_METHOD_delete( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; i : integer):PEVP_PKEY_ASN1_METHOD;
begin
 Result := PEVP_PKEY_ASN1_METHOD (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_EVP_PKEY_ASN1_METHOD_delete_ptr(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr: PEVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
begin
 Result := PEVP_PKEY_ASN1_METHOD (OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_EVP_PKEY_ASN1_METHOD_push(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_EVP_PKEY_ASN1_METHOD_unshift(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_EVP_PKEY_ASN1_METHOD_pop( sk : Pstack_st_EVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
begin
 Result := PEVP_PKEY_ASN1_METHOD (OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_EVP_PKEY_ASN1_METHOD_shift( sk : Pstack_st_EVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
begin
 Result := PEVP_PKEY_ASN1_METHOD (OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;


procedure sk_EVP_PKEY_ASN1_METHOD_pop_free( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; freefunc : sk_EVP_PKEY_ASN1_METHOD_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_EVP_PKEY_ASN1_METHOD_insert(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer(ptr), idx));
end;


function sk_EVP_PKEY_ASN1_METHOD_set(sk : Pstack_st_EVP_PKEY_ASN1_METHOD; idx : integer;const ptr: PEVP_PKEY_ASN1_METHOD):PEVP_PKEY_ASN1_METHOD;
begin
 Result := PEVP_PKEY_ASN1_METHOD (OPENSSL_sk_set(POPENSSL_STACK(sk), idx, Pointer(ptr)));
end;


function sk_EVP_PKEY_ASN1_METHOD_find(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_EVP_PKEY_ASN1_METHOD_find_ex(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_EVP_PKEY_ASN1_METHOD_find_all(sk : Pstack_st_EVP_PKEY_ASN1_METHOD;const ptr : PEVP_PKEY_ASN1_METHOD; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK(sk), Pointer(ptr), pnum));
end;


procedure sk_EVP_PKEY_ASN1_METHOD_sort( sk : Pstack_st_EVP_PKEY_ASN1_METHOD);
begin
 OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_EVP_PKEY_ASN1_METHOD_is_sorted(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK(sk)));
end;


function sk_EVP_PKEY_ASN1_METHOD_dup(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD):Pstack_st_EVP_PKEY_ASN1_METHOD;
begin
 Result := Pstack_st_EVP_PKEY_ASN1_METHOD (OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;


function sk_EVP_PKEY_ASN1_METHOD_deep_copy(const sk : Pstack_st_EVP_PKEY_ASN1_METHOD; copyfunc : sk_EVP_PKEY_ASN1_METHOD_copyfunc; freefunc : sk_EVP_PKEY_ASN1_METHOD_freefunc):Pstack_st_EVP_PKEY_ASN1_METHOD;
begin
 Result := Pstack_st_EVP_PKEY_ASN1_METHOD(OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
                 OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)));
end;


function sk_EVP_PKEY_ASN1_METHOD_set_cmp_func( sk : Pstack_st_EVP_PKEY_ASN1_METHOD; compare : sk_EVP_PKEY_ASN1_METHOD_compfunc):sk_EVP_PKEY_ASN1_METHOD_compfunc;
begin
 Result := sk_EVP_PKEY_ASN1_METHOD_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
                OPENSSL_sk_compfunc(compare)));
end;




function EVP_PKEY_get0_asn1(const pkey : PEVP_PKEY):PEVP_PKEY_ASN1_METHOD;
begin
    Result := pkey.ameth;
end;



function EVP_PKEY_asn1_find_str(pe : PPENGINE;const str : PUTF8Char; len : integer):PEVP_PKEY_ASN1_METHOD;
var
  i : integer;
  ameth : PEVP_PKEY_ASN1_METHOD;
  e : PENGINE;
begin
    ameth := nil;
    if len = -1 then
       len := Length(str);
    if pe <> nil then
    begin
{$IFNDEF OPENSSL_NO_ENGINE}
        ameth := ENGINE_pkey_asn1_find_str(@e, str, len);
        if ameth <> nil then
        begin
            {
             * Convert structural into functional reference
             }
            if 0>= ENGINE_init(e) then
                ameth := nil;
            ENGINE_free(e);
            pe^ := e;
            Exit(ameth);
        end;
{$ENDIF}
        pe^ := nil;
    end;
    i := EVP_PKEY_asn1_get_count();
    while (PostDec(i) > 0 )do
    begin
        ameth := EVP_PKEY_asn1_get0(i);
        if ameth.pkey_flags and ASN1_PKEY_ALIAS > 0 then
           continue;
        if (Length(ameth.pem_str) = len)
             and  (strncasecmp(ameth.pem_str, str, len) = 0) then
            Exit(ameth);
    end;
    Result := nil;
end;



function EVP_PKEY_asn1_get0( idx : integer):PEVP_PKEY_ASN1_METHOD;
var
    num              : integer;
begin
    num := Length(standard_methods);
    if idx < 0 then
       Exit(nil);
    if idx < num then
       Exit(standard_methods[idx]);
    idx  := idx - num;
    Result := sk_EVP_PKEY_ASN1_METHOD_value(app_methods, idx);
end;

function EVP_PKEY_asn1_find( pe : PPENGINE; _type : integer):PEVP_PKEY_ASN1_METHOD;
var
  t : PEVP_PKEY_ASN1_METHOD;
  e : PENGINE;
begin
    while true do
    begin
        t := pkey_asn1_find(_type);
        if (nil = t)  or  (0>= (t.pkey_flags and ASN1_PKEY_ALIAS)) then
            break;
        _type := t.pkey_base_id;
    end;
    if pe <> nil then begin
{$IFNDEF OPENSSL_NO_ENGINE}
        { type will contain the final unaliased type }
        e := ENGINE_get_pkey_asn1_meth_engine(_type);
        if e <> nil then
        begin
            pe^ := e;
            Exit(ENGINE_get_pkey_asn1_meth(e, _type));
        end;
{$ENDIF}
        pe^ := nil;
    end;
    Result := t;
end;




procedure EVP_PKEY_asn1_free( ameth : PEVP_PKEY_ASN1_METHOD);
begin
    if (ameth <> nil) and ( (ameth.pkey_flags and ASN1_PKEY_DYNAMIC)>0)  then
    begin
        OPENSSL_free(ameth.pem_str);
        OPENSSL_free(ameth.info);
        OPENSSL_free(ameth);
    end;
end;





function EVP_PKEY_asn1_get_count:integer;
var
  num : integer;
begin
    num := Length(standard_methods);
    if app_methods <> nil then
       num  := num + (sk_EVP_PKEY_ASN1_METHOD_num(app_methods));
    Result := num;
end;

function EVP_PKEY_asn1_get0_info(ppkey_id, ppkey_base_id, ppkey_flags : PInteger;const pinfo, ppem_str : PPUTF8Char; ameth : PEVP_PKEY_ASN1_METHOD):integer;
begin
    if nil = ameth then Exit(0);
    if ppkey_id <> nil then
       ppkey_id^ := ameth.pkey_id;
    if ppkey_base_id <> nil then
       ppkey_base_id^ := ameth.pkey_base_id;
    if ppkey_flags <> nil then
       ppkey_flags^ := ameth.pkey_flags;
    if pinfo <> nil then
       pinfo^ := ameth.info;
    if ppem_str <> nil then
       ppem_str^ := ameth.pem_str;
    Result := 1;
end;


end.
