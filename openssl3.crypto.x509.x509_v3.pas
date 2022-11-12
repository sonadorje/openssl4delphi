unit openssl3.crypto.x509.x509_v3;

interface
uses OpenSSL.Api;

 function X509v3_get_ext_count(const x : Pstack_st_X509_EXTENSION):integer;
  function X509v3_get_ext_by_NID(const x : Pstack_st_X509_EXTENSION; nid, lastpos : integer):integer;
  function X509v3_get_ext_by_OBJ(const sk : Pstack_st_X509_EXTENSION;const obj : PASN1_OBJECT; lastpos : integer):integer;
  function X509v3_get_ext_by_critical(const sk : Pstack_st_X509_EXTENSION; crit, lastpos : integer):integer;
  function X509v3_get_ext(const x : Pstack_st_X509_EXTENSION; loc : integer):PX509_EXTENSION;
  function X509v3_delete_ext( x : Pstack_st_X509_EXTENSION; loc : integer):PX509_EXTENSION;
  function X509v3_add_ext( x : PPstack_st_X509_EXTENSION; ex : PX509_EXTENSION; loc : integer):Pstack_st_X509_EXTENSION;
  function X509_EXTENSION_create_by_NID( ex : PPX509_EXTENSION; nid, crit : integer; data : PASN1_OCTET_STRING):PX509_EXTENSION;
  function X509_EXTENSION_create_by_OBJ(ex : PPX509_EXTENSION;const obj : PASN1_OBJECT; crit : integer; data : PASN1_OCTET_STRING):PX509_EXTENSION;
  function X509_EXTENSION_set_object(ex : PX509_EXTENSION;const obj : PASN1_OBJECT):integer;
  function X509_EXTENSION_set_critical( ex : PX509_EXTENSION; crit : integer):integer;
  function X509_EXTENSION_set_data( ex : PX509_EXTENSION; data : PASN1_OCTET_STRING):integer;
  function X509_EXTENSION_get_object( ex : PX509_EXTENSION):PASN1_OBJECT;
  function X509_EXTENSION_get_data( ex : PX509_EXTENSION):PASN1_OCTET_STRING;
  function X509_EXTENSION_get_critical(const ex : PX509_EXTENSION):integer;
  function sk_PROFESSION_INFO_num(sk: Pointer): int;


  function ossl_check_PROFESSION_INFO_type( ptr : PPROFESSION_INFO):PPROFESSION_INFO;
  function ossl_check_const_PROFESSION_INFO_sk_type(const sk : Pstack_st_PROFESSION_INFO):POPENSSL_STACK;
  function ossl_check_PROFESSION_INFO_sk_type( sk : Pstack_st_PROFESSION_INFO):POPENSSL_STACK;
  function ossl_check_PROFESSION_INFO_compfunc_type( cmp : sk_PROFESSION_INFO_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_PROFESSION_INFO_copyfunc_type( cpy : sk_PROFESSION_INFO_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_PROFESSION_INFO_freefunc_type( fr : sk_PROFESSION_INFO_freefunc):OPENSSL_sk_freefunc;
  function  sk_ADMISSIONS_num(sk: Pointer): int;

  function ossl_check_ADMISSIONS_type( ptr : PADMISSIONS):PADMISSIONS;
  function ossl_check_const_ADMISSIONS_sk_type(const sk : Pstack_st_ADMISSIONS):POPENSSL_STACK;
  function ossl_check_ADMISSIONS_sk_type( sk : Pstack_st_ADMISSIONS):POPENSSL_STACK;
  function ossl_check_ADMISSIONS_compfunc_type( cmp : sk_ADMISSIONS_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ADMISSIONS_copyfunc_type( cpy : sk_ADMISSIONS_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_ADMISSIONS_freefunc_type( fr : sk_ADMISSIONS_freefunc):OPENSSL_sk_freefunc;
   function sk_ADMISSIONS_value(sk: Pointer; idx: int): PADMISSIONS;
  function sk_PROFESSION_INFO_value(sk: Pointer; idx: int): PPROFESSION_INFO;
  function sk_ASN1_STRING_num(sk: Pointer): int;

  function ossl_check_ASN1_STRING_type( ptr : PASN1_STRING):PASN1_STRING;
  function ossl_check_const_ASN1_STRING_sk_type(const sk : Pstack_st_ASN1_STRING):POPENSSL_STACK;
  function ossl_check_ASN1_STRING_sk_type( sk : Pstack_st_ASN1_STRING):POPENSSL_STACK;
  function ossl_check_ASN1_STRING_compfunc_type( cmp : sk_ASN1_STRING_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ASN1_STRING_copyfunc_type( cpy : sk_ASN1_STRING_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_ASN1_STRING_freefunc_type( fr : sk_ASN1_STRING_freefunc):OPENSSL_sk_freefunc;
  function sk_ASN1_STRING_value(sk: Pointer; idx: int): PASN1_STRING;
  procedure sk_ADMISSIONS_pop_free(sk: Pointer; freefunc: sk_ADMISSIONS_freefunc);
  procedure  sk_PROFESSION_INFO_pop_free(sk: Pointer; freefunc: sk_PROFESSION_INFO_freefunc);
  procedure sk_ASN1_STRING_pop_free(sk: Pointer; freefunc: sk_ASN1_STRING_freefunc);
  function sk_X509V3_EXT_METHOD_find(sk, ptr: Pointer): int;

  function ossl_check_X509V3_EXT_METHOD_type( ptr : PX509V3_EXT_METHOD):PX509V3_EXT_METHOD;
  function ossl_check_X509V3_EXT_METHOD_compfunc_type( cmp : sk_X509V3_EXT_METHOD_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509V3_EXT_METHOD_copyfunc_type( cpy : sk_X509V3_EXT_METHOD_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509V3_EXT_METHOD_freefunc_type( fr : sk_X509V3_EXT_METHOD_freefunc):OPENSSL_sk_freefunc;
  function ossl_check_const_X509V3_EXT_METHOD_sk_type(const sk : Pstack_st_X509V3_EXT_METHOD):POPENSSL_STACK;
  function ossl_check_X509V3_EXT_METHOD_sk_type( sk : Pstack_st_X509V3_EXT_METHOD):POPENSSL_STACK;
  function sk_X509V3_EXT_METHOD_value(sk: Pointer; idx: int): PX509V3_EXT_METHOD;

implementation
uses openssl3.crypto.x509, openssl3.crypto.objects.obj_lib,
     openssl3.crypto.objects.obj_dat, OpenSSL3.Err,
     openssl3.crypto.asn1.a_octet, openssl3.crypto.stack,
     OpenSSL3.crypto.x509.x_exten, openssl3.crypto.asn1.a_object;

function sk_X509V3_EXT_METHOD_value(sk: Pointer; idx: int): PX509V3_EXT_METHOD;
begin
   Result := PX509V3_EXT_METHOD(OPENSSL_sk_value(ossl_check_const_X509V3_EXT_METHOD_sk_type(sk), (idx)))
end;

function ossl_check_const_X509V3_EXT_METHOD_sk_type(const sk : Pstack_st_X509V3_EXT_METHOD):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;

function ossl_check_X509V3_EXT_METHOD_sk_type( sk : Pstack_st_X509V3_EXT_METHOD):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;



function ossl_check_X509V3_EXT_METHOD_type( ptr : PX509V3_EXT_METHOD):PX509V3_EXT_METHOD;
begin
 Exit(ptr);
end;


function ossl_check_X509V3_EXT_METHOD_compfunc_type( cmp : sk_X509V3_EXT_METHOD_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509V3_EXT_METHOD_copyfunc_type( cpy : sk_X509V3_EXT_METHOD_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509V3_EXT_METHOD_freefunc_type( fr : sk_X509V3_EXT_METHOD_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509V3_EXT_METHOD_find(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_find(ossl_check_X509V3_EXT_METHOD_sk_type(sk),
                             ossl_check_X509V3_EXT_METHOD_type(ptr))
end;

procedure sk_ASN1_STRING_pop_free(sk: Pointer; freefunc: sk_ASN1_STRING_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_ASN1_STRING_sk_type(sk),
                       ossl_check_ASN1_STRING_freefunc_type(freefunc))
end;



procedure  sk_PROFESSION_INFO_pop_free(sk: Pointer; freefunc: sk_PROFESSION_INFO_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_PROFESSION_INFO_sk_type(sk),
                        ossl_check_PROFESSION_INFO_freefunc_type(freefunc))
end;

procedure sk_ADMISSIONS_pop_free(sk: Pointer; freefunc: sk_ADMISSIONS_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_ADMISSIONS_sk_type(sk),
               ossl_check_ADMISSIONS_freefunc_type(freefunc))
end;

function sk_ASN1_STRING_value(sk: Pointer; idx: int): PASN1_STRING;
begin
   Result := PASN1_STRING( OPENSSL_sk_value(ossl_check_const_ASN1_STRING_sk_type(sk), (idx)))
end;



function ossl_check_ASN1_STRING_type( ptr : PASN1_STRING):PASN1_STRING;
begin
 Exit(ptr);
end;


function ossl_check_const_ASN1_STRING_sk_type(const sk : Pstack_st_ASN1_STRING):POPENSSL_STACK;
begin
 Result :=  POPENSSL_STACK (sk);
end;


function ossl_check_ASN1_STRING_sk_type( sk : Pstack_st_ASN1_STRING):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_ASN1_STRING_compfunc_type( cmp : sk_ASN1_STRING_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ASN1_STRING_copyfunc_type( cpy : sk_ASN1_STRING_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_ASN1_STRING_freefunc_type( fr : sk_ASN1_STRING_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_ASN1_STRING_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_ASN1_STRING_sk_type(sk))
end;

function sk_PROFESSION_INFO_value(sk: Pointer; idx: int): PPROFESSION_INFO;
begin
   Result := PPROFESSION_INFO(OPENSSL_sk_value(ossl_check_const_PROFESSION_INFO_sk_type(sk), (idx)))
end;

function sk_ADMISSIONS_value(sk: Pointer; idx: int): PADMISSIONS;
begin
   Result := PADMISSIONS(OPENSSL_sk_value(ossl_check_const_ADMISSIONS_sk_type(sk), (idx)))
end;



function ossl_check_ADMISSIONS_type( ptr : PADMISSIONS):PADMISSIONS;
begin
 Exit(ptr);
end;


function ossl_check_const_ADMISSIONS_sk_type(const sk : Pstack_st_ADMISSIONS):POPENSSL_STACK;
begin
 Result :=  POPENSSL_STACK (sk);
end;


function ossl_check_ADMISSIONS_sk_type( sk : Pstack_st_ADMISSIONS):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_ADMISSIONS_compfunc_type( cmp : sk_ADMISSIONS_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ADMISSIONS_copyfunc_type( cpy : sk_ADMISSIONS_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_ADMISSIONS_freefunc_type( fr : sk_ADMISSIONS_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function  sk_ADMISSIONS_num(sk: Pointer): int;
begin
  Result := OPENSSL_sk_num(ossl_check_const_ADMISSIONS_sk_type(sk))
end;

function ossl_check_PROFESSION_INFO_type( ptr : PPROFESSION_INFO):PPROFESSION_INFO;
begin
 Exit(ptr);
end;


function ossl_check_const_PROFESSION_INFO_sk_type(const sk : Pstack_st_PROFESSION_INFO):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_PROFESSION_INFO_sk_type( sk : Pstack_st_PROFESSION_INFO):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_PROFESSION_INFO_compfunc_type( cmp : sk_PROFESSION_INFO_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_PROFESSION_INFO_copyfunc_type( cpy : sk_PROFESSION_INFO_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_PROFESSION_INFO_freefunc_type( fr : sk_PROFESSION_INFO_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_PROFESSION_INFO_num(sk: Pointer): int;
begin
  Result := OPENSSL_sk_num(ossl_check_const_PROFESSION_INFO_sk_type(sk))
end;

function X509v3_get_ext_count(const x : Pstack_st_X509_EXTENSION):integer;
begin
    if x = nil then Exit(0);
    Result := sk_X509_EXTENSION_num(x);
end;


function X509v3_get_ext_by_NID(const x : Pstack_st_X509_EXTENSION; nid, lastpos : integer):integer;
var
  obj : PASN1_OBJECT;
begin
    obj := OBJ_nid2obj(nid);
    if obj = nil then Exit(-2);
    Result := X509v3_get_ext_by_OBJ(x, obj, lastpos);
end;


function X509v3_get_ext_by_OBJ(const sk : Pstack_st_X509_EXTENSION;const obj : PASN1_OBJECT; lastpos : integer):integer;
var
  n : integer;
  ex : PX509_EXTENSION;
begin
    if sk = nil then Exit(-1);
       Inc(lastpos);
    if lastpos < 0 then
       lastpos := 0;
    n := sk_X509_EXTENSION_num(sk);
    while lastpos < n do
    begin
        ex := sk_X509_EXTENSION_value(sk, lastpos);
        if _OBJ_cmp(ex._object, obj) = 0  then
            Exit(lastpos);
        Inc(lastpos);
    end;
    Result := -1;
end;


function X509v3_get_ext_by_critical(const sk : Pstack_st_X509_EXTENSION; crit, lastpos : integer):integer;
var
  n : integer;
  ex : PX509_EXTENSION;
begin
    if sk = nil then Exit(-1);
    PostInc(lastpos);
    if lastpos < 0 then
       lastpos := 0;
    n := sk_X509_EXTENSION_num(sk);
    while lastpos < n do
    begin
        ex := sk_X509_EXTENSION_value(sk, lastpos);
        if ( (ex.critical > 0)   and (0 < crit) )  or
           ( (ex.critical <= 0)  and (0 >= crit) ) then
            Exit(lastpos);
        Inc(lastpos);
    end;
    Result := -1;
end;


function X509v3_get_ext(const x : Pstack_st_X509_EXTENSION; loc : integer):PX509_EXTENSION;
begin
    if (x = nil)  or  (sk_X509_EXTENSION_num(x) <= loc)  or  (loc < 0) then
        Exit(nil)
    else
        Result := sk_X509_EXTENSION_value(x, loc);
end;


function X509v3_delete_ext( x : Pstack_st_X509_EXTENSION; loc : integer):PX509_EXTENSION;
var
  ret : PX509_EXTENSION;
begin
    if (x = nil)  or  (sk_X509_EXTENSION_num(x) <= loc)  or  (loc < 0)  then
        Exit(nil);
    ret := sk_X509_EXTENSION_delete(x, loc);
    Result := ret;
end;


function X509v3_add_ext( x : PPstack_st_X509_EXTENSION; ex : PX509_EXTENSION; loc : integer):Pstack_st_X509_EXTENSION;
var
  new_ex : PX509_EXTENSION;
  n : integer;
  sk : Pstack_st_X509_EXTENSION;
  label _err2, _err;
begin
    new_ex := nil;
    sk := nil;
    if x = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        goto _err2 ;
    end;
    if x^ = nil then
    begin
       sk := sk_X509_EXTENSION_new_null();
       if sk = nil then
          goto _err ;
    end
    else
        sk := x^;
    n := sk_X509_EXTENSION_num(sk);
    if loc > n then
       loc := n
    else
    if (loc < 0) then
        loc := n;
    new_ex := X509_EXTENSION_dup(ex);
    if new_ex = nil then
         goto _err2 ;
    if 0>= sk_X509_EXTENSION_insert(sk, new_ex, loc) then
        goto _err ;
    if x^ = nil then
        x^ := sk;
    Exit(sk);
 _err:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
 _err2:
    X509_EXTENSION_free(new_ex);
    if (x <> nil)  and  (x^ = nil) then
       sk_X509_EXTENSION_free(sk);
    Result := nil;
end;


function X509_EXTENSION_create_by_NID( ex : PPX509_EXTENSION; nid, crit : integer; data : PASN1_OCTET_STRING):PX509_EXTENSION;
var
  obj : PASN1_OBJECT;
  ret : PX509_EXTENSION;
begin
    obj := OBJ_nid2obj(nid);
    if obj = nil then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_NID);
        Exit(nil);
    end;
    ret := X509_EXTENSION_create_by_OBJ(ex, obj, crit, data);
    if ret = nil then
       ASN1_OBJECT_free(obj);
    Result := ret;
end;


function X509_EXTENSION_create_by_OBJ(ex : PPX509_EXTENSION;const obj : PASN1_OBJECT; crit : integer; data : PASN1_OCTET_STRING):PX509_EXTENSION;
var
  ret : PX509_EXTENSION;
  label _err;
begin
    if (ex = nil)  or  ( ex^ = nil) then
    begin
        ret := X509_EXTENSION_new();
        if ret = nil then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else
        ret := ex^;

    if 0>= X509_EXTENSION_set_object(ret, obj) then
        goto _err ;
    if 0>= X509_EXTENSION_set_critical(ret, crit) then
        goto _err ;
    if 0>= X509_EXTENSION_set_data(ret, data ) then
        goto _err ;
    if (ex <> nil)  and  ( ex^ = nil) then
        ex^ := ret;
    Exit(ret);
 _err:
    if (ex = nil)  or  (ret <> ex^) then
        X509_EXTENSION_free(ret);
    Result := nil;
end;


function X509_EXTENSION_set_object(ex : PX509_EXTENSION;const obj : PASN1_OBJECT):integer;
begin
    if (ex = nil)  or  (obj = nil) then
        Exit(0);
    ASN1_OBJECT_free(ex._object);
    ex._object := OBJ_dup(obj);
    Result := int( ex._object <> nil);
end;


function X509_EXTENSION_set_critical( ex : PX509_EXTENSION; crit : integer):integer;
begin
    if ex = nil then Exit(0);
    ex.critical := get_result(crit>0 , $FF , -1);
    Result := 1;
end;


function X509_EXTENSION_set_data( ex : PX509_EXTENSION; data : PASN1_OCTET_STRING):integer;
var
  i : integer;
begin
    if ex = nil then Exit(0);
    i := ASN1_OCTET_STRING_set(@ex.value, data.data, data.length);
    if 0>= i then Exit(0);
    Result := 1;
end;


function X509_EXTENSION_get_object( ex : PX509_EXTENSION):PASN1_OBJECT;
begin
    if ex = nil then
       Exit(nil);
    Result := ex._object;
end;


function X509_EXTENSION_get_data( ex : PX509_EXTENSION):PASN1_OCTET_STRING;
begin
    if ex = nil then Exit(nil);
    Result := @ex.value;
end;


function X509_EXTENSION_get_critical(const ex : PX509_EXTENSION):integer;
begin
    if ex = nil then Exit(0);
    if ex.critical > 0 then Exit(1);
    Result := 0;
end;


end.
