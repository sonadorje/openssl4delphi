unit openssl3.crypto.x509.x509_att;

interface
uses OpenSSL.Api, SysUtils;

function X509at_add1_attr_by_NID(x : PPstack_st_X509_ATTRIBUTE; nid, _type : integer;const bytes : PByte; len : integer):Pstack_st_X509_ATTRIBUTE;
function X509_ATTRIBUTE_create_by_NID(attr : PPX509_ATTRIBUTE; nid, atrtype : integer;const data : Pointer; len : integer):PX509_ATTRIBUTE;
function X509_ATTRIBUTE_create_by_OBJ(attr : PPX509_ATTRIBUTE;const obj : PASN1_OBJECT; atrtype : integer;const data : Pointer; len : integer):PX509_ATTRIBUTE;
  function X509_ATTRIBUTE_create_by_txt(attr : PPX509_ATTRIBUTE;const atrname : PUTF8Char; &type : integer;const bytes : PByte; len : integer):PX509_ATTRIBUTE;
  function X509_ATTRIBUTE_set1_object(attr : PX509_ATTRIBUTE;const obj : PASN1_OBJECT):integer;
  function X509_ATTRIBUTE_set1_data(attr : PX509_ATTRIBUTE; attrtype : integer;const data : Pointer; len : integer):integer;
  function X509_ATTRIBUTE_count(const attr : PX509_ATTRIBUTE):integer;
  function X509_ATTRIBUTE_get0_object( attr : PX509_ATTRIBUTE):PASN1_OBJECT;
  function X509_ATTRIBUTE_get0_data( attr : PX509_ATTRIBUTE; idx, atrtype : integer; data : Pointer):Pointer;
  function X509_ATTRIBUTE_get0_type( attr : PX509_ATTRIBUTE; idx : integer):PASN1_TYPE;
  function X509at_add1_attr( x : PPstack_st_X509_ATTRIBUTE; attr : PX509_ATTRIBUTE):Pstack_st_X509_ATTRIBUTE;
  function X509at_add1_attr_by_OBJ(x : PPstack_st_X509_ATTRIBUTE;const obj : PASN1_OBJECT; _type : integer;const bytes : PByte; len : integer):Pstack_st_X509_ATTRIBUTE;

implementation
uses
   openssl3.crypto.objects.obj_dat, OpenSSL3.Err, openssl3.crypto.x509.x_attrib,
   openssl3.crypto.asn1.a_object, openssl3.crypto.objects.obj_lib,
   openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.a_type,
   OpenSSL3.include.openssl.asn1, openssl3.crypto.x509,
   openssl3.crypto.asn1.a_strnid, openssl3.crypto.asn1.asn1_lib;






function X509at_add1_attr_by_OBJ(x : PPstack_st_X509_ATTRIBUTE;const obj : PASN1_OBJECT; _type : integer;const bytes : PByte; len : integer):Pstack_st_X509_ATTRIBUTE;
var
  attr : PX509_ATTRIBUTE;
  ret : Pstack_st_X509_ATTRIBUTE;
begin
    attr := X509_ATTRIBUTE_create_by_OBJ(nil, obj, _type, bytes, len);
    if nil = attr then
       Exit(0);
    ret := X509at_add1_attr(x, attr);
    X509_ATTRIBUTE_free(attr);
    Result := ret;
end;



function X509at_add1_attr( x : PPstack_st_X509_ATTRIBUTE; attr : PX509_ATTRIBUTE):Pstack_st_X509_ATTRIBUTE;
var
    new_attr : PX509_ATTRIBUTE;
    sk       : Pstack_st_X509_ATTRIBUTE;
    label _err, _err2;
begin
    new_attr := nil;
    sk := nil;
    if x = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if x^ = nil then
    begin
        sk := sk_X509_ATTRIBUTE_new_null();
        if sk = nil then
            goto _err ;
    end
    else
    begin
        sk := x^;
    end;
    new_attr := X509_ATTRIBUTE_dup(attr);
    if new_attr = nil then
         goto _err2 ;
    if 0>= sk_X509_ATTRIBUTE_push(sk, new_attr) then
        goto _err ;
    if x^ = nil then
       x^ := sk;
    Exit(sk);
 _err:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
 _err2:
    X509_ATTRIBUTE_free(new_attr);
    if x^ = nil then
       sk_X509_ATTRIBUTE_free(sk);
    Result := nil;
end;

function X509_ATTRIBUTE_create_by_OBJ(attr : PPX509_ATTRIBUTE;const obj : PASN1_OBJECT; atrtype : integer;const data : Pointer; len : integer):PX509_ATTRIBUTE;
var
  ret : PX509_ATTRIBUTE;
  label _err;
begin
    if (attr = nil) or  ( attr^ = nil) then
    begin
        ret := X509_ATTRIBUTE_new();
        if ret = nil then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else
        ret := attr^;
    if 0>= X509_ATTRIBUTE_set1_object(ret, obj) then
        goto _err ;
    if 0>= X509_ATTRIBUTE_set1_data(ret, atrtype, data, len) then
        goto _err ;
    if (attr <> nil)  and  ( attr^ = nil) then
        attr^ := ret;
    Exit(ret);
 _err:
    if (attr = nil)  or  (ret <> attr^) then
        X509_ATTRIBUTE_free(ret);
    Result := nil;
end;


function X509_ATTRIBUTE_create_by_txt(attr : PPX509_ATTRIBUTE;const atrname : PUTF8Char; &type : integer;const bytes : PByte; len : integer):PX509_ATTRIBUTE;
var
  obj : PASN1_OBJECT;

  nattr : PX509_ATTRIBUTE;
begin
    obj := OBJ_txt2obj(atrname, 0);
    if obj = nil then
    begin
        ERR_raise_data(ERR_LIB_X509, X509_R_INVALID_FIELD_NAME,
                      Format( 'name=%s', [atrname]));
        Exit(nil);
    end;
    nattr := X509_ATTRIBUTE_create_by_OBJ(attr, obj, &type, bytes, len);
    ASN1_OBJECT_free(obj);
    Result := nattr;
end;


function X509_ATTRIBUTE_set1_object(attr : PX509_ATTRIBUTE;const obj : PASN1_OBJECT):integer;
begin
    if (attr = nil) or  (obj = nil) then
        Exit(0);
    ASN1_OBJECT_free(attr._object);
    attr._object := OBJ_dup(obj);
    Result := Int(attr._object <> nil);
end;


function X509_ATTRIBUTE_set1_data(attr : PX509_ATTRIBUTE; attrtype : integer;const data : Pointer; len : integer):integer;
var
  ttmp : PASN1_TYPE;

  stmp : PASN1_STRING;

  atype : integer;
  label _err;
begin
    ttmp := nil;
    stmp := nil;
    atype := 0;
    if nil = attr then
       Exit(0);
    if (attrtype and MBSTRING_FLAG) > 0 then
    begin
        stmp := ASN1_STRING_set_by_NID(nil, data, len, attrtype,
                                      OBJ_obj2nid(attr._object));
        if nil = stmp then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
            Exit(0);
        end;
        atype := stmp.&type;
    end
    else
    if (len <> -1) then
    begin
        stmp := ASN1_STRING_type_new(attrtype);
        if stmp = nil then
            goto _err ;
        if 0>= ASN1_STRING_set(stmp, data, len) then
            goto _err ;
        atype := attrtype;
    end;
    {
     * This is a bit naughty because the attribute should really have at
     * least one value but some types use and zero length SET and require
     * this.
     }
    if attrtype = 0 then
    begin
        ASN1_STRING_free(stmp);
        Exit(1);
    end;
    ttmp := ASN1_TYPE_new();
    if ttmp = nil then
        goto _err ;
    if (len = -1)  and  (0>= (attrtype and MBSTRING_FLAG)) then
    begin
        if 0>= ASN1_TYPE_set1(ttmp, attrtype, data) then
            goto _err ;
    end
    else
    begin
        ASN1_TYPE_set(ttmp, atype, stmp);
        stmp := nil;
    end;
    if 0>= sk_ASN1_TYPE_push(attr._set, ttmp) then
        goto _err ;
    Exit(1);
 _err:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    ASN1_TYPE_free(ttmp);
    ASN1_STRING_free(stmp);
    Result := 0;
end;


function X509_ATTRIBUTE_count(const attr : PX509_ATTRIBUTE):integer;
begin
    if attr = nil then
       Exit(0);
    Result := sk_ASN1_TYPE_num(attr._set);
end;


function X509_ATTRIBUTE_get0_object( attr : PX509_ATTRIBUTE):PASN1_OBJECT;
begin
    if attr = nil then
       Exit(nil);
    Result := attr._object;
end;


function X509_ATTRIBUTE_get0_data( attr : PX509_ATTRIBUTE; idx, atrtype : integer; data : Pointer):Pointer;
var
  ttmp : PASN1_TYPE;
begin
    ttmp := X509_ATTRIBUTE_get0_type(attr, idx);
    if nil = ttmp then
       Exit(nil);
    if (atrtype = V_ASN1_BOOLEAN)
             or  (atrtype = V_ASN1_NULL)
             or  (atrtype <> ASN1_TYPE_get(ttmp)) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_WRONG_TYPE);
        Exit(nil);
    end;
    Result := ttmp.value.ptr;
end;


function X509_ATTRIBUTE_get0_type( attr : PX509_ATTRIBUTE; idx : integer):PASN1_TYPE;
begin
    if attr = nil then
       Exit(nil);
    Result := sk_ASN1_TYPE_value(attr._set, idx);
end;

function X509_ATTRIBUTE_create_by_NID(attr : PPX509_ATTRIBUTE; nid, atrtype : integer;const data : Pointer; len : integer):PX509_ATTRIBUTE;
var
  obj : PASN1_OBJECT;
  ret : PX509_ATTRIBUTE;
begin
    obj := OBJ_nid2obj(nid);
    if obj = nil then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_NID);
        Exit(nil);
    end;
    ret := X509_ATTRIBUTE_create_by_OBJ(attr, obj, atrtype, data, len);
    if ret = nil then
       ASN1_OBJECT_free(obj);
    Result := ret;
end;



function X509at_add1_attr_by_NID(x : PPstack_st_X509_ATTRIBUTE; nid, _type : integer;const bytes : PByte; len : integer):Pstack_st_X509_ATTRIBUTE;
var
  attr : PX509_ATTRIBUTE;

  ret : Pstack_st_X509_ATTRIBUTE;
begin
    attr := X509_ATTRIBUTE_create_by_NID(nil, nid, _type, bytes, len);
    if nil = attr then
       Exit(0);
    ret := X509at_add1_attr(x, attr);
    X509_ATTRIBUTE_free(attr);
    Result := ret;
end;


end.
