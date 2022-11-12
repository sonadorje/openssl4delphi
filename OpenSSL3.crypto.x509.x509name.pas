unit OpenSSL3.crypto.x509.x509name;

interface
uses OpenSSL.Api, SysUtils;

function X509_NAME_entry_count(const name : PX509_NAME):integer;
 function X509_NAME_get_entry(const name : PX509_NAME; loc : integer):PX509_NAME_ENTRY;
 function X509_NAME_ENTRY_set(const ne : PX509_NAME_ENTRY):integer;
function X509_NAME_ENTRY_get_object(const ne : PX509_NAME_ENTRY):PASN1_OBJECT;
function X509_NAME_ENTRY_get_data(const ne : PX509_NAME_ENTRY):PASN1_STRING;
function X509_NAME_add_entry_by_txt(name : PX509_NAME;const field : PUTF8Char; _type : integer;const bytes : PByte; len, loc, _set : integer):integer;
function X509_NAME_ENTRY_create_by_txt(ne : PPX509_NAME_ENTRY;const field : PUTF8Char; _type : integer;const bytes : PByte; len : integer):PX509_NAME_ENTRY;
function X509_NAME_ENTRY_create_by_OBJ(ne : PPX509_NAME_ENTRY;const obj : PASN1_OBJECT; _type : integer;const bytes : PByte; len : integer):PX509_NAME_ENTRY;
function X509_NAME_ENTRY_set_object(ne : PX509_NAME_ENTRY;const obj : PASN1_OBJECT):integer;
function X509_NAME_ENTRY_set_data(ne : PX509_NAME_ENTRY; _type : integer;const bytes : PByte; len : integer):integer;
 function X509_NAME_add_entry(name : PX509_NAME;const ne : PX509_NAME_ENTRY; loc, _set : integer):integer;
function X509_NAME_get_index_by_NID(const name : PX509_NAME; nid, lastpos : integer):integer;
function X509_NAME_get_index_by_OBJ(const name : PX509_NAME; obj : PASN1_OBJECT; lastpos : integer):integer;
function X509_NAME_delete_entry( name : PX509_NAME; loc : integer):PX509_NAME_ENTRY;

implementation
uses OpenSSL3.crypto.x509, openssl3.crypto.objects.obj_dat,
     OpenSSL3.Err, OpenSSL3.crypto.x509.x_name,
     openssl3.crypto.asn1.a_print,
     openssl3.crypto.asn1.a_strnid, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.a_object, openssl3.crypto.objects.obj_lib;


function X509_NAME_delete_entry( name : PX509_NAME; loc : integer):PX509_NAME_ENTRY;
var
  ret      : PX509_NAME_ENTRY;
  i,
  n,
  set_prev,
  set_next : integer;
  sk       : Pstack_st_X509_NAME_ENTRY;
begin
    if (name = nil)  or  (sk_X509_NAME_ENTRY_num(name.entries) <= loc )
         or  (loc < 0)  then
        Exit(nil);
    sk := name.entries;
    ret := sk_X509_NAME_ENTRY_delete(sk, loc);
    n := sk_X509_NAME_ENTRY_num(sk);
    name.modified := 1;
    if loc = n then Exit(ret);
    { else we need to fixup the set field }
    if loc <> 0 then
       set_prev := (sk_X509_NAME_ENTRY_value(sk, loc - 1))._set
    else
        set_prev := ret._set - 1;
    set_next := sk_X509_NAME_ENTRY_value(sk, loc)._set;
    {-
     * set_prev is the previous set
     * set is the current set
     * set_next is the following
     * prev  1 1    1 1     1 1     1 1
     * set   1      1       2       2
     * next  1 1    2 2     2 2     3 2
     * so basically only if prev and next differ by 2, then
     * re-number down by 1
     }
    if set_prev + 1 < set_next then
       for i := loc to n-1 do
            Dec(sk_X509_NAME_ENTRY_value(sk, i)._set);
    Result := ret;
end;



function X509_NAME_get_index_by_OBJ(const name : PX509_NAME; obj : PASN1_OBJECT; lastpos : integer):integer;
var
  n : integer;
  ne : PX509_NAME_ENTRY;
  sk : Pstack_st_X509_NAME_ENTRY;
begin
    if name = nil then Exit(-1);
    if lastpos < 0 then lastpos := -1;
    sk := name.entries;
    n := sk_X509_NAME_ENTRY_num(sk);
    PostInc(lastpos);
    while (lastpos < n) do
    begin
        ne := sk_X509_NAME_ENTRY_value(sk, lastpos);
        if _OBJ_cmp(ne._object, obj) = 0  then
            Exit(lastpos);
        PostInc(lastpos);
    end;
    Result := -1;
end;

function X509_NAME_get_index_by_NID(const name : PX509_NAME; nid, lastpos : integer):integer;
var
  obj : PASN1_OBJECT;
begin
    obj := OBJ_nid2obj(nid);
    if obj = nil then Exit(-2);
    Result := X509_NAME_get_index_by_OBJ(name, obj, lastpos);
end;




function X509_NAME_add_entry(name : PX509_NAME;const ne : PX509_NAME_ENTRY; loc, _set : integer):integer;
var
  new_name : PX509_NAME_ENTRY;
  n,
  i,
  inc      : integer;
  sk       : Pstack_st_X509_NAME_ENTRY;
  label _err;
begin
    new_name := nil;
    if name = nil then Exit(0);
    sk := name.entries;
    n := sk_X509_NAME_ENTRY_num(sk);
    if loc > n then
       loc := n
    else
    if (loc < 0) then
        loc := n;
    inc := int(_set = 0);
    name.modified := 1;
    if _set = -1 then
    begin
        if loc = 0 then
        begin
            _set := 0;
            inc := 1;
        end
        else
        begin
            _set := sk_X509_NAME_ENTRY_value(sk, loc - 1)._set;
        end;
    end
    else
    begin                     { if (set >= 0) }
        if loc >= n then
        begin
            if loc <> 0 then
                _set := sk_X509_NAME_ENTRY_value(sk, loc - 1)._set + 1
            else
                _set := 0;
        end
        else
            _set := sk_X509_NAME_ENTRY_value(sk, loc)._set;
    end;
    new_name := X509_NAME_ENTRY_dup(ne);
    if new_name = nil then
        goto _err ;
    new_name._set := _set;
    if 0>= sk_X509_NAME_ENTRY_insert(sk, new_name, loc) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if inc > 0 then
    begin
        n := sk_X509_NAME_ENTRY_num(sk);
        for i := loc + 1 to n-1 do
            sk_X509_NAME_ENTRY_value(sk, i)._set  := sk_X509_NAME_ENTRY_value(sk, i)._set + 1;
    end;
    Exit(1);
 _err:
    X509_NAME_ENTRY_free(new_name);
    Result := 0;
end;


function X509_NAME_ENTRY_set_data(ne : PX509_NAME_ENTRY; _type : integer;const bytes : PByte; len : integer):integer;
var
  i : integer;
begin
    if (ne = nil)  or  ((bytes = nil)  and  (len <> 0)) then
        Exit(0);
    if (_type > 0)  and ( (_type and MBSTRING_FLAG)>0 ) then
    begin
        if ASN1_STRING_set_by_NID(@ne.value, bytes,
                                      len, _type,
                                      OBJ_obj2nid(ne._object)) <> nil then
           Exit(1)
        else
           Exit(0);
    end;
    if len < 0 then
       len := Length(PUTF8Char(bytes));
    i := ASN1_STRING_set(ne.value, bytes, len);
    if 0>= i then
       Exit(0);
    if _type <> V_ASN1_UNDEF then
    begin
        if _type = V_ASN1_APP_CHOOSE then
            ne.value.&type := ASN1_PRINTABLE_type(bytes, len)
        else
            ne.value.&type := _type;
    end;
    Result := 1;
end;



function X509_NAME_ENTRY_set_object(ne : PX509_NAME_ENTRY;const obj : PASN1_OBJECT):integer;
begin
    if (ne = nil) or  (obj = nil) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ASN1_OBJECT_free(ne._object);
    ne._object := OBJ_dup(obj);
    Result := get_result((ne._object = nil) , 0 , 1);
end;




function X509_NAME_ENTRY_create_by_OBJ(ne : PPX509_NAME_ENTRY;const obj : PASN1_OBJECT; _type : integer;const bytes : PByte; len : integer):PX509_NAME_ENTRY;
var
  ret : PX509_NAME_ENTRY;
  label _err;
begin
    if (ne = nil)  or  ( ne^ = nil) then
    begin
        ret := X509_NAME_ENTRY_new();
        if (ret = nil) then
            Exit(nil);
    end
    else
        ret := ne^;
    if 0>= X509_NAME_ENTRY_set_object(ret, obj) then
        goto _err ;
    if 0>= X509_NAME_ENTRY_set_data(ret, _type, bytes, len) then
        goto _err ;
    if (ne <> nil)  and  ( ne^ = nil) then
        ne^ := ret;
    Exit(ret);
 _err:
    if (ne = nil)  or  (ret <> ne^) then
        X509_NAME_ENTRY_free(ret);
    Result := nil;
end;




function X509_NAME_ENTRY_create_by_txt(ne : PPX509_NAME_ENTRY;const field : PUTF8Char; _type : integer;const bytes : PByte; len : integer):PX509_NAME_ENTRY;
var
  obj : PASN1_OBJECT;

  nentry : PX509_NAME_ENTRY;
begin
    obj := OBJ_txt2obj(field, 0);
    if obj = nil then
    begin
        ERR_raise_data(ERR_LIB_X509, X509_R_INVALID_FIELD_NAME,
                       Format('name=%s', [field]));
        Exit(nil);
    end;
    nentry := X509_NAME_ENTRY_create_by_OBJ(ne, obj, _type, bytes, len);
    ASN1_OBJECT_free(obj);
    Result := nentry;
end;


function X509_NAME_add_entry_by_txt(name : PX509_NAME;const field : PUTF8Char; _type : integer;const bytes : PByte; len, loc, _set : integer):integer;
var
  ne : PX509_NAME_ENTRY;
  ret : integer;
begin
    ne := X509_NAME_ENTRY_create_by_txt(nil, field, _type, bytes, len);
    if nil = ne then
       Exit(0);
    ret := X509_NAME_add_entry(name, ne, loc, _set);
    X509_NAME_ENTRY_free(ne);
    Result := ret;
end;



function X509_NAME_ENTRY_get_data(const ne : PX509_NAME_ENTRY):PASN1_STRING;
begin
    if ne = nil then Exit(nil);
    Result := ne.value;
end;

function X509_NAME_ENTRY_get_object(const ne : PX509_NAME_ENTRY):PASN1_OBJECT;
begin
    if ne = nil then
       Exit(nil);
    Result := ne._object;
end;


function X509_NAME_ENTRY_set(const ne : PX509_NAME_ENTRY):integer;
begin
    Result := ne._set;
end;


function X509_NAME_get_entry(const name : PX509_NAME; loc : integer):PX509_NAME_ENTRY;
begin
    if (name = nil)  or  (sk_X509_NAME_ENTRY_num(name.entries) <= loc)
         or  (loc < 0) then
        Exit(nil);
    Result := sk_X509_NAME_ENTRY_value(name.entries, loc);
end;

function X509_NAME_entry_count(const name : PX509_NAME):integer;
begin
    if name = nil then Exit(0);
    Result := sk_X509_NAME_ENTRY_num(name.entries);
end;

end.
