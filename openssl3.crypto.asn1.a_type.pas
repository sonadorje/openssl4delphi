unit openssl3.crypto.asn1.a_type;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

  function ASN1_TYPE_get(const a : PASN1_TYPE):integer;
  procedure ASN1_TYPE_set( a : PASN1_TYPE; &type : integer; value : Pointer);
  function ASN1_TYPE_set1(a : PASN1_TYPE; &type : integer;const value : Pointer):integer;
  function ASN1_TYPE_cmp(const a, b : PASN1_TYPE):integer;
  function ASN1_TYPE_pack_sequence(const it : PASN1_ITEM; s : Pointer; t : PPASN1_TYPE):PASN1_TYPE;
  function ASN1_TYPE_unpack_sequence(const it : PASN1_ITEM; t : PASN1_TYPE):Pointer;


implementation
uses openssl3.crypto.asn1.tasn_fre, openssl3.crypto.objects.obj_lib,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.asn1.asn_pack,
     openssl3.crypto.asn1.tasn_typ;






function ASN1_TYPE_get(const a : PASN1_TYPE):integer;
begin
    if (a._type = V_ASN1_BOOLEAN)
             or  (a._type = V_ASN1_NULL)
             or  (a.value.ptr <> nil) then
       Exit(a._type)
    else
        Result := 0;
end;


procedure ASN1_TYPE_set( a : PASN1_TYPE; &type : integer; value : Pointer);
var
  tmp_a : ^PASN1_TYPE;
begin
    if (a._type <> V_ASN1_BOOLEAN)
             and  (a._type <> V_ASN1_NULL)
             and  (a.value.ptr <> nil) then
    begin
        tmp_a^ := @a;
        ossl_asn1_primitive_free(PPASN1_VALUE(tmp_a), nil, 0);
    end;
    a._type := &type;
    if &type = V_ASN1_BOOLEAN then
       a.value._boolean := get_result(value <> nil, $ff , 0)
    else
        a.value.ptr := value;
end;


function ASN1_TYPE_set1(a : PASN1_TYPE; &type : integer;const value : Pointer):integer;
var
  p : Pointer;

  odup : PASN1_OBJECT;

  sdup : PASN1_STRING;
begin
    if (nil = value)  or  (&type = V_ASN1_BOOLEAN) then
    begin
        p := Pointer( value);
        ASN1_TYPE_set(a, &type, p);
    end
    else
    if (&type = V_ASN1_OBJECT) then
    begin
        odup := OBJ_dup(value);
        if nil = odup then
           Exit(0);
        ASN1_TYPE_set(a, &type, odup);
    end
    else
    begin
        sdup := ASN1_STRING_dup(value);
        if nil = sdup then
           Exit(0);
        ASN1_TYPE_set(a, &type, sdup);
    end;
    Result := 1;
end;


function ASN1_TYPE_cmp(const a, b : PASN1_TYPE):integer;
begin
    result := -1;
    if (nil = a)  or  (nil = b)  or  (a._type <> b._type) then
       Exit(-1);
    case a._type of
        V_ASN1_OBJECT:
            result := _OBJ_cmp(a.value._object, b.value._object);
            //break;
        V_ASN1_BOOLEAN:
            result := a.value._boolean - b.value._boolean;
            //break;
        V_ASN1_NULL:
            result := 0;             { They do not have content. }
            //break;
        V_ASN1_INTEGER,
        V_ASN1_ENUMERATED,
        V_ASN1_BIT_STRING,
        V_ASN1_OCTET_STRING,
        V_ASN1_SEQUENCE,
        V_ASN1_SET,
        V_ASN1_NUMERICSTRING,
        V_ASN1_PRINTABLESTRING,
        V_ASN1_T61STRING,
        V_ASN1_VIDEOTEXSTRING,
        V_ASN1_IA5STRING,
        V_ASN1_UTCTIME,
        V_ASN1_GENERALIZEDTIME,
        V_ASN1_GRAPHICSTRING,
        V_ASN1_VISIBLESTRING,
        V_ASN1_GENERALSTRING,
        V_ASN1_UNIVERSALSTRING,
        V_ASN1_BMPSTRING,
        V_ASN1_UTF8STRING,
        V_ASN1_OTHER:
        begin
            result := ASN1_STRING_cmp(PASN1_STRING( a.value.ptr),
                                      PASN1_STRING( b.value.ptr));
        end
        else
            result := ASN1_STRING_cmp(PASN1_STRING( a.value.ptr),
                                      PASN1_STRING( b.value.ptr));

    end;

end;


function ASN1_TYPE_pack_sequence(const it : PASN1_ITEM; s : Pointer; t : PPASN1_TYPE):PASN1_TYPE;
var
  oct : PASN1_OCTET_STRING;

  rt : PASN1_TYPE;
begin
    oct := PASN1_OCTET_STRING(ASN1_item_pack(s, it, nil));
    if oct = nil then
       Exit(nil);
    if (t <>nil)   and  (t^ <> nil) then
    begin
        rt := t^;
    end
    else
    begin
        rt := ASN1_TYPE_new();
        if rt = nil then
        begin
            ASN1_OCTET_STRING_free(oct);
            Exit(nil);
        end;
        if t <> nil then
           t^ := rt;
    end;
    ASN1_TYPE_set(rt, V_ASN1_SEQUENCE, oct);
    Result := rt;
end;


function ASN1_TYPE_unpack_sequence(const it : PASN1_ITEM; t : PASN1_TYPE):Pointer;
begin
    if (t = nil)  or  (t._type <> V_ASN1_SEQUENCE)  or  (t.value.sequence = nil) then
       Exit(nil);
    Result := ASN1_item_unpack(t.value.sequence, it);
end;


end.
