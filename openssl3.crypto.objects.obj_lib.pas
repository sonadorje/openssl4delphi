unit openssl3.crypto.objects.obj_lib;

interface
uses OpenSSL.Api;

function OBJ_dup(const o : PASN1_OBJECT):PASN1_OBJECT;
function _OBJ_cmp(const a, b : PASN1_OBJECT):integer;

implementation
uses openssl3.crypto.asn1.a_object, OpenSSL3.Err, openssl3.crypto.o_str;

function OBJ_dup(const o : PASN1_OBJECT):PASN1_OBJECT;
var
  r : PASN1_OBJECT;
  label _err;
begin
    if o = nil then Exit(nil);
    { If object isn't dynamic it's an internal OID which is never freed }
    if 0>= (o.flags and ASN1_OBJECT_FLAG_DYNAMIC) then
        Exit(PASN1_OBJECT(o));
    r := ASN1_OBJECT_new();
    if r = nil then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_ASN1_LIB);
        Exit(nil);
    end;
    { Set dynamic flags so everything gets freed up on error }
    r.flags := o.flags or (ASN1_OBJECT_FLAG_DYNAMIC or
                           ASN1_OBJECT_FLAG_DYNAMIC_STRINGS or
                           ASN1_OBJECT_FLAG_DYNAMIC_DATA);
    r.data := OPENSSL_memdup(o.data, o.length);
    if (o.length > 0)  and  (r.data = nil) then
        goto _err ;
    r.length := o.length;
    r.nid := o.nid;
    OPENSSL_strdup(r.ln, o.ln);
    if (o.ln <> nil)  and  (r.ln = nil) then
        goto _err ;
    OPENSSL_strdup(r.sn, o.sn);
    if (o.sn <> nil)  and  (r.sn = nil) then
        goto _err ;
    Exit(r);
 _err:
    ASN1_OBJECT_free(r);
    ERR_raise(ERR_LIB_OBJ, ERR_R_MALLOC_FAILURE);
    Result := nil;
end;


function _OBJ_cmp(const a, b : PASN1_OBJECT):integer;
var
  ret : integer;
begin
    ret := (a.length - b.length);
    if ret > 0 then
       Exit(ret);
    Result := memcmp(a.data, b.data, a.length);
end;


end.
