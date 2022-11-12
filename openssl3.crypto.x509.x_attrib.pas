unit openssl3.crypto.x509.x_attrib;

interface
uses OpenSSL.Api;

function X509_ATTRIBUTE_create( nid, atrtype : integer; value : Pointer):PX509_ATTRIBUTE;
function d2i_X509_ATTRIBUTE(a : PPX509_ATTRIBUTE;const _in : PPByte; len : long):PX509_ATTRIBUTE;
function i2d_X509_ATTRIBUTE(const a : PX509_ATTRIBUTE; _out : PPByte):integer;
function X509_ATTRIBUTE_new:PX509_ATTRIBUTE;
procedure X509_ATTRIBUTE_free( a : PX509_ATTRIBUTE);
function X509_ATTRIBUTE_it:PASN1_ITEM;
function X509_ATTRIBUTE_dup(const x : PX509_ATTRIBUTE):PX509_ATTRIBUTE;

var
   X509_ATTRIBUTE_seq_tt: array[0..1] of TASN1_TEMPLATE ;

implementation
uses openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.tasn_enc,
     OpenSSL3.include.openssl.asn1, openssl3.crypto.asn1.a_type,
     openssl3.crypto.asn1.a_dup,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre;







function X509_ATTRIBUTE_dup(const x : PX509_ATTRIBUTE):PX509_ATTRIBUTE;
begin
   result := ASN1_item_dup(X509_ATTRIBUTE_it, x);
end;




function X509_ATTRIBUTE_it:PASN1_ITEM;

  const local_it: TASN1_ITEM  = (
     itype: $1;
     utype: 16;
     templates: @X509_ATTRIBUTE_seq_tt;
     tcount: sizeof(X509_ATTRIBUTE_seq_tt) div sizeof(TASN1_TEMPLATE);
     funcs: Pointer(0) ;
     size: sizeof(TX509_ATTRIBUTE);
     sname: 'X509_ATTRIBUTE' );
begin
   Result := @local_it;
end;

function d2i_X509_ATTRIBUTE(a : PPX509_ATTRIBUTE;const _in : PPByte; len : long):PX509_ATTRIBUTE;
begin
 result := PX509_ATTRIBUTE(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_ATTRIBUTE_it));
end;


function i2d_X509_ATTRIBUTE(const a : PX509_ATTRIBUTE; _out : PPByte):integer;
begin
 result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_ATTRIBUTE_it);
end;


function X509_ATTRIBUTE_new:PX509_ATTRIBUTE;
begin
 result := PX509_ATTRIBUTE(ASN1_item_new(X509_ATTRIBUTE_it));
end;


procedure X509_ATTRIBUTE_free( a : PX509_ATTRIBUTE);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_ATTRIBUTE_it);
end;

function X509_ATTRIBUTE_create( nid, atrtype : integer; value : Pointer):PX509_ATTRIBUTE;
var
  ret : PX509_ATTRIBUTE;
  val : PASN1_TYPE;
  oid : PASN1_OBJECT;
  label _err;
begin
    ret := nil;
    val := nil;
    oid := OBJ_nid2obj(nid );
    if oid = nil then
        Exit(nil);
    ret := X509_ATTRIBUTE_new();
    if ret = nil then
        Exit(nil);
    ret._object := oid;
    val := ASN1_TYPE_new();
    val := ASN1_TYPE_new();
    if val = nil then
        goto _err ;
    if 0>= sk_ASN1_TYPE_push(ret._set, val) then
        goto _err ;
    ASN1_TYPE_set(val, atrtype, value);
    Exit(ret);
 _err:
    X509_ATTRIBUTE_free(ret);
    ASN1_TYPE_free(val);
    Result := nil;
end;

initialization

    X509_ATTRIBUTE_seq_tt[0] := get_ASN1_TEMPLATE(0,          0, size_t(@PX509_ATTRIBUTE(0)._object), 'object', ASN1_OBJECT_it );
    X509_ATTRIBUTE_seq_tt[1] := get_ASN1_TEMPLATE(($1 shl 1), 0, size_t(@PX509_ATTRIBUTE(0)._set),    'set'  ,  ASN1_ANY_it );

end.
