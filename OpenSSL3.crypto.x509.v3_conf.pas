unit OpenSSL3.crypto.x509.v3_conf;

interface
uses OpenSSL.Api;

function X509V3_get_section(ctx : PX509V3_CTX;const section : PUTF8Char):Pstack_st_CONF_VALUE;
 procedure X509V3_section_free( ctx : PX509V3_CTX; section : Pstack_st_CONF_VALUE);
function X509V3_EXT_i2d( ext_nid, crit : integer; ext_struc: Pointer):PX509_EXTENSION;
function do_ext_i2d(const method : PX509V3_EXT_METHOD; ext_nid, crit : integer; ext_struc: Pointer):PX509_EXTENSION;


implementation
uses OpenSSL3.Err, OpenSSL3.crypto.x509.v3_lib, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.mem, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.x509.x509_v3;





function do_ext_i2d(const method : PX509V3_EXT_METHOD; ext_nid, crit : integer;ext_struc: Pointer):PX509_EXTENSION;
var
  ext_len : integer;
  ext_oct : PASN1_OCTET_STRING;
  p, ext_der: PByte;
  ext : PX509_EXTENSION;
  label _merr;
begin
    ext_der := nil;
    ext_oct := nil;
    { Convert internal representation to DER }
    if Assigned(method.it) then
    begin
        ext_der := nil;
        ext_len := ASN1_item_i2d(ext_struc, @ext_der, method.it);
        if ext_len < 0 then
           goto _merr;
    end
    else
    begin

        ext_len := method.i2d(ext_struc, nil);
        if ext_len <= 0 then goto _merr;
        ext_der := OPENSSL_malloc(ext_len);
        if ext_der = nil then
            goto _merr;
        p := ext_der;
        method.i2d(ext_struc, @p);
    end;
    ext_oct := ASN1_OCTET_STRING_new();
    if ext_oct = nil then
        goto _merr;
    ext_oct.data := ext_der;
    ext_der := nil;
    ext_oct.length := ext_len;
    ext := X509_EXTENSION_create_by_NID(nil, ext_nid, crit, ext_oct);
    if nil =ext then goto _merr;
    ASN1_OCTET_STRING_free(ext_oct);
    Exit(ext);
 _merr:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(Pointer(ext_der));
    ASN1_OCTET_STRING_free(ext_oct);
    Exit(nil);
end;

function X509V3_EXT_i2d( ext_nid, crit : integer; ext_struc: Pointer):PX509_EXTENSION;
var
  method : PX509V3_EXT_METHOD;
begin
    method := X509V3_EXT_get_nid(ext_nid );
    if method = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_UNKNOWN_EXTENSION);
        Exit(nil);
    end;
    Result := do_ext_i2d(method, ext_nid, crit, ext_struc);
end;





procedure X509V3_section_free( ctx : PX509V3_CTX; section : Pstack_st_CONF_VALUE);
begin
    if nil = section then exit;
    if Assigned(ctx.db_meth.free_section) then
       ctx.db_meth.free_section(ctx.db, section);
end;






function X509V3_get_section(ctx : PX509V3_CTX;const section : PUTF8Char):Pstack_st_CONF_VALUE;
begin
    if (nil = ctx.db)  or  (nil = ctx.db_meth)  or  (not Assigned( ctx.db_meth.get_section)) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_OPERATION_NOT_DEFINED);
        Exit(nil);
    end;
    if Assigned(ctx.db_meth.get_section) then
       Exit(ctx.db_meth.get_section(ctx.db, section));
    Result := nil;
end;


end.
