unit OpenSSL3.crypto.x509.x509cset;

interface
uses OpenSSL.Api;

function X509_CRL_set_version( x : PX509_CRL; version : long):integer;
  function X509_CRL_set_issuer_name(x : PX509_CRL;const name : PX509_NAME):integer;
  function X509_CRL_set1_lastUpdate(x : PX509_CRL;const tm : PASN1_TIME):integer;
  function X509_CRL_set1_nextUpdate(x : PX509_CRL;const tm : PASN1_TIME):integer;
  function X509_CRL_sort( c : PX509_CRL):integer;
  function X509_CRL_up_ref( crl : PX509_CRL):integer;
  function X509_CRL_get_version(const crl : PX509_CRL):long;
  function X509_CRL_get0_lastUpdate(const crl : PX509_CRL):PASN1_TIME;
  function X509_CRL_get0_nextUpdate(const crl : PX509_CRL):PASN1_TIME;
  function X509_CRL_get_lastUpdate( crl : PX509_CRL):PASN1_TIME;
  function X509_CRL_get_nextUpdate( crl : PX509_CRL):PASN1_TIME;
  function X509_CRL_get_issuer(const crl : PX509_CRL):PX509_NAME;
  function X509_CRL_get0_extensions(const crl : PX509_CRL):Pstack_st_X509_EXTENSION;
  procedure X509_CRL_get0_signature(const crl : PX509_CRL; psig : PPASN1_BIT_STRING; palg : PPX509_ALGOR);
  function X509_CRL_get_signature_nid(const crl : PX509_CRL):integer;
  function X509_REVOKED_get0_revocationDate(const x : PX509_REVOKED):PASN1_TIME;
  function X509_REVOKED_set_revocationDate( x : PX509_REVOKED; tm : PASN1_TIME):integer;
  function X509_REVOKED_get0_serialNumber(const x : PX509_REVOKED):PASN1_INTEGER;
  function X509_REVOKED_set_serialNumber( x : PX509_REVOKED; serial : PASN1_INTEGER):integer;
  function X509_REVOKED_get0_extensions(const r : PX509_REVOKED):Pstack_st_X509_EXTENSION;
  function i2d_re_X509_CRL_tbs( crl : PX509_CRL; pp : PPByte):integer;
  function X509_CRL_get_REVOKED( crl : PX509_CRL):Pstack_st_X509_REVOKED;

implementation
uses openssl3.crypto.asn1.tasn_new, OpenSSL3.include.openssl.asn1,
     openssl3.crypto.asn1.a_int,  OpenSSL3.crypto.x509.x_name,
     OpenSSL3.crypto.x509.x509_set, OpenSSL3.crypto.x509,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.asn1.a_time,
     openssl3.crypto.x509.x_crl,
     openssl3.include.internal.refcount, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.tasn_typ;






function X509_CRL_get_REVOKED( crl : PX509_CRL):Pstack_st_X509_REVOKED;
begin
    Result := crl.crl.revoked;
end;


function X509_CRL_set_version( x : PX509_CRL; version : long):integer;
begin
    if x = nil then Exit(0);
    if x.crl.version = nil then
    begin
        x.crl.version := ASN1_INTEGER_new;
        if (x.crl.version =  nil) then
            Exit(0);
    end;
    Result := ASN1_INTEGER_set(x.crl.version, version);
end;


function X509_CRL_set_issuer_name(x : PX509_CRL;const name : PX509_NAME):integer;
begin
    if x = nil then Exit(0);
    Result := X509_NAME_set(@x.crl.issuer, name);
end;


function X509_CRL_set1_lastUpdate(x : PX509_CRL;const tm : PASN1_TIME):integer;
begin
    if x = nil then Exit(0);
    Result := ossl_x509_set1_time(@x.crl.lastUpdate, tm);
end;


function X509_CRL_set1_nextUpdate(x : PX509_CRL;const tm : PASN1_TIME):integer;
begin
    if x = nil then Exit(0);
    Result := ossl_x509_set1_time(@x.crl.nextUpdate, tm);
end;


function X509_CRL_sort( c : PX509_CRL):integer;
var
  i : integer;

  r : PX509_REVOKED;
begin
    {
     * sort the data so it will be written in serial number order
     }
    sk_X509_REVOKED_sort(c.crl.revoked);
    for i := 0 to sk_X509_REVOKED_num(c.crl.revoked)-1 do begin
        r := sk_X509_REVOKED_value(c.crl.revoked, i);
        r.sequence := i;
    end;
    c.crl.enc.modified := 1;
    Result := 1;
end;


function X509_CRL_up_ref( crl : PX509_CRL):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(crl.references, i, crl.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('X509_CRL', crl);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result(i > 1 , 1 , 0);
end;


function X509_CRL_get_version(const crl : PX509_CRL):long;
begin
    Result := ASN1_INTEGER_get(crl.crl.version);
end;


function X509_CRL_get0_lastUpdate(const crl : PX509_CRL):PASN1_TIME;
begin
    Result := crl.crl.lastUpdate;
end;


function X509_CRL_get0_nextUpdate(const crl : PX509_CRL):PASN1_TIME;
begin
    Result := crl.crl.nextUpdate;
end;


function X509_CRL_get_lastUpdate( crl : PX509_CRL):PASN1_TIME;
begin
    Result := crl.crl.lastUpdate;
end;


function X509_CRL_get_nextUpdate( crl : PX509_CRL):PASN1_TIME;
begin
    Result := crl.crl.nextUpdate;
end;


function X509_CRL_get_issuer(const crl : PX509_CRL):PX509_NAME;
begin
    Result := crl.crl.issuer;
end;


function X509_CRL_get0_extensions(const crl : PX509_CRL):Pstack_st_X509_EXTENSION;
begin
    Result := crl.crl.extensions;
end;


procedure X509_CRL_get0_signature(const crl : PX509_CRL; psig : PPASN1_BIT_STRING; palg : PPX509_ALGOR);
begin
    if psig <> nil then
       psig^ := @crl.signature;
    if palg <> nil then
       palg^ := @crl.sig_alg;
end;


function X509_CRL_get_signature_nid(const crl : PX509_CRL):integer;
begin
    Result := OBJ_obj2nid(crl.sig_alg.algorithm);
end;


function X509_REVOKED_get0_revocationDate(const x : PX509_REVOKED):PASN1_TIME;
begin
    Result := x.revocationDate;
end;


function X509_REVOKED_set_revocationDate( x : PX509_REVOKED; tm : PASN1_TIME):integer;
var
  _in : PASN1_TIME;
begin
    if x = nil then Exit(0);
    _in := x.revocationDate;
    if _in <> tm then
    begin
        _in := ASN1_STRING_dup(tm);
        if _in <> nil then
        begin
            ASN1_TIME_free(x.revocationDate);
            x.revocationDate := _in;
        end;
    end;
    Result := Int(_in <> nil);
end;


function X509_REVOKED_get0_serialNumber(const x : PX509_REVOKED):PASN1_INTEGER;
begin
    Result := @x.serialNumber;
end;


function X509_REVOKED_set_serialNumber( x : PX509_REVOKED; serial : PASN1_INTEGER):integer;
var
  _in : PASN1_INTEGER;
begin
    if x = nil then Exit(0);
    _in := @x.serialNumber;
    if _in <> serial then
       Exit(ASN1_STRING_copy(_in, serial));
    Result := 1;
end;


function X509_REVOKED_get0_extensions(const r : PX509_REVOKED):Pstack_st_X509_EXTENSION;
begin
    Result := r.extensions;
end;


function i2d_re_X509_CRL_tbs( crl : PX509_CRL; pp : PPByte):integer;
begin
    crl.crl.enc.modified := 1;
    Result := i2d_X509_CRL_INFO(@crl.crl, pp);
end;


end.
