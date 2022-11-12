unit OpenSSL3.crypto.x509.v3_ocsp;

interface
uses OpenSSL.Api;


var
  ossl_v3_ocsp_crlid, ossl_v3_ocsp_acutoff, ossl_v3_crl_invdate,
  ossl_v3_crl_hold,   ossl_v3_ocsp_nonce, ossl_v3_ocsp_nocheck,
  ossl_v3_ocsp_serviceloc: TX509V3_EXT_METHOD ;

function i2r_ocsp_crlid(const method : PX509V3_EXT_METHOD; _in : Pointer; bp : PBIO; ind : integer):integer;
function i2r_ocsp_acutoff(const method : PX509V3_EXT_METHOD; cutoff : Pointer; bp : PBIO; ind : integer):integer;
function i2r_object(const method : PX509V3_EXT_METHOD; oid : Pointer; bp : PBIO; ind : integer):integer;
function ocsp_nonce_new:Pointer;

procedure ocsp_nonce_free( a : Pointer);
function i2d_ocsp_nonce(const a : Pointer; pp : PPByte):integer;
  function d2i_ocsp_nonce(a : Pointer;{const} pp : PPByte; length : long):Pointer;
function i2r_ocsp_nonce(const method : PX509V3_EXT_METHOD; nonce : Pointer; _out : PBIO; indent : integer):integer;
function s2i_ocsp_nocheck(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):Pointer;
function i2r_ocsp_nocheck(const method : PX509V3_EXT_METHOD; nocheck : Pointer; &out : PBIO; indent : integer):integer;
function i2r_ocsp_serviceloc(const method : PX509V3_EXT_METHOD; _in : Pointer; bp : PBIO; ind : integer):integer;

implementation


uses OpenSSL3.Err,
     openssl3.crypto.ocsp.ocsp_asn,        openssl3.crypto.bio.bio_print,
     openssl3.crypto.asn1.a_gentm,         openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.a_object,        openssl3.crypto.asn1.a_octet,
     openssl3.crypto.asn1.f_string,        openssl3.crypto.asn1.a_strex,
     openssl3.crypto.x509v3,               openssl3.crypto.bio.bio_lib,
     OpenSSL3.crypto.x509.v3_san,
     openssl3.crypto.asn1.a_print,         openssl3.crypto.asn1.f_int;




function i2r_ocsp_serviceloc(const method : PX509V3_EXT_METHOD; _in : Pointer; bp : PBIO; ind : integer):integer;
var
  i : integer;
  a : POCSP_SERVICELOC;
  ad : PACCESS_DESCRIPTION;
  label _err;
begin
    a := _in;
    if BIO_printf(bp, '%*sIssuer: ', [ind, '']) <= 0  then
        goto _err;
    if X509_NAME_print_ex(bp, a.issuer, 0, XN_FLAG_ONELINE) <= 0  then
        goto _err;
    for i := 0 to sk_ACCESS_DESCRIPTION_num(a.locator)-1 do
    begin
        ad := sk_ACCESS_DESCRIPTION_value(a.locator, i);
        if BIO_printf(bp, '\n%*s', [2 * ind, '']) <= 0 then
            goto _err;
        if i2a_ASN1_OBJECT(bp, ad.method) <= 0 then
            goto _err;
        if BIO_puts(bp, ' - ') <= 0  then
            goto _err;
        if GENERAL_NAME_print(bp, ad.location) <= 0  then
            goto _err;
    end;
    Exit(1);
 _err:
    Result := 0;
end;





function i2r_ocsp_nocheck(const method : PX509V3_EXT_METHOD; nocheck : Pointer; &out : PBIO; indent : integer):integer;
begin
    Result := 1;
end;

function s2i_ocsp_nocheck(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):Pointer;
begin
    Result := ASN1_NULL_new;
end;


function i2r_ocsp_nonce(const method : PX509V3_EXT_METHOD; nonce : Pointer; _out : PBIO; indent : integer):integer;
begin
    if BIO_printf(_out, '%*s', [indent, ''])<= 0  then
        Exit(0);
    if i2a_ASN1_STRING(_out, nonce, V_ASN1_OCTET_STRING) <= 0  then
        Exit(0);
    Result := 1;
end;


function i2d_ocsp_nonce(const a : Pointer; pp : PPByte):integer;
var
  os : PASN1_OCTET_STRING;
begin
    os := a;
    if pp <> nil then begin
        memcpy( pp^, os.data, os.length);
        pp^  := pp^ + os.length;
    end;
    Result := os.length;
end;


function d2i_ocsp_nonce(a : Pointer;{const} pp : PPByte; length : long):Pointer;
var
  os: PASN1_OCTET_STRING;
  pos: PPASN1_OCTET_STRING;
  label _err;
begin
    //PASN1_OCTET_STRING os, **pos;
    pos := a;
    if (pos = nil)  or  (pos^ = nil) then
    begin
        os := ASN1_OCTET_STRING_new;
        if os = nil then goto _err;
    end
    else begin
        os := pos^;
    end;
    if 0>=ASN1_OCTET_STRING_set(os, pp^, length) then
        goto _err;
    pp^  := pp^ + length;
    if pos <> nil then
      pos^ := os;
    Exit(os);
 _err:
    if (pos = nil)  or  ( pos^ <> os) then
        ASN1_OCTET_STRING_free(os);
    ERR_raise(ERR_LIB_OCSP, ERR_R_MALLOC_FAILURE);
    Result := nil;
end;



procedure ocsp_nonce_free( a : Pointer);
begin
    ASN1_OCTET_STRING_free(a);
end;



function ocsp_nonce_new:Pointer;
begin
    Result := ASN1_OCTET_STRING_new;
end;



function i2r_object(const method : PX509V3_EXT_METHOD; oid : Pointer; bp : PBIO; ind : integer):integer;
begin
    if BIO_printf(bp, '%*s', [ind, '']) <= 0  then
        Exit(0);
    if i2a_ASN1_OBJECT(bp, oid ) <= 0 then
        Exit(0);
    Result := 1;
end;



function i2r_ocsp_acutoff(const method : PX509V3_EXT_METHOD; cutoff : Pointer; bp : PBIO; ind : integer):integer;
begin
    if BIO_printf(bp, '%*s', [ind, '']) <= 0  then
        Exit(0);
    if 0>=ASN1_GENERALIZEDTIME_print(bp, cutoff) then
        Exit(0);
    Result := 1;
end;

function i2r_ocsp_crlid(const method : PX509V3_EXT_METHOD; _in : Pointer; bp : PBIO; ind : integer):integer;
var
  a : POCSP_CRLID;
  label _err;
begin
    a := _in;
    if a.crlUrl <> nil then
    begin
        if BIO_printf(bp, '%*scrlUrl: ', [ind, '']) <= 0 then
            goto _err;
        if 0>=ASN1_STRING_print(bp, PASN1_STRING(a.crlUrl)) then
            goto _err;
        if BIO_write(bp, PUTF8Char(#10), 1) <= 0  then
            goto _err;
    end;
    if a.crlNum <> nil then
    begin
        if BIO_printf(bp, '%*scrlNum: ', [ind, '']) <= 0 then
            goto _err;
        if i2a_ASN1_INTEGER(bp, a.crlNum) <= 0 then
            goto _err;
        if BIO_write(bp, PUTF8Char(#10), 1) <= 0  then
            goto _err;
    end;
    if a.crlTime <> nil then
    begin
        if BIO_printf(bp, '%*scrlTime: ', [ind, '']) <= 0 then
            goto _err;
        if 0>=ASN1_GENERALIZEDTIME_print(bp, a.crlTime ) then
            goto _err;
        if BIO_write(bp, PUTF8Char(#10), 1) <= 0  then
            goto _err;
    end;
    Exit(1);
 _err:
    Result := 0;
end;

initialization
   ossl_v3_ocsp_crlid := get_V3_EXT_METHOD(
    NID_id_pkix_OCSP_CrlID, 0, OCSP_CRLID_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    i2r_ocsp_crlid, nil,
    nil
);
  ossl_v3_ocsp_acutoff := get_V3_EXT_METHOD (
    NID_id_pkix_OCSP_archiveCutoff, 0, ASN1_GENERALIZEDTIME_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    i2r_ocsp_acutoff, nil,
    nil
);
  ossl_v3_crl_invdate := get_V3_EXT_METHOD (
    NID_invalidity_date, 0, ASN1_GENERALIZEDTIME_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    i2r_ocsp_acutoff, nil,
    nil
);
  ossl_v3_crl_hold := get_V3_EXT_METHOD (
    NID_hold_instruction_code, 0, ASN1_OBJECT_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    i2r_object, nil,
    nil
);
  ossl_v3_ocsp_nonce := get_V3_EXT_METHOD (
    NID_id_pkix_OCSP_Nonce, 0, nil,
    ocsp_nonce_new,
    ocsp_nonce_free,
    d2i_ocsp_nonce,
    i2d_ocsp_nonce,
    nil, nil,
    nil, nil,
    i2r_ocsp_nonce, nil,
    nil
);
  ossl_v3_ocsp_nocheck := get_V3_EXT_METHOD (
    NID_id_pkix_OCSP_noCheck, 0, ASN1_NULL_it,
    nil, nil, nil, nil,
    nil, s2i_ocsp_nocheck,
    nil, nil,
    i2r_ocsp_nocheck, nil,
    nil
);
  ossl_v3_ocsp_serviceloc := get_V3_EXT_METHOD (
    NID_id_pkix_OCSP_serviceLocator, 0, OCSP_SERVICELOC_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    i2r_ocsp_serviceloc, nil,
    nil
);

end.
