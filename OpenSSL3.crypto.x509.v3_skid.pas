unit OpenSSL3.crypto.x509.v3_skid;

interface
uses OpenSSL.Api, openssl3.crypto.asn1.tasn_typ;

  function i2s_ASN1_OCTET_STRING(const method : PX509V3_EXT_METHOD;{const} oct : Pointer):PUTF8Char;
  function s2i_ASN1_OCTET_STRING(method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):PASN1_OCTET_STRING;
  function ossl_x509_pubkey_hash( pubkey : PX509_PUBKEY):PASN1_OCTET_STRING;
  function s2i_skey_id(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char): Pointer{PASN1_OCTET_STRING};

const ossl_v3_skey_id: TX509V3_EXT_METHOD  = (
    ext_nid: NID_subject_key_identifier; ext_flags: 0; it: ASN1_OCTET_STRING_it;
    ext_new: nil; ext_free: nil; d2i: nil; i2d: nil;
    i2s: {X509V3_EXT_I2S}i2s_ASN1_OCTET_STRING;
    s2i: {X509V3_EXT_S2I}s2i_skey_id;
    i2v: nil; v2i: nil; i2r: nil; r2i: nil;
    usr_data: nil
);

implementation
uses openssl3.crypto.o_str,  OpenSSL3.Err,
     openssl3.crypto.x509.x_pubkey, openssl3.crypto.evp.digest,
     openssl3.crypto.asn1.a_octet, openssl3.crypto.x509v3;

function i2s_ASN1_OCTET_STRING(const method : PX509V3_EXT_METHOD;{const} oct : Pointer):PUTF8Char;
begin
    Result := OPENSSL_buf2hexstr(PASN1_OCTET_STRING(oct).data, PASN1_OCTET_STRING(oct).length);
end;


function s2i_ASN1_OCTET_STRING(method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):PASN1_OCTET_STRING;
var
  oct : PASN1_OCTET_STRING;

  length : long;
begin
    oct := ASN1_OCTET_STRING_new();
    if oct = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    oct.data := OPENSSL_hexstr2buf(str, @length);
    if oct.data = nil then
    begin
        ASN1_OCTET_STRING_free(oct);
        Exit(nil);
    end;
    oct.length := length;
    Exit(oct);
end;


function ossl_x509_pubkey_hash( pubkey : PX509_PUBKEY):PASN1_OCTET_STRING;
var
    oct      : PASN1_OCTET_STRING;
    pklen    : integer;
    pkey_dig : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
    diglen   : uint32;
    libctx   : POSSL_LIB_CTX;
    md       : PEVP_MD;
    propq    : PUTF8Char;
    pk       : PByte;
begin
    if pubkey = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_PUBLIC_KEY);
        Exit(nil);
    end;
    if 0>= ossl_x509_PUBKEY_get0_libctx(@libctx, @propq, pubkey) then
        Exit(nil);
    md := EVP_MD_fetch(libctx, SN_sha1, propq);
    if md =  nil then
        Exit(nil);
    oct := ASN1_OCTET_STRING_new();
    if oct =  nil then
    begin
        EVP_MD_free(md);
        Exit(nil);
    end;
    X509_PUBKEY_get0_param(nil, @pk, @pklen, nil, pubkey);
    if (EVP_Digest(pk, pklen, @pkey_dig, @diglen, md, nil) > 0)  and
       (ASN1_OCTET_STRING_set(oct, @pkey_dig, diglen) > 0 ) then
    begin
        EVP_MD_free(md);
        Exit(oct);
    end;
    EVP_MD_free(md);
    ASN1_OCTET_STRING_free(oct);
    Result := nil;
end;


function s2i_skey_id(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char): Pointer{PASN1_OCTET_STRING};
begin
    if strcmp(str, 'none') = 0 then
       Exit(ASN1_OCTET_STRING_new()); { dummy }
    if strcmp(str, 'hash' )<> 0 then
        Exit(s2i_ASN1_OCTET_STRING(method, ctx { not used } , str));
    if (ctx <> nil)  and ( (ctx.flags and X509V3_CTX_TEST) <> 0)  then
        Exit(ASN1_OCTET_STRING_new());
    if (ctx = nil)
         or ( (ctx.subject_cert = nil)  and  (ctx.subject_req = nil) ) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_SUBJECT_DETAILS);
        Exit(nil);
    end;
    if ctx.subject_cert <> nil then
       Result := ossl_x509_pubkey_hash(ctx.subject_cert.cert_info.key)
    else
       Result := ossl_x509_pubkey_hash(ctx.subject_req.req_info.pubkey);
end;

end.
