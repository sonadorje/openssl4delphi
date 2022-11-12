unit OpenSSL3.crypto.x509.v3_akid;

interface
uses OpenSSL.Api, SysUtils;

function i2v_AUTHORITY_KEYID(const method : PX509V3_EXT_METHOD; akeyid : PAUTHORITY_KEYID; extlist : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_AUTHORITY_KEYID(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; values : Pstack_st_CONF_VALUE):PAUTHORITY_KEYID;

var
  ossl_v3_akey_id :TX509V3_EXT_METHOD;

implementation
uses openssl3.crypto.x509.v3_akeya, OpenSSL3.Err, OpenSSL3.crypto.x509.v3_skid,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.x509_cmp,  OpenSSL3.crypto.x509.x509_ext,
     openssl3.crypto.x509v3,  openssl3.providers.fips.fipsprov,
     OpenSSL3.crypto.x509.v3_lib, openssl3.crypto.asn1.asn1_lib,
     OpenSSL3.crypto.x509.x_name, openssl3.crypto.asn1.a_int,
     openssl3.crypto.x509.v3_genn,
     openssl3.crypto.asn1.tasn_typ,  openssl3.crypto.x509.x_pubkey,
     OpenSSL3.crypto.x509.v3_san, OpenSSL3.openssl.conf;





function i2v_AUTHORITY_KEYID(const method : PX509V3_EXT_METHOD; akeyid : PAUTHORITY_KEYID; extlist : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
    tmp,tmpextlist         : PUTF8Char;
    origextlist : Pstack_st_CONF_VALUE;
    label _err;
begin
    tmp := nil;
    origextlist := extlist;
    if akeyid.keyid <> nil then
    begin
        tmp := i2s_ASN1_OCTET_STRING(nil, akeyid.keyid);
        if tmp = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        if 0>= X509V3_add_value(
                get_result( (akeyid.issuer<>nil)  or  (akeyid.serial<>nil), PUTF8Char(' keyid')  , nil),
                              tmp, @extlist) then
        begin
            OPENSSL_free(tmp);
            ERR_raise(ERR_LIB_X509V3, ERR_R_X509_LIB);
            goto _err ;
        end;
        OPENSSL_free(tmp);
    end;
    if akeyid.issuer <> nil then
    begin
        tmpextlist := i2v_GENERAL_NAMES(nil, akeyid.issuer, extlist);
        if tmpextlist = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_X509_LIB);
            goto _err ;
        end;
        extlist := tmpextlist;
    end;
    if akeyid.serial <> nil then
    begin
        tmp := i2s_ASN1_OCTET_STRING(nil, akeyid.serial);
        if tmp = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if 0>= X509V3_add_value(' serial' , tmp, @extlist) then
        begin
            OPENSSL_free(tmp);
            goto _err ;
        end;
        OPENSSL_free(tmp);
    end;
    Exit(extlist);
 _err:
    if origextlist = nil then
       sk_CONF_VALUE_pop_free(extlist, X509V3_conf_free);
    Result := nil;
end;


function v2i_AUTHORITY_KEYID(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; values : Pstack_st_CONF_VALUE):PAUTHORITY_KEYID;
var
    keyid,issuer       : byte;
    i,
    n           : integer;
    cnf         : PCONF_VALUE;
    ikeyid      : PASN1_OCTET_STRING;
    isname      : PX509_NAME;
    gens        : PGENERAL_NAMES;
    gen         : PGENERAL_NAME;
    serial      : PASN1_INTEGER;
    ext         : PX509_EXTENSION;
    issuer_cert : PX509;
    same_issuer,
    ss          : integer;
    akeyid      : PAUTHORITY_KEYID;
    pubkey      : PX509_PUBKEY;
    label _err;
begin
    keyid := 0; issuer := 0;
    n := sk_CONF_VALUE_num(values);
    ikeyid := nil;
    isname := nil;
    gens := nil;
    gen := nil;
    serial := nil;
    akeyid := AUTHORITY_KEYID_new();
    if akeyid = nil then
       goto _err ;
    if (n = 1)  and  (strcmp(sk_CONF_VALUE_value(values, 0).name, ' none' ) = 0) then
    begin
        Exit(akeyid);
    end;
    for i := 0 to n-1 do
    begin
        cnf := sk_CONF_VALUE_value(values, i);
        if (cnf.value <> nil)  and  (strcmp(cnf.value, ' always') <> 0)   then
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_UNKNOWN_OPTION,
                          Format(' name=%s option=%s' , [cnf.name, cnf.value]));
            goto _err ;
        end;
        if (strcmp(cnf.name, ' keyid') = 0)  and  (keyid = 0)   then
        begin
            keyid := 1;
            if cnf.value <> nil then keyid := 2;
        end
        else
        if (strcmp(cnf.name, ' issuer' ) = 0)  and  (issuer = 0)   then
        begin
            issuer := 1;
            if cnf.value <> nil then issuer := 2;
        end
        else
        if (strcmp(cnf.name, ' none' ) = 0)
                    or  (strcmp(cnf.name, ' keyid' ) = 0 )
                    or  (strcmp(cnf.name, ' issuer' ) = 0)   then
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_BAD_VALUE,
                          Format(' name=%s' , [cnf.name]));
            goto _err ;
        end
        else
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_UNKNOWN_VALUE,
                           Format(' name=%s' , [cnf.name]));
            goto _err ;
        end;
    end;
    if (ctx <> nil)  and ( (ctx.flags and X509V3_CTX_TEST) <> 0)  then
        Exit(akeyid);
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER);
        goto _err ;
    end;
    issuer_cert := ctx.issuer_cert;
    if issuer_cert = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_ISSUER_CERTIFICATE);
        goto _err ;
    end;
    same_issuer := Int( ctx.subject_cert = ctx.issuer_cert);
    ERR_set_mark();
    if ctx.issuer_pkey <> nil then
       ss := X509_check_private_key(ctx.subject_cert, ctx.issuer_pkey)
    else
        ss := same_issuer;
    ERR_pop_to_mark();
    { unless forced with ' always' , AKID is suppressed for self-signed certs }
    if (keyid = 2)  or ( (keyid = 1)  and  (0>= ss)  ) then
    begin
        {
         * prefer any pre-existing subject key identifier of the issuer cert
         * except issuer cert is same as subject cert and is not self-signed
         }
        i := X509_get_ext_by_NID(issuer_cert, NID_subject_key_identifier, -1);
        ext := X509_get_ext(issuer_cert, i);
        if (i >= 0)  and  (ext  <> nil)
             and  (not ((same_issuer>0)  and  (0>= ss)) ) then
        begin
            ikeyid := X509V3_EXT_d2i(ext);
            if ASN1_STRING_length(PASN1_STRING(ikeyid)) = 0  then { indicating ' none'  }
            begin
                ASN1_OCTET_STRING_free(ikeyid);
                ikeyid := nil;
            end;
        end;
        if (ikeyid = nil)  and  (same_issuer>0)  and  (ctx.issuer_pkey <> nil) then
        begin
            { generate fallback AKID, emulating s2i_skey_id(..., ' hash' ) }
            pubkey := nil;
            if X509_PUBKEY_set(@pubkey, ctx.issuer_pkey) > 0 then
                ikeyid := ossl_x509_pubkey_hash(pubkey);
            X509_PUBKEY_free(pubkey);
        end;
        if (keyid = 2)  and  (ikeyid = nil) then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_UNABLE_TO_GET_ISSUER_KEYID);
            goto _err ;
        end;
    end;
    if (issuer = 2)  or ( (issuer = 1)  and (0>= ss)  and  (ikeyid = nil) )  then
    begin
        isname := X509_NAME_dup(X509_get_issuer_name(issuer_cert));
        serial := ASN1_INTEGER_dup(X509_get0_serialNumber(issuer_cert));
        if (isname = nil)  or  (serial = nil) then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS);
            goto _err ;
        end;
    end;
    if isname <> nil then
    begin
        gens := sk_GENERAL_NAME_new_null();
        gen := GENERAL_NAME_new();
        if (gens = nil)  or  (gen = nil)
             or  (0>= sk_GENERAL_NAME_push(gens, gen)) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        gen.&type := GEN_DIRNAME;
        gen.d.dirn := isname;
    end;
    akeyid.issuer := gens;
    gen := nil;
    gens := nil;
    akeyid.serial := serial;
    akeyid.keyid := ikeyid;
    Exit(akeyid);
 _err:
    sk_GENERAL_NAME_free(gens);
    GENERAL_NAME_free(gen);
    X509_NAME_free(isname);
    ASN1_INTEGER_free(serial);
    ASN1_OCTET_STRING_free(ikeyid);
    AUTHORITY_KEYID_free(akeyid);
    Result := nil;
end;

initialization
  ossl_v3_akey_id := get_V3_EXT_METHOD (
    NID_authority_key_identifier,
    X509V3_EXT_MULTILINE, AUTHORITY_KEYID_it,
    nil, nil, nil, nil,
    nil, nil,
    PX509V3_EXT_I2V(@i2v_AUTHORITY_KEYID)^,
    PX509V3_EXT_V2I(@v2i_AUTHORITY_KEYID)^,
    nil, nil,
    nil
);
end.
