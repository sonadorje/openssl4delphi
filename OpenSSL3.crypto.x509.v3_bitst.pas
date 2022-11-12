unit OpenSSL3.crypto.x509.v3_bitst;

interface
uses OpenSSL.Api, SysUtils,
     openssl3.crypto.asn1.tasn_typ;

var
   ns_cert_type_table: array[0..8] of TBIT_STRING_BITNAME = (
    (bitnum: 0; lname: 'SSL Client'; sname: 'client'),
    (bitnum: 1; lname: 'SSL Server'; sname: 'server'),
    (bitnum: 2; lname: 'S/MIME'; sname: 'email'),
    (bitnum: 3; lname: 'Object Signing'; sname: 'objsign'),
    (bitnum: 4; lname: 'Unused'; sname: 'reserved'),
    (bitnum: 5; lname: 'SSL CA'; sname: 'sslCA'),
    (bitnum: 6; lname: 'S/MIME CA'; sname: 'emailCA'),
    (bitnum: 7; lname: 'Object Signing CA'; sname: 'objCA'),
    (bitnum: -1; lname: nil; sname: nil)
);

  key_usage_type_table: array[0..9] of TBIT_STRING_BITNAME = (
    (bitnum: 0; lname: 'Digital Signature'; sname: 'digitalSignature'),
    (bitnum: 1; lname: 'Non Repudiation'; sname: 'nonRepudiation'),
    (bitnum: 2; lname: 'Key Encipherment'; sname: 'keyEncipherment'),
    (bitnum: 3; lname: 'Data Encipherment'; sname: 'dataEncipherment'),
    (bitnum: 4; lname: 'Key Agreement'; sname: 'keyAgreement'),
    (bitnum: 5; lname: 'Certificate Sign'; sname: 'keyCertSign'),
    (bitnum: 6; lname: 'CRL Sign'; sname: 'cRLSign'),
    (bitnum: 7; lname: 'Encipher Only'; sname: 'encipherOnly'),
    (bitnum: 8; lname: 'Decipher Only'; sname: 'decipherOnly'),
    (bitnum: -1; lname: nil; sname: nil)
);

function i2v_ASN1_BIT_STRING(const method : PX509V3_EXT_METHOD; bits :Pointer{PASN1_BIT_STRING};
                              ret :Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE;
function v2i_ASN1_BIT_STRING(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;
                              nval : Pstack_st_CONF_VALUE): Pointer{PASN1_BIT_STRING};

const
  ossl_v3_nscert: TX509V3_EXT_METHOD  =
    ( ext_nid: 71; ext_flags: 0; it: ASN1_BIT_STRING_it;
      ext_new: nil;ext_free:nil;d2i: nil;i2d: nil; i2s: nil;s2i: nil;
      i2v: i2v_ASN1_BIT_STRING;
      v2i: v2i_ASN1_BIT_STRING;
      i2r: nil; r2i: nil; usr_data: @ns_cert_type_table);

  ossl_v3_key_usage: TX509V3_EXT_METHOD  =
    ( ext_nid: 83; ext_flags: 0; it: ASN1_BIT_STRING_it;
      ext_new: nil;ext_free:nil;d2i: nil;i2d: nil; i2s: nil;s2i: nil;
      i2v: i2v_ASN1_BIT_STRING;
      v2i: v2i_ASN1_BIT_STRING;
      i2r: nil; r2i: nil; usr_data: @key_usage_type_table);


implementation
uses openssl3.crypto.asn1.a_bitstr, OpenSSL3.Err, OpenSSL3.crypto.x509.v3_utl,
     OpenSSL3.openssl.conf;

function i2v_ASN1_BIT_STRING(const method : PX509V3_EXT_METHOD; bits : Pointer{PASN1_BIT_STRING};
                              ret :Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
  bnam : PBIT_STRING_BITNAME;
begin
    bnam := method.usr_data;
    while bnam.lname <> nil do
    begin
        if ASN1_BIT_STRING_get_bit(bits, bnam.bitnum) > 0 then
           X509V3_add_value(bnam.lname, nil, @ret);
        Inc(bnam);
    end;
    Result := ret;
end;


function v2i_ASN1_BIT_STRING(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;
                              nval : Pstack_st_CONF_VALUE):Pointer{PASN1_BIT_STRING};
var
  val : PCONF_VALUE;
  bs  : PASN1_BIT_STRING;
  i   : integer;
  bnam : PBIT_STRING_BITNAME;
begin
    bs := ASN1_BIT_STRING_new();
    if bs = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        val := sk_CONF_VALUE_value(nval, i);
        bnam := method.usr_data;
        while bnam.lname <> nil do
        begin
            if (strcmp(bnam.sname, val.name)= 0)
                 or ( strcmp(bnam.lname, val.name) = 0) then
            begin
                if 0>= ASN1_BIT_STRING_set_bit(bs, bnam.bitnum, 1) then
                begin
                    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                    ASN1_BIT_STRING_free(bs);
                    Exit(nil);
                end;
                break;
            end;
            Inc(bnam);
        end;
        if nil = bnam.lname then
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT,
                           Format('%s', [val.name]));
            ASN1_BIT_STRING_free(bs);
            Exit(nil);
        end;
    end;
    Result := bs;
end;


end.
