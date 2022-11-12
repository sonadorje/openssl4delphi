unit OpenSSL3.crypto.x509.v3_int;

interface
uses OpenSSL.Api;

function s2i_asn1_int(meth : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const value : PUTF8Char):Pointer;

var
  ossl_v3_crl_num, ossl_v3_delta_crl, ossl_v3_inhibit_anyp: TX509V3_EXT_METHOD;

implementation
uses openssl3.crypto.asn1.tasn_typ, OpenSSL3.crypto.x509.v3_utl;


function s2i_asn1_int(meth : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const value : PUTF8Char):Pointer;
begin
    Result := s2i_ASN1_INTEGER(meth, value);
end;

initialization
  ossl_v3_crl_num := get_V3_EXT_METHOD(
    NID_crl_number, 0, ASN1_INTEGER_it,
    nil, nil, nil, nil,
    PX509V3_EXT_I2S(@i2s_ASN1_INTEGER)^,
    nil,
    nil, nil, nil, nil, nil
);
 ossl_v3_delta_crl := get_V3_EXT_METHOD(
    NID_delta_crl, 0, ASN1_INTEGER_it,
    nil, nil, nil, nil,
    PX509V3_EXT_I2S(@i2s_ASN1_INTEGER)^,
    nil,
    nil, nil, nil, nil, nil
);
  ossl_v3_inhibit_anyp := get_V3_EXT_METHOD(
    NID_inhibit_any_policy, 0, ASN1_INTEGER_it,
    nil, nil, nil, nil,
    PX509V3_EXT_I2S(@i2s_ASN1_INTEGER)^,
    PX509V3_EXT_S2I(@s2i_asn1_int)^,
    nil, nil, nil, nil, nil
);

end.
