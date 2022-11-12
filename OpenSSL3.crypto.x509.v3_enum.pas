unit OpenSSL3.crypto.x509.v3_enum;

interface
uses OpenSSL.Api;

function i2s_ASN1_ENUMERATED_TABLE(method : PX509V3_EXT_METHOD;const e : PASN1_ENUMERATED):PUTF8Char;

var
  ossl_v3_crl_reason :TX509V3_EXT_METHOD ;
  crl_reasons : array of TENUMERATED_NAMES ;

implementation
uses openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.a_int,
     openssl3.crypto.o_str, OpenSSL3.crypto.x509.v3_utl;




function i2s_ASN1_ENUMERATED_TABLE(method : PX509V3_EXT_METHOD;const e : PASN1_ENUMERATED):PUTF8Char;
var
  enam : PENUMERATED_NAMES;
  strval : long;
begin
    strval := ASN1_ENUMERATED_get(e);
    enam := method.usr_data;
    while enam.lname <> nil do
    begin
        if strval = enam.bitnum then
        begin
           OPENSSL_strdup(Result, enam.lname);
           Exit;
        end;

        Inc(enam);
    end;
    Result := i2s_ASN1_ENUMERATED(method, e);
end;

initialization
  crl_reasons := [
    get_ENUMERATED_NAMES(CRL_REASON_UNSPECIFIED, 'Unspecified', 'unspecified'),
    get_ENUMERATED_NAMES(CRL_REASON_KEY_COMPROMISE, 'Key Compromise', 'keyCompromise'),
    get_ENUMERATED_NAMES(CRL_REASON_CA_COMPROMISE, 'CA Compromise', 'CACompromise'),
    get_ENUMERATED_NAMES(CRL_REASON_AFFILIATION_CHANGED, 'Affiliation Changed','affiliationChanged'),
    get_ENUMERATED_NAMES(CRL_REASON_SUPERSEDED, 'Superseded', 'superseded'),
    get_ENUMERATED_NAMES(CRL_REASON_CESSATION_OF_OPERATION, 'Cessation Of Operation', 'cessationOfOperation'),
    get_ENUMERATED_NAMES(CRL_REASON_CERTIFICATE_HOLD, 'Certificate Hold', 'certificateHold'),
    get_ENUMERATED_NAMES(CRL_REASON_REMOVE_FROM_CRL, 'Remove From CRL', 'removeFromCRL'),
    get_ENUMERATED_NAMES(CRL_REASON_PRIVILEGE_WITHDRAWN, 'Privilege Withdrawn', 'privilegeWithdrawn'),
    get_ENUMERATED_NAMES(CRL_REASON_AA_COMPROMISE, 'AA Compromise', 'AACompromise'),
    get_ENUMERATED_NAMES(-1, nil, nil)];

  ossl_v3_crl_reason := get_V3_EXT_METHOD (
    NID_crl_reason, 0, ASN1_ENUMERATED_it,
    nil, nil, nil, nil,
    PX509V3_EXT_I2S(@i2s_ASN1_ENUMERATED_TABLE)^,
    nil,
    nil, nil, nil, nil,
    crl_reasons);
end.
