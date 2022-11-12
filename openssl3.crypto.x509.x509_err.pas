unit openssl3.crypto.x509.x509_err;

interface
uses OpenSSL.Api;

function ossl_err_load_X509_strings:integer;

var
  X509_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;




function ossl_err_load_X509_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(X509_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@X509_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
   X509_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_AKID_MISMATCH), 'akid mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_BAD_SELECTOR), 'bad selector'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_BAD_X509_FILETYPE), 'bad x509 filetype'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_BASE64_DECODE_ERROR),
    'base64 decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_CANT_CHECK_DH_KEY), 'cant check dh key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_CERTIFICATE_VERIFICATION_FAILED),
    'certificate verification failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_CERT_ALREADY_IN_HASH_TABLE),
    'cert already in hash table'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_CRL_ALREADY_DELTA), 'crl already delta'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_CRL_VERIFY_FAILURE),
    'crl verify failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_ERROR_GETTING_MD_BY_NID),
    'error getting md by nid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_ERROR_USING_SIGINF_SET),
    'error using siginf set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_IDP_MISMATCH), 'idp mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_ATTRIBUTES),
    'invalid attributes'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_DIRECTORY), 'invalid directory'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_DISTPOINT), 'invalid distpoint'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_FIELD_NAME),
    'invalid field name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_TRUST), 'invalid trust'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_ISSUER_MISMATCH), 'issuer mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_KEY_TYPE_MISMATCH), 'key type mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_KEY_VALUES_MISMATCH),
    'key values mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_LOADING_CERT_DIR), 'loading cert dir'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_LOADING_DEFAULTS), 'loading defaults'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_METHOD_NOT_SUPPORTED),
    'method not supported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NAME_TOO_LONG), 'name too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NEWER_CRL_NOT_NEWER),
    'newer crl not newer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERTIFICATE_FOUND),
    'no certificate found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERTIFICATE_OR_CRL_FOUND),
    'no certificate or crl found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY),
    'no cert set for us to verify'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CRL_FOUND), 'no crl found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CRL_NUMBER), 'no crl number'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_PUBLIC_KEY_DECODE_ERROR),
    'public key decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_PUBLIC_KEY_ENCODE_ERROR),
    'public key encode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_SHOULD_RETRY), 'should retry'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN),
    'unable to find parameters in chain'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY),
    'unable to get certs public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_KEY_TYPE), 'unknown key type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_NID), 'unknown nid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_PURPOSE_ID),
    'unknown purpose id'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_SIGID_ALGS),
    'unknown sigid algs'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_TRUST_ID), 'unknown trust id'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_UNSUPPORTED_ALGORITHM),
    'unsupported algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_WRONG_LOOKUP_TYPE), 'wrong lookup type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, X509_R_WRONG_TYPE), 'wrong type'),
    get_ERR_STRING_DATA(0, nil)
];
end.
