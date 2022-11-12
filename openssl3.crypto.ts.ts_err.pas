unit openssl3.crypto.ts.ts_err;

interface
uses OpenSSL.Api;

function ossl_err_load_TS_strings:integer;

var
  TS_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_TS_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(TS_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@TS_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  TS_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_BAD_PKCS7_TYPE), 'bad pkcs7 type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_BAD_TYPE), 'bad type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_CANNOT_LOAD_CERT), 'cannot load certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_CANNOT_LOAD_KEY), 'cannot load private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_CERTIFICATE_VERIFY_ERROR),
    'certificate verify error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_COULD_NOT_SET_ENGINE),
    'could not set engine'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_COULD_NOT_SET_TIME), 'could not set time'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_DETACHED_CONTENT), 'detached content'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_ESS_ADD_SIGNING_CERT_ERROR),
    'ess add signing cert error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR),
    'ess add signing cert v2 error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_ESS_SIGNING_CERTIFICATE_ERROR),
    'ess signing certificate error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_INVALID_NULL_POINTER),
    'invalid null pointer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE),
    'invalid signer certificate purpose'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_MESSAGE_IMPRINT_MISMATCH),
    'message imprint mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_NONCE_MISMATCH), 'nonce mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_NONCE_NOT_RETURNED), 'nonce not returned'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_NO_CONTENT), 'no content'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_NO_TIME_STAMP_TOKEN), 'no time stamp token'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_PKCS7_ADD_SIGNATURE_ERROR),
    'pkcs7 add signature error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR),
    'pkcs7 add signed attr error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_PKCS7_TO_TS_TST_INFO_FAILED),
    'pkcs7 to ts tst info failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_POLICY_MISMATCH), 'policy mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
    'private key does not match certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_RESPONSE_SETUP_ERROR),
    'response setup error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_SIGNATURE_FAILURE), 'signature failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_THERE_MUST_BE_ONE_SIGNER),
    'there must be one signer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TIME_SYSCALL_ERROR), 'time syscall error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TOKEN_NOT_PRESENT), 'token not present'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TOKEN_PRESENT), 'token present'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TSA_NAME_MISMATCH), 'tsa name mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TSA_UNTRUSTED), 'tsa untrusted'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TST_INFO_SETUP_ERROR),
    'tst info setup error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_TS_DATASIGN), 'ts datasign'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_UNACCEPTABLE_POLICY), 'unacceptable policy'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_UNSUPPORTED_MD_ALGORITHM),
    'unsupported md algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_UNSUPPORTED_VERSION), 'unsupported version'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_VAR_BAD_VALUE), 'var bad value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_VAR_LOOKUP_FAILURE),
    'cannot find config variable'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, TS_R_WRONG_CONTENT_TYPE), 'wrong content type'),
    get_ERR_STRING_DATA(0, nil)
];


end.
