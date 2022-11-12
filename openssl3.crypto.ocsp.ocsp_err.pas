unit openssl3.crypto.ocsp.ocsp_err;

interface
uses OpenSSL.Api;

function ossl_err_load_OCSP_strings:integer;

var
  OCSP_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_OCSP_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(OCSP_str_reasons[0].error )= nil then
        ERR_load_strings_const(@OCSP_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  OCSP_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_CERTIFICATE_VERIFY_ERROR),
    'certificate verify error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_DIGEST_ERR), 'digest err'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_DIGEST_NAME_ERR), 'digest name err'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_DIGEST_SIZE_ERR), 'digest size err'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_ERROR_IN_NEXTUPDATE_FIELD),
    'error in nextupdate field'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_ERROR_IN_THISUPDATE_FIELD),
    'error in thisupdate field'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_MISSING_OCSPSIGNING_USAGE),
    'missing ocspsigning usage'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE),
    'nextupdate before thisupdate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_NOT_BASIC_RESPONSE),
    'not basic response'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_NO_CERTIFICATES_IN_CHAIN),
    'no certificates in chain'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_NO_RESPONSE_DATA), 'no response data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_NO_REVOKED_TIME), 'no revoked time'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_NO_SIGNER_KEY), 'no signer key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
    'private key does not match certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_REQUEST_NOT_SIGNED),
    'request not signed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA),
    'response contains no revocation data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_ROOT_CA_NOT_TRUSTED),
    'root ca not trusted'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_SIGNATURE_FAILURE), 'signature failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND),
    'signer certificate not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_STATUS_EXPIRED), 'status expired'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_STATUS_NOT_YET_VALID),
    'status not yet valid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_STATUS_TOO_OLD), 'status too old'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_UNKNOWN_MESSAGE_DIGEST),
    'unknown message digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_UNKNOWN_NID), 'unknown nid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE),
    'unsupported requestorname type'),
    get_ERR_STRING_DATA(0, nil)
];


end.
