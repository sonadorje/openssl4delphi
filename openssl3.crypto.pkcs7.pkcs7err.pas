unit openssl3.crypto.pkcs7.pkcs7err;

interface
 uses OpenSSL.Api;

function ossl_err_load_PKCS7_strings:integer;

var
  PKCS7_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_PKCS7_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(PKCS7_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@PKCS7_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  PKCS7_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_CERTIFICATE_VERIFY_ERROR),
    'certificate verify error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER),
    'cipher has no object identifier'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_CIPHER_NOT_INITIALIZED),
    'cipher not initialized'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_CONTENT_AND_DATA_PRESENT),
    'content and data present'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_CTRL_ERROR), 'ctrl error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_DECRYPT_ERROR), 'decrypt error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_DIGEST_FAILURE), 'digest failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_ENCRYPTION_CTRL_FAILURE),
    'encryption ctrl failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE),
    'encryption not supported for this key type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_ERROR_ADDING_RECIPIENT),
    'error adding recipient'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_ERROR_SETTING_CIPHER),
    'error setting cipher'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_INVALID_NULL_POINTER),
    'invalid null pointer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_INVALID_SIGNED_DATA_TYPE),
    'invalid signed data type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_NO_CONTENT), 'no content'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_NO_DEFAULT_DIGEST),
    'no default digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND),
    'no matching digest type found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE),
    'no recipient matches certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_NO_SIGNATURES_ON_DATA),
    'no signatures on data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_NO_SIGNERS), 'no signers'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE),
    'operation not supported on this type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR),
    'pkcs7 add signature error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_PKCS7_ADD_SIGNER_ERROR),
    'pkcs7 add signer error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_PKCS7_DATASIGN), 'pkcs7 datasign'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
    'private key does not match certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_SIGNATURE_FAILURE),
    'signature failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND),
    'signer certificate not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_SIGNING_CTRL_FAILURE),
    'signing ctrl failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE),
    'signing not supported for this key type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_SMIME_TEXT_ERROR), 'smime text error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNABLE_TO_FIND_CERTIFICATE),
    'unable to find certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNABLE_TO_FIND_MEM_BIO),
    'unable to find mem bio'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST),
    'unable to find message digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNKNOWN_DIGEST_TYPE),
    'unknown digest type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNKNOWN_OPERATION),
    'unknown operation'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNSUPPORTED_CIPHER_TYPE),
    'unsupported cipher type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_UNSUPPORTED_CONTENT_TYPE),
    'unsupported content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_WRONG_CONTENT_TYPE),
    'wrong content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, PKCS7_R_WRONG_PKCS7_TYPE), 'wrong pkcs7 type'),
    get_ERR_STRING_DATA(0, nil)
];


end.
