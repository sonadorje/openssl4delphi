unit openssl3.crypto.store.store_err;

interface
uses OpenSSL.Api;

function ossl_err_load_OSSL_STORE_strings:integer;

var
  OSSL_STORE_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_OSSL_STORE_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(OSSL_STORE_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@OSSL_STORE_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  OSSL_STORE_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_AMBIGUOUS_CONTENT_TYPE),
    'ambiguous content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_BAD_PASSWORD_READ),
    'bad password read'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC),
    'error verifying pkcs12 mac'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST),
    'fingerprint size does not match digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_INVALID_SCHEME),
    'invalid scheme'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_IS_NOT_A), 'is not a'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_LOADER_INCOMPLETE),
    'loader incomplete'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_LOADING_STARTED),
    'loading started'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NOT_A_CERTIFICATE),
    'not a certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NOT_A_CRL), 'not a crl'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NOT_A_NAME), 'not a name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NOT_A_PRIVATE_KEY),
    'not a private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NOT_A_PUBLIC_KEY),
    'not a public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NOT_PARAMETERS),
    'not parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_NO_LOADERS_FOUND),
    'no loaders found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR),
    'passphrase callback error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_PATH_MUST_BE_ABSOLUTE),
    'path must be absolute'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES),
    'search only supported for directories'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED),
    'ui process interrupted or cancelled'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_UNREGISTERED_SCHEME),
    'unregistered scheme'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_UNSUPPORTED_CONTENT_TYPE),
    'unsupported content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_UNSUPPORTED_OPERATION),
    'unsupported operation'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_UNSUPPORTED_SEARCH_TYPE),
    'unsupported search type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, OSSL_STORE_R_URI_AUTHORITY_UNSUPPORTED),
    'uri authority unsupported'),
    get_ERR_STRING_DATA(0, nil)
];


end.
