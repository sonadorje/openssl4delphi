unit openssl3.crypto.pem.pem_err;

interface
uses OpenSSL.Api;

function ossl_err_load_PEM_strings:integer;

var
  PEM_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_PEM_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(PEM_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@PEM_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  PEM_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_BASE64_DECODE), 'bad base64 decode'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_DECRYPT), 'bad decrypt'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_END_LINE), 'bad end line'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_IV_CHARS), 'bad iv chars'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_MAGIC_NUMBER), 'bad magic number'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_PASSWORD_READ), 'bad password read'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_VERSION_NUMBER), 'bad version number'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BIO_WRITE_FAILURE), 'bio write failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_CIPHER_IS_NULL), 'cipher is null'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_ERROR_CONVERTING_PRIVATE_KEY),
    'error converting private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_DSS_KEY_BLOB),
    'expecting dss key blob'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_PRIVATE_KEY_BLOB),
    'expecting private key blob'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_PUBLIC_KEY_BLOB),
    'expecting public key blob'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_RSA_KEY_BLOB),
    'expecting rsa key blob'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_HEADER_TOO_LONG), 'header too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_INCONSISTENT_HEADER),
    'inconsistent header'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_KEYBLOB_HEADER_PARSE_ERROR),
    'keyblob header parse error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_KEYBLOB_TOO_SHORT), 'keyblob too short'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_MISSING_DEK_IV), 'missing dek iv'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NOT_DEK_INFO), 'not dek info'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NOT_ENCRYPTED), 'not encrypted'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NOT_PROC_TYPE), 'not proc type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NO_START_LINE), 'no start line'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_PROBLEMS_GETTING_PASSWORD),
    'problems getting password'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_PVK_DATA_TOO_SHORT), 'pvk data too short'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_PVK_TOO_SHORT), 'pvk too short'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_READ_KEY), 'read key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_SHORT_HEADER), 'short header'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNEXPECTED_DEK_IV), 'unexpected dek iv'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_CIPHER), 'unsupported cipher'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_ENCRYPTION),
    'unsupported encryption'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_KEY_COMPONENTS),
    'unsupported key components'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE),
    'unsupported public key type'),
    get_ERR_STRING_DATA(0, nil)
];
end.
