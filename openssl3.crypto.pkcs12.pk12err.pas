unit openssl3.crypto.pkcs12.pk12err;

interface
uses OpenSSL.Api;

function ossl_err_load_PKCS12_strings:integer;

var
  PKCS12_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_PKCS12_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(PKCS12_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@PKCS12_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  PKCS12_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_CANT_PACK_STRUCTURE),
    'cant pack structure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_CONTENT_TYPE_NOT_DATA),
    'content type not data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_DECODE_ERROR), 'decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_ENCODE_ERROR), 'encode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_ENCRYPT_ERROR), 'encrypt error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE),
    'error setting encrypted data type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_INVALID_NULL_ARGUMENT),
    'invalid null argument'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_INVALID_NULL_PKCS12_POINTER),
    'invalid null pkcs12 pointer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_INVALID_TYPE), 'invalid type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_IV_GEN_ERROR), 'iv gen error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_KEY_GEN_ERROR), 'key gen error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_MAC_ABSENT), 'mac absent'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_MAC_GENERATION_ERROR),
    'mac generation error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_MAC_SETUP_ERROR), 'mac setup error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_MAC_STRING_SET_ERROR),
    'mac string set error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_MAC_VERIFY_FAILURE),
    'mac verify failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_PARSE_ERROR), 'parse error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_PKCS12_CIPHERFINAL_ERROR),
    'pkcs12 cipherfinal error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_UNKNOWN_DIGEST_ALGORITHM),
    'unknown digest algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_UNSUPPORTED_PKCS12_MODE),
    'unsupported pkcs12 mode'),
    get_ERR_STRING_DATA(0, nil)
];

end.
