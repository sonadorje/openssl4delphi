unit openssl3.crypto.cpt_err;

interface
uses OpenSSL.Api;

var
   CRYPTO_str_reasons: array of TERR_STRING_DATA;

function _ossl_err_load_CRYPTO_strings:integer;

implementation

uses OpenSSL3.Err;



function _ossl_err_load_CRYPTO_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(CRYPTO_str_reasons[0].error) = nil then
        ERR_load_strings_const(@CRYPTO_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
   CRYPTO_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_BAD_ALGORITHM_NAME),
    'bad algorithm name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_CONFLICTING_NAMES),
    'conflicting names'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_HEX_STRING_TOO_SHORT),
    'hex string too short'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_ILLEGAL_HEX_DIGIT),
    'illegal hex digit'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INSUFFICIENT_DATA_SPACE),
    'insufficient data space'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INSUFFICIENT_PARAM_SIZE),
    'insufficient param size'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INSUFFICIENT_SECURE_DATA_SPACE),
    'insufficient secure data space'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INTEGER_OVERFLOW),
    'integer overflow'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INVALID_NEGATIVE_VALUE),
    'invalid negative value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INVALID_NULL_ARGUMENT),
    'invalid null argument'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_INVALID_OSSL_PARAM_TYPE),
    'invalid ossl param type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_NO_PARAMS_TO_MERGE),
    'no params to merge'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL),
    'no space for terminating null'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_ODD_NUMBER_OF_DIGITS),
    'odd number of digits'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY),
    'param cannot be represented exactly'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PARAM_NOT_INTEGER_TYPE),
    'param not integer type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE),
    'param of incompatible type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED),
    'param Uint32eger negative value unsupported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT),
    'param unsupported floating point format'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION),
    'param value too large for destination'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PROVIDER_ALREADY_EXISTS),
    'provider already exists'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_PROVIDER_SECTION_ERROR),
    'provider section error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_RANDOM_SECTION_ERROR),
    'random section error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_SECURE_MALLOC_FAILURE),
    'secure malloc failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_STRING_TOO_LONG), 'string too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_TOO_MANY_BYTES), 'too many bytes'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_TOO_MANY_RECORDS),
    'too many records'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_TOO_SMALL_BUFFER),
    'too small buffer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_UNKNOWN_NAME_IN_RANDOM_SECTION),
    'unknown name in random section'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_ZERO_LENGTH_NUMBER),
    'zero length number'),
    get_ERR_STRING_DATA(0, nil)
];

end.
