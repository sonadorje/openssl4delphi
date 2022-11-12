unit openssl3.crypto.rand.randerr;

interface
uses OpenSSL.Api;

function ossl_err_load_RAND_strings:integer;

var
  RAND_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_RAND_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(RAND_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@RAND_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  RAND_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ADDITIONAL_INPUT_TOO_LONG),
    'additional input too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ALREADY_INSTANTIATED),
    'already instantiated'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ARGUMENT_OUT_OF_RANGE),
    'argument out of range'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_CANNOT_OPEN_FILE), 'Cannot open file'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_DRBG_ALREADY_INITIALIZED),
    'drbg already initialized'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_DRBG_NOT_INITIALISED),
    'drbg not initialised'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ENTROPY_INPUT_TOO_LONG),
    'entropy input too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ENTROPY_OUT_OF_RANGE),
    'entropy out of range'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ERROR_ENTROPY_POOL_WAS_IGNORED),
    'error entropy pool was ignored'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ERROR_INITIALISING_DRBG),
    'error initialising drbg'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ERROR_INSTANTIATING_DRBG),
    'error instantiating drbg'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT),
    'error retrieving additional input'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ERROR_RETRIEVING_ENTROPY),
    'error retrieving entropy'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_ERROR_RETRIEVING_NONCE),
    'error retrieving nonce'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_FAILED_TO_CREATE_LOCK),
    'failed to create lock'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_FUNC_NOT_IMPLEMENTED),
    'Function not implemented'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_FWRITE_ERROR), 'Error writing file'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_GENERATE_ERROR), 'generate error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_INSUFFICIENT_DRBG_STRENGTH),
    'insufficient drbg strength'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_INTERNAL_ERROR), 'internal error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_IN_ERROR_STATE), 'in error state'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_NOT_A_REGULAR_FILE),
    'Not a regular file'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_NOT_INSTANTIATED), 'not instantiated'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED),
    'no drbg implementation selected'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_PARENT_LOCKING_NOT_ENABLED),
    'parent locking not enabled'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_PARENT_STRENGTH_TOO_WEAK),
    'parent strength too weak'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_PERSONALISATION_STRING_TOO_LONG),
    'personalisation string too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_PREDICTION_RESISTANCE_NOT_SUPPORTED),
    'prediction resistance not supported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_PRNG_NOT_SEEDED), 'PRNG not seeded'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_RANDOM_POOL_OVERFLOW),
    'random pool overflow'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_RANDOM_POOL_UNDERFLOW),
    'random pool underflow'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG),
    'request too large for drbg'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_RESEED_ERROR), 'reseed error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_SELFTEST_FAILURE), 'selftest failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_TOO_LITTLE_NONCE_REQUESTED),
    'too little nonce requested'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_TOO_MUCH_NONCE_REQUESTED),
    'too much nonce requested'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNABLE_TO_CREATE_DRBG),
    'unable to create drbg'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNABLE_TO_FETCH_DRBG),
    'unable to fetch drbg'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNABLE_TO_GET_PARENT_RESEED_PROP_COUNTER),
    'unable to get parent reseed prop counter'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNABLE_TO_GET_PARENT_STRENGTH),
    'unable to get parent strength'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNABLE_TO_LOCK_PARENT),
    'unable to lock parent'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNSUPPORTED_DRBG_FLAGS),
    'unsupported drbg flags'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, RAND_R_UNSUPPORTED_DRBG_TYPE),
    'unsupported drbg type'),
    get_ERR_STRING_DATA(0, nil)
];


end.
