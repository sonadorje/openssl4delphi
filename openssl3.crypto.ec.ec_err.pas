unit openssl3.crypto.ec.ec_err;

interface
uses OpenSSL.Api;

function ossl_err_load_EC_strings:integer;

var
  EC_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_EC_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(EC_str_reasons[0].error)= nil  then
        ERR_load_strings_const(@EC_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  EC_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_ASN1_ERROR), 'asn1 error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_BAD_SIGNATURE), 'bad signature'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_BIGNUM_OUT_OF_RANGE), 'bignum out of range'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_BUFFER_TOO_SMALL), 'buffer too small'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_CANNOT_INVERT), 'cannot invert'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_COORDINATES_OUT_OF_RANGE),
    'coordinates out of range'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_CURVE_DOES_NOT_SUPPORT_ECDH),
    'curve does not support ecdh'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA),
    'curve does not support ecdsa'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING),
    'curve does not support signing'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_DECODE_ERROR), 'decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_DISCRIMINANT_IS_ZERO),
    'discriminant is zero'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_EC_GROUP_NEW_BY_NAME_FAILURE),
    'ec group new by name failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_FAILED_MAKING_PUBLIC_KEY),
    'failed making public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_FIELD_TOO_LARGE), 'field too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_GF2M_NOT_SUPPORTED), 'gf2m not supported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_GROUP2PKPARAMETERS_FAILURE),
    'group2pkparameters failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_I2D_ECPKPARAMETERS_FAILURE),
    'i2d ecpkparameters failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INCOMPATIBLE_OBJECTS),
    'incompatible objects'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_A), 'invalid a'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_ARGUMENT), 'invalid argument'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_B), 'invalid b'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_COFACTOR), 'invalid cofactor'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_COMPRESSED_POINT),
    'invalid compressed point'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_COMPRESSION_BIT),
    'invalid compression bit'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_CURVE), 'invalid curve'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_DIGEST), 'invalid digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_DIGEST_TYPE), 'invalid digest type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_ENCODING), 'invalid encoding'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_FIELD), 'invalid field'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_FORM), 'invalid form'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_GENERATOR), 'invalid generator'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_GROUP_ORDER), 'invalid group order'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_KEY), 'invalid key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_LENGTH), 'invalid length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_NAMED_GROUP_CONVERSION),
    'invalid named group conversion'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_OUTPUT_LENGTH),
    'invalid output length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_P), 'invalid p'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_PEER_KEY), 'invalid peer key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_PENTANOMIAL_BASIS),
    'invalid pentanomial basis'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_PRIVATE_KEY), 'invalid private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_SEED), 'invalid seed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_TRINOMIAL_BASIS),
    'invalid trinomial basis'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_KDF_PARAMETER_ERROR), 'kdf parameter error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_KEYS_NOT_SET), 'keys not set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_LADDER_POST_FAILURE), 'ladder post failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_LADDER_PRE_FAILURE), 'ladder pre failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_LADDER_STEP_FAILURE), 'ladder step failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_MISSING_OID), 'missing OID'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_MISSING_PARAMETERS), 'missing parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_MISSING_PRIVATE_KEY), 'missing private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_NEED_NEW_SETUP_VALUES),
    'need new setup values'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_NOT_A_NIST_PRIME), 'not a NIST prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_NOT_IMPLEMENTED), 'not implemented'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_NOT_INITIALIZED), 'not initialized'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_NO_PARAMETERS_SET), 'no parameters set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_NO_PRIVATE_VALUE), 'no private value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_OPERATION_NOT_SUPPORTED),
    'operation not supported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_PASSED_NULL_PARAMETER),
    'passed null parameter'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_PEER_KEY_ERROR), 'peer key error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_POINT_ARITHMETIC_FAILURE),
    'point arithmetic failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_POINT_AT_INFINITY), 'point at infinity'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_POINT_COORDINATES_BLIND_FAILURE),
    'point coordinates blind failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_POINT_IS_NOT_ON_CURVE),
    'point is not on curve'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_RANDOM_NUMBER_GENERATION_FAILED),
    'random number generation failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_SHARED_INFO_ERROR), 'shared info error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_SLOT_FULL), 'slot full'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_UNDEFINED_GENERATOR), 'undefined generator'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_UNDEFINED_ORDER), 'undefined order'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_UNKNOWN_COFACTOR), 'unknown cofactor'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_UNKNOWN_GROUP), 'unknown group'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_UNKNOWN_ORDER), 'unknown order'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_UNSUPPORTED_FIELD), 'unsupported field'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_WRONG_CURVE_PARAMETERS),
    'wrong curve parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, EC_R_WRONG_ORDER), 'wrong order'),
    get_ERR_STRING_DATA(0, nil)
];


end.
