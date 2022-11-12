unit openssl3.crypto.dsa.dsa_err;

interface
uses OpenSSL.Api;

function ossl_err_load_DSA_strings:integer;

var
  DSA_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;




function ossl_err_load_DSA_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(DSA_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@DSA_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  DSA_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_BAD_FFC_PARAMETERS), 'bad ffc parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_BAD_Q_VALUE), 'bad q value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_BN_DECODE_ERROR), 'bn decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_BN_ERROR), 'bn error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_DECODE_ERROR), 'decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_INVALID_DIGEST_TYPE),
    'invalid digest type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_INVALID_PARAMETERS), 'invalid parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_MISSING_PARAMETERS), 'missing parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_MISSING_PRIVATE_KEY),
    'missing private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_MODULUS_TOO_LARGE), 'modulus too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_NO_PARAMETERS_SET), 'no parameters set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_PARAMETER_ENCODING_ERROR),
    'parameter encoding error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_P_NOT_PRIME), 'p not prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_Q_NOT_PRIME), 'q not prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, DSA_R_SEED_LEN_SMALL),
    'seed_len is less than the length of q'),
    get_ERR_STRING_DATA(0, nil)
];
end.
