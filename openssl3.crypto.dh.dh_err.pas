unit openssl3.crypto.dh.dh_err;

interface
uses OpenSSL.Api;


  function ossl_err_load_DH_strings:integer;
var
   DH_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_DH_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(DH_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@DH_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  DH_str_reasons:= [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_BAD_FFC_PARAMETERS), 'bad ffc parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_BAD_GENERATOR), 'bad generator'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_BN_DECODE_ERROR), 'bn decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_BN_ERROR), 'bn error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_INVALID_J_VALUE),
    'check invalid j value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_INVALID_Q_VALUE),
    'check invalid q value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_PUBKEY_INVALID),
    'check pubkey invalid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_PUBKEY_TOO_LARGE),
    'check pubkey too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_PUBKEY_TOO_SMALL),
    'check pubkey too small'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_P_NOT_PRIME), 'check p not prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_P_NOT_SAFE_PRIME),
    'check p not safe prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_CHECK_Q_NOT_PRIME), 'check q not prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_DECODE_ERROR), 'decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_INVALID_PARAMETER_NAME),
    'invalid parameter name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_INVALID_PARAMETER_NID),
    'invalid parameter nid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_INVALID_PUBKEY), 'invalid public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_INVALID_SECRET), 'invalid secret'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_KDF_PARAMETER_ERROR), 'kdf parameter error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_KEYS_NOT_SET), 'keys not set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_MISSING_PUBKEY), 'missing pubkey'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_MODULUS_TOO_LARGE), 'modulus too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_MODULUS_TOO_SMALL), 'modulus too small'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_NOT_SUITABLE_GENERATOR),
    'not suitable generator'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_NO_PARAMETERS_SET), 'no parameters set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_NO_PRIVATE_VALUE), 'no private value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_PARAMETER_ENCODING_ERROR),
    'parameter encoding error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_PEER_KEY_ERROR), 'peer key error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_SHARED_INFO_ERROR), 'shared info error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, DH_R_UNABLE_TO_CHECK_GENERATOR),
    'unable to check generator'),
    get_ERR_STRING_DATA(0, nil)
];
end.
