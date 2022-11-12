unit openssl3.crypto.crmf.crmf_err;

interface
uses OpenSSL.Api;

function ossl_err_load_CRMF_strings:integer;
var
  CRMF_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_CRMF_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(CRMF_str_reasons[0].error ) = nil then
        ERR_load_strings_const(@CRMF_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  CRMF_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_BAD_PBM_ITERATIONCOUNT),
    'bad pbm iterationcount'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_CRMFERROR), 'crmferror'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_ERROR), 'error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_ERROR_DECODING_CERTIFICATE),
    'error decoding certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_ERROR_DECRYPTING_CERTIFICATE),
    'error decrypting certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY),
    'error decrypting symmetric key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_FAILURE_OBTAINING_RANDOM),
    'failure obtaining random'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_ITERATIONCOUNT_BELOW_100),
    'iterationcount below 100'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_MALFORMED_IV), 'malformed iv'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_NULL_ARGUMENT), 'null argument'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_POPOSKINPUT_NOT_SUPPORTED),
    'poposkinput not supported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY),
    'popo inconsistent public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_POPO_MISSING), 'popo missing'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_POPO_MISSING_PUBLIC_KEY),
    'popo missing public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_POPO_MISSING_SUBJECT),
    'popo missing subject'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED),
    'popo raverified not accepted'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_SETTING_MAC_ALGOR_FAILURE),
    'setting mac algor failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_SETTING_OWF_ALGOR_FAILURE),
    'setting owf algor failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_UNSUPPORTED_ALGORITHM),
    'unsupported algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_UNSUPPORTED_CIPHER),
    'unsupported cipher'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO),
    'unsupported method for creating popo'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, CRMF_R_UNSUPPORTED_POPO_METHOD),
    'unsupported popo method'),
    get_ERR_STRING_DATA(0, nil)
];


end.
