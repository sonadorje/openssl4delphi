unit openssl3.crypto.ess.ess_err;

interface
uses OpenSSL.Api;

function ossl_err_load_ESS_strings:integer;

var
  ESS_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_ESS_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(ESS_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@ESS_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  ESS_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_EMPTY_ESS_CERT_ID_LIST),
    'empty ess cert id list'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_CERT_DIGEST_ERROR),
    'ess cert digest error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_CERT_ID_NOT_FOUND),
    'ess cert id not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_CERT_ID_WRONG_ORDER),
    'ess cert id wrong order'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_DIGEST_ALG_UNKNOWN),
    'ess digest alg unknown'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_SIGNING_CERTIFICATE_ERROR),
    'ess signing certificate error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_SIGNING_CERT_ADD_ERROR),
    'ess signing cert add error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_SIGNING_CERT_V2_ADD_ERROR),
    'ess signing cert v2 add error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, ESS_R_MISSING_SIGNING_CERTIFICATE_ATTRIBUTE),
    'missing signing certificate attribute'),
    get_ERR_STRING_DATA(0, nil)
];

end.
