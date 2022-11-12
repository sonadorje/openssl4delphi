unit openssl3.crypto.ct.ct_err;

interface
uses OpenSSL.Api;

function ossl_err_load_CT_strings:integer;

var
  CT_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_CT_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(CT_str_reasons[0].error) = nil  then
       ERR_load_strings_const(@CT_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  CT_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_BASE64_DECODE_ERROR), 'base64 decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_INVALID_LOG_ID_LENGTH),
    'invalid log id length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_LOG_CONF_INVALID), 'log conf invalid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_LOG_CONF_INVALID_KEY),
    'log conf invalid key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_LOG_CONF_MISSING_DESCRIPTION),
    'log conf missing description'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_LOG_CONF_MISSING_KEY),
    'log conf missing key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_LOG_KEY_INVALID), 'log key invalid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_FUTURE_TIMESTAMP),
    'sct future timestamp'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_INVALID), 'sct invalid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_INVALID_SIGNATURE),
    'sct invalid signature'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_LIST_INVALID), 'sct list invalid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_LOG_ID_MISMATCH), 'sct log id mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_NOT_SET), 'sct not set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_SCT_UNSUPPORTED_VERSION),
    'sct unsupported version'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_UNRECOGNIZED_SIGNATURE_NID),
    'unrecognized signature nid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_UNSUPPORTED_ENTRY_TYPE),
    'unsupported entry type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, CT_R_UNSUPPORTED_VERSION), 'unsupported version'),
    get_ERR_STRING_DATA(0, nil)
];

end.
