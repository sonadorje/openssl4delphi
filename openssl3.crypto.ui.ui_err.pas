unit openssl3.crypto.ui.ui_err;

interface
uses OpenSSL.Api;

 function ossl_err_load_UI_strings:integer;

 var
   UI_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_UI_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(UI_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@UI_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  UI_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_COMMON_OK_AND_CANCEL_CHARACTERS),
    'common ok and cancel characters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_INDEX_TOO_LARGE), 'index too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_INDEX_TOO_SMALL), 'index too small'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_NO_RESULT_BUFFER), 'no result buffer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_PROCESSING_ERROR), 'processing error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_RESULT_TOO_LARGE), 'result too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_RESULT_TOO_SMALL), 'result too small'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_SYSASSIGN_ERROR), 'sys$assign error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_SYSDASSGN_ERROR), 'sys$dassgn error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_SYSQIOW_ERROR), 'sys$qiow error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_UNKNOWN_CONTROL_COMMAND),
    'unknown control command'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_UNKNOWN_TTYGET_ERRNO_VALUE),
    'unknown ttyget errno value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, UI_R_USER_DATA_DUPLICATION_UNSUPPORTED),
    'user data duplication unsupported'),
    get_ERR_STRING_DATA(0, nil)
];

end.
