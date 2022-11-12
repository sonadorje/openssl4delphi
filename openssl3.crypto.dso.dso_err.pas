unit openssl3.crypto.dso.dso_err;

interface
uses OpenSSL.Api;

function ossl_err_load_DSO_strings:integer;

var
  DSO_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_DSO_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(DSO_str_reasons[0].error ) = nil then
        ERR_load_strings_const(@DSO_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  DSO_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_CTRL_FAILED), 'control command failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_DSO_ALREADY_LOADED), 'dso already loaded'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_EMPTY_FILE_STRUCTURE),
    'empty file structure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_FAILURE), 'failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_FILENAME_TOO_BIG), 'filename too big'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_FINISH_FAILED),
    'cleanup method function failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_INCORRECT_FILE_SYNTAX),
    'incorrect file syntax'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_LOAD_FAILED),
    'could not load the shared library'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_NAME_TRANSLATION_FAILED),
    'name translation failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_NO_FILENAME), 'no filename'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_NULL_HANDLE),
    'a null shared library handle was used'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_SET_FILENAME_FAILED),
    'set filename failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_STACK_ERROR),
    'the meth_data stack is corrupt'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_SYM_FAILURE),
    'could not bind to the requested symbol name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_UNLOAD_FAILED),
    'could not unload the shared library'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, DSO_R_UNSUPPORTED),
    'functionality not supported'),
    get_ERR_STRING_DATA(0, nil)
];


end.
