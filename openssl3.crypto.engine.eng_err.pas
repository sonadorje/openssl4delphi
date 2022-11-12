unit openssl3.crypto.engine.eng_err;

interface
uses OpenSSL.Api;

function ossl_err_load_ENGINE_strings:integer;

var
  ENGINE_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_ENGINE_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(ENGINE_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@ENGINE_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  ENGINE_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ALREADY_LOADED), 'already loaded'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER),
    'argument is not a number'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_CMD_NOT_EXECUTABLE),
    'cmd not executable'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_COMMAND_TAKES_INPUT),
    'command takes input'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_COMMAND_TAKES_NO_INPUT),
    'command takes no input'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_CONFLICTING_ENGINE_ID),
    'conflicting engine id'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED),
    'ctrl command not implemented'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_DSO_FAILURE), 'DSO failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_DSO_NOT_FOUND), 'dso not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ENGINES_SECTION_ERROR),
    'engines section error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ENGINE_CONFIGURATION_ERROR),
    'engine configuration error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ENGINE_IS_NOT_IN_LIST),
    'engine is not in the list'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ENGINE_SECTION_ERROR),
    'engine section error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_FAILED_LOADING_PRIVATE_KEY),
    'failed loading private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_FAILED_LOADING_PUBLIC_KEY),
    'failed loading public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_FINISH_FAILED), 'finish failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_ID_OR_NAME_MISSING),
    '''id'' or ''name'' missing'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INIT_FAILED), 'init failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INTERNAL_LIST_ERROR),
    'internal list error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INVALID_ARGUMENT),
    'invalid argument'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INVALID_CMD_NAME),
    'invalid cmd name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INVALID_CMD_NUMBER),
    'invalid cmd number'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INVALID_INIT_VALUE),
    'invalid init value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_INVALID_STRING), 'invalid string'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NOT_INITIALISED), 'not initialised'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NOT_LOADED), 'not loaded'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NO_CONTROL_FUNCTION),
    'no control function'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NO_INDEX), 'no index'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NO_LOAD_FUNCTION),
    'no load function'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NO_REFERENCE), 'no reference'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_NO_SUCH_ENGINE), 'no such engine'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_UNIMPLEMENTED_CIPHER),
    'unimplemented cipher'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_UNIMPLEMENTED_DIGEST),
    'unimplemented digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD),
    'unimplemented public key method'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, ENGINE_R_VERSION_INCOMPATIBILITY),
    'version incompatibility'),
    get_ERR_STRING_DATA(0, nil)
];


end.
