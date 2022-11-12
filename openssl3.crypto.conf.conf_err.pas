unit openssl3.crypto.conf.conf_err;

interface
uses OpenSSL.Api;

function ossl_err_load_CONF_strings:integer;

var
  CONF_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_CONF_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(CONF_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@CONF_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  CONF_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_ERROR_LOADING_DSO), 'error loading dso'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_INVALID_PRAGMA), 'invalid pragma'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_LIST_CANNOT_BE_NULL),
    'list cannot be null'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_MANDATORY_BRACES_IN_VARIABLE_EXPANSION),
    'mandatory braces in variable expansion'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_MISSING_CLOSE_SQUARE_BRACKET),
    'missing close square bracket'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_MISSING_EQUAL_SIGN),
    'missing equal sign'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_MISSING_INIT_FUNCTION),
    'missing init function'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_MODULE_INITIALIZATION_ERROR),
    'module initialization error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NO_CLOSE_BRACE), 'no close brace'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NO_CONF), 'no conf'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE),
    'no conf or environment variable'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NO_SECTION), 'no section'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NO_SUCH_FILE), 'no such file'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NO_VALUE), 'no value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_NUMBER_TOO_LARGE), 'number too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION),
    'openssl conf references missing section'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_RECURSIVE_DIRECTORY_INCLUDE),
    'recursive directory include'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_RELATIVE_PATH), 'relative path'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_SSL_COMMAND_SECTION_EMPTY),
    'ssl command section empty'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_SSL_COMMAND_SECTION_NOT_FOUND),
    'ssl command section not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_SSL_SECTION_EMPTY), 'ssl section empty'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_SSL_SECTION_NOT_FOUND),
    'ssl section not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_UNABLE_TO_CREATE_NEW_SECTION),
    'unable to create new section'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_UNKNOWN_MODULE_NAME),
    'unknown module name'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_VARIABLE_EXPANSION_TOO_LONG),
    'variable expansion too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, CONF_R_VARIABLE_HAS_NO_VALUE),
    'variable has no value'),
    get_ERR_STRING_DATA(0, nil)
];

end.
