unit openssl3.crypto.property_.property_err;

interface
uses OpenSSL.Api;

function ossl_err_load_PROP_strings:integer;

var
  PROP_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_PROP_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(PROP_str_reasons[0].error )= nil then
        ERR_load_strings_const(@PROP_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  PROP_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NAME_TOO_LONG), 'name too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NOT_AN_ASCII_CHARACTER),
    'not an ascii character'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NOT_AN_HEXADECIMAL_DIGIT),
    'not an hexadecimal digit'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NOT_AN_IDENTIFIER), 'not an identifier'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NOT_AN_OCTAL_DIGIT),
    'not an octal digit'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NOT_A_DECIMAL_DIGIT),
    'not a decimal digit'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NO_MATCHING_STRING_DELIMITER),
    'no matching string delimiter'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_NO_VALUE), 'no value'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_PARSE_FAILED), 'parse failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_STRING_TOO_LONG), 'string too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROP, 0, PROP_R_TRAILING_CHARACTERS),
    'trailing characters'),
    get_ERR_STRING_DATA(0, nil)
];


end.
