unit openssl3.crypto.comp.comp_err;

interface
uses OpenSSL.Api;

 function ossl_err_load_COMP_strings:integer;

 var
   COMP_str_reasons: array of TERR_STRING_DATA;
implementation
uses OpenSSL3.Err;

function ossl_err_load_COMP_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(COMP_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@COMP_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  COMP_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_COMP, 0, COMP_R_ZLIB_DEFLATE_ERROR),
    'zlib deflate error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_COMP, 0, COMP_R_ZLIB_INFLATE_ERROR),
    'zlib inflate error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_COMP, 0, COMP_R_ZLIB_NOT_SUPPORTED),
    'zlib not supported'),
    get_ERR_STRING_DATA(0, nil)
];

end.
