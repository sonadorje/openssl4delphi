unit openssl3.crypto.objects.obj_err;

interface
uses OpenSSL.Api;

 function ossl_err_load_OBJ_strings:integer;

 var
    OBJ_str_reasons: array of TERR_STRING_DATA ;

implementation
uses OpenSSL3.Err;

function ossl_err_load_OBJ_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(OBJ_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@OBJ_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  OBJ_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OBJ, 0, OBJ_R_OID_EXISTS), 'oid exists'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OBJ, 0, OBJ_R_UNKNOWN_NID), 'unknown nid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OBJ, 0, OBJ_R_UNKNOWN_OBJECT_NAME), 'unknown object name'),
    get_ERR_STRING_DATA(0, nil)];

end.
