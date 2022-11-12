unit openssl3.crypto.async.async_err;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_err_load_ASYNC_strings:integer;

var
  ASYNC_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_ASYNC_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(ASYNC_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@ASYNC_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  ASYNC_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_FAILED_TO_SET_POOL),
    'failed to set pool'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_FAILED_TO_SWAP_CONTEXT),
    'failed to swap context'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_INIT_FAILED), 'init failed'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_INVALID_POOL_SIZE),
    'invalid pool size'),
    get_ERR_STRING_DATA(0, nil)
];


end.
