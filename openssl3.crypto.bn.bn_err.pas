unit openssl3.crypto.bn.bn_err;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_err_load_BN_strings:integer;

implementation
uses OpenSSL3.Err;

function ossl_err_load_BN_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(BN_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@BN_str_reasons);
{$ENDIF}
    Result := 1;
end;


end.
