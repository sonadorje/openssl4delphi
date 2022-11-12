unit openssl3.crypto.buffer.buf_err;

interface
 uses OpenSSL.Api;

 function ossl_err_load_BUF_strings:integer;

implementation
uses OpenSSL3.Err;

const  BUF_str_reasons: array[0..0] of TERR_STRING_DATA =(
    (error : 0; _string: nil)
);

function ossl_err_load_BUF_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(BUF_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@BUF_str_reasons);
{$ENDIF}
    Result := 1;
end;


end.
