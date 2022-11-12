unit openssl3.crypto.cmp.cmp_util;

interface
uses OpenSSL.Api;

procedure OSSL_CMP_log_close;

implementation
uses openssl3.crypto.trace;

procedure OSSL_CMP_log_close;
begin
    OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, nil);
end;


end.
