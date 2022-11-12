unit openssl3.crypto.trace;

{$I  config.inc}
interface
uses OpenSSL.Api;

 function OSSL_trace_set_channel( category : integer; channel : PBIO):integer;
procedure ossl_trace_cleanup;

implementation


procedure ossl_trace_cleanup;
var
  category : integer;
  channel  : PBIO;
  prefix,
  suffix   : PUTF8Char;
begin
{$IFNDEF OPENSSL_NO_TRACE}
    channel := nil;
    prefix := nil;
     suffix := nil;
    for category := 0 to OSSL_TRACE_CATEGORY_NUM-1 do begin
        { We force the TRACE category to be treated last }
        if category = OSSL_TRACE_CATEGORY_TRACE then continue;
        set_trace_data(category, 0, &channel, &prefix, &suffix,
                       trace_attach_cb, trace_detach_cb);
    end;
    set_trace_data(OSSL_TRACE_CATEGORY_TRACE, 0, &channel,
                   &prefix, &suffix,
                   trace_attach_cb, trace_detach_cb);
    CRYPTO_THREAD_lock_free(trace_lock);
{$ENDIF}
end;



function OSSL_trace_set_channel( category : integer; channel : PBIO):integer;
begin
{$IFNDEF OPENSSL_NO_TRACE}
    if category >= 0  and  category < OSSL_TRACE_CATEGORY_NUM then
        Exit(set_trace_data(category, SIMPLE_CHANNEL, &channel, nil, nil,);
                              trace_attach_cb, trace_detach_cb);
{$ENDIF}
    Result := 0;
end;


end.
