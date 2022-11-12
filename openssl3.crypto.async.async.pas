unit openssl3.crypto.async.async;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

 var
  ctxkey, poolkey: CRYPTO_THREAD_LOCAL ;

 procedure async_deinit;
function async_init:integer;

implementation
uses OpenSSL3.threads_none;






function async_init:integer;
begin
    if  0>= CRYPTO_THREAD_init_local(@ctxkey, nil) then
        Exit(0);
    if  0>= CRYPTO_THREAD_init_local(@poolkey, nil) then
    begin
        CRYPTO_THREAD_cleanup_local(@ctxkey);
        Exit(0);
    end;
    Result := 1;
end;

procedure async_deinit;
begin
    CRYPTO_THREAD_cleanup_local(@ctxkey);
    CRYPTO_THREAD_cleanup_local(@poolkey);
end;


end.
