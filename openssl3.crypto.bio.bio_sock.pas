unit openssl3.crypto.bio.bio_sock;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

 procedure bio_sock_cleanup_int;

implementation


procedure bio_sock_cleanup_int;
begin
{$IFDEF OPENSSL_SYS_WINDOWS}
    if wsa_init_done then begin
        wsa_init_done := 0;
        WSACleanup();
    end;
{$ENDIF}
end;


end.
