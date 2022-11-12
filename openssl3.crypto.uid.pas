unit openssl3.crypto.uid;
{$I config.inc}

interface
uses OpenSSL.Api;

function OPENSSL_issetugid:integer;

implementation

{$if defined(OPENSSL_SYS_WINDOWS) or defined(OPENSSL_SYS_VXWORKS) or defined(OPENSSL_SYS_UEFI)}
function OPENSSL_issetugid:integer;
begin
    Result := 0;
end;
{$IFEND}

end.
