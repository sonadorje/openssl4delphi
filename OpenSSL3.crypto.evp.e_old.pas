unit OpenSSL3.crypto.evp.e_old;

interface
uses OpenSSL.Api;


function EVP_des_cfb:PEVP_CIPHER;

implementation
uses openssl3.crypto.evp.e_des;

function EVP_des_cfb:PEVP_CIPHER;
begin
    Result := EVP_des_cfb64;
end;


end.
