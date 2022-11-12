unit OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha1_hw;

interface
uses OpenSSL.Api;

function ossl_cipher_capable_aes_cbc_hmac_sha1:integer;

implementation


function ossl_cipher_capable_aes_cbc_hmac_sha1:integer;
begin
    Result := 0;
end;


end.
