unit openssl3.crypto.evp.e_aes_cbc_hmac_sha1;

interface
uses OpenSSL.Api;

 function EVP_aes_128_cbc_hmac_sha1:PEVP_CIPHER;
 function EVP_aes_256_cbc_hmac_sha1:PEVP_CIPHER;

implementation


function EVP_aes_128_cbc_hmac_sha1:PEVP_CIPHER;
begin
    Result := nil;
end;


function EVP_aes_256_cbc_hmac_sha1:PEVP_CIPHER;
begin
    Result := nil;
end;


end.
