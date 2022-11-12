unit OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha;

interface
uses OpenSSL.Api;

const  ossl_aes128cbc_hmac_sha1_functions: array[0..0] of TOSSL_DISPATCH = (
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes256cbc_hmac_sha1_functions: array[0..0] of TOSSL_DISPATCH = (
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes128cbc_hmac_sha256_functions: array[0..0] of TOSSL_DISPATCH = (
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes256cbc_hmac_sha256_functions: array[0..0] of TOSSL_DISPATCH = (
(function_id:  0; method:(code:nil; data:nil)) );

implementation

end.
