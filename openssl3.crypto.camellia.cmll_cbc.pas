unit openssl3.crypto.camellia.cmll_cbc;

interface
uses OpenSSL.Api;

procedure Camellia_cbc_encrypt(const _in : PByte; _out : PByte; len : size_t;const key : PCAMELLIA_KEY; ivec : PByte;const enc : integer);

implementation
uses openssl3.crypto.modes.cbc128, openssl3.crypto.camellia.cmll_misc;

procedure Camellia_cbc_encrypt(const _in : PByte; _out : PByte; len : size_t;const key : PCAMELLIA_KEY; ivec : PByte;const enc : integer);
begin
    if enc > 0 then
       CRYPTO_cbc128_encrypt(_in, _out, len, key, ivec,
                              Pblock128_f(@Camellia_encrypt)^)
    else
        CRYPTO_cbc128_decrypt(_in, _out, len, key, ivec,
                              Pblock128_f(@Camellia_decrypt)^);
end;

end.
