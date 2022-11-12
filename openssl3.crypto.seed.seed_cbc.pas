unit openssl3.crypto.seed.seed_cbc;

interface
uses OpenSSL.Api;

procedure SEED_cbc_encrypt(const _in : PByte; _out : PByte; len : size_t;const ks : PSEED_KEY_SCHEDULE; ivec : PByte; enc : integer);

implementation
uses openssl3.crypto.modes.cbc128, openssl3.crypto.seed.seed;

procedure SEED_cbc_encrypt(const _in : PByte; _out : PByte; len : size_t;const ks : PSEED_KEY_SCHEDULE; ivec : PByte; enc : integer);
begin
    if enc > 0 then
       CRYPTO_cbc128_encrypt(_in, _out, len, ks, ivec,
                              Pblock128_f(@SEED_encrypt)^)
    else
       CRYPTO_cbc128_decrypt(_in, _out, len, ks, ivec,
                              Pblock128_f(@SEED_decrypt)^);
end;


end.
