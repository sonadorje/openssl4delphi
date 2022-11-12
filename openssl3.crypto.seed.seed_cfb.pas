unit openssl3.crypto.seed.seed_cfb;

interface
uses OpenSSL.Api;

procedure SEED_cfb128_encrypt(const _in : PByte; _out : PByte; len : size_t;const ks : PSEED_KEY_SCHEDULE; ivec : PByte; num : PInteger; enc : integer);

implementation
uses openssl3.crypto.modes.cfb128, openssl3.crypto.seed.seed;

procedure SEED_cfb128_encrypt(const _in : PByte; _out : PByte; len : size_t;const ks : PSEED_KEY_SCHEDULE; ivec : PByte; num : PInteger; enc : integer);
begin
    CRYPTO_cfb128_encrypt(_in, _out, len, ks, ivec, num, enc,
                          Pblock128_f(@SEED_encrypt)^);
end;


end.
