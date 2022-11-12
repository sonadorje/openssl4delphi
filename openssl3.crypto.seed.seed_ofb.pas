unit openssl3.crypto.seed.seed_ofb;

interface
uses OpenSSL.Api;

 procedure SEED_ofb128_encrypt(const _in : PByte; _out : PByte; len : size_t;const ks : PSEED_KEY_SCHEDULE; ivec : PByte; num : PInteger);

implementation
uses openssl3.crypto.modes.ofb128,  openssl3.crypto.seed.seed;

procedure SEED_ofb128_encrypt(const _in : PByte; _out : PByte; len : size_t;const ks : PSEED_KEY_SCHEDULE; ivec : PByte; num : PInteger);
begin
    CRYPTO_ofb128_encrypt(_in, _out, len, ks, ivec, num,
                          Pblock128_f(@SEED_encrypt)^);
end;


end.
