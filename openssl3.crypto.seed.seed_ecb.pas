unit openssl3.crypto.seed.seed_ecb;

interface
uses OpenSSL.Api;

 procedure SEED_ecb_encrypt(const _in : PByte; _out : PByte;const ks : PSEED_KEY_SCHEDULE; enc : integer);

implementation
uses openssl3.crypto.seed.seed;

procedure SEED_ecb_encrypt(const _in : PByte; _out : PByte;const ks : PSEED_KEY_SCHEDULE; enc : integer);
begin
    if enc > 0 then
       SEED_encrypt(_in, _out, ks)
    else
       SEED_decrypt(_in, _out, ks);
end;


end.
