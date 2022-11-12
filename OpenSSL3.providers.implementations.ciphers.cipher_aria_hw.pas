unit OpenSSL3.providers.implementations.ciphers.cipher_aria_hw;

interface
uses OpenSSL.Api;

function cipher_hw_aria_initkey(dat : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;

procedure cipher_hw_aria_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);

implementation
uses OpenSSL3.crypto.aria.aria, OpenSSL3.Err;





procedure cipher_hw_aria_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
var
  sctx, dctx : PPROV_ARIA_CTX;
begin
   sctx := PPROV_ARIA_CTX(src);
   dctx := PPROV_ARIA_CTX(dst);
   dctx^ := sctx^;
   dst.ks := @dctx.ks.ks;
end;

function cipher_hw_aria_initkey(dat : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  ret, mode : integer;
  adat : PPROV_ARIA_CTX;
  ks : PARIA_KEY;
begin
    mode := dat.mode;
    adat := PPROV_ARIA_CTX(dat);
    ks := @adat.ks.ks;
    if (dat.enc > 0) or ( (mode <> EVP_CIPH_ECB_MODE)  and  (mode <> EVP_CIPH_CBC_MODE)) then
        ret := ossl_aria_set_encrypt_key(key, keylen * 8, ks)
    else
        ret := ossl_aria_set_decrypt_key(key, keylen * 8, ks);
    if ret < 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        Exit(0);
    end;
    dat.ks := ks;
    dat.block := Pblock128_f(@ossl_aria_encrypt)^;
    Result := 1;
end;


end.
