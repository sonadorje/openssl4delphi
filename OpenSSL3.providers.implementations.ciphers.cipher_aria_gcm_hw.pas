unit OpenSSL3.providers.implementations.ciphers.cipher_aria_gcm_hw;

interface
uses OpenSSL.Api,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm_hw;

function aria_gcm_initkey(ctx : PPROV_GCM_CTX;const key : PByte; keylen : size_t):integer;
  function ossl_prov_aria_hw_gcm( keybits : size_t):PPROV_GCM_HW;

const  aria_gcm: TPROV_GCM_HW = (
    setkey: aria_gcm_initkey;
    setiv: ossl_gcm_setiv;
    aadupdate: ossl_gcm_aad_update;
    cipherupdate: ossl_gcm_cipher_update;
    cipherfinal: ossl_gcm_cipher_final;
    oneshot: ossl_gcm_one_shot
);

implementation
uses OpenSSL3.crypto.aria.aria, openssl3.crypto.modes.gcm128;

function aria_gcm_initkey(ctx : PPROV_GCM_CTX;const key : PByte; keylen : size_t):integer;
var
  actx : PPROV_ARIA_GCM_CTX;
  ks : PARIA_KEY;
begin
    actx := PPROV_ARIA_GCM_CTX(ctx);
    ks := @actx.ks.ks;
    //GCM_HW_SET_KEY_CTR_FN(ks, ossl_aria_set_encrypt_key, ossl_aria_encrypt, nil);
    ctx.ks := ks;
    ossl_aria_set_encrypt_key(key, keylen * 8, ks);
    CRYPTO_gcm128_init(@ctx.gcm, ks, Pblock128_f(@ossl_aria_encrypt)^);
    ctx.ctr := nil;//(ctr128_f)((void *)0);
    ctx.key_set := 1;

    Result := 1;
end;


function ossl_prov_aria_hw_gcm( keybits : size_t):PPROV_GCM_HW;
begin
    Result := @aria_gcm;
end;


end.
