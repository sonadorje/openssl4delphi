unit OpenSSL3.providers.implementations.ciphers.cipher_aria_ccm_hw;

interface
uses OpenSSL.Api;

function ccm_aria_initkey(ctx : PPROV_CCM_CTX;const key : PByte; keylen : size_t):integer;
  function ossl_prov_aria_hw_ccm( keybits : size_t):PPROV_CCM_HW;


implementation
uses OpenSSL3.crypto.modes.ccm128, OpenSSL3.crypto.aria.aria,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_ccm_hw;


const ccm_aria: TPROV_CCM_HW  = (
    setkey: ccm_aria_initkey;
    setiv: ossl_ccm_generic_setiv;
    setaad: ossl_ccm_generic_setaad;
    auth_encrypt: ossl_ccm_generic_auth_encrypt;
    auth_decrypt: ossl_ccm_generic_auth_decrypt;
    gettag: ossl_ccm_generic_gettag
);

function ccm_aria_initkey(ctx : PPROV_CCM_CTX;const key : PByte; keylen : size_t):integer;
var
  actx : PPROV_ARIA_CCM_CTX;
begin
    actx := PPROV_ARIA_CCM_CTX(ctx);
    ossl_aria_set_encrypt_key(key, keylen * 8, @actx.ks.ks);
    CRYPTO_ccm128_init(@ctx.ccm_ctx, ctx.m, ctx.l, @actx.ks.ks,
                       Pblock128_f(@ossl_aria_encrypt)^);
    ctx.str := nil;
    ctx.key_set := 1;
    Result := 1;
end;


function ossl_prov_aria_hw_ccm( keybits : size_t):PPROV_CCM_HW;
begin
    Result := @ccm_aria;
end;


end.
