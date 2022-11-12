unit OpenSSL3.providers.implementations.ciphers.cipher_sm4_ccm_hw;

interface
uses OpenSSL.Api;

function ccm_sm4_initkey(ctx : PPROV_CCM_CTX;const key : PByte; keylen : size_t):integer;
  function ossl_prov_sm4_hw_ccm( keybits : size_t):PPROV_CCM_HW;

implementation
uses openssl3.crypto.sm4.sm4, OpenSSL3.crypto.modes.ccm128,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_ccm_hw;

const  ccm_sm4: TPROV_CCM_HW = (
    setkey: ccm_sm4_initkey;
    setiv: ossl_ccm_generic_setiv;
    setaad: ossl_ccm_generic_setaad;
    auth_encrypt: ossl_ccm_generic_auth_encrypt;
    auth_decrypt: ossl_ccm_generic_auth_decrypt;
    gettag: ossl_ccm_generic_gettag
);

function ccm_sm4_initkey(ctx : PPROV_CCM_CTX;const key : PByte; keylen : size_t):integer;
var
  actx : PPROV_SM4_CCM_CTX;
begin
    actx := PPROV_SM4_CCM_CTX (ctx);
    ossl_sm4_set_key(key, @actx.ks.ks);
    CRYPTO_ccm128_init(@ctx.ccm_ctx, ctx.m, ctx.l, @actx.ks.ks,
                       Pblock128_f(@ossl_sm4_encrypt)^);
    ctx.str := nil;
    ctx.key_set := 1;
    Result := 1;
end;


function ossl_prov_sm4_hw_ccm( keybits : size_t):PPROV_CCM_HW;
begin
    Result := @ccm_sm4;
end;


end.
