unit OpenSSL3.providers.implementations.ciphers.cipher_sm4_gcm_hw;

interface
uses OpenSSL.Api;

 function sm4_gcm_initkey(ctx : PPROV_GCM_CTX;const key : PByte; keylen : size_t):integer;
  function ossl_prov_sm4_hw_gcm( keybits : size_t):PPROV_GCM_HW;

implementation
uses openssl3.crypto.sm4.sm4, openssl3.crypto.modes.gcm128,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm_hw;

const sm4_gcm: TPROV_GCM_HW = (
    setkey: sm4_gcm_initkey;
    setiv: ossl_gcm_setiv;
    aadupdate: ossl_gcm_aad_update;
    cipherupdate: ossl_gcm_cipher_update;
    cipherfinal: ossl_gcm_cipher_final;
    oneshot: ossl_gcm_one_shot
);

function sm4_gcm_initkey(ctx : PPROV_GCM_CTX;const key : PByte; keylen : size_t):integer;
var
  actx : PPROV_SM4_GCM_CTX;
  ks : PSM4_KEY;
begin
    actx := PPROV_SM4_GCM_CTX (ctx);
    ks := @actx.ks.ks;
    ctx.ks := ks;
{$IFDEF HWSM4_CAPABLE}
    if HWSM4_CAPABLE then begin
        HWSM4_set_encrypt_key(key, ks);
        CRYPTO_gcm128_init(&ctx.gcm, ks, {block128_f}
 HWSM4_encrypt);
{$IFDEF HWSM4_ctr32_encrypt_blocks}
        ctx.ctr := (ctr128_f) HWSM4_ctr32_encrypt_blocks;
{$ELSE} { HWSM4_ctr32_encrypt_blocks }
        ctx.ctr := (ctr128_f)nil;
{$ENDIF}
    end;
 else
{$endif} { HWSM4_CAPABLE }
    begin
        ossl_sm4_set_key(key, ks);
        CRYPTO_gcm128_init(@ctx.gcm, ks, Pblock128_f(@ossl_sm4_encrypt)^);
        ctx.ctr := {ctr128_f}nil;
    end;
    ctx.key_set := 1;
    Result := 1;
end;


function ossl_prov_sm4_hw_gcm( keybits : size_t):PPROV_GCM_HW;
begin
    Result := @sm4_gcm;
end;


end.
