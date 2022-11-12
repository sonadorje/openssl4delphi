unit OpenSSL3.providers.implementations.ciphers.cipher_aes_ccm_hw;

interface
uses OpenSSL.Api;

 function ossl_prov_aes_hw_ccm( keybits : size_t):PPROV_CCM_HW;
 function ccm_generic_aes_initkey(ctx : PPROV_CCM_CTX;const key : PByte; keylen : size_t):integer;





implementation
uses openssl3.crypto.aes.aes_core,  OpenSSL3.crypto.modes.ccm128,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_ccm_hw;

const aes_ccm: TPROV_CCM_HW  = (
    setkey: ccm_generic_aes_initkey;
    setiv: ossl_ccm_generic_setiv;
    setaad: ossl_ccm_generic_setaad;
    auth_encrypt: ossl_ccm_generic_auth_encrypt;
    auth_decrypt: ossl_ccm_generic_auth_decrypt;
    gettag: ossl_ccm_generic_gettag
 );




function ccm_generic_aes_initkey(ctx : PPROV_CCM_CTX;const key : PByte; keylen : size_t):integer;
var
  actx : PPROV_AES_CCM_CTX;
begin
    actx := PPROV_AES_CCM_CTX(ctx);
{$IFDEF HWAES_CAPABLE}
    if HWAES_CAPABLE then begin
        AES_HW_CCM_SET_KEY_FN(HWAES_set_encrypt_key, HWAES_encrypt, nil, nil);
    end;
    else
{$endif} { HWAES_CAPABLE }
{$IFDEF VPAES_CAPABLE}
    if VPAES_CAPABLE then begin
        AES_HW_CCM_SET_KEY_FN(vpaes_set_encrypt_key, vpaes_encrypt, nil, nil);
    end;
 else
{$ENDIF}
    begin
        //AES_HW_CCM_SET_KEY_FN(AES_set_encrypt_key, AES_encrypt, nil, nil)
       AES_set_encrypt_key(key, keylen * 8, @actx.ccm.ks.ks);
       CRYPTO_ccm128_init(@ctx.ccm_ctx, ctx.m, ctx.l, @actx.ccm.ks.ks,
                          {block128_f}AES_encrypt);
       ctx.str := nil;
       ctx.key_set := 1;

    end;
    Result := 1;
end;



function ossl_prov_aes_hw_ccm( keybits : size_t):PPROV_CCM_HW;
begin
    Result := @aes_ccm;
end;


end.
