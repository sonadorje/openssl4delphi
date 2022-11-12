unit OpenSSL3.providers.implementations.ciphers.cipher_aes_gcm_hw;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm_hw;

function ossl_prov_aes_hw_gcm( keybits : size_t):PPROV_GCM_HW;
function aes_gcm_initkey(ctx : PPROV_GCM_CTX;const key : PByte; keylen : size_t):integer;
function generic_aes_gcm_cipher_update(ctx : PPROV_GCM_CTX;const _in : PByte; len : size_t; _out : PByte):integer;

const aes_gcm: TPROV_GCM_HW  = (
    setkey: aes_gcm_initkey;
    setiv: ossl_gcm_setiv;
    aadupdate: ossl_gcm_aad_update;
    cipherupdate: generic_aes_gcm_cipher_update;
    cipherfinal: ossl_gcm_cipher_final;
    oneshot: ossl_gcm_one_shot
);



implementation
uses openssl3.crypto.aes.aes_core, openssl3.crypto.modes.gcm128;



function aes_gcm_initkey(ctx : PPROV_GCM_CTX;const key : PByte; keylen : size_t):integer;
var
  actx : PPROV_AES_GCM_CTX;
  ks : PAES_KEY;
begin
    actx := PPROV_AES_GCM_CTX (ctx);
    ks := @actx.ks.ks;
{$IFDEF HWAES_CAPABLE}
    if HWAES_CAPABLE then
    begin
{$IFDEF HWAES_ctr32_encrypt_blocks}
        GCM_HW_SET_KEY_CTR_FN(ks, HWAES_set_encrypt_key, HWAES_encrypt,
                              HWAES_ctr32_encrypt_blocks);
{$ELSE} GCM_HW_SET_KEY_CTR_FN(ks, HWAES_set_encrypt_key, HWAES_encrypt, nil);
{$endif} { HWAES_ctr32_encrypt_blocks }
    end;
    else
{$endif} { HWAES_CAPABLE }
{$IFDEF BSAES_CAPABLE}
    if BSAES_CAPABLE then begin
        GCM_HW_SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt,
                              ossl_bsaes_ctr32_encrypt_blocks);
    end;
    else
{$endif} { BSAES_CAPABLE }
{$IFDEF VPAES_CAPABLE}
    if VPAES_CAPABLE then begin
        GCM_HW_SET_KEY_CTR_FN(ks, vpaes_set_encrypt_key, vpaes_encrypt, nil);
    end;
    else
{$endif} { VPAES_CAPABLE }
    begin
{$IFDEF AES_CTR_ASM}
        GCM_HW_SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt,
                              AES_ctr32_encrypt);
{$ELSE}
       //GCM_HW_SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt, nil);
       ctx.ks := ks;
       AES_set_encrypt_key(key, keylen * 8, ks);
       CRYPTO_gcm128_init(@ctx.gcm, ks, {block128_f}AES_encrypt);
       ctx.ctr := nil;//(ctr128_f)((void *)0);
       ctx.key_set := 1;;

{$endif} { AES_CTR_ASM }
    end;
    ctx.key_set := 1;
    Result := 1;
end;


function generic_aes_gcm_cipher_update(ctx : PPROV_GCM_CTX;const _in : PByte; len : size_t; _out : PByte):integer;
var
  bulk, res: size_t;
begin
    if ctx.enc > 0 then
    begin
        if Assigned(ctx.ctr) then
        begin
{$IF defined(AES_GCM_ASM)}
            bulk := 0;
            if len >= AES_GCM_ENC_BYTES  and  AES_GCM_ASM(ctx then ) begin
                res := (16 - ctx.gcm.mres) % 16;
                if CRYPTO_gcm128_encrypt(&ctx.gcm, in, _out, res then )
                    Exit(0);
                bulk := AES_gcm_encrypt(in + res, _out + res, len - res,
                                       ctx.gcm.key,
                                       ctx.gcm.Yi.c, ctx.gcm.Xi.u);
                ctx.gcm.len.u[1]  := ctx.gcm.len.u[1] + bulk;
                bulk  := bulk + res;
            end;
            if CRYPTO_gcm128_encrypt_ctr32(&ctx.gcm, in + bulk, _out + bulk,
                                            len - bulk, ctx.ctr then )
                Exit(0);
{$ELSE} if CRYPTO_gcm128_encrypt_ctr32(@ctx.gcm, _in, _out, len, ctx.ctr) > 0 then
                Exit(0);
{$endif} { AES_GCM_ASM }
        end
        else
        begin
            if CRYPTO_gcm128_encrypt(@ctx.gcm, _in, _out, len) > 0 then
                Exit(0);
        end;
    end
    else
    begin
        if Assigned(ctx.ctr) then
        begin
{$IF defined(AES_GCM_ASM)}
            bulk := 0;
            if len >= AES_GCM_DEC_BYTES  and  AES_GCM_ASM(ctx then ) begin
                res := (16 - ctx.gcm.mres) % 16;
                if CRYPTO_gcm128_decrypt(&ctx.gcm, in, _out, res then )
                    Exit(-1);
                bulk := AES_gcm_decrypt(in + res, _out + res, len - res,
                                       ctx.gcm.key,
                                       ctx.gcm.Yi.c, ctx.gcm.Xi.u);
                ctx.gcm.len.u[1]  := ctx.gcm.len.u[1] + bulk;
                bulk  := bulk + res;
            end;
            if CRYPTO_gcm128_decrypt_ctr32(&ctx.gcm, in + bulk, _out + bulk,
                                            len - bulk, ctx.ctr then )
                Exit(0);
{$ELSE} if CRYPTO_gcm128_decrypt_ctr32(@ctx.gcm, _in, _out, len, ctx.ctr) > 0 then
                Exit(0);
{$endif} { AES_GCM_ASM }
        end
        else
        begin
            if CRYPTO_gcm128_decrypt(@ctx.gcm, _in, _out, len) > 0 then
                Exit(0);
        end;
    end;
    Result := 1;
end;


function ossl_prov_aes_hw_gcm( keybits : size_t):PPROV_GCM_HW;
begin
    Result := @aes_gcm;
end;


end.
