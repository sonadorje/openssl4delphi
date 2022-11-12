unit OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb_hw;

interface
uses OpenSSL.Api;

 function ossl_prov_cipher_hw_aes_ocb( keybits : size_t):PPROV_CIPHER_HW;
 function cipher_hw_aes_ocb_generic_initkey(vctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;


implementation
uses OpenSSL3.openssl.params, openssl3.crypto.params, OpenSSL3.Err,
     openssl3.providers.common.provider_ctx, openssl3.crypto.modes.cfb128,
     openssl3.crypto.modes.ocb128, openssl3.crypto.aes.aes_core;







function cipher_hw_aes_ocb_generic_initkey(vctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  ctx : PPROV_AES_OCB_CTX;

  function OCB_SET_KEY_FN( fn_set_enc_key : Tfn_set_enc_key; fn_set_dec_key : Tfn_set_dec_key; fn_block_enc : Tfn_block_enc; fn_block_dec : Tfn_block_dec; fn_stream_enc : Tfn_stream_enc; fn_stream_dec : Tfn_stream_dec): int;
  var
    ocb128: ocb128_f;
  begin
      CRYPTO_ocb128_cleanup(@ctx.ocb);
      fn_set_enc_key(key, keylen * 8, @ctx.ksenc.ks);
      fn_set_dec_key(key, keylen * 8, @ctx.ksdec.ks);

      if ctx.base.enc >0 then
         ocb128 := fn_stream_enc
      else
         ocb128 := fn_stream_dec;

      if  0>= CRYPTO_ocb128_init(@ctx.ocb, @ctx.ksenc.ks, @ctx.ksdec.ks,
                              block128_f(fn_block_enc), block128_f(fn_block_dec),
                              ocb128) then
          result := 0;
      //ctx.key_set := 1;
  end;
begin
    ctx := PPROV_AES_OCB_CTX ( vctx);
{
 * We set both the encrypt and decrypt key here because decrypt
 * needs both. (i.e- AAD uses encrypt).
 }
{$IFDEF HWAES_CAPABLE}
    if HWAES_CAPABLE
    then begin
        OCB_SET_KEY_FN(HWAES_set_encrypt_key, HWAES_set_decrypt_key,
                       HWAES_encrypt, HWAES_decrypt,
                       HWAES_ocb_encrypt, HWAES_ocb_decrypt);
    end
    else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
    if VPAES_CAPABLE then
    begin
        OCB_SET_KEY_FN(vpaes_set_encrypt_key, vpaes_set_decrypt_key,
                       vpaes_encrypt, vpaes_decrypt, nil, nil);
    end
    else
{$ENDIF}
    begin
        if 0>= OCB_SET_KEY_FN(AES_set_encrypt_key, AES_set_decrypt_key,
                       AES_encrypt, AES_decrypt, nil, nil) then
           Exit(0);
        ctx.key_set := 1;
    end;
    Result := 1;
end;

function ossl_prov_cipher_hw_aes_ocb( keybits : size_t):PPROV_CIPHER_HW;
const
    aes_generic_ocb: TPROV_CIPHER_HW = (
        init: cipher_hw_aes_ocb_generic_initkey;
        cipher:nil;
    );
begin
    //PROV_CIPHER_HW_select()
    Result := @aes_generic_ocb;
end;

end.
