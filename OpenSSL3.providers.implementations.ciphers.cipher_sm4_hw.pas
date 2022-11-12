unit OpenSSL3.providers.implementations.ciphers.cipher_sm4_hw;

interface
uses OpenSSL.Api;

  function cipher_hw_sm4_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
  function ossl_prov_cipher_hw_sm4_cbc( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_sm4_ecb( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_sm4_ofb128( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_sm4_cfb128( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_sm4_ctr( keybits : size_t):PPROV_CIPHER_HW;
  procedure cipher_hw_sm4_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);

implementation
uses openssl3.crypto.sm4.sm4,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw;



const
    sm4_cbc    : TPROV_CIPHER_HW = (init:  cipher_hw_sm4_initkey;cipher: ossl_cipher_hw_generic_cbc;copyctx: cipher_hw_sm4_copyctx );
    sm4_ecb    : TPROV_CIPHER_HW = (init:  cipher_hw_sm4_initkey;cipher: ossl_cipher_hw_generic_ecb;copyctx: cipher_hw_sm4_copyctx );
    sm4_ofb128 : TPROV_CIPHER_HW = (init:  cipher_hw_sm4_initkey;cipher: ossl_cipher_hw_generic_ofb128;copyctx: cipher_hw_sm4_copyctx );
    sm4_cfb128 : TPROV_CIPHER_HW = (init:  cipher_hw_sm4_initkey;cipher: ossl_cipher_hw_generic_cfb128;copyctx: cipher_hw_sm4_copyctx );
    sm4_ctr    : TPROV_CIPHER_HW = (init:  cipher_hw_sm4_initkey;cipher: ossl_cipher_hw_generic_ctr;copyctx: cipher_hw_sm4_copyctx );





procedure cipher_hw_sm4_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
var
  sctx, dctx : PPROV_SM4_CTX;
begin
   sctx := PPROV_SM4_CTX(src);
   dctx := PPROV_SM4_CTX(dst);
   dctx^ := sctx^;
   dst.ks := @dctx.ks.ks;
end;



function ossl_prov_cipher_hw_sm4_cbc( keybits : size_t):PPROV_CIPHER_HW;
begin
 Result := @sm4_cbc;
end;


function ossl_prov_cipher_hw_sm4_ecb( keybits : size_t):PPROV_CIPHER_HW;
begin
 Result := @sm4_ecb;
end;


function ossl_prov_cipher_hw_sm4_ofb128( keybits : size_t):PPROV_CIPHER_HW;
begin
 Result := @sm4_ofb128;
end;


function ossl_prov_cipher_hw_sm4_cfb128( keybits : size_t):PPROV_CIPHER_HW;
begin
 Result := @sm4_cfb128;
end;


function ossl_prov_cipher_hw_sm4_ctr( keybits : size_t):PPROV_CIPHER_HW;
begin
 Result := @sm4_ctr;
end;

function cipher_hw_sm4_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  sctx : PPROV_SM4_CTX;
  ks : PSM4_KEY;
begin
    sctx := PPROV_SM4_CTX(ctx);
    ks := @sctx.ks.ks;
    ctx.ks := ks;
    if (ctx.enc > 0)
             or ( (ctx.mode <> EVP_CIPH_ECB_MODE)
                 and  (ctx.mode <> EVP_CIPH_CBC_MODE) ) then
    begin
{$IFDEF HWSM4_CAPABLE}
        if HWSM4_CAPABLE then  begin
            HWSM4_set_encrypt_key(key, ks);
            ctx.block := {block128_f}
HWSM4_encrypt;
            ctx.stream.cbc := nil;
{$IFDEF HWSM4_cbc_encrypt}
            if ctx.mode = EVP_CIPH_CBC_MODE then ctx.stream.cbc = {cbc128_f}
HWSM4_cbc_encrypt;
            else
{$ENDIF}
{$IFDEF HWSM4_ecb_encrypt}
            if ctx.mode = EVP_CIPH_ECB_MODE then ctx.stream.ecb = (ecb128_f)HWSM4_ecb_encrypt;
            else
{$ENDIF}
{$IFDEF HWSM4_ctr32_encrypt_blocks}
            if ctx.mode = EVP_CIPH_CTR_MODE then ctx.stream.ctr = (ctr128_f)HWSM4_ctr32_encrypt_blocks;
            else
{$ENDIF}
            (void)0;            { terminate potentially open 'else' }
        end;
 else
{$ENDIF}
        begin
            ossl_sm4_set_key(key, ks);
            ctx.block := Pblock128_f(@ossl_sm4_encrypt)^;
        end;
    end
    else
    begin
{$IFDEF HWSM4_CAPABLE}
        if HWSM4_CAPABLE then begin
            HWSM4_set_decrypt_key(key, ks);
            ctx.block := {block128_f}
HWSM4_decrypt;
            ctx.stream.cbc := nil;
{$IFDEF HWSM4_cbc_encrypt}
            if ctx.mode = EVP_CIPH_CBC_MODE then ctx.stream.cbc = {cbc128_f}
HWSM4_cbc_encrypt;
{$ENDIF}
{$IFDEF HWSM4_ecb_encrypt}
            if ctx.mode = EVP_CIPH_ECB_MODE then ctx.stream.ecb = (ecb128_f)HWSM4_ecb_encrypt;
{$ENDIF}
        end;
 else
{$ENDIF}
        begin
            ossl_sm4_set_key(key, ks);
            ctx.block := Pblock128_f(@ossl_sm4_decrypt)^;
        end;
    end;
    Result := 1;
end;

end.
