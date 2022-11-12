unit OpenSSL3.providers.implementations.ciphers.cipher_aes_xts_hw;

interface
uses OpenSSL.Api;

function ossl_prov_cipher_hw_aes_xts( keybits : size_t):PPROV_CIPHER_HW;
function cipher_hw_aes_xts_generic_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
procedure cipher_hw_aes_xts_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);

const  aes_generic_xts: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_xts_generic_initkey;
    cipher: nil;
    copyctx: cipher_hw_aes_xts_copyctx
);



implementation
uses openssl3.crypto.aes.aes_core;

procedure cipher_hw_aes_xts_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
var
  sctx, dctx : PPROV_AES_XTS_CTX;
begin
    sctx := PPROV_AES_XTS_CTX (src);
    dctx := PPROV_AES_XTS_CTX (dst);
    dctx^ := sctx^;
    dctx.xts.key1 := @dctx.ks1.ks;
    dctx.xts.key2 := @dctx.ks2.ks;
end;


function cipher_hw_aes_xts_generic_initkey(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  xctx       : PPROV_AES_XTS_CTX;
  bytes, bits : size_t;
  stream_enc,
  stream_dec : TOSSL_xts_stream_fn;
begin
    xctx := PPROV_AES_XTS_CTX (ctx);
    stream_enc := nil;
    stream_dec := nil;
{$IFDEF AES_XTS_ASM}
    stream_enc := AES_xts_encrypt;
    stream_dec := AES_xts_decrypt;
{$endif} { AES_XTS_ASM }
{$IFDEF HWAES_CAPABLE}
    if HWAES_CAPABLE then begin
{$IFDEF HWAES_xts_encrypt}
        stream_enc := HWAES_xts_encrypt;
{$endif} { HWAES_xts_encrypt }
{$IFDEF HWAES_xts_decrypt}
        stream_dec := HWAES_xts_decrypt;
{$endif} { HWAES_xts_decrypt }
        XTS_SET_KEY_FN(HWAES_set_encrypt_key, HWAES_set_decrypt_key,
                       HWAES_encrypt, HWAES_decrypt,
                       stream_enc, stream_dec);
        Exit(1);
    end
    else
{$endif} { HWAES_CAPABLE }
{$IFDEF BSAES_CAPABLE}
    if BSAES_CAPABLE then begin
        stream_enc := ossl_bsaes_xts_encrypt;
        stream_dec := ossl_bsaes_xts_decrypt;
    end;
 else
{$endif} { BSAES_CAPABLE }
{$IFDEF VPAES_CAPABLE}
    if VPAES_CAPABLE then begin
        XTS_SET_KEY_FN(vpaes_set_encrypt_key, vpaes_set_decrypt_key,
                       vpaes_encrypt, vpaes_decrypt, stream_enc, stream_dec);
        Exit(1);
    end;
 else
{$endif} { VPAES_CAPABLE }
    begin
        //(void)0;
    end;
    begin
        //XTS_SET_KEY_FN(AES_set_encrypt_key, AES_set_decrypt_key,
         //              AES_encrypt, AES_decrypt, stream_enc, stream_dec);
       bytes := keylen div 2;
       bits := bytes * 8;
       if ctx.enc > 0 then
       begin
          AES_set_encrypt_key(key, bits, @xctx.ks1.ks);
          xctx.xts.block1 := {block128_f}AES_encrypt;
       end
       else
       begin
          AES_set_decrypt_key(key, bits, @xctx.ks1.ks);
          xctx.xts.block1 := {block128_f}AES_decrypt;
       end;
       AES_set_encrypt_key(key + bytes, bits, @xctx.ks2.ks);
       xctx.xts.block2 := {block128_f}AES_encrypt;
       xctx.xts.key1 := @xctx.ks1;
       xctx.xts.key2 := @xctx.ks2;
       if ctx.enc > 0 then
          xctx.stream :=  stream_enc
       else
          xctx.stream := stream_dec;
    end;
    Result := 1;
end;



function ossl_prov_cipher_hw_aes_xts( keybits : size_t):PPROV_CIPHER_HW;
begin
    //PROV_CIPHER_HW_select_xts
    Result := @aes_generic_xts;
end;


end.
