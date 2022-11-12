unit OpenSSL3.providers.implementations.ciphers.cipher_aes_hw;

interface
uses OpenSSL.Api;//OpenSSL3.providers.implementations.ciphers.ciphercommon;

function ossl_prov_cipher_hw_aes_cfb1( keybits : size_t):PPROV_CIPHER_HW;
function cipher_hw_aes_initkey( dat : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
procedure cipher_hw_aes_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
function ossl_prov_cipher_hw_aes_ecb( keybits : size_t):PPROV_CIPHER_HW;
function ossl_prov_cipher_hw_aes_cbc( keybits : size_t):PPROV_CIPHER_HW;
function ossl_prov_cipher_hw_aes_ofb128( keybits : size_t):PPROV_CIPHER_HW;
function ossl_prov_cipher_hw_aes_cfb128( keybits : size_t):PPROV_CIPHER_HW;
function ossl_prov_cipher_hw_aes_cfb8( keybits : size_t):PPROV_CIPHER_HW;
function ossl_prov_cipher_hw_aes_ctr( keybits : size_t):PPROV_CIPHER_HW;
//function ossl_prov_cipher_hw_aes_ocb( keybits : size_t):PPROV_CIPHER_HW;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err,
     OpenSSL3.providers.implementations.ciphers.ciphercommon,
     openssl3.crypto.aes.aes_core, openssl3.crypto.aes.aes_cbc,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb_hw,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw;

(* PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_#mode(size_t keybits)
{
    const  aes_#mode: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_#mode;
    copyctx: cipher_hw_aes_copyctx;
    );
    result = &aes_#mode;
} *)

{
function ossl_prov_cipher_hw_aes_ocb( keybits : size_t):PPROV_CIPHER_HW;

    const  aes_ocb: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_ocb;
    copyctx: cipher_hw_aes_copyctx;
    );
begin
    result := @aes_ocb;
end; }



//PROV_CIPHER_HW_aes_mode(ctr)
function ossl_prov_cipher_hw_aes_ctr( keybits : size_t):PPROV_CIPHER_HW;

    const  aes_ctr: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_ctr;
    copyctx: cipher_hw_aes_copyctx;
    );
begin
    result := @aes_ctr;
end;



function ossl_prov_cipher_hw_aes_cfb8( keybits : size_t):PPROV_CIPHER_HW;

    const  aes_cfb8: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_cfb8;
    copyctx: cipher_hw_aes_copyctx;
    );
begin
    result := @aes_cfb8;
end;

function ossl_prov_cipher_hw_aes_cfb128( keybits : size_t):PPROV_CIPHER_HW;

    const  aes_cfb128: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_cfb128;
    copyctx: cipher_hw_aes_copyctx;
    );
begin
    result := @aes_cfb128;
end;

//PROV_CIPHER_HW_aes_mode(ofb128)
function ossl_prov_cipher_hw_aes_ofb128( keybits : size_t):PPROV_CIPHER_HW;
const
  aes_ofb128 : TPROV_CIPHER_HW= (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_ofb128;
    copyctx: cipher_hw_aes_copyctx;
    );
begin
    result := @aes_ofb128;
end;

//PROV_CIPHER_HW_aes_mode(cbc)
function ossl_prov_cipher_hw_aes_cbc( keybits : size_t):PPROV_CIPHER_HW;
const
   aes_cbc: TPROV_CIPHER_HW  = (
     init: cipher_hw_aes_initkey;
     cipher: ossl_cipher_hw_generic_cbc;
     copyctx: cipher_hw_aes_copyctx;
   );
begin
    //PROV_CIPHER_HW_select(mode)
    Result := @aes_cbc;
end;


function ossl_prov_cipher_hw_aes_ecb( keybits : size_t):PPROV_CIPHER_HW;
const
   aes_ecb: TPROV_CIPHER_HW = (
    init: cipher_hw_aes_initkey;
    cipher: ossl_cipher_hw_generic_ecb;
    copyctx: cipher_hw_aes_copyctx
   );
begin
    //PROV_CIPHER_HW_select(mode)
    result := @aes_ecb;
end;

procedure cipher_hw_aes_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
var
  sctx, dctx : PPROV_AES_CTX;
begin
    sctx := PPROV_AES_CTX ( src);
    dctx := PPROV_AES_CTX ( dst);
    dctx^ := sctx^;
    dst.ks := @dctx.ks.ks;
end;


function cipher_hw_aes_initkey( dat : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  ret : integer;
  adat : PPROV_AES_CTX;
  ks : PAES_KEY;
begin
    adat := PPROV_AES_CTX ( dat);
    ks := @adat.ks.ks;
    dat.ks := ks;
    if ( (dat.mode = EVP_CIPH_ECB_MODE)  or  (dat.mode = EVP_CIPH_CBC_MODE) )  and
       (0 >= dat.enc) then
    begin
{$IFDEF HWAES_CAPABLE}
        if HWAES_CAPABLE then
        begin
            ret := HWAES_set_decrypt_key(key, keylen * 8, ks);
            dat.block := (block128_f)HWAES_decrypt;
            dat.stream.cbc := nil;
{$IFDEF HWAES_cbc_encrypt}
            if dat.mode = EVP_CIPH_CBC_MODE then
               dat.stream.cbc = (cbc128_f)HWAES_cbc_encrypt;
{$ENDIF}
{$IFDEF HWAES_ecb_encrypt}
            if dat.mode = EVP_CIPH_ECB_MODE then
               dat.stream.ecb = (ecb128_f)HWAES_ecb_encrypt;
{$ENDIF}
        end
        else
{$ENDIF}
{$IFDEF BSAES_CAPABLE}
        if BSAES_CAPABLE  and  dat.mode = EVP_CIPH_CBC_MODE then
        begin
            ret := AES_set_decrypt_key(key, keylen * 8, ks);
            dat.block := (block128_f)AES_decrypt;
            dat.stream.cbc := (cbc128_f)ossl_bsaes_cbc_encrypt;
        end
        else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
        if VPAES_CAPABLE then
        begin
            ret := vpaes_set_decrypt_key(key, keylen * 8, ks);
            dat.block := (block128_f)vpaes_decrypt;
            dat.stream.cbc := (dat.mode = EVP_CIPH_CBC_MODE)
                              ?(cbc128_f)vpaes_cbc_encrypt : nil;
        end
        else
{$ENDIF}
        begin
            ret := AES_set_decrypt_key(key, keylen * 8, ks);
            dat.block := AES_decrypt;//block128_f(AES_decrypt);
            if ( dat.mode = EVP_CIPH_CBC_MODE) then
               dat.stream.cbc := {cbc128_f}AES_cbc_encrypt
            else
              dat.stream.cbc := nil;
        end;
    end
    else
{$IFDEF HWAES_CAPABLE}
    if HWAES_CAPABLE then
    begin
        ret := HWAES_set_encrypt_key(key, keylen * 8, ks);
        dat.block := (block128_f)HWAES_encrypt;
        dat.stream.cbc := nil;
{$IFDEF HWAES_cbc_encrypt}
        if dat.mode = EVP_CIPH_CBC_MODE then
           dat.stream.cbc := (cbc128_f)HWAES_cbc_encrypt
        else
{$ENDIF}
{$IFDEF HWAES_ecb_encrypt}
        if dat.mode = EVP_CIPH_ECB_MODE then d
           at.stream.ecb = (ecb128_f)HWAES_ecb_encrypt;
        else
{$ENDIF}
{$IFDEF HWAES_ctr32_encrypt_blocks}
        if dat.mode = EVP_CIPH_CTR_MODE then
           dat.stream.ctr = (ctr128_f)HWAES_ctr32_encrypt_blocks
        else
{$endif}
           (void)0;            { terminate potentially open 'else' }
    end
    else
{$ENDIF}
{$IFDEF BSAES_CAPABLE}
    if BSAES_CAPABLE  and  dat.mode = EVP_CIPH_CTR_MODE then
    begin
        ret := AES_set_encrypt_key(key, keylen * 8, ks);
        dat.block := (block128_f)AES_encrypt;
        dat.stream.ctr := (ctr128_f)ossl_bsaes_ctr32_encrypt_blocks;
    end
    else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
    if VPAES_CAPABLE then
    begin
        ret := vpaes_set_encrypt_key(key, keylen * 8, ks);
        dat.block := (block128_f)vpaes_encrypt;
        dat.stream.cbc := (dat.mode = EVP_CIPH_CBC_MODE)
                          ? (cbc128_f)vpaes_cbc_encrypt : nil;
    end
    else
{$ENDIF}
    begin
        ret := AES_set_encrypt_key(key, keylen * 8, ks);
        dat.block := {block128_f}AES_encrypt;
        if (dat.mode = EVP_CIPH_CBC_MODE) then
           dat.stream.cbc := {cbc128_f}AES_cbc_encrypt
        else
           dat.stream.cbc := nil;
{$IFDEF AES_CTR_ASM}
        if dat.mode = EVP_CIPH_CTR_MODE then
           dat.stream.ctr = (ctr128_f)AES_ctr32_encrypt;
{$ENDIF}
    end;
    if ret < 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        Exit(0);
    end;
    Result := 1;
end;

function ossl_prov_cipher_hw_aes_cfb1( keybits : size_t):PPROV_CIPHER_HW;
const
    aes_cfb1: TPROV_CIPHER_HW = (
          init:cipher_hw_aes_initkey;
          cipher:ossl_cipher_hw_generic_cfb1;
          copyctx:cipher_hw_aes_copyctx
    );
begin
   Result := @aes_cfb1;
end;




end.
