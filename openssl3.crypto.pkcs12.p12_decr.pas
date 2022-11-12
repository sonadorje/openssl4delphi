unit openssl3.crypto.pkcs12.p12_decr;

interface
 uses OpenSSL.Api;

function PKCS12_item_i2d_encrypt_ex(algor : PX509_ALGOR;const it : PASN1_ITEM; pass : PUTF8Char; passlen : integer; obj : Pointer; zbuf : integer; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PASN1_OCTET_STRING;
function PKCS12_pbe_crypt_ex(const algor : PX509_ALGOR; pass : PUTF8Char; passlen : integer;const _in : PByte; inlen : integer; data : PPByte; datalen : PInteger; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PByte;
function PKCS12_item_decrypt_d2i_ex(const algor : PX509_ALGOR; it : PASN1_ITEM; pass : PUTF8Char; passlen : integer;const oct : PASN1_OCTET_STRING; zbuf : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):Pointer;

implementation
uses openssl3.crypto.asn1.p5_pbev2,               openssl3.crypto.asn1.p5_pbe,
     openssl3.crypto.asn1.tasn_enc,               openssl3.crypto.evp.evp_pbe,
     openssl3.crypto.evp.evp_enc,                 openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print,               OpenSSL3.Err,
     openssl3.crypto.bio.bio_dump,                openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.evp.evp_lib,                 openssl3.crypto.mem;




function PKCS12_item_decrypt_d2i_ex(const algor : PX509_ALGOR; it : PASN1_ITEM; pass : PUTF8Char; passlen : integer;const oct : PASN1_OCTET_STRING; zbuf : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):Pointer;
var
  _out, p : PByte;
  ret : Pointer;
  outlen : integer;
  trc_out: PBIO ;
begin
    _out := nil;
    outlen := 0;
    if nil = PKCS12_pbe_crypt_ex(algor, pass, passlen, oct.data, oct.length,
                             @_out, @outlen, 0, libctx, propq) then
        Exit(nil);
    p := _out;
    trc_out := nil;
    if Boolean(0) then
    begin
        BIO_printf(trc_out, #10, []);
        BIO_dump(trc_out, _out, outlen);
        BIO_printf(trc_out, #10, []);
    end;

    ret := ASN1_item_d2i(nil, @p, outlen, it);
    if zbuf > 0 then
       OPENSSL_cleanse(_out, outlen);
    if nil = ret then
       ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
    OPENSSL_free(_out);
    Result := ret;
end;

function PKCS12_pbe_crypt_ex(const algor : PX509_ALGOR; pass : PUTF8Char; passlen : integer;const _in : PByte; inlen : integer; data : PPByte; datalen : PInteger; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PByte;
var
    _out        : PByte;
    outlen,
    i           : integer;
    ctx         : PEVP_CIPHER_CTX;
    max_out_len,
    mac_len     : integer;
    label _err ;
begin
    _out := nil;
    ctx := EVP_CIPHER_CTX_new();
    mac_len := 0;
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    { Process data }
    if 0>= EVP_PBE_CipherInit_ex(algor.algorithm, pass, passlen,
                               algor.parameter, ctx, en_de, libctx, propq) then
        goto _err ;
    {
     * GOST algorithm specifics:
     * OMAC algorithm calculate and encrypt MAC of the encrypted objects
     * It's appended to encrypted text on encrypting
     * MAC should be processed on decrypting separately from plain text
     }
    max_out_len := inlen + EVP_CIPHER_CTX_get_block_size(ctx);
    if (EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx))
                and EVP_CIPH_FLAG_CIPHER_WITH_MAC) <> 0 then
    begin
        if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 0, @mac_len) < 0 then
        begin
            ERR_raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
        if EVP_CIPHER_CTX_is_encrypting(ctx) >0 then
        begin
            max_out_len  := max_out_len + mac_len;
        end
        else
        begin
            if inlen < mac_len then
            begin
                ERR_raise(ERR_LIB_PKCS12, PKCS12_R_UNSUPPORTED_PKCS12_MODE);
                goto _err ;
            end;
            inlen  := inlen - mac_len;
            if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                    int(mac_len), PByte( _in) +inlen ) < 0 then
            begin
                ERR_raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
        end;
    end;
    _out := OPENSSL_malloc(max_out_len );
    if _out = nil then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if 0>= EVP_CipherUpdate(ctx, _out, @i, _in, inlen )then
    begin
        OPENSSL_free(Pointer(_out));
        _out := nil;
        ERR_raise(ERR_LIB_PKCS12, ERR_R_EVP_LIB);
        goto _err ;
    end;
    outlen := i;
    if 0>= EVP_CipherFinal_ex(ctx, _out + i, @i) then
    begin
        OPENSSL_free(Pointer(_out));
        _out := nil;
        ERR_raise_data(ERR_LIB_PKCS12, PKCS12_R_PKCS12_CIPHERFINAL_ERROR,
                   get_result(passlen = 0 , 'empty password'
                       , 'maybe wrong password'));
        goto _err ;
    end;
    outlen  := outlen + i;
    if (EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx))
                and EVP_CIPH_FLAG_CIPHER_WITH_MAC) <> 0  then
    begin
        if EVP_CIPHER_CTX_is_encrypting(ctx) >0 then
        begin
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                int (mac_len), _out+outlen) < 0)  then
            begin
                ERR_raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
            outlen  := outlen + mac_len;
        end;
    end;
    if datalen <> nil then
       datalen^ := outlen;
    if data<>nil then
       data^ := _out;
 _err:
    EVP_CIPHER_CTX_free(ctx);
    Exit(_out);
end;


function PKCS12_item_i2d_encrypt_ex(algor : PX509_ALGOR;const it : PASN1_ITEM; pass : PUTF8Char; passlen : integer; obj : Pointer; zbuf : integer; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PASN1_OCTET_STRING;
var
  oct : PASN1_OCTET_STRING;
  _in : PByte;
  inlen : integer;
  label _err;
begin
    oct := nil;
    _in := nil;
    oct := ASN1_OCTET_STRING_new();
    if oct = nil then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    inlen := ASN1_item_i2d(obj, @_in, it);
    if nil = _in then
    begin
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCODE_ERROR);
        goto _err ;
    end;
    if nil = PKCS12_pbe_crypt_ex(algor, pass, passlen, _in, inlen, @oct.data,
                             @oct.length, 1, ctx, propq ) then
    begin
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR);
        OPENSSL_free(Pointer(_in));
        goto _err ;
    end;
    if zbuf > 0 then
       OPENSSL_cleanse(_in, inlen);
    OPENSSL_free(Pointer(_in));
    Exit(oct);
 _err:
    ASN1_OCTET_STRING_free(oct);
    Result := nil;
end;








end.
