unit openssl3.crypto.evp.e_aes;

interface
uses OpenSSL.Api;

const
  WRAP_FLAGS  =    (EVP_CIPH_WRAP_MODE
                or EVP_CIPH_CUSTOM_IV or EVP_CIPH_FLAG_CUSTOM_CIPHER
                or EVP_CIPH_ALWAYS_CALL_INIT or EVP_CIPH_FLAG_DEFAULT_ASN1);

function EVP_aes_128_cbc:PEVP_CIPHER;
function EVP_aes_128_ecb:PEVP_CIPHER;
function EVP_aes_128_ofb:PEVP_CIPHER;
function EVP_aes_128_cfb128:PEVP_CIPHER;
function EVP_aes_128_cfb1:PEVP_CIPHER;
function EVP_aes_128_cfb8:PEVP_CIPHER;
function EVP_aes_128_ctr:PEVP_CIPHER;
function EVP_aes_192_cbc:PEVP_CIPHER;
function EVP_aes_192_ecb:PEVP_CIPHER;
function EVP_aes_192_ofb:PEVP_CIPHER;
function EVP_aes_192_cfb128:PEVP_CIPHER;
function EVP_aes_192_cfb1:PEVP_CIPHER;
function EVP_aes_192_cfb8:PEVP_CIPHER;
function EVP_aes_192_ctr:PEVP_CIPHER;
function EVP_aes_256_cbc:PEVP_CIPHER;
function EVP_aes_256_ecb:PEVP_CIPHER;
function EVP_aes_256_ofb:PEVP_CIPHER;
function EVP_aes_256_cfb128:PEVP_CIPHER;
function EVP_aes_256_cfb1:PEVP_CIPHER;
function EVP_aes_256_cfb8:PEVP_CIPHER;
function EVP_aes_256_ctr:PEVP_CIPHER;
function aes_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
function aes_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_cfb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_cfb8_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_cfb1_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_ctr_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function EVP_aes_128_gcm:PEVP_CIPHER;
function EVP_aes_192_gcm:PEVP_CIPHER;
function EVP_aes_256_gcm:PEVP_CIPHER;
function aes_gcm_init_key(ctx : PEVP_CIPHER_CTX;key, iv: PByte; enc : integer):integer;
function aes_gcm_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_gcm_tls_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_gcm_cleanup( c : PEVP_CIPHER_CTX):integer;
function aes_gcm_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
procedure ctr64_inc( counter : PByte);
function EVP_aes_128_ocb:PEVP_CIPHER;
function EVP_aes_192_ocb:PEVP_CIPHER;
function EVP_aes_256_ocb:PEVP_CIPHER;
function aes_ocb_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
function aes_ocb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_ocb_cleanup( c : PEVP_CIPHER_CTX):integer;
function aes_ocb_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
function EVP_aes_128_xts:PEVP_CIPHER;
function EVP_aes_256_xts:PEVP_CIPHER;
function aes_xts_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
function aes_xts_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_xts_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
function EVP_aes_128_ccm:PEVP_CIPHER;
function EVP_aes_192_ccm:PEVP_CIPHER;
function EVP_aes_256_ccm:PEVP_CIPHER;
function aes_ccm_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
function aes_ccm_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_ccm_tls_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function aes_ccm_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
function EVP_aes_128_wrap:PEVP_CIPHER;
function aes_wrap_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
function aes_wrap_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inlen : size_t):integer;
function EVP_aes_128_wrap_pad:PEVP_CIPHER;
function EVP_aes_192_wrap:PEVP_CIPHER;
function EVP_aes_192_wrap_pad:PEVP_CIPHER;
function EVP_aes_256_wrap:PEVP_CIPHER;
function EVP_aes_256_wrap_pad:PEVP_CIPHER;

var
  aes_128_ccm : TEVP_CIPHER  { 896,1, ($7==$10001||$7==$10004?2:1)*128/8, 12, $200000 | (0 | $10 | $100000 | $20 | $40 | $400 | $800)|$7, 1, aes_ccm_init_key, aes_ccm_cipher, Pointer(0) , sizeof(EVP_AES_CCM_CTX), Pointer(0) ,Pointer(0) ,aes_ccm_ctrl,Pointer(0)  };
  aes_192_ccm : TEVP_CIPHER  { 899,1, ($7==$10001||$7==$10004?2:1)*192/8, 12, $200000 | (0 | $10 | $100000 | $20 | $40 | $400 | $800)|$7, 1, aes_ccm_init_key, aes_ccm_cipher, Pointer(0) , sizeof(EVP_AES_CCM_CTX), Pointer(0) ,Pointer(0) ,aes_ccm_ctrl,Pointer(0)  };
  aes_256_ccm, aes_128_wrap : TEVP_CIPHER  { 902,1, ($7==$10001||$7==$10004?2:1)*256/8, 12, $200000 | (0 | $10 | $100000 | $20 | $40 | $400 | $800)|$7, 1, aes_ccm_init_key, aes_ccm_cipher, Pointer(0) , sizeof(EVP_AES_CCM_CTX), Pointer(0) ,Pointer(0) ,aes_ccm_ctrl,Pointer(0)  };
  aes_128_wrap_pad : TEVP_CIPHER;
  aes_192_wrap : TEVP_CIPHER;
  aes_192_wrap_pad : TEVP_CIPHER;
  aes_256_wrap : TEVP_CIPHER;
  aes_256_wrap_pad : TEVP_CIPHER;
  aes_128_cbc,
  aes_128_ecb,
  aes_128_ofb,
  aes_128_cfb,
  aes_128_cfb1,
  aes_128_cfb8,
  aes_128_ctr,
  aes_192_cbc,
  aes_192_ecb,
  aes_192_ofb,
  aes_192_cfb,
  aes_192_cfb1,
  aes_192_cfb8,
  aes_192_ctr,
  aes_256_cbc,
  aes_256_ecb,
  aes_256_ofb,
  aes_256_cfb,
  aes_256_cfb1,
  aes_256_cfb8,
  aes_256_ctr  : TEVP_CIPHER;
  aes_128_gcm, aes_192_gcm, aes_256_gcm : TEVP_CIPHER;
  aes_128_ocb, aes_192_ocb, aes_256_ocb: TEVP_CIPHER;
  aes_128_xts, aes_256_xts: TEVP_CIPHER;
  allow_insecure_decrypt: int = 1;

implementation

uses openssl3.crypto.evp.evp_lib,                openssl3.crypto.evp,
     OpenSSL3.Err,                               openssl3.crypto.modes.cbc128,
     openssl3.crypto.modes.ofb128,               openssl3.crypto.modes.cfb128,
     openssl3.crypto.modes.ctr128,               openssl3.crypto.modes.gcm128,
     openssl3.crypto.evp.evp_enc,                openssl3.crypto.cpuid,
     openssl3.crypto.mem,                        openssl3.crypto.rand.rand_lib,
     openssl3.crypto.modes.ocb128,               openssl3.crypto.modes.xts128,
     OpenSSL3.crypto.modes.ccm128,               openssl3.crypto.modes.wrap128,
     openssl3.crypto.aes.aes_core,               openssl3.crypto.aes.aes_cbc;

function EVP_aes_256_wrap_pad:PEVP_CIPHER;
begin
    Result := @aes_256_wrap_pad;
end;

function EVP_aes_256_wrap:PEVP_CIPHER;
begin
    Result := @aes_256_wrap;
end;

function EVP_aes_192_wrap_pad:PEVP_CIPHER;
begin
    Result := @aes_192_wrap_pad;
end;


function EVP_aes_192_wrap:PEVP_CIPHER;
begin
    Result := @aes_192_wrap;
end;



function EVP_aes_128_wrap_pad:PEVP_CIPHER;
begin
    Result := @aes_128_wrap_pad;
end;



function aes_wrap_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inlen : size_t):integer;
var
  wctx : PEVP_AES_WRAP_CTX;
  rv : size_t;
   pad : integer;
begin
    wctx := PEVP_AES_WRAP_CTX (EVP_CIPHER_CTX_get_cipher_data(ctx));
    { AES wrap with padding has IV length of 4, without padding 8 }
    pad := int(EVP_CIPHER_CTX_get_iv_length(ctx) = 4);
    { No final operation so always return zero length }
    if nil =_in then Exit(0);
    { Input length must always be non-zero }
    if 0>=inlen then Exit(-1);
    { If decrypting need at least 16 bytes and multiple of 8 }
    if (0>=EVP_CIPHER_CTX_is_encrypting(ctx))  and ( (inlen < 16)  or  (inlen and $7 > 0))  then
        Exit(-1);
    { If not padding input must be multiple of 8 }
    if (0>=pad)  and  (inlen and $7 > 0) then Exit(-1);
    if ossl_is_partially_overlapping(_out, _in, inlen) > 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
        Exit(0);
    end;
    if nil = _out then
    begin
        if EVP_CIPHER_CTX_is_encrypting(ctx) > 0 then
        begin
            { If padding round up to multiple of 8 }
            if pad > 0 then
                inlen := (inlen + 7) div 8 * 8;
            { 8 byte prefix }
            Exit(inlen + 8);
        end
        else
        begin
            {
             * If not padding output will be exactly 8 bytes smaller than
             * input. If padding it will be at least 8 bytes smaller but we
             * don't know how much.
             }
            Exit(inlen - 8);
        end;
    end;
    if pad > 0 then
    begin
        if EVP_CIPHER_CTX_is_encrypting(ctx) > 0 then
            rv := CRYPTO_128_wrap_pad(@wctx.ks.ks, wctx.iv,
                                     _out, _in, inlen,
                                     {block128_f}AES_encrypt)
        else
            rv := CRYPTO_128_unwrap_pad(@wctx.ks.ks, wctx.iv,
                                       _out, _in, inlen,
                                       {block128_f} AES_decrypt);
    end
    else
    begin
        if EVP_CIPHER_CTX_is_encrypting(ctx ) > 0 then
            rv := CRYPTO_128_wrap(@wctx.ks.ks, wctx.iv,
                                 _out, _in, inlen, {block128_f}AES_encrypt)
        else
            rv := CRYPTO_128_unwrap(@wctx.ks.ks, wctx.iv,
                                   _out, _in, inlen, {block128_f}AES_decrypt);
    end;
    Result := get_result(rv > 0, int(rv) , -1);
end;


function aes_wrap_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
var
  len : integer;
  wctx : PEVP_AES_WRAP_CTX;
begin
    wctx := PEVP_AES_WRAP_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (iv = nil)  and  (key = nil) then Exit(1);
    if key <> nil then
    begin
        if EVP_CIPHER_CTX_is_encrypting(ctx)>0 then
            AES_set_encrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                @wctx.ks.ks)
        else
            AES_set_decrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                @wctx.ks.ks);
        if iv = nil then wctx.iv := nil;
    end;
    if iv <> nil then
    begin
        len := EVP_CIPHER_CTX_get_iv_length(ctx);
        if (len  < 0) then
            Exit(0);
        memcpy(@ctx.iv, iv, len);
        wctx.iv := @ctx.iv;
    end;
    Result := 1;
end;



function EVP_aes_128_wrap:PEVP_CIPHER;
begin
    Result := @aes_128_wrap;
end;



function aes_ccm_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
var
    cctx     : PEVP_AES_CCM_CTX;
    len      : uint16;
    _out     : PEVP_CIPHER_CTX;
    cctx_out : PEVP_AES_CCM_CTX;
    label fall;
begin
    cctx := PEVP_AES_CCM_CTX (EVP_CIPHER_CTX_get_cipher_data(c));
    case &type of
        EVP_CTRL_INIT:
        begin
            cctx.key_set := 0;
            cctx.iv_set := 0;
            cctx.L := 8;
            cctx.M := 12;
            cctx.tag_set := 0;
            cctx.len_set := 0;
            cctx.tls_aad_len := -1;
            Exit(1);
        end;
        EVP_CTRL_GET_IVLEN:
        begin
            PInteger (ptr)^ := 15 - cctx.L;
            Exit(1);
        end;
        EVP_CTRL_AEAD_TLS1_AAD:
        begin
            { Save the AAD for later use }
            if arg <> EVP_AEAD_TLS1_AAD_LEN then Exit(0);
            memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
            cctx.tls_aad_len := arg;
            begin
                len := EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] shl 8
                    or EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
                { Correct length for explicit IV }
                if len < EVP_CCM_TLS_EXPLICIT_IV_LEN then Exit(0);
                len  := len - EVP_CCM_TLS_EXPLICIT_IV_LEN;
                { If decrypting correct for tag too }
                if 0>=EVP_CIPHER_CTX_is_encrypting(c) then
                begin
                    if len < cctx.M then
                        Exit(0);
                    len  := len - cctx.M;
                end;
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] := len  shr  8;
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] := len and $ff;
            end;
            { Extra padding: tag appended to record }
            Exit(cctx.M);
        end;
        EVP_CTRL_CCM_SET_IV_FIXED:
        begin
            { Sanity check length }
            if arg <> EVP_CCM_TLS_FIXED_IV_LEN then Exit(0);
            { Just copy to first part of IV }
            memcpy(@c.iv, ptr, arg);
            Exit(1);
        end;
        EVP_CTRL_AEAD_SET_IVLEN:
        begin
            arg := 15 - arg;
            { fall thru }
            goto fall;
        end;
        EVP_CTRL_CCM_SET_L:
        begin
fall:       if (arg < 2)  or  (arg > 8) then
               Exit(0);
            cctx.L := arg;
            Exit(1);
        end;
        EVP_CTRL_AEAD_SET_TAG:
        begin
            if (arg and 1 >0)  or  (arg < 4)  or  (arg > 16) then
                Exit(0);
            if (EVP_CIPHER_CTX_is_encrypting(c) > 0)   and  (ptr <> nil) then
                Exit(0);
            if ptr <> nil then
            begin
                cctx.tag_set := 1;
                memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
            end;
            cctx.M := arg;
            Exit(1);
        end;
        EVP_CTRL_AEAD_GET_TAG:
        begin
            if (0>=EVP_CIPHER_CTX_is_encrypting(c))  or  (0>=cctx.tag_set) then
                Exit(0);
            if 0>=CRYPTO_ccm128_tag(@cctx.ccm, ptr, size_t(arg)) then
                Exit(0);
            cctx.tag_set := 0;
            cctx.iv_set := 0;
            cctx.len_set := 0;
            Exit(1);
        end;
        EVP_CTRL_COPY:
        begin
            _out := ptr;
            cctx_out := PEVP_AES_CCM_CTX(EVP_CIPHER_CTX_get_cipher_data(_out));
            if cctx.ccm.key <> nil then
            begin
                if cctx.ccm.key <> @cctx.ks then
                    Exit(0);
                cctx_out.ccm.key := @cctx_out.ks;
            end;
            Exit(1);
        end;
        else
            Exit(-1);
    end;
end;



function aes_ccm_tls_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  cctx : PEVP_AES_CCM_CTX;
  ccm : PCCM128_CONTEXT;
  tag : array[0..15] of Byte;
begin
    cctx := PEVP_AES_CCM_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    ccm := @cctx.ccm;
    { Encrypt/decrypt must be performed in place }
    if (_out <> _in)  or  (len < EVP_CCM_TLS_EXPLICIT_IV_LEN + size_t(cctx.M)) then
        Exit(-1);
    { If encrypting set explicit IV from sequence number (start of AAD) }
    if EVP_CIPHER_CTX_is_encrypting(ctx) > 0  then
        memcpy(_out, EVP_CIPHER_CTX_buf_noconst(ctx),
               EVP_CCM_TLS_EXPLICIT_IV_LEN);
    { Get rest of IV from explicit IV }
    memcpy(PByte(@ctx.iv) + EVP_CCM_TLS_FIXED_IV_LEN, _in,
           EVP_CCM_TLS_EXPLICIT_IV_LEN);
    { Correct length value }
    len  := len - (EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx.M);
    if CRYPTO_ccm128_setiv(ccm, @ctx.iv, 15 - cctx.L, len) > 0  then
            Exit(-1);
    { Use saved AAD }
    CRYPTO_ccm128_aad(ccm, EVP_CIPHER_CTX_buf_noconst(ctx),
                      cctx.tls_aad_len);
    { Fix buffer to point to payload }
    _in  := _in + EVP_CCM_TLS_EXPLICIT_IV_LEN;
    _out  := _out + EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if EVP_CIPHER_CTX_is_encrypting(ctx) > 0 then
    begin
        if get_result(Assigned(cctx.str) , CRYPTO_ccm128_encrypt_ccm64(ccm, _in, _out, len,
                                                    cctx.str) ,
            CRYPTO_ccm128_encrypt(ccm, _in, _out, len)) > 0 then
            Exit(-1);
        if 0>=CRYPTO_ccm128_tag(ccm, _out + len, cctx.M) then
            Exit(-1);
        Exit(len + EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx.M);
    end
    else
    begin
        if get_result(Assigned(cctx.str) ,
                      not CRYPTO_ccm128_decrypt_ccm64(ccm, _in, _out, len, cctx.str),
                      not CRYPTO_ccm128_decrypt(ccm, _in, _out, len)) > 0  then
        begin
            if CRYPTO_ccm128_tag(ccm, @tag, cctx.M) > 0 then
            begin
                if 0>=CRYPTO_memcmp(@tag, _in + len, cctx.M) then
                    Exit(len);
            end;
        end;
        OPENSSL_cleanse(_out, len);
        Exit(-1);
    end;
end;


function aes_ccm_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  cctx : PEVP_AES_CCM_CTX;
  ccm : PCCM128_CONTEXT;
  rv : integer;
  tag : array[0..15] of Byte;
begin
    cctx := PEVP_AES_CCM_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    ccm := @cctx.ccm;
    { If not set up, return error }
    if 0>=cctx.key_set then Exit(-1);
    if cctx.tls_aad_len >= 0 then
       Exit(aes_ccm_tls_cipher(ctx, _out, _in, len));
    { EVP_*Final doesn't return any data }
    if (_in = nil)  and  (_out <> nil) then Exit(0);
    if 0>=cctx.iv_set then Exit(-1);
    if nil =_out then
    begin
        if nil =_in then
        begin
            if (CRYPTO_ccm128_setiv(ccm, @ctx.iv,
                                    15 - cctx.L, len) > 0 ) then
                Exit(-1);
            cctx.len_set := 1;
            Exit(len);
        end;
        { If have AAD need message length }
        if 0>=cctx.len_set  and  len then Exit(-1);
        CRYPTO_ccm128_aad(ccm, _in, len);
        Exit(len);
    end;
    { The tag must be set before actually decrypting data }
    if (0>=EVP_CIPHER_CTX_is_encrypting(ctx))  and  (0>=cctx.tag_set) then
        Exit(-1);
    { If not set length yet do it }
    if 0>=cctx.len_set then
    begin
        if CRYPTO_ccm128_setiv(ccm, @ctx.iv, 15 - cctx.L, len) > 0 then
            Exit(-1);
        cctx.len_set := 1;
    end;
    if EVP_CIPHER_CTX_is_encrypting(ctx)>0 then
    begin
        if get_result(Assigned(cctx.str) , CRYPTO_ccm128_encrypt_ccm64(ccm, _in, _out, len,
                                                    cctx.str) ,
            CRYPTO_ccm128_encrypt(ccm, _in, _out, len)) > 0 then
            Exit(-1);
        cctx.tag_set := 1;
        Exit(len);
    end
    else
    begin
        rv := -1;
        if get_result(Assigned(cctx.str),
                      not CRYPTO_ccm128_decrypt_ccm64(ccm, _in, _out, len,
                                                     cctx.str),
                      not CRYPTO_ccm128_decrypt(ccm, _in, _out, len)) > 0  then
        begin
            if CRYPTO_ccm128_tag(ccm, @tag, cctx.M) > 0 then
            begin
                if 0>=CRYPTO_memcmp(@tag, EVP_CIPHER_CTX_buf_noconst(ctx) ,
                                   cctx.M) then
                    rv := len;
            end;
        end;
        if rv = -1 then OPENSSL_cleanse(_out, len);
        cctx.iv_set := 0;
        cctx.tag_set := 0;
        cctx.len_set := 0;
        Exit(rv);
    end;
end;


function aes_ccm_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
var
  cctx : PEVP_AES_CCM_CTX;
begin
    cctx := PEVP_AES_CCM_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (nil =iv)  and  (nil =key) then Exit(1);
    if key <> nil then
       while Boolean(0) do
       begin
{$IFDEF HWAES_CAPABLE}
            if HWAES_CAPABLE then  begin
                HWAES_set_encrypt_key(key,
                                      EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &cctx.ks.ks);
                CRYPTO_ccm128_init(&cctx.ccm, cctx.M, cctx.L,
                                   &cctx.ks, {block128_f}
 HWAES_encrypt);
                cctx.str := nil;
                cctx.key_set := 1;
                break;
            end;
 else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
            if VPAES_CAPABLE then begin
                vpaes_set_encrypt_key(key,
                                      EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &cctx.ks.ks);
                CRYPTO_ccm128_init(&cctx.ccm, cctx.M, cctx.L,
                                   &cctx.ks, {block128_f}
 vpaes_encrypt);
                cctx.str := nil;
                cctx.key_set := 1;
                break;
            end;
{$ENDIF}
            AES_set_encrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                @cctx.ks.ks);
            CRYPTO_ccm128_init(@cctx.ccm, cctx.M, cctx.L,
                               @cctx.ks, {block128_f}AES_encrypt);
            cctx.str := nil;
            cctx.key_set := 1;
        end;

    if iv <> nil then
    begin
        memcpy(@ctx.iv, iv, 15 - cctx.L);
        cctx.iv_set := 1;
    end;
    Result := 1;
end;

function EVP_aes_128_ccm:PEVP_CIPHER;
begin
 Result := @aes_128_ccm;
end;


function EVP_aes_192_ccm:PEVP_CIPHER;
begin
 Result := @aes_192_ccm;
end;


function EVP_aes_256_ccm:PEVP_CIPHER;
begin
 Result := @aes_256_ccm;
end;



function aes_xts_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
var
    xctx     : PEVP_AES_XTS_CTX;
    _out     : PEVP_CIPHER_CTX;
    xctx_out : PEVP_AES_XTS_CTX;
begin
    xctx := PEVP_AES_XTS_CTX (EVP_CIPHER_CTX_get_cipher_data(c));
    if &type = EVP_CTRL_COPY then
    begin
        _out := ptr;
        xctx_out := PEVP_AES_XTS_CTX (EVP_CIPHER_CTX_get_cipher_data(_out));
        if xctx.xts.key1 <> nil then
        begin
            if xctx.xts.key1 <> @xctx.ks1 then
                Exit(0);
            xctx_out.xts.key1 := @xctx_out.ks1;
        end;
        if xctx.xts.key2 <> nil then
        begin
            if xctx.xts.key2 <> @xctx.ks2 then
                Exit(0);
            xctx_out.xts.key2 := @xctx_out.ks2;
        end;
        Exit(1);
    end
    else
    if (&type <> EVP_CTRL_INIT)then
        Exit(-1);
    { key1 and key2 are used as an indicator both key and IV are set }
    xctx.xts.key1 := nil;
    xctx.xts.key2 := nil;
    Result := 1;
end;



function aes_xts_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  xctx : PEVP_AES_XTS_CTX;
begin
    xctx := PEVP_AES_XTS_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (xctx.xts.key1 = nil)
             or  (xctx.xts.key2 = nil)
             or  (_out = nil)
             or  (_in = nil)
             or  (len < AES_BLOCK_SIZE) then Exit(0);
    {
     * Impose a limit of 2^20 blocks per data unit as specified by
     * IEEE Std 1619-2018.  The earlier and obsolete IEEE Std 1619-2007
     * indicated that this was a SHOULD NOT rather than a MUST NOT.
     * NIST SP 800-38E mandates the same limit.
     }
    if len > XTS_MAX_BLOCKS_PER_DATA_UNIT * AES_BLOCK_SIZE then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_XTS_DATA_UNIT_IS_TOO_LARGE);
        Exit(0);
    end;
    if Assigned(xctx.stream) then
       xctx.stream (_in, _out, len,
                         xctx.xts.key1, xctx.xts.key2,
                         @ctx.iv)
    else
    if CRYPTO_xts128_encrypt(@xctx.xts, @ctx.iv, _in, _out, len,
                                   EVP_CIPHER_CTX_is_encrypting(ctx))> 0 then
        Exit(0);
    Result := 1;
end;



function aes_xts_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
var
  xctx : PEVP_AES_XTS_CTX;
  bytes, bits : integer;
begin
    xctx := PEVP_AES_XTS_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (nil =iv)  and  (nil =key) then Exit(1);
    if key <> nil then
    begin
        while Boolean(0) do
        begin
            { The key is two half length keys in reality }
             bytes := EVP_CIPHER_CTX_get_key_length(ctx) div 2;
             bits := bytes * 8;
            {
             * Verify that the two keys are different.
             *
             * This addresses the vulnerability described in Rogaway's
             * September 2004 paper:
             *
             *      'Efficient Instantiations of Tweakable Blockciphers and
             *       Refinements to Modes OCB and PMAC'.
             *      (http://web.cs.ucdavis.edu/~rogaway/papers/offsets.pdf)
             *
             * FIPS 140-2 IG A.9 XTS-AES Key Generation Requirements states
             * that:
             *      'The check for Key_1 <> Key_2 shall be done at any place
             *       BEFORE using the keys in the XTS-AES algorithm to process
             *       data with them.'
             }
            if (0>=allow_insecure_decrypt)  or  (enc > 0)  and
               (CRYPTO_memcmp(key, key + bytes, bytes) = 0) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_XTS_DUPLICATED_KEYS);
                Exit(0);
            end;
{$IFDEF AES_XTS_ASM}
            xctx.stream := enc ? AES_xts_encrypt : AES_xts_decrypt;
{$ELSE} xctx.stream := nil;
{$ENDIF}
            { key_len is two AES keys }
{$IFDEF HWAES_CAPABLE}
            if HWAES_CAPABLE then begin
                if enc then  begin
                    HWAES_set_encrypt_key(key, bits, &xctx.ks.ks[0].ks);
                    xctx.xts.block1 := {block128_f}
 HWAES_encrypt;
{$IFDEF HWAES_xts_encrypt}
                    xctx.stream := HWAES_xts_encrypt;
{$ENDIF}
                end;
 else begin
                    HWAES_set_decrypt_key(key, bits, &xctx.ks.ks[0].ks);
                    xctx.xts.block1 := {block128_f} HWAES_decrypt;
{$IFDEF HWAES_xts_decrypt}
                    xctx.stream := HWAES_xts_decrypt;
{$ENDIF}
                end;
                HWAES_set_encrypt_key(key + bytes, bits, &xctx.ks.ks[1].ks);
                xctx.xts.block2 := {block128_f} HWAES_encrypt;
                xctx.xts.key1 := &xctx.ks.ks[0];
                break;
            end;
 else
{$ENDIF}
{$IFDEF BSAES_CAPABLE}
            if BSAES_CAPABLE then xctx.stream = enc ? ossl_bsaes_xts_encrypt : ossl_bsaes_xts_decrypt;
            else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
            if VPAES_CAPABLE then begin
                if enc then  begin
                    vpaes_set_encrypt_key(key, bits, &xctx.ks.ks[0].ks);
                    xctx.xts.block1 := {block128_f}
 vpaes_encrypt;
                end;
 else begin
                    vpaes_set_decrypt_key(key, bits, &xctx.ks.ks[0].ks);
                    xctx.xts.block1 := {block128_f}
 vpaes_decrypt;
                end;
                vpaes_set_encrypt_key(key + bytes, bits, &xctx.ks.ks[1].ks);
                xctx.xts.block2 := {block128_f}
 vpaes_encrypt;
                xctx.xts.key1 := &xctx.ks.ks[0];
                break;
            end;
 else
{$ENDIF}
                //(void)0;        { terminate potentially open 'else' }
            if enc > 0 then
            begin
                AES_set_encrypt_key(key, bits, @xctx.ks1.ks);
                xctx.xts.block1 := {block128_f} AES_encrypt;
            end
            else
            begin
                AES_set_decrypt_key(key, bits, @xctx.ks1.ks);
                xctx.xts.block1 := {block128_f} AES_decrypt;
            end;
            AES_set_encrypt_key(key + bytes, bits, @xctx.ks2.ks);
            xctx.xts.block2 := {block128_f} AES_encrypt;
            xctx.xts.key1 := @xctx.ks1;
        end;

    end;
    if iv <> nil then
    begin
        xctx.xts.key2 := @xctx.ks2;
        memcpy(@ctx.iv, iv, 16);
    end;
    Result := 1;
end;


function EVP_aes_128_xts:PEVP_CIPHER;
begin
 Result := @aes_128_xts;
end;


function EVP_aes_256_xts:PEVP_CIPHER;
begin
 Result := @aes_256_xts;
end;


function aes_ocb_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
var
    octx     : PEVP_AES_OCB_CTX;
    newc     : PEVP_CIPHER_CTX;
    new_octx : PEVP_AES_OCB_CTX;
begin
    octx := PEVP_AES_OCB_CTX(EVP_CIPHER_CTX_get_cipher_data(c));
    case &type of
        EVP_CTRL_INIT:
        begin
            octx.key_set := 0;
            octx.iv_set := 0;
            octx.ivlen := EVP_CIPHER_get_iv_length(c.cipher);
            octx.iv := @c.iv;
            octx.taglen := 16;
            octx.data_buf_len := 0;
            octx.aad_buf_len := 0;
            Exit(1);
        end;
        EVP_CTRL_GET_IVLEN:
        begin
            PInteger (ptr)^ := octx.ivlen;
            Exit(1);
        end;
        EVP_CTRL_AEAD_SET_IVLEN:
        begin
            { IV len must be 1 to 15 }
            if (arg <= 0)  or  (arg > 15) then Exit(0);
            octx.ivlen := arg;
            Exit(1);
        end;
        EVP_CTRL_AEAD_SET_TAG:
        begin
            if ptr = nil then
            begin
                { Tag len must be 0 to 16 }
                if (arg < 0)  or  (arg > 16) then
                    Exit(0);
                octx.taglen := arg;
                Exit(1);
            end;
            if (arg <> octx.taglen)  or  (EVP_CIPHER_CTX_is_encrypting(c) > 0) then
                Exit(0);
            memcpy(@octx.tag, ptr, arg);
            Exit(1);
        end;
        EVP_CTRL_AEAD_GET_TAG:
        begin
            if (arg <> octx.taglen)  or  (0>=EVP_CIPHER_CTX_is_encrypting(c)) then
                Exit(0);
            memcpy(ptr, @octx.tag, arg);
            Exit(1);
        end;
        EVP_CTRL_COPY:
        begin
            newc := PEVP_CIPHER_CTX (ptr);
            new_octx := PEVP_AES_OCB_CTX(EVP_CIPHER_CTX_get_cipher_data(newc));
            Exit(CRYPTO_ocb128_copy_ctx(@new_octx.ocb, @octx.ocb,
                                          @new_octx.ksenc.ks,
                                          @new_octx.ksdec.ks));
        end;
        else
            Exit(-1);
    end;
end;


function aes_ocb_cleanup( c : PEVP_CIPHER_CTX):integer;
var
  octx : PEVP_AES_OCB_CTX;
begin
    octx := PEVP_AES_OCB_CTX(EVP_CIPHER_CTX_get_cipher_data(c));
    CRYPTO_ocb128_cleanup(@octx.ocb);
    Result := 1;
end;

function aes_ocb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
    buf          : PByte;
    buf_len      : PInteger;
    written_len  : integer;
    trailing_len : size_t;
    octx         : PEVP_AES_OCB_CTX;
    remaining    : uint32;
begin
    written_len := 0;
    octx := PEVP_AES_OCB_CTX (EVP_CIPHER_CTX_get_cipher_data(ctx));
    { If IV or Key not set then return error }
    if 0>=octx.iv_set then Exit(-1);
    if 0>=octx.key_set then Exit(-1);
    if _in <> nil then
    begin
        {
         * Need to ensure we are only passing full blocks to low level OCB
         * routines. We do it here rather than in EVP_EncryptUpdate/
         * EVP_DecryptUpdate because we need to pass full blocks of AAD too
         * and those routines don't support that
         }
        { Are we dealing with AAD or normal data here? }
        if _out = nil then
        begin
            buf := @octx.aad_buf;
            buf_len := @(octx.aad_buf_len);
        end
        else
        begin
            buf := @octx.data_buf;
            buf_len := @(octx.data_buf_len);
            if ossl_is_partially_overlapping(_out + buf_len^, _in, len)>0 then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
                Exit(0);
            end;
        end;
        {
         * If we've got a partially filled buffer from a previous call then
         * use that data first
         }
        if buf_len^ > 0 then
        begin
            remaining := AES_BLOCK_SIZE - ( buf_len^);
            if remaining > len then
            begin
                memcpy(buf + ( buf_len^), _in, len);
                (buf_len)^  := (buf_len)^ + len;
                Exit(0);
            end;
            memcpy(buf + ( buf_len^), _in, remaining);
            {
             * If we get here we've filled the buffer, so process it
             }
            len  := len - remaining;
            _in  := _in + remaining;
            if _out = nil then
            begin
                if 0>=CRYPTO_ocb128_aad(@octx.ocb, buf, AES_BLOCK_SIZE) then
                    Exit(-1);
            end
            else
            if (EVP_CIPHER_CTX_is_encrypting(ctx)>0) then
            begin
                if 0>=CRYPTO_ocb128_encrypt(@octx.ocb, buf, _out,
                                           AES_BLOCK_SIZE) then
                    Exit(-1);
            end
            else
            begin
                if 0>=CRYPTO_ocb128_decrypt(@octx.ocb, buf, _out,
                                           AES_BLOCK_SIZE) then
                    Exit(-1);
            end;
            written_len := AES_BLOCK_SIZE;
            buf_len^ := 0;
            if _out <> nil then
               _out  := _out + AES_BLOCK_SIZE;
        end;
        { Do we have a partial block to handle at the end? }
        trailing_len := len mod AES_BLOCK_SIZE;
        {
         * If we've got some full blocks to handle, then process these first
         }
        if len <> trailing_len then
        begin
            if _out = nil then
            begin
                if 0>=CRYPTO_ocb128_aad(@octx.ocb, _in, len - trailing_len) then
                    Exit(-1);
            end
            else
            if (EVP_CIPHER_CTX_is_encrypting(ctx)>0) then
            begin
                if 0>=CRYPTO_ocb128_encrypt(@octx.ocb, _in, _out, len - trailing_len) then
                   Exit(-1);
            end
            else
            begin
                if 0>=CRYPTO_ocb128_decrypt(@octx.ocb, _in, _out, len - trailing_len) then
                    Exit(-1);
            end;
            written_len  := written_len + (len - trailing_len);
            _in  := _in + (len - trailing_len);
        end;
        { Handle any trailing partial block }
        if trailing_len > 0 then begin
            memcpy(buf, _in, trailing_len);
            buf_len^ := trailing_len;
        end;
        Exit(written_len);
    end
    else
    begin
        {
         * First of all empty the buffer of any partial block that we might
         * have been provided - both for data and AAD
         }
        if octx.data_buf_len > 0 then
        begin
            if EVP_CIPHER_CTX_is_encrypting(ctx) > 0 then
            begin
                if (0>=CRYPTO_ocb128_encrypt(@octx.ocb, @octx.data_buf, _out,
                                           octx.data_buf_len)) then
                    Exit(-1);
            end
            else
            begin
                if 0>=CRYPTO_ocb128_decrypt(@octx.ocb, @octx.data_buf, _out,
                                           octx.data_buf_len) then
                    Exit(-1);
            end;
            written_len := octx.data_buf_len;
            octx.data_buf_len := 0;
        end;
        if octx.aad_buf_len > 0 then
        begin
            if (0>=CRYPTO_ocb128_aad(@octx.ocb, @octx.aad_buf, octx.aad_buf_len)) then
                Exit(-1);
            octx.aad_buf_len := 0;
        end;
        { If decrypting then verify }
        if 0>=EVP_CIPHER_CTX_is_encrypting(ctx) then
        begin
            if octx.taglen < 0 then
                Exit(-1);
            if CRYPTO_ocb128_finish(@octx.ocb, @octx.tag, octx.taglen) <> 0  then
                Exit(-1);
            octx.iv_set := 0;
            Exit(written_len);
        end;
        { If encrypting then just get the tag }
        if CRYPTO_ocb128_tag(@octx.ocb, @octx.tag, 16) <> 1  then
            Exit(-1);
        { Don't reuse the IV }
        octx.iv_set := 0;
        Exit(written_len);
    end;
end;

function aes_ocb_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  octx : PEVP_AES_OCB_CTX;
begin
    octx := PEVP_AES_OCB_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (nil =iv)  and  (nil =key) then Exit(1);
    if key <> nil then
    begin
         while Boolean(0) do
         begin
            {
             * We set both the encrypt and decrypt key here because decrypt
             * needs both. We could possibly optimise to remove setting the
             * decrypt for an encryption operation.
             }
{$IFDEF HWAES_CAPABLE}
            if HWAES_CAPABLE then  begin
                HWAES_set_encrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &octx.ksenc.ks);
                HWAES_set_decrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &octx.ksdec.ks);
                if 0>=CRYPTO_ocb128_init(&octx.ocb,
                                        &octx.ksenc.ks, &octx.ksdec.ks,
                                        {block128_f}
 HWAES_encrypt,
                                        {block128_f}
 HWAES_decrypt,
                                        enc ? HWAES_ocb_encrypt
                                            : HWAES_ocb_decrypt then )
                    Exit(0);
                break;
            end;
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
            if VPAES_CAPABLE then begin
                vpaes_set_encrypt_key(key,
                                      EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &octx.ksenc.ks);
                vpaes_set_decrypt_key(key,
                                      EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &octx.ksdec.ks);
                if 0>=CRYPTO_ocb128_init(&octx.ocb,
                                        &octx.ksenc.ks, &octx.ksdec.ks,
                                        {block128_f} vpaes_encrypt,
                                        {block128_f} vpaes_decrypt,
                                        nil then )
                    Exit(0);
                break;
            end;
{$ENDIF}
            AES_set_encrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                @octx.ksenc.ks);
            AES_set_decrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                @octx.ksdec.ks);
            if 0>=CRYPTO_ocb128_init(@octx.ocb,
                                    @octx.ksenc.ks, @octx.ksdec.ks,
                                    {block128_f} AES_encrypt,
                                    {block128_f} AES_decrypt,
                                    nil )then
                Exit(0);
        end;

        {
         * If we have an iv we can set it directly, otherwise use saved IV.
         }
        if (iv = nil)  and  (octx.iv_set > 0) then
            iv := octx.iv;
        if iv <> nil then
        begin
            if CRYPTO_ocb128_setiv(@octx.ocb, iv, octx.ivlen, octx.taglen) <> 1 then
                Exit(0);
            octx.iv_set := 1;
        end;
        octx.key_set := 1;
    end
    else
    begin
        { If key set use IV, otherwise copy }
        if octx.key_set > 0 then
           CRYPTO_ocb128_setiv(@octx.ocb, iv, octx.ivlen, octx.taglen)
        else
            memcpy(octx.iv, iv, octx.ivlen);
        octx.iv_set := 1;
    end;
    Result := 1;
end;


function EVP_aes_128_ocb:PEVP_CIPHER;
begin
 Result := @aes_128_ocb;
end;


function EVP_aes_192_ocb:PEVP_CIPHER;
begin
 Result := @aes_192_ocb;
end;


function EVP_aes_256_ocb:PEVP_CIPHER;
begin
 Result := @aes_256_ocb;
end;



procedure ctr64_inc( counter : PByte);
var
  n : integer;
  c : Byte;
begin
    n := 8;
    repeat
        PreDec(n);
        c := counter[n];
        Inc(c);
        counter[n] := c;
        if c > 0 then exit;
    until not (n > 0);
end;

function aes_gcm_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
var
    gctx     : PEVP_AES_GCM_CTX;
    len      : uint32;
    _out     : PEVP_CIPHER_CTX;
    gctx_out : PEVP_AES_GCM_CTX;
begin
    gctx := PEVP_AES_GCM_CTX(EVP_CIPHER_CTX_get_cipher_data(c));
    case &type of
        EVP_CTRL_INIT:
        begin
            gctx.key_set := 0;
            gctx.iv_set := 0;
            gctx.ivlen := EVP_CIPHER_get_iv_length(c.cipher);
            gctx.iv := @c.iv;
            gctx.taglen := -1;
            gctx.iv_gen := 0;
            gctx.tls_aad_len := -1;
            Exit(1);
        end;
        EVP_CTRL_GET_IVLEN:
        begin
            PInteger (ptr)^ := gctx.ivlen;
            Exit(1);
        end;
        EVP_CTRL_AEAD_SET_IVLEN:
        begin
            if arg <= 0 then Exit(0);
            { Allocate memory for IV if needed }
            if (arg > EVP_MAX_IV_LENGTH)  and  (arg > gctx.ivlen) then
            begin
                if gctx.iv <> PByte(@c.iv) then
                    OPENSSL_free(gctx.iv);
                gctx.iv := OPENSSL_malloc(arg);
                if gctx.iv = nil then
                begin
                    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                    Exit(0);
                end;
            end;
            gctx.ivlen := arg;
            Exit(1);
        end;
        EVP_CTRL_AEAD_SET_TAG:
        begin
            if (arg <= 0)  or  (arg > 16)  or  (c.encrypt > 0) then Exit(0);
            memcpy(@c.buf, ptr, arg);
            gctx.taglen := arg;
            Exit(1);
        end;
        EVP_CTRL_AEAD_GET_TAG:
        begin
            if (arg <= 0)  or  (arg > 16)  or  (0>=c.encrypt)
                 or  (gctx.taglen < 0) then
                 Exit(0);
            memcpy(ptr, @c.buf, arg);
            Exit(1);
        end;
        EVP_CTRL_GCM_SET_IV_FIXED:
        begin
            { Special case: -1 length restores whole IV }
            if arg = -1 then begin
                memcpy(gctx.iv, ptr, gctx.ivlen);
                gctx.iv_gen := 1;
                Exit(1);
            end;
            {
             * Fixed field must be at least 4 bytes and invocation field at least
             * 8.
             }
            if (arg < 4)  or  (gctx.ivlen - arg < 8) then
                Exit(0);
            if arg > 0 then
               memcpy(gctx.iv, ptr, arg);
            if (c.encrypt > 0)  and  (RAND_bytes(gctx.iv + arg, gctx.ivlen - arg) <= 0) then
                Exit(0);
            gctx.iv_gen := 1;
            Exit(1);
        end;
        EVP_CTRL_GCM_IV_GEN:
        begin
            if (gctx.iv_gen = 0)  or  (gctx.key_set = 0) then
               Exit(0);
            CRYPTO_gcm128_setiv(@gctx.gcm, gctx.iv, gctx.ivlen);
            if (arg <= 0)  or  (arg > gctx.ivlen) then
               arg := gctx.ivlen;
            memcpy(ptr, gctx.iv + gctx.ivlen - arg, arg);
            {
             * Invocation field will be at least 8 bytes in size and so no need
             * to check wrap around or increment more than last 8 bytes.
             }
            ctr64_inc(gctx.iv + gctx.ivlen - 8);
            gctx.iv_set := 1;
            Exit(1);
        end;
        EVP_CTRL_GCM_SET_IV_INV:
        begin
            if (gctx.iv_gen = 0)  or  (gctx.key_set = 0)  or  (c.encrypt > 0) then
                Exit(0);
            memcpy(gctx.iv + gctx.ivlen - arg, ptr, arg);
            CRYPTO_gcm128_setiv(@gctx.gcm, gctx.iv, gctx.ivlen);
            gctx.iv_set := 1;
            Exit(1);
        end;
        EVP_CTRL_AEAD_TLS1_AAD:
        begin
            { Save the AAD for later use }
            if arg <> EVP_AEAD_TLS1_AAD_LEN then Exit(0);
            memcpy(@c.buf, ptr, arg);
            gctx.tls_aad_len := arg;
            gctx.tls_enc_records := 0;
            begin
                len := c.buf[arg - 2] shl 8 or c.buf[arg - 1];
                { Correct length for explicit IV }
                if len < EVP_GCM_TLS_EXPLICIT_IV_LEN then Exit(0);
                len  := len - EVP_GCM_TLS_EXPLICIT_IV_LEN;
                { If decrypting correct for tag too }
                if 0>=c.encrypt then begin
                    if len < EVP_GCM_TLS_TAG_LEN then
                        Exit(0);
                    len  := len - EVP_GCM_TLS_TAG_LEN;
                end;
                c.buf[arg - 2] := len  shr  8;
                c.buf[arg - 1] := len and $ff;
            end;
            { Extra padding: tag appended to record }
            Exit(EVP_GCM_TLS_TAG_LEN);
        end;
        EVP_CTRL_COPY:
            begin
                _out := ptr;
                gctx_out := PEVP_AES_GCM_CTX(EVP_CIPHER_CTX_get_cipher_data(_out));
                if gctx.gcm.key <> nil then
                begin
                    if gctx.gcm.key <> @gctx.ks then
                        Exit(0);
                    gctx_out.gcm.key := @gctx_out.ks;
                end;
                if gctx.iv = PByte(@c.iv) then
                   gctx_out.iv := @_out.iv
                else
                begin
                    gctx_out.iv := OPENSSL_malloc(gctx.ivlen);
                    if gctx_out.iv = nil then  begin
                        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                        Exit(0);
                    end;
                    memcpy(gctx_out.iv, gctx.iv, gctx.ivlen);
                end;
                Exit(1);
            end;
        else
            Exit(-1);
    end;
end;



function aes_gcm_cleanup( c : PEVP_CIPHER_CTX):integer;
var
  gctx : PEVP_AES_GCM_CTX;
begin
    gctx := PEVP_AES_GCM_CTX(EVP_CIPHER_CTX_get_cipher_data(c));
    if gctx = nil then Exit(0);
    OPENSSL_cleanse(@gctx.gcm, sizeof(gctx.gcm));
    if gctx.iv <> PByte(@c.iv) then
       OPENSSL_free(gctx.iv);
    Result := 1;
end;



function aes_gcm_tls_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  gctx : PEVP_AES_GCM_CTX;
  rv : integer;
  bulk : size_t;
  label _err ;
begin
    gctx := PEVP_AES_GCM_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    rv := -1;
    { Encrypt/decrypt must be performed in place }
    if (_out <> _in)
         or  (len < EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) then
        Exit(-1);
    {
     * Check for too many keys as per FIPS 140-2 IG A.5 'Key/IV Pair Uniqueness
     * Requirements from SP 800-38D'.  The requirements is for one party to the
     * communication to fail after 2^64 - 1 keys.  We do this on the encrypting
     * side only.
     }
    Inc(gctx.tls_enc_records);
    if (ctx.encrypt > 0) and  (gctx.tls_enc_records = 0)  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_TOO_MANY_RECORDS);
        goto _err;
    end;
    {
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     }
    if EVP_CIPHER_CTX_ctrl(ctx, get_result(ctx.encrypt > 0, EVP_CTRL_GCM_IV_GEN
                                              , EVP_CTRL_GCM_SET_IV_INV),
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, _out) <= 0  then
        goto _err;
    { Use saved AAD }
    if CRYPTO_gcm128_aad(@gctx.gcm, @ctx.buf, gctx.tls_aad_len) > 0 then
        goto _err;
    { Fix buffer and length to point to payload }
    _in  := _in + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    _out  := _out + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len  := len - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);
    if ctx.encrypt > 0 then
    begin
        { Encrypt payload }
        if Assigned(gctx.ctr) then
        begin
            bulk := 0;
{$IF defined(AES_GCM_ASM)}
            if len >= 32  and  AES_GCM_ASM(gctx then ) begin
                if CRYPTO_gcm128_encrypt(&gctx.gcm, nil, nil, 0) then
                    Exit(-1);
                bulk := AES_gcm_encrypt(in, out, len,
                                       gctx.gcm.key,
                                       gctx.gcm.Yi.c, gctx.gcm.Xi.u);
                gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
            end;
{$ENDIF}
            if CRYPTO_gcm128_encrypt_ctr32(@gctx.gcm,
                                            _in + bulk,
                                            _out + bulk,
                                            len - bulk, gctx.ctr) > 0 then
                goto _err;
        end
        else
        begin
            bulk := 0;
{$IF defined(AES_GCM_ASM2)}
            if len >= 32  and  AES_GCM_ASM2(gctx then ) begin
                if CRYPTO_gcm128_encrypt(&gctx.gcm, nil, nil, 0) then
                    Exit(-1);
                bulk := AES_gcm_encrypt(in, out, len,
                                       gctx.gcm.key,
                                       gctx.gcm.Yi.c, gctx.gcm.Xi.u);
                gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
            end;
{$ENDIF}
            if CRYPTO_gcm128_encrypt(@gctx.gcm,
                                      _in + bulk, _out + bulk, len - bulk) > 0  then
                goto _err;
        end;
        _out  := _out + len;
        { Finally write tag }
        CRYPTO_gcm128_tag(@gctx.gcm, _out, EVP_GCM_TLS_TAG_LEN);
        rv := len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    end
    else
    begin
        { Decrypt }
        if Assigned(gctx.ctr) then
        begin
            bulk := 0;
{$IF defined(AES_GCM_ASM)}
            if len >= 16  and  AES_GCM_ASM(gctx then ) begin
                if CRYPTO_gcm128_decrypt(&gctx.gcm, nil, nil, 0) then
                    Exit(-1);
                bulk := AES_gcm_decrypt(in, out, len,
                                       gctx.gcm.key,
                                       gctx.gcm.Yi.c, gctx.gcm.Xi.u);
                gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
            end;
{$ENDIF}
            if CRYPTO_gcm128_decrypt_ctr32(@gctx.gcm,
                                            _in + bulk,
                                            _out + bulk,
                                            len - bulk, gctx.ctr) > 0 then
                goto _err;
        end
        else
        begin
            bulk := 0;
{$IF defined(AES_GCM_ASM2)}
            if len >= 16  and  AES_GCM_ASM2(gctx then ) begin
                if CRYPTO_gcm128_decrypt(&gctx.gcm, nil, nil, 0) then
                    Exit(-1);
                bulk := AES_gcm_decrypt(in, out, len,
                                       gctx.gcm.key,
                                       gctx.gcm.Yi.c, gctx.gcm.Xi.u);
                gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
            end;
{$ENDIF}
            if CRYPTO_gcm128_decrypt(@gctx.gcm,
                                      _in + bulk, _out + bulk, len - bulk) > 0  then
                goto _err;
        end;
        { Retrieve tag }
        CRYPTO_gcm128_tag(@gctx.gcm, @ctx.buf, EVP_GCM_TLS_TAG_LEN);
        { If tag mismatch wipe buffer }
        if CRYPTO_memcmp(@ctx.buf, _in + len, EVP_GCM_TLS_TAG_LEN) > 0 then
        begin
            OPENSSL_cleanse(_out, len);
            goto _err;
        end;
        rv := len;
    end;
 _err:
    gctx.iv_set := 0;
    gctx.tls_aad_len := -1;
    Result := rv;
end;



function aes_gcm_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  gctx : PEVP_AES_GCM_CTX;
  bulk, res: size_t;
begin
    gctx := PEVP_AES_GCM_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    { If not set up, return error }
    if 0>=gctx.key_set then Exit(-1);
    if gctx.tls_aad_len >= 0 then
       Exit(aes_gcm_tls_cipher(ctx, _out, _in, len));
{$IFDEF FIPS_MODULE}
    {
     * FIPS requires generation of AES-GCM IV's inside the FIPS module.
     * The IV can still be set externally (the security policy will state that
     * this is not FIPS compliant). There are some applications
     * where setting the IV externally is the only option available.
     }
    if 0>=gctx.iv_set then begin
        if 0>=ctx.encrypt  or  (0>=aes_gcm_iv_generate(gctx, 0) then
            Exit(-1);
        CRYPTO_gcm128_setiv(&gctx.gcm, gctx.iv, gctx.ivlen);
        gctx.iv_set := 1;
        gctx.iv_gen_rand := 1;
    end;
{$ELSE} if 0>=gctx.iv_set then Exit(-1);
{$endif} { FIPS_MODULE }
    if _in <> nil then
    begin
        if _out = nil then
        begin
            if CRYPTO_gcm128_aad(@gctx.gcm, _in, len) > 0 then
                Exit(-1);
        end
        else
        if (ctx.encrypt > 0 ) then
        begin
            if Assigned(gctx.ctr) then
            begin
                bulk := 0;
{$IF defined(AES_GCM_ASM)}
                if (len >= 32)  and  (AES_GCM_ASM(gctx) > 0) then
                begin
                    res := (16 - gctx.gcm.mres) % 16;
                    if CRYPTO_gcm128_encrypt(&gctx.gcm, in, out, res then )
                        Exit(-1);
                    bulk := AES_gcm_encrypt(in + res,
                                           out + res, len - res,
                                           gctx.gcm.key, gctx.gcm.Yi.c,
                                           gctx.gcm.Xi.u);
                    gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
                    bulk  := bulk + res;
                end;
{$ENDIF}
                if CRYPTO_gcm128_encrypt_ctr32(@gctx.gcm,
                                                _in + bulk,
                                                _out + bulk,
                                                len - bulk, gctx.ctr) > 0 then
                    Exit(-1);
            end
            else
            begin
                bulk := 0;
{$IF defined(AES_GCM_ASM2)}
                if len >= 32  and  AES_GCM_ASM2(gctx then ) begin
                    res := (16 - gctx.gcm.mres) % 16;
                    if CRYPTO_gcm128_encrypt(&gctx.gcm, in, out, res then )
                        Exit(-1);
                    bulk := AES_gcm_encrypt(in + res,
                                           out + res, len - res,
                                           gctx.gcm.key, gctx.gcm.Yi.c,
                                           gctx.gcm.Xi.u);
                    gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
                    bulk  := bulk + res;
                end;
{$ENDIF}
                if CRYPTO_gcm128_encrypt(@gctx.gcm,
                                          _in + bulk, _out + bulk, len - bulk) > 0 then
                    Exit(-1);
            end;
        end
        else
        begin
            if Assigned(gctx.ctr) then
            begin
                bulk := 0;
{$IF defined(AES_GCM_ASM)}
                if len >= 16  and  AES_GCM_ASM(gctx then ) begin
                    res := (16 - gctx.gcm.mres) % 16;
                    if CRYPTO_gcm128_decrypt(&gctx.gcm, in, out, res then )
                        Exit(-1);
                    bulk := AES_gcm_decrypt(in + res,
                                           out + res, len - res,
                                           gctx.gcm.key,
                                           gctx.gcm.Yi.c, gctx.gcm.Xi.u);
                    gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
                    bulk  := bulk + res;
                end;
{$ENDIF}
                if CRYPTO_gcm128_decrypt_ctr32(@gctx.gcm,
                                                _in + bulk,
                                                _out + bulk,
                                                len - bulk, gctx.ctr) > 0 then
                    Exit(-1);
            end
            else
            begin
                bulk := 0;
{$IF defined(AES_GCM_ASM2)}
                if len >= 16  and  AES_GCM_ASM2(gctx then ) begin
                    res := (16 - gctx.gcm.mres) % 16;
                    if CRYPTO_gcm128_decrypt(&gctx.gcm, in, out, res then )
                        Exit(-1);
                    bulk := AES_gcm_decrypt(in + res,
                                           out + res, len - res,
                                           gctx.gcm.key,
                                           gctx.gcm.Yi.c, gctx.gcm.Xi.u);
                    gctx.gcm.len.u[1]  := gctx.gcm.len.u[1] + bulk;
                    bulk  := bulk + res;
                end;
{$ENDIF}
                if CRYPTO_gcm128_decrypt(@gctx.gcm,
                                          _in + bulk, _out + bulk, len - bulk) > 0 then
                    Exit(-1);
            end;
        end;
        Exit(len);
    end
    else
    begin
        if 0>=ctx.encrypt then
        begin
            if gctx.taglen < 0 then
                Exit(-1);
            if CRYPTO_gcm128_finish(@gctx.gcm, @ctx.buf, gctx.taglen) <> 0  then
                Exit(-1);
            gctx.iv_set := 0;
            Exit(0);
        end;
        CRYPTO_gcm128_tag(@gctx.gcm, @ctx.buf, 16);
        gctx.taglen := 16;
        { Don't reuse the IV }
        gctx.iv_set := 0;
        Exit(0);
    end;
end;

function aes_gcm_init_key(ctx : PEVP_CIPHER_CTX;key, iv : PByte; enc : integer):integer;
var
  gctx : PEVP_AES_GCM_CTX;
begin
    gctx := PEVP_AES_GCM_CTX(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (nil =iv)  and  (nil =key) then Exit(1);
    if key <> nil then
    begin
        while Boolean(0) do
        begin
{$IFDEF HWAES_CAPABLE}
            if HWAES_CAPABLE then
            begin
                HWAES_set_encrypt_key(key, ctx.key_len * 8, &gctx.ks.ks);
                CRYPTO_gcm128_init(&gctx.gcm, &gctx.ks,
                                   {block128_f}HWAES_encrypt);
{$IFDEF HWAES_ctr32_encrypt_blocks}
                gctx.ctr := (ctr128_f) HWAES_ctr32_encrypt_blocks;
{$ELSE} gctx.ctr = nil;
{$ENDIF}
                break;
            end;
            else
{$ENDIF}
{$IFDEF BSAES_CAPABLE}
            if BSAES_CAPABLE then
            begin
                AES_set_encrypt_key(key, ctx.key_len * 8, &gctx.ks.ks);
                CRYPTO_gcm128_init(&gctx.gcm, &gctx.ks,
                                   {block128_f}AES_encrypt);
                gctx.ctr := (ctr128_f) ossl_bsaes_ctr32_encrypt_blocks;
                break;
            end;
            else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
            if VPAES_CAPABLE then
            begin
                vpaes_set_encrypt_key(key, ctx.key_len * 8, &gctx.ks.ks);
                CRYPTO_gcm128_init(&gctx.gcm, &gctx.ks,
                                   {block128_f}vpaes_encrypt);
                gctx.ctr := nil;
                break;
            end;
            else
{$ENDIF}
            //    (void)0;        { terminate potentially open 'else' }
            AES_set_encrypt_key(key, ctx.key_len * 8, @gctx.ks.ks);
            CRYPTO_gcm128_init(@gctx.gcm, @gctx.ks,
                               {block128_f} AES_encrypt);
{$IFDEF AES_CTR_ASM}
            gctx.ctr := (ctr128_f) AES_ctr32_encrypt;
{$ELSE}     gctx.ctr := nil;
{$ENDIF}
        end;

        {
         * If we have an iv can set it directly, otherwise use saved IV.
         }
        if (iv = nil)  and  (gctx.iv_set > 0) then
           iv := gctx.iv;
        if iv <> nil then
        begin
            CRYPTO_gcm128_setiv(@gctx.gcm, iv, gctx.ivlen);
            gctx.iv_set := 1;
        end;
        gctx.key_set := 1;
    end
    else
    begin
        { If key set use IV, otherwise copy }
        if gctx.key_set > 0 then
           CRYPTO_gcm128_setiv(@gctx.gcm, iv, gctx.ivlen)
        else
           memcpy(gctx.iv, iv, gctx.ivlen);
        gctx.iv_set := 1;
        gctx.iv_gen := 0;
    end;
    Result := 1;
end;



function EVP_aes_128_gcm:PEVP_CIPHER;
begin
 Result := @aes_128_gcm;
end;


function EVP_aes_192_gcm:PEVP_CIPHER;
begin
 Result := @aes_192_gcm;
end;


function EVP_aes_256_gcm:PEVP_CIPHER;
begin
 Result := @aes_256_gcm;
end;


function aes_cfb1_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_AES_KEY;
  num : integer;
begin
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS ) > 0 then
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        CRYPTO_cfb128_1_encrypt(_in, _out, len, @dat.ks,
                                @ctx.iv, @num,
                                EVP_CIPHER_CTX_is_encrypting(ctx), dat.block);
        EVP_CIPHER_CTX_set_num(ctx, num);
        Exit(1);
    end;
    while len >= MAXBITCHUNK do
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        CRYPTO_cfb128_1_encrypt(_in, _out, MAXBITCHUNK * 8, @dat.ks,
                                @ctx.iv, @num,
                                EVP_CIPHER_CTX_is_encrypting(ctx), dat.block);
        EVP_CIPHER_CTX_set_num(ctx, num);
        len  := len - MAXBITCHUNK;
        _out  := _out + MAXBITCHUNK;
        _in   := _in  + MAXBITCHUNK;
    end;
    if len > 0 then begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        CRYPTO_cfb128_1_encrypt(_in, _out, len * 8, @dat.ks,
                                @ctx.iv, @num,
                                EVP_CIPHER_CTX_is_encrypting(ctx), dat.block);
        EVP_CIPHER_CTX_set_num(ctx, num);
    end;
    Result := 1;
end;


function aes_ctr_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  n : integer;
  num : uint32;
  dat : PEVP_AES_KEY;
begin
    n := EVP_CIPHER_CTX_get_num(ctx);
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if n < 0 then Exit(0);
    num := uint32(n);
    if Assigned(dat.stream.ctr) then
       CRYPTO_ctr128_encrypt_ctr32(_in, _out, len, @dat.ks,
                                    @ctx.iv,
                                    EVP_CIPHER_CTX_buf_noconst(ctx),
                                    @num, dat.stream.ctr)
    else
        CRYPTO_ctr128_encrypt(_in, _out, len, @dat.ks,
                              @ctx.iv,
                              EVP_CIPHER_CTX_buf_noconst(ctx), @num,
                              dat.block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    Result := 1;
end;


function aes_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  bl, i : size_t;
  dat : PEVP_AES_KEY;
begin
{$POINTERMATH ON}
    bl := EVP_CIPHER_CTX_get_block_size(ctx);
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if len < bl then Exit(1);
    i := 0; len  := len - bl;
    while i <= len do
    begin
        dat.block(_in + i, _out + i, @dat.ks);
        i := i + bl;
    end;
    Result := 1;
{$POINTERMATH OFF}
end;


function aes_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_AES_KEY;
  num : integer;
begin
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    num := EVP_CIPHER_CTX_get_num(ctx);
    CRYPTO_ofb128_encrypt(_in, _out, len, @dat.ks,
                          @ctx.iv, @num, dat.block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    Result := 1;
end;


function aes_cfb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_AES_KEY;
  num : integer;
begin
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    num := EVP_CIPHER_CTX_get_num(ctx);
    CRYPTO_cfb128_encrypt(_in, _out, len, @dat.ks,
                          @ctx.iv, @num,
                          EVP_CIPHER_CTX_is_encrypting(ctx), dat.block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    Result := 1;
end;


function aes_cfb8_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_AES_KEY;
  num : integer;
begin
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    num := EVP_CIPHER_CTX_get_num(ctx);
    CRYPTO_cfb128_8_encrypt(_in, _out, len, @dat.ks,
                            @ctx.iv, @num,
                            EVP_CIPHER_CTX_is_encrypting(ctx), dat.block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    Result := 1;
end;




function aes_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_AES_KEY;
begin
    dat := PEVP_AES_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if Assigned(dat.stream.cbc) then
       dat.stream.cbc (_in, _out, len, @dat.ks, @ctx.iv,
                            EVP_CIPHER_CTX_is_encrypting(ctx))
    else
    if (EVP_CIPHER_CTX_is_encrypting(ctx) > 0) then
        CRYPTO_cbc128_encrypt(_in, _out, len, @dat.ks, @ctx.iv,
                              dat.block)
    else
        CRYPTO_cbc128_decrypt(_in, _out, len, @dat.ks,
                              @ctx.iv, dat.block);
    Result := 1;
end;

function aes_init_key(ctx : PEVP_CIPHER_CTX; key, iv : PByte; enc : integer):integer;
var
  ret, mode : integer;
  dat : PEVP_AES_KEY;
begin
    dat := PEVP_AES_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx));
    mode := EVP_CIPHER_CTX_get_mode(ctx);
    if (mode = EVP_CIPH_ECB_MODE)  or  (mode = EVP_CIPH_CBC_MODE)  and  (0>=enc) then
    begin
{$IFDEF HWAES_CAPABLE}
        if HWAES_CAPABLE then  begin
            ret := HWAES_set_decrypt_key(key,
                                        EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                        &dat.ks.ks);
            dat.block := {block128_f}
 HWAES_decrypt;
            dat.stream.cbc := nil;
{$IFDEF HWAES_cbc_encrypt}
            if mode = EVP_CIPH_CBC_MODE then dat.stream.cbc = {cbc128_f}
 HWAES_cbc_encrypt;
{$ENDIF}
        end;
 else
{$ENDIF}
{$IFDEF BSAES_CAPABLE}
        if BSAES_CAPABLE  and  mode = EVP_CIPH_CBC_MODE then begin
            ret := AES_set_decrypt_key(key,
                                      EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      &dat.ks.ks);
            dat.block := {block128_f}
 AES_decrypt;
            dat.stream.cbc := {cbc128_f}
 ossl_bsaes_cbc_encrypt;
        end;
 else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
        if VPAES_CAPABLE then begin
            ret := vpaes_set_decrypt_key(key,
                                        EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                        &dat.ks.ks);
            dat.block := {block128_f}
 vpaes_decrypt;
            dat.stream.cbc := mode = EVP_CIPH_CBC_MODE ?
                {cbc128_f}
 vpaes_cbc_encrypt : nil;
        end;
 else
{$ENDIF}
        begin
            ret := AES_set_decrypt_key(key,
                                      EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                      @dat.ks.ks);
            dat.block := {block128_f}AES_decrypt;
            if mode = EVP_CIPH_CBC_MODE then
               dat.stream.cbc := {cbc128_f}AES_cbc_encrypt
            else
               dat.stream.cbc := nil;
        end;
    end
    else
{$IFDEF HWAES_CAPABLE}
    if HWAES_CAPABLE then begin
        ret := HWAES_set_encrypt_key(key,
                                    EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                    &dat.ks.ks);
        dat.block := {block128_f}
 HWAES_encrypt;
        dat.stream.cbc := nil;
{$IFDEF HWAES_cbc_encrypt}
        if mode = EVP_CIPH_CBC_MODE then dat.stream.cbc = {cbc128_f}
 HWAES_cbc_encrypt;
        else
{$ENDIF}
{$IFDEF HWAES_ctr32_encrypt_blocks}
        if mode = EVP_CIPH_CTR_MODE then dat.stream.ctr = (ctr128_f) HWAES_ctr32_encrypt_blocks;
        else
{$ENDIF}
            (void)0;            { terminate potentially open 'else' }
    end;
 else
{$ENDIF}
{$IFDEF BSAES_CAPABLE}
    if BSAES_CAPABLE  and  mode = EVP_CIPH_CTR_MODE then begin
        ret := AES_set_encrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                  &dat.ks.ks);
        dat.block := {block128_f}
 AES_encrypt;
        dat.stream.ctr := (ctr128_f) ossl_bsaes_ctr32_encrypt_blocks;
    end;
 else
{$ENDIF}
{$IFDEF VPAES_CAPABLE}
    if VPAES_CAPABLE then begin
        ret := vpaes_set_encrypt_key(key,
                                    EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                    &dat.ks.ks);
        dat.block := {block128_f}
 vpaes_encrypt;
        dat.stream.cbc := mode = EVP_CIPH_CBC_MODE ?
            {cbc128_f}
 vpaes_cbc_encrypt : nil;
    end;
 else
{$ENDIF}
    begin
        ret := AES_set_encrypt_key(key, EVP_CIPHER_CTX_get_key_length(ctx) * 8,
                                  @dat.ks.ks);
        dat.block := {block128_f} AES_encrypt;
        if mode = EVP_CIPH_CBC_MODE then
           dat.stream.cbc := {cbc128_f} AES_cbc_encrypt
        else
           dat.stream.cbc :=  nil;
{$IFDEF AES_CTR_ASM}
        if mode = EVP_CIPH_CTR_MODE then dat.stream.ctr = (ctr128_f) AES_ctr32_encrypt;
{$ENDIF}
    end;
    if ret < 0 then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_AES_KEY_SETUP_FAILED);
        Exit(0);
    end;
    Result := 1;
end;



function EVP_aes_128_cbc:PEVP_CIPHER;
begin
 Result := @aes_128_cbc;
end;


function EVP_aes_128_ecb:PEVP_CIPHER;
begin
 Result := @aes_128_ecb;
end;


function EVP_aes_128_ofb:PEVP_CIPHER;
begin
 Result := @aes_128_ofb;
end;


function EVP_aes_128_cfb128:PEVP_CIPHER;
begin
 Result := @aes_128_cfb;
end;


function EVP_aes_128_cfb1:PEVP_CIPHER;
begin
 Result := @aes_128_cfb1;
end;


function EVP_aes_128_cfb8:PEVP_CIPHER;
begin
 Result := @aes_128_cfb8;
end;


function EVP_aes_128_ctr:PEVP_CIPHER;
begin
 Result := @aes_128_ctr;
end;


function EVP_aes_192_cbc:PEVP_CIPHER;
begin
 Result := @aes_192_cbc;
end;


function EVP_aes_192_ecb:PEVP_CIPHER;
begin
 Result := @aes_192_ecb;
end;


function EVP_aes_192_ofb:PEVP_CIPHER;
begin
 Result := @aes_192_ofb;
end;


function EVP_aes_192_cfb128:PEVP_CIPHER;
begin
 Result := @aes_192_cfb;
end;


function EVP_aes_192_cfb1:PEVP_CIPHER;
begin
 Result := @aes_192_cfb1;
end;


function EVP_aes_192_cfb8:PEVP_CIPHER;
begin
 Result := @aes_192_cfb8;
end;


function EVP_aes_192_ctr:PEVP_CIPHER;
begin
 Result := @aes_192_ctr;
end;


function EVP_aes_256_cbc:PEVP_CIPHER;
begin
 Result := @aes_256_cbc;
end;


function EVP_aes_256_ecb:PEVP_CIPHER;
begin
 Result := @aes_256_ecb;
end;


function EVP_aes_256_ofb:PEVP_CIPHER;
begin
 Result := @aes_256_ofb;
end;


function EVP_aes_256_cfb128:PEVP_CIPHER;
begin
 Result := @aes_256_cfb;
end;


function EVP_aes_256_cfb1:PEVP_CIPHER;
begin
 Result := @aes_256_cfb1;
end;


function EVP_aes_256_cfb8:PEVP_CIPHER;
begin
 Result := @aes_256_cfb8;
end;


function EVP_aes_256_ctr:PEVP_CIPHER;
begin
 Result := @aes_256_ctr;
end;

initialization
    aes_128_cbc  := get_EVP_CIPHER( 419,16,128 div 8,16, 0 or 0 or $2, 1, aes_init_key, aes_cbc_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_128_ecb  := get_EVP_CIPHER( 418,16,128 div 8,0, 0 or 0 or $1, 1,  aes_init_key, aes_ecb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_128_ofb  := get_EVP_CIPHER( 420,1,128 div 8,16, 0 or 0 or $4, 1,  aes_init_key, aes_ofb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_128_cfb  := get_EVP_CIPHER( 421,1,128 div 8,16, 0 or 0 or $3, 1,  aes_init_key, aes_cfb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_128_cfb1 := get_EVP_CIPHER( 650,1,128 div 8,16, 0 or $3, 1,       aes_init_key, aes_cfb1_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_128_cfb8 := get_EVP_CIPHER( 653,1,128 div 8,16, 0 or $3, 1,       aes_init_key, aes_cfb8_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_128_ctr  := get_EVP_CIPHER( 904,1,128 div 8,16, 0 or $5, 1,       aes_init_key, aes_ctr_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_cbc  := get_EVP_CIPHER( 423,16,192 div 8,16, 0 or 0 or $2, 1, aes_init_key, aes_cbc_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_ecb  := get_EVP_CIPHER( 422,16,192 div 8,0, 0 or 0 or $1, 1,  aes_init_key, aes_ecb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_ofb  := get_EVP_CIPHER( 424,1,192 div 8,16, 0 or 0 or $4, 1,  aes_init_key, aes_ofb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_cfb  := get_EVP_CIPHER( 425,1,192 div 8,16, 0 or 0 or $3, 1,  aes_init_key, aes_cfb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_cfb1 := get_EVP_CIPHER( 651,1,192 div 8,16, 0 or $3, 1,      aes_init_key, aes_cfb1_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_cfb8 := get_EVP_CIPHER( 654,1,192 div 8,16, 0 or $3, 1,      aes_init_key, aes_cfb8_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_192_ctr  := get_EVP_CIPHER( 905,1,192 div 8,16, 0 or $5, 1,      aes_init_key, aes_ctr_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_cbc  := get_EVP_CIPHER( 427,16,256 div 8,16, 0 or 0 or $2, 1, aes_init_key, aes_cbc_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_ecb  := get_EVP_CIPHER( 426,16,256 div 8,0, 0 or 0 or $1, 1, aes_init_key, aes_ecb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_ofb  := get_EVP_CIPHER( 428,1,256 div 8,16, 0 or 0 or $4, 1, aes_init_key, aes_ofb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_cfb  := get_EVP_CIPHER( 429,1,256 div 8,16, 0 or 0 or $3, 1, aes_init_key, aes_cfb_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_cfb1 := get_EVP_CIPHER( 652,1,256 div 8,16, 0 or $3, 1,      aes_init_key, aes_cfb1_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_cfb8 := get_EVP_CIPHER( 655,1,256 div 8,16, 0 or $3, 1,      aes_init_key, aes_cfb8_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );
    aes_256_ctr  := get_EVP_CIPHER( 906,1,256 div 8,16, 0 or $5, 1,      aes_init_key, aes_ctr_cipher, nil , sizeof(TEVP_AES_KEY), nil ,nil ,nil ,nil  );

    aes_128_gcm := get_EVP_CIPHER(895,1, get_result( ($6=$10001) or ($6=$10004), 2,1)*128 div 8, 12,
                  $200000 or  (0 or  $10 or  $100000 or  $20 or  $40 or  $400 or  $800) or $6,
                  1, aes_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup, sizeof(TEVP_AES_GCM_CTX),
                  nil , nil,aes_gcm_ctrl,nil);

    aes_192_gcm := get_EVP_CIPHER(898,1, get_result( ($6=$10001) or ($6=$10004), 2,1)*192 div 8, 12,
                 $200000 or  (0 or  $10 or  $100000 or  $20 or  $40 or  $400 or  $800)or $6,
                 1, aes_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup, sizeof(TEVP_AES_GCM_CTX),
                 nil , nil,aes_gcm_ctrl,nil);


    aes_256_gcm := get_EVP_CIPHER(901,1, get_result( ($6=$10001) or ($6=$10004), 2,1)*256 div 8, 12,
                 $200000 or  (0 or  $10 or  $100000 or  $20 or  $40 or  $400 or  $800)or $6,
                 1, aes_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup, sizeof(TEVP_AES_GCM_CTX),
                 nil , nil,aes_gcm_ctrl,nil);

    aes_128_ocb := get_EVP_CIPHER(958,16, get_result( ($10003=$10001 ) or ( $10003=$10004), 2, 1)*128 div 8,
          12, $200000 or (0 or $10 or $100000 or $20 or $40 or $400 or $800)or $10003, 1,
          aes_ocb_init_key, aes_ocb_cipher, aes_ocb_cleanup, sizeof(TEVP_AES_OCB_CTX),
          nil ,nil ,aes_ocb_ctrl, nil  );

    aes_192_ocb := get_EVP_CIPHER(959,16,  get_result( ($10003=$10001 ) or ( $10003=$10004), 2, 1)*192 div 8,
          12, $200000 or (0 or $10 or $100000 or $20 or $40 or $400 or $800)or$10003, 1,
          aes_ocb_init_key, aes_ocb_cipher, aes_ocb_cleanup, sizeof(TEVP_AES_OCB_CTX),
          nil ,nil ,aes_ocb_ctrl,nil  );

    aes_256_ocb := get_EVP_CIPHER(960,16, get_result( ($10003=$10001 ) or ( $10003=$10004), 2, 1)*256 div 8,
         12, $200000 or (0 or $10 or $100000 or $20 or $40 or $400 or $800) or $10003, 1,
         aes_ocb_init_key, aes_ocb_cipher, aes_ocb_cleanup, sizeof(TEVP_AES_OCB_CTX),
         nil , nil ,aes_ocb_ctrl,nil  );

    aes_128_xts := get_EVP_CIPHER( 913,1, get_result( ($10001=$10001) or ($10001=$10004), 2, 1)*128 div 8, 16,
           (0 or $10 or $20 or $40 or $400)or$10001, 1, aes_xts_init_key, aes_xts_cipher,
           nil , sizeof(TEVP_AES_XTS_CTX), nil ,
           nil,aes_xts_ctrl,nil  );

   aes_256_xts := get_EVP_CIPHER(914,1, get_result( ($10001=$10001) or ($10001=$10004), 2,1)*256 div 8,
          16, (0 or $10 or $20 or $40 or $400)or$10001, 1, aes_xts_init_key, aes_xts_cipher,
          nil , sizeof(TEVP_AES_XTS_CTX), nil ,
          nil,aes_xts_ctrl,nil  );

    aes_128_ccm := get_EVP_CIPHER( 896,1, get_result( ($7=$10001) or ($7=$10004), 2,1)*128 div 8, 12, $200000  or  (0  or  $10  or  $100000  or  $20  or  $40  or  $400  or  $800) or $7, 1, aes_ccm_init_key, aes_ccm_cipher, nil , sizeof(TEVP_AES_CCM_CTX), nil ,nil ,aes_ccm_ctrl,nil  );
    aes_192_ccm := get_EVP_CIPHER( 899,1, get_result( ($7=$10001) or ($7=$10004), 2,1)*192 div 8, 12, $200000  or  (0  or  $10  or  $100000  or  $20  or  $40  or  $400  or  $800) or $7, 1, aes_ccm_init_key, aes_ccm_cipher, nil , sizeof(TEVP_AES_CCM_CTX), nil ,nil ,aes_ccm_ctrl,nil  );
    aes_256_ccm := get_EVP_CIPHER( 902,1, get_result( ($7=$10001) or ($7=$10004), 2,1)*256 div 8, 12, $200000  or  (0  or  $10  or  $100000  or  $20  or  $40  or  $400  or  $800) or $7, 1, aes_ccm_init_key, aes_ccm_cipher, nil , sizeof(TEVP_AES_CCM_CTX), nil ,nil ,aes_ccm_ctrl,nil  );

    aes_128_wrap := get_EVP_CIPHER(
        NID_id_aes128_wrap,
        8, 16, 8, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

    aes_128_wrap_pad := get_EVP_CIPHER(
        NID_id_aes128_wrap_pad,
        8, 16, 4, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

   aes_192_wrap := get_EVP_CIPHER(
        NID_id_aes192_wrap,
        8, 24, 8, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

    aes_192_wrap_pad := get_EVP_CIPHER(
        NID_id_aes192_wrap_pad,
        8, 24, 4, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

    aes_256_wrap := get_EVP_CIPHER(
        NID_id_aes256_wrap,
        8, 32, 8, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

    aes_128_wrap_pad := get_EVP_CIPHER(
        NID_id_aes128_wrap_pad,
        8, 16, 4, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

    aes_256_wrap_pad := get_EVP_CIPHER(
        NID_id_aes256_wrap_pad,
        8, 32, 4, WRAP_FLAGS, EVP_ORIG_GLOBAL,
        aes_wrap_init_key, aes_wrap_cipher,
        nil,
        sizeof(TEVP_AES_WRAP_CTX),
        nil, nil, nil, nil);

end.
