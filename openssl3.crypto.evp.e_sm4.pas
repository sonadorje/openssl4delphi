unit openssl3.crypto.evp.e_sm4;

interface
uses OpenSSL.Api;

function sm4_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
  function sm4_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
  function sm4_cfb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
  function sm4_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
  function sm4_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
  function sm4_ctr_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;

   function EVP_sm4_cbc:PEVP_CIPHER;
  function EVP_sm4_ecb:PEVP_CIPHER;
  function EVP_sm4_ofb:PEVP_CIPHER;
  function EVP_sm4_cfb128:PEVP_CIPHER;
  function EVP_sm4_ctr:PEVP_CIPHER;

var
  sm4_cbc : TEVP_CIPHER  { 1134,16,128/8,16, 0 or 0 or $2, 1, sm4_init_key, sm4_cbc_cipher, Pointer(0) , sizeof(EVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  };
  sm4_ecb : TEVP_CIPHER  { 1133,16,128/8,0, 0 or 0 or $1, 1, sm4_init_key, sm4_ecb_cipher, Pointer(0) , sizeof(EVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  };
  sm4_ofb : TEVP_CIPHER  { 1135,1,128/8,16, 0 or 0 or $4, 1, sm4_init_key, sm4_ofb_cipher, Pointer(0) , sizeof(EVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  };
  sm4_cfb : TEVP_CIPHER  { 1137,1,128/8,16, 0 or 0 or $3, 1, sm4_init_key, sm4_cfb_cipher, Pointer(0) , sizeof(EVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  };
  sm4_ctr : TEVP_CIPHER  { 1139,1,128/8,16, 0 or $5, 1, sm4_init_key, sm4_ctr_cipher, Pointer(0) , sizeof(EVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  };

implementation
uses openssl3.crypto.evp.evp_lib,           openssl3.crypto.evp,
     openssl3.crypto.modes.cfb128,          openssl3.crypto.modes.ofb128,
     openssl3.crypto.modes.ctr128,          openssl3.crypto.modes.cbc128,
     openssl3.crypto.sm4.sm4;

function EVP_sm4_cbc:PEVP_CIPHER;
begin
 Result := @sm4_cbc;
end;


function EVP_sm4_ecb:PEVP_CIPHER;
begin
 Result := @sm4_ecb;
end;


function EVP_sm4_ofb:PEVP_CIPHER;
begin
 Result := @sm4_ofb;
end;


function EVP_sm4_cfb128:PEVP_CIPHER;
begin
 Result := @sm4_cfb;
end;


function EVP_sm4_ctr:PEVP_CIPHER;
begin
 Result := @sm4_ctr;
end;

function sm4_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  mode : integer;
  dat : PEVP_SM4_KEY;
begin
    dat := PEVP_SM4_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    mode := EVP_CIPHER_CTX_get_mode(ctx);
    if (mode = EVP_CIPH_ECB_MODE)  or  (mode = EVP_CIPH_CBC_MODE)  and  (0>=enc) then
    begin
{$IFDEF HWSM4_CAPABLE}
        if HWSM4_CAPABLE then
        begin
            HWSM4_set_decrypt_key(key, &dat.ks.ks);
            dat.block := {block128_f}HWSM4_decrypt;
            dat.stream.cbc := nil;
{$IFDEF HWSM4_cbc_encrypt}
            if mode = EVP_CIPH_CBC_MODE then
               dat.stream.cbc = {cbc128_f} HWSM4_cbc_encrypt;
{$ENDIF}
{$IFDEF HWSM4_ecb_encrypt}
            if mode = EVP_CIPH_ECB_MODE then
               dat.stream.ecb = (ecb128_f) HWSM4_ecb_encrypt;
{$ENDIF}
        end
        else
{$ENDIF}
        begin
            dat.block := {block128_f} @ossl_sm4_decrypt;
            ossl_sm4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
        end;
    end
    else
{$IFDEF HWSM4_CAPABLE}
    if HWSM4_CAPABLE then
    begin
        HWSM4_set_encrypt_key(key, &dat.ks.ks);
        dat.block := {block128_f}HWSM4_encrypt;
        dat.stream.cbc := nil;
{$IFDEF HWSM4_cbc_encrypt}
        if mode = EVP_CIPH_CBC_MODE then
           dat.stream.cbc = {cbc128_f}HWSM4_cbc_encrypt;
        else
{$ENDIF}
{$IFDEF HWSM4_ecb_encrypt}
        if mode = EVP_CIPH_ECB_MODE then
           dat.stream.ecb = (ecb128_f) HWSM4_ecb_encrypt
        else
{$ENDIF}
{$IFDEF HWSM4_ctr32_encrypt_blocks}
        if mode = EVP_CIPH_CTR_MODE then dat.stream.ctr = (ctr128_f) HWSM4_ctr32_encrypt_blocks;
        else
{$ENDIF}
            (void)0;            { terminate potentially open 'else' }
    end
    else
{$ENDIF}
    begin
        dat.block := {block128_f}@ossl_sm4_encrypt;
        ossl_sm4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    end;
    Result := 1;
end;


function sm4_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_SM4_KEY;
begin
    dat := PEVP_SM4_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx));
    if Assigned(dat.stream.cbc) then
       dat.stream.cbc(_in, _out, len, @dat.ks.ks, @ctx.iv,
                            EVP_CIPHER_CTX_is_encrypting(ctx))
    else
    if (EVP_CIPHER_CTX_is_encrypting(ctx)>0) then
        CRYPTO_cbc128_encrypt(_in, _out, len, @dat.ks, @ctx.iv,
                              dat.block)
    else
        CRYPTO_cbc128_decrypt(_in, _out, len, @dat.ks, @ctx.iv, dat.block);
    Result := 1;
end;


function sm4_cfb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_SM4_KEY;
  num : integer;
begin
    dat := PEVP_SM4_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    num := EVP_CIPHER_CTX_get_num(ctx);
    CRYPTO_cfb128_encrypt(_in, _out, len, @dat.ks,
                          @ctx.iv, @num,
                          EVP_CIPHER_CTX_is_encrypting(ctx), dat.block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    Result := 1;
end;


function sm4_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  bl, i : size_t;

  dat : PEVP_SM4_KEY;
begin
    bl := EVP_CIPHER_CTX_get_block_size(ctx);
    dat := PEVP_SM4_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    if len < bl then Exit(1);
    if Assigned(dat.stream.ecb) then
       dat.stream.ecb (_in, _out, len, @dat.ks.ks,
                            EVP_CIPHER_CTX_is_encrypting(ctx))
    else
    begin
        i := 0; len  := len - bl;
        while i <= len do
        begin
            dat.block (_in + i, _out + i, @dat.ks);
            i := i + bl;
        end;
    end;
    Result := 1;
end;


function sm4_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  dat : PEVP_SM4_KEY;

  num : integer;
begin
    dat := PEVP_SM4_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
    num := EVP_CIPHER_CTX_get_num(ctx);
    CRYPTO_ofb128_encrypt(_in, _out, len, @dat.ks,
                          @ctx.iv, @num, dat.block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    Result := 1;
end;


function sm4_ctr_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  n : integer;
  num : uint32;
  dat : PEVP_SM4_KEY;
begin
    n := EVP_CIPHER_CTX_get_num(ctx);
    dat := PEVP_SM4_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx));
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

initialization
  sm4_cbc := get_EVP_CIPHER( 1134,16,128 div 8,16, 0 or 0 or $2, 1, sm4_init_key, sm4_cbc_cipher, Pointer(0) , sizeof(TEVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  );
  sm4_ecb := get_EVP_CIPHER( 1133,16,128 div 8,0,  0 or 0 or $1, 1, sm4_init_key, sm4_ecb_cipher, Pointer(0) , sizeof(TEVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  );
  sm4_ofb := get_EVP_CIPHER( 1135,1, 128 div 8,16, 0 or 0 or $4, 1, sm4_init_key, sm4_ofb_cipher, Pointer(0) , sizeof(TEVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  );
  sm4_cfb := get_EVP_CIPHER( 1137,1, 128 div 8,16, 0 or 0 or $3, 1, sm4_init_key, sm4_cfb_cipher, Pointer(0) , sizeof(TEVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  );
  sm4_ctr := get_EVP_CIPHER( 1139,1, 128 div 8,16, 0 or $5,      1, sm4_init_key, sm4_ctr_cipher, Pointer(0) , sizeof(TEVP_SM4_KEY), Pointer(0) ,Pointer(0) ,Pointer(0) ,Pointer(0)  );

end.
