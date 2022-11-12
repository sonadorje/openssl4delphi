unit openssl3.crypto.evp.e_cast;

interface
uses OpenSSL.Api;

type
  TEVP_CAST_KEY = record
   ks: TCAST_KEY;
  end ;
  PEVP_CAST_KEY = ^TEVP_CAST_KEY;

  function cast_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
  function cast5_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function cast5_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function cast5_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function cast5_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function EVP_cast5_cbc:PEVP_CIPHER;
  function EVP_cast5_cfb64:PEVP_CIPHER;
  function EVP_cast5_ofb:PEVP_CIPHER;
  function EVP_cast5_ecb:PEVP_CIPHER;

implementation
uses openssl3.crypto.evp.evp_lib,          openssl3.crypto.cast.c_skey,
     openssl3.crypto.cast.c_enc,           openssl3.crypto.cast.c_ofb64,
     openssl3.crypto.cast.c_cfb64,         openssl3.crypto.cast.c_ecb;



var
    cast5_cbc   : TEVP_CIPHER  { 108, 8, 16, 8, $8 | $2, 1, cast_init_key, cast5_cbc_cipher, Pointer(0) , sizeof(EVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };
    cast5_cfb64 : TEVP_CIPHER  { 110, 1, 16, 8, $8 | $3, 1, cast_init_key, cast5_cfb64_cipher, Pointer(0) , sizeof(EVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };
    cast5_ofb   : TEVP_CIPHER  { 111, 1, 16, 8, $8 | $4, 1, cast_init_key, cast5_ofb_cipher, Pointer(0) , sizeof(EVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };
    cast5_ecb   : TEVP_CIPHER  { 109, 8, 16, 0, $8 | $1, 1, cast_init_key, cast5_ecb_cipher, Pointer(0) , sizeof(EVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };


function get_result(condition: Boolean;result1, result2: size_t): size_t;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;

function cast5_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
   while inl>=size_t(1 shl (sizeof(long)*8-2)) do
   begin
       CAST_cbc_encrypt(_in, _out, long(size_t(1 shl (sizeof(long)*8-2))), @PEVP_CAST_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
       inl := inl - (size_t(1 shl (sizeof(long)*8-2)));
       _in  := _in + (size_t(1 shl (sizeof(long)*8-2)));
       _out := _out + (size_t(1 shl (sizeof(long)*8-2)));
   end;
   if inl > 0 then
      CAST_cbc_encrypt(_in, _out, long(inl), @PEVP_CAST_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
   Result := 1;
end;


function cast5_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  chunk : size_t;
  num: int;
begin
   chunk := size_t(1shl(sizeof(long)*8-2));
   if 64 = 1 then
      chunk := chunk shr 3;
   if inl < chunk then chunk := inl;
   while (inl > 0)  and  (inl >= chunk) do
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       CAST_cfb64_encrypt(_in, _out, long( (64 = 1)  and  (0>=get_result(EVP_CIPHER_CTX_test_flags(ctx, $2000) > 0, chunk*8 , chunk)) ),
                          @PEVP_CAST_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv,
                          @num, EVP_CIPHER_CTX_is_encrypting(ctx));
       EVP_CIPHER_CTX_set_num(ctx, num);
       inl  := inl - chunk;
       _in  := _in + chunk;
       _out  := _out + chunk;
       if inl < chunk then
          chunk := inl;
   end;
   Result := 1;
end;


function cast5_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl : size_t;
begin
   bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
   if inl < bl then Exit(1);
   inl  := inl - bl;
   i := 0;
   while i <= inl do
   begin
      CAST_ecb_encrypt(_in + i, _out + i, @PEVP_CAST_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks,
                        EVP_CIPHER_CTX_is_encrypting(ctx));
       i := i + (bl);
   end;
   Result := 1;
end;


function cast5_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num: Int;
begin
   while inl>= size_t(1 shl (sizeof(long)*8-2)) do
  begin
     num := EVP_CIPHER_CTX_get_num(ctx);
     CAST_ofb64_encrypt(_in, _out, long(size_t(1 shl (sizeof(long)*8-2))),
                     @PEVP_CAST_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
     EVP_CIPHER_CTX_set_num(ctx, num);
     inl := inl - (size_t(1 shl(sizeof(long)*8-2)));
     _in  := _in + (size_t(1 shl(sizeof(long)*8-2)));
     _out := _out + (size_t(1 shl(sizeof(long)*8-2)));
   end;
   if inl > 0 then
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       CAST_ofb64_encrypt(_in, _out, long(inl), @PEVP_CAST_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
       EVP_CIPHER_CTX_set_num(ctx, num);
   end;
   Result := 1;
  end;


function EVP_cast5_cbc:PEVP_CIPHER;
begin
 Result := @cast5_cbc;
end;


function EVP_cast5_cfb64:PEVP_CIPHER;
begin
 Result := @cast5_cfb64;
end;


function EVP_cast5_ofb:PEVP_CIPHER;
begin
 Result := @cast5_ofb;
end;


function EVP_cast5_ecb:PEVP_CIPHER;
begin
 Result := @cast5_ecb;
end;

function cast_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  keylen : integer;
begin
    keylen := EVP_CIPHER_CTX_get_key_length(ctx);
    if keylen <= 0 then Exit(0);
    CAST_set_key(@PEVP_CAST_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, keylen, key);
    Result := 1;
end;

initialization
    cast5_cbc   := get_EVP_CIPHER( 108, 8, 16, 8, $8 or $2, 1, cast_init_key, cast5_cbc_cipher, Pointer(0) , sizeof(TEVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    cast5_cfb64 := get_EVP_CIPHER( 110, 1, 16, 8, $8 or $3, 1, cast_init_key, cast5_cfb64_cipher, Pointer(0) , sizeof(TEVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    cast5_ofb   := get_EVP_CIPHER( 111, 1, 16, 8, $8 or $4, 1, cast_init_key, cast5_ofb_cipher, Pointer(0) , sizeof(TEVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    cast5_ecb   := get_EVP_CIPHER( 109, 8, 16, 0, $8 or $1, 1, cast_init_key, cast5_ecb_cipher, Pointer(0) , sizeof(TEVP_CAST_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );

end.
