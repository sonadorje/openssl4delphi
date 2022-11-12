unit openssl3.crypto.evp.e_bf;

interface
uses OpenSSL.Api;

type
   TEVP_BF_KEY = record
     ks: TBF_KEY;
   end ;
   PEVP_BF_KEY = ^TEVP_BF_KEY;

  function bf_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;

  function bf_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function bf_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function bf_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function bf_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function EVP_bf_cbc:PEVP_CIPHER;
  function EVP_bf_cfb64:PEVP_CIPHER;
  function EVP_bf_ofb:PEVP_CIPHER;
  function EVP_bf_ecb:PEVP_CIPHER;

var
    bf_cbc   : TEVP_CIPHER  { 91, 8, 16, 8, $8 | $2, 1, bf_init_key, bf_cbc_cipher, Pointer(0) , sizeof(EVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };
    bf_cfb64 : TEVP_CIPHER  { 93, 1, 16, 8, $8 | $3, 1, bf_init_key, bf_cfb64_cipher, Pointer(0) , sizeof(EVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };
    bf_ofb   : TEVP_CIPHER  { 94, 1, 16, 8, $8 | $4, 1, bf_init_key, bf_ofb_cipher, Pointer(0) , sizeof(EVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };
    bf_ecb   : TEVP_CIPHER  { 92, 8, 16, 0, $8 | $1, 1, bf_init_key, bf_ecb_cipher, Pointer(0) , sizeof(EVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  };

implementation
uses openssl3.crypto.bf.bf_enc,   openssl3.crypto.evp.evp_lib,
     openssl3.crypto.bf.bf_ofb64, openssl3.crypto.bf.bf_skey ,
     openssl3.crypto.bf.bf_cfb64, openssl3.crypto.bf.bf_ecb ;

function get_result(condition: Boolean;result1, result2: size_t): size_t;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;

function data(ctx: PEVP_CIPHER_CTX): PEVP_BF_KEY;
begin
  Result := PEVP_BF_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
end;

function bf_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
   while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
   begin
       BF_cbc_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
          @PEVP_BF_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv,
                           EVP_CIPHER_CTX_is_encrypting(ctx));
       inl := inl - ((size_t(1)  shl (sizeof(long)*8-2)));
       _in  := _in + ((size_t(1)   shl (sizeof(long)*8-2)));
       _out := _out + ((size_t(1)  shl (sizeof(long)*8-2)));
   end;
   if inl > 0 then
      BF_cbc_encrypt(_in, _out, long(inl),
           @PEVP_BF_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv,
           EVP_CIPHER_CTX_is_encrypting(ctx));
   Result := 1;
end;


function bf_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  chunk : size_t;
  num: int;
begin
   chunk := (size_t(1) shl (sizeof(long)*8-2));
   if 64 = 1 then
      chunk := chunk shr  3;
   if inl < chunk then chunk := inl;
   while (inl > 0)  and  (inl >= chunk) do
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       BF_cfb64_encrypt(_in, _out, long((64 = 1)  and
               (0>= get_result(EVP_CIPHER_CTX_test_flags(ctx, $2000) > 0, chunk*8 , chunk))),
               @PEVP_BF_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num,
               EVP_CIPHER_CTX_is_encrypting(ctx));
       EVP_CIPHER_CTX_set_num(ctx, num);
       inl  := inl - chunk;
       _in  := _in + chunk;
       _out  := _out + chunk;
       if inl < chunk then
          chunk := inl;
   end;
   Result := 1;
end;


function bf_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl : size_t;
begin
   bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
   if inl < bl then Exit(1);
   inl  := inl - bl;
   i :=0;
   while (i <= inl) do
   begin
       BF_ecb_encrypt(_in + i, _out + i,
           @PEVP_BF_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks,
           EVP_CIPHER_CTX_is_encrypting(ctx));
       i := i + (bl);
   end;
   Result := 1;
end;


function bf_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
   num: Int;
begin
     while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
    begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       BF_ofb64_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
              @PEVP_BF_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
       EVP_CIPHER_CTX_set_num(ctx, num);
       inl := inl - ((size_t(1)   shl (sizeof(long)*8-2)));
       _in  := _in + ((size_t(1)  shl (sizeof(long)*8-2)));
       _out := _out + ((size_t(1) shl (sizeof(long)*8-2)));
     end;
     if inl > 0 then
     begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        BF_ofb64_encrypt(_in, _out, long(inl),
             @PEVP_BF_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
        EVP_CIPHER_CTX_set_num(ctx, num);
     end;
     Result := 1;
end;


function EVP_bf_cbc:PEVP_CIPHER;
begin
 Result := @bf_cbc;
end;


function EVP_bf_cfb64:PEVP_CIPHER;
begin
 Result := @bf_cfb64;
end;


function EVP_bf_ofb:PEVP_CIPHER;
begin
 Result := @bf_ofb;
end;


function EVP_bf_ecb:PEVP_CIPHER;
begin
 Result := @bf_ecb;
end;



function bf_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  len : integer;
begin
    len := EVP_CIPHER_CTX_get_key_length(ctx);
    if len < 0 then Exit(0);
    BF_set_key(@data(ctx).ks, len, key);
    Result := 1;
end;

initialization
    bf_cbc   := get_EVP_CIPHER( 91, 8, 16, 8, $8 or $2, 1, bf_init_key, bf_cbc_cipher, Pointer(0) , sizeof(TEVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    bf_cfb64 := get_EVP_CIPHER( 93, 1, 16, 8, $8 or $3, 1, bf_init_key, bf_cfb64_cipher, Pointer(0) , sizeof(TEVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    bf_ofb   := get_EVP_CIPHER( 94, 1, 16, 8, $8 or $4, 1, bf_init_key, bf_ofb_cipher, Pointer(0) , sizeof(TEVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    bf_ecb   := get_EVP_CIPHER( 92, 8, 16, 0, $8 or $1, 1, bf_init_key, bf_ecb_cipher, Pointer(0) , sizeof(TEVP_BF_KEY), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );

end.
