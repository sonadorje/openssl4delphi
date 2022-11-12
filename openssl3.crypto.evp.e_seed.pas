unit openssl3.crypto.evp.e_seed;

interface
uses OpenSSL.Api;

type
 seed_key_st = record
   {$ifdef SEED_LONG}
    unsigned long data[32];
   {$else}
    data: array[0..32-1] of uint32;
   {$endif}

 end;
 TSEED_KEY_SCHEDULE = seed_key_st;

 TEVP_SEED_KEY = record
   ks: TSEED_KEY_SCHEDULE;
 end;
 PEVP_SEED_KEY = ^TEVP_SEED_KEY;

  function seed_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function seed_cfb128_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function seed_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function seed_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function EVP_seed_cbc:PEVP_CIPHER;
  function EVP_seed_cfb128:PEVP_CIPHER;
  function EVP_seed_ofb:PEVP_CIPHER;
  function EVP_seed_ecb:PEVP_CIPHER;
  function seed_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;



var
    seed_cbc    : TEVP_CIPHER ; { 777, 16, 16, 16, 0 | $2, 1, seed_init_key, seed_cbc_cipher, 0, sizeof(EVP_SEED_KEY), 0, 0, 0, Pointer(0)  }
    seed_cfb128 : TEVP_CIPHER ; { 779, 1, 16, 16, 0 | $3, 1, seed_init_key, seed_cfb128_cipher, 0, sizeof(EVP_SEED_KEY), 0, 0, 0, Pointer(0)  }
    seed_ofb    : TEVP_CIPHER ; { 778, 1, 16, 16, 0 | $4, 1, seed_init_key, seed_ofb_cipher, 0, sizeof(EVP_SEED_KEY), 0, 0, 0, Pointer(0)  }
    seed_ecb    : TEVP_CIPHER ; { 776, 16, 16, 0, 0 | $1, 1, seed_init_key, seed_ecb_cipher, 0, sizeof(EVP_SEED_KEY), 0, 0, 0, Pointer(0)  }

implementation
uses openssl3.crypto.seed.seed_cbc,       openssl3.crypto.evp.evp_lib,
     openssl3.crypto.seed.seed_ofb,       openssl3.crypto.seed.seed,
     openssl3.crypto.seed.seed_ecb,       openssl3.crypto.seed.seed_cfb;




function seed_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
begin
    SEED_set_key(key, @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks);
    Result := 1;
end;

function seed_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
   while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
   begin
       SEED_cbc_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
             @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
       inl := inl - ((size_t(1)   shl (sizeof(long)*8-2)));
       _in  := _in + ((size_t(1)  shl (sizeof(long)*8-2)));
       _out := _out + ((size_t(1) shl (sizeof(long)*8-2)));
   end;
   if inl >0 then
      SEED_cbc_encrypt(_in, _out, long(inl),
         @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
   Result := 1;
end;


function seed_cfb128_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  chunk, ret : size_t;
  num: int;
begin
   chunk := (size_t(1) shl (sizeof(long)*8-2));
   if 128 = 1 then
      chunk := chunk shr  3;
   if inl < chunk then
      chunk := inl;

   if EVP_CIPHER_CTX_test_flags(ctx, $2000) > 0 then
      ret := chunk*8
   else
      ret := chunk;
   while (inl > 0)  and  (inl >= chunk) do
   begin
      num := EVP_CIPHER_CTX_get_num(ctx);
      SEED_cfb128_encrypt(_in, _out, long( (128 = 1)  and (0>= ret ) ),
              @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num, EVP_CIPHER_CTX_is_encrypting(ctx));
      EVP_CIPHER_CTX_set_num(ctx, num);
      inl  := inl - chunk;
      _in  := _in + chunk;
      _out  := _out + chunk;
     if inl < chunk then
        chunk := inl;
   end;
   Result := 1;
end;


function seed_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl : size_t;
begin
     bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
     if inl < bl then Exit(1);
     inl  := inl - bl;
     i := 0;
     while i <= inl do
     begin
         SEED_ecb_encrypt(_in + i, _out + i,
                 @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, EVP_CIPHER_CTX_is_encrypting(ctx));
         i := i + (bl);
     end;
     Result := 1;
end;


function seed_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num: int;
begin
   while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
   begin
     num := EVP_CIPHER_CTX_get_num(ctx);
     SEED_ofb128_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
             @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
     EVP_CIPHER_CTX_set_num(ctx, num);
     inl := inl - ((size_t(1)   shl (sizeof(long)*8-2)));
     _in  := _in + ((size_t(1)  shl (sizeof(long)*8-2)));
     _out := _out + ((size_t(1) shl (sizeof(long)*8-2)));
   end;
   if inl > 0 then
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       SEED_ofb128_encrypt(_in, _out, long(inl),
            @PEVP_SEED_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
       EVP_CIPHER_CTX_set_num(ctx, num);
   end;
   Result := 1;
end;


function EVP_seed_cbc:PEVP_CIPHER;
begin
 Result := @seed_cbc;
end;


function EVP_seed_cfb128:PEVP_CIPHER;
begin
 Result := @seed_cfb128;
end;


function EVP_seed_ofb:PEVP_CIPHER;
begin
 Result := @seed_ofb;
end;


function EVP_seed_ecb:PEVP_CIPHER;
begin
 Result := @seed_ecb;
end;

initialization
    seed_cbc    := get_EVP_CIPHER( 777, 16, 16, 16, 0 or $2, 1, seed_init_key, seed_cbc_cipher, nil, sizeof(TEVP_SEED_KEY), nil, nil, nil, Pointer(0)  );
    seed_cfb128 := get_EVP_CIPHER( 779, 1, 16, 16, 0 or $3, 1, seed_init_key, seed_cfb128_cipher, nil, sizeof(TEVP_SEED_KEY), nil, nil, nil, Pointer(0)  );
    seed_ofb    := get_EVP_CIPHER( 778, 1, 16, 16, 0 or $4, 1, seed_init_key, seed_ofb_cipher, nil, sizeof(TEVP_SEED_KEY), nil, nil, nil, Pointer(0)  );
    seed_ecb    := get_EVP_CIPHER( 776, 16, 16, 0, 0 or $1, 1, seed_init_key, seed_ecb_cipher, nil, sizeof(TEVP_SEED_KEY), nil, nil, nil, Pointer(0)  );

end.
