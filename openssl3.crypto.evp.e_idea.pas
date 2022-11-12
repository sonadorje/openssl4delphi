unit openssl3.crypto.evp.e_idea;

interface
uses OpenSSL.Api;

type
  TEVP_IDEA_KEY = record
    ks: TIDEA_KEY_SCHEDULE;
  end ;

  PEVP_IDEA_KEY = ^TEVP_IDEA_KEY;

  function idea_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
  function EVP_idea_cbc:PEVP_CIPHER;
  function EVP_idea_cfb64:PEVP_CIPHER;
  function EVP_idea_ofb:PEVP_CIPHER;
  function EVP_idea_ecb:PEVP_CIPHER;

var
  idea_cbc,
  idea_cfb64,
  idea_ofb,
  idea_ecb   : TEVP_CIPHER;


function idea_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function idea_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function idea_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function idea_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;

implementation



uses openssl3.crypto.evp,                  openssl3.crypto.idea.i_skey,
     openssl3.crypto.idea.i_cbc,           openssl3.crypto.idea.i_ofb64,
     openssl3.crypto.idea.i_cfb64,         openssl3.crypto.idea.i_ecb,
     openssl3.crypto.mem,                  openssl3.crypto.evp.evp_lib;


function idea_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl: size_t ;
begin

    bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
    if (inl < bl) then Exit( 1);
    inl := inl - bl;
    i :=0 ;
    while i<= inl do
    begin
        IDEA_ecb_encrypt(_in + i, _out + i, @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks);
        i := i+bl;
    end;
    Result := 1;
end;


function idea_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
   while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
   begin
       IDEA_cbc_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
          @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
       inl := inl - ((size_t(1) shl (sizeof(long) *8-2)));
       _in  := _in + ((size_t(1) shl (sizeof(long) *8-2)));
       _out := _out + ((size_t(1) shl (sizeof(long) *8-2)));
   end;
   if inl > 0 then
      IDEA_cbc_encrypt(_in, _out, long(inl),
         @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
   Result := 1;
end;


function idea_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num: int;
begin
   while inl>= (size_t(1) shl (sizeof(long) *8-2)) do
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       IDEA_ofb64_encrypt(_in, _out, long(size_t(1) shl (sizeof(long) *8-2)),
                  @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
       EVP_CIPHER_CTX_set_num(ctx, num);
       inl := inl - ((size_t(1) shl(sizeof(long) *8-2)));
       _in  := _in + ((size_t(1) shl(sizeof(long) *8-2)));
       _out := _out + ((size_t(1) shl(sizeof(long) *8-2)));
   end;
   if inl > 0 then
   begin
      num := EVP_CIPHER_CTX_get_num(ctx);
      IDEA_ofb64_encrypt(_in, _out, long(inl),
             @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
      EVP_CIPHER_CTX_set_num(ctx, num);
   end;
 Result := 1;
end;


function idea_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  chunk, ret : size_t;
  num: int;
begin
   chunk := (size_t(1) shl (sizeof(long) *8-2));
   if 64 = 1 then
     chunk := chunk  shr 3;
   if inl < chunk then chunk := inl;
   while (inl > 0)  and  (inl >= chunk) do
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       if EVP_CIPHER_CTX_test_flags(ctx, $2000) > 0 then
          ret := chunk*8
       else
          ret := chunk;

       IDEA_cfb64_encrypt(_in, _out, long( (64 = 1)  and
                                           (0>=ret)),
              @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num, EVP_CIPHER_CTX_is_encrypting(ctx));
       EVP_CIPHER_CTX_set_num(ctx, num);
       inl  := inl - chunk;
       _in  := _in + chunk;
       _out  := _out + chunk;
       if inl < chunk then chunk := inl;
   end;
   Result := 1;
end;




function EVP_idea_cbc:PEVP_CIPHER;
begin
 Result := @idea_cbc;
end;


function EVP_idea_cfb64:PEVP_CIPHER;
begin
 Result := @idea_cfb64;
end;


function EVP_idea_ofb:PEVP_CIPHER;
begin
 Result := @idea_ofb;
end;


function EVP_idea_ecb:PEVP_CIPHER;
begin
 Result := @idea_ecb;
end;

function idea_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  tmp : TIDEA_KEY_SCHEDULE;
begin
    if 0>=enc then
    begin
        if EVP_CIPHER_CTX_get_mode(ctx) = EVP_CIPH_OFB_MODE then
            enc := 1
        else if (EVP_CIPHER_CTX_get_mode(ctx) = EVP_CIPH_CFB_MODE) then
            enc := 1;
    end;
    if enc > 0 then
       IDEA_set_encrypt_key(key, @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks)
    else
    begin
        IDEA_set_encrypt_key(key, @tmp);
        IDEA_set_decrypt_key(@tmp, @PEVP_IDEA_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx)).ks);
        OPENSSL_cleanse(@tmp, sizeof(TIDEA_KEY_SCHEDULE));
    end;
    Result := 1;
end;

initialization

    idea_cbc   := get_EVP_CIPHER( 34, 8, 16, 8, 0 or $2, 1, idea_init_key, idea_cbc_cipher, Pointer(0) , sizeof(TIDEA_KEY_SCHEDULE), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    idea_cfb64 := get_EVP_CIPHER( 35, 1, 16, 8, 0 or $3, 1, idea_init_key, idea_cfb64_cipher, Pointer(0) , sizeof(TIDEA_KEY_SCHEDULE), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    idea_ofb   := get_EVP_CIPHER( 46, 1, 16, 8, 0 or $4, 1, idea_init_key, idea_ofb_cipher, Pointer(0) , sizeof(TIDEA_KEY_SCHEDULE), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );
    idea_ecb   := get_EVP_CIPHER( 36, 8, 16, 0, 0 or $1, 1, idea_init_key, idea_ecb_cipher, Pointer(0) , sizeof(TIDEA_KEY_SCHEDULE), EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, Pointer(0) , Pointer(0)  );


end.
