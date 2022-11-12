unit openssl3.crypto.evp.e_rc2;

interface
uses OpenSSL.Api;

const
  RC2_40_MAGIC  =  $a0;
  RC2_64_MAGIC  =  $78;
  RC2_128_MAGIC =  $3a;
type
  TEVP_RC2_KEY = record
      key_bits : integer;
      ks       : TRC2_KEY;
  end;
  PEVP_RC2_KEY = ^TEVP_RC2_KEY;

  function EVP_rc2_64_cbc:PEVP_CIPHER;
  function rc2_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
  function rc2_meth_to_magic( e : PEVP_CIPHER_CTX):integer;
  function rc2_magic_to_meth( i : integer):integer;
  function rc2_get_asn1_type_and_iv( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE):integer;
  function rc2_set_asn1_type_and_iv( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE):integer;
  function rc2_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
  function data(ctx: PEVP_CIPHER_CTX): PEVP_RC2_KEY;


  function rc2_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function rc2_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function rc2_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function rc2_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function EVP_rc2_cbc:PEVP_CIPHER;
  function EVP_rc2_cfb64:PEVP_CIPHER;
  function EVP_rc2_ofb:PEVP_CIPHER;
  function EVP_rc2_ecb:PEVP_CIPHER;
  function EVP_rc2_40_cbc:PEVP_CIPHER;


var
    rc2_cbc   : TEVP_CIPHER  { 37, 8, 16, 8, $8 | $40 | $2, 1, rc2_init_key, rc2_cbc_cipher, Pointer(0) , sizeof(EVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  };
    rc2_cfb64 : TEVP_CIPHER  { 39, 1, 16, 8, $8 | $40 | $3, 1, rc2_init_key, rc2_cfb64_cipher, Pointer(0) , sizeof(EVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  };
    rc2_ofb   : TEVP_CIPHER  { 40, 1, 16, 8, $8 | $40 | $4, 1, rc2_init_key, rc2_ofb_cipher, Pointer(0) , sizeof(EVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  };
    rc2_ecb   : TEVP_CIPHER  { 38, 8, 16, 0, $8 | $40 | $1, 1, rc2_init_key, rc2_ecb_cipher, Pointer(0) , sizeof(EVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  };
    r2_64_cbc_cipher, r2_40_cbc_cipher :TEVP_CIPHER ;

implementation

uses openssl3.crypto.rc2.rc2_skey,     openssl3.crypto.evp.evp_lib,
     openssl3.crypto.asn1.evp_asn1,    openssl3.crypto.rc2.rc2_cbc,
     openssl3.crypto.rc2.rc2cfb64,     openssl3.crypto.rc2.rc2_ecb,
     openssl3.crypto.rc2.rc2ofb64,
     openssl3.crypto.evp.evp_enc,      OpenSSL3.Err;




function EVP_rc2_40_cbc:PEVP_CIPHER;
begin
    Result := @r2_40_cbc_cipher;
end;






function rc2_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
     while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
     begin
         RC2_cbc_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
               @PEVP_RC2_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks,
               @ctx.iv, EVP_CIPHER_CTX_is_encrypting(ctx));
         inl := inl - ((size_t(1)  shl (sizeof(long)*8-2)));
         _in  := _in + ((size_t(1)   shl (sizeof(long)*8-2)));
         _out := _out + ((size_t(1)  shl (sizeof(long)*8-2)));
     end;
     if inl > 0 then
        RC2_cbc_encrypt(_in, _out, long(inl),
             @PEVP_RC2_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv,
               EVP_CIPHER_CTX_is_encrypting(ctx));
     Result := 1;
end;


function rc2_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  chunk, ret : size_t;
  num: int;
begin
   chunk := (size_t(1) shl (sizeof(long)*8-2));
   if 64 = 1 then
      chunk := chunk shr  3;
   if inl < chunk then chunk := inl;
   while (inl > 0) and  (inl >= chunk) do
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       if EVP_CIPHER_CTX_test_flags(ctx, $2000) > 0 then
          ret := chunk*8
       else
          ret := chunk;
       RC2_cfb64_encrypt(_in, _out, long ((64 = 1)  and
              (0>= ret)),
              @PEVP_RC2_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv,
              @num, EVP_CIPHER_CTX_is_encrypting(ctx));

       EVP_CIPHER_CTX_set_num(ctx, num);
       inl  := inl - chunk;
       _in  := _in + chunk;
       _out  := _out + chunk;
       if inl < chunk then chunk := inl;
   end;
   Result := 1;
end;


function rc2_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl : size_t;
begin
   bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
   if inl < bl then Exit(1);
   inl  := inl - bl;
   i :=0;
   while i <= inl do
   begin
       RC2_ecb_encrypt(_in + i, _out + i,
            @PEVP_RC2_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks,
            EVP_CIPHER_CTX_is_encrypting(ctx));
       i := i + (bl);
   end;
   Result := 1;
end;


function rc2_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num: Int;
begin
   while inl>=(size_t(1) shl (sizeof(long)*8-2)) do
  begin
     num := EVP_CIPHER_CTX_get_num(ctx);
     RC2_ofb64_encrypt(_in, _out, long(size_t(1) shl (sizeof(long)*8-2)),
        @PEVP_RC2_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
     EVP_CIPHER_CTX_set_num(ctx, num);
     inl := inl - ((size_t(1)   shl (sizeof(long)*8-2)));
     _in  := _in + ((size_t(1)  shl (sizeof(long)*8-2)));
     _out := _out + ((size_t(1) shl (sizeof(long)*8-2)));
   end;
   if inl > 0 then
   begin
       num := EVP_CIPHER_CTX_get_num(ctx);
       RC2_ofb64_encrypt(_in, _out, long(inl),
          @PEVP_RC2_KEY (EVP_CIPHER_CTX_get_cipher_data(ctx)).ks, @ctx.iv, @num);
       EVP_CIPHER_CTX_set_num(ctx, num);
   end;
   Result := 1;
end;


function EVP_rc2_cbc:PEVP_CIPHER;
begin
 Result := @rc2_cbc;
end;


function EVP_rc2_cfb64:PEVP_CIPHER;
begin
 Result := @rc2_cfb64;
end;


function EVP_rc2_ofb:PEVP_CIPHER;
begin
 Result := @rc2_ofb;
end;


function EVP_rc2_ecb:PEVP_CIPHER;
begin
 Result := @rc2_ecb;
end;

function data(ctx: PEVP_CIPHER_CTX): PEVP_RC2_KEY;
begin
  Result := PEVP_RC2_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
end;

function EVP_rc2_64_cbc:PEVP_CIPHER;
begin
    Result := @r2_64_cbc_cipher;
end;


function rc2_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
begin
    RC2_set_key(@data(ctx).ks, EVP_CIPHER_CTX_get_key_length(ctx),
                key, data(ctx).key_bits);
    Result := 1;
end;


function rc2_meth_to_magic( e : PEVP_CIPHER_CTX):integer;
var
  i : integer;
begin
    if EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GET_RC2_KEY_BITS, 0, @i) <= 0  then
        Exit(0);
    if i = 128 then
       Exit(RC2_128_MAGIC)
    else if (i = 64) then
        Exit(RC2_64_MAGIC)
    else if (i = 40) then
        Exit(RC2_40_MAGIC)
    else
        Result := 0;
end;


function rc2_magic_to_meth( i : integer):integer;
begin
    if i = RC2_128_MAGIC then
       Exit(128)
    else if (i = RC2_64_MAGIC) then
        Exit(64)
    else if (i = RC2_40_MAGIC) then
        Exit(40)
    else
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_SIZE);
        Exit(0);
    end;
end;


function rc2_get_asn1_type_and_iv( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE):integer;
var
  num      : long;
  i,
  key_bits : integer;
  l        : uint32;
  iv       : array[0..(EVP_MAX_IV_LENGTH)-1] of Byte;
begin
    num := 0;
    i := 0;
    if &type <> nil then
    begin
        l := EVP_CIPHER_CTX_get_iv_length(c);
        assert(l <= sizeof(iv));
        i := ASN1_TYPE_get_int_octetstring(&type, @num, @iv, l);
        if i <> int(l) then Exit(-1);
        key_bits := rc2_magic_to_meth(int(num));
        if 0>=key_bits then Exit(-1);
        if (i > 0)  and  (0>=EVP_CipherInit_ex(c, nil, nil, nil, @iv, -1)) then
            Exit(-1);
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_RC2_KEY_BITS, key_bits,
                                nil) <= 0 )
                 or  (EVP_CIPHER_CTX_set_key_length(c, key_bits div 8) <= 0)  then
            Exit(-1);
    end;
    Result := i;
end;


function rc2_set_asn1_type_and_iv( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE):integer;
var
  num : long;
  i, j : integer;
begin
    i := 0;
    if &type <> nil then begin
        num := rc2_meth_to_magic(c);
        j := EVP_CIPHER_CTX_get_iv_length(c);
        i := ASN1_TYPE_set_int_octetstring(&type, num, @c.oiv, j);
    end;
    Result := i;
end;


function rc2_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
begin
    case &type of
        EVP_CTRL_INIT:
        begin
            data(c).key_bits := EVP_CIPHER_CTX_get_key_length(c) * 8;
            Exit(1);
        end;
        EVP_CTRL_GET_RC2_KEY_BITS:
        begin
            PInteger (ptr)^ := data(c).key_bits;
            Exit(1);
        end;
        EVP_CTRL_SET_RC2_KEY_BITS:
        begin
            if arg > 0 then begin
                data(c).key_bits := arg;
                Exit(1);
            end;
            Exit(0);
        end;
    {$IFDEF PBE_PRF_TEST}
        EVP_CTRL_PBE_PRF_NID:
        begin
            *(PInteger )ptr = NID_hmacWithMD5;
            Exit(1);
    {$ENDIF}
        else
            Exit(-1);
    end;
end;

 initialization
  r2_64_cbc_cipher := get_EVP_CIPHER(
    NID_rc2_64_cbc,
    8, 8 (* 64 bit *) , 8,
    EVP_CIPH_CBC_MODE or EVP_CIPH_VARIABLE_LENGTH or EVP_CIPH_CTRL_INIT,
    EVP_ORIG_GLOBAL,
    rc2_init_key,
    rc2_cbc_cipher,
    nil,
    sizeof(TEVP_RC2_KEY),
    rc2_set_asn1_type_and_iv,
    rc2_get_asn1_type_and_iv,
    rc2_ctrl,
    nil);
 r2_40_cbc_cipher := get_EVP_CIPHER(
    NID_rc2_40_cbc,
    8, 5 (* 40 bit *) , 8,
    EVP_CIPH_CBC_MODE or EVP_CIPH_VARIABLE_LENGTH or EVP_CIPH_CTRL_INIT,
    EVP_ORIG_GLOBAL,
    rc2_init_key,
    rc2_cbc_cipher,
    nil,
    sizeof(TEVP_RC2_KEY),
    rc2_set_asn1_type_and_iv,
    rc2_get_asn1_type_and_iv,
    rc2_ctrl,
    nil);

    rc2_cbc   := get_EVP_CIPHER( 37, 8, 16, 8, $8  or  $40  or  $2, 1, rc2_init_key, rc2_cbc_cipher, Pointer(0) ,   sizeof(TEVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  );
    rc2_cfb64 := get_EVP_CIPHER( 39, 1, 16, 8, $8  or  $40  or  $3, 1, rc2_init_key, rc2_cfb64_cipher, Pointer(0) , sizeof(TEVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  );
    rc2_ofb   := get_EVP_CIPHER( 40, 1, 16, 8, $8  or  $40  or  $4, 1, rc2_init_key, rc2_ofb_cipher, Pointer(0) ,   sizeof(TEVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  );
    rc2_ecb   := get_EVP_CIPHER( 38, 8, 16, 0, $8  or  $40  or  $1, 1, rc2_init_key, rc2_ecb_cipher, Pointer(0) ,   sizeof(TEVP_RC2_KEY), rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl, Pointer(0)  );

end.
