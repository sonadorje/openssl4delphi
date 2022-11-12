unit openssl3.crypto.evp.e_des3;

interface
uses OpenSSL.Api;

  function EVP_des_ede_cbc:PEVP_CIPHER;
  function EVP_des_ede_cfb64:PEVP_CIPHER;
  function EVP_des_ede_ofb:PEVP_CIPHER;
  function EVP_des_ede_ecb:PEVP_CIPHER;
  function EVP_des_ede3_cbc:PEVP_CIPHER;
  function EVP_des_ede3_cfb64:PEVP_CIPHER;
  function EVP_des_ede3_ofb:PEVP_CIPHER;
  function EVP_des_ede3_ecb:PEVP_CIPHER;
  function EVP_des_ede3_cfb1:PEVP_CIPHER;
  function EVP_des_ede3_cfb8:PEVP_CIPHER;


var
  des_ede_cbc,
  des_ede_cfb64,
  des_ede_ofb,
  des_ede_ecb,
  des_ede3_cbc,
  des_ede3_cfb64,
  des_ede3_ofb,
  des_ede3_ecb,
  des_ede3_cfb1,
  des3_wrap,
  des_ede3_cfb8  : TEVP_CIPHER;

function des_ede_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
function des_ede_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des3_ctrl( ctx : PEVP_CIPHER_CTX; _type, arg : integer; ptr : Pointer):integer;
function des_ede_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_ede_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function data(ctx: PEVP_CIPHER_CTX): PDES_EDE_KEY;
function des_ede_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_ede3_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
function des_ede3_cfb1_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_ede3_cfb8_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function EVP_des_ede:PEVP_CIPHER;
function EVP_des_ede3:PEVP_CIPHER;
function EVP_des_ede3_wrap:PEVP_CIPHER;
function des_ede3_wrap_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_ede3_wrap(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;

const // 1d arrays
  wrap_iv : array[0..7] of byte = (
    $4a, $dd, $a2, $2c, $79, $e8, $21, $05 );

function des_ede3_unwrap(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
implementation

uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}openssl3.crypto.evp.evp_lib,      openssl3.crypto.des.set_key,
     openssl3.crypto.rand.rand_lib,    openssl3.crypto.des.cfb64ede,
     openssl3.crypto.des.ofb64ede,     openssl3.crypto.des.ecb3_enc,
     openssl3.crypto.evp.evp_enc,      OpenSSL3.Err,
     openssl3.crypto.sha.sha1_one,     openssl3.crypto.mem,
     openssl3.crypto.buffer.buffer,    openssl3.crypto.cpuid,
     openssl3.crypto.evp,              openssl3.crypto.des.des_enc;




function des_ede3_unwrap(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  icv, iv : array[0..7] of Byte;
  sha1tmp : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
  rv : integer;
begin
    rv := -1;
    if inl < 24 then Exit(-1);
    if _out = nil then Exit(inl - 16);
    memcpy(@ctx.iv, @wrap_iv, 8);
    { Decrypt first block which will end up as icv }
    des_ede_cbc_cipher(ctx, @icv, _in, 8);
    { Decrypt central blocks }
    {
     * If decrypting in place move whole output along a block so the next
     * des_ede_cbc_cipher is in place.
     }
    if _out = _in then begin
        memmove(_out, _out + 8, inl - 8);
        _in  := _in - 8;
    end;
    des_ede_cbc_cipher(ctx, _out, _in + 8, inl - 16);
    { Decrypt final block which will be IV }
    des_ede_cbc_cipher(ctx, @iv, _in + inl - 8, 8);
    { Reverse order of everything }
    BUF_reverse(@icv, nil, 8);
    BUF_reverse(_out, nil, inl - 16);
    BUF_reverse(@ctx.iv, @iv, 8);
    { Decrypt again using new IV }
    des_ede_cbc_cipher(ctx, _out, _out, inl - 16);
    des_ede_cbc_cipher(ctx, @icv, @icv, 8);
    if (ossl_sha1(_out, inl - 16, @sha1tmp) <> nil){ Work out hash of first portion }
             and  (CRYPTO_memcmp(@sha1tmp, @icv, 8) = 0)  then
        rv := inl - 16;
    OPENSSL_cleanse(@icv, 8);
    OPENSSL_cleanse(@sha1tmp, SHA_DIGEST_LENGTH);
    OPENSSL_cleanse(@iv, 8);
    OPENSSL_cleanse(@ctx.iv, 8);
    if rv = -1 then OPENSSL_cleanse(_out, inl - 16);
    Result := rv;
end;


function des_ede3_wrap(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  sha1tmp : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
begin
    if _out = nil then Exit(inl + 16);
    { Copy input to output buffer + 8 so we have space for IV }
    memmove(_out + 8, _in, inl);
    { Work out ICV }
    if nil =ossl_sha1(_in, inl, @sha1tmp) then
        Exit(-1);
    memcpy(_out + inl + 8, @sha1tmp, 8);
    OPENSSL_cleanse(@sha1tmp, SHA_DIGEST_LENGTH);
    { Generate random IV }
    if RAND_bytes(@ctx.iv, 8) <= 0  then
        Exit(-1);
    memcpy(_out, @ctx.iv, 8);
    { Encrypt everything after IV in place }
    des_ede_cbc_cipher(ctx, _out + 8, _out + 8, inl + 8);
    BUF_reverse(_out, nil, inl + 16);
    memcpy(@ctx.iv, @wrap_iv, 8);
    des_ede_cbc_cipher(ctx, _out, _out, inl + 16);
    Result := inl + 16;
end;



function des_ede3_wrap_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    {
     * Sanity check input length: we typically only wrap keys so EVP_MAXCHUNK
     * is more than will ever be needed. Also input length must be a multiple
     * of 8 bits.
     }
    if (inl >= EVP_MAXCHUNK)  or  (inl mod 8 > 0) then Exit(-1);
    if ossl_is_partially_overlapping(_out, _in, inl) > 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
        Exit(0);
    end;
    if EVP_CIPHER_CTX_is_encrypting(ctx) > 0 then
        Exit(des_ede3_wrap(ctx, _out, _in, inl))
    else
        Result := des_ede3_unwrap(ctx, _out, _in, inl);
end;



function EVP_des_ede3_wrap:PEVP_CIPHER;
begin
    Result := @des3_wrap;
end;


function EVP_des_ede:PEVP_CIPHER;
begin
    Result := @des_ede_ecb;
end;


function EVP_des_ede3:PEVP_CIPHER;
begin
    Result := @des_ede3_ecb;
end;




function data(ctx: PEVP_CIPHER_CTX): PDES_EDE_KEY;
  begin
    Result := PDES_EDE_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
  end;



function des_ede3_cfb8_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    while inl >= EVP_MAXCHUNK do
    begin
        DES_ede3_cfb_encrypt(_in, _out, 8, long(EVP_MAXCHUNK),
                             @data(ctx).ks.ks[0], @data(ctx).ks.ks[1],
                             @data(ctx).ks.ks[2], PDES_cblock(@ctx.iv),
                             EVP_CIPHER_CTX_is_encrypting(ctx));
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then DES_ede3_cfb_encrypt(_in, _out, 8, long(inl),
                             @data(ctx).ks.ks[0], @data(ctx).ks.ks[1],
                             @data(ctx).ks.ks[2], PDES_cblock(@ctx.iv),
                             EVP_CIPHER_CTX_is_encrypting(ctx));
    Result := 1;
end;



function des_ede3_cfb1_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  n : size_t;
  c, d : array[0..0] of Byte;
begin

    if 0>=EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) then
            inl  := inl  * 8;
    for n := 0 to inl - 1 do
    begin
        c[0] := get_result(_in[n div 8] and (1 shl (7 - n mod 8)) > 0, $80 , 0);
        DES_ede3_cfb_encrypt(@c, @d, 1, 1,
                             @data(ctx).ks.ks[0], @data(ctx).ks.ks[1],
                             @data(ctx).ks.ks[2], PDES_cblock(@ctx.iv),
                             EVP_CIPHER_CTX_is_encrypting(ctx));
        _out[n div 8] := (_out[n div 8] and not ($80  shr  uint32(n mod 8)))
            or ((d[0] and $80)  shr  uint32(n mod 8));
    end;
    Result := 1;
end;



function des_ede3_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  deskey : PDES_cblock;
  dat : PDES_EDE_KEY;
  mode : integer;
begin
    deskey := PDES_cblock(key);
    dat := data(ctx);
    dat.stream.cbc := nil;
{$IF defined(SPARC_DES_CAPABLE)}
    if SPARC_DES_CAPABLE then begin
        mode := EVP_CIPHER_CTX_get_mode(ctx);
        if mode = EVP_CIPH_CBC_MODE then begin
            des_t4_key_expand(@deskey[0], @dat.ks.ks[0]);
            des_t4_key_expand(@deskey[1], @dat.ks.ks[1]);
            des_t4_key_expand(@deskey[2], @dat.ks.ks[2]);
            dat.stream.cbc := enc ? des_t4_ede3_cbc_encrypt :
                des_t4_ede3_cbc_decrypt;
            Exit(1);
        end;
    end;
{$ENDIF}
    DES_set_key_unchecked(@deskey[0], @dat.ks.ks[0]);
    DES_set_key_unchecked(@deskey[1], @dat.ks.ks[1]);
    DES_set_key_unchecked(@deskey[2], @dat.ks.ks[2]);
    Result := 1;
end;




function des_ede_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl: size_t ;
begin
    bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
    if (inl < bl) then Exit(1);
    inl := inl - bl;
    i :=0;
    while i <= inl do
    begin
        DES_ecb3_encrypt(Pconst_DES_cblock(_in + i),
                         PDES_cblock(_out + i),
                         @data(ctx).ks.ks[0], @data(ctx).ks.ks[1],
                         @data(ctx).ks.ks[2], EVP_CIPHER_CTX_is_encrypting(ctx));
        i := i + bl;
    end;
    Result := 1;
end;


function des_ede_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num : integer;
begin
    while inl >= EVP_MAXCHUNK do
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_ede3_ofb64_encrypt(_in, _out, long(EVP_MAXCHUNK),
                               @data(ctx).ks.ks[0], @data(ctx).ks.ks[1],
                               @data(ctx).ks.ks[2],
                               PDES_cblock(@ctx.iv),
                               @num);
        EVP_CIPHER_CTX_set_num(ctx, num);
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_ede3_ofb64_encrypt(_in, _out, long(inl),
                               @data(ctx).ks.ks[0], @data(ctx).ks.ks[1],
                               @data(ctx).ks.ks[2],
                               PDES_cblock(@ctx.iv),
                               @num);
        EVP_CIPHER_CTX_set_num(ctx, num);
    end;
    Result := 1;
end;



function des_ede_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num : integer;

begin
    while inl >= EVP_MAXCHUNK do
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_ede3_cfb64_encrypt(_in, _out, long(EVP_MAXCHUNK),
                               @data(ctx).ks.ks[0]{ks1}, @data(ctx).ks.ks[1]{ks2},
                               @data(ctx).ks.ks[0]{ks3}, PDES_cblock(@ctx.iv),
                               @num, EVP_CIPHER_CTX_is_encrypting(ctx));
        EVP_CIPHER_CTX_set_num(ctx, num);
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_ede3_cfb64_encrypt(_in, _out, long(inl),
                               @data(ctx).ks.ks[0]{ks1}, @data(ctx).ks.ks[1]{ks2},
                               @data(ctx).ks.ks[2]{ks3}, PDES_cblock(@ctx.iv),
                               @num, EVP_CIPHER_CTX_is_encrypting(ctx));
        EVP_CIPHER_CTX_set_num(ctx, num);
    end;
    Result := 1;
end;



function des3_ctrl( ctx : PEVP_CIPHER_CTX; _type, arg : integer; ptr : Pointer):integer;
var
  deskey : PDES_cblock;
  kl : integer;
begin
{$POINTERMATH ON}
    deskey := ptr;
    case _type of
    EVP_CTRL_RAND_KEY:
    begin
        kl := EVP_CIPHER_CTX_get_key_length(ctx);
        if (kl < 0)  or  (RAND_priv_bytes(ptr, kl) <= 0) then
            Exit(0);
        DES_set_odd_parity(deskey);
        if kl >= 16 then DES_set_odd_parity(deskey + 1);
        if kl >= 24 then DES_set_odd_parity(deskey + 2);
        Exit(1);
    end
    else
        Exit(-1);
    end;
{$POINTERMATH OFF}
end;


function des_ede_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  dat : PDES_EDE_KEY;
  function data(ctx: PEVP_CIPHER_CTX): PDES_EDE_KEY;
  begin
    Result := PDES_EDE_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
  end;
begin
    dat := data(ctx);
    if Assigned(dat.stream.cbc)then
    begin
        dat.stream.cbc (_in, _out, inl, @dat.ks.ks, @ctx.iv);
        Exit(1);
    end;
    while inl >= EVP_MAXCHUNK do
    begin
        DES_ede3_cbc_encrypt(_in, _out, long(EVP_MAXCHUNK),
                             @dat.ks.ks[0]{ks1}, @dat.ks.ks[1]{ks2}, @dat.ks.ks[2]{ks3},
                             PDES_cblock(@ctx.iv),
                             EVP_CIPHER_CTX_is_encrypting(ctx));
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then
       DES_ede3_cbc_encrypt(_in, _out, long(inl),
                             @dat.ks.ks[0]{ks1}, @dat.ks.ks[1]{ks2}, @dat.ks.ks[2]{ks3},
                             PDES_cblock(@ctx.iv),
                             EVP_CIPHER_CTX_is_encrypting(ctx));
    Result := 1;
end;

function des_ede_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  deskey : PDES_cblock;
  dat : PDES_EDE_KEY;
  mode : integer;
  function data(ctx: PEVP_CIPHER_CTX): PDES_EDE_KEY;
  begin
    Result := PDES_EDE_KEY(EVP_CIPHER_CTX_get_cipher_data(ctx))
  end;
begin
    deskey := PDES_cblock(key);
    dat := data(ctx);
    dat.stream.cbc := nil;
{$IF defined(SPARC_DES_CAPABLE)}
    if SPARC_DES_CAPABLE then
    begin
        mode := EVP_CIPHER_CTX_get_mode(ctx);
        if mode = EVP_CIPH_CBC_MODE then
        begin
            des_t4_key_expand(&deskey[0], &dat.ks.ks[0]{ks1});
            des_t4_key_expand(&deskey[1], &dat.ks.ks[1]{ks2});
            memcpy(&dat.ks.ks[2]{ks3}}, &dat.ks.ks[0]{ks1}, sizeof(dat.ks.ks[0]{ks1}));
            dat.stream.cbc := enc ? des_t4_ede3_cbc_encrypt :
                des_t4_ede3_cbc_decrypt;
            Exit(1);
        end;
    end;
{$ENDIF}
    DES_set_key_unchecked(@deskey[0], @dat.ks.ks[0]{ks1});
    DES_set_key_unchecked(@deskey[1], @dat.ks.ks[1]{ks2});
    memcpy(@dat.ks.ks[0]{ks3}, @dat.ks.ks[0]{ks1}, sizeof(dat.ks.ks[0]{ks1}));
    Result := 1;
end;



function EVP_des_ede_cbc:PEVP_CIPHER;
begin
 Result := @des_ede_cbc;
end;


function EVP_des_ede_cfb64:PEVP_CIPHER;
begin
 Result := @des_ede_cfb64;
end;


function EVP_des_ede_ofb:PEVP_CIPHER;
begin
 Result := @des_ede_ofb;
end;


function EVP_des_ede_ecb:PEVP_CIPHER;
begin
 Result := @des_ede_ecb;
end;


function EVP_des_ede3_cbc:PEVP_CIPHER;
begin
 Result := @des_ede3_cbc;
end;


function EVP_des_ede3_cfb64:PEVP_CIPHER;
begin
 Result := @des_ede3_cfb64;
end;


function EVP_des_ede3_ofb:PEVP_CIPHER;
begin
 Result := @des_ede3_ofb;
end;


function EVP_des_ede3_ecb:PEVP_CIPHER;
begin
 Result := @des_ede3_ecb;
end;


function EVP_des_ede3_cfb1:PEVP_CIPHER;
begin
 Result := @des_ede3_cfb1;
end;


function EVP_des_ede3_cfb8:PEVP_CIPHER;
begin
 Result := @des_ede3_cfb8;
end;

initialization
    des_ede_cbc    := get_EVP_CIPHER( 43, 8, 16, 8, $200 or 0 or $2, 1, des_ede_init_key, des_ede_cbc_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede_cfb64  := get_EVP_CIPHER( 60, 1, 16, 8, $200 or 0 or $3, 1, des_ede_init_key, des_ede_cfb64_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede_ofb    := get_EVP_CIPHER( 62, 1, 16, 8, $200 or 0 or $4, 1, des_ede_init_key, des_ede_ofb_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede_ecb    := get_EVP_CIPHER( 32, 8, 16, 0, $200 or 0 or $1, 1, des_ede_init_key, des_ede_ecb_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede3_cbc   := get_EVP_CIPHER( 44, 8, 24, 8, $200 or 0 or $2, 1, des_ede3_init_key, des_ede_cbc_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede3_cfb64 := get_EVP_CIPHER( 61, 1, 24, 8, $200 or 0 or $3, 1, des_ede3_init_key, des_ede_cfb64_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede3_ofb   := get_EVP_CIPHER( 63, 1, 24, 8, $200 or 0 or $4, 1, des_ede3_init_key, des_ede_ofb_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede3_ecb   := get_EVP_CIPHER( 33, 8, 24, 0, $200 or 0 or $1, 1, des_ede3_init_key, des_ede_ecb_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede3_cfb1  := get_EVP_CIPHER( 658, 1, 24, 8, $200 or 0 or $3, 1, des_ede3_init_key, des_ede3_cfb1_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );
    des_ede3_cfb8  := get_EVP_CIPHER( 659, 1, 24, 8, $200 or 0 or $3, 1, des_ede3_init_key, des_ede3_cfb8_cipher, Pointer(0) , sizeof(TDES_EDE_KEY), Pointer(0) , Pointer(0) , des3_ctrl, Pointer(0)  );

    des3_wrap := get_EVP_CIPHER (
                  NID_id_smime_alg_CMS3DESwrap,
                  8, 24, 0,
                  EVP_CIPH_WRAP_MODE or EVP_CIPH_CUSTOM_IV or EVP_CIPH_FLAG_CUSTOM_CIPHER
                      or EVP_CIPH_FLAG_DEFAULT_ASN1,
                  EVP_ORIG_GLOBAL,
                  des_ede3_init_key, des_ede3_wrap_cipher,
                  nil,
                  sizeof(TDES_EDE_KEY),
                  nil, nil, nil, nil);
end.
