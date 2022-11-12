unit openssl3.crypto.siv128;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

function ossl_siv128_init(ctx : PSIV128_CONTEXT;const key : PByte; klen : integer;const cbc, ctr : PEVP_CIPHER; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function ossl_siv128_copy_ctx( dest, src : PSIV128_CONTEXT):integer;
function ossl_siv128_set_tag(ctx : PSIV128_CONTEXT;const tag : PByte; len : size_t):integer;
function ossl_siv128_speed( ctx : PSIV128_CONTEXT; arg : integer):integer;
 function ossl_siv128_cleanup( ctx : PSIV128_CONTEXT):integer;
 function ossl_siv128_finish( ctx : PSIV128_CONTEXT):integer;
 function ossl_siv128_aad(ctx : PSIV128_CONTEXT;const aad : PByte; len : size_t):integer;
 procedure siv128_dbl( b : PSIV_BLOCK);
 function siv128_getword( const b: PSIV_BLOCK; i : size_t):uint64;
 function byteswap8( x : uint64):uint64;
  function rotl8( x : uint32):uint32;inline;
   function rotr8( x : uint32):uint32;inline;
   procedure siv128_putword( b : PSIV_BLOCK; i : size_t; x : uint64);
   procedure siv128_xorblock( x : PSIV_BLOCK; const y: PSIV_BLOCK);
   function ossl_siv128_encrypt(ctx : PSIV128_CONTEXT;const _in : PByte; _out : PByte; len : size_t):integer;
   function siv128_do_s2v_p( ctx : PSIV128_CONTEXT; _out : PSIV_BLOCK; const _in: PByte; len : size_t):integer;
   function siv128_do_encrypt( ctx : PEVP_CIPHER_CTX; _out : PByte; const _in: PByte; len : size_t; icv : PSIV_BLOCK):integer;

var // 1d arrays
  zero : array[0..15] of Byte;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,           OpenSSL3.crypto.params, OpenSSL3.Err,
     openssl3.crypto.params_from_text,  openssl3.crypto.evp.evp_lib,
     openssl3.crypto.evp.evp_enc,       openssl3.crypto.evp.mac_lib,
     openssl3.crypto.aes.aes_core,      openssl3.crypto.aes.aes_cbc,
     openssl3.crypto.evp.mac_meth,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb_hw,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw,
     openssl3.crypto.evp.ctrl_params_translate;


function siv128_do_encrypt( ctx : PEVP_CIPHER_CTX; _out : PByte; const _in: PByte; len : size_t; icv : PSIV_BLOCK):integer;
var
  out_len : integer;
begin
    out_len := int (len);
    if 0>= EVP_CipherInit_ex(ctx, nil, nil, nil, @icv.byte, 1) then
        Exit(0);
    Result := EVP_EncryptUpdate(ctx, _out, @out_len, _in, out_len);
end;

function siv128_do_s2v_p( ctx : PSIV128_CONTEXT; _out : PSIV_BLOCK; const _in: PByte; len : size_t):integer;
var
  t : TSIV_BLOCK;

  out_len : size_t;

  mac_ctx : PEVP_MAC_CTX;

  ret : integer;
  label _err;
begin
    out_len := sizeof(_out.byte);
    ret := 0;
    mac_ctx := EVP_MAC_CTX_dup(ctx.mac_ctx_init);
    if mac_ctx = nil then Exit(0);
    if len >= SIV_LEN then begin
        if 0>= EVP_MAC_update(mac_ctx, _in, len - SIV_LEN) then
            goto _err ;
        memcpy(@t, _in + (len-SIV_LEN), SIV_LEN);
        siv128_xorblock(@t, @ctx.d);
        if 0>= EVP_MAC_update(mac_ctx, @t.byte, SIV_LEN) then
            goto _err ;
    end
    else
    begin
        memset(@t, 0, sizeof(t));
        memcpy(@t, _in, len);
        t.byte[len] := $80;
        siv128_dbl(@ctx.d);
        siv128_xorblock(@t, @ctx.d);
        if 0>= EVP_MAC_update(mac_ctx, @t.byte, SIV_LEN )then
            goto _err ;
    end;
    if (0>= EVP_MAC_final(mac_ctx, @_out.byte, @out_len, sizeof(_out.byte)) )
         or  (out_len <> SIV_LEN) then
        goto _err ;
    ret := 1;
_err:
    EVP_MAC_CTX_free(mac_ctx);
    Result := ret;
end;


function ossl_siv128_encrypt(ctx : PSIV128_CONTEXT;const _in : PByte; _out : PByte; len : size_t):integer;
var
  q : TSIV_BLOCK;
begin
    { can only do one crypto operation }
    if ctx.crypto_ok = 0 then Exit(0);
    Dec(ctx.crypto_ok);
    if 0>= siv128_do_s2v_p(ctx, @q, _in, len) then
        Exit(0);
    memcpy(@ctx.tag.byte, @q, SIV_LEN);
    q.byte[8] := q.byte[8] and $7f;
    q.byte[12] := q.byte[12] and $7f;
    if 0>= siv128_do_encrypt(ctx.cipher_ctx, _out, _in, len, @q) then
        Exit(0);
    ctx.final_ret := 0;
    Result := len;
end;



procedure siv128_xorblock( x : PSIV_BLOCK; const y: PSIV_BLOCK);
begin
    x.word[0]  := x.word[0] xor (y.word[0]);
    x.word[1]  := x.word[1] xor (y.word[1]);
end;




procedure siv128_putword( b : PSIV_BLOCK; i : size_t; x : uint64);
var
  ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
       b.word[i] := byteswap8(x)
    else
        b.word[i] := x;
end;




function rotr8( x : uint32):uint32;
begin
    Result := (x  shr  8) or (x  shl  24);
end;

function rotl8( x : uint32):uint32;
begin
    Result := (x  shl  8) or (x  shr  24);
end;

function byteswap8( x : uint64):uint64;
var
  high, low : uint32;
begin
    high := uint32 (x  shr  32);
    low := uint32( x);
    high := (rotl8(high) and $00ff00ff) or (rotr8(high) and $ff00ff00);
    low := (rotl8(low) and $00ff00ff) or (rotr8(low) and $ff00ff00);
    Result := (uint64( low))  shl  32 or uint64( high);
end;

function siv128_getword( const b: PSIV_BLOCK; i : size_t):uint64;
var
  ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
       Exit(byteswap8(b.word[i]));
    Result := b.word[i];
end;




procedure siv128_dbl( b : PSIV_BLOCK);
var
  high,
  low,
  high_carry,
  low_carry  : uint64;
  low_mask   : int64;
  high_mask  : uint64;
begin
    high := siv128_getword(b, 0);
    low := siv128_getword(b, 1);
    high_carry := high and (uint64( 1)  shl  63);
    low_carry := low and (uint64( 1)  shl  63);
    low_mask := -(int64( (high_carry  shr  63))) and $87;
    high_mask := low_carry  shr  63;
    high := (high  shl  1) or high_mask;
    low := (low  shl  1)  xor  uint64( low_mask);
    siv128_putword(b, 0, high);
    siv128_putword(b, 1, low);
end;



function ossl_siv128_aad(ctx : PSIV128_CONTEXT;const aad : PByte; len : size_t):integer;
var
  mac_out : TSIV_BLOCK;

  out_len : size_t;

  mac_ctx : PEVP_MAC_CTX;
begin
    out_len := SIV_LEN;
    siv128_dbl(@ctx.d);
    mac_ctx := EVP_MAC_CTX_dup(ctx.mac_ctx_init);
    if (mac_ctx = nil)
         or  (0>= EVP_MAC_update(mac_ctx, aad, len))
         or  (0>= EVP_MAC_final(mac_ctx, @mac_out.byte, @out_len,
                          sizeof(mac_out.byte)))
         or  (out_len <> SIV_LEN) then
    begin
        EVP_MAC_CTX_free(mac_ctx);
        Exit(0);
    end;
    EVP_MAC_CTX_free(mac_ctx);
    siv128_xorblock(@ctx.d, @mac_out);
    Result := 1;
end;




function ossl_siv128_finish( ctx : PSIV128_CONTEXT):integer;
begin
    Result := ctx.final_ret;
end;

function ossl_siv128_cleanup( ctx : PSIV128_CONTEXT):integer;
begin
    if ctx <> nil then
    begin
        EVP_CIPHER_CTX_free(ctx.cipher_ctx);
        ctx.cipher_ctx := nil;
        EVP_MAC_CTX_free(ctx.mac_ctx_init);
        ctx.mac_ctx_init := nil;
        EVP_MAC_free(ctx.mac);
        ctx.mac := nil;
        OPENSSL_cleanse(@ctx.d, sizeof(ctx.d));
        OPENSSL_cleanse(@ctx.tag, sizeof(ctx.tag));
        ctx.final_ret := -1;
        ctx.crypto_ok := 1;
    end;
    Result := 1;
end;



function ossl_siv128_speed( ctx : PSIV128_CONTEXT; arg : integer):integer;
begin
    ctx.crypto_ok := get_result(arg = 1 , -1 , 1);
    Result := 1;
end;

function ossl_siv128_set_tag(ctx : PSIV128_CONTEXT;const tag : PByte; len : size_t):integer;
begin
    if len <> SIV_LEN then Exit(0);
    { Copy the tag from the supplied buffer }
    memcpy(@ctx.tag.byte, tag, len);
    Result := 1;
end;



function ossl_siv128_copy_ctx( dest, src : PSIV128_CONTEXT):integer;
begin
    memcpy(@dest.d, @src.d, sizeof(src.d));
    if dest.cipher_ctx = nil then
    begin
        dest.cipher_ctx := EVP_CIPHER_CTX_new();
        if dest.cipher_ctx = nil then Exit(0);
    end;
    if 0>= EVP_CIPHER_CTX_copy(dest.cipher_ctx, src.cipher_ctx )then
        Exit(0);
    EVP_MAC_CTX_free(dest.mac_ctx_init);
    dest.mac_ctx_init := EVP_MAC_CTX_dup(src.mac_ctx_init);
    if dest.mac_ctx_init = nil then Exit(0);
    dest.mac := src.mac;
    if dest.mac <> nil then EVP_MAC_up_ref(dest.mac);
    Result := 1;
end;





function ossl_siv128_init(ctx : PSIV128_CONTEXT;const key : PByte; klen : integer;const cbc, ctr : PEVP_CIPHER; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  out_len : size_t;

  mac_ctx : PEVP_MAC_CTX;
  cbc_name: PUTF8Char;
  params : array[0..2] of TOSSL_PARAM;
begin
    FIllchar(zero, SIV_LEN-1, 0);
    out_len := SIV_LEN;
    mac_ctx := nil;
    if ctx = nil then Exit(0);
    memset(@ctx.d, 0, sizeof(ctx.d));
    EVP_CIPHER_CTX_free(ctx.cipher_ctx);
    EVP_MAC_CTX_free(ctx.mac_ctx_init);
    EVP_MAC_free(ctx.mac);
    ctx.mac := nil;
    ctx.cipher_ctx := nil;
    ctx.mac_ctx_init := nil;
    if (key = nil)  or  (cbc = nil)  or  (ctr = nil) then Exit(0);
    cbc_name := EVP_CIPHER_get0_name(cbc);
    params[0] := OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 PUTF8Char(  cbc_name), 0);
    params[1] := OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                  Pointer( key), klen);
    params[2] := OSSL_PARAM_construct_end();
    ctx.cipher_ctx := EVP_CIPHER_CTX_new();
    ctx.mac := EVP_MAC_fetch(libctx, OSSL_MAC_NAME_CMAC, propq);
    ctx.mac_ctx_init := EVP_MAC_CTX_new(ctx.mac);
    mac_ctx := EVP_MAC_CTX_dup(ctx.mac_ctx_init);
    if (ctx.cipher_ctx = nil)
             or  (ctx.mac = nil)
             or  (ctx.mac_ctx_init = nil)
             or  (0>= EVP_MAC_CTX_set_params(ctx.mac_ctx_init, @params))
             or  (0>= EVP_EncryptInit_ex(ctx.cipher_ctx, ctr, nil, key + klen, nil))
             or  (mac_ctx = nil)
             or  (0>= EVP_MAC_update(mac_ctx, @zero, sizeof(zero)))
             or  (0>= EVP_MAC_final(mac_ctx, @ctx.d.byte, @out_len,
                              sizeof(ctx.d.byte))) then
    begin
        EVP_CIPHER_CTX_free(ctx.cipher_ctx);
        EVP_MAC_CTX_free(ctx.mac_ctx_init);
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(ctx.mac);
        Exit(0);
    end;
    EVP_MAC_CTX_free(mac_ctx);
    ctx.final_ret := -1;
    ctx.crypto_ok := 1;
    Result := 1;
end;


end.
