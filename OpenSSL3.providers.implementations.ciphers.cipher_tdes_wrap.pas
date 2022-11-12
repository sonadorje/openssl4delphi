unit OpenSSL3.providers.implementations.ciphers.cipher_tdes_wrap;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.cipher_tdes_common,
     OpenSSL3.providers.implementations.ciphers.ciphercommon;

  function des_ede3_unwrap(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
  function des_ede3_wrap(ctx : PPROV_CIPHER_CTX; _out : PByte;const _in : PByte; inl : size_t):integer;
  function tdes_wrap_cipher_internal(ctx : PPROV_CIPHER_CTX; _out : PByte;const _in : PByte; inl : size_t):integer;
  function tdes_wrap_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function tdes_wrap_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;

  function tdes_wrap_newctx( provctx : Pointer):Pointer;
  function tdes_wrap_get_params( params : POSSL_PARAM):integer;

  const  ossl_tdes_wrap_cbc_functions: array[0..13] of TOSSL_DISPATCH = (
(function_id:  2; method:(code:@ossl_tdes_einit; data:nil)),
(function_id:  3; method:(code:@ ossl_tdes_dinit; data:nil)),
(function_id:  6; method:(code:@tdes_wrap_cipher; data:nil)),
(function_id:  1; method:(code:@tdes_wrap_newctx; data:nil)),
(function_id:  7; method:(code:@ossl_tdes_freectx; data:nil)),
(function_id:  4; method:(code:@tdes_wrap_update; data:nil)),
(function_id:  5; method:(code:@ossl_cipher_generic_stream_final; data:nil)),
(function_id:  9; method:(code:@tdes_wrap_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_tdes_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_tdes_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@ossl_cipher_generic_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}openssl3.crypto.buffer.buffer,   openssl3.crypto.sha.sha1_one, OpenSSL3.Err,
     openssl3.crypto.cpuid,           openssl3.crypto.mem,
     openssl3.crypto.rand.rand_lib,   openssl3.crypto.evp,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes,
     openssl3.providers.fips.self_test,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes_wrap_hw;

const wrap_iv: array[0..7] of Byte =
(
    $4a, $dd, $a2, $2c, $79, $e8, $21, $05
);




function tdes_wrap_newctx( provctx : Pointer):Pointer;
begin
 Exit(ossl_tdes_newctx(provctx, $10002, 64*3, 64, 0, $0002 or $0010, ossl_prov_cipher_hw_tdes_wrap_cbc));
end;


function tdes_wrap_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, $0002 or $0010, 64*3, 64, 0));
end;

function des_ede3_unwrap(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  icv : array[0..7] of Byte;
  iv : array[0..(TDES_IVLEN)-1] of Byte;
  sha1tmp : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
  rv : integer;
begin
    rv := -1;
    if inl < 24 then Exit(-1);
    if _out = nil then Exit(inl - 16);
    memcpy(@ctx.iv, @wrap_iv, 8);
    { Decrypt first block which will end up as icv }
    ctx.hw.cipher(ctx, @icv, _in, 8);
    { Decrypt central blocks }
    {
     * If decrypting in place move whole output along a block so the next
     * des_ede_cbc_cipher is in place.
     }
    if _out = _in then
    begin
        memmove(_out, _out + 8, inl - 8);
        _in  := _in - 8;
    end;
    ctx.hw.cipher(ctx, _out, _in + 8, inl - 16);
    { Decrypt final block which will be IV }
    ctx.hw.cipher(ctx, @iv, _in + inl - 8, 8);
    { Reverse order of everything }
    BUF_reverse(@icv, nil, 8);
    BUF_reverse(_out, nil, inl - 16);
    BUF_reverse(@ctx.iv, @iv, 8);
    { Decrypt again using new IV }
    ctx.hw.cipher(ctx, _out, _out, inl - 16);
    ctx.hw.cipher(ctx, @icv, @icv, 8);
    if (ossl_sha1(_out, inl - 16, @sha1tmp) <> nil) { Work out hash of first portion }
             and  (CRYPTO_memcmp(@sha1tmp, @icv, 8) = 0)  then
        rv := inl - 16;
    OPENSSL_cleanse(@icv, 8);
    OPENSSL_cleanse(@sha1tmp, SHA_DIGEST_LENGTH);
    OPENSSL_cleanse(@iv, 8);
    OPENSSL_cleanse(@ctx.iv, sizeof(ctx.iv));
    if rv = -1 then
       OPENSSL_cleanse(_out, inl - 16);
    Result := rv;
end;


function des_ede3_wrap(ctx : PPROV_CIPHER_CTX; _out : PByte;const _in : PByte; inl : size_t):integer;
var
  sha1tmp : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
  ivlen, icvlen, len : size_t;
begin
    ivlen := TDES_IVLEN;
    icvlen := TDES_IVLEN;
    len := inl + ivlen + icvlen;
    if _out = nil then Exit(len);
    { Copy input to output buffer + 8 so we have space for IV }
    memmove(_out + ivlen, _in, inl);
    { Work out ICV }
    if nil =ossl_sha1(_in, inl, @sha1tmp) then
        Exit(0);
    memcpy(_out + inl + ivlen, @sha1tmp, icvlen);
    OPENSSL_cleanse(@sha1tmp, SHA_DIGEST_LENGTH);
    { Generate random IV }
    if RAND_bytes_ex(ctx.libctx, @ctx.iv, ivlen, 0) <= 0  then
        Exit(0);
    memcpy(_out, @ctx.iv, ivlen);
    { Encrypt everything after IV in place }
    ctx.hw.cipher(ctx, _out + ivlen, _out + ivlen, inl + ivlen);
    BUF_reverse(_out, nil, len);
    memcpy(@ctx.iv, @wrap_iv, ivlen);
    ctx.hw.cipher(ctx, _out, _out, len);
    Result := len;
end;


function tdes_wrap_cipher_internal(ctx : PPROV_CIPHER_CTX; _out : PByte;const _in : PByte; inl : size_t):integer;
begin
    {
     * Sanity check input length: we typically only wrap keys so EVP_MAXCHUNK
     * is more than will ever be needed. Also input length must be a multiple
     * of 8 bits.
     }
    if (inl >= EVP_MAXCHUNK)  or  (inl mod 8 > 0) then Exit(-1);
    if ctx.enc > 0 then
       Exit(des_ede3_wrap(ctx, _out, _in, inl))
    else
        Result := des_ede3_unwrap(ctx, _out, _in, inl);
end;


function tdes_wrap_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_CIPHER_CTX;
  ret : integer;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    outl^ := 0;
    if not ossl_prov_is_running then Exit(0);
    if outsize < inl then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    ret := tdes_wrap_cipher_internal(ctx, _out, _in, inl);
    if ret <= 0 then Exit(0);
    outl^ := ret;
    Result := 1;
end;


function tdes_wrap_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
begin
    outl^ := 0;
    if inl = 0 then Exit(1);
    if outsize < inl then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>=tdes_wrap_cipher(vctx, _out, outl, outsize, _in, inl) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    Result := 1;
end;

end.
