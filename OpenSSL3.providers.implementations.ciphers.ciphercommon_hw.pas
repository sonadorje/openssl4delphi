unit OpenSSL3.providers.implementations.ciphers.ciphercommon_hw;

interface
uses OpenSSL.Api;

function ossl_cipher_hw_generic_cfb128(dat : PPROV_CIPHER_CTX; &out : PByte; &in : PByte; len : size_t):integer;
function ossl_cipher_hw_generic_cfb1(dat : PPROV_CIPHER_CTX; _out : PByte; _in : PByte; len : size_t):integer;
function ossl_cipher_hw_generic_ecb(dat : PPROV_CIPHER_CTX; &out : PByte; &in : PByte; len : size_t):integer;
function ossl_cipher_hw_generic_cbc(dat : PPROV_CIPHER_CTX; _out : PByte; _in : PByte; len : size_t):integer;
function ossl_cipher_hw_generic_ofb128(dat : PPROV_CIPHER_CTX; _out : PByte; _in : PByte; len : size_t):integer;
function ossl_cipher_hw_generic_cfb8(dat : PPROV_CIPHER_CTX; _out : PByte;_in : PByte; len : size_t):integer;
function ossl_cipher_hw_generic_ctr(dat : PPROV_CIPHER_CTX; &out : PByte;_in : PByte; len : size_t):integer;
function ossl_cipher_hw_chunked_cbc(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function ossl_cipher_hw_chunked_ofb128(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function ossl_cipher_hw_chunked_cfb128( ctx : PPROV_CIPHER_CTX; _out, _in : PByte; inl : size_t):integer;

function ossl_cipher_hw_chunked_cfb8( ctx : PPROV_CIPHER_CTX; _out, _in : PByte; inl : size_t):integer;

implementation
uses OpenSSL3.openssl.params, openssl3.crypto.params, OpenSSL3.Err,
     openssl3.crypto.modes.ctr128,          openssl3.crypto.modes.ofb128,
     openssl3.crypto.modes.cbc128,
     openssl3.providers.common.provider_ctx, openssl3.crypto.modes.cfb128;




function ossl_cipher_hw_chunked_cfb8( ctx : PPROV_CIPHER_CTX; _out, _in : PByte; inl : size_t):integer;
var
  chunk : size_t;
begin
    chunk := MAXCHUNK;
    if inl < chunk then chunk := inl;
    while (inl > 0)  and  (inl >= chunk) do
    begin
        ossl_cipher_hw_generic_cfb8(ctx, _out, _in, inl);
        inl  := inl - chunk;
        _in  := _in + chunk;
        _out  := _out + chunk;
        if inl < chunk then chunk := inl;
    end;
    Result := 1;
end;



function ossl_cipher_hw_chunked_cfb128( ctx : PPROV_CIPHER_CTX; _out, _in : PByte; inl : size_t):integer;
var
  chunk : size_t;
begin
    chunk := MAXCHUNK;
    if inl < chunk then chunk := inl;
    while (inl > 0)  and  (inl >= chunk) do
    begin
        ossl_cipher_hw_generic_cfb128(ctx, _out, _in, inl);
        inl  := inl - chunk;
        _in  := _in + chunk;
        _out  := _out + chunk;
        if inl < chunk then chunk := inl;
    end;
    Result := 1;
end;




function ossl_cipher_hw_chunked_ofb128(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    while inl >= MAXCHUNK do  begin
        ossl_cipher_hw_generic_ofb128(ctx, _out, _in, MAXCHUNK);
        inl  := inl - MAXCHUNK;
        _in   := _in  + MAXCHUNK;
        _out  := _out + MAXCHUNK;
    end;
    if inl > 0 then ossl_cipher_hw_generic_ofb128(ctx, _out, _in, inl);
    Result := 1;
end;


function ossl_cipher_hw_chunked_cbc(ctx : PPROV_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    while inl >= MAXCHUNK do  begin
        ossl_cipher_hw_generic_cbc(ctx, _out, _in, MAXCHUNK);
        inl  := inl - MAXCHUNK;
        _in   := _in  + MAXCHUNK;
        _out  := _out + MAXCHUNK;
    end;
    if inl > 0 then ossl_cipher_hw_generic_cbc(ctx, _out, _in, inl);
    Result := 1;
end;

function ossl_cipher_hw_generic_ctr(dat : PPROV_CIPHER_CTX; &out : PByte;_in : PByte; len : size_t):integer;
var
  num : uint32;
begin
    num := dat.num;
    if Assigned(dat.stream.ctr) then
       CRYPTO_ctr128_encrypt_ctr32(_in, &out, len, dat.ks, @dat.iv, @dat.buf,
                                    @num, dat.stream.ctr)
    else
        CRYPTO_ctr128_encrypt(_in, &out, len, dat.ks, @dat.iv, @dat.buf,
                              @num, dat.block);
    dat.num := num;
    Result := 1;
end;

function ossl_cipher_hw_generic_cfb8(dat : PPROV_CIPHER_CTX; _out : PByte;_in : PByte; len : size_t):integer;
var
  num : integer;
begin
    num := dat.num;
    CRYPTO_cfb128_8_encrypt(_in, _out, len, dat.ks, @dat.iv, @num, dat.enc,
                            dat.block);
    dat.num := num;
    Result := 1;
end;

function ossl_cipher_hw_generic_ofb128(dat : PPROV_CIPHER_CTX; _out : PByte; _in : PByte; len : size_t):integer;
var
  num : integer;
begin
    num := dat.num;
    CRYPTO_ofb128_encrypt(_in, _out, len, dat.ks, @dat.iv, @num, dat.block);
    dat.num := num;
    Result := 1;
end;



function ossl_cipher_hw_generic_cbc(dat : PPROV_CIPHER_CTX; _out : PByte; _in : PByte; len : size_t):integer;
begin
    if Assigned(dat.stream.cbc) then
       dat.stream.cbc(_in, _out, len, dat.ks, @dat.iv, dat.enc)
    else if (dat.enc>0) then
        CRYPTO_cbc128_encrypt(_in, _out, len, dat.ks, @dat.iv, dat.block)
    else
        CRYPTO_cbc128_decrypt(_in, _out, len, dat.ks, @dat.iv, dat.block);
    Result := 1;
end;



function ossl_cipher_hw_generic_ecb(dat : PPROV_CIPHER_CTX; &out : PByte; &in : PByte; len : size_t):integer;
var
  i, bl : size_t;
begin
    bl := dat.blocksize;
    if len < bl then Exit(1);
    if Assigned(dat.stream.ecb) then
    begin
        dat.stream.ecb(&in, &out, len, dat.ks, dat.enc);
    end
    else
    begin
        i := 0; len := len-bl;
        while i <= len do
        begin
            dat.block(&in + i, &out + i, dat.ks);
            i := i+bl;
        end;
    end;
    Result := 1;
end;




function ossl_cipher_hw_generic_cfb1(dat : PPROV_CIPHER_CTX; _out : PByte; _in : PByte; len : size_t):integer;
var
  num : integer;
begin
{$POINTERMATH ON}
    num := dat.num;
    if dat.use_bits>0 then
    begin
        CRYPTO_cfb128_1_encrypt(_in, _out, len, dat.ks, @dat.iv, @num,
                                dat.enc, dat.block);
        dat.num := num;
        Exit(1);
    end;
    while len >= MAXBITCHUNK do
    begin
        CRYPTO_cfb128_1_encrypt(_in, _out, MAXBITCHUNK * 8, dat.ks,
                                @dat.iv, @num, dat.enc, dat.block);
        len  := len - MAXBITCHUNK;
        _out  := _out + MAXBITCHUNK;
        _in  := _in  + MAXBITCHUNK;
    end;
    if len >0 then
       CRYPTO_cfb128_1_encrypt(_in, _out, len * 8, dat.ks, @dat.iv, @num,
                                dat.enc, dat.block);
    dat.num := num;
    Result := 1;
{$POINTERMATH OFF}
end;



function ossl_cipher_hw_generic_cfb128(dat : PPROV_CIPHER_CTX; &out : PByte; &in : PByte; len : size_t):integer;
var
  num : integer;
begin
    num := dat.num;
    CRYPTO_cfb128_encrypt(&in, &out, len, dat.ks, @dat.iv, @num, dat.enc,
                          dat.block);
    dat.num := num;
    Result := 1;
end;







end.
