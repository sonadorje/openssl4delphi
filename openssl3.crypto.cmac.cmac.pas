unit openssl3.crypto.cmac.cmac;

interface
uses OpenSSL.Api, SysUtils;

function _CMAC_Init(ctx : PCMAC_CTX;const key : Pointer; keylen : size_t;const cipher : PEVP_CIPHER; impl : PENGINE):integer;
procedure make_kn(k1 : PByte;const l : PByte; bl : integer);
function _CMAC_Final( ctx : PCMAC_CTX; _out : PByte; poutlen : Psize_t):integer;
function CMAC_CTX_new:PCMAC_CTX;
 procedure CMAC_CTX_free( ctx : PCMAC_CTX);
 procedure CMAC_CTX_cleanup( ctx : PCMAC_CTX);
 function CMAC_CTX_copy(_out : PCMAC_CTX;const _in : PCMAC_CTX):integer;
 function CMAC_CTX_get0_cipher_ctx( ctx : PCMAC_CTX):PEVP_CIPHER_CTX;

var // 1d arrays
  zero_iv : array[0..EVP_MAX_BLOCK_LENGTH-1] of Byte;

implementation
uses openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.evp_enc,
     openssl3.crypto.mem        , OpenSSL3.Err;


function CMAC_CTX_get0_cipher_ctx( ctx : PCMAC_CTX):PEVP_CIPHER_CTX;
begin
    Result := ctx.cctx;
end;


function CMAC_CTX_copy(_out : PCMAC_CTX;const _in : PCMAC_CTX):integer;
var
  bl : integer;
begin
    if _in.nlast_block = -1 then Exit(0);
    bl := EVP_CIPHER_CTX_get_block_size(_in.cctx);
    if bl < 0 then
        Exit(0);
    if 0>=EVP_CIPHER_CTX_copy(_out.cctx, _in.cctx) then
        Exit(0);
    memcpy(@_out.k1, @_in.k1, bl);
    memcpy(@_out.k2, @_in.k2, bl);
    memcpy(@_out.tbl, @_in.tbl, bl);
    memcpy(@_out.last_block, @_in.last_block, bl);
    _out.nlast_block := _in.nlast_block;
    Result := 1;
end;




procedure CMAC_CTX_cleanup( ctx : PCMAC_CTX);
begin
    EVP_CIPHER_CTX_reset(ctx.cctx);
    OPENSSL_cleanse(@ctx.tbl, EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(@ctx.k1, EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(@ctx.k2, EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(@ctx.last_block, EVP_MAX_BLOCK_LENGTH);
    ctx.nlast_block := -1;
end;




procedure CMAC_CTX_free( ctx : PCMAC_CTX);
begin
    if nil =ctx then Exit;
    CMAC_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx.cctx);
    OPENSSL_free(Pointer(ctx));
end;





function CMAC_CTX_new:PCMAC_CTX;
var
  ctx : PCMAC_CTX;
begin
    ctx := OPENSSL_malloc(sizeof( ctx^));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.cctx := EVP_CIPHER_CTX_new;
    if ctx.cctx = nil then begin
        OPENSSL_free(Pointer(ctx));
        Exit(nil);
    end;
    ctx.nlast_block := -1;
    Result := ctx;
end;




function _CMAC_Final( ctx : PCMAC_CTX; _out : PByte; poutlen : Psize_t):integer;
var
  i, bl, lb : integer;
begin
    if ctx.nlast_block = -1 then Exit(0);
    bl := EVP_CIPHER_CTX_get_block_size(ctx.cctx);
    if bl < 0 then
        Exit(0);
    if poutlen <> nil then
       poutlen^ := size_t( bl);
    if nil = _out then Exit(1);
    lb := ctx.nlast_block;
    { Is last block complete? }
    if lb = bl then
    begin
        for i := 0 to bl-1 do
            _out[i] := ctx.last_block[i]  xor  ctx.k1[i];
    end
    else
    begin
        ctx.last_block[lb] := $80;
        if bl - lb > 1 then
           memset(PByte(@ctx.last_block) + lb + 1, 0, bl - lb - 1);
        for i := 0 to bl-1 do
            _out[i] := ctx.last_block[i]  xor  ctx.k2[i];
    end;
    if EVP_Cipher(ctx.cctx, _out, _out, bl )<= 0 then
    begin
        OPENSSL_cleanse(_out, bl);
        Exit(0);
    end;
    Result := 1;
end;

procedure make_kn(k1 : PByte;const l : PByte; bl : integer);
var
  i : integer;

  c,carry, cnext : Byte;
begin
    c := l[0]; carry := c  shr  7;
    { Shift block to left, including carry }
    for i := 0 to bl - 1 -1 do
    begin
        cnext := l[i + 1];
        k1[i] := (c  shl  1) or ((cnext)  shr  7);
        c := cnext;
    end;
    { If MSB set fixup with R }
    k1[i] := (c  shl  1)  xor  ((0 - carry) and get_result(bl = 16 , $87 , $1b));
end;

function _CMAC_Init(ctx : PCMAC_CTX;const key : Pointer; keylen : size_t;const cipher : PEVP_CIPHER; impl : PENGINE):integer;
var
  bl : integer;
begin
     FillChar(zero_iv, EVP_MAX_BLOCK_LENGTH, 0);

    { All zeros means restart }
    if (nil = key)  and  (nil = cipher)  and  (nil = impl)  and  (keylen = 0) then
    begin
        { Not initialised }
        if ctx.nlast_block = -1 then
            Exit(0);
        if 0>= EVP_EncryptInit_ex(ctx.cctx, nil, nil, nil, @zero_iv ) then
            Exit(0);
        memset(@ctx.tbl, 0, EVP_CIPHER_CTX_get_block_size(ctx.cctx));
        ctx.nlast_block := 0;
        Exit(1);
    end;
    { Initialise context }
    if cipher <> nil then
    begin
        { Ensure we can't use this ctx until we also have a key }
        ctx.nlast_block := -1;
        if 0>= EVP_EncryptInit_ex(ctx.cctx, cipher, impl, nil, nil ) then
            Exit(0);
    end;
    { Non-nil key means initialisation complete }
    if key <> nil then
    begin
        { If anything fails then ensure we can't use this ctx }
        ctx.nlast_block := -1;
        if nil = EVP_CIPHER_CTX_get0_cipher(ctx.cctx ) then
            Exit(0);
        if 0>= EVP_CIPHER_CTX_set_key_length(ctx.cctx, keylen ) then
            Exit(0);
        if 0>= EVP_EncryptInit_ex(ctx.cctx, nil, nil, key, @zero_iv ) then
            Exit(0);
        bl := EVP_CIPHER_CTX_get_block_size(ctx.cctx );
        if  bl  < 0 then
            Exit(0);
        if EVP_Cipher(ctx.cctx, @ctx.tbl, @zero_iv, bl ) <= 0 then
            Exit(0);
        make_kn(@ctx.k1, @ctx.tbl, bl);
        make_kn(@ctx.k2, @ctx.k1, bl);
        OPENSSL_cleanse(@ctx.tbl, bl);
        { Reset context again ready for first data block }
        if 0>= EVP_EncryptInit_ex(ctx.cctx, nil, nil, nil, @zero_iv ) then
            Exit(0);
        { Zero tbl so resume works }
        memset(@ctx.tbl, 0, bl);
        ctx.nlast_block := 0;
    end;
    Result := 1;
end;

end.
