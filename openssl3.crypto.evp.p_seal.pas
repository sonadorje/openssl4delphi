unit openssl3.crypto.evp.p_seal;

interface
uses openssl.api;

function EVP_SealInit(ctx : PEVP_CIPHER_CTX;const _type : PEVP_CIPHER; ek : PPByte; ekl : PInteger; iv : PByte; pubk : PPEVP_PKEY; npubk : integer):integer;
function EVP_SealFinal( ctx : PEVP_CIPHER_CTX; &out : PByte; outl : PInteger):integer;

implementation
uses
   OpenSSL3.Err, OpenSSL3.common,    openssl3.crypto.params,
   openssl3.crypto.evp.evp_enc,      openssl3.crypto.evp.evp_lib,
   openssl3.crypto.provider_core,    openssl3.crypto.rand.rand_lib,
   openssl3.crypto.evp.pmeth_lib,    openssl3.crypto.evp.asymcipher,
   openssl3.crypto.mem;


function EVP_SealInit(ctx : PEVP_CIPHER_CTX;const _type : PEVP_CIPHER; ek : PPByte; ekl : PInteger; iv : PByte; pubk : PPEVP_PKEY; npubk : integer):integer;
var
  key : array[0..(EVP_MAX_KEY_LENGTH)-1] of Byte;
  prov : POSSL_PROVIDER;
  libctx : POSSL_LIB_CTX;
  pctx : PEVP_PKEY_CTX;
  cipher : PEVP_CIPHER;
  i, len, rv : integer;
  keylen : size_t;
  label _err;
begin
{$POINTERMATH ON}
    libctx := nil;
    pctx := nil;
    rv := 0;
    if _type <> nil then
    begin
        EVP_CIPHER_CTX_reset(ctx);
        if 0>=EVP_EncryptInit_ex(ctx, _type, nil, nil, nil) then
            Exit(0);
    end;
    cipher := EVP_CIPHER_CTX_get0_cipher(ctx);
    if (cipher <> nil) then
    begin
        prov := EVP_CIPHER_get0_provider(cipher);
        if prov <> nil then
           libctx := ossl_provider_libctx(prov);
    end;
    if (npubk <= 0) or  (nil=pubk) then
        Exit(1);
    if EVP_CIPHER_CTX_rand_key(ctx, @key) <= 0  then
        Exit(0);
    len := EVP_CIPHER_CTX_get_iv_length(ctx);
    if (len < 0)  or  (RAND_priv_bytes_ex(libctx, iv, len, 0) <= 0) then
        goto _err;
    len := EVP_CIPHER_CTX_get_key_length(ctx);
    if len < 0 then
       goto _err;
    if 0>=EVP_EncryptInit_ex(ctx, nil, nil, @key, iv) then
        goto _err;
    for i := 0 to npubk-1 do
    begin
        keylen := len;
        pctx := EVP_PKEY_CTX_new_from_pkey(libctx, pubk[i], nil);
        if pctx = nil then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        if (EVP_PKEY_encrypt_init(pctx) <= 0)
             or  (EVP_PKEY_encrypt(pctx, ek[i], @keylen, @key, keylen) <= 0)  then
            goto _err;
        ekl[i] := int(keylen);
        EVP_PKEY_CTX_free(pctx);
    end;
    pctx := nil;
    rv := npubk;

_err:
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(@key, sizeof(key));
    Result := rv;
{$POINTERMATH OFF}
end;


function EVP_SealFinal( ctx : PEVP_CIPHER_CTX; &out : PByte; outl : PInteger):integer;
var
  i : integer;
begin
    i := EVP_EncryptFinal_ex(ctx, out, outl);
    if i > 0 then
       i := EVP_EncryptInit_ex(ctx, nil, nil, nil, nil);
    Result := i;
end;


end.
