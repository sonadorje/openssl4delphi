unit openssl3.crypto.evp.p_open;

interface
uses openssl.api;

 function EVP_OpenInit(ctx : PEVP_CIPHER_CTX;const &type : PEVP_CIPHER; ek : PByte; ekl : integer;const iv : PByte; priv : PEVP_PKEY):integer;
 function EVP_OpenFinal( ctx : PEVP_CIPHER_CTX; &out : PByte; outl : PInteger):integer;

implementation
uses
   OpenSSL3.Err, OpenSSL3.common,    openssl3.crypto.params,
   openssl3.crypto.evp.evp_enc,      openssl3.crypto.evp.evp_lib,
   openssl3.crypto.provider_core,    openssl3.crypto.rand.rand_lib,
   openssl3.crypto.evp.pmeth_lib,    openssl3.crypto.evp.asymcipher,
   openssl3.crypto.mem;




function EVP_OpenInit(ctx : PEVP_CIPHER_CTX;const &type : PEVP_CIPHER; ek : PByte; ekl : integer;const iv : PByte; priv : PEVP_PKEY):integer;
var
  key : PByte;
  keylen : size_t;
  ret : integer;
  pctx : PEVP_PKEY_CTX;
  label _err;
begin
    key := nil;
    keylen := 0;
    ret := 0;
    pctx := nil;
    if &type <> nil then
    begin
        EVP_CIPHER_CTX_reset(ctx);
        if 0>=EVP_DecryptInit_ex(ctx, &type, nil, nil, nil) then
            goto _err;
    end;
    if priv = nil then Exit(1);
    pctx := EVP_PKEY_CTX_new(priv, nil);
    if pctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if (EVP_PKEY_decrypt_init(pctx) <= 0 )
         or  (EVP_PKEY_decrypt(pctx, nil, @keylen, ek, ekl) <= 0) then
        goto _err;
    key := OPENSSL_malloc(keylen);
    if key = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if EVP_PKEY_decrypt(pctx, key, @keylen, ek, ekl) <= 0  then
        goto _err;
    if (0>=EVP_CIPHER_CTX_set_key_length(ctx, keylen)) or
       (0>=EVP_DecryptInit_ex(ctx, nil, nil, key, iv)) then
        goto _err;
    ret := 1;

 _err:
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_clear_free(key, keylen);
    Result := ret;
end;


function EVP_OpenFinal( ctx : PEVP_CIPHER_CTX; &out : PByte; outl : PInteger):integer;
var
  i : integer;
begin
    i := EVP_DecryptFinal_ex(ctx, out, outl);
    if i > 0 then
       i := EVP_DecryptInit_ex(ctx, nil, nil, nil, nil);
    Result := i;
end;




end.
