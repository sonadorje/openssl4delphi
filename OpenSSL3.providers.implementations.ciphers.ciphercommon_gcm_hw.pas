unit OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm_hw;

interface
 uses OpenSSL.Api;



 function ossl_gcm_setiv(ctx : PPROV_GCM_CTX;const iv : PByte; ivlen : size_t):integer;
  function ossl_gcm_aad_update(ctx : PPROV_GCM_CTX;const aad : PByte; aad_len : size_t):integer;
  function ossl_gcm_cipher_update(ctx : PPROV_GCM_CTX;const _in : PByte; len : size_t; _out : PByte):integer;
  function ossl_gcm_cipher_final( ctx : PPROV_GCM_CTX; tag : PByte):integer;
  function ossl_gcm_one_shot(ctx : PPROV_GCM_CTX; aad : PByte; aad_len : size_t;const _in : PByte; in_len : size_t; _out, tag : PByte; tag_len : size_t):integer;

implementation
uses openssl3.crypto.modes.gcm128;


function ossl_gcm_setiv(ctx : PPROV_GCM_CTX;const iv : PByte; ivlen : size_t):integer;
begin
    CRYPTO_gcm128_setiv(@ctx.gcm, iv, ivlen);
    Result := 1;
end;


function ossl_gcm_aad_update(ctx : PPROV_GCM_CTX;const aad : PByte; aad_len : size_t):integer;
begin
    Result := Int(CRYPTO_gcm128_aad(@ctx.gcm, aad, aad_len) = 0);
end;


function ossl_gcm_cipher_update(ctx : PPROV_GCM_CTX;const _in : PByte; len : size_t; _out : PByte):integer;
begin
    if ctx.enc > 0 then
    begin
        if CRYPTO_gcm128_encrypt(@ctx.gcm, _in, _out, len) > 0 then
            Exit(0);
    end
    else
    begin
        if CRYPTO_gcm128_decrypt(@ctx.gcm, _in, _out, len) > 0 then
            Exit(0);
    end;
    Result := 1;
end;


function ossl_gcm_cipher_final( ctx : PPROV_GCM_CTX; tag : PByte):integer;
begin
    if ctx.enc > 0 then
    begin
        CRYPTO_gcm128_tag(@ctx.gcm, tag, GCM_TAG_MAX_SIZE);
        ctx.taglen := GCM_TAG_MAX_SIZE;
    end
    else
    begin
        if CRYPTO_gcm128_finish(@ctx.gcm, tag, ctx.taglen) <> 0  then
            Exit(0);
    end;
    Result := 1;
end;


function ossl_gcm_one_shot(ctx : PPROV_GCM_CTX; aad : PByte; aad_len : size_t;const _in : PByte; in_len : size_t; _out, tag : PByte; tag_len : size_t):integer;
var
  ret : integer;
  label _err;
begin
    ret := 0;
    { Use saved AAD }
    if 0>=ctx.hw.aadupdate(ctx, aad, aad_len ) then
        goto _err;
    if 0>=ctx.hw.cipherupdate(ctx, _in, in_len, _out) then
        goto _err;
    ctx.taglen := GCM_TAG_MAX_SIZE;
    if 0>=ctx.hw.cipherfinal(ctx, tag) then
        goto _err;
    ret := 1;
_err:
    Result := ret;
end;


end.
