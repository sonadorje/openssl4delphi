unit OpenSSL3.providers.implementations.ciphers.ciphercommon_ccm_hw;

interface
uses OpenSSL.Api;

 function ossl_ccm_generic_setiv(ctx : PPROV_CCM_CTX;const nonce : PByte; nlen, mlen : size_t):integer;
  function ossl_ccm_generic_setaad(ctx : PPROV_CCM_CTX;const aad : PByte; alen : size_t):integer;
  function ossl_ccm_generic_gettag( ctx : PPROV_CCM_CTX; tag : PByte; tlen : size_t):integer;
  function ossl_ccm_generic_auth_encrypt(ctx : PPROV_CCM_CTX;const _in : PByte; _out : PByte; len : size_t; tag : PByte; taglen : size_t):integer;
  function ossl_ccm_generic_auth_decrypt(ctx : PPROV_CCM_CTX;const _in : PByte; _out : PByte; len : size_t; expected_tag : PByte; taglen : size_t):integer;

implementation
uses OpenSSL3.crypto.modes.ccm128, openssl3.crypto.cpuid,
     openssl3.crypto.mem;


function ossl_ccm_generic_setiv(ctx : PPROV_CCM_CTX;const nonce : PByte; nlen, mlen : size_t):integer;
begin
    Result := Int(CRYPTO_ccm128_setiv(@ctx.ccm_ctx, nonce, nlen, mlen) = 0);
end;


function ossl_ccm_generic_setaad(ctx : PPROV_CCM_CTX;const aad : PByte; alen : size_t):integer;
begin
    CRYPTO_ccm128_aad(@ctx.ccm_ctx, aad, alen);
    Result := 1;
end;


function ossl_ccm_generic_gettag( ctx : PPROV_CCM_CTX; tag : PByte; tlen : size_t):integer;
begin
    Result := Int(CRYPTO_ccm128_tag(@ctx.ccm_ctx, tag, tlen) > 0);
end;


function ossl_ccm_generic_auth_encrypt(ctx : PPROV_CCM_CTX;const _in : PByte; _out : PByte; len : size_t; tag : PByte; taglen : size_t):integer;
var
  rv : integer;
begin
    if Assigned(ctx.str) then
       rv := Int(CRYPTO_ccm128_encrypt_ccm64(@ctx.ccm_ctx, _in,
                                         _out, len, ctx.str) = 0)
    else
        rv := Int(CRYPTO_ccm128_encrypt(@ctx.ccm_ctx, _in, _out, len) = 0);
    if (rv = 1)  and  (tag <> nil) then
       rv := Int(CRYPTO_ccm128_tag(@ctx.ccm_ctx, tag, taglen) > 0);
    Result := rv;
end;


function ossl_ccm_generic_auth_decrypt(ctx : PPROV_CCM_CTX;const _in : PByte; _out : PByte; len : size_t; expected_tag : PByte; taglen : size_t):integer;
var
  rv : integer;
  tag : array[0..15] of Byte;
begin
    rv := 0;
    if Assigned(ctx.str) then
       rv := Int(CRYPTO_ccm128_decrypt_ccm64(@ctx.ccm_ctx, _in, _out, len,
                                         ctx.str) = 0)
    else
        rv := Int(CRYPTO_ccm128_decrypt(@ctx.ccm_ctx, _in, _out, len) = 0);
    if rv > 0 then
    begin
        if (0>=CRYPTO_ccm128_tag(@ctx.ccm_ctx, @tag, taglen))
             or  (CRYPTO_memcmp(@tag, expected_tag, taglen) <> 0)  then
            rv := 0;
    end;
    if rv = 0 then
       OPENSSL_cleanse(_out, len);
    Result := rv;
end;

end.
