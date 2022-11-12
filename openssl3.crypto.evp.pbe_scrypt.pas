unit openssl3.crypto.evp.pbe_scrypt;

interface
uses OpenSSL.Api;

const
   SCRYPT_MAX_MEM  = (1024 * 1024 * 32);

function EVP_PBE_scrypt_ex(pass : PUTF8Char; passlen : size_t; salt : PByte; saltlen : size_t; N, r, p, maxmem : uint64; key : PByte; keylen : size_t; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function EVP_PBE_scrypt(const pass : PUTF8Char; passlen : size_t;const salt : PByte; saltlen : size_t; N, r, p, maxmem : uint64; key : PByte; keylen : size_t):integer;

implementation
uses
   openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.kdf_meth,
   openssl3.crypto.evp.kdf_lib, openssl3.crypto.params,
   OpenSSL3.Err,  openssl3.crypto.evp.evp_pbe,
   openssl3.crypto.bio.bio_print, openssl3.crypto.bio.bio_dump;


function EVP_PBE_scrypt_ex( pass : PUTF8Char; passlen : size_t; salt : PByte; saltlen : size_t; N, r, p, maxmem : uint64; key : PByte; keylen : size_t; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  empty : PUTF8Char;
  rv : integer;
  kdf : PEVP_KDF;
  kctx : PEVP_KDF_CTX;
  params : array[0..6] of TOSSL_PARAM;
  z : POSSL_PARAM;
begin
     empty := '';
    rv := 1;
    z := @params;
    if (r > UINT32_MAX)  or  (p > UINT32_MAX) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_PARAMETER_TOO_LARGE);
        Exit(0);
    end;
    { Maintain existing behaviour. }
    if pass = nil then
    begin
        pass := empty;
        passlen := 0;
    end;
    if salt = nil then
    begin
        salt := PByte(empty);
        saltlen := 0;
    end;
    if maxmem = 0 then
       maxmem := SCRYPT_MAX_MEM;
    { Use OSSL_LIB_CTX_set0_default() if you need a library context }
    kdf := EVP_KDF_fetch(ctx, OSSL_KDF_NAME_SCRYPT, propq);
    kctx := EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if kctx = nil then Exit(0);
    PostInc(z)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                              PByte( pass),
                                                      passlen);
    PostInc(z)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             PByte( salt), saltlen);
    PostInc(z)^ := OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, @N);
    PostInc(z)^ := OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, @r);
    PostInc(z)^ := OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P, @p);
    PostInc(z)^ := OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, @maxmem);
    z^ := OSSL_PARAM_construct_end();
    if EVP_KDF_derive(kctx, key, keylen, @params) <> 1  then
        rv := 0;
    EVP_KDF_CTX_free(kctx);
    Result := rv;
end;


function EVP_PBE_scrypt(const pass : PUTF8Char; passlen : size_t;const salt : PByte; saltlen : size_t; N, r, p, maxmem : uint64; key : PByte; keylen : size_t):integer;
begin
    Exit(EVP_PBE_scrypt_ex(pass, passlen, salt, saltlen, N, r, p, maxmem,
                             key, keylen, nil, nil));
end;



end.
