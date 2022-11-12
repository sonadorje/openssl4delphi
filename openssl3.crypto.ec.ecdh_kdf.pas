unit openssl3.crypto.ec.ecdh_kdf;

interface
uses OpenSSL.Api;

function ossl_ecdh_kdf_X9_63(&out : PByte; outlen : size_t;const Z : PByte; Zlen : size_t;const sinfo : PByte; sinfolen : size_t;const md : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;

implementation
 uses openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.kdf_meth,
      openssl3.crypto.evp.kdf_lib, openssl3.crypto.params;

function ossl_ecdh_kdf_X9_63(&out : PByte; outlen : size_t;const Z : PByte; Zlen : size_t;const sinfo : PByte; sinfolen : size_t;const md : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;

  kctx : PEVP_KDF_CTX;

  params : array[0..3] of TOSSL_PARAM;
  p: POSSL_PARAM;
  mdname : PUTF8Char;

  kdf : PEVP_KDF;
begin
    ret := 0;
    kctx := nil;
    p := @params;
    mdname := EVP_MD_get0_name(md);
    kdf := EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X963KDF, propq);
    kctx := EVP_KDF_CTX_new(kdf );
    if kctx<> nil then
    begin
        PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                PUTF8Char(  mdname), 0);
        PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 Pointer( Z), Zlen);
        PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 Pointer( sinfo), sinfolen);
        p^ := OSSL_PARAM_construct_end();
        ret := Int(EVP_KDF_derive(kctx, &out, outlen, @params) > 0);
        EVP_KDF_CTX_free(kctx);
    end;
    EVP_KDF_free(kdf);
    Result := ret;
end;


end.
