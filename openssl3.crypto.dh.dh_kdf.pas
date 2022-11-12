unit openssl3.crypto.dh.dh_kdf;

interface
uses OpenSSL.Api;

function ossl_dh_kdf_X9_42_asn1(&out : PByte; outlen : size_t;const Z : PByte; Zlen : size_t;const cek_alg : PUTF8Char; ukm : PByte; ukmlen : size_t;const md : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function DH_KDF_X9_42(_out : PByte; outlen : size_t;const Z : PByte; Zlen : size_t; key_oid : PASN1_OBJECT;const ukm : PByte; ukmlen : size_t;const md : PEVP_MD):integer;

implementation
uses openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.kdf_meth,
     openssl3.crypto.evp.kdf_lib, openssl3.crypto.params,
     openssl3.crypto.provider_core, openssl3.crypto.objects.obj_dat;






function DH_KDF_X9_42(_out : PByte; outlen : size_t;const Z : PByte; Zlen : size_t; key_oid : PASN1_OBJECT;const ukm : PByte; ukmlen : size_t;const md : PEVP_MD):integer;
var
  key_alg : array[0..(OSSL_MAX_NAME_SIZE)-1] of byte;

  prov : POSSL_PROVIDER;

  libctx : POSSL_LIB_CTX;
begin
     prov := EVP_MD_get0_provider(md);
    libctx := ossl_provider_libctx(prov);
    if OBJ_obj2txt(@key_alg, sizeof(key_alg) , key_oid, 0) <= 0 then
        Exit(0);
    Exit(ossl_dh_kdf_X9_42_asn1(_out, outlen, Z, Zlen, @key_alg,
                                  ukm, ukmlen, md, libctx, nil));
end;

function ossl_dh_kdf_X9_42_asn1(&out : PByte; outlen : size_t;const Z : PByte; Zlen : size_t;const cek_alg : PUTF8Char; ukm : PByte; ukmlen : size_t;const md : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;

  kctx : PEVP_KDF_CTX;

  kdf : PEVP_KDF;

  params : array[0..4] of TOSSL_PARAM;
  p      : POSSL_PARAM;
  mdname : PUTF8Char;
  label _err;
begin
    ret := 0;
    kctx := nil;
    kdf := nil;
    p := @params;
   mdname := EVP_MD_get0_name(md);
    kdf := EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X942KDF_ASN1, propq);
    kctx := EVP_KDF_CTX_new(kdf);
    if kctx = nil then goto _err ;
    p^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            PUTF8Char(mdname), 0);
    Inc(p);
    p^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             PByte (Z), Zlen);
    Inc(p);
    if ukm <> nil then
    begin
      p^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_UKM,
                                                 PByte (ukm), ukmlen);
      Inc(p);
    end;
    p^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
                                            PUTF8Char  (cek_alg), 0);
    Inc(p);
    p^ := OSSL_PARAM_construct_end();
    ret := Int(EVP_KDF_derive(kctx, &out, outlen, @params) > 0);
_err:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    Result := ret;
end;

end.
