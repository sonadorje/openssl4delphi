unit openssl3.crypto.evp.c_alld;

interface
uses OpenSSL.Api;

procedure openssl_add_all_digests_int;

implementation
uses openssl3.crypto.evp.names,           openssl3.crypto.evp.legacy_md4,
     openssl3.crypto.evp.legacy_md5_sha1, openssl3.crypto.evp.legacy_sha,
     openssl3.crypto.evp.legacy_mdc2,     openssl3.crypto.evp.legacy_ripemd,
     openssl3.crypto.evp.legacy_md5,      openssl3.crypto.evp;

procedure openssl_add_all_digests_int;
begin
{$IFNDEF OPENSSL_NO_MD4}
    EVP_add_digest(EVP_md4);
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
    EVP_add_digest(EVP_md5);
    EVP_add_digest_alias(SN_md5, 'ssl3-md5');
    EVP_add_digest(EVP_md5_sha1);
{$ENDIF}
    EVP_add_digest(EVP_sha1);
    EVP_add_digest_alias(SN_sha1, 'ssl3-sha1');
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
{$IF not defined(OPENSSL_NO_MDC2)  and   not defined(OPENSSL_NO_DES)}
    EVP_add_digest(EVP_mdc2);
{$ENDIF}
{$IFNDEF OPENSSL_NO_RMD160}
    EVP_add_digest(EVP_ripemd160);
    EVP_add_digest_alias(SN_ripemd160, 'ripemd');
    EVP_add_digest_alias(SN_ripemd160, 'rmd160');
{$ENDIF}
    EVP_add_digest(EVP_sha224);
    EVP_add_digest(EVP_sha256);
    EVP_add_digest(EVP_sha384);
    EVP_add_digest(EVP_sha512);
    EVP_add_digest(EVP_sha512_224);
    EVP_add_digest(EVP_sha512_256);
{$IFNDEF OPENSSL_NO_WHIRLPOOL}
    //EVP_add_digest(EVP_whirlpool);
{$ENDIF}
{$IFNDEF OPENSSL_NO_SM3}
    //EVP_add_digest(EVP_sm3);
{$ENDIF}
{$IFNDEF OPENSSL_NO_BLAKE2}
    //EVP_add_digest(EVP_blake2b512);
    //EVP_add_digest(EVP_blake2s256);
{$ENDIF}
    EVP_add_digest(EVP_sha3_224);
    EVP_add_digest(EVP_sha3_256);
    EVP_add_digest(EVP_sha3_384);
    EVP_add_digest(EVP_sha3_512);
    //EVP_add_digest(EVP_shake128);
    //EVP_add_digest(EVP_shake256);
end;


end.
