unit OpenSSL3.providers.implementations.prov.implementations;

interface
uses OpenSSL.Api;

var
  ossl_sha1_functions,
  ossl_sha224_functions,
  ossl_sha256_functions,
  ossl_sha384_functions,
  ossl_sha512_functions,
  ossl_sha512_224_functions,
  ossl_sha512_256_functions,
  ossl_sha3_224_functions,
  ossl_sha3_256_functions,
  ossl_sha3_384_functions,
  ossl_sha3_512_functions,
  ossl_keccak_224_functions,
  ossl_keccak_256_functions,
  ossl_keccak_384_functions,
  ossl_keccak_512_functions,
  ossl_keccak_kmac_128_functions,
  ossl_keccak_kmac_256_functions,
  ossl_shake_128_functions,
  ossl_shake_256_functions,
  ossl_blake2s256_functions,
  ossl_blake2b512_functions,
  ossl_md5_functions,
  ossl_md5_sha1_functions,
  ossl_sm3_functions,
  ossl_md2_functions,
  ossl_md4_functions,
  ossl_mdc2_functions,
  ossl_wp_functions,
  ossl_ripemd160_functions,
  ossl_nullmd_functions: TArray<TOSSL_DISPATCH>;

  ossl_blake2bmac_functions,
  ossl_blake2smac_functions,
  ossl_cmac_functions,
  ossl_gmac_functions,
  ossl_hmac_functions,
  ossl_kmac128_functions,
  ossl_kmac256_functions,
  ossl_siphash_functions,
  ossl_poly1305_functions   : TArray<TOSSL_DISPATCH>;

implementation

end.
