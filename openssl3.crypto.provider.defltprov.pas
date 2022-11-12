unit openssl3.crypto.provider.defltprov;
{$I config.inc}
{As the compiler error message indicates, it expects a constant expression where
 you're initializing the const. But you're calling a function there, and the
 compiler won't evaluate it at compile time. }
interface
uses OpenSSL.Api,
     OpenSSL3.providers.implementations.kdfs.hkdf,
     OpenSSL3.providers.implementations.kdfs.sskdf,
     OpenSSL3.providers.implementations.kdfs.pbkdf2,
     OpenSSL3.providers.implementations.kdfs.pkcs12kdf,
     OpenSSL3.providers.implementations.kdfs.sshkdf,
     OpenSSL3.providers.implementations.kdfs.tls1_prf,
     OpenSSL3.providers.implementations.kdfs.kbkdf,
     OpenSSL3.providers.implementations.kdfs.x942kdf,
     OpenSSL3.providers.implementations.kdfs.scrypt,
     OpenSSL3.providers.implementations.kdfs.krb5kdf,
     OpenSSL3.providers.implementations.rands.drbg_ctr,
     OpenSSL3.providers.implementations.rands.drbg_hash,
     OpenSSL3.providers.implementations.rands.drbg_hmac,
     OpenSSL3.providers.implementations.rands.seed_src,
     OpenSSL3.providers.implementations.rands.test_rng,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.kdf_legacy_kmgmt,
     OpenSSL3.providers.implementations.mac_legacy_kmgmt,
     openssl3.providers.implementations.exchange.dh_exch,
     OpenSSL3.providers.implementations.exchange.ecdh_exch,
     OpenSSL3.providers.implementations.exchange.ecx_exch,
     OpenSSL3.providers.implementations.signature.dsa_sig,
     OpenSSL3.providers.implementations.signature.rsa_sig,
     OpenSSL3.providers.implementations.signature.eddsa_sig,
     OpenSSL3.providers.implementations.signature.ecdsa_sig,
     OpenSSL3.providers.implementations.signature.sm2_sig,
     OpenSSL3.providers.implementations.signature.mac_legacy_sig,
     OpenSSL3.providers.implementations.asymciphers.rsa_enc,
     OpenSSL3.providers.implementations.asymciphers.sm2_enc,
     OpenSSL3.providers.implementations.kem.rsa_kem,
     openssl3.providers.implementations.digests.sha2_prov,
     openssl3.providers.implementations.digests.sha3_prov,
     openssl3.providers.implementations.digests.sm3_prov,
     openssl3.providers.implementations.digests.md5_prov,
     openssl3.providers.implementations.digests.md5_sha1_prov,
     openssl3.providers.implementations.digests.null_prov,
     openssl3.providers.implementations.macs.blake2b_mac,
     openssl3.providers.implementations.macs.blake2s_mac,
     openssl3.providers.implementations.macs.cmac_prov,
     openssl3.providers.implementations.macs.gmac_prov,
     openssl3.providers.implementations.macs.hmac_prov,
     openssl3.providers.implementations.macs.kmac_prov,
     openssl3.providers.implementations.macs.siphash_prov,
     openssl3.providers.implementations.macs.poly1305_prov,
     openssl3.providers.implementations.encode_decode.encode_key2any,
     openssl3.providers.implementations.encode_decode.encode_key2text,
     openssl3.providers.implementations.encode_decode.encode_key2blob,
     openssl3.providers.implementations.encode_decode.encode_key2ms,
     openssl3.providers.implementations.encode_decode.decode_der2key,
     openssl3.providers.implementations.encode_decode.decode_msblob2key,
     openssl3.providers.implementations.encode_decode.decode_pvk2key,
     openssl3.providers.implementations.encode_decode.decode_pem2der,
     openssl3.providers.implementations.encode_decode.decode_spki2typespki,
     openssl3.providers.implementations.encode_decode.decode_epki2pki,
     openssl3.providers.implementations.storemgmt.file_store,
     openssl3.providers.implementations.digests.blake2_prov,
     OpenSSL3.providers.implementations.exchange.kdf_exch,
     OpenSSL3.providers.implementations.keymgmt.ecx_kmgmt;
const
   ENCODER_STRUCTURE_type_specific_keypair         = 'type-specific';
   ENCODER_STRUCTURE_type_specific_params          = 'type-specific';
   ENCODER_STRUCTURE_type_specific                 = 'type-specific';
   ENCODER_STRUCTURE_type_specific_no_pub          = 'type-specific';
   ENCODER_STRUCTURE_EncryptedPrivateKeyInfo       = 'EncryptedPrivateKeyInfo';
   ENCODER_STRUCTURE_PrivateKeyInfo                = 'PrivateKeyInfo';
   ENCODER_STRUCTURE_SubjectPublicKeyInfo          = 'SubjectPublicKeyInfo';
   ENCODER_STRUCTURE_DH                            = 'dh';
   ENCODER_STRUCTURE_DHX                           = 'dhx';
   ENCODER_STRUCTURE_DSA                           = 'dsa';
   ENCODER_STRUCTURE_EC                            = 'ec';
   ENCODER_STRUCTURE_RSA                           = 'rsa';
   ENCODER_STRUCTURE_PKCS1                         = 'pkcs1';
   ENCODER_STRUCTURE_PKCS3                         = 'pkcs3';
   ENCODER_STRUCTURE_X9_42                         = 'X9.42';
   ENCODER_STRUCTURE_X9_62                         = 'X9.62';

   DECODER_STRUCTURE_type_specific_keypair         ='type-specific';
   DECODER_STRUCTURE_type_specific_params          ='type-specific';
   DECODER_STRUCTURE_type_specific                 ='type-specific';
   DECODER_STRUCTURE_type_specific_no_pub          ='type-specific';
   DECODER_STRUCTURE_EncryptedPrivateKeyInfo       ='EncryptedPrivateKeyInfo';
   DECODER_STRUCTURE_PrivateKeyInfo                ='PrivateKeyInfo';
   DECODER_STRUCTURE_SubjectPublicKeyInfo          ='SubjectPublicKeyInfo';
   DECODER_STRUCTURE_DH                            ='dh';
   DECODER_STRUCTURE_DHX                           ='dhx';
   DECODER_STRUCTURE_DSA                           ='dsa';
   DECODER_STRUCTURE_EC                            ='ec';
   DECODER_STRUCTURE_RSA                           ='rsa';


const  deflt_digests: array[0..25] of TOSSL_ALGORITHM = (
    (* Our primary name:NIST name[:our older names] *)
    ( algorithm_names:PROV_NAMES_SHA1; property_definition:'provider=default'; _implementation:@ossl_sha1_functions ),
    ( algorithm_names:PROV_NAMES_SHA2_224; property_definition:'provider=default'; _implementation:@ossl_sha224_functions ),
    ( algorithm_names:PROV_NAMES_SHA2_256; property_definition:'provider=default'; _implementation:@ossl_sha256_functions ),
    ( algorithm_names:PROV_NAMES_SHA2_384; property_definition:'provider=default'; _implementation:@ossl_sha384_functions ),
    ( algorithm_names:PROV_NAMES_SHA2_512; property_definition:'provider=default'; _implementation:@ossl_sha512_functions ),
    ( algorithm_names:PROV_NAMES_SHA2_512_224; property_definition:'provider=default'; _implementation:@ossl_sha512_224_functions ),
    ( algorithm_names:PROV_NAMES_SHA2_512_256; property_definition:'provider=default'; _implementation:@ossl_sha512_256_functions ),

    (* We agree with NIST here; so one name only *)
    ( algorithm_names:PROV_NAMES_SHA3_224; property_definition:'provider=default'; _implementation:@ossl_sha3_224_functions ),
    ( algorithm_names:PROV_NAMES_SHA3_256; property_definition:'provider=default'; _implementation:@ossl_sha3_256_functions ),
    ( algorithm_names:PROV_NAMES_SHA3_384; property_definition:'provider=default'; _implementation:@ossl_sha3_384_functions ),
    ( algorithm_names:PROV_NAMES_SHA3_512; property_definition:'provider=default'; _implementation:@ossl_sha3_512_functions ),

    ( algorithm_names:PROV_NAMES_KECCAK_224; property_definition:'provider=default'; _implementation:@ossl_keccak_224_functions ),
    ( algorithm_names:PROV_NAMES_KECCAK_256; property_definition:'provider=default'; _implementation:@ossl_keccak_256_functions ),
    ( algorithm_names:PROV_NAMES_KECCAK_384; property_definition:'provider=default'; _implementation:@ossl_keccak_384_functions ),
    ( algorithm_names:PROV_NAMES_KECCAK_512; property_definition:'provider=default'; _implementation:@ossl_keccak_512_functions ),

    (*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * the KMAC-128 and KMAC-256.
     *)
    ( algorithm_names:PROV_NAMES_KECCAK_KMAC_128; property_definition:'provider=default';
      _implementation:@ossl_keccak_kmac_128_functions ),
    ( algorithm_names:PROV_NAMES_KECCAK_KMAC_256; property_definition:'provider=default';
      _implementation:@ossl_keccak_kmac_256_functions ),

    (* Our primary name:NIST name *)
    ( algorithm_names:PROV_NAMES_SHAKE_128; property_definition:'provider=default'; _implementation:@ossl_shake_128_functions ),
    ( algorithm_names:PROV_NAMES_SHAKE_256; property_definition:'provider=default'; _implementation:@ossl_shake_256_functions ),

{$ifndef OPENSSL_NO_BLAKE2}
    (*
     * https://blake2.net/ doesn't specify size variants;
     * but mentions that Bouncy Castle uses the names
     * BLAKE2b-160; BLAKE2b-256; BLAKE2b-384; and BLAKE2b-512
     * If we assume that '2b' and '2s' are versions; that pattern
     * fits with ours.  We also add our historical names.
     *)
    ( algorithm_names:PROV_NAMES_BLAKE2S_256; property_definition:'provider=default'; _implementation:@ossl_blake2s256_functions ),
    ( algorithm_names:PROV_NAMES_BLAKE2B_512; property_definition:'provider=default'; _implementation:@ossl_blake2b512_functions ),
{$endif} (* OPENSSL_NO_BLAKE2 *)

{$ifndef OPENSSL_NO_SM3}
    ( algorithm_names:PROV_NAMES_SM3; property_definition:'provider=default'; _implementation:@ossl_sm3_functions ),
{$endif} (* OPENSSL_NO_SM3 *)

{$ifndef OPENSSL_NO_MD5}
    ( algorithm_names:PROV_NAMES_MD5; property_definition:'provider=default'; _implementation:@ossl_md5_functions ),
    ( algorithm_names:PROV_NAMES_MD5_SHA1; property_definition:'provider=default'; _implementation:@ossl_md5_sha1_functions ),
{$endif} (* OPENSSL_NO_MD5 *)

    ( algorithm_names:PROV_NAMES_NULL; property_definition:'provider=default'; _implementation:@ossl_nullmd_functions ),
    ( algorithm_names:nil; property_definition:nil; _implementation:nil )
);

 deflt_macs: array[0..9] of TOSSL_ALGORITHM = (
{$ifndef OPENSSL_NO_BLAKE2}
    ( algorithm_names:PROV_NAMES_BLAKE2BMAC; property_definition:'provider=default'; _implementation:@ossl_blake2bmac_functions ),
    ( algorithm_names:PROV_NAMES_BLAKE2SMAC; property_definition:'provider=default'; _implementation:@ossl_blake2smac_functions ),
{$endif}
{$ifndef OPENSSL_NO_CMAC}
    ( algorithm_names:PROV_NAMES_CMAC; property_definition:'provider=default'; _implementation:@ossl_cmac_functions ),
{$endif}
    ( algorithm_names:PROV_NAMES_GMAC; property_definition:'provider=default'; _implementation:@ossl_gmac_functions ),
    ( algorithm_names:PROV_NAMES_HMAC; property_definition:'provider=default'; _implementation:@ossl_hmac_functions ),
    ( algorithm_names:PROV_NAMES_KMAC_128; property_definition:'provider=default'; _implementation:@ossl_kmac128_functions ),
    ( algorithm_names:PROV_NAMES_KMAC_256; property_definition:'provider=default'; _implementation:@ossl_kmac256_functions ),
{$ifndef OPENSSL_NO_SIPHASH}
    ( algorithm_names:PROV_NAMES_SIPHASH; property_definition:'provider=default'; _implementation:@ossl_siphash_functions ),
{$endif}
{$ifndef OPENSSL_NO_POLY1305}
    ( algorithm_names:PROV_NAMES_POLY1305; property_definition:'provider=default'; _implementation:@ossl_poly1305_functions ),
{$endif}
    ( algorithm_names:nil; property_definition:nil; _implementation:nil )
);

 deflt_kdfs: array[0..12] of TOSSL_ALGORITHM = (
    ( algorithm_names:PROV_NAMES_HKDF; property_definition:'provider=default'; _implementation:@ossl_kdf_hkdf_functions ),
    ( algorithm_names:PROV_NAMES_TLS1_3_KDF; property_definition:'provider=default'; _implementation:@ossl_kdf_tls1_3_kdf_functions ),
    ( algorithm_names:PROV_NAMES_SSKDF; property_definition:'provider=default'; _implementation:@ossl_kdf_sskdf_functions ),
    ( algorithm_names:PROV_NAMES_PBKDF2; property_definition:'provider=default'; _implementation:@ossl_kdf_pbkdf2_functions ),
    ( algorithm_names:PROV_NAMES_PKCS12KDF; property_definition:'provider=default'; _implementation:@ossl_kdf_pkcs12_functions ),
    ( algorithm_names:PROV_NAMES_SSHKDF; property_definition:'provider=default'; _implementation:@ossl_kdf_sshkdf_functions ),
    ( algorithm_names:PROV_NAMES_X963KDF; property_definition:'provider=default'; _implementation:@ossl_kdf_x963_kdf_functions ),
    ( algorithm_names:PROV_NAMES_TLS1_PRF; property_definition:'provider=default'; _implementation:@ossl_kdf_tls1_prf_functions ),
    ( algorithm_names:PROV_NAMES_KBKDF; property_definition:'provider=default'; _implementation:@ossl_kdf_kbkdf_functions ),
    ( algorithm_names:PROV_NAMES_X942KDF_ASN1; property_definition:'provider=default'; _implementation:@ossl_kdf_x942_kdf_functions ),
{$ifndef OPENSSL_NO_SCRYPT}
    ( algorithm_names:PROV_NAMES_SCRYPT; property_definition:'provider=default'; _implementation:@ossl_kdf_scrypt_functions ),
{$endif }
    ( algorithm_names:PROV_NAMES_KRB5KDF; property_definition:'provider=default'; _implementation:@ossl_kdf_krb5kdf_functions ),
    ( algorithm_names:nil; property_definition:nil; _implementation:nil )
);

  deflt_rands: array[0..5] of TOSSL_ALGORITHM = (
    ( algorithm_names: PROV_NAMES_CTR_DRBG;property_definition: 'provider=default'; _implementation:@ossl_drbg_ctr_functions ),
    ( algorithm_names: PROV_NAMES_HASH_DRBG;property_definition: 'provider=default'; _implementation:@ossl_drbg_hash_functions ),
    ( algorithm_names: PROV_NAMES_HMAC_DRBG;property_definition: 'provider=default'; _implementation:@ossl_drbg_ossl_hmac_functions ),
    ( algorithm_names: PROV_NAMES_SEED_SRC; property_definition:'provider=default'; _implementation:@ossl_seed_src_functions ),
    ( algorithm_names: PROV_NAMES_TEST_RAND;property_definition: 'provider=default'; _implementation:@ossl_test_rng_functions ),
    ( algorithm_names: nil;property_definition: nil; _implementation:nil )
);
  deflt_keymgmt: array[0..18] of TOSSL_ALGORITHM = (
{$ifndef OPENSSL_NO_DH}
    ( algorithm_names:PROV_NAMES_DH; property_definition:'provider=default'; _implementation:@ossl_dh_keymgmt_functions;
      algorithm_description:PROV_DESCS_DH ),
    ( algorithm_names:PROV_NAMES_DHX; property_definition:'provider=default'; _implementation:@ossl_dhx_keymgmt_functions;
      algorithm_description:PROV_DESCS_DHX ),
{$endif}
{$ifndef OPENSSL_NO_DSA}
    ( algorithm_names:PROV_NAMES_DSA; property_definition:'provider=default'; _implementation:@ossl_dsa_keymgmt_functions;
      algorithm_description:PROV_DESCS_DSA),
{$endif}
    ( algorithm_names:PROV_NAMES_RSA; property_definition:'provider=default'; _implementation:@ossl_rsa_keymgmt_functions;
      algorithm_description:PROV_DESCS_RSA ),
    ( algorithm_names:PROV_NAMES_RSA_PSS; property_definition:'provider=default'; _implementation:@ossl_rsapss_keymgmt_functions;
      algorithm_description:PROV_DESCS_RSA_PSS ),
{$ifndef OPENSSL_NO_EC}
    ( algorithm_names:PROV_NAMES_EC; property_definition:'provider=default'; _implementation:@ossl_ec_keymgmt_functions;
      algorithm_description:PROV_DESCS_EC ),
    ( algorithm_names:PROV_NAMES_X25519; property_definition:'provider=default'; _implementation:@ossl_x25519_keymgmt_functions;
      algorithm_description:PROV_DESCS_X25519 ),
    ( algorithm_names:PROV_NAMES_X448; property_definition:'provider=default'; _implementation:@ossl_x448_keymgmt_functions;
      algorithm_description:PROV_DESCS_X448 ),
    ( algorithm_names:PROV_NAMES_ED25519; property_definition:'provider=default'; _implementation:@ossl_ed25519_keymgmt_functions;
      algorithm_description:PROV_DESCS_ED25519 ),
    ( algorithm_names:PROV_NAMES_ED448; property_definition:'provider=default'; _implementation:@ossl_ed448_keymgmt_functions;
      algorithm_description:PROV_DESCS_ED448 ),
{$endif}
    ( algorithm_names:PROV_NAMES_TLS1_PRF; property_definition:'provider=default'; _implementation:@ossl_kdf_keymgmt_functions;
      algorithm_description:PROV_DESCS_TLS1_PRF_SIGN ),
    ( algorithm_names:PROV_NAMES_HKDF; property_definition:'provider=default'; _implementation:@ossl_kdf_keymgmt_functions;
      algorithm_description:PROV_DESCS_HKDF_SIGN ),
    ( algorithm_names:PROV_NAMES_SCRYPT; property_definition:'provider=default'; _implementation:@ossl_kdf_keymgmt_functions;
      algorithm_description:PROV_DESCS_SCRYPT_SIGN ),
    ( algorithm_names:PROV_NAMES_HMAC; property_definition:'provider=default'; _implementation:@ossl_mac_legacy_keymgmt_functions;
      algorithm_description:PROV_DESCS_HMAC_SIGN ),
    ( algorithm_names:PROV_NAMES_SIPHASH; property_definition:'provider=default'; _implementation:@ossl_mac_legacy_keymgmt_functions;
      algorithm_description:PROV_DESCS_SIPHASH_SIGN ),
{$ifndef OPENSSL_NO_POLY1305}
    ( algorithm_names:PROV_NAMES_POLY1305; property_definition:'provider=default'; _implementation:@ossl_mac_legacy_keymgmt_functions;
      algorithm_description:PROV_DESCS_POLY1305_SIGN ),
{$endif}
{$ifndef OPENSSL_NO_CMAC}
    ( algorithm_names:PROV_NAMES_CMAC; property_definition:'provider=default'; _implementation:@ossl_cmac_legacy_keymgmt_functions;
      algorithm_description:PROV_DESCS_CMAC_SIGN ),
{$endif}
{$ifndef OPENSSL_NO_SM2}
    ( algorithm_names:PROV_NAMES_SM2; property_definition:'provider=default'; _implementation:@ossl_sm2_keymgmt_functions;
      algorithm_description:PROV_DESCS_SM2 ),
{$endif}
    ( algorithm_names:nil; property_definition:nil; _implementation:nil )
);

deflt_keyexch: array[0..7] of TOSSL_ALGORITHM = (
{$ifndef OPENSSL_NO_DH}
    ( algorithm_names:PROV_NAMES_DH; property_definition:'provider=default'; _implementation:@ossl_dh_keyexch_functions ),
{$endif}
{$ifndef OPENSSL_NO_EC}
    ( algorithm_names:PROV_NAMES_ECDH; property_definition:'provider=default'; _implementation:@ossl_ecdh_keyexch_functions ),
    ( algorithm_names:PROV_NAMES_X25519; property_definition:'provider=default'; _implementation:@ossl_x25519_keyexch_functions ),
    ( algorithm_names:PROV_NAMES_X448; property_definition:'provider=default'; _implementation:@ossl_x448_keyexch_functions ),
{$endif}
    ( algorithm_names:PROV_NAMES_TLS1_PRF; property_definition:'provider=default'; _implementation:@ossl_kdf_tls1_prf_keyexch_functions ),
    ( algorithm_names:PROV_NAMES_HKDF; property_definition:'provider=default'; _implementation:@ossl_kdf_hkdf_keyexch_functions ),
    ( algorithm_names:PROV_NAMES_SCRYPT; property_definition:'provider=default';
      _implementation:@ossl_kdf_scrypt_keyexch_functions ),
    ( algorithm_names:nil; property_definition:nil; _implementation:nil )
);
 deflt_signature:array[0..10] of TOSSL_ALGORITHM = (
{$ifndef OPENSSL_NO_DSA}
    ( algorithm_names: PROV_NAMES_DSA; property_definition:'provider=default'; _implementation:@ossl_dsa_signature_functions ),
{$endif}
    ( algorithm_names: PROV_NAMES_RSA; property_definition:'provider=default'; _implementation:@ossl_rsa_signature_functions ),
{$ifndef OPENSSL_NO_EC}
    ( algorithm_names: PROV_NAMES_ED25519; property_definition:'provider=default'; _implementation:@ossl_ed25519_signature_functions ),
    ( algorithm_names: PROV_NAMES_ED448; property_definition:'provider=default'; _implementation:@ossl_ed448_signature_functions ),
    ( algorithm_names: PROV_NAMES_ECDSA; property_definition:'provider=default'; _implementation:@ossl_ecdsa_signature_functions ),
{$ifndef OPENSSL_NO_SM2}
    ( algorithm_names: PROV_NAMES_SM2; property_definition:'provider=default'; _implementation:@ossl_sm2_signature_functions ),
{$endif}
{$endif}
    ( algorithm_names: PROV_NAMES_HMAC; property_definition:'provider=default'; _implementation:@ossl_mac_legacy_hmac_signature_functions ),
    ( algorithm_names: PROV_NAMES_SIPHASH; property_definition:'provider=default';
      _implementation:@ossl_mac_legacy_siphash_signature_functions ),
{$ifndef OPENSSL_NO_POLY1305}
    ( algorithm_names: PROV_NAMES_POLY1305; property_definition:'provider=default';
      _implementation:@ossl_mac_legacy_poly1305_signature_functions ),
{$endif}
{$ifndef OPENSSL_NO_CMAC}
    ( algorithm_names: PROV_NAMES_CMAC; property_definition:'provider=default'; _implementation:@ossl_mac_legacy_cmac_signature_functions ),
{$endif}
    ( algorithm_names: nil; property_definition:nil; _implementation:nil )
);

deflt_asym_cipher: array[0..2] of TOSSL_ALGORITHM = (
    ( algorithm_names: PROV_NAMES_RSA; property_definition:'provider=default'; _implementation:@ossl_rsa_asym_cipher_functions ),
{$ifndef OPENSSL_NO_SM2}
    ( algorithm_names: PROV_NAMES_SM2; property_definition:'provider=default'; _implementation:@ossl_sm2_asym_cipher_functions ),
{$endif}
    ( algorithm_names: nil; property_definition:nil; _implementation:nil )
);

deflt_asym_kem: array[0..1] of TOSSL_ALGORITHM = (
    ( algorithm_names:PROV_NAMES_RSA; property_definition:'provider=default'; _implementation:@ossl_rsa_asym_kem_functions ),
    ( algorithm_names: nil; property_definition:nil; _implementation:nil )
);

deflt_encoder: array[0..115] of TOSSL_ALGORITHM = (
(*
 * Entries for human text 'encoders'
 *)
//ENCODER_TEXT('RSA', rsa, yes),
( algorithm_names:'RSA';
  property_definition:'provider=default, fips= yes,output=text';
  _implementation:@ossl_rsa_to_text_encoder_functions
),
//ENCODER_TEXT('RSA-PSS', rsapss, yes),
( algorithm_names: 'RSA-PSS';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_rsapss_to_text_encoder_functions
),
{$ifndef OPENSSL_NO_DH}
//ENCODER_TEXT('DH', dh, yes),
( algorithm_names: 'DH';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_dh_to_text_encoder_functions
),
//ENCODER_TEXT('DHX', dhx, yes),
( algorithm_names: 'DHX';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_dhx_to_text_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_DSA}
//ENCODER_TEXT('DSA', dsa, yes),
( algorithm_names: 'DSA';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_dsa_to_text_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_EC}
//ENCODER_TEXT('EC', ec, yes),
( algorithm_names: 'EC';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_ec_to_text_encoder_functions
),
//ENCODER_TEXT('ED25519', ed25519, yes),
( algorithm_names:'ED25519';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_ed25519_to_text_encoder_functions
),
//ENCODER_TEXT('ED448', ed448, yes),
( algorithm_names: 'ED448';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_ed448_to_text_encoder_functions
),
//ENCODER_TEXT('X25519', x25519, yes),
( algorithm_names: 'X25519';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_x25519_to_text_encoder_functions
),
//ENCODER_TEXT('X448', x448, yes),
( algorithm_names: 'X448';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_x448_to_text_encoder_functions
),
{$ifndef OPENSSL_NO_SM2}
//ENCODER_TEXT('SM2', sm2, no),
( algorithm_names: 'SM2';
  property_definition:'provider=default, fips= yes ,output=text';
  _implementation:@ossl_sm2_to_text_encoder_functions
),
{$endif}
{$endif}

(* The RSA encoders only support private key and public key output *)
//#define ENCODER_w_structure(_name, _sym, _fips, _output, _structure)
        //ENCODER_w_structure('RSA', rsa,    yes,     der, type_specific_keypair),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_type_specific_keypair;
  _implementation:@ossl_rsa_to_type_specific_keypair_der_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, pem, type_specific_keypair),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_type_specific_keypair;
  _implementation:@ossl_rsa_to_type_specific_keypair_pem_encoder_functions
),
{$ifndef OPENSSL_NO_DH }
(* DH and X9.42 DH only support key parameters output. *)
//ENCODER_w_structure('DH', dh, yes, der, type_specific_params),
( algorithm_names: 'DH';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_type_specific_params;
  _implementation:@ossl_dh_to_type_specific_params_der_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, pem, type_specific_params),
( algorithm_names: 'DH';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_type_specific_params;
  _implementation:@ossl_dh_to_type_specific_params_pem_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, der, type_specific_params),
( algorithm_names: 'DHX';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_type_specific_params;
  _implementation:@ossl_dhx_to_type_specific_params_der_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, pem, type_specific_params),
( algorithm_names: 'DHX';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_type_specific_params;
  _implementation:@ossl_dhx_to_type_specific_params_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_DSA}
//ENCODER_w_structure('DSA', dsa, yes, der, type_specific),
( algorithm_names: 'DSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_type_specific;
  _implementation:@ossl_dsa_to_type_specific_der_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, pem, type_specific),
( algorithm_names: 'DSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_type_specific;
  _implementation:@ossl_dsa_to_type_specific_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_EC}
(* EC only supports keypair and parameters DER and PEM output. *)
//ENCODER_w_structure('EC', ec, yes, der, type_specific_no_pub),
( algorithm_names: 'EC';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_type_specific_no_pub;
  _implementation:@ossl_ec_to_type_specific_no_pub_der_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, pem, type_specific_no_pub),
( algorithm_names: 'EC';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_type_specific_no_pub;
  _implementation:@ossl_ec_to_type_specific_no_pub_pem_encoder_functions
),
(* EC supports blob output for the public key *)
//ENCODER('EC', ec, yes, blob),
( algorithm_names: 'EC';
      property_definition:'provider=default,fips= yes ,output= ec';
      _implementation:@ ossl_ec_to_blob_encoder_functions
),
{$ifndef OPENSSL_NO_SM2}
//ENCODER_w_structure('SM2', sm2, no, der, type_specific_no_pub),
( algorithm_names: 'SM2';
  property_definition: 'provider= default,fips= no ,output= der, structure= ' + ENCODER_STRUCTURE_type_specific_no_pub;
  _implementation:@ossl_sm2_to_type_specific_no_pub_der_encoder_functions
),
//ENCODER_w_structure('SM2', sm2, no, pem, type_specific_no_pub),
( algorithm_names: 'SM2';
  property_definition: 'provider= default,fips= no ,output= pem, structure= ' + ENCODER_STRUCTURE_type_specific_no_pub;
  _implementation:@ossl_sm2_to_type_specific_no_pub_pem_encoder_functions
),
//ENCODER('SM2', sm2, no, blob),
( algorithm_names: 'SM2';
      property_definition:'provider=default,fips= no ,output= blob';
      _implementation:@ossl_sm2_to_blob_encoder_functions
),
{$endif}
{$endif}
(*
 * Entries for the output formats MSBLOB and PVK
 *)
//ENCODER('RSA', rsa, yes, msblob),
( algorithm_names:'RSA';
      property_definition:'provider=default,fips= yes ,output= msblob';
      _implementation:@ossl_rsa_to_msblob_encoder_functions
	) ,
//ENCODER('RSA', rsa, yes, pvk),
( algorithm_names:'RSA';
      property_definition:'provider=default,fips= yes ,output= pvk';
      _implementation:@ossl_rsa_to_pvk_encoder_functions
	) ,
{$ifndef OPENSSL_NO_DSA }
//ENCODER('DSA', dsa, yes, msblob),
( algorithm_names:'DSA';
      property_definition:'provider=default,fips= yes ,output= msblob';
      _implementation:@ossl_dsa_to_msblob_encoder_functions
	) ,
//ENCODER('DSA', dsa, yes, pvk),
( algorithm_names:'DSA';
      property_definition:'provider=default,fips= yes ,output= pvk';
      _implementation:@ossl_dsa_to_pvk_encoder_functions
	) ,
{$endif}
(*
 * Entries for encrypted PKCS#8 (EncryptedPrivateKeyInfo), unencrypted PKCS#8
 * (PrivateKeyInfo) and SubjectPublicKeyInfo.  The 'der' ones are added
 * convenience for any user that wants to use OSSL_ENCODER directly.
 * The 'pem' ones also support PEM_write_bio_PrivateKey() and
 * PEM_write_bio_PUBKEY().
 *)
//ENCODER_w_structure('RSA', rsa, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips=yes ,output=der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_rsa_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_rsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, der, PrivateKeyInfo),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_rsa_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, pem, PrivateKeyInfo),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_rsa_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, der, SubjectPublicKeyInfo),
( algorithm_names: 'RSA';
  property_definition: 'provider=default,fips=yes,output=der,structure=SubjectPublicKeyInfo' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_rsa_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, pem, SubjectPublicKeyInfo),
( algorithm_names: 'RSA';
  property_definition: 'provider=default,fips=yes,output=pem,structure=SubjectPublicKeyInfo' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_rsa_to_SubjectPublicKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_rsapss_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_rsapss_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, der, PrivateKeyInfo),
( algorithm_names:  'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_rsapss_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, pem, PrivateKeyInfo),
( algorithm_names:  'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_rsapss_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_rsapss_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_rsapss_to_SubjectPublicKeyInfo_pem_encoder_functions
),
{$ifndef OPENSSL_NO_DH}
//ENCODER_w_structure('DH', dh, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'DH';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_dh_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'DH';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_dh_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, der, PrivateKeyInfo),
( algorithm_names:  'DH';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_dh_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, pem, PrivateKeyInfo),
( algorithm_names:  'DH';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_dh_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'DH';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_dh_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'DH';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_dh_to_SubjectPublicKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'DHX';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_dhx_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'DHX';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_dhx_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, der, PrivateKeyInfo),
( algorithm_names:  'DHX';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_dhx_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, pem, PrivateKeyInfo),
( algorithm_names:  'DHX';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_dhx_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'DHX';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_dhx_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'DHX';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_dhx_to_SubjectPublicKeyInfo_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_DSA}
//ENCODER_w_structure('DSA', dsa, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'DSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_dsa_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'DSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_dsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, der, PrivateKeyInfo),
( algorithm_names:  'DSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_dsa_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, pem, PrivateKeyInfo),
( algorithm_names:  'DSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_dsa_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'DSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_dsa_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'DSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_dsa_to_SubjectPublicKeyInfo_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_EC}
//ENCODER_w_structure('EC', ec, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'EC';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_ec_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'EC';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_ec_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, der, PrivateKeyInfo),
( algorithm_names:  'EC';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_ec_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, pem, PrivateKeyInfo),
( algorithm_names:  'EC';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_ec_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'EC';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_ec_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'EC';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_ec_to_SubjectPublicKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('X25519', x25519, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'X25519';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_X25519_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('X25519', x25519, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'X25519';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_X25519_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('X25519', x25519, yes, der, PrivateKeyInfo),
( algorithm_names:  'X25519';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_X25519_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('X25519', x25519, yes, pem, PrivateKeyInfo),
( algorithm_names:  'X25519';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_X25519_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('X25519', x25519, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'X25519';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_X25519_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('X25519', x25519, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'X25519';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_X25519_to_SubjectPublicKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('X448', x448, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'X448';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_x448_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('X448', x448, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'X448';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_x448_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('X448', x448, yes, der, PrivateKeyInfo),
( algorithm_names:  'X448';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_x448_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('X448', x448, yes, pem, PrivateKeyInfo),
( algorithm_names:  'X448';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_x448_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('X448', x448, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'X448';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_x448_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('X448', x448, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'X448';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_x448_to_SubjectPublicKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('ED25519', ed25519, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'ED25519';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_ed25519_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('ED25519', ed25519, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'ED25519';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_ed25519_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('ED25519', ed25519, yes, der, PrivateKeyInfo),
( algorithm_names:  'ED25519';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_ed25519_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('ED25519', ed25519, yes, pem, PrivateKeyInfo),
( algorithm_names:  'ED25519';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_ed25519_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('ED25519', ed25519, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'ED25519';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_ed25519_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('ED25519', ed25519, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'ED25519';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_ed25519_to_SubjectPublicKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('ED448', ed448, yes, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'ED448';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_ed448_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('ED448', ed448, yes, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'ED448';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_ed448_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('ED448', ed448, yes, der, PrivateKeyInfo),
( algorithm_names:  'ED448';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_ed448_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('ED448', ed448, yes, pem, PrivateKeyInfo),
( algorithm_names:  'ED448';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_ed448_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('ED448', ed448, yes, der, SubjectPublicKeyInfo),
( algorithm_names:  'ED448';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_ed448_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('ED448', ed448, yes, pem, SubjectPublicKeyInfo),
( algorithm_names:  'ED448';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_ed448_to_SubjectPublicKeyInfo_pem_encoder_functions
),
{$ifndef OPENSSL_NO_SM2}
//ENCODER_w_structure('SM2', sm2, no, der, EncryptedPrivateKeyInfo),
( algorithm_names:  'SM2';
  property_definition: 'provider= default,fips= no ,output= der, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_sm2_to_EncryptedPrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('SM2', sm2, no, pem, EncryptedPrivateKeyInfo),
( algorithm_names:  'SM2';
  property_definition: 'provider= default,fips= no ,output= pem, structure= ' + ENCODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_sm2_to_EncryptedPrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('SM2', sm2, no, der, PrivateKeyInfo),
( algorithm_names:  'SM2';
  property_definition: 'provider= default,fips= no ,output= der, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_sm2_to_PrivateKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('SM2', sm2, no, pem, PrivateKeyInfo),
( algorithm_names:  'SM2';
  property_definition: 'provider= default,fips= no ,output= pem, structure= ' + ENCODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_sm2_to_PrivateKeyInfo_pem_encoder_functions
),
//ENCODER_w_structure('SM2', sm2, no, der, SubjectPublicKeyInfo),
( algorithm_names:  'SM2';
  property_definition: 'provider= default,fips= no ,output= der, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_sm2_to_SubjectPublicKeyInfo_der_encoder_functions
),
//ENCODER_w_structure('SM2', sm2, no, pem, SubjectPublicKeyInfo),
( algorithm_names:  'SM2';
  property_definition: 'provider= default,fips= no ,output= pem, structure= ' + ENCODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_sm2_to_SubjectPublicKeyInfo_pem_encoder_functions
),
{$ENDIF}
{$endif}
(*
 * Entries for key type specific output formats.  These are exactly the
 * same as the type specific above, except that they use the key type
 * name as structure name instead of 'type-specific', in the call on
 * OSSL_ENCODER_CTX_new_for_pkey().
 *)
(* The RSA encoders only support private key and public key output *)
//ENCODER_w_structure('RSA', rsa, yes, der, RSA),
( algorithm_names:'RSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_RSA;
  _implementation:@ossl_rsa_to_RSA_der_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, pem, RSA),
( algorithm_names:'RSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_RSA;
  _implementation:@ossl_rsa_to_RSA_pem_encoder_functions
),
{$ifndef OPENSSL_NO_DH}
(* DH and X9.42 DH only support key parameters output. *)
//ENCODER_w_structure('DH', dh, yes, der, DH),
( algorithm_names: 'DH';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_DH;
  _implementation:@ossl_dh_to_DH_der_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, pem, DH),
( algorithm_names: 'DH';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_DH;
  _implementation:@ossl_dh_to_DH_pem_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, der, DHX),
( algorithm_names:'DHX';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_DHX;
  _implementation:@ossl_dhx_to_DHX_der_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, pem, DHX),
( algorithm_names: 'DHX';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_DHX;
  _implementation:@ossl_dhx_to_DHX_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_DSA}
//ENCODER_w_structure('DSA', dsa, yes, der, DSA),
( algorithm_names:'DSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_DSA;
  _implementation:@ossl_dsa_to_DSA_der_encoder_functions
),
//ENCODER_w_structure('DSA', dsa, yes, pem, DSA),
( algorithm_names:'DSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_DSA;
  _implementation:@ossl_dsa_to_DSA_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_EC}
//ENCODER_w_structure('EC', ec, yes, der, EC),
( algorithm_names:'EC';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_EC;
  _implementation:@ossl_ec_to_EC_der_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, pem, EC),
( algorithm_names:'EC';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_EC;
  _implementation:@ossl_ec_to_EC_pem_encoder_functions
),
{$endif}
(*
 * Additional entries with structure names being the standard name.
 * This is entirely for the convenience of the user that wants to use
 * OSSL_ENCODER directly with names they may fancy.  These do not impact
 * on libcrypto functionality in any way.
 *)
(* PKCS#1 is a well known for plain RSA keys, so we add that too *)
//ENCODER_w_structure('RSA', rsa, yes, der, PKCS1),
( algorithm_names:'RSA';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PKCS1;
  _implementation:@ossl_rsa_to_PKCS1_der_encoder_functions
),
//ENCODER_w_structure('RSA', rsa, yes, pem, PKCS1),
( algorithm_names: 'RSA';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PKCS1;
  _implementation:@ossl_rsa_to_PKCS1_pem_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, der, PKCS1),
( algorithm_names:'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PKCS1;
  _implementation:@ossl_rsapss_to_PKCS1_der_encoder_functions
),
//ENCODER_w_structure('RSA-PSS', rsapss, yes, pem, PKCS1),
( algorithm_names:'RSA-PSS';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PKCS1;
  _implementation:@ossl_rsapss_to_PKCS1_pem_encoder_functions
),
{$ifndef OPENSSL_NO_DH }
(* PKCS#3 defines the format for DH parameters *)
//ENCODER_w_structure('DH', dh, yes, der, PKCS3),
( algorithm_names:'DH';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_PKCS3;
  _implementation:@ossl_dh_to_PKCS3_der_encoder_functions
),
//ENCODER_w_structure('DH', dh, yes, pem, PKCS3),
( algorithm_names:'DH';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_PKCS3;
  _implementation:@ossl_dh_to_PKCS3_pem_encoder_functions
),
(* X9.42 defines the format for DHX parameters *)
//ENCODER_w_structure('DHX', dhx, yes, der, X9_42),
( algorithm_names:'DHX';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_X9_42;
  _implementation:@ossl_dhx_to_X9_42_der_encoder_functions
),
//ENCODER_w_structure('DHX', dhx, yes, pem, X9_42),
( algorithm_names:'DHX';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_X9_42;
  _implementation:@ossl_dhx_to_X9_42_pem_encoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_EC}
(* RFC 5915 defines the format for EC keys and parameters *)
//ENCODER_w_structure('EC', ec, yes, der, X9_62),
( algorithm_names:'EC';
  property_definition: 'provider= default,fips= yes ,output= der, structure= ' + ENCODER_STRUCTURE_X9_62;
  _implementation:@ossl_ec_to_X9_62_der_encoder_functions
),
//ENCODER_w_structure('EC', ec, yes, pem, X9_62),
( algorithm_names:'EC';
  property_definition: 'provider= default,fips= yes ,output= pem, structure= ' + ENCODER_STRUCTURE_X9_62;
  _implementation:@ossl_ec_to_X9_62_pem_encoder_functions
),
{$endif}
( algorithm_names: nil; property_definition:nil; _implementation:nil )
);
(******************************decoder****************************************)
deflt_decoder: array[0..39] of TOSSL_ALGORITHM = (
{$ifndef OPENSSL_NO_DH}
//DECODER_w_structure('DH', der, PrivateKeyInfo, dh, yes),
( algorithm_names:  'DH';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_dh_decoder_functions
),
//DECODER_w_structure('DH', der, SubjectPublicKeyInfo, dh, yes),
( algorithm_names:  'DH';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_dh_decoder_functions
),
//DECODER_w_structure('DH', der, type_specific_params, dh, yes),
( algorithm_names:  'DH';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_type_specific_params;
  _implementation:@ossl_type_specific_params_der_to_dh_decoder_functions
),
//DECODER_w_structure('DH', der, DH, dh, yes),
( algorithm_names:  'DH';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_DH;
  _implementation:@ossl_DH_der_to_dh_decoder_functions
),
//DECODER_w_structure('DHX', der, PrivateKeyInfo, dhx, yes),
( algorithm_names:  'DHX';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_dhx_decoder_functions
),
//DECODER_w_structure('DHX', der, SubjectPublicKeyInfo, dhx, yes),
( algorithm_names:  'DHX';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_dhx_decoder_functions
),
//DECODER_w_structure('DHX', der, type_specific_params, dhx, yes),
( algorithm_names:  'DHX';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_type_specific_params;
  _implementation:@ossl_type_specific_params_der_to_dhx_decoder_functions
),
//DECODER_w_structure('DHX', der, DHX, dhx, yes),
( algorithm_names:  'DHX';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_DHX;
  _implementation:@ossl_DHX_der_to_dhx_decoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_DSA }
//DECODER_w_structure('DSA', der, PrivateKeyInfo, dsa, yes),
( algorithm_names: 'DSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_dsa_decoder_functions
),
//DECODER_w_structure('DSA', der, SubjectPublicKeyInfo, dsa, yes),
( algorithm_names:  'DSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_dsa_decoder_functions
),
//DECODER_w_structure('DSA', der, type_specific, dsa, yes),
( algorithm_names:  'DSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_type_specific;
  _implementation:@ossl_type_specific_der_to_dsa_decoder_functions
),
//DECODER_w_structure('DSA', der, DSA, dsa, yes),
( algorithm_names:  'DSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_DSA;
  _implementation:@ossl_DSA_der_to_dsa_decoder_functions
),
//DECODER('DSA', msblob, dsa, yes),
( algorithm_names: 'DSA';
  property_definition: 'provider=default,fips= yes ,input= msblob';
  _implementation:@ossl_msblob_to_dsa_decoder_functions
),
//DECODER('DSA', pvk, dsa, yes),
( algorithm_names: 'DSA';
  property_definition: 'provider=default,fips= yes ,input= pvk';
  _implementation:@ossl_pvk_to_dsa_decoder_functions
),
{$endif}
{$ifndef OPENSSL_NO_EC }
//DECODER_w_structure('EC', der, PrivateKeyInfo, ec, yes),
( algorithm_names:  'EC';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_ec_decoder_functions
),
//DECODER_w_structure('EC', der, SubjectPublicKeyInfo, ec, yes),
( algorithm_names:  'EC';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_ec_decoder_functions
),
//DECODER_w_structure('EC', der, type_specific_no_pub, ec, yes),
( algorithm_names:  'EC';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_type_specific_no_pub;
  _implementation:@ossl_type_specific_no_pub_der_to_ec_decoder_functions
),
//DECODER_w_structure('EC', der, EC, ec, yes),
( algorithm_names:  'EC';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_EC;
  _implementation:@ossl_EC_der_to_ec_decoder_functions
),
//DECODER_w_structure('ED25519', der, PrivateKeyInfo, ed25519, yes),
( algorithm_names:  'ED25519';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_ed25519_decoder_functions
),
//DECODER_w_structure('ED25519', der, SubjectPublicKeyInfo, ed25519, yes),
( algorithm_names:  'ED25519';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_ed25519_decoder_functions
),
//DECODER_w_structure('ED448', der, PrivateKeyInfo, ed448, yes),
( algorithm_names:  'ED448';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_ed448_decoder_functions
),
//DECODER_w_structure('ED448', der, SubjectPublicKeyInfo, ed448, yes),
( algorithm_names:  'ED448';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_ed448_decoder_functions
),
//DECODER_w_structure('X25519', der, PrivateKeyInfo, x25519, yes),
( algorithm_names:  'X25519';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_x25519_decoder_functions
),
//DECODER_w_structure('X25519', der, SubjectPublicKeyInfo, x25519, yes),
( algorithm_names:  'X25519';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_x25519_decoder_functions
),
//DECODER_w_structure('X448', der, PrivateKeyInfo, x448, yes),
( algorithm_names:  'X448';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_x448_decoder_functions
),
//DECODER_w_structure('X448', der, SubjectPublicKeyInfo, x448, yes),
( algorithm_names:  'X448';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_x448_decoder_functions
),
{$ifndef OPENSSL_NO_SM2 }
//DECODER_w_structure('SM2', der, PrivateKeyInfo, sm2, no),
( algorithm_names:  'SM2';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_sm2_decoder_functions
),
//DECODER_w_structure('SM2', der, SubjectPublicKeyInfo, sm2, no),
( algorithm_names:  'SM2';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_sm2_decoder_functions
),
{$endif}
{$endif }
//DECODER_w_structure('RSA', der, PrivateKeyInfo, rsa, yes),
( algorithm_names:  'RSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_rsa_decoder_functions
),
//DECODER_w_structure('RSA', der, SubjectPublicKeyInfo, rsa, yes),
( algorithm_names:  'RSA';
  property_definition: 'provider=default,fips=yes,input=der,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_rsa_decoder_functions
),
//DECODER_w_structure('RSA', der, type_specific_keypair, rsa, yes),
( algorithm_names:  'RSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_type_specific_keypair;
  _implementation:@ossl_type_specific_keypair_der_to_rsa_decoder_functions
),
//DECODER_w_structure('RSA', der, RSA, rsa, yes),
( algorithm_names:  'RSA';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_RSA;
  _implementation:@ossl_RSA_der_to_rsa_decoder_functions
),
//DECODER_w_structure('RSA-PSS', der, PrivateKeyInfo, rsapss, yes),
( algorithm_names: 'RSA-PSS';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_PrivateKeyInfo;
  _implementation:@ossl_PrivateKeyInfo_der_to_rsapss_decoder_functions
),
//DECODER_w_structure('RSA-PSS', der, SubjectPublicKeyInfo, rsapss, yes),
( algorithm_names: 'RSA-PSS';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_rsapss_decoder_functions
),
//DECODER('RSA', msblob, rsa, yes),
( algorithm_names: 'RSA';
  property_definition: 'provider=default,fips= yes ,input= msblob';
  _implementation:@ossl_msblob_to_rsa_decoder_functions
),
//DECODER('RSA', pvk, rsa, yes),
( algorithm_names: 'RSA';
  property_definition: 'provider=default,fips= yes ,input= pvk';
  _implementation:@ossl_pvk_to_rsa_decoder_functions
),
//DECODER_w_structure('DER', der, SubjectPublicKeyInfo, der, yes),
( algorithm_names:  'DER';
  property_definition: 'provider=default,fips= yes ,input= der ,structure=' + DECODER_STRUCTURE_SubjectPublicKeyInfo;
  _implementation:@ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions
),
//DECODER('DER', pem, der, yes),
( algorithm_names:  'DER';
  property_definition: 'provider=default,fips= yes ,input= pem';
  _implementation:@ossl_pem_to_der_decoder_functions
),
//DECODER_w_structure('DER', der, EncryptedPrivateKeyInfo, der, yes),
( algorithm_names:  'DER';
  property_definition: 'provider=default,fips= yes ,input=der ,structure=' + DECODER_STRUCTURE_EncryptedPrivateKeyInfo;
  _implementation:@ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions
),
( algorithm_names:  nil;
  property_definition: nil;
  _implementation:nil
)
);
 deflt_store: array[0..1] of TOSSL_ALGORITHM = (
     ( algorithm_names:  'file';
      property_definition: 'provider=default,fips=yes';
      _implementation:@ossl_file_store_functions
    ),
    ( algorithm_names:  nil;
      property_definition: nil;
      _implementation:nil
    ) );


function ossl_default_provider_init(const handle : POSSL_CORE_HANDLE; {const} &in : POSSL_DISPATCH;var _out : POSSL_DISPATCH; provctx : PPointer):integer;
procedure deflt_teardown( provctx : Pointer);
function deflt_gettable_params( provctx : Pointer):POSSL_PARAM;
function deflt_get_params( provctx : Pointer; params : POSSL_PARAM):integer;
function deflt_query( provctx : Pointer; operation_id : integer;var no_cache : Integer):POSSL_ALGORITHM;
function ALG(NAMES, DEF: PUTF8Char; FUNC: POSSL_DISPATCH; CHECK: Tcapable_func):TOSSL_ALGORITHM_CAPABLE; overload;
function ALG(NAMES: PUTF8Char; FUNC: POSSL_DISPATCH): TOSSL_ALGORITHM_CAPABLE; overload;
function ALGC(NAMES: PUTF8Char; FUNC: POSSL_DISPATCH; CHECK: Tcapable_func):TOSSL_ALGORITHM_CAPABLE;

var
  c_gettable_params: TOSSL_FUNC_core_gettable_params_fn  = nil;
  c_get_params: TOSSL_FUNC_core_get_params_fn  = nil;
  g_ossl_default_provider_init: TOSSL_provider_init_fn ;
  deflt_ciphers: array[0..126] of TOSSL_ALGORITHM_CAPABLE;
  exported_ciphers: array[0..126] of TOSSL_ALGORITHM;
  deflt_param_types: array[0..4] of TOSSL_PARAM ;

implementation

uses openssl3.crypto.bio.bio_prov, openssl3.crypto.provider.provider_seeding,
     OpenSSL3.openssl.core_dispatch,         OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     openssl3.providers.fips.self_test,      openssl3.crypto.bio.bio_meth,
     OpenSSL3.providers.common.provider_util,OpenSSL3.openssl.params,
     OpenSSL3.providers.implementations.ciphers.cipher_null,
     OpenSSL3.providers.implementations.ciphers.cipher_aes,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ocb,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_gcm,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_xts,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_ccm,
     OpenSSL3.providers.implementations.ciphers.cipher_aria_gcm,
     OpenSSL3.providers.implementations.ciphers.cipher_aria_ccm,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_wrp,
     OpenSSL3.providers.implementations.ciphers.cipher_aria,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes_default,
     OpenSSL3.providers.implementations.ciphers.cipher_tdes_wrap,
     OpenSSL3.providers.implementations.ciphers.cipher_sm4_gcm,
     OpenSSL3.providers.implementations.ciphers.cipher_sm4,
     OpenSSL3.providers.implementations.ciphers.cipher_sm4_ccm,
     OpenSSL3.providers.implementations.ciphers.cipher_chacha20,
     OpenSSL3.providers.implementations.ciphers.cipher_camellia,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha1_hw,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_cbc_hmac_sha256_hw,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_siv;



const deflt_dispatch_table: array[0..5] of TOSSL_DISPATCH  = (
    ( function_id:OSSL_FUNC_PROVIDER_TEARDOWN; method:(code: @deflt_teardown; data:nil )),
    ( function_id:OSSL_FUNC_PROVIDER_GETTABLE_PARAMS; method:(code:@deflt_gettable_params; data:nil) ),
    ( function_id:OSSL_FUNC_PROVIDER_GET_PARAMS; method:(code:@deflt_get_params; data:nil) ),
    ( function_id:OSSL_FUNC_PROVIDER_QUERY_OPERATION; method:(code:@deflt_query; data:nil) ),
    ( function_id:OSSL_FUNC_PROVIDER_GET_CAPABILITIES; method:(code:@ossl_prov_get_capabilities; data:nil) ),
    ( function_id:0; method:(code:nil; data:nil))
);

function ALG(NAMES, DEF: PUTF8Char; FUNC: POSSL_DISPATCH; CHECK: Tcapable_func):TOSSL_ALGORITHM_CAPABLE;
begin
   Result.alg.algorithm_names := NAMES;
   Result.alg.property_definition := DEF;
   Result.alg._implementation := FUNC;
   Result.capable := CHECK;
end;

function ALG(NAMES: PUTF8Char; FUNC: POSSL_DISPATCH): TOSSL_ALGORITHM_CAPABLE;
begin
  Result := ALGC(NAMES, FUNC, nil);
end;

function ALGC(NAMES: PUTF8Char; FUNC: POSSL_DISPATCH; CHECK: Tcapable_func):TOSSL_ALGORITHM_CAPABLE;
begin
   Result.alg.algorithm_names :=  NAMES;
   Result.alg.property_definition := 'provider=default';
   Result.alg._implementation := FUNC;
   Result.capable := CHECK;
end;

function deflt_query( provctx : Pointer; operation_id : integer;var no_cache : Integer):POSSL_ALGORITHM;
begin
    no_cache := 0;
    case operation_id of
    OSSL_OP_DIGEST:
        Exit(@deflt_digests);
    OSSL_OP_CIPHER:
        Exit(@exported_ciphers);
    OSSL_OP_MAC:
        Exit(@deflt_macs);
    OSSL_OP_KDF:
        Exit(@deflt_kdfs);
    OSSL_OP_RAND:
        Exit(@deflt_rands);
    OSSL_OP_KEYMGMT:
        Exit(@deflt_keymgmt);
    OSSL_OP_KEYEXCH:
        Exit(@deflt_keyexch);
    OSSL_OP_SIGNATURE:
        Exit(@deflt_signature);
    OSSL_OP_ASYM_CIPHER:
        Exit(@deflt_asym_cipher);
    OSSL_OP_KEM:
        Exit(@deflt_asym_kem);
    OSSL_OP_ENCODER:
        Exit(@deflt_encoder);
    OSSL_OP_DECODER:
        Exit(@deflt_decoder);
    OSSL_OP_STORE:
        Exit(@deflt_store);
    end;
    Result := nil;
end;


function deflt_get_params( provctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p <> nil)  and   (0>= OSSL_PARAM_set_utf8_ptr(p, 'OpenSSL Default Provider') )then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR) )then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR) )then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_int(p, Int(ossl_prov_is_running))) then
        Exit(0);
    Result := 1;
end;

function deflt_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @deflt_param_types;
end;

procedure deflt_teardown( provctx : Pointer);
begin
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
end;

function ossl_default_provider_init(const handle : POSSL_CORE_HANDLE; {const} &in : POSSL_DISPATCH; var _out : POSSL_DISPATCH; provctx : PPointer):integer;
var
    c_get_libctx : TOSSL_FUNC_core_get_libctx_fn;
    corebiometh  : PBIO_METHOD;
begin
    c_get_libctx := nil;
    if  (0>= ossl_prov_bio_from_dispatch(&in) )or
        (0>= ossl_prov_seeding_from_dispatch(&in))  then
        Exit(0);
    while &in.function_id <> 0 do
    begin
        case &in.function_id of
            OSSL_FUNC_CORE_GETTABLE_PARAMS:
                c_gettable_params := _OSSL_FUNC_core_gettable_params(&in);
                //break;
            OSSL_FUNC_CORE_GET_PARAMS:
                c_get_params := _OSSL_FUNC_core_get_params(&in);
                //break;
            OSSL_FUNC_CORE_GET_LIBCTX:
                c_get_libctx := _OSSL_FUNC_core_get_libctx(&in);
                //break;
            else
            { Just ignore anything we don't understand }
            begin
              //
            end;  ;
        end;
        Inc(&in);

    end;
    if not Assigned(c_get_libctx) then Exit(0);
    {
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     }
    provctx^ := ossl_prov_ctx_new( );
    corebiometh := ossl_bio_prov_init_bio_method();
    if  (provctx^  = nil )
             or  (corebiometh = nil) then
    begin
        ossl_prov_ctx_free( provctx^);
        provctx^ := nil;
        Exit(0);
    end;
    ossl_prov_ctx_set0_libctx( provctx^, POSSL_LIB_CTX (c_get_libctx(handle)) );
    ossl_prov_ctx_set0_handle( provctx^, handle);
    ossl_prov_ctx_set0_core_bio_method( provctx^, corebiometh);
    _out := @deflt_dispatch_table;
    ossl_prov_cache_exported_algorithms(@deflt_ciphers, @exported_ciphers);
    Result := 1;
end;

initialization
    deflt_ciphers[0] := ALG(PROV_NAMES_NULL, @ossl_null_functions);
    deflt_ciphers[1] := ALG(PROV_NAMES_AES_256_ECB, @ossl_aes256ecb_functions);
    deflt_ciphers[2] := ALG(PROV_NAMES_AES_192_ECB, @ossl_aes192ecb_functions);
    deflt_ciphers[3] := ALG(PROV_NAMES_AES_128_ECB, @ossl_aes128ecb_functions);
    deflt_ciphers[4] := ALG(PROV_NAMES_AES_256_CBC, @ossl_aes256cbc_functions);
    deflt_ciphers[5] := ALG(PROV_NAMES_AES_192_CBC, @ossl_aes192cbc_functions);
    deflt_ciphers[6] := ALG(PROV_NAMES_AES_128_CBC, @ossl_aes128cbc_functions);
    deflt_ciphers[7] := ALG(PROV_NAMES_AES_128_CBC_CTS, @ossl_aes128cbc_cts_functions);
    deflt_ciphers[8] := ALG(PROV_NAMES_AES_192_CBC_CTS, @ossl_aes192cbc_cts_functions);
    deflt_ciphers[9] := ALG(PROV_NAMES_AES_256_CBC_CTS, @ossl_aes256cbc_cts_functions);
    deflt_ciphers[10] := ALG(PROV_NAMES_AES_256_OFB, @ossl_aes256ofb_functions);
    deflt_ciphers[11] := ALG(PROV_NAMES_AES_192_OFB, @ossl_aes192ofb_functions);
    deflt_ciphers[12] := ALG(PROV_NAMES_AES_128_OFB, @ossl_aes128ofb_functions);
    deflt_ciphers[13] := ALG(PROV_NAMES_AES_256_CFB, @ossl_aes256cfb_functions);
    deflt_ciphers[14] := ALG(PROV_NAMES_AES_192_CFB, @ossl_aes192cfb_functions);
    deflt_ciphers[15] := ALG(PROV_NAMES_AES_128_CFB, @ossl_aes128cfb_functions);
    deflt_ciphers[16] := ALG(PROV_NAMES_AES_256_CFB1, @ossl_aes256cfb1_functions);
    deflt_ciphers[17] := ALG(PROV_NAMES_AES_192_CFB1, @ossl_aes192cfb1_functions);
    deflt_ciphers[18] := ALG(PROV_NAMES_AES_128_CFB1, @ossl_aes128cfb1_functions);
    deflt_ciphers[19] := ALG(PROV_NAMES_AES_256_CFB8, @ossl_aes256cfb8_functions);
    deflt_ciphers[20] := ALG(PROV_NAMES_AES_192_CFB8, @ossl_aes192cfb8_functions);
    deflt_ciphers[21] := ALG(PROV_NAMES_AES_128_CFB8, @ossl_aes128cfb8_functions);
    deflt_ciphers[22] := ALG(PROV_NAMES_AES_256_CTR, @ossl_aes256ctr_functions);
    deflt_ciphers[23] := ALG(PROV_NAMES_AES_192_CTR, @ossl_aes192ctr_functions);
    deflt_ciphers[24] := ALG(PROV_NAMES_AES_128_CTR, @ossl_aes128ctr_functions);
    deflt_ciphers[25] := ALG(PROV_NAMES_AES_256_XTS, @ossl_aes256xts_functions);
    deflt_ciphers[26] := ALG(PROV_NAMES_AES_128_XTS, @ossl_aes128xts_functions);
{$ifndef OPENSSL_NO_OCB}
    deflt_ciphers[27] := ALG(PROV_NAMES_AES_256_OCB, @ossl_aes256ocb_functions);
    deflt_ciphers[28] := ALG(PROV_NAMES_AES_192_OCB, @ossl_aes192ocb_functions);
    deflt_ciphers[29] := ALG(PROV_NAMES_AES_128_OCB, @ossl_aes128ocb_functions);
{$endif} (* OPENSSL_NO_OCB *)
{$ifndef OPENSSL_NO_SIV}
    deflt_ciphers[30] := ALG(PROV_NAMES_AES_128_SIV, @ossl_aes128siv_functions);
    deflt_ciphers[31] := ALG(PROV_NAMES_AES_192_SIV, @ossl_aes192siv_functions);
    deflt_ciphers[32] := ALG(PROV_NAMES_AES_256_SIV, @ossl_aes256siv_functions);
{$endif} (* OPENSSL_NO_SIV *)
    deflt_ciphers[33] := ALG(PROV_NAMES_AES_256_GCM, @ossl_aes256gcm_functions);
    deflt_ciphers[34] := ALG(PROV_NAMES_AES_192_GCM, @ossl_aes192gcm_functions);
    deflt_ciphers[35] := ALG(PROV_NAMES_AES_128_GCM, @ossl_aes128gcm_functions);
    deflt_ciphers[36] := ALG(PROV_NAMES_AES_256_CCM, @ossl_aes256ccm_functions);
    deflt_ciphers[37] := ALG(PROV_NAMES_AES_192_CCM, @ossl_aes192ccm_functions);
    deflt_ciphers[38] := ALG(PROV_NAMES_AES_128_CCM, @ossl_aes128ccm_functions);
    deflt_ciphers[39] := ALG(PROV_NAMES_AES_256_WRAP, @ossl_aes256wrap_functions);
    deflt_ciphers[40] := ALG(PROV_NAMES_AES_192_WRAP, @ossl_aes192wrap_functions);
    deflt_ciphers[41] := ALG(PROV_NAMES_AES_128_WRAP, @ossl_aes128wrap_functions);
    deflt_ciphers[42] := ALG(PROV_NAMES_AES_256_WRAP_PAD, @ossl_aes256wrappad_functions);
    deflt_ciphers[43] := ALG(PROV_NAMES_AES_192_WRAP_PAD, @ossl_aes192wrappad_functions);
    deflt_ciphers[44] := ALG(PROV_NAMES_AES_128_WRAP_PAD, @ossl_aes128wrappad_functions);
    deflt_ciphers[45] := ALG(PROV_NAMES_AES_256_WRAP_INV, @ossl_aes256wrapinv_functions);
    deflt_ciphers[46] := ALG(PROV_NAMES_AES_192_WRAP_INV, @ossl_aes192wrapinv_functions);
    deflt_ciphers[47] := ALG(PROV_NAMES_AES_128_WRAP_INV, @ossl_aes128wrapinv_functions);
    deflt_ciphers[48] := ALG(PROV_NAMES_AES_256_WRAP_PAD_INV, @ossl_aes256wrappadinv_functions);
    deflt_ciphers[49] := ALG(PROV_NAMES_AES_192_WRAP_PAD_INV, @ossl_aes192wrappadinv_functions);
    deflt_ciphers[50] := ALG(PROV_NAMES_AES_128_WRAP_PAD_INV, @ossl_aes128wrappadinv_functions);
    deflt_ciphers[51] := ALGC(PROV_NAMES_AES_128_CBC_HMAC_SHA1, @ossl_aes128cbc_hmac_sha1_functions, ossl_cipher_capable_aes_cbc_hmac_sha1);
    deflt_ciphers[52] := ALGC(PROV_NAMES_AES_256_CBC_HMAC_SHA1, @ossl_aes256cbc_hmac_sha1_functions,  ossl_cipher_capable_aes_cbc_hmac_sha1);
    deflt_ciphers[53] := ALGC(PROV_NAMES_AES_128_CBC_HMAC_SHA256, @ossl_aes128cbc_hmac_sha256_functions, ossl_cipher_capable_aes_cbc_hmac_sha256);
    deflt_ciphers[54] := ALGC(PROV_NAMES_AES_256_CBC_HMAC_SHA256, @ossl_aes256cbc_hmac_sha256_functions, ossl_cipher_capable_aes_cbc_hmac_sha256);
{$ifndef OPENSSL_NO_ARIA}
    deflt_ciphers[55] := ALG(PROV_NAMES_ARIA_256_GCM, @ossl_aria256gcm_functions);
    deflt_ciphers[56] := ALG(PROV_NAMES_ARIA_192_GCM, @ossl_aria192gcm_functions);
    deflt_ciphers[57] := ALG(PROV_NAMES_ARIA_128_GCM, @ossl_aria128gcm_functions);
    deflt_ciphers[58] := ALG(PROV_NAMES_ARIA_256_CCM, @ossl_aria256ccm_functions);
    deflt_ciphers[59] := ALG(PROV_NAMES_ARIA_192_CCM, @ossl_aria192ccm_functions);
    deflt_ciphers[60] := ALG(PROV_NAMES_ARIA_128_CCM, @ossl_aria128ccm_functions);
    deflt_ciphers[61] := ALG(PROV_NAMES_ARIA_256_ECB, @ossl_aria256ecb_functions);
    deflt_ciphers[62] := ALG(PROV_NAMES_ARIA_192_ECB, @ossl_aria192ecb_functions);
    deflt_ciphers[63] := ALG(PROV_NAMES_ARIA_128_ECB, @ossl_aria128ecb_functions);
    deflt_ciphers[64] := ALG(PROV_NAMES_ARIA_256_CBC, @ossl_aria256cbc_functions);
    deflt_ciphers[65] := ALG(PROV_NAMES_ARIA_192_CBC, @ossl_aria192cbc_functions);
    deflt_ciphers[66] := ALG(PROV_NAMES_ARIA_128_CBC, @ossl_aria128cbc_functions);
    deflt_ciphers[67] := ALG(PROV_NAMES_ARIA_256_OFB, @ossl_aria256ofb_functions);
    deflt_ciphers[68] := ALG(PROV_NAMES_ARIA_192_OFB, @ossl_aria192ofb_functions);
    deflt_ciphers[69] := ALG(PROV_NAMES_ARIA_128_OFB, @ossl_aria128ofb_functions);
    deflt_ciphers[70] := ALG(PROV_NAMES_ARIA_256_CFB, @ossl_aria256cfb_functions);
    deflt_ciphers[71] := ALG(PROV_NAMES_ARIA_192_CFB, @ossl_aria192cfb_functions);
    deflt_ciphers[72] := ALG(PROV_NAMES_ARIA_128_CFB, @ossl_aria128cfb_functions);
    deflt_ciphers[73] := ALG(PROV_NAMES_ARIA_256_CFB1, @ossl_aria256cfb1_functions);
    deflt_ciphers[74] := ALG(PROV_NAMES_ARIA_192_CFB1, @ossl_aria192cfb1_functions);
    deflt_ciphers[75] := ALG(PROV_NAMES_ARIA_128_CFB1, @ossl_aria128cfb1_functions);
    deflt_ciphers[76] := ALG(PROV_NAMES_ARIA_256_CFB8, @ossl_aria256cfb8_functions);
    deflt_ciphers[77] := ALG(PROV_NAMES_ARIA_192_CFB8, @ossl_aria192cfb8_functions);
    deflt_ciphers[78] := ALG(PROV_NAMES_ARIA_128_CFB8, @ossl_aria128cfb8_functions);
    deflt_ciphers[79] := ALG(PROV_NAMES_ARIA_256_CTR, @ossl_aria256ctr_functions);
    deflt_ciphers[80] := ALG(PROV_NAMES_ARIA_192_CTR, @ossl_aria192ctr_functions);
    deflt_ciphers[81] := ALG(PROV_NAMES_ARIA_128_CTR, @ossl_aria128ctr_functions);
{$endif} (* OPENSSL_NO_ARIA *)
{$ifndef OPENSSL_NO_CAMELLIA}
    deflt_ciphers[82] := ALG(PROV_NAMES_CAMELLIA_256_ECB, @ossl_camellia256ecb_functions);
    deflt_ciphers[83] := ALG(PROV_NAMES_CAMELLIA_192_ECB, @ossl_camellia192ecb_functions);
    deflt_ciphers[84] := ALG(PROV_NAMES_CAMELLIA_128_ECB, @ossl_camellia128ecb_functions);
    deflt_ciphers[85] := ALG(PROV_NAMES_CAMELLIA_256_CBC, @ossl_camellia256cbc_functions);
    deflt_ciphers[86] := ALG(PROV_NAMES_CAMELLIA_192_CBC, @ossl_camellia192cbc_functions);
    deflt_ciphers[87] := ALG(PROV_NAMES_CAMELLIA_128_CBC, @ossl_camellia128cbc_functions);
    deflt_ciphers[88] := ALG(PROV_NAMES_CAMELLIA_128_CBC_CTS, @ossl_camellia128cbc_cts_functions);
    deflt_ciphers[89] := ALG(PROV_NAMES_CAMELLIA_192_CBC_CTS, @ossl_camellia192cbc_cts_functions);
    deflt_ciphers[90] := ALG(PROV_NAMES_CAMELLIA_256_CBC_CTS, @ossl_camellia256cbc_cts_functions);
    deflt_ciphers[91] := ALG(PROV_NAMES_CAMELLIA_256_OFB, @ossl_camellia256ofb_functions);
    deflt_ciphers[92] := ALG(PROV_NAMES_CAMELLIA_192_OFB, @ossl_camellia192ofb_functions);
    deflt_ciphers[93] := ALG(PROV_NAMES_CAMELLIA_128_OFB, @ossl_camellia128ofb_functions);
    deflt_ciphers[94] := ALG(PROV_NAMES_CAMELLIA_256_CFB, @ossl_camellia256cfb_functions);
    deflt_ciphers[95] := ALG(PROV_NAMES_CAMELLIA_192_CFB, @ossl_camellia192cfb_functions);
    deflt_ciphers[96] := ALG(PROV_NAMES_CAMELLIA_128_CFB, @ossl_camellia128cfb_functions);
    deflt_ciphers[97] := ALG(PROV_NAMES_CAMELLIA_256_CFB1, @ossl_camellia256cfb1_functions);
    deflt_ciphers[98] := ALG(PROV_NAMES_CAMELLIA_192_CFB1, @ossl_camellia192cfb1_functions);
    deflt_ciphers[99] := ALG(PROV_NAMES_CAMELLIA_128_CFB1, @ossl_camellia128cfb1_functions);
    deflt_ciphers[100] := ALG(PROV_NAMES_CAMELLIA_256_CFB8, @ossl_camellia256cfb8_functions);
    deflt_ciphers[101] := ALG(PROV_NAMES_CAMELLIA_192_CFB8, @ossl_camellia192cfb8_functions);
    deflt_ciphers[102] := ALG(PROV_NAMES_CAMELLIA_128_CFB8, @ossl_camellia128cfb8_functions);
    deflt_ciphers[103] := ALG(PROV_NAMES_CAMELLIA_256_CTR, @ossl_camellia256ctr_functions);
    deflt_ciphers[104] := ALG(PROV_NAMES_CAMELLIA_192_CTR, @ossl_camellia192ctr_functions);
    deflt_ciphers[105] := ALG(PROV_NAMES_CAMELLIA_128_CTR, @ossl_camellia128ctr_functions);
{$endif} (* OPENSSL_NO_CAMELLIA *)
{$ifndef OPENSSL_NO_DES}
    deflt_ciphers[106] := ALG(PROV_NAMES_DES_EDE3_ECB, @ossl_tdes_ede3_ecb_functions);
    deflt_ciphers[107] := ALG(PROV_NAMES_DES_EDE3_CBC, @ossl_tdes_ede3_cbc_functions);
    deflt_ciphers[108] := ALG(PROV_NAMES_DES_EDE3_OFB, @ossl_tdes_ede3_ofb_functions);
    deflt_ciphers[109] := ALG(PROV_NAMES_DES_EDE3_CFB, @ossl_tdes_ede3_cfb_functions);
    deflt_ciphers[110] := ALG(PROV_NAMES_DES_EDE3_CFB8, @ossl_tdes_ede3_cfb8_functions);
    deflt_ciphers[111] := ALG(PROV_NAMES_DES_EDE3_CFB1, @ossl_tdes_ede3_cfb1_functions);
    deflt_ciphers[112] := ALG(PROV_NAMES_DES3_WRAP, @ossl_tdes_wrap_cbc_functions);
    deflt_ciphers[113] := ALG(PROV_NAMES_DES_EDE_ECB, @ossl_tdes_ede2_ecb_functions);
    deflt_ciphers[114] := ALG(PROV_NAMES_DES_EDE_CBC, @ossl_tdes_ede2_cbc_functions);
    deflt_ciphers[115] := ALG(PROV_NAMES_DES_EDE_OFB, @ossl_tdes_ede2_ofb_functions);
    deflt_ciphers[116] := ALG(PROV_NAMES_DES_EDE_CFB, @ossl_tdes_ede2_cfb_functions);
{$endif} (* OPENSSL_NO_DES *)
{$ifndef OPENSSL_NO_SM4}
    deflt_ciphers[117] := ALG(PROV_NAMES_SM4_GCM, @ossl_sm4128gcm_functions);
    deflt_ciphers[118] := ALG(PROV_NAMES_SM4_CCM, @ossl_sm4128ccm_functions);
    deflt_ciphers[119] := ALG(PROV_NAMES_SM4_ECB, @ossl_sm4128ecb_functions);
    deflt_ciphers[120] := ALG(PROV_NAMES_SM4_CBC, @ossl_sm4128cbc_functions);
    deflt_ciphers[121] := ALG(PROV_NAMES_SM4_CTR, @ossl_sm4128ctr_functions);
    deflt_ciphers[122] := ALG(PROV_NAMES_SM4_OFB, @ossl_sm4128ofb128_functions);
    deflt_ciphers[123] := ALG(PROV_NAMES_SM4_CFB, @ossl_sm4128cfb128_functions);
{$endif} (* OPENSSL_NO_SM4 *)
{$ifndef OPENSSL_NO_CHACHA}
    //deflt_ciphers[124] := ALG(PROV_NAMES_ChaCha20, ossl_chacha20_functions);
    deflt_ciphers[124] := ALG( nil, nil, nil, nil);
{$ifndef OPENSSL_NO_POLY1305}
    //deflt_ciphers[125] := ALG(PROV_NAMES_ChaCha20_Poly1305, ossl_chacha20_ossl_poly1305_functions);
    deflt_ciphers[125] := ALG( nil, nil, nil, nil);
{$endif} (* OPENSSL_NO_POLY1305 *)
{$endif} (* OPENSSL_NO_CHACHA *)
    deflt_ciphers[126] := ALG( nil, nil, nil, nil);
    deflt_param_types[0] := OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, nil, 0);
    deflt_param_types[1] := OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, nil, 0);
    deflt_param_types[2] := OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, nil, 0);
    deflt_param_types[3] := OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, nil, 0);
    deflt_param_types[4] := OSSL_PARAM_END;

end.
