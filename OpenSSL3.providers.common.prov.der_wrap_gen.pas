unit OpenSSL3.providers.common.prov.der_wrap_gen;

interface
uses OpenSSL.Api;

const
   DER_OID_SZ_id_alg_CMS3DESwrap = 13;
   DER_OID_SZ_id_aes128_wrap     = 11;
   DER_OID_SZ_id_aes192_wrap     = 11;
   DER_OID_SZ_id_aes256_wrap     = 11;

   ossl_der_oid_id_alg_CMS3DESwrap: array[0..DER_OID_SZ_id_alg_CMS3DESwrap-1] of Byte = (
   DER_P_OBJECT, 11, $2A, $86, $48, $86, $F7, $0D, $01, $09, $10, $03, $06 );


   ossl_der_oid_id_aes128_wrap:array[0..DER_OID_SZ_id_aes128_wrap-1] of Byte =
   (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $01, $05);

   ossl_der_oid_id_aes192_wrap: array[0..DER_OID_SZ_id_aes192_wrap-1] of Byte =
   (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $01, $19);

    ossl_der_oid_id_aes256_wrap: array[0..DER_OID_SZ_id_aes256_wrap-1] of byte =
    (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $01, $2D);
implementation


end.
