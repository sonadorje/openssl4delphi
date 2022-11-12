unit openssl3.crypto.asn1.standard_methods;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

 uses OpenSSL.Api, OpenSSL3.crypto.rsa.rsa_ameth,
      OpenSSL3.crypto.dh.dh_ameth,
      OpenSSL3.crypto.ec.ec_ameth,
      openssl3.crypto.ec.ecx_meth,
      OpenSSL3.crypto.dsa.dsa_ameth;

 const standard_methods: array[0..15] of PEVP_PKEY_ASN1_METHOD = (
    @ossl_rsa_asn1_meths[0],
    @ossl_rsa_asn1_meths[1],
{$ifndef OPENSSL_NO_DH}
    @ossl_dh_asn1_meth,
{$endif}
{$ifndef OPENSSL_NO_DSA}
    @ossl_dsa_asn1_meths[0],
    @ossl_dsa_asn1_meths[1],
    @ossl_dsa_asn1_meths[2],
    @ossl_dsa_asn1_meths[3],
    @ossl_dsa_asn1_meths[4],
{$endif}
{$ifndef OPENSSL_NO_EC}
    @ossl_eckey_asn1_meth,
{$endif}
    @ossl_rsa_pss_asn1_meth,
{$ifndef OPENSSL_NO_DH}
    @ossl_dhx_asn1_meth,
{$endif}
{$ifndef OPENSSL_NO_EC}
    @ossl_ecx25519_asn1_meth,
    @ossl_ecx448_asn1_meth,
{$endif}
{$ifndef OPENSSL_NO_EC}
    @ossl_ed25519_asn1_meth,
    @ossl_ed448_asn1_meth,
{$endif}
{$ifndef OPENSSL_NO_SM2}
    @ossl_sm2_asn1_meth
{$endif}
);
implementation

end.
