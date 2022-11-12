unit OpenSSL3.providers.common.der.der_ec_sig;

interface
uses OpenSSL.Api;

const
   DER_OID_SZ_ecdsa_with_SHA1 = 9;
   DER_OID_SZ_ecdsa_with_SHA224 = 10;
   DER_OID_SZ_ecdsa_with_SHA256 = 10;
   DER_OID_SZ_ecdsa_with_SHA384 = 10;
   DER_OID_SZ_ecdsa_with_SHA512 = 10;
   DER_OID_SZ_id_ecdsa_with_sha3_256 = 11;
   DER_OID_SZ_id_ecdsa_with_sha3_224 = 11;
   DER_OID_SZ_id_ecdsa_with_sha3_384 = 11;
   DER_OID_SZ_id_ecdsa_with_sha3_512 = 11;

   ossl_der_oid_ecdsa_with_SHA1: array[0..DER_OID_SZ_ecdsa_with_SHA1-1] of Byte = (
       DER_P_OBJECT, 7, $2A, $86, $48, $CE, $3D, $04, $01);
   ossl_der_oid_id_ecdsa_with_sha1: array[0..DER_OID_SZ_ecdsa_with_SHA1-1] of Byte = (
       DER_P_OBJECT, 7, $2A, $86, $48, $CE, $3D, $04, $01);

   ossl_der_oid_ecdsa_with_SHA224: array[0..DER_OID_SZ_ecdsa_with_SHA224-1]of Byte = (
       DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $01);
   ossl_der_oid_id_ecdsa_with_sha224: array[0..DER_OID_SZ_ecdsa_with_SHA224-1]of Byte = (
       DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $01);

   ossl_der_oid_ecdsa_with_SHA256: array[0..DER_OID_SZ_ecdsa_with_SHA256-1] of Byte = (
       DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $02);
   ossl_der_oid_id_ecdsa_with_sha256: array[0..DER_OID_SZ_ecdsa_with_SHA256-1] of Byte = (
       DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $02);

   ossl_der_oid_ecdsa_with_SHA384: array[0..DER_OID_SZ_ecdsa_with_SHA384-1]  of Byte = (
      DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $03);
   ossl_der_oid_id_ecdsa_with_sha384: array[0..DER_OID_SZ_ecdsa_with_SHA384-1]  of Byte = (
      DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $03);

   ossl_der_oid_ecdsa_with_SHA512: array[0..DER_OID_SZ_ecdsa_with_SHA512-1]  of Byte = (
      DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $04);
   ossl_der_oid_id_ecdsa_with_sha512: array[0..DER_OID_SZ_ecdsa_with_SHA512-1]  of Byte = (
      DER_P_OBJECT, 8, $2A, $86, $48, $CE, $3D, $04, $03, $04);

   ossl_der_oid_id_ecdsa_with_sha3_224: array[0..DER_OID_SZ_id_ecdsa_with_sha3_224-1] of Byte = (
      DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $09);
   ossl_der_oid_id_ecdsa_with_sha3_256: array[0..DER_OID_SZ_id_ecdsa_with_sha3_256-1]of Byte = (
      DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $0A);
   ossl_der_oid_id_ecdsa_with_sha3_384: array[0..DER_OID_SZ_id_ecdsa_with_sha3_384-1] of Byte = (
      DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $0B);
   ossl_der_oid_id_ecdsa_with_sha3_512: array[0..DER_OID_SZ_id_ecdsa_with_sha3_512-1] of Byte = (
      DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $0C);

function ossl_DER_w_algorithmIdentifier_ECDSA_with_MD( pkt : PWPACKET; cont : integer; ec : PEC_KEY; mdnid : integer):integer;

implementation
uses openssl3.crypto.der_write;

function ossl_DER_w_algorithmIdentifier_ECDSA_with_MD( pkt : PWPACKET; cont : integer; ec : PEC_KEY; mdnid : integer):integer;
var
    precompiled    : PByte;
    precompiled_sz : size_t;
begin
     precompiled := nil;
    precompiled_sz := 0;
    case mdnid of

        NID_sha1:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha1;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha1);
        end;

        NID_sha224:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha224;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha224);
        end;

        NID_sha256:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha256;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha256);
        end;

        NID_sha384:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha384;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha384);
        end;

        NID_sha512:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha512;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha512);
        end;

        NID_sha3_224:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha3_224;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha3_224);
        end;

        NID_sha3_256:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha3_256;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha3_256);
        end;

        NID_sha3_384:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha3_384;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha3_384);
        end;

        NID_sha3_512:
        begin
          precompiled := @ossl_der_oid_id_ecdsa_with_sha3_512;
          precompiled_sz := sizeof(ossl_der_oid_id_ecdsa_with_sha3_512);
        end;
        else
        Exit(0);
    end;
    result := int( (ossl_DER_w_begin_sequence(pkt, cont)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)>0)
         and  (ossl_DER_w_end_sequence(pkt, cont)>0));
end;


end.
