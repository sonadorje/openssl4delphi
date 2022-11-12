unit OpenSSL3.providers.common.der.der_dsa_sig;

interface
uses OpenSSL.Api, StrUtils;

function ossl_DER_w_algorithmIdentifier_DSA_with_MD( pkt : PWPACKET; tag : integer; dsa : PDSA; mdnid : integer):Boolean;

const // 1d arrays
   DER_OID_SZ_id_dsa = 9;
   DER_OID_SZ_id_dsa_with_sha1 = 9;
   DER_OID_SZ_id_dsa_with_sha224 = 11;
   DER_OID_SZ_id_dsa_with_sha256 = 11;
   DER_OID_SZ_id_dsa_with_sha384 = 11;
   DER_OID_SZ_id_dsa_with_sha512 = 11;
   DER_OID_SZ_id_dsa_with_sha3_224 = 11;
   DER_OID_SZ_id_dsa_with_sha3_256 = 11;
   DER_OID_SZ_id_dsa_with_sha3_384 = 11;
   DER_OID_SZ_id_dsa_with_sha3_512 = 11;

  ossl_der_oid_id_dsa : array[0.. DER_OID_SZ_id_dsa-1] of Byte = (
    {DER_OID_V_id_dsa}DER_P_OBJECT, 7, $2A, $86, $48, $CE, $38, $04, $01 );

  ossl_der_oid_id_dsa_with_sha1 : array[0.. DER_OID_SZ_id_dsa_with_sha1-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha1}DER_P_OBJECT, 7, $2A, $86, $48, $CE, $38, $04, $03 );

  ossl_der_oid_id_dsa_with_sha224 : array[0..DER_OID_SZ_id_dsa_with_sha224-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha224}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $01 );

  ossl_der_oid_id_dsa_with_sha256 : array[0..DER_OID_SZ_id_dsa_with_sha256-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha256}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $02 );

  ossl_der_oid_id_dsa_with_sha384 : array[0..DER_OID_SZ_id_dsa_with_sha384-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha384}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $03 );

  ossl_der_oid_id_dsa_with_sha512 : array[0..DER_OID_SZ_id_dsa_with_sha512-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha512}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $04 );

  ossl_der_oid_id_dsa_with_sha3_224 : array[0..DER_OID_SZ_id_dsa_with_sha3_224-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha3_224}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $05 );

  ossl_der_oid_id_dsa_with_sha3_256 : array[0..DER_OID_SZ_id_dsa_with_sha3_256-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha3_256}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $06 );

  ossl_der_oid_id_dsa_with_sha3_384 : array[0..DER_OID_SZ_id_dsa_with_sha3_384-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha3_384}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $07 );

  ossl_der_oid_id_dsa_with_sha3_512 : array[0..DER_OID_SZ_id_dsa_with_sha3_512-1] of Byte = (
    {DER_OID_V_id_dsa_with_sha3_512}DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $08 );

implementation
uses openssl3.crypto.der_write;


function ossl_DER_w_algorithmIdentifier_DSA_with_MD( pkt : PWPACKET; tag : integer; dsa : PDSA; mdnid : integer):Boolean;
var
    precompiled    : PByte;

    precompiled_sz : size_t;

begin
    precompiled := nil;
    precompiled_sz := 0;

    Case mdnid  of
      NID_sha1:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha1;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha1);
      end;
      NID_sha224:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha224;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha224);
      end;
      NID_sha256:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha256;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha256);
      end;
      NID_sha384:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha384;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha384);
      end;
      NID_sha512:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha512;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha512);
      end;
      NID_sha3_224:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha3_224;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha3_224);
      end;
      NID_sha3_256:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha3_256;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha3_256);
      end;
      NID_sha3_384:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha3_384;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha3_384);
      end;
      NID_sha3_512:
      begin
        precompiled := @ossl_der_oid_id_dsa_with_sha3_512;
        precompiled_sz := sizeof(ossl_der_oid_id_dsa_with_sha3_512);
      end;
      else
        Exit(False);
    End;



    Result := (ossl_DER_w_begin_sequence(pkt, tag)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)>0)
         and  (ossl_DER_w_end_sequence(pkt, tag)>0);
end;



end.
