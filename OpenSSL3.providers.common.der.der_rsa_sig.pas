unit OpenSSL3.providers.common.der.der_rsa_sig;

interface
uses OpenSSL.Api;

const
    DER_OID_SZ_hashAlgs                           = 10;
    DER_OID_V_hashAlgs:array[0..9] of Byte = (DER_P_OBJECT, 8, $60, $86, $48, $01, $65, $03, $04, $02);
    DER_OID_SZ_rsaEncryption                      = 11;
    DER_OID_V_rsaEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $01);

    DER_OID_V_id_RSAES_OAEP:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $07);
    DER_OID_SZ_id_RSAES_OAEP                      = 11;
    DER_OID_V_id_pSpecified:array[0..10] of Byte  = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $09);
    DER_OID_SZ_id_pSpecified                      = 11;
    DER_OID_V_id_RSASSA_PSS:array[0..10] of Byte  = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0A);
    DER_OID_SZ_id_RSASSA_PSS                      = 11;
    DER_OID_V_md2WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $02);
    DER_OID_SZ_md2WithRSAEncryption               = 11;
    DER_OID_V_md5WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $04);
    DER_OID_SZ_md5WithRSAEncryption               = 11;
    DER_OID_V_sha1WithRSAEncryption:array[0..10] of Byte= (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $05);
    DER_OID_SZ_sha1WithRSAEncryption              = 11;
    DER_OID_V_sha224WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0E);
    DER_OID_SZ_sha224WithRSAEncryption            = 11;
    DER_OID_V_sha256WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0B);
    DER_OID_SZ_sha256WithRSAEncryption            = 11;
    DER_OID_V_sha384WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0C);
    DER_OID_SZ_sha384WithRSAEncryption            = 11;
    DER_OID_V_sha512WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0D);
    DER_OID_SZ_sha512WithRSAEncryption            = 11;
    DER_OID_V_sha512_224WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0F);
    DER_OID_SZ_sha512_224WithRSAEncryption        = 11;
    DER_OID_V_sha512_256WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $10);
    DER_OID_SZ_sha512_256WithRSAEncryption        = 11;
    DER_OID_V_id_mgf1:array[0..10] of Byte        = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08);
    DER_OID_SZ_id_mgf1                            = 11;
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_224:array[0..10] of Byte = (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $0D);
    DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_224 = 11;
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_256:array[0..10] of Byte = (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $0E);
    DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_256 = 11;
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_384:array[0..10] of Byte  = (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $0F);
    DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_384 = 11;
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_512:array[0..10] of Byte  = (DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $03, $10);
    DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_512 = 11;
    DER_OID_V_md4WithRSAEncryption:array[0..10] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $03);
    DER_OID_SZ_md4WithRSAEncryption               = 11;
    DER_OID_V_ripemd160WithRSAEncryption:array[0..7] of Byte = (DER_P_OBJECT, 6, $2B, $24, $03, $03, $01, $02);
    DER_OID_SZ_ripemd160WithRSAEncryption         = 8;
    DER_OID_V_mdc2WithRSASignature:array[0..6] of Byte = (DER_P_OBJECT, 5, $2B, $0E, $03, $02, $0E);
    DER_OID_SZ_mdc2WithRSASignature               = 7;

    ossl_der_oid_id_RSASSA_PSS: array[0..DER_OID_SZ_id_RSASSA_PSS-1] of Byte = (DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $0A);

var // 1d arrays
  ossl_der_oid_rsaEncryption: array[0..10] of Byte;// =  DER_OID_V_rsaEncryption ;
  ossl_der_oid_rsassaPss: array[0..10] of Byte;// ossl_der_oid_id_RSASSA_PSS
  ossl_der_oid_id_RSAES_OAEP : array[0..10] of byte;
  ossl_der_oid_id_pSpecified : array[0..10] of byte;
  ossl_der_oid_md2WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_md5WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_sha1WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_sha224WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_sha256WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_sha384WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_sha512WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_sha512_224WithRSAEncryption : array[0..10] of byte ;
  ossl_der_oid_sha512_256WithRSAEncryption : array[0..10] of byte;
  ossl_der_oid_id_mgf1 : array[0..10] of byte;
  ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224 : array[0..10] of byte;
  ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256 : array[0..10] of byte;
  ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384 : array[0..10] of byte;
  ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512 : array[0..10] of byte;
  ossl_der_oid_md4WithRSAEncryption : array[0..10] of byte ;
  ossl_der_oid_ripemd160WithRSAEncryption : array[0..10] of byte ;
  ossl_der_oid_mdc2WithRSASignature : array[0..10] of byte ;
  ossl_der_oid_mdc2WithRSAEncryption: array[0..10] of byte ;
  ossl_der_oid_sha3_224WithRSAEncryption:array[0..10] of byte;
  ossl_der_oid_sha3_256WithRSAEncryption:array[0..10] of byte;
  ossl_der_oid_sha3_384WithRSAEncryption:array[0..10] of byte;
  ossl_der_oid_sha3_512WithRSAEncryption:array[0..10] of byte;

function ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption( pkt : PWPACKET; tag, mdnid : integer):integer;

implementation
uses openssl3.crypto.der_write;

procedure ArrayCopy(var dest: array of Byte; const Src: array of Byte);
var
  i: integer;
begin
  for i := Low(Src) to High(Src) do
    Dest[i] := Src[i];
end;

function ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption( pkt : PWPACKET; tag, mdnid : integer):integer;
var
    precompiled    : PByte;
    precompiled_sz : size_t;
begin
     precompiled := nil;
    precompiled_sz := 0;
    case mdnid of
{$IFNDEF FIPS_MODULE}
        NID_md2:
        begin
            precompiled := @ossl_der_oid_md2WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_md2WithRSAEncryption);
        end;
        NID_md5:
        begin
          precompiled := @ossl_der_oid_md5WithRSAEncryption;
          precompiled_sz := sizeof(ossl_der_oid_md5WithRSAEncryption);
        end;
        NID_md4:
        begin
            precompiled := @ossl_der_oid_md4WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_md4WithRSAEncryption);
        end;
        NID_ripemd160:
        begin
            precompiled := @ossl_der_oid_ripemd160WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_ripemd160WithRSAEncryption);
        end;
        NID_mdc2:
        begin
            precompiled := @ossl_der_oid_mdc2WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_mdc2WithRSAEncryption);
        end;
{$ENDIF}
        NID_sha1:
        begin
            precompiled := @ossl_der_oid_sha1WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha1WithRSAEncryption);
        end;
        NID_sha224:
        begin
            precompiled := @ossl_der_oid_sha224WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha224WithRSAEncryption);
        end;
        NID_sha256:
        begin
            precompiled := @ossl_der_oid_sha256WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha256WithRSAEncryption);
        end;
        NID_sha384:
        begin
            precompiled := @ossl_der_oid_sha384WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha384WithRSAEncryption);
        end;
        NID_sha512:
        begin
            precompiled := @ossl_der_oid_sha512WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha512WithRSAEncryption);
        end;
        NID_sha512_224:
        begin
            precompiled := @ossl_der_oid_sha512_224WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha512_224WithRSAEncryption);
        end;
        NID_sha512_256:
        begin
            precompiled := @ossl_der_oid_sha512_256WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha512_256WithRSAEncryption);
        end;
        NID_sha3_224:
        begin
            precompiled := @ossl_der_oid_sha3_224WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha3_224WithRSAEncryption);
        end;
        NID_sha3_256:
        begin
            precompiled := @ossl_der_oid_sha3_256WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha3_256WithRSAEncryption);
        end;
        NID_sha3_384:
        begin
            precompiled := @ossl_der_oid_sha3_384WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha3_384WithRSAEncryption);
        end;
        NID_sha3_512:
        begin
            precompiled := @ossl_der_oid_sha3_512WithRSAEncryption;
            precompiled_sz := sizeof(ossl_der_oid_sha3_512WithRSAEncryption);
        end;
        else
        {
         * Hash algorithms for which we do not have a valid OID
         * such as md5sha1 will just fail to provide the der encoding.
         * That does not prevent producing signatures if OID is not needed.
         }
        Exit(-1);
    end;
    Result := int( (ossl_DER_w_begin_sequence(pkt, tag)>0)
        { PARAMETERS, always nil according to current standards }
         and  (ossl_DER_w_null(pkt, -1)>0)
        { OID }
         and  (ossl_DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)>0)
         and  (ossl_DER_w_end_sequence(pkt, tag)>0) );
end;

initialization
  ArrayCopy(ossl_der_oid_rsaEncryption, DER_OID_V_rsaEncryption);
  ArrayCopy(ossl_der_oid_id_RSAES_OAEP ,DER_OID_V_id_RSAES_OAEP );
  ArrayCopy(ossl_der_oid_id_pSpecified, DER_OID_V_id_pSpecified );
  ArrayCopy(ossl_der_oid_rsassaPss, ossl_der_oid_id_RSASSA_PSS);
  ArrayCopy(ossl_der_oid_md2WithRSAEncryption,DER_OID_V_md2WithRSAEncryption );
  ArrayCopy(ossl_der_oid_md5WithRSAEncryption, DER_OID_V_md5WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha1WithRSAEncryption,DER_OID_V_sha1WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha224WithRSAEncryption ,DER_OID_V_sha224WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha256WithRSAEncryption ,DER_OID_V_sha256WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha384WithRSAEncryption ,DER_OID_V_sha384WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha512WithRSAEncryption ,DER_OID_V_sha512WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha512_224WithRSAEncryption ,DER_OID_V_sha512_224WithRSAEncryption );
  ArrayCopy(ossl_der_oid_sha512_256WithRSAEncryption ,DER_OID_V_sha512_256WithRSAEncryption );
  ArrayCopy(ossl_der_oid_id_mgf1 ,DER_OID_V_id_mgf1 );
  ArrayCopy(ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224 ,DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_224 );
  ArrayCopy(ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256 ,DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_256 );
  ArrayCopy(ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384 ,DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_384 );
  ArrayCopy(ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512 ,DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_512 );
  ArrayCopy(ossl_der_oid_md4WithRSAEncryption ,DER_OID_V_md4WithRSAEncryption );
  ArrayCopy(ossl_der_oid_ripemd160WithRSAEncryption ,DER_OID_V_ripemd160WithRSAEncryption );
  ArrayCopy(ossl_der_oid_mdc2WithRSASignature ,DER_OID_V_mdc2WithRSASignature );
  ArrayCopy(ossl_der_oid_mdc2WithRSAEncryption ,ossl_der_oid_mdc2WithRSASignature) ;
  ArrayCopy(ossl_der_oid_sha3_224WithRSAEncryption ,ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224);
  ArrayCopy(ossl_der_oid_sha3_256WithRSAEncryption ,ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256);
  ArrayCopy(ossl_der_oid_sha3_384WithRSAEncryption ,ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384);
  ArrayCopy(ossl_der_oid_sha3_512WithRSAEncryption ,ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512);
end.
