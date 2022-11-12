unit OpenSSL3.providers.common.der.der_rsa_key;

interface
uses OpenSSL.Api;

const
  DER_SZ_NULL = 2;
  DER_OID_SZ_id_sha1 = 7;
  DER_OID_SZ_id_sha224 = 11;
  DER_OID_SZ_id_sha256 = 11;
  DER_OID_SZ_id_sha384 = 11;
  DER_OID_SZ_id_sha512 = 11;
  DER_OID_SZ_id_sha512_224 = 11;
  DER_OID_SZ_id_sha512_256 = 11;
  DER_OID_SZ_id_mgf1 = 11;
  ossl_der_aid_sha1Identifier: array[0..10] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha1 + DER_SZ_NULL,
                               DER_P_OBJECT, 5, $2B, $0E, $03, $02, $1A, DER_P_NULL, 0);
  ossl_der_aid_sha224Identifier: array[0..14] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha224 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $04,
                               DER_P_NULL, 0);
  ossl_der_aid_sha256Identifier: array[0..14] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha256 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $01,
                               DER_P_NULL, 0);
  ossl_der_aid_sha384Identifier: array[0..14] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha384 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $02,
                               DER_P_NULL, 0);
  ossl_der_aid_sha512Identifier: array[0..14] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha512 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $03 ,
                               DER_P_NULL, 0);
  ossl_der_aid_sha512_224Identifier: array[0..14] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha512_224 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $05 ,
                               DER_P_NULL, 0);
  ossl_der_aid_sha512_256Identifier: array[0..14] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha512_256 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $06,
                               DER_P_NULL, 0);

  DER_AID_SZ_sha224Identifier = sizeof(ossl_der_aid_sha224Identifier);
  der_aid_mgf1SHA224Identifier: array[0..27] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha224Identifier,
                               DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08,
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha224 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $04 ,
                               DER_P_NULL, 0);
 DER_AID_SZ_sha256Identifier = sizeof(ossl_der_aid_sha256Identifier);
 der_aid_mgf1SHA256Identifier: array[0..27] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha256Identifier,
                               DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08,
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha256 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $01,
                               DER_P_NULL, 0);
 DER_AID_SZ_sha384Identifier = sizeof(ossl_der_aid_sha384Identifier);
 der_aid_mgf1SHA384Identifier: array[0..27] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha384Identifier,
                               DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08,
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha384 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $02,
                               DER_P_NULL, 0);
 DER_AID_SZ_sha512Identifier = sizeof(ossl_der_aid_sha512Identifier);
 der_aid_mgf1SHA512Identifier: array[0..27] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha512Identifier,
                               DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08,
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha512 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $03,
                               DER_P_NULL, 0);
 DER_AID_SZ_sha512_224Identifier = sizeof(ossl_der_aid_sha512_224Identifier);
 der_aid_mgf1SHA512_224Identifier: array[0..27] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha512_224Identifier,
                               DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08,
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha512_224 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $05,
                               DER_P_NULL, 0);
 DER_AID_SZ_sha512_256Identifier = sizeof(ossl_der_aid_sha512_256Identifier);
 der_aid_mgf1SHA512_256Identifier: array[0..27] of Byte =(
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha512_256Identifier,
                               DER_P_OBJECT, 9, $2A, $86, $48, $86, $F7, $0D, $01, $01, $08,
                               DER_P_SEQUENCE or DER_F_CONSTRUCTED,
                               DER_OID_SZ_id_sha512_256 + DER_SZ_NULL,
                               DER_P_OBJECT, 9, $60, $86, $48, $01, $65, $03, $04, $02, $06,
                               DER_P_NULL, 0);


function ossl_DER_w_algorithmIdentifier_RSA_PSS(pkt : PWPACKET; tag, rsa_type : integer;const pss : PRSA_PSS_PARAMS_30):integer;
function DER_w_MaskGenAlgorithm(pkt : PWPACKET; tag : integer;const pss : PRSA_PSS_PARAMS_30):integer;
function ossl_DER_w_RSASSA_PSS_params(pkt : PWPACKET; tag : integer;const pss : PRSA_PSS_PARAMS_30):integer;

implementation
uses OpenSSL3.providers.common.der.der_rsa_sig, openssl3.crypto.der_write,
     openssl3.crypto.rsa.rsa_pss, OpenSSL3.common ;




function DER_w_MaskGenAlgorithm(pkt : PWPACKET; tag : integer;const pss : PRSA_PSS_PARAMS_30):integer;
var
    maskgenhashalg_nid : integer;

    maskgenalg         : PByte;

    maskgenalg_sz      : size_t;
begin
    if (pss <> nil)  and  (ossl_rsa_pss_params_30_maskgenalg(pss) = NID_mgf1)  then
    begin
        maskgenhashalg_nid := ossl_rsa_pss_params_30_maskgenhashalg(pss);
         maskgenalg := nil;
        maskgenalg_sz := 0;
        case maskgenhashalg_nid of
        NID_sha1:
            begin
              //
            end;
        NID_sha224:
        begin
          maskgenalg := @der_aid_mgf1SHA224Identifier;
          maskgenalg_sz := sizeof(der_aid_mgf1SHA224Identifier);
        end;
        NID_sha256:
        begin
          maskgenalg := @der_aid_mgf1SHA256Identifier;
          maskgenalg_sz := sizeof(der_aid_mgf1SHA256Identifier);
        end;
        NID_sha384:
        begin
          maskgenalg := @der_aid_mgf1SHA384Identifier;
          maskgenalg_sz := sizeof(der_aid_mgf1SHA384Identifier);
        end;
        NID_sha512:
        begin
          maskgenalg := @der_aid_mgf1SHA512Identifier;
          maskgenalg_sz := sizeof(der_aid_mgf1SHA512Identifier);
        end;
        NID_sha512_224:
        begin
          maskgenalg := @der_aid_mgf1SHA512_224Identifier;
          maskgenalg_sz := sizeof(der_aid_mgf1SHA512_224Identifier);
        end;
        NID_sha512_256:
        begin
          maskgenalg := @der_aid_mgf1SHA512_256Identifier;
          maskgenalg_sz := sizeof(der_aid_mgf1SHA512_256Identifier);
        end;
        else
            Exit(0);
        end;
        { If there is none (or it was the default), we write nothing }
        if maskgenalg = nil then Exit(1);
        Exit(ossl_DER_w_precompiled(pkt, tag, maskgenalg, maskgenalg_sz));
    end;
    Result := 0;
end;

function ossl_DER_w_RSASSA_PSS_params(pkt : PWPACKET; tag : integer;const pss : PRSA_PSS_PARAMS_30):integer;
var
  hashalg_nid,
  default_hashalg_nid,
  saltlen,
  default_saltlen,
  trailerfield,
  default_trailerfield : integer;
  hashalg              : PByte;
  hashalg_sz           : size_t;
begin
    hashalg := nil;
    hashalg_sz := 0;
    {
     * the caller must be in control, because unrestricted keys are permitted
     * in some situations (when encoding the public key in a SubjectKeyInfo,
     * for example) while not in others, and this function doesn't know the
     * intent.  Therefore, we assert that here, the PSS parameters must show
     * that the key is restricted.
     }
    if not ossl_assert( (pss <> nil)
                      and  (0>= ossl_rsa_pss_params_30_is_unrestricted(pss)) )then
        Exit(0);
    hashalg_nid := ossl_rsa_pss_params_30_hashalg(pss);
    saltlen := ossl_rsa_pss_params_30_saltlen(pss);
    trailerfield := ossl_rsa_pss_params_30_trailerfield(pss);
    { Getting default values }
    default_hashalg_nid := ossl_rsa_pss_params_30_hashalg(nil);
    default_saltlen := ossl_rsa_pss_params_30_saltlen(nil);
    default_trailerfield := ossl_rsa_pss_params_30_trailerfield(nil);
    (*
     * From https://tools.ietf.org/html/rfc8017#appendix-A.2.1:
     *
     * OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER .= {
     *     { OID id-sha1       PARAMETERS nil }
     *     { OID id-sha224     PARAMETERS nil }
     *     { OID id-sha256     PARAMETERS nil }
     *     { OID id-sha384     PARAMETERS nil }
     *     { OID id-sha512     PARAMETERS nil }
     *     { OID id-sha512-224 PARAMETERS nil }
     *     { OID id-sha512-256 PARAMETERS nil },
     *     ...  -- Allows for future expansion --
     *
     *}
    *)
    case hashalg_nid of

        NID_sha1:
        begin
            hashalg := @ossl_der_aid_sha1Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha1Identifier);
        end;

        NID_sha224:
        begin
            hashalg := @ossl_der_aid_sha224Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha224Identifier);
        end;

        NID_sha256:
        begin
            hashalg := @ossl_der_aid_sha256Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha256Identifier);
        end;

        NID_sha384:
        begin
            hashalg := @ossl_der_aid_sha384Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha384Identifier);
        end;

        NID_sha512:
        begin
            hashalg := @ossl_der_aid_sha512Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha512Identifier);
        end;

        NID_sha512_224:
        begin
            hashalg := @ossl_der_aid_sha512_224Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha512_224Identifier);
        end;

        NID_sha512_256:
        begin
            hashalg := @ossl_der_aid_sha512_256Identifier;
            hashalg_sz := sizeof(ossl_der_aid_sha512_256Identifier);
        end;
    else
        Exit(0);
    end;
    Result := Int( (ossl_DER_w_begin_sequence(pkt, tag)>0)
         and  ( (trailerfield = default_trailerfield)
             or (ossl_DER_w_ulong(pkt, 3, trailerfield)>0) )
         and  ( (saltlen = default_saltlen)  or  (ossl_DER_w_ulong(pkt, 2, saltlen)>0) )
         and  (DER_w_MaskGenAlgorithm(pkt, 1, pss)>0)
         and  ( (hashalg_nid = default_hashalg_nid)
             or (ossl_DER_w_precompiled(pkt, 0, hashalg, hashalg_sz)>0) )
         and  (ossl_DER_w_end_sequence(pkt, tag)>0) );
end;

function ossl_DER_w_algorithmIdentifier_RSA_PSS(pkt : PWPACKET; tag, rsa_type : integer;const pss : PRSA_PSS_PARAMS_30):integer;
var
    rsa_nid    : integer;
    rsa_oid    : PByte;
    rsa_oid_sz : size_t;
begin
    rsa_nid := NID_undef;
    rsa_oid := nil;
    rsa_oid_sz := 0;
    case rsa_type of
      RSA_FLAG_TYPE_RSA:
      begin
        rsa_nid := NID_rsaEncryption;
        rsa_oid := @ossl_der_oid_rsaEncryption;
        rsa_oid_sz := sizeof(ossl_der_oid_rsaEncryption);
      end;
      RSA_FLAG_TYPE_RSASSAPSS:
      begin
        rsa_nid := NID_rsassaPss;
        rsa_oid := @ossl_der_oid_rsassaPss;
        rsa_oid_sz := sizeof(ossl_der_oid_rsassaPss);
      end;
    end;
    if rsa_oid = nil then
       Exit(0);
    Result := Int( (ossl_DER_w_begin_sequence(pkt, tag)>0)
         and  ( (rsa_nid <> NID_rsassaPss)
             or  (ossl_rsa_pss_params_30_is_unrestricted(pss)>0)
             or  (ossl_DER_w_RSASSA_PSS_params(pkt, -1, pss)>0) )
         and  (ossl_DER_w_precompiled(pkt, -1, rsa_oid, rsa_oid_sz)>0)
         and  (ossl_DER_w_end_sequence(pkt, tag)>0) );
end;


end.
