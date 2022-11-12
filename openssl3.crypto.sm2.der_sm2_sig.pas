unit openssl3.crypto.sm2.der_sm2_sig;

interface
uses OpenSSL.Api;

const DER_OID_SZ_sm2_with_SM3 =10;
   ossl_der_oid_sm2_with_SM3: array[0..DER_OID_SZ_sm2_with_SM3-1] of Byte = (
       DER_P_OBJECT, 8, $2A, $81, $1C, $CF, $55, $01, $83, $75);
   ossl_der_oid_id_sm2_with_sm3: array[0..DER_OID_SZ_sm2_with_SM3-1] of Byte = (
       DER_P_OBJECT, 8, $2A, $81, $1C, $CF, $55, $01, $83, $75);

function ossl_DER_w_algorithmIdentifier_SM2_with_MD( pkt : PWPACKET; cont : integer; ec : PEC_KEY; mdnid : integer):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
      openssl3.crypto.ec.ec_key, openssl3.crypto.bn.bn_rand,
      openssl3.crypto.bn.bn_add, openssl3.crypto.ec.ec_lib, openssl3.crypto.der_write;



function ossl_DER_w_algorithmIdentifier_SM2_with_MD( pkt : PWPACKET; cont : integer; ec : PEC_KEY; mdnid : integer):integer;
var
    precompiled    : PByte;
    precompiled_sz : size_t;
begin
    precompiled := nil;
    precompiled_sz := 0;
    case mdnid of
        NID_sm3:
        begin
          precompiled := @ossl_der_oid_id_sm2_with_sm3;
          precompiled_sz := sizeof(ossl_der_oid_id_sm2_with_sm3);
        end;
        else
        Exit(0);
    end;
    Result := int( (ossl_DER_w_begin_sequence(pkt, cont)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)>0)
         and  (ossl_DER_w_end_sequence(pkt, cont)>0));
end;







end.
