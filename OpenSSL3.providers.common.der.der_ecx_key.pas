unit OpenSSL3.providers.common.der.der_ecx_key;

interface
 uses OpenSSL.Api;

function ossl_DER_w_algorithmIdentifier_X25519( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
  function ossl_DER_w_algorithmIdentifier_X448( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
  function ossl_DER_w_algorithmIdentifier_ED25519( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
  function ossl_DER_w_algorithmIdentifier_ED448( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;

const
  DER_OID_SZ_id_X25519 = 5;
  DER_OID_SZ_id_X448   = 5;
  SZ_id_Ed25519        = 5;
  DER_OID_SZ_id_Ed448  = 5;
  ossl_der_oid_id_X25519: array[0..4] of Byte = (
                   DER_P_OBJECT, 3, $2B, $65, $6E
                   );
  ossl_der_oid_id_X448: array[0..4] of Byte = (
                  DER_P_OBJECT, 3, $2B, $65, $6F
                  );
  ossl_der_oid_id_Ed25519: array[0..4] of Byte = (
                  DER_P_OBJECT, 3, $2B, $65, $70
                  );
  ossl_der_oid_id_Ed448: array[0..4] of Byte = (
                  DER_P_OBJECT, 3, $2B, $65, $71
                  );

implementation
uses openssl3.crypto.der_write;

function ossl_DER_w_algorithmIdentifier_X25519( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
begin
    Result := Int( (ossl_DER_w_begin_sequence(pkt, cont)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, @ossl_der_oid_id_X25519,
                                  sizeof(ossl_der_oid_id_X25519))>0)
         and  (ossl_DER_w_end_sequence(pkt, cont)>0));
end;


function ossl_DER_w_algorithmIdentifier_X448( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
begin
    Result := Int( (ossl_DER_w_begin_sequence(pkt, cont)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, @ossl_der_oid_id_X448,
                                  sizeof(ossl_der_oid_id_X448))>0)
          and  (ossl_DER_w_end_sequence(pkt, cont)>0));
end;


function ossl_DER_w_algorithmIdentifier_ED25519( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
begin
    Result := Int( (ossl_DER_w_begin_sequence(pkt, cont)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, @ossl_der_oid_id_Ed25519,
                                  sizeof(ossl_der_oid_id_Ed25519))>0)
         and  (ossl_DER_w_end_sequence(pkt, cont)>0));
end;


function ossl_DER_w_algorithmIdentifier_ED448( pkt : PWPACKET; cont : integer; ec : PECX_KEY):integer;
begin
    Result := Int((ossl_DER_w_begin_sequence(pkt, cont)>0)
        { No parameters (yet?) }
         and  (ossl_DER_w_precompiled(pkt, -1, @ossl_der_oid_id_Ed448,
                                  sizeof(ossl_der_oid_id_Ed448))>0)
         and  (ossl_DER_w_end_sequence(pkt, cont)>0));
end;


end.
