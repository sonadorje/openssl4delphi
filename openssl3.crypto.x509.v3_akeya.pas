unit openssl3.crypto.x509.v3_akeya;

interface
uses OpenSSL.Api;

 function d2i_AUTHORITY_KEYID(a : PPAUTHORITY_KEYID;const _in : PPByte; len : long):PAUTHORITY_KEYID;
  function i2d_AUTHORITY_KEYID(const a : PAUTHORITY_KEYID; _out : PPByte):integer;
  function AUTHORITY_KEYID_new:PAUTHORITY_KEYID;
  procedure AUTHORITY_KEYID_free( a : PAUTHORITY_KEYID);
  function AUTHORITY_KEYID_it:PASN1_ITEM;

var
  AUTHORITY_KEYID_seq_tt: array[0..2] of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.x509.v3_genn ;


function AUTHORITY_KEYID_it:PASN1_ITEM;

 const  local_it: TASN1_ITEM = (
  itype: $1;
  utype:  16;
  templates:  @AUTHORITY_KEYID_seq_tt;
  tcount: sizeof(AUTHORITY_KEYID_seq_tt) div sizeof(TASN1_TEMPLATE);
  funcs: Pointer(0) ;
  size: sizeof(AUTHORITY_KEYID);
  sname: 'AUTHORITY_KEYID' );
begin
  result := @local_it;
end;


function d2i_AUTHORITY_KEYID(a : PPAUTHORITY_KEYID;const _in : PPByte; len : long):PAUTHORITY_KEYID;
begin
   Result :=  PAUTHORITY_KEYID( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, AUTHORITY_KEYID_it));
end;


function i2d_AUTHORITY_KEYID(const a : PAUTHORITY_KEYID; _out : PPByte):integer;
begin
   Result :=  ASN1_item_i2d(PASN1_VALUE( a), _out, AUTHORITY_KEYID_it);
end;


function AUTHORITY_KEYID_new:PAUTHORITY_KEYID;
begin
   Result :=  PAUTHORITY_KEYID(ASN1_item_new(AUTHORITY_KEYID_it));
end;


procedure AUTHORITY_KEYID_free( a : PAUTHORITY_KEYID);
begin
   ASN1_item_free(PASN1_VALUE( a), AUTHORITY_KEYID_it);
end;

initialization
    AUTHORITY_KEYID_seq_tt[0] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  ($1)), 0, size_t(@PAUTHORITY_KEYID(0).keyid), 'keyid', ASN1_OCTET_STRING_it );
    AUTHORITY_KEYID_seq_tt[1] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  (($2  shl  1) or $1)), (1), size_t(@PAUTHORITY_KEYID(0).issuer), 'issuer', GENERAL_NAME_it );
    AUTHORITY_KEYID_seq_tt[2] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  ($1)), 2, size_t(@PAUTHORITY_KEYID(0).serial), 'serial', ASN1_INTEGER_it );

end.
