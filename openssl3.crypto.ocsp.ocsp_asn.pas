unit openssl3.crypto.ocsp.ocsp_asn;

interface
uses OpenSSL.Api;

var
  OCSP_CRLID_seq_tt, OCSP_SERVICELOC_seq_tt : array of TASN1_TEMPLATE;

function OCSP_CRLID_it:PASN1_ITEM;

function OCSP_SERVICELOC_it:PASN1_ITEM;

implementation
uses openssl3.crypto.asn1.tasn_typ,         OpenSSL3.crypto.x509.x_name,
     OpenSSL3.crypto.x509.v3_info;




function OCSP_SERVICELOC_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM ($1, 16, @OCSP_SERVICELOC_seq_tt,
            sizeof(OCSP_SERVICELOC_seq_tt) div sizeof(TASN1_TEMPLATE),
            Pointer(0) , sizeof(TOCSP_SERVICELOC), 'OCSP_SERVICELOC');
  Result := @local_it;
end;




function OCSP_CRLID_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @OCSP_CRLID_seq_tt,
                       sizeof(OCSP_CRLID_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                       sizeof(TOCSP_CRLID), 'OCSP_CRLID');
   Result := @local_it;
end;

initialization
  OCSP_CRLID_seq_tt := [
           get_ASN1_TEMPLATE( (($2 shl  3) or  ($2 shl 6))  or   $1, 0, size_t(@POCSP_CRLID(0).crlUrl), ' crlUrl' , ASN1_IA5STRING_it ),
           get_ASN1_TEMPLATE( (($2 shl  3) or  ($2 shl 6))  or   $1, 1, size_t(@POCSP_CRLID(0).crlNum), ' crlNum' , ASN1_INTEGER_it ),
           get_ASN1_TEMPLATE( (($2 shl  3) or  ($2 shl 6))  or   $1, 2, size_t(@POCSP_CRLID(0).crlTime), ' crlTime' , ASN1_GENERALIZEDTIME_it )
   ] ;

   OCSP_SERVICELOC_seq_tt := [
        Get_ASN1_TEMPLATE( 0, 0, size_t(@POCSP_SERVICELOC(0).issuer), 'issuer', X509_NAME_it) ,
        get_ASN1_TEMPLATE( (($2 shl 1) or ($1)), 0, size_t(@POCSP_SERVICELOC(0).locator), 'locator', ACCESS_DESCRIPTION_it)
  ] ;



end.
