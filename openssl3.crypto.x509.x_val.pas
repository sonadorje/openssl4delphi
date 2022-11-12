unit openssl3.crypto.x509.x_val;

interface
uses OpenSSL.Api;

var
 X509_VAL_seq_tt : array of TASN1_TEMPLATE;

 function X509_VAL_it:PASN1_ITEM;

implementation
uses openssl3.crypto.asn1.a_time;

function X509_VAL_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @X509_VAL_seq_tt,
         sizeof(X509_VAL_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
         sizeof(X509_VAL), 'X509_VAL');
   Result := @local_it;
end;

initialization
   X509_VAL_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_VAL(0).notBefore), 'notBefore', ASN1_TIME_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_VAL(0).notAfter), 'notAfter', ASN1_TIME_it)
   ] ;

end.
