unit OpenSSL3.fuzz.asn1;

//extract from asn1.i
interface
uses OpenSSL.Api;

 function ossl_check_ASN1_VALUE_sk_type( sk : Pstack_st_ASN1_VALUE):POPENSSL_STACK;

function ossl_check_const_ASN1_VALUE_sk_type(const sk : Pstack_st_ASN1_VALUE):POPENSSL_STACK;

function ossl_check_ASN1_VALUE_type( ptr : PASN1_VALUE):PASN1_VALUE;

implementation


function ossl_check_ASN1_VALUE_type( ptr : PASN1_VALUE):PASN1_VALUE;
begin
   Result := ptr;
end;



function ossl_check_const_ASN1_VALUE_sk_type(const sk : Pstack_st_ASN1_VALUE):POPENSSL_STACK;
begin
   Exit(POPENSSL_STACK( sk));
end;


function ossl_check_ASN1_VALUE_sk_type( sk : Pstack_st_ASN1_VALUE):POPENSSL_STACK;
begin
   Exit(POPENSSL_STACK( sk));
end;



end.
