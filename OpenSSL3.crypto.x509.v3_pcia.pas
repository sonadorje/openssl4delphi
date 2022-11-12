unit OpenSSL3.crypto.x509.v3_pcia;

interface
uses OpenSSL.Api;

function PROXY_POLICY_it:PASN1_ITEM;
function PROXY_CERT_INFO_EXTENSION_it:PASN1_ITEM;
function d2i_PROXY_CERT_INFO_EXTENSION(a : PPPROXY_CERT_INFO_EXTENSION;const _in : PPByte; len : long):PPROXY_CERT_INFO_EXTENSION;
function i2d_PROXY_CERT_INFO_EXTENSION(const a : PPROXY_CERT_INFO_EXTENSION; _out : PPByte):integer;
function PROXY_CERT_INFO_EXTENSION_new:PPROXY_CERT_INFO_EXTENSION;
procedure PROXY_CERT_INFO_EXTENSION_free( a : PPROXY_CERT_INFO_EXTENSION);

var
  PROXY_CERT_INFO_EXTENSION_seq_tt, PROXY_POLICY_seq_tt :array of TASN1_TEMPLATE;

implementation

uses OpenSSL3.openssl.conf, openssl3.crypto.x509v3, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_san, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.o_str,
     openssl3.crypto.x509.v3_genn,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print, OpenSSL3.Err;





function d2i_PROXY_CERT_INFO_EXTENSION(a : PPPROXY_CERT_INFO_EXTENSION;const _in : PPByte; len : long):PPROXY_CERT_INFO_EXTENSION;
begin
 Result := PPROXY_CERT_INFO_EXTENSION(ASN1_item_d2i(PPASN1_VALUE( a), _in, len,
                  PROXY_CERT_INFO_EXTENSION_it));
end;


function i2d_PROXY_CERT_INFO_EXTENSION(const a : PPROXY_CERT_INFO_EXTENSION; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE( a), _out, PROXY_CERT_INFO_EXTENSION_it);
end;


function PROXY_CERT_INFO_EXTENSION_new:PPROXY_CERT_INFO_EXTENSION;
begin
 Result := PPROXY_CERT_INFO_EXTENSION(ASN1_item_new(PROXY_CERT_INFO_EXTENSION_it));
end;


procedure PROXY_CERT_INFO_EXTENSION_free( a : PPROXY_CERT_INFO_EXTENSION);
begin
 ASN1_item_free(PASN1_VALUE( a), PROXY_CERT_INFO_EXTENSION_it);
end;


function PROXY_POLICY_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @PROXY_POLICY_seq_tt,
                          sizeof(PROXY_POLICY_seq_tt) div sizeof(TASN1_TEMPLATE),
                          Pointer(0) , sizeof(PROXY_POLICY), ' PROXY_POLICY'  );
   Result := @local_it;
end;


function PROXY_CERT_INFO_EXTENSION_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM( $1, 16, @PROXY_CERT_INFO_EXTENSION_seq_tt,
                              sizeof(PROXY_CERT_INFO_EXTENSION_seq_tt) div sizeof(TASN1_TEMPLATE),
                              Pointer(0) , sizeof(PROXY_CERT_INFO_EXTENSION), ' PROXY_CERT_INFO_EXTENSION'  );
   Result := @local_it;
end;


initialization
   PROXY_CERT_INFO_EXTENSION_seq_tt := [
        get_ASN1_TEMPLATE( $1, 0,  size_t(@PPROXY_CERT_INFO_EXTENSION(0).pcPathLengthConstraint), ' pcPathLengthConstraint' , ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PPROXY_CERT_INFO_EXTENSION(0).proxyPolicy), ' proxyPolicy' , PROXY_POLICY_it)
   ] ;

   PROXY_POLICY_seq_tt := [
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PPROXY_POLICY(0).policyLanguage), ' policyLanguage' , ASN1_OBJECT_it) ,
        get_ASN1_TEMPLATE( $1, 0,  size_t(@PPROXY_POLICY(0).policy), ' policy' , ASN1_OCTET_STRING_it)
   ] ;


end.
