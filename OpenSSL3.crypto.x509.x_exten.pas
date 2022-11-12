unit OpenSSL3.crypto.x509.x_exten;

interface
uses OpenSSL.Api;

function X509_EXTENSION_dup(const x : PX509_EXTENSION):PX509_EXTENSION;
function X509_EXTENSION_it:PASN1_ITEM;
function d2i_X509_EXTENSION(a : PPX509_EXTENSION;const _in : PPByte; len : long):PX509_EXTENSION;
  function i2d_X509_EXTENSION(const a : PX509_EXTENSION; _out : PPByte):integer;
  function X509_EXTENSION_new:PX509_EXTENSION;
  procedure X509_EXTENSION_free( a : PX509_EXTENSION);

var
  X509_EXTENSION_seq_tt: array[0..2] of TASN1_TEMPLATE;

implementation
 uses openssl3.crypto.asn1.a_dup, openssl3.crypto.asn1.tasn_typ,
      openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
      openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre;


function d2i_X509_EXTENSION(a : PPX509_EXTENSION;const _in : PPByte; len : long):PX509_EXTENSION;
begin
  Result := PX509_EXTENSION( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_EXTENSION_it));
end;


function i2d_X509_EXTENSION(const a : PX509_EXTENSION; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_EXTENSION_it);
end;


function X509_EXTENSION_new:PX509_EXTENSION;
begin
  Result := PX509_EXTENSION( ASN1_item_new(X509_EXTENSION_it));
end;


procedure X509_EXTENSION_free( a : PX509_EXTENSION);
begin
 ASN1_item_free(PASN1_VALUE( a), X509_EXTENSION_it);
end;

function X509_EXTENSION_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @X509_EXTENSION_seq_tt,
                      sizeof(X509_EXTENSION_seq_tt) div sizeof(TASN1_TEMPLATE),
                      Pointer(0) , sizeof(TX509_EXTENSION), 'X509_EXTENSION');

   result := @local_it;
end;

function X509_EXTENSION_dup(const x : PX509_EXTENSION):PX509_EXTENSION;
begin
   Result := ASN1_item_dup(X509_EXTENSION_it, x);
end;

initialization
  X509_EXTENSION_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_EXTENSION(0)._object), 'object', ASN1_OBJECT_it );
  X509_EXTENSION_seq_tt[1] := get_ASN1_TEMPLATE( $1, 0, size_t(@PX509_EXTENSION(0).critical), 'critical', ASN1_BOOLEAN_it );
  X509_EXTENSION_seq_tt[2] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX509_EXTENSION(0).value), 'value', ASN1_OCTET_STRING_it);

end.
