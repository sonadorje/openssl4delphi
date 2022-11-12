unit openssl3.crypto.asn1.x_sig;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

procedure X509_SIG_get0(const sig : PX509_SIG; palg : PPX509_ALGOR; pdigest : PPASN1_OCTET_STRING);
procedure X509_SIG_getm( sig : PX509_SIG; palg : PPX509_ALGOR; pdigest : PPASN1_OCTET_STRING);
function d2i_X509_SIG(a : PPX509_SIG;const &in : PPByte; len : long):PX509_SIG;
function i2d_X509_SIG(const a : PX509_SIG; _out : PPByte):integer;
function X509_SIG_new:PX509_SIG;
procedure X509_SIG_free( a : PX509_SIG);
function X509_SIG_it:PASN1_ITEM;



var
  X509_SIG_seq_tt :array of TASN1_TEMPLATE;

implementation
 uses openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
      openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
      openssl3.crypto.asn1.x_algor,  openssl3.crypto.asn1.tasn_typ;

 var
   local_it : TASN1_ITEM;
function X509_SIG_it:PASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @X509_SIG_seq_tt[0],
                sizeof(X509_SIG_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                sizeof(TX509_SIG), 'X509_SIG');

  Result := @local_it;
end;

function d2i_X509_SIG(a : PPX509_SIG;const &in : PPByte; len : long):PX509_SIG;
begin
 Result := PX509_SIG (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, X509_SIG_it));
end;


function i2d_X509_SIG(const a : PX509_SIG; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE (a), _out, X509_SIG_it);
end;


function X509_SIG_new:PX509_SIG;
begin
 Result := PX509_SIG (ASN1_item_new(X509_SIG_it));
end;


procedure X509_SIG_free( a : PX509_SIG);
begin
 ASN1_item_free(PASN1_VALUE(a), X509_SIG_it);
end;



procedure X509_SIG_get0(const sig : PX509_SIG; palg : PPX509_ALGOR; pdigest : PPASN1_OCTET_STRING);
begin
    if palg <> nil then palg^ := sig.algor;
    if pdigest <> nil then pdigest^ := sig.digest;
end;


procedure X509_SIG_getm( sig : PX509_SIG; palg : PPX509_ALGOR; pdigest : PPASN1_OCTET_STRING);
begin
    if palg <> nil then palg^ := sig.algor;
    if pdigest <> nil then pdigest^ := sig.digest;
end;

initialization
   X509_SIG_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_SIG(0).algor), 'algor', X509_ALGOR_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_SIG(0).digest), 'digest', ASN1_OCTET_STRING_it)
   ] ;


end.
