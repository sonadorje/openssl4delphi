unit OpenSSL3.crypto.x509.v3_pku;

interface
uses OpenSSL.Api;

function PKEY_USAGE_PERIOD_it:PASN1_ITEM;
function i2r_PKEY_USAGE_PERIOD(const method : PX509V3_EXT_METHOD;usage : Pointer; _out : PBIO; indent : integer):integer;

const ossl_v3_pkey_usage_period: TX509V3_EXT_METHOD  = (
    ext_nid: NID_private_key_usage_period; ext_flags: 0; it: PKEY_USAGE_PERIOD_it;
    ext_new: nil; ext_free: nil; d2i: nil; i2d: nil;
    i2s: nil; s2i: nil;
    i2v: nil;
    v2i: nil;
    i2r: {TX509V3_EXT_I2R}i2r_PKEY_USAGE_PERIOD;
    r2i: nil;
    usr_data: nil
);

var
  PKEY_USAGE_PERIOD_seq_tt: array[0..1] of TASN1_TEMPLATE;



implementation
uses openssl3.crypto.bio.bio_print, openssl3.crypto.bio.bio_lib,
     openssl3.crypto.asn1.a_gentm, openssl3.crypto.asn1.tasn_typ;



function i2r_PKEY_USAGE_PERIOD(const method : PX509V3_EXT_METHOD;usage : Pointer; _out : PBIO; indent : integer):integer;
begin
    BIO_printf(_out, '%*s', [indent, '']);
    if PPKEY_USAGE_PERIOD(usage).notBefore <> nil then
    begin
        BIO_write(_out, PUTF8Char('Not Before: '), 12);
        ASN1_GENERALIZEDTIME_print(_out, PPKEY_USAGE_PERIOD(usage).notBefore);
        if PPKEY_USAGE_PERIOD(usage).notAfter <> nil then
           BIO_write(_out, PUTF8Char(', '), 2);
    end;
    if PPKEY_USAGE_PERIOD(usage).notAfter <> nil then
    begin
        BIO_write(_out, PUTF8Char('Not After: '), 11);
        ASN1_GENERALIZEDTIME_print(_out, PPKEY_USAGE_PERIOD(usage).notAfter);
    end;
    Result := 1;
end;



function PKEY_USAGE_PERIOD_it:PASN1_ITEM;
var
  local_it :TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM(  $1, 16, @PKEY_USAGE_PERIOD_seq_tt,
      sizeof(PKEY_USAGE_PERIOD_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
      sizeof(PKEY_USAGE_PERIOD), 'PKEY_USAGE_PERIOD');

    result := @local_it;
end;

initialization
  PKEY_USAGE_PERIOD_seq_tt[0] := get_ASN1_TEMPLATE( (($1 shl 3) or ($2 shl 6)) or $1, 0, size_t(@PPKEY_USAGE_PERIOD(0).notBefore), 'notBefore', ASN1_GENERALIZEDTIME_it );
  PKEY_USAGE_PERIOD_seq_tt[1] := get_ASN1_TEMPLATE( (($1 shl 3) or ($2 shl 6)) or $1, 1, size_t(@PPKEY_USAGE_PERIOD(0).notAfter) , 'notAfter',  ASN1_GENERALIZEDTIME_it );

end.
