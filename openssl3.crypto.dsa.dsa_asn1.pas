unit openssl3.crypto.dsa.dsa_asn1;

interface
uses OpenSSL.Api;

function i2d_DSAPrivateKey(const a : Pointer;  _out : PPByte):integer;
function dsa_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
function i2d_DSAPublicKey(const a : Pointer; _out : PPByte):integer;
function DSAPublicKey_it:PASN1_ITEM;
function i2d_DSAparams(const a : Pointer; _out : PPByte):integer;
function DSAparams_it:PASN1_ITEM;
 function d2i_DSAparams(a : PPDSA;const &in : PPByte; len : long):PDSA;
function d2i_DSAPrivateKey(a : PPDSA;const &in : PPByte; len : long):PDSA;
function DSAPrivateKey_it:PASN1_ITEM;
function d2i_DSAPublicKey(a : PPDSA;const _in : PPByte; len : long):PDSA;

var
  DSAPrivateKey_seq_tt: array[0..5] of TASN1_TEMPLATE;
  DSAPublicKey_seq_tt:  array[0..3] of TASN1_TEMPLATE;
  DSAparams_seq_tt:     array[0..3] of TASN1_TEMPLATE;

const DSAPrivateKey_aux: TASN1_AUX  = (
     app_data: nil; flags: 0; ref_offset: 0;ref_lock: 0;asn1_cb: dsa_cb;
     enc_offset: 0;asn1_const_cb: nil);

     DSAPublicKey_aux: TASN1_AUX  = (
     app_data: nil; flags: 0; ref_offset: 0;ref_lock: 0;asn1_cb:dsa_cb;
     enc_offset: 0;asn1_const_cb: nil);

     DSAparams_aux: TASN1_AUX  = (
     app_data: nil; flags: 0; ref_offset: 0;ref_lock: 0;asn1_cb:dsa_cb;
     enc_offset: 0;asn1_const_cb: nil);

implementation

uses openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.dsa.dsa_lib, openssl3.crypto.asn1.x_int64,
     openssl3.crypto.asn1.x_bignum;



function d2i_DSAPublicKey(a : PPDSA;const _in : PPByte; len : long):PDSA;
begin
 Result := PDSA(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, DSAPublicKey_it));
end;

function DSAPrivateKey_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @DSAPrivateKey_seq_tt,
                       sizeof(DSAPrivateKey_seq_tt) div sizeof(TASN1_TEMPLATE),
                       @DSAPrivateKey_aux, sizeof(TDSA), 'DSA' );
   Result := @local_it;
end;

function d2i_DSAPrivateKey(a : PPDSA;const &in : PPByte; len : long):PDSA;
begin
 Result := PDSA (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, DSAPrivateKey_it));
end;


function d2i_DSAparams(a : PPDSA;const &in : PPByte; len : long):PDSA;
begin
  Result := PDSA(ASN1_item_d2i(PPASN1_VALUE(a), &in, len, DSAparams_it));
end;




function DSAparams_it:PASN1_ITEM;
var
 local_it: TASN1_ITEM ;
begin
    local_it := get_ASN1_ITEM($1, 16, @DSAparams_seq_tt,
       sizeof(DSAparams_seq_tt) div sizeof(TASN1_TEMPLATE), @DSAparams_aux,
       sizeof(TDSA), 'DSA');
    result := @local_it;
end;


function i2d_DSAparams(const a : Pointer; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE( a), _out, DSAparams_it);
end;


function DSAPublicKey_it:PASN1_ITEM;
var
  local_it: TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM ($1, 16, @DSAPublicKey_seq_tt,
             sizeof(DSAPublicKey_seq_tt) div sizeof(TASN1_TEMPLATE), @DSAPublicKey_aux,
             sizeof(TDSA), 'DSA');
   Result := @local_it;

end;


function i2d_DSAPublicKey(const a : Pointer; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE(a), _out, DSAPublicKey_it);
end;


function dsa_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
begin
    if operation = ASN1_OP_NEW_PRE then
    begin
        pval^ := PASN1_VALUE(DSA_new);
        if pval^ <> nil then Exit(2);
        Exit(0);
    end
    else
    if (operation = ASN1_OP_FREE_PRE) then
    begin
        DSA_free(PDSA(pval^));
        pval^ := nil;
        Exit(2);
    end;
    Result := 1;
end;

function i2d_DSAPrivateKey(const a : Pointer; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, DSAPrivateKey_it);
end;


initialization

    DSAPrivateKey_seq_tt[0] := get_ASN1_TEMPLATE( ($1 shl 12), 0, (size_t(@PDSA(0).version)), 'version', INT32_it );
    DSAPrivateKey_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.p)), 'params.p', BIGNUM_it );
    DSAPrivateKey_seq_tt[2] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.q)), 'params.q', BIGNUM_it );
    DSAPrivateKey_seq_tt[3] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.g)), 'params.g', BIGNUM_it );
    DSAPrivateKey_seq_tt[4] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).pub_key)), 'pub_key',   BIGNUM_it );
    DSAPrivateKey_seq_tt[5] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).priv_key)), 'priv_key', CBIGNUM_it );

    DSAPublicKey_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).pub_key)), 'pub_key',   BIGNUM_it );
    DSAPublicKey_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.p)), 'params.p', BIGNUM_it );
    DSAPublicKey_seq_tt[2] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.q)), 'params.q', BIGNUM_it );
    DSAPublicKey_seq_tt[3] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.g)), 'params.g', BIGNUM_it );

    DSAparams_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.p)), 'params.p', BIGNUM_it );
    DSAparams_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.q)), 'params.q', BIGNUM_it );
    DSAparams_seq_tt[2] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PDSA(0).params.g)), 'params.g', BIGNUM_it );


end.
