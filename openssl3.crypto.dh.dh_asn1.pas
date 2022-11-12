unit openssl3.crypto.dh.dh_asn1;

interface
uses OpenSSL.Api;

type
  int_dhvparams = record
    seed : PASN1_BIT_STRING;
    counter : PBIGNUM;
  end;
  Pint_dhvparams = ^int_dhvparams;

  int_dhx942_dh = record
    p, q, g, j : PBIGNUM;
    vparams : Pint_dhvparams;
  end;
  Pint_dhx942_dh = ^int_dhx942_dh;
  PPint_dhx942_dh = ^Pint_dhx942_dh;

function d2i_DHxparams(a : PPDH;const pp : PPByte; length : long):PDH;
function i2d_DHxparams(const dh : PDH; pp : PPByte):integer;
function d2i_int_dhx(a : PPint_dhx942_dh;const &in : PPByte; len : long):Pint_dhx942_dh;
function i2d_int_dhx(const a : Pint_dhx942_dh; _out : PPByte):integer;
function DHxparams_it:PASN1_ITEM;
function DHvparams_it:PASN1_ITEM;
function d2i_DHparams(a : PPDH;const &in : PPByte; len : long):PDH;
function i2d_DHparams(const a : PDH; _out : PPByte):integer;
function dh_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
function DHparams_it:PASN1_ITEM;

var
  DHxparams_seq_tt, DHvparams_seq_tt, DHparams_seq_tt : array of TASN1_TEMPLATE;
  DHparams_aux :TASN1_AUX;

implementation

uses openssl3.crypto.dh.dh_lib, openssl3.crypto.dh.dh_group_params,
     openssl3.crypto.ffc.ffc_params, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.asn1.tasn_typ,  openssl3.crypto.mem,
     openssl3.crypto.asn1.x_bignum,  openssl3.crypto.asn1.x_int64,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc;





function DHparams_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @DHparams_seq_tt,
          sizeof(DHparams_seq_tt) div sizeof(TASN1_TEMPLATE),
           @DHparams_aux, sizeof(TDH), 'DHparams');
   Result := @local_it;
end;

function d2i_DHparams(a : PPDH;const &in : PPByte; len : long):PDH;
begin
   Result := PDH (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, DHparams_it));
end;


function i2d_DHparams(const a : PDH; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, DHparams_it);
end;

function DHvparams_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @DHvparams_seq_tt,
          sizeof(DHvparams_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
          sizeof(int_dhvparams), 'int_dhvparams');
   Result := @local_it;
end;



function DHxparams_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @DHxparams_seq_tt,
                   sizeof(DHxparams_seq_tt) div sizeof(TASN1_TEMPLATE),
                   Pointer(0) , sizeof(int_dhx942_dh), 'int_dhx942_dh');
   Result := @local_it;
end;




function d2i_int_dhx(a : PPint_dhx942_dh;const &in : PPByte; len : long):Pint_dhx942_dh;
begin
 Result := Pint_dhx942_dh (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, DHxparams_it));
end;


function i2d_int_dhx(const a : Pint_dhx942_dh; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE(a), _out, DHxparams_it);
end;

function dh_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  dh : PDH;
begin
    if operation = ASN1_OP_NEW_PRE then
    begin
        pval^ := PASN1_VALUE(DH_new);
        if pval^ <> nil then Exit(2);
        Exit(0);
    end
    else if (operation = ASN1_OP_FREE_PRE) then
    begin
        DH_free(PDH(pval^));
        pval^ := nil;
        Exit(2);
    end
    else
    if (operation = ASN1_OP_D2I_POST) then
    begin
        dh := PDH(pval^);
        DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
        DH_set_flags(dh, DH_FLAG_TYPE_DH);
        ossl_dh_cache_named_group(dh);
        Inc(dh.dirty_cnt);
    end;
    Result := 1;
end;



function d2i_DHxparams(a : PPDH;const pp : PPByte; length : long):PDH;
var
  params : PFFC_PARAMS;
  dhx : Pint_dhx942_dh;
  dh : PDH;
  counter : size_t;
begin
    dhx := nil;
    dh := nil;
    dh := DH_new;
    if dh = nil then Exit(nil);
    dhx := d2i_int_dhx(nil, pp, length);
    if dhx = nil then begin
        DH_free(dh);
        Exit(nil);
    end;
    if a <> nil then begin
        DH_free( a^);
        a^ := dh;
    end;
    params := @dh.params;
    DH_set0_pqg(dh, dhx.p, dhx.q, dhx.g);
    ossl_ffc_params_set0_j(params, dhx.j);
    if dhx.vparams <> nil then
    begin
        { The counter has a maximum value of 4 * numbits(p) - 1 }
        counter := size_t(BN_get_word(dhx.vparams.counter));
        ossl_ffc_params_set_validate_params(params, dhx.vparams.seed.data,
                                            dhx.vparams.seed.length,
                                            counter);
        ASN1_BIT_STRING_free(dhx.vparams.seed);
        BN_free(dhx.vparams.counter);
        OPENSSL_free(Pointer(dhx.vparams));
        dhx.vparams := nil;
    end;
    OPENSSL_free(Pointer(dhx));
    DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
    DH_set_flags(dh, DH_FLAG_TYPE_DHX);
    Result := dh;
end;


function i2d_DHxparams(const dh : PDH; pp : PPByte):integer;
var
  ret : integer;
  dhx : int_dhx942_dh;
  dhv : int_dhvparams;
  seed : TASN1_BIT_STRING;
  seedlen : size_t;
  params : PFFC_PARAMS;
  counter : integer;
  label _err;
begin
    ret := 0;
    dhv := default(int_dhvparams);

    seedlen := 0;
     params := @dh.params;
    ossl_ffc_params_get0_pqg(params, PPBIGNUM (@dhx.p),
                             PPBIGNUM (@dhx.q), PPBIGNUM(@dhx.g));
    dhx.j := params.j;
    ossl_ffc_params_get_validate_params(params, @seed.data, @seedlen, @counter);
    seed.length := int(seedlen);
    if (counter <> -1)  and  (seed.data <> nil)  and  (seed.length > 0) then
    begin
        seed.flags := ASN1_STRING_FLAG_BITS_LEFT;
        dhv.seed := @seed;
        dhv.counter := BN_new;
        if dhv.counter = nil then Exit(0);
        if 0>=BN_set_word(dhv.counter, BN_ULONG(counter)) then
            goto _err;
        dhx.vparams := @dhv;
    end
    else
    begin
        dhx.vparams := nil;
    end;
    ret := i2d_int_dhx(@dhx, pp);
_err:
    BN_free(dhv.counter);
    Result := ret;
end;

initialization
  DHxparams_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pint_dhx942_dh(0).p), 'p', BIGNUM_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pint_dhx942_dh(0).g), 'g', BIGNUM_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pint_dhx942_dh(0).q), 'q', BIGNUM_it) ,
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@Pint_dhx942_dh(0).j), 'j', BIGNUM_it) ,
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@Pint_dhx942_dh(0).vparams), 'vparams', DHvparams_it)
 ] ;

  DHvparams_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pint_dhvparams(0).seed), 'seed', ASN1_BIT_STRING_it) ,
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pint_dhvparams(0).counter), 'counter', BIGNUM_it)
] ;

 DHparams_seq_tt := [
        get_ASN1_TEMPLATE ( 0, 0, size_t(@PDH(0).params.p), 'params.p', BIGNUM_it) ,
        get_ASN1_TEMPLATE ( 0, 0, size_t(@PDH(0).params.g), 'params.g', BIGNUM_it) ,
        get_ASN1_TEMPLATE ( (($1) or ($1 shl 12)), 0, size_t(@PDH(0).length), 'length', ZINT32_it)
] ;

DHparams_aux := get_ASN1_AUX (Pointer(0) , 0, 0, 0, dh_cb, 0, Pointer(0) );

end.
