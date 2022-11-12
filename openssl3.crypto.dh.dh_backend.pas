unit openssl3.crypto.dh.dh_backend;

interface
uses OpenSSL.Api;

function ossl_dh_dup(const dh : PDH; selection : integer):PDH;
function ossl_dh_is_foreign(const dh : PDH):integer;
function dh_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
 function ossl_dh_params_todata( dh : PDH; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
function ossl_dh_key_todata( dh : PDH; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
function ossl_dh_params_fromdata(dh : PDH;const params : POSSL_PARAM):integer;
function dh_ffc_params_fromdata(dh : PDH;const params : POSSL_PARAM):integer;
function ossl_dh_key_fromdata(dh : PDH;const params : POSSL_PARAM):integer;
function ossl_dh_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PDH;

implementation

uses
  OpenSSL3.common,  openssl3.err,  openssl3.crypto.dh.dh_lib,
  openssl3.crypto.ffc.ffc_params,  openssl3.crypto.param_build_set,
  openssl3.crypto.dh.dh_key,       openssl3.crypto.ex_data,
  openssl3.crypto.asn1.p8_pkey,    openssl3.crypto.asn1.x_algor,
  openssl3.crypto.asn1.tasn_typ,   openssl3.crypto.objects.obj_dat,
  openssl3.crypto.dh.dh_asn1,      openssl3.crypto.asn1.a_int,
  openssl3.crypto.asn1.asn1_lib,   openssl3.crypto.dh.dh_group_params,
  openssl3.crypto.ffc.ffc_backend, openssl3.crypto.params,
  openssl3.crypto.bn.bn_lib;



function ossl_dh_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PDH;
var
  p, pm      : PByte;
  pklen,
  pmlen,
  ptype      : integer;
  pval       : Pointer;
  pstr       : PASN1_STRING;
  palg       : PX509_ALGOR;
  privkey_bn : PBIGNUM;
  privkey    : PASN1_INTEGER;
  dh         : PDH;
  label _decerr, _dherr, _done;
begin
    privkey_bn := nil;
    privkey := nil;
    dh := nil;
    if 0>=PKCS8_pkey_get0(nil, @p, @pklen, @palg, p8inf) then
        Exit(0);
    X509_ALGOR_get0(nil, @ptype, @pval, palg);
    if ptype <> V_ASN1_SEQUENCE then
       goto _decerr;
    privkey := d2i_ASN1_INTEGER(nil, @p, pklen);
    if privkey = nil then
        goto _decerr;
    pstr := pval;
    pm := pstr.data;
    pmlen := pstr.length;
    case (OBJ_obj2nid(palg.algorithm)) of
      NID_dhKeyAgreement:
          dh := d2i_DHparams(nil, @pm, pmlen);
      NID_dhpublicnumber:
          dh := d2i_DHxparams(nil, @pm, pmlen);
    else
        goto _decerr;
    end;
    if dh = nil then goto _decerr;
    { We have parameters now set private key }
    privkey_bn := BN_secure_new;
    if (privkey_bn =  nil) or  (nil =ASN1_INTEGER_to_BN(privkey, privkey_bn)) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_BN_ERROR);
        BN_clear_free(privkey_bn);
        goto _dherr;
    end;
    if 0>=DH_set0_key(dh, nil, privkey_bn ) then
        goto _dherr;
    { Calculate public key, increments dirty_cnt }
    if 0>=DH_generate_key(dh ) then
        goto _dherr;
    goto _done;

 _decerr:
    ERR_raise(ERR_LIB_DH, EVP_R_DECODE_ERROR);
 _dherr:
    DH_free(dh);
    dh := nil;
 _done:
    ASN1_STRING_clear_free(privkey);
    Result := dh;
end;


function ossl_dh_key_fromdata(dh : PDH;const params : POSSL_PARAM):integer;
var
  param_priv_key,
  param_pub_key  : POSSL_PARAM;
  priv_key,
  pub_key        : PBIGNUM;
  label _err;
begin
    priv_key := nil;
    pub_key := nil;
    if dh = nil then Exit(0);
    param_priv_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if ( (param_priv_key <> nil)
          and   (0>= OSSL_PARAM_get_BN(param_priv_key, @priv_key )) )
         or  ( (param_pub_key <> nil)
             and   (0>= OSSL_PARAM_get_BN(param_pub_key, @pub_key)) ) then
        goto _err ;
    if  0>= DH_set0_key(dh, pub_key, priv_key)  then
        goto _err ;
    Exit(1);
 _err:
    BN_clear_free(priv_key);
    BN_free(pub_key);
    Result := 0;
end;

function dh_ffc_params_fromdata(dh : PDH;const params : POSSL_PARAM):integer;
var
  ret : integer;
  ffc : PFFC_PARAMS;
begin
    if dh = nil then Exit(0);
    ffc := ossl_dh_get0_params(dh);
    if ffc = nil then Exit(0);
    ret := ossl_ffc_params_fromdata(ffc, params);
    if ret>0 then
       ossl_dh_cache_named_group(dh); { This increments dh.dirty_cnt }
    Result := ret;
end;

function ossl_dh_params_fromdata(dh : PDH;const params : POSSL_PARAM):integer;
var
    param_priv_len : POSSL_PARAM;
    priv_len       : long;
begin
    if  0>= dh_ffc_params_fromdata(dh, params)  then
        Exit(0);
    param_priv_len := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
    if (param_priv_len <> nil)
         and  ( (0>= OSSL_PARAM_get_long(param_priv_len, @priv_len) ) or
                (0>= DH_set_length(dh, priv_len)) )  then
        Exit(0);
    Result := 1;
end;




function ossl_dh_key_todata( dh : PDH; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
  priv, pub : PBIGNUM;
begin
    priv := nil;
    pub := nil;
    if dh = nil then Exit(0);
    DH_get0_key(dh, @pub, @priv);
    if (priv <> nil)
         and   (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv) ) then
        Exit(0);
    if (pub <> nil)
         and   (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub )) then
        Exit(0);
    Result := 1;
end;




function ossl_dh_params_todata( dh : PDH; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
  l : long;
begin
    l := DH_get_length(dh);
    if  0>= ossl_ffc_params_todata(ossl_dh_get0_params(dh) , bld, params) then
        Exit(0);
    if (l > 0)
         and   (0>= ossl_param_build_set_long(bld, params, OSSL_PKEY_PARAM_DH_PRIV_LEN, l)) then
        Exit(0);
    Result := 1;
end;

function dh_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
begin
    &out^ := BN_dup(f);
    if (f <> nil)  and  (&out = nil)  then
        Exit(0);
    Result := 1;
end;



function ossl_dh_is_foreign(const dh : PDH):integer;
begin
{$IFNDEF FIPS_MODULE}
    if (dh.engine <> nil)  or  (ossl_dh_get_method(dh) <> DH_OpenSSL()) then
        Exit(1);
{$ENDIF}
    Result := 0;
end;


function ossl_dh_dup(const dh : PDH; selection : integer):PDH;
var
  dupkey : PDH;
  label _err;
begin
    dupkey := nil;
    { Do not try to duplicate foreign DH keys }
    if ossl_dh_is_foreign(dh )>0 then
        Exit(nil);
     dupkey := ossl_dh_new_ex(dh.libctx ) ;
    if dupkey = nil then
        Exit(nil);
    dupkey.length := DH_get_length(dh);
    if ( (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0 )
         and  (0>= ossl_ffc_params_copy(@dupkey.params, @dh.params))  then
        goto _err ;
    dupkey.flags := dh.flags;
    if ( (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 )
         and  ( ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) = 0 )
             or (0>= dh_bn_dup_check(@dupkey.pub_key, dh.pub_key)))  then
        goto _err ;
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY)  <> 0 )
         and  ( ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) = 0 )
             or (0>= dh_bn_dup_check(@dupkey.priv_key, dh.priv_key))) then
        goto _err ;
{$IFNDEF FIPS_MODULE}
    if 0>= CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DH,
                            @dupkey.ex_data, @dh.ex_data ) then
        goto _err ;
{$ENDIF}
    Exit(dupkey);
 _err:
    DH_free(dupkey);
    Result := nil;
end;


end.
