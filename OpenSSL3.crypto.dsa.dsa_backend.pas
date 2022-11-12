unit OpenSSL3.crypto.dsa.dsa_backend;

interface
uses OpenSSL.Api;

function ossl_dsa_dup(const dsa : PDSA; selection : integer):PDSA;
function dsa_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
function ossl_dsa_is_foreign(const dsa : PDSA):integer;
function ossl_dsa_key_fromdata(dsa : PDSA;const params : POSSL_PARAM):integer;
function ossl_dsa_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PDSA;

implementation
uses
   openssl3.crypto.dsa.dsa_lib, openssl3.crypto.ffc.ffc_params,
   openssl3.crypto.params, openssl3.crypto.bn.bn_lib,
   openssl3.crypto.asn1.a_int, OpenSSL3.Err,
   openssl3.crypto.asn1.asn1_lib,
   openssl3.crypto.bn.bn_exp, openssl3.crypto.bn.bn_ctx,
   openssl3.crypto.asn1.tasn_typ, openssl3.crypto.dsa.dsa_asn1,
   openssl3.crypto.asn1.p8_pkey,  openssl3.crypto.asn1.x_algor,
   openssl3.crypto.dsa.dsa_ossl, openssl3.crypto.ex_data;



function ossl_dsa_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PDSA;
var
  p,
  pm         : PByte;
  pklen,
  pmlen,
  ptype      : integer;
  dsa_p, dsa_g: PBIGNUM;
  pval       : Pointer;
  pstr       : PASN1_STRING;
  palg       : PX509_ALGOR;
  privkey    : PASN1_INTEGER;
  dsa_pubkey, dsa_privkey : PBIGNUM;
  ctx        : PBN_CTX;
  dsa        : PDSA;
  label _decerr, _dsaerr, _done;
begin
    privkey := nil;

    dsa_pubkey := nil; dsa_privkey := nil;
    ctx := nil;
    dsa := nil;
    if 0>=PKCS8_pkey_get0(nil, @p, @pklen, @palg, p8inf) then
        Exit(0);
    X509_ALGOR_get0(nil, @ptype, @pval, palg);
    privkey := d2i_ASN1_INTEGER(nil, @p, pklen);
    if privkey = nil then
        goto _decerr;
    if (privkey.&type = V_ASN1_NEG_INTEGER)  or  (ptype <> V_ASN1_SEQUENCE) then
       goto _decerr;
    pstr := pval;
    pm := pstr.data;
    pmlen := pstr.length;
    dsa := d2i_DSAparams(nil, @pm, pmlen);
    if dsa = nil then
        goto _decerr;
    { We have parameters now set private key }
    dsa_privkey := BN_secure_new;
    if (dsa_privkey =  nil )
         or  (nil =ASN1_INTEGER_to_BN(privkey, dsa_privkey)) then begin
        ERR_raise(ERR_LIB_DSA, DSA_R_BN_ERROR);
        goto _dsaerr;
    end;
    { Calculate public key }
    dsa_pubkey := BN_new();
    if dsa_pubkey =  nil then  begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        goto _dsaerr;
    end;
    ctx := BN_CTX_new();
    if ctx = nil then  begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        goto _dsaerr;
    end;
    dsa_p := DSA_get0_p(dsa);
    dsa_g := DSA_get0_g(dsa);
    BN_set_flags(dsa_privkey, BN_FLG_CONSTTIME);
    if 0>=BN_mod_exp(dsa_pubkey, dsa_g, dsa_privkey, dsa_p, ctx ) then begin
        ERR_raise(ERR_LIB_DSA, DSA_R_BN_ERROR);
        goto _dsaerr;
    end;
    DSA_set0_key(dsa, dsa_pubkey, dsa_privkey);
    goto _done;
 _decerr:
    ERR_raise(ERR_LIB_DSA, DSA_R_DECODE_ERROR);
 _dsaerr:
    BN_free(dsa_privkey);
    BN_free(dsa_pubkey);
    DSA_free(dsa);
    dsa := nil;
 _done:
    BN_CTX_free(ctx);
    ASN1_STRING_clear_free(privkey);
    Result := dsa;
end;



function ossl_dsa_key_fromdata(dsa : PDSA;const params : POSSL_PARAM):integer;
var
  param_priv_key,
  param_pub_key  : POSSL_PARAM;

  priv_key,
  pub_key        : PBIGNUM;
  label _err;
begin
    priv_key := nil;
    pub_key := nil;
    if dsa = nil then Exit(0);
    param_priv_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    { It's ok if neither half is present }
    if (param_priv_key = nil)  and  (param_pub_key = nil) then Exit(1);
    if (param_pub_key <> nil)  and
       (0>= OSSL_PARAM_get_BN(param_pub_key, @pub_key) )  then
        goto _err ;
    if (param_priv_key <> nil)  and
       (0>= OSSL_PARAM_get_BN(param_priv_key, @priv_key))   then
        goto _err ;
    if  0>= DSA_set0_key(dsa, pub_key, priv_key)  then
        goto _err ;
    Exit(1);
 _err:
    BN_clear_free(priv_key);
    BN_free(pub_key);
    Result := 0;
end;

function dsa_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
begin
   &out^ := BN_dup(f);
    if (f <> nil)  and  (&out = nil)   then
        Exit(0);
    Result := 1;
end;

function ossl_dsa_is_foreign(const dsa : PDSA):integer;
begin
{$IFNDEF FIPS_MODULE}
    if (dsa.engine <> nil)  or  (DSA_get_method(PDSA(dsa)) <> DSA_OpenSSL)    then
        Exit(1);
{$ENDIF}
    Result := 0;
end;



function ossl_dsa_dup(const dsa : PDSA; selection : integer):PDSA;
var
  dupkey : PDSA;
  label _err;
begin
    dupkey := nil;
    { Do not try to duplicate foreign DSA keys }
    if ossl_dsa_is_foreign(dsa )>0 then
        Exit(nil);
    dupkey := ossl_dsa_new(dsa.libctx ) ;
    if dupkey  = nil then
        Exit(nil);
    if ( (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0)
         and  (0>= ossl_ffc_params_copy(@dupkey.params, @dsa.params)) then
        goto _err ;
    dupkey.flags := dsa.flags;
    if ( (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 )
         and  ( ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) = 0)
             or  (0>= dsa_bn_dup_check(@dupkey.pub_key, dsa.pub_key)))  then
        goto _err ;
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 )
         and ( ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) = 0)
             or  (0>= dsa_bn_dup_check(@dupkey.priv_key, dsa.priv_key))) then
        goto _err ;
{$IFNDEF FIPS_MODULE}
    if 0>= CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DSA,
                            @dupkey.ex_data, @dsa.ex_data ) then
        goto _err ;
{$ENDIF}
    Exit(dupkey);
 _err:
    DSA_free(dupkey);
    Result := nil;
end;


end.
