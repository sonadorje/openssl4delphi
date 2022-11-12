unit OpenSSL3.crypto.dsa_backend;

interface
uses OpenSSL.Api;

function ossl_dsa_dup(const dsa : PDSA; selection : integer):PDSA;
function dsa_bn_dup_check(&out : PPBIGNUM;const f : PBIGNUM):integer;
function ossl_dsa_is_foreign(const dsa : PDSA):integer;
function ossl_dsa_key_fromdata(dsa : PDSA;const params : POSSL_PARAM):integer;

implementation
uses
   openssl3.crypto.dsa.dsa_lib, openssl3.crypto.ffc.ffc_params,
   openssl3.crypto.params, openssl3.crypto.bn.bn_lib,
   openssl3.crypto.dsa.dsa_ossl, openssl3.crypto.ex_data;





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
