unit OpenSSL3.crypto.dsa_check;

interface
uses OpenSSL.Api;

function ossl_dsa_check_params(const dsa : PDSA; checktype : integer; ret : PInteger):integer;
function ossl_dsa_check_pub_key(const dsa : PDSA; pub_key : PBIGNUM; ret : PInteger):integer;
function ossl_dsa_check_priv_key(const dsa : PDSA; priv_key : PBIGNUM; ret : PInteger):integer;
function ossl_dsa_check_pairwise(const dsa : PDSA):integer;

implementation
uses
   openssl3.crypto.dsa.dsa_lib, openssl3.crypto.ffc.ffc_params,
   openssl3.crypto.params, openssl3.crypto.bn.bn_lib,
   openssl3.crypto.ffc.ffc_params_validate, openssl3.crypto.ffc.ffc_key_validate,
   openssl3.crypto.bn.bn_ctx, openssl3.crypto.dsa.dsa_key;






function ossl_dsa_check_pairwise(const dsa : PDSA):integer;
var
  ret : integer;

  ctx : PBN_CTX;

  pub_key : PBIGNUM;
  label _err;
begin
    ret := 0;
    ctx := nil;
    pub_key := nil;
    if (dsa.params.p = nil)
         or  (dsa.params.g = nil)
         or  (dsa.priv_key = nil)
         or  (dsa.pub_key = nil) then Exit(0);
    ctx := BN_CTX_new_ex(dsa.libctx);
    if ctx = nil then goto _err ;
    pub_key := BN_new();
    if pub_key = nil then goto _err ;
    { recalculate the public key = (g ^ priv) mod p }
    if  0>= ossl_dsa_generate_public_key(ctx, dsa, dsa.priv_key, pub_key )then
        goto _err ;
    { check it matches the existing pubic_key }
    ret := Int(BN_cmp(pub_key, dsa.pub_key) = 0);
_err:
    BN_free(pub_key);
    BN_CTX_free(ctx);
    Result := ret;
end;

function ossl_dsa_check_priv_key(const dsa : PDSA; priv_key : PBIGNUM; ret : PInteger):integer;
begin
    ret^ := 0;
    Result := int( (dsa.params.q <> nil) and
              (ossl_ffc_validate_private_key(dsa.params.q, priv_key, ret)>0));
end;

function ossl_dsa_check_pub_key(const dsa : PDSA; pub_key : PBIGNUM; ret : PInteger):integer;
begin
    Result := ossl_ffc_validate_public_key(@dsa.params, pub_key, ret);
end;




function ossl_dsa_check_params(const dsa : PDSA; checktype : integer; ret : PInteger):integer;
begin
    if checktype = OSSL_KEYMGMT_VALIDATE_QUICK_CHECK then
       Exit(ossl_ffc_params_simple_validate(dsa.libctx, @dsa.params,
                                               FFC_PARAM_TYPE_DSA, ret))
    else
        {
         * Do full FFC domain params validation according to FIPS-186-4
         *  - always in FIPS_MODULE
         *  - only if possible (i.e., seed is set) in default provider
         }
        Exit(ossl_ffc_params_full_validate(dsa.libctx, @dsa.params,
                                             FFC_PARAM_TYPE_DSA, ret));
end;


end.
