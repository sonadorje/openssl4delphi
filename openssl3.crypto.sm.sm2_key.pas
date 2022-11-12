unit openssl3.crypto.sm.sm2_key;

interface
uses OpenSSL.Api;

function ossl_sm2_key_private_check(const eckey : PEC_KEY):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_word, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.ec.ec_key, openssl3.crypto.ec.ec_lib;

function ossl_sm2_key_private_check(const eckey : PEC_KEY):integer;
var
    ret      : integer;

    max      : PBIGNUM;

    group    : PEC_GROUP;

  priv_key,
  order    : PBIGNUM;
  label _end;
begin
    ret := 0;
    max := nil;
     group := nil;
     priv_key := nil;
    order := nil;
    group := EC_KEY_get0_group(eckey);
    priv_key := EC_KEY_get0_private_key(eckey);
    order := EC_GROUP_get0_order(group);
    if (eckey = nil)
             or  (group = nil)
             or  (priv_key = nil)
             or  (order = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { range of SM2 private key is [1, n-1) }
    max := BN_dup(order);
    if (max = nil)  or  (0>= BN_sub_word(max, 1))  then
        goto _end ;
    if (BN_cmp(priv_key, BN_value_one) < 0)
         or  (BN_cmp(priv_key, max) >= 0) then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY);
        goto _end ;
    end;
    ret := 1;
 _end:
    BN_free(max);
    Result := ret;
end;


end.
