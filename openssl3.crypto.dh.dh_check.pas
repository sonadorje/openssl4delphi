unit openssl3.crypto.dh.dh_check;

interface
uses OpenSSL.Api;

function ossl_dh_check_pub_key_partial(const dh : PDH; pub_key : PBIGNUM; ret : PInteger):integer;
function ossl_dh_check_priv_key(const dh : PDH; priv_key : PBIGNUM; ret : PInteger):integer;
function ossl_dh_check_pairwise(const dh : PDH):integer;
function DH_check_ex(const dh : PDH):integer;
function DH_check(const dh : PDH; ret : PInteger):integer;
function DH_check_params(const dh : PDH; ret : PInteger):integer;
function DH_check_pub_key_ex(const dh : PDH; pub_key : PBIGNUM):integer;
function DH_check_pub_key(const dh : PDH; pub_key : PBIGNUM; ret : PInteger):integer;
function DH_check_params_ex(const dh : PDH):integer;

implementation

uses openssl3.crypto.ffc.ffc_dh, openssl3.crypto.ffc.ffc_key_validate,
     openssl3.crypto.dh.dh_group_params, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.dh.dh_key,
     openssl3.crypto.bn.bn_exp, openssl3.crypto.bn.bn_prime,
     openssl3.crypto.bn.bn_div, OpenSSL3.Err,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_word;


function DH_check_params_ex(const dh : PDH):integer;
var
  errflags : integer;
begin
    errflags := 0;
    if 0>=DH_check_params(dh, @errflags) then
        Exit(0);
    if errflags and DH_CHECK_P_NOT_PRIME  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_P_NOT_PRIME);
    if errflags and DH_NOT_SUITABLE_GENERATOR <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_NOT_SUITABLE_GENERATOR);
    if errflags and DH_MODULUS_TOO_SMALL  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
    if errflags and DH_MODULUS_TOO_LARGE  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
    Result := Int(errflags = 0);
end;


function DH_check_pub_key(const dh : PDH; pub_key : PBIGNUM; ret : PInteger):integer;
begin
    Result := ossl_ffc_validate_public_key(@dh.params, pub_key, ret);
end;



function DH_check_pub_key_ex(const dh : PDH; pub_key : PBIGNUM):integer;
var
  errflags : integer;
begin
    errflags := 0;
    if 0>=DH_check_pub_key(dh, pub_key, @errflags) then
        Exit(0);
    if errflags and DH_CHECK_PUBKEY_TOO_SMALL  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_PUBKEY_TOO_SMALL);
    if errflags and DH_CHECK_PUBKEY_TOO_LARGE  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_PUBKEY_TOO_LARGE);
    if errflags and DH_CHECK_PUBKEY_INVALID  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_PUBKEY_INVALID);
    Result := 0; errflags := 0;
end;




function DH_check_params(const dh : PDH; ret : PInteger):integer;
var
  ok : integer;
  tmp : PBIGNUM;
  ctx : PBN_CTX;
  label _err;
begin
    ok := 0;
    tmp := nil;
    ctx := nil;
    ret^ := 0;
    ctx := BN_CTX_new;
    if ctx = nil then goto _err;
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    if tmp = nil then goto _err;
    if not BN_is_odd(dh.params.p) then
        ret^  := ret^  or DH_CHECK_P_NOT_PRIME;
    if (BN_is_negative(dh.params.g)>0)  or  (BN_is_zero(dh.params.g))
         or  (BN_is_one(dh.params.g)) then
        ret^  := ret^  or DH_NOT_SUITABLE_GENERATOR;
    if (BN_copy(tmp, dh.params.p) = nil)  or  (0>=BN_sub_word(tmp, 1))  then
        goto _err;
    if BN_cmp(dh.params.g, tmp ) >= 0  then
       ret^  := ret^  or DH_NOT_SUITABLE_GENERATOR;
    if BN_num_bits(dh.params.p) < DH_MIN_MODULUS_BITS  then
       ret^  := ret^  or DH_MODULUS_TOO_SMALL;
    if BN_num_bits(dh.params.p ) > OPENSSL_DH_MAX_MODULUS_BITS then
        ret^  := ret^  or DH_MODULUS_TOO_LARGE;
    ok := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ok;
end;



function DH_check(const dh : PDH; ret : PInteger):integer;
var
  ok, r : integer;
  ctx : PBN_CTX;
  t1, t2 : PBIGNUM;
  nid : integer;
  label _err;
begin
{$IFDEF FIPS_MODULE}
    Exit(DH_check_params(dh, ret));
{$ELSE} ok := 0;
    ctx := nil;
    t1 := nil; t2 := nil;
    nid := DH_get_nid(PDH(dh));
    ret^ := 0;
    if nid <> NID_undef then Exit(1);
    if 0>=DH_check_params(dh, ret) then
        Exit(0);
    ctx := BN_CTX_new;
    if ctx = nil then goto _err;
    BN_CTX_start(ctx);
    t1 := BN_CTX_get(ctx);
    t2 := BN_CTX_get(ctx);
    if t2 = nil then goto _err;
    if dh.params.q <> nil then
    begin
        if BN_cmp(dh.params.g, BN_value_one) <= 0 then
            ret^  := ret^  or DH_NOT_SUITABLE_GENERATOR
        else
        if BN_cmp(dh.params.g, dh.params.p) >= 0 then
            ret^  := ret^  or DH_NOT_SUITABLE_GENERATOR
        else
        begin
            { Check g^q = 1 mod p }
            if 0>=BN_mod_exp(t1, dh.params.g, dh.params.q, dh.params.p, ctx) then
                goto _err;
            if not BN_is_one(t1) then
                ret^  := ret^  or DH_NOT_SUITABLE_GENERATOR;
        end;
        r := BN_check_prime(dh.params.q, ctx, nil);
        if r < 0 then goto _err;
        if 0>=r then
           ret^  := ret^  or DH_CHECK_Q_NOT_PRIME;
        { Check p = 1 mod q  i.e. q divides p - 1 }
        if 0>=BN_div(t1, t2, dh.params.p, dh.params.q, ctx) then
            goto _err;
        if not BN_is_one(t2) then
            ret^  := ret^  or DH_CHECK_INVALID_Q_VALUE;
        if (dh.params.j <> nil)
             and  (BN_cmp(dh.params.j, t1) > 0) then
            ret^  := ret^  or DH_CHECK_INVALID_J_VALUE;
    end;
    r := BN_check_prime(dh.params.p, ctx, nil);
    if r < 0 then goto _err;
    if 0>=r then
       ret^  := ret^  or DH_CHECK_P_NOT_PRIME
    else
    if (dh.params.q = nil) then
    begin
        if 0>=BN_rshift1(t1, dh.params.p) then
            goto _err;
        r := BN_check_prime(t1, ctx, nil);
        if r < 0 then goto _err;
        if 0>=r then
           ret^  := ret^  or DH_CHECK_P_NOT_SAFE_PRIME;
    end;
    ok := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Exit(ok);
{$endif} { FIPS_MODULE }
end;




function DH_check_ex(const dh : PDH):integer;
var
  errflags : integer;
begin
    errflags := 0;
    if 0>=DH_check(dh, @errflags )then
        Exit(0);
    if errflags and DH_NOT_SUITABLE_GENERATOR  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_NOT_SUITABLE_GENERATOR);
    if errflags and DH_CHECK_Q_NOT_PRIME  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_Q_NOT_PRIME);
    if errflags and DH_CHECK_INVALID_Q_VALUE  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_INVALID_Q_VALUE);
    if errflags and DH_CHECK_INVALID_J_VALUE  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_INVALID_J_VALUE);
    if errflags and DH_UNABLE_TO_CHECK_GENERATOR  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_UNABLE_TO_CHECK_GENERATOR);
    if errflags and DH_CHECK_P_NOT_PRIME  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_P_NOT_PRIME);
    if errflags and DH_CHECK_P_NOT_SAFE_PRIME  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_CHECK_P_NOT_SAFE_PRIME);
    if errflags and DH_MODULUS_TOO_SMALL  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
    if errflags and DH_MODULUS_TOO_LARGE  <> 0 then
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
    Result := 0; errflags := 0;
end;

function ossl_dh_check_pairwise(const dh : PDH):integer;
var
  ret : integer;

  ctx : PBN_CTX;

  pub_key : PBIGNUM;
  label _err;
begin
    ret := 0;
    ctx := nil;
    pub_key := nil;
    if (dh.params.p = nil)
         or  (dh.params.g = nil)
         or  (dh.priv_key = nil)
         or  (dh.pub_key = nil) then Exit(0);
    ctx := BN_CTX_new_ex(dh.libctx);
    if ctx = nil then goto _err ;
    pub_key := BN_new();
    if pub_key = nil then goto _err ;
    { recalculate the public key = (g ^ priv) mod p }
    if  0>= ossl_dh_generate_public_key(ctx, dh, dh.priv_key, pub_key ) then
        goto _err ;
    { check it matches the existing pubic_key }
    ret := Int(BN_cmp(pub_key, dh.pub_key) = 0);
_err:
    BN_free(pub_key);
    BN_CTX_free(ctx);
    Result := ret;
end;

function ossl_dh_check_priv_key(const dh : PDH; priv_key : PBIGNUM; ret : PInteger):integer;
var
    ok       : int;
    two_powN,upper : PBIGNUM;
    label _err;
begin
    ok := (0);
    two_powN := nil;
    ret^ := 0;
    two_powN := BN_new();
    if two_powN = nil then Exit(0);
    if dh.params.q = nil then goto _err ;
    upper := dh.params.q;
    { Is it from an approved Safe prime group ?}
    if (DH_get_nid(PDH(dh)) <> NID_undef )  and ( dh.length <> 0)    then
    begin
        if  0>= BN_lshift(two_powN, BN_value_one, dh.length) then
            goto _err ;
        if BN_cmp(two_powN, dh.params.q) < 0  then
            upper := two_powN;
    end;
    if  0>= ossl_ffc_validate_private_key(upper, priv_key, ret)  then
        goto _err ;
    ok := 1;
_err:
    BN_free(two_powN);
    Result := ok;
end;

function ossl_dh_check_pub_key_partial(const dh : PDH; pub_key : PBIGNUM; ret : PInteger):integer;
begin
    Result := ossl_ffc_validate_public_key_partial(@dh.params, pub_key, ret);
end;

end.
