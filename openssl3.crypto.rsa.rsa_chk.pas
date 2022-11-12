unit openssl3.crypto.rsa.rsa_chk;

interface
uses OpenSSL.Api, openssl3.crypto.rsa.rsa_sp800_56b_check;

function ossl_rsa_validate_private(const key : PRSA):Integer;
 function ossl_rsa_validate_pairwise(const key : PRSA):integer;
function ossl_rsa_validate_public(const key : PRSA):integer;

function RSA_check_key_ex(const key : PRSA; cb : PBN_GENCB):integer;

 function rsa_validate_keypair_multiprime(const key : PRSA; cb : PBN_GENCB):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.rsa.rsa_local, OpenSSL3.crypto.rsa_mp,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_add, openssl3.crypto.bn.bn_gcd,
     openssl3.crypto.bn.bn_div, openssl3.crypto.bn.bn_mod,
     openssl3.crypto.bn.bn_prime, openssl3.crypto.bn.bn_mul;

function rsa_validate_keypair_multiprime(const key : PRSA; cb : PBN_GENCB):integer;
var
  i, j, k, l, m : PBIGNUM;
  ctx : PBN_CTX;
  ret, ex_primes, idx : integer;
  pinfo : PRSA_PRIME_INFO;
  label _err;
begin
    ret := 1; ex_primes := 0;
    if (key.p = nil)  or  (key.q = nil)  or  (key.n = nil)
             or  (key.e = nil)  or  (key.d = nil) then begin
        ERR_raise(ERR_LIB_RSA, RSA_R_VALUE_MISSING);
        Exit(0);
    end;
    { multi-prime? }
    if key.version = RSA_ASN1_VERSION_MULTI then
    begin
        ex_primes := sk_RSA_PRIME_INFO_num(key.prime_infos);
        if (ex_primes <= 0)
                 or  (ex_primes + 2  > ossl_rsa_multip_cap(BN_num_bits(key.n))) then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MULTI_PRIME_KEY);
            Exit(0);
        end;
    end;
    i := BN_new;
    j := BN_new;
    k := BN_new;
    l := BN_new;
    m := BN_new;
    ctx := BN_CTX_new_ex(key.libctx);
    if (i = nil)  or  (j = nil)  or  (k = nil)  or  (l = nil)
             or  (m = nil)  or  (ctx = nil) then
    begin
        ret := -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if BN_is_one(key.e) then  begin
        ret := 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
    end;
    if not BN_is_odd(key.e ) then  begin
        ret := 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
    end;
    { p prime? }
    if BN_check_prime(key.p, ctx, cb ) <> 1 then begin
        ret := 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_P_NOT_PRIME);
    end;
    { q prime? }
    if BN_check_prime(key.q, ctx, cb ) <> 1 then begin
        ret := 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_Q_NOT_PRIME);
    end;
    { r_i prime? }
    for idx := 0 to ex_primes-1 do begin
        pinfo := sk_RSA_PRIME_INFO_value(key.prime_infos, idx);
        if BN_check_prime(pinfo.r, ctx, cb) <> 1  then begin
            ret := 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_MP_R_NOT_PRIME);
        end;
    end;
    { n = p*q * r_3...r_i? }
    if 0>=BN_mul(i, key.p, key.q, ctx) then  begin
        ret := -1;
        goto _err;
    end;
    for idx := 0 to ex_primes-1 do begin
        pinfo := sk_RSA_PRIME_INFO_value(key.prime_infos, idx);
        if 0>=BN_mul(i, i, pinfo.r, ctx ) then  begin
            ret := -1;
            goto _err;
        end;
    end;
    if BN_cmp(i, key.n) <> 0  then begin
        ret := 0;
        if ex_primes>0 then
           ERR_raise(ERR_LIB_RSA, RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES)
        else
            ERR_raise(ERR_LIB_RSA, RSA_R_N_DOES_NOT_EQUAL_P_Q);
    end;
    { d*e = 1  mod \lambda(n)? }
    if 0>=BN_sub(i, key.p, BN_value_one) then  begin
        ret := -1;
        goto _err;
    end;
    if 0>=BN_sub(j, key.q, BN_value_one) then  begin
        ret := -1;
        goto _err;
    end;
    { now compute k = \lambda(n) = LCM(i, j, r_3 - 1...) }
    if 0>=BN_mul(l, i, j, ctx) then  begin
        ret := -1;
        goto _err;
    end;
    if 0>=BN_gcd(m, i, j, ctx) then  begin
        ret := -1;
        goto _err;
    end;
    for idx := 0 to ex_primes-1 do begin
        pinfo := sk_RSA_PRIME_INFO_value(key.prime_infos, idx);
        if 0>=BN_sub(k, pinfo.r, BN_value_one) then  begin
            ret := -1;
            goto _err;
        end;
        if 0>=BN_mul(l, l, k, ctx) then  begin
            ret := -1;
            goto _err;
        end;
        if 0>=BN_gcd(m, m, k, ctx) then  begin
            ret := -1;
            goto _err;
        end;
    end;
    if 0>=BN_div(k, nil, l, m, ctx) then  begin  { remainder is 0 }
        ret := -1;
        goto _err;
    end;
    if 0>=BN_mod_mul(i, key.d, key.e, k, ctx) then  begin
        ret := -1;
        goto _err;
    end;
    if not BN_is_one(i) then  begin
        ret := 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_D_E_NOT_CONGRUENT_TO_1);
    end;
    if (key.dmp1 <> nil)  and  (key.dmq1 <> nil)  and  (key.iqmp <> nil) then begin
        { dmp1 = d mod (p-1)? }
        if 0>=BN_sub(i, key.p, BN_value_one) then  begin
            ret := -1;
            goto _err;
        end;
        if 0>=BN_mod(j, key.d, i, ctx) then  begin
            ret := -1;
            goto _err;
        end;
        if BN_cmp(j, key.dmp1) <> 0  then begin
            ret := 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_DMP1_NOT_CONGRUENT_TO_D);
        end;
        { dmq1 = d mod (q-1)? }
        if 0>=BN_sub(i, key.q, BN_value_one )then begin
            ret := -1;
            goto _err;
        end;
        if 0>=BN_mod(j, key.d, i, ctx) then  begin
            ret := -1;
            goto _err;
        end;
        if BN_cmp(j, key.dmq1) <> 0  then begin
            ret := 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_DMQ1_NOT_CONGRUENT_TO_D);
        end;
        { iqmp = q^-1 mod p? }
        if nil = BN_mod_inverse(i, key.q, key.p, ctx ) then begin
            ret := -1;
            goto _err;
        end;
        if BN_cmp(i, key.iqmp ) <> 0 then begin
            ret := 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_IQMP_NOT_INVERSE_OF_Q);
        end;
    end;
    for idx := 0 to ex_primes-1 do begin
        pinfo := sk_RSA_PRIME_INFO_value(key.prime_infos, idx);
        { d_i = d mod (r_i - 1)? }
        if 0>=BN_sub(i, pinfo.r, BN_value_one )then  begin
            ret := -1;
            goto _err;
        end;
        if 0>=BN_mod(j, key.d, i, ctx) then  begin
            ret := -1;
            goto _err;
        end;
        if BN_cmp(j, pinfo.d ) <> 0 then begin
            ret := 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D);
        end;
        { t_i = R_i ^ -1 mod r_i ? }
        if nil =BN_mod_inverse(i, pinfo.pp, pinfo.r, ctx ) then  begin
            ret := -1;
            goto _err;
        end;
        if BN_cmp(i, pinfo.t) <> 0  then begin
            ret := 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R);
        end;
    end;
 _err:
    BN_free(i);
    BN_free(j);
    BN_free(k);
    BN_free(l);
    BN_free(m);
    BN_CTX_free(ctx);
    Result := ret;
end;



function RSA_check_key_ex(const key : PRSA; cb : PBN_GENCB):integer;
begin
{$IFDEF FIPS_MODULE}
    Exit(ossl_rsa_validate_public(key));
            and  ossl_rsa_validate_private(key)
            and  ossl_rsa_validate_pairwise(key);
{$ELSE}
   Exit(rsa_validate_keypair_multiprime(key, cb));
{$endif} { FIPS_MODULE }
end;






function ossl_rsa_validate_public(const key : PRSA):integer;
begin
    Result := ossl_rsa_sp800_56b_check_public(key);
end;



function ossl_rsa_validate_pairwise(const key : PRSA):integer;
begin
{$IFDEF FIPS_MODULE}
    Exit(ossl_rsa_sp800_56b_check_keypair(key, nil, -1, RSA_bits(key)));
{$ELSE Exit(rsa_validate_keypair_multiprime(key, nil));}
{$ENDIF}
end;

function ossl_rsa_validate_private(const key : PRSA):Integer;
begin
    Result := ossl_rsa_sp800_56b_check_private(key);
end;

end.
