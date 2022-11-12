unit OpenSSL3.crypto.rsa.rsa_sp800_56b_gen;

interface
uses OpenSSL.Api;

const
  RSA_FIPS1864_MIN_KEYGEN_KEYSIZE = 2048;
  RSA_FIPS1864_MIN_KEYGEN_STRENGTH = 112;

 function ossl_rsa_sp800_56b_generate_key(rsa : PRSA; nbits : integer;const efixed : PBIGNUM; cb : PBN_GENCB):integer;
 function ossl_rsa_sp800_56b_validate_strength( nbits, strength : integer):integer;
 function rsa_validate_rng_strength( rng : PEVP_RAND_CTX; nbits : integer):integer;
 function ossl_rsa_fips186_4_gen_prob_primes(rsa : PRSA; test : PRSA_ACVP_TEST; nbits : integer;const e : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
 function ossl_rsa_sp800_56b_derive_params_from_pq(rsa : PRSA; nbits : integer;const e : PBIGNUM; ctx : PBN_CTX):integer;
 function ossl_rsa_sp800_56b_pairwise_test( rsa : PRSA; ctx : PBN_CTX):integer;

implementation
uses openssl3.crypto.rsa.rsa_lib, OpenSSL3.Err, openssl3.crypto.rand.rand_lib,
      openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.bn.bn_gcd, openssl3.crypto.bn.bn_mul,
      openssl3.crypto.bn.bn_exp,
      OpenSSL3.crypto.rsa.rsa_sp800_56b_check, openssl3.crypto.bn.bn_rsa_fips186_4;





function ossl_rsa_sp800_56b_pairwise_test( rsa : PRSA; ctx : PBN_CTX):integer;
var
  ret : integer;

  k, tmp : PBIGNUM;
  label _err;
begin
    ret := 0;
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    k := BN_CTX_get(ctx);
    if k = nil then goto _err ;
    BN_set_flags(k, BN_FLG_CONSTTIME);
    ret := int( (BN_set_word(k, 2)>0)
            and ( BN_mod_exp(tmp, k, rsa.e, rsa.n, ctx)>0)
            and ( BN_mod_exp(tmp, tmp, rsa.d, rsa.n, ctx)>0)
            and ( BN_cmp(k, tmp) = 0));
    if ret = 0 then
       ERR_raise(ERR_LIB_RSA, RSA_R_PAIRWISE_TEST_FAILURE);
_err:
    BN_CTX_end(ctx);
    Result := ret;
end;

function ossl_rsa_sp800_56b_derive_params_from_pq(rsa : PRSA; nbits : integer;const e : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;

  p1, q1, lcm, p1q1, gcd : PBIGNUM;
  label _err;
begin
    ret := -1;
    BN_CTX_start(ctx);
    p1 := BN_CTX_get(ctx);
    q1 := BN_CTX_get(ctx);
    lcm := BN_CTX_get(ctx);
    p1q1 := BN_CTX_get(ctx);
    gcd := BN_CTX_get(ctx);
    if gcd = nil then goto _err ;
    BN_set_flags(p1, BN_FLG_CONSTTIME);
    BN_set_flags(q1, BN_FLG_CONSTTIME);
    BN_set_flags(lcm, BN_FLG_CONSTTIME);
    BN_set_flags(p1q1, BN_FLG_CONSTTIME);
    BN_set_flags(gcd, BN_FLG_CONSTTIME);
    { LCM((p-1, q-1)) }
    if ossl_rsa_get_lcm(ctx, rsa.p, rsa.q, lcm, gcd, p1, q1, p1q1) <> 1  then
        goto _err ;
    { copy e }
    BN_free(rsa.e);
    rsa.e := BN_dup(e);
    if rsa.e = nil then goto _err ;
    BN_clear_free(rsa.d);
    { (Step 3) d = (e^-1) mod (LCM(p-1, q-1)) }
    rsa.d := BN_secure_new();
    if rsa.d = nil then goto _err ;
    BN_set_flags(rsa.d, BN_FLG_CONSTTIME);
    if BN_mod_inverse(rsa.d, e, lcm, ctx)= nil  then
        goto _err ;
    { (Step 3) return an error if d is too small }
    if BN_num_bits(rsa.d) <= (nbits  shr  1)  then
    begin
        ret := 0;
        goto _err ;
    end;
    { (Step 4) n = pq }
    if rsa.n = nil then
       rsa.n := BN_new();
    if (rsa.n = nil)  or  (0>= BN_mul(rsa.n, rsa.p, rsa.q, ctx)) then
        goto _err ;
    { (Step 5a) dP = d mod (p-1) }
    if rsa.dmp1 = nil then
       rsa.dmp1 := BN_secure_new();
    if rsa.dmp1 = nil then
       goto _err ;
    BN_set_flags(rsa.dmp1, BN_FLG_CONSTTIME);
    if 0>= BN_mod(rsa.dmp1, rsa.d, p1, ctx ) then
        goto _err ;
    { (Step 5b) dQ = d mod (q-1) }
    if rsa.dmq1 = nil then
       rsa.dmq1 := BN_secure_new();
    if rsa.dmq1 = nil then
       goto _err ;
    BN_set_flags(rsa.dmq1, BN_FLG_CONSTTIME);
    if 0>= BN_mod(rsa.dmq1, rsa.d, q1, ctx) then
        goto _err ;
    { (Step 5c) qInv = (inverse of q) mod p }
    BN_free(rsa.iqmp);
    rsa.iqmp := BN_secure_new();
    if rsa.iqmp = nil then
       goto _err ;
    BN_set_flags(rsa.iqmp, BN_FLG_CONSTTIME);
    if BN_mod_inverse(rsa.iqmp, rsa.q, rsa.p, ctx) = nil  then
        goto _err ;
    Inc(rsa.dirty_cnt);
    ret := 1;
_err:
    if ret <> 1 then
    begin
        BN_free(rsa.e);
        rsa.e := nil;
        BN_free(rsa.d);
        rsa.d := nil;
        BN_free(rsa.n);
        rsa.n := nil;
        BN_free(rsa.iqmp);
        rsa.iqmp := nil;
        BN_free(rsa.dmq1);
        rsa.dmq1 := nil;
        BN_free(rsa.dmp1);
        rsa.dmp1 := nil;
    end;
    BN_clear(p1);
    BN_clear(q1);
    BN_clear(lcm);
    BN_clear(p1q1);
    BN_clear(gcd);
    BN_CTX_end(ctx);
    Result := ret;
end;

function ossl_rsa_fips186_4_gen_prob_primes(rsa : PRSA; test : PRSA_ACVP_TEST; nbits : integer;const e : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
var
  ret, ok : integer;
  Xqo, tmp, p2, q2, Xqout,
  Xp1, Xp2, Xq1, Xq2,
  Xpo, p1, q1, Xpout, Xp, Xq : PBIGNUM;
  label _err;
begin
    ret := 0;
    { Temp allocated BIGNUMS }
    Xpo := nil; Xqo := nil; tmp := nil;
    { Intermediate BIGNUMS that can be returned for testing }
    p1 := nil; p2 := nil;
    q1 := nil; q2 := nil;
    { Intermediate BIGNUMS that can be input for testing }
    Xpout := nil; Xqout := nil;
    Xp := nil; Xp1 := nil; Xp2 := nil;
    Xq := nil; Xq1 := nil; Xq2 := nil;
{$IF defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ACVP_TESTS)}
    if test <> nil then
    begin
        Xp1 := test.Xp1;
        Xp2 := test.Xp2;
        Xq1 := test.Xq1;
        Xq2 := test.Xq2;
        Xp := test.Xp;
        Xq := test.Xq;
        p1 := test.p1;
        p2 := test.p2;
        q1 := test.q1;
        q2 := test.q2;
    end;
{$ENDIF}
    { (Step 1) Check key length
     * NOTE: SP800-131A Rev1 Disallows key lengths of < 2048 bits for RSA
     * Signature Generation and Key Agree/Transport.
     }
    if nbits < RSA_FIPS1864_MIN_KEYGEN_KEYSIZE then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        Exit(0);
    end;
    if 0>= ossl_rsa_check_public_exponent(e) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        Exit(0);
    end;
    { (Step 3) Determine strength and check rand generator strength is ok -
     * this step is redundant because the generator always returns a higher
     * strength than is required.
     }
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    Xpo := get_result(Xpout <> nil , Xpout , BN_CTX_get(ctx));
    Xqo := get_result(Xqout <> nil , Xqout , BN_CTX_get(ctx));
    if (tmp = nil)  or  (Xpo = nil)  or  (Xqo = nil) then
       goto _err ;
    BN_set_flags(Xpo, BN_FLG_CONSTTIME);
    BN_set_flags(Xqo, BN_FLG_CONSTTIME);
    if rsa.p = nil then
       rsa.p := BN_secure_new();
    if rsa.q = nil then
       rsa.q := BN_secure_new();
    if (rsa.p = nil)  or  (rsa.q = nil) then
       goto _err ;
    BN_set_flags(rsa.p, BN_FLG_CONSTTIME);
    BN_set_flags(rsa.q, BN_FLG_CONSTTIME);
    { (Step 4) Generate p, Xp }
    if 0>= ossl_bn_rsa_fips186_4_gen_prob_primes(rsa.p, Xpo, p1, p2, Xp, Xp1, Xp2,
                                               nbits, e, ctx, cb) then
        goto _err ;
    while true do
    begin
        { (Step 5) Generate q, Xq}
        if 0>= ossl_bn_rsa_fips186_4_gen_prob_primes(rsa.q, Xqo, q1, q2, Xq, Xq1,
                                                   Xq2, nbits, e, ctx, cb) then
            goto _err ;
        { (Step 6) |Xp - Xq| > 2^(nbitlen/2 - 100) }
        ok := ossl_rsa_check_pminusq_diff(tmp, Xpo, Xqo, nbits);
        if ok < 0 then goto _err ;
        if ok = 0 then continue;
        { (Step 6) |p - q| > 2^(nbitlen/2 - 100) }
        ok := ossl_rsa_check_pminusq_diff(tmp, rsa.p, rsa.q, nbits);
        if ok < 0 then goto _err ;
        if ok = 0 then continue;
        break; { successfully finished }
    end;
    Inc(rsa.dirty_cnt);
    ret := 1;
_err:
    { Zeroize any internally generated values that are not returned }
    if Xpo <> Xpout then BN_clear(Xpo);
    if Xqo <> Xqout then BN_clear(Xqo);
    BN_clear(tmp);
    BN_CTX_end(ctx);
    Result := ret;
end;

function rsa_validate_rng_strength( rng : PEVP_RAND_CTX; nbits : integer):integer;
begin
    if rng = nil then Exit(0);
{$IFDEF FIPS_MODULE}
    {
     * This should become mainstream once similar tests are added to the other
     * key generations and once there is a way to disable these checks.
     }
    if EVP_RAND_get_strength(rng) < ossl_ifc_ffc_compute_security_bits(nbits))  then
    begin
        ERR_raise(ERR_LIB_RSA,
                  RSA_R_RANDOMNESS_SOURCE_STRENGTH_INSUFFICIENT);
        Exit(0);
    end;
{$ENDIF}
    Result := 1;
end;

function ossl_rsa_sp800_56b_validate_strength( nbits, strength : integer):integer;
var
  s : integer;
begin
    s := int (ossl_ifc_ffc_compute_security_bits(nbits));
{$IFDEF FIPS_MODULE}
    if s < RSA_FIPS1864_MIN_KEYGEN_STRENGTH then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        Exit(0);
    end;
{$ENDIF}
    if (strength <> -1)  and  (s <> strength) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_STRENGTH);
        Exit(0);
    end;
    Result := 1;
end;

function ossl_rsa_sp800_56b_generate_key(rsa : PRSA; nbits : integer;const efixed : PBIGNUM; cb : PBN_GENCB):integer;
var
  ret, ok : integer;
  ctx : PBN_CTX;
  e : PBIGNUM;
  info : PRSA_ACVP_TEST;
  rnd  : PEVP_RAND_CTX;
  label _err ;
begin
    ret := 0;
    ctx := nil;
    e := nil;
    info := nil;
{$IF defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ACVP_TESTS)}
    info := rsa.acvp_test;
{$ENDIF}
    { (Steps 1a-1b) : Currently ignores the strength check }
    if 0>= ossl_rsa_sp800_56b_validate_strength(nbits, -1) then
        Exit(0);
    { Check that the RNG is capable of generating a key this large }
    rnd := RAND_get0_private(rsa.libctx);
   if 0>= rsa_validate_rng_strength(rnd , nbits)  then
        Exit(0);
    ctx := BN_CTX_new_ex(rsa.libctx);
    if ctx = nil then Exit(0);
    { Set default if e is not passed in }
    if efixed = nil then
    begin
        e := BN_new();
        if (e = nil)  or  (0>= BN_set_word(e, 65537) ) then
            goto _err ;
    end
    else
    begin
        e := efixed;
    end;
    { (Step 1c) fixed exponent is checked later .}
    while true do
    begin
        { (Step 2) Generate prime factors }
        if 0>= ossl_rsa_fips186_4_gen_prob_primes(rsa, info, nbits, e, ctx, cb) then
            goto _err ;
        { (Steps 3-5) Compute params d, n, dP, dQ, qInv }
        ok := ossl_rsa_sp800_56b_derive_params_from_pq(rsa, nbits, e, ctx);
        if ok < 0 then goto _err ;
        if ok > 0 then break;
        { Gets here if computed d is too small - so try again }
    end;
    { (Step 6) Do pairwise test - optional validity test has been omitted }
    ret := ossl_rsa_sp800_56b_pairwise_test(rsa, ctx);
_err:
    if efixed = nil then
       BN_free(e);
    BN_CTX_free(ctx);
    Result := ret;
end;


end.
