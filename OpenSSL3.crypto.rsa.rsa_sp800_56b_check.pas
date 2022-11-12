unit OpenSSL3.crypto.rsa.rsa_sp800_56b_check;

interface
uses OpenSSL.Api;

function ossl_rsa_check_public_exponent(const e : PBIGNUM):integer;
function ossl_rsa_check_pminusq_diff(diff : PBIGNUM;const p, q : PBIGNUM; nbits : integer):integer;
function ossl_rsa_get_lcm(ctx : PBN_CTX;const p, q : PBIGNUM; lcm, gcd, p1, q1, p1q1 : PBIGNUM):integer;
function ossl_rsa_sp800_56b_check_public(const rsa : PRSA):integer;
function ossl_rsa_sp800_56b_check_private(const rsa : PRSA):integer;

function ossl_rsa_check_prime_factor_range(const p : PBIGNUM; nbits : integer; ctx : PBN_CTX):integer;
function ossl_rsa_check_prime_factor( p, e : PBIGNUM; nbits : integer; ctx : PBN_CTX):integer;
function ossl_rsa_check_private_exponent(const rsa : PRSA; nbits : integer; ctx : PBN_CTX):integer;

function ossl_rsa_check_crt_components(const rsa : PRSA; ctx : PBN_CTX):integer;

function ossl_rsa_sp800_56b_check_keypair(const rsa : PRSA; efixed : PBIGNUM; strength, nbits : integer):integer;

implementation

 uses openssl3.crypto.bn.bn_lib,     openssl3.crypto.bn.bn_add,
      openssl3.crypto.bn.bn_word,    openssl3.crypto.bn.bn_mul,
      OpenSSL3.Err,                  openssl3.crypto.bn.bn_ctx,
      openssl3.crypto.bn.bn_prime,   openssl3.crypto.bn.bn_rsa_fips186_4,
      openssl3.crypto.bn.bn_gcd,     openssl3.crypto.bn.bn_div,
      openssl3.crypto.bn.bn_shift,   openssl3.crypto.bn.bn_mod,
      OpenSSL3.crypto.rsa.rsa_sp800_56b_gen   ;


(*
 * RSA key pair validation.
 *
 * SP800-56Br1.
 *    6.4.1.2 "RSAKPV1 Family: RSA Key - Pair Validation with a Fixed Exponent"
 *    6.4.1.3 "RSAKPV2 Family: RSA Key - Pair Validation with a Random Exponent"
 *
 * It uses:
 *     6.4.1.2.3 "rsakpv1 - crt"
 *     6.4.1.3.3 "rsakpv2 - crt"
 *)


function ossl_rsa_sp800_56b_check_keypair(const rsa : PRSA; efixed : PBIGNUM; strength, nbits : integer):integer;
var
  ret : Boolean;
  ctx : PBN_CTX;
  r : PBIGNUM;
  label _err;
begin
    ret := Boolean(0);
    ctx := nil;
    r := nil;
    if (rsa.p = nil)
             or  (rsa.q = nil)
             or  (rsa.e = nil)
             or  (rsa.d = nil)
             or  (rsa.n = nil) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
        Exit(0);
    end;
    { (Step 1): Check Ranges }
    if 0>=ossl_rsa_sp800_56b_validate_strength(nbits, strength) then
        Exit(0);
    { If the exponent is known }
    if efixed <> nil then begin
        { (2): Check fixed exponent matches public exponent. }
        if BN_cmp(efixed, rsa.e) <> 0 then  begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
            Exit(0);
        end;
    end;
    { (Step 1.c): e is odd integer 65537 <= e < 2^256 }
    if 0>=ossl_rsa_check_public_exponent(rsa.e) then begin
        { exponent out of range }
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        Exit(0);
    end;
    { (Step 3.b): check the modulus }
    if nbits <> BN_num_bits(rsa.n) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(rsa.libctx);
    if ctx = nil then Exit(0);
    BN_CTX_start(ctx);
    r := BN_CTX_get(ctx);
    if (r = nil)  or  (0>=BN_mul(r, rsa.p, rsa.q, ctx)) then
        goto _err;
    { (Step 4.c): Check n = pq }
    if BN_cmp(rsa.n, r) <> 0  then begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
        goto _err;
    end;
    { (Step 5): check prime factors p and q }
    ret := (ossl_rsa_check_prime_factor(rsa.p, rsa.e, nbits, ctx) > 0)
           and  (ossl_rsa_check_prime_factor(rsa.q, rsa.e, nbits, ctx) > 0)
           and  (ossl_rsa_check_pminusq_diff(r, rsa.p, rsa.q, nbits) > 0)
          { (Step 6): Check the private exponent d }
           and  (ossl_rsa_check_private_exponent(rsa, nbits, ctx) > 0)
          { 6.4.1.2.3 (Step 7): Check the CRT components }
           and  (ossl_rsa_check_crt_components(rsa, ctx) > 0);
    if ret <> Boolean(1) then
       ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);
_err:
    BN_clear(r);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := Int(ret);
end;

(*
 * Part of the RSA keypair test.
 * Check the Chinese Remainder Theorem components are valid.
 *
 * See SP800-5bBr1
 *   6.4.1.2.3: rsakpv1-crt Step 7
 *   6.4.1.3.3: rsakpv2-crt Step 7
 *)
function ossl_rsa_check_crt_components(const rsa : PRSA; ctx : PBN_CTX):integer;
var
  ret : Boolean;
  r, p1, q1 : PBIGNUM;
begin
    ret := Boolean(0);
    r := nil; p1 := nil; q1 := nil;
    { check if only some of the crt components are set }
    if (rsa.dmp1 = nil)  or  (rsa.dmq1 = nil)  or  (rsa.iqmp = nil) then
    begin
        if (rsa.dmp1 <> nil)  or  (rsa.dmq1 <> nil)  or  (rsa.iqmp <> nil) then
            Exit(0);
        Exit( 1); { return ok if all components are nil }
    end;
    BN_CTX_start(ctx);
    r := BN_CTX_get(ctx);
    p1 := BN_CTX_get(ctx);
    q1 := BN_CTX_get(ctx);
    if q1 <> nil then
    begin
        BN_set_flags(r, BN_FLG_CONSTTIME);
        BN_set_flags(p1, BN_FLG_CONSTTIME);
        BN_set_flags(q1, BN_FLG_CONSTTIME);
        ret := Boolean(1);
    end
    else begin
        ret := Boolean(0);
    end;
    ret := ret
          { p1 = p -1 }
           and  (BN_copy(p1, rsa.p) <> nil)
           and  (BN_sub_word(p1, 1) > 0)
          { q1 = q - 1 }
           and  (BN_copy(q1, rsa.q) <> nil)
           and  (BN_sub_word(q1, 1) > 0)
          { (a) 1 < dP < (p 每 1). }
           and  (BN_cmp(rsa.dmp1, BN_value_one) > 0)
           and  (BN_cmp(rsa.dmp1, p1) < 0)
          { (b) 1 < dQ < (q - 1). }
           and  (BN_cmp(rsa.dmq1, BN_value_one) > 0)
           and  (BN_cmp(rsa.dmq1, q1) < 0)
          { (c) 1 < qInv < p }
           and  (BN_cmp(rsa.iqmp, BN_value_one) > 0)
           and  (BN_cmp(rsa.iqmp, rsa.p) < 0)
          { (d) 1 = (dP . e) mod (p - 1)}
           and  (BN_mod_mul(r, rsa.dmp1, rsa.e, p1, ctx) > 0)
           and  (BN_is_one(r))
          { (e) 1 = (dQ . e) mod (q - 1) }
           and  (BN_mod_mul(r, rsa.dmq1, rsa.e, q1, ctx) > 0)
           and  (BN_is_one(r))
          { (f) 1 = (qInv . q) mod p }
           and  (BN_mod_mul(r, rsa.iqmp, rsa.q, rsa.p, ctx) > 0)
           and  (BN_is_one(r));
    BN_clear(r);
    BN_clear(p1);
    BN_clear(q1);
    BN_CTX_end(ctx);
    Result := Int(ret);
end;


(*
 * See SP800-56Br1 6.4.1.2.3 Part 6(a-b) Check the private exponent d
 * satisfies:
 *     (Step 6a) 2^(nBit/2) < d < LCM(p每1, q每1).
 *     (Step 6b) 1 = (d*e) mod LCM(p每1, q每1)
 *)

function ossl_rsa_check_private_exponent(const rsa : PRSA; nbits : integer; ctx : PBN_CTX):integer;
var
  ret : Boolean;
  r, p1, q1, lcm, p1q1, gcd : PBIGNUM;
begin
    { (Step 6a) 2^(nbits/2) < d }
    if BN_num_bits(rsa.d) <= (nbits  shr  1)  then
        Exit(0);
    BN_CTX_start(ctx);
    r := BN_CTX_get(ctx);
    p1 := BN_CTX_get(ctx);
    q1 := BN_CTX_get(ctx);
    lcm := BN_CTX_get(ctx);
    p1q1 := BN_CTX_get(ctx);
    gcd := BN_CTX_get(ctx);
    if gcd <> nil then
    begin
        BN_set_flags(r, BN_FLG_CONSTTIME);
        BN_set_flags(p1, BN_FLG_CONSTTIME);
        BN_set_flags(q1, BN_FLG_CONSTTIME);
        BN_set_flags(lcm, BN_FLG_CONSTTIME);
        BN_set_flags(p1q1, BN_FLG_CONSTTIME);
        BN_set_flags(gcd, BN_FLG_CONSTTIME);
        ret := Boolean(1);
    end
    else begin
        ret := Boolean(0);
    end;
    ret := ret
          { LCM(p - 1, q - 1) }
           and  (ossl_rsa_get_lcm(ctx, rsa.p, rsa.q, lcm, gcd, p1, q1,
                               p1q1) = 1)
          { (Step 6a) d < LCM(p - 1, q - 1) }
           and  (BN_cmp(rsa.d, lcm) < 0)
          { (Step 6b) 1 = (e . d) mod LCM(p - 1, q - 1) }
           and  (BN_mod_mul(r, rsa.e, rsa.d, lcm, ctx) > 0)
           and  (BN_is_one(r));
    BN_clear(r);
    BN_clear(p1);
    BN_clear(q1);
    BN_clear(lcm);
    BN_clear(gcd);
    BN_CTX_end(ctx);
    Result := Int(ret);
end;

(*
 * Part of the RSA keypair test.
 * Check the prime factor (for either p or q)
 * i.e: p is prime AND GCD(p - 1, e) = 1
 *
 * See SP800-56Br1 6.4.1.2.3 Step 5 (a to d) & (e to h).
 *)
function ossl_rsa_check_prime_factor( p, e : PBIGNUM; nbits : integer; ctx : PBN_CTX):integer;
var
  ret : Boolean;
  p1, gcd : PBIGNUM;

begin
{$POINTERMATH ON}
    ret := Boolean(0);
    p1 := nil;
    gcd := nil;

    { (Steps 5 a-b) prime test }
    if (BN_check_prime(p, ctx, nil) <> 1)
            { (Step 5c) (﹟2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2 - 1) }
             or  (ossl_rsa_check_prime_factor_range(p, nbits, ctx) <> 1)  then
        Exit(0);
    BN_CTX_start(ctx);
    p1 := BN_CTX_get(ctx);
    gcd := BN_CTX_get(ctx);
    if gcd <> nil then
    begin
        BN_set_flags(p1, BN_FLG_CONSTTIME);
        BN_set_flags(gcd, BN_FLG_CONSTTIME);
        ret := Boolean(1);
    end
    else
    begin
        ret := Boolean(0);
    end;
    ret := ret
          { (Step 5d) GCD(p-1, e) = 1 }
           and  (BN_copy(p1, p) <> nil)
           and  (BN_sub_word(p1, 1) > 0)
           and  (BN_gcd(gcd, p1, e, ctx) > 0)
           and  (BN_is_one(gcd));
    BN_clear(p1);
    BN_CTX_end(ctx);
    Result := Int(ret);
{$POINTERMATH OFF}
end;

(*
 * Part of the RSA keypair test.
 * Check that (﹟2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
 *
 * See SP800-5bBr1 6.4.1.2.1 Part 5 (c) & (g) - used for both p and q.
 *
 * (﹟2)(2^(nbits/2 - 1) = (﹟2/2)(2^(nbits/2))
 *)
function ossl_rsa_check_prime_factor_range(const p : PBIGNUM; nbits : integer; ctx : PBN_CTX):integer;
var
  ret : integer;
  low : PBIGNUM;
  shift : integer;
  label _err;
begin
    ret := 0;
    nbits := nbits shr 1;
    shift := nbits - BN_num_bits(@ossl_bn_inv_sqrt_2);
    { Upper bound check }
    if BN_num_bits(p) <> nbits  then
        Exit(0);
    BN_CTX_start(ctx);
    low := BN_CTX_get(ctx);
    if low = nil then
       goto _err;
    { set low = (﹟2)(2^(nbits/2 - 1) }
    if nil = BN_copy(low, @ossl_bn_inv_sqrt_2) then
       goto _err;
    if shift >= 0 then
    begin
        {
         * We don't have all the bits. ossl_bn_inv_sqrt_2 contains a rounded up
         * value, so there is a very low probability that we'll reject a valid
         * value.
         }
        if 0 >= BN_lshift(low, low, shift) then
            goto _err;
    end
    else
    if (0 >= BN_rshift(low, low, -shift)) then
    begin
        goto _err;
    end;
    if BN_cmp(p, low) <= 0  then
        goto _err;
    ret := 1;

_err:
    BN_CTX_end(ctx);
    Result := ret;
end;

function ossl_rsa_sp800_56b_check_public(const rsa : PRSA):integer;
var
  ret, nbits, status : integer;
  ctx : PBN_CTX;
  gcd : PBIGNUM;
  label _err;
begin
    ret := 0;
    ctx := nil;
    gcd := nil;
    if (rsa.n = nil)  or  (rsa.e = nil) then Exit(0);
    nbits := BN_num_bits(rsa.n);
{$IFDEF FIPS_MODULE}
    {
     * (Step a): modulus must be 2048 or 3072 (caveat from SP800-56Br1)
     * NOTE: changed to allow keys >= 2048
     }
    if  0>= ossl_rsa_sp800_56b_validate_strength(nbits, -1 )then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
{$ENDIF}
    if  not BN_is_odd(rsa.n) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        Exit(0);
    end;
    { (Steps b-c): 2^16 < e < 2^256, n and e must be odd }
    if  0>= ossl_rsa_check_public_exponent(rsa.e) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(rsa.libctx);
    gcd := BN_new();
    if (ctx = nil)  or  (gcd = nil) then
       goto _err ;
    { (Steps d-f):
     * The modulus is composite, but not a power of a prime.
     * The modulus has no factors smaller than 752.
     }
    if ( 0>= BN_gcd(gcd, rsa.n, ossl_bn_get0_small_factors, ctx) )
         or  (not BN_is_one(gcd)) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        goto _err ;
    end;
    ret := ossl_bn_miller_rabin_is_prime(rsa.n, 0, ctx, nil, 1, status);
{$ifdef FIPS_MODULE}

    if (ret <> 1) or (status <> BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME) then
    begin
{$else}
    if (ret <> 1) or ( (status <> BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME)
                     and ( (nbits >= RSA_MIN_MODULUS_BITS)
                         or (status <> BN_PRIMETEST_COMPOSITE_WITH_FACTOR))) then
    begin
{$endif}
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        ret := 0;
        goto _err;
    end;
    ret := 1;
_err:
    BN_free(gcd);
    BN_CTX_free(ctx);
    Result := ret;
end;

function ossl_rsa_sp800_56b_check_private(const rsa : PRSA):Integer;
begin
    if (rsa.d = nil)  or  (rsa.n = nil) then
       Exit(0);
    Result := Int( (BN_cmp(rsa.d, BN_value_one) >= 0)  and  (BN_cmp(rsa.d, rsa.n) < 0));
end;

function ossl_rsa_get_lcm(ctx : PBN_CTX;const p, q : PBIGNUM; lcm, gcd, p1, q1, p1q1 : PBIGNUM):integer;
begin
    Result := int( (BN_sub(p1, p, BN_value_one)>0)    { p-1 }
                    and  (BN_sub(q1, q, BN_value_one)>0) { q-1 }
                    and  (BN_mul(p1q1, p1, q1, ctx)>0)     { (p-1)(q-1) }
                    and  (BN_gcd(gcd, p1, q1, ctx)>0)
                    and  (BN_div(lcm, nil, p1q1, gcd, ctx)>0)); { LCM((p-1, q-1)) }
end;



function ossl_rsa_check_pminusq_diff(diff : PBIGNUM;const p, q : PBIGNUM; nbits : integer):integer;
var
  bitlen : integer;
begin
    bitlen := (nbits  shr  1) - 100;
    if 0>= BN_sub(diff, p, q) then
        Exit(-1);
    BN_set_negative(diff, 0);
    if BN_is_zero(diff ) then
        Exit(0);
    if 0>= BN_sub_word(diff, 1 ) then
        Exit(-1);
    Result := int(BN_num_bits(diff) > bitlen);
end;

function ossl_rsa_check_public_exponent(const e : PBIGNUM):integer;
var
  bitlen : integer;
begin
{$IFDEF FIPS_MODULE}
    bitlen := BN_num_bits(e);
    Exit((BN_is_odd(e)  and  bitlen > 16  and  bitlen < 257));
{$ELSE} { Allow small exponents larger than 1 for legacy purposes }
    Result := Int( (BN_is_odd(e))  and  (BN_cmp(e, BN_value_one) > 0) );
{$endif} { FIPS_MODULE }
end;


end.
