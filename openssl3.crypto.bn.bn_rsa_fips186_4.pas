unit openssl3.crypto.bn.bn_rsa_fips186_4;

interface
uses OpenSSL.Api;

function ossl_bn_rsa_fips186_4_gen_prob_primes(p, Xpout, p1, p2 : PBIGNUM;const Xp, Xp1, Xp2 : PBIGNUM; nlen : integer;const e : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
 function bn_rsa_fips186_5_aux_prime_min_size( nbits : integer):integer;
function bn_rsa_fips186_4_find_aux_prob_prime(const Xp1 : PBIGNUM; p1 : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
function bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes( nbits : integer):integer;
 function ossl_bn_rsa_fips186_4_derive_prime(Y, X : PBIGNUM;const Xin, r1, r2 : PBIGNUM; nlen : integer;const e : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;

(* 1 / sqrt(2) * 2^256, rounded up *)
const  inv_sqrt_2_val: array[0..3] of BN_ULONG = (
    (UInt64($ED17AC85) shl 32) or $83339916, (UInt64($1D6F60BA) shl 32) or $893BA84C,
    (UInt64($597D89B3) shl 32) or $754ABE9F, (UInt64($B504F333) shl 32) or $F9DE6484);

var
     ossl_bn_inv_sqrt_2: TBIGNUM;

implementation
uses openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_rand,
     openssl3.crypto.bn.bn_word, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_add, openssl3.crypto.bn.bn_gcd,
     openssl3.crypto.bn.bn_mul, openssl3.crypto.bn.bn_mod,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_prime;


{$if BN_BITS2 = 64}
function BN_DEF(lo, hi: UInt32): BN_ULONG;
begin
   Result := BN_ULONG(hi shl 32 or lo );
end;

{$else}
define BN_DEF(lo, hi) lo, hi
{$endif}

function ossl_bn_rsa_fips186_4_derive_prime(Y, X : PBIGNUM;const Xin, r1, r2 : PBIGNUM; nlen : integer;const e : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
var
  ret, i, imax, bits : integer;
  tmp, R, r1r2x2, y1, r1x2, base, range : PBIGNUM;
  rv : integer;
  label _err, _end ;
begin
    ret := 0;
    bits := nlen  shr  1;
    BN_CTX_start(ctx);
    base := BN_CTX_get(ctx);
    range := BN_CTX_get(ctx);
    R := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    r1r2x2 := BN_CTX_get(ctx);
    y1 := BN_CTX_get(ctx);
    r1x2 := BN_CTX_get(ctx);
    if r1x2 = nil then goto _err ;
    if (Xin <> nil)  and  (BN_copy(X, Xin) = nil) then
        goto _err ;
    {
     * We need to generate a random number X in the range
     * 1/sqrt(2) * 2^(nlen/2) <= X < 2^(nlen/2).
     * We can rewrite that as:
     * base = 1/sqrt(2) * 2^(nlen/2)
     * range = ((2^(nlen/2))) - (1/sqrt(2) * 2^(nlen/2))
     * X = base + random(range)
     * We only have the first 256 bit of 1/sqrt(2)
     }
    if Xin = nil then
    begin
        if bits < BN_num_bits(@ossl_bn_inv_sqrt_2) then
            goto _err ;
        if (0>= BN_lshift(base, @ossl_bn_inv_sqrt_2,
                       bits - BN_num_bits(@ossl_bn_inv_sqrt_2)))
             or  (0>= BN_lshift(range, BN_value_one, bits))
             or  (0>= BN_sub(range, range, base)) then
            goto _err ;
    end;
    if not ( (BN_lshift1(r1x2, r1) > 0) { (Step 1) GCD(2r1, r2) = 1 }
             and  (BN_gcd(tmp, r1x2, r2, ctx) > 0)
             and  (BN_is_one(tmp))
            { (Step 2) R = ((r2^-1 mod 2r1) * r2) - ((2r1^-1 mod r2)*2r1) }
             and  (BN_mod_inverse(R, r2, r1x2, ctx) <> nil)
             and  (BN_mul(R, R, r2, ctx) > 0) { R = (r2^-1 mod 2r1) * r2 }
             and  (BN_mod_inverse(tmp, r1x2, r2, ctx) <> nil)
             and  (BN_mul(tmp, tmp, r1x2, ctx) > 0) { tmp = (2r1^-1 mod r2)*2r1 }
             and  (BN_sub(R, R, tmp) > 0)
            { Calculate 2r1r2 }
             and  (BN_mul(r1r2x2, r1x2, r2, ctx) > 0) ) then
        goto _err ;
    { Make positive by adding the modulus }
    if (BN_is_negative(R)>0)  and  (0>= BN_add(R, R, r1r2x2))  then
        goto _err ;
    imax := 5 * bits; { max = 5/2 * nbits }
    while true do
    begin
        if Xin = nil then
        begin
            {
             * (Step 3) Choose Random X such that
             *    sqrt(2) * 2^(nlen/2-1) <= Random X <= (2^(nlen/2)) - 1.
             }
            if (0>= BN_priv_rand_range_ex(X, range, 0, ctx))  or  (0>= BN_add(X, X, base)) then
                goto _end ;
        end;
        { (Step 4) Y = X + ((R - X) mod 2r1r2) }
        if (0>= BN_mod_sub(Y, R, X, r1r2x2, ctx))  or  (0>= BN_add(Y, Y, X)) then
            goto _err ;
        { (Step 5) }
        i := 0;
        while true do
        begin
            { (Step 6) }
            if BN_num_bits(Y)> bits  then
            begin
                if Xin = nil then
                    break { Randomly Generated X so Go back to Step 3 }
                else
                    goto _err ; { X is not random so it will always fail }
            end;
            BN_GENCB_call(cb, 0, 2);
            { (Step 7) If GCD(Y-1) = 1 and Y is probably prime then return Y }
            if (BN_copy(y1, Y) = nil)
                     or  (0>= BN_sub_word(y1, 1))
                     or  (0>= BN_gcd(tmp, y1, e, ctx)) then
                goto _err ;
            if BN_is_one(tmp) then
            begin
                rv := BN_check_prime(Y, ctx, cb);
                if rv > 0 then goto _end ;
                if rv < 0 then goto _err ;
            end;
            { (Step 8-10) }
            if (PreInc(i) >= imax)  or  (0>= BN_add(Y, Y, r1r2x2)) then
                goto _err ;
        end;
    end;

_end:
    ret := 1;
    BN_GENCB_call(cb, 3, 0);

_err:
    BN_clear(y1);
    BN_CTX_end(ctx);
    Result := ret;
end;

function bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes( nbits : integer):integer;
begin
    if nbits >= 4096 then Exit(2030);
    if nbits >= 3072 then Exit(1518);
    if nbits >= 2048 then Exit(1007);
    Result := 0;
end;

function bn_rsa_fips186_4_find_aux_prob_prime(const Xp1 : PBIGNUM; p1 : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
var
  ret, i, tmp : integer;
  label _err;
begin
    ret := 0;
    i := 0;
    tmp := 0;
    if BN_copy(p1, Xp1) = nil then
        Exit(0);
    BN_set_flags(p1, BN_FLG_CONSTTIME);
    { Find the first odd number >= Xp1 that is probably prime }
    while true do
    begin
        Inc(i);
        BN_GENCB_call(cb, 0, i);
        { MR test with trial division }
        tmp := BN_check_prime(p1, ctx, cb);
        if tmp > 0 then
           break;
        if tmp < 0 then
           goto _err ;
        { Get next odd number }
        if 0>= BN_add_word(p1, 2) then
            goto _err ;
    end;
    BN_GENCB_call(cb, 2, i);
    ret := 1;

_err:
    Result := ret;
end;

function bn_rsa_fips186_5_aux_prime_min_size( nbits : integer):integer;
begin
    if nbits >= 4096 then Exit(201);
    if nbits >= 3072 then Exit(171);
    if nbits >= 2048 then Exit(141);
    Result := 0;
end;

function ossl_bn_rsa_fips186_4_gen_prob_primes(p, Xpout, p1, p2 : PBIGNUM;
                                               const Xp, Xp1, Xp2 : PBIGNUM;
                                               nlen : integer;const e : PBIGNUM;
                                               ctx : PBN_CTX; cb : PBN_GENCB):integer;
var
  ret : integer;
  p1i, p2i, Xp1i, Xp2i : PBIGNUM;
  bitlen : integer;
  label _err;
begin
    ret := 0;
    p1i := nil;
    p2i := nil;
    Xp1i := nil;
    Xp2i := nil;
    if (p = nil)  or  (Xpout = nil) then Exit(0);
    BN_CTX_start(ctx);
    p1i := get_result((p1 <> nil) , p1 , BN_CTX_get(ctx));
    p2i := get_result((p2 <> nil) , p2 , BN_CTX_get(ctx));
    Xp1i := get_result((Xp1 <> nil) , Xp1 , BN_CTX_get(ctx));
    Xp2i := get_result((Xp2 <> nil) , Xp2 , BN_CTX_get(ctx));
    if (p1i = nil)  or  (p2i = nil)  or  (Xp1i = nil)  or  (Xp2i = nil) then
       goto _err ;
    bitlen := bn_rsa_fips186_5_aux_prime_min_size(nlen);
    if bitlen = 0 then
       goto _err ;
    { (Steps 4.1/5.1): Randomly generate Xp1 if it is not passed in }
    if Xp1 = nil then
    begin
        { Set the top and bottom bits to make it odd and the correct size }
        if (0>= BN_priv_rand_ex(Xp1i, bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD,
                             0, ctx)) then
            goto _err ;
    end;
    { (Steps 4.1/5.1): Randomly generate Xp2 if it is not passed in }
    if Xp2 = nil then
    begin
        { Set the top and bottom bits to make it odd and the correct size }
        if (0>= BN_priv_rand_ex(Xp2i, bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD,
                             0, ctx)) then
            goto _err ;
    end;
    { (Steps 4.2/5.2) - find first auxiliary probable primes }
    if (0>= bn_rsa_fips186_4_find_aux_prob_prime(Xp1i, p1i, ctx, cb))  or
       (0>= bn_rsa_fips186_4_find_aux_prob_prime(Xp2i, p2i, ctx, cb))  then
        goto _err ;
    { (Table B.1) auxiliary prime Max length check }
    if BN_num_bits(p1i) + BN_num_bits(p2i)  >=
            bn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(nlen) then
        goto _err ;
    { (Steps 4.3/5.3) - generate prime }
    if 0>= ossl_bn_rsa_fips186_4_derive_prime(p, Xpout, Xp, p1i, p2i, nlen, e,
                                            ctx, cb) then
        goto _err ;
    ret := 1;

_err:
    { Zeroize any internally generated values that are not returned }
    if p1 = nil then BN_clear(p1i);
    if p2 = nil then BN_clear(p2i);
    if Xp1 = nil then BN_clear(Xp1i);
    if Xp2 = nil then BN_clear(Xp2i);
    BN_CTX_end(ctx);
    Result := ret;
end;

initialization

   ossl_bn_inv_sqrt_2.d     := @inv_sqrt_2_val[0];
   ossl_bn_inv_sqrt_2.top   := Length(inv_sqrt_2_val);
   ossl_bn_inv_sqrt_2.dmax  := Length(inv_sqrt_2_val);
   ossl_bn_inv_sqrt_2.neg   := 0;
   ossl_bn_inv_sqrt_2.flags := BN_FLG_STATIC_DATA;

end.
