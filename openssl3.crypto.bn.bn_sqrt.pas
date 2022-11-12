unit openssl3.crypto.bn.bn_sqrt;

interface
 uses OpenSSL.Api;

 function BN_mod_sqrt(_in : PBIGNUM;const _a, p : PBIGNUM; ctx : PBN_CTX):PBIGNUM;


implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_word,
     openssl3.crypto.bn.bn_exp, openssl3.crypto.bn.bn_rand,
     openssl3.crypto.bn.bn_add, openssl3.crypto.bn.bn_kron,

     openssl3.crypto.bn.bn_asm, openssl3.crypto.bn.bn_mod;






function BN_mod_sqrt(_in : PBIGNUM;const _a, p : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
var
  ret      : PBIGNUM;

  err,
  r        : integer;

  A,
  b,
  q,
  t,
  x,
  y        : PBIGNUM;
  e,
  i,
  j,
  used_ctx : integer;
  label _end, _vrfy;
begin
    ret := _in;
    err := 1;
    used_ctx := 0;
    if (not BN_is_odd(p))  or  (BN_abs_is_word(p, 1))  then
    begin
        if BN_abs_is_word(p, 2) then
        begin
            if ret = nil then
                ret := BN_new();
            if ret = nil then goto _end ;
            if 0>= BN_set_word(ret, BN_is_bit_set(_a, 0))  then
            begin
                if ret <> _in then
                    BN_free(ret);
                Exit(nil);
            end;
            bn_check_top(ret);
            Exit(ret);
        end;
        ERR_raise(ERR_LIB_BN, BN_R_P_IS_NOT_PRIME);
        Exit(nil);
    end;
    if (BN_is_zero(_a))  or  (BN_is_one(_a))  then
    begin
        if ret = nil then
            ret := BN_new();
        if ret = nil then goto _end ;
        if 0>= BN_set_word(ret, Int(BN_is_one(_a)))  then
        begin
            if ret <> _in then
                BN_free(ret);
            Exit(nil);
        end;
        bn_check_top(ret);
        Exit(ret);
    end;
    BN_CTX_start(ctx);
    used_ctx := 1;
    A := BN_CTX_get(ctx);
    b := BN_CTX_get(ctx);
    q := BN_CTX_get(ctx);
    t := BN_CTX_get(ctx);
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    if y = nil then goto _end ;
    if ret = nil then ret := BN_new();
    if ret = nil then goto _end ;
    { A = a mod p }
    if 0>= BN_nnmod(A, _a, p, ctx) then
        goto _end ;
    { now write  |p| - 1  as  2^e*q  where  q  is odd }
    e := 1;
    while 0>= BN_is_bit_set(p, e) do
        Inc(e);
    { we'll set  q  later (if needed) }
    if e = 1 then
    begin
        {-
         * The easy case:  (|p|-1)/2  is odd, so 2 has an inverse
         * modulo  (|p|-1)/2,  and square roots can be computed
         * directly by modular exponentiation.
         * We have
         *     2 * (|p|+1)/4 = 1   (mod (|p|-1)/2),
         * so we can use exponent  (|p|+1)/4,  i.e.  (|p|-3)/4 + 1.
         }
        if 0>= BN_rshift(q, p, 2) then
            goto _end ;
        q.neg := 0;
        if 0>= BN_add_word(q, 1) then
            goto _end ;
        if 0>= BN_mod_exp(ret, A, q, p, ctx) then
            goto _end ;
        err := 0;
        goto _vrfy ;
    end;
    if e = 2 then
    begin
        {-
         * |p| = 5  (mod 8)
         *
         * In this case  2  is always a non-square since
         * Legendre(2,p) = (-1)^((p^2-1)/8)  for any odd prime.
         * So if  a  really is a square, then  2*a  is a non-square.
         * Thus for
         *      b := (2*a)^((|p|-5)/8),
         *      i := (2*a)*b^2
         * we have
         *     i^2 = (2*a)^((1 + (|p|-5)/4)*2)
         *         = (2*a)^((p-1)/2)
          :=  * -1;
         * so if we set
         *      x := a*b*(i-1),
         * then
         *     x^2 = a^2 * b^2 * (i^2 - 2*i + 1)
         *         = a^2 * b^2 * (-2*i)
         *         = a*(-i)*(2*a*b^2)
         *         = a*(-i)*i
         *         = a.
         *
         * (This is due to A.O.L. Atkin,
         * Subject: Square Roots and Cognate Matters modulo p=8n+5.
         * URL: https://listserv.nodak.edu/cgi-bin/wa.exe?A2=ind9211&L=NMBRTHRY&P=4026
         * November 1992.)
         }
        { t := 2*a }
        if 0>= BN_mod_lshift1_quick(t, A, p ) then
            goto _end ;
        { b := (2*a)^((|p|-5)/8) }
        if 0>= BN_rshift(q, p, 3 ) then
            goto _end ;
        q.neg := 0;
        if 0>= BN_mod_exp(b, t, q, p, ctx ) then
            goto _end ;
        { y := b^2 }
        if 0>= BN_mod_sqr(y, b, p, ctx ) then
            goto _end ;
        { t := (2*a)*b^2 - 1 }
        if 0>= BN_mod_mul(t, t, y, p, ctx ) then
            goto _end ;
        if 0>= BN_sub_word(t, 1 ) then
            goto _end ;
        { x = a*b*t }
        if 0>= BN_mod_mul(x, A, b, p, ctx ) then
            goto _end ;
        if 0>= BN_mod_mul(x, x, t, p, ctx ) then
            goto _end ;
        if nil = BN_copy(ret, x ) then
            goto _end ;
        err := 0;
        goto _vrfy ;
    end;
    {
     * e > 2, so we really have to use the Tonelli/Shanks algorithm. First,
     * find some y that is not a square.
     }
    if nil = BN_copy(q, p) then
        goto _end ;               { use 'q' as temp }
    q.neg := 0;
    i := 2;
    repeat
        {
         * numbers.
         }
        if i < 22 then
        begin
            if 0>= BN_set_word(y, i) then
                goto _end ;
        end
        else
        begin
            if 0>= BN_priv_rand_ex(y, BN_num_bits(p ) , 0, 0, 0, ctx) then
                goto _end ;
            if BN_ucmp(y, p) >= 0 then
            begin
                if p.neg > 0 then
                begin
                  if 0>= BN_add(y, y, p) then
                    goto _end;
                end
                else
                begin
                   if 0>= BN_sub(y, y, p) then
                      goto _end;
                end;
            end;
            { now 0 <= y < |p| }
            if BN_is_zero(y)  then
                if 0>= BN_set_word(y, i) then
                    goto _end ;
        end;
        r := BN_kronecker(y, q, ctx); { here 'q' is |p| }
        if r < -1 then goto _end ;
        if r = 0 then
        begin
            { m divides p }
            ERR_raise(ERR_LIB_BN, BN_R_P_IS_NOT_PRIME);
            goto _end ;
        end;
    until not( (r = 1)  and  (PreInc(i) < 82)) ;

    if r <> -1 then
    begin
        {
         * Many rounds and still no non-square -- this is more likely a bug
         * than just bad luck. Even if p is not prime, we should have found
         * some y such that r = -1.
         }
        ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS);
        goto _end ;
    end;
    { Here's our actual 'q': }
    if 0>= BN_rshift(q, q, e) then
        goto _end ;
    {
     * Now that we have some non-square, we can find an element of order 2^e
     * by computing its q'th power.
     }
    if 0>= BN_mod_exp(y, y, q, p, ctx) then
        goto _end ;
    if BN_is_one(y)  then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_P_IS_NOT_PRIME);
        goto _end ;
    end;
    {-
     * Now we know that (if  p  is indeed prime) there is an integer
     * k,  0 <= k < 2^e,  such that
     *
     *      a^q * y^k = 1   (mod p).
     *
     * As  a^q  is a square and  y  is not,  k  must be even.
     * q+1  is even, too, so there is an element
     *
     *     X := a^((q+1)/2) * y^(k/2),
     *
     * and it satisfies
     *
     *     X^2 = a^q * a     * y^k
     *         = a,
     *
     * so it is the square root that we are looking for.
     }
    { t := (q-1)/2  (note that  q  is odd) }
    if 0>= BN_rshift1(t, q)  then
        goto _end ;
    { x := a^((q-1)/2) }
    if BN_is_zero(t)  then
    begin         { special case: p = 2^e + 1 }
        if 0>= BN_nnmod(t, A, p, ctx) then
            goto _end ;
        if BN_is_zero(t)  then
        begin
            { special case: a = 0  (mod p) }
            BN_zero(ret);
            err := 0;
            goto _end ;
        end
        else if (0>= BN_one(x))  then
            goto _end ;
    end
    else
    begin
        if 0>= BN_mod_exp(x, A, t, p, ctx) then
            goto _end ;
        if BN_is_zero(x)  then
        begin
            { special case: a = 0  (mod p) }
            BN_zero(ret);
            err := 0;
            goto _end ;
        end;
    end;
    { b := a*x^2  (= a^q) }
    if 0>= BN_mod_sqr(b, x, p, ctx ) then
        goto _end ;
    if 0>= BN_mod_mul(b, b, A, p, ctx ) then
        goto _end ;
    { x := a*x    (= a^((q+1)/2)) }
    if 0>= BN_mod_mul(x, x, A, p, ctx ) then
        goto _end ;
    while True do
    begin
        {-
         * Now  b  is  a^q * y^k  for some even  k  (0 <= k < 2^E
         * where  E  refers to the original value of  e,  which we
         * don't keep in a variable),  and  x  is  a^((q+1)/2) * y^(k/2).
         *
         * We have  a*b = x^2,
         *    y^2^(e-1) = -1,
         *    b^2^(e-1) = 1.
         }
        if BN_is_one(b ) then  begin
            if nil = BN_copy(ret, x) then
                goto _end ;
            err := 0;
            goto _vrfy ;
        end;
        { find smallest  i  such that  b^(2^i) = 1 }
        i := 1;
        if 0>= BN_mod_sqr(t, b, p, ctx ) then
            goto _end ;
        while not BN_is_one(t) do
        begin
            Inc(i);
            if i = e then
            begin
                ERR_raise(ERR_LIB_BN, BN_R_NOT_A_SQUARE);
                goto _end ;
            end;
            if 0>= BN_mod_mul(t, t, t, p, ctx ) then
                goto _end ;
        end;
        { t := y^2^(e - i - 1) }
        if nil = BN_copy(t, y ) then
            goto _end ;
        j := e - i - 1;
        while j > 0 do
        begin
            if 0>= BN_mod_sqr(t, t, p, ctx ) then
                goto _end ;
            Dec(j);
        end;
        if 0>= BN_mod_mul(y, t, t, p, ctx ) then
            goto _end ;
        if 0>= BN_mod_mul(x, x, t, p, ctx ) then
            goto _end ;
        if 0>= BN_mod_mul(b, b, y, p, ctx ) then
            goto _end ;
        e := i;
    end;
 _vrfy:
    if 0>= err then
    begin
        {
         * verify the result -- the input might have been not a square (test
         * added in 0.9.8)
         }
        if 0>= BN_mod_sqr(x, ret, p, ctx) then
            err := 1;
        if (0>= err)  and  (0 <> BN_cmp(x, A)) then
        begin
            ERR_raise(ERR_LIB_BN, BN_R_NOT_A_SQUARE);
            err := 1;
        end;
    end;
 _end:
    if err>0 then
    begin
        if ret <> _in then
            BN_clear_free(ret);
        ret := nil;
    end;
    if used_ctx>0 then BN_CTX_end(ctx);
    bn_check_top(ret);
    Result := ret;
end;







end.
