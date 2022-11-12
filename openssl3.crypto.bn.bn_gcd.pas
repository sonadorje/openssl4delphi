unit openssl3.crypto.bn.bn_gcd;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function int_bn_mod_inverse(_in : PBIGNUM;const in_a, n : PBIGNUM; ctx : PBN_CTX; pnoinv : PInteger):PBIGNUM;
function bn_mod_inverse_no_branch(_in : PBIGNUM;const in_a, n : PBIGNUM; ctx : PBN_CTX; pnoinv : PInteger):PBIGNUM;
function BN_mod_inverse(_in : PBIGNUM;const a, n : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
function BN_gcd(r : PBIGNUM;const in_a, in_b : PBIGNUM; ctx : PBN_CTX):integer;



implementation
uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.bn.bn_mod, openssl3.crypto.bn.bn_div,
     openssl3.crypto.bn.bn_mul,  openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_word,
     openssl3.crypto.evp.evp_rand, openssl3.crypto.bn.bn_add;


function BN_gcd(r : PBIGNUM;const in_a, in_b : PBIGNUM; ctx : PBN_CTX):integer;
var
  g, temp : PBIGNUM;
  mask : BN_ULONG;
  i, j, top, rlen, glen, m, bit,
  delta, shifts, cond, ret : integer;
  label _err;
begin
{$POINTERMATH ON}
    temp := nil;
    mask := 0;
    bit := 1;
    delta := 1;
    shifts := 0;
    ret := 0;
    { Note 2: zero input corner cases are not constant-time since they are
     * handled immediately. An attacker can run an attack under this
     * assumption without the need of side-channel information. }
    if BN_is_zero(in_b) then
    begin
        ret := Int(BN_copy(r, in_a) <> nil);
        r.neg := 0;
        Exit(ret);
    end;
    if BN_is_zero(in_a) then
    begin
        ret := Int(BN_copy(r, in_b) <> nil);
        r.neg := 0;
        Exit(ret);
    end;
    bn_check_top(in_a);
    bn_check_top(in_b);
    BN_CTX_start(ctx);
    temp := BN_CTX_get(ctx);
    g := BN_CTX_get(ctx);
    { make r <> 0, g <> 0 even, so BN_rshift is not a potential nop }
    if (g = nil)
         or  (0>= BN_lshift1(g, in_b))  or  (0>= BN_lshift1(r, in_a))  then
        goto _err ;
    { find shared powers of two, i.e. 'shifts' >= 1 }
    i := 0;
    while (i < r.dmax)  and  (i < g.dmax-1) do
    begin
        mask := not (r.d[i] or g.d[i]);
        for j := 0 to BN_BITS2-1 do
        begin
            bit := bit and mask;
            shifts  := shifts + bit;
            mask  := mask shr  1;
        end;
        Inc(i);
    end;
    if (0>= BN_rshift(r, r, shifts))  or  (0>= BN_rshift(g, g, shifts)) then
        goto _err ;
    { expand to biggest nword, with room for a possible extra word }
    top := 1 + get_result ((r.top >= g.top) , r.top , g.top);
    if (bn_wexpand(r, top) = nil)
         or  (bn_wexpand(g, top) = nil)
         or  (bn_wexpand(temp, top) = nil)  then
        goto _err ;
    { re arrange inputs s.t. r is odd }
    BN_consttime_swap((not r.d[0]) and 1, r, g, top);
    { compute the number of iterations }
    rlen := BN_num_bits(r);
    glen := BN_num_bits(g);
    m := 4 + 3 * get_result((rlen >= glen) , rlen , glen);
    for i := 0 to m-1 do
    begin
        { conditionally flip signs if delta is positive and g is odd }
        cond := (-delta  shr  (8 * sizeof(delta) - 1)) and g.d[0] and 1
            { make sure g.top > 0 (i.e. if top = 0 then g = 0 always) }
            and (not ((g.top - 1)  shr  (sizeof(g.top) * 8 - 1)));
        delta := (-cond and -delta) or ((cond - 1) and delta);
        r.neg  := r.neg xor cond;
        { swap }
        BN_consttime_swap(cond, r, g, top);
        { elimination step }
        PostInc(delta);
        if 0>= BN_add(temp, g, r )then
            goto _err ;
        BN_consttime_swap(g.d[0] and 1 { g is odd }
                { make sure g.top > 0 (i.e. if top = 0 then g = 0 always) }
                and (not ((g.top - 1)  shr  (sizeof(g.top) * 8 - 1))),
                g, temp, top);
        if 0>= BN_rshift1(g, g) then
            goto _err ;
    end;
    { remove possible negative sign }
    r.neg := 0;
    { add powers of 2 removed, then correct the artificial shift }
    if (0>= BN_lshift(r, r, shifts))  or  (0>= BN_rshift1(r, r))  then
        goto _err ;
    ret := 1;

 _err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    Result := ret;
 {$POINTERMATH OFF}
end;
(* solves ax == 1 (mod n) *)
function BN_mod_inverse(_in : PBIGNUM;const a, n : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
var
  new_ctx : PBN_CTX;
  rv : PBIGNUM;
  noinv : integer;
begin
    new_ctx := nil;
    noinv := 0;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(nil);
        ctx := new_ctx;
        if ctx = nil then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end;
    rv := int_bn_mod_inverse(_in, a, n, ctx, @noinv);
    if noinv>0 then
       ERR_raise(ERR_LIB_BN, BN_R_NO_INVERSE);
    BN_CTX_free(new_ctx);
    Result := rv;
end;

function bn_mod_inverse_no_branch(_in : PBIGNUM;const in_a, n : PBIGNUM; ctx : PBN_CTX; pnoinv : PInteger):PBIGNUM;
var
  A, B, X, Y, M, D, T, R, ret : PBIGNUM;
  sign : integer;
  local_B : TBIGNUM;
  tmp : PBIGNUM;
  localA : TBIGNUM;
  count: int;
  label _err;
begin
    R := nil;
    ret := nil;
    bn_check_top(in_a);
    bn_check_top(n);
    BN_CTX_start(ctx);
    A := BN_CTX_get(ctx);
    B := BN_CTX_get(ctx);
    X := BN_CTX_get(ctx);
    D := BN_CTX_get(ctx);
    M := BN_CTX_get(ctx);
    Y := BN_CTX_get(ctx);
    T := BN_CTX_get(ctx);
    if T = nil then
       goto _err ;
    if _in = nil then
       R := BN_new()
    else
       R := _in;
    if R = nil then
       goto _err ;
    BN_set_word(X,1); //BN_one(X);
    BN_zero(Y);
    if BN_copy(B, in_a) = nil  then
        goto _err ;
    if BN_copy(A, n) = nil then
        goto _err ;
    A.neg := 0;
    if (B.neg >0) or  (BN_ucmp(B, A ) >= 0)  then
    begin
        {
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
         * BN_div_no_branch will be called eventually.
         }

            bn_init(@local_B);
            BN_with_flags(@local_B, B, BN_FLG_CONSTTIME);
            if 0>= BN_nnmod(B, @local_B, A, ctx) then
                goto _err ;
            { Ensure local_B goes out of scope before any further use of B }

    end;
    sign := -1;
    {-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  =  B   (mod |n|),
     *      sign*Y*a  =  A   (mod |n|).
     }
     count:=0;
    while not BN_is_zero(B) do
    begin
        {-
         *      0 < B < A,
         * ( *) -sign*X*a  =  B   (mod |n|),
         *      sign*Y*a  =  A   (mod |n|)
         }
        {
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
         * BN_div_no_branch will be called eventually.
         }
        begin
            bn_init(@localA);
            BN_with_flags(@localA, A, BN_FLG_CONSTTIME);
            { (D, M) := (A/B, A%B) ... }
            if 0>= BN_div(D, M, @localA, B, ctx) then
                goto _err ;
            { Ensure localA goes out of scope before any further use of A }
        end;
        {-
         * Now
         *      A = D*B + M;
         * thus we have
         * ( **)  sign*Y*a  =  D*B + M   (mod |n|).
         }
        tmp := A;                { keep the BIGNUM object, the value does not
                                 * matter }
        { (A, B) := (B, A mod B) ... }
        A := B;
        B := M;
        { ... so we have  0 <= B < A  again }
        {-
         * Since the former  M  is now  B  and the former  B  is now  A,
         * ( **) translates into
         *       sign*Y*a  =  D*A + B    (mod |n|),
         * i.e.
         *       sign*Y*a - D*A  =  B    (mod |n|).
         * Similarly, ( *) translates into
         *      -sign*X*a  =  A          (mod |n|).
         *
         * Thus,
         *   sign*Y*a + D*sign*X*a  =  B  (mod |n|),
         * i.e.
         *        sign*(Y + D*X)*a  =  B  (mod |n|).
         *
         * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
         *      -sign*X*a  =  B   (mod |n|),
         *       sign*Y*a  =  A   (mod |n|).
         * Note that  X  and  Y  stay non-negative all the time.
         }
         Inc(count);
        if 0>= BN_mul(tmp, D, X, ctx) then
            goto _err ;

        if 0>= BN_add(tmp, tmp, Y) then
            goto _err ;
        M := Y;                  { keep the BIGNUM object, the value does not
                                 * matter }
        Y := X;
        X := tmp;
        sign := -sign;
    end;
    {-
     * The while loop (Euclid's algorithm) ends when
     *      A = gcd(a,n);
     * we have
     *       sign*Y*a  =  A  (mod |n|),
     * where  Y  is non-negative.
     }
    if sign < 0 then
    begin
        if 0>= BN_sub(Y, n, Y) then
           goto _err ;
    end;
    { Now  Y*a  =  A  (mod |n|).  }
    if BN_is_one(A )then
    begin
        { Y*a = 1  (mod |n|) }
        if (0>= Y.neg)  and  (BN_ucmp(Y, n) < 0) then
        begin
            if nil = BN_copy(R, Y) then
                goto _err ;
        end
        else
        begin
            if 0>= BN_nnmod(R, Y, n, ctx)  then
                goto _err ;
        end;
    end
    else
    begin
        pnoinv^ := 1;
        { caller sets the BN_R_NO_INVERSE error }
        goto _err ;
    end;
    ret := R;
    pnoinv^ := 0;

 _err:
    if (ret = nil) and  (_in = nil) then
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    Result := ret;
end;


function int_bn_mod_inverse(_in : PBIGNUM;const in_a, n : PBIGNUM; ctx : PBN_CTX; pnoinv : PInteger):PBIGNUM;
var
  A, B, X, Y, M, D, T, R, ret : PBIGNUM;
  sign, shift : integer;
  tmp : PBIGNUM;
  label _err;
begin
{$POINTERMATH ON}
    R := nil;
    ret := nil;
    { This is invalid input so we don't worry about constant time here }
    if (BN_abs_is_word(n, 1))  or  (BN_is_zero(n)) then
    begin
        pnoinv^ := 1;
        Exit(nil);
    end;
    pnoinv^ := 0;
    if (BN_get_flags(in_a, BN_FLG_CONSTTIME) <> 0)  or
       (BN_get_flags(n, BN_FLG_CONSTTIME) <> 0) then
    begin
        Exit(bn_mod_inverse_no_branch(_in, in_a, n, ctx, pnoinv));
    end;
    bn_check_top(in_a);
    bn_check_top(n);
    BN_CTX_start(ctx);
    A := BN_CTX_get(ctx);
    B := BN_CTX_get(ctx);
    X := BN_CTX_get(ctx);
    D := BN_CTX_get(ctx);
    M := BN_CTX_get(ctx);
    Y := BN_CTX_get(ctx);
    T := BN_CTX_get(ctx);
    if T = nil then
       goto _err ;
    if _in = nil then
       R := BN_new()
    else
        R := _in;
    if R = nil then
       goto _err ;
    BN_set_word(X,1);//BN_one(X);
    BN_zero(Y);
    if BN_copy(B, in_a) = nil then
        goto _err ;
    if BN_copy(A, n) = nil then
        goto _err ;
    A.neg := 0;
    if (B.neg >0)  or  (BN_ucmp(B, A) >= 0) then
    begin
        if 0>= BN_nnmod(B, B, A, ctx) then
            goto _err ;
    end;
    sign := -1;

    {-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  =  B   (mod |n|),
     *      sign*Y*a  =  A   (mod |n|).
     }
    if (BN_is_odd(n))  and  (BN_num_bits(n) <= 2048)  then
    begin
        {
         * than the general algorithm if the modulus is sufficiently small
         * (about 400 .. 500 bits on 32-bit systems, but much more on 64-bit
         * systems)
         }
        while not BN_is_zero(B) do
        begin
            {-
             *      0 < B < |n|,
             *      0 < A <= |n|,
             * (1) -sign*X*a  =  B   (mod |n|),
             * (2)  sign*Y*a  =  A   (mod |n|)
             }
            {
             * Now divide B by the maximum possible power of two in the
             * integers, and divide X by the same value mod |n|. When we're
             * done, (1) still holds.
             }
            shift := 0;
            while 0>= BN_is_bit_set(B, shift) do
            begin  { note that 0 < B }
                Inc(shift);
                if BN_is_odd(X)  then
                begin
                    if 0>= BN_uadd(X, X, n) then  goto _err ;
                end;
                {
                 * now X is even, so we can easily divide it by two
                 }
                if 0>= BN_rshift1(X, X ) then goto _err ;
            end;
            if shift > 0 then
            begin
                if 0>= BN_rshift(B, B, shift) then goto _err ;
            end;
            {
             * Same for A and Y.  Afterwards, (2) still holds.
             }
            shift := 0;
            while 0>= BN_is_bit_set(A, shift) do
            begin  { note that 0 < A }
                PostInc(shift);
                if BN_is_odd(Y)  then
                begin
                    if 0>= BN_uadd(Y, Y, n) then goto _err ;
                end;
                { now Y is even }
                if 0>= BN_rshift1(Y, Y) then goto _err ;
            end;
            if shift > 0 then
            begin
                if 0>= BN_rshift(A, A, shift) then goto _err ;
            end;
            {-
             * We still have (1) and (2).
             * Both  A  and  B  are odd.
             * The following computations ensure that
             *
             *     0 <= B < |n|,
             *      0 < A < |n|,
             * (1) -sign*X*a  =  B   (mod |n|),
             * (2)  sign*Y*a  =  A   (mod |n|),
             *
             * and that either  A  or  B  is even in the next iteration.
             }
            if BN_ucmp(B, A ) >= 0 then
            begin
                { -sign*(X + Y)*a = B - A  (mod |n|) }
                if 0>= BN_uadd(X, X, Y) then goto _err ;
                {
                 * NB: we could use BN_mod_add_quick(X, X, Y, n), but that
                 * actually makes the algorithm slower
                 }
                if 0>= BN_usub(B, B, A )then goto _err ;
            end
            else
            begin
                {  sign*(X + Y)*a = A - B  (mod |n|) }
                if 0>= BN_uadd(Y, Y, X )then goto _err ;
                { * as above, BN_mod_add_quick(Y, Y, X, n) would slow things down}
                if 0>= BN_usub(A, A, B) then goto _err ;
            end;
        end; //-->while not BN_is_zero(B)

    end //-->if (BN_is_odd(n))  and  (BN_num_bits(n) <= 2048)
    else
    begin
        { general inversion algorithm }
        while not BN_is_zero(B) do
        begin
            {-
             *      0 < B < A,
             * ( *) -sign*X*a  =  B   (mod |n|),
             *      sign*Y*a  =  A   (mod |n|)
             }
            { (D, M) := (A/B, A%B) ... }
            if BN_num_bits(A) = BN_num_bits(B)  then
            begin
                if 0>= BN_set_word(D,1) then goto _err ;
                if 0>= BN_sub(M, A, B) then  goto _err ;
            end
            else
            if (BN_num_bits(A) = BN_num_bits(B) + 1) then
            begin
                { A/B is 1, 2, or 3 }
                if 0>= BN_lshift1(T, B) then goto _err ;
                if BN_ucmp(A, T) < 0  then
                begin
                    { A < 2*B, so D=1 }
                    if 0>= BN_set_word(D,1) then//BN_one(D) then
                        goto _err ;
                    if 0>= BN_sub(M, A, B) then
                        goto _err ;
                end
                else
                begin
                    { A >= 2*B, so D=2 or D=3 }
                    if 0>= BN_sub(M, A, T) then
                        goto _err ;
                    if 0>= BN_add(D, T, B)  then
                        goto _err ; { use D (:= 3*B) as temp }
                    if BN_ucmp(A, D) < 0  then
                    begin
                        { A < 3*B, so D=2 }
                        if 0>= BN_set_word(D, 2) then
                            goto _err ;
                        {* M (= A - 2*B) already has the correct value }
                    end
                    else
                    begin
                        { only D=3 remains }
                        if 0>= BN_set_word(D, 3) then
                            goto _err ;
                        {* currently M = A - 2*B, but we need M = A - 3*B }
                        if 0>= BN_sub(M, M, B) then goto _err ;
                    end;
                end;
            end
            else
            begin
                if 0>= BN_div(D, M, A, B, ctx) then goto _err ;
            end;
            {-
             * Now
             *      A = D*B + M;
             * thus we have
             * ( **)  sign*Y*a  =  D*B + M   (mod |n|).
             }
            tmp := A;    { keep the BIGNUM object, the value does not matter }
            { (A, B) := (B, A mod B) ... }
            A := B;
            B := M;
            { ... so we have  0 <= B < A  again }
            {-
             * Since the former  M  is now  B  and the former  B  is now  A,
             * ( **) translates into
             *       sign*Y*a  =  D*A + B    (mod |n|),
             * i.e.
             *       sign*Y*a - D*A  =  B    (mod |n|).
             * Similarly, ( *) translates into
             *      -sign*X*a  =  A          (mod |n|).
             *
             * Thus,
             *   sign*Y*a + D*sign*X*a  =  B  (mod |n|),
             * i.e.
             *        sign*(Y + D*X)*a  =  B  (mod |n|).
             *
             * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
             *      -sign*X*a  =  B   (mod |n|),
             *       sign*Y*a  =  A   (mod |n|).
             * Note that  X  and  Y  stay non-negative all the time.
             }
            {
             * most of the time D is very small, so we can optimize tmp := D*X+Y
             }
            if BN_is_one(D) then
            begin
                if 0>= BN_add(tmp, X, Y) then goto _err ;
            end
            else
            begin
                if BN_is_word(D, 2) then
                begin
                    if 0>= BN_lshift1(tmp, X) then goto _err ;
                end
                else
                if (BN_is_word(D, 4)) then
                begin
                    if 0>= BN_lshift(tmp, X, 2) then goto _err ;
                end
                else
                if (D.top = 1) then
                begin
                    if nil = BN_copy(tmp, X) then   goto _err ;
                    if 0>= BN_mul_word(tmp, D.d[0]) then  goto _err ;
                end
                else
                begin
                    if 0>= BN_mul(tmp, D, X, ctx) then goto _err ;
                end;
                if 0>= BN_add(tmp, tmp, Y) then goto _err ;
            end;
            M := Y;      { keep the BIGNUM object, the value does not matter }
            Y := X;
            X := tmp;
            sign := -sign;
        end; //-->while not BN_is_zero(B)

    end;
    {-
     * The while loop (Euclid's algorithm) ends when
     *      A = gcd(a,n);
     * we have
     *       sign*Y*a  =  A  (mod |n|),
     * where  Y  is non-negative.
     }
   
    if sign < 0 then
    begin
        if 0>= BN_sub(Y, n, Y) then  goto _err ;
    end;

    { Now  Y*a  =  A  (mod |n|).  }
    if BN_is_one(A)  then
    begin
        { Y*a = 1  (mod |n|) }
        if (0>= Y.neg)  and  (BN_ucmp(Y, n) < 0) then
        begin
            if nil = BN_copy(R, Y) then  goto _err ;
        end
        else
        begin
            if 0>= BN_nnmod(R, Y, n, ctx )then goto _err ;
        end;
       
    end
    else
    begin
        pnoinv^ := 1;
        goto _err ;
    end;
    ret := R;
    //var t1: BN_ULONG := R.d[0];
 _err:
    if (ret = nil)  and  (_in = nil) then
        BN_free(R);

    BN_CTX_end(ctx);
    bn_check_top(ret);
    Result := ret;
 {$POINTERMATH OFF}
end;

end.
