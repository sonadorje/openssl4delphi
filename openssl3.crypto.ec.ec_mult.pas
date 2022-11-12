unit openssl3.crypto.ec.ec_mult;

interface
uses OpenSSL.Api;

function ossl_ec_wNAF_mul(const group : PEC_GROUP; r : PEC_POINT;const scalar : PBIGNUM; num : size_t;const points : PPEC_POINT;const scalars : PPBIGNUM; ctx : PBN_CTX):integer;
 function ossl_ec_scalar_mul_ladder(const group : PEC_GROUP; r : PEC_POINT;const scalar : PBIGNUM; point : PEC_POINT; ctx : PBN_CTX):integer;
 function EC_ec_pre_comp_dup( pre : PEC_PRE_COMP):PEC_PRE_COMP;
 procedure EC_ec_pre_comp_free( pre : PEC_PRE_COMP);

implementation
 uses openssl3.crypto.ec.ec_lib, openssl3.crypto.ec.ec_key,
      openssl3.crypto.ec.ecdh_ossl, openssl3.crypto.ec.ecdsa_ossl,
      openssl3.crypto.bn.bn_intern, openssl3.crypto.bn.bn_gf2m,
      OpenSSL3.Err,  openssl3.crypto.bn.bn_rand,
      openssl3.include.internal.refcount,
      OpenSSL3.threads_none,
      openssl3.crypto.bn.bn_add, openssl3.crypto.mem,
      openssl3.crypto.bn.bn_mul, openssl3.crypto.bn.bn_mod,
      openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx;


procedure EC_ec_pre_comp_free( pre : PEC_PRE_COMP);
var
  i : integer;

  pts : PPEC_POINT;
begin
    if pre = nil then exit;
    CRYPTO_DOWN_REF(pre.references, i, pre.lock);
    REF_PRINT_COUNT('EC_ec', pre);
    if i > 0 then exit;
    REF_ASSERT_ISNT(i < 0);
    if pre.points <> nil then
    begin
        pts := pre.points;
        while (pts^ <> nil) do
        begin
            EC_POINT_free(pts^);
            Inc(pts);
        end;
        OPENSSL_free(Pointer(pre.points));
    end;
    CRYPTO_THREAD_lock_free(pre.lock);
    OPENSSL_free(Pointer(pre));
end;
function EC_ec_pre_comp_dup( pre : PEC_PRE_COMP):PEC_PRE_COMP;
var
  i : integer;
begin
    if pre <> nil then
       CRYPTO_UP_REF(pre.references, i, pre.lock);
    Result := pre;
end;

function EC_window_bits_for_scalar_size(b: size_t):size_t;
begin
   Result :=  size_t(
       get_result(b >= 2000 , 6 ,
       get_result( b >=  800 , 5 ,
       get_result( b >=  300 , 4 ,
       get_result( b >=   70 , 3 ,
       get_result( b >=   20 , 2 ,
        1))))))
end;

function ossl_ec_scalar_mul_ladder(const group : PEC_GROUP; r : PEC_POINT;const scalar : PBIGNUM; point : PEC_POINT; ctx : PBN_CTX):integer;
var
  i,
  cardinality_bits,
  group_top,
  kbit,
  pbit,
  Z_is_one         : integer;
  p,
  s                : PEC_POINT;
  k,
  lambda,
  cardinality      : PBIGNUM;
  ret              : integer;
  label _err;

  procedure EC_POINT_BN_set_flags(P: PEC_POINT; flags: int) ;
  begin
    BN_set_flags(P.X, (flags));
    BN_set_flags(P.Y, (flags));
    BN_set_flags(P.Z, (flags));
  end;

  procedure EC_POINT_CSWAP(c: int; a, b: PEC_POINT; w:int; var t: int);
  begin
        BN_consttime_swap(c, a.X, b.X, w);
        BN_consttime_swap(c, a.Y, b.Y, w);
        BN_consttime_swap(c, a.Z, b.Z, w);
        t := (a.Z_is_one xor b.Z_is_one) and (c);
        a.Z_is_one := a.Z_is_one xor (t);
        b.Z_is_one := b.Z_is_one xor (t);
  end;

begin
    p := nil;
    s := nil;
    k := nil;
    lambda := nil;
    cardinality := nil;
    ret := 0;
    { early exit if the input point is the point at infinity }
    if (point <> nil)  and  (EC_POINT_is_at_infinity(group, point)>0) then
        Exit(EC_POINT_set_to_infinity(group, r));
    if BN_is_zero(group.order)  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_ORDER);
        Exit(0);
    end;
    if BN_is_zero(group.cofactor) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_COFACTOR);
        Exit(0);
    end;
    BN_CTX_start(ctx);
    p := EC_POINT_new(group);
    s := EC_POINT_new(group);
    if (p = nil) or  (s = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if point = nil then
    begin
        if 0>= EC_POINT_copy(p, group.generator) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end
    else
    begin
        if 0>= EC_POINT_copy(p, point) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end;
    EC_POINT_BN_set_flags(p, BN_FLG_CONSTTIME);
    EC_POINT_BN_set_flags(r, BN_FLG_CONSTTIME);
    EC_POINT_BN_set_flags(s, BN_FLG_CONSTTIME);
    cardinality := BN_CTX_get(ctx);
    lambda := BN_CTX_get(ctx);
    k := BN_CTX_get(ctx);
    if k = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if 0>= BN_mul(cardinality, group.order, group.cofactor, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    {
     * Group cardinalities are often on a word boundary.
     * So when we pad the scalar, some timing diff might
     * pop if it needs to be expanded due to carries.
     * So expand ahead of time.
     }
    cardinality_bits := BN_num_bits(cardinality);
    group_top := bn_get_top(cardinality);
    if (bn_wexpand(k, group_top + 2)= nil)   or
       (bn_wexpand(lambda, group_top + 2) = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    if nil = BN_copy(k, scalar) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    BN_set_flags(k, BN_FLG_CONSTTIME);
    if (BN_num_bits(k) > cardinality_bits)  or  (BN_is_negative(k)>0) then
    begin
        {-
         * this is an unusual input, and we don't guarantee
         * constant-timeness
         }
        if 0>= BN_nnmod(k, k, cardinality, ctx) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto _err ;
        end;
    end;
    if 0>= BN_add(lambda, k, cardinality) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    if 0>= BN_add(k, lambda, cardinality) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    {
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     }
    kbit := BN_is_bit_set(lambda, cardinality_bits);
    BN_consttime_swap(kbit, k, lambda, group_top + 2);
    group_top := bn_get_top(group.field);
    if (bn_wexpand(s.X, group_top) = nil)
         or  (bn_wexpand(s.Y, group_top) = nil)
         or  (bn_wexpand(s.Z, group_top) = nil)
         or  (bn_wexpand(r.X, group_top) = nil)
         or  (bn_wexpand(r.Y, group_top) = nil)
         or  (bn_wexpand(r.Z, group_top) = nil)
         or  (bn_wexpand(p.X, group_top) = nil)
         or  (bn_wexpand(p.Y, group_top) = nil)
         or  (bn_wexpand(p.Z, group_top) = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { ensure input point is in affine coords for ladder step efficiency }
    if (0>= p.Z_is_one)  and ( (not Assigned(group.meth.make_affine))
                          or   (0>= group.meth.make_affine(group, p, ctx)) ) then
    begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
    end;
    { Initialize the Montgomery ladder }
    if 0>= ec_point_ladder_pre(group, r, s, p, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_LADDER_PRE_FAILURE);
        goto _err ;
    end;
    { top bit is a 1, in a fixed pos }
    pbit := 1;
    {-
     * The ladder step, with branches, is
     *
     * k[i] = 0: S = add(R, S), R = dbl(R)
     * k[i] = 1: R = add(S, R), S = dbl(S)
     *
     * Swapping R, S conditionally on k[i] leaves you with state
     *
     * k[i] = 0: T, U = R, S
     * k[i] = 1: T, U = S, R
     *
     * Then perform the ECC ops.
     *
     * U = add(T, U)
     * T = dbl(T)
     *
     * Which leaves you with state
     *
     * k[i] = 0: U = add(R, S), T = dbl(R)
     * k[i] = 1: U = add(S, R), T = dbl(S)
     *
     * Swapping T, U conditionally on k[i] leaves you with state
     *
     * k[i] = 0: R, S = T, U
     * k[i] = 1: R, S = U, T
     *
     * Which leaves you with state
     *
     * k[i] = 0: S = add(R, S), R = dbl(R)
     * k[i] = 1: R = add(S, R), S = dbl(S)
     *
     * So we get the same logic, but instead of a branch it's a
     * conditional swap, followed by ECC ops, then another conditional swap.
     *
     * Optimization: The end of iteration i and start of i-1 looks like
     *
     * ...
     * CSWAP(k[i], R, S)
     * ECC
     * CSWAP(k[i], R, S)
     * (next iteration)
     * CSWAP(k[i-1], R, S)
     * ECC
     * CSWAP(k[i-1], R, S)
     * ...
     *
     * So instead of two contiguous swaps, you can merge the condition
     * bits and do a single swap.
     *
     * k[i]   k[i-1]    Outcome
     * 0      0         No Swap
     * 0      1         Swap
     * 1      0         Swap
     * 1      1         No Swap
     *
     * This is XOR. pbit tracks the previous bit of k.
     }
    for i := cardinality_bits - 1 downto 0 do
    begin
        kbit := BN_is_bit_set(k, i)  xor  pbit;
        EC_POINT_CSWAP(kbit, r, s, group_top, Z_is_one);
        { Perform a single step of the Montgomery ladder }
        if 0>= ec_point_ladder_step(group, r, s, p, ctx) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_LADDER_STEP_FAILURE);
            goto _err ;
        end;
        {
         * pbit logic merges this cswap with that of the
         * next iteration
         }
        pbit  := pbit xor kbit;
    end;
    { one final cswap to move the right value into r }
    EC_POINT_CSWAP(pbit, r, s, group_top, Z_is_one);

    { Finalize ladder (and recover full point coordinates) }
    if 0>= ec_point_ladder_post(group, r, s, p, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_LADDER_POST_FAILURE);
        goto _err ;
    end;
    ret := 1;
 _err:
    EC_POINT_free(p);
    EC_POINT_clear_free(s);
    BN_CTX_end(ctx);
    Result := ret;
end;

function ossl_ec_wNAF_mul(const group : PEC_GROUP; r : PEC_POINT;const scalar : PBIGNUM; num : size_t;const points : PPEC_POINT; const scalars : PPBIGNUM; ctx : PBN_CTX):integer;
var
  generator,
  tmp                  : PEC_POINT;

  totalnum,
  blocksize, numblocks,
  pre_points_per_block,
  i,
  j                    : size_t;

  k,
  r_is_inverted,
  r_is_at_infinity     : integer;
  wsize                : Psize_t;
  wNAF                 : PPint8;
  wNAF_len             : Psize_t;
  max_len,
  num_val              : size_t;
  val,
  v                    : PPEC_POINT;
  val_sub              : PPPEC_POINT;
  pre_comp             : PEC_PRE_COMP;
  num_scalar,
  ret                  : integer;
  bits                 : size_t;
  tmp_wNAF             : Pint8;
  tmp_len              : size_t;
  pp                   : Pint8;
  tmp_points           : PPEC_POINT;
  digit,
  is_neg               : integer;
  w                    : PPint8;
  label _err;
begin
{$POINTERMATH ON}
    generator := nil;
    tmp := nil;
    blocksize := 0; numblocks := 0;
    pre_points_per_block := 0;
    r_is_inverted := 0;
    r_is_at_infinity := 1;
    wsize := nil;
    wNAF := nil;
    wNAF_len := nil;
    max_len := 0;
    val := nil;
     val_sub := nil;
                                 { 'pre_comp.points' }
    pre_comp := nil;
    num_scalar := 0;
                                 { treated like other scalars, i.e.
                                  precomputation is not available }
    ret := 0;
    if (not BN_is_zero(group.order))  and  (not BN_is_zero(group.cofactor))  then
    begin
        {-
         * Handle the common cases where the scalar is secret, enforcing a
         * scalar multiplication implementation based on a Montgomery ladder,
         * with various timing attack defenses.
         }
        if (scalar <> group.order)  and  (scalar <> nil)  and  (num = 0) then  begin
            {-
             * In this case we want to compute scalar * GeneratorPoint: this
             * codepath is reached most prominently by (ephemeral) key
             * generation of EC cryptosystems (i.e. ECDSA keygen and sign setup,
             * ECDH keygen/first half), where the scalar is always secret. This
             * is why we ignore if BN_FLG_CONSTTIME is actually set and we
             * always call the ladder version.
             }
            Exit(ossl_ec_scalar_mul_ladder(group, r, scalar, nil, ctx));
        end;
        if (scalar = nil)  and  (num = 1)  and  (scalars[0] <> group.order) then
        begin
            {-
             * In this case we want to compute scalar * VariablePoint: this
             * codepath is reached most prominently by the second half of ECDH,
             * where the secret scalar is multiplied by the peer's public point.
             * To protect the secret scalar, we ignore if BN_FLG_CONSTTIME is
             * actually set and we always call the ladder version.
             }
            Exit(ossl_ec_scalar_mul_ladder(group, r, scalars[0], points[0], ctx));
        end;
    end;
    if scalar <> nil then
    begin
        generator := EC_GROUP_get0_generator(group);
        if generator = nil then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
            goto _err ;
        end;
        { look if we can use precomputed multiples of generator }
        pre_comp := group.pre_comp.ec;
        if (pre_comp <> nil)  and  (pre_comp.numblocks>0)
             and  (EC_POINT_cmp(group, generator, pre_comp.points[0], ctx ) =
                0) then
        begin
            blocksize := pre_comp.blocksize;
            {
             * determine maximum number of blocks that wNAF splitting may
             * yield (NB: maximum wNAF length is bit length plus one)
             }
            numblocks := (BN_num_bits(scalar) div blocksize) + 1;
            {
             * we cannot use more blocks than we have precomputation for
             }
            if numblocks > pre_comp.numblocks then
               numblocks := pre_comp.numblocks;
            pre_points_per_block := size_t( 1  shl  (pre_comp.w - 1));
            { check that pre_comp looks sane }
            if pre_comp.num <> (pre_comp.numblocks * pre_points_per_block) then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
        end
        else
        begin
            { can't use precomputation }
            pre_comp := nil;
            numblocks := 1;
            num_scalar := 1;     { treat 'scalar' like 'num'-th element of
                                 * 'scalars' }
        end;
    end;
    totalnum := num + numblocks;
    wsize := OPENSSL_malloc(totalnum * sizeof(wsize[0]));
    wNAF_len := OPENSSL_malloc(totalnum * sizeof(wNAF_len[0]));
    { include space for pivot }
    wNAF := OPENSSL_malloc((totalnum + 1) * sizeof(wNAF[0]));
    val_sub := OPENSSL_malloc(totalnum * sizeof(val_sub[0]));
    { Ensure wNAF is initialised in case we end up going to err }
    if wNAF <> nil then wNAF[0] := nil;
    if (wsize = nil)  or  (wNAF_len = nil)  or  (wNAF = nil)  or  (val_sub = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    {
     * num_val will be the total number of temporarily precomputed points
     }
    num_val := 0;
    for i := 0 to num + num_scalar-1 do
    begin
        bits := get_result(i < num , BN_num_bits(scalars[i]) , BN_num_bits(scalar));
        wsize[i] := EC_window_bits_for_scalar_size(bits);
        num_val  := num_val + size_t( 1  shl  (wsize[i] - 1));
        wNAF[i + 1] := nil;     { make sure we always have a pivot }
        wNAF[i] := bn_compute_wNAF( get_result(i < num , scalars[i] , scalar), wsize[i],
                            @wNAF_len[i]);
        if wNAF[i] = nil then goto _err ;
        if wNAF_len[i] > max_len then
           max_len := wNAF_len[i];
    end;
    if numblocks > 0 then
    begin
        { we go here iff scalar <> nil }
        if pre_comp = nil then
        begin
            if num_scalar <> 1 then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
            { we have already generated a wNAF for 'scalar' }
        end
        else
        begin
            tmp_wNAF := nil;
            tmp_len := 0;
            if num_scalar <> 0 then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
            {
             * use the window size for which we have precomputation
             }
            wsize[num] := pre_comp.w;
            tmp_wNAF := bn_compute_wNAF(scalar, wsize[num], @tmp_len);
            if nil = tmp_wNAF then goto _err ;
            if tmp_len <= max_len then
            begin
                {
                 * One of the other wNAFs is at least as long as the wNAF
                 * belonging to the generator, so wNAF splitting will not buy
                 * us anything.
                 }
                numblocks := 1;
                totalnum := num + 1; { don't use wNAF splitting }
                wNAF[num] := tmp_wNAF;
                wNAF[num + 1] := nil;
                wNAF_len[num] := tmp_len;
                {
                 * pre_comp.points starts with the points that we need here:
                 }
                val_sub[num] := pre_comp.points;
            end
            else
            begin
                {
                 * don't include tmp_wNAF directly into wNAF array - use wNAF
                 * splitting and include the blocks
                 }
                if tmp_len < numblocks * blocksize then
                begin
                    {
                     * possibly we can do with fewer blocks than estimated
                     }
                    numblocks := (tmp_len + blocksize - 1) div blocksize;
                    if numblocks > pre_comp.numblocks then
                    begin
                        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(Pointer(tmp_wNAF));
                        goto _err ;
                    end;
                    totalnum := num + numblocks;
                end;
                { split wNAF in 'numblocks' parts }
                pp := tmp_wNAF;
                tmp_points := pre_comp.points;
                for i := num to totalnum-1 do
                begin
                    if i < totalnum - 1 then
                    begin
                        wNAF_len[i] := blocksize;
                        if tmp_len < blocksize then
                        begin
                            ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                            OPENSSL_free(Pointer(tmp_wNAF));
                            goto _err ;
                        end;
                        tmp_len  := tmp_len - blocksize;
                    end
                    else
                        {
                         * last block gets whatever is left (this could be
                         * more or less than 'blocksize'!)
                         }
                        wNAF_len[i] := tmp_len;
                    wNAF[i + 1] := nil;
                    wNAF[i] := OPENSSL_malloc(wNAF_len[i]);
                    if wNAF[i] = nil then
                    begin
                        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                        OPENSSL_free(Pointer(tmp_wNAF));
                        goto _err ;
                    end;
                    memcpy(wNAF[i], pp, wNAF_len[i]);
                    if wNAF_len[i] > max_len then
                       max_len := wNAF_len[i];
                    if tmp_points^ = nil then
                    begin
                        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(Pointer(tmp_wNAF));
                        goto _err ;
                    end;
                    val_sub[i] := tmp_points;
                    tmp_points  := tmp_points + pre_points_per_block;
                    pp  := pp + blocksize;
                end;
                OPENSSL_free(Pointer(tmp_wNAF));
            end;
        end;
    end;
    {
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp.points' if we already have precomputation.
     }
    val := OPENSSL_malloc((num_val + 1) * sizeof(val[0]));
    if val = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    val[num_val] := nil;
    { allocate points for precomputation }
    v := val;
    for i := 0 to num + num_scalar-1 do
    begin
        val_sub[i] := v;
        for j := 0 to size_t( 1  shl  (wsize[i] - 1))-1 do
        begin
            v^ := EC_POINT_new(group);
            if v^ = nil then goto _err ;
            Inc(v);
        end;
    end;
    v := val + num_val;
    if nil = v then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    tmp := EC_POINT_new(group);
    if tmp = nil then
        goto _err ;
    {-
     * prepare precomputed values:
     *    val_sub[i][0] :=     points[i]
     *    val_sub[i][1] := 3 * points[i]
     *    val_sub[i][2] := 5 * points[i]
     *    ...
     }
    for i := 0 to num + num_scalar-1 do
    begin
        if i < num then
        begin
            if 0>= EC_POINT_copy(val_sub[i][0], points[i]) then
                goto _err ;
        end
        else
        begin
            if 0>= EC_POINT_copy(val_sub[i][0], generator) then
                goto _err ;
        end;
        if wsize[i] > 1 then
        begin
            if 0>= EC_POINT_dbl(group, tmp, val_sub[i][0], ctx) then
                goto _err ;
            for j := 1 to size_t( 1  shl  (wsize[i] - 1))-1 do
            begin
                if 0>= EC_POINT_add
                    (group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx ) then
                    goto _err ;
            end;
        end;
    end;
    if (not Assigned(group.meth.points_make_affine))
         or  (0>= group.meth.points_make_affine(group, num_val, val, ctx)) then
        goto _err ;
    r_is_at_infinity := 1;
    for k := max_len - 1 downto 0 do
    begin
        if 0>= r_is_at_infinity then
        begin
            if 0>= EC_POINT_dbl(group, r, r, ctx) then
                goto _err ;
        end;
        for i := 0 to totalnum-1 do
        begin
            if wNAF_len[i] > size_t( k) then
            begin
                digit := wNAF[i][k];
                if digit > 0 then
                begin
                    is_neg := Int(digit < 0);
                    if is_neg > 0 then
                       digit := -digit;
                    if is_neg <> r_is_inverted then
                    begin
                        if 0>= r_is_at_infinity then
                        begin
                            if 0>= EC_POINT_invert(group, r, ctx) then
                                goto _err ;
                        end;
                        r_is_inverted := not r_is_inverted;
                    end;
                    { digit > 0 }
                    if r_is_at_infinity > 0 then
                    begin
                        if 0>= EC_POINT_copy(r, val_sub[i][digit  shr  1]) then
                            goto _err ;
                        {-
                         * Apply coordinate blinding for EC_POINT.
                         *
                         * The underlying EC_METHOD can optionally implement this function:
                         * ossl_ec_point_blind_coordinates() returns 0 in case of errors or 1 on
                         * success or if coordinate blinding is not implemented for this
                         * group.
                         }
                        if 0>= ossl_ec_point_blind_coordinates(group, r, ctx) then
                        begin
                            ERR_raise(ERR_LIB_EC, EC_R_POINT_COORDINATES_BLIND_FAILURE);
                            goto _err ;
                        end;
                        r_is_at_infinity := 0;
                    end
                    else
                    begin
                        if 0>= EC_POINT_add
                            (group, r, r, val_sub[i][digit  shr  1], ctx) then
                            goto _err ;
                    end;
                end;
            end;
        end;
    end;
    if r_is_at_infinity > 0 then
    begin
        if 0>= EC_POINT_set_to_infinity(group, r) then
            goto _err ;
    end
    else
    begin
        if r_is_inverted > 0 then
           if (0>= EC_POINT_invert(group, r, ctx)) then
                goto _err ;
    end;
    ret := 1;
 _err:
    EC_POINT_free(tmp);
    OPENSSL_free(Pointer(wsize));
    OPENSSL_free(Pointer(wNAF_len));
    if wNAF <> nil then
    begin
        w := wNAF;
        while w^ <> nil do
        begin
            OPENSSL_free(Pointer(w^));
            Inc(w);
        end;
        OPENSSL_free(Pointer(wNAF));
    end;
    if val <> nil then
    begin
        v := val;
        while v^ <> nil do
        begin
            EC_POINT_clear_free(v^);
            Inc(v);
        end;
        OPENSSL_free(Pointer(val));
    end;
    OPENSSL_free(Pointer(val_sub));
    Result := ret;
 {$POINTERMATH OFF}
end;


end.
