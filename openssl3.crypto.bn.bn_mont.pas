unit openssl3.crypto.bn.bn_mont;

interface
 uses OpenSSL.Api;

{$define MONT_WORD}

function bn_mul_mont_fixed_top(r : PBIGNUM;const a, b : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
function BN_mod_mul_montgomery(r : PBIGNUM;const a, b : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
function BN_from_montgomery(dest : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
function bn_to_mont_fixed_top(r : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
function bn_from_mont_fixed_top(ret : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
function bn_from_montgomery_word( ret, r : PBIGNUM; mont : PBN_MONT_CTX):integer;
function BN_MONT_CTX_new:PBN_MONT_CTX;
procedure BN_MONT_CTX_init( ctx : PBN_MONT_CTX);
procedure BN_MONT_CTX_free( mont : PBN_MONT_CTX);
function BN_MONT_CTX_set(mont : PBN_MONT_CTX;const _mod : PBIGNUM; ctx : PBN_CTX):integer;
function BN_MONT_CTX_set_locked(pmont : PPBN_MONT_CTX; lock : PCRYPTO_RWLOCK;const _mod : PBIGNUM; ctx : PBN_CTX):PBN_MONT_CTX;
function BN_MONT_CTX_copy( _to, from : PBN_MONT_CTX):PBN_MONT_CTX;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_asm, openssl3.crypto.bn.bn_gcd,
     openssl3.crypto.bn.bn_div,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_word,
     openssl3.crypto.bn.bn_sqr, openssl3.crypto.bn.bn_mul;

//{$RANGECHECKS OFF}
function BN_MONT_CTX_copy( _to, from : PBN_MONT_CTX):PBN_MONT_CTX;
begin
    if _to = from then Exit(_to);
    if nil = BN_copy(PBIGNUM(@_to.RR), PBIGNUM(@from.RR))  then
        Exit(nil);
    if nil = BN_copy(@_to.N, @from.N) then
        Exit(nil);
    if nil = BN_copy(@_to.Ni, @from.Ni) then
        Exit(nil);
    _to.ri := from.ri;
    _to.n0[0] := from.n0[0];
    _to.n0[1] := from.n0[1];
    Result := _to;
end;

function BN_MONT_CTX_set_locked(pmont : PPBN_MONT_CTX; lock : PCRYPTO_RWLOCK;const _mod : PBIGNUM; ctx : PBN_CTX):PBN_MONT_CTX;
var
  ret : PBN_MONT_CTX;
begin
    if 0>= CRYPTO_THREAD_read_lock(lock) then
        Exit(nil);
    ret := pmont^;
    CRYPTO_THREAD_unlock(lock);
    if ret <> nil then Exit(ret);
    {
     * We don't want to serialize globally while doing our lazy-init math in
     * BN_MONT_CTX_set. That punishes threads that are doing independent
     * things. Instead, punish the case where more than one thread tries to
     * lazy-init the same 'pmont', by having each do the lazy-init math work
     * independently and only use the one from the thread that wins the race
     * (the losers throw away the work they've done).
     }
    ret := BN_MONT_CTX_new();
    if ret = nil then Exit(nil);

    //breakpoint
    if 0>= BN_MONT_CTX_set(ret, _mod, ctx )then
    begin
        BN_MONT_CTX_free(ret);
        Exit(nil);
    end;
    { The locked compare-and-set, after the local work is done. }
    if 0>= CRYPTO_THREAD_write_lock(lock) then
    begin
        BN_MONT_CTX_free(ret);
        Exit(nil);
    end;
    if pmont^ <> nil then
    begin
        BN_MONT_CTX_free(ret);
        ret := pmont^;
    end
    else
        pmont^ := ret;
    CRYPTO_THREAD_unlock(lock);
    Result := ret;
end;


function BN_MONT_CTX_set(mont : PBN_MONT_CTX;const _mod : PBIGNUM; ctx : PBN_CTX):integer;
var
  i, ret : integer;
  Ri, R : PBIGNUM;
  tmod : TBIGNUM;
  buf : array[0..1] of BN_ULONG;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0;
    if BN_is_zero(_mod) then
        Exit(0);
    BN_CTX_start(ctx);
    Ri := BN_CTX_get(ctx);
    if Ri = nil then
        goto _err ;
    R := @(mont.RR);            { grab RR as a temp }
    if nil = BN_copy(@mont.N, _mod) then
        goto _err ;               { Set N }
    if BN_get_flags(_mod, BN_FLG_CONSTTIME) <> 0  then
        BN_set_flags(@(mont.N), BN_FLG_CONSTTIME);
    mont.N.neg := 0;
{$IFDEF MONT_WORD}
    begin
        bn_init(@tmod);

        tmod.d := @buf;
        tmod.dmax := 2;
        tmod.neg := 0;
        if BN_get_flags(_mod, BN_FLG_CONSTTIME) <> 0  then
           BN_set_flags(@tmod, BN_FLG_CONSTTIME);
        mont.ri := (BN_num_bits(_mod) + (BN_BITS2 - 1)) div BN_BITS2 * BN_BITS2;
{$IF defined(OPENSSL_BN_ASM_MONT)  and  (BN_BITS2<=32)}
  {
    Only certain BN_BITS2<=32 platforms actually make use of n0[1],
    and we could use the #else case (with a shorter R value) for the
    others.  However, currently only the assembler files do know which
    is which.
   }
  BN_zero(R);
  if 0>= (BN_set_bit(R, 2 * BN_BITS2))  then
      goto_err ;
  tmod.top := 0;
  if buf[0] = &mod.d[0] then  then
      tmod.top := 1;
  if buf[1] = &mod.top > 1 ? &mod.d[1] : 0 then  then
      tmod.top := 2;
  if BN_is_one(&tmod then )
      BN_zero(Ri);
  else if ((BN_mod_inverse(Ri, R, &tmod, ctx)) = nil)
      goto_err ;
  if 0>= BN_lshift(Ri, Ri, 2 * BN_BITS2 then )
      goto_err ;           { R x Ri }
  if 0>= BN_is_zero(Ri then ) begin
      if 0>= BN_sub_word(Ri, 1) then
          goto_err ;
  end;
  else
  begin                 { if N mod word size = 1 }
      if bn_expand(Ri, int sizeof(BN_ULONG then * 2) = nil)
          goto_err ;
      { PostDec(Ri) (mod double word size) }
      Ri.neg := 0;
      Ri.d[0] := BN_MASK2;
      Ri.d[1] := BN_MASK2;
      Ri.top := 2;
  end;
  if 0>= BN_div(Ri, nil, Ri, &tmod, ctx then )
      goto_err ;
  {
    Ni = (R*Ri-1)/N, keep only couple of least significant words:
   }
  mont.n0[0] := (Ri.top > 0) ? Ri.d[0] : 0;
  mont.n0[1] := (Ri.top > 1) ? Ri.d[1] : 0;
{$ELSE}
        BN_zero(R);
        if 0>= BN_set_bit(R, BN_BITS2 ) then
            goto _err ;           { R }
        buf[0] := _mod.d[0];
        buf[1] := 0;
       
        tmod.top := get_result( buf[0] <> 0 , 1 , 0);
        { Ri = R^-1 mod N }
        if BN_is_one(@tmod) then
            BN_zero(Ri)
        else  //breakpt
        if BN_mod_inverse(Ri, R, @tmod, ctx) = nil then
            goto _err ;
       
        if 0>= BN_lshift(Ri, Ri, BN_BITS2) then
            goto _err ;           { R*Ri }
        if not BN_is_zero(Ri) then
        begin
            if 0>= BN_sub_word(Ri, 1) then
                goto _err ;
        end
        else
        begin                 { if N mod word size = 1 }
            if 0>= BN_set_word(Ri, BN_MASK2) then
                goto _err ;       { PostDec(Ri) (mod word size) }
        end;
        if 0>= BN_div(Ri, nil, Ri, @tmod, ctx) then
            goto _err ;
        {
         * Ni = (R*Ri-1)/N, keep only least significant word:
         }
        mont.n0[0] := get_result(Ri.top > 0 , Ri.d[0] , 0);
        mont.n0[1] := 0;
{$ENDIF}
    end;
{$ELSE} { !MONT_WORD }
    begin                            { bignum version }
        mont.ri := BN_num_bits(@mont.N);
        BN_zero(R);
        if 0>= BN_set_bit(R, mont.ri) then
            goto _err ;           { R = 2^ri }
        { Ri = R^-1 mod N }
        if BN_mod_inverse(Ri, R, @mont.N, ctx) = nil then
            goto _err ;
        if 0>= BN_lshift(Ri, Ri, mont.ri) then
            goto _err ;           { R*Ri }
        if 0>= BN_sub_word(Ri, 1) then
            goto _err ;
        {
         * Ni = (R*Ri-1) / N
         }
        if 0>= BN_div(@mont.Ni , nil, Ri, @mont.N, ctx) then
            goto _err ;
        
    end;
{$ENDIF}
    { setup RR for conversions }
    BN_zero(@mont.RR);
    if 0>= BN_set_bit(@mont.RR, mont.ri * 2)  then
        goto _err ;
    if 0>= BN_mod(@mont.RR, @mont.RR, @mont.N, ctx)  then
        goto _err ;
    i := mont.RR.top; ret := mont.N.top;
    while i < ret do
    begin
        mont.RR.d[i] := 0;
        Inc(i);
    end;
    mont.RR.top := ret;
    mont.RR.flags  := mont.RR.flags  or BN_FLG_FIXED_TOP;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
 {$POINTERMATH OFF}
end;

procedure BN_MONT_CTX_init( ctx : PBN_MONT_CTX);
begin
    ctx.ri := 0;
    bn_init(@ctx.RR);
    bn_init(@ctx.N);
    bn_init(@ctx.Ni);
    ctx.n0[0] := 0;
    ctx.n0[1] := 0;
    ctx.flags := 0;
end;


procedure BN_MONT_CTX_free( mont : PBN_MONT_CTX);
begin
    if mont = nil then exit;
    BN_clear_free(@mont.RR);
    BN_clear_free(@mont.N);
    BN_clear_free(@mont.Ni);
    if (mont.flags and BN_FLG_MALLOCED)>0 then
       OPENSSL_free(Pointer(mont));
end;


function BN_MONT_CTX_new:PBN_MONT_CTX;
var
  ret : PBN_MONT_CTX;
begin
    ret := OPENSSL_malloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    BN_MONT_CTX_init(ret);
    ret.flags := BN_FLG_MALLOCED;
    Result := ret;
end;

 function bn_from_montgomery_word( ret, r : PBIGNUM; mont : PBN_MONT_CTX):integer;
var
  n : PBIGNUM;
  ap, np, rp : PBN_ULONG;
  n0, v, carry, t : BN_ULONG;
  nl, max: integer;
  rtop : uint32;
  i, j: int;
const
   bitsz = 8 * sizeof(uint32) - 1;
begin
{$POINTERMATH ON}
{$Q-}
    n := @mont.N;
    nl := n.top;
    if nl = 0 then
    begin
        ret.top := 0;
        Exit(1);
    end;
    max := (2 * nl);             { carry is stored separately }
    if bn_wexpand(r, max) = nil  then
        Exit(0);
    r.neg  := r.neg xor n.neg;
    np := n.d;
    rp := r.d;
    { clear the top words of T }
    rtop := r.top;

    //must tell complier j is a int
    for  i := 0 to max-1 do
    begin
        j := (i - rtop);
        t := (j  shr  bitsz);
        v := BN_ULONG(0) - t;
        rp[i] := rp[i] and v;
    end;
    r.top := max;
    r.flags  := r.flags  or BN_FLG_FIXED_TOP;
    n0 := mont.n0[0];
    {
     * Add multiples of |n| to |r| until R = 2^(nl * BN_BITS2) divides it. On
     * input, we had |r| < |n| * R, so now |r| < 2 * |n| * R. Note that |r|
     * includes |carry| which is stored separately.
     }
    carry := 0;
    for  i := 0 to nl-1 do
    begin
        v := bn_mul_add_words(rp, np, nl, (rp[0] * n0) and BN_MASK2);
        v := (v + carry + rp[nl]) and BN_MASK2;
        carry  := carry  or (int(v <> rp[nl]));
        carry := carry and int(v <= rp[nl]);
        rp[nl] := v;
        Inc(rp);
    end;
    if bn_wexpand(ret, nl) = nil  then
        Exit(0);
    ret.top := nl;
    ret.flags  := ret.flags  or BN_FLG_FIXED_TOP;
    ret.neg := r.neg;
    rp := ret.d;
    {
     * Shift |nl| words to divide by R. We have |ap| < 2 * |n|. Note that |ap|
     * includes |carry| which is stored separately.
     }
    ap := @(r.d[nl]);
    carry  := carry - (bn_sub_words(rp, ap, np, nl));
    {
     * |carry| is -1 if |ap| - |np| underflowed or zero if it did not. Note
     * |carry| cannot be 1. That would imply the subtraction did not fit in
     * |nl| words, and we know at most one subtraction is needed.
     }
    for i := 0 to nl-1 do
    begin
        rp[i] := (carry and ap[i]) or (not carry and rp[i]);
        ap[i] := 0;
    end;
    Result := 1;
{$POINTERMATH OFF}
{$Q+}
end;

function bn_from_mont_fixed_top(ret : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
var
  t, t1, t2 : PBIGNUM;
  label _err;
begin
    result := 0;
{$IFDEF MONT_WORD}
    BN_CTX_start(ctx);
    t := BN_CTX_get(ctx);
    if (t <> nil) and (nil <> BN_copy(t, a)) then
    begin
        result := bn_from_montgomery_word(ret, t, mont);
    end;
    BN_CTX_end(ctx);
{$ELSE} { !MONT_WORD }
    BN_CTX_start(ctx);
    t1 := BN_CTX_get(ctx);
    t2 := BN_CTX_get(ctx);
    if t2 = nil then goto _err ;
    if 0>= BN_copy(t1, a then )
        goto _err ;
    BN_mask_bits(t1, mont.ri);
    if 0>= BN_mul(t2, t1, &mont.Ni, ctx) then
        goto _err ;
    BN_mask_bits(t2, mont.ri);
    if 0>= BN_mul(t1, t2, &mont.N, ctx) then
        goto _err ;
    if 0>= BN_add(t2, a, t1) then
        goto _err ;
    if 0>= BN_rshift(ret, t2, mont.ri) then
        goto _err ;
    if BN_ucmp(ret, @(mont.N)) >= 0  then
    begin
        if 0>= BN_usub(ret, ret, @(mont.N)) then
            goto _err ;
    end;
    retn := 1;
    bn_check_top(ret);
 _err:
    BN_CTX_end(ctx);
{$endif}                          { MONT_WORD }

end;

function bn_to_mont_fixed_top(r : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
begin
    Result := bn_mul_mont_fixed_top(r, a, @mont.RR, mont, ctx);
end;

function BN_from_montgomery(dest : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
begin
    Result := bn_from_mont_fixed_top(dest, a, mont, ctx); //same as vc
    bn_correct_top(dest);
    bn_check_top(dest);
end;



function BN_mod_mul_montgomery(r : PBIGNUM;const a, b : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
    ret := bn_mul_mont_fixed_top(r, a, b, mont, ctx);
    bn_correct_top(r);
    bn_check_top(r);
    Result := ret;
end;

function bn_mul_mont_fixed_top(r : PBIGNUM;const a, b : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
var
  tmp : PBIGNUM;
  ret, num : integer;
  label _err;
begin
    ret := 0;
    num := mont.N.top;
{$IF defined(OPENSSL_BN_ASM_MONT)  and  defined(MONT_WORD)}
    if num > 1  and  a.top = num  and  b.top = num then begin
        if bn_wexpand(r, num) = nil then
            Exit(0);
        if bn_mul_mont(r.d, a.d, b.d, mont.N.d, mont.n0, num then ) begin
            r.neg := a.neg  xor  b.neg;
            r.top := num;
            r.flags  := r.flags  or BN_FLG_FIXED_TOP;
            Exit(1);
        end;
    end;
{$ENDIF}
    if (a.top + b.top) > 2 * num then
        Exit(0);
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    if tmp = nil then goto _err ;
    bn_check_top(tmp);
    if a = b then begin
        if 0>= bn_sqr_fixed_top(tmp, a, ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= bn_mul_fixed_top(tmp, a, b, ctx) then
            goto _err ;
    end;
    { reduce from aRR to aR }
{$IFDEF MONT_WORD}
    if 0>= bn_from_montgomery_word(r, tmp, mont) then
        goto _err ;
{$ELSE}
    if 0>= BN_from_montgomery(r, tmp, mont, ctx) then
        goto _err ;
{$ENDIF}
    ret := 1;

 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;
//{$RANGECHECKS ON}

end.
