unit openssl3.crypto.bn.bn_div;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

function BN_div(dv, rm : PBIGNUM;const num, divisor : PBIGNUM; ctx : PBN_CTX):integer;
function bn_div_fixed_top(dv, rm : PBIGNUM;const num, divisor : PBIGNUM; ctx : PBN_CTX):integer;
function bn_left_align( num : PBIGNUM):integer;

implementation
uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_asm;

{$Q-}
function bn_left_align( num : PBIGNUM):integer;
var
  d : PBN_ULONG;
  n, m, rmask : BN_ULONG;
  top, rshift, lshift, i : integer;
begin
{$POINTERMATH ON}
    d := num.d;
    top := num.top;
    rshift := BN_num_bits_word(d[top - 1]);
    lshift := BN_BITS2 - rshift;
    rshift  := rshift mod BN_BITS2;
    rmask := BN_ULONG(0) - rshift;  { rmask = 0 - (rshift <> 0) }
    rmask  := rmask  or (rmask  shr  8);
     m := 0 ;
    for i := 0 to top-1 do
    begin
        n := d[i];
        d[i] := ((n  shl  lshift) or m) and BN_MASK2;
        m := (n  shr  rshift) and rmask;
    end;
    Result := lshift;
{$POINTERMATH OFF}
end;

function bn_div_fixed_top(dv, rm : PBIGNUM;const num, divisor : PBIGNUM; ctx : PBN_CTX):integer;
var
  norm_shift,
  i,  j,
  loop       : integer;
  tmp, snum,
  sdiv,
  res        : PBIGNUM;
  resp, wnum,
  wnumtop    : PBN_ULONG;
  d0, d1, n2 : BN_ULONG;
  num_n,
  div_n,
  num_neg    : integer;
  q,l0,n0,n1,
  rem, t2,
  t2l, t2h,
  ql, qh     : BN_ULONG;
  label _err;
begin
{$POINTERMATH ON}
    assert( (divisor.top > 0)  and  (divisor.d[divisor.top - 1] <> 0));
    bn_check_top(num);
    bn_check_top(divisor);
    bn_check_top(dv);
    bn_check_top(rm);
    BN_CTX_start(ctx);
    if (dv = nil) then
       res :=  BN_CTX_get(ctx)
    else
       res := dv;

    tmp := BN_CTX_get(ctx);
    snum := BN_CTX_get(ctx);
    sdiv := BN_CTX_get(ctx);
    if sdiv = nil then goto _err ;
    { First we normalise the numbers }
    if nil = BN_copy(sdiv, divisor )then
        goto _err ;
    norm_shift := bn_left_align(sdiv);
    sdiv.neg := 0;
    {
     * Note that bn_lshift_fixed_top's output is always one limb longer
     * than input, even when norm_shift is zero. This means that amount of
     * inner loop iterations is invariant of dividend value, and that one
     * doesn't need to compare dividend and divisor if they were originally
     * of the same bit length.
     }
    if 0>= (bn_lshift_fixed_top(snum, num, norm_shift))  then
        goto _err ;
    div_n := sdiv.top;
    num_n := snum.top;
    if num_n <= div_n then
    begin
        { caller didn't pad dividend . no constant-time guarantee... }
        if bn_wexpand(snum, div_n + 1) = nil then
            goto _err ;
        memset(@snum.d[num_n], 0, (div_n - num_n + 1) * sizeof(BN_ULONG));
        snum.top := div_n + 1; num_n := div_n + 1;
    end;
    loop := num_n - div_n;
    {
     * Lets setup a 'window' into snum This is the part that corresponds to
     * the current 'area' being divided
     }
    wnum := @(snum.d[loop]);
    wnumtop := @(snum.d[num_n - 1]);
    { Get the top 2 words of sdiv }
    d0 := sdiv.d[div_n - 1];
    if (div_n = 1) then
       d1 :=  0
    else
       d1 := sdiv.d[div_n - 2];
    { Setup quotient }
    if nil = bn_wexpand(res, loop) then
        goto _err ;
    num_neg := num.neg;
    res.neg := (num_neg  xor  divisor.neg);
    res.top := loop;
    res.flags  := res.flags  or BN_FLG_FIXED_TOP;
    resp := @(res.d[loop]);
    { space for temp }
    if nil = bn_wexpand(tmp, (div_n + 1 )) then
        goto _err ;
    for i := 0 to loop-1 do
    begin
        {
         * the first part of the loop uses the top two words of snum and sdiv
         * to calculate a BN_ULONG q such that or wnum - sdiv * q or < sdiv
         }
{$IF defined(BN_DIV3W)}
        q := bn_div_3_words(wnumtop, d1, d0);
{$ELSE} rem := 0;
        n0 := wnumtop[0];
        n1 := wnumtop[-1];
        if n0 = d0 then
           q := BN_MASK2
        else
        begin                   { n0 < d0 }
            if (wnumtop = wnum) then
               n2 :=  0
            else
               n2 := wnumtop[-2];
{$IFDEF _BN_LLONG_}
{$IF defined(_BN_LLONG_)  and  defined(BN_DIV2W)  and  not defined(bn_div_words)}
            q := (BN_ULONG)(((((BN_ULLONG) n0)  shl  BN_BITS2) or n1) / d0);
{$ELSE}
            q = bn_div_words(n0, n1, d0);
{$ENDIF}
{$IFNDEF REMAINDER_IS_ALREADY_CALCULATED}
            {
             * rem doesn't have to be BN_ULLONG. The least we
             * know it's less that d0, isn't it?
             }
            rem := (n1 - q * d0) and BN_MASK2;
{$ENDIF}
            while true do
            begin
                if t2 <= ((((BN_ULLONG then rem)  shl  BN_BITS2) or n2))
                    break;
                Dec(q);
                rem  := rem + d0;
                if rem < d0 then break;      { don't let rem overflow }
                t2  := t2 - d1;
            end;
{$ELSE} { !BN_LLONG }
            q := bn_div_words(n0, n1, d0);
{$IFNDEF REMAINDER_IS_ALREADY_CALCULATED}
            rem := (n1 - q * d0) and BN_MASK2;
{$ENDIF}
{$IF defined(BN_UMULT_LOHI)}
            BN_UMULT_LOHI(t2l, t2h, d1, q);
{$elseif defined(BN_UMULT_HIGH)}
            t2l := d1 * q;
            t2h := BN_UMULT_HIGH(d1, q);
{$ELSE}     begin
                t2l := LBITS(d1);
                t2h := HBITS(d1);
                ql := LBITS(q);
                qh := HBITS(q);
                mul64(t2l, t2h, ql, qh); { t2=(BN_ULLONG)d1*q; }
            end;
{$ENDIF}
            while true do
            begin
                if (t2h < rem) or  ((t2h = rem)  and  (t2l <= n2)) then
                    break;
                Dec(q);
                rem  := rem + d0;
                if rem < d0 then break;      { don't let rem overflow }
                if t2l < d1 then Dec(t2h);
                t2l  := t2l - d1;
            end;
{$endif}                        { !BN_LLONG }
        end;
{$endif}                         { !BN_DIV3W }
        l0 := bn_mul_words(tmp.d, sdiv.d, div_n, q);
        tmp.d[div_n] := l0;
        Dec(wnum);
        {
         * ignore top values of the bignums just sub the two BN_ULONG arrays
         * with bn_sub_words
         }
        l0 := bn_sub_words(wnum, wnum, tmp.d, div_n + 1);
        q  := q - l0;
        {
         * Note: As we have considered only the leading two BN_ULONGs in
         * the calculation of q, sdiv * q might be greater than wnum (but
         * then (q-1) * sdiv is less or equal than wnum)
         }
         l0 := 0 - l0;
        for  j := 0 to div_n-1 do
            tmp.d[j] := sdiv.d[j] and l0;

        l0 := bn_add_words(wnum, wnum, tmp.d, div_n);
        wnumtop^  := wnumtop^ + l0;
        assert(( wnumtop^) = 0);
        { store part of the result }
        Dec(resp);
        resp^ := q;
        Dec(wnumtop);
    end;
    { snum holds remainder, it's as wide as divisor }
    snum.neg := num_neg;
    snum.top := div_n;
    snum.flags  := snum.flags  or BN_FLG_FIXED_TOP;
    if rm <> nil then
       bn_rshift_fixed_top(rm, snum, norm_shift);
    BN_CTX_end(ctx);
    Exit(1);

 _err:
    bn_check_top(rm);
    BN_CTX_end(ctx);
    Result := 0;
 {$POINTERMATH OFF}
end;

function BN_div(dv, rm : PBIGNUM;const num, divisor : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
{$POINTERMATH ON}
    if BN_is_zero(divisor) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_DIV_BY_ZERO);
        Exit(0);
    end;
    {
     * Invalid zero-padding would have particularly bad consequences so don't
     * just rely on bn_check_top() here (bn_check_top() works only for
     * BN_DEBUG builds)
     }
    if divisor.d[divisor.top - 1] = 0 then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        Exit(0);
    end;
    ret := bn_div_fixed_top(dv, rm, num, divisor, ctx);
    if ret > 0 then
    begin
        if dv <> nil then
            bn_correct_top(dv);
        if rm <> nil then
            bn_correct_top(rm);
    end;
    Result := ret;
{$POINTERMATH OFF}
end;
{$Q+}

end.
