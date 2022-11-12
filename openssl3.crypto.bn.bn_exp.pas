unit openssl3.crypto.bn.bn_exp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

{$DEFINE MONT_MUL_MOD}
{$DEFINE MONT_EXP_WORD}
{$DEFINE RECP_MUL_MOD}
{$DEFINE alloca}
const
   TABLE_SIZE = 32;
   {$IFNDEF FPC}
   _alloca: function(Size: NativeInt): Pointer =  AllocMem;
   {$ENDIF}
function BN_mod_exp(r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX):integer;

function BN_mod_exp_mont_word(rr : PBIGNUM; a : BN_ULONG;const p, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX):integer;
function BN_mod_exp_mont(rr : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX):integer;
function BN_mod_exp_mont_consttime(rr : PBIGNUM; a, p, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX):integer;
function MOD_EXP_CTIME_COPY_TO_PREBUF(const b : PBIGNUM; top : integer; buf : PByte; idx, window : integer):integer;
function bn_get_bits(const a : PBIGNUM; bitpos : integer):BN_ULONG;
function MOD_EXP_CTIME_COPY_FROM_PREBUF( b : PBIGNUM; top : integer; buf : PByte; idx, window : integer):integer;
function BN_mod_exp_recp(r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX):integer;
function BN_mod_exp_mont_consttime_x2(rr1 : PBIGNUM;const a1, p1, m1 : PBIGNUM; in_mont1 : PBN_MONT_CTX; rr2 : PBIGNUM;const a2, p2, m2 : PBIGNUM; in_mont2 : PBN_MONT_CTX; ctx : PBN_CTX):integer;


implementation
uses openssl3.crypto.bn.bn_lib,OpenSSL3.Err, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_mont, openssl3.crypto.bn.bn_word,
     openssl3.crypto.bn.bn_mod, openssl3.crypto.mem,
     openssl3.internal.constant_time, openssl3.crypto.bn.bn_recp;


{
const // 1d arrays
  pwr5_funcs : array[0..3] of bn_pwr5_mont_f = (
    bn_pwr5_mont_t4_8, bn_pwr5_mont_t4_16, bn_pwr5_mont_t4_24,
    bn_pwr5_mont_t4_32 );

  mul_funcs : array[0..3] of bn_mul_mont_f = (
    bn_mul_mont_t4_8, bn_mul_mont_t4_16, bn_mul_mont_t4_24,
    bn_mul_mont_t4_32 );
}

function BN_mod_exp_mont_consttime_x2(rr1 : PBIGNUM;const a1, p1, m1 : PBIGNUM;
                                      in_mont1 : PBN_MONT_CTX; rr2 : PBIGNUM;
                                      const a2, p2, m2 : PBIGNUM;
                                      in_mont2 : PBN_MONT_CTX; ctx : PBN_CTX):integer;
var
  ret      : integer;
  mont1,
  mont2    : PBN_MONT_CTX;
  topn,
  mod_bits : integer;
begin
    ret := 0;
{$IFDEF RSAZ_ENABLED}
    mont1 := nil;
    mont2 := nil;
    if ossl_rsaz_avx512ifma_eligible( then  and
        (((a1.top = 16)  and  (p1.top = 16)  and  (BN_num_bits(m1) = 1024)  and
          (a2.top = 16)  and  (p2.top = 16)  and  (BN_num_bits(m2) = 1024))  or
         ((a1.top = 24)  and  (p1.top = 24)  and  (BN_num_bits(m1) = 1536)  and
          (a2.top = 24)  and  (p2.top = 24)  and  (BN_num_bits(m2) = 1536))  or
         ((a1.top = 32)  and  (p1.top = 32)  and  (BN_num_bits(m1) = 2048)  and
          (a2.top = 32)  and  (p2.top = 32)  and  (BN_num_bits(m2) = 2048)))) begin
        topn := a1.top;
        { Modulus bits of |m1| and |m2| are equal }
        mod_bits := BN_num_bits(m1);
        if bn_wexpand(rr1, topn then = nil)
            goto_err ;
        if bn_wexpand(rr2, topn then = nil)
            goto_err ;
        {  Ensure that montgomery contexts are initialized }
        if in_mont1 <> nil then begin
            mont1 := in_mont1;
        end
        else begin
            if mont1 = BN_MONT_CTX_new( then ) = nil then
                goto_err ;
            if 0>= BN_MONT_CTX_set(mont1, m1, ctx then )
                goto_err ;
        end;
        if in_mont2 <> nil then begin
            mont2 := in_mont2;
        end
        else begin
            if mont2 = BN_MONT_CTX_new( then ) = nil then
                goto_err ;
            if 0>= BN_MONT_CTX_set(mont2, m2, ctx then )
                goto_err ;
        end;
        ret := ossl_rsaz_mod_exp_avx512_x2(rr1.d, a1.d, p1.d, m1.d,
                                          mont1.RR.d, mont1.n0[0],
                                          rr2.d, a2.d, p2.d, m2.d,
                                          mont2.RR.d, mont2.n0[0],
                                          mod_bits);
        rr1.top := topn;
        rr1.neg := 0;
        bn_correct_top(rr1);
        bn_check_top(rr1);
        rr2.top := topn;
        rr2.neg := 0;
        bn_correct_top(rr2);
        bn_check_top(rr2);
        goto_err ;
    end;
{$ENDIF}
    { rr1 = a1^p1 mod m1 }
    ret := BN_mod_exp_mont_consttime(rr1, a1, p1, m1, ctx, in_mont1); //same as vc
    { rr2 = a2^p2 mod m2 }
    ret := ret and BN_mod_exp_mont_consttime(rr2, a2, p2, m2, ctx, in_mont2);
{$IFDEF RSAZ_ENABLED}
err:
    if in_mont2 = nil then BN_MONT_CTX_free(mont2);
    if in_mont1 = nil then BN_MONT_CTX_free(mont1);
{$ENDIF}
    Result := ret;
end;

function BN_mod_exp_recp(r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX):integer;
var
  i, j, bits, wstart, wend,
  window, wvalue,
  ret, start : integer;
  aa : PBIGNUM;
  val : array[0..(TABLE_SIZE)-1] of PBIGNUM;
  recp : TBN_RECP_CTX;
  label _err;
begin
    ret := 0;
    start := 1;
    { Table of variables obtained from 'ctx' }
    if (BN_get_flags(p, BN_FLG_CONSTTIME) <> 0) or
       (BN_get_flags(a, BN_FLG_CONSTTIME) <> 0) or
       (BN_get_flags(m, BN_FLG_CONSTTIME) <> 0)  then
    begin
        { BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() }
        ERR_raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    bits := BN_num_bits(p);
    if bits = 0 then
    begin
        { x**0 mod 1, or x**0 mod -1 is still zero. }
        if BN_abs_is_word(m, 1) then
        begin
            ret := 1;
            BN_zero(r);
        end
        else
        begin
            ret := BN_one(r);
        end;
        Exit(ret);
    end;
    BN_CTX_start(ctx);
    aa := BN_CTX_get(ctx);
    val[0] := BN_CTX_get(ctx);
    if val[0] = nil then
       goto _err ;
    BN_RECP_CTX_init(@recp);
    if m.neg>0 then
    begin
        { ignore sign of 'm' }
        if nil = BN_copy(aa, m) then
            goto _err ;
        aa.neg := 0;
        if BN_RECP_CTX_set(@recp, aa, ctx) <= 0  then
            goto _err ;
    end
    else
    begin
        if BN_RECP_CTX_set(@recp, m, ctx) <= 0  then
            goto _err ;
    end;
    if 0>= BN_nnmod(val[0], a, m, ctx) then
        goto _err ;               { 1 }
    if BN_is_zero(val[0])  then
    begin
        BN_zero(r);
        ret := 1;
        goto _err ;
    end;
    window := BN_window_bits_for_exponent_size(bits);
    if window > 1 then
    begin
        if 0>= BN_mod_mul_reciprocal(aa, val[0], val[0], @recp, ctx) then
           goto _err ;           { 2 }
        j := 1  shl  (window - 1);
        for i := 1 to j-1 do
        begin
            val[i] := BN_CTX_get(ctx);
            if (val[i] = nil )   or
               (0>= BN_mod_mul_reciprocal(val[i], val[i - 1], aa, @recp, ctx))  then
                goto _err ;
        end;
    end;
    start := 1;                  { This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. }
    wvalue := 0;                 { The 'value' of the window }
    wstart := bits - 1;          { The top bit of the window }
    wend := 0;                   { The bottom bit of the window }
    if 0>= BN_one(r )  then
        goto _err ;
    while true do
    begin
        if BN_is_bit_set(p, wstart) = 0  then
        begin
            if 0>= start then
                if (0>= BN_mod_mul_reciprocal(r, r, r, @recp, ctx)) then
                    goto _err ;
            if wstart = 0 then
               break;
            Dec(wstart);
            continue;
        end;
        {
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         }
        wvalue := 1;
        wend := 0;
        for i := 1 to window-1 do
        begin
            if wstart - i < 0 then
               break;
            if BN_is_bit_set(p, wstart - i)>0 then
            begin
                wvalue  := wvalue shl (i - wend);
                wvalue  := wvalue  or 1;
                wend := i;
            end;
        end;
        { wend is the size of the current window }
        j := wend + 1;
        { add the 'bytes above' }
        if 0>= start then
        for i := 0 to j-1 do
        begin
                if 0>= BN_mod_mul_reciprocal(r, r, r, @recp, ctx) then
                    goto _err ;
        end;
        { wvalue will be an odd number < 2^window }
        if 0>= BN_mod_mul_reciprocal(r, r, val[wvalue  shr  1], @recp, ctx) then
            goto _err ;
        { move the 'window' down further }
        wstart  := wstart - (wend + 1);
        wvalue := 0;
        start := 0;
        if wstart < 0 then
           break;
    end;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_RECP_CTX_free(@recp);
    bn_check_top(r);
    Result := ret;
end;


function MOD_EXP_CTIME_COPY_FROM_PREBUF( b : PBIGNUM; top : integer; buf : PByte; idx, window : integer):integer;
var
  i, j, width : integer;
  table    : PBN_ULONG  ;
  xstride : integer;
  y0, y1, y2, y3, acc, t : BN_ULONG;
begin
{$POINTERMATH ON}
{$Q-}
    width := 1  shl  window;
    {
     * We declare table 'volatile' in order to discourage compiler
     * from reordering loads from the table. Concern is that if
     * reordered in specific manner loads might give away the
     * information we are trying to conceal. Some would argue that
     * compiler can reorder them anyway, but it can as well be
     * argued that doing so would be violation of standard...
     }
    table  := PBN_ULONG(buf);
    if bn_wexpand(b, top)  = nil then
        Exit(0);
    if window <= 3 then
    begin
        for i := 0 to top-1 do
        begin
            acc := 0;
            for j := 0 to width-1 do
            begin
                acc := acc or table[j] and
                       (BN_ULONG(0) - (constant_time_eq_int(j,idx) and 1));
            end;
            b.d[i] := acc;
            table := table + width;
        end;
    end
    else
    begin
        xstride := 1  shl  (window - 2);
        i := idx  shr  (window - 2);        { equivalent of idx / xstride }
        idx := idx and (xstride - 1);             { equivalent of idx % xstride }
        y0 := BN_ULONG(0) - (constant_time_eq_int(i,0) and 1);
        y1 := BN_ULONG(0) - (constant_time_eq_int(i,1) and 1);
        y2 := BN_ULONG(0) - (constant_time_eq_int(i,2) and 1);
        y3 := BN_ULONG(0) - (constant_time_eq_int(i,3) and 1);
        for i := 0 to top-1 do
        begin
            acc := 0;
            for j := 0 to xstride-1 do
            begin
                t := (BN_ULONG(0) - (constant_time_eq_int(j,idx) and 1));
                acc := acc or (
                        ((table[j + 0 * xstride] and y0) or
                         (table[j + 1 * xstride] and y1) or
                         (table[j + 2 * xstride] and y2) or
                         (table[j + 3 * xstride] and y3) )
                       and t );

            end;
            b.d[i] := acc;
            table := table + width;
        end;
    end;
    b.top := top;
    b.flags  := b.flags  or BN_FLG_FIXED_TOP;
    Result := 1;
{$POINTERMATH OFF}
{$Q+}
end;

function bn_get_bits(const a : PBIGNUM; bitpos : integer):BN_ULONG;
var
  ret : BN_ULONG;
  wordpos : integer;
begin
{$POINTERMATH ON}
    ret := 0;
    wordpos := bitpos div BN_BITS2;
    bitpos  := bitpos mod BN_BITS2;
    if (wordpos >= 0)  and  (wordpos < a.top) then
    begin
        ret := a.d[wordpos] and BN_MASK2;
        if bitpos > 0 then
        begin
            ret := ret shr  bitpos;
            if PreInc(wordpos) < a.top  then
                ret  := ret  or (a.d[wordpos]  shl  (BN_BITS2 - bitpos));
        end;
    end;
    Result := ret and BN_MASK2;
{$POINTERMATH OFF}
end;


function MOD_EXP_CTIME_COPY_TO_PREBUF(const b : PBIGNUM; top : integer; buf : PByte; idx, window : integer):integer;
var
  i, j, width : integer;
  table : PBN_ULONG;
begin
{$POINTERMATH ON}
    width := 1  shl  window;
    table := PBN_ULONG(buf);
    if top > b.top then
       top := b.top;           { this works because 'buf' is explicitly
                                 * zeroed }
    j := idx;
    for i := 0 to top-1 do
    begin
        table[j] := b.d[i];
        j := j + width;
    end;
    Result := 1;
{$POINTERMATH OFF}
end;

function MOD_EXP_CTIME_ALIGN(x_: PByte) : PByte;
begin
    Result := x_ + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (size_t(x_) and MOD_EXP_CTIME_MIN_CACHE_LINE_MASK)) ;
end;

function BN_mod_exp_mont_consttime(rr : PBIGNUM; a, p, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX):integer;
var
    i, bits, len,
    ret, window, wvalue, wmask, window0,
    top          : integer;
    mont         : PBN_MONT_CTX;
    numPowers    : integer;
    powerbufFree : PByte;
    powerbufLen  : integer;
    powerbuf     : PByte;
    tmp, am      : TBIGNUM;
    t4           : uint32;
    reduced      : PBIGNUM;
    //pwr5_worker  : bn_pwr5_mont_f;
    //mul_worker   : bn_mul_mont_f;
    np           : PBN_ULONG;
    stride       : integer;
    n0           : PBN_ULONG;
    j            : integer;
    addr         : AnsiString;
    label _err;
begin
{$POINTERMATH ON}
{$Q-}
    ret := 0;
    mont := nil;
    powerbufLen := 0;
    powerbuf := nil;
{$IF defined(SPARC_T4_MONT)}
    t4 := 0;
{$ENDIF}
    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);
    if not BN_is_odd(m)  then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS);
        Exit(0);
    end;
    top := m.top;
    {
     * Use all bits stored in |p|, rather than |BN_num_bits|, so we do not leak
     * whether the top bits are zero.
     }
    bits := p.top * BN_BITS2;
    if bits = 0 then
    begin
        { x**0 mod 1, or x**0 mod -1 is still zero. }
        if BN_abs_is_word(m, 1) then
        begin
            ret := 1;
            BN_zero(rr);
        end
        else
        begin
            ret := BN_one(rr);
        end;
        Exit(ret);
    end;
    BN_CTX_start(ctx);
    {
     * Allocate a montgomery context if it was not supplied by the caller. If
     * this is not done, things will break in the montgomery part.
     }
    if in_mont <> nil then
       mont := in_mont
    else
    begin
        mont := BN_MONT_CTX_new();
        if mont =  nil then
            goto _err ;
        if 0>= BN_MONT_CTX_set(mont, m, ctx) then
            goto _err ;
    end;
    if (a.neg >0)  or  (BN_ucmp(a, m) >= 0)  then
    begin
        reduced := BN_CTX_get(ctx);
        if (reduced = nil)
             or  (0>= BN_nnmod(reduced, a, m, ctx))  then
        begin
            goto _err ;
        end;
        a := reduced;
    end;
{$IFDEF RSAZ_ENABLED}
    {
     * If the size of the operands allow it, perform the optimized
     * RSAZ exponentiation. For further information see
     * crypto/bn/rsaz_exp.c and accompanying assembly modules.
     }
    if 16 = a.top then  and  (16 = p.top)  and  (BN_num_bits(m) = 1024 then
         and  rsaz_avx2_eligible()) begin
        if nil = bn_wexpand(rr, 16) then
            goto_err ;
        RSAZ_1024_mod_exp_avx2(rr.d, a.d, p.d, m.d, mont.RR.d,
                               mont.n0[0]);
        rr.top := 16;
        rr.neg := 0;
        bn_correct_top(rr);
        ret := 1;
        goto_err ;
    end
    else if ((8 = a.top)  and  (8 = p.top)  and  (BN_num_bits(m) = 512)) begin
        if nil = bn_wexpand(rr, 8 then )
            goto_err ;
        RSAZ_512_mod_exp(rr.d, a.d, p.d, m.d, mont.n0[0], mont.RR.d);
        rr.top := 8;
        rr.neg := 0;
        bn_correct_top(rr);
        ret := 1;
        goto_err ;
    end;
{$ENDIF}
    { Get the window size to use with size of p. }
    window := BN_window_bits_for_ctime_exponent_size(bits);
{$IF defined(SPARC_T4_MONT)}
    if window >= 5  and  ((top and 15)= 0)  and  top <= 64  and
        (OPENSSL_sparcv9cap_P[1] and (CFR_MONTMUL or CFR_MONTSQR)) =
        (CFR_MONTMUL or CFR_MONTSQR)  and  (t4 = OPENSSL_sparcv9cap_P[0]))
        window := 5;
    else
{$ENDIF}
{$IF defined(OPENSSL_BN_ASM_MONT5)}
    if window >= 5 then begin
        window := 5;             { ~5% improvement for RSA2048 sign, and even
                                 * for RSA4096 }
        { reserve space for mont.N.d[] copy }
        powerbufLen  := powerbufLen + (top * sizeof(mont.N.d[0]));
    end;
{$ENDIF}
    //(void)0;
    {
     * Allocate a buffer large enough to hold all of the pre-computed powers
     * of am, am itself and tmp.
     }
    powerbufFree := nil;
    numPowers := 1  shl  window;
    powerbufLen := powerbufLen + sizeof(m.d[0]) * (top * numPowers +
                          get_result((2 * top) > numPowers , (2 * top) , numPowers));
{$IFDEF alloca}
    if powerbufLen < 3072 then
       powerbufFree := {$IFNDEF FPC}_alloca{$ELSE}AllocMem{$ENDIF}(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH)
    else
{$ENDIF}
        powerbufFree := OPENSSL_malloc(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH);

    //len=32,48 而vc中的值为48，这很奇怪！！
    {Addr:= Format('$%p', [powerbufFree]);
    Writeln('powerbufFree:' + Addr);
    Len:= MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (StrToInt64(addr) and MOD_EXP_CTIME_MIN_CACHE_LINE_MASK);
    }
    len := MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (size_t(powerbufFree) and MOD_EXP_CTIME_MIN_CACHE_LINE_MASK);
    if (powerbufFree = nil) then
        goto _err ;
    //powerbuf := MOD_EXP_CTIME_ALIGN(powerbufFree);
    powerbuf := powerbufFree + len;
    memset(powerbuf, 0, powerbufLen);
{$IFDEF alloca}
    if powerbufLen < 3072 then
       powerbufFree := nil;
{$ENDIF}
    { lay down tmp and am right after powers table }
    tmp.d := PBN_ULONG(powerbuf + sizeof(m.d[0]) * top * numPowers);
    am.d := tmp.d + top;
    tmp.top := 0; am.top := 0;
    tmp.dmax := top; am.dmax := top;
    tmp.neg := 0; am.neg := 0;
    tmp.flags := BN_FLG_STATIC_DATA; am.flags := BN_FLG_STATIC_DATA;
    { prepare a^0 in Montgomery domain }
{$IF true}                           { by Shay Gueron's suggestion }
    if (m.d[top - 1] and (BN_ULONG(1)  shl  (BN_BITS2 - 1)) ) > 0 then
    begin
        { 2^(top*BN_BITS2) - m }
        tmp.d[0] := (0 - m.d[0]) and BN_MASK2;
        for i := 1 to top-1 do
            tmp.d[i] := (not m.d[i]) and BN_MASK2;
        tmp.top := top;
    end
    else
{$ENDIF}
    if 0>= bn_to_mont_fixed_top(@tmp, BN_value_one , mont, ctx) then
        goto _err ;
    { prepare a^1 in Montgomery domain }
    //ctx.pool.current.vals same as vc
    if 0>= bn_to_mont_fixed_top(@am, a, mont, ctx) then
        goto _err ;
{$IF defined(SPARC_T4_MONT)}
    if t4 then begin
        static const bn_pwr5_mont_f pwr5_funcs[4] = begin
            bn_pwr5_mont_t4_8, bn_pwr5_mont_t4_16,
            bn_pwr5_mont_t4_24, bn_pwr5_mont_t4_32
        end;
;
        pwr5_worker := pwr5_funcs[top / 16 - 1];
        static const bn_mul_mont_f mul_funcs[4] = begin
            bn_mul_mont_t4_8, bn_mul_mont_t4_16,
            bn_mul_mont_t4_24, bn_mul_mont_t4_32
        end;
;
        mul_worker := mul_funcs[top / 16 - 1];
        np := mont.N.d, *n0 = mont.n0;
        stride := 5 * (6 - (top / 16 - 1));
                                                * than 32 }
        {
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG build...
         }
        for i := am.top to top-1 do
            am.d[i] := 0;
        for i := tmp.top to top-1 do
            tmp.d[i] := 0;
        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 0);
        bn_flip_n_scatter5_t4(am.d, top, powerbuf, 1);
        if 0>= ( *mul_worker then (tmp.d, am.d, am.d, np, n0)  and
             not ( *mul_worker) (tmp.d, am.d, am.d, np, n0))
            bn_mul_mont_vis3(tmp.d, am.d, am.d, np, n0, top);
        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 2);
        for i := 3 to 31 do begin
            { Calculate a^i = a^(i-1) * a }
            if 0>= ( *mul_worker then (tmp.d, tmp.d, am.d, np, n0)  and
                 not ( *mul_worker) (tmp.d, tmp.d, am.d, np, n0))
                bn_mul_mont_vis3(tmp.d, tmp.d, am.d, np, n0, top);
            bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, i);
        end;
        { switch to 64-bit domain }
        np := alloca(top * sizeof(BN_ULONG));
        top  := top  / 2;
        bn_flip_t4(np, mont.N.d, top);
        {
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         }
        window0 := (bits - 1) % 5 + 1;
        wmask := (1  shl  window0) - 1;
        bits  := bits - window0;
        wvalue := bn_get_bits(p, bits) and wmask;
        bn_gather5_t4(tmp.d, top, powerbuf, wvalue);
        {
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         }
        while bits > 0 do  begin
            if bits < stride then stride = bits;
            bits  := bits - stride;
            wvalue := bn_get_bits(p, bits);
            if *pwr5_worker then (tmp.d, np, n0, powerbuf, wvalue, stride) then
                continue;
            { retry once and fall back }
            if *pwr5_worker then (tmp.d, np, n0, powerbuf, wvalue, stride) then
                continue;
            bits  := bits + (stride - 5);
            wvalue  shr = stride - 5;
            wvalue &= 31;
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_gather5_t4(tmp.d, tmp.d, powerbuf, np, n0, top,
                                   wvalue);
        end;
        bn_flip_t4(tmp.d, tmp.d, top);
        top  := top  * 2;
        { back to 32-bit domain }
        tmp.top := top;
        bn_correct_top(&tmp);
        OPENSSL_cleanse(np, top * sizeof(BN_ULONG));
    end;
    else
{$ENDIF}
{$IF defined(OPENSSL_BN_ASM_MONT5)}
    if window = 5  and  top > 1 then begin
        {
         * This optimization uses ideas from http://eprint.iacr.org/2011/239,
         * specifically optimization of cache-timing attack countermeasures
         * and pre-computation optimization.
         }
        {
         * Dedicated window=4 case improves 512-bit RSA sign by ~15%, but as
         * 512-bit RSA is hardly relevant, we omit it to spare size...
         }
        n0 := mont.n0, *np;
        {
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG build...
         }
        for i := am.top to top-1 do
            am.d[i] := 0;
        for i := tmp.top to top-1 do
            tmp.d[i] := 0;
        {
         * copy mont.N.d[] to improve cache locality
         }
        for np := am.d + top, i = 0 to top-1 do
            np[i] := mont.N.d[i];
        bn_scatter5(tmp.d, top, powerbuf, 0);
        bn_scatter5(am.d, am.top, powerbuf, 1);
        bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
        bn_scatter5(tmp.d, top, powerbuf, 2);
{$IF false}
        for i := 3 to 31 do begin
            { Calculate a^i = a^(i-1) * a }
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        end;
{$ELSE} { same as above, but uses squaring for 1/2 of operations }
        for (i = 4; i < 32; i *= 2) begin
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, i);
        end;
        for (i = 3; i < 8; i += 2) begin
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            for (j = 2 * i; j < 32; j *= 2) begin
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_scatter5(tmp.d, top, powerbuf, j);
            end;
        end;
        for (; i < 16; i += 2) begin
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, 2 * i);
        end;
        for (; i < 32; i += 2) begin
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        end;
{$ENDIF}
        {
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         }
        window0 := (bits - 1) % 5 + 1;
        wmask := (1  shl  window0) - 1;
        bits  := bits - window0;
        wvalue := bn_get_bits(p, bits) and wmask;
        bn_gather5(tmp.d, top, powerbuf, wvalue);
        {
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         }
        if top and 7 then begin
            while bits > 0 do  begin
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top,
                                    bn_get_bits5(p.d, bits  := bn_get_bits5(p.d, bits - (5)));
            end;
        end
        else begin
            while bits > 0 do  begin
                bn_power5(tmp.d, tmp.d, powerbuf, np, n0, top,
                          bn_get_bits5(p.d, bits  := bn_get_bits5(p.d, bits - (5)));
            end;
        end;
        ret := bn_from_montgomery(tmp.d, tmp.d, nil, np, n0, top);
        tmp.top := top;
        bn_correct_top(&tmp);
        if ret then begin
            if 0>= BN_copy(rr, &tmp) then
                ret := 0;
            goto_err ;           { non-zero ret means it's not error }
        end;
    end;
 else
{$ENDIF}
    begin
        if 0>= MOD_EXP_CTIME_COPY_TO_PREBUF(@tmp, top, powerbuf, 0, window) then
            goto _err ;
        if 0>= MOD_EXP_CTIME_COPY_TO_PREBUF(@am, top, powerbuf, 1, window) then
            goto _err ;
        {
         * If the window size is greater than 1, then calculate
         * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1) (even
         * powers could instead be computed as (a^(i/2))^2 to use the slight
         * performance advantage of sqr over mul).
         }
        if window > 1 then
        begin //same as vc
            if 0>= bn_mul_mont_fixed_top(@tmp, @am, @am, mont, ctx) then
                goto _err ;
            if 0>= MOD_EXP_CTIME_COPY_TO_PREBUF(@tmp, top, powerbuf, 2, window) then
                goto _err ;
            for i := 3 to numPowers-1 do
            begin
                { Calculate a^i = a^(i-1) * a }
                if 0>= bn_mul_mont_fixed_top(@tmp, @am, @tmp, mont, ctx )then
                    goto _err ;
                if 0>= MOD_EXP_CTIME_COPY_TO_PREBUF(@tmp, top, powerbuf, i,
                                                  window) then
                    goto _err ;
            end;
        end;
        {
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         }
        window0 := (bits - 1) mod window + 1;
        wmask := (1  shl  window0) - 1;
        bits  := bits - window0;
        wvalue := bn_get_bits(p, bits) and wmask;
        if 0>= MOD_EXP_CTIME_COPY_FROM_PREBUF(@tmp, top, powerbuf, wvalue, window) then
            goto _err ; //same as vc
        wmask := (1  shl  window) - 1;
        {
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         } //same as vc
        while bits > 0 do
        begin
            { Square the result window-size times }
            for i := 0 to window-1 do
                if 0>= bn_mul_mont_fixed_top(@tmp, @tmp, @tmp, mont, ctx) then
                    goto _err ;
            {
             * Get a window's worth of bits from the exponent
             * This avoids calling BN_is_bit_set for each bit, which
             * is not only slower but also makes each bit vulnerable to
             * EM (and likely other) side-channel attacks like One&Done
             * (for details see "One&Done: A Single-Decryption EM-Based
             *  Attack on OpenSSL's Constant-Time Blinded RSA" by M. Alam,
             *  H. Khan, M. Dey, N. Sinha, R. Callan, A. Zajic, and
             *  M. Prvulovic, in USENIX Security'18)
             }
            bits  := bits - window;
            wvalue := bn_get_bits(p, bits) and wmask;
            {
             * Fetch the appropriate pre-computed value from the pre-buf
             }
            if 0>= MOD_EXP_CTIME_COPY_FROM_PREBUF(@am, top, powerbuf, wvalue,
                                                window) then
                goto _err ;
            { Multiply the result into the intermediate result }
            if 0>= bn_mul_mont_fixed_top(@tmp, @tmp, @am, mont, ctx ) then
                goto _err ;
        end; //-->while bits > 0
    end;
    {
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     }
{$IF defined(SPARC_T4_MONT)}
    if OPENSSL_sparcv9cap_P[0] and (SPARCV9_VIS3 or SPARCV9_PREFER_FPU then ) begin
        am.d[0] := 1;            { borrow am }
        for i := 1 to top-1 do
            am.d[i] := 0;
        if 0>= BN_mod_mul_montgomery(rr, &tmp, &am, mont, ctx then )
            goto_err ;
    end;
 else
{$ENDIF}   //err at here
    if 0>= BN_from_montgomery(rr, @tmp, mont, ctx) then  //same as vc
       goto _err ;
    ret := 1;

 _err:
    if in_mont = nil then
       BN_MONT_CTX_free(mont);
    if powerbuf <> nil then
    begin
        OPENSSL_cleanse(powerbuf, powerbufLen);
        OPENSSL_free(powerbufFree);
    end;
    BN_CTX_end(ctx);
    Result := ret;
 {$POINTERMATH OFF}
 {$Q+}
end;

function BN_mod_exp_mont(rr : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX):integer;
var
  i, j, bits, wstart,
  wend, window, wvalue,
  ret, start : integer;
  d, r, aa : PBIGNUM;
  val : array[0..(TABLE_SIZE)-1] of PBIGNUM;
  mont : PBN_MONT_CTX;
  function get_val: PBIGNUM;
  begin
     val[i] := BN_CTX_get(ctx);
     Exit(val[i]);
  end;
  label _err;
begin
{$POINTERMATH ON}
{$Q-}
    ret := 0;
    start := 1;
    { Table of variables obtained from 'ctx' }
    mont := nil;
    if (BN_get_flags(p, BN_FLG_CONSTTIME) <> 0 )
             or  (BN_get_flags(a, BN_FLG_CONSTTIME) <> 0)
             or  (BN_get_flags(m, BN_FLG_CONSTTIME) <> 0)  then
    begin
        Exit(BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont));
    end;
    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);
    if not BN_is_odd(m)  then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS);
        Exit(0);
    end;
    bits := BN_num_bits(p);
    if bits = 0 then
    begin
        { x**0 mod 1, or x**0 mod -1 is still zero. }
        if BN_abs_is_word(m, 1) then
        begin
            ret := 1;
            BN_zero(rr);
        end
        else
        begin
            ret := BN_one(rr);
        end;
        Exit(ret);
    end;
    BN_CTX_start(ctx);
    d := BN_CTX_get(ctx);
    r := BN_CTX_get(ctx);
    val[0] := BN_CTX_get(ctx);
    if val[0] = nil then
       goto _err ;
    {
     * If this is not done, things will break in the montgomery part
     }
    if in_mont <> nil then
       mont := in_mont
    else
    begin
        mont := BN_MONT_CTX_new();
        if mont = nil then
            goto _err ;
        if 0>= BN_MONT_CTX_set(mont, m, ctx )  then
            goto _err ;
    end;
    if (a.neg >0) or  (BN_ucmp(a, m) >= 0)  then
    begin
        if 0>= BN_nnmod(val[0], a, m, ctx) then
            goto _err ;
        aa := val[0];
    end
    else
        aa := a;
    if 0>= bn_to_mont_fixed_top(val[0], aa, mont, ctx) then
        goto _err ;               { 1 }
    window := BN_window_bits_for_exponent_size(bits);
    if window > 1 then
    begin
        if 0>= bn_mul_mont_fixed_top(d, val[0], val[0], mont, ctx) then
            goto _err ;           { 2 }
        j := 1  shl  (window - 1);
        for i := 1 to j-1 do
        begin
            if (get_val = nil) or
               (0>= bn_mul_mont_fixed_top(val[i], val[i - 1], d, mont, ctx)) then
                goto _err ;
        end;
    end;
    start := 1;                  { This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. }
    wvalue := 0;                 { The 'value' of the window }
    wstart := bits - 1;          { The top bit of the window }
    wend := 0;                   { The bottom bit of the window }
{$IF true}                           { by Shay Gueron's suggestion }
    j := m.top;                 { borrow j }
    //if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1)))
    if m.d[j - 1] and (BN_ULONG(1)  shl  (BN_BITS2 - 1)) >0   then
    begin
        if bn_wexpand(r, j) = nil then
            goto _err ;
        { 2^(top*BN_BITS2) - m }
        r.d[0] := (0 - m.d[0]) and BN_MASK2;
        for i := 1 to j-1 do
            r.d[i] := (not m.d[i]) and BN_MASK2;
        r.top := j;
        r.flags  := r.flags  or BN_FLG_FIXED_TOP;
    end
    else
{$ENDIF}
    if 0 >= bn_to_mont_fixed_top(r, BN_value_one, mont, ctx) then
        goto _err ;
    while true do
    begin
        if BN_is_bit_set(p, wstart) = 0  then
        begin
            if 0>= start then
            begin
                if 0>= bn_mul_mont_fixed_top(r, r, r, mont, ctx) then
                   goto _err ;
            end;
            if wstart = 0 then
               break;
            Dec(wstart);
            continue;
        end;
        {
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         }
        wvalue := 1;
        wend := 0;
        for i := 1 to window-1 do
        begin
            if wstart - i < 0 then
               break;
            if BN_is_bit_set(p, wstart - i )>0  then
            begin
                wvalue  := wvalue shl  (i - wend);
                wvalue  := wvalue or 1;
                wend := i;
            end;
        end;
        { wend is the size of the current window }
        j := wend + 1;
        { add the 'bytes above' }
        if 0>= start then
        for i := 0 to j-1 do
        begin
           if 0>= bn_mul_mont_fixed_top(r, r, r, mont, ctx) then
              goto _err ;
        end;
        { wvalue will be an odd number < 2^window }
        if 0>= bn_mul_mont_fixed_top(r, r, val[wvalue  shr  1], mont, ctx) then
            goto _err ;
        { move the 'window' down further }
        wstart  := wstart - (wend + 1);
        wvalue := 0;
        start := 0;
        if wstart < 0 then break;
    end; //-->while true do
    {
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     }
{$IF defined(SPARC_T4_MONT)}
    if OPENSSL_sparcv9cap_P[0] and (SPARCV9_VIS3 or SPARCV9_PREFER_FPU then )
    begin
        j := mont.N.top;        { borrow j }
        val[0].d[0] := 1;       { borrow val[0] }
        for i := 1 to j-1 do
            val[0].d[i] := 0;
        val[0].top := j;
        if 0>= BN_mod_mul_montgomery(rr, r, val[0], mont, ctx then )
            goto_err ;
    end;
 else
{$ENDIF}
    if 0>= BN_from_montgomery(rr, r, mont, ctx) then
        goto _err ;
    ret := 1;
 _err:
    if in_mont = nil then
       BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    Result := ret;
 {$POINTERMATH OFF}
 {$Q+}
end;

function BN_mod_exp_mont_word(rr : PBIGNUM; a : BN_ULONG;const p, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX):integer;
var
  mont     : PBN_MONT_CTX;
  b, bits,
  ret, r_is_one : integer;
  w, next_w   : BN_ULONG;
  r, t, swap_tmp : PBIGNUM;
  label _err;

  //#define BN_MOD_MUL_WORD(r, w, m)
  function ok: Integer;
  begin
     swap_tmp := r; r := t; t := swap_tmp;
     result := 1;
  end;
  function BN_MOD_MUL_WORD: Boolean;
  begin

     Result := (BN_mul_word(r, w) >0) and
               (BN_mod(t, r, m, ctx) > 0) and (ok > 0);
  end;

  //#define BN_TO_MONTGOMERY_WORD(r, w, mont)
  function BN_TO_MONTGOMERY_WORD: Boolean;
  begin
     Result := (BN_set_word(r, w)>0) and (BN_to_montgomery(r, r, mont, ctx)>0)
  end;

begin
{$POINTERMATH ON}
{$Q-}
    mont := nil;
    ret := 0;
    if (BN_get_flags(p, BN_FLG_CONSTTIME) <> 0) or
       (BN_get_flags(m, BN_FLG_CONSTTIME) <> 0)  then
    begin
        { BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() }
        ERR_raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    bn_check_top(p);
    bn_check_top(m);
    if not BN_is_odd(m)  then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS);
        Exit(0);
    end;
    if m.top = 1 then
       a  := a mod (m.d[0]);
    bits := BN_num_bits(p);
    if bits = 0 then
    begin
        { x**0 mod 1, or x**0 mod -1 is still zero. }
        if BN_abs_is_word(m, 1) then
        begin
            ret := 1;
            BN_zero(rr);
        end
        else
        begin
            ret := BN_set_word(rr,1); //BN_one(rr);
        end;
        Exit(ret);
    end;
    if a = 0 then
    begin
        BN_zero(rr);
        ret := 1;
        Exit(ret);
    end;
    BN_CTX_start(ctx);
    r := BN_CTX_get(ctx);
    t := BN_CTX_get(ctx);
    if t = nil then
       goto _err ;
    if in_mont <> nil then
       mont := in_mont
    else
    begin
        mont := BN_MONT_CTX_new() ;
        if mont = nil then
            goto _err ;
        if 0>= BN_MONT_CTX_set(mont, m, ctx) then
            goto _err ;
    end;
    r_is_one := 1;               { except for Montgomery factor }
    { bits-1 >= 0 }
    { The result is accumulated in the product r*w. }
    w := a;                      { bit 'bits-1' of 'p' is always set }
    for b := bits - 2 downto 0 do
    begin
        { First, square r*w. }
        next_w := w * w;
       
        if (next_w div w ) <> w then
        begin  { overflow }
            if r_is_one>0 then
            begin
                if not BN_TO_MONTGOMERY_WORD() then
                   goto _err ;
                r_is_one := 0;
            end
            else
            begin
                //#define BN_MOD_MUL_WORD(r, w, m)
                if not BN_MOD_MUL_WORD() then
                    goto _err ;
            end;
            next_w := 1;
        end;
        w := next_w;
        if 0>= r_is_one then
        begin
            if 0>= BN_mod_mul_montgomery(r, r, r, mont, ctx) then
                goto _err ;
        end;
        { Second, multiply r*w by 'a' if exponent bit is set. }
        if BN_is_bit_set(p, b)>0 then
        begin
            next_w := w * a;
            if (next_w div a ) <> w then
            begin  { overflow }
                if r_is_one >0 then
                begin
                    if not BN_TO_MONTGOMERY_WORD then
                        goto _err ;
                    r_is_one := 0;
                end
                else
                begin
                    if not BN_MOD_MUL_WORD then
                        goto _err ;
                end;
                next_w := a;
            end;
            w := next_w;
        end;
    end;
    { Finally, set r:=r*w. }
    if w <> 1 then
    begin
        if r_is_one >0 then
        begin
            if not BN_TO_MONTGOMERY_WORD then
                goto _err ;
            r_is_one := 0;
        end
        else
        begin
            if not BN_MOD_MUL_WORD  then
               goto _err ;
        end;
    end;
    if r_is_one >0 then
    begin              { can happen only if a = 1 }
        if 0>= BN_set_word(rr,1) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_from_montgomery(rr, r, mont, ctx) then
            goto _err ;
    end;
    ret := 1;

 _err:
    if in_mont = nil then
       BN_MONT_CTX_free(mont);

    BN_CTX_end(ctx);
    bn_check_top(rr);
    Result := ret;
 {$POINTERMATH OFF}
 {$Q+}
end;

function BN_mod_exp(r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
  _A : BN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);
    {-
     * For even modulus  m = 2^k*m_odd, it might make sense to compute
     * a^p mod m_odd  and  a^p mod 2^k  separately (with Montgomery
     * exponentiation for the odd part), using appropriate exponent
     * reductions, and combine the results using the CRT.
     *
     * exponentiation using the reciprocal-based quick remaindering
     * algorithm is used.
     *
     * (Timing obtained with expspeed.c [computations  a^p mod m
     * where  a, p, m  are of the same length: 256, 512, 1024, 2048,
     * 4096, 8192 bits], compared to the running time of the
     * standard algorithm:
     *
     *   BN_mod_exp_mont   33 .. 40 %  [AMD K6-2, Linux, debug configuration]
     *                     55 .. 77 %  [UltraSparc processor, but
     *                                  debug-solaris-sparcv8-gcc conf.]
     *
     *   BN_mod_exp_recp   50 .. 70 %  [AMD K6-2, Linux, debug configuration]
     *                     62 .. 118 % [UltraSparc, debug-solaris-sparcv8-gcc]
     *
     * On the Sparc, BN_mod_exp_recp was faster than BN_mod_exp_mont
     * at 2048 and more bits, but at 512 and 1024 bits, it was
     * slower even than the standard algorithm!
     *
     * 'Real' timings [linux-elf, solaris-sparcv9-gcc configurations]
     * should be obtained when the new Montgomery reduction code
     * has been integrated into OpenSSL.)
     }
{$DEFINE MONT_MUL_MOD}
{$DEFINE MONT_EXP_WORD}
{$DEFINE RECP_MUL_MOD}
{$IFDEF MONT_MUL_MOD}
    if BN_is_odd(m) then
    begin
{$IFDEF MONT_EXP_WORD}
        if (a.top = 1)  and  (0>= a.neg)
             and  (BN_get_flags(p, BN_FLG_CONSTTIME) = 0)
             and  (BN_get_flags(a, BN_FLG_CONSTTIME) = 0)
             and  (BN_get_flags(m, BN_FLG_CONSTTIME) = 0) then
        begin
            _A := a.d[0];
            ret := BN_mod_exp_mont_word(r, _A, p, m, ctx, nil);
        end
        else
{$ENDIF}
            ret := BN_mod_exp_mont(r, a, p, m, ctx, nil);
    end
    else
{$ENDIF}
{$IFDEF RECP_MUL_MOD}
    begin
        ret := BN_mod_exp_recp(r, a, p, m, ctx);
    end;
{$ELSE}
    begin
        ret := BN_mod_exp_simple(r, a, p, m, ctx);
    end;
{$ENDIF}
    bn_check_top(r);
    Result := ret;
{$POINTERMATH OFF}
end;

end.
