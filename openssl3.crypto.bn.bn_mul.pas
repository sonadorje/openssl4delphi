unit openssl3.crypto.bn.bn_mul;

{$I config.inc}
interface
 uses OpenSSL.Api;

function bn_mul_fixed_top(r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
procedure bn_mul_normal( r, a : PBN_ULONG; na : integer; b : PBN_ULONG; nb : integer);
function BN_mul(r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
procedure bn_mul_part_recursive( r, a, b : PBN_ULONG; n, tna, tnb : integer; t : PBN_ULONG);
function bn_sub_part_words(r : PBN_ULONG;{const} a, b : PBN_ULONG; cl, dl : integer):BN_ULONG;
procedure bn_mul_recursive( r, a, b : PBN_ULONG; n2, dna, dnb : integer; t : PBN_ULONG);

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.bn.bn_lib,         openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_sqr,         openssl3.crypto.bn.bn_asm;

procedure bn_mul_recursive( r, a, b : PBN_ULONG; n2, dna, dnb : integer; t : PBN_ULONG);
var
  n, tna, tnb, OWC10XP, c1, c2 : integer;
  neg, zero : uint32;
  ln, lo: BN_ULONG;
  p : PBN_ULONG;
begin
{$POINTERMATH ON}
    n := n2 div 2;
    tna := n + dna; tnb := n + dnb;
{$IFDEF BN_MUL_COMBA}
{$IF false}
    if n2 = 4 then begin
        bn_mul_comba4(r, a, b);
        return;
    end;
{$IFEND}
    {
     * Only call bn_mul_comba 8 if n2 = 8 and the two arrays are complete
     * [steve]
     }
    if (n2 = 8)  and  (dna = 0)  and  (dnb = 0) then
    begin
        bn_mul_comba8(r, a, b);
        Exit;
    end;
{$endif}                         { BN_MUL_COMBA }
    { Else do normal multiply }
    if n2 < BN_MUL_RECURSIVE_SIZE_NORMAL then
    begin
        bn_mul_normal(r, a, n2 + dna, b, n2 + dnb);
        if dna + dnb < 0 then
            memset(@r[2 * n2 + dna + dnb], 0,
                   sizeof(BN_ULONG) * -(dna + dnb));
        exit;
    end;
    { r=(a[0]-a[1])*(b[1]-b[0]) }
    c1 := bn_cmp_part_words(a, @a[n], tna, n - tna);
    c2 := bn_cmp_part_words(@b[n], b, tnb, tnb - n);
    zero := 0; neg := 0;
    case c1 * 3 + c2 of
        -4:
        begin
            bn_sub_part_words(t, @(a[n]), a, tna, tna - n); { - }
            bn_sub_part_words(@(t[n]), b, @(b[n]), tnb, n - tnb); { - }
        end;
        -3:
            zero := 1;
            //break;
        -2:
        begin
            bn_sub_part_words(t, @(a[n]), a, tna, tna - n); { - }
            bn_sub_part_words(@(t[n]), @(b[n]), b, tnb, tnb - n); { + }
            neg := 1;
        end;
        -1,
        0,
        1:
            zero := 1;
            //break;
        2:
        begin
            bn_sub_part_words(t, a, @(a[n]), tna, n - tna); { + }
            bn_sub_part_words(@(t[n]), b, @(b[n]), tnb, n - tnb); { - }
            neg := 1;
        end;
        3:
            zero := 1;
            //break;
        4:
        begin
            bn_sub_part_words(t, a, @(a[n]), tna, n - tna);
            bn_sub_part_words(@(t[n]), @(b[n]), b, tnb, tnb - n);
        end;
    end;
{$IFDEF BN_MUL_COMBA}
    if (n = 4)  and  (dna = 0)  and  (dnb = 0) then begin  { XXX: bn_mul_comba4 could take
                                           * extra args to do this well }
        if 0>=zero then
            bn_mul_comba4(@(t[n2]), t, @(t[n]))
        else
            memset(@t[n2], 0, sizeof( t^) * 8);
        bn_mul_comba4(r, a, b);
        bn_mul_comba4(@(r[n2]), @(a[n]), @(b[n]));
    end
    else
    if (n = 8)  and  (dna = 0)  and  (dnb = 0) then begin  { XXX: bn_mul_comba8 could
                                                  * take extra args to do
                                                  * this well }
        if 0>=zero then
           bn_mul_comba8(@(t[n2]), t, @(t[n]))
        else
            memset(@t[n2], 0, sizeof( t^) * 16);
        bn_mul_comba8(r, a, b);
        bn_mul_comba8(@(r[n2]), @(a[n]), @(b[n]));
    end
    else
{$endif}                         { BN_MUL_COMBA }
    begin
        p := @(t[n2 * 2]);
        if 0>=zero then
           bn_mul_recursive(@(t[n2]), t, @(t[n]), n, 0, 0, p)
        else
            memset(@t[n2], 0, sizeof( t^) * n2);
        bn_mul_recursive(r, a, b, n, 0, 0, p);
        bn_mul_recursive(@(r[n2]), @(a[n]), @(b[n]), n, dna, dnb, p);
    end;
    {-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     }
    c1 := int((bn_add_words(t, r, @(r[n2]), n2)));
    if neg > 0 then begin                   { if t[32] is negative }
        c1  := c1 - int((bn_sub_words(@(t[n2]), t, @(t[n2]), n2)));
    end
    else begin
        { Might have a carry }
        c1  := c1 + int((bn_add_words(@(t[n2]), @(t[n2]), t, n2)));
    end;
    {-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     * c1 holds the carry bits
     }
    c1  := c1 + int((bn_add_words(@(r[n]), @(r[n]), @(t[n2]), n2)));
    if c1 > 0 then begin
        p := @(r[n + n2]);
        lo := p^;
        ln := (lo + c1) and BN_MASK2;
        p^ := ln;
        {
         * The overflow will stop before we over write words we should not
         * overwrite
         }
        if ln < BN_ULONG(c1) then
        begin
            repeat
                Inc(p);
                lo := p^;
                ln := (lo + 1) and BN_MASK2;
                p^ := ln;
            until not (ln = 0);
        end;
    end;
 {$POINTERMATH OFF}
end;

function bn_sub_part_words(r : PBN_ULONG;{const} a, b : PBN_ULONG; cl, dl : integer):BN_ULONG;
var
  c, t : BN_ULONG;
  save_dl : integer;
  label _fall1, _fall2, _fall3, _break;
begin
{$POINTERMATH ON}
    assert(cl >= 0);
    c := bn_sub_words(r, a, b, cl);
    if dl = 0 then Exit(c);
    r  := r + cl;
    a  := a + cl;
    b  := b + cl;
    if dl < 0 then
    begin
        while true do
        begin
            t := b[0];
            r[0] := (0 - t - c) and BN_MASK2;
            if t <> 0 then c := 1;
            if PreInc(dl) >= 0  then
                break;
            t := b[1];
            r[1] := (0 - t - c) and BN_MASK2;
            if t <> 0 then c := 1;
            if PreInc(dl) >= 0  then
                break;
            t := b[2];
            r[2] := (0 - t - c) and BN_MASK2;
            if t <> 0 then c := 1;
            if PreInc(dl) >= 0  then
                break;
            t := b[3];
            r[3] := (0 - t - c) and BN_MASK2;
            if t <> 0 then c := 1;
            if PreInc(dl) >= 0  then
                break;
            b  := b + 4;
            r  := r + 4;
        end;
    end
    else
    begin
        save_dl := dl;
        while c > 0 do
        begin
            t := a[0];
            r[0] := (t - c) and BN_MASK2;
            if t <> 0 then c := 0;
            if PreDec(dl) <= 0  then
                break;
            t := a[1];
            r[1] := (t - c) and BN_MASK2;
            if t <> 0 then c := 0;
            if PreDec(dl) <= 0  then
                break;
            t := a[2];
            r[2] := (t - c) and BN_MASK2;
            if t <> 0 then c := 0;
            if PreDec(dl) <= 0  then
                break;
            t := a[3];
            r[3] := (t - c) and BN_MASK2;
            if t <> 0 then c := 0;
            if PreDec(dl) <= 0  then
                break;
            save_dl := dl;
            a  := a + 4;
            r  := r + 4;
        end;
        if dl > 0 then
        begin
            if save_dl > dl then
            begin
               case save_dl - dl of
                  1:
                  begin
                      r[1] := a[1];
                      if PreDec(dl) <= 0  then
                          goto _break;
                      { fall thru }
                      goto _fall1;
                  end;
                  2:
                  begin
          _fall1:
                      r[2] := a[2];
                      if PreDec(dl) <= 0  then
                          goto _break;
                      { fall thru }
                      goto _fall2;
                  end;
                  3:
                  begin
          _fall2:
                      r[3] := a[3];
                      if PreDec(dl) <= 0  then
                          goto _break;
                  end;
               end;
_break:
                a  := a + 4;
                r  := r + 4;
            end;
        end;
        if dl > 0 then
        begin
            while true do
            begin
                r[0] := a[0];
                if PreDec(dl) <= 0 then
                    break;
                r[1] := a[1];
                if PreDec(dl) <= 0 then
                    break;
                r[2] := a[2];
                if PreDec(dl) <= 0 then
                    break;
                r[3] := a[3];
                if PreDec(dl) <= 0 then
                    break;
                a  := a + 4;
                r  := r + 4;
            end;
        end;
    end;
    Result := c;
 {$POINTERMATH OFF}
end;

(*
 * n+tn is the word length t needs to be n*4 is size, as does r
 *
 * tnX may not be negative but less than n *)
procedure bn_mul_part_recursive( r, a, b : PBN_ULONG; n, tna, tnb : integer; t : PBN_ULONG);
var
  i, j, n2, c1, c2, neg : integer;
  ln, lo:BN_ULONG;
  p : PBN_ULONG;
begin
{$POINTERMATH ON}
    n2 := n * 2;
    if n < 8 then begin
        bn_mul_normal(r, a, n + tna, b, n + tnb);
        exit;
    end;
    { r=(a[0]-a[1])*(b[1]-b[0]) }
    c1 := bn_cmp_part_words(a, @(a[n]), tna, n - tna);
    c2 := bn_cmp_part_words(@(b[n]), b, tnb, tnb - n);
    neg := 0;
    case c1 * 3 + c2 of
        -4:
        begin
            bn_sub_part_words(t, @(a[n]), a, tna, tna - n); { - }
            bn_sub_part_words(@(t[n]), b, @(b[n]), tnb, n - tnb); { - }
        end;
        -3,
        -2:
        begin
            bn_sub_part_words(t, @(a[n]), a, tna, tna - n); { - }
            bn_sub_part_words(@(t[n]), @(b[n]), b, tnb, tnb - n); { + }
            neg := 1;
        end;
        -1,
        0,
        1,
        2:
        begin
            bn_sub_part_words(t, a, @(a[n]), tna, n - tna); { + }
            bn_sub_part_words(@(t[n]), b, @(b[n]), tnb, n - tnb); { - }
            neg := 1;
        end;
        3,
        4:
        begin
            bn_sub_part_words(t, a, @(a[n]), tna, n - tna);
            bn_sub_part_words(@(t[n]), @(b[n]), b, tnb, tnb - n);
        end;
    end;
    {
     * The zero case isn't yet implemented here. The speedup would probably
     * be negligible.
     }
{$if false}
    if n = 4 then begin
        bn_mul_comba4(&(t[n2]), t, &(t[n]));
        bn_mul_comba4(r, a, b);
        bn_mul_normal(@(r[n2]), @(a[n]), tn, @(b[n]), tn);
        memset(&r[n2 + tn * 2], 0, sizeof( r^) * (n2 - tn * 2));
    end
    else
{$ifend}
    if n = 8 then begin
        bn_mul_comba8(@(t[n2]), t, @(t[n]));
        bn_mul_comba8(r, a, b);
        bn_mul_normal(@(r[n2]), @(a[n]), tna, @(b[n]), tnb);
        memset(@r[n2 + tna + tnb], 0, sizeof( r^) * (n2 - tna - tnb));
    end
    else
    begin
        p := @(t[n2 * 2]);
        bn_mul_recursive(@(t[n2]), t, @(t[n]), n, 0, 0, p);
        bn_mul_recursive(r, a, b, n, 0, 0, p);
        i := n div 2;
        {
         * If there is only a bottom half to the number, just do it
         }
        if tna > tnb then
           j := tna - i
        else
            j := tnb - i;
        if j = 0 then begin
            bn_mul_recursive(@(r[n2]), @(a[n]), @(b[n]),
                             i, tna - i, tnb - i, p);
            memset(@r[n2 + i * 2], 0, sizeof( r^) * (n2 - i * 2));
        end
        else
        if (j > 0) then begin      { eg, n = 16, i = 8 and tn = 11 }
            bn_mul_part_recursive(@(r[n2]), @(a[n]), @(b[n]),
                                  i, tna - i, tnb - i, p);
            memset(@(r[n2 + tna + tnb]), 0,
                   sizeof(BN_ULONG) * (n2 - tna - tnb));
        end
        else
        begin                 { (j < 0) eg, n = 16, i = 8 and tn = 5 }
            memset(@r[n2], 0, sizeof( r^) * n2);
            if (tna < BN_MUL_RECURSIVE_SIZE_NORMAL)   and
               (tnb < BN_MUL_RECURSIVE_SIZE_NORMAL) then
            begin
                bn_mul_normal(@(r[n2]), @(a[n]), tna, @(b[n]), tnb);
            end
            else
            begin
                while true do
                begin
                    i  := i  div 2;
                    {
                     * these simplified conditions work exclusively because
                     * difference between tna and tnb is 1 or 0
                     }
                    if (i < tna)  or  (i < tnb) then
                    begin
                        bn_mul_part_recursive(@(r[n2]),
                                              @(a[n]), @(b[n]),
                                              i, tna - i, tnb - i, p);
                        break;
                    end
                    else
                    if (i = tna)  or  (i = tnb) then
                    begin
                        bn_mul_recursive(@(r[n2]),
                                         @(a[n]), @(b[n]),
                                         i, tna - i, tnb - i, p);
                        break;
                    end;
                end;
            end;
        end;
    end;
    {-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     }
    c1 := int(bn_add_words(t, r, @(r[n2]), n2));
    if neg > 0 then
    begin                   { if t[32] is negative }
        c1  := c1 - int((bn_sub_words(@(t[n2]), t, @(t[n2]), n2)));
    end
    else
    begin
        { Might have a carry }
        c1  := c1 + int((bn_add_words(@(t[n2]), @(t[n2]), t, n2)));
    end;
    {-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     * c1 holds the carry bits
     }
    c1  := c1 + int((bn_add_words(@(r[n]), @(r[n]), @(t[n2]), n2)));
    if c1 > 0 then
    begin
        p := @(r[n + n2]);
        lo := p^;
        ln := (lo + c1) and BN_MASK2;
        p^ := ln;
        {
         * The overflow will stop before we over write words we should not
         * overwrite
         }
        if ln < BN_ULONG(c1) then
        begin
            repeat
                Inc(p);
                lo := p^;
                ln := (lo + 1) and BN_MASK2;
                p^ := ln;
            until not (ln = 0);
        end;
    end;
 {$POINTERMATH OFF}
end;

function BN_mul(r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
    ret := bn_mul_fixed_top(r, a, b, ctx);
    bn_correct_top(r);
    bn_check_top(r);
    Result := ret;
end;

procedure bn_mul_normal( r, a : PBN_ULONG; na : integer; b : PBN_ULONG; nb : integer);
var
  rr : PBN_ULONG;
  itmp : integer;
  ltmp : PBN_ULONG;
begin
{$POINTERMATH ON}
    if na < nb then
    begin
        itmp := na;
        na := nb;
        nb := itmp;
        ltmp := a;
        a := b;
        b := ltmp;
    end;
    rr := @r[na];
    if nb <= 0 then
    begin
        bn_mul_words(r, a, na, 0);
        exit;
    end
    else
        rr[0] := bn_mul_words(r, a, na, b[0]);
    while true do
    begin
        if PreDec(nb) <= 0  then
            exit;
        rr[1] := bn_mul_add_words(@r[1], a, na, b[1]);
        if PreDec(nb) <= 0  then
            exit;
        rr[2] := bn_mul_add_words(@r[2], a, na, b[2]);
        if PreDec(nb) <= 0  then
            exit;
        rr[3] := bn_mul_add_words(@r[3], a, na, b[3]);
        if PreDec(nb) <= 0  then
            exit;
        rr[4] := bn_mul_add_words(@r[4], a, na, b[4]);
        rr := rr + 4;
        r  := r + 4;
        b  := b + 4;
    end;
{$POINTERMATH OFF}
end;

function bn_mul_fixed_top(r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret, top, al, bl : integer;
  rr : PBIGNUM;
{$IF defined(BN_MUL_COMBA)  or  defined(BN_RECURSION)}
  i : integer;
{$IFEND}
{$ifdef BN_RECURSION}
  t : PBIGNUM;
  j, k : integer;
{$ENDIF}
  label _err, _end;
begin
    ret := 0;

{$IFDEF BN_RECURSION}
    t := nil;
    j := 0;
{$ENDIF}
    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(r);
    al := a.top;
    bl := b.top;
    if (al = 0 )  or  (bl = 0) then
    begin
        BN_zero(r);
        Exit(1);
    end;
    top := al + bl;
    BN_CTX_start(ctx);
    if (r = a )  or  (r = b) then
    begin
        rr := BN_CTX_get(ctx);
        if rr = nil then
            goto _err ;
    end
    else
        rr := r;
{$IF defined(BN_MUL_COMBA)  or  defined(BN_RECURSION)}
    i := al - bl;
{$IFEND}
{$IFDEF BN_MUL_COMBA}
    if i = 0 then
    begin
{$if false}
        if al = 4 then
        begin
            if bn_wexpand(rr, 8) = nil then
                goto _err ;
            rr.top := 8;
            bn_mul_comba4(rr.d, a.d, b.d);
            goto _end ;
        end;
{$ifend}
        if al = 8 then
        begin
            if bn_wexpand(rr, 16) = nil then
                goto _err ;
            rr.top := 16;
            bn_mul_comba8(rr.d, a.d, b.d);
            goto _end ;
        end;
    end;
{$endif}                          { BN_MUL_COMBA }
{$IFDEF BN_RECURSION}
    if (al >= BN_MULL_SIZE_NORMAL)  and  (bl >= BN_MULL_SIZE_NORMAL) then
    begin
        if (i >= -1)  and  (i <= 1) then
        begin
            {
             * Find out the power of two lower or equal to the longest of the
             * two numbers
             }
            if i >= 0 then
            begin
                j := BN_num_bits_word(BN_ULONG(al));
            end;
            if i = -1 then
            begin
                j := BN_num_bits_word(BN_ULONG(bl));
            end;
            j := 1  shl  (j - 1);
            assert( (j <= al)  or  (j <= bl) );
            k := j + j;
            t := BN_CTX_get(ctx);
            if t = nil then
               goto _err ;
            if (al > j)  or  (bl > j) then
            begin
                if bn_wexpand(t, k * 4) = nil then
                    goto _err ;
                if bn_wexpand(rr, k * 4 ) = nil then
                    goto _err ;
                bn_mul_part_recursive(rr.d, a.d, b.d,
                                      j, al - j, bl - j, t.d);
            end
            else
            begin             { al <= j  or  bl <= j }
                if bn_wexpand(t, k * 2 ) = nil then
                    goto _err ;
                if bn_wexpand(rr, k * 2) = nil then
                    goto _err ;
                bn_mul_recursive(rr.d, a.d, b.d, j, al - j, bl - j, t.d);
            end;
            rr.top := top;
            goto _end ;
        end;
    end;
{$endif}                          { BN_RECURSION }
    if bn_wexpand(rr, top) = nil  then
        goto _err ;
    rr.top := top;
    bn_mul_normal(rr.d, a.d, al, b.d, bl);
{$IF defined(BN_MUL_COMBA)  or  defined(BN_RECURSION)}
 _end:
{$IFEND}
    rr.neg := a.neg  xor  b.neg;
    rr.flags  := rr.flags  or BN_FLG_FIXED_TOP;
    if (r <> rr)  and ( BN_copy(r, rr) = nil)  then
        goto _err ;
    ret := 1;

 _err:
    bn_check_top(r);
    BN_CTX_end(ctx);
    Result := ret;
end;

end.
