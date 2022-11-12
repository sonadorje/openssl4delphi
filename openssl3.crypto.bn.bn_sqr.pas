unit openssl3.crypto.bn.bn_sqr;

{$I config.inc}
interface
 uses OpenSSL.Api;

function bn_sqr_fixed_top(r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
 procedure bn_sqr_normal(r : PBN_ULONG;const a : PBN_ULONG; n : integer; tmp : PBN_ULONG);
 function BN_sqr(r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
procedure bn_sqr_recursive(r : PBN_ULONG;const a : PBN_ULONG; n2 : integer; t : PBN_ULONG);

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.bn.bn_lib,         openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_asm;

procedure bn_sqr_recursive(r : PBN_ULONG;const a : PBN_ULONG; n2 : integer; t : PBN_ULONG);
var
  n, zero, c1 : integer;
  ln, lo: BN_ULONG;
  p : PBN_ULONG;
begin
{$POINTERMATH ON}
    n := n2 div 2;
    if n2 = 4 then
    begin
  {$ifndef BN_SQR_COMBA}
        bn_sqr_normal(r, a, 4, t);
  {$else}
        bn_sqr_comba4(r, a);
  {$endif}
        Exit;
    end
    else if (n2 = 8) then
    begin
  {$ifndef BN_SQR_COMBA }
        bn_sqr_normal(r, a, 8, t);
  {$else}
        bn_sqr_comba8(r, a);
  {$endif }
        Exit;
    end;
    if n2 < BN_SQR_RECURSIVE_SIZE_NORMAL then
    begin
        bn_sqr_normal(r, a, n2, t);
        Exit;
    end;
    { r=(a[0]-a[1])*(a[1]-a[0]) }
    c1 := bn_cmp_words(a, @(a[n]), n);
    zero := 0;
    if c1 > 0 then
       bn_sub_words(t, a, @(a[n]), n)
    else if (c1 < 0) then
        bn_sub_words(t, @(a[n]), a, n)
    else
        zero := 1;
    { The result will always be negative unless it is zero }
    p := @(t[n2 * 2]);
    if 0>=zero then
       bn_sqr_recursive(@(t[n2]), t, n, p)
    else
        memset(@t[n2], 0, sizeof( t^) * n2);
    bn_sqr_recursive(r, a, n, p);
    bn_sqr_recursive(@(r[n2]), @(a[n]), n, p);
    {-
     * t[32] holds (a[0]-a[1])*(a[1]-a[0]), it is negative or zero
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     }
    c1 := int(bn_add_words(t, r, @(r[n2]), n2));
    { t[32] is negative }
    c1  := c1 - int(bn_sub_words(@(t[n2]), t, @(t[n2]), n2));
    {-
     * t[32] holds (a[0]-a[1])*(a[1]-a[0])+(a[0]*a[0])+(a[1]*a[1])
     * r[10] holds (a[0]*a[0])
     * r[32] holds (a[1]*a[1])
     * c1 holds the carry bits
     }
    c1  := c1 + int(bn_add_words(@(r[n]), @(r[n]), @(t[n2]), n2));
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

function BN_sqr(r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
    ret := bn_sqr_fixed_top(r, a, ctx);
    bn_correct_top(r);
    bn_check_top(r);
    Result := ret;
end;

procedure bn_sqr_normal(r : PBN_ULONG;const a : PBN_ULONG; n : integer; tmp : PBN_ULONG);
var
  i, j, max : integer;
  ap, rp : PBN_ULONG;
begin
{$POINTERMATH ON}
    max := n * 2;
    ap := a;
    rp := r;
    rp[0] := 0; rp[max - 1] := 0;
    Inc(rp);
    j := n;
    if PreDec(j)> 0  then
    begin
        Inc(ap);
        rp[j] := bn_mul_words(rp, ap, j, ap[-1]);
        rp  := rp + 2;
    end;
    for i := n - 2 downto 1 do
    begin
        Dec(j);
        Inc(ap);
        rp[j] := bn_mul_add_words(rp, ap, j, ap[-1]);
        rp  := rp + 2;
    end;
    bn_add_words(r, r, r, max);
    { There will not be a carry }
    bn_sqr_words(tmp, a, n);
    bn_add_words(r, r, tmp, max);
{$POINTERMATH OFF}
end;

function bn_sqr_fixed_top(r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
var
  max, al, ret : integer;
  tmp, rr : PBIGNUM;
  t : array of BN_ULONG;
  j, k : integer;
  label _err;
begin
    ret := 0;
    bn_check_top(a);
    al := a.top;
    if al <= 0 then
    begin
        r.top := 0;
        r.neg := 0;
        Exit(1);
    end;
    BN_CTX_start(ctx);
    if (a <> r) then
       rr :=  r
    else
       rr := BN_CTX_get(ctx);

    tmp := BN_CTX_get(ctx);
    if (rr = nil)  or  (tmp = nil) then
       goto _err ;
    max := 2 * al;               { Non-zero (from above) }
    if bn_wexpand(rr, max)= nil  then
        goto _err ;
    if al = 4 then
    begin
{$IFNDEF BN_SQR_COMBA}
        SetLength(t,8);
        bn_sqr_normal(rr.d, a.d, 4, @t);
{$ELSE}
        bn_sqr_comba4(rr.d, a.d);
{$ENDIF}
    end
    else
    if (al = 8) then
    begin
{$IFNDEF BN_SQR_COMBA}
        SetLength(t, 16);
        bn_sqr_normal(rr.d, a.d, 8, @t);
{$ELSE}
        bn_sqr_comba8(rr.d, a.d);
{$ENDIF}
    end
    else
    begin
{$IF defined(BN_RECURSION)}
        if al < BN_SQR_RECURSIVE_SIZE_NORMAL then
        begin
            SetLength(t, BN_SQR_RECURSIVE_SIZE_NORMAL * 2);
            bn_sqr_normal(rr.d, a.d, al, @t[0]);
        end
        else
        begin
            j := BN_num_bits_word(BN_ULONG(al));
            j := 1  shl  (j - 1);
            k := j + j;
            if al = j then
            begin
                if bn_wexpand(tmp, k * 2) = nil then
                    goto _err ;
                bn_sqr_recursive(rr.d, a.d, al, tmp.d);
            end
            else
            begin
                if bn_wexpand(tmp, max) = nil  then
                    goto _err ;
                bn_sqr_normal(rr.d, a.d, al, tmp.d);
            end;
        end;
{$ELSE} if bn_wexpand(tmp, max) = nil  then
            goto _err ;
        bn_sqr_normal(rr.d, a.d, al, tmp.d);
{$IFEND}
    end;
    rr.neg := 0;
    rr.top := max;
    rr.flags  := rr.flags  or BN_FLG_FIXED_TOP;
    if (r <> rr)  and  (BN_copy(r, rr) = nil)  then
        goto _err ;
    ret := 1;
 _err:
    bn_check_top(rr);
    bn_check_top(tmp);
    BN_CTX_end(ctx);
    SetLength(t, 0);
    Result := ret;
end;

end.
