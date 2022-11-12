unit openssl3.crypto.bn.bn_mod;

interface
 uses OpenSSL.Api;

function BN_mod_mul(r : PBIGNUM;const a, b, m : PBIGNUM; ctx : PBN_CTX):integer;
function BN_nnmod(r : PBIGNUM;const m, d : PBIGNUM; ctx : PBN_CTX):integer;
function BN_mod_add_quick(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
function bn_mod_add_fixed_top(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
 function BN_mod_sqr(r : PBIGNUM;const a, m : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_mod_lshift1_quick(r : PBIGNUM;const a, m : PBIGNUM):integer;
 function BN_mod_sub_quick(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
 function BN_mod_sub(r : PBIGNUM;const a, b, m : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_mod_add(r : PBIGNUM;const a, b, m : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_mod_lshift_quick(r : PBIGNUM;const a : PBIGNUM; n : integer;const m : PBIGNUM):integer;
 function bn_mod_sub_fixed_top(r : PBIGNUM;const a, b, m : PBIGNUM):integer;

implementation
uses openssl3.crypto.bn.bn_lib,   openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_add,   openssl3.crypto.mem,
     OpenSSL3.Err,                openssl3.crypto.bn.bn_asm,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_mul,
     openssl3.crypto.bn.bn_sqr;

{$Q-}
function bn_mod_sub_fixed_top(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
var
  i, ai, bi, mtop : size_t;
  borrow, carry, ta, tb, mask: BN_ULONG;
  ap, bp, rp : PBN_ULONG;
begin
{$POINTERMATH ON}
    mtop := m.top;
    if bn_wexpand(r, mtop )= nil then
        Exit(0);
    rp := r.d;
    ap := get_result(a.d <> nil , a.d , rp);
    bp := get_result(b.d <> nil , b.d , rp);
    i := 0; ai := 0; bi := 0; borrow := 0;
    while (i < mtop) do
    begin
        mask := BN_ULONG(0) - ((i - a.top)  shr  (8 * sizeof(i) - 1));
        ta := ap[ai] and mask;
        mask := BN_ULONG(0) - ((i - b.top)  shr  (8 * sizeof(i) - 1));
        tb := bp[bi] and mask;
        rp[i] := ta - tb - borrow;
        if ta <> tb then
           borrow := int(ta < tb);
        Inc(i);
        ai  := ai + ((i - a.dmax)  shr  (8 * sizeof(i) - 1));
        bi  := bi + ((i - b.dmax)  shr  (8 * sizeof(i) - 1));
    end;

    ap := m.d;
    mask := 0 - borrow; carry := 0;
    for i := 0 to mtop-1 do
    begin
        ta := ((ap[i] and mask) + carry) and BN_MASK2;
        carry := int(ta < carry);
        rp[i] := (rp[i] + ta) and BN_MASK2;
        carry  := carry + (int(rp[i] < ta));
    end;
    borrow  := borrow - carry;
    mask := 0 - borrow; carry := 0;
    for i := 0 to mtop-1 do
    begin
        ta := ((ap[i] and mask) + carry) and BN_MASK2;
        carry := int(ta < carry);
        rp[i] := (rp[i] + ta) and BN_MASK2;
        carry  := carry + (int(rp[i] < ta));
    end;
    r.top := mtop;
    r.flags  := r.flags  or BN_FLG_FIXED_TOP;
    r.neg := 0;
    Result := 1;
{$POINTERMATH OFF}
end;

function BN_mod_lshift_quick(r : PBIGNUM;const a : PBIGNUM; n : integer;const m : PBIGNUM):integer;
var
  max_shift : integer;
begin
    if r <> a then
    begin
        if BN_copy(r, a) = nil then
            Exit(0);
    end;
    while n > 0 do
    begin
        { 0 < r < m }
        max_shift := BN_num_bits(m) - BN_num_bits(r);
        { max_shift >= 0 }
        if max_shift < 0 then begin
            ERR_raise(ERR_LIB_BN, BN_R_INPUT_NOT_REDUCED);
            Exit(0);
        end;
        if max_shift > n then max_shift := n;
        if max_shift > 0 then
        begin
            if 0>= BN_lshift(r, r, max_shift) then
                Exit(0);
            n  := n - max_shift;
        end
        else
        begin
            if 0>= BN_lshift1(r, r) then
                Exit(0);
            PreDec(n);
        end;
        { BN_num_bits(r) <= BN_num_bits(m) }
        if BN_cmp(r, m ) >= 0 then
        begin
            if 0>= BN_sub(r, r, m) then
                Exit(0);
        end;
    end;
    bn_check_top(r);
    Result := 1;
end;

function BN_mod_add(r : PBIGNUM;const a, b, m : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if 0>= BN_add(r, a, b ) then
        Exit(0);
    Result := BN_nnmod(r, r, m, ctx);
end;

function BN_mod_sub(r : PBIGNUM;const a, b, m : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if 0>= BN_sub(r, a, b) then
        Exit(0);
    Result := BN_nnmod(r, r, m, ctx);
end;

function BN_mod_sub_quick(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
begin
    if 0>= BN_sub(r, a, b) then
        Exit(0);
    if r.neg >0 then
        Exit(BN_add(r, r, m));
    Result := 1;
end;

function BN_mod_lshift1_quick(r : PBIGNUM;const a, m : PBIGNUM):integer;
begin
    if 0>= BN_lshift1(r, a) then
        Exit(0);
    bn_check_top(r);
    if BN_cmp(r, m) >= 0  then
        Exit(BN_sub(r, r, m));
    Result := 1;
end;

function BN_mod_sqr(r : PBIGNUM;const a, m : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if 0>= BN_sqr(r, a, ctx )then
        Exit(0);
    { r.neg = 0,  thus we don't need BN_nnmod }
    Result := BN_mod(r, r, m, ctx);
end;

function bn_mod_add_fixed_top(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
var
  i, ai, bi, mtop : size_t;
  storage : array[0..(1024 div BN_BITS2)-1] of BN_ULONG;
  carry, temp, mask : BN_ULONG;
  rp, tp, ap, bp : PBN_ULONG;
begin
{$POINTERMATH ON}
    mtop := m.top;
    tp := @storage;
    if bn_wexpand(r, mtop ) = nil then
        Exit(0);
    if mtop > sizeof(storage) div sizeof(storage[0])  then
    begin
        tp := OPENSSL_malloc(mtop * sizeof(BN_ULONG));
        if tp = nil then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    ap := get_result(a.d <> nil , a.d , tp);
    bp := get_result(b.d <> nil , b.d , tp);
    i := 0; ai := 0; bi := 0; carry := 0;
    while i < mtop do
    begin
        mask := BN_ULONG(0) - ((i - a.top)  shr  (8 * sizeof(i) - 1));
        temp := ((ap[ai] and mask) + carry) and BN_MASK2;
        carry := int(temp < carry);
        mask := BN_ULONG(0) - ((i - b.top)  shr  (8 * sizeof(i) - 1));
        tp[i] := ((bp[bi] and mask) + temp) and BN_MASK2;
        carry  := carry + (int(tp[i] < temp));
        Inc(i);
        ai  := ai + ((i - a.dmax)  shr  (8 * sizeof(i) - 1));
        bi  := bi + ((i - b.dmax)  shr  (8 * sizeof(i) - 1));
    end;
    rp := r.d;
    carry  := carry - (bn_sub_words(rp, tp, m.d, mtop));
    for i := 0 to mtop-1 do
    begin
        rp[i] := (carry and tp[i]) or (not carry and rp[i]);
        PBN_ULONG(tp)[i] := 0;
    end;
    r.top := mtop;
    r.flags  := r.flags  or BN_FLG_FIXED_TOP;
    r.neg := 0;
    if tp <> @storage then
       OPENSSL_free(tp);
    Result := 1;
{$POINTERMATH OFF}
end;

function BN_mod_add_quick(r : PBIGNUM;const a, b, m : PBIGNUM):integer;
var
  ret : integer;
begin
    ret := bn_mod_add_fixed_top(r, a, b, m);
    if ret > 0 then
       bn_correct_top(r);
    Result := ret;
end;

function BN_nnmod(r : PBIGNUM;const m, d : PBIGNUM; ctx : PBN_CTX):integer;
begin
    {
     * like BN_mod, but returns non-negative remainder (i.e., 0 <= r < |d|
     * always holds)
     }
    if 0>= (BN_mod(r, m, d, ctx ))then
        Exit(0);
    if 0>= r.neg then Exit(1);
    { now   -|d| < r < 0,  so we have to set  r := r + |d| }
    if d.neg >0 then
       Result := BN_sub(r, r, d)
    else
       Result := BN_add(r, r, d);
end;

function BN_mod_mul(r : PBIGNUM;const a, b, m : PBIGNUM; ctx : PBN_CTX):integer;
var
  t : PBIGNUM;
  ret : integer;
  label _err;
begin
    ret := 0;
    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(m);
    BN_CTX_start(ctx);
    t := BN_CTX_get(ctx);
    if t = nil then
        goto _err ;
    if a = b then
    begin
        if 0>= BN_sqr(t, a, ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_mul(t, a, b, ctx) then
            goto _err ;
    end;
    if 0>= BN_nnmod(r, t, m, ctx) then
        goto _err ;
    bn_check_top(r);
    ret := 1;

 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;
{$Q+}

end.
