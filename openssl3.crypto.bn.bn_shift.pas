unit openssl3.crypto.bn.bn_shift;

interface
uses OpenSSL.Api;

 function bn_lshift_fixed_top(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
 function bn_rshift_fixed_top(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
 function BN_lshift(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
 function BN_rshift1(r : PBIGNUM;const a : PBIGNUM):integer;
 function BN_rshift(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
 function BN_lshift1(r : PBIGNUM;const a : PBIGNUM):integer;

implementation
uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err;

{$Q-}
function BN_lshift1(r : PBIGNUM;const a : PBIGNUM):integer;
var
  ap, rp : PBN_ULONG;
  t, c : BN_ULONG;
  i : integer;
begin
    bn_check_top(r);
    bn_check_top(a);
    if r <> a then
    begin
        r.neg := a.neg;
        if bn_wexpand(r, a.top + 1) = nil  then
            Exit(0);
        r.top := a.top;
    end
    else
    begin
        if bn_wexpand(r, a.top + 1) = nil  then
            Exit(0);
    end;
    ap := a.d;
    rp := r.d;
    c := 0;
    for i := 0 to a.top-1 do
    begin
        t := ap^;
        Inc(ap);
        rp^ := ((t  shl  1) or c) and BN_MASK2;
        Inc(rp);
        c := t  shr  (BN_BITS2 - 1);
    end;
    rp^ := c;
    r.top  := r.top + c;
    bn_check_top(r);
    Result := 1;
end;


function BN_rshift(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
var
  ret : integer;
begin
    ret := 0;
    if n < 0 then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_SHIFT);
        Exit(0);
    end;
    ret := bn_rshift_fixed_top(r, a, n);
    bn_correct_top(r);
    bn_check_top(r);
    Result := ret;
end;


function BN_rshift1(r : PBIGNUM;const a : PBIGNUM):integer;
var
  ap, rp : PBN_ULONG;
  t, c : BN_ULONG;
  i : integer;
begin
{$POINTERMATH ON}
    bn_check_top(r);
    bn_check_top(a);
    if BN_is_zero(a) then
    begin
        BN_zero(r);
        Exit(1);
    end;
    i := a.top;
    ap := a.d;
    if a <> r then
    begin
        if bn_wexpand(r, i) = nil then
            Exit(0);
        r.neg := a.neg;
    end;
    rp := r.d;
    r.top := i;
    t := ap[PreDec(i)];
    rp[i] := t  shr  1;
    c := t  shl  (BN_BITS2 - 1);
    r.top  := r.top - (int(t = 1));
    while i > 0 do
    begin
        t := ap[PreDec(i)];
        rp[i] := ((t  shr  1) and BN_MASK2) or c;
        c := t  shl  (BN_BITS2 - 1);
    end;
    if 0>= r.top then r.neg := 0; { don't allow negative zero }
    bn_check_top(r);
    Result := 1;
{$POINTERMATH OFF}
end;




function BN_lshift(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
var
  ret : integer;
begin
    if n < 0 then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_SHIFT);
        Exit(0);
    end;
    ret := bn_lshift_fixed_top(r, a, n);
    bn_correct_top(r);
    bn_check_top(r);
    Result := ret;
end;

function bn_rshift_fixed_top(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
var
  i, top, nw : integer;
  lb, rb : uint32;
  t, f : PBN_ULONG;
  l, m, mask : BN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(r);
    bn_check_top(a);
    assert(n >= 0);
    nw := n div BN_BITS2;
    if nw >= a.top then
    begin
        { shouldn't happen, but formally required }
        BN_zero(r);
        Exit(1);
    end;
    rb := uint32( n) mod BN_BITS2;
    lb := BN_BITS2 - rb;
    lb  := lb mod BN_BITS2;
    mask := BN_ULONG(0) - lb;   { mask = 0 - (lb <> 0) }
    mask  := mask  or (mask  shr  8);
    top := a.top - nw;
    if (r <> a)  and  (bn_wexpand(r, top)= nil)  then
        Exit(0);
    t := @(r.d[0]);
    f := @(a.d[nw]);
    l := f[0];
    i := 0;
    while i < top - 1 do
    begin
        m := f[i + 1];
        t[i] := (l  shr  rb) or ((m  shl  lb) and mask);
        l := m;
        Inc(i);
    end;
    t[i] := l  shr  rb;
    r.neg := a.neg;
    r.top := top;
    r.flags  := r.flags  or BN_FLG_FIXED_TOP;
    Result := 1;
{$POINTERMATH OFF}
end;

function bn_lshift_fixed_top(r : PBIGNUM;const a : PBIGNUM; n : integer):integer;
var
  i, nw : integer;
  lb, rb : uint32;
  t, f : PBN_ULONG;
  l, m, rmask : BN_ULONG;
begin
{$POINTERMATH ON}
    rmask := 0;
    assert(n >= 0);
    bn_check_top(r);
    bn_check_top(a);
    nw := n div BN_BITS2;
    if bn_wexpand(r, a.top + nw + 1 )= nil then
        Exit(0);
    if a.top <> 0 then
    begin
        lb := uint32( n) mod BN_BITS2;
        rb := BN_BITS2 - lb;
        rb  := rb mod BN_BITS2;
        rmask := BN_ULONG(0) - rb;  { rmask = 0 - (rb <> 0) }
        rmask  := rmask  or (rmask  shr  8);
        f := @(a.d[0]);
        t := @(r.d[nw]);
        l := f[a.top - 1];
        t[a.top] := (l  shr  rb) and rmask;
        i := a.top - 1 ;
        while i > 0 do
        begin
            m := l  shl  lb;
            l := f[i - 1];
            t[i] := (m or ((l  shr  rb) and rmask)) and BN_MASK2;
            Dec(i);
        end;
        t[0] := (l  shl  lb) and BN_MASK2;
    end
    else
    begin
        { shouldn't happen, but formally required }
        r.d[nw] := 0;
    end;
    if nw <> 0 then memset(r.d, 0, sizeof(t^) * nw);
    r.neg := a.neg;
    r.top := a.top + nw + 1;
    r.flags  := r.flags  or BN_FLG_FIXED_TOP;
    Result := 1;
{$POINTERMATH OFF}
end;
{$Q+}
end.
