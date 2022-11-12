unit openssl3.crypto.bn.bn_asm;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

function bn_mul_words(rp : PBN_ULONG; ap : PBN_ULONG; num : integer; w : BN_ULONG):BN_ULONG;
function bn_sub_words(r : PBN_ULONG; a, b : PBN_ULONG; n : integer):BN_ULONG;
 function bn_add_words(r : PBN_ULONG; a, b : PBN_ULONG; n : integer):BN_ULONG;
function bn_mul_add_words(rp : PBN_ULONG; ap : PBN_ULONG; num : integer; w : BN_ULONG):BN_ULONG;
function bn_div_words( h, l, d : BN_ULONG):BN_ULONG;
procedure bn_sqr_words(r : PBN_ULONG; a : PBN_ULONG; n : integer);
procedure bn_mul_comba8( r, a, b : PBN_ULONG);
procedure bn_mul_comba4( r, a, b : PBN_ULONG);
procedure mul_add_c2(a,b: BN_ULONG; var c0,c1,c2: BN_ULONG);
procedure bn_sqr_comba4(r : PBN_ULONG;const a : PBN_ULONG);
procedure sqr_add_c2(a: PBN_ULONG; i,j: int;var c0,c1,c2: BN_ULONG);
procedure sqr_add_c(a: PBN_ULONG;i: Int;var c0,c1,c2: BN_ULONG);
procedure bn_sqr_comba8(r : PBN_ULONG;const a : PBN_ULONG);

implementation

uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_shift;

{$Q-}
procedure bn_sqr_comba8(r : PBN_ULONG;const a : PBN_ULONG);
var
  c1, c2, c3 : BN_ULONG;
begin
{$POINTERMATH ON}
    c1 := 0;
    c2 := 0;
    c3 := 0;
    sqr_add_c(a, 0, c1, c2, c3);
    r[0] := c1;
    c1 := 0;
    sqr_add_c2(a, 1, 0, c2, c3, c1);
    r[1] := c2;
    c2 := 0;
    sqr_add_c(a, 1, c3, c1, c2);
    sqr_add_c2(a, 2, 0, c3, c1, c2);
    r[2] := c3;
    c3 := 0;
    sqr_add_c2(a, 3, 0, c1, c2, c3);
    sqr_add_c2(a, 2, 1, c1, c2, c3);
    r[3] := c1;
    c1 := 0;
    sqr_add_c(a, 2, c2, c3, c1);
    sqr_add_c2(a, 3, 1, c2, c3, c1);
    sqr_add_c2(a, 4, 0, c2, c3, c1);
    r[4] := c2;
    c2 := 0;
    sqr_add_c2(a, 5, 0, c3, c1, c2);
    sqr_add_c2(a, 4, 1, c3, c1, c2);
    sqr_add_c2(a, 3, 2, c3, c1, c2);
    r[5] := c3;
    c3 := 0;
    sqr_add_c(a, 3, c1, c2, c3);
    sqr_add_c2(a, 4, 2, c1, c2, c3);
    sqr_add_c2(a, 5, 1, c1, c2, c3);
    sqr_add_c2(a, 6, 0, c1, c2, c3);
    r[6] := c1;
    c1 := 0;
    sqr_add_c2(a, 7, 0, c2, c3, c1);
    sqr_add_c2(a, 6, 1, c2, c3, c1);
    sqr_add_c2(a, 5, 2, c2, c3, c1);
    sqr_add_c2(a, 4, 3, c2, c3, c1);
    r[7] := c2;
    c2 := 0;
    sqr_add_c(a, 4, c3, c1, c2);
    sqr_add_c2(a, 5, 3, c3, c1, c2);
    sqr_add_c2(a, 6, 2, c3, c1, c2);
    sqr_add_c2(a, 7, 1, c3, c1, c2);
    r[8] := c3;
    c3 := 0;
    sqr_add_c2(a, 7, 2, c1, c2, c3);
    sqr_add_c2(a, 6, 3, c1, c2, c3);
    sqr_add_c2(a, 5, 4, c1, c2, c3);
    r[9] := c1;
    c1 := 0;
    sqr_add_c(a, 5, c2, c3, c1);
    sqr_add_c2(a, 6, 4, c2, c3, c1);
    sqr_add_c2(a, 7, 3, c2, c3, c1);
    r[10] := c2;
    c2 := 0;
    sqr_add_c2(a, 7, 4, c3, c1, c2);
    sqr_add_c2(a, 6, 5, c3, c1, c2);
    r[11] := c3;
    c3 := 0;
    sqr_add_c(a, 6, c1, c2, c3);
    sqr_add_c2(a, 7, 5, c1, c2, c3);
    r[12] := c1;
    c1 := 0;
    sqr_add_c2(a, 7, 6, c2, c3, c1);
    r[13] := c2;
    c2 := 0;
    sqr_add_c(a, 7, c3, c1, c2);
    r[14] := c3;
    r[15] := c1;
{$POINTERMATH OFF}
end;

procedure mul_add_c2(a,b: BN_ULONG; var c0,c1,c2: BN_ULONG);
var
 tt,lo, hi, bl,bh: BN_ULONG;
begin
    lo := LBITS(a); hi := HBITS(a);
    bl := LBITS(b); bh := HBITS(b);
    mul64(lo,hi,bl,bh);
    tt := hi;
    c0 := (c0+lo) and BN_MASK2;
    if (c0<lo) then PostInc(tt);
    c1 := (c1+tt) and BN_MASK2;
    if (c1<tt) then PostInc(c2);
    c0 := (c0+lo) and BN_MASK2;
    if (c0<lo) then PostInc(hi);
    c1 := (c1+hi) and BN_MASK2;
    if (c1<hi) then PostInc(c2);
end;

procedure sqr_add_c2(a: PBN_ULONG; i,j: int;var c0,c1,c2: BN_ULONG);
begin
{$POINTERMATH ON}
    mul_add_c2(a[i],a[j],c0,c1,c2)
{$POINTERMATH OFF}
end;

procedure sqr_add_c(a: PBN_ULONG;i: Int;var c0,c1,c2: BN_ULONG);
var
   lo, hi: BN_ULONG;
begin
{$POINTERMATH ON}
    sqr64(lo,hi, a[i]);
    c0 := (c0+lo) and BN_MASK2;
    if (c0<lo) then PostInc(hi);
    c1 := (c1+hi) and BN_MASK2;
    if (c1<hi) then PostInc(c2);
{$POINTERMATH OFF}
end;

procedure bn_sqr_comba4(r : PBN_ULONG;const a : PBN_ULONG);
var
  c1, c2, c3 : BN_ULONG;
begin
{$POINTERMATH ON}
    c1 := 0;
    c2 := 0;
    c3 := 0;
    sqr_add_c(a, 0, c1, c2, c3);
    r[0] := c1;
    c1 := 0;
    sqr_add_c2(a, 1, 0, c2, c3, c1);
    r[1] := c2;
    c2 := 0;
    sqr_add_c(a, 1, c3, c1, c2);
    sqr_add_c2(a, 2, 0, c3, c1, c2);
    r[2] := c3;
    c3 := 0;
    sqr_add_c2(a, 3, 0, c1, c2, c3);
    sqr_add_c2(a, 2, 1, c1, c2, c3);
    r[3] := c1;
    c1 := 0;
    sqr_add_c(a, 2, c2, c3, c1);
    sqr_add_c2(a, 3, 1, c2, c3, c1);
    r[4] := c2;
    c2 := 0;
    sqr_add_c2(a, 3, 2, c3, c1, c2);
    r[5] := c3;
    c3 := 0;
    sqr_add_c(a, 3, c1, c2, c3);
    r[6] := c1;
    r[7] := c2;
{$POINTERMATH OFF}
end;

procedure mul_add_c(a,b: BN_ULONG; var c0,c1,c2: BN_ULONG);
var
  hi, lo, bh, bl : BN_ULONG;
begin
    lo := LBITS(a);
    hi := HBITS(a);
    bl := LBITS(b);
    bh := HBITS(b);
    mul64(lo,hi,bl,bh);
    c0 := (c0 + lo) and BN_MASK2;
    if c0 < lo then Inc(hi);
    c1 := (c1 + hi) and BN_MASK2;
    if c1 < hi then Inc(c2);
end;

procedure bn_mul_comba4( r, a, b : PBN_ULONG);
var
  c1, c2, c3 : BN_ULONG;
begin
{$POINTERMATH ON}
    c1 := 0;
    c2 := 0;
    c3 := 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] := c1;
    c1 := 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] := c2;
    c2 := 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] := c3;
    c3 := 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] := c1;
    c1 := 0;
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    r[4] := c2;
    c2 := 0;
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    r[5] := c3;
    c3 := 0;
    mul_add_c(a[3], b[3], c1, c2, c3);
    r[6] := c1;
    r[7] := c2;
{$POINTERMATH OFF}
end;

procedure bn_mul_comba8( r, a, b : PBN_ULONG);
var
  c1, c2, c3 : BN_ULONG;
begin
{$POINTERMATH ON}
    c1 := 0;
    c2 := 0;
    c3 := 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] := c1;
    c1 := 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] := c2;
    c2 := 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] := c3;
    c3 := 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] := c1;
    c1 := 0;
    mul_add_c(a[4], b[0], c2, c3, c1);
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    mul_add_c(a[0], b[4], c2, c3, c1);
    r[4] := c2;
    c2 := 0;
    mul_add_c(a[0], b[5], c3, c1, c2);
    mul_add_c(a[1], b[4], c3, c1, c2);
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    mul_add_c(a[4], b[1], c3, c1, c2);
    mul_add_c(a[5], b[0], c3, c1, c2);
    r[5] := c3;
    c3 := 0;
    mul_add_c(a[6], b[0], c1, c2, c3);
    mul_add_c(a[5], b[1], c1, c2, c3);
    mul_add_c(a[4], b[2], c1, c2, c3);
    mul_add_c(a[3], b[3], c1, c2, c3);
    mul_add_c(a[2], b[4], c1, c2, c3);
    mul_add_c(a[1], b[5], c1, c2, c3);
    mul_add_c(a[0], b[6], c1, c2, c3);
    r[6] := c1;
    c1 := 0;
    mul_add_c(a[0], b[7], c2, c3, c1);
    mul_add_c(a[1], b[6], c2, c3, c1);
    mul_add_c(a[2], b[5], c2, c3, c1);
    mul_add_c(a[3], b[4], c2, c3, c1);
    mul_add_c(a[4], b[3], c2, c3, c1);
    mul_add_c(a[5], b[2], c2, c3, c1);
    mul_add_c(a[6], b[1], c2, c3, c1);
    mul_add_c(a[7], b[0], c2, c3, c1);
    r[7] := c2;
    c2 := 0;
    mul_add_c(a[7], b[1], c3, c1, c2);
    mul_add_c(a[6], b[2], c3, c1, c2);
    mul_add_c(a[5], b[3], c3, c1, c2);
    mul_add_c(a[4], b[4], c3, c1, c2);
    mul_add_c(a[3], b[5], c3, c1, c2);
    mul_add_c(a[2], b[6], c3, c1, c2);
    mul_add_c(a[1], b[7], c3, c1, c2);
    r[8] := c3;
    c3 := 0;
    mul_add_c(a[2], b[7], c1, c2, c3);
    mul_add_c(a[3], b[6], c1, c2, c3);
    mul_add_c(a[4], b[5], c1, c2, c3);
    mul_add_c(a[5], b[4], c1, c2, c3);
    mul_add_c(a[6], b[3], c1, c2, c3);
    mul_add_c(a[7], b[2], c1, c2, c3);
    r[9] := c1;
    c1 := 0;
    mul_add_c(a[7], b[3], c2, c3, c1);
    mul_add_c(a[6], b[4], c2, c3, c1);
    mul_add_c(a[5], b[5], c2, c3, c1);
    mul_add_c(a[4], b[6], c2, c3, c1);
    mul_add_c(a[3], b[7], c2, c3, c1);
    r[10] := c2;
    c2 := 0;
    mul_add_c(a[4], b[7], c3, c1, c2);
    mul_add_c(a[5], b[6], c3, c1, c2);
    mul_add_c(a[6], b[5], c3, c1, c2);
    mul_add_c(a[7], b[4], c3, c1, c2);
    r[11] := c3;
    c3 := 0;
    mul_add_c(a[7], b[5], c1, c2, c3);
    mul_add_c(a[6], b[6], c1, c2, c3);
    mul_add_c(a[5], b[7], c1, c2, c3);
    r[12] := c1;
    c1 := 0;
    mul_add_c(a[6], b[7], c2, c3, c1);
    mul_add_c(a[7], b[6], c2, c3, c1);
    r[13] := c2;
    c2 := 0;
    mul_add_c(a[7], b[7], c3, c1, c2);
    r[14] := c3;
    r[15] := c1;
{$POINTERMATH OFF}
end;

procedure bn_sqr_words(r : PBN_ULONG; a : PBN_ULONG; n : integer);
begin
{$POINTERMATH ON}
    assert(n >= 0);
    if n <= 0 then Exit;
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    while (n and (not 3)) > 0 do
    begin
        sqr64(r[0], r[1], a[0]);
        sqr64(r[2], r[3], a[1]);
        sqr64(r[4], r[5], a[2]);
        sqr64(r[6], r[7], a[3]);
        a  := a + 4;
        r  := r + 8;
        n  := n - 4;
    end;
{$ENDIF}
    while n > 0 do
    begin
        sqr64(r[0], r[1], a[0]);
        Inc(a);
        r  := r + 2;
        Dec(n);
    end;
{$POINTERMATH OFF}
end;

function bn_mul_add_words(rp : PBN_ULONG; ap : PBN_ULONG; num : integer; w : BN_ULONG):BN_ULONG;
var
  c, bl, bh : BN_ULONG;
begin
{$POINTERMATH ON}
    c := 0;
    assert(num >= 0);
    if num <= 0 then Exit(BN_ULONG(0));
    bl := LBITS(w);
    bh := HBITS(w);
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    while (num and (not 3))>0 do
    begin
        mul_add(rp[0], ap[0], bl, bh, c);
        mul_add(rp[1], ap[1], bl, bh, c);
        mul_add(rp[2], ap[2], bl, bh, c);
        mul_add(rp[3], ap[3], bl, bh, c);
        ap  := ap + 4;
        rp  := rp + 4;
        num := num - 4;
    end;
{$ENDIF}
    while num>0 do
    begin
        mul_add(rp[0], ap[0], bl, bh, c);
        Inc(ap);
        Inc(rp);
        Dec(num);
    end;
    Result := c;
{$POINTERMATH OFF}
end;


function bn_add_words(r : PBN_ULONG;a, b : PBN_ULONG; n : integer):BN_ULONG;
var
  c, l, t : BN_ULONG;
begin
{$POINTERMATH ON}
    assert(n >= 0);
    if n <= 0 then Exit(BN_ULONG(0));
    c := 0;
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    while (n and (not 3))>0 do
    begin
        t := a[0];
        t := (t + c) and BN_MASK2;
        c := int(t < c);
        l := (t + b[0]) and BN_MASK2;
        c  := c + int(l < t);
        r[0] := l;
        t := a[1];
        t := (t + c) and BN_MASK2;
        c := int(t < c);
        l := (t + b[1]) and BN_MASK2;
        c  := c + int(l < t);
        r[1] := l;
        t := a[2];
        t := (t + c) and BN_MASK2;
        c := int(t < c);
        l := (t + b[2]) and BN_MASK2;
        c  := c + int(l < t);
        r[2] := l;
        t := a[3];
        t := (t + c) and BN_MASK2;
        c := int(t < c);
        l := (t + b[3]) and BN_MASK2;
        c  := c + int(l < t);
        r[3] := l;
        a  := a + 4;
        b  := b + 4;
        r  := r + 4;
        n  := n - 4;
    end;
{$ENDIF}
    while n > 0 do
    begin
        t := a[0];
        t := (t + c) and BN_MASK2;
        c := int(t < c);
        l := (t + b[0]) and BN_MASK2;
        c  := c + int(l < t);
        r[0] := l;
        Inc(a);
        Inc(b);
        Inc(r);
        Dec(n);
    end;
    Result := BN_ULONG(c);
{$POINTERMATH OFF}
end;

function bn_sub_words(r : PBN_ULONG; a, b : PBN_ULONG; n : integer):BN_ULONG;
var
  t1, t2 : BN_ULONG;
  c : integer;
begin
{$POINTERMATH ON}
    c := 0;
    assert(n >= 0);
    if n <= 0 then Exit(BN_ULONG(0));
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    while (n and (not 3)) > 0 do
    begin
        t1 := a[0];
        t2 := b[0];
        r[0] := (t1 - t2 - c) and BN_MASK2;
        if t1 <> t2 then
           c := int(t1 < t2);
        t1 := a[1];
        t2 := b[1];
        r[1] := (t1 - t2 - c) and BN_MASK2;
        if t1 <> t2 then
           c := int(t1 < t2);
        t1 := a[2];
        t2 := b[2];
        r[2] := (t1 - t2 - c) and BN_MASK2;
        if t1 <> t2 then
           c := int(t1 < t2);
        t1 := a[3];
        t2 := b[3];
        r[3] := (t1 - t2 - c) and BN_MASK2;
        if t1 <> t2 then
           c := int(t1 < t2);
        a  := a + 4;
        b  := b + 4;
        r  := r + 4;
        n  := n - 4;
    end;
{$ENDIF}
    while n > 0 do
    begin
        t1 := a[0];
        t2 := b[0];
        r[0] := (t1 - t2 - c) and BN_MASK2;
        if t1 <> t2 then
           c := int(t1 < t2);
        Inc(a);
        Inc(b);
        Inc(r);
        Dec(n);
    end;
    Result := c;
{$POINTERMATH OFF}
end;


function bn_mul_words(rp : PBN_ULONG; ap : PBN_ULONG; num : integer; w : BN_ULONG):BN_ULONG;
var
  carry, bl, bh : BN_ULONG;
begin
{$POINTERMATH ON}
    carry := 0;
    assert(num >= 0);
    if num <= 0 then Exit(BN_ULONG(0));
    bl := LBITS(w);
    bh := HBITS(w);
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    while (num and (not 3))>0 do
    begin
        mul(rp[0], ap[0], bl, bh, carry);
        mul(rp[1], ap[1], bl, bh, carry);
        mul(rp[2], ap[2], bl, bh, carry);
        mul(rp[3], ap[3], bl, bh, carry);
        ap  := ap + 4;
        rp  := rp + 4;
        num  := num - 4;
    end;
{$ENDIF}
    while num > 0 do
    begin
        mul(rp[0], ap[0], bl, bh, carry);
        Inc(ap);
        Inc(rp);
        Dec(num);
    end;
    Result := carry;
 {$POINTERMATH OFF}
end;

function bn_div_words( h, l, d : BN_ULONG):BN_ULONG;
var
  dh, dl, q, th, tl, t, ret : BN_ULONG;
  i, count : integer;
begin
    ret := 0;
    count := 2;
    if d = 0 then Exit(BN_MASK2);
    i := BN_num_bits_word(d);
    assert((i = BN_BITS2)  or  (h <= BN_ULONG(1)  shl  i));
    i := BN_BITS2 - i;
    if h >= d then h  := h - d;
    if i >0 then
    begin
        d := d shl i;
        h := (h  shl  i) or (l  shr  (BN_BITS2 - i));
        l := l shl i;
    end;
    dh := (d and BN_MASK2h)  shr  BN_BITS4;
    dl := (d and BN_MASK2l);
    while true do
    begin
        if (h  shr  BN_BITS4) = dh then
            q := BN_MASK2l
        else
            q := h div dh;
        th := q * dh;
        tl := dl * q;
        while true do
        begin
            t := h - th;
            if ( (t and BN_MASK2h) > 0 )  or
                ((tl) <= ((t  shl  BN_BITS4) or ((l and BN_MASK2h)  shr  BN_BITS4))) then
                break;
            Dec(q);
            th  := th - dh;
            tl  := tl - dl;
        end;
        t := (tl  shr  BN_BITS4);
        tl := (tl  shl  BN_BITS4) and BN_MASK2h;
        th  := th + t;
        if l < tl then
           Inc(th);
        l  := l - tl;
        if h < th then
        begin
            h  := h + d;
            Dec(q);
        end;
        h  := h - th;
        if PreDec(count) = 0  then
            break;
        ret := q  shl  BN_BITS4;
        h := ((h  shl  BN_BITS4) or (l  shr  BN_BITS4)) and BN_MASK2;
        l := (l and BN_MASK2l)  shl  BN_BITS4;
    end;
    ret  := ret  or q;
    Result := ret;
end;
{$Q+}

end.
