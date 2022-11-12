unit openssl3.crypto.bn.bn_gf2m;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$I config.inc}
interface
uses OpenSSL.Api, SysUtils;

const
    MAX_ITERATIONS = 50;

function BN_GF2m_mod_arr(r : PBIGNUM;const a : PBIGNUM; const p : Pinteger):integer;
function BN_GF2m_mod_sqrt_arr(r : PBIGNUM;const a : PBIGNUM; const p : Pinteger; ctx : PBN_CTX):int;
 function BN_GF2m_mod_exp_arr(r : PBIGNUM;const a, b : PBIGNUM; const p : Pinteger; ctx : PBN_CTX):integer;
function BN_GF2m_mod_mul_arr(r : PBIGNUM;const a, b : PBIGNUM;const p : pinteger; ctx : PBN_CTX):integer;
function BN_GF2m_mod_sqr_arr(r : PBIGNUM;const a : PBIGNUM; p : pinteger; ctx : PBN_CTX):integer;
procedure bn_GF2m_mul_2x2(r : PBN_ULONG;const a1, a0, b1, b0 : BN_ULONG);
 procedure bn_GF2m_mul_1x1(r1, r0 : PBN_ULONG;const a, b : BN_ULONG);
 function BN_GF2m_add(r : PBIGNUM;const a, b : PBIGNUM):integer;
 function BN_GF2m_mod_solve_quad_arr(r : PBIGNUM;const a_ : PBIGNUM; p : pinteger; ctx : PBN_CTX):integer;
  function BN_GF2m_poly2arr(const a : PBIGNUM; p: PInteger; max : integer):integer;
 function BN_GF2m_mod_div(r : PBIGNUM;const y, x, p : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_GF2m_mod_inv(r : PBIGNUM;const a, p : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_GF2m_mod_mul(r : PBIGNUM;const a, b, p : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_GF2m_mod_inv_vartime(r : PBIGNUM;const a, p : PBIGNUM; ctx : PBN_CTX):integer;
 function BN_GF2m_mod(r : PBIGNUM;const a, p : PBIGNUM):integer;


implementation
uses  openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.bio.bio_print, openssl3.crypto.bn.bn_ctx,
      openssl3.crypto.bn.bn_rand;


function BN_GF2m_mod(r : PBIGNUM;const a, p : PBIGNUM):integer;
var
  ret : integer;

  arr : array[0..5] of integer;
begin
    ret := 0;
    bn_check_top(a);
    bn_check_top(p);
    ret := BN_GF2m_poly2arr(p, @arr, Length(arr));
    if (0>= ret)  or  (ret > int( Length(arr))) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        Exit(0);
    end;
    ret := BN_GF2m_mod_arr(r, a, @arr);
    bn_check_top(r);
    Result := ret;
end;







function BN_GF2m_mod_inv_vartime(r : PBIGNUM;const a, p : PBIGNUM; ctx : PBN_CTX):integer;
var
  b, c, u, v, tmp : PBIGNUM;
  ret, i, ubits, vbits, top : integer;
  udp, bdp, vdp, cdp : PBN_ULONG;
  u0, u1, b0, b1, mask, ul : BN_ULONG;
  utop : integer;
  label _err;
begin
{$POINTERMATH ON}
    c := nil;
    u := nil;
    v := nil;
    ret := 0;
    bn_check_top(a);
    bn_check_top(p);
    BN_CTX_start(ctx);
    b := BN_CTX_get(ctx);
    c := BN_CTX_get(ctx);
    u := BN_CTX_get(ctx);
    v := BN_CTX_get(ctx);
    if v = nil then goto _err ;
    if 0>= BN_GF2m_mod(u, a, p) then
        goto _err ;
    if BN_is_zero(u) then
        goto _err ;
    if nil = BN_copy(v, p) then
        goto _err ;
{$IF false}
    if 0>= BN_one(b) then
        goto _err ;
    while 1 do  begin
        while 0>= BN_is_odd(u) do  begin
            if BN_is_zero(u) then
                goto _err ;
            if 0>= BN_rshift1(u, u) then
                goto _err ;
            if BN_is_odd(b) then  begin
                if 0>= BN_GF2m_add(b, b, p) then
                    goto _err ;
            end;
            if 0>= BN_rshift1(b, b) then
                goto _err ;
        end;
        if BN_abs_is_word(u, 1) then
            break;
        if BN_num_bits(u then < BN_num_bits(v)) begin
            tmp := u;
            u := v;
            v := tmp;
            tmp := b;
            b := c;
            c := tmp;
        end;
        if 0>= BN_GF2m_add(u, u, v) then
            goto _err ;
        if 0>= BN_GF2m_add(b, b, c) then
            goto _err ;
    end;
{$ELSE}
    begin
        ubits := BN_num_bits(u);
        vbits := BN_num_bits(v);
        top := p.top;
        if nil = bn_wexpand(u, top) then
            goto _err ;
        udp := u.d;
        for i := u.top to top-1 do
            udp[i] := 0;
        u.top := top;
        if nil = bn_wexpand(b, top) then
          goto _err ;
        bdp := b.d;
        bdp[0] := 1;
        for i := 1 to top-1 do
            bdp[i] := 0;
        b.top := top;
        if nil = bn_wexpand(c, top) then
          goto _err ;
        cdp := c.d;
        for i := 0 to top-1 do
            cdp[i] := 0;
        c.top := top;
        vdp := v.d;             { It pays off to 'cache' *.d pointers,
                                 because it allows optimizer to be more
                                  aggressive. But we don't have to 'cache'
                                  p.d, because *p is declared 'const'... }
        while Boolean(1) do
        begin
            while (ubits >0 )  and  (0>= (udp[0] and 1)) do
            begin
                u0 := udp[0];
                b0 := bdp[0];
                mask := BN_ULONG(0) - (b0 and 1);
                b0  := b0 xor (p.d[0] and mask);
                for i := 0 to top - 1-1 do
                begin
                    u1 := udp[i + 1];
                    udp[i] := ((u0  shr  1) or (u1  shl  (BN_BITS2 - 1))) and BN_MASK2;
                    u0 := u1;
                    b1 := bdp[i + 1]  xor  (p.d[i + 1] and mask);
                    bdp[i] := ((b0  shr  1) or (b1  shl  (BN_BITS2 - 1))) and BN_MASK2;
                    b0 := b1;
                end;
                udp[i] := u0  shr  1;
                bdp[i] := b0  shr  1;
                PostDec(ubits);
            end;
            if ubits <= BN_BITS2 then begin
                if udp[0] = 0 then  { poly was reducible }
                    goto _err ;
                if udp[0] = 1 then break;
            end;
            if ubits < vbits then begin
                i := ubits;
                ubits := vbits;
                vbits := i;
                tmp := u;
                u := v;
                v := tmp;
                tmp := b;
                b := c;
                c := tmp;
                udp := vdp;
                vdp := v.d;
                bdp := cdp;
                cdp := c.d;
            end;
            for i := 0 to top-1 do
            begin
                udp[i]  := udp[i] xor (vdp[i]);
                bdp[i]  := bdp[i] xor (cdp[i]);
            end;
            if ubits = vbits then
            begin
                utop := (ubits - 1) div BN_BITS2;
                ul := udp[utop];
                while (ul = 0)  and ( utop>0) do
                begin
                    Dec(utop);
                    ul := udp[utop];
                end;
                ubits := utop * BN_BITS2 + BN_num_bits_word(ul);
            end;
        end;
        bn_correct_top(b);
    end;
{$ENDIF}
    if nil = BN_copy(r, b) then
        goto _err ;
    bn_check_top(r);
    ret := 1;
 _err:
{$IFDEF BN_DEBUG}
    { BN_CTX_end would complain about the expanded form }
    bn_correct_top(c);
    bn_correct_top(u);
    bn_correct_top(v);
{$ENDIF}
    BN_CTX_end(ctx);
    Result := ret;
{$POINTERMATH OFF}
end;



function BN_GF2m_mod_mul(r : PBIGNUM;const a, b, p : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret, max : integer;

  arr : PInteger;
  label _err;
begin
    ret := 0;
     max := BN_num_bits(p) + 1;
    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(p);
    arr := OPENSSL_malloc(sizeof( arr^) * max);
    if arr = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ret := BN_GF2m_poly2arr(p, arr, max);
    if (0>= ret)  or  (ret > max) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        goto _err ;
    end;
    ret := BN_GF2m_mod_mul_arr(r, a, b, arr, ctx);
    bn_check_top(r);
 _err:
    OPENSSL_free(Pointer(arr));
    Result := ret;
end;

function SQR_nibble(w: BN_ULONG): BN_ULONG;
begin
  Result := (((w and 8)  shl  3)
         or  ((w and 4)  shl  2)
         or  ((w and 2)  shl  1)
         or   (w and 1))
end;

{$if defined(SIXTY_FOUR_BIT) or defined(SIXTY_FOUR_BIT_LONG)}
function SQR1(w: BN_ULONG): BN_ULONG;
begin
    Result := SQR_nibble(w  shr  60)  shl  56 or SQR_nibble(w  shr  56)  shl  48 or
              SQR_nibble(w  shr  52)  shl  40 or SQR_nibble(w  shr  48)  shl  32 or
              SQR_nibble(w  shr  44)  shl  24 or SQR_nibble(w  shr  40)  shl  16 or
              SQR_nibble(w  shr  36)  shl   8 or SQR_nibble(w  shr  32)
end;


function SQR0(w: BN_ULONG): BN_ULONG;
begin
   Result := SQR_nibble(w  shr  28)  shl  56 or SQR_nibble(w  shr  24)  shl  48 or
             SQR_nibble(w  shr  20)  shl  40 or SQR_nibble(w  shr  16)  shl  32 or
             SQR_nibble(w  shr  12)  shl  24 or SQR_nibble(w  shr   8)  shl  16 or
             SQR_nibble(w  shr   4)  shl   8 or SQR_nibble(w      )
end;

{$endif}





function BN_GF2m_mod_inv(r : PBIGNUM;const a, p : PBIGNUM; ctx : PBN_CTX):integer;
var
  b : PBIGNUM;

  ret : integer;
  label _err;
begin
    b := nil;
    ret := 0;
    BN_CTX_start(ctx);
    b := BN_CTX_get(ctx);
    if b =  nil then
        goto _err ;
    { generate blinding value }
     while (BN_is_zero(b)) do
     begin
        if 0>= BN_priv_rand_ex(b, BN_num_bits(p) - 1,
                             BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx)  then
            goto _err ;
    end;

    { r := a * b }
    if 0>= BN_GF2m_mod_mul(r, a, b, p, ctx ) then
        goto _err ;
    { r := 1/(a * b) }
    if 0>= BN_GF2m_mod_inv_vartime(r, r, p, ctx) then
        goto _err ;
    { r := b/(a * b) = 1/a }
    if 0>= BN_GF2m_mod_mul(r, r, b, p, ctx) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;



function BN_GF2m_mod_div(r : PBIGNUM;const y, x, p : PBIGNUM; ctx : PBN_CTX):integer;
var
  xinv : PBIGNUM;

  ret : integer;
  label _err;
begin
    xinv := nil;
    ret := 0;
    bn_check_top(y);
    bn_check_top(x);
    bn_check_top(p);
    BN_CTX_start(ctx);
    xinv := BN_CTX_get(ctx);
    if xinv = nil then goto _err ;
    if 0>= BN_GF2m_mod_inv(xinv, x, p, ctx) then
        goto _err ;
    if 0>= BN_GF2m_mod_mul(r, y, xinv, p, ctx) then
        goto _err ;
    bn_check_top(r);
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;


function BN_GF2m_poly2arr(const a : PBIGNUM; p: PInteger; max : integer):integer;
var
  i, j, k : integer;

  mask : BN_ULONG;
begin
{$POINTERMATH ON}
    k := 0;
    if BN_is_zero(a ) then
        Exit(0);
    for i := a.top - 1 downto 0 do
    begin
        if 0>= a.d[i] then { skip word if a.d[i] = 0 }
            continue;
        mask := BN_TBIT;
        for j := BN_BITS2 - 1 downto 0 do
        begin
            if (a.d[i] and mask) > 0 then
            begin
                if k < max then
                    p[k] := BN_BITS2 * i + j;
                Inc(k);
            end;
            mask := mask shr  1;
        end;
    end;
    if k < max then
    begin
        p[k] := -1;
        Inc(k);
    end;
    Result := k;
{$POINTERMATH OFF}
end;

function BN_GF2m_mod_solve_quad_arr(r : PBIGNUM;const a_ : PBIGNUM; p : pinteger; ctx : PBN_CTX):integer;
var
  ret, count, j : integer;

  a, z, rho, w, w2, tmp : PBIGNUM;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0; count := 0;
    bn_check_top(a_);
    if p[0] = 0 then
    begin
        { reduction mod 1 => return 0 }
        BN_zero(r);
        Exit(1);
    end;
    BN_CTX_start(ctx);
    a := BN_CTX_get(ctx);
    z := BN_CTX_get(ctx);
    w := BN_CTX_get(ctx);
    if w = nil then goto _err ;
    if 0>= BN_GF2m_mod_arr(a, a_, p ) then
        goto _err ;
    if BN_is_zero(a ) then
    begin
        BN_zero(r);
        ret := 1;
        goto _err ;
    end;
    if (p[0] and $1) > 0 then
    begin            { m is odd }
        { compute half-trace of a }
        if nil = BN_copy(z, a) then
            goto _err ;
        for j := 1 to (p[0] - 1) div 2 do
        begin
            if 0>= BN_GF2m_mod_sqr_arr(z, z, p, ctx ) then
                goto _err ;
            if 0>= BN_GF2m_mod_sqr_arr(z, z, p, ctx ) then
                goto _err ;
            if 0>= BN_GF2m_add(z, z, a ) then
                goto _err ;
        end;
    end
    else
    begin                     { m is even }
        rho := BN_CTX_get(ctx);
        w2 := BN_CTX_get(ctx);
        tmp := BN_CTX_get(ctx);
        if tmp = nil then
           goto _err ;
        while (BN_is_zero(w)  and  (count < MAX_ITERATIONS)) do
        begin
            if 0>= BN_priv_rand_ex(rho, p[0], BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY,
                                 0, ctx ) then
                goto _err ;
            if 0>= BN_GF2m_mod_arr(rho, rho, p ) then
                goto _err ;
            BN_zero(z);
            if nil = BN_copy(w, rho ) then
                goto _err ;
            for j := 1 to p[0] - 1 do
            begin
                if 0>= BN_GF2m_mod_sqr_arr(z, z, p, ctx ) then
                    goto _err ;
                if 0>= BN_GF2m_mod_sqr_arr(w2, w, p, ctx ) then
                    goto _err ;
                if 0>= BN_GF2m_mod_mul_arr(tmp, w2, a, p, ctx ) then
                    goto _err ;
                if 0>= BN_GF2m_add(z, z, tmp ) then
                    goto _err ;
                if 0>= BN_GF2m_add(w, w2, rho ) then
                    goto _err ;
            end;
            Inc(count);
        end;

        if BN_is_zero(w ) then
        begin
            ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS);
            goto _err ;
        end;
    end;
    if 0>= BN_GF2m_mod_sqr_arr(w, z, p, ctx ) then
        goto _err ;
    if 0>= BN_GF2m_add(w, z, w ) then
        goto _err ;
    if BN_GF2m_cmp(w, a ) > 0 then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_NO_SOLUTION);
        goto _err ;
    end;
    if nil = BN_copy(r, z ) then
        goto _err ;
    bn_check_top(r);
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
 {$POINTERMATH OFF}
end;




function BN_GF2m_add(r : PBIGNUM;const a, b : PBIGNUM):integer;
var
  i : integer;
  at, bt: PBIGNUM ;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    bn_check_top(b);
    if a.top < b.top then
    begin
        at := b;
        bt := a;
    end
    else
    begin
        at := a;
        bt := b;
    end;
    if bn_wexpand(r, at.top) = nil  then
       Exit(0);
    for i := 0 to bt.top-1 do
    begin
        r.d[i] := at.d[i]  xor  bt.d[i];
    end;
    while i < at.top do
    begin
        r.d[i] := at.d[i];
        Inc(i);
    end;
    r.top := at.top;
    bn_correct_top(r);
    Result := 1;
{$POINTERMATH OFF}
end;




procedure bn_GF2m_mul_1x1(r1, r0 : PBN_ULONG;const a, b : BN_ULONG);
var
  h, l, s : BN_ULONG;

  tab : array[0..15] of BN_ULONG;

  top3b, a1, a2, a4, a8 : BN_ULONG;
begin
    top3b := a  shr  61;
    a1 := a and uint64($1FFFFFFFFFFFFFFF);
    a2 := a1  shl  1;
    a4 := a2  shl  1;
    a8 := a4  shl  1;
    tab[0] := 0;
    tab[1] := a1;
    tab[2] := a2;
    tab[3] := a1  xor  a2;
    tab[4] := a4;
    tab[5] := a1  xor  a4;
    tab[6] := a2  xor  a4;
    tab[7] := a1  xor  a2  xor  a4;
    tab[8] := a8;
    tab[9] := a1  xor  a8;
    tab[10] := a2  xor  a8;
    tab[11] := a1  xor  a2  xor  a8;
    tab[12] := a4  xor  a8;
    tab[13] := a1  xor  a4  xor  a8;
    tab[14] := a2  xor  a4  xor  a8;
    tab[15] := a1  xor  a2  xor  a4  xor  a8;
    s := tab[b and $F];
    l := s;
    s := tab[b  shr  4 and $F];
    l  := l xor (s  shl  4);
    h := s  shr  60;
    s := tab[b  shr  8 and $F];
    l  := l xor (s  shl  8);
    h  := h xor (s  shr  56);
    s := tab[b  shr  12 and $F];
    l  := l xor (s  shl  12);
    h  := h xor (s  shr  52);
    s := tab[b  shr  16 and $F];
    l  := l xor (s  shl  16);
    h  := h xor (s  shr  48);
    s := tab[b  shr  20 and $F];
    l  := l xor (s  shl  20);
    h  := h xor (s  shr  44);
    s := tab[b  shr  24 and $F];
    l  := l xor (s  shl  24);
    h  := h xor (s  shr  40);
    s := tab[b  shr  28 and $F];
    l  := l xor (s  shl  28);
    h  := h xor (s  shr  36);
    s := tab[b  shr  32 and $F];
    l  := l xor (s  shl  32);
    h  := h xor (s  shr  32);
    s := tab[b  shr  36 and $F];
    l  := l xor (s  shl  36);
    h  := h xor (s  shr  28);
    s := tab[b  shr  40 and $F];
    l  := l xor (s  shl  40);
    h  := h xor (s  shr  24);
    s := tab[b  shr  44 and $F];
    l  := l xor (s  shl  44);
    h  := h xor (s  shr  20);
    s := tab[b  shr  48 and $F];
    l  := l xor (s  shl  48);
    h  := h xor (s  shr  16);
    s := tab[b  shr  52 and $F];
    l  := l xor (s  shl  52);
    h  := h xor (s  shr  12);
    s := tab[b  shr  56 and $F];
    l  := l xor (s  shl  56);
    h  := h xor (s  shr  8);
    s := tab[b  shr  60];
    l  := l xor (s  shl  60);
    h  := h xor (s  shr  4);
    { compensate for the top three bits of a }
    if (top3b and 01) > 0 then
    begin
        l  := l xor (b  shl  61);
        h  := h xor (b  shr  3);
    end;
    if (top3b and 02) > 0 then
    begin
        l  := l xor (b  shl  62);
        h  := h xor (b  shr  2);
    end;
    if (top3b and 04) > 0 then
    begin
        l  := l xor (b  shl  63);
        h  := h xor (b  shr  1);
    end;
    r1^ := h;
    r0^ := l;
end;

procedure bn_GF2m_mul_2x2(r : PBN_ULONG;const a1, a0, b1, b0 : BN_ULONG);
var
  m1, m0 : BN_ULONG;
begin
{$POINTERMATH ON}
    { r[3] = h1, r[2] = h0; r[1] = l1; r[0] = l0 }
    bn_GF2m_mul_1x1(r + 3, r + 2, a1, b1);
    bn_GF2m_mul_1x1(r + 1, r, a0, b0);
    bn_GF2m_mul_1x1(@m1, @m0, a0  xor  a1, b0  xor  b1);
    { Correction on m1 xor= l1 xor h1; m0  :=  Correction on m1 xor= l1 xor h1; m0 xor (l0 xor h0);}
    r[2] := r[2] xor (m1 xor r[1] xor r[3]); // h0 ^= m1 ^ l1 ^ h1;
    r[1] := r[3] xor r[2] xor r[0] xor m1 xor m0; // l1 ^= l0 ^ h0 ^ m0;
{$POINTERMATH OFF}
end;


function BN_GF2m_mod_sqr_arr(r : PBIGNUM;const a : PBIGNUM; p : pinteger; ctx : PBN_CTX):integer;
var
  i, ret : integer;

  s : PBIGNUM;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0;
    bn_check_top(a);
    BN_CTX_start(ctx);
    s := BN_CTX_get(ctx);
    if s = nil then
        goto _err ;
    if nil = bn_wexpand(s, 2 * a.top) then
        goto _err ;
    for i := a.top - 1 downto 0 do
    begin
        s.d[2 * i + 1] := SQR1(a.d[i]);
        s.d[2 * i]     := SQR0(a.d[i]);
    end;
    s.top := 2 * a.top;
    bn_correct_top(s);
    if 0>= BN_GF2m_mod_arr(r, s, p)  then
        goto _err ;
    bn_check_top(r);
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
 {$POINTERMATH OFF}
end;





function BN_GF2m_mod_mul_arr(r : PBIGNUM;const a, b : PBIGNUM;const p : pinteger; ctx : PBN_CTX):integer;
var
  zlen, i, j, k, ret : integer;
  s : PBIGNUM;
  x1, x0, y1, y0 : BN_ULONG;
  zz : array[0..3] of BN_ULONG;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0;
    bn_check_top(a);
    bn_check_top(b);
    if a = b then
    begin
        Exit(BN_GF2m_mod_sqr_arr(r, a, p, ctx));
    end;
    BN_CTX_start(ctx);
    s := BN_CTX_get(ctx);
    if s = nil then
        goto _err ;
    zlen := a.top + b.top + 4;
    if nil = bn_wexpand(s, zlen) then
        goto _err ;
    s.top := zlen;
    for i := 0 to zlen-1 do
        s.d[i] := 0;
    j := 0;
    while j < b.top do
    begin
        y0 := b.d[j];
        y1 := get_result((j + 1) = b.top, 0 , b.d[j + 1]);
        i := 0;
        while i < a.top do
        begin
            x0 := a.d[i];
            x1 := get_result((i + 1) = a.top , 0 , a.d[i + 1]);
            bn_GF2m_mul_2x2(@zz, x1, x0, y1, y0);
            for k := 0 to 3 do
                s.d[i + j + k]  := s.d[i + j + k] xor (zz[k]);
            i := i + 2;
        end;
         j := j + 2;
    end;
    bn_correct_top(s);
    if BN_GF2m_mod_arr(r, s, p ) > 0 then
        ret := 1;
    bn_check_top(r);
 _err:
    BN_CTX_end(ctx);
    Result := ret;
 {$POINTERMATH OFF}
end;

function BN_GF2m_mod_exp_arr(r : PBIGNUM;const a, b : PBIGNUM; const p : Pinteger; ctx : PBN_CTX):integer;
var
  ret, i, n : integer;

  u : PBIGNUM;
  label _err ;
begin
    ret := 0;
    bn_check_top(a);
    bn_check_top(b);
    if BN_is_zero(b)  then
        Exit(BN_one(r));
    if BN_abs_is_word(b, 1) then
        Exit(int (BN_copy(r, a) <> nil));
    BN_CTX_start(ctx);
    u := BN_CTX_get(ctx);
    if u = nil then
        goto _err ;
    if 0>= BN_GF2m_mod_arr(u, a, p) then
        goto _err ;
    n := BN_num_bits(b) - 1;
    i := n - 1;
    while i >= 0 do
    begin
        if 0>= BN_GF2m_mod_sqr_arr(u, u, p, ctx ) then
            goto _err ;
        if BN_is_bit_set(b, i)>0  then
        begin
            if 0>= BN_GF2m_mod_mul_arr(u, u, a, p, ctx) then
                goto _err ;
        end;
        Dec(i);
    end;
    if nil = BN_copy(r, u) then
        goto _err ;
    bn_check_top(r);
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;





function BN_GF2m_mod_sqrt_arr(r : PBIGNUM;const a : PBIGNUM; const p : Pinteger; ctx : PBN_CTX):int;
var
  ret : integer;

  u : PBIGNUM;
  label _err ;
begin
{$POINTERMATH ON}
    ret := 0;
    bn_check_top(a);
    if p[0] = 0 then
    begin
        { reduction mod 1 => return 0 }
        BN_zero(r);
        Exit(1);
    end;
    BN_CTX_start(ctx);
    u := BN_CTX_get(ctx);
    if u = nil then
        goto _err ;
    if 0>= BN_set_bit(u, p[0] - 1 ) then
        goto _err ;
    ret := BN_GF2m_mod_exp_arr(r, a, u, p, ctx);
    bn_check_top(r);
 _err:
    BN_CTX_end(ctx);
    Result := ret;
{$POINTERMATH OFF}
end;



function BN_GF2m_mod_arr(r : PBIGNUM;const a : PBIGNUM; const p : Pinteger):integer;
var
  j,
  k,
  n,
  dN,
  d0,
  d1        : integer;

  zz        : BN_ULONG;
  z         : PBN_ULONG;
  tmp_ulong : BN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    if p[0] = 0 then
    begin
        { reduction mod 1 => return 0 }
        BN_zero(r);
        Exit(1);
    end;
    {
     * Since the algorithm does reduction in the r value, if a <> r, copy the
     * contents of a into r so we can do reduction in r.
     }
    if a <> r then
    begin
        if nil = bn_wexpand(r, a.top) then
            Exit(0);
        for j := 0 to a.top-1 do
        begin
            r.d[j] := a.d[j];
        end;
        r.top := a.top;
    end;
    z := r.d;
    { start reduction }
    dN := p[0] div BN_BITS2;
    j := r.top - 1;
    while j > dN do
    begin
        zz := z[j];
        if z[j] = 0 then
        begin
            Dec(j);
            continue;
        end;
        z[j] := 0;
        k := 1;
        while p[k] <> 0 do
        begin
            { reducing component t^p[k] }
            n := p[0] - p[k];
            d0 := n mod BN_BITS2;
            d1 := BN_BITS2 - d0;
            n  := n  div BN_BITS2;
            z[j - n]  := z[j - n] xor ((zz  shr  d0));
            if d0 > 0 then
               z[j - n - 1]  := z[j - n - 1] xor ((zz  shl  d1));
            Inc(k);
        end;
        { reducing component t^0 }
        n := dN;
        d0 := p[0] mod BN_BITS2;
        d1 := BN_BITS2 - d0;
        z[j - n]  := z[j - n] xor ((zz  shr  d0));
        if d0>0 then
           z[j - n - 1]  := z[j - n - 1] xor ((zz  shl  d1));
    end;
    { final round of reduction }
    while j = dN do
    begin
        d0 := p[0] mod BN_BITS2;
        zz := z[dN]  shr  d0;
        if zz = 0 then break;
        d1 := BN_BITS2 - d0;
        { clear up the top d1 bits }
        if d0 >0 then
           z[dN] := (z[dN]  shl  d1)  shr  d1
        else
            z[dN] := 0;
        z[0]  := z[0] xor zz;
        k := 1;
        while p[k] <> 0 do
        begin
            { reducing component t^p[k] }
            n := p[k] div BN_BITS2;
            d0 := p[k] mod BN_BITS2;
            d1 := BN_BITS2 - d0;
            z[n]  := z[n] xor ((zz  shl  d0));
            if (d0 > 0) and  (tmp_ulong = (zz  shr  d1)) then
                z[n + 1]  := z[n + 1] xor tmp_ulong;
            Inc(k);
        end;
    end;
    bn_correct_top(r);
    Result := 1;
{$POINTERMATH OFF}
end;


end.
