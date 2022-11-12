unit openssl3.crypto.bn.bn_lib;

interface
uses OpenSSL.Api;

const
  MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH  =    ( 64 );
  MOD_EXP_CTIME_MIN_CACHE_LINE_MASK   =    (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - 1);

 {$if MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH = 64}

  BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE =   (6);
{$elseif MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH = 32 }

 BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE =   (5);
{$endif}

type
  endianess_t = (BIG, LITTLE) ;
  signedness_t = (SIGNED, UNSIGNED);
  PTR_SIZE_INT = size_t;
  Tcallback_func2 = function( p1, p2 : integer; p3 : PBN_GENCB):integer;
  Tcallback_func1 = procedure( p1, p2 : integer; p3 : PBN_GENCB);


 function BN_num_bits(const a : PBIGNUM):integer;
 function BN_num_bytes(const a : PBIGNUM): Integer;
 procedure bn_check_top(a : PBIGNUM);
function bn_num_bits_consttime(const a : pBIGNUM):integer;
function BN_bn2nativepad(const a : PBIGNUM; _to : PByte; tolen : integer):integer;
procedure BN_zero_ex( a : PBIGNUM);
procedure BN_zero(a: PBIGNUM);
function bn_expand( a : PBIGNUM; bits : integer):PBIGNUM;
function bn_expand2( b : PBIGNUM; words : integer):PBIGNUM;
 function bn_expand_internal(const b : PBIGNUM; words : integer):PBN_ULONG;
function BN_get_flags(const b : PBIGNUM; n : integer):integer;
procedure bn_free_d( a : PBIGNUM; clear : integer);
 procedure bn_correct_top( a : PBIGNUM);
 function BN_native2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
function BN_signed_native2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
function BN_signed_lebin2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
function bin2bn(const src : PByte; len : integer; dest : PBIGNUM; endianess : endianess_t; signedness : signedness_t):PBIGNUM;
function bn_wexpand( a : PBIGNUM; words : integer):PBIGNUM;
function BN_signed_bin2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
function BN_signed_bn2native(const a : PBIGNUM; &to : PByte; tolen : integer):integer;
function BN_signed_bn2lebin(const a : PBIGNUM; _to : PByte; tolen : integer):integer;
function bn2binpad(const a : PBIGNUM; _to : PByte; tolen : integer; endianess : endianess_t; signedness : signedness_t):integer;
function BN_signed_bn2bin(const a : PBIGNUM; _to : PByte; tolen : integer):integer;
function BN_is_zero(const a : PBIGNUM):Boolean;
function BN_is_bit_set(const a : PBIGNUM; n : integer):integer;
procedure BN_free( a : PBIGNUM);
function BN_cmp(const a, b : PBIGNUM):integer;
function BN_set_word( a : PBIGNUM; w : BN_ULONG):integer;
function BN_is_one(const a : PBIGNUM):Boolean;
function BN_abs_is_word(const a : PBIGNUM;const w : BN_ULONG):Boolean;
function BN_copy(dest : PBIGNUM;const b : PBIGNUM):PBIGNUM;
function BN_mod(rem: PBIGNUM;const m, d: PBIGNUM; ctx: PBN_CTX): Integer;
function BN_new:PBIGNUM;
function BN_num_bits_word( l : BN_ULONG):integer;
procedure BN_clear_free( a : PBIGNUM);
function BN_value_one:PBIGNUM;
procedure bn_init( a : PBIGNUM);
function BN_is_odd(const a : PBIGNUM):Boolean;
function BN_is_word(const a : PBIGNUM;const w : BN_ULONG):Boolean;
procedure BN_GENCB_set( gencb : PBN_GENCB; callback : Tcallback_func2; cb_arg : Pointer);
function BN_secure_new:PBIGNUM;
procedure BN_set_flags( b : PBIGNUM; n : integer);
function LBITS(a: BN_ULONG):BN_ULONG;
function HBITS(a: BN_ULONG):BN_ULONG;
procedure mul64(var l,h: BN_ULONG; bl,bh: BN_ULONG);
procedure mul(var r: BN_ULONG; a,bl,bh: BN_ULONG;var c: BN_ULONG);
function BN_lebin2bn(const src : PByte; len : integer; dest : PBIGNUM):PBIGNUM;
function BN_bin2bn(const src : PByte; len : integer; dest : PBIGNUM):PBIGNUM;
function BN_bn2lebinpad(const a : PBIGNUM; &to : PByte; tolen : integer):integer;
function BN_bn2binpad(const a : PBIGNUM; &to : PByte; tolen : integer):integer;
function BN_is_negative(const a : PBIGNUM):integer;
procedure BN_set_negative( a : PBIGNUM; b : integer);
function BN_dup(const a : PBIGNUM):PBIGNUM;
procedure mul_add(var r: BN_ULONG;const a,bl,bh: BN_ULONG; var c:BN_ULONG);
procedure sqr64(var lo,ho: BN_ULONG; const _in: BN_ULONG);
function BN_ucmp(const a, b : PBIGNUM):integer;
procedure BN_with_flags(dest : PBIGNUM;const b : PBIGNUM; flags : integer);
function BN_set_bit( a : PBIGNUM; n : integer):integer;
function BN_to_montgomery(r : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
function BN_one(a : PBIGNUM): int; inline;
function BN_window_bits_for_ctime_exponent_size(b: int): Int;
function BN_window_bits_for_exponent_size(b: int): Int;
procedure BN_clear( a : PBIGNUM);
function BN_clear_bit( a : PBIGNUM; n : integer):integer;
procedure BN_consttime_swap( condition : BN_ULONG; a, b : PBIGNUM; nwords : integer);
function BN_mask_bits( a : PBIGNUM; n : integer):integer;
function BN_GENCB_new:PBN_GENCB;
function BN_GENCB_get_arg( cb : PBN_GENCB):Pointer;
function BN_get_word(const a : PBIGNUM):BN_ULONG;
procedure BN_GENCB_free( cb : PBN_GENCB);
function BN_bn2bin(const a : PBIGNUM; &to : PByte):integer;
function BN_security_bits( L, N : integer):integer;
function bn_cmp_part_words(const a, b : PBN_ULONG; cl, dl : integer):integer;
function bn_cmp_words(const a, b : PBN_ULONG; n : integer):integer;
procedure BN_GENCB_set_old( gencb : PBN_GENCB; callback : Tcallback_func1; cb_arg : Pointer);

const
   BN_GF2m_cmp: function(const a, b : PBIGNUM):integer = BN_ucmp;

implementation

uses
  openssl3.internal.constant_time, OpenSSL3.Err, openssl3.crypto.mem_sec,
  openssl3.crypto.mem, OpenSSL3.common, openssl3.crypto.bn.bn_div,
  openssl3.crypto.rand.rand_lib, openssl3.crypto.bn.bn_mont;


const
    data_one: BN_ULONG = LONG(1);
    const_one : TBIGNUM = ( d:@data_one; top:1; dmax:1; neg:0; flags:BN_FLG_STATIC_DATA );
var
    nilbn: TBIGNUM;


{$Q-}
procedure BN_GENCB_set_old( gencb : PBN_GENCB; callback : Tcallback_func1; cb_arg : Pointer);
var
  tmp_gencb : PBN_GENCB;
begin
    tmp_gencb := gencb;
    tmp_gencb.ver := 1;
    tmp_gencb.arg := cb_arg;
    tmp_gencb.cb.cb_1 := @callback;
end;

function bn_cmp_words(const a, b : PBN_ULONG; n : integer):integer;
var
  i : integer;
  aa, bb : BN_ULONG;
begin
{$POINTERMATH ON}
    if n = 0 then Exit(0);
    aa := a[n - 1];
    bb := b[n - 1];
    if aa <> bb then
       Exit( get_result(aa > bb , 1 , -1));
    i := n - 2;
    while i >= 0 do
    begin
        aa := a[i];
        bb := b[i];
        if aa <> bb then
           Exit(get_result(aa > bb , 1 , -1));
        Dec(i);
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

function bn_cmp_part_words(const a, b : PBN_ULONG; cl, dl : integer):integer;
var
  n, i : integer;
begin
{$POINTERMATH ON}
    n := cl - 1;
    if dl < 0 then begin
        for i := dl to -1 do begin
            if b[n - i] <> 0 then Exit(-1);      { a < b }
        end;
    end;
    if dl > 0 then begin
        i := dl;
        while i > 0 do begin
            if a[n + i] <> 0 then Exit(1);       { a > b }
            Dec(i);
        end;
    end;
    Result := bn_cmp_words(a, b, cl);
{$POINTERMATH OFF}
end;

function BN_security_bits( L, N : integer):integer;
var
  secbits, bits : integer;
begin
    if L >= 15360 then secbits := 256
    else if (L >= 7680) then
        secbits := 192
    else if (L >= 3072) then
        secbits := 128
    else if (L >= 2048) then
        secbits := 112
    else if (L >= 1024) then
        secbits := 80
    else
        Exit(0);
    if N = -1 then Exit(secbits);
    bits := N div 2;
    if bits < 80 then Exit(0);
    Result := get_result( bits >= secbits , secbits , bits);
end;

function BN_bn2bin(const a : PBIGNUM; &to : PByte):integer;
begin
    Result := bn2binpad(a, &to, -1, BIG, UNSIGNED);
end;

procedure BN_GENCB_free( cb : PBN_GENCB);
begin
    if cb = nil then exit;
    OPENSSL_free(Pointer(cb));
end;



function BN_get_word(const a : PBIGNUM):BN_ULONG;
begin
{$POINTERMATH ON}
    if a.top > 1 then
      Exit(BN_MASK2)
    else if (a.top = 1) then
        Exit(a.d[0]);
    { a.top = 0 }
    Result := 0;
{$POINTERMATH OFF}
end;

function BN_GENCB_get_arg( cb : PBN_GENCB):Pointer;
begin
    Result := cb.arg;
end;

function BN_GENCB_new:PBN_GENCB;
var
  ret : PBN_GENCB;
begin
    ret := OPENSSL_malloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    Result := ret;
end;

function BN_mask_bits( a : PBIGNUM; n : integer):integer;
var
  b, w : integer;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    if n < 0 then Exit(0);
    w := n div BN_BITS2;
    b := n mod BN_BITS2;
    if w >= a.top then Exit(0);
    if b = 0 then
       a.top := w
    else
    begin
        a.top := w + 1;
        a.d[w] := a.d[w] and (not (BN_MASK2  shl  b));
    end;
    bn_correct_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;

procedure BN_consttime_swap( condition : BN_ULONG; a, b : PBIGNUM; nwords : integer);
const
  BN_CONSTTIME_SWAP_FLAGS = (BN_FLG_CONSTTIME or BN_FLG_FIXED_TOP);
var
  t : BN_ULONG;
  i : integer;
begin
{$POINTERMATH ON}
    if a = b then exit;
    //bn_wcheck_size(a, nwords);
    //bn_wcheck_size(b, nwords);
    condition := ((not condition and ((condition - 1)))  shr  (BN_BITS2 - 1)) - 1;
    t := (a.top  xor  b.top) and condition;
    a.top  := a.top xor t;
    b.top  := b.top xor t;
    t := (a.neg  xor  b.neg) and condition;
    a.neg  := a.neg xor t;
    b.neg  := b.neg xor t;
    {-
     * BN_FLG_STATIC_DATA: indicates that data may not be written to. Intention
     * is actually to treat it as it's read-only data, and some (if not most)
     * of it does reside in read-only segment. In other words observation of
     * BN_FLG_STATIC_DATA in BN_consttime_swap should be treated as fatal
     * condition. It would either cause SEGV or effectively cause data
     * corruption.
     *
     * BN_FLG_MALLOCED: refers to BN structure itself, and hence must be
     * preserved.
     *
     * BN_FLG_SECURE: must be preserved, because it determines how x.d was
     * allocated and hence how to free it.
     *
     * BN_FLG_CONSTTIME: sufficient to mask and swap
     *
     * BN_FLG_FIXED_TOP: indicates that we haven't called bn_correct_top() on
     * the data, so the d array may be padded with additional 0 values (i.e.
     * top could be greater than the minimal value that it could be). We should
     * be swapping it
     }

    t := ((a.flags  xor  b.flags) and BN_CONSTTIME_SWAP_FLAGS) and condition;
    a.flags  := a.flags xor t;
    b.flags  := b.flags xor t;
    { conditionally swap the data }
    for i := 0 to nwords-1 do
    begin
        t := (a.d[i]  xor  b.d[i]) and condition;
        a.d[i]  := a.d[i] xor t;
        b.d[i]  := b.d[i] xor t;
    end;
{$POINTERMATH OFF}
end;

function BN_clear_bit( a : PBIGNUM; n : integer):integer;
var
  i, j : integer;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    if n < 0 then Exit(0);
    i := n div BN_BITS2;
    j := n mod BN_BITS2;
    if a.top <= i then Exit(0);
    a.d[i] := a.d[i] and (not(BN_ULONG(1)  shl  j));
    bn_correct_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;


procedure BN_clear( a : PBIGNUM);
begin
    if a = nil then exit;
    bn_check_top(a);
    if a.d <> nil then
       OPENSSL_cleanse(Pointer(a.d), sizeof( a^.d) * a.dmax);
    a.neg := 0;
    a.top := 0;
    a.flags := a.flags and  (not BN_FLG_FIXED_TOP);
end;

function BN_window_bits_for_exponent_size(b: int): Int;
begin
   Result :=  get_result(b > 671 , 6 ,
              get_result(b > 239 , 5 ,
              get_result(b >  79 , 4 ,
              get_result(b >  23 , 3 , 1))));
end;

function BN_window_bits_for_ctime_exponent_size(b: int): Int;
begin
   Result :=  get_result(b > 937 , 6 ,
              get_result(b > 306 , 5 ,
              get_result(b > 89 , 4 ,
              get_result(b > 22 , 3 , 1))));
end;

function BN_one(a : PBIGNUM): int;
begin
   Result :=  BN_set_word(a, 1);
end;



function BN_to_montgomery(r : PBIGNUM;const a : PBIGNUM; mont : PBN_MONT_CTX; ctx : PBN_CTX):integer;
begin
    Result := BN_mod_mul_montgomery(r, a, @mont.RR, mont, ctx);
end;


function BN_set_bit( a : PBIGNUM; n : integer):integer;
var
  i, j, k : integer;
begin
{$POINTERMATH ON}
    if n < 0 then Exit(0);
    i := n div BN_BITS2;
    j := n mod BN_BITS2;
    if a.top <= i then
    begin
        if bn_wexpand(a, i + 1) = nil then
            Exit(0);
        for k := a.top to i do
           a.d[k] := 0;
        a.top := i + 1;
        a.flags := a.flags and ( not BN_FLG_FIXED_TOP);
    end;
    a.d[i]  := a.d[i]  or (BN_ULONG(1)  shl  j);
    bn_check_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;

procedure BN_with_flags(dest : PBIGNUM;const b : PBIGNUM; flags : integer);
begin
    dest.d := b.d;
    dest.top := b.top;
    dest.dmax := b.dmax;
    dest.neg := b.neg;
    dest.flags := ((dest.flags and BN_FLG_MALLOCED)
                   or (b.flags and not BN_FLG_MALLOCED)
                   or BN_FLG_STATIC_DATA or flags);
    //dest.nums := B.nums;

end;


function BN_ucmp(const a, b : PBIGNUM):integer;
var
  i : integer;
  t1, t2: BN_ULONG;
  ap, bp : PBN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    bn_check_top(b);
    i := a.top - b.top;
    if i <> 0 then Exit(i);
    ap := a.d;
    bp := b.d;
    i := a.top - 1;
    while i >= 0 do
    begin
        t1 := ap[i];
        t2 := bp[i];
        if t1 <> t2 then
           Exit( get_result(t1 > t2 , 1 , -1));
        Dec(i);
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

procedure sqr64(var lo,ho: BN_ULONG; const _in: BN_ULONG);
var
  l, h, m : BN_ULONG;
begin
  h := (_in);
  l := LBITS(h);
  h := HBITS(h);
  m := (l)*(h);
  l := l * l;
  h := h * h;
  h := h + ((m and BN_MASK2h1) shr (BN_BITS4-1));
  m := (m and BN_MASK2l) shl (BN_BITS4+1);
  l := (l+m) and BN_MASK2;
  if (l < m) then
     Inc(h);
  lo := l;
  ho := h;
end;

procedure mul_add(var r: BN_ULONG;const a,bl,bh: BN_ULONG; var c:BN_ULONG);
var
  l, h : BN_ULONG;
begin
    h := (a);
    l := LBITS(h);
    h := HBITS(h);
    mul64(l,h, bl, bh);
    { non-multiply part }
    l := (l+c) and BN_MASK2;
    if l < c then
        Inc(h);
    c := (r);
    l := (l+c) and BN_MASK2;
    if l < c then
       Inc(h);
    c := h and BN_MASK2;
    r := l;
end;


function BN_dup(const a : PBIGNUM):PBIGNUM;
var
  t : PBIGNUM;
begin
    if a = nil then Exit(nil);
    bn_check_top(a);
    if BN_get_flags(a, BN_FLG_SECURE) > 0 then
       t :=  BN_secure_new()
    else
       t := BN_new();
    if t = nil then Exit(nil);
    if nil = BN_copy(t, a) then
    begin
        BN_free(t);
        Exit(nil);
    end;
    bn_check_top(t);
    Result := t;
end;

procedure BN_set_negative( a : PBIGNUM; b : integer);
begin
    if (b>0)  and  (not BN_is_zero(a)) then
        a.neg := 1
    else
        a.neg := 0;
end;

function BN_is_negative(const a : PBIGNUM):integer;
begin
    Result := int(a.neg <> 0);
end;



function BN_bn2binpad(const a : PBIGNUM; &to : PByte; tolen : integer):integer;
begin
    if tolen < 0 then Exit(-1);
    Result := bn2binpad(a, &to, tolen, BIG, UNSIGNED);
end;

function BN_bn2lebinpad(const a : PBIGNUM; &to : PByte; tolen : integer):integer;
begin
    if tolen < 0 then Exit(-1);
    Result := bn2binpad(a, &to, tolen, LITTLE, UNSIGNED);
end;

function BN_bin2bn(const src : PByte; len : integer; dest : PBIGNUM):PBIGNUM;
begin
    Result := bin2bn(src, len, dest, BIG, UNSIGNED);
end;

function BN_lebin2bn(const src : PByte; len : integer; dest : PBIGNUM):PBIGNUM;
begin
    Result := bin2bn(src, len, dest, LITTLE, UNSIGNED);
end;

function L2HBITS(a: BN_ULONG): BN_ULONG;
begin
   Result :=  ((a shl BN_BITS4) and BN_MASK2)
end;

procedure mul(var r: BN_ULONG; a,bl,bh: BN_ULONG;var c: BN_ULONG);
var
  l, h : BN_ULONG;
begin
    h := (a);
    l := LBITS(h);
    h := HBITS(h);
    mul64(l,h,(bl),(bh));
    { non-multiply part }
    l := l + c;
    if (l and BN_MASK2) < c then
       Inc(h);
    c := h and BN_MASK2;
    r := l and BN_MASK2;
end;

procedure mul64(var l,h: BN_ULONG; bl,bh: BN_ULONG);
var
  m, m1, lt, ht : BN_ULONG;
begin
    lt := l;
    ht := h;
    m := (bh)*(lt);
    lt := (bl)*(lt);
    m1 := (bl)*(ht);
    ht := (bh)*(ht);
    m := (m+m1) and BN_MASK2;
    if m < m1 then
      ht := ht + L2HBITS(BN_ULONG(1));
    ht := ht + HBITS(m);
    m1 := L2HBITS(m);
    lt := (lt+m1) and BN_MASK2;
    if lt < m1 then
       Inc(ht);
    l := lt;
    h := ht;
end;

function HBITS(a: BN_ULONG):BN_ULONG;
begin
   Result := ((a shr BN_BITS4) and BN_MASK2l)
end;

function LBITS(a: BN_ULONG):BN_ULONG;
begin
   Result:= ((a) and BN_MASK2l)
end;

procedure BN_set_flags( b : PBIGNUM; n : integer);
begin
    b.flags  := b.flags  or n;
end;

function BN_secure_new:PBIGNUM;
begin
     Result := BN_new();
     if Result <> nil then
        Result.flags  := Result.flags  or BN_FLG_SECURE;
end;



procedure BN_GENCB_set( gencb : PBN_GENCB; callback : Tcallback_func2; cb_arg : Pointer);
var
  tmp_gencb : PBN_GENCB;
begin
    tmp_gencb := gencb;
    tmp_gencb.ver := 2;
    tmp_gencb.arg := cb_arg;
    tmp_gencb.cb.cb_2 := callback;
end;

function BN_is_word(const a : PBIGNUM;const w : BN_ULONG):Boolean;
begin
    Result := (BN_abs_is_word(a, w))  and  ( (0 = w) or (0 >= a.neg) );
end;

function BN_is_odd(const a : PBIGNUM):Boolean;
begin
{$POINTERMATH ON}
    Result := (a.top > 0)  and  ((a.d[0] and 1)>0);
{$POINTERMATH OFF}
end;

procedure bn_init( a : PBIGNUM);
begin
    a^ := nilbn;
    bn_check_top(a);
end;


function BN_value_one:PBIGNUM;
begin
   Result := @const_one;
end;

procedure BN_clear_free( a : PBIGNUM);
begin
    if a = nil then exit;
    if (a.d <> nil)  and   (0>= BN_get_flags(a, BN_FLG_STATIC_DATA))  then
        bn_free_d(a, 1);
    if BN_get_flags(a, BN_FLG_MALLOCED )>0 then
    begin
        a^ := default(TBIGNUM);
        OPENSSL_free(a);
    end;
end;

{$Q-}
function BN_num_bits_word( l : BN_ULONG):integer;
var
  x, mask : BN_ULONG;
  bits : integer;
begin
    bits := int(l <> 0);
{$IF BN_BITS2 > 32}
    x := l  shr  32;
    mask := (0 - x) and BN_MASK2;
    mask := (0 - (mask  shr  (BN_BITS2 - 1)));
    bits  := bits + (32 and mask);
    l  := l xor ((x xor l) and mask);
{$ENDIF}
    x := l  shr  16;
    mask := (0 - x) and BN_MASK2;
    mask := (0 - (mask  shr  (BN_BITS2 - 1)));
    bits  := bits + (16 and mask);
    l  := l xor ((x xor l) and mask);
    x := l  shr  8;
    mask := (0 - x) and BN_MASK2;
    mask := (0 - (mask  shr  (BN_BITS2 - 1)));
    bits  := bits + (8 and mask);
    l  := l xor ((x xor l) and mask);
    x := l  shr  4;
    mask := (0 - x) and BN_MASK2;
    mask := (0 - (mask  shr  (BN_BITS2 - 1)));
    bits  := bits + (4 and mask);
    l  := l xor ((x xor l) and mask);
    x := l  shr  2;
    mask := (0 - x) and BN_MASK2;
    mask := (0 - (mask  shr  (BN_BITS2 - 1)));
    bits  := bits + (2 and mask);
    l  := l xor ((x xor l) and mask);
    x := l  shr  1;
    mask := (0 - x) and BN_MASK2;
    mask := (0 - (mask  shr  (BN_BITS2 - 1)));
    bits  := bits + (1 and mask);
    Result := bits;
end;
{$Q+}
function BN_new:PBIGNUM;
begin
    result := OPENSSL_zalloc(sizeof( result^ ));
    if result = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    Result^ := default(TBIGNUM);
    result.flags := BN_FLG_MALLOCED;
    bn_check_top(result);
end;

function BN_mod(rem: PBIGNUM;const m, d: PBIGNUM; ctx: PBN_CTX): Integer;
begin
  RESULT := BN_div(nil, rem, m, d, ctx)
end;

function BN_copy(dest : PBIGNUM;const b : PBIGNUM):PBIGNUM;
var
  bn_words,i : integer;
begin
{$POINTERMATH ON}
    bn_check_top(b);
    bn_words := get_result(BN_get_flags(b, BN_FLG_CONSTTIME)>0 , b.dmax , b.top);
    if dest = b then Exit(dest);
    if bn_wexpand(dest, bn_words) = nil then
        Exit(nil);
    if b.top > 0 then
       memcpy(dest.d, b.d, sizeof(b.d[0]) * bn_words);

    dest.neg := b.neg;
    dest.top := b.top;
    dest.flags  := dest.flags  or (b.flags and BN_FLG_FIXED_TOP);
    bn_check_top(dest);
    Result := dest;
{$POINTERMATH OFF}
end;

function BN_abs_is_word(const a : PBIGNUM;const w : BN_ULONG):Boolean;
begin
{$POINTERMATH ON}
    Result := ((a.top = 1) and (a.d[0] = w)) or ((w = 0)  and  (a.top = 0));
{$POINTERMATH OFF}
end;

function BN_is_one(const a : PBIGNUM):Boolean;
begin
    Result := (BN_abs_is_word(a, 1))  and   (0>= a.neg);
end;

function BN_set_word( a : PBIGNUM; w : BN_ULONG):integer;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    if bn_expand(a, int( sizeof(BN_ULONG) * 8)) = nil then
        Exit(0);
    a.neg := 0;
    a.d[0] := w;
    a.top := get_result(w>0 , 1 , 0);
    a.flags := a.flags and (not BN_FLG_FIXED_TOP);
    bn_check_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;

function BN_cmp(const a, b : PBIGNUM):integer;
var
  i, gt, lt : integer;
  t1, t2 : BN_ULONG;
begin
{$POINTERMATH ON}
    if (a = nil)  or  (b = nil) then
    begin
        if a <> nil then
            Exit(-1)
        else
        if (b <> nil) then
            Exit(1)
        else
            Exit(0);
    end;
    bn_check_top(a);
    bn_check_top(b);
    if a.neg <> b.neg then
    begin
        if a.neg>0 then
            Exit(-1)
        else
            Exit(1);
    end;
    if a.neg = 0 then
    begin
        gt := 1;
        lt := -1;
    end
    else
    begin
        gt := -1;
        lt := 1;
    end;
    if a.top > b.top then Exit(gt);
    if a.top < b.top then Exit(lt);
    i := a.top - 1;
    while ( i >= 0) do
    begin
        t1 := a.d[i];
        t2 := b.d[i];
        if t1 > t2 then Exit(gt);
        if t1 < t2 then Exit(lt);
        Dec(i);
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

procedure BN_free( a : PBIGNUM);
begin
    if a = nil then exit;
    if  0>= BN_get_flags(a, BN_FLG_STATIC_DATA) then
        bn_free_d(a, 0);
    if (a.flags and BN_FLG_MALLOCED)>0 then
       OPENSSL_free(a);
end;

function BN_is_bit_set(const a : PBIGNUM; n : integer):integer;
var
  i, j : integer;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    if n < 0 then Exit(0);
    i := n div BN_BITS2;
    j := n mod BN_BITS2;
    if a.top <= i then Exit(0);
    Result := int((a.d[i] shr  j) and BN_ULONG(1));
{$POINTERMATH OFF}
end;

function BN_is_zero(const a : PBIGNUM):Boolean;
begin
    Result := a.top = 0;
end;

function BN_signed_bn2bin(const a : PBIGNUM; _to : PByte; tolen : integer):integer;
begin
    if tolen < 0 then Exit(-1);
    Result := bn2binpad(a, _to, tolen, BIG, SIGNED);
end;

function bn2binpad(const a : PBIGNUM; _to : PByte; tolen : integer; endianess : endianess_t; signedness : signedness_t):integer;
var
  inc1,  n,
  n8, carry, ext,
  _xor       : integer;
  i, lasti,
  j, atop,
  mask       : size_t;
  l, t       : BN_ULONG;
  temp       : TBIGNUM;
  _byte,
  byte_xored : byte;
begin
{$POINTERMATH ON}
{$Q-}
    _xor := 0; carry := 0; ext := 0;
    {
     * In case |a| is fixed-top, BN_num_bits can return bogus length,
     * but it's assumed that fixed-top inputs ought to be 'nominated'
     * even for padded output, so it works out...
     }
    n8 := BN_num_bits(a);
    n := (n8 + 7) div 8;           { This is what BN_num_bytes() does }
    { Take note of the signedness of the bignum }
    if signedness = SIGNED then
    begin
        _xor := get_result( a.neg >0, $ff , $00);
        carry := a.neg;
        {
         * if |n * 8 = n|, then the MSbit is set, otherwise unset.
         * We must compensate with one extra byte if that doesn't
         * correspond to the signedness of the bignum with regards
         * to 2's complement.
         }
        ext := get_result( (n * 8 = n8)
            ,  -1* a.neg            { MSbit set on nonnegative bignum }
            , a.neg);            { MSbit unset on negative bignum }
    end;
    if tolen = -1 then
    begin
        tolen := n + ext;
    end
    else
    if (tolen < n + ext) then
    begin  { uncommon/unlike case }
        temp := a^;
        bn_correct_top(@temp);
        n8 := BN_num_bits(@temp);
        n := (n8 + 7) div 8;       { This is what BN_num_bytes() does }
        if tolen < n + ext then Exit(-1);
    end;
    { Swipe through whole available data and don't give away padded zero. }
    atop := a.dmax * BN_BYTES;
    if atop = 0 then
    begin
        if tolen <> 0 then
            memset(_to, 0, tolen);
        Exit(tolen);
    end;
    {
     * The loop that does the work iterates from least significant
     * to most significant BIGNUM limb, so we adapt parameters to
     * tranfer output bytes accordingly.
     }
    case endianess of
      LITTLE:
          inc1 := 1;
          //break;
      BIG:
      begin
          inc1 := -1;
          _to  := _to + (tolen - 1);
      end;
    end;
    lasti := atop - 1;
    atop := a.top * BN_BYTES;
    i := 0;
    for j := 0 to size_t(tolen) -1 do
    begin
        l := a.d[i div BN_BYTES];
        mask := 0 - ((j - atop)  shr  (8 * sizeof(i) - 1));
        t := (l  shr  (8 * (i mod BN_BYTES)) and mask);
        _byte := Byte(t);
        byte_xored := _byte  xor  _xor;
        _to^ := Byte(byte_xored + carry);
        carry := Int(byte_xored > _to^); { Implicit 1 or 0 }
        _to  := _to + inc1;
        i  := i + ((i - lasti)  shr  (8 * sizeof(i) - 1));

    end;
    Result := tolen;
{$POINTERMATH OFF}
{$Q+}
end;

function BN_signed_bn2lebin(const a : PBIGNUM; _to : PByte; tolen : integer):integer;
begin
    if tolen < 0 then
       Exit(-1);
    Result := bn2binpad(a, _to, tolen, LITTLE, SIGNED);
end;

function BN_signed_bn2native(const a : PBIGNUM; &to : PByte; tolen : integer):integer;
var
  ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
       Exit(BN_signed_bn2lebin(a, &to, tolen));
    Result := BN_signed_bn2bin(a, &to, tolen);
end;


function BN_signed_bin2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
begin
    Result := bin2bn(s, len, ret, BIG, SIGNED);
end;

function bn_wexpand( a : PBIGNUM; words : integer):PBIGNUM;
begin
   if (words <= a.dmax) then
      Result := a
   else
      Result := bn_expand2(a, words);
end;

function bin2bn(const src : PByte; len : integer; dest : PBIGNUM; endianess : endianess_t; signedness : signedness_t):PBIGNUM;
var
  inc1, inc2,
  neg        : integer;
  _xor, carry,
  i, n       : uint32;
  bn         : PBIGNUM;
  l          : BN_ULONG;
  m          : uint32;
  s2,s       : PByte;
  byte_xored,
  _byte       : BN_ULONG;
begin
{$POINTERMATH ON}
    neg := 0; _xor := 0; carry := 0;
    bn := nil;
    s := src;
    if Dest = nil then
    begin
       bn := BN_new();
       Dest := bn;
    end;
    if Dest = nil then
       Exit(nil);
    bn_check_top(Dest);
    {
     * The loop that does the work iterates from least to most
     * significant BIGNUM chunk, so we adapt parameters to tranfer
     * input bytes accordingly.
     }
    case endianess of
        LITTLE:
        begin
            s2 := s + len - 1;
            inc2 := -1;
            inc1 := 1;
        end;
        BIG:
        begin
            s2 := s;
            inc2 := 1;
            inc1 := -1;
            s  := s + (len - 1);

        end;
    end;
    { Take note of the signedness of the input bytes}
    if signedness = SIGNED then
    begin
        neg := not  not ( s2^ and $80);
        _xor := get_result( neg > 0, $ff , $00);
        carry := neg;
    end;
    {
     * Skip leading sign extensions (the value of |xor|).
     * This is the only spot where |s2| and |inc2| are used.
     }
    while (len > 0)  and  (s2^ = _xor) do
    begin
        s2 := s2 + inc2;
        Dec(len);
        continue;
    end;
    {
     * If there was a set of $ff, we backtrack one byte unless the next
     * one has a sign bit, as the last $ff is then part of the actual
     * number, rather then a mere sign extension.
     }
    if _xor = $ff then
    begin
        if (len = 0)  or   (0>= ( s2^ and $80)) then
            Inc(len);
    end;
    { If it was all zeros, we're done }
    if len = 0 then
    begin
        Dest.top := 0;
        Exit(Dest);
    end;
    n := ((len - 1) div BN_BYTES) + 1; { Number of resulting bignum chunks }
    if  not ossl_assert( bn_wexpand(Dest, int(n)) <> nil)  then
    begin
        BN_free(bn);
        Exit(nil);
    end;
    Dest.top := n;
    Dest.neg := neg;
    i := 0;
    while PostDec(n) > 0 do
    begin
        l := 0;
        m := 0;
        while ( len > 0)  and  (m < BN_BYTES * 8) do
        begin
            byte_xored := s^  xor  _xor;
            _byte := (byte_xored + carry) and $ff;
            carry := Int(byte_xored > _byte); { Implicit 1 or 0 }
            l  := l  or ((_byte  shl  m));
            Dec(len); s := s + inc1; m := m+8;
        end;
        Dest.d[i] := l;
        Inc(i);
    end;
    {
     * need to call this due to clear byte at top if avoiding having the top
     * bit set (-ve number)
     }
    bn_correct_top(Dest);
    Result := Dest;
{$POINTERMATH OFF}
end;

function BN_signed_lebin2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
begin
    Result := bin2bn(s, len, ret, LITTLE, SIGNED);
end;

function BN_signed_native2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
var
  ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
       Exit(BN_signed_lebin2bn(s, len, ret));
    Result := BN_signed_bin2bn(s, len, ret);
end;

function BN_native2bn(const s : PByte; len : integer; ret : PBIGNUM):PBIGNUM;
var
 ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
       Exit(BN_lebin2bn(s, len, ret));
    Result := BN_bin2bn(s, len, ret);
end;

procedure bn_pollute(a: PBIGNUM);
begin
  //
end;

procedure bn_correct_top( a : PBIGNUM);
var
  ftl : PBN_ULONG;
  tmp_top : integer;
begin
{$POINTERMATH ON}
    tmp_top := a.top;
    if tmp_top > 0 then
    begin
       ftl := @a.d[tmp_top];
       while ( tmp_top > 0) do
       begin
          Dec(ftl);
          if ftl^ <> 0 then
            break;
          Dec(tmp_top)
       end;
        a.top := tmp_top;
    end;
    if a.top = 0 then
       a.neg := 0;
    a.flags := a.flags and  not BN_FLG_FIXED_TOP;
    bn_pollute(a);
{$POINTERMATH ON}
end;

procedure bn_free_d( a : PBIGNUM; clear : integer);
begin
{$POINTERMATH ON}
    if BN_get_flags(a, BN_FLG_SECURE)>0 then
        OPENSSL_secure_clear_free(a.d, a.dmax * sizeof(a.d[0]))
    else
    if (clear <> 0) then
        OPENSSL_clear_free(a.d, a.dmax * sizeof(a.d[0]))
    else
        OPENSSL_free(a.d);
{$POINTERMATH ON}
end;


function BN_get_flags(const b : PBIGNUM; n : integer):integer;
begin
    Result := b.flags and n;
end;


function bn_expand_internal(const b : PBIGNUM; words : integer):PBN_ULONG;
begin
    Result := nil;
    if words > (INT_MAX DIV (4 * BN_BITS2)) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_BIGNUM_TOO_LONG);
        Exit(nil);
    end;
    if BN_get_flags(b, BN_FLG_STATIC_DATA)>0 then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        Exit(nil);
    end;
    if BN_get_flags(b, BN_FLG_SECURE)>0 then
        Result :=  OPENSSL_secure_zalloc(words * sizeof( Result^))
     else
        Result := OPENSSL_zalloc(words * sizeof(Result^));
    if Result = nil then begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    assert(b.top <= words);
    if (b.top > 0) then
        memcpy(Result, b.d, sizeof(BN_ULONG) * b.top);
end;

function bn_expand2( b : PBIGNUM; words : integer):PBIGNUM;
var
  a : PBN_ULONG;
  i: Integer;
begin
    if words > b.dmax then
    begin
        a := (bn_expand_internal(b, words));
        if nil = a then
           Exit(nil);
        if b.d <> nil then
           bn_free_d(b, 1);

        b.d := a;
        b.dmax := words;
    end;
    Result := b;
end;

function bn_expand( a : PBIGNUM; bits : integer):PBIGNUM;
begin
    if bits > (INT_MAX - BN_BITS2 + 1) then
        Exit(nil);
    if ( (bits+BN_BITS2-1 ) div BN_BITS2) <= a.dmax then
        Exit(a);
    Result := bn_expand2(a, (bits+BN_BITS2-1) div BN_BITS2);
end;


procedure BN_zero_ex( a : PBIGNUM);
begin
    a.neg := 0;
    a.top := 0;
    a.flags := a.flags and (not BN_FLG_FIXED_TOP);
end;

 {$IF OPENSSL_API_LEVEL > 908}
procedure BN_zero(a: PBIGNUM);
begin
   BN_zero_ex(a);
end;
{$ELSE}
  define BN_zero(a)      (BN_set_word((a),0))
{$ENDIF}


function BN_bn2nativepad(const a : PBIGNUM; _to : PByte; tolen : integer):integer;
var
 ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
       Exit(BN_bn2lebinpad(a, _to, tolen));
    Result := BN_bn2binpad(a, _to, tolen);
end;

function bn_num_bits_consttime(const a : pBIGNUM):integer;
var
  j, ret : integer;
  mask, past_i : uint32;
  i : integer;
begin
{$PointerMATH ON}
    i := a.top - 1;
    bn_check_top(a);
    j := 0; past_i := 0; ret := 0;
    WHILE  j < a.dmax do
    begin
        mask := constant_time_eq_int(i, j); { $ff..ff if i=j, $0 otherwise }
        ret  := ret + (BN_BITS2 and ( (not mask) and (not past_i)) );
        ret  := ret + (BN_num_bits_word(a.d[j]) and mask);
        past_i  := past_i  or mask;
        Inc(j);
    end;
    {
     * if BN_is_zero(a) => i is -1 and ret contains garbage, so we mask the
     * final result.
     }
    mask := not (constant_time_eq_int(i, int(-1)));
    Result := ret and mask;
{$PointerMATH OFF}
end;


//#  define bn_check_top(a)
procedure bn_check_top(a : PBIGNUM);
begin
  
end;

function BN_num_bytes(const a : PBIGNUM): Integer;
begin
  Result := ((BN_num_bits(a)+7) div 8);
end;

function BN_num_bits(const a : PBIGNUM):integer;
var
  i : integer;
begin
{$PointerMATH ON}
    i := a.top - 1;
    bn_check_top(a);
    if (a.flags and BN_FLG_CONSTTIME)>0 then
    begin
        {
         * We assume that BIGNUMs flagged as CONSTTIME have also been expanded
         * so that a.dmax is not leaking secret information.
         *
         * In other words, it's the caller's responsibility to ensure `a` has
         * been preallocated in advance to a public length if we hit this
         * branch.
         *
         }
        Exit(bn_num_bits_consttime(a));
    end;
    if BN_is_zero(a ) then
        Exit(0);
    Result := ((i * BN_BITS2) + BN_num_bits_word(a.d[i]));
{$PointerMATH OFF}
end;
{$Q+}

initialization
    {$IFNDEF FPC}
    nilbn := default(TBIGNUM);
    {$ELSE}

    {$ENDIF}
end.
