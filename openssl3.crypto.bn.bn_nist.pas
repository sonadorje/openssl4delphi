unit openssl3.crypto.bn.bn_nist;

interface
uses OpenSSL.Api;

type
  TBN_nist_mod_func = function(r: PBIGNUM; a: PBIGNUM; field: PBIGNUM; ctx: PBN_CTX): Integer;
  bn_addsub_f = function(p1: PBN_ULONG; p2, p3: PBN_ULONG ;p4: integer): BN_ULONG ;

const
  BN_NIST_192_TOP =  (192+BN_BITS2-1) div BN_BITS2;
  BN_NIST_224_TOP =  (224+BN_BITS2-1) div BN_BITS2;
  BN_NIST_256_TOP =  (256+BN_BITS2-1) div BN_BITS2;
  BN_NIST_384_TOP =  (384+BN_BITS2-1) div BN_BITS2;
  BN_NIST_521_TOP =  (521+BN_BITS2-1) div BN_BITS2;

  BN_NIST_521_RSHIFT   =   (521 mod BN_BITS2);
  BN_NIST_521_LSHIFT   =   (BN_BITS2-BN_NIST_521_RSHIFT);
  BN_NIST_521_TOP_MASK =   (BN_ULONG(BN_MASK2) shr BN_NIST_521_LSHIFT);
{$if BN_BITS2 = 64}
 const  _nist_p_192: array[0..2, 0..BN_NIST_192_TOP-1] of BN_ULONG = (
    (UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFE), UInt64($FFFFFFFFFFFFFFFF)),
    (UInt64($FFFFFFFFFFFFFFFE), UInt64($FFFFFFFFFFFFFFFD), UInt64($FFFFFFFFFFFFFFFF)),
    (UInt64($FFFFFFFFFFFFFFFD), UInt64($FFFFFFFFFFFFFFFC), UInt64($FFFFFFFFFFFFFFFF))
);

 const  _nist_p_192_sqr: array[0..5] of BN_ULONG = (
    UInt64($0000000000000001), UInt64($0000000000000002), UInt64($0000000000000001),
    UInt64($FFFFFFFFFFFFFFFE), UInt64($FFFFFFFFFFFFFFFD), UInt64($FFFFFFFFFFFFFFFF)
);

 const  _nist_p_224: array[0..1 , 0..BN_NIST_224_TOP-1] of BN_ULONG = (
    (UInt64($0000000000000001), UInt64($FFFFFFFF00000000),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($00000000FFFFFFFF)),
    (UInt64($0000000000000002), UInt64($FFFFFFFE00000000),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($00000001FFFFFFFF)) // this one is
                                                    // "carry-full"
);

 const  _nist_p_224_sqr: array[0..6] of BN_ULONG = (
    UInt64($0000000000000001), UInt64($FFFFFFFE00000000),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($0000000200000000),
    UInt64($0000000000000000), UInt64($FFFFFFFFFFFFFFFE),
    UInt64($FFFFFFFFFFFFFFFF)
);

 const  _nist_p_256: array[0..4, 0..BN_NIST_256_TOP-1] of BN_ULONG = (
    (UInt64($FFFFFFFFFFFFFFFF), UInt64($00000000FFFFFFFF),
     UInt64($0000000000000000), UInt64($FFFFFFFF00000001)),
    (UInt64($FFFFFFFFFFFFFFFE), UInt64($00000001FFFFFFFF),
     UInt64($0000000000000000), UInt64($FFFFFFFE00000002)),
    (UInt64($FFFFFFFFFFFFFFFD), UInt64($00000002FFFFFFFF),
     UInt64($0000000000000000), UInt64($FFFFFFFD00000003)),
    (UInt64($FFFFFFFFFFFFFFFC), UInt64($00000003FFFFFFFF),
     UInt64($0000000000000000), UInt64($FFFFFFFC00000004)),
    (UInt64($FFFFFFFFFFFFFFFB), UInt64($00000004FFFFFFFF),
     UInt64($0000000000000000), UInt64($FFFFFFFB00000005))
);

 const  _nist_p_256_sqr: array[0..7] of BN_ULONG = (
    UInt64($0000000000000001), UInt64($FFFFFFFE00000000),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($00000001FFFFFFFE),
    UInt64($00000001FFFFFFFE), UInt64($00000001FFFFFFFE),
    UInt64($FFFFFFFE00000001), UInt64($FFFFFFFE00000002)
);

 const  _nist_p_384: array[0..4, 0..BN_NIST_384_TOP-1] of BN_ULONG = (
    (UInt64($00000000FFFFFFFF), UInt64($FFFFFFFF00000000), UInt64($FFFFFFFFFFFFFFFE),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF)),
    (UInt64($00000001FFFFFFFE), UInt64($FFFFFFFE00000000), UInt64($FFFFFFFFFFFFFFFD),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF)),
    (UInt64($00000002FFFFFFFD), UInt64($FFFFFFFD00000000), UInt64($FFFFFFFFFFFFFFFC),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF)),
    (UInt64($00000003FFFFFFFC), UInt64($FFFFFFFC00000000), UInt64($FFFFFFFFFFFFFFFB),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF)),
    (UInt64($00000004FFFFFFFB), UInt64($FFFFFFFB00000000), UInt64($FFFFFFFFFFFFFFFA),
     UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF))
);

 const  _nist_p_384_sqr: array[0..11] of BN_ULONG = (
    UInt64($FFFFFFFE00000001), UInt64($0000000200000000), UInt64($FFFFFFFE00000000),
    UInt64($0000000200000000), UInt64($0000000000000001), UInt64($0000000000000000),
    UInt64($00000001FFFFFFFE), UInt64($FFFFFFFE00000000), UInt64($FFFFFFFFFFFFFFFD),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF)
);

 const _nist_p_521: array[0..8] of BN_ULONG = (
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF),
    UInt64($00000000000001FF)
);

 const  _nist_p_521_sqr: array[0..16] of BN_ULONG = (
    UInt64($0000000000000001), UInt64($0000000000000000), UInt64($0000000000000000),
    UInt64($0000000000000000), UInt64($0000000000000000), UInt64($0000000000000000),
    UInt64($0000000000000000), UInt64($0000000000000000), UInt64($FFFFFFFFFFFFFC00),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF), UInt64($FFFFFFFFFFFFFFFF),
    UInt64($FFFFFFFFFFFFFFFF), UInt64($000000000003FFFF)
);
{$ENDIF}

function BN_nist_mod_192(r : PBIGNUM; a, field : PBIGNUM; ctx : PBN_CTX):integer;
function BN_nist_mod_func(const p : PBIGNUM): TBN_nist_mod_func;
procedure nist_cp_bn_0(dst : PBN_ULONG;const src : PBN_ULONG; top, max : integer);
procedure nist_cp_bn(dst : PBN_ULONG;const src : PBN_ULONG; top : integer);
function BN_nist_mod_224(r : PBIGNUM;a, field : PBIGNUM; ctx : PBN_CTX):integer;
function BN_nist_mod_256(r : PBIGNUM;a, field : PBIGNUM; ctx : PBN_CTX):integer;
function BN_nist_mod_384(r : PBIGNUM; a, field : PBIGNUM; ctx : PBN_CTX):integer;
function BN_nist_mod_521(r : PBIGNUM;a, field : PBIGNUM; ctx : PBN_CTX):integer;
function BN_get0_nist_prime_192:PBIGNUM;

function BN_get0_nist_prime_224:PBIGNUM;
function BN_get0_nist_prime_256:PBIGNUM;
function BN_get0_nist_prime_384:PBIGNUM;
function BN_get0_nist_prime_521:PBIGNUM;

var
   ossl_bignum_nist_p_192,  ossl_bignum_nist_p_224,
   ossl_bignum_nist_p_256,  ossl_bignum_nist_p_384,
   ossl_bignum_nist_p_521: TBIGNUM;

implementation

uses
    openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_mod,
    openssl3.crypto.bn.bn_asm;

function get_result(condition: Boolean;result1, result2: BN_ULONG): BN_ULONG;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;

function BN_get0_nist_prime_192:PBIGNUM;
begin
    Result := @ossl_bignum_nist_p_192;
end;


function BN_get0_nist_prime_224:PBIGNUM;
begin
    Result := @ossl_bignum_nist_p_224;
end;


function BN_get0_nist_prime_256:PBIGNUM;
begin
    Result := @ossl_bignum_nist_p_256;
end;


function BN_get0_nist_prime_384:PBIGNUM;
begin
    Result := @ossl_bignum_nist_p_384;
end;


function BN_get0_nist_prime_521:PBIGNUM;
begin
    Result := @ossl_bignum_nist_p_521;
end;

procedure bn_cp_32_naked(_to: PBN_ULONG; n: int; from: PBN_ULONG; m: int);
begin
{$POINTERMATH ON}
 if ((n and 1) > 0) then
    _to[n div 2] := _to[n div 2] and
                    get_result( (m and 1)>0, (from[m div 2] and BN_MASK2h), (from[m div 2] shl 32))
 else
   _to[n div 2] := get_result( (m and 1)> 0, (from[m div 2] shr 32),
                               (from[m div 2] and BN_MASK2l));
 {$POINTERMATH OFF}
end;

procedure bn_32_set_0(_to: PBN_ULONG; n: int);
begin
{$POINTERMATH ON}
   if (n and 1) >0  then
     _to[n div 2] := _to[n div 2] and BN_MASK2l
   else
     _to[n div 2] := 0 ;
{$POINTERMATH OFF}
end;

procedure bn_cp_32(_to: PBN_ULONG; n: Int; from: PBN_ULONG; m: int);
begin
    if ((m)>=0) then
       bn_cp_32_naked(_to,n,from,m)
    else
       bn_32_set_0(_to,n)
end;

procedure nist_set_224(_to, from: PBN_ULONG; a1, a2, a3, a4, a5, a6, a7: int);
begin
	bn_cp_32(_to, 0, from, (a7) - 7);
	bn_cp_32(_to, 1, from, (a6) - 7);
	bn_cp_32(_to, 2, from, (a5) - 7);
	bn_cp_32(_to, 3, from, (a4) - 7);
	bn_cp_32(_to, 4, from, (a3) - 7);
	bn_cp_32(_to, 5, from, (a2) - 7);
	bn_cp_32(_to, 6, from, (a1) - 7);
end;


procedure nist_set_256(_to, from: PBN_ULONG; a1, a2, a3, a4, a5, a6, a7, a8: int);
begin
	bn_cp_32(_to, 0, from, (a8) - 8);
	bn_cp_32(_to, 1, from, (a7) - 8);
	bn_cp_32(_to, 2, from, (a6) - 8);
	bn_cp_32(_to, 3, from, (a5) - 8);
	bn_cp_32(_to, 4, from, (a4) - 8);
	bn_cp_32(_to, 5, from, (a3) - 8);
	bn_cp_32(_to, 6, from, (a2) - 8);
	bn_cp_32(_to, 7, from, (a1) - 8);
end;


procedure nist_set_384(_to,from: PBN_ULONG; a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12: int);
begin
	bn_cp_32(_to, 0, from,  (a12) - 12);
	bn_cp_32(_to, 1, from,  (a11) - 12);
	bn_cp_32(_to, 2, from,  (a10) - 12);
	bn_cp_32(_to, 3, from,  (a9) - 12);
	bn_cp_32(_to, 4, from,  (a8) - 12);
	bn_cp_32(_to, 5, from,  (a7) - 12);
	bn_cp_32(_to, 6, from,  (a6) - 12);
	bn_cp_32(_to, 7, from,  (a5) - 12);
	bn_cp_32(_to, 8, from,  (a4) - 12);
	bn_cp_32(_to, 9, from,  (a3) - 12);
	bn_cp_32(_to, 10, from, (a2) - 12);
	bn_cp_32(_to, 11, from, (a1) - 12);
end;





function BN_nist_mod_521(r : PBIGNUM;a, field : PBIGNUM; ctx : PBN_CTX):integer;
var
  top, i : integer;
  r_d, a_d : PBN_ULONG;
  t_d : array[0..(BN_NIST_521_TOP)-1] of BN_ULONG;
  val, tmp : BN_ULONG;
  res : PBN_ULONG;
  mask : PTR_SIZE_INT;
  ossl_bignum_nist_p_521_sqr: TBIGNUM;
begin
{$POINTERMATH ON}
    top := a.top;
    a_d := a.d;
    ossl_bignum_nist_p_521_sqr := get_BIGNUM(
        PBN_ULONG(@_nist_p_521_sqr),
        Length(_nist_p_521_sqr),
        Length(_nist_p_521_sqr),
        0, BN_FLG_STATIC_DATA
    );
    field := @ossl_bignum_nist_p_521; { just to make sure }
    if (BN_is_negative(a)>0)  or ( BN_ucmp(a, @ossl_bignum_nist_p_521_sqr) >= 0) then
        Exit(BN_nnmod(r, a, field, ctx));
    i := BN_ucmp(field, a);
    if i = 0 then
    begin
        BN_zero(r);
        Exit(1);
    end
    else
    if (i > 0) then
        Exit( get_result(r = a, 1 , int(BN_copy(r, a) <> nil)));
    if r <> a then
    begin
        if nil = bn_wexpand(r, BN_NIST_521_TOP) then
            Exit(0);
        r_d := r.d;
        nist_cp_bn(r_d, a_d, BN_NIST_521_TOP);
    end
    else
        r_d := a_d;
    { upper 521 bits, copy ... }
    nist_cp_bn_0(@t_d, a_d + (BN_NIST_521_TOP - 1),
                 top - (BN_NIST_521_TOP - 1), BN_NIST_521_TOP);
    { ... and right shift }
    val := t_d[0];
    for  i := 0 to BN_NIST_521_TOP - 1-1 do
    begin
{$IF false}
        {
         * MSC ARM compiler [version 2013, presumably even earlier,
         * much earlier] miscompiles this code, but not one in
         * #else section. See RT#3541.
         }
        tmp := val  shr  BN_NIST_521_RSHIFT;
        val := t_d[i + 1];
        t_d[i] := (tmp or val  shl  BN_NIST_521_LSHIFT) and BN_MASK2;
{$ELSE}
        tmp := t_d[i + 1];
        t_d[i] := (val  shr  BN_NIST_521_RSHIFT or tmp shl BN_NIST_521_LSHIFT) and BN_MASK2;
        val := tmp;
{$ENDIF}
    end;
    t_d[i] := val  shr  BN_NIST_521_RSHIFT;
    { lower 521 bits }
    r_d[i] := r_d[i] and BN_NIST_521_TOP_MASK;
    bn_add_words(r_d, r_d, @t_d, BN_NIST_521_TOP);
    mask := 0 - PTR_SIZE_INT(bn_sub_words(@t_d, r_d, @_nist_p_521,
                                        BN_NIST_521_TOP));
    res := @t_d;
    res := PBN_ULONG((PTR_SIZE_INT( res) and not mask) or
                       (  PTR_SIZE_INT( r_d) and mask));
    nist_cp_bn(r_d, res, BN_NIST_521_TOP);
    r.top := BN_NIST_521_TOP;
    bn_correct_top(r);
    Result := 1;
{$POINTERMATH OFF}
end;


function BN_nist_mod_256(r : PBIGNUM;a, field : PBIGNUM; ctx : PBN_CTX):integer;
type
  buf_st = record
      case integer of
        0: ( bn: array[0..BN_NIST_256_TOP-1] of BN_ULONG);
        1: ( ui: array[0..BN_NIST_256_TOP * sizeof(BN_ULONG) div sizeof(uint32)-1 ] of Uint32);
    end;

   u_st = record
      case integer of
       0: (f: bn_addsub_f);
       1: (p: PTR_SIZE_INT);
   end;

var
  i, top, carry : integer;
  a_d, r_d : PBN_ULONG;
  bn, c_d : array[0..(BN_NIST_256_TOP)-1] of BN_ULONG;
  mask : PTR_SIZE_INT;
  f : bn_addsub_f;
  p : PTR_SIZE_INT;
  buf: buf_st;
  u: u_st;
  t_d : array[0..(BN_NIST_256_TOP)-1] of BN_ULONG;
  ap,res: PBN_ULONG;
  t, c: BN_ULONG;
  ossl_bignum_nist_p_256_sqr: TBIGNUM;
begin
{$POINTERMATH ON}
    top := a.top;
    carry := 0;
     a_d := a.d;


    ossl_bignum_nist_p_256_sqr := get_BIGNUM(
        PBN_ULONG(@_nist_p_256_sqr),
        Length(_nist_p_256_sqr),
        Length(_nist_p_256_sqr),
        0, BN_FLG_STATIC_DATA
    );
    field := @ossl_bignum_nist_p_256; { just to make sure }
    if (BN_is_negative(a)>0)  or ( BN_ucmp(a, @ossl_bignum_nist_p_256_sqr) >= 0) then
        Exit(BN_nnmod(r, a, field, ctx));
    i := BN_ucmp(field, a);
    if i = 0 then
    begin
        BN_zero(r);
        Exit(1);
    end
    else
    if (i > 0) then
        Exit( get_result(r = a , 1 , int(BN_copy(r, a) <> nil)));
    if r <> a then
    begin
        if nil = bn_wexpand(r, BN_NIST_256_TOP) then
            Exit(0);
        r_d := r.d;
        nist_cp_bn(r_d, a_d, BN_NIST_256_TOP);
    end
    else
        r_d := a_d;
    nist_cp_bn_0(@buf.bn, a_d + BN_NIST_256_TOP, top - BN_NIST_256_TOP,
                 BN_NIST_256_TOP);
{$IF defined(NIST_INT64)}
    begin
        rp := (Puint32 )r_d;
        acc := rp[0];
        acc  := acc + (bp[8 - 8]);
        acc  := acc + (bp[9 - 8]);
        acc  := acc - (bp[11 - 8]);
        acc  := acc - (bp[12 - 8]);
        acc  := acc - (bp[13 - 8]);
        acc  := acc - (bp[14 - 8]);
        rp[0] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[1]);
        acc  := acc + (bp[9 - 8]);
        acc  := acc + (bp[10 - 8]);
        acc  := acc - (bp[12 - 8]);
        acc  := acc - (bp[13 - 8]);
        acc  := acc - (bp[14 - 8]);
        acc  := acc - (bp[15 - 8]);
        rp[1] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[2]);
        acc  := acc + (bp[10 - 8]);
        acc  := acc + (bp[11 - 8]);
        acc  := acc - (bp[13 - 8]);
        acc  := acc - (bp[14 - 8]);
        acc  := acc - (bp[15 - 8]);
        rp[2] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[3]);
        acc  := acc + (bp[11 - 8]);
        acc  := acc + (bp[11 - 8]);
        acc  := acc + (bp[12 - 8]);
        acc  := acc + (bp[12 - 8]);
        acc  := acc + (bp[13 - 8]);
        acc  := acc - (bp[15 - 8]);
        acc  := acc - (bp[8 - 8]);
        acc  := acc - (bp[9 - 8]);
        rp[3] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[4]);
        acc  := acc + (bp[12 - 8]);
        acc  := acc + (bp[12 - 8]);
        acc  := acc + (bp[13 - 8]);
        acc  := acc + (bp[13 - 8]);
        acc  := acc + (bp[14 - 8]);
        acc  := acc - (bp[9 - 8]);
        acc  := acc - (bp[10 - 8]);
        rp[4] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[5]);
        acc  := acc + (bp[13 - 8]);
        acc  := acc + (bp[13 - 8]);
        acc  := acc + (bp[14 - 8]);
        acc  := acc + (bp[14 - 8]);
        acc  := acc + (bp[15 - 8]);
        acc  := acc - (bp[10 - 8]);
        acc  := acc - (bp[11 - 8]);
        rp[5] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[6]);
        acc  := acc + (bp[14 - 8]);
        acc  := acc + (bp[14 - 8]);
        acc  := acc + (bp[15 - 8]);
        acc  := acc + (bp[15 - 8]);
        acc  := acc + (bp[14 - 8]);
        acc  := acc + (bp[13 - 8]);
        acc  := acc - (bp[8 - 8]);
        acc  := acc - (bp[9 - 8]);
        rp[6] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[7]);
        acc  := acc + (bp[15 - 8]);
        acc  := acc + (bp[15 - 8]);
        acc  := acc + (bp[15 - 8]);
        acc  := acc + (bp[8 - 8]);
        acc  := acc - (bp[10 - 8]);
        acc  := acc - (bp[11 - 8]);
        acc  := acc - (bp[12 - 8]);
        acc  := acc - (bp[13 - 8]);
        rp[7] := uint32( acc;
        carry := int (acc  shr  32);
    end;
{$ELSE}
    begin
        {
         * S1
         }
        nist_set_256(@t_d, @buf.bn, 15, 14, 13, 12, 11, 0, 0, 0);
        {
         * S2
         }
        nist_set_256(@c_d, @buf.bn, 0, 15, 14, 13, 12, 0, 0, 0);
        carry := int (bn_add_words(@t_d, @t_d, @c_d, BN_NIST_256_TOP));
        { left shift }
        begin
            //PBN_ULONG  ap, t, c;
            ap := @t_d;
            c := 0;
            i := BN_NIST_256_TOP;
            while i <> 0 do
            begin
                t := ap^;
                (ap)^ := ((t  shl  1) or c) and BN_MASK2;
                Inc(ap);
                c := get_result( (t and BN_TBIT) >0, 1 , 0);
                Dec(i);
            end;
            carry  := carry shl 1;
            carry  := carry  or c;
        end;
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
        {
         * S3
         }
        nist_set_256(@t_d, @buf.bn, 15, 14, 0, 0, 0, 10, 9, 8);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
        {
         * S4
         }
        nist_set_256(@t_d, @buf.bn, 8, 13, 15, 14, 13, 11, 10, 9);
        carry  := carry + int (bn_add_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
        {
         * D1
         }
        nist_set_256(@t_d, @buf.bn, 10, 8, 0, 0, 0, 13, 12, 11);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
        {
         * D2
         }
        nist_set_256(@t_d, @buf.bn, 11, 9, 0, 0, 15, 14, 13, 12);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
        {
         * D3
         }
        nist_set_256(@t_d, @buf.bn, 12, 0, 10, 9, 8, 15, 14, 13);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
        {
         * D4
         }
        nist_set_256(@t_d, @buf.bn, 13, 0, 11, 10, 9, 0, 15, 14);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_256_TOP));
    end;
{$ENDIF}
    { see BN_nist_mod_224 for explanation }
    u.f := bn_sub_words;
    if carry > 0 then
       carry := int (bn_sub_words(r_d, r_d, @_nist_p_256[carry - 1],
                              BN_NIST_256_TOP))
    else
    if (carry < 0) then
    begin
        carry := int (bn_add_words(r_d, r_d, @_nist_p_256[-carry - 1],
                              BN_NIST_256_TOP));
        mask := 0 - PTR_SIZE_INT( carry);
        u.p := (PTR_SIZE_INT(Addr( bn_sub_words)) and mask) or
               (PTR_SIZE_INT(Addr( bn_add_words)) and not mask);
    end
    else
        carry := 1;
    mask := 0 - PTR_SIZE_INT ( u.f(@c_d, r_d, @_nist_p_256[0], BN_NIST_256_TOP));
    mask := mask and ( 0 - PTR_SIZE_INT(carry));
    res := @c_d;
    res := PBN_ULONG ((PTR_SIZE_INT( res) and not mask) or
                      (PTR_SIZE_INT( r_d) and mask));
    nist_cp_bn(r_d, res, BN_NIST_256_TOP);
    r.top := BN_NIST_256_TOP;
    bn_correct_top(r);
    Result := 1;
 {$POINTERMATH OFF}
end;

function BN_nist_mod_224(r : PBIGNUM;a, field : PBIGNUM; ctx : PBN_CTX):integer;
type
   buf_st = record
      case integer of
        0: ( bn: array[0..BN_NIST_224_TOP-1] of BN_ULONG);
        1: ( ui: array[0..BN_NIST_224_TOP * sizeof(BN_ULONG) div sizeof(uint32)-1 ] of Uint32);
    end;

   u_st = record
      case integer of
       0: (f: bn_addsub_f);
       1: (p: PTR_SIZE_INT);
   end;
var
  top, carry, i  : integer;
  r_d, a_d : PBN_ULONG;
  bn, c_d, t_d : array[0..(BN_NIST_224_TOP)-1] of BN_ULONG;

  res : PBN_ULONG;
  mask : PTR_SIZE_INT;
  ossl_bignum_nist_p_224_sqr: TBIGNUM ;
  u: u_st;
  //acc : NIST_INT64;
  buf: buf_st;

begin
{$POINTERMATH ON}
    top := a.top;
    a_d := a.d;
    ossl_bignum_nist_p_224_sqr := get_BIGNUM(
        PBN_ULONG(@_nist_p_224_sqr),
        Length(_nist_p_224_sqr),
        Length(_nist_p_224_sqr),
        0, BN_FLG_STATIC_DATA
    );

    field := @ossl_bignum_nist_p_224; { just to make sure }
    if (BN_is_negative(a)>0)  or  (BN_ucmp(a, @ossl_bignum_nist_p_224_sqr) >= 0)  then
        Exit(BN_nnmod(r, a, field, ctx));
    i := BN_ucmp(field, a);
    if i = 0 then
    begin
        BN_zero(r);
        Exit(1);
    end
    else
    if (i > 0) then
        Exit( get_result(r = a, 1 , int(BN_copy(r, a) <> nil)));
    if r <> a then
    begin
        if nil = bn_wexpand(r, BN_NIST_224_TOP) then
           Exit(0);
        r_d := r.d;
        nist_cp_bn(r_d, a_d, BN_NIST_224_TOP);
    end
    else
        r_d := a_d;
{$IF BN_BITS2=64}
    { copy upper 256 bits of 448 bit number ... }
    nist_cp_bn_0(@c_d, a_d + (BN_NIST_224_TOP - 1),
                 top - (BN_NIST_224_TOP - 1), BN_NIST_224_TOP);
    { ... and right shift by 32 to obtain upper 224 bits }
    nist_set_224(@buf.bn, @c_d, 14, 13, 12, 11, 10, 9, 8);
    { truncate lower part to 224 bits too }
    r_d[BN_NIST_224_TOP - 1] := r_d[BN_NIST_224_TOP - 1] and BN_MASK2l;
{$ELSE}
    nist_cp_bn_0(buf.bn, a_d + BN_NIST_224_TOP, top - BN_NIST_224_TOP,
                 BN_NIST_224_TOP);
{$ENDIF}
{$IF defined(NIST_INT64)  and  (BN_BITS2 <> 64)}
    begin
        rp := Puint32(r_d);
        acc := rp[0];
        acc  := acc - (bp[7 - 7]);
        acc  := acc - (bp[11 - 7]);
        rp[0] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[1]);
        acc  := acc - (bp[8 - 7]);
        acc  := acc - (bp[12 - 7]);
        rp[1] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[2]);
        acc  := acc - (bp[9 - 7]);
        acc  := acc - (bp[13 - 7]);
        rp[2] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[3]);
        acc  := acc + (bp[7 - 7]);
        acc  := acc + (bp[11 - 7]);
        acc  := acc - (bp[10 - 7]);
        rp[3] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[4]);
        acc  := acc + (bp[8 - 7]);
        acc  := acc + (bp[12 - 7]);
        acc  := acc - (bp[11 - 7]);
        rp[4] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[5]);
        acc  := acc + (bp[9 - 7]);
        acc  := acc + (bp[13 - 7]);
        acc  := acc - (bp[12 - 7]);
        rp[5] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[6]);
        acc  := acc + (bp[10 - 7]);
        acc  := acc - (bp[13 - 7]);
        rp[6] := uint32( acc;
        carry := int (acc  shr  32);
{$IF BN_BITS2=64}
        rp[7] := carry;
{$ENDIF}
    end;
{$ELSE }
    begin
        nist_set_224(@t_d, @buf.bn, 10, 9, 8, 7, 0, 0, 0);
        carry := int( bn_add_words(r_d, r_d, @t_d, BN_NIST_224_TOP));
        nist_set_224(@t_d, @buf.bn, 0, 13, 12, 11, 0, 0, 0);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_224_TOP));
        nist_set_224(@t_d, @buf.bn, 13, 12, 11, 10, 9, 8, 7);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_224_TOP));
        nist_set_224(@t_d, @buf.bn, 0, 0, 0, 0, 13, 12, 11);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_224_TOP));
{$IF BN_BITS2=64}
        carry := int (r_d[BN_NIST_224_TOP - 1]  shr  32);
{$ENDIF}
    end;
{$ENDIF}
    u.f := bn_sub_words;
    if carry > 0 then
    begin
        carry := int (bn_sub_words(r_d, r_d, @_nist_p_224[carry - 1],
                              BN_NIST_224_TOP));
{$IF BN_BITS2=64}
        carry := int (not (r_d[BN_NIST_224_TOP - 1]  shr  32)) and 1;
{$ENDIF}
    end
    else
    if (carry < 0)  then
    begin
        {
         * it's a bit more complicated logic in this case. if bn_add_words
         * yields no carry, then result has to be adjusted by unconditionally
         * *adding* the modulus. but if it does, then result has to be
         * compared to the modulus and conditionally adjusted by
         * *subtracting* the latter.
         }
        carry := int (bn_add_words(r_d, r_d, @_nist_p_224[-carry - 1],
                              BN_NIST_224_TOP));
        mask := 0 - PTR_SIZE_INT( carry);
        u.p := (PTR_SIZE_INT(Addr(bn_sub_words)) and mask) or
               (PTR_SIZE_INT(Addr(bn_add_words)) and not mask);
    end
    else
        carry := 1;
    { otherwise it's effectively same as in BN_nist_mod_192... }
    mask := 0 - PTR_SIZE_INT (u.f(@c_d, r_d, @_nist_p_224[0], BN_NIST_224_TOP));
    mask := mask and ( 0 - PTR_SIZE_INT(carry));
    res := @c_d;
    res := PBN_ULONG((PTR_SIZE_INT( res) and not mask) or
                       (PTR_SIZE_INT(r_d) and mask));
    nist_cp_bn(r_d, res, BN_NIST_224_TOP);
    r.top := BN_NIST_224_TOP;
    bn_correct_top(r);
    Result := 1;
 {$POINTERMATH OFF}
end;

procedure bn_cp_64(_to: PBN_ULONG; n: int; from: PBN_ULONG; m: int) ;
begin
{$POINTERMATH ON}
   _to[n] := get_result( (m>=0), from[m] ,0);
{$POINTERMATH OFF}
end;

procedure nist_set_192(_to, from: PBN_ULONG; a1, a2, a3: int) ;
begin
	bn_cp_64(_to, 0, from, (a3) - 3);
	bn_cp_64(_to, 1, from, (a2) - 3);
	bn_cp_64(_to, 2, from, (a1) - 3);
end;



procedure nist_cp_bn_0(dst : PBN_ULONG;const src : PBN_ULONG; top, max : integer);
var
  i : integer;
begin
{$POINTERMATH ON}
{$IFDEF BN_DEBUG}
    ossl_assert(top <= max);
{$ENDIF}
    for i := 0 to top-1 do
        dst[i] := src[i];
    while i < max do
    begin
        dst[i] := 0;
        Inc(i);
    end;
{$POINTERMATH OFF}
end;


procedure nist_cp_bn(dst : PBN_ULONG;const src : PBN_ULONG; top : integer);
var
  i : integer;
begin
 {$POINTERMATH ON}
    for i := 0 to top-1 do
        dst[i] := src[i];
 {$POINTERMATH OFF}
end;


function BN_nist_mod_384(r : PBIGNUM; a, field : PBIGNUM; ctx : PBN_CTX):integer;
type
  buf_st = record
     bn : array[0..(BN_NIST_384_TOP)-1] of BN_ULONG;
     ui:  array[0..BN_NIST_384_TOP * sizeof(BN_ULONG) div sizeof(uint32)-1 ] of UInt32;
  end;
  u_st = record
      case integer of
       0: (f: bn_addsub_f);
       1: (p: PTR_SIZE_INT);
   end;
var
  i, top, carry : integer;
  r_d, a_d : PBN_ULONG;
  c_d : array[0..(BN_NIST_384_TOP)-1] of BN_ULONG;
  ap,res : PBN_ULONG;
  mask : PTR_SIZE_INT;

  t_d : array[0..(BN_NIST_384_TOP)-1] of BN_ULONG;
  buf: buf_st;
  u: u_st;
  ossl_bignum_nist_p_384_sqr: TBIGNUM ;
  t, c: BN_ULONG  ;
begin
{$POINTERMATH ON}
    top := a.top;
    carry := 0;
    a_d := a.d;
    ossl_bignum_nist_p_384_sqr := get_BIGNUM(
        PBN_ULONG(@_nist_p_384_sqr),
        Length(_nist_p_384_sqr),
        Length(_nist_p_384_sqr),
        0, BN_FLG_STATIC_DATA
    );
    field := @ossl_bignum_nist_p_384; { just to make sure }
    if (BN_is_negative(a)>0)  or ( BN_ucmp(a, @ossl_bignum_nist_p_384_sqr) >= 0) then
        Exit(BN_nnmod(r, a, field, ctx));
    i := BN_ucmp(field, a);
    if i = 0 then
    begin
        BN_zero(r);
        Exit(1);
    end
    else
    if (i > 0) then
        Exit(get_result (r = a , 1 , int(BN_copy(r, a) <> nil)));
    if r <> a then
    begin
        if nil = bn_wexpand(r, BN_NIST_384_TOP) then
            Exit(0);
        r_d := r.d;
        nist_cp_bn(r_d, a_d, BN_NIST_384_TOP);
    end
    else
        r_d := a_d;
    nist_cp_bn_0(@buf.bn, a_d + BN_NIST_384_TOP, top - BN_NIST_384_TOP,
                 BN_NIST_384_TOP);
{$IF defined(NIST_INT64)}
    begin
        rp := (Puint32 )r_d;
        acc := rp[0];
        acc  := acc + (bp[12 - 12]);
        acc  := acc + (bp[21 - 12]);
        acc  := acc + (bp[20 - 12]);
        acc  := acc - (bp[23 - 12]);
        rp[0] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[1]);
        acc  := acc + (bp[13 - 12]);
        acc  := acc + (bp[22 - 12]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc - (bp[12 - 12]);
        acc  := acc - (bp[20 - 12]);
        rp[1] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[2]);
        acc  := acc + (bp[14 - 12]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc - (bp[13 - 12]);
        acc  := acc - (bp[21 - 12]);
        rp[2] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[3]);
        acc  := acc + (bp[15 - 12]);
        acc  := acc + (bp[12 - 12]);
        acc  := acc + (bp[20 - 12]);
        acc  := acc + (bp[21 - 12]);
        acc  := acc - (bp[14 - 12]);
        acc  := acc - (bp[22 - 12]);
        acc  := acc - (bp[23 - 12]);
        rp[3] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[4]);
        acc  := acc + (bp[21 - 12]);
        acc  := acc + (bp[21 - 12]);
        acc  := acc + (bp[16 - 12]);
        acc  := acc + (bp[13 - 12]);
        acc  := acc + (bp[12 - 12]);
        acc  := acc + (bp[20 - 12]);
        acc  := acc + (bp[22 - 12]);
        acc  := acc - (bp[15 - 12]);
        acc  := acc - (bp[23 - 12]);
        acc  := acc - (bp[23 - 12]);
        rp[4] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[5]);
        acc  := acc + (bp[22 - 12]);
        acc  := acc + (bp[22 - 12]);
        acc  := acc + (bp[17 - 12]);
        acc  := acc + (bp[14 - 12]);
        acc  := acc + (bp[13 - 12]);
        acc  := acc + (bp[21 - 12]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc - (bp[16 - 12]);
        rp[5] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[6]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc + (bp[18 - 12]);
        acc  := acc + (bp[15 - 12]);
        acc  := acc + (bp[14 - 12]);
        acc  := acc + (bp[22 - 12]);
        acc  := acc - (bp[17 - 12]);
        rp[6] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[7]);
        acc  := acc + (bp[19 - 12]);
        acc  := acc + (bp[16 - 12]);
        acc  := acc + (bp[15 - 12]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc - (bp[18 - 12]);
        rp[7] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[8]);
        acc  := acc + (bp[20 - 12]);
        acc  := acc + (bp[17 - 12]);
        acc  := acc + (bp[16 - 12]);
        acc  := acc - (bp[19 - 12]);
        rp[8] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[9]);
        acc  := acc + (bp[21 - 12]);
        acc  := acc + (bp[18 - 12]);
        acc  := acc + (bp[17 - 12]);
        acc  := acc - (bp[20 - 12]);
        rp[9] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[10]);
        acc  := acc + (bp[22 - 12]);
        acc  := acc + (bp[19 - 12]);
        acc  := acc + (bp[18 - 12]);
        acc  := acc - (bp[21 - 12]);
        rp[10] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[11]);
        acc  := acc + (bp[23 - 12]);
        acc  := acc + (bp[20 - 12]);
        acc  := acc + (bp[19 - 12]);
        acc  := acc - (bp[22 - 12]);
        rp[11] := uint32( acc;
        carry := int (acc  shr  32);
    end;
{$ELSE }
    begin
        {
         * S1
         }
        nist_set_256(@t_d, @buf.bn, 0, 0, 0, 0, 0, 23 - 4, 22 - 4, 21 - 4);
        { left shift }
        begin

            ap := @t_d;
            c := 0;
            i := 3;
            while i <> 0 do
            begin
                t := ap^;
                (ap)^ := ((t  shl  1) or c) and BN_MASK2;
                Inc(ap);
                c := get_result( (t and BN_TBIT) > 0, 1 , 0);
                Dec(i);
            end;
            ap^ := c;
        end;
        carry := int (bn_add_words(r_d + (128 div BN_BITS2), r_d + (128 div BN_BITS2),
                              @t_d, BN_NIST_256_TOP));
        {
         * S2
         }
        carry  := carry + int( bn_add_words(r_d, r_d, @buf.bn, BN_NIST_384_TOP));
        {
         * S3
         }
        nist_set_384(@t_d, @buf.bn, 20, 19, 18, 17, 16, 15, 14, 13, 12, 23, 22,
                     21);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
        {
         * S4
         }
        nist_set_384(@t_d, @buf.bn, 19, 18, 17, 16, 15, 14, 13, 12, 20, 0, 23,
                     0);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
        {
         * S5
         }
        nist_set_384(@t_d, @buf.bn, 0, 0, 0, 0, 23, 22, 21, 20, 0, 0, 0, 0);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
        {
         * S6
         }
        nist_set_384(@t_d, @buf.bn, 0, 0, 0, 0, 0, 0, 23, 22, 21, 0, 0, 20);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
        {
         * D1
         }
        nist_set_384(@t_d, @buf.bn, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                     23);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
        {
         * D2
         }
        nist_set_384(@t_d, @buf.bn, 0, 0, 0, 0, 0, 0, 0, 23, 22, 21, 20, 0);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
        {
         * D3
         }
        nist_set_384(@t_d, @buf.bn, 0, 0, 0, 0, 0, 0, 0, 23, 23, 0, 0, 0);
        carry  := carry - int( bn_sub_words(r_d, r_d, @t_d, BN_NIST_384_TOP));
    end;
{$ENDIF}
    { see BN_nist_mod_224 for explanation }
    u.f := bn_sub_words;
    if carry > 0 then
       carry := int( bn_sub_words(r_d, r_d, @_nist_p_384[carry - 1],
                              BN_NIST_384_TOP))
    else
    if (carry < 0) then
    begin
        carry := int (bn_add_words(r_d, r_d, @_nist_p_384[-carry - 1],
                              BN_NIST_384_TOP));
        mask := 0 - PTR_SIZE_INT(carry);
        u.p := (PTR_SIZE_INT(Addr( bn_sub_words)) and mask) or
               (PTR_SIZE_INT(Addr( bn_add_words)) and not mask);
    end
    else
        carry := 1;
    mask := 0 - PTR_SIZE_INT( u.f(@c_d, r_d, @_nist_p_384[0], BN_NIST_384_TOP));
    mask := mask and ( 0 - PTR_SIZE_INT(carry));
    res := @c_d;
    res := PBN_ULONG((PTR_SIZE_INT( res) and not mask) or
                       (PTR_SIZE_INT( r_d) and mask));
    nist_cp_bn(r_d, res, BN_NIST_384_TOP);
    r.top := BN_NIST_384_TOP;
    bn_correct_top(r);
    Result := 1;
 {$POINTERMATH OFF}
end;



function BN_nist_mod_192(r : PBIGNUM; a, field : PBIGNUM; ctx : PBN_CTX):integer;
type
  buf_st = record
     bn : array[0..(BN_NIST_192_TOP)-1] of BN_ULONG;
     ui:  array[0..BN_NIST_192_TOP * sizeof(BN_ULONG) div sizeof(uint32)-1 ] of UInt32;
  end;

var
  top, carry, i : integer;
  r_d, a_d : PBN_ULONG;
  bn, c_d : array[0..(BN_NIST_192_TOP)-1] of BN_ULONG;
  res : PBN_ULONG;
  mask : PTR_SIZE_INT;
  ossl_bignum_nist_p_192_sqr: TBIGNUM;
  t_d : array[0..(BN_NIST_192_TOP)-1] of BN_ULONG;
  buf: buf_st;
begin
{$POINTERMATH ON}
    top := a.top;
    a_d := a.d;

    ossl_bignum_nist_p_192_sqr := get_BIGNUM(
        PBN_ULONG(@_nist_p_192_sqr),
        Length(_nist_p_192_sqr),
        Length(_nist_p_192_sqr),
        0, BN_FLG_STATIC_DATA
    );

    field := @ossl_bignum_nist_p_192; { just to make sure }
    if (BN_is_negative(a)>0)  or  (BN_ucmp(a, @ossl_bignum_nist_p_192_sqr) >= 0) then
        Exit(BN_nnmod(r, a, field, ctx));
    i := BN_ucmp(field, a);
    if i = 0 then
    begin
        BN_zero(r);
        Exit(1);
    end
    else
    if (i > 0) then
        Exit( get_result(r = a , 1 , int(BN_copy(r, a) <> nil)));
    if r <> a then
    begin
        if nil = bn_wexpand(r, BN_NIST_192_TOP) then
            Exit(0);
        r_d := r.d;
        nist_cp_bn(r_d, a_d, BN_NIST_192_TOP);
    end
    else
        r_d := a_d;
    nist_cp_bn_0(@buf.bn, a_d + BN_NIST_192_TOP, top - BN_NIST_192_TOP,
                 BN_NIST_192_TOP);
{$IF defined(NIST_INT64)}
    begin
        rp := Puint32(r_d);
        acc := rp[0];
        acc  := acc + (bp[3 * 2 - 6]);
        acc  := acc + (bp[5 * 2 - 6]);
        rp[0] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[1]);
        acc  := acc + (bp[3 * 2 - 5]);
        acc  := acc + (bp[5 * 2 - 5]);
        rp[1] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[2]);
        acc  := acc + (bp[3 * 2 - 6]);
        acc  := acc + (bp[4 * 2 - 6]);
        acc  := acc + (bp[5 * 2 - 6]);
        rp[2] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[3]);
        acc  := acc + (bp[3 * 2 - 5]);
        acc  := acc + (bp[4 * 2 - 5]);
        acc  := acc + (bp[5 * 2 - 5]);
        rp[3] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[4]);
        acc  := acc + (bp[4 * 2 - 6]);
        acc  := acc + (bp[5 * 2 - 6]);
        rp[4] := uint32( acc;
        acc  shr = 32;
        acc  := acc + (rp[5]);
        acc  := acc + (bp[4 * 2 - 5]);
        acc  := acc + (bp[5 * 2 - 5]);
        rp[5] := uint32( acc;
        carry := int (acc  shr  32);
    end;
{$ELSE}
    begin
        nist_set_192(@t_d, @buf.bn, 0, 3, 3);
        carry := int (bn_add_words(r_d, r_d, @t_d, BN_NIST_192_TOP));
        nist_set_192(@t_d, @buf.bn, 4, 4, 0);
        carry  := carry + int( bn_add_words(r_d, r_d, @t_d, BN_NIST_192_TOP));
        nist_set_192(@t_d, @buf.bn, 5, 5, 5);
        carry  := carry + int(bn_add_words(r_d, r_d, @t_d, BN_NIST_192_TOP));
    end;
{$ENDIF}
    if carry > 0 then
       carry := int( bn_sub_words(r_d, r_d, @_nist_p_192[carry - 1],
                              BN_NIST_192_TOP))
    else
        carry := 1;
    {
     * we need 'if (carry=0  or  result>=modulus) result := * we need 'if (carry=0  or  result>=modulus) result - modulus;
     * as comparison implies subtraction, we can write
     * 'tmp=result-modulus; if (0>= carry  or  (0>= borrow) result=tmp;'
     * this is what happens below, but without explicit if:-) a.
     }
    mask := 0 - PTR_SIZE_INT( bn_sub_words(@c_d, r_d, @_nist_p_192[0],
                                        BN_NIST_192_TOP));
    mask := mask and ( 0 - PTR_SIZE_INT(carry));
    res := @c_d;
    res := PBN_ULONG
        ((PTR_SIZE_INT(res) and (not mask) ) or (PTR_SIZE_INT(r_d) and mask));
    nist_cp_bn(r_d, res, BN_NIST_192_TOP);
    r.top := BN_NIST_192_TOP;
    bn_correct_top(r);
    Result := 1;
{$POINTERMATH OFF}
end;

{int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
                                          const BIGNUM *field, BN_CTX *ctx);
}
//New function BN_nist_mod_func which returns an appropriate function
function BN_nist_mod_func(const p : PBIGNUM): TBN_nist_mod_func;
begin
    Result := nil;
    if BN_ucmp(@ossl_bignum_nist_p_192, p ) =0 then
        Result := BN_nist_mod_192;
    if BN_ucmp(@ossl_bignum_nist_p_224, p ) =0 then
        Result := BN_nist_mod_224;
    if BN_ucmp(@ossl_bignum_nist_p_256, p ) =0 then
       Result := BN_nist_mod_256;
    if BN_ucmp(@ossl_bignum_nist_p_384, p ) =0 then
       Result := BN_nist_mod_384;
    if BN_ucmp(@ossl_bignum_nist_p_521, p ) =0 then
       Result := BN_nist_mod_521;

end;

initialization
  ossl_bignum_nist_p_192 := get_BIGNUM(
    PBN_ULONG(@_nist_p_192[0]),
    BN_NIST_192_TOP,
    BN_NIST_192_TOP,
    0,
    BN_FLG_STATIC_DATA
  );

  ossl_bignum_nist_p_224 := get_BIGNUM(
    PBN_ULONG(@_nist_p_224[0]),
    BN_NIST_224_TOP,
    BN_NIST_224_TOP,
    0,
    BN_FLG_STATIC_DATA
 );

 ossl_bignum_nist_p_256 := get_BIGNUM(
    PBN_ULONG(@_nist_p_256[0]),
    BN_NIST_256_TOP,
    BN_NIST_256_TOP,
    0,
    BN_FLG_STATIC_DATA
);
  ossl_bignum_nist_p_384 := get_BIGNUM(
    PBN_ULONG(@_nist_p_384[0]),
    BN_NIST_384_TOP,
    BN_NIST_384_TOP,
    0,
    BN_FLG_STATIC_DATA
);
  ossl_bignum_nist_p_521 := get_BIGNUM(
    PBN_ULONG(@_nist_p_521),
    BN_NIST_521_TOP,
    BN_NIST_521_TOP,
    0,
    BN_FLG_STATIC_DATA
);

end.
