unit openssl3.crypto.ec.curve448.f_generic;

interface
uses OpenSSL.Api;

function gf_deserialize(x : Tgf;const serial : PByte; with_hibit : integer; hi_nmask : byte):mask_t;
function gf_hibit(const x : Tgf):mask_t;
procedure gf_add(d : Tgf;const a, b : Tgf);
procedure gf_strong_reduce( a : Tgf);
procedure gf_sub(d : Tgf;const a, b : Tgf);
function gf_isr(a : Tgf;const x : Tgf):mask_t;
function gf_eq(const a, b : Tgf):mask_t;
procedure gf_serialize(serial : PByte;const x : Tgf; with_hibit : integer);
function gf_lobit(const x : Tgf):mask_t;

var
   MODULUS: Tgf;

implementation
uses openssl3.crypto.ec.curve448.field
{$IF ARCH_WORD_BITS = 32}
   ,openssl3.crypto.ec.curve448.arch_32.f_impl
{$endif};






function gf_lobit(const x : Tgf):mask_t;
var
  y : Tgf;
begin
    gf_copy(y, x);
    gf_strong_reduce(y);
    Result := 0 - (y[0].limb[0] and 1);
end;




procedure gf_serialize(serial : PByte;const x : Tgf; with_hibit : integer);
var
  j,fill : uint32;
  buffer : dword_t;
  i, count : integer;
  red : Tgf;
begin
    j := 0; fill := 0;
    buffer := 0;
    gf_copy(red, x);
    gf_strong_reduce(red);
    if 0>= with_hibit then
       assert(gf_hibit(red) = 0);
    count := get_result(with_hibit >0, X_SER_BYTES , SER_BYTES);
    for i := 0 to count-1 do
    begin
        if (fill < 8)  and  (j < NLIMBS) then
        begin
            buffer  := buffer  or (dword_t( red[0].limb[LIMBPERM(j)])  shl  fill);
            fill  := fill + (LIMB_PLACE_VALUE(LIMBPERM(j)));
            Inc(j);
        end;
        serial[i] := uint8( buffer);
        fill  := fill - 8;
        buffer := buffer shr 8;
    end;
end;

function gf_eq(const a, b : Tgf):mask_t;
var
  c : Tgf;

  ret : mask_t;

  i : uint32;
begin
    ret := 0;
    gf_sub(c, a, b);
    gf_strong_reduce(c);
    for i := 0 to NLIMBS-1 do
        ret  := ret  or (c[0].limb[LIMBPERM(i)]);
    Result := word_is_zero(ret);
end;



function gf_isr(a : Tgf;const x : Tgf):mask_t;
var
  L0, L1, L2 : Tgf;
begin
    gf_sqr(@L1, x);
    gf_mul(@L2, x, L1);
    gf_sqr(@L1, L2);
    gf_mul(@L2, x, L1);
    gf_sqrn(@L1, L2, 3);
    gf_mul(@L0, L2, L1);
    gf_sqrn(@L1, L0, 3);
    gf_mul(@L0, L2, L1);
    gf_sqrn(@L2, L0, 9);
    gf_mul(@L1, L0, L2);
    gf_sqr(@L0, L1);
    gf_mul(@L2, x, L0);
    gf_sqrn(@L0, L2, 18);
    gf_mul(@L2, L1, L0);
    gf_sqrn(@L0, L2, 37);
    gf_mul(@L1, L2, L0);
    gf_sqrn(@L0, L1, 37);
    gf_mul(@L1, L2, L0);
    gf_sqrn(@L0, L1, 111);
    gf_mul(@L2, L1, L0);
    gf_sqr(@L0, L2);
    gf_mul(@L1, x, L0);
    gf_sqrn(@L0, L1, 223);
    gf_mul(@L1, L2, L0);
    gf_sqr(@L2, L1);
    gf_mul(@L0, L2, x);
    gf_copy(a, L1);
    Result := gf_eq(L0, ONE);
end;
procedure gf_sub(d : Tgf;const a, b : Tgf);
begin
    gf_sub_RAW(d, a, b);
    gf_bias(d, 2);
    gf_weak_reduce(d);
end;




procedure gf_strong_reduce( a : Tgf);
var
    scarry   : dsword_t;

    scarry_0 : word_t;

    carry    : dword_t;

    i        : uint32;
begin
    carry := 0;
    { first, clear high }
    gf_weak_reduce(a);          { Determined to have negligible perf impact. }
    { now the total is less than 2p }
    { compute total_value - p.  No need to reduce mod p. }
    scarry := 0;
    for i := 0 to NLIMBS-1 do
    begin
        scarry := scarry + a[0].limb[LIMBPERM(i)] - MODULUS[0].limb[LIMBPERM(i)];
        a[0].limb[LIMBPERM(i)] := scarry and LIMB_MASK(LIMBPERM(i));
        scarry  := scarry shr LIMB_PLACE_VALUE(LIMBPERM(i));
    end;
    {
     * uncommon case: it was >= p, so now scarry = 0 and this = x common case:
     * it was < p, so now scarry = -1 and this = x - p + 2^255 so let's add
     * back in p.  will carry back off the top for 2^255.
     }
    assert( (scarry = 0)  or  (scarry = -1));
    scarry_0 := word_t(scarry);
    { add it back }
    for i := 0 to NLIMBS-1 do
    begin
        carry := carry + a[0].limb[LIMBPERM(i)] +
            (scarry_0 and MODULUS[0].limb[LIMBPERM(i)]);
        a[0].limb[LIMBPERM(i)] := carry and LIMB_MASK(LIMBPERM(i));
        carry  := carry shr LIMB_PLACE_VALUE(LIMBPERM(i));
    end;
    assert( (carry < 2)  and  (word_t(carry) + scarry_0 = 0) );
end;




procedure gf_add(d : Tgf;const a, b : Tgf);
begin
    gf_add_RAW(d, a, b);
    gf_weak_reduce(d);
end;





function gf_hibit(const x : Tgf):mask_t;
var
  y : Tgf;
begin
    gf_add(y, x, x);
    gf_strong_reduce(y);
    Result := 0 - (y[0].limb[0] and 1);
end;

function gf_deserialize(x : Tgf;const serial : PByte; with_hibit : integer; hi_nmask : byte):mask_t;
var
  j, fill : uint32;
  buffer : dword_t;
  scarry : dsword_t;
  nbytes : uint32;
  i : uint32;
  succ : mask_t;
  sj : uint8;
begin
    j := 0; fill := 0;
    buffer := 0;
    scarry := 0;
    nbytes := get_result( with_hibit>0 , X_SER_BYTES , SER_BYTES);
    for i := 0 to NLIMBS-1 do
    begin
        while (fill < LIMB_PLACE_VALUE(LIMBPERM(i)) ) and  (j < nbytes) do
        begin
            sj := serial[j];
            if j = nbytes - 1 then
               sj := sj and (not hi_nmask);
            buffer  := buffer  or (dword_t (sj)  shl  fill);
            fill  := fill + 8;
            Inc(j);
        end;
        if (i < NLIMBS - 1) then
           x[0].limb[LIMBPERM(i)] := word_t(buffer and LIMB_MASK(LIMBPERM(i)))
        else
           x[0].limb[LIMBPERM(i)] := word_t(buffer);

        fill  := fill - (LIMB_PLACE_VALUE(LIMBPERM(i)));
        buffer := buffer shr  LIMB_PLACE_VALUE(LIMBPERM(i));
        scarry := (scarry + x[0].limb[LIMBPERM(i)] -
             MODULUS[0].limb[LIMBPERM(i)])  shr  (8 * sizeof(word_t));
    end;
    if with_hibit>0 then
      succ := 0 //0 - mask_t(1)
    else
      succ :=  not gf_hibit(x);
    Result := succ and word_is_zero(word_t(buffer)) and (not word_is_zero(word_t(scarry)));
end;

initialization
  MODULUS[0].limb[0] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[1] := LIMB2($ffffffffffffff);

  MODULUS[0].limb[2] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[3] := LIMB2($ffffffffffffff);

  MODULUS[0].limb[4] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[5] := LIMB2($ffffffffffffff);

  MODULUS[0].limb[6] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[7] := LIMB2($ffffffffffffff);

  MODULUS[0].limb[8] := LIMB1($fffffffffffffe);
  MODULUS[0].limb[9] := LIMB2($fffffffffffffe);

  MODULUS[0].limb[10] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[11] := LIMB2($ffffffffffffff);

  MODULUS[0].limb[12] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[13] := LIMB2($ffffffffffffff);

  MODULUS[0].limb[14] := LIMB1($ffffffffffffff);
  MODULUS[0].limb[15] := LIMB2($ffffffffffffff);
end.
