unit openssl3.crypto.ec.curve448.arch_32.f_impl;

interface
uses OpenSSL.Api;

const GF_HEADROOM = 2;

function LIMB_PLACE_VALUE(i: uint32): uint32;
function LIMB1(x: uint64): uint32;
function LIMB2(x: uint64): uint32;
 procedure gf_add_RAW(&out : Tgf;const a, b : Tgf);
procedure gf_weak_reduce( a : Tgf);
function word_is_zero(a: uint32):UInt32;
procedure gf_sub_RAW(_out : Tgf;const a, b : Tgf);
procedure gf_mul(cs : Pgf_s;const _as, bs : Tgf);
function widemul( a, b : uint32):uint64;
procedure gf_sqr(cs : Pgf_s;const _as : Tgf);

procedure gf_mulw_unsigned(cs : Pgf_s;const _as : Tgf; b : uint32);

implementation
uses openssl3.internal.constant_time;




procedure gf_mulw_unsigned(cs : Pgf_s;const _as : Tgf; b : uint32);
var
  a, c : Puint32_t;

  accum0,accum8 : uint64;

  mask : uint32;

  i : integer;
begin
{$POINTERMATH ON}
    a := @_as[0].limb;
    c := @cs.limb;
    accum0 := 0; accum8 := 0;
    mask := (1  shl  28) - 1;
    assert(b <= mask);
    for i := 0 to 7 do
    begin
        accum0  := accum0 + (widemul(b, a[i]));
        accum8  := accum8 + (widemul(b, a[i + 8]));
        c[i] := accum0 and mask;
        accum0 := accum0 shr 28;
        c[i + 8] := accum8 and mask;
        accum8 := accum8 shr 28;
    end;
    accum0  := accum0 + (accum8 + c[8]);
    c[8] := uint32( accum0) and mask;
    c[9]  := c[9] + uint32( (accum0  shr  28));
    accum8  := accum8 + (c[0]);
    c[0] := uint32( accum8) and mask;
    c[1]  := c[1] + uint32( (accum8  shr  28));
{$POINTERMATH OFF}
end;




procedure gf_sqr(cs : Pgf_s;const _as : Tgf);
begin
    gf_mul(cs, _as, _as);         { Performs better with a dedicated square }
end;

function widemul( a, b : uint32):uint64;
begin
    Result := uint64( a) * b;
end;

procedure gf_mul(cs : Pgf_s;const _as, bs : Tgf);
var
  a, b, c : Puint32_t;

  accum0,accum1,accum2 : uint64;

  mask : uint32;

  aa, bb : array[0..8-1] of uint32;

  i, j : integer;
begin
{$POINTERMATH ON}
    a := @_as[0].limb;
    b := @bs[0].limb;
    c := @cs.limb;
    accum0 := 0; accum1 := 0; accum2 := 0;
    mask := (1  shl  28) - 1;

    for i := 0 to 7 do
    begin
        aa[i] := a[i] + a[i + 8];
        bb[i] := b[i] + b[i + 8];
    end;
    for j := 0 to 7 do begin
        accum2 := 0;
        for i := 0 to j + 1-1 do
        begin
            accum2  := accum2 + (widemul(a[j - i], b[i]));
            accum1  := accum1 + (widemul(aa[j - i], bb[i]));
            accum0  := accum0 + (widemul(a[8 + j - i], b[8 + i]));
        end;
        accum1  := accum1 - accum2;
        accum0  := accum0 + accum2;
        accum2 := 0;
        for i := j + 1 to 7 do
        begin
            accum0  := accum0 - (widemul(a[8 + j - i], b[i]));
            accum2  := accum2 + (widemul(aa[8 + j - i], bb[i]));
            accum1  := accum1 + (widemul(a[16 + j - i], b[8 + i]));
        end;
        accum1  := accum1 + accum2;
        accum0  := accum0 + accum2;
        c[j] := uint32( (accum0)) and mask;
        c[j + 8] := uint32(accum1) and mask;
        accum0 := accum0 shr  28;
        accum1 := accum1 shr  28;
    end;
    accum0  := accum0 + accum1;
    accum0  := accum0 + (c[8]);
    accum1  := accum1 + (c[0]);
    c[8] := uint32( (accum0)) and mask;
    c[0] := uint32( (accum1)) and mask;
    accum0  := accum0 shr 28;
    accum1  := accum1 shr 28;
    c[9]  := c[9] + uint32(accum0);
    c[1]  := c[1] + uint32(accum1);
{$POINTERMATH OFF}
end;

procedure gf_sub_RAW(_out : Tgf;const a, b : Tgf);
var
  i : uint32;
begin
    for i := 0 to NLIMBS-1 do
        _out[0].limb[i] := a[0].limb[i] - b[0].limb[i];
end;

function word_is_zero(a: uint32):UInt32;
begin
   Result :=  constant_time_is_zero_32(a);
end;

procedure gf_weak_reduce( a : Tgf);
var
  mask, tmp, i : uint32;
begin
    mask := (1  shl  28) - 1;
    tmp := a[0].limb[NLIMBS - 1]  shr  28;
    a[0].limb[NLIMBS div 2]  := a[0].limb[NLIMBS div 2] + tmp;
    i := NLIMBS - 1;
    while ( i > 0) do
    begin
        a[0].limb[i] := (a[0].limb[i] and mask) + (a[0].limb[i - 1]  shr  28);
        Dec(i);
    end;
    a[0].limb[0] := (a[0].limb[0] and mask) + tmp;
end;





procedure gf_add_RAW(&out : Tgf;const a, b : Tgf);
var
  i : uint32;
begin
    for i := 0 to NLIMBS-1 do
        &out[0].limb[i] := a[0].limb[i] + b[0].limb[i];
end;

function LIMB1(x: uint64): uint32;
begin
   Result := ((x) and ((1 shl 28) - 1));
end;

function LIMB2(x: uint64): uint32;
begin
   Result := ((x) shr 28) ;
end;

function LIMB_PLACE_VALUE(i: uint32): uint32;
begin
  Result := 28;
end;

end.
