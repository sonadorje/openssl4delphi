unit openssl3.crypto.ec.curve448.field;

interface
uses OpenSSL.Api;

const
   X_PRIVATE_BITS  = 448;

function  LIMBPERM(i: uint32): uint32;
function LIMB_MASK(i: uint32): uint32;
procedure gf_copy(_out : Tgf;const a : Tgf);
procedure gf_cond_swap( x : Tgf; y : Pgf_s; swap : mask_t);
procedure gf_add_nr(_out : Tgf;const a, b : Tgf);
procedure gf_sub_nr(c : Tgf;const a, b : Tgf);
 procedure gf_bias( a : Tgf; amt : integer);
procedure gf_mulw(c : Tgf;const a : Tgf; w : integer);
 procedure gf_sqrn(y: Pgf_s;const x : Tgf; n : integer);
 procedure gf_subx_nr(c : Tgf;const a, b : Tgf; amt : integer);
procedure gf_cond_neg( x : Tgf; neg : mask_t);
procedure gf_cond_sel(x : Tgf;const y, z : Tgf; is_z : mask_t);

var
  ZERO, ONE: Tgf ;

implementation

uses openssl3.internal.constant_time, openssl3.crypto.ec.curve448.f_generic,
{$IF ARCH_WORD_BITS = 32}
   openssl3.crypto.ec.curve448.arch_32.f_impl
{$ELSEIF ARCH_WORD_BITS = 64}
   openssl3.crypto.ec.curve448.arch_64.f_impl
{$endif};






procedure gf_cond_sel(x : Tgf;const y, z : Tgf; is_z : mask_t);
var
  i : size_t;
begin
    for i := 0 to NLIMBS-1 do begin
{$IF ARCH_WORD_BITS = 32}
        x[0].limb[i] := constant_time_select_32(is_z, z[0].limb[i],
                                               y[0].limb[i]);
{$ELSE} { Must be 64 bit }
        x[0].limb[i] := constant_time_select_64(is_z, z[0].limb[i],
                                               y[0].limb[i]);
{$ENDIF}
    end;
end;

procedure gf_cond_neg( x : Tgf; neg : mask_t);
var
  y : Tgf;
begin
    gf_sub(y, ZERO, x);
    gf_cond_sel(x, x, y, neg);
end;

procedure gf_subx_nr(c : Tgf;const a, b : Tgf; amt : integer);
begin
    gf_sub_RAW(c, a, b);
    gf_bias(c, amt);
    if GF_HEADROOM < amt + 1 then gf_weak_reduce(c);
end;



procedure gf_sqrn(y : Pgf_s;const x : Tgf; n : integer);
var
  tmp,tmp2 : Tgf;
begin
{$POINTERMATH ON}
    assert(n > 0);
    if (n and 1)>0 then
    begin
        gf_sqr(y, x);
        Dec(n);
    end
    else
    begin
        gf_sqr(@tmp, x);
        gf_sqr(y, tmp);
        n  := n - 2;
    end;
    while n>0 do
    begin
       tmp2[0].limb := y.limb;
        gf_sqr(@tmp, tmp2);
        gf_sqr(y, tmp);
        n := n-2;
    end;
{$POINTERMATH OFF}
end;



procedure gf_mulw(c : Tgf;const a : Tgf; w : integer);
begin
    if w > 0 then
    begin
        gf_mulw_unsigned(@c, a, w);
    end
    else
    begin
        gf_mulw_unsigned(@c, a, -w);
        gf_sub(c, ZERO, c);
    end;
end;






procedure gf_bias( a : Tgf; amt : integer);
var
  i, co1, co2 : uint32;
begin
    co1 := ((1  shl  28) - 1) * amt;
    co2 := co1 - amt;
    for i := 0 to NLIMBS-1 do
        a[0].limb[i]  := a[0].limb[i] + get_result((i = NLIMBS div 2) , co2 , co1);
end;



procedure gf_sub_nr(c : Tgf;const a, b : Tgf);
begin
    gf_sub_RAW(c, a, b);
    gf_bias(c, 2);
    if GF_HEADROOM < 3 then
      gf_weak_reduce(c);
end;

procedure gf_add_nr(_out : Tgf;const a, b : Tgf);
begin
  gf_add_RAW(_out, a, b);
end;


procedure gf_cond_swap( x : Tgf; y : Pgf_s; swap : mask_t);
var
  i : size_t;
begin
{$POINTERMATH ON}
    for i := 0 to NLIMBS-1 do
    begin
{$IF ARCH_WORD_BITS = 32}
        constant_time_cond_swap_32(swap, @(x[0].limb[i]), @(y.limb[i]));
{$ELSE { Must be 64 bit }}
        constant_time_cond_swap_64(swap, &(x[0].limb[i]), &(y.limb[i]));
{$ENDIF}
    end;
{$POINTERMATH OFF}
end;




procedure gf_copy(_out : Tgf;const a : Tgf);
begin
    _out[0] := a[0];
end;

function  LIMBPERM(i: uint32): uint32;
begin
  Result := (i);
end;

function LIMB_MASK(i: uint32): uint32;
begin
   Result := ((1) shl LIMB_PLACE_VALUE(i))-1;
end;

initialization
  FillChar(ZERO, SizeOf(ZERO), 0);
  FillChar(ZERO, SizeOf(ONE), 1);
end.

