unit openssl3.crypto.bn.bn_word;

interface
uses OpenSSL.Api;

function BN_add_word( a : PBIGNUM; w : BN_ULONG):integer;
function BN_sub_word( a : PBIGNUM; w : BN_ULONG):integer;
function BN_div_word( a : PBIGNUM; w : BN_ULONG):BN_ULONG;
function BN_mul_word( a : PBIGNUM; w : BN_ULONG):integer;
 function BN_mod_word(const a : PBIGNUM; w : BN_ULONG):BN_ULONG;

implementation
uses  openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_shift,
      openssl3.crypto.bn.bn_asm;


function BN_mod_word(const a : PBIGNUM; w : BN_ULONG):BN_ULONG;
var
{$IFNDEF BN_LLONG}
  ret : BN_ULONG;
{$ELSE}
  ret : BN_ULLONG;
{$ENDIF}
  i : integer;
  tmp : PBIGNUM;
begin
{$POINTERMATH ON}
    ret := 0;
    if w = 0 then
       Exit(BN_ULONG(-1));
{$IFNDEF BN_LLONG}
    {
     * If |w| is too long and we don't have BN_ULLONG then we need to fall
     * back to using BN_div_word
     }
    if w > (BN_ULONG(1)  shl  BN_BITS4)  then
    begin
        tmp := BN_dup(a);
        if tmp = nil then
           Exit(BN_ULONG(-1));
        ret := BN_div_word(tmp, w);
        BN_free(tmp);
        Exit(ret);
    end;
{$ENDIF}
    bn_check_top(a);
    w := w and BN_MASK2;
    for i := a.top - 1 downto 0 do
    begin
{$IFNDEF BN_LLONG}
        {
         * We can assume here that or w <= ((BN_ULONG)1  shl  BN_BITS4) or and so
         * or ret < ((BN_ULONG)1  shl  BN_BITS4) or and therefore the shifts here are
         * safe and will not overflow
         }
        ret := ((ret  shl  BN_BITS4) or ((a.d[i]  shr  BN_BITS4) and BN_MASK2l)) mod w;
        ret := ((ret  shl  BN_BITS4) or ( a.d[i]                 and BN_MASK2l)) mod w;
{$ELSE}
        ret := BN_ULLONG ( ((ret  shl  BN_ULLONG(BN_BITS2)) or a.d[i]) mod BN_ULLONG(w));
{$ENDIF}
    end;
    Result := BN_ULONG(ret);
{$POINTERMATH OFF}
end;


{$Q-}
function BN_mul_word( a : PBIGNUM; w : BN_ULONG):integer;
var
  ll : BN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    w := w and BN_MASK2;
    if a.top > 0 then
    begin
        if w = 0 then
            BN_zero(a)
        else
        begin
            ll := bn_mul_words(a.d, a.d, a.top, w);
            if ll > 0 then
            begin
                if bn_wexpand(a, a.top + 1) = nil then
                    Exit(0);
                a.d[PostInc(a.top)] := ll;
            end;
        end;
    end;
    bn_check_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;

function BN_div_word( a : PBIGNUM; w : BN_ULONG):BN_ULONG;
var
  ret : BN_ULONG;
  i, j : integer;
  l, d : BN_ULONG;
begin
{$POINTERMATH ON}
    ret := 0;
    bn_check_top(a);
    w := w and BN_MASK2;
    if 0>= w then { actually this an error (division by zero) }
        Exit(BN_ULONG(-1));
    if a.top = 0 then
       Exit(0);
    { normalize input (so bn_div_words doesn't complain) }
    j := BN_BITS2 - BN_num_bits_word(w);
    w := w shl  j;
    if 0>= BN_lshift(a, a, j) then
        Exit(BN_ULONG(-1));
    for i := a.top - 1 downto 0 do
    begin
        l := a.d[i];
        d := bn_div_words(ret, l, w);
        ret := (l - ((d * w) and BN_MASK2)) and BN_MASK2;
        a.d[i] := d;
    end;
    if (a.top > 0 )  and  (a.d[a.top - 1] = 0) then
        Dec(a.top);
    ret := ret shr j;
    if 0>= a.top then a.neg := 0; { don't allow negative zero }
    bn_check_top(a);
    Result := ret;

{$POINTERMATH OFF}
end;

function BN_sub_word( a : PBIGNUM; w : BN_ULONG):integer;
var
  i : integer;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    w := w and BN_MASK2;
    { degenerate case: w is zero }
    if  0 >= w then Exit(1);
    { degenerate case: a is zero }
    if BN_is_zero(a) then
    begin
        i := BN_set_word(a, w);
        if i <> 0 then
           BN_set_negative(a, 1);
        Exit(i);
    end;
    { handle 'a' when negative }
    if a.neg >0 then
    begin
        a.neg := 0;
        i := BN_add_word(a, w);
        a.neg := 1;
        Exit(i);
    end;
    if (a.top = 1 )  and  (a.d[0] < w) then
    begin
        a.d[0] := w - a.d[0];
        a.neg := 1;
        Exit(1);
    end;
    i := 0;
    while True do
    begin
        if a.d[i] >= w then
        begin
            a.d[i]  := a.d[i] - w;
            break;
        end
        else
        begin
            a.d[i] := (a.d[i] - w) and BN_MASK2;
            Inc(i);
            w := 1;
        end;
    end;
    if (a.d[i] = 0)  and  (i = (a.top - 1)) then
        Dec(a.top);
    bn_check_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;

function BN_add_word( a : PBIGNUM; w : BN_ULONG):integer;
var
  l : BN_ULONG;
  i : integer;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    w := w and BN_MASK2;
    { degenerate case: w is zero }
    if  0>= w then Exit(1);
    { degenerate case: a is zero }
    if BN_is_zero(a ) then
        Exit(BN_set_word(a, w));
    { handle 'a' when negative }
    if a.neg > 0 then
    begin
        a.neg := 0;
        i := BN_sub_word(a, w);
        if not BN_is_zero(a) then
            a.neg := not (a.neg);
        Exit(i);
    end;
    i := 0;
    while ( w <> 0)  and  (i < a.top) do
    begin
        l := (a.d[i] + w) and BN_MASK2;
        a.d[i] := l;
        w := get_result(w > l, 1 , 0);
        Inc(i);
    end;
    if (w > 0)  and  (i = a.top) then
    begin
        if bn_wexpand(a, a.top + 1) = nil then
            Exit(0);
        Inc(a.top);
        a.d[i] := w;
    end;
    bn_check_top(a);
    Result := 1;
{$POINTERMATH OFF}
end;
{$Q+}
end.
