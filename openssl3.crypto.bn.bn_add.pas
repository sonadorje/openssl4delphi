unit openssl3.crypto.bn.bn_add;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function BN_add(r : PBIGNUM;const a, b : PBIGNUM):integer;
function BN_uadd(r : PBIGNUM; a, b : PBIGNUM):integer;
function BN_usub(r : PBIGNUM;const a, b : PBIGNUM):integer;
function BN_sub(r : PBIGNUM;const a, b : PBIGNUM):integer;

implementation
uses  openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_asm,
      OpenSSL3.Err;

function BN_sub(r : PBIGNUM;const a, b : PBIGNUM):integer;
var
  ret, r_neg, cmp_res : integer;
begin
    bn_check_top(a);
    bn_check_top(b);
    if a.neg <> b.neg then
    begin
        r_neg := a.neg;
        ret := BN_uadd(r, a, b);
    end
    else
    begin
        cmp_res := BN_ucmp(a, b);
        if cmp_res > 0 then
        begin
            r_neg := a.neg;
            ret := BN_usub(r, a, b);
        end
        else
        if (cmp_res < 0) then
        begin
            r_neg := Int(not Boolean(b.neg));
            ret := BN_usub(r, b, a);
        end
        else
        begin
            r_neg := 0;
            BN_zero(r);
            ret := 1;
        end;
    end;
    r.neg := r_neg;
    bn_check_top(r);
    Result := ret;
end;

function BN_usub(r : PBIGNUM;const a, b : PBIGNUM):integer;
var
  max, min, dif : integer;
  t1, t2, borrow : BN_ULONG;
  rp, ap, bp : PBN_ULONG;
begin
    bn_check_top(a);
    bn_check_top(b);
    max := a.top;
    min := b.top;
    dif := max - min;
    if dif < 0 then
    begin               { hmm... should not be happening }
        ERR_raise(ERR_LIB_BN, BN_R_ARG2_LT_ARG3);
        Exit(0);
    end;
    if bn_wexpand(r, max) = nil  then
        Exit(0);
    ap := a.d;
    bp := b.d;
    rp := r.d;
    borrow := bn_sub_words(rp, ap, bp, min);
    Inc(ap, min);
    Inc(rp, min);
    while dif > 0 do
    begin
        Dec(dif);
        t1 := PostInc(ap)^;
        t2 := (t1 - borrow) and BN_MASK2;
        PostInc(rp)^ := t2;
        borrow := borrow and int(t1 = 0);
    end;
    while (max>0)  and  (PreDec(rp)^ = 0) do
        Dec(max);
    r.top := max;
    r.neg := 0;
    //bn_pollute(r);
    Result := 1;
end;

function BN_uadd(r : PBIGNUM; a, b : PBIGNUM):integer;
var
  max, min, dif : integer;
  tmp: PBIGNUM;
  ap, bp, rp : PBN_ULONG;
  carry, t1, t2 : BN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(a);
    bn_check_top(b);
    if a.top < b.top then
    begin
        tmp := a;
        a := b;
        b := tmp;
    end;
    max := a.top;
    min := b.top;
    dif := max - min;
    if bn_wexpand(r, max + 1)= nil  then
        Exit(0);
    r.top := max;
    ap := a.d;
    bp := b.d;
    rp := r.d;
    carry := bn_add_words(rp, ap, bp, min);
    rp  := rp + min;
    ap  := ap + min;
    while dif>0 do
    begin
        Dec(dif);
        t1 := (ap)^;
        Inc(ap);
        t2 := (t1 + carry) and BN_MASK2;
        rp^ := t2;
        Inc(rp);
        carry := carry and int(t2 = 0);
    end;
    rp^ := carry;
    r.top  := r.top + carry;
    r.neg := 0;
    bn_check_top(r);
    Result := 1;
{$POINTERMATH OFF}
end;



function BN_add(r : PBIGNUM;const a, b : PBIGNUM):integer;
var
  ret, r_neg, cmp_res : integer;
begin
    bn_check_top(a);
    bn_check_top(b);
    if a.neg = b.neg then
    begin
        r_neg := a.neg;
        ret := BN_uadd(r, a, b);
    end
    else
    begin
          cmp_res := BN_ucmp(a, b);
          if cmp_res > 0 then
          begin
              r_neg := a.neg;
              ret := BN_usub(r, a, b);
          end
          else
          if (cmp_res < 0) then
          begin
            r_neg := b.neg;
            ret := BN_usub(r, b, a);
          end
          else
          begin
            r_neg := 0;
            BN_zero(r);
            ret := 1;
          end;
    end;
    r.neg := r_neg;
    bn_check_top(r);
    Result := ret;
end;


end.
