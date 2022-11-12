unit openssl3.crypto.bn.bn_kron;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

function BN_kronecker(const _a, _b : PBIGNUM; ctx : PBN_CTX):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_mod,
     openssl3.crypto.bn.bn_sqr, openssl3.crypto.bn.bn_asm;





const // 1d arrays
  tab : array[0..7] of integer = (
    0, 1, 0, -1, 0, -1, 0, 1 );



function BN_lsw(n: PBIGNUM): int;
begin
{$POINTERMATH ON}
   Result := get_result(n.top = 0 , BN_ULONG(0) , n.d[0])
end;

function BN_kronecker(const _a, _b : PBIGNUM; ctx : PBN_CTX):integer;
var
  i, ret, err,w : integer;

  A, B, tmp : PBIGNUM;
  label _end;

begin
    ret := -2;
    err := 0;
    {-
     * In 'tab', only odd-indexed entries are relevant:
     * For any odd BIGNUM n,
     *     tab[BN_lsw(n) and 7]
     * is $(-1)^ (n^2-1)/8) $ (using TeX notation).
     * Note that the sign of n does not matter.
     }


    bn_check_top(_a);
    bn_check_top(_b);
    BN_CTX_start(ctx);
    A := BN_CTX_get(ctx);
    B := BN_CTX_get(ctx);
    if B = nil then goto _end ;
    err := int(not Assigned(BN_copy(A, _a)));
    if err>0 then goto _end ;
    err := int(not Assigned(BN_copy(B, _b)));
    if err > 0 then
       goto _end ;
    {
     * Kronecker symbol, implemented according to Henri Cohen,
     * 'A Course in Computational Algebraic Number Theory'
     * (algorithm 1.4.10).
     }
    { Cohen's step 1: }
    if BN_is_zero(B) then
    begin
        ret := Int(BN_abs_is_word(A, 1));
        goto _end ;
    end;
    { Cohen's step 2: }
    if (not BN_is_odd(A)) and  (not BN_is_odd(B))  then
    begin
        ret := 0;
        goto _end ;
    end;
    { now  B  is non-zero }
    i := 0;
    while 0>= BN_is_bit_set(B, i) do
        Inc(i);
    err := Int(0>= BN_rshift(B, B, i));
    if err > 0 then
       goto _end ;
    if (i and 1)>0 then
    begin
        { i is odd }
        { (thus  B  was even, thus  A  must be odd!)  }
        { set 'ret' to $(-1)^((A^2-1)/8)$ }
        ret := tab[BN_lsw(A) and 7];
    end
    else
    begin
        { i is even }
        ret := 1;
    end;
    if B.neg>0 then
    begin
        B.neg := 0;
        if A.neg > 0 then
           ret := -ret;
    end;
    {
     * now B is positive and odd, so what remains to be done is to compute
     * the Jacobi symbol (A/B) and multiply it by 'ret'
     }
    while True do
    begin
        { Cohen's step 3: }
        {  B  is positive and odd }
        if BN_is_zero(A) then
        begin
            ret := get_result(BN_is_one(B) , ret , 0);
            goto _end ;
        end;
        { now  A  is non-zero }
        i := 0;
        while 0>= BN_is_bit_set(A, i) do
            PostInc(i);
        err := not BN_rshift(A, A, i);
        if err >0 then goto _end ;
        if (i and 1)>0 then
        begin
            { i is odd }
            { multiply 'ret' by  $(-1)^((B^2-1)/8)$ }
            ret := ret * tab[BN_lsw(B) and 7];
        end;
        { Cohen's step 4: }
        { multiply 'ret' by  $(-1)^((A-1)(B-1)/4)$ }
        if A.neg > 0 then
           w := not BN_lsw(A)
        else
           w := BN_lsw(A);
        if (w and BN_lsw(B) and 2) > 0 then
            ret := -ret;
        { (A, B) := (B mod |A|, |A|) }
        err := Int(0>= BN_nnmod(B, B, A, ctx));
        if err > 0 then
           goto _end ;
        tmp := A;
        A := B;
        B := tmp;
        tmp.neg := 0;
    end;
 _end:
    BN_CTX_end(ctx);
    if err > 0 then
       Exit(-2)
    else
        Result := ret;
end;






end.
