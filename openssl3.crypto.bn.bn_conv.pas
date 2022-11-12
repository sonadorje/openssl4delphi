unit openssl3.crypto.bn.bn_conv;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function BN_hex2bn(bn : PPBIGNUM;a : PUTF8Char):integer;
function BN_bn2dec(const a : PBIGNUM):PUTF8Char;
function BN_asc2bn(bn : PPBIGNUM;const a : PUTF8Char):integer;
function BN_dec2bn(bn : PPBIGNUM; a : PUTF8Char):integer;
function BN_bn2hex(const a : PBIGNUM):PUTF8Char;

implementation

uses openssl3.crypto.ctype, OpenSSL3.Err, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bio.bio_print,
     openssl3.crypto.o_str, openssl3.crypto.mem, openssl3.crypto.bn.bn_word;


const Hex: PUTF8Char = '0123456789ABCDEF';



function BN_bn2hex(const a : PBIGNUM):PUTF8Char;
var
  i, j, v, z : integer;
  buf, p : PUTF8Char;
  label _err;
begin
{$POINTERMATH ON}
    z := 0;
    if BN_is_zero(a) then
    begin
      OPENSSL_strdup(Result, '0');
      Exit(Result);
    end;

    buf := OPENSSL_malloc(a.top * BN_BYTES * 2 + 2);
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    p := buf;
    if a.neg > 0 then
       PostInc(p)^ :=  '-';
    for i := a.top - 1 downto 0 do
    begin
        j := BN_BITS2 - 8;
        while j >= 0 do
        begin
            { strip leading zeros }
            v := int ((a.d[i]  shr  j) and $ff);
            if z  or  v <> 0 then
            begin
                PostInc(p)^ :=  Hex[v  shr  4];
                PostInc(p)^ :=  Hex[v and $0f];
                z := 1;
            end;
            j := j - 8;
        end;
    end;
    p^ := #0;
 _err:
    Result := buf;
 {$POINTERMATH OFF}
end;

function BN_dec2bn(bn : PPBIGNUM; a : PUTF8Char):integer;
var
  ret : PBIGNUM;
  l : BN_ULONG;
  neg, num, i, j : integer;
  label _err;
begin
    ret := nil;
    l := 0;
    neg := 0;
    if (a = nil)  or  (a^ = #0) then
       Exit(0);
    if a^ = '-' then
    begin
        neg := 1;
        Inc(a);
    end;
    i := 0;
    while (i <= INT_MAX div 4) and (ossl_isdigit(a[i]))  do
    begin
        Inc(i);
        continue;

    end;
    if (i = 0)  or  (i > INT_MAX div 4) then
       goto _err ;
    num := i + neg;
    if bn = nil then Exit(num);
    {
     * a is the start of the digits, and it is 'i' long. We chop it into
     * BN_DEC_NUM digits at a time
     }
    if bn^ = nil then
    begin
        ret := BN_new();
        if ret = nil then
            Exit(0);
    end
    else
    begin
        ret := bn^;
        BN_zero(ret);
    end;
    { i is the number of digits, a bit of an over expand }
    if bn_expand(ret, i * 4) = nil  then
        goto _err ;
    j := BN_DEC_NUM - i mod BN_DEC_NUM;
    if j = BN_DEC_NUM then
       j := 0;
    l := 0;
    while PreDec(i) >= 0 do
    begin
        l  := l  * 10;
        l  := l + (Ord( a^) - Ord('0'));
        PostInc(a);
        if PreInc(j) = BN_DEC_NUM  then
        begin
            if (0>= BN_mul_word(ret, BN_DEC_CONV) )
                 or  (0>= BN_add_word(ret, l)) then
                goto _err ;
            l := 0;
            j := 0;
        end;
    end;
    bn_correct_top(ret);
    bn^ := ret;
    bn_check_top(ret);
    { Don't set the negative flag if it's zero. }
    if ret.top <> 0 then
       ret.neg := neg;
    Exit(num);
 _err:
    if bn^ = nil then
       BN_free(ret);
    Result := 0;
end;

function BN_asc2bn(bn : PPBIGNUM;const a : PUTF8Char):integer;
var
  p : PUTF8Char;
begin
     p := a;
    if p^ = '-' then
       Inc(p);
    if (p[0] = '0')  and ( (p[1] = 'X')  or  (p[1] = 'x') ) then
    begin
        if 0>= BN_hex2bn(bn, p + 2) then
            Exit(0);
    end
    else
    begin
        if 0>= BN_dec2bn(bn, p)  then
            Exit(0);
    end;
    { Don't set the negative flag if it's zero. }
    if (a^ = '-')  and  ( bn^.top <> 0)  then
       bn^.neg := 1;
    Result := 1;
end;



function BN_bn2dec(const a : PBIGNUM):PUTF8Char;
var
    i, num, ok, n, tbytes           : integer;
    buf,
    p           : PUTF8Char;
    t           : PBIGNUM;
    bn_data, lp     : PBN_ULONG;
    bn_data_num : integer;
    label _err;
begin
{$POINTERMATH ON}
    i := 0; ok := 0;
    buf := nil;
    t := nil;
    bn_data := nil;
    {-
     * get an upper bound for the length of the decimal integer
     * num <= (BN_num_bits(a) + 1) * log(2)
     *     <= 3 * BN_num_bits(a) * 0.101 + log(2) + 1     (rounding error)
     *     <= 3 * BN_num_bits(a) / 10 + 3 * BN_num_bits / 1000 + 1 + 1
     }
    i := BN_num_bits(a) * 3;
    num := (i div 10 + i div 1000 + 1) + 1;
    tbytes := num + 3;   { negative and terminator and one spare? }
    bn_data_num := num div BN_DEC_NUM + 1;
    bn_data := OPENSSL_malloc(bn_data_num * sizeof(BN_ULONG));
    buf := OPENSSL_malloc(tbytes);
    if (buf = nil)  or  (bn_data = nil) then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    t := BN_dup(a) ;
    if t = nil then
        goto _err ;
    p := buf;
    lp := bn_data;
    if BN_is_zero(t)  then
    begin
        PostInc(p)^ := '0';
        PostInc(p)^ := #0;
    end
    else
    begin
        if BN_is_negative(t) > 0 then
            PostInc(p)^ := '-';
        while not BN_is_zero(t) do
        begin
            if lp - bn_data >= bn_data_num then
               goto _err ;
            lp^ := BN_div_word(t, BN_DEC_CONV);
            if lp^ = BN_ULONG(-1) then
                goto _err ;
            Inc(lp);
        end;
        Dec(lp);
        {
         * We now have a series of blocks, BN_DEC_NUM chars in length, where
         * the last one needs truncation. The blocks need to be reversed in
         * order.
         }
        n := BIO_snprintf(p, tbytes - size_t(p - buf), BN_DEC_FMT1, [lp^]);
        if n < 0 then
           goto _err ;
        p  := p + n;
        while lp <> bn_data do
        begin
            Dec(lp);
            n := BIO_snprintf(p, tbytes - size_t(p - buf), BN_DEC_FMT2, [lp^]);
            if n < 0 then
               goto _err ;
            p  := p + n;
        end;
    end;
    ok := 1;
 _err:
    OPENSSL_free(Pointer(bn_data));
    BN_free(t);
    if ok>0 then
       Exit(buf);
    OPENSSL_free(Pointer(buf));
    Result := nil;
{$POINTERMATH OFF}
end;

function BN_hex2bn(bn : PPBIGNUM;a : PUTF8Char):integer;
var
  ret : PBIGNUM;
  l : BN_ULONG;
  neg, num,
  h, m, i, j, k : integer;
  c: UTF8Char;
  label err ;
begin
{$POINTERMATH ON}
    ret := nil;
    l := 0;
    neg := 0;
    if (a = nil)  or  (a^ = #0) then Exit(0);
    if a^ = '-' then
    begin
        neg := 1;
        Inc(a);
    end;
    i := 0;
    while (i<= INT_MAX div 4)  and  (ossl_isdigit(a[i])) do
    begin
       Inc(i);
       continue;
    end;

    if (i = 0)  or  (i > INT_MAX div 4) then
       Exit(0);
    num := i + neg;
    if bn = nil then
       Exit(num);
    { a is the start of the hex digits, and it is 'i' long }
    if bn^ = nil then
    begin
       ret := BN_new();
       if ret  = nil then
            Exit(0);
    end
    else
    begin
        ret := bn^;
        if BN_get_flags(ret, BN_FLG_STATIC_DATA)>0 then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT);
            Exit(0);
        end;
        BN_zero(ret);
    end;
    { i is the number of hex digits }
    if bn_expand(ret, i * 4) = nil then
       goto err;
    j := i;                      { least significant 'hex' }
    m := 0;
    h := 0;
    while j > 0 do
    begin
        m := get_result(BN_BYTES * 2 <= j , BN_BYTES * 2 , j);
        l := 0;
        while True do
        begin
            c := a[j - m];
            k := OPENSSL_hexchar2int(c);
            if k < 0 then k := 0;          { paranoia }
            l := (l  shl  4) or k;
            Dec(m);
            if m  <= 0 then
            begin
                ret.d[h] := l;
                Inc(h);
                break;
            end;
        end;
        j  := j - (BN_BYTES * 2);
    end;
    ret.top := h;
    bn_correct_top(ret);
    bn^ := ret;
    bn_check_top(ret);
    { Don't set the negative flag if it's zero. }
    if ret.top <> 0 then
       ret.neg := neg;
    Exit(num);
 err:
    if bn^ = nil then
       BN_free(ret);
    Result := 0;
 {$POINTERMATH OFF}
end;


end.
