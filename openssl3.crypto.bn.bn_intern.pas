unit openssl3.crypto.bn.bn_intern;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function bn_get_top(const a : PBIGNUM):integer;
function bn_get_words(const a : PBIGNUM):PBN_ULONG;
 procedure bn_set_all_zero( a : PBIGNUM);
 function bn_compute_wNAF(const scalar : PBIGNUM; w : integer; ret_len : Psize_t):Pint8;

implementation
uses  openssl3.crypto.bn.bn_lib, openssl3.crypto.mem, OpenSSL3.Err;

function bn_compute_wNAF(const scalar : PBIGNUM; w : integer; ret_len : Psize_t):Pint8;
var
    window_val : integer;
    r          : Pint8;
    sign,
    bit,
    next_bit,
    mask       : integer;
    len, j        : size_t;
    digit      : integer;
    label _err;
begin
{$POINTERMATH ON}
    r := nil;
    sign := 1;
    len := 0;
    if BN_is_zero(scalar) then
    begin
        r := OPENSSL_malloc(1);
        if r = nil then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        r[0] := 0;
        ret_len^ := 1;
        Exit(r);
    end;
    if (w <= 0)  or  (w > 7) then begin       { 'int8 ' can represent integers with
                                 * absolute values less than 2^7 }
        ERR_raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    bit := 1  shl  w;               { at most 128 }
    next_bit := bit  shl  1;        { at most 256 }
    mask := next_bit - 1;        { at most 255 }
    if BN_is_negative(scalar) >0 then
    begin
        sign := -1;
    end;
    if (scalar.d = nil)  or  (scalar.top = 0) then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    len := BN_num_bits(scalar);
    r := OPENSSL_malloc(len + 1); {
                                  * Modified wNAF may be one digit longer than binary
representation
                                  * ( *ret_len will be set to the actual length, i.e. at most
                                  * BN_num_bits(scalar) + 1)
                                  }
    if r = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    window_val := scalar.d[0] and mask;
    j := 0;
    while (window_val <> 0)  or  (j + w + 1 < len) do  begin  { if j+w+1 >= len,
                                                      * window_val will not
                                                      * increase }
        digit := 0;
        { 0 <= window_val <= 2^(w+1) }
        if (window_val and 1)>0 then
        begin
            { 0 < window_val < 2^(w+1) }
            if (window_val and bit)>0 then
            begin
                digit := window_val - next_bit; { -2^w < digit < 0 }
{$IF true}                           { modified wNAF }
                if j + w + 1 >= len then
                begin
                    {
                     * Special case for generating modified wNAFs:
                     * no new bits will be added into window_val,
                     * so using a positive digit here will decrease
                     * the total length of the representation
                     }
                    digit := window_val and (mask  shr  1); { 0 < digit < 2^w }
                end;
{$ENDIF}
            end
            else
            begin
                digit := window_val; { 0 < digit < 2^w }
            end;
            if (digit <= -bit)  or  (digit >= bit)  or  (0>= (digit and 1)) then
            begin
                ERR_raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
            window_val  := window_val - digit;
            {
             * for modified window NAFs, it may also be 2^w
             }
            if (window_val <> 0)  and  (window_val <> next_bit)
                 and  (window_val <> bit) then
            begin
                ERR_raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
        end;
        r[PostInc(j)] := sign * digit;
        window_val := window_val shr 1;
        window_val := window_val + (bit * BN_is_bit_set(scalar, j + w));
        if window_val > next_bit then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
    end;
    if j > len + 1 then begin
        ERR_raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    ret_len^ := j;
    Exit(r);
 _err:
    OPENSSL_free(Pointer(r));
    Result := nil;
{$POINTERMATH OFF}
end;



procedure bn_set_all_zero( a : PBIGNUM);
var
  i : integer;
begin
{$POINTERMATH ON}
    for i := a.top to a.dmax-1 do
        a.d[i] := 0;
{$POINTERMATH OFF}
end;



function bn_get_words(const a : PBIGNUM):PBN_ULONG;
begin
    Result := a.d;
end;






function bn_get_top(const a : PBIGNUM):integer;
begin
    Result := a.top;
end;

end.
