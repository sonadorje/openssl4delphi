unit openssl3.crypto.punycode;

interface
uses OpenSSL.Api, SysUtils;

var
    base         : uint32 = 36;
    tmin         : uint32 = 1;
    tmax         : uint32 = 26;
    skew         : uint32 = 38;
    damp         : uint32 = 700;
    initial_bias : uint32 = 72;
    initial_n    : uint32 = $80;
    maxint       : uint32 = $FFFFFFFF;

const
    delimiter    = '-';
   LABEL_BUF_SIZE = 512;

function ossl_a2ulabel(const _in : PUTF8Char; _out : PUTF8Char; outlen: Psize_t):integer;
function ossl_punycode_decode(const pEncoded : PUTF8Char; enc_len : size_t; pDecoded, pout_length : Puint32):integer;
function is_basic( a : uint32):integer;
function digit_decoded(const a : Byte):integer;
function adapt( delta, numpoints, firsttime : uint32):integer;
function codepoint2utf8( _out : PByte; utf : Cardinal):integer;

implementation
uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}OpenSSL3.common;






function codepoint2utf8( _out : PByte; utf : Cardinal):integer;
begin
    if utf <= $7F then
    begin
        { Plain ASCII }
        _out[0] := Byte(utf);
        _out[1] := 0;
        Exit(1);
    end
    else
    if (utf <= $07FF) then
    begin
        { 2-byte unicode }
        _out[0] := Byte(((utf  shr  6) and $1F) or $C0);
        _out[1] := Byte(((utf  shr  0) and $3F) or $80);
        _out[2] := 0;
        Exit(2);
    end
    else
    if (utf <= $FFFF) then
    begin
        { 3-byte unicode }
        _out[0] := Byte(((utf  shr  12) and $0F) or $E0);
        _out[1] := Byte(((utf  shr  6) and $3F) or $80);
        _out[2] := Byte(((utf  shr  0) and $3F) or $80);
        _out[3] := 0;
        Exit(3);
    end
    else
    if (utf <= $10FFFF) then
    begin
        { 4-byte unicode }
        _out[0] := Byte(((utf  shr  18) and $07) or $F0);
        _out[1] := Byte(((utf  shr  12) and $3F) or $80);
        _out[2] := Byte(((utf  shr  6) and $3F) or $80);
        _out[3] := Byte(((utf  shr  0) and $3F) or $80);
        _out[4] := 0;
        Exit(4);
    end
    else
    begin
        { error - use replacement character }
        _out[0] := Byte($EF);
        _out[1] := Byte($BF);
        _out[2] := Byte($BD);
        _out[3] := 0;
        Exit(0);
    end;
end;

function adapt( delta, numpoints, firsttime : uint32):integer;
var
  k : uint32;
begin
    k := 0;
    if firsttime>0 then
       delta := delta div damp
    else
       delta := (delta div 2);
    delta := delta + delta div numpoints;
    while delta > ((base - tmin) * tmax) div 2 do
    begin
        delta := delta div (base - tmin);
        k := k + base;
    end;
    Result := k + (((base - tmin + 1) * delta) div (delta + skew));
end;




function digit_decoded(const a : Byte):integer;
begin
    if (a >= $41)  and  (a <= $5A) then Exit(a - $41);
    if (a >= $61)  and  (a <= $7A) then Exit(a - $61);
    if (a >= $30)  and  (a <= $39) then Exit(a - $30 + 26);
    Result := -1;
end;

function is_basic( a : uint32):integer;
begin
    Result := get_result(a < $80 , 1 , 0);
end;



function ossl_punycode_decode(const pEncoded : PUTF8Char; enc_len : size_t; pDecoded, pout_length : Puint32):integer;
var
  n,i,
  bias         : uint32;
  processed_in,
  written_out : size_t;
  max_out,
  basic_count,
  loop,
  oldi,
  w,  k,
  t            : uint32;
  digit        : integer;
begin
{$POINTERMATH ON}
    n := initial_n;
    i := 0;
    bias := initial_bias;
    processed_in := 0; written_out := 0;
    max_out := pout_length^;
    basic_count := 0;
    for loop := 0 to enc_len-1 do
    begin
        if pEncoded[loop] = delimiter then
           basic_count := loop;
    end;
    if basic_count > 0 then
    begin
        if basic_count > max_out then
            Exit(0);
        for loop := 0 to basic_count-1 do
        begin
            if is_basic(Ord(pEncoded[loop])) = 0  then
                Exit(0);
            pDecoded[loop] := Ord(pEncoded[loop]);
            Inc(written_out);
        end;
        processed_in := basic_count + 1;
    end;
    loop := processed_in;
    while loop < enc_len do
    begin
        oldi := i;
        w := 1;
        k := base;
        while True do
        begin
            if loop >= enc_len then Exit(0);
            digit := digit_decoded(Ord(pEncoded[loop]));
            Inc(loop);
            if digit < 0 then Exit(0);
            if uint32(digit) > (maxint - i) div w  then
                Exit(0);
            i := i + digit * w;
            t := get_result(k <= bias , tmin , get_result(k >= bias + tmax , tmax , k - bias));
            if uint32(digit) < t then break;
            if w > maxint div (base - t) then
                Exit(0);
            w := w * (base - t);
            k := k + base;
        end;
        bias := adapt(i - oldi, written_out + 1, int(oldi = 0));
        if i div (written_out + 1) > maxint - n  then
            Exit(0);
        n := n + i div (written_out + 1);
        i  := i mod ((written_out + 1));
        if written_out > max_out then Exit(0);
        memmove(pDecoded + i + 1, pDecoded + i,
                (written_out - i) * sizeof (pDecoded^));
        pDecoded[i] := n;
        Inc(i);
        Inc(written_out);
    end;
    pout_length^ := written_out;
    Result := 1;
{$POINTERMATH OFF}
end;

function ossl_a2ulabel(const _in : PUTF8Char; _out : PUTF8Char; outlen: Psize_t):integer;
var
  outptr, inptr : PUTF8Char;
  size : size_t;
//  result : integer;

  buf : array[0..(LABEL_BUF_SIZE)-1] of uint32;
  tmpptr : PUTF8Char;
  delta : size_t;
  bufsize, i : uint32;
  seed : array[0..5] of Byte;
  utfsize : size_t;
begin
    {-
     * Domain name has some parts consisting of ASCII chars joined with dot.
     * If a part is shorter than 5 chars, it becomes U-label as is.
     * If it does not start with PostDec(xn),    it becomes U-label as is.
     * Otherwise we try to decode it.
     }
    outptr := _out;
    inptr := _in;
    size := 0;
    result := 1;
    if _out = nil then result := 0;
    while Boolean(1) do
    begin
        tmpptr := strchr(inptr, '.');
        delta := get_result(tmpptr <> nil , size_t(tmpptr - inptr) , length(inptr));
        if not HAS_PREFIX(inptr, 'xn--') then
        begin
            size  := size + (delta + 1);
            if size >= outlen^ - 1 then result := 0;
            if result > 0 then begin
                memcpy(outptr, inptr, delta + 1);
                outptr  := outptr + (delta + 1);
            end;
        end
        else
        begin
            bufsize := LABEL_BUF_SIZE;
            if ossl_punycode_decode(inptr + 4, delta - 4, @buf, @bufsize) <= 0  then
                Exit(-1);
            for i := 0 to bufsize-1 do
            begin
                utfsize := codepoint2utf8(@seed, buf[i]);
                if utfsize = 0 then Exit(-1);
                size  := size + utfsize;
                if size >= outlen^ - 1 then result := 0;
                if result > 0 then
                begin
                    memcpy(outptr, @seed, utfsize);
                    outptr  := outptr + utfsize;
                end;
            end;
            if tmpptr <> nil then
            begin
                outptr^ := '.';
                Inc(outptr);
                Inc(size);
                if size >= outlen^ - 1 then result := 0;
            end;
        end;
        if tmpptr = nil then break;
        inptr := tmpptr + 1;
    end;
    Result := result;
end;


end.
