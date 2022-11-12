unit openssl3.crypto.bio.bio_print;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, TypInfo, Math;

const
 DP_S_DEFAULT =   0;
 DP_S_FLAGS   =   1;
 DP_S_MIN     =   2;
 DP_S_DOT     =   3;
 DP_S_MAX     =   4;
 DP_S_MOD     =   5;
 DP_S_CONV    =   6;
 DP_S_DONE    =   7;
 BUFFER_INC  = 1024;
  DP_F_MINUS = (1 shl 0);
  DP_F_PLUS = (1 shl 1);
  DP_F_SPACE = (1 shl 2);
  DP_F_NUM = (1 shl 3);
  DP_F_ZERO = (1 shl 4);
  DP_F_UP = (1 shl 5);
  DP_F_UNSIGNED = (1 shl 6);
  DP_C_SHORT = 1;
  DP_C_LONG = 2;
  DP_C_LDOUBLE = 3;
  DP_C_LLONG = 4;
  DP_C_SIZE = 5;
  F_FORMAT = 0;
  E_FORMAT = 1;
  G_FORMAT = 2;
type
{$ifdef HAVE_LONG_DOUBLE  }
  LDOUBLE = Extended;
{$else}
  LDOUBLE = double ;
{$endif}

function BIO_printf(bio: PBIO; const _format : PUTF8Char; args: array of const): Integer;
function BIO_vprintf( bio : PBIO; const _format : PUTF8Char; args: array of const):integer;
function fmtint(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t; value : int64; base, _min, _max, flags : integer):integer;
function doapr_outch(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t; c : UTF8Char):integer;
function fmtfp(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t; fvalue : LDOUBLE; min, max, flags, style : integer):integer;
function pow_10( in_exp : integer):LDOUBLE;
function abs_val( value : LDOUBLE):LDOUBLE;
function roundv( value : LDOUBLE):long;
function fmtstr(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t;const value : PUTF8Char; flags, min, max : integer):integer;
function BIO_write(b : PBIO;const data : Pointer; dlen : integer):integer;
function BIO_snprintf(buf : PUTF8Char; n : size_t;const format : PUTF8Char; args: array of const):integer;
function BIO_vsnprintf(buf : PUTF8Char; n : size_t;const format : PUTF8Char; args : array of const):integer;
function _dopr(sbuffer, buffer : PPUTF8Char; maxlen, retlen : Psize_t; truncated : PInteger; _format : PUTF8Char; args : array of const):integer;

implementation

uses
   OpenSSL3.common, openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.ctype,
   openssl3.crypto.bio.bio_lib, openssl3.crypto.o_str;


function char_to_int(p: UTF8Char): int;
begin
   Result :=  Ord(p) - Ord('0')
end;

function BIO_vsnprintf(buf : PUTF8Char; n : size_t;const format : PUTF8Char; args : array of const):integer;
var
    retlen    : size_t;
    truncated : integer;
begin

    if 0>= _dopr(@buf, nil, @n, @retlen, @truncated, format, args) then
        Exit(-1);
    if truncated > 0 then {
         * In case of truncation, return -1 like traditional snprintf.
         * (Current drafts for ISO/IEC 9899 say snprintf should return the
         * number of UTF8Characters that would have been written, had the buffer
         * been large enough.)
         }
        Exit(-1);
    Result := get_result(retlen <= INT_MAX , int( retlen) , -1);
end;

function BIO_snprintf(buf : PUTF8Char; n : size_t;const format : PUTF8Char; args: array of const):integer;
begin
   Result := BIO_vsnprintf(buf, n, format, args);
end;

function BIO_write(b : PBIO;const data : Pointer; dlen : integer):integer;
var
  written : size_t;
  ret : integer;
begin
    if dlen <= 0 then
       Exit(0);
    written := 0;
    ret := bio_write_intern(b, data, size_t(dlen), @written);
    if ret > 0 then begin
        { written should always be <= dlen }
        ret := int(written);
    end;
    Result := ret;
end;

function fmtstr(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t;
                const value : PUTF8Char; flags, min, max : integer):integer;
var
  padlen : integer;
  strln, len : size_t;
  cnt : integer;
  p: PUTF8Char;
begin
{$Q-}
    cnt := 0;
    p := value;
    if p = nil then
       p := '<NULL>';
    if  max < 0 then
       len :=  SIZE_MAX
    else
       len := size_t(max);
    strln := OPENSSL_strnlen(p, len);
    padlen := min - strln;
    if (min < 0)  or  (padlen < 0) then
       padlen := 0;
    if max >= 0 then
    begin
        {
         * Calculate the maximum output including padding.
         * Make sure max doesn't overflow into negativity
         }
        if max < INT_MAX - padlen then
            max  := max + padlen
        else
            max := INT_MAX;
    end;
    if (flags and DP_F_MINUS)>0 then
       padlen := -padlen;

    while (padlen > 0)  and  ( (max < 0)  or  (cnt < max) ) do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, ' ')  then
            Exit(0);
        Dec(padlen);
        Inc(cnt);
    end;
    while (strln > 0)  and  ( (max < 0)  or  (cnt < max) ) do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, p^) then
            Exit(0);
        Dec(strln);
        Inc(cnt);
        Inc(p);
    end;
    while (padlen < 0)  and  ( (max < 0)  or  (cnt < max) ) do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, ' ' ) then
            Exit(0);
        Inc(padlen);
        Inc(cnt);
    end;
    Result := 1;
{$Q+}
end;

function roundv( value : LDOUBLE):long;
var
  intpart : long;
begin
    intpart := Round(value);
    value := value - intpart;
    if value >= 0.5 then
       Inc(intpart);
    Result := intpart;
end;

function abs_val( value : LDOUBLE):LDOUBLE;
begin
    result := value;
    if value < 0 then
       result := -value;
end;

function pow_10( in_exp : integer):LDOUBLE;
begin
    result := 1;
    while in_exp > 0 do
    begin
        result  := result  * 10;
        Dec(in_exp);
    end;
    Result := result;
end;

function fmtfp(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t; fvalue : LDOUBLE; min, max, flags, style : integer):integer;
var
  signvalue : UTF8Char;
  ufvalue,
  tmpvalue  : LDOUBLE;
  iconvert,
  fconvert,
  econvert  : array[0..19] of UTF8Char;
  iplace,
  fplace,
  eplace,
  padlen,
  zpadlen   : integer;
  exp       : long;
  intpart,
  fracpart,
  max10     : Cardinal;
  realstyle,
  tmpexp    : integer;
  s         : PUTF8Char;
  ech       : UTF8Char;
begin
    signvalue := #0;
    iplace := 0;
    fplace := 0;
    eplace := 0;
    padlen := 0;
    zpadlen := 0;
    exp := 0;
    if max < 0 then max := 6;
    if fvalue < 0 then
       signvalue := '-'
    else
    if (flags and DP_F_PLUS) > 0 then
        signvalue := '+'
    else
    if (flags and DP_F_SPACE) > 0 then
        signvalue := ' ';
    {
     * G_FORMAT sometimes prints like E_FORMAT and sometimes like F_FORMAT
     * depending on the number to be printed. Work out which one it is and use
     * that from here on.
     }
    if style = G_FORMAT then
    begin
        if fvalue = 0.0 then
        begin
            realstyle := F_FORMAT;
        end
        else
        if (fvalue < 0.0001) then
        begin
                  realstyle := E_FORMAT;
        end
        else
        if ( (max = 0) and  (fvalue >= 10))   or
           ( (max > 0) and  (fvalue >= pow_10(max)) ) then
        begin
           realstyle := E_FORMAT;
        end
        else
        begin
            realstyle := F_FORMAT;
        end;
    end
    else
    begin
        realstyle := style;
    end;
    if style <> F_FORMAT then
    begin
        tmpvalue := fvalue;
        { Calculate the exponent }
        if fvalue <> 0.0 then
        begin
            while tmpvalue < 1 do
            begin
                tmpvalue  := tmpvalue  * 10;
                Dec(exp);
            end;
            while tmpvalue > 10 do  begin
                tmpvalue  := tmpvalue  / 10;
                PostInc(exp);
            end;
        end;
        if style = G_FORMAT then
        begin
            {
             * In G_FORMAT the 'precision' represents significant digits. We
             * always have at least 1 significant digit.
             }
            if max = 0 then
                max := 1;
            { Now convert significant digits to decimal places }
            if realstyle = F_FORMAT then
            begin
                max  := max - ((exp + 1));
                if max < 0 then
                begin
                    {
                     * Should not happen. If we're in F_FORMAT then exp < max?
                     }
                    doapr_outch(sbuffer, buffer, currlen, maxlen, #0);
                    Exit(0);
                end;
            end
            else
            begin
                {
                 * In E_FORMAT there is always one significant digit in front
                 * of the decimal point, so:
                 * significant digits = 1 + decimal places
                 }
                Dec(max);
            end;
        end;
        if realstyle = E_FORMAT then
           fvalue := tmpvalue;
    end;
    ufvalue := abs_val(fvalue);
    {
     * By subtracting 65535 (2^16-1) we cancel the low order 15 bits
     * of ULONG_MAX to avoid using imprecise floating point values.
     }
    if ufvalue >= (ULONG_MAX - 65535) + 65536.0 then
    begin
        { Number too big }
        doapr_outch(sbuffer, buffer, currlen, maxlen, #0);
        Exit(0);
    end;
    intpart := Round(ufvalue);
    {
     * sorry, we only support 9 digits past the decimal because of our
     * conversion method
     }
    if max > 9 then max := 9;
    {
     * we 'cheat' by converting the fractional part to integer by multiplying
     * by a factor of 10
     }
    max10 := roundv(pow_10(max));
    fracpart := roundv(pow_10(max) * (ufvalue - intpart));
    if fracpart >= max10 then
    begin
        Inc(intpart);
        fracpart  := fracpart - max10;
    end;
    { convert integer part }
    repeat
        iconvert[iplace] := PUTF8Char('0123456789')[intpart mod 10];
        intpart := (intpart div 10);
        Inc(iplace);
    until (intpart <=0)  and  (iplace >= int(sizeof(iconvert)));
    if iplace = sizeof(iconvert) then
       Dec(iplace);
    iconvert[iplace] := Chr(0);
    { convert fractional part }
    while fplace < max do
    begin
        if (style = G_FORMAT)  and  (fplace = 0)  and  ( (fracpart mod 10) = 0) then
        begin
            { We strip trailing zeros in G_FORMAT }
            Dec(max);
            fracpart := fracpart div 10;
            if fplace < max then
               continue;
            break;
        end;
        fconvert[fplace] := PUTF8Char('0123456789')[fracpart mod 10];
        fracpart := (fracpart div 10);
        Inc(fplace);
    end;
    if fplace = sizeof(fconvert)  then
       Dec(fplace);
    fconvert[fplace] := Chr(0);
    { convert exponent part }
    if realstyle = E_FORMAT then
    begin
        if exp < 0 then
            tmpexp := -exp
        else
            tmpexp := exp;
        repeat
            econvert[eplace] := PUTF8Char('0123456789')[tmpexp mod 10];
            tmpexp := (tmpexp div 10);
            Inc(eplace);
        until (tmpexp <= 0)  and  (eplace >= int(sizeof(econvert)));
        { Exponent is huge!! Too big to print }
        if tmpexp > 0 then
        begin
            doapr_outch(sbuffer, buffer, currlen, maxlen, #0);
            Exit(0);
        end;
        { Add a leading 0 for single digit exponents }
        if eplace = 1 then
        begin
           econvert[eplace] := '0';
           Inc(eplace);
        end;
    end;
    {
     * -1 for decimal point (if we have one, i.e. max > 0),
     * another -1 if we are printing a sign
     }
    padlen := min - iplace - max - get_result(max > 0 , 1 , 0) -
              get_result((signvalue <> #0) , 1 , 0);
    { Take some off for exponent prefix '+e' and exponent }
    if realstyle = E_FORMAT then padlen  := padlen - (2 + eplace);
    zpadlen := max - fplace;
    if zpadlen < 0 then zpadlen := 0;
    if padlen < 0 then padlen := 0;
    if (flags and DP_F_MINUS)>0 then
       padlen := -padlen;
    if ( (flags and DP_F_ZERO)>0)  and  (padlen > 0) then
    begin
        if Ord(signvalue)>0 then
        begin
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue) then
                Exit(0);
            Dec(padlen);
            signvalue := Chr(0);
        end;
        while padlen > 0 do
        begin
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, '0') then
                Exit(0);
            Dec(padlen);
        end;
    end;
    while padlen > 0 do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, ' ')then
            Exit(0);
        Dec(padlen);
    end;
    if (Ord(signvalue)>0)  and
       (0>= doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue)  ) then
        Exit(0);
    while iplace > 0 do
    begin
        Dec(iplace);
        if  0>=doapr_outch(sbuffer, buffer, currlen, maxlen, iconvert[iplace]) then
            Exit(0);


    end;
    {
     * Decimal point. This should probably use locale to find the correct
     * char to print out.
     }
    if (max > 0)  or  ( (flags and DP_F_NUM )>0 ) then
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, '.' ) then
            Exit(0);
        while fplace > 0 do
        begin
            Dec(fplace);
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen,
                            fconvert[fplace] )  then
                Exit(0);
        end;
    end;
    while zpadlen > 0 do  begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, '0' ) then
            Exit(0);
        Dec(zpadlen);
    end;
    if realstyle = E_FORMAT then
    begin
        if (flags and DP_F_UP) = 0 then
            ech := 'e'
        else
            ech := 'E';
        if  0>=doapr_outch(sbuffer, buffer, currlen, maxlen, ech )  then
                Exit(0);
        if exp < 0 then
        begin
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, '-') then
                    Exit(0);
        end
        else
        begin
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, '+' ) then
                    Exit(0);
        end;
        while eplace > 0 do
        begin
            Dec(eplace);
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen,
                           econvert[eplace])  then
                Exit(0);
        end;
    end;
    while padlen < 0 do
    begin
        if  0>=doapr_outch(sbuffer, buffer, currlen, maxlen, ' ' ) then
            Exit(0);
        Inc(padlen);
    end;
    Result := 1;
end;

function fmtint(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t; value : int64; base, _min, _max, flags : integer):integer;
const
    DECIMAL_SIZE =     ((sizeof(value)*8+2)div 3+1) ;
var
    signvalue : UTF8Char;
    prefix    : PUTF8Char;
    uvalue    : uint64;
    convert   : array[0..(DECIMAL_SIZE + 3)-1] of UTF8Char;
    s         : PUTF8Char;
    place,
    spadlen,
    zpadlen,
    caps      : integer;
begin
    signvalue := UTF8Char(0);
    prefix := '';
    place := 0;
    spadlen := 0;
    zpadlen := 0;
    caps := 0;
    if _max < 0 then _max := 0;
    uvalue := value;
    if  0>= (flags and DP_F_UNSIGNED ) then
    begin
        if value < 0 then
        begin
            signvalue := '-';
            uvalue := 0 - uint64_t(value);
        end
        else
        if (flags and DP_F_PLUS)>0 then
            signvalue := '+'
        else
        if (flags and DP_F_SPACE) > 0 then
            signvalue := ' ';
    end;
    if (flags and DP_F_NUM)>0 then
    begin
        if base = 8 then
           prefix := '0';
        if base = 16 then
           prefix := '$';
    end;
    if (flags and DP_F_UP) > 0 then
       caps := 1;


    while  (uvalue > 0 )  and  (place < sizeof(convert)) do
    begin
        if caps > 0 then
           s :=  '0123456789ABCDEF'
        else
           s :=  '0123456789abcdef';
        convert[PostInc(place)] := s[uvalue mod unsigned(base)];
        uvalue := (uvalue div unsigned(base));
    end;

    if place = sizeof(convert) then
       Dec(place);
    convert[place] := #0;
    zpadlen := _max - place;
    spadlen := _min - MAX(_max, place) - get_result(signvalue<>#0 , 1 , 0) - Length(prefix);
    if zpadlen < 0 then zpadlen := 0;
    if spadlen < 0 then spadlen := 0;
    if (flags and DP_F_ZERO)>0 then
    begin
        zpadlen := MAX(zpadlen, spadlen);
        spadlen := 0;
    end;
    if (flags and DP_F_MINUS)>0 then
       spadlen := -spadlen;
    { spaces }
    while spadlen > 0 do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, ' ') then
            Exit(0);
        Dec(spadlen);
    end;
    { sign }
    if signvalue <> #0 then
       if ( 0>= doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue)) then
            Exit(0);
    { prefix }
    while prefix^ <> #0 do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, prefix^) then
            Exit(0);
        Inc(prefix);
    end;
    { zeros }
    if zpadlen > 0 then
    begin
        while zpadlen > 0 do
        begin
            if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, '0') then
                Exit(0);
            Dec(zpadlen);
        end;
    end;
    { digits }
    while place > 0 do
    begin
        Dec(place);
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, convert[place])  then
            Exit(0);
    end;
    { left justified spaces }
    while spadlen < 0 do
    begin
        if  0>= doapr_outch(sbuffer, buffer, currlen, maxlen, ' ' ) then
            Exit(0);
        Inc(spadlen);
    end;
    Result := 1;
end;

function doapr_outch(sbuffer, buffer : PPUTF8Char; currlen, maxlen : Psize_t; c : UTF8Char):integer;
var
  tmpbuf : PUTF8Char;
  idx: size_t;
begin
    { If we haven't at least one buffer, someone has done a big booboo }
    if  not ossl_assert( (sbuffer^ <> nil)   or  (buffer <> nil) ) then
        Exit(0);
    { |currlen| must always be <= |*maxlen| }
    if  not ossl_assert( currlen^ <= maxlen^) then
        Exit(0);
    if (nil <> buffer)  and  (currlen^ <= maxlen^) then
    begin
        if maxlen^ > INT_MAX - BUFFER_INC then
            Exit(0);
        maxlen^  := maxlen^ + BUFFER_INC;
        if buffer^ = nil then
        begin
            buffer^ := OPENSSL_malloc( maxlen^);
            if  buffer^ = nil then
            begin
                ERR_raise(ERR_LIB_BIO, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            if currlen^ > 0 then
            begin
                if  not ossl_assert(sbuffer^ <> nil) then
                    Exit(0);
                memcpy(buffer^, sbuffer^, currlen^);
            end;
            sbuffer^ := nil;
        end
        else
        begin
            tmpbuf := OPENSSL_realloc(buffer^, maxlen^);
            if buffer = nil then
            begin
                ERR_raise(ERR_LIB_BIO, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            buffer^ := tmpbuf;
        end;
    end;
    if currlen^ < maxlen^ then
    begin
        if nil <> sbuffer^ then
           sbuffer^[PostInc(currlen^)] := c
        else
           buffer^[PostInc(currlen^)] := c;
    end;
    Result := 1;
end;

function _dopr(sbuffer, buffer : PPUTF8Char; maxlen, retlen : Psize_t; truncated : Pinteger; _format : PUTF8Char; args : array of const):integer;
var
    ch       : UTF8Char;
    value    : int64;
    strvalue : PUTF8Char;
    _min,  base,
    _max,
    state,
    flags,
    cflags,n  : integer;
    currlen  : size_t;
    num      : Pinteger;
    ptr_int      : PInteger;
    num_int     : array[0..0] of Integer;
    num_u32    : array[0..0] of UInt32;
    ptr_u32      : PUInt32;
{$IFNDEF OPENSSL_SYS_UEFI}
    fvalue   : LDOUBLE;
{$ENDIF}
begin

    state := DP_S_DEFAULT;
    flags := 0;currlen := 0; cflags := 0; _min := 0;
    _max := -1;
    ch := _format^;
    Inc(_format);
    while state <> DP_S_DONE do
    begin
      if (ch = #0)  or  ( (buffer = nil)  and  (currlen >= maxlen^) ) then
          state := DP_S_DONE;
      case state of
        DP_S_DEFAULT:
        begin

            if ch = '%' then
               state := DP_S_FLAGS
            else
                if  0>= doapr_outch(sbuffer, buffer, @currlen, maxlen, ch) then
                    Exit(0);
            ch := _format^;
            Inc(_format);
        end;
        DP_S_FLAGS:
        begin
            case ch of
              '-':
              begin
                  flags  := flags  or DP_F_MINUS;
                  ch := (_format^);
                  inc(_format);
              end;
              '+':
              begin
                  flags  := flags  or DP_F_PLUS;
                  ch := (_format^);
                  inc(_format);
              end;
              ' ':
              begin
                  flags  := flags  or DP_F_SPACE;
                  ch := (_format^);
                  inc(_format);
              end;
              '#':
              begin
                  flags  := flags  or DP_F_NUM;
                  ch := (_format^);
                  inc(_format);
              end;
              '0':
              begin
                  flags  := flags  or DP_F_ZERO;
                  ch := (_format^);
                  inc(_format);
              end;
              else
                  state := DP_S_MIN;

            end;
        end;
        DP_S_MIN:
        begin
            if ossl_isdigit(ch)  then
            begin
                _min := 10 * _min + char_to_int(ch);
                ch := (_format^);
                inc(_format);
            end
            else
            if (ch = '*') then
            begin

                _min := Pinteger(va_arg(args, TypeInfo(integer)))^;
                ch := (_format^);
                inc(_format);
                state := DP_S_DOT;
            end
            else
                state := DP_S_DOT;
        end;
        DP_S_DOT:
        begin
            if ch = '.' then
            begin
                state := DP_S_MAX;
                ch := (_format^);
                inc(_format);
            end
            else
                state := DP_S_MOD;
        end;
        DP_S_MAX:
        begin
            if ossl_isdigit(ch) then
            begin
                if _max < 0 then
                    _max := 0;
                _max := 10 * _max + Ord(ch);
                ch := (_format^);
                inc(_format);
            end
            else
            if (ch = '*') then
            begin
                _max := Pinteger(va_arg(args, TypeInfo(integer)))^;
                ch := (_format^);
                inc(_format);
                state := DP_S_MOD;
            end
            else
                state := DP_S_MOD;
        end;
        DP_S_MOD:
        begin
          case ch of
            'h':
            begin
                cflags := DP_C_SHORT;
                ch := (_format^);
                inc(_format);
            end;
            'l':
            begin
                if _format^ = 'l' then
                begin
                    cflags := DP_C_LLONG;
                    Inc(_format);
                end
                else
                    cflags := DP_C_LONG;
                ch := (_format^);
                inc(_format);
            end;
            'q',
            'j':
            begin
                cflags := DP_C_LLONG;
                ch := (_format^);
                inc(_format);
            end;
            'L':
            begin
                cflags := DP_C_LDOUBLE;
                ch := (_format^);
                inc(_format);
            end;
            'z':
            begin
                cflags := DP_C_SIZE;
                ch := (_format^);
                inc(_format);
            end;
            else
            begin
              //
            end;  ;
          end;
          state := DP_S_CONV;
        end;
        DP_S_CONV:
        begin
            case ch of
                'd',
                'i':
                begin
                    case cflags of
                      DP_C_SHORT:
                          value := PShortInt(va_arg(args, TypeInfo(integer)))^;
                          //break;
                      DP_C_LONG:
                          value := PLong(va_arg(args, TypeInfo(longint)))^;
                          //break;
                      DP_C_LLONG:
                          value := Pint64(va_arg(args, TypeInfo(int64)))^;
                          //break;
                      DP_C_SIZE:
                          value := Possl_ssize_t(va_arg(args, TypeInfo(ossl_ssize_t)))^;
                          //break;
                      else
                      begin
                          ptr_int := @num_int;
                          ptr_int := PInteger(va_arg(args, TypeInfo(integer)));
                          value := ptr_int^;

                      end;
                          //break;
                    end;
                    if  0>= fmtint(sbuffer, buffer, @currlen, maxlen, value, 10, _min,
                                _max, flags) then
                        Exit(0);
                end;
                'X':
                    flags  := flags  or DP_F_UP;
                    { FALLTHROUGH }
                'x',
                'o',
                'u':
                begin
                    flags  := flags  or DP_F_UNSIGNED;
                    case cflags of
                     DP_C_SHORT:
                          value := PUint16(va_arg(args, TypeInfo(uint)))^;

                      DP_C_LONG:
                      begin
                          //怪哉！！！fpc下运行了本句，maxlen从8突变为2
                          ptr_u32 := va_arg(args, TypeInfo(ulongint));
                          value := ptr_u32^;
                      end;

                      DP_C_LLONG:
                          value := PUInt64(va_arg(args, TypeInfo(uint64)))^;

                      DP_C_SIZE:
                          value := Psize_t(va_arg(args, TypeInfo(size_t)))^;

                      else
                      begin
                          ptr_u32 := @num_u32;
                          ptr_u32 := PUInt32(va_arg(args, TypeInfo(integer)));
                          value := ptr_u32^;
                      end;

                    end;
                    base := get_result(ch = 'o' , 8 , get_result(ch = 'u' , 10 , 16) );
                    if  0>= fmtint(sbuffer, buffer, @currlen, maxlen, value,
                                   base, _min, _max, flags) then
                        Exit(0);
                end;
    {$IFNDEF OPENSSL_SYS_UEFI}
                'f':
                begin
                    if cflags = DP_C_LDOUBLE then
                       fvalue := PDouble(va_arg(args, TypeInfo(LDOUBLE)))^
                    else
                        fvalue := PDouble(va_arg(args, TypeInfo(double)))^;
                    if  0>= fmtfp(sbuffer, buffer, @currlen, maxlen, fvalue, _min, _max,
                               flags, F_FORMAT) then
                        Exit(0);
                end;
                'E':
                    flags  := flags  or DP_F_UP;
                    { fall thru }
                'e':
                begin
                    if cflags = DP_C_LDOUBLE then
                       fvalue := PDouble(va_arg(args, TypeInfo(LDOUBLE)))^
                    else
                        fvalue := PDouble(va_arg(args, TypeInfo(double)))^;
                    if  0>= fmtfp(sbuffer, buffer, @currlen, maxlen, fvalue, _min, _max,
                               flags, E_FORMAT ) then
                        Exit(0);
                end;
                'G':
                    flags  := flags  or DP_F_UP;
                    { fall thru }
                'g':
                begin
                    if cflags = DP_C_LDOUBLE then
                       fvalue := PDouble(va_arg(args, TypeInfo(LDOUBLE)))^
                    else
                        fvalue := PDouble(va_arg(args, TypeInfo(DOUBLE)))^;
                    if  0>= fmtfp(sbuffer, buffer, @currlen, maxlen, fvalue, _min, _max,
                               flags, G_FORMAT ) then
                        Exit(0);
                end;
    {$ELSE }    'f',
                'E',
                'e',
                'G',
                'g':
                begin    { not implemented for UEFI }
                    ERR_raise(ERR_LIB_BIO, ERR_R_UNSUPPORTED);
                    Exit(0);
                end;
    {$ENDIF}
                'c':
                begin
                    if  0>= doapr_outch(sbuffer, buffer, @currlen, maxlen,
                                    PAnsiChar( va_arg(args, TypeInfo(UTF8Char)))^ ) then
                        Exit(0);
                end;
                's':
                begin
                    strvalue := PUTF8Char(va_arg(args, TypeInfo(PUTF8Char )));
                    if _max < 0 then
                    begin
                        if Assigned(buffer) then
                            _max := INT_MAX
                        else
                            _max := maxlen^;
                    end;
                    if  0>= fmtstr(sbuffer, buffer, @currlen, maxlen, get_result(strvalue = '', #0, strvalue),
                                flags, _min, _max )  then
                        Exit(0);
                end;
                'p':
                begin
                    value := size_t(va_arg(args, TypeInfo(Pointer)));
                    if  0>= fmtint(sbuffer, buffer, @currlen, maxlen,
                                value, 16, _min, _max, flags or DP_F_NUM )then
                        Exit(0);
                end;
                'n':
                begin
                    num := Pinteger(va_arg(args, TypeInfo(Pinteger)));
                    num^ := currlen;
                end;

                '%':
                    if  0>= doapr_outch(sbuffer, buffer, @currlen, maxlen, ch) then
                        Exit(0);

                'w':
                    { not supported yet, treat as next PUTF8Char }
                    Inc(_format);

                else
                { unknown, skip }
                begin
                  //
                end;
            end;
            ch := _format^;
            Inc(_format);
            state := DP_S_DEFAULT;
            flags := 0; cflags := 0; _min := 0;
            _max := -1;
        end;
        DP_S_DONE:
        begin
          //
        end;
        else
        begin
          //
        end;
      end;
    end;
    {
     * We have to truncate if there is no dynamic buffer and we have filled the
     * static buffer.
     }
    if buffer = nil then
    begin
        truncated^ := int(currlen > maxlen^ - 1);
        if truncated^>0 then
           currlen := maxlen^ - 1;
    end;
    if  0>= doapr_outch(sbuffer, buffer, @currlen, maxlen, #0) then
        Exit(0);
    retlen^ := currlen - 1;
    Result := 1;
end;


function BIO_vprintf( bio : PBIO; const _format : PUTF8Char; args: array of const):integer;
var
    ret         : integer;
    retlen      : size_t;
    hugebuf     : array[0..(1024*2)-1] of UTF8Char;
    hugebufp    : PUTF8Char;
    hugebufsize : size_t;
    dynbuf      : PUTF8Char;
    ignored     : integer;
begin
    FillChar(hugebuf, SizeOf(hugebuf), 0);
    hugebufp := @hugebuf;
    hugebufsize := sizeof(hugebuf);
    dynbuf := nil;

    if  0>= _dopr(@hugebufp, @dynbuf, @hugebufsize, @retlen, @ignored, _format, args ) then
    begin
        OPENSSL_free(dynbuf);
        Exit(-1);
    end;
    if dynbuf <> nil then
    begin
        ret := BIO_write(bio, dynbuf, int(retlen));
        OPENSSL_free(dynbuf);
    end
    else
    begin
        ret := BIO_write(bio, @hugebuf, int(retlen));
    end;
    Result := ret;
end;


function BIO_printf(bio: PBIO; const _format : PUTF8Char; args: array of const): Integer;
var
  ret : integer;
begin
    ret := BIO_vprintf(bio, _format, args);
    Result := ret;
end;


end.
