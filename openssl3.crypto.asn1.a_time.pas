unit openssl3.crypto.asn1.a_time;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, DateUtils;

const
  _asn1_mon: array[0..12-1] of PUTF8Char= (
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
);

function ASN1_TIME_check(const t : PASN1_TIME):integer;
function ossl_asn1_time_to_tm(tm : Ptm;const d : PASN1_TIME):integer;
function ossl_asn1_time_from_tm( s : PASN1_TIME; ts : Ptm; _type : integer):PASN1_TIME;
function ASN1_TIME_print(bp : PBIO;const tm : PASN1_TIME):integer;
function ASN1_TIME_print_ex(bp : PBIO;const tm : PASN1_TIME; flags : Cardinal):integer;
 function ossl_asn1_time_print_ex(bp : PBIO;const tm : PASN1_TIME; flags : Cardinal):integer;
function is_utc(const year : integer):integer;
function leap_year(const year : integer):integer;
procedure determine_days( tm : Ptm);
 procedure ASN1_TIME_free( a : PASN1_TIME);
 function ASN1_TIME_it:PASN1_ITEM;
 function ASN1_TIME_compare(const a, b : PASN1_TIME):integer;
function ASN1_TIME_diff(pday, psec : PInteger;const from, _to : PASN1_TIME):integer;
function ASN1_TIME_to_tm(const s : PASN1_TIME; tm : Ptm):integer;
 function ASN1_TIME_adj( s : PASN1_TIME; t : time_t; offset_day : integer; offset_sec : long):PASN1_TIME;
function ASN1_TIME_set( s : PASN1_TIME; t : time_t):PASN1_TIME;

implementation
uses openssl3.crypto.asn1.a_gentm, openssl3.crypto.bio.bio_lib,
     openssl3.crypto.o_time,  openssl3.crypto.asn1.a_utctm,
     openssl3.crypto.asn1.tasn_fre, OpenSSL3.Err,
     openssl3.crypto.bio.bio_print, openssl3.crypto.asn1.asn1_lib;

function ASN1_TIME_set( s : PASN1_TIME; t : time_t):PASN1_TIME;
begin
    Result := ASN1_TIME_adj(s, t, 0, 0);
end;

function ASN1_TIME_adj( s : PASN1_TIME; t : time_t; offset_day : integer; offset_sec : long):PASN1_TIME;
var
  ts : Ptm;
  data : Ttm;
begin
    data := default(Ttm);
    ts := OPENSSL_gmtime(@t, @data);
    if ts = nil then begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ERROR_GETTING_TIME);
        Exit(nil);
    end;
    if (offset_day > 0) or  (offset_sec > 0) then begin
        if 0>=OPENSSL_gmtime_adj(ts, offset_day, offset_sec) then
            Exit(nil);
    end;
    Result := ossl_asn1_time_from_tm(s, ts, V_ASN1_UNDEF);
end;

function ASN1_TIME_to_tm(const s : PASN1_TIME; tm : Ptm):integer;
var
  now_t : time_t;
begin
    if s = nil then
    begin
        _time(@now_t);
        memset(tm, 0, sizeof( tm^));
        if OPENSSL_gmtime(@now_t, tm ) <> nil then
            Exit(1);
        Exit(0);
    end;
    Result := ossl_asn1_time_to_tm(tm, s);
end;

function ASN1_TIME_diff(pday, psec : PInteger;const from, _to : PASN1_TIME):integer;
var
  tm_from, tm_to : Ttm;
begin
    if 0>=ASN1_TIME_to_tm(from, @tm_from) then
        Exit(0);
    if 0>=ASN1_TIME_to_tm(_to, @tm_to) then
        Exit(0);
    Result := OPENSSL_gmtime_diff(pday, psec, @tm_from, @tm_to);
end;

function ASN1_TIME_compare(const a, b : PASN1_TIME):integer;
var
  day, sec : integer;
begin
    if 0>=ASN1_TIME_diff(@day, @sec, b, a) then
        Exit(-2);
    if (day > 0)  or  (sec > 0) then Exit(1);
    if (day < 0)  or  (sec < 0) then Exit(-1);
    Result := 0;
end;


function ASN1_TIME_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($5, $4000 or $8000,
               Pointer(0) , 0, Pointer(0) , sizeof(TASN1_STRING), 'ASN1_TIME');
    Result := @local_it;
end;

procedure ASN1_TIME_free( a : PASN1_TIME);
begin
  ASN1_item_free(PASN1_VALUE(a), ASN1_TIME_it);
end;


procedure determine_days( tm : Ptm);
const // 1d arrays
  ydays : array[0..11] of integer = (
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 );

var
  y, m, d, c : integer;
begin

    y := tm.tm_year + 1900;
    m := tm.tm_mon;
    d := tm.tm_mday;
    tm.tm_yday := ydays[m] + d - 1;
    if m >= 2 then
    begin
        { March and onwards can be one day further into the year }
        tm.tm_yday  := tm.tm_yday + (leap_year(y));
        m  := m + 2;
    end
    else
    begin
        { Treat January and February as part of the previous year }
        m  := m + 14;
        Dec(y);
    end;
    c := y div 100;
    y  := y mod 100;
    { Zeller's congruence }
    tm.tm_wday := (d + (13 * m) div 5 + y + y div 4 + c div 4 + 5 * c + 6) mod 7;
end;






function leap_year(const year : integer):integer;
begin
    if (year mod 400 = 0)  or ( (year mod 100 <> 0)  and  (year mod 4 = 0) ) then
        Exit(1);
    Result := 0;
end;



function is_utc(const year : integer):integer;
begin
    if (50 <= year)  and  (year <= 149) then
       Exit(1);
    Result := 0;
end;




function ossl_asn1_time_print_ex(bp : PBIO;const tm : PASN1_TIME; flags : Cardinal):integer;
var
  v : PUTF8Char;
  gmt, l : integer;
  stm : Ttm;
  upper_z, period : byte;
  f : PUTF8Char;
  f_len : integer;
begin
    gmt := 0;
    upper_z := $5A; period := $2E;
    { ossl_asn1_time_to_tm will check the time type }
    if 0>= ossl_asn1_time_to_tm(@stm, tm) then
        Exit(get_result(BIO_write(bp, PUTF8Char('Bad time value'), 14) >0, -1 , 0));
    l := tm.length;
    v := PUTF8Char(tm.data);
    if Ord(v[l - 1]) = upper_z then
       gmt := 1;
    if tm.&type = V_ASN1_GENERALIZEDTIME then
    begin
        f := nil;
        f_len := 0;
        {
         * Try to parse fractional seconds. '14' is the place of
         * 'fraction point' in a GeneralizedTime string.
         }
        if (tm.length > 15)  and  (Ord(v[14]) = period) then
        begin
            f := @v[14];
            f_len := 1;
            while (14 + f_len < l)  and  (ossl_ascii_isdigit(Ord(f[f_len]))>0) do
                PreInc(f_len);
        end;
        if (flags and ASN1_DTFLGS_TYPE_MASK) = ASN1_DTFLGS_ISO8601 then
        begin
            Exit(Int(BIO_printf(bp, '%4d-%02d-%02d %02d:%02d:%02d%.*s%s',
                          [stm.tm_year + 1900, stm.tm_mon + 1,
                          stm.tm_mday, stm.tm_hour,
                          stm.tm_min, stm.tm_sec, f_len, f,
                          get_result(gmt>0 , 'Z' , '')]) > 0));
        end
        else
        begin
            Exit(Int(BIO_printf(bp, '%s %2d %02d:%02d:%02d%.*s %d%s',
                          [_asn1_mon[stm.tm_mon], stm.tm_mday, stm.tm_hour,
                          stm.tm_min, stm.tm_sec, f_len, f, stm.tm_year + 1900,
                          get_result(gmt>0 , ' GMT' , '')]) > 0));
        end;
    end
    else
    begin
        if (flags and ASN1_DTFLGS_TYPE_MASK) = ASN1_DTFLGS_ISO8601 then
        begin
            Exit(Int(BIO_printf(bp, '%4d-%02d-%02d %02d:%02d:%02d%s',
                          [stm.tm_year + 1900, stm.tm_mon + 1,
                          stm.tm_mday, stm.tm_hour,
                          stm.tm_min, stm.tm_sec,
                          get_result(gmt>0 , 'Z' , '')]) > 0));
        end
        else
        begin
            Exit(Int(BIO_printf(bp, '%s %2d %02d:%02d:%02d %d%s',
                          [_asn1_mon[stm.tm_mon], stm.tm_mday, stm.tm_hour,
                          stm.tm_min, stm.tm_sec, stm.tm_year + 1900,
                          get_result(gmt>0 , ' GMT' , '')]) > 0));
        end;
    end;
end;




function ASN1_TIME_print_ex(bp : PBIO;const tm : PASN1_TIME; flags : Cardinal):integer;
begin
    Result := Int(ossl_asn1_time_print_ex(bp, tm, flags) > 0);
end;


function ASN1_TIME_print(bp : PBIO;const tm : PASN1_TIME):integer;
begin
    Result := ASN1_TIME_print_ex(bp, tm, ASN1_DTFLGS_RFC822);
end;



function ossl_asn1_time_from_tm( s : PASN1_TIME; ts : Ptm; _type : integer):PASN1_TIME;
var
  p : PUTF8Char;
  tmps : PASN1_TIME;
  len : size_t;
  label _err;
begin
    tmps := nil;
    len := 20;
    if _type = V_ASN1_UNDEF then
    begin
        if is_utc(ts.tm_year) > 0 then
            _type := V_ASN1_UTCTIME
        else
            _type := V_ASN1_GENERALIZEDTIME;
    end
    else
    if (_type = V_ASN1_UTCTIME) then
    begin
        if 0>= is_utc(ts.tm_year) then
            goto _err ;
    end
    else
    if (_type <> V_ASN1_GENERALIZEDTIME) then
    begin
        goto _err ;
    end;
    if s = nil then
       tmps := PASN1_TIME(ASN1_STRING_new)
    else
        tmps := s;
    if tmps = nil then
       Exit(nil);
    if 0>= ASN1_STRING_set(PASN1_STRING(tmps), nil, len ) then
        goto _err ;
    tmps.&type := _type;
    p := PUTF8Char(tmps.data);
    if _type = V_ASN1_GENERALIZEDTIME then
       tmps.length := BIO_snprintf(p, len, '%04d%02d%02d%02d%02d%02dZ',
                                    [ts.tm_year + 1900, ts.tm_mon + 1,
                                    ts.tm_mday, ts.tm_hour, ts.tm_min,
                                    ts.tm_sec])
    else
        tmps.length := BIO_snprintf(p, len, '%02d%02d%02d%02d%02d%02dZ',
                                   [ ts.tm_year mod 100, ts.tm_mon + 1,
                                    ts.tm_mday, ts.tm_hour, ts.tm_min,
                                    ts.tm_sec]);
{$IFDEF CHARSET_EBCDIC}
    ebcdic2ascii(tmps.data, tmps.data, tmps.length);
{$ENDIF}
    Exit(tmps);
 _err:
    if tmps <> s then
       ASN1_STRING_free(PASN1_STRING(tmps));
    Result := nil;
end;

function ossl_asn1_time_to_tm(tm : Ptm;const d : PASN1_TIME):integer;
const // 1d arrays
  min : array[0..8] of integer = (0, 0, 1, 1, 0, 0, 0, 0, 0 );
  max : array[0..8] of integer = (99, 99, 12, 31, 23, 59, 59, 12, 59 );
  mdays : array[0..11] of integer = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );
  {$IF defined(CHARSET_EBCDIC)}
  upper_z = $5A; num_zero = $30; period = $2E; minus = $2D; plus = $2B;
  {$ELSE}
  upper_z = 'Z'; num_zero = '0'; period = '.'; minus = '-'; plus = '+';
  {$endif}
var
  a : PUTF8Char;
  n, i, i2, l, o, md, min_l, _strict, _end, btz : integer;
  tmp : Ttm;
  offsign, offset : integer;
  label _err;

begin

    min_l := 11;
    _strict := 0;
    _end := 6;
    btz := 5;

    {
     * ASN1_STRING_FLAG_X509_TIME is used to enforce RFC 5280
     * time string format, in which:
     *
     * 1. 'seconds' is a 'MUST'
     * 2. 'Zulu' timezone is a 'MUST'
     * 3. '+|-' is not allowed to indicate a time zone
     }
    if d.&type = V_ASN1_UTCTIME then
    begin
        if (d.flags and ASN1_STRING_FLAG_X509_TIME) > 0 then
        begin
            min_l := 13;
            _strict := 1;
        end;
    end
    else
    if (d.&type = V_ASN1_GENERALIZEDTIME) then
    begin
        _end := 7;
        btz := 6;
        if (d.flags and ASN1_STRING_FLAG_X509_TIME) > 0 then
        begin
            min_l := 15;
            _strict := 1;
        end
        else
        begin
            min_l := 13;
        end;
    end
    else
    begin
        Exit(0);
    end;
    l := d.length;
    a := PUTF8Char(d.data);
    o := 0;
    memset(@tmp, 0, sizeof(tmp));
    {
     * GENERALIZEDTIME is similar to UTCTIME except the year is represented
     * as YYYY. This stuff treats everything as a two digit field so make
     * first two fields 00 to 99
     }
    if l < min_l then
       goto _err ;
    i := 0;
    while i <= _end-1 do
    begin
        if (0>= _strict)  and  (i = btz) and  ((a[o] = upper_z)  or  (a[o] = plus)  or  (a[o] = minus))  then
        begin
            Inc(i);
            break;
        end;
        if 0>= ossl_ascii_isdigit(Ord(a[o])) then
            goto _err ;
        n := Ord(a[o]) - Ord(num_zero);
        { incomplete 2-digital number }
        if PreInc(o) = l then
            goto _err ;
        if 0>= ossl_ascii_isdigit(Ord(a[o])) then
            goto _err ;
        n := (n * 10) + Ord(a[o]) - Ord(num_zero);
        { no more bytes to read, but we haven't seen time-zone yet }
        if PreInc(o ) = l then
            goto _err ;
        i2 := get_result(d.&type = V_ASN1_UTCTIME , i + 1 , i);
        if (n < min[i2])  or  (n > max[i2]) then
            goto _err ;
        case i2 of
            0:
                { UTC will never be here }
                tmp.tm_year := n * 100 - 1900;
                //break;
            1:
            begin
                if d.&type = V_ASN1_UTCTIME then
                   tmp.tm_year := get_result(n < 50 , n + 100 , n)
                else
                    tmp.tm_year  := tmp.tm_year + n;
            end;
            2:
                tmp.tm_mon := n - 1;
                //break;
            3:
            begin
                { check if tm_mday is valid in tm_mon }
                if tmp.tm_mon = 1 then
                begin
                    { it's February }
                    md := mdays[1] + leap_year(tmp.tm_year + 1900);
                end
                else
                begin
                    md := mdays[tmp.tm_mon];
                end;
                if n > md then
                   goto _err ;
                tmp.tm_mday := n;
                determine_days(@tmp);
            end;
            4:
                tmp.tm_hour := n;
                //break;
            5:
                tmp.tm_min := n;
                //break;
            6:
                tmp.tm_sec := n;
                //break;
        end;
        Inc(i);
    end;
    {
     * Optional fractional seconds: decimal point followed by one or more
     * digits.
     }
    if (d.&type = V_ASN1_GENERALIZEDTIME)  and  (a[o] = period) then
    begin
        if _strict>0 then
            { RFC 5280 forbids fractional seconds }
            goto _err ;
        if PreInc(o) = l  then
            goto _err ;
        i := o;
        while (o < l)  and  (ossl_ascii_isdigit(Ord(a[o])) > 0) do
            Inc(o);
        { Must have at least one digit after decimal poPInteger /
        if i = o then goto_err ;
        { no more bytes to read, but we haven't seen time-zone yet }
        if o = l then
           goto _err ;
    end;
    {
     * 'o' will never point to #0 at this point, the only chance
     * 'o' can point to #0 is either the subsequent if or the first
     * else if is true.
     }
    if a[o] = upper_z then
    begin
        Inc(o);
    end
    else
    if (0>= _strict)  and  ((a[o] = plus)  or  (a[o] = minus)) then
    begin
        a[o] := UTF8Char(get_result( Ord(minus) >0, 1 , -1));
        offsign := Ord(a[o]);
        offset := 0;
        Inc(o);
        {
         * if not equal, no need to do subsequent checks
         * since the following for-loop will add 'o' by 4
         * and the final return statement will check if 'l'
         * and 'o' are equal.
         }
        if o + 4 <> l then goto _err ;
        for i := _end to _end + 2-1 do
        begin
            if 0>= ossl_ascii_isdigit(Ord(a[o])) then
                goto _err ;
            n := Ord(a[o]) - Ord(num_zero);
            Inc(o);
            if 0>= ossl_ascii_isdigit(Ord(a[o])) then
                goto _err ;
            n := (n * 10) + Ord(a[o]) - Ord(num_zero);
            i2 := get_result(d.&type = V_ASN1_UTCTIME,  i + 1 , i);
            if (n < min[i2])  or  (n > max[i2]) then
                goto _err ;
            { if tm is nil, no need to adjust }
            if tm <> nil then
            begin
                if i = _end then
                    offset := n * 3600
                else
                if (i = _end + 1) then
                    offset  := offset + (n * 60);
            end;
            PostInc(o);
        end;
        if (offset>0)  and  (0>= OPENSSL_gmtime_adj(@tmp, 0, offset * offsign)) then
            goto _err ;
    end
    else
    begin
        { not Z, or not +/- in non-strict mode }
        goto _err ;
    end;
    if o = l then
    begin
        { success, check if tm should be filled }
        if tm <> nil then
           tm^ := tmp;
        Exit(1);
    end;

 _err:
    Result := 0;
end;

function ASN1_TIME_check(const t : PASN1_TIME):integer;
begin
    if t.&type = V_ASN1_GENERALIZEDTIME then
       Exit(ASN1_GENERALIZEDTIME_check(t))
    else
    if (t.&type = V_ASN1_UTCTIME) then
       Exit(ASN1_UTCTIME_check(t));
    Result := 0;
end;


end.
