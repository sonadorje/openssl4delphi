unit openssl3.crypto.o_time;

interface
uses {$if defined(MSWINDOWS)}libc.win, {$ENDIF}
      OpenSSL.Api;

const
   SECS_PER_DAY = (24 * 60 * 60);

function OPENSSL_gmtime(const timer : Ptime_t; result1 : Ptm):Ptm;
function OPENSSL_gmtime_adj( tm : Ptm; off_day : integer; offset_sec : long):integer;
function julian_adj(const tm : Ptm; off_day : integer; offset_sec : long; pday : Plong; psec : PInteger):integer;
function date_to_julian( y, m, d : integer):long;
procedure julian_to_date( jd : long; y, m, d : PInteger);

function OPENSSL_gmtime_diff(pday, psec : PInteger;const from, _to : Ptm):integer;

implementation


function OPENSSL_gmtime_diff(pday, psec : PInteger;const from, _to : Ptm):integer;
var
  from_sec,
  to_sec,
  diff_sec : integer;
  from_jd,
  to_jd,
  diff_day : long;
begin
    if 0>= julian_adj(from, 0, 0, @from_jd, @from_sec) then
        Exit(0);
    if 0>= julian_adj(_to, 0, 0, @to_jd, @to_sec ) then
        Exit(0);
    diff_day := to_jd - from_jd;
    diff_sec := to_sec - from_sec;
    { Adjust differences so both positive or both negative }
    if (diff_day > 0)  and  (diff_sec < 0) then
    begin
        Dec(diff_day);
        diff_sec  := diff_sec + SECS_PER_DAY;
    end;
    if (diff_day < 0)  and  (diff_sec > 0) then
    begin
        Inc(diff_day);
        diff_sec  := diff_sec - SECS_PER_DAY;
    end;
    if pday <> nil then
       pday^ := int(diff_day);
    if (psec <> nil) then
       psec^ := diff_sec;
    Exit(1);
end;


procedure julian_to_date( jd : long; y, m, d : PInteger);
var
  L, n, i, j : long;
begin
    L := jd + 68569;
    n := (4 * L) div 146097;
    L := L - (146097 * n + 3) div 4;
    i := (4000 * (L + 1)) div 1461001;
    L := L - (1461 * i) div 4 + 31;
    j := (80 * L) div 2447;
    d^ := L - (2447 * j) div 80;
    L := j div 11;
    m^ := j + 2 - (12 * L);
    y^ := 100 * (n - 49) + i + L;
end;


function date_to_julian( y, m, d : integer):long;
begin
   Result := (1461 * (y + 4800 + (m - 14) div 12)) div 4 +
              (367 * (m - 2 - 12 * ((m - 14) div 12))) div 12 -
              (3 * ((y + 4900 + (m - 14) div 12) div 100)) div 4 + d - 32075;
end;



function julian_adj(const tm : Ptm; off_day : integer; offset_sec : long; pday : Plong; psec : PInteger):integer;
var
  offset_hms : integer;
  offset_day,
  time_jd    : long;
  time_year,
  time_month,
  time_day   : integer;
begin
    { split offset into days and day seconds }
    offset_day := offset_sec div SECS_PER_DAY;
    { Avoid sign issues with % operator }
    offset_hms := offset_sec - (offset_day * SECS_PER_DAY);
    offset_day  := offset_day + off_day;
    { Add current time seconds to offset }
    offset_hms  := offset_hms + (tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec);
    { Adjust day seconds if overflow }
    if offset_hms >= SECS_PER_DAY then
    begin
        Inc(offset_day);
        offset_hms  := offset_hms - SECS_PER_DAY;
    end
    else
    if (offset_hms < 0) then
    begin
        Dec(offset_day);
        offset_hms  := offset_hms + SECS_PER_DAY;
    end;
    {
     * Convert date of time structure into a Julian day number.
     }
    time_year := tm.tm_year + 1900;
    time_month := tm.tm_mon + 1;
    time_day := tm.tm_mday;
    time_jd := date_to_julian(time_year, time_month, time_day);
    { Work out Julian day of new date }
    time_jd  := time_jd + offset_day;
    if time_jd < 0 then
       Exit(0);
    pday^ := time_jd;
    psec^ := offset_hms;
    Result := 1;
end;

function OPENSSL_gmtime_adj( tm : Ptm; off_day : integer; offset_sec : long):integer;
var
  time_sec,
  time_year,
  time_month,
  time_day   : integer;
  time_jd    : long;
begin
    { Convert time and offset into Julian day and seconds }
    if 0>= julian_adj(tm, off_day, offset_sec, @time_jd, @time_sec) then
        Exit(0);
    { Convert Julian day back to date }
    julian_to_date(time_jd, @time_year, @time_month, @time_day);
    if (time_year < 1900)  or  (time_year > 9999) then
       Exit(0);
    { Update tm structure }
    tm.tm_year := time_year - 1900;
    tm.tm_mon  := time_month - 1;
    tm.tm_mday := time_day;
    tm.tm_hour := time_sec div 3600;
    tm.tm_min  := (time_sec div 60) mod 60;
    tm.tm_sec  := time_sec mod 60;
    Exit(1);
end;


function OPENSSL_gmtime(const timer : Ptime_t; result1 : Ptm):Ptm;
var
  ts : Ptm;
  data: Ttm;
  ts2: Ptm;
begin
    ts := nil;
{$IF defined(OPENSSL_THREADS)  and  defined(OPENSSL_SYS_VMS)}
    begin
        {
         * On VMS, gmtime_r() takes a 32-bit pointer as second argument.
         * Since we can't know that |result1| is in a space that can easily
         * translate to a 32-bit pointer, we must store temporarily on stack
         * and copy the result1.  The stack is always reachable with 32-bit
         * pointers.
         }
{$IF defined(OPENSSL_SYS_VMS)  and  (__INITIAL_POINTER_SIZE > 0)}
# pragma pointer_size save
# pragma pointer_size 32
{$ENDIF}
        ts2 := @data;
{$IF defined(OPENSSL_SYS_VMS)  and  (__INITIAL_POINTER_SIZE > 0)}
# pragma pointer_size restore
{$ENDIF}
        if gmtime_r(timer, ts2) = nil  then
            Exit(nil);
        memcpy(result1, ts2, sizeof(struct tm));
        ts := result1;
    end;
{$elseif defined(OPENSSL_THREADS)  and  not defined(OPENSSL_SYS_WIN32)  and  not defined(OPENSSL_SYS_MACOSX)}
    if gmtime_r(timer, result1) = nil  then
        Exit(nil);
    ts := result1;
{$elseif defined(OPENSSL_SYS_WINDOWS)  and  not defined(_WIN32_WCE)}
    if gmtime_s(result1, timer) >0 then
        Exit(nil);
    ts := result1;
{$ELSE}
    ts := gmtime(timer);
    if ts = nil then
       Exit(nil);
    memcpy(result1, ts, sizeof(Ttm));
    FreeMem(ts);
    ts := result1;
{$ENDIF}
    Exit(ts);
end;


end.
