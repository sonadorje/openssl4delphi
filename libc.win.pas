unit libc.win;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, DateUtils, SysUtils,
     {$IFNDEF FPC} Windows,
     {$ELSE} jwawindows,
     {$ENDIF}      Types;

type

  _dev_t = UInt32;
  _ino_t = UInt16;
  _off_t = Long;
  Tstat = record
      st_dev     : _dev_t;
      st_ino     : _ino_t;
      st_mode    : uint16;
      st_nlink,
      st_uid,
      st_gid     : Int16;
      st_rdev    : _dev_t;
      st_size    : _off_t;
      st_atime,
      st_mtime,
      st_ctime   : time_t;
  end;

  Pstat = ^Tstat;
  TCDeclProcedure = procedure; cdecl;
  _onexit_t = function:integer;
  TQSortFunc = function (const _para1, _para2:pointer):longint; //cdecl;
const
  _O_TEXT  =      $4000;
  _O_BINARY =     $8000;  // file mode is binary (untranslated)
  _IOFBF = $0000;
  _IOLBF = $0040;
  _IONBF = $0004;
  libc_nlm = 'msvcrt.dll';
  kernel32 = 'kernel32.dll';


  //procedure qsort(_para1:pointer; _para2: int; _para3:size_t; _para4:TQSortFunc);cdecl;external libc_nlm name 'qsort';
  function _errno:Plongint;cdecl;external libc_nlm name '_errno';
  function fputs(__restrict:PAnsiChar; __restrict1:PFILE):longint;cdecl;external libc_nlm name 'fputs';
  function fputc(_para1:longint; _para2:PFILE):longint;cdecl;external libc_nlm name 'fputc';
  function fopen(const filename, mode: PAnsiChar): PFILE; cdecl; external libc_nlm name 'fopen';
  function fclose(_para1:PFILE):longint;cdecl;external libc_nlm name 'fclose';
  function _wfopen(const  _FileName, _Mode: PAnsiChar): PFile; cdecl; external libc_nlm name '_wfopen';
  function fread(__restrict:pointer; _para2:size_t; _para3:size_t; __restrict1:PFILE):size_t;cdecl;external libc_nlm name 'fread';
  function ferror(_para1:PFILE):longint;cdecl;external libc_nlm name 'ferror';
  function ftell(_para1:PFILE):longint;cdecl;external libc_nlm name 'ftell';
  function fseek(fp:PFILE; offset:longint; whence:longint):longint;cdecl;external libc_nlm name 'fseek';
  function _feof(_para1:PFILE):longint;cdecl;external libc_nlm name 'feof';
  function fwrite(__restrict:pointer; _para2:size_t; _para3:size_t; __restrict1:PFILE):size_t;cdecl;external libc_nlm name 'fwrite';
  function getc(_para1:PFILE):longint;cdecl;external libc_nlm name 'getc';
  function _fileno(_para1:PFILE):longint;cdecl;external 'ucrtbased.dll' name '_fileno';
  function memmove(_para1, _para2:pointer; _para3:size_t):pointer;cdecl;external libc_nlm name 'memmove';
  function setvbuf(stream: PFILE; buf: PAnsiChar; mode: Integer; size: size_t): Integer;cdecl;external libc_nlm name 'setvbuf';
  function fflush(_para1:PFILE):longint;cdecl;external libc_nlm name 'fflush';
  function fgets(_para1:PAnsiChar; _para2:longint; _para3:PFILE):PAnsiChar;cdecl;external libc_nlm name 'fgets';
  function _setmode(_FileHandle, _Mode: integer): integer;cdecl;external libc_nlm name '_setmode';
  //function gmtime_s(const _Tm: Ptm; const _Time: Ptime_t): Int; cdecl;external 'ucrtbased.dll' name 'gmtime_s';
  function fprintf(__restrict:PFILE; __restrict1:PAnsiChar):longint;cdecl;external libc_nlm name 'fprintf';
  function getenv(_para1:PAnsiChar):PUTF8Char;cdecl;external libc_nlm name 'getenv';
  function stat(path:PAnsiChar; buf:Pstat):longint;cdecl;external 'ucrtbased.dll' name '_stat64i32';
  function _lrotr(_para1:dword; _para2:dword):dword;cdecl;external libc_nlm name '_lrotr';
  function atexit(_para1:TCDeclProcedure ):longint;cdecl;external libc_nlm name 'atexit';
  function wcslen(_para1:PWChar):size_t;cdecl;external libc_nlm name 'wcslen';
  function wcscpy(__restrict:Pwchar; __restrict1:Pwchar):Pwchar;cdecl;external libc_nlm name 'wcscpy';
  function _onexit(_Func: _onexit_t): _onexit_t; cdecl;external libc_nlm name '_onexit';
  function strerror_s(_Buffer:PAnsiChar; _SizeInBytes: size_t; _ErrorNumber: int):longint;cdecl;external libc_nlm name 'strerror_s';
  function GetModuleHandleExW(dwFlags: DWORD; lpModuleName: LPCWSTR; var phModule: HMODULE): BOOL; cdecl; external kernel32 name 'GetModuleHandleExW';
  function gmtime(timer: Ptime_t): Ptm;


implementation



var
   gTimebuf: Ttm;
const TM_YEAR_BASE =  1900;
      DAYSPERLYEAR =  366;
      DAYSPERNYEAR =  365;
      DAYSPERWEEK  =  7;
      EPOCH_YR     =  1970;
      TIME_MAX     =  2147483647;
      SECS_DAY     = 24 * 60 * 60;

const
  _days:  array[0..6] of Pchar = ('Sunday', 'Monday', 'Tuesday', 'Wednesday',
  'Thursday', 'Friday', 'Saturday');

 _days_abbrev: array[0..6] of Pchar = (
  'Sun', 'Mon', 'Tue', 'Wed',
  'Thu', 'Fri', 'Sat'
);

 _months: array[0..11] of Pchar = (
  'January', 'February', 'March',
  'April', 'May', 'June',
  'July', 'August', 'September',
  'October', 'November', 'December'
);

 _months_abbrev: array[0..11] of PAnsichar = (
  'Jan', 'Feb', 'Mar',
  'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec'
);

 _ytab: array[0..1, 0..11] of Integer = (
  (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31),
  (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
);

function LEAPYEAR(year: UInt16): UInt8;
begin
   if (year mod 4 = 0) and ((year mod 100 > 0) or (year mod 400 = 0)) then
      Result := 1
   else
     Result := 0;
end;

function YEARSIZE(year: UInt16): Integer;
begin
   if LEAPYEAR(year) > 0 then
      Result := 366
   else
      Result := 365;
end;

function gmtime_r(const timer : Ptime_t; tmbuf: Ptm): Ptm;
var
  time     : time_t;
  dayclock,
  dayno    : uint32;
  year     : integer;
begin
  time := timer^;
  year := EPOCH_YR;
  dayclock := ulong(time mod SECS_DAY);
  dayno := ulong(time div SECS_DAY);
  tmbuf.tm_sec := dayclock mod 60;
  tmbuf.tm_min := (dayclock mod 3600) div 60;
  tmbuf.tm_hour := dayclock div 3600;
  tmbuf.tm_wday := (dayno + 4) mod 7; // Day 0 was a thursday
  while dayno >= ulong(YEARSIZE(year)) do
  begin
    dayno  := dayno - (YEARSIZE(year));
    Inc(year);
  end;
  tmbuf.tm_year := year - TM_YEAR_BASE;
  tmbuf.tm_yday := dayno;
  tmbuf.tm_mon := 0;
  while dayno >= ulong(_ytab[Integer(LEAPYEAR(year))][tmbuf.tm_mon]) do
  begin
    dayno  := dayno - (_ytab[Integer(LEAPYEAR(year))][tmbuf.tm_mon]);
    Inc(tmbuf.tm_mon);
  end;
  tmbuf.tm_mday := dayno + 1;
  tmbuf.tm_isdst := 0;
  tmbuf.__tm_gmtoff := 0;
  tmbuf.__tm_zone := 'UTC';
  Result := tmbuf;
end;

function gmtime(timer: Ptime_t): Ptm;
var
  tmbuf: Ptm;
begin
  tmbuf := AllocMem(SizeOf(Ttm));
  Result := gmtime_r(timer, tmbuf);
end;

initialization

end.
