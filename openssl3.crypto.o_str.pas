unit openssl3.crypto.o_str;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

const
  DEFAULT_SEPARATOR: UTF8Char = ':';
  CH_ZERO: UTF8Char = #0;
  _MSC_VER = 1930;

procedure CRYPTO_strndup(var Result: PUTF8Char; const str : PUTF8Char; sz : size_t);
procedure CRYPTO_strdup(var Result: PUTF8Char; const str: PUTF8Char);

procedure OPENSSL_strndup(var dest: PUTF8Char; const str : PUTF8Char; n : size_t);
procedure OPENSSL_strdup(var dest: PUTF8Char; const source : PUTF8Char);

function OPENSSL_strlcat(var dst : PUTF8Char;const src : PUTF8Char; size : size_t):size_t;
function OPENSSL_hexchar2int( c : UTF8char):integer;
function OPENSSL_hexstr2buf_ex(buf : PByte; buf_n : size_t; buflen : Psize_t;const str : PUTF8Char; sep : UTF8Char):integer;
function hexstr2buf_sep(buf : PByte; buf_n : size_t; buflen : Psize_t;const str : PUTF8Char; sep : UTF8Char):integer;
function CRYPTO_memdup(const data : Pointer; siz : size_t):Pointer;
function OPENSSL_memdup(str:Pointer; sz: size_t): Pointer;
function OPENSSL_strlcpy(var dst : PUTF8Char; src : PUTF8Char; size : size_t):size_t;
function OPENSSL_strnlen(const str : PUTF8Char; _maxlen : size_t):size_t;
function OPENSSL_hexstr2buf(const str : PUTF8Char; buflen : Plong):PByte;
function ossl_hexstr2buf_sep(const str : PUTF8Char; buflen : Plong;const sep : UTF8Char):PByte;
function OPENSSL_buf2hexstr(const buf : PByte; buflen : long):PUTF8Char;
function ossl_buf2hexstr_sep(const buf : PByte; buflen : long; sep : UTF8Char):PUTF8Char;
function buf2hexstr_sep(str : PUTF8Char; str_n : size_t; _strlen : Psize_t;const buf : PByte; buflen : size_t;const sep : UTF8Char):integer;
function openssl_strerror_r( errnum : integer; buf : PUTF8Char; buflen : size_t):integer;




implementation
uses {$IFDEF MSWINDOWS }libc.win, {$ENDIF}
  openssl3.crypto.mem, OpenSSL3.Err;

procedure OPENSSL_strdup(var dest: PUTF8Char; const source : PUTF8Char);
var
  len: size_t;
begin
  { allocate a copy of a string }
  if (source = nil)  then
  begin
     dest := nil;
     Exit;
  end;
  //dest := StrNew(source);


  len := StrSize(source); //#0 tail
  dest := AllocMem(len);

  if dest <> nil then
     strcopy(dest, source);

end;

function openssl_strerror_r( errnum : integer; buf : PUTF8Char; buflen : size_t):integer;
var
  err : PUTF8Char;
begin
{$IF (_MSC_VER>=1400)  and  not defined(_WIN32_WCE)}
    Exit( not strerror_s(PAnsiChar(buf), buflen, errnum));
{$elseif defined(_GNU_SOURCE)}
    {
     * GNU strerror_r may not actually set buf.
     * It can return a pointer to some (immutable)   string in which case
     * buf is left unused.
     }
    err := strerror_r(errnum, buf, buflen);
    if err = nil  or  buflen = 0 then Exit(0);
    {
     * If err is  ally allocated, err <> buf and we need to copy the data.
     * If err points somewhere inside buf, OPENSSL_strlcpy can handle this,
     * since src and dest are not annotated with __restrict and the function
     * reads src byte for byte and writes to dest.
     * If err = buf we do not have to copy anything.
     }
    if err <> buf then OPENSSL_strlcpy(buf, err, buflen);
    Exit(1);
{$elseif defined(_POSIX_C_SOURCE)  or defined(_XOPEN_SOURCE)  }
    {
     * We can use 'real' strerror_r. The OpenSSL version differs in that it
     * gives 1 on success and 0 on failure for consistency with other OpenSSL
     * functions. Real strerror_r does it the other way around
     }
    Exit( not strerror_r(errnum, buf, buflen));
{$ELSE} { Fall back to non-thread safe strerror...its all we can do }
    if buflen < 2 then Exit(0);
    err := strerror(errnum);
    { Can this ever happen? }
    if err = nil then Exit(0);
    OPENSSL_strlcpy(buf, err, buflen);
    Exit(1);
{$ENDIF}
end;



function buf2hexstr_sep(str : PUTF8Char; str_n : size_t; _strlen : Psize_t;const buf : PByte; buflen : size_t;const sep : UTF8Char):integer;
var
  p : PByte;
  q : PUTF8Char;
  i : size_t;
  has_sep : integer;
  len : size_t;
const
  hexdig: PUTF8Char = '0123456789ABCDEF';
begin

    has_sep := int(sep <> CH_ZERO);
    if has_sep>0 then
       len := buflen * 3
    else
       len := 1 + buflen * 2;
    if _strlen <> nil then
       _strlen^ := len;
    if str = nil then
       Exit(1);
    if str_n < ulong(len)   then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
        Exit(0);
    end;
    q := str;
    i := 0; p := buf;
    while i < buflen do
    begin
        PostInc(q)^ :=  hexdig[( p^  shr  4) and $f];
        PostInc(q)^ :=  hexdig[p^ and $f];
        if has_sep>0 then
           PostInc(q)^ :=  sep;
        Inc(i); Inc(p);
    end;
    if has_sep > 0 then
       Dec(q);
    q^ := CH_ZERO;
{$IFDEF CHARSET_EBCDIC}
    ebcdic2ascii(str, str, q - str - 1);
{$ENDIF}
    Result := 1;
end;


function ossl_buf2hexstr_sep(const buf : PByte; buflen : long; sep : UTF8Char):PUTF8Char;
var
  tmp_n : size_t;
begin
    if buflen = 0 then
       Exit(OPENSSL_zalloc(SizeOf(UTF8Char)));
    if sep <> CH_ZERO then
       tmp_n := buflen * 3
    else
       tmp_n := Char_Size + buflen * 2;
    Result := OPENSSL_malloc(tmp_n);
    if Result = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if buf2hexstr_sep(Result, tmp_n, nil, buf, buflen, sep) > 0 then
       Exit(Result);
    OPENSSL_free(Pointer(Result));
    Result := nil;
end;

function OPENSSL_buf2hexstr(const buf : PByte; buflen : long):PUTF8Char;
begin
    Result := ossl_buf2hexstr_sep(buf, buflen, ':');
end;


function ossl_hexstr2buf_sep(const str : PUTF8Char; buflen : Plong;const sep : UTF8Char):PByte;
var
  buf        : PByte;
  buf_n,
  tmp_buflen : size_t;
begin
    buf_n := StrSize(str);
    if buf_n <= 1 then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_HEX_STRING_TOO_SHORT);
        Exit(nil);
    end;
    buf_n  := buf_n  div 2;
    buf := OPENSSL_malloc(buf_n );
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if buflen <> nil then
       buflen^ := 0;
    tmp_buflen := 0;
    if hexstr2buf_sep(buf, buf_n, @tmp_buflen, str, sep) > 0 then
    begin
        if buflen <> nil then
           buflen^ := long(tmp_buflen);
        Exit(buf);
    end;
    OPENSSL_free(Pointer(buf));
    Result := nil;
end;

function OPENSSL_hexstr2buf(const str : PUTF8Char; buflen : Plong):PByte;
begin
    Result := ossl_hexstr2buf_sep(str, buflen, (DEFAULT_SEPARATOR));
end;

function OPENSSL_strnlen(const str : PUTF8Char; _maxlen : size_t):size_t;
var
  pc: PUTF8Char;
begin
    pc := str;
    while (_maxlen <> 0)  and  (pc^ <> CH_ZERO) do
    begin
       Inc(pc) ;
       Dec(_maxlen);
    end;
    Result := pc - str;
end;

function OPENSSL_strlcpy(var dst : PUTF8Char; src : PUTF8Char; size : size_t):size_t;
var
  l : size_t;
begin
    l := 0;
    while (size > 1)  and  (src^ <> #0) do
    begin
        //PostInc(dst)^ := PostInc(src)^;
        dst[l] := PostInc(src)^;
        Inc(l);
        Dec(size);
    end;
    if size >0 then
       dst[l] := CH_ZERO;
    Result := l + strlen(src);
end;

function CRYPTO_memdup(const data : Pointer; siz : size_t):Pointer;
begin
    if (data = nil)  or  (siz >= INT_MAX) then Exit(nil);
    result := CRYPTO_malloc(siz);
    if result = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    Result := memcpy(result, data, siz);
end;

function OPENSSL_memdup(str:Pointer; sz: size_t): Pointer;
begin
    Result := CRYPTO_memdup(str, sz )
end;

function hexstr2buf_sep(buf : PByte; buf_n : size_t; buflen : Psize_t;const str : PUTF8Char; sep : UTF8Char):integer;
var
  q : PByte;
  ch, cl : Byte;
  chi, cli : integer;
  p : PByte;
  cnt : size_t;
begin
    p := PByte (str); q := buf; cnt := 0;
    while ( chr(p^) <> #0 ) do
    begin
        ch := p^;
        Inc(p);
        { A separator of CH_ZERO means there is no separator }
        if (ch = Ord(sep))  and  (sep <> CH_ZERO) then
           continue;
        cl := p^;
        Inc(p);
        if  0>= cl then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_ODD_NUMBER_OF_DIGITS);
            Exit(0);
        end;
        cli := OPENSSL_hexchar2int(UTF8Char(cl));
        chi := OPENSSL_hexchar2int(UTF8Char(ch));
        if (cli < 0)  or  (chi < 0) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_ILLEGAL_HEX_DIGIT);
            Exit(0);
        end;
        Inc(cnt);
        if q <> nil then
        begin
            if cnt > buf_n then
            begin
                ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
                Exit(0);
            end;
            q^ :=  Byte((chi  shl  4) or cli);
            Inc(q);
        end;
    end;
    if buflen <> nil then
       buflen^ := cnt;
    Result := 1;
end;

function OPENSSL_hexstr2buf_ex(buf : PByte; buf_n : size_t; buflen : Psize_t;const str : PUTF8Char; sep : UTF8Char):integer;
begin
    Result := hexstr2buf_sep(buf, buf_n, buflen, str, sep);
end;


function OPENSSL_hexchar2int( c : UTF8char):integer;
begin
{$IFDEF CHARSET_EBCDIC}
    c := os_toebcdic[c];
{$ENDIF}
    case c of
    '0':
        Exit(0);
    '1':
        Exit(1);
    '2':
        Exit(2);
    '3':
        Exit(3);
    '4':
          Exit(4);
    '5':
          Exit(5);
    '6':
          Exit(6);
    '7':
          Exit(7);
    '8':
          Exit(8);
    '9':
          Exit(9);
    'a','A':
          Exit($0A);
    'b', 'B':
          Exit($0B);
    'c', 'C':
          Exit($0C);
    'd', 'D':
          Exit($0D);
    'e', 'E':
          Exit($0E);
    'f', 'F':
          Exit($0F);
    end;
    Result := -1;
end;

function OPENSSL_strlcat(var dst : PUTF8Char;const src : PUTF8Char; size : size_t):size_t;
var
  l : size_t;
begin
    l := 0;
    while (size > 0)  and  (dst^ <> #0) do
    begin
       Inc(l);
       Dec(size); Inc(dst);
    end;
    Result := l + OPENSSL_strlcpy(dst, src, size);
end;

procedure CRYPTO_strdup(var Result: PUTF8Char; const str: PUTF8Char);
begin
    if str = nil then
    begin
       Result := nil;
       Exit;
    end;
    Result := CRYPTO_malloc(StrSize(str));
    if Result <> nil then
       strcpy(Result, str);

end;

procedure CRYPTO_strndup(var Result: PUTF8Char; const str : PUTF8Char; sz : size_t);
var
  maxlen : size_t;
begin
    if str = nil then
    begin
       Result := nil;
       Exit;
    end;
    maxlen := OPENSSL_strnlen(str, sz);
    Result := CRYPTO_malloc((maxlen+1)*Char_Size);
    if Result <> nil then
    begin
        StrLCopy(Result, str, maxlen);
        Result[maxlen] := CH_ZERO;
    end;

end;

procedure OPENSSL_strndup(var dest: PUTF8Char; const str : PUTF8Char; n : size_t);
begin
   CRYPTO_strndup(dest, str, n);
end;
end.
