unit OpenSSL3.crypto.err.err_prn;

interface
uses OpenSSL.Api, SysUtils;

type
   Tcb_func = function(const str : PUTF8Char; len : size_t; u : Pointer):integer;

  procedure ERR_print_errors_cb(cb: Tcb_func; u : Pointer);
  procedure put_error(lib : integer;const func : PUTF8Char; reason : integer;const _file : PUTF8Char; line : integer);
  procedure ERR_add_error_txt(separator, txt : PUTF8Char);
  procedure ERR_add_error_mem_bio(const separator : PUTF8Char; bio : PBIO);
  function print_bio(const str : PUTF8Char; len : size_t; bp : Pointer):integer;
  procedure ERR_print_errors( bp : PBIO);
  procedure ERR_print_errors_fp( fp : PFILE);

const
    ERR_PRINT_BUF_SIZE             = 4096;
    TYPICAL_MAX_OUTPUT_BEFORE_DATA = 100;
    MAX_DATA_LEN                   = (ERR_PRINT_BUF_SIZE - TYPICAL_MAX_OUTPUT_BEFORE_DATA);


function openssl_error_cb(const str : PUTF8Char; len : size_t; u : Pointer):integer;

implementation
uses openssl3.crypto.bio.bio_print,         OpenSSL3.threads_none,
     openssl3.crypto.o_str,                 openssl3.crypto.mem,
     openssl3.crypto.bio.bio_lib,           OpenSSL3.Err,
     openssl3.test.testutil.output,
     openssl3.providers.fips.fipsprov,      openssl3.crypto.bio.bss_file;




function openssl_error_cb(const str : PUTF8Char; len : size_t; u : Pointer):integer;
begin
    Result := test_printf_stderr('%s', [str]);
end;

procedure ERR_print_errors_cb(cb: Tcb_func; u : Pointer);
var
  tid : CRYPTO_THREAD_ID;
  l : Cardinal;
  _file, data, func : PUTF8Char;
  line, flags : integer;
  buf : array[0..(ERR_PRINT_BUF_SIZE)-1] of UTF8Char;
  hex : PUTF8Char;
  offset : integer;
  function get_l: uint32;
  begin
     l := ERR_get_error_all(@_file, @line, @func, @data, @flags);
     Exit(l);
  end;
begin
    tid := CRYPTO_THREAD_get_current_id();
    while (get_l <> 0) do
    begin
        buf := '';
        hex := nil;
        if (flags and ERR_TXT_STRING) = 0 then
            data := '';
        hex := ossl_buf2hexstr_sep(PByte(@tid), sizeof(tid), #0);
        BIO_snprintf(buf, sizeof(buf), '%s:', [get_result(hex = nil , '<null>' , hex)]);
        offset := Length(buf);
        ossl_err_string_int(l, func, buf + offset, sizeof(buf) - offset);
        offset  := offset + (Length(buf + offset));
        BIO_snprintf(buf + offset, sizeof(buf) - offset, ':%s:%d:%s'#10,
                     [_file, line, data]);
        OPENSSL_free(Pointer(hex));
        if cb(buf, Length(buf) , u) <= 0  then
            break;              { abort outputting the error report }
    end;
end;


procedure put_error(lib : integer;const func : PUTF8Char; reason : integer;const _file : PUTF8Char; line : integer);
begin
    ERR_new();
    ERR_set_debug(_file);// line, func);
    ERR_set_error(lib, reason, '');//nil { no data here, so fmt is nil });
end;


procedure ERR_add_error_txt(separator, txt : PUTF8Char);
var
  _file, next        : PUTF8Char;
  line               : integer;
  func,
  data               : PUTF8Char;
  flags              : integer;
  err                : Cardinal;
  available_len,
  data_len           : size_t;
  curr,
  leading_separator  : PUTF8Char;
  trailing_separator : integer;
  tmp                : PUTF8Char;
  len_next           : size_t;
begin
    _file := nil;
    func := nil;
    data := nil;
    err := ERR_peek_last_error();
    if separator = nil then
       separator := '';
    if err = 0 then
       put_error(ERR_LIB_NONE, nil, 0, '', 0);
    repeat
        curr := txt; next := txt;
        leading_separator := separator;
        trailing_separator := 0;
        ERR_peek_last_error_all(@_file, @line, @func, @data, @flags);
        if (flags and ERR_TXT_STRING) = 0 then
        begin
            data := '';
            leading_separator := '';
        end;
        data_len := Length(data);
        { workaround for limit of ERR_print_errors_cb() }
        if (data_len >= MAX_DATA_LEN)
                 or ( Length(separator) >= size_t(MAX_DATA_LEN - data_len)) then
            available_len := 0
        else
            available_len := MAX_DATA_LEN - data_len - Length(separator) - 1;
        { MAX_DATA_LEN > available_len >= 0 }
        if separator^ = #0 then
        begin
           len_next := Length(next);
            if len_next <= available_len then
            begin
                next  := next + len_next;
                curr := nil; { no need to split }
            end
            else
            begin
                next  := next + available_len;
                curr := next; // will split at this point
            end;
        end
        else
        begin
            while (next^ <> #0)  and  (size_t(next - txt) <= available_len) do
            begin
                curr := next;
                next := strstr(curr, separator);
                if next <> nil then
                begin
                    next  := next + (Length(separator));
                    trailing_separator := ord(#0); next^ := #0;
                end
                else
                begin
                    next := curr + Length(curr);
                end;
            end;
            if size_t(next - txt) <= available_len  then
               curr := nil; // the above loop implies *next = #0
        end;
        if curr <> nil then
        begin
            // split error msg at curr since error data would get too long
            if curr <> txt then
            begin
                OPENSSL_strndup(tmp, txt, curr - txt);
                if tmp = nil then exit;
                ERR_add_error_data(2, [separator, tmp]);
                OPENSSL_free(Pointer(tmp));
            end;
            put_error(ERR_GET_LIB(err), func, err, _file, line);
            txt := curr;
        end
        else
        begin
            if trailing_separator > 0 then
            begin
                OPENSSL_strndup(tmp, txt, next - Length(separator) - txt);
                if tmp = nil then
                   exit ;
                { output txt without the trailing separator }
                ERR_add_error_data(2, [leading_separator, tmp]);
                OPENSSL_free(Pointer(tmp));
            end
            else
            begin
                ERR_add_error_data(2, [leading_separator, txt]);
            end;
            txt := next; { finished }
        end;
    until not (txt^ <> #0);
end;

procedure ERR_add_error_mem_bio(const separator : PUTF8Char; bio : PBIO);
var
  str : PUTF8Char;
  len : long;
begin
    if bio <> nil then
    begin
        len := BIO_get_mem_data(bio, Pointer(str));
        if len > 0 then
        begin
            if str[len - 1] <> #0 then
            begin
                if BIO_write(bio, PUTF8Char(''), 1) <= 0 then
                   exit;
                len := BIO_get_mem_data(bio, Pointer(str));
            end;
            if len > 1 then
               ERR_add_error_txt(separator, str);
        end;
    end;
end;


function print_bio(const str : PUTF8Char; len : size_t; bp : Pointer):integer;
begin
    Result := BIO_write(PBIO(bp), str, len);
end;


procedure ERR_print_errors( bp : PBIO);
begin
    ERR_print_errors_cb(print_bio, bp);
end;


procedure ERR_print_errors_fp( fp : PFILE);
var
  bio : PBIO;
begin
    bio := BIO_new_fp(fp, BIO_NOCLOSE);
    if bio = nil then
       Exit ;
    ERR_print_errors_cb(print_bio, bio);
    BIO_free(bio);
end;

end.
