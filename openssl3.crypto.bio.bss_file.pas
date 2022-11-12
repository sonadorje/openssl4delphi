unit openssl3.crypto.bio.bss_file;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$I config.inc}
interface
uses
  OpenSSL.Api,
  {$IFDEF MSWINDOWS}
      Windows, libc.win,
  {$ENDIF}SysUtils, Classes;

(*
  obj when you build your project for 32-bit Windows.
  o when you build your project for any other supported platform.
*)



  function BIO_s_file:PBIO_METHOD;
  function BIO_new_file(const filename: PUTF8Char; mode: string):PBIO;
  function BIO_new_fp( stream : PFILE; close_flag : integer):PBIO;
  function file_new( bi : PBIO):integer;
  function file_free( a : PBIO):integer;
  function file_read( b : PBIO; _out : PUTF8Char; outl : integer):integer;
  function file_write(b : PBIO;{const} _in : PByte; inl : integer):integer;
  function file_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
  function file_gets( bp : PBIO; buf : PUTF8Char; size : integer):integer;
  function file_puts(bp : PBIO;const str : PUTF8Char):integer;





const
  EOF  =  (-1);
  
implementation
uses openssl3.crypto.bio.bio_meth, openssl3.crypto.o_fopen,
     openssl3.crypto.o_str,
     OpenSSL3.Err, openssl3.crypto.bio.bio_lib;//, libc.stdio.io;

const  methods_filep: TBIO_METHOD = (
    &type: BIO_TYPE_FILE;
    name: 'FILE pointer';
    bwrite: bwrite_conv;
    bwrite_old: file_write;
    bread: bread_conv;
    bread_old: file_read;
    bputs: file_puts;
    bgets: file_gets;
    ctrl: file_ctrl;
    create: file_new;
    destroy: file_free;
    callback_ctrl: nil                      (* file_callback_ctrl *)
);

function BIO_new_file(const filename: PUTF8Char; mode: string):PBIO;
var
    _file    : PFILE;
    fp_flags : integer;
    errno: int;
begin
    _file := openssl_fopen(filename, mode);
    fp_flags := BIO_CLOSE;
    if strchr(PUTF8Char(mode), 'b') = nil  then
        fp_flags  := fp_flags  or BIO_FP_TEXT;
    if _file = nil then
    begin
        errno := get_last_sys_error();
        ERR_raise_data(ERR_LIB_SYS, errno,
                     Format('calling fopen(%s, %s)',
                       [filename, mode]));

        if errno = ENOENT
{$IFDEF ENXIO}
             or  errno = ENXIO
{$ENDIF}
             then
             ERR_raise(ERR_LIB_BIO, BIO_R_NO_SUCH_FILE)
        else
            ERR_raise(ERR_LIB_BIO, ERR_R_SYS_LIB);
        Exit(nil);
    end;
    Result := BIO_new(BIO_s_file);
    if Result = nil then
    begin
        fclose(_file);
        Exit(nil);
    end;
    { we did fopen . we disengage UPLINK }
    BIO_clear_flags(Result, BIO_FLAGS_UPLINK_INTERNAL);
    BIO_set_fp(Result, _file, fp_flags);
end;


function BIO_new_fp( stream : PFILE; close_flag : integer):PBIO;
var
  ret : PBIO;
begin
    ret := BIO_new(BIO_s_file);
    if ret = nil then
        Exit(nil);
    { redundant flag, left for documentation purposes }
    BIO_set_flags(ret, BIO_FLAGS_UPLINK_INTERNAL);
    BIO_set_fp(ret, stream, close_flag);
    Result := ret;
end;


function BIO_s_file:PBIO_METHOD;
begin
    Result := @methods_filep;
end;


function file_new( bi : PBIO):integer;
begin
    bi.init := 0;
    bi.num := 0;
    bi.ptr := nil;
    bi.flags := BIO_FLAGS_UPLINK_INTERNAL; { default to UPLINK }
    Result := 1;
end;


function file_free( a : PBIO):integer;
begin
    if a = nil then Exit(0);
    if a.shutdown > 0 then
    begin
        if (a.init > 0)  and  (a.ptr <> nil) then
        begin
            if (a.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
                fclose(a.ptr) //UP_fclose(a.ptr)
            else
                fclose(a.ptr);
            a.ptr := nil;
            a.flags := BIO_FLAGS_UPLINK_INTERNAL;
        end;
        a.init := 0;
    end;
    Result := 1;
end;


function file_read( b : PBIO; _out : PUTF8Char; outl : integer):integer;
var
  ret : integer;
begin
    ret := 0;
    if (b.init > 0)  and  (_out <> nil) then
    begin
        if (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
            ret := fread{UP_fread}(_out, 1, int( outl), b.ptr)
        else
            ret := fread(_out, 1, int(outl), PFILE(b.ptr) );

        if (ret = 0)
             and ( get_result( (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0
                               , ferror(PFILE(b.ptr)) , ferror(PFILE(b.ptr)) ) > 0) then
        begin
            ERR_raise_data(ERR_LIB_SYS, get_last_sys_error(),
                           'calling fread()');
            ERR_raise(ERR_LIB_BIO, ERR_R_SYS_LIB);
            ret := -1;
        end;
    end;
    Result := ret;
end;


function file_write(b : PBIO;{const} _in : PByte; inl : integer):integer;
var
  ret : integer;
  str: AnsiString;
begin
    ret := 0;
    if (b.init > 0)  and  (_in <> nil) then
    begin
        if (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
            ret := fwrite(_in, int(inl), 1, b.ptr)
        else
        begin
            //ret := fwrite(_in, int(inl), 1, PFILE(b.ptr));
            Write(PTextFile(b.ptr)^, PUTF8Char(_in));
            ret := 1;
        end;

        if ret > 0 then
           ret := inl;

        {
         * according to Tim Hudson <tjh@openssl.org>, the commented out
         * version above can cause 'inl' write calls under some stupid stdio
         * implementations (VMS)
         }
    end;
    Result := ret;
end;


function file_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
var
  ret : long;
  fp : PFILE;
  fpp : PPFILE;
  p : array[0..3] of UTF8Char;
  buff: array[0..1023] of AnsiChar;
  pc: PUTF8Char;
  st, fd : integer;
  s: string;
  label _break;
begin
    ret := 1;
    fp := b.ptr;
    FillChar(buff, 1024, #0);
    case cmd of
        BIO_C_FILE_SEEK,
        BIO_CTRL_RESET:
        begin
            if (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
               ret := long(fseek(b.ptr, num, 0))
            else
               ret := long(fseek(fp, num, 0));
        end;
        BIO_CTRL_EOF:
        begin
            if (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
                ret := long(_feof(fp))
            else
                ret := long(_feof(fp));
        end;
        BIO_C_FILE_TELL,
        BIO_CTRL_INFO:
        begin
            if (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
               ret := ftell(b.ptr)
            else
                ret := ftell(fp);
        end;
        BIO_C_SET_FILE_PTR:
        begin
            file_free(b);
            b.shutdown := int (num and BIO_CLOSE);
            b.ptr := ptr;
            b.init := 1;

    {$IF BIO_FLAGS_UPLINK_INTERNAL<>0}
    {$IF defined(__MINGW32__)  and  defined(__MSVCRT__)  and  (not defined(_IOB_ENTRIES))}
    #define _IOB_ENTRIES 20
    {$IFEND}
            { Safety net to catch purely internal BIO_set_fp calls }
    {$IF defined(__BORLANDC__)}
            if (ptr = @System.in)  or  (ptr = stdout)  or  (ptr = stderr) then
               BIO_clear_flags(b, BIO_FLAGS_UPLINK_INTERNAL);
    {$elseif defined(_IOB_ENTRIES)}
            if size_t( ptr >= size_t( stdin  and
                size_t( ptr < size_t( (stdin + _IOB_ENTRIES then )
                BIO_clear_flags(b, BIO_FLAGS_UPLINK_INTERNAL);
    {$IFEND}
    {$IFEND}
    {$IFDEF UP_fsetmod}
            if b.flags and BIO_FLAGS_UPLINK_INTERNAL then
               UP_fsetmod(b.ptr, (char)((num and BIO_FP_TEXT) ? 't' : 'b'));
            else
    {$ENDIF}
            begin
    {$IF defined(OPENSSL_SYS_WINDOWS)}

                fd := _fileno(PFILE(ptr));
                if (num and BIO_FP_TEXT) > 0 then
                    _setmode(fd, _O_TEXT)
                else
                    _setmode(fd, _O_BINARY);
    {$elseif defined(OPENSSL_SYS_MSDOS)}
                fd := fileno((PFILE  )ptr);
                { Set correct text/binary mode }
                if (num and BIO_FP_TEXT) > 0 then
                   _setmode(fd, _O_TEXT);
                { Dangerous to set stdin/stdout to raw (unless redirected) }
                else
                begin
                    if (fd = STDIN_FILENO)  or  (fd = STDOUT_FILENO) then
                    begin
                        if isatty(fd) <= 0 then
                            _setmode(fd, _O_BINARY);
                    end
                    else
                        _setmode(fd, _O_BINARY);
                end;
    {$elseif defined(OPENSSL_SYS_WIN32_CYGWIN)}
                fd := fileno((PFILE  )ptr);
                if 0>= (num and BIO_FP_TEXT then )
                    setmode(fd, O_BINARY);
    {$IFEND}
            end;
        end;
        BIO_C_SET_FILENAME:
        begin
            file_free(b);
            b.shutdown := int (num and BIO_CLOSE);
            if (num and BIO_FP_APPEND) > 0 then
            begin
                pc := @p;
                if (num and BIO_FP_READ) > 0 then
                   OPENSSL_strlcpy(pc, 'a+', sizeof(p))
                else
                   OPENSSL_strlcpy(pc, 'a', sizeof(p));
            end
            else
            if ( (num and BIO_FP_READ) >0  ) and  ( (num and BIO_FP_WRITE) > 0 )  then
                OPENSSL_strlcpy(pc, 'r+', sizeof(p))
            else if (num and BIO_FP_WRITE) > 0 then
                OPENSSL_strlcpy(pc, 'w', sizeof(p))
            else if (num and BIO_FP_READ) > 0 then
                OPENSSL_strlcpy(pc, 'r', sizeof(p))
            else
            begin
                ERR_raise(ERR_LIB_BIO, BIO_R_BAD_FOPEN_MODE);
                ret := 0;
                goto _break;
            end;
    {$IF defined(OPENSSL_SYS_MSDOS)  or  defined(OPENSSL_SYS_WINDOWS)}
            pc := @p;
            if 0>= (num and BIO_FP_TEXT) then
                OPENSSL_strlcat(pc, 'b', sizeof(p))
            else
                OPENSSL_strlcat(pc, 't', sizeof(p));
    {$elseif defined(OPENSSL_SYS_WIN32_CYGWIN)}
            if 0>= (num and BIO_FP_TEXT) then
                OPENSSL_strlcat(pc, 'b', sizeof(p));
    {$IFEND}
            SetString(s, PUTF8Char(@p), Length(p));
            fp := openssl_fopen(ptr, s);
            if fp = nil then
            begin
                ERR_raise_data(ERR_LIB_SYS, get_last_sys_error(),
                             Format(  'calling fopen(%s, %s)',
                               [ptr, @p]));
                ERR_raise(ERR_LIB_BIO, ERR_R_SYS_LIB);
                ret := 0;
                goto _break;
            end;
            b.ptr := fp;
            b.init := 1;
            { we did fopen . we disengage UPLINK }
            BIO_clear_flags(b, BIO_FLAGS_UPLINK_INTERNAL);
        end;
        BIO_C_GET_FILE_PTR:
        begin
            { the ptr parameter is actually a PFILE  * in this case. }
            if ptr <> nil then
            begin
                fpp := PPFILE(ptr);
                fpp^ := PFILE(b.ptr);
            end;
        end;
        BIO_CTRL_GET_CLOSE:
            ret := long(b.shutdown);
            //break;
        BIO_CTRL_SET_CLOSE:
           goto _break;
        BIO_CTRL_FLUSH:
        begin
            if (b.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
               st := fflush(b.ptr)
            else
            begin
                {$IFNDEF FPC}
                st := System.Flush(PTextFile(b.ptr)^);
                {$ELSE}
                flush(PTextFile(b.ptr)^);
                st := 0;
                {$ENDIF}
            end;

            if st <> 0 {= EOF} then
            begin
                ERR_raise_data(ERR_LIB_SYS, get_last_sys_error(),
                               'calling fflush()');
                ERR_raise(ERR_LIB_BIO, ERR_R_SYS_LIB);
                ret := 0;
            end;
        end;
        BIO_CTRL_DUP:
            ret := 1;
            //break;
        _BIO_CTRL_WPENDING,
        _BIO_CTRL_PENDING,
        BIO_CTRL_PUSH,
        BIO_CTRL_POP:
        else
            ret := 0;
            //break;
    end;

_break:
    Result := ret;
end;


function file_gets( bp : PBIO; buf : PUTF8Char; size : integer):integer;
var
  ret, I : integer;
  _buf: array[0..511] of AnsiChar;
  label _err;
begin
    ret := 0;
    FillChar(_buf, 512, #0);
    if (bp.flags and BIO_FLAGS_UPLINK_INTERNAL) > 0 then
    begin
        if nil = fgets(_buf, size, bp.ptr) then
            goto _err ;
    end
    else
    begin
        if nil = fgets(_buf, size, PFILE(bp.ptr)) then
            goto _err ;
    end;

    //add by softwind 2022-07-13
    I := 0;
    while _buf[I] <> #0 do
    begin
       buf[I] := UTF8Char(_buf[I]);
       Inc(I);
    end;
    ret := I + 1;
    for I := ret-1 to size -1 do
       buf[I] := #0;
 _err:
    Result := ret;
end;


function file_puts(bp : PBIO;const str : PUTF8Char):integer;
var
  n, ret : integer;
  _bytes: TBytes;
begin
    _bytes := StrToBytes(str);
    n := Length(_bytes);
    ret := file_write(bp, PByte(_bytes), n);
    Result := ret;
    SetLength(_bytes, 0);
end;


end.
