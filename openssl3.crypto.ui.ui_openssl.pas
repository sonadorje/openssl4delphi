unit openssl3.crypto.ui.ui_openssl;

{$I  config.inc}
interface
uses OpenSSL.Api, SysUtils,
    {$if defined(MSWINDOWS)}
      {$IFNDEF FPC}  Winapi.Windows, {$ELSE} windows, {$ENDIF} libc.win,
     {$ENDIF}
     Types;

type
   PText = ^Text;
   Tsavsig_func = procedure(p: Int);


function UI_get_default_method:PUI_METHOD;
function open_console( ui : PUI):integer;
function write_string( ui : PUI; uis : PUI_STRING):integer;
function read_string( ui : PUI; uis : PUI_STRING):integer;
function close_console( ui : PUI):integer;
function read_string_inner( ui : PUI; uis : PUI_STRING; echo, strip_nl : integer):integer;
procedure pushsig;
procedure popsig;
procedure recsig( i : integer);
function noecho_console( ui : PUI):integer;
 function read_till_nl( _in : PFILE):integer;
function signal(sig:longint; func:Tsavsig_func):Tsavsig_func;cdecl;external 'ucrtbased.dll' name 'signal';
function echo_console( ui : PUI):integer;


const
  ui_openssl: TUI_METHOD  = (
    name: 'OpenSSL default user interface';
    ui_open_session: open_console;
    ui_write_string: write_string;
    ui_flush: nil;                       // No flusher is needed for command lines
    ui_read_string: read_string;
    ui_close_session: close_console;
    ui_duplicate_data: nil
 );

var
  intr_signal: sig_atomic_t;
{$ifdef OPENSSL_SYS_VMS}
static struct IOSB iosb;
static $DESCRIPTOR(terminal, "TT");
static long tty_orig[3], tty_new[3]; /* XXX Is there any guarantee that this
                                      * will always suffice for the actual
                                      * structures? */
static long status;
static unsigned short channel = 0;
{$endif}
{$if defined(MSWINDOWS)}
   tty_orig, tty_new: DWORD ;
{$else}
{$if not defined(OPENSSL_SYS_MSDOS) or defined(__DJGPP__)}
static TTY_STRUCT tty_orig, tty_new;
{$endif}
{$endif}

  tty_in, tty_out: PFile ;

const
      default_UI_meth: PUI_METHOD = @ui_openssl;
{$ifndef NX509_SIG}
      NX509_SIG = 32;
{$endif}

var
  ps, is_a_tty: Int;
  savsig: array[0..NX509_SIG-1] of Tsavsig_func;

implementation
uses OpenSSL3.threads_none, openssl3.crypto.ui.ui_lib, openssl3.crypto.mem;


procedure popsig;
var
  i : integer;
begin
{$IFDEF OPENSSL_SYS_WIN32}
    signal(SIGABRT, savsig[SIGABRT]);
    signal(SIGFPE, savsig[SIGFPE]);
    signal(SIGILL, savsig[SIGILL]);
    signal(SIGINT, savsig[SIGINT]);
    signal(SIGSEGV, savsig[SIGSEGV]);
    signal(SIGTERM, savsig[SIGTERM]);
{$ELSE}
    for i := 1 to NX509_SIG-1 do
    begin
{$IFDEF SIGUSR1}
        if i = SIGUSR1 then continue;
{$ENDIF}
{$IFDEF SIGUSR2}
        if i = SIGUSR2 then continue;
{$ENDIF}
{$IFDEF SIGACTION}
        sigaction(i, &savsig[i], nil);
{$ELSE}
        signal(i, savsig[i]);
{$ENDIF}
    end;
{$ENDIF}
end;


function echo_console( ui : PUI):integer;
begin
{$IF defined(TTY_set)  and  not defined(OPENSSL_SYS_VMS)}
    memcpy(&(tty_new), &(tty_orig), sizeof(tty_orig));
    if is_a_tty  and  (TTY_set(fileno(tty_in then , &tty_new) = -1))
        Exit(0);
{$ENDIF}
{$IFDEF OPENSSL_SYS_VMS}
    if is_a_tty then begin
        tty_new[0] := tty_orig[0];
        tty_new[1] := tty_orig[1];
        tty_new[2] := tty_orig[2];
        status := sys$qiow(0, channel, IO$_SETMODE, &iosb, 0, 0, tty_new, 12,
                          0, 0, 0, 0);
        if status <> SS$_NORMAL then  or  (iosb.iosb$w_value <> SS$_NORMAL) then  begin
            ERR_raise_data(ERR_LIB_UI, UI_R_SYSQIOW_ERROR,
                           'status=%%X%08X, iosb.iosb$w_value=%%X%08X',
                           status, iosb.iosb$w_value);
            Exit(0);
        end;
    end;
{$ENDIF}
{$IF defined(MSWINDOWS)}
    if is_a_tty >0 then
    begin
        tty_new := tty_orig;
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), tty_new);
    end;
{$ENDIF}
    Result := 1;
end;


function read_till_nl( _in : PFILE):integer;
const SIZE = 4;
var
  buf : array[0..(SIZE + 1)-1] of AnsiChar;
begin

    repeat
        if nil = fgets(@buf, SIZE, _in) then
            Exit(0);
    until not (strchr(buf, #10) = nil);
    Result := 1;
end;



function noecho_console( ui : PUI):integer;
begin
{$IFDEF TTY_FLAGS}
    memcpy(&(tty_new), &(tty_orig), sizeof(tty_orig));
    tty_new.TTY_FLAGS &= ~ECHO;
{$ENDIF}
{$IF defined(TTY_set)  and  not defined(OPENSSL_SYS_VMS)}
    if is_a_tty  and  (TTY_set(fileno(tty_in then , &tty_new) = -1))
        Exit(0);
{$ENDIF}
{$IFDEF OPENSSL_SYS_VMS}
    if is_a_tty then
    begin
        tty_new[0] := tty_orig[0];
        tty_new[1] := tty_orig[1] or TT$M_NOECHO;
        tty_new[2] := tty_orig[2];
        status := sys$qiow(0, channel, IO$_SETMODE, &iosb, 0, 0, tty_new, 12,
                          0, 0, 0, 0);
        if status <> SS$_NORMAL then  or  (iosb.iosb$w_value <> SS$_NORMAL) then  begin
            ERR_raise_data(ERR_LIB_UI, UI_R_SYSQIOW_ERROR,
                           'status=%%X%08X, iosb.iosb$w_value=%%X%08X',
                           status, iosb.iosb$w_value);
            Exit(0);
        end;
    end;
{$ENDIF}
{$IF defined(MSWINDOWS)}
    if is_a_tty > 0 then
    begin
        tty_new := tty_orig;
        tty_new := tty_new and (not ENABLE_ECHO_INPUT);
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), tty_new);
    end;
{$ENDIF}
    Result := 1;
end;


procedure recsig( i : integer);
begin
    intr_signal := i;
end;


procedure pushsig;
var
  i : integer;
{$IFDEF SIGACTION}
  sa : sigaction;
{$ENDIF}
begin
{$IFNDEF OPENSSL_SYS_WIN32}
{$ENDIF}
{$IFDEF SIGACTION}
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler := recsig;
{$ENDIF}
{$IFDEF OPENSSL_SYS_WINDOWS}
    savsig[SIGABRT] := signal(SIGABRT, recsig);
    savsig[SIGFPE]  := signal(SIGFPE, recsig);
    savsig[SIGILL]  := signal(SIGILL, recsig);
    savsig[SIGINT]  := signal(SIGINT, recsig);
    savsig[SIGSEGV] := signal(SIGSEGV, recsig);
    savsig[SIGTERM] := signal(SIGTERM, recsig);
{$ELSE}
    for i := 1 to NX509_SIG-1 do begin
{$IFDEF SIGUSR1}
        if i = SIGUSR1 then continue;
{$ENDIF}
{$IFDEF SIGUSR2}
        if i = SIGUSR2 then continue;
{$ENDIF}
{$IFDEF SIGKILL}
        if i = SIGKILL then { We can't make any action on that. }
            continue;
{$ENDIF}
{$IFDEF SIGACTION}
        sigaction(i, &sa, &savsig[i]);
{$ELSE}
        savsig[i] := signal(i, recsig);
{$ENDIF}
    end;
{$ENDIF}
{$IFDEF SIGWINCH}
    signal(SIGWINCH, SIG_DFL);
{$ENDIF}
end;

function read_string_inner( ui : PUI; uis : PUI_STRING; echo, strip_nl : integer):integer;
var
    ok       : integer;
    _result  : array[0..(BUFSIZ)-1] of AnsiChar;
    maxsize  : integer;
    p        : PAnsiChar;
    echo_eol : integer;
    numread  : DWORD;
    wresult  : array[0..(BUFSIZ)-1] of WideCHAR;
    label _error;
begin
    maxsize := BUFSIZ - 1;
{$IF not defined(OPENSSL_SYS_WINCE)}
    p := nil;
    echo_eol :=  not echo;
    intr_signal := 0;
    ok := 0;
    ps := 0;
    pushsig();
    ps := 1;
    if (0>= echo)  and  (0>= noecho_console(ui) ) then
        goto _error ;
    ps := 2;
    _result[0] := #0;
{$IF defined(MSWINDOWS)}
    if is_a_tty > 0 then
    begin
{$IF CP_UTF8=65001}
        if GetEnvironmentVariableW('OPENSSL_WIN32_UTF8', nil, 0) <> 0 then
        begin
            if ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE) ,
                         @wresult, maxsize, numread, nil)  then
            begin
                if (numread >= 2)  and
                    (wresult[numread-2] = #13)  and
                    (wresult[numread-1] = #10) then
                begin
                    wresult[numread-2] := #10;
                    Dec(numread);
                end;
                wresult[numread] := #0;
                if WideCharToMultiByte(CP_UTF8, 0, wresult, -1,
                                        @_result, sizeof(_result) , nil, 0) > 0  then
                    p := _result;
                OPENSSL_cleanse(@wresult, sizeof(wresult));
            end;
        end
        else
{$ENDIF}
        if ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE) ,
                         @_result, maxsize, numread, nil)  then
        begin
            if (numread >= 2)  and
               (_result[numread-2] = #13)  and (_result[numread-1] = #10)  then
            begin
                _result[numread-2] := #10;
                Dec(numread);
            end;
            _result[numread] := #0;
            p := _result;
        end;
    end
    else
{$elseif defined(OPENSSL_SYS_MSDOS)}
    if 0>= echo then
    begin
        noecho_fgets(result, maxsize, tty_in);
        p := _result;             { FIXME: noecho_fgets doesn't return errors }
    end
    else
{$ENDIF}
    p := fgets(PAnsiChar(@_result), maxsize, tty_in);
    if p = nil then
       goto _error ;
    if _feof(tty_in) > 0 then
        goto _error ;
    if ferror(tty_in) > 0 then
        goto _error ;
    p := (strchr(_result, #10));
    if  p <> nil then
    begin
        if strip_nl >0 then
            p^ := #0;
    end
    else
    if (0>= read_till_nl(tty_in)) then
        goto _error ;
    if UI_set_result(ui, uis, @_result) >= 0  then
        ok := 1;
 _error:
    if intr_signal = SIGINT then
       ok := -1;
    if echo_eol > 0 then
       fprintf(tty_out, #10);
    if (ps >= 2)  and  (0>= echo)  and  (0>= echo_console(ui)) then
        ok := 0;
    if ps >= 1 then
       popsig();
{$ELSE}
      ok := 1;
{$ENDIF}
    OPENSSL_cleanse(@_result, BUFSIZ);
    Result := ok;
end;

function close_console( ui : PUI):integer;
var
  ret : integer;
begin
    ret := 1;
    if tty_in <> @System.Input{stdin} then
       fclose(tty_in);
    if tty_out <> @System.ErrOutput {stderr} then
       fclose(tty_out);
{$IFDEF OPENSSL_SYS_VMS}
    status := sys$dassgn(channel);
    if status <> SS$_NORMAL then
    begin
        ERR_raise_data(ERR_LIB_UI, UI_R_SYSDASSGN_ERROR,
                       'status=%%X%08X', status);
        ret := 0;
    end;
{$ENDIF}
    CRYPTO_THREAD_unlock(ui.lock);
    Result := ret;
end;



function write_string( ui : PUI; uis : PUI_STRING):integer;
begin
    case (UI_get_string_type(uis)) of
        UIT_ERROR,
        UIT_INFO:
        begin
            fputs(PAnsiChar(UI_get0_output_string(uis)), tty_out);
            fflush(tty_out);
        end;
        UIT_NONE,
        UIT_PROMPT,
        UIT_VERIFY,
        UIT_BOOLEAN:
        begin
          //break;
        end;
    end;
    Result := 1;
end;


function read_string( ui : PUI; uis : PUI_STRING):integer;
var
  ok : integer;
begin
    ok := 0;
    case (UI_get_string_type(uis)) of
        UIT_BOOLEAN:
        begin
            fputs(PAnsiChar(UI_get0_output_string(uis)), tty_out);
            fputs(PAnsiChar(UI_get0_action_string(uis)), tty_out);
            fflush(tty_out);
            Exit(read_string_inner(ui, uis,
                                   UI_get_input_flags(uis) and UI_INPUT_FLAG_ECHO,
                                   0));
        end;
        UIT_PROMPT:
        begin
            fputs(PAnsiChar(UI_get0_output_string(uis)), tty_out);
            fflush(tty_out);
            Exit(read_string_inner(ui, uis,
                                   UI_get_input_flags(uis) and UI_INPUT_FLAG_ECHO,
                                   1));
        end;
        UIT_VERIFY:
        begin
            Write(Format('Verifying - %s',[]));
            fflush(tty_out);
            ok := read_string_inner(ui, uis,
                                        UI_get_input_flags(uis) and
                                        UI_INPUT_FLAG_ECHO, 1);
            if ok <= 0  then
                Exit(ok);
            if strcmp(UI_get0_result_string(uis) , UI_get0_test_string(uis)) <> 0  then
            begin
                WriteLn('Verify failure');
                fflush(tty_out);
                Exit(0);
            end;
        end;
        UIT_NONE,
        UIT_INFO,
        UIT_ERROR:
        begin
            //break;
        end;
    end;
    Result := 1;
end;


function open_console( ui : PUI):integer;
begin
    if 0>= CRYPTO_THREAD_write_lock(ui.lock) then
        Exit(0);
    is_a_tty := 1;
{$IF defined(OPENSSL_SYS_VXWORKS)}
    tty_in := stdin;
    tty_out := stderr;
{$elseif defined(MSWINDOWS)}
    tty_out := fopen('conout$', 'w');
    if tty_out = nil then
       tty_out := @ErrOutput{stderr};
    if GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE) , tty_orig) then
    begin
        tty_in := @Input{stdin};
    end
    else
    begin
        is_a_tty := 0;
        tty_in := fopen('conin$', 'r');
        if tty_in = nil then
            tty_in := @System.Input{stdin};
    end;
{$ELSE} {$IFDEF OPENSSL_SYS_MSDOS}
  # define DEV_TTY 'con'
{$ELSE}
  # define DEV_TTY '/dev/tty'
{$ENDIF}
    if tty_in = fopen(DEV_TTY, 'r' then ) = nil then
        tty_in := stdin;
    if tty_out = fopen(DEV_TTY, 'w' then ) = nil then
        tty_out := stderr;
{$ENDIF}
{$IF defined(TTY_get)  and  not defined(OPENSSL_SYS_VMS)}
    if TTY_get(fileno(tty_in then , &tty_orig) = -1) begin
{$IFDEF ENOTTY}
        if errno = ENOTTY then
            is_a_tty := 0;
        else
{$ENDIF}
{$IFDEF EINVAL}
            {
             * Ariel Glenn reports that solaris can return EINVAL instead.
             * This should be ok
             }
        if errno = EINVAL then
           is_a_tty := 0
        else
{$ENDIF}
{$IFDEF ENXIO}
            {
             * Solaris can return ENXIO.
             * This should be ok
             }
        if errno = ENXIO then is_a_tty = 0;
        else
{$ENDIF}
{$IFDEF EIO}
            {
             * Linux can return EIO.
             * This should be ok
             }
        if errno = EIO then is_a_tty = 0;
        else
{$ENDIF}
{$IFDEF EPERM}
            {
             * Linux can return EPERM (Operation not permitted),
             * e.g. if a daemon executes openssl via fork()+execve()
             * This should be ok
             }
        if errno = EPERM then is_a_tty = 0;
        else
{$ENDIF}
{$IFDEF ENODEV}
            {
             * MacOS X returns ENODEV (Operation not supported by device),
             * which seems appropriate.
             }
        if errno = ENODEV then is_a_tty = 0;
        else
{$ENDIF}
            begin
                ERR_raise_data(ERR_LIB_UI, UI_R_UNKNOWN_TTYGET_ERRNO_VALUE,
                               'errno=%d', errno);
                Exit(0);
            end;
    end;
{$ENDIF}
{$IFDEF OPENSSL_SYS_VMS}
    status := sys$assign(&terminal, &channel, 0, 0);
    { if there isn't a TT device, something is very wrong }
    if status <> SS$_NORMAL then begin
        ERR_raise_data(ERR_LIB_UI, UI_R_SYSASSIGN_ERROR,
                       'status=%%X%08X', status);
        Exit(0);
    end;
    status := sys$qiow(0, channel, IO$_SENSEMODE, &iosb, 0, 0, tty_orig, 12,
                      0, 0, 0, 0);
    { If IO$_SENSEMODE doesn't work, this is not a terminal device }
    if status <> SS$_NORMAL then  or  (iosb.iosb$w_value <> SS$_NORMAL) then
        is_a_tty := 0;
{$ENDIF}
    Result := 1;
end;



function UI_get_default_method:PUI_METHOD;
begin
    Result := default_UI_meth;
end;


end.
