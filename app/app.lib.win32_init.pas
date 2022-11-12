unit app.lib.win32_init;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses

  windows,
  SysUtils, libc.win, OpenSSL.api;

{$POINTERMATH ON}
type
   PPPChar = ^PPChar;

var
  newargc: int ;
  newargv: PPchar;
  saved_cp: uint;

function validate_argv( argc : integer):integer;
procedure cleanup;cdecl;
procedure win32_utf8argv( argc: PInteger; argv: PPPChar);
function process_glob( wstr : PWideChar; wlen : integer):integer;

implementation

function process_glob( wstr : PWideChar; wlen : integer):integer;
var
  i,
  slash,
  udlen      : integer;
  saved_char : WCHAR;
  data       : WIN32_FIND_DATAW;
  h          : THANDLE;
  uflen      : integer;
  arg        : PChar;
  s          : AnsiString;
  _arg       : PAnsiChar;
begin
    {
     * Note that we support wildcard characters only in filename part
     * of the path, and not in directories. Windows users are used to
     * this, that's why recursive glob processing is not implemented.
     }
    {
     * Start by looking for last slash or backslash, ...
     }
    slash := 0;
    for  i := 0 to wlen-1 do
        if (wstr[i] = #47{/})  or  (wstr[i] = #92{\}) then
           slash := i + 1;
    {
     * ... then look for asterisk or question mark in the file name.
     }
    for i := slash to wlen-1 do
        if (wstr[i] = '*')  or  (wstr[i] = '?') then
            break;
    if i = wlen then Exit(0);   { definitely not a glob }
    saved_char := wstr[wlen];
    wstr[wlen] := #0;
    h := FindFirstFileW(wstr, &data);
    wstr[wlen] := saved_char;
    if h = INVALID_HANDLE_VALUE then Exit(0);   { not a valid glob, just pass... }
    if slash > 0 then
       udlen := WideCharToMultiByte(CP_UTF8, 0, wstr, slash,
                                    nil, 0, nil, nil)
    else
        udlen := 0;
    repeat
        {
         * skip over . and ..
         }
        if data.cFileName[0] = '.' then
        begin
            if (data.cFileName[1] = #0 )   or
               ( (data.cFileName[1] = '.')  and  (data.cFileName[2] = #0) )then
                continue;
        end;
        if 0>=validate_argv(newargc + 1) then
            break;
        {
         * -1 below means 'scan for trailing #0 *and* count it',
         * so that |uflen| covers even trailing #0.
         }
        uflen := WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1,
                                    nil, 0, nil, nil);
        arg := malloc(udlen + uflen);
        if arg = nil then break;

        s := arg;
        _arg := PAnsiChar(s);
        if udlen > 0 then
           WideCharToMultiByte(CP_UTF8, 0, wstr, slash,
                                _arg, udlen, nil, nil);
        WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1,
                            _arg + udlen, uflen, nil, nil);
        newargv[PostInc(newargc)] := arg;
    until not (FindNextFileW(h, data) );
    FileClose(h); { *Converted from CloseHandle* }
    Result := 1;
end;


procedure cleanup;cdecl;
var
  i : integer;
begin
    SetConsoleOutputCP(saved_cp);
    for i := 0 to newargc-1 do
        free(newargv[i]);
    free(newargv);
end;



function validate_argv( argc : integer):integer;
var
  size : integer;
  ptr : PPChar;
begin
      size := 0;
    if argc >= size then
    begin
        while argc >= size do
            size  := size + 64;
        reallocmem(newargv, size * sizeof(newargv[0]));
        if newargv = nil then
           Exit(0);
        newargv[argc] := nil;
    end
    else
    begin
        newargv[argc] := nil;
    end;
    Result := 1;
end;

procedure win32_utf8argv( argc: PInteger; argv: PPPChar);
var
   wcmdline,
   warg,
   wend,
   p        : PWideChar;

  wlen,
  ulen,
  valid    : integer;
  arg      : PChar;
  in_quote : integer;
  q        : PWideChar;
  i        : integer;
  _arg     : PAnsiChar;
  s        : AnsiString;
begin
   if (GetEnvironmentVariableW('OPENSSL_WIN32_UTF8', nil, 0) = 0) then
        exit;

    newargc := 0;
    newargv := nil;
    if (0>=validate_argv(newargc)) then
        exit;

    wcmdline := GetCommandLineW;
    if (wcmdline = nil) then
       exit;

    (*
     * make a copy of the command line, since we might have to modify it...
     *)
    wlen := wcslen(wcmdline);
    p := AllocMem((wlen + 1) * sizeof(WCHAR));
    wcscpy(p, wcmdline);

    while (p^ <> #0) do
    begin
        in_quote := 0;

        if (p^ = ' ') or (p^ = #9) then
        begin
            Inc(p); (* skip over whitespace *)
            continue;
        end;

        (*
         * Note: because we may need to fiddle with the number of backslashes,
         * the argument string is copied into itself.  This is safe because
         * the number of characters will never expand.
         *)
        warg := p; wend := p;
        while (p^ <> #0)  and
              ( (in_quote >0) or ( (p^ <> ' ') and (p^ <> #9))) do
        begin
            case (p^) of
                 '\':
                    (*
                     * Microsoft documentation on how backslashes are treated
                     * is:
                     *
                     * + Backslashes are interpreted literally, unless they
                     *   immediately precede a double quotation mark.
                     * + If an even number of backslashes is followed by a double
                     *   quotation mark, one backslash is placed in the argv array
                     *   for every pair of backslashes, and the double quotation
                     *   mark is interpreted as a string delimiter.
                     * + If an odd number of backslashes is followed by a double
                     *   quotation mark, one backslash is placed in the argv array
                     *   for every pair of backslashes, and the double quotation
                     *   mark is 'escaped' by the remaining backslash, causing a
                     *   literal double quotation mark (') to be placed in argv.
                     *
                     * Ref: https://msdn.microsoft.com/en-us/library/17w5ykft.aspx
                     *
                     * Though referred page doesn't mention it, multiple qouble
                     * quotes are also special. Pair of double quotes in quoted
                     * string is counted as single double quote.
                     *)
                 begin
                        q := p;


                        while (p^ = '') do
                            Inc(p);

                        if (p^ = '''') then
                        begin
                            //int i;

                            for i := (p - q) div 2 downto 1 do
                                PostInc(wend)^ := '\';

                            (*
                             * if odd amount of backslashes before the quote,
                             * said quote is part of the argument, not a delimiter
                             *)
                            if ((p - q) mod 2 = 1) then
                                PostInc(wend)^ := PostInc(p)^;
                        end
                        else
                        begin
                            for i := p - q downto 1 do
                                PostInc(wend)^ := '\';
                        end;
                 end;
                    //break;
                 '''':
                 begin
                    (*
                     * Without the preceding backslash (or when preceded with an
                     * even number of backslashes), the double quote is a simple
                     * string delimiter and just slightly change the parsing state
                     *)
                    if (in_quote > 0) and (p[1] = '''') then
                        PostInc(wend)^ := PostInc(p)^
                    else
                        in_quote := not in_quote;
                    Inc(p);
                 end;
                 else
                    (*
                     * Any other non-delimiter character is just taken verbatim
                     *)
                    PostInc(wend)^ := PostInc(p)^;
            end;
        end;

        wlen := wend - warg;

        if (wlen = 0) or (0>=process_glob(warg, wlen)) then
        begin
            if (0>=validate_argv(newargc + 1)) then
            begin
                valid := 0;
                break;
            end;

            ulen := 0;
            if (wlen > 0) then
            begin
                ulen := WideCharToMultiByte(CP_UTF8, 0, warg, wlen,
                                           nil, 0, nil, nil);
                if (ulen <= 0) then
                    continue;
            end;

            arg := malloc(ulen + 1);
            if (arg = nil) then
            begin
                valid := 0;
                break;
            end;
            s := arg;
            _arg := PAnsiChar(s);
            if (wlen > 0) then
                WideCharToMultiByte(CP_UTF8, 0, warg, wlen,
                                    _arg, ulen, nil, nil);
            arg[ulen] := '0';

            newargv[PostInc(newargc)] := arg;
        end;
    end;

    if (valid > 0) then
    begin
        saved_cp := GetConsoleOutputCP;
        SetConsoleOutputCP(CP_UTF8);

        argc^ := newargc;
        argv^ := newargv;

        atexit(cleanup);
    end
    else
    if (newargv <> nil) then
    begin
        for i := 0 to newargc-1 do
            free(newargv[i]);

        free(newargv);

        newargc := 0;
        newargv := nil;
    end;

    exit;
end;

end.
