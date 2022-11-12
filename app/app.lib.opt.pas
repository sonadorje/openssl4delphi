unit app.lib.opt;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$I config.inc}
interface
uses
{$ifdef MSWINDOWS}
  windows,
  libc.win,
{$ENDIF}  OpenSSL.api, Variants, SysUtils;


const
    OPT_FMT_PEMDER         = long(1) shl  1;
   OPT_FMT_PKCS12          = long(1) shl  2;
   OPT_FMT_SMIME           = long(1) shl  3;
   OPT_FMT_ENGINE          = long(1) shl  4;
   OPT_FMT_MSBLOB          = long(1) shl  5;
  (* = long(1) shl  6; was OPT_FMT_NETSCAPE, but wasn't used *)
   OPT_FMT_NSS             = long(1) shl  7;
   OPT_FMT_TEXT            = long(1) shl  8;
   OPT_FMT_HTTP            = long(1) shl  9;
   OPT_FMT_PVK             = long(1) shl 10;
   OPT_FMT_PDE             = OPT_FMT_PEMDER or OPT_FMT_ENGINE;
   OPT_FMT_PDS             = OPT_FMT_PEMDER or OPT_FMT_SMIME;
   OPT_FMT_ANY             = OPT_FMT_PEMDER or OPT_FMT_PKCS12 or OPT_FMT_SMIME or
                             OPT_FMT_ENGINE or OPT_FMT_MSBLOB or OPT_FMT_NSS   or
                             OPT_FMT_TEXT   or OPT_FMT_HTTP   or OPT_FMT_PVK;
   OPT_HELP_STR = '-H';
   OPT_MORE_STR = '-M';
   OPT_SECTION_STR = '-S';
   OPT_PARAM_STR = '-P';
   OPT_PARAM = 0; (* same as OPT_EOF usually defined in apps *)
   OPT_DUP   = -2; (* marks duplicate occurrence of option in help output *)


   MAX_OPT_HELP_WIDTH = 30;


type
  options_st = record
    name : PUTF8Char;
    retval : integer;
    valtype: UTF8Char;
    helpstr : PUTF8Char;
  end;
  TOPTIONS = options_st;
  POPTIONS = ^TOPTIONS;

  string_int_pair_st = record
    name : PUTF8Char;
    retval : integer;
  end;
  TOPT_PAIR =string_int_pair_st;
  POPT_PAIR = ^TOPT_PAIR;
  TSTRINT_PAIR = string_int_pair_st;

const
  formats : array[0..9] of TOPT_PAIR = (
    (name :'PEM/DER'; retval : OPT_FMT_PEMDER),
    (name :'pkcs12';  retval : OPT_FMT_PKCS12),
    (name :'smime';   retval : OPT_FMT_SMIME),
    (name :'engine';  retval : OPT_FMT_ENGINE),
    (name :'msblob';  retval : OPT_FMT_MSBLOB),
    (name :'nss';     retval : OPT_FMT_NSS),
    (name :'text';    retval : OPT_FMT_TEXT),
    (name :'http';    retval : OPT_FMT_HTTP),
    (name :'pvk';     retval : OPT_FMT_PVK),
    (name :nil;       retval : 0)
);

 function opt_init(ac : integer; av : PPUTF8Char;const o : POPTIONS):PUTF8Char;



var
  argc, opt_index: int;
  argv: PPUTF8Char;
  arg, flag: PUTF8Char;
  opts, unknown: POPTIONS;
  prog: array[0..40-1] of UTF8Char;
  unknown_name, dunno: PUTF8Char;

 procedure opt_begin;
 function opt_progname(const argv0 : PUTF8Char):PUTF8Char;
 function opt_path_end(const filename : PUTF8Char):PUTF8Char;
 function get_OPTIONS(name : PUTF8Char; retval : integer; valtype: UTF8Char; helpstr : PUTF8Char):  TOPTIONS;

function opt_next:integer;
function opt_isdir(const name: PUTF8Char): int;

function opt_int(const value : PUTF8Char; _result : PInteger):integer;
function opt_int_arg:integer;

procedure opt_number_error(const v : PUTF8Char);
function opt_intmax(const value : PUTF8Char;var _result : ossl_intmax_t):integer;
function opt_uintmax(const value : PUTF8Char;var _result : ossl_uintmax_t):integer;

function opt_format(const s : PUTF8Char; flags : Cardinal; _result : PInteger):integer;
function opt_format_error(const s : PUTF8Char; flags : Cardinal):integer;
 procedure opt_help(const list : POPTIONS);

function valtype2param(const o : POPTIONS):PUTF8Char;
procedure opt_print(const o : POPTIONS; doingparams, width : integer);
function opt_flag:PUTF8Char;
function opt_arg:PUTF8Char;
function opt_rest:PPUTF8Char;

function opt_num_rest:integer;

implementation


uses
     openssl3.test.testutil.options,
     OpenSSL3.common, libc.error, Character;


{$POINTERMATH ON}


function opt_num_rest:integer;
var
  i : integer;
  pp : PPUTF8Char;
begin
    i := 0;
    pp := opt_rest;
    while pp^ <> nil do
    begin
       Inc(pp);
       Inc(i);
       continue;
    end;
    Result := i;
end;



function opt_rest:PPUTF8Char;
begin
    Result := @&argv[opt_index];
end;

function opt_arg:PUTF8Char;
begin
    Result := arg;
end;

function opt_flag:PUTF8Char;
begin
    Result := flag;
end;


procedure opt_print(const o : POPTIONS; doingparams, width : integer);
var
  help : PUTF8Char;
  start : array[0..80] of UTF8Char;
  p, pname, pstart : PUTF8Char;
  I: int;
begin
    help := get_result(o.helpstr <>nil, o.helpstr , '(No additional info)');
    if o.name = OPT_HELP_STR then
    begin
        pname := @prog;
        opt_printf_stderr(help, [pname]);
        exit;
    end;
    if o.name = OPT_SECTION_STR then begin
        Write(#10);
        opt_printf_stderr(help, [prog]);
        exit;
    end;
    if o.name = OPT_PARAM_STR then begin
        Write(#10'Parameters:'#10);
        exit;
    end;
    { Pad out prefix }
    for I := Low(start) to High(start) do
        start[I] := ' ';
    //memset(@start, 32, sizeof(start) - Char_Size);
    start[length(start) - 1] := #0;
    if o.name = OPT_MORE_STR then begin
        start[width] := #0;
        opt_printf_stderr('%s  %s'#10, [@start, help]);
        exit;
    end;
    { Build up the '-flag [param]' part. }
//p指向静态数组start，数组成员将会变化
    p := @start;
    pstart := @start;
    PostInc(p)^ := ' ';
    if 0>=doingparams then
       PostInc(p)^ := '-';
    if o.name[0] <> #0 then
       //p  := p + (Length(strcpy(p, o.name)))
       Inc(p , Length(strcpy(p, o.name)))
    else
       PostInc(p)^ := '*';
    if o.valtype <> ('-') then
    begin
        PostInc(p)^ := ' ';
        //p  := p + (Length(strcpy(p, valtype2param(o))));
        Inc(p , Length(strcpy(p, valtype2param(o))));
    end;
    p^ := ' ';
    //指针偏移量
    if int(p - pstart) >= MAX_OPT_HELP_WIDTH then
    begin
        p^ := #0;
        opt_printf_stderr('%s'#10, [PUTF8Char(@start)]);
        for I := Low(start) to High(start) do
            start[I] := ' ';
    end;
    start[width] := #0;
    opt_printf_stderr('%s  %s'#10, [pstart, help]);
end;

function valtype2param(const o : POPTIONS):PUTF8Char;
begin
    case (o.valtype) of
    Chr(0),
    '-':
        Exit('');
    ':':
        Exit('uri');
    's':
        Exit('val');
    '/':
        Exit('dir');
    '<':
        Exit('infile');
    '>':
        Exit('outfile');
    'p':
        Exit('+int');
    'n':
        Exit('int');
    'l':
        Exit('long');
    'u':
        Exit('ulong');
    'E':
        Exit('PEM|DER|ENGINE');
    'F':
        Exit('PEM|DER');
    'f':
        Exit('format');
    'M':
        Exit('intmax');
    'N':
        Exit('nonneg');
    'U':
        Exit('uintmax');
    end;
    Result := 'parm';
end;



procedure opt_help(const list : POPTIONS);
var
  o               : POPTIONS;
  i,
  sawparams, width       : int;
  standard_prolog : Boolean;
  start           : array[0..(80 + 1)-1] of UTF8Char;
begin
    sawparams := 0; width := 5;
    { Starts with its own help message? }
    standard_prolog := list[0].name <> OPT_HELP_STR;
    { Find the widest help. }
    o := list;
    while o.name <> nil do
    begin
        if o.name = OPT_MORE_STR then
        begin
          Inc(o);
          continue;
        end;
        i := 2 + Length(o.name);
        if o.valtype <> ('-') then
           i  := i + (Char_Size + Length(valtype2param(o)));
        if (i < MAX_OPT_HELP_WIDTH)  and  (i > width) then
           width := i;
        assert(i < int(sizeof(start)));
        Inc(o);
    end;
    if standard_prolog then
    begin
        Writeln(Format('Usage: %s [options]', [prog]));
        if list[0].name <> OPT_SECTION_STR then
           Writeln(Format('Valid options are:', [prog]));
    end;
    { Now let's print. }
    o := list;
    while o.name <> nil  do
    begin
        if o.name = OPT_PARAM_STR then
           sawparams := 1;
        opt_print(o, sawparams, width);
        Inc(o);
    end;
end;


function opt_format_error(const s : PUTF8Char; flags : Cardinal):integer;
var
  ap : POPT_PAIR;
begin
    if flags = OPT_FMT_PEMDER then begin
        WriteLn(Format('%s: Bad format ''%s''; must be pem or der',
                          [prog, s]));
    end
    else
    begin
        WriteLn(Format('%s: Bad format ''%s''; must be one of:',
                          [prog, s]));
        ap := @formats;
        while ( ap.name <> nil) do
        begin
            if flags and ap.retval > 0 then
               WriteLn(Format('   %s', [ap.name]));
            Inc(ap);
        end;
    end;
    Result := 0;
end;



function opt_format(const s : PUTF8Char; flags : Cardinal; _result : PInteger):integer;
begin
    case  s^ of

      'D',
      'd':
       begin
          if flags and OPT_FMT_PEMDER = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_ASN1;
       end;
      'T',
      't':
       begin
          if flags and OPT_FMT_TEXT  = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_TEXT;
       end;
      'N',
      'n':
       begin
          if flags and OPT_FMT_NSS  = 0 then
              Exit(opt_format_error(s, flags));
          if (strcmp(s, 'NSS') <> 0)  and  (strcmp(s, 'nss') <> 0) then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_NSS;
       end;
      'S',
      's':
       begin
          if flags and OPT_FMT_SMIME  = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_SMIME;
       end;
      'M',
      'm':
       begin
          if flags and OPT_FMT_MSBLOB  = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_MSBLOB;
       end;
      'E',
      'e':
       begin
          if flags and OPT_FMT_ENGINE = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_ENGINE;
       end;
      'H',
      'h':
       begin
          if flags and OPT_FMT_HTTP  = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_HTTP;
       end;
      '1':
       begin
          if flags and OPT_FMT_PKCS12 = 0 then
              Exit(opt_format_error(s, flags));
          _result^ := FORMAT_PKCS12;
       end;
      'P',
      'p':
       begin
          if (s[1] = #0)  or  (strcmp(s, 'PEM') = 0)  or  (strcmp(s, 'pem') = 0)  then
          begin
              if (flags and OPT_FMT_PEMDER) = 0 then
                  Exit(opt_format_error(s, flags));
              _result^ := FORMAT_PEM;
          end
          else
          if (strcmp(s, 'PVK') = 0)  or  (strcmp(s, 'pvk') = 0)  then
          begin
              if flags and OPT_FMT_PVK  = 0 then
                  Exit(opt_format_error(s, flags));
              _result^ := FORMAT_PVK;
          end
          else
          if (strcmp(s, 'P12') = 0)  or  (strcmp(s, 'p12') = 0)
                      or  (strcmp(s, 'PKCS12') = 0)  or  (strcmp(s, 'pkcs12') = 0)  then
          begin
              if flags and OPT_FMT_PKCS12  = 0 then
                  Exit(opt_format_error(s, flags));
              _result^ := FORMAT_PKCS12;
          end
          else
          begin
              WriteLn(Format('%s: Bad format ''%s''', [prog, s]));
              Exit(0);
          end;
      end;
      else
      begin
         WriteLn(Format('%s: Bad format ''%s''', [prog, s]));
         Exit(0);
      end;
    end;
    Result := 1;
end;

function opt_ulong(const value : PUTF8Char; _result : Pulong):integer;
var
  oerrno : integer;
  endptr : PUTF8Char;

  l : Cardinal;
begin
    errno := _errno^;
    oerrno := errno;
    errno := 0;
    l := strtoul(value, @endptr, 0);
    if (endptr^ <> #0) or  (endptr = value)
             or  ( (l = ULONG_MAX) and  (errno = ERANGE) )
             or  ( (l = 0)  and  (errno <> 0) ) then
    begin
        opt_number_error(value);
        errno := oerrno;
        Exit(0);
    end;
    _result^ := l;
    errno := oerrno;
    Result := 1;
end;

function opt_long(const value : PUTF8Char; _result : Plong):integer;
var
  oerrno : integer;
  l : long;
  endp : PUTF8Char;
begin
    errno := _errno^;
    oerrno := errno;
    errno := 0;
    l := strtol(value, @endp, 0);
    if (endp^ <> #0)
             or  (endp = value)
             or  ( ( (l = LONG_MAX)  or  (l = LONG_MIN) )  and  (errno = ERANGE) )
             or  ( (l = 0)  and  (errno <> 0) ) then
    begin
        opt_number_error(value);
        errno := oerrno;
        Exit(0);
    end;
    _result^ := l;
    errno := oerrno;
    Exit(1);
end;



function opt_intmax(const value : PUTF8Char;var _result : ossl_intmax_t):integer;
var
  m : long;
  ret : integer;
begin
    ret := opt_long(value, @m);
    if ret > 0 then
        _result := m;
    Result := ret;
end;


function opt_uintmax(const value : PUTF8Char;var _result : ossl_uintmax_t):integer;
var
  m : Cardinal;
  ret : integer;
begin
    ret := opt_ulong(value, @m);
    if ret > 0 then
       _result := m;
    Result := ret;
end;


procedure opt_number_error(const v : PUTF8Char);
type
  strstr_pair_st = record
    prefix, name : PUTF8Char;
  end;
var
  i : size_t;
  prefix, name : PUTF8Char;
const
  b: array[0..2] of strstr_pair_st = (
      (prefix: '$';  name :'a hexadecimal'),
      (prefix: '0X'; name :'a hexadecimal'),
      (prefix: '0';  name :'an octal'));

begin
    i := 0;

    for i := 0 to length(b)-1 do
    begin
        if strncmp(v, b[i].prefix, Length(b[i].prefix)) = 0  then
        begin
            Writeln(Format('%s: Can''t parse ''%s'' as %s number',
                              [prog, v, b[i].name]));
            exit;
        end;
    end;
    Writeln(Format('%s: Can''t parse ''%s'' as a number', [prog, v]));
    exit;
end;


function opt_int(const value : PUTF8Char; _result : PInteger):integer;
var
  l : long;
begin
    if 0>=opt_long(value, @l) then
        Exit(0);
    _result^ := int(l);
    if _result^ <> l then begin
        Writeln(Format('%s: Value ''%s'' outside integer range'#10,
                          [prog, value]));
        Exit(0);
    end;
    Exit(1);
end;


function opt_int_arg:integer;
begin
    result := -1;
    opt_int(arg, @result);
end;



function opt_next:integer;
var
  p : PUTF8Char;
  o : POPTIONS;
  ival : integer;
  lval : long;
  ulval : Cardinal;
  imval : ossl_intmax_t;
  umval : ossl_uintmax_t;
  procedure _break;
  begin
    //nothing
  end;
begin
    arg := nil;
    p := argv[opt_index];
    if (p = nil) or (p = '') then Exit(0);
    { If word doesn't start with a -, we're done. }
    if p^ <> '-' then Exit(0);
    { Hit '--' ? We're done. }
    PostInc(opt_index);
    if strcmp(p, '--' ) = 0 then
        Exit(0);
    { Allow -nnn and PreDec(nnn) }
    if PreInc(p)^ = '-' then
        PostInc(p);
    flag := p - 1;
    { If we have PreDec(flag)=foo, snip it off }
    arg := strchr(p, '=');
    if arg <> nil then
        PostInc(arg)^ := #0;
    o := opts;
    while o.name <> nil do
    begin
        { If not this option, move on to the next one. }
        if (not ( (strcmp(p, 'h') = 0)  and  (strcmp(o.name, 'help') = 0)) )
                 and  (strcmp(p, o.name) <> 0) then
        begin
            Inc(o);
            continue;
        end;

        { If it doesn't take a value, make sure none was given. }
        if (o.valtype = Chr(0))  or  (o.valtype = ('-')) then
        begin
            if arg <> nil then
            begin
                Writeln(Format('%s: Option -%s does not take a value'#10,
                                  [prog, p]));
                Exit(-1);
            end;
            Exit(o.retval);
        end;
        if arg = nil then
        begin
            if argv[opt_index] = nil then
            begin
                Writeln(Format('%s: Option -%s needs a value'#10,
                                  [prog, o.name]));
                Exit(-1);
            end;
            arg := {ParamStr}argv[PostInc(opt_index)];
        end;
        { Syntax-check value. }
        case (o.valtype) of

            's',
            ':':
                { Just a string. }
                _break;
            '.':
                { Parameters }
                _break;
            '/':
            begin
                if opt_isdir(arg)  > 0 then
                    break;
                Writeln(Format('%s: Not a directory: %s'#10, [prog, arg]));
                Exit(-1);
            end;
            '<':
                { Input file. }
                _break;
            '>':
                { Output file. }
                _break;
            'p',
            'n',
            'N':
            begin
                if 0>=opt_int(arg, @ival) then
                    Exit(-1);
                if (o.valtype = ('p'))  and  (ival <= 0) then
                begin
                    Writeln(Format('%s: Non-positive number ''%s'' for option -%s'#10,
                                      [prog, arg, o.name]));
                    Exit(-1);
                end;
                if (o.valtype = ('N'))  and  (ival < 0) then
                begin
                    Writeln(Format('%s: Negative number ''%s'' for option -%s'#10,
                                      [prog, arg, o.name]));
                    Exit(-1);
                end;
            end;
            'M':
                if 0>=opt_intmax(arg, &imval) then
                    Exit(-1);
                //break;
            'U':
                if 0>=opt_uintmax(arg, &umval )then
                    Exit(-1);
                //break;
            'l':
                if 0>=opt_long(arg, @lval) then
                    Exit(-1);
                //break;
            'u':
                if 0>=opt_ulong(arg, @ulval) then
                    Exit(-1);
                //break;
            'c',
            'E',
            'F',
            'f':
            begin
                if opt_format(arg,
                              get_result(o.valtype = ('c') , OPT_FMT_PDS ,
                              get_result( o.valtype = ('E') , OPT_FMT_PDE ,
                              get_result( o.valtype = ('F') , OPT_FMT_PEMDER
                               , OPT_FMT_ANY))), @ival) > 0 then
                    break;
                writeln(Format('%s: Invalid format ''%s'' for option -%s',
                                  [prog, arg, o.name]));
                Exit(-1);
            end;
            else
            begin
              //
            end;
        end;
        { Return the flag value. }
        Exit(o.retval);
    end;


    if unknown <> nil then
    begin
        if dunno <> nil then
        begin
            writeln(Format('%s: Multiple %s or unknown options: -%s and -%s',
                              [prog, unknown_name, dunno, p]));
            Exit(-1);
        end;
        dunno := p;
        Exit(unknown.retval);
    end;
    writeln(Format('%s: Unknown option: -%s', [prog, p]));
    Result := -1;
end;

function get_OPTIONS(
    name : PUTF8Char;
    retval : integer;
    valtype: UTF8Char;
    helpstr : PUTF8Char):  TOPTIONS;
begin
   Result.name := name;
    Result.retval := retval;
    Result.valtype := valtype;
    Result.helpstr := helpstr;
end;


function opt_path_end(const filename : PUTF8Char):PUTF8Char;
var
  p : PUTF8Char;
begin
    { Could use strchr, but this is like the ones above. }
    p := filename + Length(filename);
    while ( PreDec(p) > filename) do
        if (p^ = '/') or (p^ = '\') or (p^ = ':') then
        begin
            Inc(p);
            break;
        end;
    Result := p;
end;


function opt_progname(const argv0 : PUTF8Char):PUTF8Char;
var
  i, n : size_t;
  p, q : PUTF8Char;
begin
    p := opt_path_end(argv0);
    { Strip off trailing nonsense. }
    n := Length(p);
    if (n > 4)  and
       ( (strcmp(@p[n - 4], '.exe') = 0)  or  (strcmp(@p[n - 4], '.EXE') = 0)) then
        n  := n - 4;
    { Copy over the name, in lowercase. }
    if n > sizeof(prog) - Char_Size then
        n := sizeof(prog) - Char_Size;
    q := prog; i := 0;
    while (i < n) do
    begin
       {$IFDEF FPC}
       PostInc(q)^ := tolower( p^);
       {$ELSE}
       PostInc(q)^ := UTF8Char(tolower(Ord( p^)));
       {$ENDIF}
        PostInc(i); PostInc(p);
    end;
    q^ := #0;
    Result := prog;
end;




procedure opt_begin;
begin
    opt_index := 1;
    arg := nil;
    flag := nil;
end;

function opt_init(ac : integer; av : PPUTF8Char;const o : POPTIONS):PUTF8Char;
var
  next       : POPTIONS;
  duplicated : Boolean;
  i          : UTF8Char;
begin
    { Store state. }
    argc := ac;
    argv := av;
    opt_begin();

    opts := o;
    unknown := nil;
    { Make sure prog name is set for usage output }
    opt_progname(argv[0]);
    { Check all options up until the PARAM marker (if present) }
    while (opts.name <> nil)  and  (opts.name <> OPT_PARAM_STR) do
    begin
        if (opts.name = OPT_HELP_STR) or  (opts.name = OPT_MORE_STR)
                 or  (opts.name = OPT_SECTION_STR) then
        begin
           Inc(opts);
           continue;
        end;

{$IFNDEF NDEBUG}
        i := (opts.valtype);
        { Make sure options are legit. }
        assert(opts.name[0] <> '-');
        if opts.valtype = ('.') then
           assert(opts.retval = OPT_PARAM)
        else
           assert( (opts.retval = OPT_DUP)  or  (opts.retval > OPT_PARAM));
        case i of
          Chr(0),
          '-',
          '.',
          '/',
          '<',
          '>',
          'E',
          'F',
          'M',
          'U',
          'f',
          'l',
          'n',
          'p',
          's',
          'u',
          'c',
          ':',
          'N':
          begin
             //break;
          end;
          else
              assert(Boolean(0));
        end;
        { Make sure there are no duplicates. }
        next := opts + 1;
        while next.name <> nil do
        begin
            {
             * Some compilers inline strcmp and the assert string is too long.
             }
            duplicated := (next.retval <> OPT_DUP) and (strcmp(opts.name, next.name) = 0);

            if duplicated then begin
                writeln(Format('%s: Internal error: duplicate option %s'#10,
                                  [prog, opts.name]));
                assert(not duplicated);
            end;
            Inc(next);
        end;
{$ENDIF}
        if opts.name[0] = #0 then
        begin
            assert(unknown_name <> nil);
            assert(unknown = nil);
            unknown := opts;
            assert( (unknown.valtype = chr(0))  or  (unknown.valtype = ('-')) );
        end;
        Inc(opts);
    end;
    Result := prog;
    //回到初始位置
    opts := o;
end;

(* opt_isdir section *)
function opt_isdir(const name: PUTF8Char): int;
var
  attr: DWORD ;
  i, len_0: size_t;
  tempname: array[0..MAX_PATH-1] of WIDECHAR;
begin

{$if defined(_UNICODE_) or defined(_UNICODE)}
    len_0 := strlen(name) + 1;
    if (len_0 > MAX_PATH) then
        exit( -1);

    for i := 0 to len_0 -1 do
        tempname[i] := WideCHAR(name[i]);

    attr := GetFileAttributes(@tempname);
{$else}
    attr := GetFileAttributes(name);
{$endif}
    if (attr = INVALID_FILE_ATTRIBUTES) then
        Exit( -1);
    Result := Int((attr and FILE_ATTRIBUTE_DIRECTORY) <> 0);
end;



end.
