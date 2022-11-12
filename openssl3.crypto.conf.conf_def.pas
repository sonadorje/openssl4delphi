unit openssl3.crypto.conf.conf_def;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils
    {$IFDEF  MSWINDOWS}, libc.win {$ENDIF};

const
   CONF_NUMBER       =1;
   CONF_UPPER        =2;
   CONF_LOWER        =4;
   CONF_UNDER        =256;
   CONF_PUNCT        =512;
   CONF_WS           =16;
   CONF_ESC          =32;
   CONF_QUOTE        =64;
   CONF_DQUOTE       =1024;
   CONF_COMMENT      =128;
   CONF_FCOMMENT     =2048;
   CONF_DOLLAR       =4096;
   CONF_EOF          =8;
   CONF_ALPHA        =(CONF_UPPER or CONF_LOWER);
   CONF_ALNUM        =(CONF_ALPHA or CONF_NUMBER or CONF_UNDER);
   CONF_ALNUM_PUNCT  =(CONF_ALPHA or CONF_NUMBER or CONF_UNDER or CONF_PUNCT);

   MAX_CONF_VALUE_LENGTH = 65536;
   CONF_type_default: array[0..128-1] of UInt16 = (
    $0008, $0000, $0000, $0000, $0000, $0000, $0000, $0000,
    $0000, $0010, $0010, $0000, $0000, $0010, $0000, $0000,
    $0000, $0000, $0000, $0000, $0000, $0000, $0000, $0000,
    $0000, $0000, $0000, $0000, $0000, $0000, $0000, $0000,
    $0010, $0200, $0040, $0080, $1000, $0200, $0200, $0040,
    $0000, $0000, $0200, $0200, $0200, $0200, $0200, $0200,
    $0001, $0001, $0001, $0001, $0001, $0001, $0001, $0001,
    $0001, $0001, $0000, $0200, $0000, $0000, $0000, $0200,
    $0200, $0002, $0002, $0002, $0002, $0002, $0002, $0002,
    $0002, $0002, $0002, $0002, $0002, $0002, $0002, $0002,
    $0002, $0002, $0002, $0002, $0002, $0002, $0002, $0002,
    $0002, $0002, $0002, $0000, $0020, $0000, $0200, $0100,
    $0040, $0004, $0004, $0004, $0004, $0004, $0004, $0004,
    $0004, $0004, $0004, $0004, $0004, $0004, $0004, $0004,
    $0004, $0004, $0004, $0004, $0004, $0004, $0004, $0004,
    $0004, $0004, $0004, $0000, $0200, $0000, $0200, $0000
);
type
  Tconf_def_fn = procedure(const p1: PCONF_VALUE; p2: PBIO);

  function NCONF_default:PCONF_METHOD;
  function def_create( meth : PCONF_METHOD):PCONF;
  function def_init_default( conf : PCONF):integer;
  function def_destroy( conf : PCONF):integer;
  function def_destroy_data( conf : PCONF):integer;
  function def_load(conf : PCONF;const name : PUTF8Char; line : Plong):integer;
  function def_load_bio( conf : PCONF; _in : PBIO; line : Plong):integer;
  function def_dump(const conf : PCONF; _out : PBIO):integer;
  function def_is_number(const conf : PCONF; c :UTF8Char):integer;
  function def_to_int(const conf : PCONF; c :UTF8Char):integer;

const
  default_method: TCONF_METHOD  = (
    name: 'OpenSSL default';
    create: def_create;
    init: def_init_default;
    destroy: def_destroy;
    destroy_data: def_destroy_data;
    load_bio: def_load_bio;
    dump: def_dump;
    is_number: def_is_number;
    to_int: def_to_int;
    load: def_load
);


const
  CONFBUFSIZE = 512;


procedure dump_value_doall_arg(const a : PCONF_VALUE; _out : PBIO);
procedure trim_ws( conf : PCONF; start : PUTF8Char);
procedure lh_CONF_VALUE_doall_BIO( lh : Plhash_st_CONF_VALUE;fn: Tconf_def_fn; arg : PBIO);
procedure clear_comments( conf : PCONF; p : PUTF8Char);

function IS_NUMBER(conf: PCONF;c:UTF8Char): int;
function is_keytype(const conf : PCONF; c :UTF8Char; _type : uint16):int;
function get_next_file(const path : PUTF8Char;dirctx : PPOPENSSL_DIR_CTX):PBIO;
function IS_ESC(conf: PCONF; c:UTF8Char): Boolean;
function IS_FCOMMENT(conf: PCONF; c:UTF8Char): int;
function IS_WS(conf: PCONF; c:UTF8Char): int;
function IS_COMMENT(conf: PCONF; c:UTF8Char): int;
function IS_DQUOTE(conf: PCONF; c:UTF8Char): int;
function scan_dquote( conf : PCONF; p : PUTF8Char):PUTF8Char;
function scan_quote( conf : PCONF; p : PUTF8Char):PUTF8Char;
function IS_EOF(conf: PCONF; c:UTF8Char): int;
function scan_esc(conf : PCONF; p : PUTF8Char):PUTF8Char;
function eat_ws( conf : PCONF; p : PUTF8Char):PUTF8Char;
function eat_alpha_numeric( conf : PCONF; p : PUTF8Char):PUTF8Char;
function IS_ALNUM_PUNCT(conf: PCONF; c:UTF8Char): int;
function IS_DOLLAR(conf: PCONF; c:UTF8Char): int;
function str_copy( conf : PCONF; section : PUTF8Char;var pto : PUTF8Char; from : PUTF8Char):int;
function parsebool(const pval : PUTF8Char; flag : PInteger):integer;
function process_include( include : PUTF8Char; dirctx : PPOPENSSL_DIR_CTX; dirpath : PPUTF8Char):PBIO;
function S_ISDIR(a: Word): Boolean;
function _BUF_MEM_grow( str : PBUF_MEM; len : size_t):size_t;
implementation

uses openssl3.crypto.lhash,                      openssl3.crypto.bio.bio_print,
     openssl3.crypto.conf.conf_api,              openssl3.crypto.bio.bio_lib,
     openssl3.crypto.getenv,                     openssl3.crypto.conf.conf_lib,
     openssl3.crypto.mem,                        openssl3.crypto.bio.bss_file,
     OpenSSL3.Err,directory_win,                 openssl3.crypto.buffer.buffer,
     OpenSSL3.common,                            openssl3.crypto.o_str;

function S_ISDIR(a: Word): Boolean;
begin
   Result := (a and S_IFMT) = S_IFDIR;
end;

function process_include( include : PUTF8Char; dirctx : PPOPENSSL_DIR_CTX; dirpath : PPUTF8Char):PBIO;
var
  st : Tstat;
  next : PBIO;
begin
    if stat(PAnsiChar(include), @st)  < 0 then
    begin
        ERR_raise_data(ERR_LIB_SYS, _errno, Format(' calling stat(%s)' , [include]));
        { missing include file is not fatal error }
        Exit(nil);
    end;
    if S_ISDIR(st.st_mode) then
    begin
        if dirctx^ <> nil then
        begin
            ERR_raise_data(ERR_LIB_CONF, CONF_R_RECURSIVE_DIRECTORY_INCLUDE,
                          Format(' %s' , [include]));
            Exit(nil);
        end;
        { a directory, load its contents }
        next := get_next_file(include, dirctx);
        if next <> nil then
           dirpath^ := include;
        Exit(next);
    end;
    next := BIO_new_file(include, ' r' );
    Result := next;
end;


function parsebool(const pval : PUTF8Char; flag : PInteger):integer;
begin
    if (strcasecmp(pval, ' on') = 0) or  (strcasecmp(pval, ' true' ) = 0) then
    begin
        flag^ := 1;
    end
    else
    if (strcasecmp(pval, ' off' ) = 0) or  (strcasecmp(pval, ' false' ) = 0) then
    begin
        flag^ := 0;
    end
    else
    begin
        ERR_raise(ERR_LIB_CONF, CONF_R_INVALID_PRAGMA);
        Exit(0);
    end;
    Result := 1;
end;

procedure trim_ws( conf : PCONF; start : PUTF8Char);
var
  p : PUTF8Char;
begin
    p := start;
    while 0>= IS_EOF(conf, p^) do
        Inc(p);
    Dec(p);
    while (p >= start)  and  (IS_WS(conf, p^)>0) do
        Dec(p);
    Inc(p);
    p^ := #0;
end;

function IS_ALNUM(conf: PCONF; c:UTF8Char): int;
begin
   Result :=  is_keytype(conf, c, CONF_ALNUM)
end;

function IS_QUOTE(conf: PCONF; c:UTF8Char): int;
begin
   Result := is_keytype(conf, c, CONF_QUOTE)
end;


function str_copy( conf : PCONF; section : PUTF8Char;var pto : PUTF8Char; from : PUTF8Char):int;
var
  rr, r, q: UTF8Char;
  _to, len : integer;
  s, e, rp, p, rrp, np, cp : PUTF8Char;
  v :UTF8Char;
  _buf : PBUF_MEM;
  newsize : size_t;
  label _err;
begin
    rr := #0;
    _to := 0;
    len := 0;
    _buf := BUF_MEM_new();
    if _buf = nil then
        Exit(0);

    len := StrSize(from);
    if 0>= _BUF_MEM_grow(_buf, len) then
        goto _err ;
    while true do
    begin
        if IS_QUOTE(conf, from^) > 0 then
        begin
            q := (from^);
            Inc(from);
            while (0>= IS_EOF(conf, from^))  and  (from^ <> q) do
            begin
                if IS_ESC(conf, from^)  then
                begin
                    Inc(from);
                    if IS_EOF(conf, from^) > 0 then
                        break;
                end;
                _buf.data[PostInc(_to)] := PostInc(from)^;
            end;
            if (from^) = q then
               Inc(from);
        end
        else
        if (IS_DQUOTE(conf, from^)>0) then
        begin
            q := (from^);
            Inc(from);
            while 0>= IS_EOF(conf, from^) do
            begin
                if (from^) = q then
                begin
                    if (from + 1)^ = (q) then
                    begin
                        Inc(from);
                    end
                    else
                    begin
                        break;
                    end;
                end;
                _buf.data[PostInc(_to)] := PostInc(from)^;
            end;
            if (from^) = q then
               Inc(from);
        end
        else
        if IS_ESC(conf, from^)  then
        begin
            Inc(from);
            v := PostInc(from)^;
            if IS_EOF(conf, v) > 0 then
                break
            else if (v = 'r')  then
                v := #13
            else if (v = 'n') then
                v := #10
            else if (v = 'b') then
                v := {Backspace} #8
            else if (v = 't') then
                v := #9;
            _buf.data[PostInc(_to)] := v;
        end
        else
        if (IS_EOF(conf, from^) > 0) then
            break
        else
        if ( from^ = '$') and
           ( (0>= conf.flag_dollarid) or (from[1] = '{')  or  (from[1] = '(') ) then
        begin
            { try to expand it }
            rrp := nil;
            s := @(from[1]);
            if (s^ = '{') then
               q := '}'
            else if ( s^ = '(')  then
                q := ')'
            else
                q := Chr(0);
            if Ord(q) > 0 then
               Inc(s);
            cp := section;
            e := s; np := s;
            while (IS_ALNUM(conf, e^) > 0)
                or ( (conf.flag_dollarid>0)  and  (IS_DOLLAR(conf, e^)>0) ) do
                Inc(e);
            if (e[0] = ':') and  (e[1] = ':') then
            begin
                cp := np;
                rrp := e;
                rr :=  e^;
                rrp^ := #0;
                e  := e + 2;
                np := e;
                while (IS_ALNUM(conf, e^)>0)
                        or ( (conf.flag_dollarid>0)  and  (IS_DOLLAR(conf, e^)>0) ) do
                    Inc(e);
            end;
            r := e^;
            e^ := #0;
            rp := e;
            if Ord(q) > 0 then
            begin
                if r <> q then
                begin
                    ERR_raise(ERR_LIB_CONF, CONF_R_NO_CLOSE_BRACE);
                    goto _err ;
                end;
                Inc(e);
            end;
            {-
             * So at this point we have
             * np which is the start of the name string which is
             *   #0 terminated.
             * cp which is the start of the section string which is
             *   #0 terminated.
             * e is the 'next point after'.
             * r and rr are theUTF8Chars replaced by the #0
             * rp and rrp is where 'r' and 'rr' came from.
             }
            p := _CONF_get_string(conf, cp, np);
            if rrp <> nil then
               rrp^ := rr;
            rp^ := r;
            if p = nil then
            begin
                ERR_raise(ERR_LIB_CONF, CONF_R_VARIABLE_HAS_NO_VALUE);
                goto _err ;
            end;
            newsize := StrSize(p) + _buf.length - (e - from)*Char_Size;
            if newsize > MAX_CONF_VALUE_LENGTH then
            begin
                ERR_raise(ERR_LIB_CONF, CONF_R_VARIABLE_EXPANSION_TOO_LONG);
                goto _err ;
            end;
            if 0>= BUF_MEM_grow_clean(_buf, newsize) then
            begin
                ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            while p^ <> #0 do
                _buf.data[PostInc(_to)] := PostInc(p)^;
            {
             * Since we change the pointer 'from', we also have to change the
             * perceived length of the string it points at.  /RL
             }
            len  := len - (e - from)*Char_Size;
            from := e;
            {
             * In case there were no braces or parenthesis around the
             * variable reference, we have to put back theUTF8Character that was
             * replaced with a #0.  /RL
             }
            rp^ := r;
        end
        else
            _buf.data[PostInc(_to)] := PostInc(from)^;
    end; //-->while true

    _buf.data[_to] := #0;
    OPENSSL_strdup(pto, _buf.data);
    _buf^ := default(TBUF_MEM);
    _buf:= nil;
    Free(_buf);
    Exit(1);

 _err:
    BUF_MEM_free(_buf);
    Exit(0);
end;


function IS_DOLLAR(conf: PCONF; c:UTF8Char): int;
begin
   Result := is_keytype(conf, c, CONF_DOLLAR)
end;

function IS_ALNUM_PUNCT(conf: PCONF; c:UTF8Char): int;
begin
  Result := is_keytype(conf, c, CONF_ALNUM_PUNCT)
end;


function eat_alpha_numeric( conf : PCONF; p : PUTF8Char):PUTF8Char;
begin
    while true do
    begin
        if IS_ESC(conf, p^)  then
        begin
            p := scan_esc(conf, p);
            continue;
        end;
        if (not (IS_ALNUM_PUNCT(conf, p^)>0))  or
           ( (conf.flag_dollarid > 0)  and  (IS_DOLLAR(conf, p^) > 0) ) then
            Exit(p);
        PostInc(p);
    end;
end;



function eat_ws( conf : PCONF; p : PUTF8Char):PUTF8Char;
begin
    while (IS_WS(conf, p^)>0)  and  (0>= IS_EOF(conf, p^)) do
        Inc(p);
    Result := p;
end;

function scan_esc(conf : PCONF; p : PUTF8Char):PUTF8Char;
begin
   Result := get_result(IS_EOF(conf, p[1]) > 0, p+1, p+2)
end;

function IS_EOF(conf: PCONF; c:UTF8Char): int;
begin
   Result := is_keytype(conf, c, CONF_EOF)
end;


function scan_quote( conf : PCONF; p : PUTF8Char):PUTF8Char;
var
  q : integer;
begin
    q := Ord(p^);
    Inc(p);
    while (not (IS_EOF(conf, p^) > 0))  and  ( Ord(p^) <> q) do
    begin
        if IS_ESC(conf, p^)  then
        begin
            Inc(p);
            if IS_EOF(conf, p^) > 0 then
                Exit(p);
        end;
        Inc(p);
    end;
    if Ord(p^) = q then
       Inc(p);
    Result := p;
end;


function scan_dquote( conf : PCONF; p : PUTF8Char):PUTF8Char;
var
  q : integer;
begin
    q := Ord(p^);
    Inc(p);
    while 0>= (IS_EOF(conf, p^)) do
    begin
        if Ord(p^) = q then
        begin
            if (p + 1)^ = UTF8Char(q) then
            begin
                Inc(p);
            end
            else
            begin
                break;
            end;
        end;
        Inc(p);
    end;
    if Ord(p^) = q then
       Inc(p);
    Result := p;
end;

function IS_DQUOTE(conf: PCONF; c:UTF8Char): int;
begin
   Result :=  is_keytype(conf, c, CONF_DQUOTE)
end;

function  IS_COMMENT(conf: PCONF; c:UTF8Char): int;
begin
  Result := is_keytype(conf, c, CONF_COMMENT)
end;

function IS_WS(conf: PCONF; c:UTF8Char): int;
begin
   Result :=  is_keytype(conf, c, CONF_WS)
end;

function IS_FCOMMENT(conf: PCONF; c:UTF8Char): int;
begin
  Result :=    is_keytype(conf, c, CONF_FCOMMENT)
end;

procedure clear_comments( conf : PCONF; p : PUTF8Char);
begin
    while true do
    begin
        if IS_FCOMMENT(conf, p^) > 0 then begin
            p^ := #0;
            Exit;
        end;
        if not (IS_WS(conf, p^) > 0) then begin
            break;
        end;
        Inc(p);
    end;
    while true do
    begin
        if IS_COMMENT(conf, p^) > 0 then begin
            p^ := #0;
            exit;
        end;
        if IS_DQUOTE(conf, p^) > 0 then begin
            p := scan_dquote(conf, p);
            continue;
        end;
        if IS_QUOTE(conf, p^) > 0 then begin
            p := scan_quote(conf, p);
            continue;
        end;
        if IS_ESC(conf, p^)  then begin
            p := scan_esc(conf, p);
            continue;
        end;
        if IS_EOF(conf, p^) > 0 then
            Exit
        else
            Inc(p);
    end;
end;

function IS_ESC(conf: PCONF; c:UTF8Char): Boolean;
begin
   Result := Boolean(is_keytype(conf, c, CONF_ESC))
end;


function get_next_file(const path : PUTF8Char;dirctx : PPOPENSSL_DIR_CTX):PBIO;
var
  filename : PUTF8Char;
  pathlen,
  namelen,
  newlen   : size_t;
  newpath  : PUTF8Char;
  bio      : PBIO;
  function get_filename: PUTF8Char;
  begin
     filename := OPENSSL_DIR_read(dirctx, path);
     Result := filename;
  end;
  begin
    pathlen := StrSize(path);
    while (get_filename  <> nil) do
    begin
        namelen := StrSize(filename);
        if ( (namelen > 5)  and  (strcasecmp(filename + namelen - 5, ' .conf') = 0) ) or
           ( (namelen > 4)  and  (strcasecmp(filename + namelen - 4, ' .cnf' ) = 0) ) then
        begin
            newlen := pathlen + namelen + 2;
            newpath := OPENSSL_zalloc(newlen);
            if newpath = nil then
            begin
                ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                break;
            end;
{$IFDEF OPENSSL_SYS_VMS}
            {
             * If the given path isn't clear VMS syntax,
             * we treat it as on Unix.
             }
            if path[pathlen - 1] = ']'
                 or  path[pathlen - 1] = '>'
                 or  path[pathlen - 1] = ':' then
            begin
                { Clear VMS directory syntax, just copy as is }
                OPENSSL_strlcpy(newpath, path, newlen);
            end;
{$ENDIF}
            if newpath[0] = #0 then
            begin
                OPENSSL_strlcpy(newpath, path, newlen);
                OPENSSL_strlcat(newpath, ' /' , newlen);
            end;
            OPENSSL_strlcat(newpath, filename, newlen);
            bio := BIO_new_file(newpath, ' r' );
            OPENSSL_free(Pointer(newpath));
            { Errors when opening files are non-fatal. }
            if bio <> nil then Exit(bio);
        end;
    end;
    OPENSSL_DIR_end(dirctx);
    dirctx^ := nil;
    Result := nil;
end;

function is_keytype(const conf : PCONF; c :UTF8Char; _type : uint16):int;
var
    keytypes : PUint16;
    key      : Byte;
begin
{$POINTERMATH ON}
   keytypes := PUint16(conf.meth_data);
    key := ord( c);
{$IFDEF CharSET_EBCDIC}
{$IF Char_BIT > 8}
    if key > 255 then begin
        { key is out of range for os_toascii table }
        Exit(0);
    end;
{$ENDIF}
    { convert key from ebcdic to ascii }
    key := os_toascii[key];
{$ENDIF}
    if key > 127 then
    begin
        { key is not a seven bit asciiUTF8Character }
        Exit(0);
    end;
    Result := get_result((keytypes[key] and _type) > 0, 1 , 0);
{$POINTERMATH OFF}
end;

function IS_NUMBER(conf: PCONF;c:UTF8Char): int;
begin
   Result :=  is_keytype(conf, c, CONF_NUMBER)
end;

procedure dump_value_doall_arg(const a : PCONF_VALUE; _out : PBIO);
begin
    if a.name <> nil then
       BIO_printf(_out, ' [%s] %s=%s'#10 , [a.section, a.name, a.value])
    else
        BIO_printf(_out, ' [[%s]]'#10 , [a.section]);
end;

procedure lh_CONF_VALUE_doall_BIO( lh : Plhash_st_CONF_VALUE;fn: Tconf_def_fn; arg : PBIO);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNCARG(fn), Pointer( arg));
end;



function def_dump(const conf : PCONF; _out : PBIO):integer;
begin
    lh_CONF_VALUE_doall_BIO(conf.data, dump_value_doall_arg, _out);
    Result := 1;
end;


function def_is_number(const conf : PCONF; c :UTF8Char):integer;
begin
    Result := IS_NUMBER(conf, c);
end;


function def_to_int(const conf : PCONF; c :UTF8Char):integer;
begin
    Result := Ord(c) - Ord('0');
end;


function _BUF_MEM_grow( str : PBUF_MEM; len : size_t):size_t;
var
  ret : TArray<UTF8Char>;
  n : size_t;
begin

    if str.length >= len then
    begin
        str.length := len;
        Exit(len);
    end;
    if str.max >= len then
    begin
        if str.data <> nil then
        begin
           memset(@str.data[str.length], 0, len - str.length);
        end;
        str.length := len;
        Exit(len);
    end;
    // This limit is sufficient to ensure (len+3)/3*4 < 2**31
    if len > LIMIT_BEFORE_EXPANSION then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    n := (len + 3) div 3 * 4;
    if (str.flags and BUF_MEM_FLAG_SECURE) > 0  then
    begin
        ret := sec_alloc_realloc(str, n);
        Str.buffer := ret;
        str.data := @str.buffer[0];
    end
    else
    begin
        if (str.data = nil) then
        begin
           if n > 0 then
           begin
              Setlength(str.buffer, n);
              //memset(str.buffer, Ord(' '),n);
              str.data := @str.buffer[0];
           end;
        end
        else
        begin
           if n = 0 then
           begin
              Setlength(str.buffer, 0);
              str.data := nil;
           end;

        end;

    end;

    if str.data = nil then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        len := 0;
    end
    else
    begin
        str.max := n;
        //memset(@str.data[str.length], 0, len - str.length);
        str.length := len;

    end;
    Result := len;
end;

function def_load_bio( conf : PCONF; _in : PBIO; line : Plong):integer;
const
   DECIMAL_SIZE = ((sizeof(Long)*8+2) div 3 + 1);
var
  bufnum, i, ii: integer;
  buff         : PBUF_MEM;
  s, p, _end   : PUTF8Char;
  again,
  first_call   : integer;
  eline        : long;
  btmp         : array[0..(DECIMAL_SIZE + 1)-1] of UTF8Char;
  v            : PCONF_VALUE;
  tv,sv        : PCONF_VALUE;
  section, buf,
  start,
  psection,
  pname        : PUTF8Char;
  h            : Pointer;
  biosk        : Pstack_st_BIO;
  dirpath      : PUTF8Char;
  dirctx       : POPENSSL_DIR_CTX;
  utf8_bom     : array{[0..2]} of Byte;
  parent,
  next         : PBIO;
  ss,  pval,
  include      : PUTF8Char;
  include_dir,
  include_path : PUTF8Char;
  newlen       : size_t;
  popped       : PBIO;
  str: string;
  label _err, _read_retry, _again;
begin
{ The macro BUFSIZE conflicts with a system macro in VxWorks }
{$POINTERMATH ON}
    FillChar(btmp, sizeof(btmp), #0);
    bufnum := 0;
    buff := nil;
    first_call := 1;
    eline := 0;
    v := nil;
    sv := nil;
    section := nil;
    h := conf.data;
    biosk := nil;
{$IFNDEF OPENSSL_NO_POSIX_IO}
    dirpath := nil;
    dirctx := nil;
{$ENDIF}
    buff := BUF_MEM_new();
    if buff = nil then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_BUF_LIB);
        goto _err ;
    end;
    OPENSSL_strdup(section,'default' );

    if section = nil then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if _CONF_new_data(conf) = 0  then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    sv := _CONF_new_section(conf, section);
    if sv = nil then
    begin
        ERR_raise(ERR_LIB_CONF, CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
        goto _err ;
    end;
    bufnum := 0;
    again := 0;
    while true do
    begin
        if 0>= _BUF_MEM_grow(buff, bufnum + CONFBUFSIZE) then
        begin
            ERR_raise(ERR_LIB_CONF, ERR_R_BUF_LIB);
            goto _err ;
        end;

        p := @buff.data[bufnum];
        p^ := #0;

 _read_retry:
        if (_in <> nil)  and (BIO_gets(_in, p, CONFBUFSIZE - 1) < 0)  then
            goto _err ;
        p[CONFBUFSIZE - 1] := #0;
        ii := Length(p);
        i := ii;
        if first_call > 0 then
        begin
            { Other BOMs imply unsupported multibyte encoding,
             * so don't strip them and let the error raise }
            utf8_bom := [$EF, $BB, $BF];

            if (i >= 3)  and  (memcmp(p, utf8_bom, 3) = 0) then
            begin
                memmove(p, p + 3, i - 3);
                p[i - 3] := Chr(0);
                i  := i - 3;
                ii  := ii - 3;
            end;
            first_call := 0;
        end;
        if (i = 0)  and  (0>= again) then
        begin
            { the currently processed BIO is nil or at EOF }
{$IFNDEF OPENSSL_NO_POSIX_IO}
            { continue processing with the next file from directory }
            if dirctx <> nil then
            begin
                next := get_next_file(dirpath, @dirctx);
                if (next <> nil) then
                begin
                    BIO_vfree(_in);
                    _in := next;
                    goto _read_retry ;
                end
                else
                begin
                    OPENSSL_free(Pointer(dirpath));
                    dirpath := nil;
                end;
            end;
{$ENDIF}
            { no more files in directory, continue with processing parent }
            parent := sk_BIO_pop(biosk);
            if parent = nil then
            begin
                { everything processed get out of the loop }
                break;
            end
            else
            begin
                BIO_vfree(_in);
                _in := parent;
                goto _read_retry ;
            end;
        end;
        again := 0;
        while i > 0 do
        begin
            if (p[i - 1] <> #13)  and  (p[i - 1] <> #10) then
                break
            else
                Dec(i);
        end;
        {
         * we removed some trailing stuff so there is a new line on the end.
         }
        if (ii > 0) and  (i = ii) then
           again := 1          { long line }
        else
        begin
            p[i] := #0;
            Inc(eline);            { another input line }
        end;
        { we now have a line with trailing \r\n removed }
        { i is the number of bytes }
        bufnum := bufnum + i;
        //v := nil;
        { check for line continuation }
        if bufnum >= 1 then
        begin
            {
             * If we have bytes and the lastUTF8Char \ and second lastUTF8Char
             * is not \
             }
            p := @buff.data[bufnum - 1];
            //p := @buff.buffer[bufnum - 1];
            if (IS_ESC(conf, p[0]))  and  ((bufnum <= 1)  or  (not IS_ESC(conf, p[-1]))) then
            begin
                Dec(bufnum);
                again := 1;
            end;
        end;
        if again > 0 then continue;
        bufnum := 0;
        buf := buff.data;
        //buf := @buff.buffer;
        clear_comments(conf, buf);
        s := eat_ws(conf, buf);
        if IS_EOF(conf, s^) > 0 then
            continue;           { blank line }
        if s^ = '[' then
        begin
            Inc(s);
            start := eat_ws(conf, s);
            ss := start;
 _again:
            _end := eat_alpha_numeric(conf, ss);
            p := eat_ws(conf, _end);
            if p^ <> ']' then
            begin
                if (p^ <> #0)  and  (ss <> p) then
                begin
                    ss := p;
                    goto _again ;
                end;
                ERR_raise(ERR_LIB_CONF, CONF_R_MISSING_CLOSE_SQUARE_BRACKET);
                goto _err ;
            end;
            _end^ := #0;
            if 0>= str_copy(conf, nil, section, start) then
                goto _err ;

            sv := _CONF_get_section(conf, section);
            if sv = nil then
               sv := _CONF_new_section(conf, section);
            if sv = nil then
            begin
                ERR_raise(ERR_LIB_CONF, CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
                goto _err ;
            end;
            continue;
        end
        else
        begin
            pname := s;
            _end := eat_alpha_numeric(conf, s);
            if (_end[0] = ':')  and  (_end[1] = ':') then
            begin
                _end^ := #0;
                _end  := _end + 2;
                psection := pname;
                pname := _end;
                _end := eat_alpha_numeric(conf, _end);
            end
            else
            begin
                psection := section;
            end;
            p := eat_ws(conf, _end);
            if (CHECK_AND_SKIP_PREFIX(pname, '.pragma') > 0)  and
               ( (p <> pname)  or  (p^ = '=') ) then
            begin
                if p^ = '=' then
                begin
                    Inc(p);
                    p := eat_ws(conf, p);
                end;
                trim_ws(conf, p);
                { Pragma values take the form keyword:value }
                pval := strchr(p, ':');
                if (pval = nil)  or  (pval = p)  or  (pval[1] = #0) then
                begin
                    ERR_raise(ERR_LIB_CONF, CONF_R_INVALID_PRAGMA);
                    goto _err ;
                end;
                PostInc(pval)^ :=  #0;
                trim_ws(conf, p);
                pval := eat_ws(conf, pval);
                {
                 * Known pragmas:
                 *
                 * dollarid     takes ' on' , ' true or ' off' , ' false'
                 * abspath      takes ' on' , ' true or ' off' , ' false'
                 * includedir   directory prefix
                 }
                if strcmp(p, PUTF8Char('dollarid')) = 0 then
                begin
                    if 0>= parsebool(pval, @conf.flag_dollarid) then
                        goto _err ;
                end
                else
                if strcmp(p, PUTF8Char('abspath')) = 0  then
                begin
                    if 0>= parsebool(pval, @conf.flag_abspath) then
                        goto _err ;
                end
                else
                if (strcmp(p, PUTF8Char('includedir') ) = 0) then
                begin
                    OPENSSL_free(Pointer(conf.includedir));
                    OPENSSL_strdup(conf.includedir, pval);
                    if conf.includedir = nil then
                    begin
                        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                        goto _err ;
                    end;
                end;
                {
                 * We *ignore* any unknown pragma.
                 }
                continue;
            end
            else
            if (CHECK_AND_SKIP_PREFIX(pname, '.include' ) > 0)   and
               ( (p <> pname)  or  (p^ = '=') ) then
            begin
                include := nil;
                include_dir := ossl_safe_getenv('OPENSSL_CONF_INCLUDE' );
                include_path := nil;
                if include_dir = nil then
                   include_dir := conf.includedir;
                if p^ = '=' then
                begin
                    Inc(p);
                    p := eat_ws(conf, p);
                end;
                trim_ws(conf, p);
                if 0>= str_copy(conf, psection, include, p) then
                    goto _err ;
                if (include_dir <> nil)  and  (0>= ossl_is_absolute_path(include) ) then
                begin
                    newlen := Length(include_dir) + Length(include) + 2;
                    include_path := OPENSSL_malloc(newlen);
                    if include_path = nil then
                    begin
                        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                        OPENSSL_free(Pointer(include));
                        goto _err ;
                    end;
                    OPENSSL_strlcpy(include_path, include_dir, newlen);
                    if 0>= ossl_ends_with_dirsep(include_path) then
                        OPENSSL_strlcat(include_path, '/' , newlen);
                    OPENSSL_strlcat(include_path, include, newlen);
                    OPENSSL_free(Pointer(include));
                end
                else
                begin
                    include_path := include;
                end;
                if (conf.flag_abspath > 0)
                         and  (0>= ossl_is_absolute_path(include_path)) then
                begin
                    ERR_raise(ERR_LIB_CONF, CONF_R_RELATIVE_PATH);
                    OPENSSL_free(Pointer(include_path));
                    goto _err ;
                end;
                { get the BIO of the included file }
{$IFNDEF OPENSSL_NO_POSIX_IO}
                next := process_include(include_path, @dirctx, @dirpath);
                if include_path <> dirpath then
                begin
                    { dirpath will contain include in case of a directory }
                    OPENSSL_free(Pointer(include_path));
                end;
{$ELSE}
                next := BIO_new_file(include_path, 'r' );
                OPENSSL_free(include_path);
{$ENDIF}
                if next <> nil then
                begin
                    { push the currently processing BIO onto stack }
                    if biosk = nil then
                    begin
                        biosk := sk_BIO_new_null();
                        if (biosk = nil) then
                        begin
                            ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                            BIO_free(next);
                            goto _err ;
                        end;
                    end;
                    if 0>= sk_BIO_push(biosk, _in) then
                    begin
                        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                        BIO_free(next);
                        goto _err ;
                    end;
                    { continue with reading from the included PBIO }
                    _in := next;
                end;
                continue;
            end
            else
            if ( p^ <> '=') then
            begin
                ERR_raise_data(ERR_LIB_CONF, CONF_R_MISSING_EQUAL_SIGN,
                            Format('HERE-->%s' , [p]));
                goto _err ;
            end;
            _end^ := #0;
            Inc(p);
            start := eat_ws(conf, p);
            trim_ws(conf, start);
            //v := default(TCONF_VALUE);
            v := OPENSSL_malloc(sizeof(v^));
            if v = nil then
            begin
                ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            OPENSSL_strdup(v.name ,pname);
            v.value := nil;
            if v.name = nil then
            begin
                ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            if 0>= str_copy(conf, psection, v.value, start)  then
                goto _err ;
            if strcmp(psection, section ) <> 0 then
            begin
                tv := _CONF_get_section(conf, psection);
                if (tv = nil) then
                    tv := _CONF_new_section(conf, psection);
                if tv = nil then
                begin
                    ERR_raise(ERR_LIB_CONF, CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
                    goto _err ;
                end;
            end
            else
                tv := sv;
            if _CONF_add_string(conf, tv, v) = 0  then
            begin
                ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            v := nil;
            //v 在后面的value_free_stack_doall被释放

        end;
    end;{-->while true}
    BUF_MEM_free(buff);
    OPENSSL_free(section);
    {
     * No need to pop, since we only get here if the stack is empty.
     * If this causes a BIO leak, THE ISSUE IS SOMEWHERE ELSE!
     }
    sk_BIO_free(biosk);
    Exit(1);

 _err:
    BUF_MEM_free(buff);
    Free(section);
    {
     * Since |in| is the first element of the stack and should NOT be freed
     * here, we cannot use sk_BIO_pop_free().  Instead, we pop and free one
     * BIO at a time, making sure that the last one popped isn't.
     }
    while sk_BIO_num(biosk) > 0 do
    begin
        popped := sk_BIO_pop(biosk);
        BIO_vfree(_in);
        _in := popped;
    end;
    sk_BIO_free(biosk);
{$IFNDEF OPENSSL_NO_POSIX_IO}
    OPENSSL_free(Pointer(dirpath));
    if dirctx <> nil then
       OPENSSL_DIR_end(@dirctx);
{$ENDIF}
    if line <> nil then
       line^ := eline;
    BIO_snprintf(btmp, sizeof(btmp), ' %ld' , [eline]);
    ERR_add_error_data(2, [PUTF8Char('line ') , PUTF8Char(@btmp)]);
    if h <> conf.data then
    begin
        CONF_free(conf.data);
        conf.data := nil;
    end;
    if v <> nil then
    begin
        OPENSSL_free(Pointer(v.name));
        OPENSSL_free(Pointer(v.value));
        OPENSSL_free(Pointer(v));
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

function def_destroy( conf : PCONF):integer;
begin
    if def_destroy_data(conf ) > 0 then
    begin
        OPENSSL_free(Pointer(conf));
        Exit(1);
    end;
    Result := 0;
end;


function def_destroy_data( conf : PCONF):integer;
begin
    if conf = nil then
       Exit(0);
    _CONF_free_data(conf);
    Result := 1;
end;


function def_load(conf : PCONF;const name : PUTF8Char; line : Plong):integer;
var
  ret : integer;
  _in : PBIO;
begin
    _in := nil;
{$IFDEF OPENSSL_SYS_VMS}
    in := BIO_new_file(name, ' r' );
{$ELSE}
    _in := BIO_new_file(name, 'rb');
{$ENDIF}
    if _in = nil then
    begin
        if ERR_GET_REASON(ERR_peek_last_error()) = BIO_R_NO_SUCH_FILE then
            ERR_raise(ERR_LIB_CONF, CONF_R_NO_SUCH_FILE)
        else
            ERR_raise(ERR_LIB_CONF, ERR_R_SYS_LIB);
        Exit(0);
    end;
    ret := def_load_bio(conf, _in, line);
    BIO_free(_in);
    Result := ret;
end;



function def_create( meth : PCONF_METHOD):PCONF;
begin
    Result := OPENSSL_malloc(sizeof( Result^));
    if Result <> nil then
       if (meth.init(Result) = 0) then
       begin
            OPENSSL_free(Pointer(Result));
            Result := nil;
        end;

end;


function def_init_default( conf : PCONF):integer;
begin
    if conf = nil then Exit(0);
    //memset(conf, 0, sizeof( conf^));
    //FillChar(conf, sizeof( conf^), 0);
    conf.meth := @default_method;
    conf.meth_data := (@CONF_type_default);
    Result := 1;
end;



function NCONF_default:PCONF_METHOD;
begin
    Result := @default_method;
end;

end.

