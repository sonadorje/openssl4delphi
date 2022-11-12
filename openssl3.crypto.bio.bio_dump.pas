unit openssl3.crypto.bio.bio_dump;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils, TypInfo;

const
  DUMP_WIDTH = 16;

type
    Tcb_func = function (const data : Pointer; len : size_t; u : Pointer):integer;

function BIO_hex_string(&out : PBIO; indent, width : integer;const data : Pointer; datalen : integer):integer;
function BIO_dump(bp : PBIO;const s : Pointer; len : integer):integer;
function BIO_dump_cb(cb: Tcb_func; fp : Pointer;const data : Pointer; len : integer):integer;
function BIO_dump_indent_cb(cb : Tcb_func; fp : Pointer;const data : Pointer; len, indent : integer):integer;
function write_bio(const data : Pointer; len : size_t; bp : Pointer):integer;
function BIO_dump_indent(bp : PBIO;const s : Pointer; len, indent : integer):integer;
function BIO_dump_indent_fp(fp : PFILE;const s : Pointer; len, indent : integer):integer;
function write_fp(const data : Pointer; len : size_t; fp : Pointer):integer;
function BIO_dump_fp(fp : PFILE;const data : Pointer; len : integer):integer;

implementation
uses {$IFDEF MSWINDOWS}
{$IFnDEF FPC}
  Windows,
{$ELSE}
{$ENDIF}
  libc.win, {$ENDIF} openssl3.crypto.bio.bio_print;

function BIO_dump_fp(fp : PFILE;const data : Pointer; len : integer):integer;
begin
    Result := BIO_dump_cb(write_fp, fp, data, len);
end;

function write_fp(const data : Pointer; len : size_t; fp : Pointer):integer;
var
  hConsole: THandle;
  p: PUTF8Char;
begin

    {$IFDEF MSWINDOWS}
    {hConsole := GetStdHandle(STD_OUTPUT_HANDLE);
    Result := filewrite(hConsole, TBytes(data), 1, len);
    }
    p := PUTF8Char(data);
    while PostDec(len) > 0  do
    begin
       Write(PTextFile(fp)^, Format('%s', [p^]));
       Inc(p);
    end;

    {$ELSE}
    {$ifdef fpc}
    hConsole := fpdup(StdOutputHandle);;//stdout;
    {$else}
    hConsole := dup(STDOUT_FILENO);;//stdout;
    {$endif}
    {$ENDIF}
end;

function BIO_dump_indent_fp(fp : PFILE;const s : Pointer; len, indent : integer):integer;
begin
    Result := BIO_dump_indent_cb(write_fp, fp, s, len, indent);
end;



function BIO_dump_indent(bp : PBIO;const s : Pointer; len, indent : integer):integer;
begin
    Result := BIO_dump_indent_cb(write_bio, bp, s, len, indent);
end;

function write_bio(const data : Pointer; len : size_t; bp : Pointer):integer;
begin
    Result := BIO_write(PBIO(bp), PUTF8Char(data), len);
end;

function DUMP_WIDTH_LESS_INDENT(i: integer): Integer;
begin
  Result := (DUMP_WIDTH - ((i - get_result(i > 6 , 6 , i) + 3) div 4))
end;



function BIO_dump_indent_cb(cb : Tcb_func; fp : Pointer;const data : Pointer; len, indent : integer):integer;
var
  s          : PByte;
  res,
  ret        : integer;
  buf        : array[0..288] of UTF8Char;
  i,j,rows,n : integer;
  ch         : Byte;
  dump_width : integer;
  _bytes: TBytes;
  function SPACE(pos, n: Integer): Boolean;
  begin
     Result := sizeof(buf) - (pos) > n;
  end;
begin
    FillChar(buf, SizeOf(buf), 0);
    s := Pbyte(data);
    ret := 0;
    if indent < 0 then
       indent := 0
    else
    if (indent > 64) then
        indent := 64;
    dump_width := DUMP_WIDTH_LESS_INDENT(indent);
    rows := len div dump_width;
    if rows * dump_width  < len then
        PostInc(rows);
    for i := 0 to rows-1 do
    begin
        n := BIO_snprintf(buf, sizeof(buf), '%*s%04x - ', [indent, PUTF8Char(''),
                         i * dump_width]);
        for j := 0 to dump_width-1 do
        begin
            if SPACE(n, 3 ) then
            begin
                if ((i * dump_width) + j) >= len then
                begin
                    strcpy(PUTF8Char(@buf) + n , '   ');
                end
                else
                begin
                    ch := (s + i * dump_width + j)^ and $ff;
                    BIO_snprintf(buf + n, 4, '%02x%c', [ch,
                                 get_result(j = 7 , UTF8Char('-') , UTF8Char(' '))]);
                end;
                n  := n + 3;
            end;
        end;
        if SPACE(n, 2) then
        begin
            strcpy(PUTF8Char(@buf) + n , '  ');
            n  := n + 2;
        end;
        for j := 0 to dump_width-1 do
        begin
            if ((i * dump_width) + j) >= len then
                break;
            if SPACE(n, 1)  then
            begin
                ch := (s + i * dump_width + j)^ and $ff;
{$IFNDEF CHARSET_EBCDIC}
                buf[PostInc(n)] := get_result( (ch >= Ord(' '))  and  (ch <= Ord('~')) , UTF8Char(ch) , '.');
{$ELSE}
                buf[PostInc(n)] = get_result((ch >= os_toascii[' '])  and  (ch <= os_toascii['~']))
                           , os_toebcdic[ch]
                           , '.');
{$ENDIF}
                buf[n] := #0;
            end;
        end;
        if SPACE(n, 1 ) then
        begin
            buf[PostInc(n)] := #10;
            buf[n] := #0;
        end;
        {
         * if this is the last call then update the ddt_dump thing so that we
         * will move the selection point in the debug window
         }

        res := cb(@buf, n, fp);
        if res < 0 then Exit(res);
        ret  := ret + res;
    end; //->for i := 0 to rows-1
    Result := ret;
end;


function BIO_dump_cb(cb: Tcb_func; fp : Pointer;const data : Pointer; len : integer):integer;
begin
    Result := BIO_dump_indent_cb(cb, fp, data, len, 0);
end;



function BIO_dump(bp : PBIO;const s : Pointer; len : integer):integer;
begin
    Result := BIO_dump_cb(write_bio, bp, s, len);
end;

function BIO_hex_string(&out : PBIO; indent, width : integer;const data : Pointer; datalen : integer):integer;
var
  d : PByte;

  i, j : integer;
begin
    d := data;
    j := 0;
    if datalen < 1 then Exit(1);
    for i := 0 to datalen - 1-1 do
    begin
        if (i>0)  and  (j<=0) then
           BIO_printf(&out, '%*s', [indent, '']);
        BIO_printf(&out, '%02X:', [d[i]]);
        j := (j + 1) mod width;
        if  0>=j then
           BIO_printf(&out, #10, []);
    end;
    if (i>0)  and  (0>= j) then
       BIO_printf(&out, '%*s', [indent, '']);
    BIO_printf(&out, '%02X', [ d[datalen - 1] ]);
    Result := 1;
end;


end.
