unit openssl3.crypto.bio.bf_prefix;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  prefix_ctx_st = record
      prefix    : PUTF8Char;
      indent    : uint32;
      linestart : integer;
  end;
  TPREFIX_CTX = prefix_ctx_st;
  PPREFIX_CTX = ^TPREFIX_CTX;

  function BIO_f_prefix:PBIO_METHOD;
  function prefix_create( b : PBIO):integer;
  function prefix_destroy( b : PBIO):integer;
  function prefix_read( b : PBIO; _in : PUTF8Char; size : size_t; numread : Psize_t):integer;
  function prefix_write(b : PBIO;{const} _out : PByte; outl : size_t; numwritten : Psize_t):integer;
  function prefix_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
  function prefix_callback_ctrl( b : PBIO; cmd : integer; fp : TBIO_info_cb):long;
  function prefix_gets( b : PBIO; buf : PUTF8Char; size : integer):integer;
  function prefix_puts(b : PBIO;const str : PUTF8Char):integer;

const prefix_meth: TBIO_METHOD  = (
    &type: BIO_TYPE_BUFFER;
    name: 'prefix';
    bwrite: prefix_write;
    bwrite_old: NiL;
    bread: prefix_read;
    bread_old: NIL;
    bputs: prefix_puts;
    bgets: prefix_gets;
    ctrl: prefix_ctrl;
    create: prefix_create;
    destroy: prefix_destroy;
    callback_ctrl: prefix_callback_ctrl
);

implementation
uses openssl3.crypto.mem, openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bio_print,
     openssl3.crypto.o_str;

function BIO_f_prefix:PBIO_METHOD;
begin
    Result := @prefix_meth;
end;


function prefix_create( b : PBIO):integer;
var
  ctx : PPREFIX_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then Exit(0);
    ctx.prefix := nil;
    ctx.indent := 0;
    ctx.linestart := 1;
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    Result := 1;
end;


function prefix_destroy( b : PBIO):integer;
var
  ctx : PPREFIX_CTX;
begin
    ctx := BIO_get_data(b);
    OPENSSL_free(Pointer(ctx.prefix));
    OPENSSL_free(Pointer(ctx));
    Result := 1;
end;


function prefix_read( b : PBIO; _in : PUTF8Char; size : size_t; numread : Psize_t):integer;
begin
    Result := BIO_read_ex(BIO_next(b), _in, size, numread);
end;


function prefix_write(b : PBIO;{const} _out : PByte; outl : size_t; numwritten : Psize_t):integer;
var
  ctx      : PPREFIX_CTX;
  i        : size_t;
  c        : UTF8Char;
  dontcare,
  num, ret      : size_t;
begin
    ctx := BIO_get_data(b);
    if ctx = nil then Exit(0);
    {
     * If no prefix is set or if it's empty, and no indentation amount is set,
     * we've got nothing to do here
     }
    if ((ctx.prefix = nil)  or  (ctx.prefix^ = #0))  and  (ctx.indent = 0) then
    begin
        {
         * We do note if what comes next will be a new line, though, so we're
         * prepared to handle prefix and indentation the next time around.
         }
        if outl > 0 then
        begin
            ctx.linestart := int(_out[outl-1]  = Ord(#10));

        end;
        Exit(BIO_write_ex(BIO_next(b), _out, outl, numwritten));
    end;
    numwritten^ := 0;
    while outl > 0 do
    begin
        {
         * If we know that we're at the start of the line, output prefix and
         * indentation.
         }
        if ctx.linestart > 0 then
        begin
            ret := BIO_write_ex(BIO_next(b), ctx.prefix, Length(ctx.prefix), @dontcare);
            if (ctx.prefix <> nil) and  (0 >= ret) then
                Exit(0);
            BIO_printf(BIO_next(b), '%*s', [ctx.indent, PUTF8Char('')]);
            ctx.linestart := 0;
        end;
        { Now, go look for the next LF, or the end of the string }
        c := #0;
        i := 0;
        while (i < outl) do
        begin
            c := UTF8Char(_out[i]);
            if c <> #10 then
            begin
              Inc(i);
              continue;
            end
            else Break;
        end;
        if c = #10 then
           Inc(i);
        { Output what we found so far }
        while i > 0 do
        begin
            num := 0;
            if 0>= BIO_write_ex(BIO_next(b) , _out, i, @num)  then
                Exit(0);
            _out  := _out + num;
            outl  := outl - num;
            numwritten^  := numwritten^ + num;
            i  := i - num;
        end;
        { If we found a LF, what follows is a new line, so take note }
        if c = #10 then
           ctx.linestart := 1;
    end;
    Result := 1;
end;


function prefix_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
var
  ret : long;
  ctx : PPREFIX_CTX;
  next : PBIO;
begin
    ret := 0;
    ctx := BIO_get_data(b);
    if (b = nil)  or  (ctx = nil) then
        Exit(-1);
    case cmd of
        BIO_CTRL_SET_PREFIX:
        begin
            OPENSSL_free(Pointer(ctx.prefix));
            if ptr = nil then
            begin
                ctx.prefix := nil;
                ret := 1;
            end
            else
            begin
                OPENSSL_strdup(ctx.prefix ,PUTF8Char(ptr));
                ret := Int(ctx.prefix <> nil);
            end;
        end;
        BIO_CTRL_SET_INDENT:
            if num >= 0 then
            begin
                ctx.indent := uint32( num);
                ret := 1;
            end;
            //break;
        BIO_CTRL_GET_INDENT:
            ret := long(ctx.indent);
            //break;
        else
        begin
            // Commands that we intercept before passing them along
            case cmd of
              BIO_C_FILE_SEEK,
              BIO_CTRL_RESET:
                  ctx.linestart := 1;
                  //break;
            end;
            next := BIO_next(b);
            if next <> nil  then
               ret := BIO_ctrl(next, cmd, num, ptr);
        end;
    end;
    Result := ret;
end;


function prefix_callback_ctrl( b : PBIO; cmd : integer; fp : TBIO_info_cb):long;
begin
    Result := BIO_callback_ctrl(BIO_next(b), cmd, fp);
end;


function prefix_gets( b : PBIO; buf : PUTF8Char; size : integer):integer;
begin
    Result := BIO_gets(BIO_next(b), buf, size);
end;


function prefix_puts(b : PBIO;const str : PUTF8Char):integer;
begin
    Result := BIO_write(b, str, Length(str));
end;


end.
