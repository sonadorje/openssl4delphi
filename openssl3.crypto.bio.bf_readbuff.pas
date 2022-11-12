unit openssl3.crypto.bio.bf_readbuff;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
  DEFAULT_BUFFER_SIZE = 4096;

  function BIO_f_readbuffer:PBIO_METHOD;
  function readbuffer_new( bi : PBIO):integer;
  function readbuffer_free( a : PBIO):integer;
  function readbuffer_resize( ctx : PBIO_F_BUFFER_CTX; sz : integer):integer;
  function readbuffer_read( b : PBIO; _out : PUTF8Char; outl : integer):integer;
  function readbuffer_write(b : PBIO;{const} _in : PByte; inl : integer):integer;
  function readbuffer_puts(b : PBIO;const str : PUTF8Char):integer;
  function readbuffer_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
  function readbuffer_callback_ctrl(b : PBIO; cmd : integer;fp : TBIO_info_cb):long;
  function readbuffer_gets( b : PBIO; buf : PUTF8Char; size : integer):integer;


implementation

uses openssl3.crypto.bio.bio_meth, openssl3.crypto.mem,
     openssl3.crypto.bio.bio_lib;


function readbuffer_new( bi : PBIO):integer;
var
  ctx : PBIO_F_BUFFER_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then Exit(0);
    ctx.ibuf_size := DEFAULT_BUFFER_SIZE;
    ctx.ibuf := OPENSSL_zalloc(DEFAULT_BUFFER_SIZE);
    if ctx.ibuf = nil then
    begin
        OPENSSL_free(ctx);
        Exit(0);
    end;
    bi.init := 1;
    bi.ptr := PUTF8Char(ctx);
    bi.flags := 0;
    Result := 1;
end;


function readbuffer_free( a : PBIO):integer;
var
  b : PBIO_F_BUFFER_CTX;
begin
    if a = nil then Exit(0);
    b := PBIO_F_BUFFER_CTX( a.ptr);
    OPENSSL_free(b.ibuf);
    OPENSSL_free(a.ptr);
    a.ptr := nil;
    a.init := 0;
    a.flags := 0;
    Result := 1;
end;


function readbuffer_resize( ctx : PBIO_F_BUFFER_CTX; sz : integer):integer;
var
  tmp : PUTF8Char;
begin
    { Figure out how many blocks are required }
    sz  := sz + ((ctx.ibuf_off + DEFAULT_BUFFER_SIZE - 1));
    sz := DEFAULT_BUFFER_SIZE * (sz div DEFAULT_BUFFER_SIZE);
    { Resize if the buffer is not big enough }
    if sz > ctx.ibuf_size then
    begin
        OPENSSL_realloc(Pointer(ctx.ibuf), sz);
        if tmp = nil then Exit(0);
        //ctx.ibuf := tmp;
        ctx.ibuf_size := sz;
    end;
    Result := 1;
end;


function readbuffer_read( b : PBIO; _out : PUTF8Char; outl : integer):integer;
var
  i, num : integer;

  ctx : PBIO_F_BUFFER_CTX;
begin
    num := 0;
    if (_out = nil)  or  (outl = 0) then
       Exit(0);
    ctx := PBIO_F_BUFFER_CTX( b.ptr);
    if (ctx = nil)  or  (b.next_bio = nil) then
        Exit(0);
    BIO_clear_retry_flags(b);
    while true do
    begin
        i := ctx.ibuf_len;
        { If there is something in the buffer just read it. }
        if i <> 0 then
        begin
            if i > outl then
                i := outl;
            memcpy(_out, @(ctx.ibuf[ctx.ibuf_off]), i);
            ctx.ibuf_off  := ctx.ibuf_off + i;
            ctx.ibuf_len  := ctx.ibuf_len - i;
            num  := num + i;
            { Exit if we have read the bytes required out of the buffer }
            if outl = i then
               Exit(num);
            outl  := outl - i;
            _out  := _out + i;
        end;
        { Only gets here if the buffer has been consumed }
        if 0>= readbuffer_resize(ctx, outl) then
            Exit(0);
        { Do some buffering by reading from the next bio }
        i := BIO_read(b.next_bio, ctx.ibuf + ctx.ibuf_off, outl);
        if i <= 0 then
        begin
            BIO_copy_next_retry(b);
            if i < 0 then
               Exit(get_result((num > 0) , num , i))
            else
               Exit(num); { i = 0 }
        end;
        ctx.ibuf_len := i;
    end;
end;


function readbuffer_write(b : PBIO;{const} _in : PByte; inl : integer):integer;
begin
    Result := 0;
end;


function readbuffer_puts(b : PBIO;const str : PUTF8Char):integer;
begin
    Result := 0;
end;


function readbuffer_ctrl( b : PBIO; cmd : integer; num :long; ptr : Pointer):long;
var
  ctx : PBIO_F_BUFFER_CTX;
  ret, sz : long;
begin
    ret := 1;
    ctx := PBIO_F_BUFFER_CTX( b.ptr);
    case cmd of
        BIO_CTRL_EOF:
        begin
            if ctx.ibuf_len > 0 then Exit(0);
            if b.next_bio = nil then Exit(1);
            ret := BIO_ctrl(b.next_bio, cmd, num, ptr);
        end;
        BIO_C_FILE_SEEK,
        BIO_CTRL_RESET:
        begin
            sz := ctx.ibuf_off + ctx.ibuf_len;
            { Assume it can only seek backwards }
            if (num < 0)  or  (num > sz) then Exit(0);
            ctx.ibuf_off := num;
            ctx.ibuf_len := sz - num;
        end;
        BIO_C_FILE_TELL,
        BIO_CTRL_INFO:
            ret := long(ctx.ibuf_off);
            //break;
        _BIO_CTRL_PENDING:
        begin
            ret := long(ctx.ibuf_len);
            if ret = 0 then
            begin
                if b.next_bio = nil then
                    Exit(0);
                ret := BIO_ctrl(b.next_bio, cmd, num, ptr);
            end;
        end;
        BIO_CTRL_DUP,
        BIO_CTRL_FLUSH:
            ret := 1;
            //break;
        else
            ret := 0;
            //break;
    end;
    Result := ret;
end;


function readbuffer_callback_ctrl(b : PBIO; cmd : integer;fp : TBIO_info_cb):long;
begin
    if b.next_bio = nil then
       Exit(0);
    Result := BIO_callback_ctrl(b.next_bio, cmd, fp);
end;


function readbuffer_gets( b : PBIO; buf : PUTF8Char; size : integer):integer;
var
  ctx : PBIO_F_BUFFER_CTX;
  num, num_chars, found_newline : integer;
  p : PUTF8Char;
  i, j : integer;
begin
    num := 0;
    if size = 0 then
      Exit(0);
    PreDec(size); { the passed in size includes the terminator - so remove it here }
    ctx := PBIO_F_BUFFER_CTX( b.ptr);
    BIO_clear_retry_flags(b);
    { If data is already buffered then use this first }
    if ctx.ibuf_len > 0 then
    begin
        p := ctx.ibuf + ctx.ibuf_off;
        found_newline := 0;
        num_chars := 0;
        while (num_chars < ctx.ibuf_len)  and  (num_chars < size) do
        begin
            PostInc(buf)^ := p[num_chars];
            if p[num_chars] = #10 then
            begin
                found_newline := 1;
                PostInc(num_chars);
                break;
            end;
            Inc(num_chars);
        end;
        num  := num + num_chars;
        size  := size - num_chars;
        ctx.ibuf_len  := ctx.ibuf_len - num_chars;
        ctx.ibuf_off  := ctx.ibuf_off + num_chars;
        if (found_newline > 0) or  (size = 0) then
        begin
            buf^ := #0;
            Exit(num);
        end;
    end;
    {
     * If there is no buffered data left then read any remaining data from the
     * next bio.
     }
     { Resize if we have to }
     if 0>= readbuffer_resize(ctx, 1 + size) then
         Exit(0);
     {
      * Read more data from the next bio using BIO_read_ex:
      * Note we cannot use BIO_gets() here as it does not work on a
      * binary stream that contains $00. (Since strlen() will stop at
      * any $00 not at the last read #10 in a FILE bio).
      * Also note that some applications open and close the file bio
      * multiple times and need to read the next available block when using
      * stdin - so we need to READ one byte at a time!
      }
     p := ctx.ibuf + ctx.ibuf_off;
     for i := 0 to size - 1 do
     begin
         j := BIO_read(b.next_bio, p, 1);
         if j <= 0 then
         begin
             BIO_copy_next_retry(b);
             buf^ := #0;
             Exit(get_result(num > 0 , num , j));
         end;
         PostInc(buf)^ := p^;
         Inc(num);
         Inc(ctx.ibuf_off);
         if p^ = #10 then
            break;
         Inc(p);
     end;
     buf^ := #0;
     Result := num;
end;

const  methods_readbuffer: TBIO_METHOD = (
    &type: BIO_TYPE_BUFFER;
    name: 'readbuffer';
    bwrite: bwrite_conv;
    bwrite_old: readbuffer_write;
    bread: bread_conv;
    bread_old: readbuffer_read;
    bputs: readbuffer_puts;
    bgets: readbuffer_gets;
    ctrl: readbuffer_ctrl;
    create: readbuffer_new;
    destroy: readbuffer_free;
    callback_ctrl: readbuffer_callback_ctrl
);

function BIO_f_readbuffer:PBIO_METHOD;
begin
    Result := @methods_readbuffer;
end;


end.
