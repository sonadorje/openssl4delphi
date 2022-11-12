unit openssl3.crypto.evp.bio_b64;

interface
uses openssl.api, SysUtils, Math;

const
   B64_BLOCK_SIZE  = 1024;
   B64_BLOCK_SIZE2 = 768;
   B64_NONE        = 0;
   B64_ENCODE      = 1;
   B64_DECODE      = 2;
   EVP_ENCODE_LENGTH =    ((((B64_BLOCK_SIZE)+2)div 3*4)+((B64_BLOCK_SIZE) div 48+1)*2+80) ;

type
  b64_struct = record
    buf_len, buf_off, tmp_len, tmp_nl, encode, start, cont : integer;
    base64 : PEVP_ENCODE_CTX;
    buf : array[0..(EVP_ENCODE_LENGTH + 10)-1] of byte;
    tmp : array[0..(B64_BLOCK_SIZE)-1] of byte;
  end;
  TBIO_B64_CTX = b64_struct;
  PBIO_B64_CTX = ^TBIO_B64_CTX;

function BIO_f_base64:PBIO_METHOD;
function b64_write(b : PBIO;{const} data : PByte; inl : integer):integer;
function b64_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
function b64_callback_ctrl( b : PBIO; cmd : integer; fp : TBIO_info_cb):long;
function b64_puts(b : PBIO;const str : PUTF8Char):integer;
function b64_read( b : PBIO; &out : PUTF8Char; outl : integer):integer;
function b64_new( bi : PBIO):integer;
function b64_free( a : PBIO):integer;
//https://blog.csdn.net/fjhyy/article/details/115363424

function Base64Encode(const _in : PByte; inlen : integer; _out : PAnsiChar; outlen : PInteger; newline : Byte):integer;overload;
function Base64Encode(InputBuffer :TBytes) :TBytes; overload;
function base64_decode(const _in : PAnsiChar; inlen : integer; _out : PByte; outlen : PInteger; newline : Byte):integer;
function base64Encode(const _message : PByte; length : size_t):PAnsiChar; overload;
function base64Decode(const b64message : PUTF8Char; length : size_t; buffer : PPByte):integer;
function calcDecodeLength(const b64input : PUTF8Char; length : size_t):integer;

implementation

uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}
     openssl3.crypto.bio.bio_meth,        openssl3.crypto.mem, OpenSSL3.Err,
     openssl3.crypto.evp.encode,          openssl3.crypto.bio.bio_lib,
     openssl3.crypto.bio.bss_mem;

const  methods_b64: TBIO_METHOD = (
    &type: BIO_TYPE_BASE64;
    name: 'base64 encoding';
    bwrite: bwrite_conv;
    bwrite_old: b64_write;
    bread: bread_conv;
    bread_old: b64_read;
    bputs:b64_puts;
    bgets: nil;                       // b64_gets;
    ctrl:b64_ctrl;
    create:b64_new;
    destroy:b64_free;
    callback_ctrl:b64_callback_ctrl
);


function base64Encode(const _message : PByte; length : size_t):PAnsiChar;
var
  encodedSize : integer;
  b64text     : PUTF8Char;
  b64,
  bio         : PBIO;
  bufferPtr   : PBUF_MEM;
begin
  encodedSize := 4 * ceil(double(length) / 3);
  b64text := malloc(encodedSize + 1);
  if b64text = nil then begin
    WriteLn('Failed to allocate memory');
    exit(nil);
  end;
  b64 := BIO_new(BIO_f_base64);
  bio := BIO_new(BIO_s_mem);
  bio := BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, _message, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, @bufferPtr);
  BIO_set_close(bio, BIO_CLOSE);
  memcpy(b64text, ( bufferPtr^).data, (bufferPtr^).length + 1);
  b64text[(bufferPtr^).length] := #0;
  BIO_free_all(bio);
  Result := b64text;
end;


function base64Decode(const b64message : PUTF8Char; length : size_t; buffer : PPByte):integer;
var
  decodedLength : integer;
  bio,
  b64           : PBIO;
begin
  decodedLength := calcDecodeLength(b64message, length);
  buffer^ := malloc(decodedLength + 1);
  if buffer^ = nil then begin
    WriteLn('Failed to allocate memory');
    exit(1);
  end;
  bio := BIO_new_mem_buf(b64message, -1);
  b64 := BIO_new(BIO_f_base64);
  bio := BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  decodedLength := BIO_read(bio, buffer^, StrLen(b64message));
  ( buffer^)[decodedLength] := Ord(#0);
  BIO_free_all(bio);
  Result := decodedLength;
end;


function calcDecodeLength(const b64input : PUTF8Char; length : size_t):integer;
var
  padding : uint32;
begin
  padding := 0;
  // Check for trailing '=''s as padding
  if (b64input[length - 1] = '=')  and  (b64input[length - 2] = '=') then
  begin
    padding := 2;
  end
  else if (b64input[length - 1] = '=') then
  begin
    padding := 1;
  end;
  Result := round(length * 0.75 - padding);
end;


function base64_decode(const _in : PAnsiChar; inlen : integer; _out : PByte; outlen : PInteger; newline : Byte):integer;
var
  b64, bio : PBIO;
begin
    b64 := nil;
    bio := nil;
    b64 := BIO_new(BIO_f_base64);
    bio := BIO_new_mem_buf(Pointer(_in), inlen);
    if (nil = b64)  or  (nil = bio) then
    begin
        raise Exception.Create('fail to BIO_new');
        Exit(-1);
    end;
    bio := BIO_push(b64, bio);
    if 0 >= newline then begin
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    end;
    outlen^ := BIO_read(bio, _out, inlen);
    if outlen^ <= 0 then
    begin
        raise Exception.Create('fail to BIO_write');
        Exit(-1);
    end;
    BIO_free_all(bio);
    Result := 0;
end;

function Base64Encode(InputBuffer :TBytes) :TBytes;
var
  bio, b64 :PBIO;
  bdata :Pointer;
  datalen :Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new(BIO_s_mem());
  BIO_push(b64, bio);

  BIO_write(b64, @InputBuffer[0], Length(InputBuffer));
  BIO_flush(b64);

  bdata := nil;
  datalen :=  BIO_get_mem_data(bio, bdata);
  SetLength(Result, datalen);
  Move(bdata^, Result[0], datalen);

  BIO_free_all(b64);

end;

function Base64Encode(const _in : PByte; inlen : integer; _out : PAnsiChar; outlen : PInteger; newline : Byte):integer;
var
  bmem, b64 : PBIO;
  bptr : PBUF_MEM;
begin
    bmem := nil;
    b64 := nil;
    bptr := nil;
    b64 := BIO_new(BIO_f_base64);
    bmem := BIO_new(BIO_s_mem);
    if (nil = b64)  or  (nil = bmem) then
    begin
        raise Exception.Create('fail to BIO_new');
        Exit(-1);
    end;
    b64 := BIO_push(b64, bmem);
    if newline = 0 then
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);


    outlen^ := BIO_write(b64, _in, inlen);
    if (outlen^ <= 0)  or  (outlen^ <> inlen) then
    begin
        raise Exception.Create('fail to BIO_write');
        Exit(-1);
    end;
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, @bptr);
    outlen^ := bptr.length;
    memcpy(_out, bptr.data, outlen^);
    BIO_free_all(b64);
    Result := 0;
end;

function b64_new( bi : PBIO):integer;
var
  ctx : PBIO_B64_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then  begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ctx.cont := 1;
    ctx.start := 1;
    ctx.base64 := EVP_ENCODE_CTX_new;
    if ctx.base64 = nil then begin
        OPENSSL_free(ctx);
        Exit(0);
    end;
    BIO_set_data(bi, ctx);
    BIO_set_init(bi, 1);
    Result := 1;
end;


function b64_free( a : PBIO):integer;
var
  ctx : PBIO_B64_CTX;
begin
    if a = nil then Exit(0);
    ctx := BIO_get_data(a);
    if ctx = nil then Exit(0);
    EVP_ENCODE_CTX_free(ctx.base64);
    OPENSSL_free(ctx);
    BIO_set_data(a, nil);
    BIO_set_init(a, 0);
    Result := 1;
end;

function b64_read( b : PBIO; &out : PUTF8Char; outl : integer):integer;
var
  ret, num,
  i, ii, j,
  k, x, n,
  ret_code : integer;
  ctx      : PBIO_B64_CTX;
  p, q     : PByte;
  next     : PBIO;
  z,jj       : integer;
begin
    ret := 0;
    ret_code := 0;
    if out = nil then Exit(0);
    ctx := PBIO_B64_CTX(BIO_get_data(b));
    next := BIO_next(b);
    if (ctx = nil) or  (next = nil) then
        Exit(0);
    BIO_clear_retry_flags(b);
    if ctx.encode <> B64_DECODE then begin
        ctx.encode := B64_DECODE;
        ctx.buf_len := 0;
        ctx.buf_off := 0;
        ctx.tmp_len := 0;
        EVP_DecodeInit(ctx.base64);
    end;
    { First check if there are bytes decoded/encoded }
    if ctx.buf_len > 0 then begin
        assert(ctx.buf_len >= ctx.buf_off);
        i := ctx.buf_len - ctx.buf_off;
        if i > outl then i := outl;
        assert(ctx.buf_off + i < int(sizeof(ctx.buf)));
        memcpy(out, @(ctx.buf[ctx.buf_off]), i);
        ret := i;
        out  := out + i;
        outl  := outl - i;
        ctx.buf_off  := ctx.buf_off + i;
        if ctx.buf_len = ctx.buf_off then begin
            ctx.buf_len := 0;
            ctx.buf_off := 0;
        end;
    end;
    {
     * At this point, we have room of outl bytes and an empty buffer, so we
     * should read in some more.
     }
    ret_code := 0;
    while outl > 0 do
    begin
        if ctx.cont <= 0 then break;
        i := BIO_read(next, @(ctx.tmp[ctx.tmp_len]),
                     B64_BLOCK_SIZE - ctx.tmp_len);
        if i <= 0 then
        begin
            ret_code := i;
            { Should we continue next time we are called? }
            if 0>=BIO_should_retry(next) then  begin
                ctx.cont := i;
                { If buffer empty break }
                if ctx.tmp_len = 0 then
                   break
                { Fall through and process what we have }
                else
                    i := 0;
            end
            { else we retry and add more data to buffer }
            else
                break;
        end;
        i  := i + ctx.tmp_len;
        ctx.tmp_len := i;
        {
         * We need to scan, a line at a time until we have a valid line if we
         * are starting.
         }
        if (ctx.start > 0) and  (BIO_get_flags(b) and BIO_FLAGS_BASE64_NO_NL > 0) then
        begin
            { ctx.start=1; }
            ctx.tmp_len := 0;
        end
        else
        if (ctx.start > 0) then
        begin
            q := PByte(@ctx.tmp); p := PByte(@ctx.tmp);
            num := 0;
            for j := 0 to i-1 do
            begin
                if PostInc(q)^ <> Ord(#10) then
                    continue;
                {
                 * due to a previous very long line, we need to keep on
                 * scanning for a '\n' before we even start looking for
                 * base64 encoded stuff.
                 }
                if ctx.tmp_nl > 0 then begin
                    p := q;
                    ctx.tmp_nl := 0;
                    continue;
                end;
                k := EVP_DecodeUpdate(ctx.base64,
                                     @ctx.buf,
                                     @num, p, q - p);
                if (k <= 0)  and  (num = 0)  and  (ctx.start > 0) then
                    EVP_DecodeInit(ctx.base64)
                else
                begin
                    if p <> PByte(@ctx.tmp[0]) then
                    begin
                        i := i- (p - PByte(@ctx.tmp[0]));
                        for x := 0 to i-1 do
                            ctx.tmp[x] := p[x];
                    end;
                    EVP_DecodeInit(ctx.base64);
                    ctx.start := 0;
                    break;
                end;
                p := q;
            end;
            { we fell off the end without starting }
            if (j = i)  and  (num = 0) then
            begin
                {
                 * Is this is one long chunk?, if so, keep on reading until a
                 * new line.
                 }
                if p = PByte(@ctx.tmp[0]) then
                begin
                    { Check buffer full }
                    if i = B64_BLOCK_SIZE then  begin
                        ctx.tmp_nl := 1;
                        ctx.tmp_len := 0;
                    end;
                end
                else if (p <> q) then
                begin  { finished on a '\n' }
                    n := q - p;
                    for ii := 0 to n-1 do
                        ctx.tmp[ii] := p[ii];
                    ctx.tmp_len := n;
                end;
                { else finished on a '\n' }
                continue;
            end
            else
            begin
                ctx.tmp_len := 0;
            end;
        end
        else
        if (i < B64_BLOCK_SIZE)  and  (ctx.cont > 0) then
        begin
            {
             * If buffer isn't full and we can retry then restart to read in
             * more data.
             }
            continue;
        end;
        if (BIO_get_flags(b) and BIO_FLAGS_BASE64_NO_NL) > 0 then
        begin
            jj := i and (not 3);        { process per 4 }
            z := EVP_DecodeBlock(PByte(@ctx.buf), PByte(@ctx.tmp), jj);
            if jj > 2 then
            begin
                if ctx.tmp[jj - 1] = Ord('=') then
                begin
                    Dec(z);
                    if ctx.tmp[jj - 2] = Ord('=') then
                       Dec(z);
                end;
            end;
            {
             * z is now number of output bytes and jj is the number consumed
             }
            if jj <> i then
            begin
                memmove(@ctx.tmp, @ctx.tmp[jj], i - jj);
                ctx.tmp_len := i - jj;
            end;
            ctx.buf_len := 0;
            if z > 0 then begin
                ctx.buf_len := z;
            end;
            i := z;
        end
        else
        begin
            i := EVP_DecodeUpdate(ctx.base64,
                                 PByte(@ctx.buf), @ctx.buf_len,
                                 PByte(@ctx.tmp), i);
            ctx.tmp_len := 0;
        end;
        {
         * If eof or an error was signalled, then the condition
         * 'ctx.cont <= 0' will prevent b64_read from reading
         * more data on subsequent calls. This assignment was
         * deleted accidentally in commit 5562cfaca4f3.
         }
        ctx.cont := i;
        ctx.buf_off := 0;
        if i < 0 then begin
            ret_code := 0;
            ctx.buf_len := 0;
            break;
        end;
        if ctx.buf_len <= outl then
           i := ctx.buf_len
        else
            i := outl;
        memcpy(out, @ctx.buf, i);
        ret  := ret + i;
        ctx.buf_off := i;
        if ctx.buf_off = ctx.buf_len then
        begin
            ctx.buf_len := 0;
            ctx.buf_off := 0;
        end;
        outl  := outl - i;
        out  := out + i;
    end;
    { BIO_clear_retry_flags(b); }
    BIO_copy_next_retry(b);
    Result := get_result(ret = 0 , ret_code , ret);
end;



function b64_write(b : PBIO;{const} data : PByte; inl : integer):integer;
var
  ret, n, i : integer;
  ctx : PBIO_B64_CTX;
  next : PBIO;
begin
    ret := 0;
    ctx := PBIO_B64_CTX(BIO_get_data(b));
    next := BIO_next(b);
    if (ctx = nil) or  (next = nil) then
        Exit(0);
    BIO_clear_retry_flags(b);
    if ctx.encode <> B64_ENCODE then
    begin
        ctx.encode := B64_ENCODE;
        ctx.buf_len := 0;
        ctx.buf_off := 0;
        ctx.tmp_len := 0;
        EVP_EncodeInit(ctx.base64);
    end;
    assert(ctx.buf_off < int(sizeof(ctx.buf)));
    assert(ctx.buf_len <= int(sizeof(ctx.buf)));
    assert(ctx.buf_len >= ctx.buf_off);
    n := ctx.buf_len - ctx.buf_off;
    while n > 0 do
    begin
        i := BIO_write(next, @ctx.buf[ctx.buf_off], n);
        if i <= 0 then begin
            BIO_copy_next_retry(b);
            Exit(i);
        end;
        assert(i <= n);
        ctx.buf_off  := ctx.buf_off + i;
        assert(ctx.buf_off <= int(sizeof(ctx.buf)));
        assert(ctx.buf_len >= ctx.buf_off);
        n  := n - i;
    end;
    { at this point all pending data has been written }
    ctx.buf_off := 0;
    ctx.buf_len := 0;
    if (data = nil) or  (inl <= 0) then
        Exit(0);
    while inl > 0 do
    begin
        n := get_result(inl > B64_BLOCK_SIZE , B64_BLOCK_SIZE , inl);
        if (BIO_get_flags(b) and BIO_FLAGS_BASE64_NO_NL) > 0 then
        begin
            if ctx.tmp_len > 0 then
            begin
                assert(ctx.tmp_len <= 3);
                n := 3 - ctx.tmp_len;
                {
                 * There's a theoretical possibility for this
                 }
                if n > inl then n := inl;
                memcpy(@(ctx.tmp[ctx.tmp_len]), data, n);
                ctx.tmp_len  := ctx.tmp_len + n;
                ret  := ret + n;
                if ctx.tmp_len < 3 then break;
                ctx.buf_len := EVP_EncodeBlock(PByte(@ctx.buf),
                                    PByte(@ctx.tmp), ctx.tmp_len);
                assert(ctx.buf_len <= int(sizeof(ctx.buf)));
                assert(ctx.buf_len >= ctx.buf_off);
                {
                 * Since we're now done using the temporary buffer, the
                 * length should be 0'd
                 }
                ctx.tmp_len := 0;
            end
            else
            begin
                if n < 3 then
                begin
                    memcpy(@ctx.tmp, data, n);
                    ctx.tmp_len := n;
                    ret  := ret + n;
                    break;
                end;
                n  := n - (n mod 3);
                ctx.buf_len := EVP_EncodeBlock(@ctx.buf, data, n);
                assert(ctx.buf_len <= int(sizeof(ctx.buf)));
                assert(ctx.buf_len >= ctx.buf_off);
                ret  := ret + n;
            end;
        end
        else
        begin
            if 0>=EVP_EncodeUpdate(ctx.base64,
                                 PByte(@ctx.buf), @ctx.buf_len, data, n) then
                Result := get_result(ret = 0 , -1 , ret);
            assert(ctx.buf_len <= int(sizeof(ctx.buf)));
            assert(ctx.buf_len >= ctx.buf_off);
            ret  := ret + n;
        end;
        inl  := inl - n;
        data  := data + n;
        ctx.buf_off := 0;
        n := ctx.buf_len;
        while n > 0 do
        begin
            i := BIO_write(next, @ctx.buf[ctx.buf_off], n);
            if i <= 0 then begin
                BIO_copy_next_retry(b);
                Result := get_result(ret = 0 , i , ret);
            end;
            assert(i <= n);
            n  := n - i;
            ctx.buf_off  := ctx.buf_off + i;
            assert(ctx.buf_off <= int(sizeof(ctx.buf)));
            assert(ctx.buf_len >= ctx.buf_off);
        end;
        ctx.buf_len := 0;
        ctx.buf_off := 0;
    end;
    Result := ret;
end;


function b64_ctrl( b : PBIO; cmd : integer; num : long; ptr : Pointer):long;
var
  ctx : PBIO_B64_CTX;
  ret : long;
  i : integer;
  next : PBIO;
  label _again;
begin
    ret := 1;
    ctx := PBIO_B64_CTX(BIO_get_data(b));
    next := BIO_next(b);
   
    if (ctx = nil) or  (next = nil) then
        Exit(0);
    case cmd of
    BIO_CTRL_RESET:
    begin
        ctx.cont := 1;
        ctx.start := 1;
        ctx.encode := B64_NONE;
        ret := BIO_ctrl(next, cmd, num, ptr);
    end;
    BIO_CTRL_EOF:          { More to read }
    begin
        if ctx.cont <= 0 then
           ret := 1
        else
            ret := BIO_ctrl(next, cmd, num, ptr);
    end;
    BIO_CTRL_WPENDING:     { More to write in buffer }
    begin
        assert(ctx.buf_len >= ctx.buf_off);
        ret := ctx.buf_len - ctx.buf_off;
        if (ret = 0)  and  (ctx.encode <> B64_NONE)
             and  (EVP_ENCODE_CTX_num(ctx.base64) <> 0) then
            ret := 1
        else if (ret <= 0) then
            ret := BIO_ctrl(next, cmd, num, ptr);
    end;
    BIO_CTRL_PENDING:      { More to read in buffer }
    begin
        assert(ctx.buf_len >= ctx.buf_off);
        ret := ctx.buf_len - ctx.buf_off;
        if ret <= 0 then ret := BIO_ctrl(next, cmd, num, ptr);
    end;
    BIO_CTRL_FLUSH:
    begin    { do a final write }
 _again:
        while ctx.buf_len <> ctx.buf_off do  begin
            i := b64_write(b, nil, 0);
            if i < 0 then Exit(i);
        end;
        if BIO_get_flags(b) and BIO_FLAGS_BASE64_NO_NL > 0 then
        begin
            if ctx.tmp_len <> 0 then
            begin
                ctx.buf_len := EVP_EncodeBlock(PByte(@ctx.buf),
                                               PByte(@ctx.tmp),
                                               ctx.tmp_len);
                ctx.buf_off := 0;
                ctx.tmp_len := 0;
                goto _again;
            end;
        end
        else
        if (ctx.encode <> B64_NONE)
                    and  (EVP_ENCODE_CTX_num(ctx.base64) <> 0) then
        begin
            ctx.buf_off := 0;
            EVP_EncodeFinal(ctx.base64, PByte(@ctx.buf), @ctx.buf_len);
            { push out the bytes }
            goto _again;
        end;
        { Finally flush the underlying PBIO }
        ret := BIO_ctrl(next, cmd, num, ptr);
    end;
    BIO_C_DO_STATE_MACHINE:
    begin
        BIO_clear_retry_flags(b);
        ret := BIO_ctrl(next, cmd, num, ptr);
        BIO_copy_next_retry(b);
    end;
    BIO_CTRL_DUP:
    begin
      //
    end;
    BIO_CTRL_INFO,
    BIO_CTRL_GET,
    BIO_CTRL_SET:
        ret := BIO_ctrl(next, cmd, num, ptr);
    else
        ret := BIO_ctrl(next, cmd, num, ptr);

    end;
    Result := ret;
end;


function b64_callback_ctrl( b : PBIO; cmd : integer; fp : TBIO_info_cb):long;
var
  next : PBIO;
begin
    next := BIO_next(b);
    if next = nil then Exit(0);
    Result := BIO_callback_ctrl(next, cmd, fp);
end;


function b64_puts(b : PBIO;const str : PUTF8Char):integer;
var
  bt: TBytes;
begin
    bt:= StrToBytes(str);
    Result := b64_write(b, Pbyte(bt), Length(bt));
    SetLength(bt,0);
end;

function BIO_f_base64:PBIO_METHOD;
begin
    Result := @methods_b64;
end;


end.
