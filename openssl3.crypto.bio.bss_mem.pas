unit openssl3.crypto.bio.bss_mem;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils, math;

type
  bio_buf_mem_st = record
    buf,   (* allocated buffer *)
    readp: PBUF_MEM; (* read pointer *)
  end;
  TBIO_BUF_MEM = bio_buf_mem_st;
  PBIO_BUF_MEM = ^TBIO_BUF_MEM;

  function BIO_s_mem:PBIO_METHOD;
  function BIO_s_secmem:PBIO_METHOD;
  function BIO_new_mem_buf(const buf : Pointer; len : integer):PBIO;
  function mem_init( bi : PBIO; flags : Cardinal):integer;
  function mem_new( bi : PBIO):integer;
  function secmem_new( bi : PBIO):integer;
  function mem_free( a : PBIO):integer;
  function mem_buf_free( a : PBIO):integer;
  function mem_buf_sync( b : PBIO):integer;
  function mem_read( bp : PBIO; _out : PUTF8Char; outl : integer):integer;
  function mem_write(bp : PBIO;{const} _in : PByte; inl : integer):integer;
  function mem_ctrl( bp : PBIO; cmd : integer; num : long; ptr : Pointer):long;
  function mem_gets( bp : PBIO; buf : PUTF8Char; size : integer):integer;
  function mem_puts(bp : PBIO;const str : PUTF8Char):integer;


implementation
uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}
     openssl3.crypto.bio.bio_meth, OpenSSL3.Err, openssl3.crypto.bio.bio_lib,
     openssl3.crypto.mem, openssl3.crypto.buffer.buffer;

const mem_method: TBIO_METHOD  = (
    &type: BIO_TYPE_MEM;
    name: 'memory buffer';
    bwrite: bwrite_conv;
    bwrite_old: mem_write;
    bread: bread_conv;
    bread_old: mem_read;
    bputs: mem_puts;
    bgets: mem_gets;
    ctrl: mem_ctrl;
    create: mem_new;
    destroy: mem_free;
    callback_ctrl: nil                      (* mem_callback_ctrl *)
);
 secmem_method: TBIO_METHOD = (
    &type: BIO_TYPE_MEM;
    name: 'secure memory buffer';
    bwrite: bwrite_conv;
    bwrite_old: mem_write;
    bread: bread_conv;
    bread_old: mem_read;
    bputs: mem_puts;
    bgets: mem_gets;
    ctrl: mem_ctrl;
    create: secmem_new;
    destroy: mem_free;
    callback_ctrl: nil;                      (* mem_callback_ctrl *)
);

function BIO_s_mem:PBIO_METHOD;
begin
    Result := @mem_method;
end;


function BIO_s_secmem:PBIO_METHOD;
begin
    Result := (@secmem_method);
end;


function BIO_new_mem_buf(const buf : Pointer; len : integer):PBIO;
var
  b : PBUF_MEM;
  bb : PBIO_BUF_MEM;
  sz : size_t;
begin
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if len < 0 then
       sz := StrSize(PAnsiChar(buf))
    else
       sz := size_t(len);
    result := BIO_new(BIO_s_mem);
    if result = nil then
        Exit(nil);
    bb := PBIO_BUF_MEM(result.ptr);
    b := bb.buf;
    { Cast away const and trust in the MEM_RDONLY flag. }
    // Added by Administrator 2022-09-16 16:20:54
    SetLength(b.buffer, sz);
    Move(Pbyte(buf)^, PByte(b.buffer)^, sz);
    //b.data := Pointer( buf);
    b.data := @b.buffer[0];
    b.length := sz;
    b.max := sz;
    bb.readp^ := bb.buf^;
    result.flags  := result.flags  or BIO_FLAGS_MEM_RDONLY;
    { Since this is  data retrying won't help }
    result.num := 0;

    // Added by Administrator 2022-09-24 15:49:31
    Result.ptrinfo := TypeInfo(PBIO_BUF_MEM);
end;


function mem_init( bi : PBIO; flags : Cardinal):integer;
var
  bb : PBIO_BUF_MEM;
begin
    bb := OPENSSL_zalloc(sizeof( bb^));
    if bb = nil then Exit(0);
    bb.buf := BUF_MEM_new_ex(flags);
    if bb.buf = nil then
    begin
        OPENSSL_free(Pointer(bb));
        Exit(0);
    end;
    bb.readp := OPENSSL_zalloc(sizeof(bb.readp^));
    if bb.readp = nil then
    begin
        BUF_MEM_free(bb.buf);
        OPENSSL_free(Pointer(bb));
        Exit(0);
    end;
    bb.readp^ := bb.buf^;
    bi.shutdown := 1;
    bi.init := 1;
    bi.num := -1;
    bi.ptr := PUTF8Char(  bb);
    Result := 1;
end;


function mem_new( bi : PBIO):integer;
begin
    Result := mem_init(bi, 0);
end;


function secmem_new( bi : PBIO):integer;
begin
    Result := mem_init(bi, BUF_MEM_FLAG_SECURE);
end;


function mem_free( a : PBIO):integer;
var
  bb : PBIO_BUF_MEM;
begin
    if a = nil then Exit(0);
    bb := PBIO_BUF_MEM(a.ptr);
    if 0>= mem_buf_free(a) then
        Exit(0);
    OPENSSL_free(Pointer(bb.readp));
    OPENSSL_free(Pointer(bb));
    Result := 1;
end;


function mem_buf_free( a : PBIO):integer;
var
  bb : PBIO_BUF_MEM;
  b : PBUF_MEM;
begin
    if a = nil then Exit(0);
    if (a.shutdown>0)  and  (a.init>0)  and  (a.ptr <> nil) then
    begin
        bb := PBIO_BUF_MEM(a.ptr);
        b := bb.buf;
        if (a.flags and BIO_FLAGS_MEM_RDONLY)>0 then
           b.data := nil;
        BUF_MEM_free(b);
    end;
    Result := 1;
end;


function mem_buf_sync( b : PBIO):integer;
var
  bbm : PBIO_BUF_MEM;
begin
    if (b <> nil)  and  (b.init <> 0)  and  (b.ptr <> nil) then
    begin
        bbm := PBIO_BUF_MEM(b.ptr);
        if bbm.readp.data <> bbm.buf.data then
        begin
            memmove(bbm.buf.data, bbm.readp.data, bbm.readp.length);
            bbm.buf.length := bbm.readp.length;
            bbm.readp.data := bbm.buf.data;
        end;
    end;
    Result := 0;
end;


function mem_read( bp : PBIO; _out : PUTF8Char; outl : integer):integer;
var
  ret : integer;
  bbm : PBIO_BUF_MEM;
  bm : PBUF_MEM;
begin
    ret := -1;
    bbm := PBIO_BUF_MEM(bp.ptr);
    bm := bbm.readp;
    if (bp.flags and BIO_FLAGS_MEM_RDONLY) > 0 then
       bm := bbm.buf;
    BIO_clear_retry_flags(bp);
    ret := get_result((outl >= 0)  and  (size_t(outl) > bm.length) , int(bm.length) , outl);
    if (_out <> nil)  and  (ret > 0) then
    begin
        memcpy(_out, bm.data, ret);
        bm.length  := bm.length - ret;
        bm.max  := bm.max - ret;
        bm.data  := bm.data + ret;
        if bm.length = 1 then
           dec(bm.length);//减去结尾符#0
    end
    else
    if (bm.length = 0) then
    begin
        ret := bp.num;
        if ret <> 0 then
           BIO_set_retry_read(bp);
    end;

    Result := ret;
end;


function mem_write(bp : PBIO;{const} _in : PByte; inl : integer):integer;
var
  ret, blen : integer;
  bbm : PBIO_BUF_MEM;
  label _end;
begin
    ret := -1;
    bbm := PBIO_BUF_MEM(bp.ptr);
    if (bp.flags and BIO_FLAGS_MEM_RDONLY)>0 then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_WRITE_TO_READ_ONLY_BIO);
        goto _end ;
    end;
    BIO_clear_retry_flags(bp);
    if inl = 0 then Exit(0);
    if _in = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        goto _end ;
    end;
    blen := bbm.readp.length;
    mem_buf_sync(bp);
    if BUF_MEM_grow_clean(bbm.buf, blen + inl) = 0  then
        goto _end ;
    //memcpy(bbm.buf.data + blen, _in, inl);
    memcpy(PByte(bbm.buf.buffer) + blen, _in, inl);
    bbm.readp^ := bbm.buf^;
    ret := inl;
 _end:
    Result := ret;
end;


function mem_ctrl( bp : PBIO; cmd : integer; num : long; ptr : Pointer):long;
var
  ret, I : long;
  bbm : PBIO_BUF_MEM;
  bm, bo : PBUF_MEM;
  off, remain : long;
  pptr : PPAnsiChar;
  label _fall;
begin
    ret := 1;
    bbm := PBIO_BUF_MEM(bp.ptr);
    if (bp.flags and BIO_FLAGS_MEM_RDONLY)>0 then
    begin
        bm := bbm.buf;
        bo := bbm.readp;
    end
    else
    begin
        bm := bbm.readp;
        bo := bbm.buf;
    end;
    off := get_result(bm.data = bo.data , 0 , bm.data - bo.data);
    remain := bm.length;
    case cmd of
        BIO_CTRL_RESET:
        begin
            bm := bbm.buf;
            if bm.data <> nil then
            begin
                if 0>= (bp.flags and BIO_FLAGS_MEM_RDONLY) then
                begin
                    if 0>= (bp.flags and BIO_FLAGS_NONCLEAR_RST) then
                    begin
                        memset(bm.data, 0, bm.max);
                        bm.length := 0;
                    end;
                    bbm.readp^ := bbm.buf^;
                end
                else
                begin
                    { For read only case just reset to the start again }
                    bbm.buf^ := bbm.readp^;
                end;
            end;
        end;
        BIO_C_FILE_SEEK:
        begin
            if (num < 0)  or  (num > off + remain) then
               Exit(-1);   { Can't see outside of the current buffer }
            if (num <> 0) then
                bm.data := bo.data + num
            else
                bm.data := bo.data;
            bm.length := bo.length - num;
            bm.max := bo.max - num;
            off := num;
            { FALLTHRU }
            goto _fall;
        end;
        BIO_C_FILE_TELL:
   _fall:
            ret := off;
        BIO_CTRL_EOF:
            ret := long(bm.length = 0);
            //break;
        BIO_C_SET_BUF_MEM_EOF_RETURN:
        begin
           // break;
        end;
        BIO_CTRL_INFO:
        begin
            ret := long(bm.length);
            if ptr <> nil then
            begin
                pptr := PPAnsiChar(ptr);
                pptr^ := PAnsiChar(bm.data);
            end;
        end;
        BIO_C_SET_BUF_MEM:
        begin
            mem_buf_free(bp);
            bbm.buf := ptr;
            bbm.readp^ := bbm.buf^;
        end;
        BIO_C_GET_BUF_MEM_PTR:
        begin
            if ptr <> nil then
            begin
                if 0>= (bp.flags and BIO_FLAGS_MEM_RDONLY) then
                    mem_buf_sync(bp);
                bm := bbm.buf;
                pptr := PPAnsiChar(ptr);
                pptr^ := PAnsiChar(bm);
                {
                SetLength(PBUF_MEM(ptr).buffer, length(bm.buffer));
                for I := Low(bm.buffer) to High(bm.buffer) do
                   PBUF_MEM(ptr).buffer[I] := bm.buffer[I];
                PBUF_MEM(ptr).length := bm.length;
                PBUF_MEM(ptr).max := bm.max;
                PBUF_MEM(ptr).flags := bm.flags;
                }

            end;
        end;
        BIO_CTRL_GET_CLOSE:
            ret := long(bp.shutdown);
            //break;
        BIO_CTRL_SET_CLOSE:
            begin
              //break;
            end;
        _BIO_CTRL_WPENDING:
            ret := 0;
            //break;
        _BIO_CTRL_PENDING:
            ret := long(bm.length);
            //break;
        BIO_CTRL_DUP,
        BIO_CTRL_FLUSH:
            ret := 1;
            //break;
        BIO_CTRL_PUSH,
        BIO_CTRL_POP:
        begin
          //
        end;
        else
            ret := 0;
            //break;
    end;
    Result := ret;
end;


function mem_gets( bp : PBIO; buf : PUTF8Char; size : integer):integer;
var
  i, j, ret : integer;
  p : PUTF8Char;
  bbm : PBIO_BUF_MEM;
  bm : PBUF_MEM;
begin
    ret := -1;
    bbm := PBIO_BUF_MEM(bp.ptr);
    bm := bbm.readp;
    if (bp.flags and BIO_FLAGS_MEM_RDONLY)>0 then
       bm := bbm.buf;
    BIO_clear_retry_flags(bp);
    j := bm.length;
    if size - 1  < j then
        j := size - 1;
    if j <= 0 then
    begin
        buf^ := #0;
        Exit(0);
    end;
    p := bm.data;

    for i := 0  to j-1 do
    begin
        if p[i] = #10 then
        begin
            break;
        end;
    end;
    {
     * i is now the max num of bytes to copy, either j or up to
     * and including the first newline
     }
    Inc(i);

    i := mem_read(bp, buf, i);
    if i > 0 then buf[i] := #0;
    ret := i;
    Result := ret;
end;


function mem_puts(bp : PBIO;const str : PUTF8Char):integer;
var
  n, ret : integer;
begin
    n := Strlen(str);
    ret := mem_write(bp, PByte(str), n);
    { memory semantics is that it will always work }
    Result := ret;
    // Added by Administrator 2022-09-24 23:47:40
    if bp.ptrinfo = nil then
       bp.ptrinfo := TypeInfo(PBIO_BUF_MEM);
end;

end.
