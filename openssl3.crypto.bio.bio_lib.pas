unit openssl3.crypto.bio.bio_lib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$I config.inc}

interface
 uses OpenSSL.Api, SysUtils;

function bio_call_callback(b : PBIO; oper : integer;const argp : PUTF8Char; len : size_t; argi : integer; argl, inret : long; processed : Psize_t):long;
function HAS_LEN_OPER(o: integer): Boolean;
function bio_write_intern(b : PBIO;const data : Pointer; dlen : size_t; written : Psize_t):integer;
function HAS_CALLBACK(b: PBIO): Boolean;
function BIO_new(const method : PBIO_METHOD):PBIO;
function BIO_new_ex(libctx : POSSL_LIB_CTX;const method : PBIO_METHOD):PBIO;
procedure BIO_clear_flags( b : PBIO; flags : integer);
function BIO_ctrl( b : PBIO; cmd : integer; larg : long;parg : Pointer):long;
procedure BIO_set_fp(b: PBIO; fp: Pointer; c: integer);
procedure BIO_set_flags( b : PBIO; flags : integer);
function BIO_free( a : PBIO):integer;
function BIO_write(b : PBIO;const data : Pointer; dlen : integer):integer;
function BIO_puts(bp : PBIO;const buf : PUTF8Char):integer;
function BIO_indent( b : PBIO; indent, max : integer):integer;
function BIO_gets( bp : PBIO; buf : PUTF8Char; size : integer):integer;
procedure BIO_clear_retry_flags(b: PBIO);
procedure BIO_set_retry_read(b: PBIO);
//function UI_get_input_flags( uis : PUI_STRING):integer;
function BIO_get_mem_data(b :PBIO; pp: PPointer): LongInt;
function BIO_read( bp : PBIO; data : Pointer; dlen : integer):integer;
function bio_read_intern( b : PBIO; data : Pointer; dlen : size_t; readbytes : Psize_t):integer;
function BIO_tell(b: PBIO): int;
procedure BIO_copy_next_retry( b : PBIO);
function BIO_get_retry_flags(b: PBIO) :Int;
function BIO_test_flags(const b : PBIO; flags : integer):integer;
function BIO_callback_ctrl(b : PBIO; cmd : integer;fp : TBIO_info_cb):long;
function BIO_push( b, bio : PBIO):PBIO;
function BIO_up_ref( a : PBIO):integer;
function BIO_seek(bp: PBIO; ofs: int): Int;
function BIO_pop( b : PBIO):PBIO;
function BIO_set_prefix(b: PBIO; p: Pointer): Long;
procedure BIO_set_data( a : PBIO; ptr : Pointer);
procedure BIO_set_init( a : PBIO; init : integer);
function BIO_get_data( a : PBIO):Pointer;
function BIO_read_ex( b : PBIO; data : Pointer; dlen : size_t; readbytes : Psize_t):integer;
function BIO_next( b : PBIO):PBIO;
function BIO_write_ex(b : PBIO;const data : Pointer; dlen : size_t; written : Psize_t):integer;
function BIO_get_indent(b: PBIO): long;
function BIO_set_indent(b: PBIO; i: int): long;
function BIO_get_mem_ptr(b: PBIO; pp: PPBUF_MEM):Long;
function BIO_should_retry(a: PBIO): int;
procedure BIO_free_all( bio : PBIO);
procedure BIO_vfree( a : PBIO);
function sk_BIO_pop(sk: Pointer): PBIO;

function ossl_check_BIO_type( ptr : PBIO):PBIO;
function ossl_check_BIO_sk_type( sk : Pstack_st_BIO):POPENSSL_STACK;
function ossl_check_BIO_compfunc_type( cmp : sk_BIO_compfunc):OPENSSL_sk_compfunc;
function ossl_check_BIO_copyfunc_type( cpy : sk_BIO_copyfunc):OPENSSL_sk_copyfunc;
function ossl_check_BIO_freefunc_type( fr : sk_BIO_freefunc):OPENSSL_sk_freefunc;
function sk_BIO_new_null:Pstack_st_BIO;
function sk_BIO_push(sk, ptr: Pointer): int;
procedure sk_BIO_free(sk: Pointer);
function sk_BIO_num(sk: Pointer): int;
function ossl_check_const_BIO_sk_type(const sk : Pstack_st_BIO):POPENSSL_STACK;
function BIO_pending(b: PBIO): Int;
function BIO_eof(b: PBIO): Int;
function BIO_get_flags(b: PBio): int;
function BIO_flush(b : PBIO): long;
//function BIO_set_indent(b: PBio;i: int): int;
procedure bio_cleanup;
function BIO_to_string(b : PBIO; Encoding: TEncoding): string; overload;
function BIO_to_string(b : PBIO): string; overload;
function BIO_set_close(b: PBIO; c: int): int;
function BIO_get_callback(const b : PBIO):BIO_callback_fn;
procedure BIO_set_callback( b : PBIO; cb : BIO_callback_fn);
function BIO_get_callback_ex(const b : PBIO):BIO_callback_fn_ex;
procedure BIO_set_callback_ex( b : PBIO; cb : BIO_callback_fn_ex);
procedure BIO_set_callback_arg( b : PBIO; arg : PUTF8Char);
function BIO_get_callback_arg(const b : PBIO):PUTF8Char;
function BIO_method_name(const b : PBIO):PUTF8Char;
function BIO_method_type(const b : PBIO):integer;

implementation

uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.ex_data,
     openssl3.crypto.cryptlib,
     openssl3.crypto.stack,             openssl3.crypto.bio.bio_sock,
     openssl3.crypto.bio.bio_addr,      openssl3.crypto.bio.bio_meth,
     OpenSSL3.threads_none,             openssl3.include.internal.refcount;

function BIO_method_name(const b : PBIO):PUTF8Char;
begin
    Result := b.method.name;
end;


function BIO_method_type(const b : PBIO):integer;
begin
    Result := b.method.&type;
end;

procedure BIO_set_callback_arg( b : PBIO; arg : PUTF8Char);
begin
    b.cb_arg := arg;
end;


function BIO_get_callback_arg(const b : PBIO):PUTF8Char;
begin
    Result := b.cb_arg;
end;

function BIO_get_callback_ex(const b : PBIO):BIO_callback_fn_ex;
begin
    Result := b.callback_ex;
end;


procedure BIO_set_callback_ex( b : PBIO; cb : BIO_callback_fn_ex);
begin
    b.callback_ex := cb;
end;


function BIO_get_callback(const b : PBIO):BIO_callback_fn;
begin
    Result := b.callback;
end;


procedure BIO_set_callback( b : PBIO; cb : BIO_callback_fn);
begin
    b.callback := cb;
end;


function BIO_set_close(b: PBIO; c: int): int;
var
  p: Pointer;
begin
   p := nil;
   Result := int(BIO_ctrl(b,BIO_CTRL_SET_CLOSE, c, p))
end;

function BIO_to_string(b : PBIO; Encoding: TEncoding): string;
const
  BuffSize = 1024;
var
  Buffer: TBytes;
begin
  Result := '';
  SetLength(Buffer, BuffSize);
  while BIO_read(b, buffer, BuffSize) > 0 do
  begin
    Result := Result + Encoding.GetString(Buffer);
  end;
end;

function BIO_to_string(b : PBIO): string;
begin
  Result := BIO_to_string(b, TEncoding.ANSI);
end;

function BIO_get_flags(b: PBio): int;
begin
   Result:= BIO_test_flags(b, not ($0))
end;

procedure bio_cleanup;
begin
{$IFNDEF OPENSSL_NO_SOCK}
    bio_sock_cleanup_int;
    CRYPTO_THREAD_lock_free(bio_lookup_lock);
    bio_lookup_lock := nil;
{$ENDIF}
    CRYPTO_THREAD_lock_free(bio_type_lock);
    bio_type_lock := nil;
end;

function BIO_eof(b: PBIO): Int;
var
  p: Pointer;
begin
   p := nil;
   Result := int(BIO_ctrl(b,BIO_CTRL_EOF, 0, p));
end;

function BIO_pending(b: PBIO): Int;
var
  p: Pointer;
begin
   p := nil;
   Result := int(BIO_ctrl(b, _BIO_CTRL_PENDING, 0, p));
end;

function ossl_check_const_BIO_sk_type(const sk : Pstack_st_BIO):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK(sk);
end;


function sk_BIO_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_BIO_sk_type(sk))
end;

procedure sk_BIO_free(sk: Pointer);
begin
   OPENSSL_sk_free(ossl_check_BIO_sk_type(sk))
end;

function sk_BIO_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr))
end;

function sk_BIO_new_null:Pstack_st_BIO;
begin
   Result := Pstack_st_BIO(OPENSSL_sk_new_null)
end;

function ossl_check_BIO_type( ptr : PBIO):PBIO;
begin
 Exit(ptr);
end;


function ossl_check_BIO_sk_type( sk : Pstack_st_BIO):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_BIO_compfunc_type( cmp : sk_BIO_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_BIO_copyfunc_type( cpy : sk_BIO_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_BIO_freefunc_type( fr : sk_BIO_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_BIO_pop(sk: Pointer): PBIO;
begin
   Result := PBIO(OPENSSL_sk_pop(ossl_check_BIO_sk_type(sk)))
end;


procedure BIO_vfree( a : PBIO);
begin
    BIO_free(a);
end;

procedure BIO_free_all( bio : PBIO);
var
  b : PBIO;
  ref : integer;
begin
    while bio <> nil do
    begin
        b := bio;
        ref := b.references;
        bio := bio.next_bio;
        BIO_free(b);
        { Since ref count > 1, don't free anyone else. }
        if ref > 1 then break;
    end;
end;

function BIO_should_retry(a: PBIO): int;
begin
   Result := BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)
end;

function BIO_get_mem_ptr(b: PBIO; pp: PPBUF_MEM):Long;
begin
   BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0,  Pointer(pp));
end;

function BIO_set_indent(b: PBIO; i: int): long;
var
  p: Pointer;
begin
   p := nil;
   Result := BIO_ctrl(b, BIO_CTRL_SET_INDENT, i, p)
end;

function BIO_get_indent(b: PBIO): long;
var
  p: Pointer;
begin
   p := nil;
  Result := BIO_ctrl(b, BIO_CTRL_GET_INDENT, 0, p)
end;

function BIO_write_ex(b : PBIO;const data : Pointer; dlen : size_t; written : Psize_t):integer;
var
  ret: int;
begin
    ret := bio_write_intern(b, data, dlen, written);
    Result := Int(  (ret > 0) or  ( (b <> nil)  and  (dlen = 0) ) ); { order is important for *written }
end;

function BIO_next( b : PBIO):PBIO;
begin
    if b = nil then Exit(nil);
    Result := b.next_bio;
end;


function BIO_read_ex( b : PBIO; data : Pointer; dlen : size_t; readbytes : Psize_t):integer;
begin
    Result := Int(bio_read_intern(b, data, dlen, readbytes) > 0);
end;


function BIO_get_data( a : PBIO):Pointer;
begin
    Result := a.ptr;
end;

procedure BIO_set_init( a : PBIO; init : integer);
begin
    a.init := init;
end;

procedure BIO_set_data( a : PBIO; ptr : Pointer);
begin
    a.ptr := ptr;
end;

function BIO_set_prefix(b: PBIO; p: Pointer): Long;
begin
   Result := BIO_ctrl(b, BIO_CTRL_SET_PREFIX, 0, Pointer(p))
end;

function BIO_pop( b : PBIO):PBIO;
begin
    if b = nil then Exit(nil);
    Result := b.next_bio;
    BIO_ctrl(b, BIO_CTRL_POP, 0, Pointer(b));
    if b.prev_bio <> nil then
       b.prev_bio.next_bio := b.next_bio;
    if b.next_bio <> nil then
       b.next_bio.prev_bio := b.prev_bio;
    b.next_bio := nil;
    b.prev_bio := nil;

end;

function BIO_seek(bp: PBIO; ofs: int): Int;
var
  p: Pointer;
begin
   p := nil;
   Result := int(BIO_ctrl(bp,BIO_C_FILE_SEEK,ofs, p))
end;

function BIO_up_ref( a : PBIO):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(a.references, i, a.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('BIO', a);
    REF_ASSERT_ISNT(i < 2);
    Result := Int(i > 1);
end;



function BIO_push( b, bio : PBIO):PBIO;
begin
    if b = nil then
       Exit(bio);
    Result := b;
    while Result.next_bio <> nil do
        Result := Result.next_bio;
    Result.next_bio := bio;
    if bio <> nil then
       bio.prev_bio := Result;
    { called to do internal processing }
    BIO_ctrl(b, BIO_CTRL_PUSH, 0, Pointer(Result));
    Result := b;
end;

function BIO_callback_ctrl(b : PBIO; cmd : integer;fp : TBIO_info_cb):long;
var
  ret : long;
begin
    if b = nil then Exit(-2);
    if (b.method = nil)  or  (not Assigned(b.method.callback_ctrl))
             or  (cmd <> BIO_CTRL_SET_CALLBACK) then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD);
        Exit(-2);
    end;
    if HAS_CALLBACK(b) then
    begin
        ret := bio_call_callback(b, BIO_CB_CTRL, Pointer( @fp), 0, cmd, 0, 1,
                                nil);
        if ret <= 0 then
           Exit(ret);
    end;
    ret := b.method.callback_ctrl(b, cmd, fp);
    if HAS_CALLBACK(b) then
        ret := bio_call_callback(b, BIO_CB_CTRL or BIO_CB_RETURN, Pointer(@fp), 0,
                                cmd, 0, ret, nil);
    Result := ret;
end;

function BIO_test_flags(const b : PBIO; flags : integer):integer;
begin
    Result := (b.flags and flags);
end;

function BIO_get_retry_flags(b: PBIO) :Int;
begin
   Result := BIO_test_flags(b, (BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY));
end;



procedure BIO_copy_next_retry( b : PBIO);
begin
    BIO_set_flags(b, BIO_get_retry_flags(b.next_bio));
    b.retry_reason := b.next_bio.retry_reason;
end;

function BIO_tell(b: PBIO): int;
var
  p: Pointer;
begin
    p := nil;
    Result := int(BIO_ctrl(b,BIO_C_FILE_TELL,0, p))
end;


function bio_read_intern( b : PBIO; data : Pointer; dlen : size_t; readbytes : Psize_t):integer;
var
  ret : integer;
  function get_ret: int;
  begin
     ret := int (bio_call_callback(b, BIO_CB_READ, data, dlen, 0, 0, 1,nil));
     Exit(ret);
  end;
begin
    if b = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if (b.method = nil)  or  (Assigned(b.method.bread) = False) then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD);
        Exit(-2);
    end;

    if HAS_CALLBACK(b)  and  (get_ret <= 0)  then
        Exit(ret);
    if 0>= b.init then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED);
        Exit(-1);
    end;
    ret := b.method.bread(b, data, dlen, readbytes);
    if ret > 0 then
       b.num_read  := b.num_read + uint64( readbytes^);
    if HAS_CALLBACK(b) then
        ret := int (bio_call_callback(b, BIO_CB_READ or BIO_CB_RETURN, data,
                                     dlen, 0, 0, ret, readbytes));
    { Shouldn't happen }
    if (ret > 0)  and  (readbytes^ > dlen) then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_INTERNAL_ERROR);
        Exit(-1);
    end;
    Result := ret;
end;


function BIO_read( bp : PBIO; data : Pointer; dlen : integer):integer;
var
    readbytes : size_t;
    ret       : integer;
begin
    if dlen < 0 then
       Exit(0);
    ret := bio_read_intern(bp, data, size_t( dlen), @readbytes);
    if ret > 0 then
    begin
        { *readbytes should always be <= dlen }
        ret := int(readbytes);
    end;
    Result := ret;
end;

function BIO_get_mem_data(b :PBIO; pp: PPointer): LongInt;
begin
   Result :=  BIO_ctrl(b,BIO_CTRL_INFO,0, PUTF8Char(pp))
end;


procedure BIO_set_retry_read(b: PBIO);
begin
    BIO_set_flags(b, (BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY))
end;

procedure BIO_clear_retry_flags(b: PBIO);
begin
   BIO_clear_flags(b, (BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY))
end;

function BIO_gets( bp : PBIO; buf : PUTF8Char; size : integer):integer;
var
    ret       : integer;
    readbytes : size_t;
begin
    readbytes := 0;
    if bp = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if (bp.method = nil)  or  (not Assigned(bp.method.bgets)) then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD);
        Exit(-2);
    end;
    if size < 0 then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_INVALID_ARGUMENT);
        Exit(-1);
    end;
    if HAS_CALLBACK(bp) then
    begin
        ret := int (bio_call_callback(bp, BIO_CB_GETS, buf, size, 0, 0, 1, nil));
        if ret <= 0 then Exit(ret);
    end;
    if 0>= bp.init then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED);
        Exit(-1);
    end;
    ret := bp.method.bgets(bp, buf, size);
    if ret > 0 then begin
        readbytes := ret;
        ret := 1;
    end;
    if HAS_CALLBACK(bp ) then
        ret := int (bio_call_callback(bp, BIO_CB_GETS or BIO_CB_RETURN, buf, size,
                                     0, 0, ret, @readbytes));
    if ret > 0 then
    begin
        { Shouldn't happen }
        if readbytes > size_t( size ) then
            ret := -1
        else
            ret := int(readbytes);
    end;
    Result := ret;
end;



function BIO_indent( b : PBIO; indent, max : integer):integer;
begin
    if indent < 0 then
       indent := 0;
    if indent > max then
       indent := max;
    while PostDec(indent) > 0 do
        if BIO_puts(b, ' ') <> 1  then
           Exit(0);
    Result := 1;
end;

function BIO_puts(bp : PBIO;const buf : PUTF8Char):integer;
var
  ret : integer;
  written : size_t;
begin
    written := 0;
    if bp = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if (bp.method = nil)  or  (not Assigned(bp.method.bputs)) then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD);
        Exit(-2);
    end;
    if HAS_CALLBACK(bp) then
    begin
        ret := int (bio_call_callback(bp, BIO_CB_PUTS, buf, 0, 0, 0, 1, nil));
        if ret <= 0 then
           Exit(ret);
    end;
    if 0>= bp.init then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED);
        Exit(-1);
    end;
    ret := bp.method.bputs(bp, buf);
    if ret > 0 then
    begin
        bp.num_write  := bp.num_write + uint64( ret);
        written := ret;
        ret := 1;
    end;
    if HAS_CALLBACK(bp) then
        ret := int (bio_call_callback(bp, BIO_CB_PUTS or BIO_CB_RETURN, buf, 0, 0,
                                     0, ret, @written));
    if ret > 0 then
    begin
        if written > INT_MAX then
        begin
            ERR_raise(ERR_LIB_BIO, BIO_R_LENGTH_TOO_LONG);
            ret := -1;
        end
        else
        begin
            ret := int(written);
        end;
    end;
    Result := ret;
end;

function BIO_write(b : PBIO;const data : Pointer; dlen : integer):integer;
var
  written : size_t;
  ret : integer;
begin
    if dlen <= 0 then
       Exit(0);
    ret := bio_write_intern(b, data, size_t( dlen), @written);
    if ret > 0 then
    begin
        { written should always be <= dlen }
        ret := int(written);
    end;
    Result := ret;
end;

function BIO_free( a : PBIO):integer;
var
  ret : integer;
begin
    if a = nil then Exit(0);
    if CRYPTO_DOWN_REF(a.references, ret, a.lock) <= 0 then
        Exit(0);
    REF_PRINT_COUNT('BIO', a);
    if ret > 0 then
       Exit(1);
    REF_ASSERT_ISNT(ret < 0);


    if HAS_CALLBACK(a ) then
    begin
        ret := int (bio_call_callback(a, BIO_CB_FREE, nil, 0, 0, 0, 1, nil));
        if ret <= 0 then Exit(0);
    end;
    if (a.method <> nil)  and  (Assigned(a.method.destroy)) then
        a.method.destroy(a);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, @a.ex_data);
    CRYPTO_THREAD_lock_free(a.lock);
    OPENSSL_free(a);
    //TType_Info.Empty(a);
    Result := 1;
end;


procedure BIO_set_flags( b : PBIO; flags : integer);
begin
    b.flags  := b.flags  or flags;
end;

procedure BIO_set_fp(b: PBIO; fp: Pointer; c: long);
begin
   BIO_ctrl(b, BIO_C_SET_FILE_PTR, c, fp)
end;


procedure BIO_clear_flags( b : PBIO; flags : integer);
begin
    b.flags := b.flags and (not flags);
end;



function BIO_new_ex(libctx : POSSL_LIB_CTX;const method : PBIO_METHOD):PBIO;
var
  bio : PBIO;
  label _err;
begin
    bio := OPENSSL_zalloc(sizeof( bio^));
    if bio = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    bio.libctx := libctx;
    bio.method := method;
    bio.shutdown := 1;
    bio.references := 1;
    if 0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, @bio.ex_data) then
        goto _err ;
    bio.lock := CRYPTO_THREAD_lock_new();
    if bio.lock = nil then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_MALLOC_FAILURE);
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio, @bio.ex_data);
        goto _err ;
    end;
    if ( Assigned(method.create))  and  (0>= method.create(bio))  then
    begin
        ERR_raise(ERR_LIB_BIO, ERR_R_INIT_FAIL);
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio, @bio.ex_data);
        CRYPTO_THREAD_lock_free(bio.lock);
        goto _err ;
    end;
    if not Assigned(method.create) then
       bio.init := 1;
    Exit(bio);

_err:
    OPENSSL_free(Pointer(bio));
    Result := nil;
end;

function BIO_flush(b : PBIO): long;
var
  p: Pointer;
begin
   p := nil;
   Result := BIO_ctrl(b,BIO_CTRL_FLUSH,0, p);
end;

function BIO_new(const method : PBIO_METHOD):PBIO;
begin
    Result := BIO_new_ex(nil, method);
end;

function BIO_ctrl( b : PBIO; cmd : integer; larg : long; parg : Pointer):long;
var
  ret : long;
begin
    if b = nil then Exit(-1);
    if (b.method = nil)  or  (not Assigned(b.method.ctrl)) then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD);
        Exit(-2);
    end;
    if HAS_CALLBACK(b) then
    begin
        ret := bio_call_callback(b, BIO_CB_CTRL, parg, 0, cmd, larg, 1, nil);
        if ret <= 0 then Exit(ret);
    end;
    ret := b.method.ctrl(b, cmd, larg, parg);
    if HAS_CALLBACK(b)  then
        ret := bio_call_callback(b, BIO_CB_CTRL or BIO_CB_RETURN, parg, 0, cmd,
                                larg, ret, nil);
    Result := ret;
end;

{$ifndef OPENSSL_NO_DEPRECATED_3_0}
function HAS_CALLBACK(b: PBIO): Boolean;
begin
    Result := ( Assigned(b.callback) ) or (Assigned(b.callback_ex));
end;
{$else}
# define HAS_CALLBACK(b) ((b)->callback_ex != NULL)
{$endif}

function bio_write_intern(b : PBIO;const data : Pointer; dlen : size_t; written : Psize_t):integer;
var
    local_written : size_t;
    ret           : integer;
    function get_ret :int;
    begin
       ret := int(bio_call_callback(b, BIO_CB_WRITE, data, dlen, 0, 0, 1, nil));
       Exit(ret);
    end;
begin
    if written <> nil then
       written^ := 0;
    {
     * b = nil is not an error but just means that zero bytes are written.
     * Do not raise an error here.
     }
    if b = nil then
       Exit(0);
    if (b.method = nil)  or  ( not Assigned(b.method.bwrite) ) then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD);
        Exit(-2);
    end;


    if (HAS_CALLBACK(b)) and (get_ret <= 0) then
        Exit(ret);
    if  0>= b.init then
    begin
        ERR_raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED);
        Exit(-1);
    end;
    local_written := 0;
    ret := b.method.bwrite(b, data, dlen, @local_written); //function bwrite_conv
    if ret > 0 then
       b.num_write  := b.num_write + (uint64_t(local_written));
    if HAS_CALLBACK(b)  then
        ret := int(bio_call_callback(b, BIO_CB_WRITE or BIO_CB_RETURN, data,
                                     dlen, 0, 0, ret, @local_written));
    if written <> nil then
       written^ := local_written;
    Result := ret;
end;

function HAS_LEN_OPER(o: integer): Boolean;
begin
   Result := (o = BIO_CB_READ) or (o = BIO_CB_WRITE ) or (o = BIO_CB_GETS);
end;

function bio_call_callback(b : PBIO; oper : integer;const argp : PUTF8Char; len : size_t; argi : integer; argl, inret : long; processed : Psize_t):long;
var
    ret      : long;
    bareoper : integer;
begin
    ret := inret;
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    if Assigned(b.callback_ex ) then
{$endif}
        Exit(b.callback_ex(b, oper, argp, len, argi, argl, inret, processed));
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    { Strip off any BIO_CB_RETURN flag }
    bareoper := oper and (not BIO_CB_RETURN);
    {
     * We have an old style callback, so we will have to do nasty casts and
     * check for overflows.
     }
    if HAS_LEN_OPER(bareoper) then
    begin
        { In this case |len| is set, and should be used instead of |argi| }
        if len > INT_MAX then
            Exit(-1);
        argi := int(len);
    end;
    if (inret > 0)  and  ((oper and BIO_CB_RETURN)>0)  and ( bareoper <> BIO_CB_CTRL) then
    begin
        if processed^ > INT_MAX then
            Exit(-1);
        inret := processed^;
    end;
    ret := b.callback(b, oper, argp, argi, argl, inret);
    if (ret > 0)  and ( (oper and BIO_CB_RETURN)>0)  and  (bareoper <> BIO_CB_CTRL) then
    begin
        processed^ := size_t(ret);
        ret := 1;
    end;
{$ENDIF}
    Result := ret;
end;

end.
