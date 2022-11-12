unit openssl3.crypto.packet;

interface
uses OpenSSL.Api;

const
   DEFAULT_BUF_SIZE = 256;

function WPACKET_init_static_len( pkt : PWPACKET; buf : PByte; len, lenbytes : size_t):integer;
function maxmaxsize( lenbytes : size_t):size_t;
 function wpacket_intern_init_len( pkt : PWPACKET; lenbytes : size_t):integer;
function WPACKET_allocate_bytes( pkt : PWPACKET; len : size_t; allocbytes : PPByte):integer;
function WPACKET_reserve_bytes( pkt : PWPACKET; len : size_t; allocbytes : PPByte):integer;
function WPACKET_get_curr( pkt : PWPACKET):PByte;
function WPACKET_start_sub_packet_u8(pkt: PWPACKET): int;
function WPACKET_put_bytes_u16(pkt: PWPACKET; val: size_t): int;
function WPACKET_put_bytes__( pkt : PWPACKET; val : cardinal; size : size_t):integer;
function put_value( data : PByte; value, len : size_t):integer;
function WPACKET_start_sub_packet_u24(pkt: PWPACKET): int;
function WPACKET_start_sub_packet_u32(pkt: PWPACKET):int;
function WPACKET_start_sub_packet_len__( pkt : PWPACKET; lenbytes : size_t):integer;
function WPACKET_memcpy(pkt : PWPACKET;const src : Pointer; len : size_t):integer;
 function WPACKET_close( pkt : PWPACKET):integer;
function wpacket_intern_close( pkt : PWPACKET; sub : PWPACKET_SUB; doclose : integer):integer;
function  GETBUF(p : PWPACKET): PByte;
function WPACKET_put_bytes_u8(pkt: PWPACKET; val: size_t): int;
function WPACKET_sub_memcpy_u8(pkt: PWPACKET; src: PByte; len: size_t): int;
function WPACKET_sub_memcpy__(pkt : PWPACKET;const src : Pointer; len, lenbytes : size_t):integer;
function WPACKET_get_total_written( pkt : PWPACKET; written : Psize_t):integer;
function WPACKET_finish( pkt : PWPACKET):integer;
procedure WPACKET_cleanup( pkt : PWPACKET);
function WPACKET_init_der( pkt : PWPACKET; buf : PByte; len : size_t):integer;
function WPACKET_init_null_der( pkt : PWPACKET):integer;
function WPACKET_start_sub_packet( pkt : PWPACKET):integer;
function WPACKET_set_flags( pkt : PWPACKET; flags : uint32):integer;
function WPACKET_init_null( pkt : PWPACKET; lenbytes : size_t):integer;
 function WPACKET_init_len( pkt : PWPACKET; buf : PBUF_MEM; lenbytes : size_t):integer;
 function WPACKET_is_null_buf( pkt : PWPACKET):integer;
 function WPACKET_get_length( pkt : PWPACKET; len : Psize_t):integer;

implementation

uses OpenSSL3.common, openssl3.crypto.mem, openssl3.err,

     openssl3.include.internal.packet, openssl3.crypto.buffer.buffer;





function WPACKET_get_length( pkt : PWPACKET; len : Psize_t):integer;
begin
    { Internal API, so should not fail }
    if not ossl_assert( (pkt.subs <> nil)  and  (len <> nil)) then
        Exit(0);
    len^ := pkt.written - pkt.subs.pwritten;
    Result := 1;
end;

function WPACKET_is_null_buf( pkt : PWPACKET):integer;
begin
    Result := Int( (pkt.buf = nil)  and  (pkt.staticbuf = nil));
end;


function WPACKET_init_len( pkt : PWPACKET; buf : PBUF_MEM; lenbytes : size_t):integer;
begin
    { Internal API, so should not fail }
    if not ossl_assert(buf <> nil) then
        Exit(0);
    pkt.staticbuf := nil;
    pkt.buf := buf;
    pkt.maxsize := maxmaxsize(lenbytes);
    pkt.endfirst := 0;
    Result := wpacket_intern_init_len(pkt, lenbytes);
end;


function WPACKET_init_null( pkt : PWPACKET; lenbytes : size_t):integer;
begin
    pkt.staticbuf := nil;
    pkt.buf := nil;
    pkt.maxsize := maxmaxsize(lenbytes);
    pkt.endfirst := 0;
    Result := wpacket_intern_init_len(pkt, 0);
end;

function WPACKET_set_flags( pkt : PWPACKET; flags : uint32):integer;
begin
    { Internal API, so should not fail }
    if  not ossl_assert(pkt.subs <> nil )then
        Exit(0);
    pkt.subs.flags := flags;
    Result := 1;
end;

function WPACKET_start_sub_packet( pkt : PWPACKET):integer;
begin
    Result := WPACKET_start_sub_packet_len__(pkt, 0);
end;


function WPACKET_init_null_der( pkt : PWPACKET):integer;
begin
    pkt.staticbuf := nil;
    pkt.buf := nil;
    pkt.maxsize := SIZE_MAX;
    pkt.endfirst := 1;
    Result := wpacket_intern_init_len(pkt, 0);
end;



function WPACKET_init_der( pkt : PWPACKET; buf : PByte; len : size_t):integer;
begin
    { Internal API, so should not fail }
    if  not ossl_assert( (buf <> nil)  and  (len > 0) )then
        Exit(0);
    pkt.staticbuf := buf;
    pkt.buf := nil;
    pkt.maxsize := len;
    pkt.endfirst := 1;
    Result := wpacket_intern_init_len(pkt, 0);
end;






procedure WPACKET_cleanup( pkt : PWPACKET);
var
  sub, parent : PWPACKET_SUB;
begin
    sub := pkt.subs;
    while ( sub <> nil )do
    begin
        parent := sub.parent;
        OPENSSL_free(Pointer(sub));
        sub := parent
    end;
    pkt.subs := nil;
end;





function WPACKET_finish( pkt : PWPACKET):integer;
var
  ret : integer;
begin
    {
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     }
    if (pkt.subs = nil)  or  (pkt.subs.parent <> nil) then Exit(0);
    ret := wpacket_intern_close(pkt, pkt.subs, 1);
    if ret>0 then
    begin
        OPENSSL_free(Pointer(pkt.subs));
        pkt.subs := nil;
    end;
    Result := ret;
end;

function WPACKET_get_total_written( pkt : PWPACKET; written : Psize_t):integer;
begin
    { Internal API, so should not fail }
    if  not ossl_assert(written <> nil)  then
        Exit(0);
    written^ := pkt.written;
    Result := 1;
end;

function WPACKET_sub_memcpy__(pkt : PWPACKET;const src : Pointer; len, lenbytes : size_t):integer;
begin
    if  (0>= WPACKET_start_sub_packet_len__(pkt, lenbytes))  or
        (0>= WPACKET_memcpy(pkt, src, len) )      or
        (0>= WPACKET_close(pkt))  then
        Exit(0);
    Result := 1;
end;

function WPACKET_sub_memcpy_u8(pkt: PWPACKET; src: PByte; len: size_t): int;
begin
   Result := WPACKET_sub_memcpy__((pkt), (src), (len), 1);
end;




function wpacket_intern_close( pkt : PWPACKET; sub : PWPACKET_SUB; doclose : integer):integer;
var
    packlen     : size_t;

    buf         : PByte;

  tmplen,
  numlenbytes : size_t;
begin
    packlen := pkt.written - sub.pwritten;
    if (packlen = 0)
             and ( (sub.flags and WPACKET_FLAGS_NON_ZERO_LENGTH) <> 0)  then
        Exit(0);
    if packlen = 0
             and  sub.flags and WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH then begin
        { We can't handle this case. Return an error }
        if  0>= doclose then
            Exit(0);
        { Deallocate any bytes allocated for the length of the PWPACKET  /
        if pkt.curr - sub.lenbytes then = sub.packet_len then  {
            pkt.written  := pkt.written - sub.lenbytes;
            pkt.curr  := pkt.curr - sub.lenbytes;
        }
        { Don't write out the packet length }
        sub.packet_len := 0;
        sub.lenbytes := 0;
    end;
    { Write out the WPACKET length if needed }
    if sub.lenbytes > 0 then begin
        buf := GETBUF(pkt);
        if (buf <> nil)  and
           (0>= put_value(@buf[sub.packet_len], packlen,
                              sub.lenbytes))  then
            Exit(0);
    end
    else
    if (pkt.endfirst>0)  and  (sub.parent <> nil) and
     ( (packlen <> 0)  or
       ( (sub.flags and WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) = 0)) then
    begin
        tmplen := packlen;
        numlenbytes := 1;
        tmplen := tmplen  shr  8;
        while (tmplen  > 0 ) do
        begin
            Inc(numlenbytes);
            tmplen := tmplen  shr  8;
        end;
        if  0>= WPACKET_put_bytes__(pkt, packlen, numlenbytes) then
            Exit(0);
        if packlen > $7f then
        begin
            numlenbytes  := numlenbytes  or $80;
            if  0>= WPACKET_put_bytes_u8(pkt, numlenbytes )  then
                Exit(0);
        end;
    end;
    if doclose > 0 then
    begin
        pkt.subs := sub.parent;
        OPENSSL_free(Pointer(sub));
    end;
    Result := 1;
end;





function WPACKET_close( pkt : PWPACKET):integer;
begin
    {
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     }
    if (pkt.subs = nil)  or  (pkt.subs.parent = nil) then Exit(0);
    Result := wpacket_intern_close(pkt, pkt.subs, 1);
end;

function WPACKET_memcpy(pkt : PWPACKET;const src : Pointer; len : size_t):integer;
var
  dest : PByte;
begin
    if len = 0 then Exit(1);
    if 0>= WPACKET_allocate_bytes(pkt, len, @dest) then
        Exit(0);
    if dest <> nil then memcpy(dest, src, len);
    Result := 1;
end;




function WPACKET_start_sub_packet_len__( pkt : PWPACKET; lenbytes : size_t):integer;
var
    sub      : PWPACKET_SUB;

    lenchars : PByte;
begin
    { Internal API, so should not fail }
    if  not ossl_assert(pkt.subs <> nil) then
        Exit(0);
    { We don't support lenbytes greater than 0 when doing endfirst writing }
    if (lenbytes > 0)  and  (pkt.endfirst>0) then Exit(0);
    sub := OPENSSL_zalloc(sizeof( sub^ ));
    if sub =  nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    sub.parent := pkt.subs;
    pkt.subs := sub;
    sub.pwritten := pkt.written + lenbytes;
    sub.lenbytes := lenbytes;
    if lenbytes = 0 then
    begin
        sub.packet_len := 0;
        Exit(1);
    end;
    sub.packet_len := pkt.written;
    if  0>= WPACKET_allocate_bytes(pkt, lenbytes, @lenchars) then
        Exit(0);
    Result := 1;
end;

function WPACKET_put_bytes_u8(pkt: PWPACKET; val: size_t): int;
begin
   Result := WPACKET_put_bytes__((pkt), (val), 1)
end;

function WPACKET_start_sub_packet_u8(pkt: PWPACKET): int;
begin
    Result := WPACKET_start_sub_packet_len__((pkt), 1)
end;

function WPACKET_start_sub_packet_u24(pkt: PWPACKET): int;
begin
   Result := WPACKET_start_sub_packet_len__((pkt), 3)
end;

function WPACKET_start_sub_packet_u32(pkt: PWPACKET):int;
begin
   Result := WPACKET_start_sub_packet_len__((pkt), 4)
end;

function put_value( data : PByte; value, len : size_t):integer;
begin
    if data = nil then Exit(1);
    data  := data + (len - 1);
    while ( len > 0) do
    begin
        data^ := Byte(value and $ff);
        Dec(data);
        value := value shr 8;
    end;
    { Check whether we could fit the value in the assigned number of bytes }
    if value > 0 then Exit(0);
    Result := 1;
end;



function WPACKET_put_bytes__( pkt : PWPACKET; val : cardinal; size : size_t):integer;
var
  data : PByte;
begin
    { Internal API, so should not fail }
    if  (not ossl_assert(size <= sizeof(UINT)) )
             or  ( 0>= WPACKET_allocate_bytes(pkt, size, @data))
             or  ( 0>= put_value(data, val, size))  then
        Exit(0);
    Result := 1;
end;

function WPACKET_put_bytes_u16(pkt: PWPACKET; val: size_t): int;
begin
   Result := WPACKET_put_bytes__((pkt), (val), 2)
end;

function  GETBUF(p : PWPACKET): PByte;
var
  p2: PByte;
begin

   if p.buf <> nil then
      p2 := PByte(p.buf.data)
   else
      p2 := nil;
   if p.staticbuf <> nil then
      Result := p.staticbuf
   else
      Result := p2;
end;

function WPACKET_get_curr( pkt : PWPACKET):PByte;
var
  buf : PByte;
begin
    buf := GETBUF(pkt);
    if buf = nil then Exit(nil);
    if pkt.endfirst>0 then
       Exit(buf + pkt.maxsize - pkt.curr);
    Result := buf + pkt.curr;
end;

function WPACKET_reserve_bytes( pkt : PWPACKET; len : size_t; allocbytes : PPByte):integer;
var
  newlen, reflen : size_t;
begin
    { Internal API, so should not fail }
    if  (not ossl_assert(pkt.subs <> nil))  and  (len <> 0 ) then
        Exit(0);
    if pkt.maxsize - pkt.written < len then Exit(0);
    if (pkt.buf <> nil)  and  (pkt.buf.length - pkt.written < len) then
    begin
        reflen := get_result(len > pkt.buf.length, len , pkt.buf.length);
        if reflen > SIZE_MAX div 2 then
        begin
            newlen := SIZE_MAX;
        end
        else
        begin
            newlen := reflen * 2;
            if newlen < DEFAULT_BUF_SIZE then
               newlen := DEFAULT_BUF_SIZE;
        end;
        if BUF_MEM_grow(pkt.buf, newlen)= 0  then
            Exit(0);
    end;
    if allocbytes <> nil then
    begin
        allocbytes^ := WPACKET_get_curr(pkt);
        if (pkt.endfirst>0)  and  (allocbytes^ <> nil )then
           allocbytes^  := allocbytes^ - len;
    end;
    Result := 1;
end;


function WPACKET_allocate_bytes( pkt : PWPACKET; len : size_t; allocbytes : PPByte):integer;
begin
    if  0>= WPACKET_reserve_bytes(pkt, len, allocbytes) then
        Exit(0);
    pkt.written  := pkt.written + len;
    pkt.curr  := pkt.curr + len;
    Result := 1;
end;



function wpacket_intern_init_len( pkt : PWPACKET; lenbytes : size_t):integer;
var
  lenchars : PByte;
begin
    pkt.curr := 0;
    pkt.written := 0;
    pkt.subs := OPENSSL_zalloc(sizeof( pkt.subs^));
    if pkt.subs = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if lenbytes = 0 then Exit(1);
    pkt.subs.pwritten := lenbytes;
    pkt.subs.lenbytes := lenbytes;
    if  0>= WPACKET_allocate_bytes(pkt, lenbytes, @lenchars) then
    begin
        OPENSSL_free(Pointer(pkt.subs));
        pkt.subs := nil;
        Exit(0);
    end;
    pkt.subs.packet_len := 0;
    Result := 1;
end;

function maxmaxsize( lenbytes : size_t):size_t;
begin
    if (lenbytes >= sizeof(size_t)) or  (lenbytes = 0)  then
        Exit(SIZE_MAX);
    Result := (size_t(1)  shl  (lenbytes * 8)) - 1 + lenbytes;
end;

function WPACKET_init_static_len( pkt : PWPACKET; buf : PByte; len, lenbytes : size_t):integer;
var
  max : size_t;
begin
    max := maxmaxsize(lenbytes);
    { Internal API, so should not fail }
    if  (not ossl_assert(buf <> nil))  and  (len > 0) then
        Exit(0);
    pkt.staticbuf := buf;
    pkt.buf := nil;
    pkt.maxsize := get_result(max < len , max , len);
    pkt.endfirst := 0;
    Result := wpacket_intern_init_len(pkt, lenbytes);
end;

end.
