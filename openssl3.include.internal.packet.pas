unit openssl3.include.internal.packet;

interface
 uses OpenSSL.Api;

function PACKET_buf_init(pkt : PPACKET;const buf : PByte; len : size_t):integer;
function PACKET_get_1( pkt : PPACKET; data : Puint32):integer;
 function PACKET_peek_1(const pkt : PPACKET; data : Puint32):integer;
function PACKET_remaining(const pkt : PPACKET):size_t;
procedure packet_forward( pkt : PPACKET; len : size_t);
function PACKET_get_sub_packet( pkt, subpkt : PPACKET; len : size_t):integer;
function PACKET_peek_sub_packet(const pkt : PPACKET; subpkt : PPACKET; len : size_t):integer;
function PACKET_get_length_prefixed_1( pkt, subpkt : PPACKET):integer;
function PACKET_get_bytes(pkt : PPACKET;const data : PPByte; len : size_t):integer;
function PACKET_peek_bytes(const pkt : PPACKET; data : PPByte; len : size_t):integer;
function PACKET_get_length_prefixed_2( pkt, subpkt : PPACKET):integer;
function PACKET_get_net_2( pkt : PPACKET; data : Puint32):integer;
function PACKET_peek_net_2(const pkt : PPACKET; data : Puint32):integer;
function PACKET_data(const pkt : PPACKET):PByte;

implementation


function PACKET_data(const pkt : PPACKET):PByte;
begin
    Result := pkt.curr;
end;



function PACKET_peek_net_2(const pkt : PPACKET; data : Puint32):integer;
begin
    if PACKET_remaining(pkt) < 2  then
        Exit(0);
    data^ := (uint32( pkt^.curr))  shl  8;
    data^  := data^  or ( (pkt.curr + 1)^);
    Result := 1;
end;



function PACKET_get_net_2( pkt : PPACKET; data : Puint32):integer;
begin
    if 0>= PACKET_peek_net_2(pkt, data) then
        Exit(0);
    packet_forward(pkt, 2);
    Result := 1;
end;



function PACKET_get_length_prefixed_2( pkt, subpkt : PPACKET):integer;
var
  _length : uint32;

  data : PByte;

  tmp : TPACKET;
begin
    tmp := pkt^;
    if (0>= PACKET_get_net_2(@tmp, @_length))  or
       (0>= PACKET_get_bytes(@tmp, @data, size_t( _length)))  then
    begin
        Exit(0);
    end;
    pkt^ := tmp;
    subpkt.curr := data;
    subpkt.remaining := _length;
    Result := 1;
end;



function PACKET_peek_bytes(const pkt : PPACKET; data : PPByte; len : size_t):integer;
begin
    if PACKET_remaining(pkt) < len  then
        Exit(0);
    data^ := pkt.curr;
    Result := 1;
end;



function PACKET_get_bytes(pkt : PPACKET;const data : PPByte; len : size_t):integer;
begin
    if 0>= PACKET_peek_bytes(pkt, data, len) then
        Exit(0);
    packet_forward(pkt, len);
    Result := 1;
end;



function PACKET_get_length_prefixed_1( pkt, subpkt : PPACKET):integer;
var
  length : uint32;

  data : PByte;

  tmp : TPACKET;
begin
    tmp := pkt^;
    if (0>= PACKET_get_1(@tmp, @length)) or
       (0>= PACKET_get_bytes(@tmp, @data, size_t( length))) then
    begin
        Exit(0);
    end;
    pkt^ := tmp;
    subpkt.curr := data;
    subpkt.remaining := length;
    Result := 1;
end;



function PACKET_peek_sub_packet(const pkt : PPACKET; subpkt : PPACKET; len : size_t):integer;
begin
    if PACKET_remaining(pkt) < len  then
        Exit(0);
    Result := PACKET_buf_init(subpkt, pkt.curr, len);
end;


function PACKET_get_sub_packet( pkt, subpkt : PPACKET; len : size_t):integer;
begin
    if 0>= PACKET_peek_sub_packet(pkt, subpkt, len)  then
        Exit(0);
    packet_forward(pkt, len);
    Result := 1;
end;



procedure packet_forward( pkt : PPACKET; len : size_t);
begin
    pkt.curr  := pkt.curr + len;
    pkt.remaining  := pkt.remaining - len;
end;



function PACKET_remaining(const pkt : PPACKET):size_t;
begin
    Result := pkt.remaining;
end;



function PACKET_peek_1(const pkt : PPACKET; data : Puint32):integer;
begin
    if 0>= PACKET_remaining(pkt) then
        Exit(0);
    data^ := pkt.curr^;
    Result := 1;
end;




function PACKET_get_1( pkt : PPACKET; data : Puint32):integer;
begin
    if 0>= PACKET_peek_1(pkt, data) then
        Exit(0);
    packet_forward(pkt, 1);
    Result := 1;
end;



function PACKET_buf_init(pkt : PPACKET;const buf : PByte; len : size_t):integer;
begin
    { Sanity check for negative values. }
    if len > size_t( (SIZE_MAX div 2)) then
        Exit(0);
    pkt.curr := buf;
    pkt.remaining := len;
    Result := 1;
end;



end.
