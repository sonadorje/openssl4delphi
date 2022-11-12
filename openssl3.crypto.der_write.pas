unit openssl3.crypto.der_write;

interface
uses OpenSSL.Api;
type
  Tput_bytes_func = function (pkt : PWPACKET;const v : Pointer; top_byte : Puint32):integer;


function ossl_DER_w_begin_sequence( pkt : PWPACKET; tag : integer):int;
function ossl_DER_w_octet_string(pkt : PWPACKET; tag : integer;const data : PByte; data_n : size_t):integer;
function int_end_context( pkt : PWPACKET; tag : integer):integer;
function ossl_DER_w_octet_string_uint32( pkt : PWPACKET; tag : integer; value : uint32):integer;
function ossl_DER_w_precompiled(pkt : PWPACKET; tag : integer;const precompiled : PByte; precompiled_n : size_t):integer;
function ossl_DER_w_end_sequence( pkt : PWPACKET; tag : integer):integer;
 function ossl_DER_w_null( pkt : PWPACKET; tag : integer):integer;
function int_start_context( pkt : PWPACKET; tag : integer):integer;
function ossl_DER_w_ulong( pkt : PWPACKET; tag : integer; v : Cardinal):integer;
function int_der_w_integer(pkt : PWPACKET; tag : integer; put_bytes : Tput_bytes_func;const v : Pointer):integer;
function int_put_bytes_ulong(pkt : PWPACKET;const v : Pointer; top_byte : Puint32):integer;

implementation
uses
   openssl3.crypto.packet, OpenSSL3.common ;





function int_put_bytes_ulong(pkt : PWPACKET;const v : Pointer; top_byte : Puint32):integer;
var
  value : Puint32;
  tmp: uint32;
  n : size_t;
begin
    value := v;
    tmp := value^;
    n := 0;
    while tmp <> 0 do
    begin
        Inc(n);
        top_byte^ := (tmp and $FF);
        tmp := tmp shr 8;
    end;
    if n = 0 then n := 1;
    Result := WPACKET_put_bytes__(pkt, value^, n);
end;



function int_der_w_integer(pkt : PWPACKET; tag : integer; put_bytes : Tput_bytes_func;const v : Pointer):integer;
var
  top_byte : uint32;
begin
    top_byte := 0;
    Result := Int( (int_start_context(pkt, tag)>0)
         and ( WPACKET_start_sub_packet(pkt) >0)
         and ( put_bytes(pkt, v, @top_byte)>0)
         and  ( ((top_byte and $80) = 0)  or  (WPACKET_put_bytes_u8(pkt, 0)>0) )
         and ( WPACKET_close(pkt)>0)
         and ( WPACKET_put_bytes_u8(pkt, DER_P_INTEGER)>0)
         and ( int_end_context(pkt, tag)>0) );
end;




function ossl_DER_w_ulong( pkt : PWPACKET; tag : integer; v : Cardinal):integer;
begin
    Result := int_der_w_integer(pkt, tag, int_put_bytes_ulong, @v);
end;






function ossl_DER_w_null( pkt : PWPACKET; tag : integer):integer;
begin
    Result := Int( (int_start_context(pkt, tag)>0)
         and  (WPACKET_start_sub_packet(pkt)>0)
         and  (WPACKET_close(pkt)>0)
         and  (WPACKET_put_bytes_u8(pkt, DER_P_NULL)>0)
         and  (int_end_context(pkt, tag)>0) );
end;

function ossl_DER_w_end_sequence( pkt : PWPACKET; tag : integer):integer;
var
  size1, size2 : size_t;
  ok: int;
begin
    {
     * If someone set the flag WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH on this
     * sub-packet and this sub-packet has nothing written to it, the DER length
     * will not be written, and the total written size will be unchanged before
     * and after WPACKET_close().  We use size1 and size2 to determine if
     * anything was written, and only write our tag if it has.
     *
     * Because we know that int_end_context() needs to do the same check,
     * we reproduce this flag if the written length was unchanged, or we will
     * have an erroneous context tag.
     }
    if size1 = size2 then
       ok := WPACKET_set_flags(pkt, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH)
    else
       ok := WPACKET_put_bytes_u8(pkt, DER_F_CONSTRUCTED or DER_P_SEQUENCE);

    Result := int( (WPACKET_get_total_written(pkt, @size1)>0)
         and  (WPACKET_close(pkt)>0)
         and  (WPACKET_get_total_written(pkt, @size2)>0)
         and  (ok>0)
         and  (int_end_context(pkt, tag)>0));
end;

function ossl_DER_w_precompiled(pkt : PWPACKET; tag : integer;const precompiled : PByte; precompiled_n : size_t):integer;
begin
    Result := int( (int_start_context(pkt, tag)>0)
         and  (WPACKET_memcpy(pkt, precompiled, precompiled_n)>0)
         and  (int_end_context(pkt, tag)>0));
end;




function ossl_DER_w_octet_string_uint32( pkt : PWPACKET; tag : integer; value : uint32):integer;
var
  tmp : array[0..3] of Byte;

  pbuf : PByte;
begin
    FillChar(tmp,4,0);
    pbuf := PByte(@tmp) + (sizeof(tmp) - 1);
    while value > 0 do
    begin
        pbuf^ := ((value and $FF));
        Dec(pbuf);
        value := value shr 8;
    end;
    Result := ossl_DER_w_octet_string(pkt, tag, @tmp, sizeof(tmp));
end;




function int_end_context( pkt : PWPACKET; tag : integer):integer;
var
  size1, size2 : size_t;
begin
    {
     * If someone set the flag WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH on this
     * sub-packet and this sub-packet has nothing written to it, the DER length
     * will not be written, and the total written size will be unchanged before
     * and after WPACKET_close().  We use size1 and size2 to determine if
     * anything was written, and only write our tag if it has.
     *
     }
    if tag < 0 then Exit(1);
    if  not ossl_assert(tag <= 30)    then
        Exit(0);
    { Context specific are normally (?) constructed }
    tag  := tag  or (DER_F_CONSTRUCTED or DER_C_CONTEXT);
    Result := int( (WPACKET_get_total_written(pkt, @size1)>0)
         and  (WPACKET_close(pkt) >0)
         and  (WPACKET_get_total_written(pkt, @size2)>0)
         and  ( (size1 = size2)  or  (WPACKET_put_bytes_u8(pkt, tag)>0) ));
end;




function ossl_DER_w_octet_string(pkt : PWPACKET; tag : integer;const data : PByte; data_n : size_t):integer;
begin
    Result := int( (int_start_context(pkt, tag)>0)
         and  (WPACKET_start_sub_packet(pkt)>0)
         and  (WPACKET_memcpy(pkt, data, data_n)>0)
         and  (WPACKET_close(pkt)>0)
         and  (WPACKET_put_bytes_u8(pkt, DER_P_OCTET_STRING)>0)
         and  (int_end_context(pkt, tag)>0));
end;

function int_start_context( pkt : PWPACKET; tag : integer):integer;
begin
    if (tag < 0) then Exit(1);
    if  not ossl_assert(tag <= 30)  then
        Exit(0);
    Result := WPACKET_start_sub_packet(pkt);
end;



function ossl_DER_w_begin_sequence( pkt : PWPACKET; tag : integer):int;
begin
    Result := int( (int_start_context(pkt, tag)>0 )
         and  (WPACKET_start_sub_packet(pkt)>0) );
end;


end.
