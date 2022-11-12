unit openssl3.crypto.asn1_dsa;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
  ID_SEQUENCE = $30;
  ID_INTEGER  = $02;

function ossl_decode_der_dsa_sig(r, s : PBIGNUM;const ppin : PPByte; len : size_t):size_t;
function ossl_decode_der_length( pkt, subpkt : PPACKET):integer;
function ossl_decode_der_integer( pkt : PPACKET; n : PBIGNUM):integer;
function ossl_encode_der_dsa_sig(pkt : PWPACKET;const r, s : PBIGNUM):integer;
function ossl_encode_der_integer(pkt : PWPACKET;const n : PBIGNUM):integer;
function ossl_encode_der_length( pkt : PWPACKET; cont_len : size_t):integer;



implementation
uses openssl3.include.internal.packet, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.packet;





function ossl_encode_der_length( pkt : PWPACKET; cont_len : size_t):integer;
begin
    if cont_len > $ffff then Exit(0); { Too large for supported length encodings }
    if cont_len > $ff then
    begin
        if (0>= WPACKET_put_bytes_u8(pkt, $82))
                 or  (0>= WPACKET_put_bytes_u16(pkt, cont_len)) then
            Exit(0);
    end
    else
    begin
        if (cont_len > $7f)
                 and  (0>= WPACKET_put_bytes_u8(pkt, $81)) then
            Exit(0);
        if 0>= WPACKET_put_bytes_u8(pkt, cont_len) then
            Exit(0);
    end;
    Result := 1;
end;




function ossl_encode_der_integer(pkt : PWPACKET;const n : PBIGNUM):integer;
var
    bnbytes  : PByte;

    cont_len : size_t;
begin
    if BN_is_negative(n ) > 0 then
        Exit(0);
    {
     * Calculate the ASN.1 INTEGER DER content length for n.
     * This is the number of whole bytes required to represent n (i.e. rounded
     * down), plus one.
     * If n is zero then the content is a single zero byte (length = 1).
     * If the number of bits of n is a multiple of 8 then an extra zero padding
     * byte is included to ensure that the value is still treated as positive
     * in the INTEGER two's complement representation.
     }
    cont_len := BN_num_bits(n) div 8 + 1;
    if (0>= WPACKET_start_sub_packet(pkt))  or
       (0>= WPACKET_put_bytes_u8(pkt, ID_INTEGER))
             or  (0>= ossl_encode_der_length(pkt, cont_len))
             or  (0>= WPACKET_allocate_bytes(pkt, cont_len, @bnbytes))
             or  (0>= WPACKET_close(pkt))  then
        Exit(0);
    if (bnbytes <> nil)
             and  (BN_bn2binpad(n, bnbytes, int(cont_len)) <> int (cont_len))  then
        Exit(0);
    Result := 1;
end;





function ossl_encode_der_dsa_sig(pkt : PWPACKET;const r, s : PBIGNUM):integer;
var
  tmppkt   : TWPACKET;
  dummypkt : PWPACKET;

    cont_len : size_t;

    isnull   : integer;
begin
    isnull := WPACKET_is_null_buf(pkt);
    if 0>= WPACKET_start_sub_packet(pkt) then
        Exit(0);
    if 0>= isnull then
    begin
        if 0>= WPACKET_init_null(@tmppkt, 0) then
            Exit(0);
        dummypkt := @tmppkt;
    end
    else
    begin
        { If the input packet has a nil buffer, we don't need a dummy packet }
        dummypkt := pkt;
    end;
    { Calculate the content length }
    if (0>= ossl_encode_der_integer(dummypkt, r))  or
       (0>= ossl_encode_der_integer(dummypkt, s))
             or  (0>= WPACKET_get_length(dummypkt, @cont_len) )
             or ( (0>= isnull)  and  (0>= WPACKET_finish(dummypkt))) then
    begin
        if 0>= isnull then
            WPACKET_cleanup(dummypkt);
        Exit(0);
    end;
    { Add the tag and length bytes }
    if (0>= WPACKET_put_bytes_u8(pkt, ID_SEQUENCE))  or
       (0>= ossl_encode_der_length(pkt, cont_len))
               {
                * Really encode the integers. We already wrote to the main pkt
                * if it had a nil buffer, so don't do it again
                }
             or  ( (0>= isnull)  and  (0>= ossl_encode_der_integer(pkt, r)))
             or  ( (0>= isnull)  and  (0>= ossl_encode_der_integer(pkt, s)))
             or  (0>= WPACKET_close(pkt))  then
        Exit(0);
    Result := 1;
end;



function ossl_decode_der_integer( pkt : PPACKET; n : PBIGNUM):integer;
var
  contpkt, tmppkt : TPACKET;

  tag, tmp : uint32;
begin
    { Check we have an integer and get the content bytes }
    if (0>= PACKET_get_1(pkt, @tag)) or  (tag <> ID_INTEGER)
             or  (0>= ossl_decode_der_length(pkt, @contpkt)) then
        Exit(0);
    { Peek ahead at the first bytes to check for proper encoding }
    tmppkt := contpkt;
    { The INTEGER must be positive }
    if (0>= PACKET_get_1(@tmppkt, @tmp))  or ( (tmp and $80) <> 0) then
        Exit(0);
    { If there a zero padding byte the next byte must have the msb set }
    if (PACKET_remaining(@tmppkt) > 0)  and  (tmp = 0)  then
    begin
        if (0>= PACKET_get_1(@tmppkt, @tmp))
                 or ( (tmp and $80) = 0)  then
            Exit(0);
    end;
    if BN_bin2bn(PACKET_data(@contpkt),
                  int(PACKET_remaining(@contpkt)), n) = nil  then
        Exit(0);
    Result := 1;
end;


function ossl_decode_der_length( pkt, subpkt : PPACKET):integer;
var
  _byte : uint32;
begin
    if 0>= PACKET_get_1(pkt, @_byte) then
        Exit(0);
    if _byte < $80 then Exit(PACKET_get_sub_packet(pkt, subpkt, size_t( _byte)));
    if _byte = $81 then Exit(PACKET_get_length_prefixed_1(pkt, subpkt));
    if _byte = $82 then Exit(PACKET_get_length_prefixed_2(pkt, subpkt));
    { Too large, invalid, or not DER. }
    Result := 0;
end;

function ossl_decode_der_dsa_sig(r, s : PBIGNUM;const ppin : PPByte; len : size_t):size_t;
var
  consumed : size_t;
  pkt,
  contpkt  : TPACKET;
  tag      : uint32;
begin
    if (0>= PACKET_buf_init(@pkt, ppin^, len))  or
       (0>= PACKET_get_1(@pkt, @tag))
             or  (tag <> ID_SEQUENCE)
             or  (0>= ossl_decode_der_length(@pkt, @contpkt) )
             or  (0>= ossl_decode_der_integer(@contpkt, r))
             or  (0>= ossl_decode_der_integer(@contpkt, s))
             or  (PACKET_remaining(@contpkt) <> 0)  then
        Exit(0);
    consumed := PACKET_data(@pkt) - ppin^;
    ppin^  := ppin^ + consumed;
    Result := consumed;
end;


end.
