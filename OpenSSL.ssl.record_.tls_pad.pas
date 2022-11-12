unit OpenSSL.ssl.record_.tls_pad;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

{$define CBC_MAC_ROTATE_IN_PLACE}

function ssl3_cbc_remove_padding_and_mac( reclen : Psize_t; origreclen : size_t; recdata : PByte; mac : PPByte; alloced : PInteger; block_size, mac_size : size_t; libctx : POSSL_LIB_CTX):integer;
function ssl3_cbc_copy_mac( reclen : Psize_t; origreclen : size_t; recdata : PByte; mac : PPByte; alloced : PInteger; block_size, mac_size, good : size_t; libctx : POSSL_LIB_CTX):integer;
function tls1_cbc_remove_padding_and_mac( reclen : Psize_t; origreclen : size_t; recdata : PByte; mac : PPByte; alloced : PInteger; block_size, mac_size : size_t; aead : integer; libctx : POSSL_LIB_CTX):integer;

implementation
uses openssl3.internal.constant_time, OpenSSL3.common,openssl3.crypto.rand.rand_lib,
     openssl3.crypto.mem;





function tls1_cbc_remove_padding_and_mac( reclen : Psize_t; origreclen : size_t; recdata : PByte; mac : PPByte; alloced : PInteger; block_size, mac_size : size_t; aead : integer; libctx : POSSL_LIB_CTX):integer;
var
  good: ssize_t;
  padding_length,
  to_check,
  i,
  overhead       : size_t;

  mask,
  b              : Byte;
begin
    good := -1;
    overhead := get_result((block_size = 1) , 0 , 1) { padding length byte }
                      + mac_size;
    {
     * These lengths are all public so we can test them in non-constant
     * time.
     }
    if overhead > reclen^ then
       Exit(0);
    if block_size <> 1 then
    begin
        padding_length := recdata[reclen^ - 1];
        if aead >0 then
        begin
            { padding is already verified and we don't need to check the MAC }
            reclen^  := reclen^ - (padding_length + 1 + mac_size);
            Exit(1);
        end;
        good := constant_time_ge_s( reclen^, overhead + padding_length);
        {
         * The padding consists of a length byte at the end of the record and
         * then that many bytes of padding, all with the same value as the
         * length byte. Thus, with the length byte included, there are i+1 bytes
         * of padding. We can't check just |padding_length+1| bytes because that
         * leaks decrypted information. Therefore we always have to check the
         * maximum amount of padding possible. (Again, the length of the record
         * is public information so we can use it.)
         }
        to_check := 256;        { maximum amount of padding, inc length byte. }
        if to_check > reclen^ then
           to_check := reclen^;
        for i := 0 to to_check-1 do
        begin
            mask := constant_time_ge_8_s(padding_length, i);
            b := recdata[reclen^ - 1 - i];
            {
             * The final |padding_length+1| bytes should all have the value
             * |padding_length|. Therefore the XOR should be zero.
             }
            good := good and not (mask and (padding_length  xor  b));
        end;
        {
         * If any of the final |padding_length+1| bytes had the wrong value, one
         * or more of the lower eight bits of |good| will be cleared.
         }
        good := constant_time_eq_s($ff, good and $ff);
        reclen^  := reclen^ - (good and (padding_length + 1));
    end;
    Exit(ssl3_cbc_copy_mac(reclen, origreclen, recdata, mac, alloced,
                             block_size, mac_size, good, libctx));
end;




function ssl3_cbc_copy_mac( reclen : Psize_t; origreclen : size_t; recdata : PByte; mac : PPByte; alloced : PInteger; block_size, mac_size, good : size_t; libctx : POSSL_LIB_CTX):integer;
var
  {$IF defined(CBC_MAC_ROTATE_IN_PLACE)}
  rotated_mac_buf : array[0..(64 + EVP_MAX_MD_SIZE)-1] of Byte;
  rotated_mac: PByte;
  {$ELSE}
  rotated_mac: array[0..EVP_MAX_MD_SIZE-1] of Byte;
  {$ENDIF}
  randmac         : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  &out            : PByte;
  mac_end,
  mac_start,
  in_mac,
  scan_start,
  i,
  j,
  rotate_offset,
  mac_started,
  mac_ended       : size_t;
  pb: PByte;
    b               : Byte;
begin


    {
     * mac_end is the index of |recdata| just after the end of the MAC.
     }
    mac_end := reclen^;
    mac_start := mac_end - mac_size;
    {
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     }
    scan_start := 0;
    if not ossl_assert( (origreclen >= mac_size)
                      and  (mac_size <= EVP_MAX_MD_SIZE) ) then
        Exit(0);
    { If no MAC then nothing to be done }
    if mac_size = 0 then
    begin
        { No MAC so we can do this in non-constant time }
        if good = 0 then
            Exit(0);
        Exit(1);
    end;
    reclen^  := reclen^ - mac_size;
    if block_size = 1 then
    begin
        { There's no padding so the position of the MAC is fixed }
        if mac <> nil then
           mac^ := @recdata[reclen^];
        if alloced <> nil then
           alloced^ := 0;
        Exit(1);
    end;
    { Create the random MAC we will emit if padding is bad }
    if RAND_bytes_ex(libctx, @randmac, mac_size, 0 )<= 0 then
        Exit(0);
    if not ossl_assert( (mac <> nil)  and  (alloced <> nil)) then
        Exit(0);
    &out := OPENSSL_malloc(mac_size);
    mac^ := &out;
    if mac^ = nil then Exit(0);
    alloced^ := 1;
{$IF defined(CBC_MAC_ROTATE_IN_PLACE)}
    rotated_mac := PByte(@rotated_mac_buf) + ((0 - size_t(@rotated_mac_buf)) and 63);
{$ENDIF}
    { This information is public so it's safe to branch based on it. }
    if origreclen > mac_size + 255 + 1 then
       scan_start := origreclen - (mac_size + 255 + 1);
    in_mac := 0;
    rotate_offset := 0;
    memset(rotated_mac, 0, mac_size);
    j := 0 ;
    for i := scan_start to origreclen-1 do
    begin
        mac_started := constant_time_eq_s(i, mac_start);
        mac_ended := constant_time_lt_s(i, mac_end);
        b := recdata[i];
        in_mac  := in_mac  or mac_started;
        in_mac := in_mac and mac_ended;
        rotate_offset  := rotate_offset  or (j and mac_started);
        rotated_mac[PostInc(j)]  := rotated_mac[PostInc(j)]  or (b and in_mac);
        j := j and constant_time_lt_s(j, mac_size);
    end;
    { Now rotate the MAC }
{$IF defined(CBC_MAC_ROTATE_IN_PLACE)}
    j := 0;
    for i := 0 to mac_size-1 do
    begin
        { in case cache-line is 32 bytes, touch second line }
        pb := PByte(@rotated_mac[rotate_offset  xor  32]);
        { If the padding wasn't good we emit a random MAC }
        out[PostInc(j)] := constant_time_select_8(Byte(good and $ff),
                                          rotated_mac[PostInc(rotate_offset)],
                                          pb[i]);// randmac[i]);
        rotate_offset := rotate_offset and constant_time_lt_s(rotate_offset, mac_size);
    end;
{$ELSE}
    memset(out, 0, mac_size);
    rotate_offset := mac_size - rotate_offset;
    rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
    for i := 0 to mac_size-1 do begin
        for j := 0 to mac_size-1 do
            out[j]  := out[j]  or (rotated_mac[i] and constant_time_eq_8_s(j, rotate_offset));
        PostInc(rotate_offset);
        rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
        { If the padding wasn't good we emit a random MAC }
        out[i] := constant_time_select_8(Byte( (good and $ff), out[i],
                                        randmac[i]);
    end;
{$ENDIF}
    Result := 1;
end;

function ssl3_cbc_remove_padding_and_mac( reclen : Psize_t; origreclen : size_t; recdata : PByte; mac : PPByte; alloced : PInteger; block_size, mac_size : size_t; libctx : POSSL_LIB_CTX):integer;
var
  padding_length,
  good,
  overhead       : size_t;
begin
     overhead := 1 { padding length byte } + mac_size;

    {
     * These lengths are all public so we can test them in non-constant time.
     }
    if overhead > reclen^ then
       Exit(0);
    padding_length := recdata[reclen^ - 1];
    good := constant_time_ge_s( reclen^, padding_length + overhead);
    { SSLv3 requires that the padding is minimal. }
    good := good and constant_time_ge_s(block_size, padding_length + 1);
    reclen^  := reclen^ - (good and (padding_length + 1));
    Exit(ssl3_cbc_copy_mac(reclen, origreclen, recdata, mac, alloced,
                             block_size, mac_size, good, libctx));
end;


end.
