unit OpenSSL.ssl.s3_cbc;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
    LARGEST_DIGEST_CTX = TSHA512_CTX;
    Tmd_final_raw_func = procedure(ctx: Pointer ; block: PByte);
    Tmd_transform_func = procedure(ctx: Pointer ; const block: PByte);

const
   MAX_HASH_BIT_COUNT_BYTES = 16;
   MAX_HASH_BLOCK_SIZE      = 128;

function ssl3_cbc_digest_record(const md : PEVP_MD; md_out : PByte; md_out_size : Psize_t;const header, data : PByte; data_size, data_plus_mac_plus_padding_size : size_t;const mac_secret : PByte; mac_secret_length : size_t; is_sslv3 : byte):integer;
procedure tls1_sha1_final_raw( ctx : Pointer; md_out : PByte);
 procedure tls1_md5_final_raw( ctx : Pointer; md_out : PByte);
  procedure tls1_sha256_final_raw( ctx : Pointer; md_out : PByte);
 procedure tls1_sha512_final_raw( ctx : Pointer; md_out : PByte);

var
  length_is_big_endian: Byte = 1;

implementation
uses
   OpenSSL3.common, openssl3.crypto.evp.evp_lib, openssl3.crypto.md5.md5_dgst,
   openssl3.crypto.sha.sha_local, openssl3.crypto.sha.sha1dgst,
   openssl3.crypto.sha.sha256, openssl3.crypto.sha.sha512,
   openssl3.crypto.evp.digest,
   openssl3.internal.constant_time;

type
  md_state_st = record
    case Integer of
      0: (align: Double);
      1: (align_int: ossl_uintmax_t);
      2: (align_ptr: Pointer);
      3: (c: array [0..sizeof(LARGEST_DIGEST_CTX)-1] of Byte);
  end;

function get_result(condition: Boolean;result1, result2: size_t): size_t;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;

procedure l2n8(l: uint64; c: PByte);
begin
   PostInc(c)^ :=Byte((l shr 56) and $ff);
   PostInc(c)^ :=Byte((l shr 48) and $ff);
   PostInc(c)^ :=Byte((l shr 40) and $ff);
   PostInc(c)^ :=Byte((l shr 32) and $ff);
   PostInc(c)^ :=Byte((l shr 24) and $ff);
   PostInc(c)^ :=Byte((l shr 16) and $ff);
   PostInc(c)^ :=Byte((l shr  8) and $ff);
   PostInc(c)^ :=Byte((l    ) and $ff);
end;

procedure u32toLE(n: uint32; p: PByte);
begin
  PostInc(p)^ :=Byte(n);
  PostInc(p)^ :=Byte(n shr 8);
  PostInc(p)^ :=Byte(n shr 16);
  PostInc(p)^ :=Byte(n shr 24);
end;

procedure tls1_md5_final_raw( ctx : Pointer; md_out : PByte);
var
  md5 : PMD5_CTX;
begin
    md5 := ctx;
    u32toLE(md5.A, md_out);
    u32toLE(md5.B, md_out);
    u32toLE(md5.C, md_out);
    u32toLE(md5.D, md_out);
end;

procedure l2n(l: Uint32; c: PByte);
begin
     PostInc(c)^ :=Byte((l shr 24) and $ff);
     PostInc(c)^ :=Byte((l shr 16) and $ff);
     PostInc(c)^ :=Byte((l shr  8) and $ff);
     PostInc(c)^ :=Byte((l    ) and $ff);
end;






procedure tls1_sha256_final_raw( ctx : Pointer; md_out : PByte);
var
  sha256 : PSHA256_CTX;

  i : unsigned;
begin
    sha256 := ctx;
    for i := 0 to 7 do begin
        l2n(sha256.h[i], md_out);
    end;
end;


procedure tls1_sha1_final_raw( ctx : Pointer; md_out : PByte);
var
  sha1 : PSHA_CTX;
begin
    sha1 := ctx;
    l2n(sha1.h0, md_out);
    l2n(sha1.h1, md_out);
    l2n(sha1.h2, md_out);
    l2n(sha1.h3, md_out);
    l2n(sha1.h4, md_out);
end;

procedure tls1_sha512_final_raw( ctx : Pointer; md_out : PByte);
var
  sha512 : PSHA512_CTX;

  i : unsigned;
begin
    sha512 := ctx;
    for i := 0 to 7 do begin
        l2n8(sha512.h[i], md_out);
    end;
end;

function ssl3_cbc_digest_record(const md : PEVP_MD; md_out : PByte; md_out_size : Psize_t;const header, data : PByte; data_size, data_plus_mac_plus_padding_size : size_t;const mac_secret : PByte; mac_secret_length : size_t; is_sslv3 : byte):integer;
var


  md_size,
  md_block_size,
  sslv3_pad_length,
  header_length, variance_blocks,
  len, max_mac_bytes, num_blocks,
  num_starting_blocks, k, mac_end_offset, c, index_a, index_b ,
  bits                 : size_t;

  length_bytes         : array[0..(MAX_HASH_BIT_COUNT_BYTES)-1] of Byte;
  hmac_pad,
  first_block          : array[0..(MAX_HASH_BLOCK_SIZE)-1] of Byte;
  mac_out              : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  i,
  j                    : size_t;
  md_out_size_u        : unsigned;
  md_ctx               : PEVP_MD_CTX;
  md_length_size       : size_t;
  length_is_big_endian : byte;
  ret                  : integer;
  overhang             : size_t;
  block                : array[0..(MAX_HASH_BLOCK_SIZE)-1] of Byte;
  is_block_a,
  is_block_b,
  b, is_past_c, is_past_cp1: Byte;
  md_state          : md_state_st;
  md_transform: Tmd_transform_func;
  md_final_raw :Tmd_final_raw_func ;
  label _Err;
begin

    //void ( *md_final_raw) (Pointer ctx, PByte md_out);
    //void ( *md_transform) (Pointer ctx, const PByte block);
    md_block_size := 64;
    sslv3_pad_length := 40;
    { hmac_pad is the masked HMAC key. }
    md_ctx := nil;
    {
     * mdLengthSize is the number of bytes in the length field that
     * terminates * the hash.
     }
    md_length_size := 8;
    length_is_big_endian := 1;
    ret := 0;
    {
     * This is a, hopefully redundant, check that allows us to forget about
     * many possible overflows later in this function.
     }
    if not ossl_assert(data_plus_mac_plus_padding_size < 1024 * 1024) then
        Exit(0);
    if EVP_MD_is_a(md, 'MD5') then
    begin
{$IFDEF FIPS_MODULE}
        Exit(0);
{$ELSE} if MD5_Init(PMD5_CTX (@ md_state.c))  <= 0 then
            Exit(0);
        md_final_raw := tls1_md5_final_raw;
        md_transform := MD5_Transform;
        md_size := 16;
        sslv3_pad_length := 48;
        length_is_big_endian := 0;
{$ENDIF}
    end
    else
    if (EVP_MD_is_a(md, 'SHA1')) then
    begin
        if _SHA1_Init(PSHA_CTX (@ md_state.c)) <= 0  then
            Exit(0);
        md_final_raw := tls1_sha1_final_raw;
        md_transform := _SHA1_Transform;
        md_size := 20;
    end
    else
    if (EVP_MD_is_a(md, 'SHA2-224')) then
    begin
        if _SHA224_Init(PSHA256_CTX(@ md_state.c )) <= 0 then
            Exit(0);
        md_final_raw := tls1_sha256_final_raw;
        md_transform := SHA256_Transform;
        md_size := 224 div 8;
     end
     else
     if (EVP_MD_is_a(md, 'SHA2-256')) then
     begin
        if _SHA256_Init(PSHA256_CTX(@ md_state.c)) <= 0  then
            Exit(0);
        md_final_raw := tls1_sha256_final_raw;
        md_transform := SHA256_Transform;
        md_size := 32;
     end
     else
     if (EVP_MD_is_a(md, 'SHA2-384')) then
     begin
        if _SHA384_Init(PSHA512_CTX (@md_state.c)) <= 0 then
            Exit(0);
        md_final_raw := tls1_sha512_final_raw;
        md_transform := SHA512_Transform;
        md_size := 384 div 8;
        md_block_size := 128;
        md_length_size := 16;
    end
    else
    if (EVP_MD_is_a(md, 'SHA2-512')) then
    begin
        if _SHA512_Init(PSHA512_CTX (@md_state.c)) <= 0  then
            Exit(0);
        md_final_raw := tls1_sha512_final_raw;
        md_transform := SHA512_Transform;
        md_size := 64;
        md_block_size := 128;
        md_length_size := 16;
    end
    else
    begin
        {
         * ssl3_cbc_record_digest_supported should have been called first to
         * check that the hash function is supported.
         }
        if md_out_size <> nil then
           md_out_size^ := 0;
        Exit( Int(ossl_assert(Boolean(0))) );
    end;
    if (not ossl_assert(md_length_size <= MAX_HASH_BIT_COUNT_BYTES ))  or
       (not ossl_assert(md_block_size <= MAX_HASH_BLOCK_SIZE) )
             or  (not ossl_assert(md_size <= EVP_MAX_MD_SIZE)) then
        Exit(0);
    header_length := 13;
    if is_sslv3 >0 then
    begin
        header_length := mac_secret_length + sslv3_pad_length + 8 { sequence
                                                                  * number }
  +
            1 { record type }
  +
            2 { record length }
 ;
    end;
    {
     * variance_blocks is the number of blocks of the hash that we have to
     * calculate in constant time because they could be altered by the
     * padding value. In SSLv3, the padding must be minimal so the end of
     * the plaintext varies by, at most, 15+20 = 35 bytes. (We conservatively
     * assume that the MAC size varies from 0..20 bytes.) In case the 9 bytes
     * of hash termination ($80 + 64-bit length) don't fit in the final
     * block, we say that the final two blocks can vary based on the padding.
     * TLSv1 has MACs up to 48 bytes long (SHA-384) and the padding is not
     * required to be minimal. Therefore we say that the final |variance_blocks|
     * blocks can
     * vary based on the padding. Later in the function, if the message is
     * short and there obviously cannot be this many blocks then
     * variance_blocks can be reduced.
     }
    variance_blocks := get_result(is_sslv3 >0, 2 , ( ((255 + 1 + md_size + md_block_size - 1) div md_block_size) + 1) );
    {
     * From now on we're dealing with the MAC, which conceptually has 13
     * bytes of `header' before the start of the data (TLS) or 71/75 bytes
     * (SSLv3)
     }
    len := data_plus_mac_plus_padding_size + header_length;
    {
     * max_mac_bytes contains the maximum bytes of bytes in the MAC,
     * including * |header|, assuming that there's no padding.
     }
    max_mac_bytes := len - md_size - 1;
    { num_blocks is the maximum number of hash blocks. }
    num_blocks := (max_mac_bytes + 1 + md_length_size + md_block_size -
         1) div md_block_size;
    {
     * In order to calculate the MAC in constant time we have to handle the
     * final blocks specially because the padding value could cause the end
     * to appear somewhere in the final |variance_blocks| blocks and we can't
     * leak where. However, |num_starting_blocks| worth of data can be hashed
     * right away because no padding value can affect whether they are
     * plaintext.
     }
    num_starting_blocks := 0;
    {
     * k is the starting byte offset into the conceptual header or data where
     * we start processing.
     }
    k := 0;
    {
     * mac_end_offset is the index just past the end of the data to be MACed.
     }
    mac_end_offset := data_size + header_length;
    {
     * c is the index of the $80 byte in the final hash block that contains
     * application data.
     }
    c := mac_end_offset mod md_block_size;
    {
     * index_a is the hash block number that contains the $80 terminating
     * value.
     }
    index_a := mac_end_offset div md_block_size;
    {
     * index_b is the hash block number that contains the 64-bit hash length,
     * in bits.
     }
    index_b := (mac_end_offset + md_length_size) div md_block_size;
    {
     * bits is the hash-length in bits. It includes the additional hash block
     * for the masked HMAC key, or whole of |header| in the case of SSLv3.
     }
    {
     * For SSLv3, if we're going to have any starting blocks then we need at
     * least two because the header is larger than a single block.
     }
    if num_blocks > variance_blocks + get_result(is_sslv3>0 , 1 , 0 ) then
    begin
        num_starting_blocks := num_blocks - variance_blocks;
        k := md_block_size * num_starting_blocks;
    end;
    bits := 8 * mac_end_offset;
    if 0>= is_sslv3 then
    begin
        {
         * Compute the initial HMAC block. For SSLv3, the padding and secret
         * bytes are included in |header| because they take more than a
         * single block.
         }
        bits  := bits + (8 * md_block_size);
        memset(@hmac_pad, 0, md_block_size);
        if not ossl_assert(mac_secret_length <= sizeof(hmac_pad)) then
            Exit(0);
        memcpy(@hmac_pad, mac_secret, mac_secret_length);
        for i := 0 to md_block_size-1 do
            hmac_pad[i]  := hmac_pad[i] xor $36;
        md_transform(@md_state.c, @hmac_pad);
    end;
    if length_is_big_endian>0 then
    begin
        memset(@length_bytes, 0, md_length_size - 4);
        length_bytes[md_length_size - 4] := Byte (bits  shr  24);
        length_bytes[md_length_size - 3] := Byte (bits  shr  16);
        length_bytes[md_length_size - 2] := Byte (bits  shr  8);
        length_bytes[md_length_size - 1] := Byte( bits);
    end
    else
    begin
        memset(@length_bytes, 0, md_length_size);
        length_bytes[md_length_size - 5] := Byte(bits  shr  24);
        length_bytes[md_length_size - 6] := Byte(bits  shr  16);
        length_bytes[md_length_size - 7] := Byte(bits  shr  8);
        length_bytes[md_length_size - 8] := Byte(bits);
    end;
    if k > 0 then
    begin
        if is_sslv3 >0 then
        begin
            {
             * The SSLv3 header is larger than a single block. overhang is
             * the number of bytes beyond a single block that the header
             * consumes: either 7 bytes (SHA1) or 11 bytes (MD5). There are no
             * ciphersuites in SSLv3 that are not SHA1 or MD5 based and
             * therefore we can be confident that the header_length will be
             * greater than |md_block_size|. However we add a sanity check just
             * in case
             }
            if header_length <= md_block_size then
            begin
                { Should never happen }
                Exit(0);
            end;
            overhang := header_length - md_block_size;
            md_transform(@md_state.c, header);
            memcpy(@first_block, header + md_block_size, overhang);
            memcpy(PByte(@first_block) + overhang, data, md_block_size - overhang);
            md_transform(@md_state.c, @first_block);
            for i := 1 to k div md_block_size - 1-1 do
                md_transform(@md_state.c, data + md_block_size * i - overhang);
        end
        else
        begin
            { k is a multiple of md_block_size. }
            memcpy(@first_block, header, 13);
            memcpy(PByte(@first_block) + 13, data, md_block_size - 13);
            md_transform(@md_state.c, @first_block);
            for i := 1 to k div md_block_size-1 do
                md_transform(@md_state.c, data + md_block_size * i - 13);
        end;
    end;
    memset(@mac_out, 0, sizeof(mac_out));
    {
     * We now process the final hash blocks. For each block, we construct it
     * in constant time. If the |i=index_a| then we'll include the $80
     * bytes and zero pad etc. For each block we selectively copy it, in
     * constant time, to |mac_out|.
     }
    for i := num_starting_blocks to num_starting_blocks + variance_blocks do
    begin
        is_block_a := constant_time_eq_8_s(i, index_a);
        is_block_b := constant_time_eq_8_s(i, index_b);
        for j := 0 to md_block_size-1 do
        begin
            b := 0;
            if k < header_length then
               b := header[k]
            else
            if (k < data_plus_mac_plus_padding_size + header_length) then
                b := data[k - header_length];
            Inc(k);
            is_past_c := is_block_a and constant_time_ge_8_s(j, c);
            is_past_cp1 := is_block_a and constant_time_ge_8_s(j, c + 1);
            {
             * If this is the block containing the end of the application
             * data, and we are at the offset for the $80 value, then
             * overwrite b with $80.
             }
            b := constant_time_select_8(is_past_c, $80, b);
            {
             * If this block contains the end of the application data
             * and we're past the $80 value then just write zero.
             }
            b := b and (not is_past_cp1);
            {
             * If this is index_b (the final block), but not index_a (the end
             * of the data), then the 64-bit length didn't fit into index_a
             * and we're having to add an extra block of zeros.
             }
            b := b and (not is_block_b) or is_block_a;
            {
             * The final bytes of one of the blocks contains the length.
             }
            if j >= md_block_size - md_length_size then begin
                { If this is index_b, write a length byte. }
                b := constant_time_select_8(is_block_b,
                                           length_bytes[j -
                                                        (md_block_size -
                                                         md_length_size)], b);
            end;
            block[j] := b;
        end;
        md_transform(@md_state.c, @block);
        md_final_raw(@md_state.c, @block);
        { If this is index_b, copy the hash value to |mac_out|. }
        for j := 0 to md_size-1 do
            mac_out[j]  := mac_out[j]  or (block[j] and is_block_b);
    end;
    md_ctx := EVP_MD_CTX_new();
    if md_ctx = nil then
       goto _err ;
    if EVP_DigestInit_ex(md_ctx, md, nil) { engine } <= 0 then
        goto _err ;
    if is_sslv3>0 then
    begin
        { We repurpose |hmac_pad| to contain the SSLv3 pad2 block. }
        memset(@hmac_pad, $5c, sslv3_pad_length);
        if (EVP_DigestUpdate(md_ctx, mac_secret, mac_secret_length) <= 0)
             or  (EVP_DigestUpdate(md_ctx, @hmac_pad, sslv3_pad_length) <= 0 )
             or  (EVP_DigestUpdate(md_ctx, @mac_out, md_size) <= 0)  then
            goto _err ;
    end
    else
    begin
        { Complete the HMAC in the standard manner. }
        for i := 0 to md_block_size-1 do
            hmac_pad[i]  := hmac_pad[i] xor $6a;
        if (EVP_DigestUpdate(md_ctx, @hmac_pad, md_block_size)  <= 0 )
             or  (EVP_DigestUpdate(md_ctx, @mac_out, md_size) <= 0) then
            goto _err ;
    end;
    ret := EVP_DigestFinal(md_ctx, md_out, @md_out_size_u);
    if (ret >0 ) and  (md_out_size <> nil) then
       md_out_size^ := md_out_size_u;
    ret := 1;
 _err:
    EVP_MD_CTX_free(md_ctx);
    Result := ret;
end;

end.
