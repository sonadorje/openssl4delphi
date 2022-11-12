unit openssl3.crypto.bn.bn_rand;

interface
uses OpenSSL.Api, SysUtils;

type
  bnrand_flag_e = (NORMAL, TESTING, _PRIVATE);
 TBNRAND_FLAG = bnrand_flag_e;

function BN_priv_rand_range_ex(r : PBIGNUM;const range : PBIGNUM; strength : uint32; ctx : PBN_CTX):integer;
function bnrand_range(flag : TBNRAND_FLAG; r : PBIGNUM;const range : PBIGNUM; strength : uint32; ctx : PBN_CTX):integer;
function bnrand( flag : TBNRAND_FLAG; rnd : PBIGNUM; bits, top, bottom : integer; strength : uint32; ctx : PBN_CTX):integer;
function BN_priv_rand_ex( rnd : PBIGNUM; bits, top, bottom : integer; strength : uint32; ctx : PBN_CTX):integer;
function BN_generate_dsa_nonce(_out : PBIGNUM;const range, priv : PBIGNUM; message : PByte; message_len : size_t; ctx : PBN_CTX):integer;
function BN_rand_ex( rnd : PBIGNUM; bits, top, bottom : integer; strength : uint32; ctx : PBN_CTX):integer;


implementation
uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.evp.digest,
     openssl3.crypto.evp.evp_rand, openssl3.crypto.bn.bn_add;

{$POINTERMATH ON}
function BN_rand_ex( rnd : PBIGNUM; bits, top, bottom : integer; strength : uint32; ctx : PBN_CTX):integer;
begin
    Result := bnrand(NORMAL, rnd, bits, top, bottom, strength, ctx);
end;

function BN_generate_dsa_nonce(_out : PBIGNUM;const range, priv : PBIGNUM; message : PByte; message_len : size_t; ctx : PBN_CTX):integer;
var
    mdctx         : PEVP_MD_CTX;
    random_bytes  : array[0..63] of Byte;
    digest        : array[0..(SHA512_DIGEST_LENGTH)-1] of Byte;
    done,
    todo,
    num_k_bytes   : uint32;
    private_bytes : array[0..95] of Byte;
    k_bytes       : PByte;
    ret           : integer;
    md            : PEVP_MD;
    libctx        : POSSL_LIB_CTX;
    label _err;
begin
    mdctx := EVP_MD_CTX_new();
    {
     * We use 512 bits of random data per iteration to ensure that we have at
     * least |range| bits of randomness.
     }
    { We generate |range|+8 bytes of random output. }
    num_k_bytes := BN_num_bytes(range) + 8;
    k_bytes := nil;
    ret := 0;
    md := nil;
    libctx := ossl_bn_get_libctx(ctx);
    if mdctx = nil then goto _err ;
    k_bytes := OPENSSL_malloc(num_k_bytes);
    if k_bytes = nil then goto _err ;
    { We copy |priv| into a local buffer to avoid exposing its length. }
    if BN_bn2binpad(priv, @private_bytes, sizeof(private_bytes )) < 0  then
    begin
        {
         * No reasonable DSA or ECDSA key should have a private key this
         * large and we don't handle this case in order to avoid leaking the
         * length of the private key.
         }
        ERR_raise(ERR_LIB_BN, BN_R_PRIVATE_KEY_TOO_LARGE);
        goto _err ;
    end;
    md := EVP_MD_fetch(libctx, 'SHA512', nil);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_NO_SUITABLE_DIGEST);
        goto _err ;
    end;

    done := 0;
    while done <= num_k_bytes-1 do
    begin
        if RAND_priv_bytes_ex(libctx, @random_bytes, sizeof(random_bytes) , 0) <= 0  then
            goto _err ;
        if (0>= EVP_DigestInit_ex(mdctx, md, nil)) or
           (0>= EVP_DigestUpdate(mdctx, @done, sizeof(done)))
           or  (0>= EVP_DigestUpdate(mdctx, @private_bytes, sizeof(private_bytes)))
           or  (0>= EVP_DigestUpdate(mdctx, message, message_len))
           or  (0>= EVP_DigestUpdate(mdctx, @random_bytes, sizeof(random_bytes)))
           or  (0>= EVP_DigestFinal_ex(mdctx, @digest, nil))  then
            goto _err ;
        todo := num_k_bytes - done;
        if todo > SHA512_DIGEST_LENGTH then
           todo := SHA512_DIGEST_LENGTH;
        memcpy(k_bytes + done, @digest, todo);
        done  := done + todo;
    end;
    if nil = BN_bin2bn(k_bytes, num_k_bytes, _out )then
        goto _err ;
    if BN_mod(_out, _out, range, ctx) <> 1  then
        goto _err ;
    ret := 1;

 _err:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    OPENSSL_free(k_bytes);
    OPENSSL_cleanse(@private_bytes, sizeof(private_bytes));
    Result := ret;
end;


function BN_priv_rand_ex( rnd : PBIGNUM; bits, top, bottom : integer; strength : uint32; ctx : PBN_CTX):integer;
begin
    Result := bnrand(_PRIVATE, rnd, bits, top, bottom, strength, ctx);
end;

function bnrand( flag : TBNRAND_FLAG; rnd : PBIGNUM; bits, top, bottom : integer; strength : uint32; ctx : PBN_CTX):integer;
var
  buf : TBytes;
  b, ret, bit, bytes, mask : integer;
  libctx : POSSL_LIB_CTX;
  i : integer;
  c : Byte;
  label _toosmall, _err;
begin
    buf := nil;
    ret := 0;
    libctx := ossl_bn_get_libctx(ctx);
    if bits = 0 then
    begin
        if (top <> BN_RAND_TOP_ANY)  or  (bottom <> BN_RAND_BOTTOM_ANY) then
            goto _toosmall ;
        BN_zero(rnd);
        Exit(1);
    end;
    if (bits < 0)  or  ( (bits = 1)  and  (top > 0 ) )then
        goto _toosmall ;
    bytes := (bits + 7) div 8;
    bit := (bits - 1) mod 8;
    mask := $ff  shl  (bit + 1);
    //buf := OPENSSL_malloc(bytes);
    SetLength(buf, bytes) ;
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    { make a random number and set the top and bottom bits }
    if flag = NORMAL then
       b :=  RAND_bytes_ex(libctx, @buf[0], bytes, strength)
    else
       b := RAND_priv_bytes_ex(libctx, @buf[0], bytes, strength);

    if b <= 0 then goto _err ;
    if flag = TESTING then
    begin
        {
         * generate patterns that are more likely to trigger BN library bugs
         }
        for i := 0 to bytes-1 do
        begin
            if RAND_bytes_ex(libctx, @c, 1, strength) <= 0 then
                goto _err ;
            if (c >= 128)  and  (i > 0) then
               buf[i] := buf[i - 1]
            else
            if (c < 42) then
                buf[i] := 0
            else
            if (c < 84) then
                buf[i] := 255;
        end;
    end;
    if top >= 0 then
    begin
        if Boolean(top) then
        begin
            if bit = 0 then
            begin
                buf[0] := 1;
                buf[1] := buf[1]  or $80;
            end
            else
            begin
                buf[0] := buf[0]  or ((3  shl  (bit - 1)));
            end;
        end
        else
        begin
            buf[0] := buf[0] or (1 shl bit);
        end;
    end;
    buf[0] := buf[0] and (not mask);
    if Boolean(bottom) then { set bottom bit if requested }
        buf[bytes - 1]  := buf[bytes - 1]  or 1;
    if nil = BN_bin2bn(@buf[0], bytes, rnd)  then
        goto _err ;
    ret := 1;

 _err:
    //OPENSSL_clear_free(buf, bytes);
    SetLength(buf, 0) ;
    bn_check_top(rnd);
    Exit(ret);

_toosmall:
    ERR_raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL);
    Result := 0;
end;

function bnrand_range(flag : TBNRAND_FLAG; r : PBIGNUM;const range : PBIGNUM; strength : uint32; ctx : PBN_CTX):integer;
var
  n, count : integer;
begin
    count := 100;
    if (range.neg>0)  or  (BN_is_zero(range)) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_RANGE);
        Exit(0);
    end;
    n := BN_num_bits(range);     { n > 0 }
    { BN_is_bit_set(range, n - 1) always holds }
    if n = 1 then
       BN_zero(r)
    else
    if ( 0>= BN_is_bit_set(range, n - 2) )  and  ( 0>= BN_is_bit_set(range, n - 3)) then
    begin
        {
         * range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range
         }
        repeat
            if  0>= bnrand(flag, r, n + 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY,
                        strength, ctx)  then
                Exit(0);
            {
             * If r < 3*range, use r := r MOD range (which is either r, r -
             * range, or r - 2*range). Otherwise, iterate once more. Since
             * 3*range = 11..._2, each iteration succeeds with probability >=
             * .75.
             }
            if BN_cmp(r, range)>= 0  then
            begin
                if  0>= BN_sub(r, r, range) then
                    Exit(0);
                if BN_cmp(r, range)  >= 0 then
                    if  0>= BN_sub(r, r, range) then
                        Exit(0);
            end;
            if  0>= PreDec(count) then
            begin
                ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS);
                Exit(0);
            end;
        until not (BN_cmp(r, range) >= 0) ;
    end
    else
    begin
        repeat
            { range = 11..._2  or  range = 101..._2 }
            if  0>= bnrand(flag, r, n, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx)  then
                Exit(0);
            if  0>= PreDec(count) then
            begin
                ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS);
                Exit(0);
            end;
        until not (BN_cmp(r, range) >= 0) ;
    end;
    bn_check_top(r);
    Result := 1;

end;

function BN_priv_rand_range_ex(r : PBIGNUM;const range : PBIGNUM; strength : uint32; ctx : PBN_CTX):integer;
begin
    Result := bnrand_range(_PRIVATE, r, range, strength, ctx);
end;

end.
