unit openssl3.crypto.rsa.rsa_pk1;

interface
 uses OpenSSL.Api;

 function ossl_rsa_padding_check_PKCS1_type_2_TLS(libctx : POSSL_LIB_CTX; &to : PByte; tlen : size_t;const from : PByte; flen : size_t; client_version, alt_version : integer):integer;
 function ossl_rsa_padding_add_PKCS1_type_2_ex(libctx : POSSL_LIB_CTX; _to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
 function RSA_padding_add_PKCS1_type_1(_to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
 function RSA_padding_check_PKCS1_type_2(_to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;
 function RSA_padding_check_PKCS1_type_1(_to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.rand.rand_lib, openssl3.internal.constant_time,
     openssl3.crypto.mem;

function RSA_padding_check_PKCS1_type_1(_to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;
var
  i, j : integer;
  p : PByte;
begin
    p := from;
    {
     * The format is
     * 00  or  01  or  PS  or  00  or  D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     }
    if num < RSA_PKCS1_PADDING_SIZE then
       Exit(-1);
    { Accept inputs with and without the leading 0-byte. }
    if num = flen then
    begin
        if ( PostInc(p)^) <> $00 then
         begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING);
            Exit(-1);
        end;
        Dec(flen);
    end;
    if (num <> (flen + 1))  or  ( PostInc(p)^ <> $01) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_BLOCK_TYPE_IS_NOT_01);
        Exit(-1);
    end;
    { scan over padding data }
    j := flen - 1;               { one for type. }
    for i := 0 to j-1 do
    begin
        if p^ <> $ff then
        begin        { should decrypt to $ff }
            if p^ = 0 then
            begin
                Inc(p);
                break;
            end
            else
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_BAD_FIXED_HEADER_DECRYPT);
                Exit(-1);
            end;
        end;
        Inc(p);
    end;
    if i = j then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_NULL_BEFORE_BLOCK_MISSING);
        Exit(-1);
    end;
    if i < 8 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_PAD_BYTE_COUNT);
        Exit(-1);
    end;
    Inc(i);                        { Skip over the #0 }
    j  := j - i;
    if j > tlen then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        Exit(-1);
    end;
    memcpy(_to, p, uint32(j));
    Result := j;
end;

function RSA_padding_check_PKCS1_type_2(_to : PByte; tlen : integer;const from : PByte; flen, num : integer):integer;
var
    i               : integer;
    em              : PByte;
    good,
    found_zero_byte,
    mask            : uint32;
    zero_index, mlen,
    msg_index       : integer;
    equals0         : uint32;
    _from           : PByte;
begin
    { |em| is the encoded message, zero-padded to exactly |num| bytes }
    _from := (from);
    em := nil;
    zero_index := 0;
    mlen := -1;
    if (tlen <= 0)  or  (flen <= 0) then
       Exit(-1);
    {
     * PKCS#1 v1.5 decryption. See 'PKCS #1 v2.2: RSA Cryptography Standard',
     * section 7.2.2.
     }
    if (flen > num)  or  (num < RSA_PKCS1_PADDING_SIZE) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_PKCS_DECODING_ERROR);
        Exit(-1);
    end;
    em := OPENSSL_malloc(num);
    if em = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    {
     * Caller is encouraged to pass zero-padded message created with
     * BN_bn2binpad. Trouble is that since we can't read out of |from|'s
     * bounds, it's impossible to have an invariant memory access pattern
     * in case |from| was not zero-padded in advance.
     }
    _from := _from + flen;
    em  := em + num;
    for  i := 0 to num-1 do
    begin
        mask := not constant_time_is_zero(flen);
        flen  := flen - (1 and mask);
        _from  := _from - (1 and mask);
        PreDec(em)^ := _from^ and mask;
    end;
    good := constant_time_is_zero(em[0]);
    good := good and constant_time_eq(em[1], 2);
    { scan over padding data }
    found_zero_byte := 0;
    for i := 2 to num-1 do
    begin
        equals0 := constant_time_is_zero(em[i]);
        zero_index := constant_time_select_int(not found_zero_byte and equals0,
                                              i, zero_index);
        found_zero_byte  := found_zero_byte  or equals0;
    end;
    {
     * PS must be at least 8 bytes long, and it starts two bytes into |em|.
     * If we never found a 0-byte, then |zero_index| is 0 and the check
     * also fails.
     }
    good := good and constant_time_ge(zero_index, 2 + 8);
    {
     * Skip the zero byte. This is incorrect if we never found a zero-byte
     * but in this case we also do not copy the message out.
     }
    msg_index := zero_index + 1;
    mlen := num - msg_index;
    {
     * For good measure, do this check in constant time as well.
     }
    good := good and constant_time_ge(tlen, mlen);
    {
     * Move the result in-place by |num|-RSA_PKCS1_PADDING_SIZE-|mlen| bytes to the left.
     * Then if |good| move |mlen| bytes from |em|+RSA_PKCS1_PADDING_SIZE to |to|.
     * Otherwise leave |to| unchanged.
     * Copy the memory back in a way that does not reveal the size of
     * the data being copied via a timing side channel. This requires copying
     * parts of the buffer multiple times based on the bits set in the real
     * length. Clear bits do a non-copy with identical access pattern.
     * The loop below has overall complexity of O(N*log(N)).
     }
    tlen := constant_time_select_int(constant_time_lt(num - RSA_PKCS1_PADDING_SIZE, tlen),
                                    num - RSA_PKCS1_PADDING_SIZE, tlen);
    msg_index := 1;
    while msg_index < num - RSA_PKCS1_PADDING_SIZE do
    begin
        mask := not constant_time_eq(msg_index and (num - RSA_PKCS1_PADDING_SIZE - mlen), 0);
        for i := RSA_PKCS1_PADDING_SIZE to num - msg_index-1 do
            em[i] := constant_time_select_8(mask, em[i + msg_index], em[i]);
        msg_index := msg_index shl  1;
    end;
    for i := 0 to tlen-1 do
    begin
        mask := good and constant_time_lt(i, mlen);
        _to[i] := constant_time_select_8(mask, em[i + RSA_PKCS1_PADDING_SIZE], _to[i]);
    end;
    OPENSSL_clear_free(em, num);
{$IFNDEF FIPS_MODULE}
    {
     * This trick doesn't work in the FIPS provider because libcrypto manages
     * the error stack. Instead we opt not to put an error on the stack at all
     * in case of padding failure in the FIPS provider.
     }
    ERR_raise(ERR_LIB_RSA, RSA_R_PKCS_DECODING_ERROR);
    err_clear_last_constant_time(1 and good);
{$ENDIF}
    Result := constant_time_select_int(good, mlen, -1);
end;


function RSA_padding_add_PKCS1_type_1(_to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
var
  j : integer;
  p : PByte;
begin

    if flen > (tlen - RSA_PKCS1_PADDING_SIZE) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        Exit(0);
    end;
    p := _to;
    PostInc(p)^ := 0;
    PostInc(p)^ := 1;                 { Private Key BT (Block Type) }
    { pad out with $ff data }
    j := tlen - 3 - flen;
    memset(p, $ff, j);
    p  := p + j;
    PostInc(p)^ := Ord(#0);
    memcpy(p, from, uint32( flen));
    Result := 1;

end;


function ossl_rsa_padding_add_PKCS1_type_2_ex(libctx : POSSL_LIB_CTX; _to : PByte; tlen : integer;const from : PByte; flen : integer):integer;
var
  i, j : integer;
  p : PByte;
begin
    if flen > (tlen - RSA_PKCS1_PADDING_SIZE) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        Exit(0);
    end
    else
    if (flen < 0) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_LENGTH);
        Exit(0);
    end;
    p := _to;
    (PostInc(p))^ := 0;
    (PostInc(p))^ := 2;                 { Public Key BT (Block Type) }
    { pad out with non-zero random data }
    j := tlen - 3 - flen;
    if RAND_bytes_ex(libctx, p, j, 0) <= 0  then
        Exit(0);
    for i := 0 to j-1 do
    begin
        if p^ = ord(#0) then
        repeat
            if RAND_bytes_ex(libctx, p, 1, 0) <= 0 then
                Exit(0);
        until not ( p^ = ord(#0));

        Inc(p);
    end;
    PostInc(p)^ := ord(#0);
    memcpy(p, from, uint32( flen));
    Result := 1;
end;

function ossl_rsa_padding_check_PKCS1_type_2_TLS(libctx : POSSL_LIB_CTX; &to : PByte; tlen : size_t;const from : PByte; flen : size_t; client_version, alt_version : integer):integer;
var
  i,
good,
  version_good          : uint32;

    rand_premaster_secret : array[0..(SSL_MAX_MASTER_KEY_LENGTH)-1] of Byte;

    workaround_good       : uint32;
begin
    {
     * If these checks fail then either the message in publicly invalid, or
     * we've been called incorrectly. We can fail immediately.
     }
    if (flen < RSA_PKCS1_PADDING_SIZE + SSL_MAX_MASTER_KEY_LENGTH)
             or  (tlen < SSL_MAX_MASTER_KEY_LENGTH) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_PKCS_DECODING_ERROR);
        Exit(-1);
    end;
    {
     * Generate a random premaster secret to use in the event that we fail
     * to decrypt.
     }
    if RAND_priv_bytes_ex(libctx, @rand_premaster_secret,
                           sizeof(rand_premaster_secret ) , 0) <= 0 then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR);
        Exit(-1);
    end;
    good := constant_time_is_zero(from[0]);
    good := good and constant_time_eq(from[1], 2);
    { Check we have the expected padding data }
    for i := 2 to flen - SSL_MAX_MASTER_KEY_LENGTH - 1-1 do
        good := good and (not constant_time_is_zero_8(from[i]));
    good := good and constant_time_is_zero_8(from[flen - SSL_MAX_MASTER_KEY_LENGTH - 1]);
    {
     * If the version in the decrypted pre-master secret is correct then
     * version_good will be $ff, otherwise it'll be zero. The
     * Klima-Pokorny-Rosa extension of Bleichenbacher's attack
     * (http://eprint.iacr.org/2003/052/) exploits the version number
     * check as a 'bad version oracle'. Thus version checks are done in
     * constant time and are treated like any other decryption error.
     }
    version_good := constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH],
                         (client_version  shr  8) and $ff);
    version_good := good and
        constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH + 1],
                         client_version and $ff);
    {
     * The premaster secret must contain the same version number as the
     * ClientHello to detect version rollback attacks (strangely, the
     * protocol does not offer such protection for DH ciphersuites).
     * However, buggy clients exist that send the negotiated protocol
     * version instead if the server does not support the requested
     * protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set then we tolerate
     * such clients. In that case alt_version will be non-zero and set to
     * the negotiated version.
     }
    if alt_version > 0 then
    begin
        workaround_good := constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH],
                             (alt_version  shr  8) and $ff);
        workaround_good := good and
            constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH + 1],
                             alt_version and $ff);
        version_good  := version_good  or workaround_good;
    end;
    good := good and version_good;
    {
     * Now copy the result over to the to buffer if good, or random data if
     * not good.
     }
    for i := 0 to SSL_MAX_MASTER_KEY_LENGTH-1 do
    begin
        &to[i] := constant_time_select_8(good,
                                   from[flen - SSL_MAX_MASTER_KEY_LENGTH + i],
                                   rand_premaster_secret[i]);
    end;
    {
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
     * So, whether we actually succeeded or not, return success.
     }
    Result := SSL_MAX_MASTER_KEY_LENGTH;
end;


end.
