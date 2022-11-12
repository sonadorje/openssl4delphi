unit OpenSSL3.crypto.rsa.rsa_oaep;

interface
uses OpenSSL.Api;

function PKCS1_MGF1(mask : PByte; len : long;const seed : PByte; seedlen : long;const dgst : PEVP_MD):integer;
function RSA_padding_add_PKCS1_OAEP_mgf1(&to : PByte; tlen : integer;const from : PByte; flen : integer;const param : PByte; plen : integer;const md, mgf1md : PEVP_MD):integer;
 function ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(libctx : POSSL_LIB_CTX; &to : PByte; tlen : integer;const from : PByte; flen : integer;const param : PByte; plen : integer; md, mgf1md : PEVP_MD):integer;
function RSA_padding_check_PKCS1_OAEP_mgf1(&to : PByte; tlen : integer; from : PByte; flen, num : integer;const param : PByte; plen : integer; md, mgf1md : PEVP_MD):integer;
function RSA_padding_check_PKCS1_OAEP(_to : PByte; tlen : integer;const from : PByte; flen, num : integer;const param : PByte; plen : integer):integer;


implementation
uses OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.bn.bn_lib,
     OpenSSL3.crypto.rsa.rsa_crpt, openssl3.crypto.mem,
     openssl3.internal.constant_time, openssl3.crypto.cpuid,
     openssl3.crypto.rand.rand_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.evp.digest, openssl3.crypto.evp.legacy_sha;





function RSA_padding_check_PKCS1_OAEP(_to : PByte; tlen : integer;const from : PByte; flen, num : integer;const param : PByte; plen : integer):integer;
begin
    Exit(RSA_padding_check_PKCS1_OAEP_mgf1(_to, tlen, from, flen, num,
                                             param, plen, nil, nil));
end;




function RSA_padding_check_PKCS1_OAEP_mgf1(&to : PByte; tlen : integer; from : PByte; flen, num : integer;const param : PByte; plen : integer;md, mgf1md : PEVP_MD):integer;
var
  i, dblen
  , mlen, one_index,
  msg_index : integer;
  good, found_one_byte, mask : uint32;
  db, em : PByte;
  mdlen : integer;
  equals1, equals0 : uint32;
  maskedseed, maskeddb: PByte;
  seed,  phash: array[0..EVP_MAX_MD_SIZE-1] of Byte;
  label _cleanup;
begin
    dblen := 0; mlen := -1; one_index := 0;
    good := 0;

    {
     * |em| is the encoded message, zero-padded to exactly |num| bytes: em =
     * Y  or  maskedSeed  or  maskedDB
     }
    db := nil; em := nil;
    if md = nil then
    begin
{$IFNDEF FIPS_MODULE}
        md := EVP_sha1();
{$ELSE ERR_raise(ERR_LIB_RSA, ERR_R_PASSED_nil_PARAMETER);}
        Exit(-1);
{$ENDIF}
    end;
    if mgf1md = nil then
       mgf1md := md;
    mdlen := EVP_MD_get_size(md);
    if (tlen <= 0)  or  (flen <= 0) then Exit(-1);
    {
     * encoded message. Therefore, for any |from| that was obtained by
     * decrypting a ciphertext, we must have |flen| <= |num|. Similarly,
     * |num| >= 2 * |mdlen| + 2 must hold for the modulus irrespective of
     * the ciphertext, see PKCS #1 v2.2, section 7.1.2.
     * This does not leak any side-channel information.
     }
    if (num < flen)  or  (num < 2 * mdlen + 2) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_OAEP_DECODING_ERROR);
        Exit(-1);
    end;
    dblen := num - mdlen - 1;
    db := OPENSSL_malloc(dblen);
    if db = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _cleanup ;
    end;
    em := OPENSSL_malloc(num);
    if em = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _cleanup ;
    end;
    {
     * Caller is encouraged to pass zero-padded message created with
     * BN_bn2binpad. Trouble is that since we can't read out of |from|'s
     * bounds, it's impossible to have an invariant memory access pattern
     * in case |from| was not zero-padded in advance.
     }

    from := from + flen; em := em + num; i := 0;
    while i < num do
    begin
        mask := not constant_time_is_zero(flen);
        flen  := flen - (1 and mask);
        from  := from - (1 and mask);
        PreDec(em)^ := from^ and mask;
    end;
    {
     * The first byte must be zero, however we must not leak if this is
     * true. See James H. Manger, "A Chosen Ciphertext  Attack on RSA
     * Optimal Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001).
     }
    good := constant_time_is_zero(em[0]);
    maskedseed := em + 1;
    maskeddb := em + 1 + mdlen;
    if PKCS1_MGF1(@seed, mdlen, maskeddb, dblen, mgf1md) > 0 then
        goto _cleanup ;
    for i := 0 to mdlen-1 do
        seed[i]  := seed[i] xor (maskedseed[i]);
    if PKCS1_MGF1(db, dblen, @seed, mdlen, mgf1md) > 0 then
        goto _cleanup ;
    for i := 0 to dblen-1 do
        db[i]  := db[i] xor (maskeddb[i]);
    if 0>= EVP_Digest(Pointer( param), plen, @phash, nil, md, nil) then
        goto _cleanup ;
    good := good and constant_time_is_zero(CRYPTO_memcmp(db, @phash, mdlen));
    found_one_byte := 0;
    for i := mdlen to dblen-1 do
    begin
        {
         * Padding consists of a number of 0-bytes, followed by a 1.
         }
        equals1 := constant_time_eq(db[i], 1);
        equals0 := constant_time_is_zero(db[i]);
        one_index := constant_time_select_int(not found_one_byte and equals1,
                                             i, one_index);
        found_one_byte  := found_one_byte  or equals1;
        good := good and (found_one_byte or equals0);
    end;
    good := good and found_one_byte;
    {
     * At this point |good| is zero unless the plaintext was valid,
     * so plaintext-awareness ensures timing side-channels are no longer a
     * concern.
     }
    msg_index := one_index + 1;
    mlen := dblen - msg_index;
    {
     * For good measure, do this check in constant time as well.
     }
    good := good and constant_time_ge(tlen, mlen);
    {
     * Move the result in-place by |dblen|-|mdlen|-1-|mlen| bytes to the left.
     * Then if |good| move |mlen| bytes from |db|+|mdlen|+1 to |to|.
     * Otherwise leave |to| unchanged.
     * Copy the memory back in a way that does not reveal the size of
     * the data being copied via a timing side channel. This requires copying
     * parts of the buffer multiple times based on the bits set in the real
     * length. Clear bits do a non-copy with identical access pattern.
     * The loop below has overall complexity of O(N*log(N)).
     }
    tlen := constant_time_select_int(constant_time_lt(dblen - mdlen - 1, tlen),
                                    dblen - mdlen - 1, tlen);
    msg_index := 1;
    while msg_index < dblen - mdlen - 1 do
    begin
        mask := not constant_time_eq(msg_index and (dblen - mdlen - 1 - mlen), 0);
        for i := mdlen + 1 to dblen - msg_index-1 do
            db[i] := constant_time_select_8(mask, db[i + msg_index], db[i]);
        msg_index := msg_index shl  1;
    end;
    for i := 0 to tlen-1 do
    begin
        mask := good and constant_time_lt(i, mlen);
        &to[i] := constant_time_select_8(mask, db[i + mdlen + 1], &to[i]);
    end;
{$IFNDEF FIPS_MODULE}
    {
     * To avoid chosen ciphertext attacks, the error message should not
     * reveal which kind of decoding error happened.
     *
     * This trick doesn't work in the FIPS provider because libcrypto manages
     * the error stack. Instead we opt not to put an error on the stack at all
     * in case of padding failure in the FIPS provider.
     }
    ERR_raise(ERR_LIB_RSA, RSA_R_OAEP_DECODING_ERROR);
    err_clear_last_constant_time(1 and good);
{$ENDIF}
 _cleanup:
    OPENSSL_cleanse(@seed, sizeof(seed));
    OPENSSL_clear_free(Pointer(db), dblen);
    OPENSSL_clear_free(Pointer(em), num);
    Result := constant_time_select_int(good, mlen, -1);
end;



function ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(libctx : POSSL_LIB_CTX; &to : PByte; tlen : integer;const from : PByte; flen : integer;const param : PByte; plen : integer; md, mgf1md : PEVP_MD):integer;
var
  rv,
  i,
  emlen      : integer;

  db,
  seed,
  dbmask     : PByte;
  seedmask   : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  mdlen,
  dbmask_len : integer;
  label _err;
begin
    rv := 0;
    emlen := tlen - 1;
    dbmask := nil;
    dbmask_len := 0;
    if md = nil then
    begin
{$IFNDEF FIPS_MODULE}
        md := EVP_sha1();
{$ELSE}
        ERR_raise(ERR_LIB_RSA, ERR_R_PASSED_nil_PARAMETER);
        Exit(0);
{$ENDIF}
    end;
    if mgf1md = nil then
       mgf1md := md;
    mdlen := EVP_MD_get_size(md);
    if mdlen <= 0 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_LENGTH);
        Exit(0);
    end;
    { step 2b: check KLen > nLen - 2 HLen - 2 }
    if flen > emlen - 2 * mdlen - 1 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        Exit(0);
    end;
    if emlen < 2 * mdlen + 1 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        Exit(0);
    end;
    { step 3i: EM = 00000000  or  maskedMGF  or  maskedDB }
    &to[0] := 0;
    seed := &to + 1;
    db := &to + mdlen + 1;
    { step 3a: hash the additional input }
    if 0>= EVP_Digest(Pointer( param), plen, db, nil, md, nil) then
        goto _err ;
    { step 3b: zero bytes array of length nLen - KLen - 2 HLen -2 }
    memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
    { step 3c: DB = HA  or  PS  or  00000001  or  K }
    db[emlen - flen - mdlen - 1] := $01;
    memcpy(db + emlen - flen - mdlen, from, uint32( flen));
    { step 3d: generate random byte string }
    if RAND_bytes_ex(libctx, seed, mdlen, 0 )  <= 0 then
        goto _err ;
    dbmask_len := emlen - mdlen;
    dbmask := OPENSSL_malloc(dbmask_len);
    if dbmask = nil then begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    { step 3e: dbMask = MGF(mgfSeed, nLen - HLen - 1) }
    if PKCS1_MGF1(dbmask, dbmask_len, seed, mdlen, mgf1md ) < 0 then
        goto _err ;
    { step 3f: maskedDB = DB XOR dbMask }
    for i := 0 to dbmask_len-1 do
        db[i]  := db[i] xor (dbmask[i]);
    { step 3g: mgfSeed = MGF(maskedDB, HLen) }
    if PKCS1_MGF1(@seedmask, mdlen, db, dbmask_len, mgf1md) < 0  then
        goto _err ;
    { stepo 3h: maskedMGFSeed = mgfSeed XOR mgfSeedMask }
    for i := 0 to mdlen-1 do
        seed[i]  := seed[i] xor (seedmask[i]);
    rv := 1;
 _err:
    OPENSSL_cleanse(@seedmask, sizeof(seedmask));
    OPENSSL_clear_free(Pointer(dbmask), dbmask_len);
    Result := rv;
end;




function RSA_padding_add_PKCS1_OAEP_mgf1(&to : PByte; tlen : integer;const from : PByte; flen : integer;const param : PByte; plen : integer;const md, mgf1md : PEVP_MD):integer;
begin
    Exit(ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(nil, &to, tlen, from, flen,
                                                   param, plen, md, mgf1md));
end;

function PKCS1_MGF1(mask : PByte; len : long;const seed : PByte; seedlen : long;const dgst : PEVP_MD):integer;
var
  i, outlen : long;
  cnt : array[0..3] of Byte;
  c : PEVP_MD_CTX;
  md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  mdlen, rv : integer;
  label _err;
begin
    outlen := 0;
    c := EVP_MD_CTX_new();
    rv := -1;
    if c = nil then goto _err ;
    mdlen := EVP_MD_get_size(dgst);
    if mdlen < 0 then goto _err ;
    { step 4 }
    for i := 0 to len-1 do
    begin
        { step 4a: D = I2BS(counter, 4) }
        cnt[0] := Byte ((i  shr  24) and 255);
        cnt[1] := Byte ((i  shr  16) and 255);
        cnt[2] := Byte ((i  shr  8)) and 255;
        cnt[3] := Byte (i and 255);
        { step 4b: T =T  or  hash(mgfSeed  or  D) }
        if (0>= EVP_DigestInit_ex(c, dgst, nil ))  or
           (0>= EVP_DigestUpdate(c, seed, seedlen))
             or  (0>= EVP_DigestUpdate(c, @cnt, 4)) then
            goto _err ;
        if outlen + mdlen <= len then
        begin
            if 0>= EVP_DigestFinal_ex(c, mask + outlen, nil) then
                goto _err ;
            outlen  := outlen + mdlen;
        end
        else
        begin
            if 0>= EVP_DigestFinal_ex(c, @md, nil) then
                goto _err ;
            memcpy(mask + outlen, @md, len - outlen);
            outlen := len;
        end;
    end;
    rv := 0;
 _err:
    OPENSSL_cleanse(@md, sizeof(md));
    EVP_MD_CTX_free(c);
    Result := rv;
end;


end.
