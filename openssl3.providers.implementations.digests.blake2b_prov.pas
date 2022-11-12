unit openssl3.providers.implementations.digests.blake2b_prov;

interface
uses OpenSSL.Api,  SysUtils,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.md5.md5_dgst,
     openssl3.crypto.md5.md5_sha1;


procedure blake2b_set_lastblock( S : PBLAKE2B_CTX);
  procedure blake2b_init0( S : PBLAKE2B_CTX);
  procedure blake2b_init_param(S : PBLAKE2B_CTX;const P : PBLAKE2B_PARAM);
  procedure ossl_blake2b_param_init( P : Pointer);
  procedure ossl_blake2b_param_set_digest_length( P : Pointer; outlen : byte);
  procedure ossl_blake2b_param_set_key_length( P : Pointer; keylen : byte);
  procedure ossl_blake2b_param_set_personal(P : Pointer;const personal : PByte; len : size_t);
  procedure ossl_blake2b_param_set_salt(P : Pointer;const salt : PByte; len : size_t);
  function ossl_blake2b_init(c : PBLAKE2B_CTX;const P : Pointer):integer;
  function ossl_blake2b_init_key(c : Pointer;const P : Pointer; const key : Pointer):integer;
  procedure blake2b_compress(S : PBLAKE2B_CTX; blocks : PByte; len : size_t);
  function ossl_blake2b_update(c : Pointer;const data : Pointer; datalen : size_t):integer;
  function ossl_blake2b_final( md : PByte; c : Pointer):integer;


implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.openssl.params,
     openssl3.providers.implementations.digests.blake2_impl;

const // 1d arrays
  blake2b_IV : array[0..7] of uint64 = (
    $6a09e667f3bcc908, $bb67ae8584caa73b, $3c6ef372fe94f82b,
    $a54ff53a5f1d36f1, $510e527fade682d1, $9b05688c2b3e6c1f,
    $1f83d9abfb41bd6b, $5be0cd19137e2179 );

const // 2d arrays
  blake2b_sigma : array[0..11,0..15] of byte = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3));

procedure blake2b_set_lastblock( S : PBLAKE2B_CTX);
begin
    S.f[0] := -1;
end;


procedure blake2b_init0( S : PBLAKE2B_CTX);
var
  i : integer;
begin
    memset(S, 0, sizeof(TBLAKE2B_CTX));
    for i := 0 to 8-1 do
    begin
        S.h[i] := blake2b_IV[i];
    end;
end;


procedure blake2b_init_param(S : PBLAKE2B_CTX;const P : PBLAKE2B_PARAM);
var
  i : size_t;

  _p : PByte;
begin
    _p := PByte(P);
    blake2b_init0(S);
    S.outlen := P.digest_length;
    { The param struct is carefully hand packed, and should be 64 bytes on
     * every platform. }
    assert(sizeof(TBLAKE2B_PARAM) = 64);
    { IV XOR ParamBlock }
    for i := 0 to 8-1 do
    begin
        S.h[i]  := S.h[i] xor (load64(_p + sizeof(S.h[i]) * i));
    end;
end;


procedure ossl_blake2b_param_init( P : Pointer);
begin
    PBLAKE2B_PARAM(P).digest_length := BLAKE2B_DIGEST_LENGTH;
    PBLAKE2B_PARAM(P).key_length := 0;
    PBLAKE2B_PARAM(P).fanout := 1;
    PBLAKE2B_PARAM(P).depth := 1;
    store32(@PBLAKE2B_PARAM(P).leaf_length, 0);
    store64(@PBLAKE2B_PARAM(P).node_offset, 0);
    PBLAKE2B_PARAM(P).node_depth := 0;
    PBLAKE2B_PARAM(P).inner_length := 0;
    memset(@PBLAKE2B_PARAM(P).reserved, 0, sizeof(PBLAKE2B_PARAM(P).reserved));
    memset(@PBLAKE2B_PARAM(P).salt,     0, sizeof(PBLAKE2B_PARAM(P).salt));
    memset(@PBLAKE2B_PARAM(P).personal, 0, sizeof(PBLAKE2B_PARAM(P).personal));
end;


procedure ossl_blake2b_param_set_digest_length( P : Pointer; outlen : byte);
begin
    PBLAKE2B_PARAM(P).digest_length := outlen;
end;


procedure ossl_blake2b_param_set_key_length( P : Pointer; keylen : byte);
begin
    PBLAKE2B_PARAM(P).key_length := keylen;
end;


procedure ossl_blake2b_param_set_personal(P : Pointer;const personal : PByte; len : size_t);
begin
    memcpy(@PBLAKE2B_PARAM(P).personal, personal, len);
    memset(PByte(@PBLAKE2B_PARAM(P).personal) + len, 0, BLAKE2B_PERSONALBYTES - len);
end;


procedure ossl_blake2b_param_set_salt(P : Pointer;const salt : PByte; len : size_t);
begin
    memcpy(@PBLAKE2B_PARAM(P).salt, salt, len);
    memset(PByte(@PBLAKE2B_PARAM(P).salt) + len, 0, BLAKE2B_SALTBYTES - len);
end;


function ossl_blake2b_init(c : PBLAKE2B_CTX;const P : Pointer):integer;
begin
    blake2b_init_param(c, PBLAKE2B_PARAM(P));
    Result := 1;
end;


function ossl_blake2b_init_key(c : Pointer;const P : Pointer; const key : Pointer):integer;
var
  block : array[0..(BLAKE2B_BLOCKBYTES)-1] of byte;
begin
    blake2b_init_param(PBLAKE2B_CTX(c), PBLAKE2B_PARAM(P));
    { Pad the key to form first data block }
    begin
        FillChar(block, BLAKE2B_BLOCKBYTES, 0);

        memcpy(@block, key, PBLAKE2B_PARAM(P).key_length);
        ossl_blake2b_update(PBLAKE2B_CTX(c), @block, BLAKE2B_BLOCKBYTES);
        OPENSSL_cleanse(@block, BLAKE2B_BLOCKBYTES);
    end;
    Result := 1;
end;



procedure blake2b_compress(S : PBLAKE2B_CTX;blocks : PByte; len : size_t);
var
  m,
  v         : array[0..15] of uint64;

    i         : integer;

    increment : size_t;
    procedure G(r,i: UInt64; var a,b,c,d: Uint64);
    begin
        a := a + b + m[blake2b_sigma[r][2*i+0]];
        d := rotr64(d  xor  a, 32);
        c := c + d;
        b := rotr64(b  xor  c, 24);
        a := a + b + m[blake2b_sigma[r][2*i+1]];
        d := rotr64(d  xor  a, 16);
        c := c + d;
        b := rotr64(b  xor  c, 63);
    end;

    procedure ROUND(r: Uint64);
    begin
        G(r,0,v[ 0],v[ 4],v[ 8],v[12]);
        G(r,1,v[ 1],v[ 5],v[ 9],v[13]);
        G(r,2,v[ 2],v[ 6],v[10],v[14]);
        G(r,3,v[ 3],v[ 7],v[11],v[15]);
        G(r,4,v[ 0],v[ 5],v[10],v[15]);
        G(r,5,v[ 1],v[ 6],v[11],v[12]);
        G(r,6,v[ 2],v[ 7],v[ 8],v[13]);
        G(r,7,v[ 3],v[ 4],v[ 9],v[14]);
    end;

begin
    {
     * There are two distinct usage vectors for this function:
     *
     * a) BLAKE2b_Update uses it to process complete blocks,
     *
     * b) BLAK2b_Final uses it to process last block, always
     *    single but possibly incomplete, in which case caller
     *    pads input with zeros.
     }
    assert( (len < BLAKE2B_BLOCKBYTES)  or  (len mod BLAKE2B_BLOCKBYTES = 0));
    {
     * Since last block is always processed with separate call,
     * |len| not being multiple of complete blocks can be observed
     * only with |len| being less than BLAKE2B_BLOCKBYTES ('less'
     * including even zero), which is why following assignment doesn't
     * have to reside inside the main loop below.
     }
    increment := get_result(len < BLAKE2B_BLOCKBYTES , len , BLAKE2B_BLOCKBYTES);
    for i := 0 to 8-1 do
    begin
        v[i] := S.h[i];
    end;
    repeat
        for i := 0 to 16-1 do
        begin
            m[i] := load64(blocks + i * sizeof(m[i]));
        end;
        { blake2b_increment_counter }
        S.t[0]  := S.t[0] + increment;
        S.t[1]  := S.t[1] + int((S.t[0] < increment));
        v[8] := blake2b_IV[0];
        v[9] := blake2b_IV[1];
        v[10] := blake2b_IV[2];
        v[11] := blake2b_IV[3];
        v[12] := S.t[0]  xor  blake2b_IV[4];
        v[13] := S.t[1]  xor  blake2b_IV[5];
        v[14] := S.f[0]  xor  blake2b_IV[6];
        v[15] := S.f[1]  xor  blake2b_IV[7];

{$IF defined(OPENSSL_SMALL_FOOTPRINT)}
        { 3x size reduction on x86_64, almost 7x on ARMv8, 9x on ARMv4 }
        for i := 0 to 11 do begin
            ROUND(i);
        end;
{$ELSE} ROUND(0);
        ROUND(1);
        ROUND(2);
        ROUND(3);
        ROUND(4);
        ROUND(5);
        ROUND(6);
        ROUND(7);
        ROUND(8);
        ROUND(9);
        ROUND(10);
        ROUND(11);
{$ENDIF}
        for i := 0 to 8-1 do
        begin
            v[i]  := v[i] xor (v[i + 8] xor S.h[i]);
            S.h[i] := v[i];
        end;

        blocks := blocks + increment;
        len  := len - increment;
    until (not (len>0));
end;


function ossl_blake2b_update(c : Pointer;const data : Pointer; datalen : size_t):integer;
var
  _in      : PByte;
  fill,
  stashlen : size_t;
begin
    _in := data;
    {
     * Intuitively one would expect intermediate buffer, c.buf, to
     * store incomplete blocks. But in this case we are interested to
     * temporarily stash even complete blocks, because last one in the
     * stream has to be treated in special way, and at this point we
     * don't know if last block in *this* call is last one 'ever'. This
     * is the reason for why |datalen| is compared as >, and not >=.
     }
    fill := sizeof(PBLAKE2B_CTX(c).buf) - PBLAKE2B_CTX(c).buflen;
    if datalen > fill then
    begin
        if PBLAKE2B_CTX(c).buflen >0 then
        begin
            memcpy(PByte(@PBLAKE2B_CTX(c).buf) + PBLAKE2B_CTX(c).buflen, _in, fill); { Fill buffer }
            blake2b_compress(c, @PBLAKE2B_CTX(c).buf, BLAKE2B_BLOCKBYTES);
            PBLAKE2B_CTX(c).buflen := 0;
            _in  := _in + fill;
            datalen  := datalen - fill;
        end;
        if datalen > BLAKE2B_BLOCKBYTES then
        begin
            stashlen := datalen mod BLAKE2B_BLOCKBYTES;
            {
             * If |datalen| is a multiple of the blocksize, stash
             * last complete block, it can be final one...
             }
            stashlen := get_result(stashlen >0, stashlen , BLAKE2B_BLOCKBYTES);
            datalen  := datalen - stashlen;
            blake2b_compress(c, _in, datalen);
            _in  := _in + datalen;
            datalen := stashlen;
        end;
    end;
    assert(datalen <= BLAKE2B_BLOCKBYTES);
    memcpy(PByte(@PBLAKE2B_CTX(c).buf) + PBLAKE2B_CTX(c).buflen, _in, datalen);
    PBLAKE2B_CTX(c).buflen  := PBLAKE2B_CTX(c).buflen + datalen;
    Result := 1;
end;


function ossl_blake2b_final( md : PByte; c : Pointer):integer;
var
  outbuffer : array[0..(BLAKE2B_OUTBYTES)-1] of byte;
  target    : PByte;
  iter, i     : integer;
begin
    FillChar(outbuffer, BLAKE2B_OUTBYTES, 0);
    target := @outbuffer;
    iter := (PBLAKE2B_CTX(c).outlen + 7) div 8;
    { Avoid writing to the temporary buffer if possible }
    if PBLAKE2B_CTX(c).outlen mod sizeof(PBLAKE2B_CTX(c).h[0]) = 0 then
        target := md;
    blake2b_set_lastblock(c);
    { Padding }
    memset(PByte(@PBLAKE2B_CTX(c).buf) + PBLAKE2B_CTX(c).buflen, 0, sizeof(PBLAKE2B_CTX(c).buf) - PBLAKE2B_CTX(c).buflen);
    blake2b_compress(c, @PBLAKE2B_CTX(c).buf, PBLAKE2B_CTX(c).buflen);
    { Output full hash to buffer }
    for i := 0 to iter-1 do
        store64(target + sizeof(PBLAKE2B_CTX(c).h[i]) * i, PBLAKE2B_CTX(c).h[i]);
    if target <> md then
       memcpy(md, target, PBLAKE2B_CTX(c).outlen);
    OPENSSL_cleanse(c, sizeof(TBLAKE2B_CTX));
    Result := 1;
end;






end.
