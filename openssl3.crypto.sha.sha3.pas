unit openssl3.crypto.sha.sha3;

interface
uses OpenSSL.Api;

const
   KECCAK1600_WIDTH = 1600;

  procedure ossl_sha3_reset( ctx : PKECCAK1600_CTX);
  function ossl_sha3_init( ctx : PKECCAK1600_CTX; pad : Byte; bitlen : size_t):integer;
  function ossl_keccak_kmac_init( ctx : PKECCAK1600_CTX; pad : Byte; bitlen : size_t):integer;
  function ossl_sha3_update(ctx : PKECCAK1600_CTX;const _inp : Pointer; len : size_t):integer;
  function ossl_sha3_final( md : PByte; ctx : PKECCAK1600_CTX):integer;
  function SHA3_BLOCKSIZE(bitlen: size_t): size_t;inline;

implementation

uses  openssl3.crypto.sha.sha_local,     openssl3.crypto.sha.keccak1600;

//openssl3.include.crypto.md32_common,




procedure ossl_sha3_reset( ctx : PKECCAK1600_CTX);
begin
    memset(@ctx.A, 0, sizeof(ctx.A));
    ctx.bufsz := 0;
end;

function SHA3_BLOCKSIZE(bitlen: size_t): size_t;
begin
   Result := (KECCAK1600_WIDTH - bitlen * 2) div 8
end;

function ossl_sha3_init( ctx : PKECCAK1600_CTX; pad : Byte; bitlen : size_t):integer;
var
  bsz : size_t;
begin
    bsz := SHA3_BLOCKSIZE(bitlen);
    if bsz <= sizeof(ctx.buf ) then
    begin
        ossl_sha3_reset(ctx);
        ctx.block_size := bsz;
        ctx.md_size := bitlen div 8;
        ctx.pad := pad;
        Exit(1);
    end;
    Result := 0;
end;


function ossl_keccak_kmac_init( ctx : PKECCAK1600_CTX; pad : Byte; bitlen : size_t):integer;
var
  ret : integer;
begin
    ret := ossl_sha3_init(ctx, pad, bitlen);
    if ret >0 then
       ctx.md_size  := ctx.md_size  * 2;
    Result := ret;
end;


function ossl_sha3_update(ctx : PKECCAK1600_CTX;const _inp : Pointer; len : size_t):integer;
var
  inp : PByte;

  bsz, num, rem : size_t;
begin
     inp := _inp;
    bsz := ctx.block_size;
    if len = 0 then Exit(1);
    num := ctx.bufsz;
    if num <> 0 then
    begin       { process intermediate buffer? }
        rem := bsz - num;
        if len < rem then
        begin
            memcpy(PByte(@ctx.buf) + num, inp, len);
            ctx.bufsz  := ctx.bufsz + len;
            Exit(1);
        end;
        {
         * We have enough data to fill or overflow the intermediate
         * buffer. So we append |rem| bytes and process the block,
         * leaving the rest for later processing...
         }
        memcpy(PByte(@ctx.buf) + num, inp, rem);
        inp := inp+rem;
        len := len - rem;
        SHA3_absorb(@ctx.A, @ctx.buf, bsz, bsz);
        ctx.bufsz := 0;
        { ctx.buf is processed, ctx.num is guaranteed to be zero }
    end;
    if len >= bsz then
       rem := SHA3_absorb(@ctx.A, inp, len, bsz)
    else
        rem := len;
    if rem>0 then
    begin
        memcpy(@ctx.buf, inp + len - rem, rem);
        ctx.bufsz := rem;
    end;
    Result := 1;
end;


function ossl_sha3_final( md : PByte; ctx : PKECCAK1600_CTX):integer;
var
  bsz, num : size_t;
begin
    bsz := ctx.block_size;
    num := ctx.bufsz;
    if ctx.md_size = 0 then Exit(1);
    {
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     }
    memset(PByte(@ctx.buf) + num, 0, bsz - num);
    ctx.buf[num] := ctx.pad;
    ctx.buf[bsz - 1]  := ctx.buf[bsz - 1]  or $80;
    SHA3_absorb(@ctx.A, @ctx.buf, bsz, bsz);
    SHA3_squeeze(@ctx.A, md, ctx.md_size, bsz);
    Result := 1;
end;


end.
