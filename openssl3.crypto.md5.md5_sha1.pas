unit openssl3.crypto.md5.md5_sha1;
{$i     config.inc}
{md5_local.h
#define HASH_LONG               MD5_LONG
#define HASH_CTX                MD5_CTX
#define HASH_CBLOCK             MD5_CBLOCK
#define HASH_UPDATE             MD5_Update
#define HASH_TRANSFORM          MD5_Transform
#define HASH_FINAL              MD5_Final
}



interface
uses OpenSSL.Api;

const
   MD5_SHA1_DIGEST_LENGTH = (MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH);
   MD5_SHA1_CBLOCK        = MD5_CBLOCK;

  function ossl_md5_sha1_init( mctx : PMD5_SHA1_CTX):integer;
  function ossl_md5_sha1_update(mctx : PMD5_SHA1_CTX;const data : Pointer; count : size_t):integer;
  function ossl_md5_sha1_final( md : PByte; mctx : PMD5_SHA1_CTX):integer;
  function ossl_md5_sha1_ctrl( mctx : PMD5_SHA1_CTX; cmd, mslen : integer; ms : Pointer):integer;

implementation
uses
   openssl3.include.crypto.md32_common, openssl3.crypto.sha.sha_local,
   openssl3.crypto.md5.md5_dgst, openssl3.crypto.sha.sha1dgst,
   openssl3.crypto.mem;

type
  PHASH_CTX = PSHA_CTX;

{$I openssl3.include.crypto.md32_common.inc}

const _SHA1_Final: function( md : PByte; c : PHASH_CTX):integer = HASH_FINAL;




function ossl_md5_sha1_init( mctx : PMD5_SHA1_CTX):integer;
begin
    if 0>= MD5_Init(@mctx.md5) then
        Exit(0);
    Result := _SHA1_Init(@mctx.sha1);
end;


function ossl_md5_sha1_update(mctx : PMD5_SHA1_CTX;const data : Pointer; count : size_t):integer;
begin
    if 0>= MD5_Update(@mctx.md5, data, count )then
        Exit(0);
    Result := _SHA1_Update(@mctx.sha1, data, count);
end;


function ossl_md5_sha1_final( md : PByte; mctx : PMD5_SHA1_CTX):integer;
begin
    if 0>= MD5_Final(md, @mctx.md5 ) then
        Exit(0);
    Result := _SHA1_Final(md + MD5_DIGEST_LENGTH, @mctx.sha1);
end;


function ossl_md5_sha1_ctrl( mctx : PMD5_SHA1_CTX; cmd, mslen : integer; ms : Pointer):integer;
var
  padtmp : array[0..47] of Byte;

  md5tmp : array[0..(MD5_DIGEST_LENGTH)-1] of Byte;

  sha1tmp : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
begin
    if cmd <> EVP_CTRL_SSL3_MASTER_SECRET then Exit(-2);
    if mctx = nil then Exit(0);
    { SSLv3 client auth handling: see RFC-6101 5.6.8 }
    if mslen <> 48 then Exit(0);
    { At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     }
    if ossl_md5_sha1_update(mctx, ms, mslen ) <= 0 then
        Exit(0);
    { Set padtmp to pad_1 value }
    memset(@padtmp, $36, sizeof(padtmp));
    if 0>= MD5_Update(@mctx.md5, @padtmp, sizeof(padtmp)) then
        Exit(0);
    if 0>= MD5_Final(@md5tmp, @mctx.md5 ) then
        Exit(0);
    if 0>= _SHA1_Update(@mctx.sha1, @padtmp, 40 ) then
        Exit(0);
    if 0>= _SHA1_Final(@sha1tmp, @mctx.sha1 ) then
        Exit(0);
    { Reinitialise context }
    if 0>= ossl_md5_sha1_init(mctx ) then
        Exit(0);
    if ossl_md5_sha1_update(mctx, ms, mslen) <= 0  then
        Exit(0);
    { Set padtmp to pad_2 value }
    memset(@padtmp, $5c, sizeof(padtmp));
    if 0>= MD5_Update(@mctx.md5, @padtmp, sizeof(padtmp )) then
        Exit(0);
    if 0>= MD5_Update(@mctx.md5, @md5tmp, sizeof(md5tmp ) )then
        Exit(0);
    if 0>= _SHA1_Update(@mctx.sha1, @padtmp, 40 ) then
        Exit(0);
    if 0>= _SHA1_Update(@mctx.sha1, @sha1tmp, sizeof(sha1tmp )) then
        Exit(0);
    { Now when ctx is finalised it will return the SSL v3 hash value }
    OPENSSL_cleanse(@md5tmp, sizeof(md5tmp));
    OPENSSL_cleanse(@sha1tmp, sizeof(sha1tmp));
    Result := 1;
end;


end.
