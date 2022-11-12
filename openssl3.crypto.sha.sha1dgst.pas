unit openssl3.crypto.sha.sha1dgst;

interface
uses OpenSSL.Api;

type
  PHASH_CTX = PSHA_CTX;

function ossl_sha1_ctrl(sha1 : PSHA_CTX; cmd, mslen : integer; ms : Pointer):integer;
function _SHA1_Update( c : PHASH_CTX;const data_ : Pointer; len : size_t):integer;
function HASH_FINAL( md : PByte; c : PHASH_CTX):integer;
//extract from sha1dgst.i
 procedure _SHA1_Transform(c : Pointer;const data : PByte);

const _SHA1_Final: function( md : PByte; c : PHASH_CTX):integer = HASH_FINAL;
implementation

uses  openssl3.crypto.sha.sha_local,  openssl3.crypto.mem ;

{$I openssl3.include.crypto.md32_common.inc}

procedure _SHA1_Transform(c : Pointer;const data : PByte);
begin
    sha1_block_data_order(PSHA_CTX(c), data, 1);
end;

//与函数sha1_update 重名
function _SHA1_Update( c : PHASH_CTX;const data_ : Pointer; len : size_t):integer;
var
  data, p : PByte;

  l : HASH_LONG;

  n : size_t;
begin
     data := data_;
    if len = 0 then Exit(1);
    l := (c.Nl + ((HASH_LONG(len))  shl  3)) and $ffffffff;
    if l < c.Nl then { overflow }
        Inc(c.Nh);
    c.Nh  := c.Nh + (HASH_LONG(len  shr  29));// might cause compiler warning on 16-bit
    c.Nl := l;
    n := c.num;
    if n <> 0 then
    begin
        p := PByte( @c.data);
        if (len >= HASH_CBLOCK)  or  (len + n >= HASH_CBLOCK) then
        begin
            memcpy(p + n, data, HASH_CBLOCK - n);
            sha1_block_data_order(c, p, 1);
            n := HASH_CBLOCK - n;
            data  := data + n;
            len  := len - n;
            c.num := 0;
            {
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             }
            memset(p, 0, HASH_CBLOCK); { keep it zeroed }
        end
        else
        begin
            memcpy(p + n, data, len);
            c.num  := c.num + Uint32 (len);
            Exit(1);
        end;
    end;
    n := len div HASH_CBLOCK;
    if n > 0 then
    begin
        sha1_block_data_order(c, data, n);
        n  := n  * HASH_CBLOCK;
        data  := data + n;
        len  := len - n;
    end;
    if len <> 0 then
    begin
        p := PByte( @c.data);
        c.num := Uint32 (len);
        memcpy(p, data, len);
    end;
    Result := 1;
end;

function ossl_sha1_ctrl(sha1 : PSHA_CTX; cmd, mslen : integer; ms : Pointer):integer;
var
  padtmp : array[0..39] of Byte;

  sha1tmp : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
begin
    if cmd <> EVP_CTRL_SSL3_MASTER_SECRET then
       Exit(-2);
    if sha1 = nil then Exit(0);
    { SSLv3 client auth handling: see RFC-6101 5.6.8 }
    if mslen <> 48 then Exit(0);
    { At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     }
    if _SHA1_Update(sha1, ms, mslen) <= 0  then
        Exit(0);
    { Set padtmp to pad_1 value }
    memset(@padtmp, $36, sizeof(padtmp));
    if 0>= _SHA1_Update(sha1, @padtmp, sizeof(padtmp)) then
        Exit(0);
    if 0>= _SHA1_Final(@sha1tmp, sha1)  then
        Exit(0);
    { Reinitialise context }
    if 0>= _SHA1_Init(sha1) then
        Exit(0);
    if _SHA1_Update(sha1, ms, mslen) <= 0  then
        Exit(0);
    { Set padtmp to pad_2 value }
    memset(@padtmp, $5c, sizeof(padtmp));
    if 0>= _SHA1_Update(sha1, @padtmp, sizeof(padtmp))  then
        Exit(0);
    if 0>= _SHA1_Update(sha1, @sha1tmp, sizeof(sha1tmp)) then
        Exit(0);
    { Now when ctx is finalised it will return the SSL v3 hash value }
    OPENSSL_cleanse(@sha1tmp, sizeof(sha1tmp));
    Result := 1;
end;


end.
