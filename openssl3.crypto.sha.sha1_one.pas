unit openssl3.crypto.sha.sha1_one;

interface
 uses OpenSSL.Api;

function ossl_sha1(const d : PByte; n : size_t; md : PByte):PByte;
function SHA1(const d : PByte; n : size_t; md : PByte):PByte;
function SHA224(const d : PByte; n : size_t; md : PByte):PByte;
function SHA256(const key : PByte; key_len : size_t; md : PByte):PByte;
function SHA384(const d : PByte; n : size_t; md : PByte):PByte;
function SHA512(const d : PByte; n : size_t; md : PByte):PByte;

implementation
uses openssl3.crypto.sha.sha_local,         openssl3.crypto.mem,
     openssl3.crypto.evp.digest;

type
  PHASH_CTX = PSHA_CTX;

{$I openssl3.include.crypto.md32_common.inc}

const _SHA1_Final: function( md : PByte; c : PHASH_CTX):integer = HASH_FINAL;
      _SHA1_Update: function ( c : PHASH_CTX;const data_ : Pointer; len : size_t):integer = HASH_UPDATE;

function SHA1(const d : PByte; n : size_t; md : PByte):PByte;
var
  m : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
begin
    if md = nil then
       md := @m;
    if EVP_Q_digest(nil, 'SHA1', nil, d, n, md, nil) > 0  then
       Result :=  md
    else
       Result := nil;
end;


function SHA224(const d : PByte; n : size_t; md : PByte):PByte;
var
  m : array[0..(SHA224_DIGEST_LENGTH)-1] of Byte;
begin
    if md = nil then md := @m;
    Result := get_result(EVP_Q_digest(nil, 'SHA224', nil, d, n, md, nil) >0, md , nil);
end;


function SHA256(const key : PByte; key_len : size_t; md : PByte):PByte;
var
  m : array[0..(SHA256_DIGEST_LENGTH)-1] of Byte;
begin
    if md = nil then md := @m;
    Result := get_result(EVP_Q_digest(nil, 'SHA256', nil, key, key_len, md, nil) > 0 , md , nil);
end;


function SHA384(const d : PByte; n : size_t; md : PByte):PByte;
var
  m : array[0..(SHA384_DIGEST_LENGTH)-1] of Byte;
begin
    if md = nil then md := @m;
    Result := get_result(EVP_Q_digest(nil, 'SHA384', nil, d, n, md, nil) > 0, md , nil);
end;


function SHA512(const d : PByte; n : size_t; md : PByte):PByte;
var
  m : array[0..(SHA512_DIGEST_LENGTH)-1] of Byte;
begin
    if md = nil then md := @m;
    Result := get_result(EVP_Q_digest(nil, 'SHA512', nil, d, n, md, nil) > 0, md , nil);
end;

function ossl_sha1(const d : PByte; n : size_t; md : PByte):PByte;
var
  c : TSHA_CTX;
  m : array[0..(SHA_DIGEST_LENGTH)-1] of Byte;
begin
    if md = nil then
       md := @m;
    if 0>= _SHA1_Init(@c) then
        Exit(nil);
    _SHA1_Update(@c, d, n);
    _SHA1_Final(md, @c);
    OPENSSL_cleanse(@c, sizeof(c));
    Result := md;
end;


end.
