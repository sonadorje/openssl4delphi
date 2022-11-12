unit openssl3.crypto.evp.legacy_sha;

interface
uses OpenSSL.Api;

type
  PHASH_CTX = PSHA_CTX;

 function EVP_sha1:PEVP_MD;
 function sha1_init( ctx : PEVP_MD_CTX):integer;
 function sha1_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
 function sha1_final( ctx : PEVP_MD_CTX; md : PByte):integer;
 function sha1_int_ctrl( ctx : PEVP_MD_CTX; cmd, p1 : integer; p2 : Pointer):integer;
 function HASH_FINAL( md : PByte; c : PHASH_CTX):integer;


  function sha224_init( ctx : PEVP_MD_CTX):integer;
  function sha224_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha224_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function sha256_init( ctx : PEVP_MD_CTX):integer;
  function sha256_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha256_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function sha384_init( ctx : PEVP_MD_CTX):integer;
  function sha384_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha384_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function sha512_init( ctx : PEVP_MD_CTX):integer;
  function sha512_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha512_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function sha512_224_int_init( ctx : PEVP_MD_CTX):integer;
  function sha512_224_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha512_224_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function sha512_256_int_init( ctx : PEVP_MD_CTX):integer;
  function sha512_256_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha512_256_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function sha3_int_init( ctx : PEVP_MD_CTX):integer;
  function sha3_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sha3_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
  function shake_init( ctx : PEVP_MD_CTX):integer;

 const  sha1_md: TEVP_MD = (
    &type: NID_sha1;
    pkey_type:NID_sha1WithRSAEncryption;
    md_size:SHA_DIGEST_LENGTH;
    flags:EVP_MD_FLAG_DIGALGID_ABSENT;
    origin:EVP_ORIG_GLOBAL;
    init: sha1_init;
    update:sha1_update;
    &final: sha1_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA_CBLOCK;
    ctx_size: 0;
    md_ctrl: sha1_int_ctrl
);

const  sha224_md: TEVP_MD = (
    &type: NID_sha224;
    pkey_type: NID_sha224WithRSAEncryption;
    md_size: SHA224_DIGEST_LENGTH;
    flags: EVP_MD_FLAG_DIGALGID_ABSENT;
    origin: EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(sha224_init, sha224_update, sha224_final, nil,
                             SHA256_CBLOCK),}
    init: sha224_init;
    update:sha224_update;
    &final: sha224_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA256_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil
);

const  sha256_md: TEVP_MD = (
    &type: NID_sha256;
    pkey_type: NID_sha256WithRSAEncryption;
    md_size: SHA256_DIGEST_LENGTH;
    flags: EVP_MD_FLAG_DIGALGID_ABSENT;
    origin: EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(sha256_init, sha256_update, sha256_final, nil,
                             SHA256_CBLOCK),}
    init: sha256_init;
    update:sha256_update;
    &final: sha256_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA256_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil);

const  sha384_md: TEVP_MD = (
    &type: NID_sha384;
    pkey_type: NID_sha384WithRSAEncryption;
    md_size:SHA384_DIGEST_LENGTH;
    flags:EVP_MD_FLAG_DIGALGID_ABSENT;
    origin:EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(sha384_init, sha384_update, sha384_final, nil,
                             SHA512_CBLOCK),}
    init: sha384_init;
    update:sha384_update;
    &final: sha384_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA512_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil);

const  sha512_md: TEVP_MD = (
    &type: NID_sha512;
    pkey_type:NID_sha512WithRSAEncryption;
    md_size:SHA512_DIGEST_LENGTH;
    flags:EVP_MD_FLAG_DIGALGID_ABSENT;
    origin:EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(sha512_init, sha512_update, sha512_final, nil,
                             SHA512_CBLOCK),}
    init: sha512_init;
    update:sha512_update;
    &final: sha512_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA512_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil);

 const  sha512_224_md: TEVP_MD = (
    &type:NID_sha512_224;
    pkey_type:NID_sha512_224WithRSAEncryption;
    md_size:SHA224_DIGEST_LENGTH;
    flags:EVP_MD_FLAG_DIGALGID_ABSENT;
    origin:EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(sha512_224_int_init, sha512_224_int_update,
                             sha512_224_int_final, nil, SHA512_CBLOCK),}
    init: sha512_224_int_init;
    update:sha512_224_int_update;
    &final: sha512_224_int_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA512_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil);

 const  sha512_256_md:TEVP_MD = (
    &type:NID_sha512_256;
    pkey_type:NID_sha512_256WithRSAEncryption;
    md_size:SHA256_DIGEST_LENGTH;
    flags:EVP_MD_FLAG_DIGALGID_ABSENT;
    origin:EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(sha512_256_int_init, sha512_256_int_update,
                             sha512_256_int_final, nil, SHA512_CBLOCK),}
    init: sha512_256_int_init;
    update:sha512_256_int_update;
    &final: sha512_256_int_final;
    copy:nil;
    cleanup: nil;
    block_size: SHA512_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil);

const _SHA1_Final: function( md : PByte; c : PHASH_CTX):integer = HASH_FINAL;

function EVP_sha224:PEVP_MD;
function EVP_sha256:PEVP_MD;
function EVP_sha384:PEVP_MD;
function EVP_sha512:PEVP_MD;
function EVP_sha512_224:PEVP_MD;
function EVP_sha512_256:PEVP_MD;

function EVP_sha3_224:PEVP_MD;
  function EVP_sha3_256:PEVP_MD;
  function EVP_sha3_384:PEVP_MD;
  function EVP_sha3_512:PEVP_MD;

implementation

uses  openssl3.crypto.sha.sha1dgst,     openssl3.crypto.evp.evp_lib,
      openssl3.crypto.sha.sha256,       openssl3.crypto.sha.sha512,
      openssl3.crypto.sha.sha3,
      openssl3.crypto.sha.sha_local,    openssl3.crypto.mem ;

{$I openssl3.include.crypto.md32_common.inc}





function EVP_sha3_224:PEVP_MD;
const
  sha3_224_md : TEVP_MD = (
       &type:1096; pkey_type:1116; md_size:224 div 8; flags:$0008; origin:1;
       init:sha3_int_init; update:sha3_int_update; &final:sha3_int_final;
       copy:Pointer(0) ; cleanup:Pointer(0) ; block_size:(1600 - 224 * 2) div 8;
       ctx_size:0; md_ctrl:Pointer(0) );
begin
   Result := @sha3_224_md;
end;


function EVP_sha3_256:PEVP_MD;
const
  sha3_256_md : TEVP_MD = (
        &type:1097; pkey_type:1117; md_size:256 div 8; flags:$0008; origin:1;
        init:sha3_int_init; update:sha3_int_update; &final:sha3_int_final;
        copy:nil; cleanup: nil; block_size:(1600 - 256 * 2) div 8; ctx_size:0; md_ctrl:nil);
begin
Result := @sha3_256_md;
end;


function EVP_sha3_384:PEVP_MD;
const
  sha3_384_md : TEVP_MD = (
        &type:1098; pkey_type:1118; md_size:384 div 8; flags:$0008; origin:1;
        init:sha3_int_init; update:sha3_int_update;  &final:sha3_int_final;
        copy:nil; cleanup: nil; block_size:(1600 - 384 * 2) div 8; ctx_size:0; md_ctrl:nil);
begin
  Result := @sha3_384_md;
end;


function EVP_sha3_512:PEVP_MD;
const
  sha3_512_md : TEVP_MD = (
       &type:1099; pkey_type:1119; md_size:512 div 8; flags:$0008; origin:1;
       init:sha3_int_init; update:sha3_int_update; &final:sha3_int_final;
       copy:nil; cleanup: nil; block_size: (1600 - 512 * 2) div 8; ctx_size:0; md_ctrl:nil);
begin
   Result := @sha3_512_md;
end;

function EVP_sha512_256:PEVP_MD;
begin
    Result := @sha512_256_md;
end;


function EVP_sha512_224:PEVP_MD;
begin
    Result := @sha512_224_md;
end;



function EVP_sha512:PEVP_MD;
begin
    Result := @sha512_md;
end;


function EVP_sha384:PEVP_MD;
begin
    Result := @sha384_md;
end;



function EVP_sha256:PEVP_MD;
begin
    Result := @sha256_md;
end;

function sha224_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := _SHA224_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha224_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := _SHA224_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha224_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := _SHA224_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function sha256_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := _SHA256_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha256_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := _SHA256_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha256_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := _SHA256_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function sha384_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := _SHA384_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha384_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := _SHA384_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha384_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := _SHA384_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function sha512_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := _SHA512_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha512_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := _SHA512_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha512_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := _SHA512_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function sha512_224_int_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := sha512_224_init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha512_224_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := _SHA512_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha512_224_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := _SHA512_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function sha512_256_int_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := sha512_256_init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha512_256_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := _SHA512_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha512_256_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := _SHA512_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function sha3_int_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := ossl_sha3_init(EVP_MD_CTX_get0_md_data(ctx), $06, ctx.digest.md_size * 8);
end;


function sha3_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
  Result := ossl_sha3_update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha3_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
  Result := ossl_sha3_final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function shake_init( ctx : PEVP_MD_CTX):integer;
begin
  Result := ossl_sha3_init(EVP_MD_CTX_get0_md_data(ctx), $1f, ctx.digest.md_size * 8);
end;

function EVP_sha224:PEVP_MD;
begin
    Result := @sha224_md;
end;


function sha1_int_ctrl( ctx : PEVP_MD_CTX; cmd, p1 : integer; p2 : Pointer):integer;
begin
   if ctx <> nil then
      Result := ossl_sha1_ctrl( EVP_MD_CTX_get0_md_data(ctx),
                          cmd, p1, p2)
   else
      Result := ossl_sha1_ctrl(nil, cmd, p1, p2);
end;

function sha1_init( ctx : PEVP_MD_CTX):integer;
begin
    result :=  _SHA1_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sha1_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
    result :=  _SHA1_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sha1_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
    result :=  _SHA1_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function EVP_sha1:PEVP_MD;
begin
    Result := @sha1_md;
end;


end.
