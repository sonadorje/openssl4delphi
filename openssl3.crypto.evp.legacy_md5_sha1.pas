unit openssl3.crypto.evp.legacy_md5_sha1;

interface
uses OpenSSL.Api,   openssl3.crypto.md5.md5_sha1;

function md5_sha1_int_ctrl( ctx : PEVP_MD_CTX; cmd, mslen : integer; ms : Pointer):integer;
function EVP_md5_sha1:PEVP_MD;
function md5_sha1_int_init( ctx : PEVP_MD_CTX):integer;
  function md5_sha1_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function md5_sha1_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;


 const md5_sha1_md: TEVP_MD  = (
    &type: NID_md5_sha1;
    pkey_type: NID_md5_sha1;
    md_size: MD5_SHA1_DIGEST_LENGTH;
    flags: 0;
    origin: EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(md5_sha1_int_init; md5_sha1_int_update;
                             md5_sha1_int_final; md5_sha1_int_ctrl;
                             MD5_SHA1_CBLOCK); }
    init: md5_sha1_int_init;
    update: md5_sha1_int_update;
    &final: md5_sha1_int_final;
    copy: nil;
    cleanup: nil;
    block_size: MD5_SHA1_CBLOCK;
    ctx_size: 0;
    md_ctrl: md5_sha1_int_ctrl
);


implementation
uses openssl3.crypto.evp.evp_lib;

function md5_sha1_int_init( ctx : PEVP_MD_CTX):integer;
begin
 Result := ossl_md5_sha1_init(EVP_MD_CTX_get0_md_data(ctx));
end;


function md5_sha1_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
 Result := ossl_md5_sha1_update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function md5_sha1_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
 Result := ossl_md5_sha1_final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function md5_sha1_int_ctrl( ctx : PEVP_MD_CTX; cmd, mslen : integer; ms : Pointer):integer;
begin
    Result := ossl_md5_sha1_ctrl(EVP_MD_CTX_get0_md_data(ctx), cmd, mslen, ms);
end;


function EVP_md5_sha1:PEVP_MD;
begin
    Result := @md5_sha1_md;
end;


end.
