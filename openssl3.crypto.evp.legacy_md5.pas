unit openssl3.crypto.evp.legacy_md5;

interface
uses OpenSSL.Api;


  function EVP_md5:PEVP_MD;
  function _md5_init( ctx : PEVP_MD_CTX):integer;
  function _md5_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function _md5_final( ctx : PEVP_MD_CTX; md : PByte):integer;

const
  md5_md: TEVP_MD = (
    &type: NID_md5;
    pkey_type: NID_md5WithRSAEncryption;
    md_size: MD5_DIGEST_LENGTH;
    flags: 0;
    origin: EVP_ORIG_GLOBAL;
    init: _md5_init;
    update: _md5_update;
    &final: _md5_final;
    copy: nil;
    cleanup: nil;
    block_size: MD5_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil;
  );



implementation
uses openssl3.crypto.md5.md5_dgst, openssl3.crypto.evp.evp_lib;

function _md5_init( ctx : PEVP_MD_CTX):integer;
begin
   Result := MD5_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function _md5_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
   Result := MD5_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function _md5_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
   Result := MD5_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;



function EVP_md5:PEVP_MD;
begin
    Result := @md5_md;
end;



end.
