unit openssl3.crypto.evp.legacy_md4;

interface
uses OpenSSL.Api;

function EVP_md4:PEVP_MD;
function md4_init( ctx : PEVP_MD_CTX):integer;
  function md4_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function md4_final( ctx : PEVP_MD_CTX; md : PByte):integer;

const
  md4_md :TEVP_MD = (
    &type: NID_md4;
    pkey_type: NID_md4WithRSAEncryption;
    md_size: MD4_DIGEST_LENGTH;
    flags: 0;
    origin: EVP_ORIG_GLOBAL;
    //LEGACY_EVP_MD_METH_TABLE(md4_init; md4_update; md4_final; NULL; MD4_CBLOCK);
    init: md4_init;
    update: md4_update;
    &final: md4_final;
    copy: nil;
    cleanup: nil;
    block_size: MD4_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil
);


implementation
uses openssl3.crypto.evp.evp_lib,               openssl3.crypto.md4.md4_dgst;


function md4_init( ctx : PEVP_MD_CTX):integer;
begin
   result := _MD4_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function md4_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
   result := _MD4_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function md4_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
   result := _MD4_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;



function EVP_md4:PEVP_MD;
begin
    Result := @md4_md;
end;

initialization

end.
