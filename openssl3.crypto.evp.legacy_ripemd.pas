unit openssl3.crypto.evp.legacy_ripemd;

interface
uses OpenSSL.Api;

function EVP_ripemd160:PEVP_MD;
function ripe_init( ctx : PEVP_MD_CTX):integer;
  function ripe_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function ripe_final( ctx : PEVP_MD_CTX; md : PByte):integer;

const
  ripemd160_md: TEVP_MD = (
    &type: NID_ripemd160;
    pkey_type: NID_ripemd160WithRSA;
    md_size: RIPEMD160_DIGEST_LENGTH;
    flags: 0;
    origin: EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(ripe_init; ripe_update; ripe_final; nil;
                             RIPEMD160_CBLOCK), }

    init: ripe_init;
    update: ripe_update;
    &final: ripe_final;
    copy: nil;
    cleanup: nil;
    block_size: RIPEMD160_CBLOCK;
    ctx_size: 0;
    md_ctrl: nil
);


implementation
uses openssl3.crypto.ripemd.rmd_dgst,          openssl3.crypto.evp.evp_lib;

function ripe_init( ctx : PEVP_MD_CTX):integer;
begin
   result := RIPEMD160_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function ripe_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
   result := RIPEMD160_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function ripe_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
   result := RIPEMD160_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;



function EVP_ripemd160:PEVP_MD;
begin
    Result := @ripemd160_md;
end;

end.
