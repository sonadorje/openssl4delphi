unit openssl3.crypto.evp.legacy_mdc2;

interface
uses OpenSSL.Api;

function EVP_mdc2:PEVP_MD;
function mdc2_init( ctx : PEVP_MD_CTX):integer;
  function mdc2_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function mdc2_final( ctx : PEVP_MD_CTX; md : PByte):integer;

const  mdc2_md: TEVP_MD = (
    &type: NID_mdc2;
    pkey_type: NID_mdc2WithRSA;
    md_size: MDC2_DIGEST_LENGTH;
    flags: 0;
    origin: EVP_ORIG_GLOBAL;
    {LEGACY_EVP_MD_METH_TABLE(mdc2_init; mdc2_update; mdc2_final; nil;
                             MDC2_BLOCK);}
    init: mdc2_init;
    update: mdc2_update;
    &final: mdc2_final;
    copy: nil;
    cleanup: nil;
    block_size: MDC2_BLOCK;
    ctx_size: 0;
    md_ctrl: nil
);


implementation
uses openssl3.crypto.mdc2.mdc2dgst,            openssl3.crypto.evp.evp_lib;

function mdc2_init( ctx : PEVP_MD_CTX):integer;
begin
   result := _MDC2_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function mdc2_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
   result := _MDC2_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function mdc2_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
   result := _MDC2_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;



function EVP_mdc2:PEVP_MD;
begin
    Result := @mdc2_md;
end;

end.
