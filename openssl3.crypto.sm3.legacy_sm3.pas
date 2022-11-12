unit openssl3.crypto.sm3.legacy_sm3;

interface
uses OpenSSL.Api;

  function sm3_int_init( ctx : PEVP_MD_CTX):integer;
  function sm3_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  function sm3_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;

implementation
uses openssl3.crypto.sm3.sm3,                   openssl3.crypto.evp.evp_lib;


function sm3_int_init( ctx : PEVP_MD_CTX):integer;
begin
   result := ossl_sm3_init(EVP_MD_CTX_get0_md_data(ctx));
end;


function sm3_int_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
   result := ossl_sm3_update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;


function sm3_int_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
   result := ossl_sm3_final(md, EVP_MD_CTX_get0_md_data(ctx));
end;



end.
