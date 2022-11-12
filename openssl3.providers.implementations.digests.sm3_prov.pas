unit openssl3.providers.implementations.digests.sm3_prov;

interface
uses OpenSSL.Api, openssl3.crypto.sha.sha_local,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.sha.sha256,
     openssl3.crypto.sha.sha512,
     openssl3.crypto.sm3.sm3,
     openssl3.crypto.sha.sha1dgst;

  function sm3_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function sm3_newctx( prov_ctx : Pointer):Pointer;
  procedure sm3_freectx( vctx : Pointer);
  function sm3_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
  function sm3_get_params( params : POSSL_PARAM):integer;
  function sm3_dupctx( ctx : Pointer):Pointer;

const ossl_sm3_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sm3_newctx; data:nil)),
 (function_id:  3; method:(code:@ossl_sm3_update; data:nil)),
 (function_id:  4; method:(code:@sm3_internal_final; data:nil)),
 (function_id:  6; method:(code:@sm3_freectx; data:nil)),
 (function_id:  7; method:(code:@sm3_dupctx; data:nil)),
 (function_id:  8; method:(code:@sm3_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sm3_internal_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );


implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.crypto.sha.keccak1600,
     OpenSSL3.openssl.params;







function sm3_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSM3_CTX;
begin
   _in := PSM3_CTX ( ctx);
    if ossl_prov_is_running()  then
           ret := OPENSSL_malloc(sizeof( ret^))
    else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;






function sm3_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (ossl_sm3_init(ctx)>0));
end;


function sm3_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSM3_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure sm3_freectx( vctx : Pointer);
var
  ctx : PSM3_CTX;
begin
   ctx := PSM3_CTX(vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sm3_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running) and  (outsz >= 32)  and
      (ossl_sm3_final(_out, ctx)>0) then
   begin
       outl^ := 32;
       Exit(1);
   end;
   Result := 0;
end;


function sm3_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, 64, 32, 0));
end;

initialization
   


end.
