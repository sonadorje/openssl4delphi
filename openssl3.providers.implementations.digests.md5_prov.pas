unit openssl3.providers.implementations.digests.md5_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.md5.md5_dgst;

  function md5_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function md5_newctx( prov_ctx : Pointer):Pointer;
  procedure md5_freectx( vctx : Pointer);
  function md5_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
  function md5_get_params( params : POSSL_PARAM):integer;
  function md5_dupctx( ctx : Pointer):Pointer;



const ossl_md5_functions: array[0..8] of TOSSL_DISPATCH  = (
 (function_id:  1; method:(code:@md5_newctx; data:nil)),
 (function_id:  3; method:(code:@MD5_Update; data:nil)),
 (function_id:  4; method:(code:@md5_internal_final; data:nil)),
 (function_id:  6; method:(code:@md5_freectx; data:nil)),
 (function_id:  7; method:(code:@md5_dupctx; data:nil)),
 (function_id:  8; method:(code:@md5_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@md5_internal_init; data:nil)),
 (function_id:  0; method:(code:@md5_internal_init; data:nil)) );



implementation
uses openssl3.crypto.params, OpenSSL3.Err,       openssl3.crypto.sha.sha3,
     openssl3.crypto.mem,                        openssl3.providers.prov_running;



function md5_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PMD5_CTX;
begin
   _in := PMD5_CTX ( ctx);
   if ossl_prov_is_running()  then
             ret := OPENSSL_malloc(sizeof( ret^))
   else
       ret := nil;
   if ret <> nil then
      ret^ := _in^;
    result := ret;
end;



function md5_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (MD5_Init(ctx)>0) );
end;


function md5_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PMD5_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure md5_freectx( vctx : Pointer);
var
  ctx : PMD5_CTX;
begin
   ctx := PMD5_CTX ( vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function md5_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= 16)  and  (MD5_Final(&out, ctx)>0) then
   begin
     outl^ := 16;
     Exit(1);
   end;
   Result := 0;
end;


function md5_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, 64, 16, 0));
end;




initialization
   


end.
