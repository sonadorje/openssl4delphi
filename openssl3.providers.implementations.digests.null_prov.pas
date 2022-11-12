unit openssl3.providers.implementations.digests.null_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.md5.md5_dgst,
     openssl3.crypto.md5.md5_sha1;

  function nullmd_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function nullmd_newctx( prov_ctx : Pointer):Pointer;
  procedure nullmd_freectx( vctx : Pointer);
  function nullmd_dupctx( ctx : Pointer):Pointer;
  function nullmd_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
  function nullmd_get_params( params : POSSL_PARAM):integer;
  function null_init( ctx : PNULLMD_CTX):integer;
  function null_update(ctx : PNULLMD_CTX;const data : Pointer; datalen : size_t):integer;
  function null_final( md : PByte; ctx : PNULLMD_CTX):integer;

const ossl_nullmd_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@nullmd_newctx; data:nil)),
 (function_id:  3; method:(code:@null_update; data:nil)),
 (function_id:  4; method:(code:@nullmd_internal_final; data:nil)),
 (function_id:  6; method:(code:@nullmd_freectx; data:nil)),
 (function_id:  7; method:(code:@nullmd_dupctx; data:nil)),
 (function_id:  8; method:(code:@nullmd_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@nullmd_internal_init; data:nil)),
 (function_id:  0;  method:(code:nil; data:nil)) );


implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.openssl.params;





function null_init( ctx : PNULLMD_CTX):integer;
begin
    Result := 1;
end;


function null_update(ctx : PNULLMD_CTX;const data : Pointer; datalen : size_t):integer;
begin
    Result := 1;
end;


function null_final( md : PByte; ctx : PNULLMD_CTX):integer;
begin
    Result := 1;
end;






function nullmd_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Exit( Int( (ossl_prov_is_running)  and (null_init(ctx)>0)) );
end;


function nullmd_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PNULLMD_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure nullmd_freectx( vctx : Pointer);
var
  ctx : PNULLMD_CTX;
begin
  ctx := PNULLMD_CTX(vctx);
  OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function nullmd_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PNULLMD_CTX;
begin
  _in := PNULLMD_CTX(  ctx);
  if ossl_prov_is_running()  then
             ret := OPENSSL_malloc(sizeof( ret^))
   else
       ret := nil;
   if ret <> nil then
      ret^ := _in^;
   result := ret;
end;


function nullmd_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (null_final(&out, ctx)>0)  then
   begin
       outl^ := 0;
       Exit(1);
   end;
   Result := 0;
end;


function nullmd_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, 0, 0, 0));
end;



end.
