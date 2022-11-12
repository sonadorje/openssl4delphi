unit openssl3.providers.implementations.digests.md5_sha1_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.md5.md5_dgst,
     openssl3.crypto.md5.md5_sha1;

 function md5_sha1_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function md5_sha1_newctx( prov_ctx : Pointer):Pointer;
  procedure md5_sha1_freectx( vctx : Pointer);
  function md5_sha1_dupctx( ctx : Pointer):Pointer;
  function md5_sha1_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
  function md5_sha1_get_params( params : POSSL_PARAM):integer;
  function md5_sha1_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function md5_sha1_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;

 const ossl_md5_sha1_functions: array[0..10] of TOSSL_DISPATCH  = (
 (function_id:  1; method:(code:@md5_sha1_newctx; data:nil)),
 (function_id:  3; method:(code:@ossl_md5_sha1_update; data:nil)),
 (function_id:  4; method:(code:@md5_sha1_internal_final; data:nil)),
 (function_id:  6; method:(code:@md5_sha1_freectx; data:nil)),
 (function_id:  7; method:(code:@md5_sha1_dupctx; data:nil)),
 (function_id:  8; method:(code:@md5_sha1_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@md5_sha1_internal_init; data:nil)),
 (function_id:  12; method:(code:@md5_sha1_settable_ctx_params; data:nil)),
 (function_id:  9; method:(code:@md5_sha1_set_ctx_params; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );


implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.openssl.params;

var
  known_md5_sha1_settable_ctx_params: array[0..1] of TOSSL_PARAM ;





function md5_sha1_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PMD5_SHA1_CTX;
  p   : POSSL_PARAM;
begin
    ctx := PMD5_SHA1_CTX ( vctx);
    if ctx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS);
    if (p <> nil)  and  (p.data_type = OSSL_PARAM_OCTET_STRING) then
       Exit(ossl_md5_sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET,
                                  p.data_size, p.data));
    Result := 1;
end;



function md5_sha1_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_md5_sha1_settable_ctx_params;
end;



function md5_sha1_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (ossl_md5_sha1_init(ctx)>0)
                and  (md5_sha1_set_ctx_params(ctx, params)>0) );
end;


function md5_sha1_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PMD5_SHA1_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure md5_sha1_freectx( vctx : Pointer);
var
  ctx : PMD5_SHA1_CTX;
begin
   ctx := PMD5_SHA1_CTX(vctx);

   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function md5_sha1_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PMD5_SHA1_CTX;
begin
   _in := PMD5_SHA1_CTX(ctx);
   if ossl_prov_is_running()  then
             ret := OPENSSL_malloc(sizeof( ret^))
   else
       ret := nil;
   if ret <> nil then
      ret^ := _in^;
    result := ret;
end;


function md5_sha1_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= (16 + 20))  and
      (ossl_md5_sha1_final(&out, ctx)>0)  then
   begin
       outl^ := (16 + 20);
       Exit(1);
   end;
   Result := 0;
end;


function md5_sha1_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, 64, (16 + 20), 0));
end;

initialization
  known_md5_sha1_settable_ctx_params[0] := OSSL_PARAM_DEFN(OSSL_DIGEST_PARAM_SSL3_MS, OSSL_PARAM_OCTET_STRING, nil, 0, 0);
  known_md5_sha1_settable_ctx_params[1] :=  OSSL_PARAM_END;


end.
