unit openssl3.providers.implementations.digests.blake2_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2b_prov,
     openssl3.providers.implementations.digests.blake2s_prov;

function blake2s256_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
function blake2s256_newctx( prov_ctx : Pointer):Pointer;
procedure blake2s256_freectx( vctx : Pointer);
function blake2s256_dupctx( ctx : Pointer):Pointer;
function blake2s256_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
function blake2s256_get_params( params : POSSL_PARAM):integer;
function blake2b512_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
function blake2b512_newctx( prov_ctx : Pointer):Pointer;
procedure blake2b512_freectx( vctx : Pointer);
function blake2b512_dupctx( ctx : Pointer):Pointer;
function blake2b512_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
function blake2b512_get_params( params : POSSL_PARAM):integer;

 const ossl_blake2s256_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@blake2s256_newctx; data:nil)),
(function_id:  3; method:(code:@ossl_blake2s_update; data:nil)),
(function_id:  4; method:(code:@blake2s256_internal_final; data:nil)),
(function_id:  6; method:(code:@blake2s256_freectx; data:nil)),
(function_id:  7; method:(code:@blake2s256_dupctx; data:nil)),
(function_id:  8; method:(code:@blake2s256_get_params; data:nil)),
(function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
(function_id:  2; method:(code:@blake2s256_internal_init; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

ossl_blake2b512_functions: array[0..8] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@blake2b512_newctx; data:nil)),
(function_id:  3; method:(code:@ossl_blake2b_update; data:nil)),
(function_id:  4; method:(code:@blake2b512_internal_final; data:nil)),
(function_id:  6; method:(code:@blake2b512_freectx; data:nil)),
(function_id:  7; method:(code:@blake2b512_dupctx; data:nil)),
(function_id:  8; method:(code:@blake2b512_get_params; data:nil)),
(function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
(function_id:  2; method:(code:@blake2b512_internal_init; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 function ossl_blake2s256_init( ctx : Pointer):integer;
  function ossl_blake2b512_init( ctx : Pointer):integer;

implementation
uses openssl3.providers.fips.self_test,          openssl3.crypto.mem;


function blake2s256_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (ossl_blake2s256_init(ctx) > 0 ) );
end;


function blake2s256_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PBLAKE2S_CTX;
begin
   if ossl_prov_is_running  then
      ctx :=  CRYPTO_zalloc(sizeof(ctx^))
   else
      ctx :=  Pointer(0) ;
   Exit(ctx);
end;


procedure blake2s256_freectx( vctx : Pointer);
var
  ctx : PBLAKE2S_CTX;
begin
  ctx := PBLAKE2S_CTX(vctx);
  CRYPTO_clear_free(ctx, sizeof(ctx^));
end;


function blake2s256_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PBLAKE2S_CTX;
begin
   _in := PBLAKE2S_CTX(ctx);
   if ossl_prov_is_running  then
      ret :=  CRYPTO_malloc(sizeof(ret^))
   else
      ret :=  Pointer(0) ;
   if ret <> Pointer(0) then
      ret^ := _in^;
   Exit(ret);
end;


function blake2s256_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= 32)  and  (ossl_blake2s_final(out, ctx) > 0) then
  begin
     outl^ := 32;
     Exit(1);
   end;
   Exit(0);
end;


function blake2s256_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, 64, 32, 0));
end;


function blake2b512_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (ossl_blake2b512_init(ctx) > 0) );
end;


function blake2b512_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PBLAKE2B_CTX;
begin
   if ossl_prov_is_running then
      ctx := CRYPTO_zalloc(sizeof( ctx^))
   else
      ctx := Pointer(0) ;
   Exit(ctx);
end;


procedure blake2b512_freectx( vctx : Pointer);
var
  ctx : PBLAKE2B_CTX;
begin
 ctx := PBLAKE2B_CTX (vctx);
 CRYPTO_clear_free(ctx, sizeof(ctx^));
end;


function blake2b512_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PBLAKE2B_CTX;
begin
   _in := PBLAKE2B_CTX (ctx);
   if ossl_prov_is_running then
      ret :=  CRYPTO_malloc(sizeof( ret^))
   else
      ret := Pointer(0) ;
   if ret <> Pointer(0) then
      ret^ := _in^;
   Exit(ret);
end;


function blake2b512_internal_final( ctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= 64)  and  (ossl_blake2b_final(out, ctx) > 0) then
  begin
    outl^ := 64;
    Exit(1);
  end;
   Exit(0);
end;


function blake2b512_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, 128, 64, 0));
end;

function ossl_blake2s256_init( ctx : Pointer):integer;
var
  P : TBLAKE2S_PARAM;
begin
    ossl_blake2s_param_init(@P);
    Result := ossl_blake2s_init(PBLAKE2S_CTX(ctx), @P);
end;


function ossl_blake2b512_init( ctx : Pointer):integer;
var
  P : TBLAKE2B_PARAM;
begin
    ossl_blake2b_param_init(@P);
    Result := ossl_blake2b_init(PBLAKE2B_CTX (ctx), @P);
end;


end.
