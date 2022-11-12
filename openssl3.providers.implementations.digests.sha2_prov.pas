unit openssl3.providers.implementations.digests.sha2_prov;

interface
uses OpenSSL.Api, openssl3.crypto.sha.sha_local,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.sha.sha256,
     openssl3.crypto.sha.sha512,
     openssl3.crypto.sha.sha1dgst;
const
  SHA2_FLAGS = PROV_DIGEST_FLAG_ALGID_ABSENT;

 function sha1_newctx( prov_ctx : Pointer):Pointer;
 function sha1_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
 function sha1_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
 procedure sha1_freectx( ctx : PSHA_CTX);
 procedure sha1_dupctx(const sctx : PSHA_CTX; var dctx:PSHA_CTX);
 function sha1_get_params( params : POSSL_PARAM):integer;
 function sha1_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
 function sha1_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;

 function sha224_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
 procedure sha224_freectx( vctx : Pointer);
 function sha224_newctx( prov_ctx : Pointer):Pointer;
 function sha224_dupctx( ctx : Pointer):Pointer;
 function sha224_get_params( params : POSSL_PARAM):integer;
 function sha224_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;

  function sha256_newctx( prov_ctx : Pointer):Pointer;
  function sha256_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
  procedure sha256_freectx( vctx : Pointer);
  function sha256_dupctx( ctx : Pointer):Pointer;
  function sha256_get_params( params : POSSL_PARAM):integer;
   function sha256_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;

   function sha384_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function sha384_newctx( prov_ctx : Pointer):Pointer;
  procedure sha384_freectx( vctx : Pointer);
  function sha384_dupctx( ctx : Pointer):Pointer;
  function sha384_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
  function sha384_get_params( params : POSSL_PARAM):integer;

  function sha512_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function sha512_newctx( prov_ctx : Pointer):Pointer;
  procedure sha512_freectx( vctx : Pointer);
  function sha512_dupctx( ctx : Pointer):Pointer;
  function sha512_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
  function sha512_get_params( params : POSSL_PARAM):integer;


  function sha512_224_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function sha512_224_newctx( prov_ctx : Pointer):Pointer;
  procedure sha512_224_freectx( vctx : Pointer);
  function sha512_224_dupctx( ctx : Pointer):Pointer;
  function sha512_224_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
  function sha512_224_get_params( params : POSSL_PARAM):integer;

  function sha512_256_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
  function sha512_256_newctx( prov_ctx : Pointer):Pointer;
  procedure sha512_256_freectx( vctx : Pointer);
  function sha512_256_dupctx( ctx : Pointer):Pointer;
  function sha512_256_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
  function sha512_256_get_params( params : POSSL_PARAM):integer;

const ossl_sha1_functions: array[0..10] of TOSSL_DISPATCH = (
   (function_id:  1; method:(code:@sha1_newctx; data:nil)),
	 (function_id:  3; method:(code:@_SHA1_Update; data:nil)),
	 (function_id:  4; method:(code:@sha1_internal_final; data:nil)),
	 (function_id:  6; method:(code:@sha1_freectx; data:nil)),
	 (function_id:  7; method:(code:@sha1_dupctx; data:nil)),
	 (function_id:  8; method:(code:@sha1_get_params; data:nil)),
	 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
	 (function_id:  2; method:(code:@sha1_internal_init; data:nil)),
	 (function_id:  12; method:(code:@sha1_settable_ctx_params; data:nil)),
	 (function_id:  9; method:(code:@sha1_set_ctx_params; data:nil)),
	 (function_id:  0; method:(code:nil; data:nil) )
);

ossl_sha224_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha224_newctx; data:nil)),
 (function_id:  3; method:(code:@_SHA224_Update; data:nil)),
 (function_id:  4; method:(code:@sha224_internal_final; data:nil)),
 (function_id:  6; method:(code:@sha224_freectx; data:nil)),
 (function_id:  7; method:(code:@sha224_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha224_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sha224_internal_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

ossl_sha256_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha256_newctx; data:nil)),
 (function_id:  3; method:(code:@_SHA256_Update; data:nil)),
 (function_id:  4; method:(code:@sha256_internal_final; data:nil)),
 (function_id:  6; method:(code:@sha256_freectx; data:nil)),
 (function_id:  7; method:(code:@sha256_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha256_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sha256_internal_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

ossl_sha384_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha384_newctx; data:nil)),
 (function_id:  3; method:(code:@_SHA384_Update; data:nil)),
 (function_id:  4; method:(code:@sha384_internal_final; data:nil)),
 (function_id:  6; method:(code:@sha384_freectx; data:nil)),
 (function_id:  7; method:(code:@sha384_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha384_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sha384_internal_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 ossl_sha512_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha512_newctx; data:nil)),
 (function_id:  3; method:(code:@_SHA512_Update; data:nil)),
 (function_id:  4; method:(code:@sha512_internal_final; data:nil)),
 (function_id:  6; method:(code:@sha512_freectx; data:nil)),
 (function_id:  7; method:(code:@sha512_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha512_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sha512_internal_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 ossl_sha512_224_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha512_224_newctx; data:nil)),
 (function_id:  3; method:(code:@_SHA512_Update; data:nil)),
 (function_id:  4; method:(code:@sha512_224_internal_final; data:nil)),
 (function_id:  6; method:(code:@sha512_224_freectx; data:nil)),
 (function_id:  7; method:(code:@sha512_224_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha512_224_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sha512_224_internal_init; data:nil)),
 (function_id:  0; method:(code:@sha512_224_internal_init; data:nil))
 );

 ossl_sha512_256_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha512_256_newctx; data:nil)),
 (function_id:  3; method:(code:@_SHA512_Update; data:nil)),
 (function_id:  4; method:(code:@sha512_256_internal_final; data:nil)),
 (function_id:  6; method:(code:@sha512_256_freectx; data:nil)),
 (function_id:  7; method:(code:@sha512_256_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha512_256_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@sha512_256_internal_init; data:nil)),
 (function_id:  0; method:(code:@sha512_224_internal_init; data:nil) )
 );

implementation
uses openssl3.crypto.params,
     openssl3.crypto.mem, openssl3.providers.prov_running;

type
  PHASH_CTX = PSHA_CTX;

{$I openssl3.include.crypto.md32_common.inc}

const _SHA1_Final: function( md : PByte; c : PHASH_CTX):integer = HASH_FINAL;

function sha512_256_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := Int( (ossl_prov_is_running)  and  (sha512_256_init(ctx)>0) );
end;


function sha512_256_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA512_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure sha512_256_freectx( vctx : Pointer);
var
  ctx : PSHA512_CTX;
begin
   ctx := PSHA512_CTX ( vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sha512_256_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSHA512_CTX;
begin
   _in := PSHA512_CTX ( ctx);
   if ossl_prov_is_running()  then
           ret := OPENSSL_malloc(sizeof( ret^))
   else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;


function sha512_256_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
     if (ossl_prov_is_running)  and  (outsz >= SHA256_DIGEST_LENGTH)  and  (_SHA512_Final(_out, ctx)>0) then
     begin
         outl^ := SHA256_DIGEST_LENGTH;
         Exit(1);
     end;
     result := 0;
end;


function sha512_256_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (SHA512_CBLOCK), SHA256_DIGEST_LENGTH, SHA2_FLAGS));
end;


function sha512_224_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (sha512_224_init(ctx)>0) );
end;


function sha512_224_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA512_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure sha512_224_freectx( vctx : Pointer);
var
  ctx : PSHA512_CTX;
begin
   ctx := PSHA512_CTX ( vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sha512_224_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSHA512_CTX;
begin
   _in := PSHA512_CTX ( ctx);
   if ossl_prov_is_running()  then
         ret := OPENSSL_malloc(sizeof( ret^))
   else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;


function sha512_224_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
     if (ossl_prov_is_running)  and ( outsz >= SHA224_DIGEST_LENGTH)  and  (_SHA512_Final(_out, ctx)>0) then
     begin
         outl^ := SHA224_DIGEST_LENGTH;
         Exit(1);
     end;
     result := 0;
end;


function sha512_224_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (16*8), 28, SHA2_FLAGS));
end;




function sha512_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := int( (ossl_prov_is_running)  and  (_SHA512_Init(ctx)>0) );
end;


function sha512_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA512_CTX;
begin
  if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure sha512_freectx( vctx : Pointer);
var
  ctx : PSHA512_CTX;
begin
   ctx := PSHA512_CTX ( vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sha512_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSHA512_CTX;
begin
   _in := PSHA512_CTX ( ctx);
   if ossl_prov_is_running()  then
       ret := OPENSSL_malloc(sizeof( ret^))
    else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;


function sha512_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
     if (ossl_prov_is_running)  and  (outsz >= SHA512_DIGEST_LENGTH)  and  (_SHA512_Final(_out, ctx)>0) then
     begin
         outl^ := SHA512_DIGEST_LENGTH;
         Exit(1);
     end;
     result := 0;
end;


function sha512_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (16*8), 64, $0002));
end;

function sha384_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := Int( (ossl_prov_is_running)  and  (_SHA384_Init(ctx)>0) );
end;


function sha384_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA512_CTX;
begin
  if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;


procedure sha384_freectx( vctx : Pointer);
var
  ctx : PSHA512_CTX;
begin
  ctx := PSHA512_CTX (vctx);
  OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sha384_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSHA512_CTX;
begin
   _in := PSHA512_CTX (ctx);
   if ossl_prov_is_running()  then
       ret := OPENSSL_malloc(sizeof( ret^))
    else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;


function sha384_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
     if (ossl_prov_is_running) and  (outsz >= SHA384_DIGEST_LENGTH)  and  (_SHA384_Final(_out, ctx)>0) then
     begin
         outl^ := SHA384_DIGEST_LENGTH;
         Exit(1);
     end;
     result := 0;
end;


function sha384_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (16*8), 48, $0002));
end;


function sha256_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   result := Int( (ossl_prov_is_running)  and  (_SHA256_Init(ctx)>0));
end;





function sha256_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, (16*4), 32, $0002));
end;





function sha256_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSHA256_CTX;
begin
   _in := PSHA256_CTX( ctx);
  if ossl_prov_is_running()  then
       ret := OPENSSL_malloc(sizeof( ret^))
    else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;

procedure sha256_freectx( vctx : Pointer);
var
  ctx : PSHA256_CTX;
begin
   ctx := PSHA256_CTX( vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;

function sha256_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= SHA256_DIGEST_LENGTH)  and  (_SHA256_Final(_out, ctx)>0)  then
   begin
       outl^ := SHA256_DIGEST_LENGTH;
       Exit(1);
   end;
   result := 0;
end;





function sha256_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA256_CTX;
begin
  if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;

function sha224_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
   Result := Int( (ossl_prov_is_running)  and  (_SHA224_Init(ctx)>0));
end;

function sha224_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, (16*4), 28, $0002));
end;

function sha224_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PSHA256_CTX;
begin
   _in := PSHA256_CTX( ctx);
  if ossl_prov_is_running()  then
       ret := OPENSSL_malloc(sizeof( ret^))
    else
       ret := nil;
    if ret <> nil then
      ret^ := _in^;
    result := ret;
end;

procedure sha224_freectx( vctx : Pointer);
var
  ctx : PSHA256_CTX;
begin
   ctx := PSHA256_CTX( vctx);
   OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function sha224_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= SHA224_DIGEST_LENGTH)  and  (_SHA224_Final(_out, ctx)>0)  then
   begin
      outl^ := SHA224_DIGEST_LENGTH;
       Exit(1);
   end;
   Result := 0;
end;

function sha224_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA256_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;

function sha1_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;

  ctx : PSHA_CTX;
begin
    ctx := PSHA_CTX ( vctx);
    if ctx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS);
    if (p <> nil)  and  (p.data_type = OSSL_PARAM_OCTET_STRING) then
       Exit(ossl_sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET,
                              p.data_size, p.data));
    Result := 1;
end;


var
  known_sha1_settable_ctx_params: array[0..1] of TOSSL_PARAM ;

function sha1_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_sha1_settable_ctx_params;
end;

function sha1_get_params( params : POSSL_PARAM):integer;
begin
    Result := ossl_digest_default_get_params(params, (16*4), 20, $0002);
end;

procedure sha1_freectx( ctx : PSHA_CTX);
begin
    ctx^ := Default(TSHA_CTX);
    ctx := nil;
    Free(ctx);
    //OPENSSL_clear_free(ctx,  sizeof( ctx^));
end;


procedure sha1_dupctx(const sctx : PSHA_CTX; var dctx:PSHA_CTX);
begin
    if ossl_prov_is_running()  then
       dctx := AllocMem(SizeOf(TSHA_CTX))
    else
       dctx := nil;
    if dctx <> nil then
      move(sctx^, dctx^, SizeOf(dctx^));

end;



function sha1_internal_final( ctx : Pointer; _out : PByte; outl : Psize_t; outsz : size_t):integer;
begin
   if (ossl_prov_is_running)  and  (outsz >= SHA_DIGEST_LENGTH)  and  (_SHA1_Final(_out, ctx)>0) then
   begin
       outl^ := SHA_DIGEST_LENGTH;
       Exit(1);
   end;
   Result := 0;
end;


function sha1_internal_init(ctx : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := int( (ossl_prov_is_running)
            and  (_SHA1_init(ctx)>0)
            and  (sha1_set_ctx_params(ctx, params)>0));
end;





function sha1_newctx( prov_ctx : Pointer):Pointer;
var
  ctx : PSHA_CTX;
begin
    if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof( ctx^))
    else
       ctx := nil;
    Result := ctx;
end;

initialization
  known_sha1_settable_ctx_params[0].key := OSSL_DIGEST_PARAM_SSL3_MS;
  known_sha1_settable_ctx_params[0].data_type := OSSL_PARAM_OCTET_STRING;
  known_sha1_settable_ctx_params[0].data := nil;
  known_sha1_settable_ctx_params[0].data_size := 0;
  known_sha1_settable_ctx_params[0].return_size :=  0;
  known_sha1_settable_ctx_params[1] := OSSL_PARAM_END;

end.
