unit openssl3.providers.implementations.digests.sha3_prov;

interface
uses OpenSSL.Api, openssl3.crypto.sha.sha_local,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.sha.sha256,
     openssl3.crypto.sha.sha512,
     openssl3.crypto.sha.sha1dgst;
const
  SHA2_FLAGS = PROV_DIGEST_FLAG_ALGID_ABSENT;

 function sha3_224_newctx( provctx : Pointer):Pointer;
 function sha3_224_get_params( params : POSSL_PARAM):integer;
 function keccak_update(vctx : Pointer; inp : PByte; len : size_t):integer;
 function keccak_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
  function generic_sha3_absorb(vctx : Pointer;const inp : Pointer; len : size_t):size_t;
  function generic_sha3_final( md : PByte; vctx : Pointer):integer;
  procedure keccak_freectx( vctx : Pointer);
  function keccak_dupctx( ctx : Pointer):Pointer;
  function keccak_init(vctx : Pointer;const params : POSSL_PARAM):integer;
  function keccak_init_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function shake_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function sha3_256_newctx( provctx : Pointer):Pointer;
  function sha3_256_get_params( params : POSSL_PARAM):integer;
  function sha3_384_newctx( provctx : Pointer):Pointer;
  function sha3_384_get_params( params : POSSL_PARAM):integer;
  function sha3_512_newctx( provctx : Pointer):Pointer;
  function sha3_512_get_params( params : POSSL_PARAM):integer;

  function keccak_224_newctx( provctx : Pointer):Pointer;
  function keccak_224_get_params( params : POSSL_PARAM):integer;
  function keccak_256_newctx( provctx : Pointer):Pointer;
  function keccak_256_get_params( params : POSSL_PARAM):integer;
  function keccak_384_newctx( provctx : Pointer):Pointer;
  function keccak_384_get_params( params : POSSL_PARAM):integer;
  function keccak_512_newctx( provctx : Pointer):Pointer;
  function keccak_512_get_params( params : POSSL_PARAM):integer;
  function keccak_kmac_128_newctx( provctx : Pointer):Pointer;
  function keccak_kmac_128_get_params( params : POSSL_PARAM):integer;
  function shake_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function keccak_kmac_256_newctx( provctx : Pointer):Pointer;
  function keccak_kmac_256_get_params( params : POSSL_PARAM):integer;
  function shake_128_newctx( provctx : Pointer):Pointer;
  function shake_128_get_params( params : POSSL_PARAM):integer;
  function shake_256_newctx( provctx : Pointer):Pointer;
  function shake_256_get_params( params : POSSL_PARAM):integer;

 const ossl_sha3_224_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha3_224_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha3_224_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 ossl_sha3_256_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha3_256_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha3_256_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)  )
 );

 const ossl_sha3_384_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha3_384_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha3_384_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 const ossl_sha3_512_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@sha3_512_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@sha3_512_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 ossl_keccak_224_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@keccak_224_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@keccak_224_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 const ossl_keccak_256_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@keccak_256_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@keccak_256_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 const ossl_keccak_384_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@keccak_384_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@keccak_384_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 const ossl_keccak_512_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@keccak_512_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@keccak_512_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 const ossl_keccak_kmac_128_functions: array[0..10] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@keccak_kmac_128_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@keccak_kmac_128_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init_params; data:nil)),
 (function_id:  9; method:(code:@shake_set_ctx_params; data:nil)),
 (function_id:  12; method:(code:@shake_settable_ctx_params; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) )
 );

 const ossl_keccak_kmac_256_functions: array[0..10] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@keccak_kmac_256_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@keccak_kmac_256_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init_params; data:nil)),
 (function_id:  9; method:(code:@shake_set_ctx_params; data:nil)),
 (function_id:  12; method:(code:@shake_settable_ctx_params; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) ));

 const ossl_shake_128_functions: array[0..10] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@shake_128_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@shake_128_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init_params; data:nil)),
 (function_id:  9; method:(code:@shake_set_ctx_params; data:nil)),
 (function_id:  12; method:(code:@shake_settable_ctx_params; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) ));

 const  ossl_shake_256_functions: array[0..10] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@shake_256_newctx; data:nil)),
 (function_id:  3; method:(code:@keccak_update; data:nil)),
 (function_id:  4; method:(code:@keccak_final; data:nil)),
 (function_id:  6; method:(code:@keccak_freectx; data:nil)),
 (function_id:  7; method:(code:@keccak_dupctx; data:nil)),
 (function_id:  8; method:(code:@shake_256_get_params; data:nil)),
 (function_id:  11; method:(code:@ossl_digest_default_gettable_params; data:nil)),
 (function_id:  2; method:(code:@keccak_init_params; data:nil)),
 (function_id:  9; method:(code:@shake_set_ctx_params; data:nil)),
 (function_id:  12; method:(code:@shake_settable_ctx_params; data:nil)),
 (function_id:  0; method:(code:nil; data:nil) ));


implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.crypto.sha.keccak1600,
      OpenSSL3.openssl.params;

const
  sha3_generic_md : TPROV_SHA3_METHOD = (
     absorb: generic_sha3_absorb;
     &final: generic_sha3_final );
var
 known_shake_settable_ctx_params: array[0..1] of TOSSL_PARAM;






function shake_128_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
  if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $1f, 128);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function shake_128_get_params( params : POSSL_PARAM):integer;
begin
  Exit(ossl_digest_default_get_params(params, (1600 - 128 * 2) div 8, (128 div 8), $0001));
end;


function shake_256_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $1f, 256);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function shake_256_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 256 * 2) div 8, (256 div 8), $0001));
end;

function keccak_kmac_256_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
    if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_keccak_kmac_init(ctx, $04, 256);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function keccak_kmac_256_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 256 * 2) div 8, 2 * (256 div  8), $0001));
end;




function shake_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_shake_settable_ctx_params;
end;



function keccak_kmac_128_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
    if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_keccak_kmac_init(ctx, $04, 128);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function keccak_kmac_128_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 128 * 2) div 8, 2 * (128 div 8), $0001));
end;

function keccak_512_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $01, 512);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function keccak_512_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, (1600 - 512 * 2) div 8, (512 div 8), $0002));
end;


function keccak_384_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $01, 384);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function keccak_384_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_digest_default_get_params(params, (1600 - 384 * 2) div 8, (384 div 8), $0002));
end;



function keccak_256_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
  if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $01, 256);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function keccak_256_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 256 * 2) div 8, (256 div 8), $0002));
end;





function keccak_224_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $01, 224);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function keccak_224_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 224 * 2) div 8, (224 div 8), $0002));
end;





function sha3_512_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
  if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $06, 512);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function sha3_512_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 512 * 2) div 8, (512 div 8), $0002));
end;



function sha3_384_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
   if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
    else
       ctx := nil;

   if (ctx = nil) then
       exit(nil);
   ossl_sha3_init(ctx, $06, 384);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function sha3_384_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 384 * 2) div 8, (384 div 8), $0002));
end;


function sha3_256_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
     if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
     else
       ctx := nil;

     if (ctx = nil) then
        exit(nil);
   ossl_sha3_init(ctx, $06, 256);
   ctx.meth := sha3_generic_md;
   Exit(ctx);
end;


function sha3_256_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 256 * 2) div 8, (256 div 8), $0002));
end;

function shake_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
  ctx : PKECCAK1600_CTX;
begin
    ctx := PKECCAK1600_CTX ( vctx);
    if ctx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_size_t(p, @ctx.md_size)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;




function keccak_init(vctx : Pointer;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running then
        Exit(0);
    { The newctx() handles most of the ctx fixed setup. }
    ossl_sha3_reset(PKECCAK1600_CTX ( vctx));
    Result := 1;
end;


function keccak_init_params(vctx : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := Int( (keccak_init(vctx, nil)>0)
             and  (shake_set_ctx_params(vctx, params)>0));
end;


procedure keccak_freectx( vctx : Pointer);
var
  ctx : PKECCAK1600_CTX;
begin
    ctx := PKECCAK1600_CTX ( vctx);
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function keccak_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PKECCAK1600_CTX;
begin
    _in := PKECCAK1600_CTX ( ctx);
    if ossl_prov_is_running then
      ret := OPENSSL_malloc(sizeof( ret^))
    else
      ret := nil;
    if ret <> nil then
       ret^ := _in^;
    Result := ret;
end;

function keccak_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsz : size_t):integer;
var
  ret : integer;

  ctx : PKECCAK1600_CTX;
begin
    ret := 1;
    ctx := vctx;
    if not ossl_prov_is_running then
        Exit(0);
    if outsz > 0 then
       ret := ctx.meth.final(out, ctx);
    outl^ := ctx.md_size;
    Result := ret;
end;


function generic_sha3_absorb(vctx : Pointer;const inp : Pointer; len : size_t):size_t;
var
  ctx : PKECCAK1600_CTX;
begin
    ctx := vctx;
    Result := SHA3_absorb(@ctx.A, inp, len, ctx.block_size);
end;


function generic_sha3_final( md : PByte; vctx : Pointer):integer;
begin
    Result := ossl_sha3_final(md, PKECCAK1600_CTX ( vctx));
end;





function keccak_update(vctx : Pointer;inp : PByte; len : size_t):integer;
var
  ctx : PKECCAK1600_CTX;

  bsz, num, rem : size_t;
begin
    ctx := vctx;
   bsz := ctx.block_size;
    if len = 0 then Exit(1);
    { Is there anything in the buffer already ? }
    num := ctx.bufsz;
    if num <> 0 then
    begin
        { Calculate how much space is left in the buffer }
        rem := bsz - num;
        { If the new input does not fill the buffer then just add it }
        if len < rem then
        begin
            memcpy(PByte(@ctx.buf) + num, inp, len);
            ctx.bufsz  := ctx.bufsz + len;
            Exit(1);
        end;
        { otherwise fill up the buffer and absorb the buffer }
        memcpy(PByte(@ctx.buf) + num, inp, rem);
        { Update the input pointer }
        inp  := inp + rem;
        len  := len - rem;
        ctx.meth.absorb(ctx, @ctx.buf, bsz);
        ctx.bufsz := 0;
    end;
    { Absorb the input - rem = leftover part of the input < blocksize) }
    rem := ctx.meth.absorb(ctx, inp, len);
    { Copy the leftover bit of the input into the buffer }
    if rem >0 then
    begin
        memcpy(@ctx.buf, inp + len - rem, rem);
        ctx.bufsz := rem;
    end;
    Result := 1;
end;

function sha3_224_newctx( provctx : Pointer):Pointer;
var
  ctx : PKECCAK1600_CTX;
begin
     if ossl_prov_is_running() then
       ctx := OPENSSL_zalloc(sizeof(ctx^))
     else
       ctx := nil;

     if (ctx = nil) then
        exit(nil);
    //ossl_sha3_init(ctx, pad, bitlen);
    ossl_sha3_init(ctx, $06, 224);
    ctx.meth := sha3_generic_md;
    Exit(ctx);
end;


function sha3_224_get_params( params : POSSL_PARAM):integer;
begin
   Exit(ossl_digest_default_get_params(params, (1600 - 224 * 2) div 8, (224 div 8), $0002));
end;


initialization
   known_shake_settable_ctx_params[0] := OSSL_PARAM_DEFN(OSSL_DIGEST_PARAM_XOFLEN, OSSL_PARAM_UNSIGNED_INTEGER, nil, 0, 0);
   known_shake_settable_ctx_params[1] := OSSL_PARAM_END;


end.
