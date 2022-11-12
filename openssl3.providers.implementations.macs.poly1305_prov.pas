unit openssl3.providers.implementations.macs.poly1305_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;

function poly1305_new( provctx : Pointer):Pointer;
  procedure poly1305_free( vmacctx : Pointer);
  function poly1305_dup( vsrc : Pointer):Pointer;
  function poly1305_size:size_t;
  function poly1305_setkey(ctx : Ppoly1305_data_st;const key : PByte; keylen : size_t):integer;
  function poly1305_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function poly1305_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function poly1305_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function poly1305_gettable_params( provctx : Pointer):POSSL_PARAM;
  function poly1305_get_params( params : POSSL_PARAM):integer;
  function poly1305_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function poly1305_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;

const  ossl_poly1305_functions: array[0..10] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@poly1305_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@poly1305_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@poly1305_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@poly1305_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@poly1305_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@poly1305_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_PARAMS; method:(code:@poly1305_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_PARAMS; method:(code:@poly1305_get_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@poly1305_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@poly1305_set_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.cmac.cmac,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.mem_sec,
     OpenSSL.ssl.s3_cbc, openssl3.crypto.hmac.hmac, OpenSSL3.common,
     openssl3.crypto.siphash.siphash, openssl3.crypto.poly1305.poly1305,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;



var // 1d arrays
  known_gettable_params, known_settable_ctx_params: array[0..1] of TOSSL_PARAM;


function poly1305_new( provctx : Pointer):Pointer;
var
  ctx : Ppoly1305_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then ctx.provctx := provctx;
    Result := ctx;
end;


procedure poly1305_free( vmacctx : Pointer);
begin
    OPENSSL_free(vmacctx);
end;


function poly1305_dup( vsrc : Pointer):Pointer;
var
  src, dst : Ppoly1305_data_st;
begin
    src := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    dst := poly1305_new(src.provctx);
    if dst = nil then Exit(nil);
    dst.poly1305 := src.poly1305;
    Result := dst;
end;


function poly1305_size:size_t;
begin
    Result := POLY1305_DIGEST_SIZE;
end;


function poly1305_setkey(ctx : Ppoly1305_data_st;const key : PByte; keylen : size_t):integer;
begin
    if keylen <> POLY1305_KEY_SIZE then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    _Poly1305_Init(@ctx.poly1305, key);
    Result := 1;
end;


function poly1305_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : Ppoly1305_data_st;
begin
    ctx := vmacctx;
    { initialize the context in MAC_ctrl function }
    if (not ossl_prov_is_running ) or  (0>= poly1305_set_ctx_params(ctx, params))then
        Exit(0);
    if key <> nil then Exit(poly1305_setkey(ctx, key, keylen));
    Result := 1;
end;


function poly1305_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  ctx : Ppoly1305_data_st;
begin
    ctx := vmacctx;
    if datalen = 0 then Exit(1);
    { poly1305 has nothing to return in its update function }
    _Poly1305_Update(@ctx.poly1305, data, datalen);
    Result := 1;
end;


function poly1305_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : Ppoly1305_data_st;
begin
    ctx := vmacctx;
    if not ossl_prov_is_running then
        Exit(0);
    _Poly1305_Final(@ctx.poly1305, &out);
    outl^ := poly1305_size();
    Result := 1;
end;


function poly1305_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_params;
end;


function poly1305_get_params( params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, poly1305_size()));
    Result := 1;
end;


function poly1305_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;


function poly1305_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : Ppoly1305_data_st;

  p : POSSL_PARAM;
begin
    ctx := vmacctx;
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY );
    if (p  <> nil)
             and  (0>= poly1305_setkey(ctx, p.data, p.data_size)) then
        Exit(0);
    Result := 1;
end;

initialization
  known_gettable_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
  known_gettable_params[1] := OSSL_PARAM_END ;

  known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
  known_settable_ctx_params[1] := OSSL_PARAM_END ;



end.
