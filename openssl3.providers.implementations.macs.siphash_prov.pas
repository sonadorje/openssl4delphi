unit openssl3.providers.implementations.macs.siphash_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;



  function crounds( ctx : Psiphash_data_st):uint32;
  function drounds( ctx : Psiphash_data_st):uint32;
  function siphash_new( provctx : Pointer):Pointer;
  procedure siphash_free( vmacctx : Pointer);
  function siphash_dup( vsrc : Pointer):Pointer;
  function siphash_size( vmacctx : Pointer):size_t;
  function siphash_setkey(ctx : Psiphash_data_st;const key : PByte; keylen : size_t):integer;
  function siphash_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function siphash_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function siphash_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function siphash_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function siphash_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
  function siphash_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function siphash_set_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;




const ossl_siphash_functions: array[0..10] of TOSSL_DISPATCH  = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@siphash_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@siphash_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@siphash_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@siphash_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@siphash_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@siphash_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS;
      method:(code:@siphash_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_CTX_PARAMS; method:(code:@siphash_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@siphash_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@siphash_set_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.cmac.cmac,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.mem_sec,
     OpenSSL.ssl.s3_cbc, openssl3.crypto.hmac.hmac, OpenSSL3.common,
     openssl3.crypto.siphash.siphash,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;


function crounds( ctx : Psiphash_data_st):uint32;
begin
    Result := get_result( ctx.crounds <> 0 , ctx.crounds , SIPHASH_C_ROUNDS);
end;


function drounds( ctx : Psiphash_data_st):uint32;
begin
    Result := get_result( ctx.drounds <> 0 , ctx.drounds , SIPHASH_D_ROUNDS);
end;


function siphash_new( provctx : Pointer):Pointer;
var
  ctx : Psiphash_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then ctx.provctx := provctx;
    Result := ctx;
end;


procedure siphash_free( vmacctx : Pointer);
begin
    OPENSSL_free(vmacctx);
end;


function siphash_dup( vsrc : Pointer):Pointer;
var
  ssrc, sdst : Psiphash_data_st;
begin
    ssrc := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    sdst := siphash_new(ssrc.provctx);
    if sdst = nil then Exit(nil);
    sdst.siphash := ssrc.siphash;
    Result := sdst;
end;


function siphash_size( vmacctx : Pointer):size_t;
var
  ctx : Psiphash_data_st;
begin
    ctx := vmacctx;
    Result := SipHash_hash_size(@ctx.siphash);
end;


function siphash_setkey(ctx : Psiphash_data_st;const key : PByte; keylen : size_t):integer;
begin
    if keylen <> SIPHASH_KEY_SIZE then Exit(0);
    Result := _SipHash_Init(@ctx.siphash, key, crounds(ctx), drounds(ctx));
end;


function siphash_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : Psiphash_data_st;
begin
    ctx := vmacctx;
    if (not ossl_prov_is_running) or  (0>= siphash_set_params(ctx, params))  then
        Exit(0);
    { Without a key, there is not much to do here,
     * The actual initialization happens through controls.
     }
    if key = nil then Exit(1);
    Result := siphash_setkey(ctx, key, keylen);
end;


function siphash_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  ctx : Psiphash_data_st;
begin
    ctx := vmacctx;
    if datalen = 0 then Exit(1);
    SipHash_Update(@ctx.siphash, data, datalen);
    Result := 1;
end;


function siphash_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : Psiphash_data_st;

  hlen : size_t;
begin
    ctx := vmacctx;
    hlen := siphash_size(ctx);
    if (not ossl_prov_is_running)  or  (outsize < hlen) then
        Exit(0);
    outl^ := hlen;
    Result := _SipHash_Final(@ctx.siphash, out, hlen);
end;


function siphash_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
var
  known_gettable_ctx_params : array[0..3] of TOSSL_PARAM;
begin

    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := _OSSL_PARAM_uint(OSSL_MAC_PARAM_C_ROUNDS, nil);
    known_gettable_ctx_params[2] := _OSSL_PARAM_uint(OSSL_MAC_PARAM_D_ROUNDS, nil);
    known_gettable_ctx_params[3] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;


function siphash_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : Psiphash_data_st;

  p : POSSL_PARAM;
begin
    ctx := vmacctx;
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE );
    if (p  <> nil )
         and  (0>= OSSL_PARAM_set_size_t(p, siphash_size(vmacctx))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_C_ROUNDS );
    if (p  <> nil)
         and  (0>= OSSL_PARAM_set_uint(p, crounds(ctx))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_D_ROUNDS );
    if (p  <> nil)
         and  (0>= OSSL_PARAM_set_uint(p, drounds(ctx))) then
        Exit(0);
    Result := 1;
end;


function siphash_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
var
  known_settable_ctx_params : array[0..4] of TOSSL_PARAM;
begin

    known_settable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
    known_settable_ctx_params[1] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_uint(OSSL_MAC_PARAM_C_ROUNDS, nil);
    known_settable_ctx_params[3] := _OSSL_PARAM_uint(OSSL_MAC_PARAM_D_ROUNDS, nil);
    known_settable_ctx_params[4] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;


function siphash_set_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : Psiphash_data_st;

  p : POSSL_PARAM;

  size : size_t;
begin
    ctx := vmacctx;
     p := nil;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE );
    if (p <> nil) then
    begin
        if (0>= OSSL_PARAM_get_size_t(p, @size))
             or  (0>= SipHash_set_hash_size(@ctx.siphash, size)) then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_C_ROUNDS);
    if (p  <> nil)
             and  (0>= OSSL_PARAM_get_uint(p, @ctx.crounds)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_D_ROUNDS );
    if (p  <> nil)
             and  (0>= OSSL_PARAM_get_uint(p, @ctx.drounds)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY );
    if (p <> nil) then
        if (p.data_type <> OSSL_PARAM_OCTET_STRING )
             or  (0>= siphash_setkey(ctx, p.data, p.data_size)) then
            Exit(0);
    Result := 1;
end;



end.
