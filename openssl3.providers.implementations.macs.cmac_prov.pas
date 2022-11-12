unit openssl3.providers.implementations.macs.cmac_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;

  function cmac_new( provctx : Pointer):Pointer;
  procedure cmac_free( vmacctx : Pointer);
  function cmac_dup( vsrc : Pointer):Pointer;
  function cmac_size( vmacctx : Pointer):size_t;
  function cmac_setkey(macctx : Pcmac_data_st;const key : PByte; keylen : size_t):integer;
  function cmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function cmac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function cmac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function cmac_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function cmac_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
  function cmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function cmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;

const ossl_cmac_functions: array[0..10] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@cmac_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@cmac_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@cmac_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@cmac_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@cmac_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@cmac_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS;
      method:(code:@cmac_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_CTX_PARAMS; method:(code:@cmac_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@cmac_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@cmac_set_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);


implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.cmac.cmac,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;

var
  known_gettable_ctx_params: array[0..2] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..3] of TOSSL_PARAM ;

function cmac_new( provctx : Pointer):Pointer;
var
  macctx : Pcmac_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    macctx := OPENSSL_zalloc(sizeof( macctx^) );
    macctx.ctx := CMAC_CTX_new();
    if (macctx = nil)or  (macctx.ctx = nil) then
    begin
        OPENSSL_free(Pointer(macctx));
        macctx := nil;
    end
    else
    begin
        macctx.provctx := provctx;
    end;
    Result := macctx;
end;


procedure cmac_free( vmacctx : Pointer);
var
  macctx : Pcmac_data_st;
begin
    macctx := vmacctx;
    if macctx <> nil then
    begin
        CMAC_CTX_free(macctx.ctx);
        ossl_prov_cipher_reset(@macctx.cipher);
        OPENSSL_free(Pointer(macctx));
    end;
end;


function cmac_dup( vsrc : Pointer):Pointer;
var
  src, dst : Pcmac_data_st;
begin
    src := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    dst := cmac_new(src.provctx);
    if dst = nil then Exit(nil);
    if (0>= CMAC_CTX_copy(dst.ctx, src.ctx))  or
       (0>= ossl_prov_cipher_copy(@dst.cipher, @src.cipher))  then
    begin
        cmac_free(dst);
        Exit(nil);
    end;
    Result := dst;
end;


function cmac_size( vmacctx : Pointer):size_t;
var
  macctx : Pcmac_data_st;
begin
    macctx := vmacctx;
    Result := EVP_CIPHER_CTX_get_block_size(CMAC_CTX_get0_cipher_ctx(macctx.ctx));
end;


function cmac_setkey(macctx : Pcmac_data_st;const key : PByte; keylen : size_t):integer;
var
  rv : integer;
begin
    rv := _CMAC_Init(macctx.ctx, key, keylen,
                       ossl_prov_cipher_cipher(@macctx.cipher),
                       ossl_prov_cipher_engine(@macctx.cipher));
    ossl_prov_cipher_reset(@macctx.cipher);
    Result := rv;
end;


function cmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  macctx : Pcmac_data_st;
begin
    macctx := vmacctx;
    if (not ossl_prov_is_running)  or  (0>= cmac_set_ctx_params(macctx, params)) then
        Exit(0);
    if key <> nil then Exit(cmac_setkey(macctx, key, keylen));
    Result := 1;
end;


function cmac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  macctx : Pcmac_data_st;
begin
    macctx := vmacctx;
    Result := CMAC_Update(macctx.ctx, data, datalen);
end;


function cmac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  macctx : Pcmac_data_st;
begin
    macctx := vmacctx;
    if not ossl_prov_is_running then
        Exit(0);
    Result := _CMAC_Final(macctx.ctx, out, outl);
end;


function cmac_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function cmac_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if  (p  <> nil)
             and  (0>= OSSL_PARAM_set_size_t(p, cmac_size(vmacctx))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (p  <> nil)
             and  (0>= OSSL_PARAM_set_size_t(p, cmac_size(vmacctx))) then
        Exit(0);
    Result := 1;
end;


function cmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;


function cmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  macctx : Pcmac_data_st;
  ctx : POSSL_LIB_CTX;
  p : POSSL_PARAM;
begin
    macctx := vmacctx;
    ctx := PROV_LIBCTX_OF(macctx.provctx);
    if params = nil then Exit(1);
    if 0>= ossl_prov_cipher_load_from_params(@macctx.cipher, params, ctx) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY );
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
            Exit(0);
        Exit(cmac_setkey(macctx, p.data, p.data_size));
    end;
    Result := 1;
end;

initialization

    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, nil);
    known_gettable_ctx_params[2] := OSSL_PARAM_END;


    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
    known_settable_ctx_params[3] := OSSL_PARAM_END;

end.
