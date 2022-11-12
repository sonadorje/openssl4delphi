unit openssl3.providers.implementations.macs.gmac_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;

  procedure gmac_free( vmacctx : Pointer);
  function gmac_new( provctx : Pointer):Pointer;
  function gmac_dup( vsrc : Pointer):Pointer;
  function gmac_size:size_t;
  function gmac_setkey(macctx : Pgmac_data_st;const key : PByte; keylen : size_t):integer;
  function gmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function gmac_update(vmacctx : Pointer; data : PByte; datalen : size_t):integer;
  function gmac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function gmac_gettable_params( provctx : Pointer):POSSL_PARAM;
  function gmac_get_params( params : POSSL_PARAM):integer;
  function gmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function gmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;

const ossl_gmac_functions: array[0..10] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@gmac_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@gmac_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@gmac_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@gmac_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@gmac_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@gmac_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_PARAMS; method:(code:@gmac_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_PARAMS; method:(code:@gmac_get_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@gmac_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@gmac_set_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);



implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.cmac.cmac,
     openssl3.crypto.evp.evp_enc,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;

var
  known_gettable_ctx_params: array[0..1] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..4] of TOSSL_PARAM ;









procedure gmac_free( vmacctx : Pointer);
var
  macctx : Pgmac_data_st;
begin
    macctx := vmacctx;
    if macctx <> nil then
    begin
        EVP_CIPHER_CTX_free(macctx.ctx);
        ossl_prov_cipher_reset(@macctx.cipher);
        OPENSSL_free(Pointer(macctx));
    end;
end;


function gmac_new( provctx : Pointer):Pointer;
var
  macctx : Pgmac_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    macctx := OPENSSL_zalloc(sizeof( macctx^));
    macctx.ctx := EVP_CIPHER_CTX_new();
    if (macctx = nil) or  (macctx.ctx = nil) then
    begin
        gmac_free(macctx);
        Exit(nil);
    end;
    macctx.provctx := provctx;
    Result := macctx;
end;


function gmac_dup( vsrc : Pointer):Pointer;
var
  src, dst : Pgmac_data_st;
begin
    src := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    dst := gmac_new(src.provctx);
    if dst = nil then Exit(nil);
    if (0>= EVP_CIPHER_CTX_copy(dst.ctx, src.ctx)) or
       (0>= ossl_prov_cipher_copy(@dst.cipher, @src.cipher)) then
    begin
        gmac_free(dst);
        Exit(nil);
    end;
    Result := dst;
end;


function gmac_size:size_t;
begin
    Result := EVP_GCM_TLS_TAG_LEN;
end;


function gmac_setkey(macctx : Pgmac_data_st;const key : PByte; keylen : size_t):integer;
var
  ctx : PEVP_CIPHER_CTX;
begin
    ctx := macctx.ctx;
    if keylen <> size_t( EVP_CIPHER_CTX_get_key_length(ctx)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    if 0>= EVP_EncryptInit_ex(ctx, nil, nil, key, nil) then
        Exit(0);
    Result := 1;
end;


function gmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  macctx : Pgmac_data_st;
begin
    macctx := vmacctx;
    if (not ossl_prov_is_running)  or  (0>= gmac_set_ctx_params(macctx, params))  then
        Exit(0);
    if key <> nil then
       Exit(gmac_setkey(macctx, key, keylen));
    Result := 1;
end;


function gmac_update(vmacctx : Pointer; data : PByte; datalen : size_t):integer;
var
  macctx : Pgmac_data_st;

  ctx : PEVP_CIPHER_CTX;

  outlen : integer;
begin
    macctx := vmacctx;
    ctx := macctx.ctx;
    if datalen = 0 then Exit(1);
    while datalen > INT_MAX do
    begin
        if 0>= EVP_EncryptUpdate(ctx, nil, @outlen, data, INT_MAX) then
            Exit(0);
        data  := data + INT_MAX;
        datalen  := datalen - INT_MAX;
    end;
    Result := EVP_EncryptUpdate(ctx, nil, @outlen, data, datalen);
end;


function gmac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  params : array[0..1] of TOSSL_PARAM;

  macctx : Pgmac_data_st;

  hlen : integer;
begin
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;

    macctx := vmacctx;
    hlen := 0;
    if not ossl_prov_is_running then
        Exit(0);
    if 0>= EVP_EncryptFinal_ex(macctx.ctx, &out, @hlen) then
        Exit(0);
    hlen := gmac_size();
    params[0] := OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  &out, size_t( hlen));
    if 0>= EVP_CIPHER_CTX_get_params(macctx.ctx, @params) then
        Exit(0);
    outl^ := hlen;
    Result := 1;
end;


function gmac_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function gmac_get_params( params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, gmac_size()));
    Result := 1;
end;


function gmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;


function gmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  macctx : Pgmac_data_st;

  ctx : PEVP_CIPHER_CTX;
  p : POSSL_PARAM;
  provctx : POSSL_LIB_CTX;
begin
    macctx := vmacctx;
    ctx := macctx.ctx;
    provctx := PROV_LIBCTX_OF(macctx.provctx);
    if params = nil then Exit(1);
    if (ctx = nil)
         or  (0>= ossl_prov_cipher_load_from_params(@macctx.cipher, params, provctx)) then
        Exit(0);
    if EVP_CIPHER_get_mode(ossl_prov_cipher_cipher(@macctx.cipher))
        <> EVP_CIPH_GCM_MODE then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        Exit(0);
    end;
    if 0>= EVP_EncryptInit_ex(ctx, ossl_prov_cipher_cipher(@macctx.cipher) ,
                            ossl_prov_cipher_engine(@macctx.cipher), nil,
                            nil)  then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY );
    if p <> nil then
        if (p.data_type <> OSSL_PARAM_OCTET_STRING )
                 or  (0>= gmac_setkey(macctx, p.data, p.data_size)) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_IV );
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
            Exit(0);
        if (0>= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 p.data_size, nil)) or
           (0>= EVP_EncryptInit_ex(ctx, nil, nil, nil, p.data))then
            Exit(0);
    end;
    Result := 1;
end;

initialization

    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, Nil);
    known_gettable_ctx_params[1] := OSSL_PARAM_END;


    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_IV, nil, 0);
    known_settable_ctx_params[4] := OSSL_PARAM_END;

end.
