unit openssl3.providers.implementations.macs.hmac_prov;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;

  function hmac_new( provctx : Pointer):Pointer;
  procedure hmac_free( vmacctx : Pointer);
  function hmac_dup( vsrc : Pointer):Pointer;
  function hmac_size( macctx : Phmac_data_st):size_t;
  function hmac_block_size( macctx : Phmac_data_st):integer;
  function hmac_setkey(macctx : Phmac_data_st;const key : PByte; keylen : size_t):integer;
  function hmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function hmac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function hmac_final( vmacctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
  function hmac_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function hmac_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
  function hmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function set_flag(const params : POSSL_PARAM; key : PUTF8Char; mask : integer; flags : PInteger):integer;
  function hmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;

const  ossl_hmac_functions: array[0..10] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@hmac_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@hmac_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@hmac_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@hmac_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@hmac_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@hmac_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS;
      method:(code:@hmac_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_CTX_PARAMS; method:(code:@hmac_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@hmac_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@hmac_set_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.cmac.cmac,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.mem_sec,
     OpenSSL.ssl.s3_cbc, openssl3.crypto.hmac.hmac,
     openssl3.crypto.evp,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;

var
  known_gettable_ctx_params: array[0..2] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..6] of TOSSL_PARAM ;





function hmac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  macctx : Phmac_data_st;

  ctx : POSSL_LIB_CTX;

  p : POSSL_PARAM;

  flags : integer;
begin
    macctx := vmacctx;
    ctx := PROV_LIBCTX_OF(macctx.provctx);
    flags := 0;
    if params = nil then Exit(1);
    if 0>= ossl_prov_digest_load_from_params(@macctx.digest, params, ctx) then
        Exit(0);
    if 0>= set_flag(params, OSSL_MAC_PARAM_DIGEST_NOINIT, EVP_MD_CTX_FLAG_NO_INIT,
                  @flags) then
        Exit(0);
    if 0>= set_flag(params, OSSL_MAC_PARAM_DIGEST_ONESHOT, EVP_MD_CTX_FLAG_ONESHOT,
                  @flags) then
        Exit(0);
    if flags > 0 then
       HMAC_CTX_set_flags(macctx.ctx, flags);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY );
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
            Exit(0);
        if macctx.keylen > 0 then
           OPENSSL_secure_clear_free(macctx.key, macctx.keylen);
        { Keep a copy of the key if we need it for TLS HMAC }
        macctx.key := OPENSSL_secure_malloc( get_result(p.data_size > 0 , p.data_size , 1));
        if macctx.key = nil then Exit(0);
        memcpy(macctx.key, p.data, p.data_size);
        macctx.keylen := p.data_size;
        if 0>= HMAC_Init_ex(macctx.ctx, p.data, p.data_size,
                          ossl_prov_digest_md(@macctx.digest) ,
                          nil ) then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_TLS_DATA_SIZE );
    if (p <> nil) then
    begin
        if 0>= OSSL_PARAM_get_size_t(p, @macctx.tls_data_size) then
            Exit(0);
    end;
    Result := 1;
end;

function hmac_new( provctx : Pointer):Pointer;
var
  macctx : Phmac_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    macctx := OPENSSL_zalloc(sizeof(macctx^));
    macctx.ctx := HMAC_CTX_new();
    if (macctx  = nil) or  (macctx.ctx = nil) then
    begin
        OPENSSL_free(Pointer(macctx));
        Exit(nil);
    end;
    macctx.provctx := provctx;
    Result := macctx;
end;


procedure hmac_free( vmacctx : Pointer);
var
  macctx : Phmac_data_st;
begin
    macctx := vmacctx;
    if macctx <> nil then begin
        HMAC_CTX_free(macctx.ctx);
        ossl_prov_digest_reset(@macctx.digest);
        OPENSSL_secure_clear_free(macctx.key, macctx.keylen);
        OPENSSL_free(Pointer(macctx));
    end;
end;


function hmac_dup( vsrc : Pointer):Pointer;
var
  src, dst : Phmac_data_st;

  ctx : PHMAC_CTX;
begin
    src := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    dst := hmac_new(src.provctx);
    if dst = nil then Exit(nil);
    ctx := dst.ctx;
    dst^ := src^;
    dst.ctx := ctx;
    dst.key := nil;
    if (0>= HMAC_CTX_copy(dst.ctx, src.ctx) ) or
       (0>= ossl_prov_digest_copy(@dst.digest, @src.digest)) then
    begin
        hmac_free(dst);
        Exit(nil);
    end;
    if src.key <> nil then
    begin
        { There is no 'secure' OPENSSL_memdup }
        dst.key := OPENSSL_secure_malloc(get_result( src.keylen > 0 , src.keylen , 1));
        if dst.key = nil then begin
            hmac_free(dst);
            Exit(0);
        end;
        memcpy(dst.key, src.key, src.keylen);
    end;
    Result := dst;
end;


function hmac_size( macctx : Phmac_data_st):size_t;
begin
    Result := _HMAC_size(macctx.ctx);
end;


function hmac_block_size( macctx : Phmac_data_st):integer;
var
  md : PEVP_MD;
begin
    md := ossl_prov_digest_md(@macctx.digest);
    if md = nil then Exit(0);
    Result := EVP_MD_block_size(md);
end;


function hmac_setkey(macctx : Phmac_data_st;const key : PByte; keylen : size_t):integer;
var
  digest : PEVP_MD;
begin
    if macctx.keylen > 0 then OPENSSL_secure_clear_free(macctx.key, macctx.keylen);
    { Keep a copy of the key in case we need it for TLS HMAC }
    macctx.key := OPENSSL_secure_malloc(get_result( keylen > 0 , keylen , 1));
    if macctx.key = nil then Exit(0);
    memcpy(macctx.key, key, keylen);
    macctx.keylen := keylen;
    digest := ossl_prov_digest_md(@macctx.digest);
    { HMAC_Init_ex doesn't tolerate all zero params, so we must be careful }
    if (key <> nil)  or  ( (macctx.tls_data_size = 0)  and  (digest <> nil) ) then
        Exit(HMAC_Init_ex(macctx.ctx, key, keylen, digest,
                            ossl_prov_digest_engine(@macctx.digest)));
    Result := 1;
end;


function hmac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  macctx : Phmac_data_st;
begin
    macctx := vmacctx;
    if (not ossl_prov_is_running)  or  (0>= hmac_set_ctx_params(macctx, params))  then
        Exit(0);
    if (key <> nil)  and  (0>= hmac_setkey(macctx, key, keylen)) then
        Exit(0);
    Result := 1;
end;


function hmac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  macctx : Phmac_data_st;
begin
    macctx := vmacctx;
    if macctx.tls_data_size > 0 then begin
        { We're doing a TLS HMAC }
        if 0>= macctx.tls_header_set then  begin
            { We expect the first update call to contain the TLS header }
            if datalen <> sizeof(macctx.tls_header) then
                Exit(0);
            memcpy(@macctx.tls_header, data, datalen);
            macctx.tls_header_set := 1;
            Exit(1);
        end;
        { macctx.tls_data_size is datalen plus the padding length }
        if macctx.tls_data_size < datalen then Exit(0);
        Exit(ssl3_cbc_digest_record(ossl_prov_digest_md(@macctx.digest),
                                      @macctx.tls_mac_out,
                                      @macctx.tls_mac_out_size,
                                      @macctx.tls_header,
                                      data,
                                      datalen,
                                      macctx.tls_data_size,
                                      macctx.key,
                                      macctx.keylen,
                                      0));
    end;
    Result := HMAC_Update(macctx.ctx, data, datalen);
end;


function hmac_final( vmacctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  hlen : uint32;

  macctx : Phmac_data_st;
begin
    macctx := vmacctx;
    if not ossl_prov_is_running then
        Exit(0);
    if macctx.tls_data_size > 0 then
    begin
        if macctx.tls_mac_out_size = 0 then
            Exit(0);
        if outl <> nil then
           outl^ := macctx.tls_mac_out_size;
        memcpy(@_out, @macctx.tls_mac_out, macctx.tls_mac_out_size);
        Exit(1);
    end;
    if 0>= _HMAC_Final(macctx.ctx, _out, @hlen) then
        Exit(0);
    outl^ := hlen;
    Result := 1;
end;


function hmac_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function hmac_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
var
  macctx : Phmac_data_st;

  p : POSSL_PARAM;
begin
    macctx := vmacctx;
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE );
    if (p  <> nil )
             and  (0>= OSSL_PARAM_set_size_t(p, hmac_size(macctx))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE );
    if (p  <> nil)
             and  (0>= OSSL_PARAM_set_int(p, hmac_block_size(macctx))) then
        Exit(0);
    Result := 1;
end;


function hmac_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;


function set_flag(const params : POSSL_PARAM; key : PUTF8Char; mask : integer; flags : PInteger):integer;
var
  p : POSSL_PARAM;

  flag : integer;
begin
    p := OSSL_PARAM_locate_const(params, key);
    flag := 0;
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_int(p, @flag) then
            Exit(0);
        if flag = 0 then
           flags^ := flags^ and (not mask)
        else
           flags^ := flags^  or mask;
    end;
    Result := 1;
end;



initialization

    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, nil);
    known_gettable_ctx_params[2] := OSSL_PARAM_END;

    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, nil);
    known_settable_ctx_params[4] := _OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, nil);
    known_settable_ctx_params[5] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, nil);
    known_settable_ctx_params[6] := OSSL_PARAM_END ;

end.
