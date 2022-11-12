unit OpenSSL3.providers.implementations.ciphers.cipher_aes_xts;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;


  function aes_256_xts_get_params( params : POSSL_PARAM):integer;
  function aes_256_xts_newctx( provctx : Pointer):Pointer;
  function aes_128_xts_get_params( params : POSSL_PARAM):integer;
  function aes_128_xts_newctx( provctx : Pointer):Pointer;
  function aes_xts_check_keys_differ(const key : PByte; bytes : size_t; enc : integer):integer;
  function aes_xts_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
  function aes_xts_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_xts_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_xts_newctx( provctx : Pointer; mode : uint32; flags : uint64; kbits, blkbits, ivbits : size_t):Pointer;
  procedure aes_xts_freectx( vctx : Pointer);
  function aes_xts_dupctx( vctx : Pointer):Pointer;
  function aes_xts_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function aes_xts_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function aes_xts_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
  function aes_xts_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
  function aes_xts_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;

const  ossl_aes256xts_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_256_xts_newctx; data:nil)),
(function_id:  2; method:(code:@aes_xts_einit; data:nil)),
(function_id:  3; method:(code:@aes_xts_dinit; data:nil)),
(function_id:  4; method:(code:@aes_xts_stream_update; data:nil)),
(function_id:  5; method:(code:@aes_xts_stream_final; data:nil)),
(function_id:  6; method:(code:@aes_xts_cipher; data:nil)),
(function_id:  7; method:(code:@aes_xts_freectx; data:nil)),
(function_id:  8; method:(code:@aes_xts_dupctx; data:nil)),
(function_id:  9; method:(code:@aes_256_xts_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_xts_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@aes_xts_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes128xts_functions: array[0..14] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_128_xts_newctx; data:nil)),
(function_id:  2; method:(code:@aes_xts_einit; data:nil)),
(function_id:  3; method:(code:@aes_xts_dinit; data:nil)),
(function_id:  4; method:(code:@aes_xts_stream_update; data:nil)),
(function_id:  5; method:(code:@aes_xts_stream_final; data:nil)),
(function_id:  6; method:(code:@aes_xts_cipher; data:nil)),
(function_id:  7; method:(code:@aes_xts_freectx; data:nil)),
(function_id:  8; method:(code:@aes_xts_dupctx; data:nil)),
(function_id:  9; method:(code:@aes_128_xts_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_xts_set_ctx_params; data:nil)),
(function_id:  14; method:(code:@aes_xts_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );


var // 1d arrays
  aes_xts_known_settable_ctx_params : array of TOSSL_PARAM;

implementation
uses openssl3.crypto.cpuid, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.providers.fips.self_test,  openssl3.crypto.modes.xts128,
     openssl3.crypto.params,             OpenSSL3.openssl.params,
     OpenSSL3.providers.implementations.ciphers.cipher_aes_xts_hw;

function aes_xts_check_keys_differ(const key : PByte; bytes : size_t; enc : integer):integer;
begin
    if ( (0>=ossl_aes_xts_allow_insecure_decrypt)  or  (enc > 0) )  and
       ( CRYPTO_memcmp(key, key + bytes, bytes) = 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_XTS_DUPLICATED_KEYS);
        Exit(0);
    end;
    Result := 1;
end;


function aes_xts_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
  xctx : PPROV_AES_XTS_CTX;
  ctx : PPROV_CIPHER_CTX;
begin
    xctx := PPROV_AES_XTS_CTX (vctx);
    ctx := @xctx.base;
    if not ossl_prov_is_running then Exit(0);
    ctx.enc := enc;
    if iv <> nil then begin
        if 0>=ossl_cipher_generic_initiv(vctx, iv, ivlen) then
            Exit(0);
    end;
    if key <> nil then
    begin
        if keylen <> ctx.keylen then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>=aes_xts_check_keys_differ(key, keylen div 2, enc) then
            Exit(0);
        if 0>=ctx.hw.init(ctx, key, keylen) then
            Exit(0);
    end;
    Result := aes_xts_set_ctx_params(ctx, params);
end;


function aes_xts_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := aes_xts_init(vctx, key, keylen, iv, ivlen, params, 1);
end;


function aes_xts_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := aes_xts_init(vctx, key, keylen, iv, ivlen, params, 0);
end;


function aes_xts_newctx( provctx : Pointer; mode : uint32; flags : uint64; kbits, blkbits, ivbits : size_t):Pointer;
var
  ctx : PPROV_AES_XTS_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
    begin
        ossl_cipher_generic_initkey(@ctx.base, kbits, blkbits, ivbits, mode,
                                    flags, ossl_prov_cipher_hw_aes_xts(kbits),
                                    nil);
    end;
    Result := ctx;
end;


procedure aes_xts_freectx( vctx : Pointer);
var
  ctx : PPROV_AES_XTS_CTX;
begin
    ctx := PPROV_AES_XTS_CTX (vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX (vctx));
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function aes_xts_dupctx( vctx : Pointer):Pointer;
var
  _in, ret : PPROV_AES_XTS_CTX;
begin
    _in := PPROV_AES_XTS_CTX (vctx);
    ret := nil;
    if not ossl_prov_is_running then Exit(nil);
    if _in.xts.key1 <> nil then
    begin
        if _in.xts.key1 <> @_in.ks1 then
            Exit(nil);
    end;
    if _in.xts.key2 <> nil then
    begin
        if _in.xts.key2 <> @_in.ks2 then
            Exit(nil);
    end;
    ret := OPENSSL_malloc(sizeof( ret^));
    if ret = nil then begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    _in.base.hw.copyctx(@ret.base, @_in.base);
    Result := ret;
end;


function aes_xts_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_AES_XTS_CTX;
begin
    ctx := PPROV_AES_XTS_CTX (vctx);
    if (not ossl_prov_is_running)
             or  (ctx.xts.key1 = nil)
             or  (ctx.xts.key2 = nil)
             or  (0>=ctx.base.iv_set)
             or  (_out = nil)
             or  (_in = nil)
             or  (inl < AES_BLOCK_SIZE) then Exit(0);
    {
     * Impose a limit of 2^20 blocks per data unit as specified by
     * IEEE Std 1619-2018.  The earlier and obsolete IEEE Std 1619-2007
     * indicated that this was a SHOULD NOT rather than a MUST NOT.
     * NIST SP 800-38E mandates the same limit.
     }
    if inl > XTS_MAX_BLOCKS_PER_DATA_UNIT * AES_BLOCK_SIZE then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE);
        Exit(0);
    end;
    if Assigned(ctx.stream) then
       ctx.stream(_in, _out, inl, ctx.xts.key1, ctx.xts.key2, @ctx.base.iv)
    else
    if (CRYPTO_xts128_encrypt(@ctx.xts, @ctx.base.iv, _in, _out, inl,
                                   ctx.base.enc) > 0 ) then
        Exit(0);
    outl^ := inl;
    Result := 1;
end;


function aes_xts_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_AES_XTS_CTX;
begin
    ctx := PPROV_AES_XTS_CTX (vctx);
    if outsize < inl then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>=aes_xts_cipher(ctx, _out, outl, outsize, _in, inl) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    Result := 1;
end;


function aes_xts_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
begin
    if not ossl_prov_is_running then Exit(0);
    outl^ := 0;
    Result := 1;
end;


function aes_xts_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @aes_xts_known_settable_ctx_params[0];
end;


function aes_xts_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p : POSSL_PARAM;
  keylen : size_t;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if p <> nil then
    begin
        if 0>=OSSL_PARAM_get_size_t(p, @keylen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        { The key length can not be modified for xts mode }
        if keylen <> ctx.keylen then Exit(0);
    end;
    Result := 1;
end;



function aes_256_xts_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10001, $0002, 2 * 256, 8, 128));
end;


function aes_256_xts_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_xts_newctx(provctx, $10001, $0002, 2 * 256, 8, 128));
end;


function aes_128_xts_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10001, $0002, 2 * 128, 8, 128));
end;


function aes_128_xts_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_xts_newctx(provctx, $10001, $0002, 2 * 128, 8, 128));
end;

initialization
   aes_xts_known_settable_ctx_params := [
     _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil), OSSL_PARAM_END ];

end.
