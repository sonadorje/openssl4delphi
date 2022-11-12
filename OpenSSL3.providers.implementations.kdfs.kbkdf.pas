unit OpenSSL3.providers.implementations.kdfs.kbkdf;

interface
uses OpenSSL.Api, Math;

function kbkdf_new( provctx : Pointer):Pointer;
procedure kbkdf_free( vctx : Pointer);
procedure kbkdf_reset( vctx : Pointer);
function kbkdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function kbkdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kbkdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function kbkdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kbkdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;

const  ossl_kdf_kbkdf_functions: array[0..8] of TOSSL_DISPATCH= (
    ( function_id: OSSL_FUNC_KDF_NEWCTX; method:(code:@kbkdf_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX; method:(code:@kbkdf_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET; method:(code:@kbkdf_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE; method:(code:@kbkdf_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;
      method:(code:@kbkdf_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@kbkdf_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;
      method:(code:@kbkdf_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@kbkdf_get_ctx_params ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil))
);

function kbkdf_set_buffer(var _out : PByte; out_len : Psize_t;const p : POSSL_PARAM):integer;
function be32( host : uint32):uint32;
function derive( ctx_init : PEVP_MAC_CTX; mode : kbkdf_mode; iv : PByte; iv_len : size_t; &label : PByte; label_len : size_t; context : PByte; context_len : size_t; k_i : PByte; h : size_t; l : uint32; has_separator : integer; ko : PByte; ko_len : size_t; r : integer):integer;
procedure init( ctx : PKBKDF);


var // 1d arrays
  known_settable_ctx_params : array[0..33] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM;


implementation
uses OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib;



procedure init( ctx : PKBKDF);
begin
    ctx.r := 32;
    ctx.use_l := 1;
    ctx.use_separator := 1;
end;



function derive( ctx_init : PEVP_MAC_CTX; mode : kbkdf_mode; iv : PByte; iv_len : size_t; &label : PByte; label_len : size_t; context : PByte; context_len : size_t; k_i : PByte; h : size_t; l : uint32; has_separator : integer; ko : PByte; ko_len : size_t; r : integer):integer;
var
  ret : integer;
  ctx : PEVP_MAC_CTX;
  written,to_write, k_i_len : size_t;
  zero : Byte;
  counter, i : uint32;
  has_l : Boolean;
  label _done;
begin
{$POINTERMATH ON}
    ret := 0;
    ctx := nil;
    written := 0; k_i_len := iv_len;
    zero := 0;
    {
     * From SP800-108:
     * The fixed input data is a concatenation of a Label,
     * a separation indicator $00, the Context, and L.
     * One or more of these fixed input data fields may be omitted.
     *
     * has_separator = 0 means that the separator is omitted.
     * Passing a value of l = 0 means that L is omitted.
     * The Context and L are omitted automatically if a nil buffer is passed.
     }
    has_l := (l <> 0);
    { Setup K(0) for feedback mode. }
    if iv_len > 0 then memcpy(k_i, iv, iv_len);
    for counter := 1 to ko_len-1 do
    begin
        i := be32(counter);
        ctx := EVP_MAC_CTX_dup(ctx_init);
        if ctx = nil then goto _done ;
        { Perform feedback, if appropriate. }
        if (mode = FEEDBACK)  and  (0>= EVP_MAC_update(ctx, k_i, k_i_len)) then
            goto _done ;
        if (0>= EVP_MAC_update(ctx, 4 - (r div 8 ) + PByte(@i), r div 8))
             or  (0>= EVP_MAC_update(ctx, &label, label_len))
             or  ( (has_separator>0)  and  (0>= EVP_MAC_update(ctx, @zero, 1)) )
             or  (0>= EVP_MAC_update(ctx, context, context_len))
             or  ( (has_l)  and  (0>= EVP_MAC_update(ctx, PByte(@l), 4)) )
             or  (0>= EVP_MAC_final(ctx, k_i, nil, h)) then
            goto _done ;
        to_write := ko_len - written;
        memcpy(ko + written, k_i, min(to_write, h));
        written  := written + h;
        k_i_len := h;
        EVP_MAC_CTX_free(ctx);
        ctx := nil;
    end;
    ret := 1;
_done:
    EVP_MAC_CTX_free(ctx);
    Result := ret;

{$POINTERMATH OFF}
end;




function be32( host : uint32):uint32;
var
  big : uint32;
  ossl_is_endian: endian_st;
begin
    big := 0;
    ossl_is_endian.one := 1;
    if  not (ossl_is_endian.little <> 0 ) then
        Exit(host);
    big  := big  or ((host and $ff000000)  shr  24);
    big  := big  or ((host and $00ff0000)  shr  8);
    big  := big  or ((host and $0000ff00)  shl  8);
    big  := big  or ((host and $000000ff)  shl  24);
    Result := big;
end;



function kbkdf_set_buffer(var _out : PByte; out_len : Psize_t;const p : POSSL_PARAM):integer;
begin
    if (p.data = nil)  or  (p.data_size = 0) then Exit(1);
    OPENSSL_clear_free( Pointer(_out), out_len^);
    _out := nil;
    Result := OSSL_PARAM_get_octet_string(p, Pointer(_out), 0, out_len);
end;

function kbkdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if p = nil then Exit(-2);
    { KBKDF can produce results as large as you like. }
    Result := OSSL_PARAM_set_size_t(p, SIZE_MAX);
end;



function kbkdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[0] := OSSL_PARAM_END ;
    Result := @known_gettable_ctx_params;
end;



function kbkdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PKBKDF;

  libctx : POSSL_LIB_CTX;

  p : POSSL_PARAM;

  new_r : integer;
begin
    ctx := (PKBKDF  (vctx));
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    if 0>= ossl_prov_macctx_load_from_params(@ctx.ctx_init, params, nil,
                                           nil, nil, libctx ) then
        Exit(0)
    else
    if (ctx.ctx_init <> nil)
              and  (not EVP_MAC_is_a(EVP_MAC_CTX_get0_mac(ctx.ctx_init),
                              OSSL_MAC_NAME_HMAC))
              and  (not EVP_MAC_is_a(EVP_MAC_CTX_get0_mac(ctx.ctx_init),
                              OSSL_MAC_NAME_CMAC)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
        Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p <> nil ) and  (strncasecmp('counter', p.data, p.data_size)= 0)  then
    begin
        ctx.mode := COUNTER;
    end
    else
    if (p <> nil)
                and  (strncasecmp('feedback', p.data, p.data_size) = 0) then
    begin
        ctx.mode := FEEDBACK;
    end
    else if (p <> nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p <> nil)  and  (0>= kbkdf_set_buffer(ctx.ki, @ctx.ki_len, p )) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p <> nil)  and  (0>= kbkdf_set_buffer(ctx.&label, @ctx.label_len, p )) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (p <> nil)  and  (0>= kbkdf_set_buffer(ctx.context, @ctx.context_len, p) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
    if (p <> nil)  and  (0>= kbkdf_set_buffer(ctx.iv, @ctx.iv_len, p) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_L);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @ctx.use_l) ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_R);
    if p <> nil then
    begin
        new_r := 0;
        if 0>= OSSL_PARAM_get_int(p, @new_r ) then
            Exit(0);
        if (new_r <> 8)  and  (new_r <> 16)  and  (new_r <> 24)  and  (new_r <> 32) then Exit(0);
        ctx.r := new_r;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @ctx.use_separator) ) then
        Exit(0);
    { Set up digest context, if we can. }
    if (ctx.ctx_init <> nil)  and  (ctx.ki_len <> 0)
             and  (0>= EVP_MAC_init(ctx.ctx_init, ctx.ki, ctx.ki_len, nil) ) then
            Exit(0);
    Result := 1;
end;



function kbkdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[0] := _OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_L, nil);
    known_settable_ctx_params[0] := _OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, nil);
    known_settable_ctx_params[0] := _OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_R, nil);
    known_settable_ctx_params[0] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;


function kbkdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
    ctx         : PKBKDF;

    ret         : integer;

    k_i         : PByte;

    l           : uint32;

    h           : size_t;

    counter_max : uint64;
    label _done;
begin
    ctx := (PKBKDF  (vctx));
    ret := 0;
    k_i := nil;
    l := 0;
    h := 0;
    if (not ossl_prov_is_running)  or  (0>= kbkdf_set_ctx_params(ctx, params)) then
        Exit(0);
    { label, context, and iv are permitted to be empty.  Check everything
     * else. }
    if ctx.ctx_init = nil then
    begin
        if (ctx.ki_len = 0)  or  (ctx.ki = nil) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            Exit(0);
        end;
        { Could either be missing MAC or missing message digest or missing
         * cipher - arbitrarily, I pick this one. }
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MAC);
        Exit(0);
    end;
    { Fail if the output length is zero }
    if keylen = 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    h := EVP_MAC_CTX_get_mac_size(ctx.ctx_init);
    if h = 0 then goto _done ;
    if (ctx.iv_len <> 0)  and  (ctx.iv_len <> h) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        goto _done ;
    end;
    if ctx.mode = COUNTER then
    begin
        { Fail if keylen is too large for r }
        counter_max := uint64_t(1)  shl  uint64_t(ctx.r);
        if uint64_t(keylen div h) >= counter_max then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto _done ;
        end;
    end;
    if ctx.use_l <> 0 then
       l := be32(keylen * 8);
    k_i := OPENSSL_zalloc(h);
    if k_i = nil then goto _done ;
    ret := derive(ctx.ctx_init, ctx.mode, ctx.iv, ctx.iv_len, ctx.&label,
                 ctx.label_len, ctx.context, ctx.context_len, k_i, h, l,
                 ctx.use_separator, key, keylen, ctx.r);
_done:
    if ret <> 1 then OPENSSL_cleanse(key, keylen);
    OPENSSL_clear_free(Pointer(k_i), h);
    Result := ret;
end;


procedure kbkdf_reset( vctx : Pointer);
var
  ctx : PKBKDF;

  provctx : Pointer;
begin
    ctx := (PKBKDF  (vctx));
    provctx := ctx.provctx;
    EVP_MAC_CTX_free(ctx.ctx_init);
    OPENSSL_clear_free(Pointer(ctx.context), ctx.context_len);
    OPENSSL_clear_free(Pointer(ctx.&label), ctx.label_len);
    OPENSSL_clear_free(Pointer(ctx.ki), ctx.ki_len);
    OPENSSL_clear_free(Pointer(ctx.iv), ctx.iv_len);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
    init(ctx);
end;



procedure kbkdf_free( vctx : Pointer);
var
  ctx : PKBKDF;
begin
    ctx := (PKBKDF  (vctx));
    if ctx <> nil then
    begin
        kbkdf_reset(ctx);
        OPENSSL_free(ctx);
    end;
end;



function kbkdf_new( provctx : Pointer):Pointer;
var
  ctx : PKBKDF;
begin
    if not ossl_prov_is_running( ) then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.provctx := provctx;
    init(ctx);
    Result := ctx;
end;

end.
