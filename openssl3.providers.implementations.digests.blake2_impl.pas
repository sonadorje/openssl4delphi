unit openssl3.providers.implementations.digests.blake2_impl;


interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.crypto.md5.md5_dgst,
     openssl3.crypto.md5.md5_sha1;

  function load32(const src : PByte):uint32;
  function load64( src : PByte):uint64;
  procedure store32( dst : PByte; w : uint32);
  procedure store64( dst : PByte; w : uint64);
  function load48(const src : PByte):uint64;
  procedure store48( dst : PByte; w : uint64);
  function rotr32(const w, c : uint32):uint32;
  function rotr64(const w : uint64; c : uint32):uint64;
  function blake2_mac_new( unused_provctx : Pointer):Pointer;
  function blake2_mac_dup( vsrc : Pointer):Pointer;
  procedure blake2_mac_free( vmacctx : Pointer);
  function blake2_mac_size( vmacctx : Pointer):size_t;
  function blake2_setkey(macctx : Pblake2_mac_data_st;const key : PByte; keylen : size_t):integer;
  function blake2_mac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
  function blake2_mac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
  function blake2_mac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
  function blake2_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function blake2_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
  function blake2_mac_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
  function blake2_mac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;

const  BLAKE2_FUNCTIONS: array[0..10] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_MAC_NEWCTX; method:(code:@blake2_mac_new; data:nil)),
    (function_id:  OSSL_FUNC_MAC_DUPCTX; method:(code:@blake2_mac_dup; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FREECTX; method:(code:@blake2_mac_free; data:nil)),
    (function_id:  OSSL_FUNC_MAC_INIT; method:(code:@blake2_mac_init; data:nil)),
    (function_id:  OSSL_FUNC_MAC_UPDATE; method:(code:@blake2_mac_update; data:nil)),
    (function_id:  OSSL_FUNC_MAC_FINAL; method:(code:@blake2_mac_final; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS;
      method:(code:@blake2_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_GET_CTX_PARAMS; method:(code:@blake2_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS;
      method:(code:@blake2_mac_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_MAC_SET_CTX_PARAMS; method:(code:@blake2_mac_set_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

//以下大写参数译自blake2_impl.c定义的同名宏
var
  BLAKE2_PARAM_SET_KEY_LENGTH: TBLAKE2_PARAM_SET_KEY_LENGTH_FUNC;
  BLAKE2_PARAM_INIT: TBLAKE2_PARAM_INIT_FUNC;
  BLAKE2_INIT_KEY: TBLAKE2_INIT_KEY_FUNC;
  BLAKE2_UPDATE: TBLAKE2_UPDATE_FUNC;
  BLAKE2_FINAL: TBLAKE2_FINAL_FUNC ;
  BLAKE2_BLOCKBYTES, BLAKE2_KEYBYTES, BLAKE2_OUTBYTES,
  BLAKE2_PERSONALBYTES, BLAKE2_SALTBYTES: size_t;
  BLAKE2_PARAM_SET_DIGEST_LENGTH: TBLAKE2_PARAM_SET_DIGEST_LENGTH_FUNC;
  BLAKE2_PARAM_SET_PERSONAL: TBLAKE2_PARAM_SET_PERSONAL_FUNC;
  BLAKE2_PARAM_SET_SALT: TBLAKE2_PARAM_SET_SALT_FUNC;

implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.openssl.params;

var
  known_gettable_ctx_params: array[0..2] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..4] of TOSSL_PARAM ;

function blake2_mac_new( unused_provctx : Pointer):Pointer;
var
  macctx : Pblake2_mac_data_st;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    macctx := OPENSSL_zalloc(sizeof( macctx^));
    if macctx <> nil then
    begin
        BLAKE2_PARAM_INIT(@macctx.params) ;//ossl_blake2b_param_init(@macctx.params);
    end;
    Result := macctx;
end;


function blake2_mac_dup( vsrc : Pointer):Pointer;
var
  dst, src : Pblake2_mac_data_st;
begin
    src := vsrc;
    if not ossl_prov_is_running then
        Exit(nil);
    dst := OPENSSL_zalloc(sizeof( dst^));
    if dst = nil then
        Exit(nil);
    dst^ := src^;
    Result := dst;
end;


function blake2_setkey(macctx : Pblake2_mac_data_st;
        const key : PByte; keylen : size_t):integer;
begin
    if (keylen > 64)  or  (keylen = 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    memcpy(@macctx.key, key, keylen);
    if keylen < 64 then
       memset(PByte(@macctx.key) + keylen, 0, 64 - keylen);
    BLAKE2_PARAM_SET_KEY_LENGTH(@macctx.params,  uint8( keylen));
    //ossl_blake2b_param_set_key_length(&macctx.params,  uint8( keylen);
    Result := 1;
end;


function blake2_mac_init(vmacctx : Pointer;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  macctx : Pblake2_mac_data_st;
begin
    macctx := vmacctx;
    if (not ossl_prov_is_running)  or
       (0>= blake2_mac_set_ctx_params(macctx, params))  then
        Exit(0);
    if key <> nil then
    begin
        if 0>= blake2_setkey(macctx, key, keylen) then
            Exit(0);
    end
    else
    if (macctx.params.key_length = 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    Result := BLAKE2_INIT_KEY(@macctx.ctx, @macctx.params, @macctx.key);
    //ossl_blake2b_init_key(@macctx.ctx, @macctx.params, macctx.key);
end;


function blake2_mac_update(vmacctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  macctx : Pblake2_mac_data_st;
begin
    macctx := vmacctx;
    if datalen = 0 then Exit(1);
    Result := BLAKE2_UPDATE(@macctx.ctx, data, datalen);
end;


function blake2_mac_final( vmacctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  macctx : Pblake2_mac_data_st;
begin
    macctx := vmacctx;
    if not ossl_prov_is_running then
        Exit(0);
    outl^ := blake2_mac_size(macctx);
    Result := BLAKE2_FINAL(&out, @macctx.ctx);
end;


function blake2_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function blake2_get_ctx_params( vmacctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p <> nil)
             and  (0>= OSSL_PARAM_set_size_t(p, blake2_mac_size(vmacctx))) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (p <> nil)
             and  (0>= OSSL_PARAM_set_size_t(p, BLAKE2_BLOCKBYTES)) then
        Exit(0);
    Result := 1;
end;


function blake2_mac_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;


function blake2_mac_set_ctx_params(vmacctx : Pointer;const params : POSSL_PARAM):integer;
var
  macctx : Pblake2_mac_data_st;
   p :POSSL_PARAM;
  size : size_t;
begin
    macctx := vmacctx;
    if params = nil then
        Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE) ;
    if p  <> nil then
    begin
        if (0>= OSSL_PARAM_get_size_t(p, @size) )
             or  (size < 1)
             or  (size > BLAKE2_OUTBYTES) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_XOF_OR_INVALID_LENGTH);
            Exit(0);
        end;
        BLAKE2_PARAM_SET_DIGEST_LENGTH(@macctx.params,  uint8( size));
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p <> nil)
             and  (0>= blake2_setkey(macctx, p.data, p.data_size)) then
        Exit(0);

    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM);
    if p <> nil then
    begin
        if p.data_size > BLAKE2_PERSONALBYTES then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH);
            Exit(0);
        end;
        BLAKE2_PARAM_SET_PERSONAL(@macctx.params, p.data, p.data_size);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SALT);
    if p <> nil then
    begin
        if p.data_size > BLAKE2_SALTBYTES then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            Exit(0);
        end;
        BLAKE2_PARAM_SET_SALT(@macctx.params, p.data, p.data_size);
    end;
    Result := 1;
end;

procedure blake2_mac_free( vmacctx : Pointer);
var
  macctx : Pblake2_mac_data_st;
begin
    macctx := vmacctx;
    if macctx <> nil then
    begin
        OPENSSL_cleanse(@macctx.key, sizeof(macctx.key));
        OPENSSL_free(Pointer(macctx));
    end;
end;

function blake2_mac_size( vmacctx : Pointer):size_t;
var
  macctx : Pblake2_mac_data_st;
begin
    macctx := vmacctx;
    Result := macctx.params.digest_length;
end;

function load32(const src : PByte):uint32;
var
  w : uint32;
  ossl_is_endian: endian_st;
begin
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
    begin
        memcpy(@w, src, sizeof(w));
        Exit(w);
    end
    else
    begin
        w := uint32( src[0])
                   or uint32( src[1]  shl   8)
                   or uint32( src[2]  shl  16)
                   or uint32( src[3]  shl  24);
        Exit(w);
    end;
end;


function load64( src : PByte):uint64;
var
  w : uint64;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
    begin
        memcpy(@w, src, sizeof(w));
        Exit(w);
    end
    else
    begin
        w := uint64( src[0])
               or (uint64( src[1])  shl   8)
               or (uint64( src[2])  shl  16)
               or (uint64( src[3])  shl  24)
               or (uint64( src[4])  shl  32)
               or (uint64( src[5])  shl  40)
               or (uint64( src[6])  shl  48)
               or (uint64( src[7])  shl  56);
        Exit(w);
    end;
{$POINTERMATH OFF}
end;


procedure store32( dst : PByte; w : uint32);
var
  p : PByte;
  i : integer;
  ossl_is_endian: endian_st;
begin

    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0 then
    begin
        memcpy(dst, @w, sizeof(w));
    end
    else
    begin
         p := PByte(dst);
        for i := 0 to 3 do
            p[i] := uint8(w  shr  (8 * i));
    end;
end;


procedure store64( dst : PByte; w : uint64);
var
  p : PByte;
  i : integer;
  ossl_is_endian: endian_st;
begin

    ossl_is_endian.one := 1;
    if ossl_is_endian.little <> 0  then
    begin
        memcpy(dst, @w, sizeof(w));
    end
    else
    begin
         p := PByte(dst);
        for i := 0 to 7 do
            p[i] := uint8(w  shr  (8 * i));
    end;
end;


function load48(const src : PByte):uint64;
var
  w : uint64;
begin
    w := uint64( src[0])
               or (uint64( src[1])  shl   8)
               or (uint64( src[2])  shl  16)
               or (uint64( src[3])  shl  24)
               or (uint64( src[4])  shl  32)
               or (uint64( src[5])  shl  40);
    Result := w;
end;


procedure store48( dst : PByte; w : uint64);
var
  p : PByte;
begin
    p    := (dst);
    p[0] := uint8(w);
    p[1] := uint8(w shr 8);
    p[2] := uint8(w shr 16);
    p[3] := uint8(w shr 24);
    p[4] := uint8(w shr 32);
    p[5] := uint8(w shr 40);
end;


function rotr32(const w, c : uint32):uint32;
begin
    Result := (w  shr  c) or (w  shl  (32 - c));
end;


function rotr64(const w : uint64; c : uint32):uint64;
begin
    Result := (w  shr  c) or (w  shl  (64 - c));
end;

initialization

   known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
   known_gettable_ctx_params[1] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, nil);
   known_gettable_ctx_params[2] := OSSL_PARAM_END ;

   known_settable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, nil);
   known_settable_ctx_params[1] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, nil, 0);
   known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, nil, 0);
   known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_MAC_PARAM_SALT, nil, 0);
   known_settable_ctx_params[4] := OSSL_PARAM_END;


end.
