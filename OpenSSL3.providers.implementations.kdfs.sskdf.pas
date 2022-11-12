unit OpenSSL3.providers.implementations.kdfs.sskdf;

interface
 uses OpenSSL.Api;


function sskdf_new( provctx : Pointer):Pointer;
procedure sskdf_free( vctx : Pointer);
procedure sskdf_reset( vctx : Pointer);
 function sskdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function sskdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function sskdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function sskdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function sskdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function sskdf_size( ctx : PKDF_SSKDF):size_t;
function sskdf_set_buffer(var _out : PByte; out_len : Psize_t;const p : POSSL_PARAM):integer;
function SSKDF_mac_kdm(ctx_init : PEVP_MAC_CTX;const kmac_custom : PByte; kmac_custom_len, kmac_out_len : size_t;const salt : PByte; salt_len : size_t;const z : PByte; z_len : size_t;const info : PByte; info_len : size_t; derived_key : PByte; derived_key_len : size_t):integer;
function kmac_init(ctx : PEVP_MAC_CTX;const custom : PByte; custom_len, kmac_out_len, derived_key_len : size_t; &out : PPByte):integer;
function SSKDF_hash_kdm(const kdf_md : PEVP_MD; z : PByte; z_len : size_t;const info : PByte; info_len : size_t; append_ctr : uint32; derived_key : PByte; derived_key_len : size_t):integer;
function x963kdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;

const
  ossl_kdf_sskdf_functions: array[0..8] of TOSSL_DISPATCH  = (
    ( function_id:OSSL_FUNC_KDF_NEWCTX; method: (code:@sskdf_new ;data:nil) ),
    ( function_id:OSSL_FUNC_KDF_FREECTX; method: (code:@sskdf_free ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_RESET; method:(code:@sskdf_reset ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_DERIVE; method:(code:@sskdf_derive ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS; method:(code:@sskdf_settable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@sskdf_set_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS; method:(code:@sskdf_gettable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@sskdf_get_ctx_params ;data:nil)),
    ( function_id:0; method:(code:nil;data:nil))
	);


 ossl_kdf_x963_kdf_functions: array[0..8] of TOSSL_DISPATCH = (
    ( function_id: OSSL_FUNC_KDF_NEWCTX; method:(code:@sskdf_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX; method:(code:@sskdf_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET; method:(code:@sskdf_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE; method:(code:@x963kdf_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;
      method:(code:@sskdf_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@sskdf_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;
      method:(code:@sskdf_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@sskdf_get_ctx_params ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil) )
);
   kmac_custom_str: array[0..2] of Byte = ( $4B, $44, $46 );
   SSKDF_MAX_INLEN = (1 shl 30);
   SSKDF_KMAC128_DEFAULT_SALT_SIZE = (168-4);
   SSKDF_KMAC256_DEFAULT_SALT_SIZE = (136-4);

var // 1d arrays
  known_settable_ctx_params : array[0..8] of TOSSL_PARAM;
// 1d arrays

   known_gettable_ctx_params : array[0..2] of TOSSL_PARAM;

implementation
uses openssl3.crypto.params, OpenSSL3.providers.common.provider_util,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, OpenSSL3.openssl.params,
     openssl3.providers.common.provider_ctx, openssl3.crypto.mem,
     openssl3.crypto.evp,  openssl3.crypto.evp.digest,
     openssl3.providers.fips.self_test, openssl3.crypto.evp.mac_lib;





function x963kdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_SSKDF;

  md : PEVP_MD;
begin
    ctx := (PKDF_SSKDF  (vctx));
    if  (not ossl_prov_is_running) or
       (0>= sskdf_set_ctx_params(ctx, params))  then
        Exit(0);
    if ctx.secret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        Exit(0);
    end;
    if ctx.macctx <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        Exit(0);
    end;
    { H(x) = hash }
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    Exit(SSKDF_hash_kdm(md, ctx.secret, ctx.secret_len,
                          ctx.info, ctx.info_len, 1, key, keylen));
end;





function SSKDF_hash_kdm(const kdf_md : PEVP_MD; z : PByte; z_len : size_t;const info : PByte; info_len : size_t; append_ctr : uint32; derived_key : PByte; derived_key_len : size_t):integer;
var
  ret,hlen : integer;
  counter, out_len, len : size_t;
  c : array[0..3] of Byte;
  mac : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  _out : PByte;
  ctx,ctx_init : PEVP_MD_CTX;
  label &end;
begin
    ret := 0;
    len := derived_key_len;
    _out := derived_key;
    ctx := nil; ctx_init := nil;
    if (z_len > SSKDF_MAX_INLEN)  or  (info_len > SSKDF_MAX_INLEN)
             or  (derived_key_len > SSKDF_MAX_INLEN)
             or  (derived_key_len = 0) then Exit(0);
    hlen := EVP_MD_get_size(kdf_md);
    if hlen <= 0 then Exit(0);
    out_len := size_t(hlen);
    ctx := EVP_MD_CTX_create();
    ctx_init := EVP_MD_CTX_create();
    if (ctx = nil)  or  (ctx_init = nil) then
       goto &end;
    if ( 0>= EVP_DigestInit(ctx_init, kdf_md)) then
       goto &end;
    counter := 1;
    while True do
    begin
        c[0] := ((counter  shr  24) and $ff);
        c[1] := ((counter  shr  16) and $ff);
        c[2] := ((counter  shr  8) and $ff);
        c[3] := (counter and $ff);
        if  not ( (EVP_MD_CTX_copy_ex(ctx, ctx_init)>0)  and  ( (append_ctr>0)  or  (EVP_DigestUpdate(ctx, @c, sizeof(c))>0)
                 and  (EVP_DigestUpdate(ctx, z, z_len)>0)
                 and  ( (0>= append_ctr)  or  (EVP_DigestUpdate(ctx, @c, sizeof(c))>0) )
                 and  (EVP_DigestUpdate(ctx, info, info_len)>0))) then
            goto &end;
        if len >= out_len then
        begin
            if  0>= EVP_DigestFinal_ex(ctx, _out, nil) then
                goto &end;
            _out  := _out + out_len;
            len  := len - out_len;
            if len = 0 then break;
        end
        else
        begin
            if  0>= EVP_DigestFinal_ex(ctx, @mac, nil ) then
                goto &end;
            memcpy(_out, @mac, len);
            break;
        end;
        Inc(counter);
    end;
    ret := 1;
&end:
    EVP_MD_CTX_destroy(ctx);
    EVP_MD_CTX_destroy(ctx_init);
    OPENSSL_cleanse(@mac, sizeof(mac));
    Result := ret;
end;




function kmac_init(ctx : PEVP_MAC_CTX;const custom : PByte; custom_len, kmac_out_len, derived_key_len : size_t; &out : PPByte):integer;
var
  params : array[0..1] of TOSSL_PARAM;
begin
    { Only KMAC has custom data - so return if not KMAC }
    if custom = nil then Exit(1);
    params[0] := OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM,
                                                  Pointer (custom), custom_len);
    params[1] := OSSL_PARAM_construct_end();
    if  0>= EVP_MAC_CTX_set_params(ctx, @params)  then
        Exit(0);
    { By default only do one iteration if kmac_out_len is not specified }
    if kmac_out_len = 0 then
       kmac_out_len := derived_key_len
    { otherwise check the size is valid }
    else
    if  not ( (kmac_out_len = derived_key_len)
         or  (kmac_out_len = 20)
         or  (kmac_out_len = 28)
         or  (kmac_out_len = 32)
         or  (kmac_out_len = 48)
         or  (kmac_out_len = 64) ) then
        Exit(0);
    params[0] := OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE,
                                            @kmac_out_len);
    if EVP_MAC_CTX_set_params(ctx, @params) <= 0 then
        Exit(0);
    {
     * For kmac the output buffer can be larger than EVP_MAX_MD_SIZE: so
     * alloc a buffer for this case.
     }
    if kmac_out_len > EVP_MAX_MD_SIZE then begin
        &out^ := OPENSSL_zalloc(kmac_out_len);
        if &out^ = nil then Exit(0);
    end;
    Result := 1;
end;

function SSKDF_mac_kdm(ctx_init : PEVP_MAC_CTX;const kmac_custom : PByte; kmac_custom_len, kmac_out_len : size_t;const salt : PByte; salt_len : size_t;const z : PByte; z_len : size_t;const info : PByte; info_len : size_t; derived_key : PByte; derived_key_len : size_t):integer;
var
  ret : integer;
  counter, out_len, len : size_t;
  c : array[0..3] of Byte;
  mac_buf : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  &out,kmac_buffer : PByte;
  ctx : PEVP_MAC_CTX;
  mac : PByte;
  label _end;
begin
    ret := 0;
    &out := derived_key;
    ctx := nil;
    mac := @mac_buf ;kmac_buffer := nil;
    if (z_len > SSKDF_MAX_INLEN)  or  (info_len > SSKDF_MAX_INLEN)
             or  (derived_key_len > SSKDF_MAX_INLEN)
             or  (derived_key_len = 0) then
        Exit(0);
    if  0>= kmac_init(ctx_init, kmac_custom, kmac_custom_len, kmac_out_len,
                   derived_key_len, @kmac_buffer) then
         goto _end;
    if kmac_buffer <> nil then
        mac := kmac_buffer;
    if  0>= EVP_MAC_init(ctx_init, salt, salt_len, nil) then
        goto _end;
    out_len := EVP_MAC_CTX_get_mac_size(ctx_init); { output size }
    if (out_len <= 0)  or
       ( (mac = @mac_buf)  and  (out_len > sizeof(mac_buf) ))then
       goto _end;
    len := derived_key_len;
    counter := 1;
    while True do
    begin
        c[0] := ((counter  shr  24) and $ff);
        c[1] := ((counter  shr  16) and $ff);
        c[2] := ((counter  shr  8) and $ff);
        c[3] := (counter and $ff);
        ctx := EVP_MAC_CTX_dup(ctx_init);
        if  not ( (ctx <> nil)
                 and  (Boolean(EVP_MAC_update(ctx, @c, sizeof(c))))
                 and  (Boolean(EVP_MAC_update(ctx, z, z_len))
                 and  (Boolean(EVP_MAC_update(ctx, info, info_len)))) ) then
            goto _end;
        if len >= out_len then
        begin
            if  0>= EVP_MAC_final(ctx, &out, nil, len) then
                goto _end;
            &out  := &out + out_len;
            len  := len - out_len;
            if len = 0 then break;
        end
        else
        begin
            if  0>= EVP_MAC_final(ctx, mac, nil, out_len )  then
               goto _end;
            memcpy(&out, mac, len);
            break;
        end;
        EVP_MAC_CTX_free(ctx);
        ctx := nil;
        Inc(counter);
    end;
    ret := 1;
_end:
    if kmac_buffer <> nil then
       OPENSSL_clear_free(Pointer(kmac_buffer), kmac_out_len)
    else
        OPENSSL_cleanse(@mac_buf, sizeof(mac_buf));
    EVP_MAC_CTX_free(ctx);
    Result := ret;
end;



function sskdf_set_buffer(var _out : PByte; out_len : Psize_t;const p : POSSL_PARAM):integer;
begin
    if (p.data = nil)  or  (p.data_size = 0) then Exit(1);
    OPENSSL_free( _out);
    _out := nil;
    Result := OSSL_PARAM_get_octet_string(p, Pointer (_out), 0, out_len);
end;





function sskdf_size( ctx : PKDF_SSKDF):size_t;
var
  len : integer;

  md : PEVP_MD;
begin
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    len := EVP_MD_get_size(md);
    Result := get_result(len <= 0, 0 , size_t(len));
end;

function sskdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PKDF_SSKDF;

  p : POSSL_PARAM;
begin
    ctx := PKDF_SSKDF(vctx);
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, sskdf_size(ctx)));
    Result := -2;
end;


function sskdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] :=  _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] :=  OSSL_PARAM_END;
    Result := @known_gettable_ctx_params;
end;


function sskdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
  ctx : PKDF_SSKDF;
  libctx : POSSL_LIB_CTX;
  sz : size_t;
begin
    ctx := vctx;
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    if  0>= ossl_prov_digest_load_from_params(@ctx.digest, params, libctx) then
        Exit(0);
    if  0>= ossl_prov_macctx_load_from_params(@ctx.macctx, params,
                                           nil, nil, nil, libctx)  then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET);
    if (p = nil) then
        p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if p <> nil then
       if  0>= sskdf_set_buffer(ctx.secret, @ctx.secret_len, p) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if p  <> nil then
        if ( 0>= sskdf_set_buffer(ctx.info, @ctx.info_len, p)) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if p <> nil then
        if ( 0>= sskdf_set_buffer(ctx.salt, @ctx.salt_len, p))  then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC_SIZE);
    if p <> nil then
    begin
        if  (0>= OSSL_PARAM_get_size_t(p, @sz))  or  (sz = 0) then
            Exit(0);
        ctx.out_len := sz;
    end;
    Result := 1;
end;


function sskdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
   known_settable_ctx_params[0] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, nil, 0);
   known_settable_ctx_params[1] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
   known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, nil, 0);
   known_settable_ctx_params[3] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
   known_settable_ctx_params[4] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
   known_settable_ctx_params[5] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, nil, 0);
   known_settable_ctx_params[6] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
   known_settable_ctx_params[7] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_MAC_SIZE, nil);
   known_settable_ctx_params[8] :=  OSSL_PARAM_END ;
   Result := @known_settable_ctx_params;
end;

function sskdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
    ctx              : PKDF_SSKDF;
    md               : PEVP_MD;
    ret              : integer;
    custom           : PByte;
    custom_len       : size_t;
    default_salt_len : integer;
    mac              : PEVP_MAC;
begin
    ctx := PKDF_SSKDF(vctx);
    if  (not ossl_prov_is_running) or   (0>= sskdf_set_ctx_params(ctx, params))  then
        Exit(0);
    if ctx.secret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        Exit(0);
    end;
    md := ossl_prov_digest_md(@ctx.digest);
    if ctx.macctx <> nil then
    begin
        { H(x) = KMAC or H(x) = HMAC }
        custom := nil;
        custom_len := 0;
        mac := EVP_MAC_CTX_get0_mac(ctx.macctx);
        if EVP_MAC_is_a(mac, OSSL_MAC_NAME_HMAC) then
        begin
            { H(x) = HMAC(x, salt, hash) }
            if md = nil then  begin
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
                Exit(0);
            end;
            default_salt_len := EVP_MD_get_size(md);
            if default_salt_len <= 0 then Exit(0);
        end
        else
        if EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC128)
                    or  EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC256) then
        begin
            { H(x) = KMACzzz(x, salt, custom) }
            custom := @kmac_custom_str;
            custom_len := sizeof(kmac_custom_str);
            if EVP_MAC_is_a(mac, OSSL_MAC_NAME_KMAC128) then
                default_salt_len := SSKDF_KMAC128_DEFAULT_SALT_SIZE
            else
                default_salt_len := SSKDF_KMAC256_DEFAULT_SALT_SIZE;
        end
        else
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_MAC_TYPE);
            Exit(0);
        end;
        { If no salt is set then use a default_salt of zeros }
        if (ctx.salt = nil)  or  (ctx.salt_len <= 0) then
        begin
            ctx.salt := OPENSSL_zalloc(default_salt_len);
            if ctx.salt = nil then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            ctx.salt_len := default_salt_len;
        end;
        ret := SSKDF_mac_kdm(ctx.macctx,
                            custom, custom_len, ctx.out_len,
                            ctx.salt, ctx.salt_len,
                            ctx.secret, ctx.secret_len,
                            ctx.info, ctx.info_len, key, keylen);
        Exit(ret);
    end
    else
    begin
        { H(x) = hash }
        if md = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
            Exit(0);
        end;
        Exit(SSKDF_hash_kdm(md, ctx.secret, ctx.secret_len,
                              ctx.info, ctx.info_len, 0, key, keylen));
    end;
end;


procedure sskdf_reset( vctx : Pointer);
var
  ctx : PKDF_SSKDF;

  provctx : Pointer;
begin
    ctx := PKDF_SSKDF  (vctx);
    provctx := ctx.provctx;
    EVP_MAC_CTX_free(ctx.macctx);
    ossl_prov_digest_reset(@ctx.digest);
    OPENSSL_clear_free(Pointer(ctx.secret), ctx.secret_len);
    OPENSSL_clear_free(Pointer(ctx.info), ctx.info_len);
    OPENSSL_clear_free(Pointer(ctx.salt), ctx.salt_len);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
end;




procedure sskdf_free( vctx : Pointer);
var
  ctx : PKDF_SSKDF;
begin
    ctx := PKDF_SSKDF  (vctx);
    if ctx <> nil then
    begin
        sskdf_reset(ctx);
        OPENSSL_free(ctx);
    end;
end;


function sskdf_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_SSKDF;
begin
    if  not ossl_prov_is_running( )   then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^ ));
    if ctx = nil then
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    ctx.provctx := provctx;
    Result := ctx;
end;
end.
