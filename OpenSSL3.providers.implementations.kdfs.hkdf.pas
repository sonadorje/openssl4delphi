unit OpenSSL3.providers.implementations.kdfs.hkdf;

interface
uses OpenSSL.Api;

function kdf_hkdf_new( provctx : Pointer):Pointer;
procedure kdf_hkdf_free( vctx : Pointer);
procedure kdf_hkdf_reset( vctx : Pointer);
function kdf_hkdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function kdf_hkdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_hkdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function kdf_hkdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_hkdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function kdf_hkdf_size( ctx : PKDF_HKDF):size_t;
function hkdf_common_set_ctx_params(ctx : PKDF_HKDF;const params : POSSL_PARAM):integer;
function HKDF_Extract(libctx : POSSL_LIB_CTX;const evp_md : PEVP_MD; salt : PByte; salt_len : size_t;const ikm : PByte; ikm_len : size_t; prk : PByte; prk_len : size_t):integer;
function HKDF_Expand(const evp_md : PEVP_MD; prk : PByte; prk_len : size_t;const info : PByte; info_len : size_t; okm : PByte; okm_len : size_t):integer;
function HKDF(libctx : POSSL_LIB_CTX;const evp_md : PEVP_MD; salt : PByte; salt_len : size_t;const ikm : PByte; ikm_len : size_t;const info : PByte; info_len : size_t; okm : PByte; okm_len : size_t):int;
function kdf_tls1_3_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function kdf_tls1_3_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_tls1_3_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function prov_tls13_hkdf_generate_secret(libctx : POSSL_LIB_CTX;const md : PEVP_MD; prevsecret : PByte; prevsecretlen : size_t;var insecret : PByte; insecretlen : size_t;const prefix : PByte; prefixlen : size_t;const &label : PByte; labellen : size_t; &out : PByte; outlen : size_t):integer;
function prov_tls13_hkdf_expand(const md : PEVP_MD; key : PByte; keylen : size_t;const prefix : PByte; prefixlen : size_t;const &label : PByte; labellen : size_t;const data : PByte; datalen : size_t; &out : PByte; outlen : size_t):integer;

const
 HKDF_MAXBUF = 2048;
 ossl_kdf_hkdf_functions: array[0..8] of TOSSL_DISPATCH = (
    ( function_id:OSSL_FUNC_KDF_NEWCTX;  method:(code:@kdf_hkdf_new; data:nil)  ),
    ( function_id:OSSL_FUNC_KDF_FREECTX; method:(code: @kdf_hkdf_free; data:nil) ),
    ( function_id:OSSL_FUNC_KDF_RESET;  method:(code: @kdf_hkdf_reset; data:nil)  ),
    ( function_id:OSSL_FUNC_KDF_DERIVE;  method:(code: @kdf_hkdf_derive; data:nil)  ),
    ( function_id:OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;  method:(code: @kdf_hkdf_settable_ctx_params ; data:nil)  ),
    ( function_id:OSSL_FUNC_KDF_SET_CTX_PARAMS;  method:(code: @kdf_hkdf_set_ctx_params ; data:nil)  ),
    ( function_id:OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;  method:(code: @kdf_hkdf_gettable_ctx_params ; data:nil)  ),
    ( function_id:OSSL_FUNC_KDF_GET_CTX_PARAMS;  method:(code: @kdf_hkdf_get_ctx_params ; data:nil)  ),
    ( function_id:0;  method:(code: nil ; data:nil) )
);

 ossl_kdf_tls1_3_kdf_functions: array[0..8] of TOSSL_DISPATCH = (
    ( function_id:OSSL_FUNC_KDF_NEWCTX; method:(code:@kdf_hkdf_new ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_FREECTX; method:(code:@kdf_hkdf_free ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_RESET; method:(code:@kdf_hkdf_reset ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_DERIVE; method:(code:@kdf_tls1_3_derive ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;    method:(code:@kdf_tls1_3_settable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@kdf_tls1_3_set_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS; method:(code:@kdf_hkdf_gettable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@kdf_hkdf_get_ctx_params ;data:nil)),
    ( function_id:0; method:(code: nil; data:nil))
);

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.providers.common.capabilities,
     openssl3.crypto.params, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, OpenSSL3.openssl.params,
     openssl3.crypto.evp.digest, openssl3.crypto.hmac.hmac,
     openssl3.providers.common.provider_ctx, openssl3.providers.fips.self_test,
     openssl3.crypto.evp.mac_lib, openssl3.crypto.packet;



function prov_tls13_hkdf_expand(const md : PEVP_MD; key : PByte; keylen : size_t;const prefix : PByte; prefixlen : size_t;const &label : PByte; labellen : size_t;const data : PByte; datalen : size_t; &out : PByte; outlen : size_t):integer;
var
    hkdflabellen : size_t;
    hkdflabel    : array[0..(HKDF_MAXBUF)-1] of Byte;
    pkt          : TWPACKET;
begin
    {
     * 2 bytes for length of derived secret + 1 byte for length of combined
     * prefix and label + bytes for the label itself + 1 byte length of hash
     * + bytes for the hash itself.  We've got the maximum the KDF can handle
     * which should always be sufficient.
     }
    if  (0>= WPACKET_init_static_len(@pkt, @hkdflabel, sizeof(hkdflabel) , 0) )
         or   (0>= WPACKET_put_bytes_u16(@pkt, outlen))
         or   (0>= WPACKET_start_sub_packet_u8(@pkt))
         or   (0>= WPACKET_memcpy(@pkt, prefix, prefixlen))
         or   (0>= WPACKET_memcpy(@pkt, &label, labellen))
         or   (0>= WPACKET_close(@pkt))
         or   (0>= WPACKET_sub_memcpy_u8(@pkt, data, get_result(data = nil, 0 , datalen)))
         or   (0>= WPACKET_get_total_written(@pkt, @hkdflabellen))
         or   (0>= WPACKET_finish(@pkt)) then
    begin
        WPACKET_cleanup(@pkt);
        Exit(0);
    end;
    Exit(HKDF_Expand(md, key, keylen, @hkdflabel, hkdflabellen,
                       &out, outlen));
end;

function prov_tls13_hkdf_generate_secret(libctx : POSSL_LIB_CTX;const md : PEVP_MD;
                                         prevsecret : PByte; prevsecretlen : size_t;
                                         var insecret : PByte; insecretlen : size_t;
                                         const prefix : PByte; prefixlen :
                                         size_t;const &label : PByte; labellen : size_t;
                                         &out : PByte; outlen : size_t):integer;
var
    mdlen         : size_t;
    ret           : integer;
    preextractsec,
    default_zeros : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
    mctx          : PEVP_MD_CTX;
    hash          : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
begin
    { Always filled with zeros }
    ret := EVP_MD_get_size(md);
    { Ensure cast to size_t is safe }
    if ret <= 0 then Exit(0);
    mdlen := size_t(ret);
    if insecret = nil then
    begin
        insecret := @default_zeros;
        insecretlen := mdlen;
    end;
    if prevsecret = nil then
    begin
        prevsecret := @default_zeros;
        prevsecretlen := 0;
    end
    else
    begin
        mctx := EVP_MD_CTX_new();
        { The pre-extract derive step uses a hash of no messages }
        if (mctx = nil)
                 or ( EVP_DigestInit_ex(mctx, md, nil) <= 0)
                 or ( EVP_DigestFinal_ex(mctx, @hash, nil) <= 0) then
        begin
            EVP_MD_CTX_free(mctx);
            Exit(0);
        end;
        EVP_MD_CTX_free(mctx);
        { Generate the pre-extract secret }
        if  0>= prov_tls13_hkdf_expand(md, prevsecret, mdlen,
                                    prefix, prefixlen, &label, labellen,
                                    @hash, mdlen, @preextractsec, mdlen)  then
            Exit(0);
        prevsecret := @preextractsec;
        prevsecretlen := mdlen;
    end;
    ret := HKDF_Extract(libctx, md, prevsecret, prevsecretlen,
                       insecret, insecretlen, out, outlen);
    if prevsecret = @preextractsec then
       OPENSSL_cleanse(@preextractsec, mdlen);
    Result := ret;
end;



function kdf_tls1_3_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_HKDF;
  p: POSSL_PARAM;
begin
    ctx := vctx;
    if params = nil then Exit(1);
    if  0>= hkdf_common_set_ctx_params(ctx, params) then
        Exit(0);
    if ctx.mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX );
    if p <> nil then
    begin
        OPENSSL_free(ctx.prefix);
        ctx.prefix := nil;
        if  0>= OSSL_PARAM_get_octet_string(p, Pointer(ctx.prefix), 0,
                                         @ctx.prefix_len)  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL );
    if p <> nil then
    begin
        OPENSSL_free(ctx.&label);
        ctx.&label := nil;
        if 0>= OSSL_PARAM_get_octet_string(p, Pointer(ctx.&label), 0,
                                         @ctx.label_len)  then
            Exit(0);
    end;
    OPENSSL_clear_free(Pointer(ctx.data), ctx.data_len);
    ctx.data := nil;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA);
    if  (p  <> nil)
             and  (0>= OSSL_PARAM_get_octet_string(p, Pointer(ctx.data), 0,
                                            @ctx.data_len)) then
        Exit(0);
    Result := 1;
end;

function kdf_tls1_3_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
var
  known_settable_ctx_params : array[0..9] of TOSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, nil);
    known_settable_ctx_params[2] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[4] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
    known_settable_ctx_params[5] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
    known_settable_ctx_params[6] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, nil, 0);
    known_settable_ctx_params[7] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, nil, 0);
    known_settable_ctx_params[8] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, nil, 0);
    known_settable_ctx_params[9] := OSSL_PARAM_END ;
    
    Result := @known_settable_ctx_params;
end;



function kdf_tls1_3_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_HKDF;
  md:PEVP_MD;
begin
    ctx := PKDF_HKDF (vctx);
    if  (not ossl_prov_is_running) or
        (0>= kdf_tls1_3_set_ctx_params(ctx, params))then
        Exit(0);
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    case ctx.mode of

    EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        Exit(prov_tls13_hkdf_generate_secret(PROV_LIBCTX_OF(ctx.provctx),
                                               md,
                                               ctx.salt, ctx.salt_len,
                                               ctx.key, ctx.key_len,
                                               ctx.prefix, ctx.prefix_len,
                                               ctx.&label, ctx.label_len,
                                               key, keylen));
    EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        Exit(prov_tls13_hkdf_expand(md, ctx.key, ctx.key_len,
                                      ctx.prefix, ctx.prefix_len,
                                      ctx.&label, ctx.label_len,
                                      ctx.data, ctx.data_len,
                                      key, keylen));
    else
        Exit(0);
    end;
end;

function HKDF(libctx : POSSL_LIB_CTX;const evp_md : PEVP_MD; salt : PByte; salt_len : size_t;const ikm : PByte; ikm_len : size_t;const info : PByte; info_len : size_t; okm : PByte; okm_len : size_t):int;
var
  prk : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  ret, sz : integer;

  prk_len : size_t;
begin
    sz := EVP_MD_get_size(evp_md);
    if sz < 0 then Exit(0);
    prk_len := size_t(sz);
    { Step 1: HKDF-Extract(salt, IKM) . PRK }
    if  0>= HKDF_Extract(libctx, evp_md,
                      salt, salt_len, ikm, ikm_len, @prk, prk_len)   then
        Exit(0);
    { Step 2: HKDF-Expand(PRK, info, L) . OKM }
    ret := HKDF_Expand(evp_md, @prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(@prk, sizeof(prk));
    Result := ret;
end;





function HKDF_Expand(const evp_md : PEVP_MD; prk : PByte; prk_len : size_t;const info : PByte; info_len : size_t; okm : PByte; okm_len : size_t):integer;
var
    hmac     : PHMAC_CTX;
    ret ,sz     : integer;
    i        : uint32;
    prev     : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
    done_len, dig_len, n : size_t;
    copy_len : size_t;
    ctr      : Byte;

  label err;

begin
    ret := 0;
    done_len := 0;
    sz := EVP_MD_get_size(evp_md);
    if sz <= 0 then Exit(0);
    dig_len := size_t(sz);
    { calc: N = ceil(L/HashLen) }
    n := okm_len div dig_len;
    if (okm_len mod dig_len)>0 then
       Inc(n);
    if (n > 255)  or  (okm = nil) then Exit(0);
    hmac := HMAC_CTX_new( );
    if hmac  = nil then
        Exit(0);
    if  0>= HMAC_Init_ex(hmac, prk, prk_len, evp_md, nil)  then
        goto err;
    for i := 1 to n do
    begin
        ctr := i;
        { calc: T(i) = HMAC-Hash(PRK, T(i - 1) or info or i) }
        if i > 1 then
        begin
            if 0>= HMAC_Init_ex(hmac, nil, 0, nil, nil) then
               goto err;
            if 0>= HMAC_Update(hmac, @prev, dig_len)  then
               goto err;
        end;
        if 0>= HMAC_Update(hmac, info, info_len) then
           goto err;
        if 0>= HMAC_Update(hmac, @ctr, 1) then
           goto err;
        if 0>= HMAC_Final(hmac, @prev, nil) then
           goto err;
        copy_len := get_result(done_len + dig_len > okm_len ,
                       okm_len - done_len ,
                       dig_len);
        memcpy(okm + done_len, @prev, copy_len);
        done_len  := done_len + copy_len;
    end;
    ret := 1;
 err:
    OPENSSL_cleanse(@prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    Result := ret;
end;

function HKDF_Extract(libctx : POSSL_LIB_CTX;const evp_md : PEVP_MD; salt : PByte; salt_len : size_t;const ikm : PByte; ikm_len : size_t; prk : PByte; prk_len : size_t):integer;
var
  sz : integer;
begin
    sz := EVP_MD_get_size(evp_md);
    if sz < 0 then Exit(0);
    if prk_len <> size_t(sz)  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_OUTPUT_BUFFER_SIZE);
        Exit(0);
    end;
    { calc: PRK = HMAC-Hash(salt, IKM) }
    Result := Int(  EVP_Q_mac(libctx, 'HMAC', nil, EVP_MD_get0_name(evp_md), nil, salt,
              salt_len, ikm, ikm_len, prk, EVP_MD_get_size(evp_md), nil) <> nil);
end;

function hkdf_common_set_ctx_params(ctx : PKDF_HKDF;const params : POSSL_PARAM):integer;
var
  libctx : POSSL_LIB_CTX;
  p : POSSL_PARAM;
  n : integer;
begin
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then
       Exit(1);
    if 0>= ossl_prov_digest_load_from_params(@ctx.digest, params, libctx) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if p <> nil then
    begin
        if p.data_type = OSSL_PARAM_UTF8_STRING then
        begin
            if strcasecmp(p.data, 'EXTRACT_AND_EXPAND') = 0 then
            begin
                ctx.mode := EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            end
            else
            if (strcasecmp(p.data, 'EXTRACT_ONLY') = 0) then
            begin
               ctx.mode := EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            end
            else
            if (strcasecmp(p.data, 'EXPAND_ONLY') = 0) then
            begin
               ctx.mode := EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            end
            else
            begin
              ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
              Exit(0);
            end;
        end
        else
        if (OSSL_PARAM_get_int(p, @n)>0) then
        begin
            if (n <> EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND)
                 and ( n <> EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
                 and ( n <> EVP_KDF_HKDF_MODE_EXPAND_ONLY) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                Exit(0);
            end;
            ctx.mode := n;
        end
        else
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY );
    if p <> nil then
    begin
        OPENSSL_clear_free(Pointer(ctx.key), ctx.key_len);
        ctx.key := nil;
        if  0>= OSSL_PARAM_get_octet_string(p, Pointer(ctx.key), 0,
                                         @ctx.key_len)  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT );
    if p <> nil then
    begin
        if (p.data_size <> 0)  and  (p.data <> nil) then
        begin
            OPENSSL_free(ctx.salt);
            ctx.salt := nil;
            if  0>= OSSL_PARAM_get_octet_string(p, Pointer(ctx.salt), 0,
                                             @ctx.salt_len)  then
                Exit(0);
        end;
    end;
    Result := 1;
end;

function kdf_hkdf_size( ctx : PKDF_HKDF):size_t;
var
  sz : integer;

  md : PEVP_MD;
begin
    md := ossl_prov_digest_md(@ctx.digest);
    if ctx.mode <> EVP_KDF_HKDF_MODE_EXTRACT_ONLY then
       Exit(SIZE_MAX);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    sz := EVP_MD_get_size(md);
    if sz < 0 then Exit(0);
    Result := sz;
end;

function kdf_hkdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PKDF_HKDF;
  p : POSSL_PARAM;
  sz : size_t;
begin
    ctx := PKDF_HKDF (vctx);
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
    begin
        sz := kdf_hkdf_size(ctx);
        if sz = 0 then Exit(0);
        Exit(OSSL_PARAM_set_size_t(p, sz));
    end;
    Result := -2;
end;

function kdf_hkdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
var
  known_gettable_ctx_params : array[0..1] of TOSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := OSSL_PARAM_END;

    Result := @known_gettable_ctx_params;
end;




function kdf_hkdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;

  ctx : PKDF_HKDF;

  q : Pointer;

  sz : size_t;
begin
    ctx := vctx;
    if params = nil then Exit(1);
    if  0>= hkdf_common_set_ctx_params(ctx, params) then
        Exit(0);
    { The info fields concatenate, so process them all }
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO );
    if p <> nil then
    begin
        ctx.info_len := 0;
        while p <> nil do
        begin
            q := PByte(@ctx.info) + ctx.info_len;
            sz := 0;
            if (p.data_size <> 0)
                 and  (p.data <> nil)
                 and  (0>= OSSL_PARAM_get_octet_string(p, Pointer(q),
                                                HKDF_MAXBUF - ctx.info_len,
                                                @sz))   then
                Exit(0);
            ctx.info_len  := ctx.info_len + sz;
            Inc(p);
            p := OSSL_PARAM_locate_const(p , OSSL_KDF_PARAM_INFO);
        end;
    end;
    Result := 1;
end;

function kdf_hkdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
var
  known_settable_ctx_params : array[0..7] of TOSSL_PARAM;
begin

    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, nil);
    known_settable_ctx_params[2] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[4] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
    known_settable_ctx_params[5] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
    known_settable_ctx_params[6] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, nil, 0);
    known_settable_ctx_params[7] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;




function kdf_hkdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_HKDF;
  md  : PEVP_MD;
  libctx : POSSL_LIB_CTX;
begin
    ctx := PKDF_HKDF (vctx);
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    if  (not ossl_prov_is_running())  or
        (0>= kdf_hkdf_set_ctx_params(ctx, params))  then
        Exit(0);
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    if ctx.key = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        Exit(0);
    end;
    if keylen = 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;

    case ctx.mode of

      EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
          Exit(HKDF_Extract(libctx, md, ctx.salt, ctx.salt_len,
                              ctx.key, ctx.key_len, key, keylen));
      EVP_KDF_HKDF_MODE_EXPAND_ONLY:
          Exit(HKDF_Expand(md, ctx.key, ctx.key_len, @ctx.info,
                             ctx.info_len, key, keylen));
      EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
      else
          Exit(HKDF(libctx, md, ctx.salt, ctx.salt_len,
                      ctx.key, ctx.key_len, @ctx.info, ctx.info_len, key, keylen));
    end;
end;

procedure kdf_hkdf_reset( vctx : Pointer);
var
  ctx : PKDF_HKDF;

  provctx : Pointer;
begin
    ctx := PKDF_HKDF (vctx);
    provctx := ctx.provctx;
    ossl_prov_digest_reset(@ctx.digest);
    OPENSSL_free(ctx.salt);
    OPENSSL_free(ctx.prefix);
    OPENSSL_free(ctx.&label);
    OPENSSL_clear_free(Pointer(ctx.data), ctx.data_len);
    OPENSSL_clear_free(Pointer(ctx.key), ctx.key_len);
    OPENSSL_cleanse(@ctx.info, ctx.info_len);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
end;

procedure kdf_hkdf_free( vctx : Pointer);
var
  ctx : PKDF_HKDF;
begin
    ctx := PKDF_HKDF (vctx);
    if ctx <> nil then begin
        kdf_hkdf_reset(ctx);
        OPENSSL_free(ctx);
    end;
end;

function kdf_hkdf_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_HKDF;
begin
    if  not ossl_prov_is_running()   then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof(ctx^));
    if ctx = nil then
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE)
    else
        ctx.provctx := provctx;
    Result := ctx;
end;


end.
