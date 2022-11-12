unit OpenSSL3.providers.implementations.kdfs.pkcs12kdf;

interface
uses OpenSSL.Api;

function kdf_pkcs12_new( provctx : Pointer):Pointer;
procedure kdf_pkcs12_free( vctx : Pointer);
procedure kdf_pkcs12_reset( vctx : Pointer);
function kdf_pkcs12_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
 function kdf_pkcs12_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_pkcs12_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function kdf_pkcs12_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function kdf_pkcs12_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function pkcs12kdf_set_membuf(var buffer : PByte; buflen : Psize_t;const p : POSSL_PARAM):integer;
function pkcs12kdf_derive(const pass : PByte; passlen : size_t;const salt : PByte; saltlen : size_t; id : integer; iter : uint64;const md_type : PEVP_MD; &out : PByte; n : size_t):integer;
procedure kdf_pkcs12_cleanup( ctx : PKDF_PKCS12);

const  ossl_kdf_pkcs12_functions: array[0..8] of TOSSL_DISPATCH = (
    ( function_id:OSSL_FUNC_KDF_NEWCTX; method:(code:@kdf_pkcs12_new ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_FREECTX; method:(code:@kdf_pkcs12_free ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_RESET; method:(code:@kdf_pkcs12_reset ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_DERIVE; method:(code:@kdf_pkcs12_derive ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS; method:(code:@kdf_pkcs12_settable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@kdf_pkcs12_set_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;
                 method:(code:@kdf_pkcs12_gettable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GET_CTX_PARAMS;
                 method:(code:@kdf_pkcs12_get_ctx_params ;data:nil)),
    ( function_id:0;method:(code:nil ;data:nil))
);






var // 1d arrays
  known_settable_ctx_params : array[0..6] of TOSSL_PARAM;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;



implementation
uses OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     openssl3.crypto.evp.digest,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,openssl3.crypto.evp.evp_lib;





procedure kdf_pkcs12_cleanup( ctx : PKDF_PKCS12);
begin
    ossl_prov_digest_reset(@ctx.digest);
    OPENSSL_free(ctx.salt);
    OPENSSL_clear_free(Pointer(ctx.pass), ctx.pass_len);
    memset(ctx, 0, sizeof( ctx^));
end;




function pkcs12kdf_derive(const pass : PByte; passlen : size_t;const salt : PByte; saltlen : size_t; id : integer; iter : uint64;const md_type : PEVP_MD; &out : PByte; n : size_t):integer;
var
  B,  D,   I,  p,  Ai       : PByte;
  Slen,Plen, Ilen,
  i1,j,k,u,v        : size_t;
  iter_cnt : uint64;
  ret,
  ui,vi       : integer;
  ctx      : PEVP_MD_CTX;
  Ij       : PByte;
  c        : uint16;
  label _end;

begin
    B := nil;
    D := nil;
    I := nil;
    p := nil;
    Ai := nil;
    ret := 0;
    ctx := nil;
    ctx := EVP_MD_CTX_new();
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _end;
    end;
    vi := EVP_MD_get_block_size(md_type);
    ui := EVP_MD_get_size(md_type);
    if (ui <= 0)  or  (vi <= 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_SIZE);
        goto _end;
    end;
    u := size_t(ui);
    v := size_t(vi);
    D := OPENSSL_malloc(v);
    Ai := OPENSSL_malloc(u);
    B := OPENSSL_malloc(v + 1);
    Slen := v *  ((saltlen + v - 1) div v);
    if (passlen <> 0) then
        Plen := v *  ((passlen + v - 1) div v)
    else
        Plen := 0;
    Ilen := Slen + Plen;
    I := OPENSSL_malloc(Ilen);
    if (D = nil)  or  (Ai = nil)  or  (B = nil)  or  (I = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _end;
    end;
    for i1 := 0 to v-1 do
        D[i1] := id;
    p := I;
    for i1 := 0 to Slen-1 do
    begin
        p^ :=  (salt[i1 mod saltlen]);
        inc(p);
    end;
    for i1 := 0 to Plen-1 do
    begin
       p^ := (pass[i1 mod passlen]);
       Inc(p);
    end;

    while true do
    begin
        if  (0>= EVP_DigestInit_ex(ctx, md_type, nil))  or
            (0>= EVP_DigestUpdate(ctx, D, v))
             or   (0>= EVP_DigestUpdate(ctx, I, Ilen))
             or   (0>= EVP_DigestFinal_ex(ctx, Ai, nil)) then
            goto _end;
        iter_cnt := 1 ;
        while iter_cnt <= iter-1 do
        begin
            if  (0>= EVP_DigestInit_ex(ctx, md_type, nil))   or
                (0>= EVP_DigestUpdate(ctx, Ai, u))
                 or   (0>= EVP_DigestFinal_ex(ctx, Ai, nil)) then
                goto _end;
            Inc (iter_cnt);
        end;
        memcpy(&out, Ai, get_result(n < u , n , u));
        if u >= n then
        begin
            ret := 1;
            break;
        end;
        n  := n - u;
        &out  := &out + u;
        for j := 0 to v-1 do
            B[j] := Ai[j mod u];

        j := 0;
        while ( j < Ilen ) do
        begin
            Ij := I + j;
            c := 1;

            k := v;
            while k > 0 do
            begin
                Dec(k);
                c  := c + (Ij[k] + B[k]);
                Ij[k] := c;
                c  := c shr 8;
            end;
            j := j+v;
        end;
    end;
 _end:
    OPENSSL_free(Ai);
    OPENSSL_free(B);
    OPENSSL_free(D);
    OPENSSL_free(I);
    EVP_MD_CTX_free(ctx);
    Result := ret;
end;

function pkcs12kdf_set_membuf(var buffer : PByte; buflen : Psize_t;const p : POSSL_PARAM):integer;
begin
    OPENSSL_clear_free( Pointer(buffer), buflen^);
    buffer := nil;
    buflen^ := 0;
    if p.data_size = 0 then
    begin
        buffer := OPENSSL_malloc(1);
        if buffer = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end
    else
    if (p.data <> nil) then
    begin
        if  0>= OSSL_PARAM_get_octet_string(p, Pointer(buffer), 0, buflen)  then
            Exit(0);
    end;
    Result := 1;
end;

function kdf_pkcs12_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, SIZE_MAX));
    Result := -2;
end;

function kdf_pkcs12_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[0] := OSSL_PARAM_END;
    Result := @known_gettable_ctx_params;
end;

function kdf_pkcs12_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_PKCS12;
  p   : POSSL_PARAM;
  provctx : POSSL_LIB_CTX;
begin
    ctx := vctx;
    provctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    if  0>=ossl_prov_digest_load_from_params(@ctx.digest, params, provctx) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD);
    if p <> nil then
        if ( 0>= pkcs12kdf_set_membuf(ctx.pass, @ctx.pass_len, p))  then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if p <> nil then
        if ( 0>= pkcs12kdf_set_membuf(ctx.salt, @ctx.salt_len, p)) then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS12_ID);
    if p <> nil then
        if ( 0>= OSSL_PARAM_get_int(p, @ctx.id))  then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER);
    if p <> nil then
        if ( 0>= OSSL_PARAM_get_uint64(p, @ctx.iter)) then
            Exit(0);
    Result := 1;
end;


function kdf_pkcs12_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
    known_settable_ctx_params[4] := _OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, nil);
    known_settable_ctx_params[5] := _OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS12_ID, nil);
    known_settable_ctx_params[6] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;



function kdf_pkcs12_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_PKCS12;
  md: PEVP_MD;
begin
    ctx := PKDF_PKCS12(vctx);
    if  (not ossl_prov_is_running) or
        (0>= kdf_pkcs12_set_ctx_params(ctx, params))  then
        Exit(0);
    if ctx.pass = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        Exit(0);
    end;
    if ctx.salt = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        Exit(0);
    end;
    md := ossl_prov_digest_md(@ctx.digest);
    Exit(pkcs12kdf_derive(ctx.pass, ctx.pass_len, ctx.salt, ctx.salt_len,
                            ctx.id, ctx.iter, md, key, keylen));
end;



procedure kdf_pkcs12_reset( vctx : Pointer);
var
  ctx : PKDF_PKCS12;

  provctx : Pointer;
begin
    ctx := PKDF_PKCS12(vctx);
    provctx := ctx.provctx;
    kdf_pkcs12_cleanup(ctx);
    ctx.provctx := provctx;
end;



procedure kdf_pkcs12_free( vctx : Pointer);
var
  ctx : PKDF_PKCS12;
begin
    ctx := PKDF_PKCS12(vctx);
    if ctx <> nil then
    begin
        kdf_pkcs12_cleanup(ctx);
        OPENSSL_free(ctx);
    end;
end;


function kdf_pkcs12_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_PKCS12;
begin
    if  not ossl_prov_is_running( )  then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.provctx := provctx;
    Result := ctx;
end;

end.
