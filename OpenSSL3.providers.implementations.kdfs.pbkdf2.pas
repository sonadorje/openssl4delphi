unit OpenSSL3.providers.implementations.kdfs.pbkdf2;

interface
uses OpenSSL.Api, TypInfo;

function kdf_pbkdf2_new( provctx : Pointer):Pointer;
procedure kdf_pbkdf2_free( vctx : PKDF_PBKDF2);
procedure kdf_pbkdf2_reset( vctx : Pointer);
 function kdf_pbkdf2_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function kdf_pbkdf2_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function kdf_pbkdf2_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
function kdf_pbkdf2_gettable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
function kdf_pbkdf2_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function pbkdf2_set_membuf(var buffer : PByte; buflen : Psize_t;const p : POSSL_PARAM):integer;
function pbkdf2_derive(const pass : PUTF8Char; passlen : size_t;const salt : PByte; saltlen : integer; iter : uint64;const digest : PEVP_MD; key : PByte; keylen : size_t; lower_bound_checks : integer):integer;
procedure kdf_pbkdf2_cleanup( ctx : PKDF_PBKDF2);
procedure kdf_pbkdf2_init( ctx : PKDF_PBKDF2);

const ossl_kdf_pbkdf2_functions: array[0..8] of TOSSL_DISPATCH  = (
    ( function_id:OSSL_FUNC_KDF_NEWCTX; method:(code:@kdf_pbkdf2_new ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_FREECTX; method:(code:@kdf_pbkdf2_free ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_RESET; method:(code:@kdf_pbkdf2_reset ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_DERIVE; method:(code:@kdf_pbkdf2_derive ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS; method:(code:@kdf_pbkdf2_settable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@kdf_pbkdf2_set_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS; method:(code:@kdf_pbkdf2_gettable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@kdf_pbkdf2_get_ctx_params ;data:nil)),
    ( function_id:0; method:(code:nil;data:nil) )
);
  KDF_PBKDF2_MIN_KEY_LEN_BITS = 112;
  KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO = $FFFFFFFF;
  KDF_PBKDF2_MIN_ITERATIONS = 1000;
  KDF_PBKDF2_MIN_SALT_LEN = (128 div 8);

{$ifdef FIPS_MODULE}
 ossl_kdf_pbkdf2_default_checks = 1;
{$else}
 ossl_kdf_pbkdf2_default_checks = 0;
{$ENDIF}
implementation
uses OpenSSL3.Err ,   openssl3.crypto.params,
     OpenSSL3.openssl.params,                  openssl3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util,  openssl3.crypto.mem,
     openssl3.crypto.hmac.hmac,                openssl3.providers.prov_running,
     OpenSSL3.providers.common.capabilities,   openssl3.crypto.evp.evp_lib;


var // 1d arrays
  known_settable_ctx_params : array[0..6] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;


procedure kdf_pbkdf2_init( ctx : PKDF_PBKDF2);
var
  params : array[0..1] of TOSSL_PARAM;
  provctx : POSSL_LIB_CTX;
begin
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END ;
    provctx := PROV_LIBCTX_OF(ctx.provctx);
    params[0] := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha1, 0);
    if  0>= ossl_prov_digest_load_from_params(@ctx.digest, @params, provctx)  then
        { This is an error, but there is no way to indicate such directly }
        ossl_prov_digest_reset(@ctx.digest);
    ctx.iter := PKCS5_DEFAULT_ITER;
    ctx.lower_bound_checks := ossl_kdf_pbkdf2_default_checks;
end;

procedure kdf_pbkdf2_cleanup( ctx : PKDF_PBKDF2);
begin
    ossl_prov_digest_reset(@ctx.digest);
    OPENSSL_free(ctx.salt);
    OPENSSL_clear_free(ctx.pass, ctx.pass_len);
    //memset(ctx, 0, sizeof( ctx^));
    ctx^ := default(TKDF_PBKDF2);
end;

function pbkdf2_derive(const pass : PUTF8Char; passlen : size_t;const salt : PByte; saltlen : integer; iter : uint64;const digest : PEVP_MD; key : PByte; keylen : size_t; lower_bound_checks : integer):integer;
var
  ret      : integer;
  digtmp   : array[0..EVP_MAX_MD_SIZE-1] of Byte;
  itmp     : array[0..4-1] of Byte;
  p        : PByte;
  cplen,
  k,t1,t2,t3,
  tkeylen,
  mdlen    : integer;
  j        : Uint64;
  i        : Cardinal;
  hctx_tpl,
  hctx     : PHMAC_CTX;
  tp: PTypeInfo;
  label err;

begin

    ret := 0;
    i := 1;
    hctx_tpl := nil; hctx := nil;
    mdlen := EVP_MD_get_size(digest);
    if mdlen <= 0 then Exit(0);
    {
     * This check should always be done because keylen / mdlen >= (2^32 - 1)
     * results in an overflow of the loop counter 'i'.
     }
    if (keylen div mdlen ) >= KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    if lower_bound_checks > 0 then
    begin
        if (keylen * 8) < KDF_PBKDF2_MIN_KEY_LEN_BITS then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            Exit(0);
        end;
        if saltlen < KDF_PBKDF2_MIN_SALT_LEN then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            Exit(0);
        end;
        if iter < KDF_PBKDF2_MIN_ITERATIONS then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_ITERATION_COUNT);
            Exit(0);
        end;
    end;
    hctx_tpl := HMAC_CTX_new();
    if hctx_tpl = nil then Exit(0);
    p := key;
    tkeylen := keylen;
    if  0>= HMAC_Init_ex(hctx_tpl, StrtoBytes(pass), passlen*Char_Size, digest, nil) then
       goto err;
    hctx := HMAC_CTX_new();
    if hctx = nil then
       goto err;
    while (tkeylen>0) do
    begin
        if tkeylen > mdlen then
            cplen := mdlen
        else
            cplen := tkeylen;
        {
         * We are unlikely to ever use more than 256 blocks (5120 bits!) but
         * just in case...
         }
        itmp[0] := ((i  shr  24) and $ff);
        itmp[1] := ((i  shr  16) and $ff);
        itmp[2] := ((i  shr  8) and $ff);
        itmp[3] := (i and $ff);
        if  0>= HMAC_CTX_copy(hctx, hctx_tpl ) then
            goto err;

        t1 := HMAC_Update(hctx, salt, saltlen);
        t2 := HMAC_Update(hctx, @itmp, 4);
        t3 := HMAC_Final(hctx, @digtmp, nil);
        if  (0 >= t1) or (0 >= t2) or   (0 >= t3)  then
            goto err;
        memcpy(p, @digtmp, cplen);
        j := 1;
        while j<= iter-1 do
        begin
            if  0>= HMAC_CTX_copy(hctx, hctx_tpl  ) then
                goto err;
            if  (0>= HMAC_Update(hctx, @digtmp, mdlen)) or
                (0>= HMAC_Final(hctx, @digtmp, nil))   then
                goto err;
            for k := 0 to cplen-1 do
                p[k]  := p[k] xor (digtmp[k]);
            inc(j);
        end;
        tkeylen  := tkeylen - cplen;
        Inc(i);
        p  := p + cplen;
    end;
    ret := 1;
err:
    HMAC_CTX_free(hctx);
    HMAC_CTX_free(hctx_tpl);
    Result := ret;
end;

function pbkdf2_set_membuf(var buffer : PByte; buflen : Psize_t;const p : POSSL_PARAM):integer;
begin
    //OPENSSL_clear_free( Pointer(buffer), buflen^);
    FillChar(buffer, buflen^, 0);
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

function kdf_pbkdf2_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, SIZE_MAX));
    Result := -2;
end;



function kdf_pbkdf2_gettable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := OSSL_PARAM_END;
    Result := @known_gettable_ctx_params;
end;


function kdf_pbkdf2_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  p        : POSSL_PARAM;
  ctx      : PKDF_PBKDF2;
  provctx  : POSSL_LIB_CTX;
  pkcs5    : integer;
  iter,
  min_iter : uint64;
begin
    ctx := vctx;
    provctx := PROV_LIBCTX_OF(ctx.provctx);
    if params = nil then Exit(1);
    if  0>= ossl_prov_digest_load_from_params(@ctx.digest, params, provctx) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS5 );
    if p <> nil then
    begin
        if  0>= OSSL_PARAM_get_int(p, @pkcs5) then
            Exit(0);
        ctx.lower_bound_checks := 0;
        pkcs5 := 0;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD );
    if p <> nil then
        if ( 0>= pbkdf2_set_membuf(ctx.pass, @ctx.pass_len, p))  then
            Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT );
    if p  <> nil then
    begin
        if (ctx.lower_bound_checks <> 0 )
             and  (p.data_size < KDF_PBKDF2_MIN_SALT_LEN) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            Exit(0);
        end;
        if  0>= pbkdf2_set_membuf(ctx.salt, @ctx.salt_len, p)  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER );
    if p <> nil then
    begin
        if  0>= OSSL_PARAM_get_uint64(p, @iter) then
            Exit(0);
        min_iter := get_result(ctx.lower_bound_checks <> 0 , KDF_PBKDF2_MIN_ITERATIONS , 1);
        if iter < min_iter then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_ITERATION_COUNT);
            Exit(0);
        end;
        ctx.iter := iter;
    end;
    Result := 1;
end;



function kdf_pbkdf2_settable_ctx_params( ctx, p_ctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, nil, 0);
    known_settable_ctx_params[4] := _OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, nil);
    known_settable_ctx_params[5] := _OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS5, nil);
    known_settable_ctx_params[6] := OSSL_PARAM_END ;
   
    Result := @known_settable_ctx_params;
end;

function kdf_pbkdf2_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_PBKDF2;
  md  : PEVP_MD;
begin
    ctx := PKDF_PBKDF2(vctx);
    if  (not ossl_prov_is_running) or
        (0>= kdf_pbkdf2_set_ctx_params(ctx, params)) then
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
    Result := pbkdf2_derive(PUTF8Char(ctx.pass), ctx.pass_len,
                            ctx.salt, ctx.salt_len, ctx.iter,
                            md, key, keylen, ctx.lower_bound_checks);
end;

procedure kdf_pbkdf2_reset( vctx : Pointer);
var
  ctx : PKDF_PBKDF2;
  provctx : Pointer;
begin
    ctx := PKDF_PBKDF2  (vctx);
    provctx := ctx.provctx;
    kdf_pbkdf2_cleanup(ctx);
    ctx.provctx := provctx;
    kdf_pbkdf2_init(ctx);
end;

procedure kdf_pbkdf2_free( vctx : PKDF_PBKDF2);
begin
    if vctx <> nil then
    begin
        kdf_pbkdf2_cleanup(vctx);
        OPENSSL_free(vctx);
    end;
end;

function kdf_pbkdf2_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_PBKDF2;
begin
    if  not ossl_prov_is_running() then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof(ctx^));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.provctx := provctx;
    kdf_pbkdf2_init(ctx);
    Result := ctx;
end;


end.
