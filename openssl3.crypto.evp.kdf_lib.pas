unit openssl3.crypto.evp.kdf_lib;

interface
uses OpenSSL.Api;


function EVP_KDF_CTX_new( kdf : PEVP_KDF):PEVP_KDF_CTX;
function EVP_KDF_derive(ctx : PEVP_KDF_CTX; key : PByte; keylen : size_t;const params : POSSL_PARAM):int;
procedure EVP_KDF_CTX_free( ctx : PEVP_KDF_CTX);
function EVP_KDF_CTX_get_kdf_size( ctx : PEVP_KDF_CTX):size_t;
function EVP_KDF_CTX_dup(const src : PEVP_KDF_CTX):PEVP_KDF_CTX;
function EVP_KDF_CTX_set_params(ctx : PEVP_KDF_CTX;const params : POSSL_PARAM):integer;

function EVP_KDF_get0_provider(const kdf : PEVP_KDF):POSSL_PROVIDER;

implementation

uses
   openssl3.crypto.mem,   OpenSSL3.Err,     openssl3.crypto.provider_core,
   openssl3.crypto.params,
   openssl3.crypto.evp.kdf_meth,            OpenSSL3.openssl.params ;

function EVP_KDF_get0_provider(const kdf : PEVP_KDF):POSSL_PROVIDER;
begin
    Result := kdf.prov;
end;

function EVP_KDF_CTX_set_params(ctx : PEVP_KDF_CTX;const params : POSSL_PARAM):integer;
begin
    if Assigned(ctx.meth.set_ctx_params) then
       Exit(ctx.meth.set_ctx_params(ctx.algctx, params));
    Result := 1;
end;



function EVP_KDF_CTX_dup(const src : PEVP_KDF_CTX):PEVP_KDF_CTX;
var
  dst : PEVP_KDF_CTX;
begin
    if (src = nil)  or  (src.algctx = nil)  or  (not Assigned(src.meth.dupctx)) then
       Exit(nil);
    dst := OPENSSL_malloc(sizeof( dst^));
    if dst = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    memcpy(dst, src, sizeof( dst^));
    if 0>=EVP_KDF_up_ref(dst.meth) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(dst);
        Exit(nil);
    end;
    dst.algctx := src.meth.dupctx(src.algctx);
    if dst.algctx = nil then begin
        EVP_KDF_CTX_free(dst);
        Exit(nil);
    end;
    Result := dst;
end;



function EVP_KDF_CTX_get_kdf_size( ctx : PEVP_KDF_CTX):size_t;
var
  params : array of TOSSL_PARAM;
  s : size_t;
begin
    params:=[OSSL_PARAM_END, OSSL_PARAM_END];
    s := 0;
    if ctx = nil then Exit(0);
    params[0] := OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, @s);
    if (Assigned(ctx.meth.get_ctx_params))
         and  (ctx.meth.get_ctx_params(ctx.algctx, @params) > 0 ) then
            Exit(s);
    if (Assigned(ctx.meth.get_params))
         and  (ctx.meth.get_params(@params) > 0)  then
            Exit(s);
    Result := 0;
end;

procedure EVP_KDF_CTX_free( ctx : PEVP_KDF_CTX);
begin
    if ctx = nil then exit;
    ctx.meth.freectx(ctx.algctx);
    ctx.algctx := nil;
    EVP_KDF_free(ctx.meth);
    OPENSSL_free(ctx);
end;


function EVP_KDF_derive(ctx : PEVP_KDF_CTX; key : PByte; keylen : size_t;const params : POSSL_PARAM):int;
begin
    if ctx = nil then Exit(0);
    Result := ctx.meth.derive(ctx.algctx, key, keylen, params);
end;


function EVP_KDF_CTX_new( kdf : PEVP_KDF):PEVP_KDF_CTX;
var
  ctx : PEVP_KDF_CTX;
begin
    ctx := nil;
    if kdf = nil then Exit(nil);
    ctx := OPENSSL_zalloc(sizeof(TEVP_KDF_CTX));
    ctx.algctx := kdf.newctx(ossl_provider_ctx(kdf.prov ));
    if (ctx = nil)
         or  (ctx.algctx =  nil)
         or  (0>= EVP_KDF_up_ref(kdf)) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        if ctx <> nil then
           kdf.freectx(ctx.algctx);
        OPENSSL_free(ctx);
        ctx := nil;
    end
    else
    begin
        ctx.meth := kdf;
    end;
    Result := ctx;
end;



end.
