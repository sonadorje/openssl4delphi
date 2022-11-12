unit openssl3.crypto.provider.provider_ctx;

interface
uses OpenSSL.Api;

function ossl_prov_ctx_new:PPROV_CTX;
procedure ossl_prov_ctx_free( ctx : PPROV_CTX);
procedure ossl_prov_ctx_set0_libctx( ctx : PPROV_CTX; libctx : POSSL_LIB_CTX);
procedure ossl_prov_ctx_set0_handle(ctx : PPROV_CTX;const handle : POSSL_CORE_HANDLE);
procedure ossl_prov_ctx_set0_core_bio_method( ctx : PPROV_CTX; corebiometh : PBIO_METHOD);
function PROV_LIBCTX_OF(provctx: Pointer):POSSL_LIB_CTX;
function ossl_prov_ctx_get0_libctx( ctx : PPROV_CTX):POSSL_LIB_CTX;
function ossl_prov_ctx_get0_handle( ctx : PPROV_CTX):POSSL_CORE_HANDLE;
function ossl_prov_ctx_get0_core_bio_method( ctx : PPROV_CTX):PBIO_METHOD;


implementation

uses
    openssl3.crypto.mem;



function ossl_prov_ctx_get0_core_bio_method( ctx : PPROV_CTX):PBIO_METHOD;
begin
    if ctx = nil then Exit(nil);
    Result := ctx.corebiometh;
end;

function ossl_prov_ctx_get0_handle( ctx : PPROV_CTX):POSSL_CORE_HANDLE;
begin
    if ctx = nil then Exit(nil);
    Result := ctx.handle;
end;

function ossl_prov_ctx_get0_libctx( ctx : PPROV_CTX):POSSL_LIB_CTX;
begin
    if ctx = nil then
       Exit(nil);
    Result := ctx.libctx;
end;

function PROV_LIBCTX_OF(provctx: Pointer):POSSL_LIB_CTX;
begin
   Result := ossl_prov_ctx_get0_libctx((provctx))
end;

procedure ossl_prov_ctx_set0_core_bio_method( ctx : PPROV_CTX; corebiometh : PBIO_METHOD);
begin
    if ctx <> nil then
       ctx.corebiometh := corebiometh;
end;


procedure ossl_prov_ctx_set0_handle(ctx : PPROV_CTX;const handle : POSSL_CORE_HANDLE);
begin
    if ctx <> nil then ctx.handle := handle;
end;

procedure ossl_prov_ctx_set0_libctx( ctx : PPROV_CTX; libctx : POSSL_LIB_CTX);
begin
    if ctx <> nil then ctx.libctx := libctx;
end;

procedure ossl_prov_ctx_free( ctx : PPROV_CTX);
begin
    OPENSSL_free(ctx);
end;


function ossl_prov_ctx_new:PPROV_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(TPROV_CTX));
end;



end.
