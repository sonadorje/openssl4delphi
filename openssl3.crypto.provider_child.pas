unit openssl3.crypto.provider_child;

interface
 uses OpenSSL.Api;


 function ossl_provider_free_parent( prov : POSSL_PROVIDER; deactivate : integer):integer;
 function child_prov_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
 procedure child_prov_ossl_ctx_free( vgbl : Pointer);

 const child_prov_ossl_ctx_method: TOSSL_LIB_CTX_METHOD  = (
    priority :OSSL_LIB_CTX_METHOD_LOW_PRIORITY;
    new_func:child_prov_ossl_ctx_new;
    free_func:child_prov_ossl_ctx_free
 );

function ossl_provider_up_ref_parent( prov : POSSL_PROVIDER; activate : integer):integer;
procedure ossl_provider_deinit_child( ctx : POSSL_LIB_CTX);

implementation


uses
   openssl3.crypto.context, openssl3.crypto.provider_core, openssl3.crypto.mem,
   OpenSSL3.threads_none;



procedure ossl_provider_deinit_child( ctx : POSSL_LIB_CTX);
var
  gbl : Pchild_prov_globals;
begin
    gbl := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                @child_prov_ossl_ctx_method);
    if gbl = nil then Exit;
    gbl.c_provider_deregister_child_cb(gbl.handle);
end;



function ossl_provider_up_ref_parent( prov : POSSL_PROVIDER; activate : integer):integer;
var
  gbl: Pchild_prov_globals;
  ctx: POSSL_LIB_CTX;
begin
    ctx := ossl_provider_libctx(prov);
    gbl := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                @child_prov_ossl_ctx_method);
    if gbl = nil then Exit(0);
    Result := gbl.c_prov_up_ref(ossl_provider_get_parent(prov), activate);
end;


procedure child_prov_ossl_ctx_free( vgbl : Pointer);
var
  gbl : Pchild_prov_globals;
begin
    gbl := vgbl;
    CRYPTO_THREAD_lock_free(gbl.lock);
    OPENSSL_free(gbl);
end;



function child_prov_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
begin
    Result := OPENSSL_zalloc(sizeof(child_prov_globals));
end;

function ossl_provider_free_parent( prov : POSSL_PROVIDER; deactivate : integer):integer;
var
  gbl : Pchild_prov_globals;
  ctx: POSSL_LIB_CTX;
begin
    ctx := ossl_provider_libctx(prov);
    gbl := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                @child_prov_ossl_ctx_method);
    if gbl = nil then Exit(0);
    Result := gbl.c_prov_free(ossl_provider_get_parent(prov), deactivate);
end;

end.
