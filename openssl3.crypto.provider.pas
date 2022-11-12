unit openssl3.crypto.provider;

interface
uses OpenSSL.Api;

type
  Tcb_func = function( provider : POSSL_PROVIDER; cbdata : Pointer):integer;

function OSSL_PROVIDER_try_load(libctx : POSSL_LIB_CTX;const name : PUTF8Char; retain_fallbacks : integer):POSSL_PROVIDER;
function OSSL_PROVIDER_load(libctx : POSSL_LIB_CTX;const name : PUTF8Char):POSSL_PROVIDER;
function OSSL_PROVIDER_unload( prov : POSSL_PROVIDER):integer;
function OSSL_PROVIDER_gettable_params(const prov : POSSL_PROVIDER):POSSL_PARAM;
function OSSL_PROVIDER_get_params(const prov : POSSL_PROVIDER; params : POSSL_PARAM):integer;
function OSSL_PROVIDER_query_operation(const prov : POSSL_PROVIDER; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;
function OSSL_PROVIDER_get0_provider_ctx(const prov : POSSL_PROVIDER):Pointer;
function OSSL_PROVIDER_get0_dispatch(const prov : POSSL_PROVIDER):POSSL_DISPATCH;
function OSSL_PROVIDER_self_test(const prov : POSSL_PROVIDER):integer;
function OSSL_PROVIDER_get_capabilities(const prov : POSSL_PROVIDER; capability : PUTF8Char; cb : POSSL_CALLBACK; arg : Pointer):integer;
function OSSL_PROVIDER_add_builtin(libctx : POSSL_LIB_CTX;const name : PUTF8Char;init_fn : TOSSL_provider_init_fn):integer;
function OSSL_PROVIDER_get0_name(const prov : POSSL_PROVIDER):PUTF8Char;
function OSSL_PROVIDER_do_all( ctx : POSSL_LIB_CTX; provider : POSSL_PROVIDER; cb: Tcb_func; cbdata : Pointer):integer;
function ossl_provider_activate( prov : POSSL_PROVIDER; upcalls, aschild : integer):integer;
procedure OSSL_PROVIDER_unquery_operation(const prov : POSSL_PROVIDER; operation_id : integer;const algs : POSSL_ALGORITHM);

implementation
uses openssl3.crypto.provider_core, OpenSSL3.Err, openssl3.crypto.o_str;


function ossl_provider_activate( prov : POSSL_PROVIDER; upcalls, aschild : integer):integer;
var
  count : integer;
begin
    if prov = nil then
       Exit(0);
{$IFNDEF FIPS_MODULE}
    {
     * If aschild is true, then we only actually do the activation if the
     * provider is a child. If its not, this is still success.
     }
    if (aschild > 0) and  (0>= prov.ischild) then
       Exit(1);
{$ENDIF}
    count := provider_activate(prov, 1, upcalls);
    if count > 0 then
        Exit(get_result(count = 1 , provider_flush_store_cache(prov) , 1));
    Result := 0;
end;

function OSSL_PROVIDER_try_load(libctx : POSSL_LIB_CTX;const name : PUTF8Char; retain_fallbacks : integer):POSSL_PROVIDER;
var
  prov,actual : POSSL_PROVIDER;
  isnew : integer;
begin
    prov := nil;
    isnew := 0;
    { Find it or create it }
    prov := ossl_provider_find(libctx, name, 0);
    if prov =  nil then
    begin
        prov := ossl_provider_new(libctx, name, nil, 0);
        if (prov = nil) then
            Exit(nil);
        isnew := 1;
    end;
    if 0>= ossl_provider_activate(prov, 1, 0 )then
    begin
        ossl_provider_free(prov);
        Exit(nil);
    end;
    actual := prov;
    if (isnew > 0)  and  (0>= ossl_provider_add_to_store(prov, @actual, retain_fallbacks)) then
    begin
        ossl_provider_deactivate(prov, 1);
        ossl_provider_free(prov);
        Exit(nil);
    end;
    if actual <> prov then
    begin
        if 0>= ossl_provider_activate(actual, 1, 0) then
        begin
            ossl_provider_free(actual);
            Exit(nil);
        end;
    end;
    Result := actual;
end;


function OSSL_PROVIDER_load(libctx : POSSL_LIB_CTX;const name : PUTF8Char):POSSL_PROVIDER;
begin
    { Any attempt to load a provider disables auto-loading of defaults }
    if ossl_provider_disable_fallback_loading(libctx ) > 0 then
        Exit(OSSL_PROVIDER_try_load(libctx, name, 0));
    Result := nil;
end;


function OSSL_PROVIDER_unload( prov : POSSL_PROVIDER):integer;
begin
    if 0>= ossl_provider_deactivate(prov, 1) then
        Exit(0);
    ossl_provider_free(prov);
    Result := 1;
end;


function OSSL_PROVIDER_gettable_params(const prov : POSSL_PROVIDER):POSSL_PARAM;
begin
    Result := ossl_provider_gettable_params(prov);
end;


function OSSL_PROVIDER_get_params(const prov : POSSL_PROVIDER; params : POSSL_PARAM):integer;
begin
    Result := ossl_provider_get_params(prov, params);
end;


function OSSL_PROVIDER_query_operation(const prov : POSSL_PROVIDER; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;
begin
    Result := ossl_provider_query_operation(prov, operation_id, no_cache);
end;


procedure OSSL_PROVIDER_unquery_operation(const prov : POSSL_PROVIDER; operation_id : integer;const algs : POSSL_ALGORITHM);
begin
    ossl_provider_unquery_operation(prov, operation_id, algs);
end;


function OSSL_PROVIDER_get0_provider_ctx(const prov : POSSL_PROVIDER):Pointer;
begin
    Result := ossl_provider_prov_ctx(prov);
end;


function OSSL_PROVIDER_get0_dispatch(const prov : POSSL_PROVIDER):POSSL_DISPATCH;
begin
    Result := ossl_provider_get0_dispatch(prov);
end;


function OSSL_PROVIDER_self_test(const prov : POSSL_PROVIDER):integer;
begin
    Result := ossl_provider_self_test(prov);
end;


function OSSL_PROVIDER_get_capabilities(const prov : POSSL_PROVIDER; capability : PUTF8Char; cb : POSSL_CALLBACK; arg : Pointer):integer;
begin
    Result := ossl_provider_get_capabilities(prov, capability, cb, arg);
end;


function OSSL_PROVIDER_add_builtin(libctx : POSSL_LIB_CTX;const name : PUTF8Char;init_fn : TOSSL_provider_init_fn):integer;
var
  entry : TOSSL_PROVIDER_INFO;
begin
    if (name = nil)  or  (not Assigned(init_fn)) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    memset(@entry, 0, sizeof(entry));
    OPENSSL_strdup(entry.name ,name);
    if entry.name = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    entry.init := init_fn;
    if 0>= ossl_provider_info_add_to_store(libctx, @entry) then
    begin
        ossl_provider_info_clear(@entry);
        Exit(0);
    end;
    Result := 1;
end;


function OSSL_PROVIDER_get0_name(const prov : POSSL_PROVIDER):PUTF8Char;
begin
    Result := ossl_provider_name(prov);
end;


function OSSL_PROVIDER_do_all( ctx : POSSL_LIB_CTX; provider : POSSL_PROVIDER; cb: Tcb_func; cbdata : Pointer):integer;
begin
    Result := ossl_provider_doall_activated(ctx, cb, cbdata);
end;


end.
