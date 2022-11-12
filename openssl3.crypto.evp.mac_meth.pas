unit openssl3.crypto.evp.mac_meth;

interface
uses OpenSSL.Api;

function EVP_MAC_get0_provider(const mac : PEVP_MAC):POSSL_PROVIDER;
function EVP_MAC_settable_ctx_params(const mac : PEVP_MAC):POSSL_PARAM;
function evp_mac_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_mac_new:Pointer;
procedure evp_mac_free( vmac : Pointer);
function EVP_MAC_fetch(libctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_MAC;
function evp_mac_up_ref( vmac : Pointer):integer;

implementation

uses openssl3.crypto.provider_core, openssl3.crypto.mem,   OpenSSL3.Err,
     openssl3.crypto.core_algorithm,  OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.evp.evp_fetch,
     OpenSSL3.threads_none, openssl3.include.internal.refcount;

function evp_mac_up_ref( vmac : Pointer):integer;
var
  mac : PEVP_MAC;
  ref : integer;
begin
    mac := vmac;
    ref := 0;
    CRYPTO_UP_REF(mac.refcnt, ref, mac.lock);
    Result := 1;
end;

function EVP_MAC_fetch(libctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_MAC;
begin
    Exit(evp_generic_fetch(libctx, OSSL_OP_MAC, algorithm, properties,
                             evp_mac_from_algorithm, evp_mac_up_ref,
                             evp_mac_free));
end;

procedure evp_mac_free( vmac : Pointer);
var
  mac : PEVP_MAC;
  ref : integer;
begin
    mac := vmac;
    ref := 0;
    if mac = nil then exit;
    CRYPTO_DOWN_REF(mac.refcnt, ref, mac.lock);
    if ref > 0 then exit;
    OPENSSL_free(mac.type_name);
    ossl_provider_free(mac.prov);
    CRYPTO_THREAD_lock_free(mac.lock);
    OPENSSL_free(mac);
end;

function evp_mac_new:Pointer;
var
  mac : PEVP_MAC;
begin
    mac := nil;
    mac := OPENSSL_zalloc(sizeof( mac^) );
    if mac <> nil then
       mac.lock := CRYPTO_THREAD_lock_new();
    if (mac = nil)
         or  (mac.lock = nil)then
    begin
        evp_mac_free(mac);
        Exit(nil);
    end;
    mac.refcnt := 1;
    Result := mac;
end;

function evp_mac_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
    fns      : POSSL_DISPATCH;
    mac      : PEVP_MAC;
    fnmaccnt,fnctxcnt : integer;
begin
    fns := algodef._implementation;
    mac := nil;
    fnmaccnt := 0; fnctxcnt := 0;
    mac := evp_mac_new( );
    if mac =  nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    mac.name_id := name_id;
    mac.type_name := ossl_algorithm_get1_first_name(algodef );
    if mac.type_name = nil then
    begin
        evp_mac_free(mac);
        Exit(nil);
    end;
    mac.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_MAC_NEWCTX:
        begin
            if Assigned(mac.newctx) then break;
            mac.newctx := _OSSL_FUNC_mac_newctx(fns);
            Inc(fnctxcnt);
        end;
        OSSL_FUNC_MAC_DUPCTX:
        begin
            if Assigned(mac.dupctx) then break;
            mac.dupctx := _OSSL_FUNC_mac_dupctx(fns);
        end;
        OSSL_FUNC_MAC_FREECTX:
        begin
            if Assigned(mac.freectx ) then break;
            mac.freectx := _OSSL_FUNC_mac_freectx(fns);
            Inc(fnctxcnt);
        end;
        OSSL_FUNC_MAC_INIT:
        begin
            if Assigned(mac.init) then break;
            mac.init := _OSSL_FUNC_mac_init(fns);
            Inc(fnmaccnt);
        end;
        OSSL_FUNC_MAC_UPDATE:
        begin
            if Assigned(mac.update ) then break;
            mac.update := _OSSL_FUNC_mac_update(fns);
            Inc(fnmaccnt);
        end;
        OSSL_FUNC_MAC_FINAL:
        begin
            if Assigned(mac.final ) then break;
            mac.final := _OSSL_FUNC_mac_final(fns);
            PostInc(fnmaccnt);
        end;
        OSSL_FUNC_MAC_GETTABLE_PARAMS:
        begin
            if Assigned(mac.gettable_params ) then break;
            mac.gettable_params := _OSSL_FUNC_mac_gettable_params(fns);
        end;
        OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS:
        begin
            if Assigned(mac.gettable_ctx_params ) then break;
            mac.gettable_ctx_params := _OSSL_FUNC_mac_gettable_ctx_params(fns);
        end;
        OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS:
        begin
            if Assigned(mac.settable_ctx_params ) then break;
            mac.settable_ctx_params := _OSSL_FUNC_mac_settable_ctx_params(fns);
        end;
        OSSL_FUNC_MAC_GET_PARAMS:
        begin
            if Assigned(mac.get_params ) then break;
            mac.get_params := _OSSL_FUNC_mac_get_params(fns);
        end;
        OSSL_FUNC_MAC_GET_CTX_PARAMS:
        begin
            if Assigned(mac.get_ctx_params ) then break;
            mac.get_ctx_params := _OSSL_FUNC_mac_get_ctx_params(fns);
        end;
        OSSL_FUNC_MAC_SET_CTX_PARAMS:
        begin
            if Assigned(mac.set_ctx_params ) then break;
            mac.set_ctx_params := _OSSL_FUNC_mac_set_ctx_params(fns);
        end;
        end;
        Inc(fns);
    end;
    if (fnmaccnt <> 3) or  (fnctxcnt <> 2) then
    begin
        {
         * In order to be a consistent set of functions we must have at least
         * a complete set of 'mac' functions, and a complete set of context
         * management functions, as well as the size function.
         }
        evp_mac_free(mac);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    mac.prov := prov;
    if prov <> nil then ossl_provider_up_ref(prov);
    Result := mac;
end;

function EVP_MAC_get0_provider(const mac : PEVP_MAC):POSSL_PROVIDER;
begin
    Result := mac.prov;
end;


function EVP_MAC_settable_ctx_params(const mac : PEVP_MAC):POSSL_PARAM;
var
  alg : Pointer;
begin
    if not Assigned(mac.settable_ctx_params) then Exit(nil);
    alg := ossl_provider_ctx(EVP_MAC_get0_provider(mac));
    Result := mac.settable_ctx_params(nil, alg);
end;



end.
