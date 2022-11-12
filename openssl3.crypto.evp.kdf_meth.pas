unit openssl3.crypto.evp.kdf_meth;

interface
uses OpenSSL.Api;

function EVP_KDF_fetch(libctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KDF;
function evp_kdf_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_kdf_new:Pointer;
procedure evp_kdf_free( vkdf : Pointer);
function evp_kdf_up_ref( vkdf : Pointer):integer;

function EVP_KDF_settable_ctx_params(const kdf : PEVP_KDF):POSSL_PARAM;

implementation
uses
   openssl3.crypto.evp.evp_fetch, openssl3.crypto.mem, OpenSSL3.Err,
   openssl3.crypto.core_algorithm,    openssl3.include.internal.refcount,
   openssl3.crypto.provider_core,     OpenSSL3.openssl.core_dispatch,
   openssl3.crypto.evp.kdf_lib,
   openssl3.crypto.evp.keymgmt_meth,  OpenSSL3.threads_none;




function EVP_KDF_settable_ctx_params(const kdf : PEVP_KDF):POSSL_PARAM;
var
  alg : Pointer;
begin
    if not Assigned(kdf.settable_ctx_params) then
       Exit(nil);
    alg := ossl_provider_ctx(EVP_KDF_get0_provider(kdf));
    Result := kdf.settable_ctx_params(nil, alg);
end;

function evp_kdf_up_ref( vkdf : Pointer):integer;
var
  kdf : PEVP_KDF;
  ref : integer;
begin
    kdf := PEVP_KDF(vkdf);
    ref := 0;
    CRYPTO_UP_REF(kdf.refcnt, ref, kdf.lock);
    Result := 1;
end;

procedure evp_kdf_free( vkdf : Pointer);
var
  kdf : PEVP_KDF;
  ref : integer;
begin
    kdf := (PEVP_KDF  (vkdf));
    ref := 0;
    if kdf = nil then exit;
    CRYPTO_DOWN_REF(kdf.refcnt, ref, kdf.lock);
    if ref > 0 then exit;
    OPENSSL_free(kdf.type_name);
    ossl_provider_free(kdf.prov);
    CRYPTO_THREAD_lock_free(kdf.lock);
    OPENSSL_free(kdf);
end;


function evp_kdf_new:Pointer;
var
  kdf : PEVP_KDF;
begin
    kdf := nil;
    kdf := OPENSSL_zalloc(sizeof( kdf^));
    kdf.lock := CRYPTO_THREAD_lock_new();
    if (kdf  = nil)
         or  (kdf.lock = nil) then
    begin
        OPENSSL_free(kdf);
        Exit(nil);
    end;
    kdf.refcnt := 1;
    Result := kdf;
end;




function evp_kdf_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
    fns      : POSSL_DISPATCH;

    kdf      : PEVP_KDF;

    fnkdfcnt,fnctxcnt : integer;
begin
    fns := algodef._implementation;
    kdf := nil;
    fnkdfcnt := 0; fnctxcnt := 0;
    kdf := evp_kdf_new();
    if kdf = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    kdf.name_id := name_id;
    kdf.type_name := ossl_algorithm_get1_first_name(algodef );
    if kdf.type_name = nil then
    begin
        evp_kdf_free(kdf);
        Exit(nil);
    end;
    kdf.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_KDF_NEWCTX:
        begin
            if Assigned(kdf.newctx)  then break;
            kdf.newctx := _OSSL_FUNC_kdf_newctx(fns);
            Inc(fnctxcnt);
        end;
        OSSL_FUNC_KDF_DUPCTX:
        begin
            if Assigned(kdf.dupctx)  then break;
            kdf.dupctx := _OSSL_FUNC_kdf_dupctx(fns);
        end;
        OSSL_FUNC_KDF_FREECTX:
        begin
            if Assigned(kdf.freectx)  then break;
            kdf.freectx := _OSSL_FUNC_kdf_freectx(fns);
            Inc(fnctxcnt);
        end;
        OSSL_FUNC_KDF_RESET:
        begin
            if Assigned(kdf.reset)  then break;
            kdf.reset := _OSSL_FUNC_kdf_reset(fns);
        end;
        OSSL_FUNC_KDF_DERIVE:
        begin
            if Assigned(kdf.derive)  then break;
            kdf.derive := _OSSL_FUNC_kdf_derive(fns);
            Inc(fnkdfcnt);
        end;
        OSSL_FUNC_KDF_GETTABLE_PARAMS:
        begin
            if Assigned(kdf.gettable_params)  then break;
            kdf.gettable_params := _OSSL_FUNC_kdf_gettable_params(fns);
        end;
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS:
        begin
            if Assigned(kdf.gettable_ctx_params)  then break;
            kdf.gettable_ctx_params := _OSSL_FUNC_kdf_gettable_ctx_params(fns);
        end;
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS:
        begin
            if Assigned(kdf.settable_ctx_params)  then break;
            kdf.settable_ctx_params := _OSSL_FUNC_kdf_settable_ctx_params(fns);
        end;
        OSSL_FUNC_KDF_GET_PARAMS:
        begin
            if Assigned(kdf.get_params)  then break;
            kdf.get_params := _OSSL_FUNC_kdf_get_params(fns);
        end;
        OSSL_FUNC_KDF_GET_CTX_PARAMS:
        begin
            if Assigned(kdf.get_ctx_params)  then break;
            kdf.get_ctx_params := _OSSL_FUNC_kdf_get_ctx_params(fns);
        end;
        OSSL_FUNC_KDF_SET_CTX_PARAMS:
        begin
            if Assigned(kdf.set_ctx_params)  then break;
            kdf.set_ctx_params := _OSSL_FUNC_kdf_set_ctx_params(fns);
        end;
        end;

        Inc(fns);
    end;
    if (fnkdfcnt <> 1)  or  (fnctxcnt <> 2) then
    begin
        {
         * In order to be a consistent set of functions we must have at least
         * a derive function, and a complete set of context management
         * functions.
         }
        evp_kdf_free(kdf);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    kdf.prov := prov;
    if prov <> nil then ossl_provider_up_ref(prov);
    Result := kdf;
end;

function EVP_KDF_fetch(libctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KDF;
begin
    Exit(evp_generic_fetch(libctx, OSSL_OP_KDF, algorithm, properties,
                             evp_kdf_from_algorithm, evp_kdf_up_ref,
                             evp_kdf_free));
end;

end.
