unit openssl3.crypto.evp.kem;

interface
uses OpenSSL.Api;

type
  Tfn = procedure(kem: PEVP_KEM; arg: Pointer);
  Tkem_fn = procedure(const p1: PUTF8Char; arg: Pointer);

  function evp_kem_init(ctx : PEVP_PKEY_CTX; operation : integer;const params : POSSL_PARAM):integer;
  function EVP_PKEY_encapsulate_init(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
  function EVP_PKEY_encapsulate( ctx : PEVP_PKEY_CTX; &out : PByte; outlen : Psize_t; secret : PByte; secretlen : Psize_t):integer;
  function EVP_PKEY_decapsulate_init(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
  function EVP_PKEY_decapsulate(ctx : PEVP_PKEY_CTX; secret : PByte; secretlen : Psize_t;const &in : PByte; inlen : size_t):integer;
  function evp_kem_new( prov : POSSL_PROVIDER):PEVP_KEM;
  function evp_kem_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
  procedure EVP_KEM_free( kem : Pointer);
  function EVP_KEM_up_ref( kem : Pointer):integer;
  function EVP_KEM_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KEM;
  function evp_kem_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_KEM;
  function EVP_KEM_is_a(const kem : PEVP_KEM; name : PUTF8Char):Boolean;
  function evp_kem_get_number(const kem : PEVP_KEM):integer;
  function EVP_KEM_get0_name(const kem : PEVP_KEM):PUTF8Char;
  function EVP_KEM_get0_description(const kem : PEVP_KEM):PUTF8Char;
  procedure EVP_KEM_do_all_provided( libctx : POSSL_LIB_CTX; kem : PEVP_KEM; fn: Tfn; arg : Pointer);
  function EVP_KEM_names_do_all(const kem : PEVP_KEM; name : PUTF8Char; fn: Tkem_fn; data : Pointer):integer;
  function EVP_KEM_gettable_ctx_params(const kem : PEVP_KEM):POSSL_PARAM;
  function EVP_KEM_settable_ctx_params(const kem : PEVP_KEM):POSSL_PARAM;
  function EVP_KEM_get0_provider(const kem : PEVP_KEM):POSSL_PROVIDER;
  
implementation
uses OpenSSL3.Err, openssl3.crypto.evp.pmeth_lib, OpenSSL3.common,
     openssl3.crypto.evp.keymgmt_lib, openssl3.crypto.evp.keymgmt_meth,
     openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.core_algorithm, openssl3.crypto.evp.evp_fetch,
     openssl3.include.internal.refcount,
     openssl3.crypto.evp.p_lib, openssl3.crypto.provider_core;





function EVP_KEM_get0_provider(const kem : PEVP_KEM):POSSL_PROVIDER;
begin
    Result := kem.prov;
end;

function evp_kem_init(ctx : PEVP_PKEY_CTX; operation : integer;const params : POSSL_PARAM):integer;
var
    ret                : integer;
    kem                : PEVP_KEM;
    tmp_keymgmt        : PEVP_KEYMGMT;
    tmp_prov           : POSSL_PROVIDER;
    provkey            : Pointer;
    supported_kem      : PUTF8Char;
    iter               : integer;
    tmp_keymgmt_tofree : PEVP_KEYMGMT;
    label _err;
begin
    ret := 0;
    kem := nil;
    tmp_keymgmt := nil;
     tmp_prov := nil;
    provkey := nil;
     supported_kem := nil;
    if (ctx = nil)  or  (ctx.keytype = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
    end;
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := operation;
    if ctx.pkey = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        goto _err ;
    end;
    {
     * Try to derive the supported kem from |ctx.keymgmt|.
     }
    if not ossl_assert( (ctx.pkey.keymgmt = nil)
                      or  (ctx.pkey.keymgmt = ctx.keymgmt)) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    supported_kem := evp_keymgmt_util_query_operation_name(ctx.keymgmt,
                                                          OSSL_OP_KEM);
    if supported_kem = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err ;
    end;
    {
     * Because we cleared out old ops, we shouldn't need to worry about
     * checking if kem is already there.
     * We perform two iterations:
     *
     * 1.  Do the normal kem fetch, using the fetching data given by
     *     the EVP_PKEY_CTX.
     * 2.  Do the provider specific kem fetch, from the same provider
     *     as |ctx.keymgmt|
     *
     * We then try to fetch the keymgmt from the same provider as the
     * kem, and try to export |ctx.pkey| to that keymgmt (when this
     * keymgmt happens to be the same as |ctx.keymgmt|, the export is
     * a no-op, but we call it anyway to not complicate the code even
     * more).
     * If the export call succeeds (returns a non-nil provider key pointer),
     * we're done and can perform the operation itself.  If not, we perform
     * the second iteration, or jump to legacy.
     }
    iter := 1; provkey := nil;
    while (iter < 3)  and  (provkey = nil) do
    begin
        tmp_keymgmt_tofree := nil;
        {
         * If we're on the second iteration, free the results from the first.
         * They are nil on the first iteration, so no need to check what
         * iteration we're on.
         }
        EVP_KEM_free(kem);
        EVP_KEYMGMT_free(tmp_keymgmt);
        case iter of
            1:
            begin
                kem := EVP_KEM_fetch(ctx.libctx, supported_kem, ctx.propquery);
                if kem <> nil then
                   tmp_prov := EVP_KEM_get0_provider(kem);
            end;
            2:
            begin
                tmp_prov := EVP_KEYMGMT_get0_provider(ctx.keymgmt);
                kem := evp_kem_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                              supported_kem, ctx.propquery);
                if kem = nil then
                begin
                    ERR_raise(ERR_LIB_EVP,
                              EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                    ret := -2;
                    goto _err ;
                end;
            end;
        end;
        if kem = nil then continue;
        {
         * Ensure that the key is provided, either natively, or as a cached
         * export.  We start by fetching the keymgmt with the same name as
         * |ctx.pkey|, but from the provider of the kem method, using the
         * same property query as when fetching the kem method.
         * With the keymgmt we found (if we did), we try to export |ctx.pkey|
         * to it (evp_pkey_export_to_provider() is smart enough to only actually
         * export it if |tmp_keymgmt| is different from |ctx.pkey|'s keymgmt)
         }
        tmp_keymgmt :=
            evp_keymgmt_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                        EVP_KEYMGMT_get0_name(ctx.keymgmt),
                                        ctx.propquery);
        tmp_keymgmt_tofree := tmp_keymgmt;
        if tmp_keymgmt <> nil then
           provkey := evp_pkey_export_to_provider(ctx.pkey, ctx.libctx,
                                                  @tmp_keymgmt, ctx.propquery);
        if tmp_keymgmt = nil then
           EVP_KEYMGMT_free(tmp_keymgmt_tofree);

        inc(iter);
    end;
    if provkey = nil then
    begin
        EVP_KEM_free(kem);
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err ;
    end;
    ctx.op.encap.kem := kem;
    ctx.op.encap.algctx := kem.newctx(ossl_provider_ctx(kem.prov));
    if ctx.op.encap.algctx = nil then
    begin
        { The provider key can stay in the cache }
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err ;
    end;
    case operation of
        EVP_PKEY_OP_ENCAPSULATE:
        begin
            if not Assigned(kem.encapsulate_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err ;
            end;
            ret := kem.encapsulate_init(ctx.op.encap.algctx, provkey, params);
        end;
        EVP_PKEY_OP_DECAPSULATE:
        begin
            if not Assigned(kem.decapsulate_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err ;
            end;
            ret := kem.decapsulate_init(ctx.op.encap.algctx, provkey, params);
        end;
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err ;
        end;
    end;
    EVP_KEYMGMT_free(tmp_keymgmt);
    tmp_keymgmt := nil;
    if ret > 0 then Exit(1);
 _err:
    if ret <= 0 then
    begin
        evp_pkey_ctx_free_old_ops(ctx);
        ctx.operation := EVP_PKEY_OP_UNDEFINED;
    end;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Result := ret;
end;


function EVP_PKEY_encapsulate_init(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
begin
    Result := evp_kem_init(ctx, EVP_PKEY_OP_ENCAPSULATE, params);
end;


function EVP_PKEY_encapsulate( ctx : PEVP_PKEY_CTX; &out : PByte; outlen : Psize_t; secret : PByte; secretlen : Psize_t):integer;
begin
    if ctx = nil then Exit(0);
    if ctx.operation <> EVP_PKEY_OP_ENCAPSULATE then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.encap.algctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if (out <> nil)  and  (secret = nil) then Exit(0);
    Exit(ctx.op.encap.kem.encapsulate(ctx.op.encap.algctx,
                                          out, outlen, secret, secretlen));
end;


function EVP_PKEY_decapsulate_init(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
begin
    Result := evp_kem_init(ctx, EVP_PKEY_OP_DECAPSULATE, params);
end;


function EVP_PKEY_decapsulate(ctx : PEVP_PKEY_CTX; secret : PByte; secretlen : Psize_t;const &in : PByte; inlen : size_t):integer;
begin
    if (ctx = nil)
         or ( (&in = nil)  or  (inlen = 0)) or ( (secret = nil)  and  (secretlen = nil))  then
        Exit(0);
    if ctx.operation <> EVP_PKEY_OP_DECAPSULATE then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.encap.algctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    Exit(ctx.op.encap.kem.decapsulate(ctx.op.encap.algctx,
                                          secret, secretlen, &in, inlen));
end;


function evp_kem_new( prov : POSSL_PROVIDER):PEVP_KEM;
var
  kem : PEVP_KEM;
begin
    kem := OPENSSL_zalloc(sizeof(TEVP_KEM));
    if kem = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    kem.lock := CRYPTO_THREAD_lock_new();
    if kem.lock = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(kem);
        Exit(nil);
    end;
    kem.prov := prov;
    ossl_provider_up_ref(prov);
    kem.refcnt := 1;
    Result := kem;
end;


function evp_kem_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
    fns         : POSSL_DISPATCH;
    kem         : PEVP_KEM;
    ctxfncnt, encfncnt, decfncnt,
    gparamfncnt,
    sparamfncnt : integer;
    label _err;
begin
    fns := algodef._implementation;
    kem := nil;
    ctxfncnt := 0; encfncnt := 0; decfncnt := 0;
    gparamfncnt := 0; sparamfncnt := 0;
    kem := evp_kem_new(prov);
    if kem = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    kem.name_id := name_id;
    kem.type_name := ossl_algorithm_get1_first_name(algodef);
    if kem.type_name = nil then
        goto _err ;
    kem.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
            OSSL_FUNC_KEM_NEWCTX:
            begin
                if Assigned(kem.newctx) then
                   break;
                kem.newctx := _OSSL_FUNC_kem_newctx(fns);
                Inc(ctxfncnt);
            end;
            OSSL_FUNC_KEM_ENCAPSULATE_INIT:
            begin
                if Assigned(kem.encapsulate_init) then break;
                kem.encapsulate_init := _OSSL_FUNC_kem_encapsulate_init(fns);
                Inc(encfncnt);
            end;
            OSSL_FUNC_KEM_ENCAPSULATE:
            begin
                if Assigned(kem.encapsulate) then break;
                kem.encapsulate := _OSSL_FUNC_kem_encapsulate(fns);
                Inc(encfncnt);
            end;
            OSSL_FUNC_KEM_DECAPSULATE_INIT:
            begin
                if Assigned(kem.decapsulate_init) then break;
                kem.decapsulate_init := _OSSL_FUNC_kem_decapsulate_init(fns);
                Inc(decfncnt);
            end;
            OSSL_FUNC_KEM_DECAPSULATE:
            begin
                if Assigned(kem.decapsulate )  then break;
                kem.decapsulate := _OSSL_FUNC_kem_decapsulate(fns);
                Inc(decfncnt);
            end;
            OSSL_FUNC_KEM_FREECTX:
            begin
                if Assigned(kem.freectx )  then break;
                kem.freectx := _OSSL_FUNC_kem_freectx(fns);
                Inc(ctxfncnt);
            end;
            OSSL_FUNC_KEM_DUPCTX:
            begin
                if Assigned(kem.dupctx )  then break;
                kem.dupctx := _OSSL_FUNC_kem_dupctx(fns);
            end;
            OSSL_FUNC_KEM_GET_CTX_PARAMS:
            begin
                if Assigned(kem.get_ctx_params )  then break;
                kem.get_ctx_params := _OSSL_FUNC_kem_get_ctx_params(fns);
                Inc(gparamfncnt);
            end;
            OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS:
            begin
                if Assigned(kem.gettable_ctx_params )  then break;
                kem.gettable_ctx_params := _OSSL_FUNC_kem_gettable_ctx_params(fns);
                Inc(gparamfncnt);
            end;
            OSSL_FUNC_KEM_SET_CTX_PARAMS:
            begin
                if Assigned(kem.set_ctx_params )  then break;
                kem.set_ctx_params := _OSSL_FUNC_kem_set_ctx_params(fns);
                Inc(sparamfncnt);
            end;
            OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS:
            begin
                if Assigned(kem.settable_ctx_params )  then break;
                kem.settable_ctx_params := _OSSL_FUNC_kem_settable_ctx_params(fns);
                Inc(sparamfncnt);
            end;
        end;
        Inc(fns);
    end;
    if (ctxfncnt <> 2)
         or ( (encfncnt <> 0)     and  (encfncnt <> 2) )
         or ( (decfncnt <> 0)     and  (decfncnt <> 2) )
         or ( (encfncnt <> 2)     and  (decfncnt <> 2) )
         or ( (gparamfncnt <> 0)  and  (gparamfncnt <> 2) )
         or ( (sparamfncnt <> 0)  and  (sparamfncnt <> 2) ) then
    begin
        {
         * In order to be a consistent set of functions we must have at least
         * a set of context functions (newctx and freectx) as well as a pair of
         * 'kem' functions: (encapsulate_init, encapsulate) or
         * (decapsulate_init, decapsulate). set_ctx_params and settable_ctx_params are
         * optional, but if one of them is present then the other one must also
         * be present. The same applies to get_ctx_params and
         * gettable_ctx_params. The dupctx function is optional.
         }
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        goto _err ;
    end;
    Exit(kem);
 _err:
    EVP_KEM_free(kem);
    Result := nil;
end;


procedure EVP_KEM_free( kem : Pointer);
var
  i : integer;
begin
    if kem = nil then Exit;
    CRYPTO_DOWN_REF(PEVP_KEM(kem).refcnt, i, PEVP_KEM(kem).lock);
    if i > 0 then Exit;
    OPENSSL_free(PEVP_KEM(kem).type_name);
    ossl_provider_free(PEVP_KEM(kem).prov);
    CRYPTO_THREAD_lock_free(PEVP_KEM(kem).lock);
    OPENSSL_free(kem);
end;


function EVP_KEM_up_ref( kem : Pointer):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(PEVP_KEM(kem).refcnt, ref, PEVP_KEM(kem).lock);
    Result := 1;
end;


function EVP_KEM_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KEM;
begin
    result := PEVP_KEM(evp_generic_fetch(ctx, OSSL_OP_KEM, algorithm, properties,
                                         evp_kem_from_algorithm,
                                         EVP_KEM_up_ref,
                                         EVP_KEM_free));
end;


function evp_kem_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_KEM;
begin
    Exit(evp_generic_fetch_from_prov(prov, OSSL_OP_KEM, algorithm, properties,
                                       evp_kem_from_algorithm,
                                       EVP_KEM_up_ref,
                                       EVP_KEM_free));
end;


function EVP_KEM_is_a(const kem : PEVP_KEM; name : PUTF8Char):Boolean;
begin
    Result := evp_is_a(kem.prov, kem.name_id, nil, name);
end;


function evp_kem_get_number(const kem : PEVP_KEM):integer;
begin
    Result := kem.name_id;
end;


function EVP_KEM_get0_name(const kem : PEVP_KEM):PUTF8Char;
begin
    Result := kem.type_name;
end;


function EVP_KEM_get0_description(const kem : PEVP_KEM):PUTF8Char;
begin
    Result := kem.description;
end;


procedure EVP_KEM_do_all_provided( libctx : POSSL_LIB_CTX; kem : PEVP_KEM; fn: Tfn; arg : Pointer);
begin
    evp_generic_do_all(libctx, OSSL_OP_KEM, Tuser_fn(fn), arg,
                       evp_kem_from_algorithm,
                       EVP_KEM_up_ref,
                       EVP_KEM_free);
end;


function EVP_KEM_names_do_all(const kem : PEVP_KEM; name : PUTF8Char; fn: Tkem_fn; data : Pointer):integer;
begin
    if kem.prov <> nil then
       Exit(evp_names_do_all(kem.prov, kem.name_id, fn, data));
    Result := 1;
end;


function EVP_KEM_gettable_ctx_params(const kem : PEVP_KEM):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (kem = nil)  or  (not Assigned(kem.gettable_ctx_params) ) then
        Exit(nil);
    provctx := ossl_provider_ctx(EVP_KEM_get0_provider(kem));
    Result := kem.gettable_ctx_params(nil, provctx);
end;


function EVP_KEM_settable_ctx_params(const kem : PEVP_KEM):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (kem = nil)  or  (not Assigned(kem.settable_ctx_params)) then
        Exit(nil);
    provctx := ossl_provider_ctx(EVP_KEM_get0_provider(kem));
    Result := kem.settable_ctx_params(nil, provctx);
end;

end.
