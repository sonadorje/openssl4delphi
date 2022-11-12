unit openssl3.crypto.evp.signature;

interface
uses OpenSSL.Api;

function EVP_SIGNATURE_get0_provider(const signature : PEVP_SIGNATURE):POSSL_PROVIDER;
 procedure EVP_SIGNATURE_free( signature : PEVP_SIGNATURE);
 function EVP_PKEY_verify_init( ctx : PEVP_PKEY_CTX):integer;
 function evp_pkey_signature_init(ctx : PEVP_PKEY_CTX; operation : integer;const params : POSSL_PARAM):integer;
 function EVP_SIGNATURE_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_SIGNATURE;
 function evp_signature_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
 function evp_signature_new( prov : POSSL_PROVIDER):PEVP_SIGNATURE;
 function EVP_SIGNATURE_up_ref( signature : PEVP_SIGNATURE):integer;
  function evp_signature_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_SIGNATURE;
  function EVP_PKEY_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function EVP_PKEY_sign_init( ctx : PEVP_PKEY_CTX):integer;
 function EVP_PKEY_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;

implementation
uses openssl3.include.internal.refcount, openssl3.crypto.mem,
     openssl3.crypto.provider_core, OpenSSL3.threads_none,
     OpenSSL3.Err, openssl3.crypto.evp.pmeth_lib,
     OpenSSL3.common,  openssl3.crypto.evp.keymgmt_lib,
     openssl3.crypto.evp.p_lib, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.core_algorithm, OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.evp.keymgmt_meth,  openssl3.crypto.evp.evp_fetch,
     openssl3.providers.fips.fipsprov, openssl3.crypto.evp;


function EVP_PKEY_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret : integer;
  pksize : size_t;
  label _legacy;
begin
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if ctx.operation <> EVP_PKEY_OP_SIGN then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.sig.algctx = nil then
       goto _legacy;
    ret := ctx.op.sig.signature.sign(ctx.op.sig.algctx, sig, siglen,
                                      get_result(sig = nil , 0 , siglen^), tbs, tbslen);
    Exit(ret);

 _legacy:
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.sign)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    //M_check_autoarg(ctx, sig, siglen, EVP_F_EVP_PKEY_SIGN)
    if ctx.pmeth.flags and EVP_PKEY_FLAG_AUTOARGLEN > 0 then
    begin
        pksize := size_t(EVP_PKEY_get_size(ctx.pkey));
        if pksize = 0 then begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); {ckerr_ignore}
            exit( 0);
        end;
        if sig = nil then begin
            siglen^ := pksize;
            exit( 1);
        end;
        if siglen^ < pksize then begin
            ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL); {ckerr_ignore}
            exit( 0);
        end;
    end;
    Result := ctx.pmeth.sign(ctx, sig, siglen, tbs, tbslen);
end;

function EVP_PKEY_sign_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_signature_init(ctx, EVP_PKEY_OP_SIGN, nil);
end;


function EVP_PKEY_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret : integer;
  label _legacy;
begin
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if ctx.operation <> EVP_PKEY_OP_VERIFY then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.sig.algctx = nil then goto _legacy;
    ret := ctx.op.sig.signature.verify(ctx.op.sig.algctx, sig, siglen,
                                        tbs, tbslen);
    Exit(ret);
 _legacy:
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.verify)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    Result := ctx.pmeth.verify(ctx, sig, siglen, tbs, tbslen);
end;

function evp_signature_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_SIGNATURE;
begin
    Exit(evp_generic_fetch_from_prov(prov, OSSL_OP_SIGNATURE,
                                       algorithm, properties,
                                       evp_signature_from_algorithm,
                                       @EVP_SIGNATURE_up_ref,
                                       @EVP_SIGNATURE_free));
end;




function EVP_SIGNATURE_up_ref( signature : PEVP_SIGNATURE):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(signature.refcnt, ref, signature.lock);
    Result := 1;
end;




function evp_signature_new( prov : POSSL_PROVIDER):PEVP_SIGNATURE;
var
  signature : PEVP_SIGNATURE;
begin
    signature := OPENSSL_zalloc(sizeof(TEVP_SIGNATURE));
    if signature = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    signature.lock := CRYPTO_THREAD_lock_new;
    if signature.lock = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(signature);
        Exit(nil);
    end;
    signature.prov := prov;
    ossl_provider_up_ref(prov);
    signature.refcnt := 1;
    Result := signature;
end;




function evp_signature_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  fns          : POSSL_DISPATCH;
  signature    : PEVP_SIGNATURE;
  ctxfncnt,
  signfncnt,
  verifyfncnt,
  verifyrecfncnt,
  digsignfncnt, digverifyfncnt,
  sparamfncnt, gmdparamfncnt, smdparamfncnt,
  gparamfncnt  : integer;
  label _err;
begin
     fns := algodef._implementation;
    signature := nil;
    ctxfncnt := 0; signfncnt := 0; verifyfncnt := 0; verifyrecfncnt := 0;
    digsignfncnt := 0; digverifyfncnt := 0;
    gparamfncnt := 0; sparamfncnt := 0; gmdparamfncnt := 0; smdparamfncnt := 0;
    signature := evp_signature_new(prov);
    if signature = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    signature.name_id := name_id;
    signature.type_name := ossl_algorithm_get1_first_name(algodef);
    if signature.type_name = nil then
        goto _err;
    signature.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
            OSSL_FUNC_SIGNATURE_NEWCTX:
            begin
                if Assigned(signature.newctx) then break;
                signature.newctx := _OSSL_FUNC_signature_newctx(fns);
                Inc(ctxfncnt);
            end;
            OSSL_FUNC_SIGNATURE_SIGN_INIT:
            begin
                if Assigned(signature.sign_init) then break;
                signature.sign_init := _OSSL_FUNC_signature_sign_init(fns);
                Inc(signfncnt);
            end;
            OSSL_FUNC_SIGNATURE_SIGN:
            begin
                if Assigned(signature.sign) then break;
                signature.sign := _OSSL_FUNC_signature_sign(fns);
                Inc(signfncnt);
            end;
            OSSL_FUNC_SIGNATURE_VERIFY_INIT:
            begin
                if Assigned(signature.verify_init) then break;
                signature.verify_init := _OSSL_FUNC_signature_verify_init(fns);
                Inc(verifyfncnt);
            end;
            OSSL_FUNC_SIGNATURE_VERIFY:
            begin
                if Assigned(signature.verify) then break;
                signature.verify := _OSSL_FUNC_signature_verify(fns);
                PostInc(verifyfncnt);
            end;
            OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT:
            begin
                if Assigned(signature.verify_recover_init) then break;
                signature.verify_recover_init := _OSSL_FUNC_signature_verify_recover_init(fns);
                PostInc(verifyrecfncnt);
            end;
            OSSL_FUNC_SIGNATURE_VERIFY_RECOVER:
            begin
                if Assigned(signature.verify_recover) then break;
                signature.verify_recover := _OSSL_FUNC_signature_verify_recover(fns);
                PostInc(verifyrecfncnt);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT:
            begin
                if Assigned(signature.digest_sign_init) then break;
                signature.digest_sign_init := _OSSL_FUNC_signature_digest_sign_init(fns);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE:
            begin
                if Assigned(signature.digest_sign_update) then break;
                signature.digest_sign_update := _OSSL_FUNC_signature_digest_sign_update(fns);
                PostInc(digsignfncnt);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL:
            begin
                if Assigned(signature.digest_sign_final) then break;
                signature.digest_sign_final := _OSSL_FUNC_signature_digest_sign_final(fns);
                PostInc(digsignfncnt);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN:
            begin
                if Assigned(signature.digest_sign) then break;
                signature.digest_sign := _OSSL_FUNC_signature_digest_sign(fns);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT:
            begin
                if Assigned(signature.digest_verify_init) then break;
                signature.digest_verify_init := _OSSL_FUNC_signature_digest_verify_init(fns);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE:
            begin
                if Assigned(signature.digest_verify_update) then break;
                signature.digest_verify_update := _OSSL_FUNC_signature_digest_verify_update(fns);
                PostInc(digverifyfncnt);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL:
            begin
                if Assigned(signature.digest_verify_final) then break;
                signature.digest_verify_final := _OSSL_FUNC_signature_digest_verify_final(fns);
                PostInc(digverifyfncnt);
            end;
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY:
            begin
                if Assigned(signature.digest_verify) then break;
                signature.digest_verify := _OSSL_FUNC_signature_digest_verify(fns);
            end;
            OSSL_FUNC_SIGNATURE_FREECTX:
            begin
                if Assigned(signature.freectx) then break;
                signature.freectx := _OSSL_FUNC_signature_freectx(fns);
                PostInc(ctxfncnt);
            end;
            OSSL_FUNC_SIGNATURE_DUPCTX:
            begin
                if Assigned(signature.dupctx) then break;
                signature.dupctx := _OSSL_FUNC_signature_dupctx(fns);
            end;
            OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS:
            begin
                if Assigned(signature.get_ctx_params) then break;
                signature.get_ctx_params := _OSSL_FUNC_signature_get_ctx_params(fns);
                PostInc(gparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS:
            begin
                if Assigned(signature.gettable_ctx_params) then break;
                signature.gettable_ctx_params := _OSSL_FUNC_signature_gettable_ctx_params(fns);
                PostInc(gparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS:
            begin
                if Assigned(signature.set_ctx_params) then break;
                signature.set_ctx_params := _OSSL_FUNC_signature_set_ctx_params(fns);
                PostInc(sparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS:
            begin
                if Assigned(signature.settable_ctx_params) then break;
                signature.settable_ctx_params := _OSSL_FUNC_signature_settable_ctx_params(fns);
                PostInc(sparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS:
            begin
                if Assigned(signature.get_ctx_md_params) then break;
                signature.get_ctx_md_params := _OSSL_FUNC_signature_get_ctx_md_params(fns);
                Inc(gmdparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS:
            begin
                if Assigned(signature.gettable_ctx_md_params) then break;
                signature.gettable_ctx_md_params := _OSSL_FUNC_signature_gettable_ctx_md_params(fns);
                Inc(gmdparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS:
            begin
                if Assigned(signature.set_ctx_md_params) then break;
                signature.set_ctx_md_params := _OSSL_FUNC_signature_set_ctx_md_params(fns);
                Inc(smdparamfncnt);
            end;
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS:
            begin
                if Assigned(signature.settable_ctx_md_params) then break;
                signature.settable_ctx_md_params := _OSSL_FUNC_signature_settable_ctx_md_params(fns);
                Inc(smdparamfncnt);
            end;
        end;
        Inc(fns);
    end;
    if (ctxfncnt <> 2)
         or ( (signfncnt = 0)
             and  (verifyfncnt = 0)
             and  (verifyrecfncnt = 0)
             and  (digsignfncnt = 0)
             and  (digverifyfncnt = 0)
             and  (not Assigned(signature.digest_sign))
             and  (not Assigned(signature.digest_verify)) )
         or (  (signfncnt <> 0)  and  (signfncnt <> 2) )
         or (  (verifyfncnt <> 0)  and  (verifyfncnt <> 2) )
         or (  (verifyrecfncnt <> 0)  and  (verifyrecfncnt <> 2) )
         or (  (digsignfncnt <> 0)  and  (digsignfncnt <> 2) )
         or (  (digsignfncnt = 2)  and  (not Assigned(signature.digest_sign_init)) )
         or (  (digverifyfncnt <> 0)  and  (digverifyfncnt <> 2) )
         or (  (digverifyfncnt = 2)  and  (not Assigned(signature.digest_verify_init)) )
         or (  (Assigned(signature.digest_sign))
             and  (not Assigned(signature.digest_sign_init)) )
         or  ( (Assigned(signature.digest_verify))
             and  (not Assigned(signature.digest_verify_init)) )
         or  ( (gparamfncnt <> 0)  and  (gparamfncnt <> 2) )
         or  ( (sparamfncnt <> 0)  and  (sparamfncnt <> 2) )
         or  ( (gmdparamfncnt <> 0)  and  (gmdparamfncnt <> 2) )
         or  ( (smdparamfncnt <> 0)  and  (smdparamfncnt <> 2) ) then
         begin
        {
         * In order to be a consistent set of functions we must have at least
         * a set of context functions (newctx and freectx) as well as a set of
         * 'signature' functions:
         *  (sign_init, sign) or
         *  (verify_init verify) or
         *  (verify_recover_init, verify_recover) or
         *  (digest_sign_init, digest_sign_update, digest_sign_final) or
         *  (digest_verify_init, digest_verify_update, digest_verify_final) or
         *  (digest_sign_init, digest_sign) or
         *  (digest_verify_init, digest_verify).
         *
         * set_ctx_params and settable_ctx_params are optional, but if one of
         * them is present then the other one must also be present. The same
         * applies to get_ctx_params and gettable_ctx_params. The same rules
         * apply to the 'md_params' functions. The dupctx function is optional.
         }
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        goto _err;
    end;
    Exit(signature);
 _err:
    EVP_SIGNATURE_free(signature);
    Result := nil;
end;


function EVP_SIGNATURE_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_SIGNATURE;
begin
    Exit(evp_generic_fetch(ctx, OSSL_OP_SIGNATURE, algorithm, properties,
                             evp_signature_from_algorithm,
                             @EVP_SIGNATURE_up_ref,
                             @EVP_SIGNATURE_free));
end;





function evp_pkey_signature_init(ctx : PEVP_PKEY_CTX; operation : integer;const params : POSSL_PARAM):integer;
var
    ret                : integer;
    provkey            : Pointer;
    signature          : PEVP_SIGNATURE;
    tmp_keymgmt        : PEVP_KEYMGMT;
    tmp_prov           : POSSL_PROVIDER;
    supported_sig      : PUTF8Char;
    iter               : integer;
    tmp_keymgmt_tofree : PEVP_KEYMGMT;
    label _err, _legacy, _end;
begin
    ret := 0;
    provkey := nil;
    signature := nil;
    tmp_keymgmt := nil;
    tmp_prov := nil;
    supported_sig := nil;

    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := operation;
    ERR_set_mark;
    if evp_pkey_ctx_is_legacy(ctx)  then
        goto _legacy;
    if ctx.pkey = nil then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        goto _err;
    end;
    {
     * Try to derive the supported signature from |ctx.keymgmt|.
     }
    if not ossl_assert( (ctx.pkey.keymgmt = nil)
                      or(ctx.pkey.keymgmt = ctx.keymgmt) ) then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    supported_sig := evp_keymgmt_util_query_operation_name(ctx.keymgmt,
                                                          OSSL_OP_SIGNATURE);
    if supported_sig = nil then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
    {
     * We perform two iterations:
     *
     * 1.  Do the normal signature fetch, using the fetching data given by
     *     the EVP_PKEY_CTX.
     * 2.  Do the provider specific signature fetch, from the same provider
     *     as |ctx.keymgmt|
     *
     * We then try to fetch the keymgmt from the same provider as the
     * signature, and try to export |ctx.pkey| to that keymgmt (when
     * this keymgmt happens to be the same as |ctx.keymgmt|, the export
     * is a no-op, but we call it anyway to not complicate the code even
     * more).
     * If the export call succeeds (returns a non-nil provider key pointer),
     * we're done and can perform the operation itself.  If not, we perform
     * the second iteration, or jump to legacy.
     }
    iter := 1;
    while (iter <= 3 -1)  and  (provkey = nil) do
    begin
        tmp_keymgmt_tofree := nil;
        {
         * If we're on the second iteration, free the results from the first.
         * They are nil on the first iteration, so no need to check what
         * iteration we're on.
         }
        EVP_SIGNATURE_free(signature);
        EVP_KEYMGMT_free(tmp_keymgmt);
        case iter of
            1:
            begin
                signature := EVP_SIGNATURE_fetch(ctx.libctx, supported_sig, ctx.propquery);
                if signature <> nil then
                   tmp_prov := EVP_SIGNATURE_get0_provider(signature);
            end;
            2:
            begin
                tmp_prov := EVP_KEYMGMT_get0_provider(ctx.keymgmt);
                signature := evp_signature_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                                  supported_sig, ctx.propquery);
                if signature = nil then goto _legacy;
            end;
        end;
        if signature = nil then continue;
        {
         * Ensure that the key is provided, either natively, or as a cached
         * export.  We start by fetching the keymgmt with the same name as
         * |ctx.pkey|, but from the provider of the signature method, using
         * the same property query as when fetching the signature method.
         * With the keymgmt we found (if we did), we try to export |ctx.pkey|
         * to it (evp_pkey_export_to_provider is smart enough to only actually
         * export it if |tmp_keymgmt| is different from |ctx.pkey|'s keymgmt)
         }
        tmp_keymgmt := evp_keymgmt_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                        EVP_KEYMGMT_get0_name(ctx.keymgmt),
                                        ctx.propquery);
        tmp_keymgmt_tofree := tmp_keymgmt;
        if tmp_keymgmt <> nil then
           provkey := evp_pkey_export_to_provider(ctx.pkey, ctx.libctx,
                                                  @tmp_keymgmt, ctx.propquery);
        if tmp_keymgmt = nil then
           EVP_KEYMGMT_free(tmp_keymgmt_tofree);

        Inc(iter);
    end;
    if provkey = nil then
    begin
        EVP_SIGNATURE_free(signature);
        goto _legacy;
    end;
    ERR_pop_to_mark;
    { No more legacy from here down to legacy: }
    ctx.op.sig.signature := signature;
    ctx.op.sig.algctx := signature.newctx(ossl_provider_ctx(signature.prov), ctx.propquery);
    if ctx.op.sig.algctx = nil then
    begin
        { The provider key can stay in the cache }
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;

    case operation of
        EVP_PKEY_OP_SIGN:
        begin
            if not Assigned(signature.sign_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err;
            end;
            ret := signature.sign_init(ctx.op.sig.algctx, provkey, params);
        end;
        EVP_PKEY_OP_VERIFY:
        begin
            if not Assigned(signature.verify_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err;
            end;
            ret := signature.verify_init(ctx.op.sig.algctx, provkey, params);
        end;
        EVP_PKEY_OP_VERIFYRECOVER:
        begin
            if not Assigned(signature.verify_recover_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err;
            end;
            ret := signature.verify_recover_init(ctx.op.sig.algctx, provkey,
                                                 params);
        end;
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err;
        end;
    end;
    if ret <= 0 then
    begin
        signature.freectx(ctx.op.sig.algctx);
        ctx.op.sig.algctx := nil;
        goto _err;
    end;
    goto _end;
 _legacy:
    {
     * If we don't have the full support we need with provided methods,
     * let's go see if legacy does.
     }
    ERR_pop_to_mark;
    EVP_KEYMGMT_free(tmp_keymgmt);
    tmp_keymgmt := nil;
    if (ctx.pmeth = nil)       or
       ( (operation = EVP_PKEY_OP_SIGN)  and  (not Assigned(ctx.pmeth.sign)) )   or
       ( (operation = EVP_PKEY_OP_VERIFY)  and  (not Assigned(ctx.pmeth.verify)) ) or
       ( (operation = EVP_PKEY_OP_VERIFYRECOVER) and  (not Assigned(ctx.pmeth.verify_recover)) ) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;

    case operation of
        EVP_PKEY_OP_SIGN:
        begin
            if not Assigned(ctx.pmeth.sign_init) then Exit(1);
            ret := ctx.pmeth.sign_init(ctx);
        end;
        EVP_PKEY_OP_VERIFY:
        begin
            if not Assigned(ctx.pmeth.verify_init) then Exit(1);
            ret := ctx.pmeth.verify_init(ctx);
        end;
        EVP_PKEY_OP_VERIFYRECOVER:
        begin
            if not Assigned(ctx.pmeth.verify_recover_init) then Exit(1);
            ret := ctx.pmeth.verify_recover_init(ctx);
        end;
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err;
        end
    end;
    if ret <= 0 then goto _err;
 _end:
{$IFNDEF FIPS_MODULE}
    if ret > 0 then
       ret := evp_pkey_ctx_use_cached_data(ctx);
{$ENDIF}
    EVP_KEYMGMT_free(tmp_keymgmt);
    Exit(ret);
 _err:
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := EVP_PKEY_OP_UNDEFINED;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Result := ret;
end;





function EVP_PKEY_verify_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_signature_init(ctx, EVP_PKEY_OP_VERIFY, nil);
end;


procedure EVP_SIGNATURE_free(signature : PEVP_SIGNATURE);
var
  i : integer;
begin
    if signature = nil then Exit;
    CRYPTO_DOWN_REF(signature.refcnt, i, signature.lock);
    if i > 0 then exit;
    OPENSSL_free(signature.type_name);
    ossl_provider_free(signature.prov);
    CRYPTO_THREAD_lock_free(signature.lock);
    OPENSSL_free(signature);
end;

function EVP_SIGNATURE_get0_provider(const signature : PEVP_SIGNATURE):POSSL_PROVIDER;
begin
    Result := signature.prov;
end;


end.
