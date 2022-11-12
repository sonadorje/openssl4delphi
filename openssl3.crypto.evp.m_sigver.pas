unit openssl3.crypto.evp.m_sigver;

interface
 uses OpenSSL.Api;

function EVP_DigestVerifyInit(ctx : PEVP_MD_CTX; pctx : PPEVP_PKEY_CTX;const _type : PEVP_MD; e : PENGINE; pkey : PEVP_PKEY):integer;
function canon_mdname(const mdname : PUTF8Char):PUTF8Char;
function do_sigver_init(ctx : PEVP_MD_CTX; pctx : PPEVP_PKEY_CTX;{const} _type : PEVP_MD; mdname : PUTF8Char; libctx : POSSL_LIB_CTX;{const} props : PUTF8Char; e : PENGINE; pkey : PEVP_PKEY; ver : integer;const params : POSSL_PARAM):integer;
 function EVP_DigestVerify(ctx : PEVP_MD_CTX;const sigret : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
 function EVP_DigestVerifyUpdate(ctx : PEVP_MD_CTX;const data : Pointer; dsize : size_t):integer;
 function EVP_DigestVerifyFinal(ctx : PEVP_MD_CTX;const sig : PByte; siglen : size_t):integer;
 function EVP_DigestSignInit(ctx : PEVP_MD_CTX; pctx : PPEVP_PKEY_CTX;const &type : PEVP_MD; e : PENGINE; pkey : PEVP_PKEY):integer;
 function EVP_DigestSign(ctx : PEVP_MD_CTX; sigret : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
 function EVP_DigestSignUpdate(ctx : PEVP_MD_CTX;const data : Pointer; dsize : size_t):integer;
 function EVP_DigestSignFinal( ctx : PEVP_MD_CTX; sigret : PByte; siglen : Psize_t):integer;

implementation
uses OpenSSL3.common, OpenSSL3.Err, openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.evp,  openssl3.crypto.evp.evp_lib,
     openssl3.crypto.evp.p_lib,  openssl3.crypto.provider_core,
     openssl3.crypto.evp.signature, openssl3.crypto.evp.keymgmt_meth,
     openssl3.crypto.evp.digest, openssl3.crypto.evp.names,

     openssl3.providers.fips.fipsprov, openssl3.crypto.evp.keymgmt_lib;


function EVP_DigestSignFinal( ctx : PEVP_MD_CTX; sigret : PByte; siglen : Psize_t):integer;
var
  sctx, r : integer;
  dctx, pctx : PEVP_PKEY_CTX;
  md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  mdlen : uint32;
  tmp_ctx : PEVP_MD_CTX;
  s : integer;
  label _legacy;
begin
    sctx := 0; r := 0;
    pctx := ctx.pctx;
    if (pctx = nil)
             or  (pctx.operation <> EVP_PKEY_OP_SIGNCTX)
             or  (pctx.op.sig.algctx = nil)
             or  (pctx.op.sig.signature = nil) then
        goto _legacy;
    if (sigret = nil)  or  (ctx.flags and EVP_MD_CTX_FLAG_FINALISE <> 0) then
        Exit(pctx.op.sig.signature.digest_sign_final(pctx.op.sig.algctx,
                                                         sigret, siglen,
                                                       get_result(sigret = nil , 0 , siglen^)));
    dctx := EVP_PKEY_CTX_dup(pctx);
    if dctx = nil then Exit(0);
    r := dctx.op.sig.signature.digest_sign_final(dctx.op.sig.algctx,
                                                  sigret, siglen,
                                                  siglen^);
    EVP_PKEY_CTX_free(dctx);
    Exit(r);
 _legacy:
    if (pctx = nil)  or  (pctx.pmeth = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
    end;
    { do_sigver_init checked that |digest_custom| is non-nil }
    if (pctx.flag_call_digest_custom > 0)
         and  (0>=ctx.pctx.pmeth.digest_custom(ctx.pctx, ctx)) then
        Exit(0);
    pctx.flag_call_digest_custom := 0;
    if pctx.pmeth.flags and EVP_PKEY_FLAG_SIGCTX_CUSTOM > 0 then
    begin
        if sigret = nil then
            Exit(pctx.pmeth.signctx(pctx, sigret, siglen, ctx));
        if ctx.flags and EVP_MD_CTX_FLAG_FINALISE > 0 then
           r := pctx.pmeth.signctx(pctx, sigret, siglen, ctx)
        else
        begin
            dctx := EVP_PKEY_CTX_dup(pctx);
            if dctx = nil then Exit(0);
            r := dctx.pmeth.signctx(dctx, sigret, siglen, ctx);
            EVP_PKEY_CTX_free(dctx);
        end;
        Exit(r);
    end;
    if Assigned(pctx.pmeth.signctx) then
       sctx := 1
    else
        sctx := 0;
    if sigret <> nil then
    begin
        mdlen := 0;
        if ctx.flags and EVP_MD_CTX_FLAG_FINALISE > 0 then
        begin
            if sctx > 0 then
                r := pctx.pmeth.signctx(pctx, sigret, siglen, ctx)
            else
                r := EVP_DigestFinal_ex(ctx, @md, @mdlen);
        end
        else
        begin
            tmp_ctx := EVP_MD_CTX_new;
            if tmp_ctx = nil then Exit(0);
            if 0>=EVP_MD_CTX_copy_ex(tmp_ctx, ctx ) then
            begin
                EVP_MD_CTX_free(tmp_ctx);
                Exit(0);
            end;
            if sctx > 0 then
               r := tmp_ctx.pctx.pmeth.signctx(tmp_ctx.pctx,
                                                  sigret, siglen, tmp_ctx)
            else
                r := EVP_DigestFinal_ex(tmp_ctx, @md, @mdlen);
            EVP_MD_CTX_free(tmp_ctx);
        end;
        if (sctx > 0) or  (0>=r) then Exit(r);
        if EVP_PKEY_sign(pctx, sigret, siglen, @md, mdlen) <= 0  then
            Exit(0);
    end
    else
    begin
        if sctx > 0 then
        begin
            if pctx.pmeth.signctx(pctx, sigret, siglen, ctx) <= 0 then
                Exit(0);
        end
        else
        begin
            s := EVP_MD_get_size(ctx.digest);
            if (s < 0)  or  (EVP_PKEY_sign(pctx, sigret, siglen, nil, s) <= 0) then
                Exit(0);
        end;
    end;
    Result := 1;
end;




function EVP_DigestSignUpdate(ctx : PEVP_MD_CTX;const data : Pointer; dsize : size_t):integer;
var
  pctx : PEVP_PKEY_CTX;
  label _legacy;
begin
    pctx := ctx.pctx;
    if (pctx = nil)
             or  (pctx.operation <> EVP_PKEY_OP_SIGNCTX)
             or  (pctx.op.sig.algctx = nil)
             or  (pctx.op.sig.signature = nil) then
        goto _legacy;
    if not Assigned(pctx.op.sig.signature.digest_sign_update) then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Exit(pctx.op.sig.signature.digest_sign_update(pctx.op.sig.algctx,
                                                      data, dsize));
 _legacy:
    if pctx <> nil then begin
        { do_sigver_init checked that |digest_custom| is non-nil }
        if (pctx.flag_call_digest_custom > 0)
             and  (0>=ctx.pctx.pmeth.digest_custom(ctx.pctx, ctx)) then
            Exit(0);
        pctx.flag_call_digest_custom := 0;
    end;
    Result := EVP_DigestUpdate(ctx, data, dsize);
end;




function EVP_DigestSign(ctx : PEVP_MD_CTX; sigret : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  pctx : PEVP_PKEY_CTX;
begin
    pctx := ctx.pctx;
    if (pctx <> nil)
             and  (pctx.operation = EVP_PKEY_OP_SIGNCTX)
             and  (pctx.op.sig.algctx <> nil)
             and  (pctx.op.sig.signature <> nil) then
    begin
        if Assigned(pctx.op.sig.signature.digest_sign) then
            Exit(pctx.op.sig.signature.digest_sign(pctx.op.sig.algctx,
                                                       sigret, siglen,
                                                    get_result(sigret = nil , 0 , siglen^),
                                                       tbs, tbslen));
    end
    else
    begin
        { legacy }
        if (ctx.pctx.pmeth <> nil)  and  (Assigned(ctx.pctx.pmeth.digestsign)) then
           Exit(ctx.pctx.pmeth.digestsign(ctx, sigret, siglen, tbs, tbslen));
    end;
    if (sigret <> nil)  and  (EVP_DigestSignUpdate(ctx, tbs, tbslen)<= 0) then
        Exit(0);
    Result := EVP_DigestSignFinal(ctx, sigret, siglen);
end;


function EVP_DigestSignInit(ctx : PEVP_MD_CTX; pctx : PPEVP_PKEY_CTX;const &type : PEVP_MD; e : PENGINE; pkey : PEVP_PKEY):integer;
begin
    Exit(do_sigver_init(ctx, pctx, &type, nil, nil, nil, e, pkey, 0, nil));
end;



function EVP_DigestVerifyFinal(ctx : PEVP_MD_CTX;const sig : PByte; siglen : size_t):integer;
var
  md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  r : integer;
  mdlen : uint32;
  vctx : integer;
  dctx, pctx : PEVP_PKEY_CTX;
  tmp_ctx : PEVP_MD_CTX;
  label _legacy;
begin
    r := 0;
    mdlen := 0;
    vctx := 0;
    pctx := ctx.pctx;
    if (pctx = nil)
             or  (pctx.operation <> EVP_PKEY_OP_VERIFYCTX)
             or  (pctx.op.sig.algctx = nil)
             or  (pctx.op.sig.signature = nil) then
       goto _legacy;
    if (ctx.flags and EVP_MD_CTX_FLAG_FINALISE) <> 0 then
        Exit(pctx.op.sig.signature.digest_verify_final(pctx.op.sig.algctx,
                                                           sig, siglen));
    dctx := EVP_PKEY_CTX_dup(pctx);
    if dctx = nil then Exit(0);
    r := dctx.op.sig.signature.digest_verify_final(dctx.op.sig.algctx,
                                                    sig, siglen);
    EVP_PKEY_CTX_free(dctx);
    Exit(r);
 _legacy:
    if (pctx = nil)  or  (pctx.pmeth = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
    end;
    { do_sigver_init checked that |digest_custom| is non-nil }
    if (pctx.flag_call_digest_custom > 0)
         and  (0>=ctx.pctx.pmeth.digest_custom(ctx.pctx, ctx )) then
        Exit(0);
    pctx.flag_call_digest_custom := 0;
    if Assigned(pctx.pmeth.verifyctx) then
       vctx := 1
    else
        vctx := 0;
    if (ctx.flags and EVP_MD_CTX_FLAG_FINALISE) > 0 then
    begin
        if vctx > 0 then
            r := pctx.pmeth.verifyctx(pctx, sig, siglen, ctx)
        else
            r := EVP_DigestFinal_ex(ctx, @md, @mdlen);
    end
    else
    begin
        tmp_ctx := EVP_MD_CTX_new;
        if tmp_ctx = nil then Exit(-1);
        if 0>=EVP_MD_CTX_copy_ex(tmp_ctx, ctx ) then
        begin
            EVP_MD_CTX_free(tmp_ctx);
            Exit(-1);
        end;
        if vctx > 0 then
           r := tmp_ctx.pctx.pmeth.verifyctx(tmp_ctx.pctx,
                                                sig, siglen, tmp_ctx)
        else
            r := EVP_DigestFinal_ex(tmp_ctx, @md, @mdlen);
        EVP_MD_CTX_free(tmp_ctx);
    end;
    if (vctx > 0) or  (0>=r) then
       Exit(r);
    Result := EVP_PKEY_verify(pctx, sig, siglen, @md, mdlen);
end;

function EVP_DigestVerifyUpdate(ctx : PEVP_MD_CTX;const data : Pointer; dsize : size_t):integer;
var
  pctx : PEVP_PKEY_CTX;
  label _legacy;
begin
    pctx := ctx.pctx;
    if (pctx = nil)
             or  (pctx.operation <> EVP_PKEY_OP_VERIFYCTX)
             or  (pctx.op.sig.algctx = nil)
             or  (pctx.op.sig.signature = nil) then
             goto _legacy;
    if not Assigned(pctx.op.sig.signature.digest_verify_update) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Exit(pctx.op.sig.signature.digest_verify_update(pctx.op.sig.algctx,
                                                        data, dsize));
 _legacy:
    if pctx <> nil then
    begin
        { do_sigver_init checked that |digest_custom| is non-nil }
        if (pctx.flag_call_digest_custom > 0)
             and  (0>=ctx.pctx.pmeth.digest_custom(ctx.pctx, ctx)) then
            Exit(0);
        pctx.flag_call_digest_custom := 0;
    end;
    Result := EVP_DigestUpdate(ctx, data, dsize);
end;


function EVP_DigestVerify(ctx : PEVP_MD_CTX;const sigret : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  pctx : PEVP_PKEY_CTX;
begin
    pctx := ctx.pctx;
    if (pctx <> nil)
             and  (pctx.operation = EVP_PKEY_OP_VERIFYCTX)
             and  (pctx.op.sig.algctx <> nil)
             and  (pctx.op.sig.signature <> nil) then
    begin
        if Assigned(pctx.op.sig.signature.digest_verify) then
            Exit(pctx.op.sig.signature.digest_verify(pctx.op.sig.algctx,
                                                         sigret, siglen,
                                                         tbs, tbslen));
    end
    else
    begin
        { legacy }
        if (ctx.pctx.pmeth <> nil)  and  (Assigned(ctx.pctx.pmeth.digestverify)) then
           Exit(ctx.pctx.pmeth.digestverify(ctx, sigret, siglen, tbs, tbslen));
    end;
    if EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0  then
        Exit(-1);
    Result := EVP_DigestVerifyFinal(ctx, sigret, siglen);
end;

function canon_mdname(const mdname : PUTF8Char):PUTF8Char;
begin
    if (mdname <> nil)  and  (strcmp(mdname, 'UNDEF') = 0) then
        Exit(nil);
    Result := mdname;
end;

function do_sigver_init(ctx : PEVP_MD_CTX; pctx : PPEVP_PKEY_CTX;{const} _type : PEVP_MD; mdname : PUTF8Char; libctx : POSSL_LIB_CTX;{const} props : PUTF8Char; e : PENGINE; pkey : PEVP_PKEY; ver : integer;const params : POSSL_PARAM):integer;
var
    locpctx            : PEVP_PKEY_CTX;
    signature          : PEVP_SIGNATURE;
    tmp_keymgmt        : PEVP_KEYMGMT;
    tmp_prov           : POSSL_PROVIDER;
    supported_sig      : PUTF8Char;
    locmdname          : array[0..79] of UTF8Char;
    provkey            : Pointer;
    ret,
    iter,
    reinit             : integer;
    tmp_keymgmt_tofree : PEVP_KEYMGMT;
    def_nid            : integer;
    label _legacy, _reinitialize, _err, _end;
begin
    locpctx := nil;
    signature := nil;
    tmp_keymgmt := nil;
     tmp_prov := nil;
     supported_sig := nil;
    locmdname := '';
    provkey := nil;
    reinit := 1;
    if ctx.algctx <> nil then
    begin
        if not ossl_assert(ctx.digest <> nil) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
        if Assigned(ctx.digest.freectx) then
           ctx.digest.freectx(ctx.algctx);
        ctx.algctx := nil;
    end;
    if ctx.pctx = nil then
    begin
        reinit := 0;
        if e = nil then
           ctx.pctx := EVP_PKEY_CTX_new_from_pkey(libctx, pkey, props)
        else
            ctx.pctx := EVP_PKEY_CTX_new(pkey, e);
    end;
    if ctx.pctx = nil then
       Exit(0);
    locpctx := ctx.pctx;
    ERR_set_mark;
    if evp_pkey_ctx_is_legacy(locpctx) then
        goto _legacy;
    { do not reinitialize if pkey is set or operation is different }
    signature := locpctx.op.sig.signature;
    if (reinit > 0)
         and ( (pkey <> nil)
             or (locpctx.operation <> get_result(ver>0 , EVP_PKEY_OP_VERIFYCTX
                                          , EVP_PKEY_OP_SIGNCTX))
             or (signature =  nil)
             or  (locpctx.op.sig.algctx = nil)) then
        reinit := 0;
    if props = nil then
       props := locpctx.propquery;
    if locpctx.pkey = nil then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        goto _err;
    end;
    if 0>=reinit then
    begin
        evp_pkey_ctx_free_old_ops(locpctx);
    end
    else
    begin
        if (mdname = nil)  and  (_type = nil) then
           mdname := canon_mdname(EVP_MD_get0_name(ctx.reqdigest));
        goto _reinitialize;
    end;
    {
     * Try to derive the supported signature from |locpctx.keymgmt|.
     }
    if not ossl_assert( (locpctx.pkey.keymgmt = nil)
                     or (locpctx.pkey.keymgmt = locpctx.keymgmt)  ) then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    supported_sig := evp_keymgmt_util_query_operation_name(locpctx.keymgmt,
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
    iter := 1; provkey := nil;
    while (iter < 3)  and  (provkey = nil) do
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
                signature := EVP_SIGNATURE_fetch(locpctx.libctx, supported_sig,
                                                locpctx.propquery);
                if signature <> nil then
                   tmp_prov := EVP_SIGNATURE_get0_provider(signature);
            end;
            2:
            begin
                tmp_prov := EVP_KEYMGMT_get0_provider(locpctx.keymgmt);
                signature := evp_signature_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                                  supported_sig, locpctx.propquery);
                if signature = nil then goto _legacy;
            end;
        end;
        if signature = nil then continue;
        {
         * Ensure that the key is provided, either natively, or as a cached
         * export.  We start by fetching the keymgmt with the same name as
         * |locpctx.pkey|, but from the provider of the signature method, using
         * the same property query as when fetching the signature method.
         * With the keymgmt we found (if we did), we try to export |locpctx.pkey|
         * to it (evp_pkey_export_to_provider is smart enough to only actually
         * export it if |tmp_keymgmt| is different from |locpctx.pkey|'s keymgmt)
         }
        tmp_keymgmt := evp_keymgmt_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                        EVP_KEYMGMT_get0_name(locpctx.keymgmt),
                                        locpctx.propquery);
        tmp_keymgmt_tofree := tmp_keymgmt;
        if tmp_keymgmt <> nil then
           provkey := evp_pkey_export_to_provider(locpctx.pkey, locpctx.libctx,
                                                  @tmp_keymgmt, locpctx.propquery);
        if tmp_keymgmt = nil then
           EVP_KEYMGMT_free(tmp_keymgmt_tofree);
        Inc(iter  );
    end;
    if provkey = nil then
    begin
        EVP_SIGNATURE_free(signature);
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
    ERR_pop_to_mark;
    { No more legacy from here down to legacy: }
    locpctx.op.sig.signature := signature;
    locpctx.operation := get_result(ver>0 , EVP_PKEY_OP_VERIFYCTX
                             , EVP_PKEY_OP_SIGNCTX);
    locpctx.op.sig.algctx := signature.newctx(ossl_provider_ctx(signature.prov), props);
    if locpctx.op.sig.algctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP,  EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
 _reinitialize:
    if pctx <> nil then
       pctx^ := locpctx;
    if _type <> nil then
    begin
        ctx.reqdigest := _type;
        if mdname = nil then
           mdname := canon_mdname(EVP_MD_get0_name(_type));
    end
    else
    begin
        if (mdname = nil)  and  (0>=reinit) then
        begin
            if (evp_keymgmt_util_get_deflt_digest_name(tmp_keymgmt, provkey,
                                                       locmdname,
                                                       sizeof(locmdname)) > 0) then
            begin
                mdname := canon_mdname(locmdname);
            end;
        end;
        if mdname <> nil then
        begin
            {
             * We're about to get a new digest so clear anything associated with
             * an old digest.
             }
            evp_md_ctx_clear_digest(ctx, 1);
            { legacy code support for engines }
            ERR_set_mark;
            {
             * This might be requested by a later call to EVP_MD_CTX_get0_md.
             * In that case the 'explicit fetch' rules apply for that
             * function (as per man pages), i.e. the ref count is not updated
             * so the EVP_MD should not be used beyond the lifetime of the
             * EVP_MD_CTX.
             }
            ctx.fetched_digest := EVP_MD_fetch(locpctx.libctx, mdname, props);
            if ctx.fetched_digest <> nil then
            begin
                ctx.digest := ctx.fetched_digest;
                ctx.reqdigest := ctx.fetched_digest;
            end
            else
            begin
                { legacy engine support : remove the mark when this is deleted }
                ctx.digest := EVP_get_digestbyname(mdname);
                ctx.reqdigest := ctx.digest ;
                if ctx.digest = nil then
                begin
                    ERR_clear_last_mark;
                    ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
                    goto _err;
                end;
            end;
            ERR_pop_to_mark;
        end;
    end;
    if ver > 0 then
    begin
        if not Assigned(signature.digest_verify_init) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err;
        end;
        ret := signature.digest_verify_init(locpctx.op.sig.algctx,
                                            mdname, provkey, params);
    end
    else
    begin
        if not Assigned(signature.digest_sign_init) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err;
        end;
        ret := signature.digest_sign_init(locpctx.op.sig.algctx,
                                          mdname, provkey, params);
    end;
    {
     * If the operation was not a success and no digest was found, an error
     * needs to be raised.
     }
    if (ret > 0)  or  (mdname <> nil) then
        goto _end;
    if _type = nil then { This check is redundant but clarifies matters }
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_DEFAULT_DIGEST);
 _err:
    evp_pkey_ctx_free_old_ops(locpctx);
    locpctx.operation := EVP_PKEY_OP_UNDEFINED;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Exit(0);
 _legacy:
    {
     * If we don't have the full support we need with provided methods,
     * let's go see if legacy does.
     }
    ERR_pop_to_mark;
    EVP_KEYMGMT_free(tmp_keymgmt);
    tmp_keymgmt := nil;
    if (_type = nil)  and  (mdname <> nil) then
       _type := evp_get_digestbyname_ex(locpctx.libctx, mdname);
    if ctx.pctx.pmeth = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(0);
    end;
    if 0>=(ctx.pctx.pmeth.flags and EVP_PKEY_FLAG_SIGCTX_CUSTOM) then
    begin
        if _type = nil then
        begin
            if EVP_PKEY_get_default_digest_nid(pkey, @def_nid) > 0 then
                _type := EVP_get_digestbynid(def_nid);
        end;
        if _type = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_NO_DEFAULT_DIGEST);
            Exit(0);
        end;
    end;
    if ver > 0 then
    begin
        if Assigned(ctx.pctx.pmeth.verifyctx_init) then
        begin
            if ctx.pctx.pmeth.verifyctx_init(ctx.pctx, ctx) <= 0 then
                Exit(0);
            ctx.pctx.operation := EVP_PKEY_OP_VERIFYCTX;
        end
        else
        if Assigned(ctx.pctx.pmeth.digestverify) then
        begin
            ctx.pctx.operation := EVP_PKEY_OP_VERIFY;
            ctx.update := update;
        end
        else
        if (EVP_PKEY_verify_init(ctx.pctx) <= 0) then
        begin
            Exit(0);
        end;
    end
    else
    begin
        if Assigned(ctx.pctx.pmeth.signctx_init) then
        begin
            if ctx.pctx.pmeth.signctx_init(ctx.pctx, ctx) <= 0 then
                Exit(0);
            ctx.pctx.operation := EVP_PKEY_OP_SIGNCTX;
        end
        else
        if Assigned(ctx.pctx.pmeth.digestsign) then
        begin
            ctx.pctx.operation := EVP_PKEY_OP_SIGN;
            ctx.update := update;
        end
        else
        if (EVP_PKEY_sign_init(ctx.pctx) <= 0) then
        begin
            Exit(0);
        end;
    end;
    if EVP_PKEY_CTX_set_signature_md(ctx.pctx, _type) <= 0  then
        Exit(0);
    if pctx <> nil then
       pctx^ := ctx.pctx;
    if (ctx.pctx.pmeth.flags and EVP_PKEY_FLAG_SIGCTX_CUSTOM) > 0 then
       Exit(1);
    if 0>=EVP_DigestInit_ex(ctx, _type, e ) then
        Exit(0);
    {
     * This indicates the current algorithm requires
     * special treatment before hashing the tbs-message.
     }
    ctx.pctx.flag_call_digest_custom := 0;
    if Assigned(ctx.pctx.pmeth.digest_custom) then
       ctx.pctx.flag_call_digest_custom := 1;
    ret := 1;
 _end:
{$IFNDEF FIPS_MODULE}
    if ret > 0 then ret := evp_pkey_ctx_use_cached_data(locpctx);
{$ENDIF}
    EVP_KEYMGMT_free(tmp_keymgmt);
    Result := get_result(ret > 0 , 1 , 0);
end;


function EVP_DigestVerifyInit(ctx : PEVP_MD_CTX; pctx : PPEVP_PKEY_CTX;const _type : PEVP_MD; e : PENGINE; pkey : PEVP_PKEY):integer;
begin
    Exit(do_sigver_init(ctx, pctx, _type, nil, nil, nil, e, pkey, 1, nil));
end;


end.
