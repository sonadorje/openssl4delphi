unit openssl3.crypto.evp.exchange;

interface
uses OpenSSL.Api;

 function EVP_KEYEXCH_get0_provider(const exchange : PEVP_KEYEXCH):POSSL_PROVIDER;
 function EVP_KEYEXCH_up_ref( exchange : PEVP_KEYEXCH):integer;
procedure EVP_KEYEXCH_free( exchange : PEVP_KEYEXCH);
 function EVP_PKEY_derive_init( ctx : PEVP_PKEY_CTX):integer;
function EVP_PKEY_derive_init_ex(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
function EVP_KEYEXCH_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KEYEXCH;
function evp_keyexch_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_keyexch_new( prov : POSSL_PROVIDER):PEVP_KEYEXCH;

function _OSSL_FUNC_keyexch_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_newctx_fn;
function _OSSL_FUNC_keyexch_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_init_fn;
function _OSSL_FUNC_keyexch_derive(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_derive_fn;
function _OSSL_FUNC_keyexch_set_peer(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_set_peer_fn;
function _OSSL_FUNC_keyexch_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_freectx_fn;
function _OSSL_FUNC_keyexch_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_dupctx_fn;
function _OSSL_FUNC_keyexch_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_set_ctx_params_fn;
function _OSSL_FUNC_keyexch_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_settable_ctx_params_fn;
function _OSSL_FUNC_keyexch_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_get_ctx_params_fn;
function _OSSL_FUNC_keyexch_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_gettable_ctx_params_fn;
function evp_keyexch_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_KEYEXCH;
function EVP_PKEY_derive_set_peer( ctx : PEVP_PKEY_CTX; peer : PEVP_PKEY):integer;
function EVP_PKEY_derive_set_peer_ex( ctx : PEVP_PKEY_CTX; peer : PEVP_PKEY; validate_peer : integer):integer;
function EVP_PKEY_derive( ctx : PEVP_PKEY_CTX; key : PByte; pkeylen : Psize_t):integer;

implementation

 uses openssl3.include.internal.refcount,  openssl3.crypto.mem, OpenSSL3.Err,
      openssl3.crypto.evp.pmeth_lib,       openssl3.providers.fips.fipsprov,
      openssl3.crypto.evp,                 openssl3.crypto.evp.p_lib,
      openssl3.crypto.evp.keymgmt_meth,    OpenSSL3.common,
      openssl3.crypto.evp.keymgmt_lib,     openssl3.crypto.evp.evp_fetch,
      openssl3.crypto.core_algorithm,      openssl3.crypto.evp.pmeth_check,
      openssl3.crypto.provider_core,       OpenSSL3.threads_none;




function EVP_PKEY_derive( ctx : PEVP_PKEY_CTX; key : PByte; pkeylen : Psize_t):integer;
var
  ret : integer;
  pksize: size_t;
  label _legacy;
begin
    if (ctx = nil)  or  (pkeylen = nil) then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if not EVP_PKEY_CTX_IS_DERIVE_OP(ctx) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.kex.algctx = nil then goto _legacy;
    ret := ctx.op.kex.exchange.derive(ctx.op.kex.algctx, key, pkeylen,
                                      get_result(key <> nil , pkeylen^ , 0));
    Exit(ret);
 _legacy:
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.derive)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if (ctx.pmeth.flags and 2) > 0 then
    begin
       pksize := size_t(EVP_PKEY_get_size(ctx.pkey));
       if (pksize = 0) then
       begin
           ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
           Exit(0);
       end;
       if (key = nil) then
       begin
           pkeylen^ := pksize;
           Exit(1);
       end;
       if (pkeylen^ < pksize) then
       begin
          ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL);
          Exit( 0);
       end;
   end;

    Result := ctx.pmeth.derive(ctx, key, pkeylen);
end;



function EVP_PKEY_derive_set_peer_ex( ctx : PEVP_PKEY_CTX; peer : PEVP_PKEY; validate_peer : integer):integer;
var
  ret, check                : integer;
  provkey            : Pointer;
  check_ctx          : PEVP_PKEY_CTX;
  tmp_keymgmt,
  tmp_keymgmt_tofree : PEVP_KEYMGMT;
  label _legacy;
begin
    ret := 0;
    provkey := nil;
    check_ctx := nil;
    tmp_keymgmt := nil;
    tmp_keymgmt_tofree := nil;
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if (not EVP_PKEY_CTX_IS_DERIVE_OP(ctx))  or  (ctx.op.kex.algctx = nil) then
        goto _legacy;
    if not Assigned(ctx.op.kex.exchange.set_peer) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if validate_peer > 0 then
    begin
        check_ctx := EVP_PKEY_CTX_new_from_pkey(ctx.libctx, peer, ctx.propquery);
        if check_ctx = nil then Exit(-1);
        check := EVP_PKEY_public_check(check_ctx);
        EVP_PKEY_CTX_free(check_ctx);
        if check <= 0 then Exit(-1);
    end;
    {
     * Ensure that the |peer| is provided, either natively, or as a cached
     * export.  We start by fetching the keymgmt with the same name as
     * |ctx.keymgmt|, but from the provider of the exchange method, using
     * the same property query as when fetching the exchange method.
     * With the keymgmt we found (if we did), we try to export |peer|
     * to it (evp_pkey_export_to_provider is smart enough to only actually
     * export it if |tmp_keymgmt| is different from |peer|'s keymgmt)
     }
    tmp_keymgmt := evp_keymgmt_fetch_from_prov(POSSL_PROVIDER(
                                    EVP_KEYEXCH_get0_provider(ctx.op.kex.exchange)),
                                    EVP_KEYMGMT_get0_name(ctx.keymgmt),
                                    ctx.propquery);
    tmp_keymgmt_tofree := tmp_keymgmt;

    if tmp_keymgmt <> nil then
       provkey := evp_pkey_export_to_provider(peer, ctx.libctx,
                                              @tmp_keymgmt, ctx.propquery);
    EVP_KEYMGMT_free(tmp_keymgmt_tofree);
    {
     * If making the key provided wasn't possible, legacy may be able to pick
     * it up
     }
    if provkey = nil then goto _legacy;
    Exit(ctx.op.kex.exchange.set_peer(ctx.op.kex.algctx, provkey));
 _legacy:
{$IFDEF FIPS_MODULE}
    Exit(ret);
{$ELSE} if (ctx.pmeth = nil)
         or  (not ( (Assigned(ctx.pmeth.derive))   or
                    (Assigned(ctx.pmeth.encrypt))   or
                    (Assigned(ctx.pmeth.decrypt)) ) )
         or  (not Assigned(ctx.pmeth.ctrl)) then
        begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if (ctx.operation <> EVP_PKEY_OP_DERIVE)
         and  (ctx.operation <> EVP_PKEY_OP_ENCRYPT)
         and  (ctx.operation <> EVP_PKEY_OP_DECRYPT) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    ret := ctx.pmeth.ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 0, peer);
    if ret <= 0 then Exit(ret);
    if ret = 2 then Exit(1);
    if ctx.pkey = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        Exit(-1);
    end;
    if ctx.pkey.&type <> peer.&type then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
        Exit(-1);
    end;
    {
     * For clarity.  The error is if parameters in peer are
     * present (0>=missing) but don't match.  EVP_PKEY_parameters_eq may return
     * 1 (match), 0 (don't match) and -2 (comparison is not defined).  -1
     * (different key types) is impossible here because it is checked earlier.
     * -2 is OK for us here, as well as 1, so we can check for 0 only.
     }
    if (0>=EVP_PKEY_missing_parameters(peer))  and
       (0>=EVP_PKEY_parameters_eq(ctx.pkey, peer)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_PARAMETERS);
        Exit(-1);
    end;
    EVP_PKEY_free(ctx.peerkey);
    ctx.peerkey := peer;
    ret := ctx.pmeth.ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 1, peer);
    if ret <= 0 then begin
        ctx.peerkey := nil;
        Exit(ret);
    end;
    EVP_PKEY_up_ref(peer);
    Exit(1);
{$ENDIF}
end;

function EVP_PKEY_derive_set_peer( ctx : PEVP_PKEY_CTX; peer : PEVP_PKEY):integer;
begin
    Result := EVP_PKEY_derive_set_peer_ex(ctx, peer, 1);
end;



function evp_keyexch_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_KEYEXCH;
begin
    Exit(evp_generic_fetch_from_prov(prov, OSSL_OP_KEYEXCH,
                                       algorithm, properties,
                                       evp_keyexch_from_algorithm,
                                       @EVP_KEYEXCH_up_ref,
                                       @EVP_KEYEXCH_free));
end;


function _OSSL_FUNC_keyexch_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_newctx_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_newctx_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_init_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_init_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_derive(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_derive_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_derive_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_set_peer(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_set_peer_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_set_peer_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_freectx_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_freectx_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_dupctx_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_dupctx_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_set_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_set_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_settable_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_settable_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_get_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_get_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_keyexch_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keyexch_gettable_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_keyexch_gettable_ctx_params_fn *)opf.function;
end;




function evp_keyexch_new( prov : POSSL_PROVIDER):PEVP_KEYEXCH;
var
  exchange : PEVP_KEYEXCH;
begin
    exchange := OPENSSL_zalloc(sizeof(TEVP_KEYEXCH));
    if exchange = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    exchange.lock := CRYPTO_THREAD_lock_new;
    if exchange.lock = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(exchange);
        Exit(nil);
    end;
    exchange.prov := prov;
    ossl_provider_up_ref(prov);
    exchange.refcnt := 1;
    Result := exchange;
end;



function evp_keyexch_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  fns         : POSSL_DISPATCH;
  exchange    : PEVP_KEYEXCH;
  fncnt,
  sparamfncnt,
  gparamfncnt : integer;
  label _err;
begin
    fns := algodef._implementation;
    exchange := nil;
    fncnt := 0;
    sparamfncnt := 0;
    gparamfncnt := 0;
    exchange := evp_keyexch_new(prov);
    if exchange = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    exchange.name_id := name_id;
    exchange.type_name := ossl_algorithm_get1_first_name(algodef);
    if exchange.type_name = nil then
        goto _err;
    exchange.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
            OSSL_FUNC_KEYEXCH_NEWCTX:
            begin
                if Assigned(exchange.newctx) then break;
                exchange.newctx := _OSSL_FUNC_keyexch_newctx(fns);
                PostInc(fncnt);
            end;
            OSSL_FUNC_KEYEXCH_INIT:
            begin
                if Assigned(exchange.init) then break;
                exchange.init := _OSSL_FUNC_keyexch_init(fns);
                PostInc(fncnt);
            end;
            OSSL_FUNC_KEYEXCH_SET_PEER:
            begin
                if Assigned(exchange.set_peer) then break;
                exchange.set_peer := _OSSL_FUNC_keyexch_set_peer(fns);
            end;
            OSSL_FUNC_KEYEXCH_DERIVE:
            begin
                if Assigned(exchange.derive) then break;
                exchange.derive := _OSSL_FUNC_keyexch_derive(fns);
                PostInc(fncnt);
            end;
            OSSL_FUNC_KEYEXCH_FREECTX:
            begin
                if Assigned(exchange.freectx) then break;
                exchange.freectx := _OSSL_FUNC_keyexch_freectx(fns);
                PostInc(fncnt);
            end;
            OSSL_FUNC_KEYEXCH_DUPCTX:
            begin
                if Assigned(exchange.dupctx) then break;
                exchange.dupctx := _OSSL_FUNC_keyexch_dupctx(fns);
            end;
            OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS:
            begin
                if Assigned(exchange.get_ctx_params) then break;
                exchange.get_ctx_params := _OSSL_FUNC_keyexch_get_ctx_params(fns);
                PostInc(gparamfncnt);
            end;
            OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS:
            begin
                if Assigned(exchange.gettable_ctx_params) then break;
                exchange.gettable_ctx_params := _OSSL_FUNC_keyexch_gettable_ctx_params(fns);
                PostInc(gparamfncnt);
            end;
            OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS:
            begin
                if Assigned(exchange.set_ctx_params) then break;
                exchange.set_ctx_params := _OSSL_FUNC_keyexch_set_ctx_params(fns);
                PostInc(sparamfncnt);
            end;
            OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS:
            begin
                if Assigned(exchange.settable_ctx_params) then break;
                exchange.settable_ctx_params := _OSSL_FUNC_keyexch_settable_ctx_params(fns);
                PostInc(sparamfncnt);
            end;
        end;
        Inc(fns);
    end;
    if (fncnt <> 4) or
       ( (gparamfncnt <> 0)  and  (gparamfncnt <> 2) ) or
       ( (sparamfncnt <> 0)  and  (sparamfncnt <> 2) ) then
       begin
        {
         * In order to be a consistent set of functions we must have at least
         * a complete set of 'exchange' functions: init, derive, newctx,
         * and freectx. The set_ctx_params and settable_ctx_params functions are
         * optional, but if one of them is present then the other one must also
         * be present. Same goes for get_ctx_params and gettable_ctx_params.
         * The dupctx and set_peer functions are optional.
         }
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        goto _err;
    end;
    Exit(exchange);
 _err:
    EVP_KEYEXCH_free(exchange);
    Result := nil;
end;

function EVP_KEYEXCH_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KEYEXCH;
begin
    Exit(evp_generic_fetch(ctx, OSSL_OP_KEYEXCH, algorithm, properties,
                             evp_keyexch_from_algorithm,
                             @EVP_KEYEXCH_up_ref,
                             @EVP_KEYEXCH_free));
end;


function EVP_PKEY_derive_init_ex(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
var
    ret                : integer;
    provkey            : Pointer;
    exchange           : PEVP_KEYEXCH;
    tmp_keymgmt        : PEVP_KEYMGMT;
    tmp_prov           : POSSL_PROVIDER;
    supported_exch     : PUTF8Char;
    iter               : integer;
    pkey               : PEVP_PKEY;
    tmp_keymgmt_tofree : PEVP_KEYMGMT;
    label _legacy, _err;
begin
    provkey := nil;
    exchange := nil;
    tmp_keymgmt := nil;
    tmp_prov := nil;
    supported_exch := nil;
    if ctx = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-2);
    end;
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := EVP_PKEY_OP_DERIVE;
    ERR_set_mark;
    if evp_pkey_ctx_is_legacy(ctx) then
        goto _legacy;
    {
     * Some algorithms (e.g. legacy KDFs) don't have a pkey - so we create
     * a blank one.
     }
    if ctx.pkey = nil then
    begin
        pkey := EVP_PKEY_new;
        pkey.keydata := evp_keymgmt_newdata(ctx.keymgmt);
        if (pkey = nil) or  (0>=EVP_PKEY_set_type_by_keymgmt(pkey, ctx.keymgmt))  or
           (pkey.keydata = nil) then
        begin
            ERR_clear_last_mark;
            EVP_PKEY_free(pkey);
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err;
        end;
        ctx.pkey := pkey;
    end;
    {
     * Try to derive the supported exch from |ctx.keymgmt|.
     }
    if not ossl_assert( (ctx.pkey.keymgmt = nil)
                      or (ctx.pkey.keymgmt = ctx.keymgmt) ) then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    supported_exch := evp_keymgmt_util_query_operation_name(ctx.keymgmt,
                                                           OSSL_OP_KEYEXCH);
    if supported_exch = nil then begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
    {
     * We perform two iterations:
     *
     * 1.  Do the normal exchange fetch, using the fetching data given by
     *     the EVP_PKEY_CTX.
     * 2.  Do the provider specific exchange fetch, from the same provider
     *     as |ctx.keymgmt|
     *
     * We then try to fetch the keymgmt from the same provider as the
     * exchange, and try to export |ctx.pkey| to that keymgmt (when
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
        EVP_KEYEXCH_free(exchange);
        EVP_KEYMGMT_free(tmp_keymgmt);
        case iter of
            1:
            begin
                exchange := EVP_KEYEXCH_fetch(ctx.libctx, supported_exch, ctx.propquery);
                if exchange <> nil then
                   tmp_prov := EVP_KEYEXCH_get0_provider(exchange);
            end;
            2:
            begin
                tmp_prov := EVP_KEYMGMT_get0_provider(ctx.keymgmt);
                exchange := evp_keyexch_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                                  supported_exch, ctx.propquery);
                if exchange = nil then
                   goto _legacy;
            end;
        end;
        if exchange = nil then continue;
        {
         * Ensure that the key is provided, either natively, or as a cached
         * export.  We start by fetching the keymgmt with the same name as
         * |ctx.keymgmt|, but from the provider of the exchange method, using
         * the same property query as when fetching the exchange method.
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
        inc (iter);
    end;

    if provkey = nil then
    begin
        EVP_KEYEXCH_free(exchange);
        goto _legacy;
    end;
    ERR_pop_to_mark;
    { No more legacy from here down to legacy: }
    ctx.op.kex.exchange := exchange;
    ctx.op.kex.algctx := exchange.newctx(ossl_provider_ctx(exchange.prov));
    if ctx.op.kex.algctx = nil then
    begin
        { The provider key can stay in the cache }
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
    ret := exchange.init(ctx.op.kex.algctx, provkey, params);
    EVP_KEYMGMT_free(tmp_keymgmt);
    Exit(get_result(ret > 0, 1 , 0));
 _err:
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := EVP_PKEY_OP_UNDEFINED;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Exit(0);
 _legacy:
    {
     * If we don't have the full support we need with provided methods,
     * let's go see if legacy does.
     }
    ERR_pop_to_mark;
{$IFDEF FIPS_MODULE}
    Exit(0);
{$ELSE}
    if (ctx.pmeth = nil)  or  (Assigned(ctx.pmeth.derive)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if not Assigned(ctx.pmeth.derive_init) then Exit(1);
    ret := ctx.pmeth.derive_init(ctx);
    if ret <= 0 then ctx.operation := EVP_PKEY_OP_UNDEFINED;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Exit(ret);
{$ENDIF}
end;


function EVP_PKEY_derive_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := EVP_PKEY_derive_init_ex(ctx, nil);
end;


function EVP_KEYEXCH_up_ref( exchange : PEVP_KEYEXCH):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(exchange.refcnt, ref, exchange.lock);
    Result := 1;
end;

procedure EVP_KEYEXCH_free( exchange : PEVP_KEYEXCH);
var
  i : integer;
begin
    if exchange = nil then Exit;
    CRYPTO_DOWN_REF(exchange.refcnt, i, exchange.lock);
    if i > 0 then Exit;
    OPENSSL_free(exchange.type_name);
    ossl_provider_free(exchange.prov);
    CRYPTO_THREAD_lock_free(exchange.lock);
    OPENSSL_free(exchange);
end;



function EVP_KEYEXCH_get0_provider(const exchange : PEVP_KEYEXCH):POSSL_PROVIDER;
begin
    Result := exchange.prov;
end;


end.
