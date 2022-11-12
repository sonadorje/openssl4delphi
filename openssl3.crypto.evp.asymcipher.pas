unit openssl3.crypto.evp.asymcipher;

interface
uses OpenSSL.Api;

function EVP_ASYM_CIPHER_get0_provider(const cipher : PEVP_ASYM_CIPHER):POSSL_PROVIDER;
procedure EVP_ASYM_CIPHER_free( cipher : PEVP_ASYM_CIPHER);
function EVP_ASYM_CIPHER_up_ref( cipher : PEVP_ASYM_CIPHER):integer;
function EVP_PKEY_encrypt_init( ctx : PEVP_PKEY_CTX):integer;
function evp_pkey_asym_cipher_init(ctx : PEVP_PKEY_CTX; operation : integer;const params : POSSL_PARAM):integer;
function EVP_ASYM_CIPHER_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_ASYM_CIPHER;

function evp_asym_cipher_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_asym_cipher_new( prov : POSSL_PROVIDER):PEVP_ASYM_CIPHER;

function _OSSL_FUNC_asym_cipher_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_newctx_fn;
function _OSSL_FUNC_asym_cipher_encrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_encrypt_init_fn;
function _OSSL_FUNC_asym_cipher_encrypt(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_encrypt_fn;
function _OSSL_FUNC_asym_cipher_decrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_decrypt_init_fn;
function _OSSL_FUNC_asym_cipher_decrypt(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_decrypt_fn;
function _OSSL_FUNC_asym_cipher_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_freectx_fn;
function _OSSL_FUNC_asym_cipher_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_dupctx_fn;
function _OSSL_FUNC_asym_cipher_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_get_ctx_params_fn;
function _OSSL_FUNC_asym_cipher_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_gettable_ctx_params_fn;
function _OSSL_FUNC_asym_cipher_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_set_ctx_params_fn;
function _OSSL_FUNC_asym_cipher_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_settable_ctx_params_fn;
function evp_asym_cipher_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_ASYM_CIPHER;
function EVP_PKEY_decrypt_init( ctx : PEVP_PKEY_CTX):integer;
function EVP_PKEY_encrypt(ctx : PEVP_PKEY_CTX; _out : PByte; outlen : Psize_t;const _in : PByte; inlen : size_t):integer;
function EVP_PKEY_decrypt(ctx : PEVP_PKEY_CTX; _out : PByte; outlen : Psize_t;const _in : PByte; inlen : size_t):integer;
function EVP_PKEY_encrypt_init_ex(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
function EVP_PKEY_decrypt_init_ex(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;

implementation

uses openssl3.crypto.mem, OpenSSL3.Err,      OpenSSL3.threads_none,
     openssl3.crypto.evp,                    OpenSSL3.common,
     openssl3.crypto.evp.pmeth_lib,          openssl3.providers.fips.fipsprov,
     openssl3.crypto.evp.keymgmt_lib,        openssl3.crypto.evp.keymgmt_meth,
     openssl3.crypto.evp.evp_fetch,          openssl3.crypto.core_algorithm,
     OpenSSL3.openssl.core_dispatch,         openssl3.crypto.evp.p_lib,
     openssl3.include.internal.refcount,     openssl3.crypto.provider_core;




function EVP_PKEY_decrypt_init_ex(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
begin
    Result := evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_DECRYPT, params);
end;

function EVP_PKEY_encrypt_init_ex(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
begin
    Result := evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_ENCRYPT, params);
end;


function EVP_PKEY_decrypt(ctx : PEVP_PKEY_CTX; _out : PByte; outlen : Psize_t;const _in : PByte; inlen : size_t):integer;
var
  ret : integer;
  pksize: size_t;
  label _legacy;
begin
    if ctx = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if ctx.operation <> EVP_PKEY_OP_DECRYPT then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.ciph.algctx = nil then goto _legacy;
    ret := ctx.op.ciph.cipher.decrypt(ctx.op.ciph.algctx, _out, outlen,
                                      get_result(_out = nil , 0 , outlen^), _in, inlen);
    Exit(ret);

 _legacy:
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.decrypt)) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if (ctx.pmeth.flags and 2) > 0 then
    begin
      pksize := size_t(EVP_PKEY_get_size(ctx.pkey));
      if (pksize = 0) then
      begin
         ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
         Exit( 0);
      end;
      if (_out = nil) then
      begin
         outlen^ := pksize;
         Exit( 1);
      end;
      if (outlen^ < pksize) then
      begin
         ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL);
         Exit( 0);
      end;
    end;

    Result := ctx.pmeth.decrypt(ctx, _out, outlen, _in, inlen);
end;



function EVP_PKEY_encrypt(ctx : PEVP_PKEY_CTX; _out : PByte; outlen : Psize_t;const _in : PByte; inlen : size_t):integer;
var
  ret : integer;
  pksize: size_t;
  label  _legacy;

begin
    if ctx = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if ctx.operation <> EVP_PKEY_OP_ENCRYPT then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    if ctx.op.ciph.algctx = nil then goto _legacy;
    ret := ctx.op.ciph.cipher.encrypt(ctx.op.ciph.algctx, _out, outlen,
                                      get_result(_out = nil , 0 , outlen^), _in, inlen);
    Exit(ret);
 _legacy:
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.encrypt)) then
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

        if (_out = nil)  then
        begin
           outlen^ := pksize;
           Exit( 1);
        end;
        if (outlen^ < pksize) then
        begin
          ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL);
          exit(0);
        end;
    end;

    Result := ctx.pmeth.encrypt(ctx, _out, outlen, _in, inlen);
end;


function EVP_PKEY_decrypt_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_DECRYPT, nil);
end;



function evp_asym_cipher_fetch_from_prov(prov : POSSL_PROVIDER;const algorithm, properties : PUTF8Char):PEVP_ASYM_CIPHER;
begin
    Exit(evp_generic_fetch_from_prov(prov, OSSL_OP_ASYM_CIPHER,
                                       algorithm, properties,
                                       evp_asym_cipher_from_algorithm,
                                       @EVP_ASYM_CIPHER_up_ref,
                                       @EVP_ASYM_CIPHER_free));
end;




function _OSSL_FUNC_asym_cipher_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_newctx_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_newctx_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_encrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_encrypt_init_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_encrypt_init_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_encrypt(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_encrypt_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_encrypt_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_decrypt_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_decrypt_init_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_decrypt_init_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_decrypt(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_decrypt_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_decrypt_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_freectx_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_freectx_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_dupctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_dupctx_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_dupctx_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_get_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_get_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_get_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_gettable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_gettable_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_set_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_set_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_asym_cipher_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_asym_cipher_settable_ctx_params_fn;
begin
 Result := opf.method.Code; // OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)opf.function;
end;


function evp_asym_cipher_new( prov : POSSL_PROVIDER):PEVP_ASYM_CIPHER;
var
  cipher : PEVP_ASYM_CIPHER;
begin
    cipher := OPENSSL_zalloc(sizeof(TEVP_ASYM_CIPHER));
    if cipher = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    cipher.lock := CRYPTO_THREAD_lock_new;
    if cipher.lock = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(cipher);
        Exit(nil);
    end;
    cipher.prov := prov;
    ossl_provider_up_ref(prov);
    cipher.refcnt := 1;
    Result := cipher;
end;



function evp_asym_cipher_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  fns         : POSSL_DISPATCH;
  cipher      : PEVP_ASYM_CIPHER;
  ctxfncnt, encfncnt, decfncnt ,
  gparamfncnt, sparamfncnt : integer;
  label _err;
begin
     fns := algodef._implementation;
    cipher := nil;
    ctxfncnt := 0; encfncnt := 0; decfncnt := 0;
    gparamfncnt := 0; sparamfncnt := 0;
    cipher := evp_asym_cipher_new(prov);
    if cipher = nil then  begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    cipher.name_id := name_id;
    cipher.type_name := ossl_algorithm_get1_first_name(algodef);
    if cipher.type_name = nil then
        goto _err;
    cipher.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
      case fns.function_id of
        OSSL_FUNC_ASYM_CIPHER_NEWCTX:
        begin
            if Assigned(cipher.newctx) then break;
            cipher.newctx := _OSSL_FUNC_asym_cipher_newctx(fns);
            PostInc(ctxfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT:
        begin
            if Assigned(cipher.encrypt_init) then break;
            cipher.encrypt_init := _OSSL_FUNC_asym_cipher_encrypt_init(fns);
            PostInc(encfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_ENCRYPT:
        begin
            if Assigned(cipher.encrypt) then break;
            cipher.encrypt := _OSSL_FUNC_asym_cipher_encrypt(fns);
            PostInc(encfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT:
        begin
            if Assigned(cipher.decrypt_init) then break;
            cipher.decrypt_init := _OSSL_FUNC_asym_cipher_decrypt_init(fns);
            PostInc(decfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_DECRYPT:
        begin
            if Assigned(cipher.decrypt) then break;
            cipher.decrypt := _OSSL_FUNC_asym_cipher_decrypt(fns);
            PostInc(decfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_FREECTX:
        begin
            if Assigned(cipher.freectx) then break;
            cipher.freectx := _OSSL_FUNC_asym_cipher_freectx(fns);
            PostInc(ctxfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_DUPCTX:
        begin
            if Assigned(cipher.dupctx) then break;
            cipher.dupctx := _OSSL_FUNC_asym_cipher_dupctx(fns);
        end;
        OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS:
        begin
            if Assigned(cipher.get_ctx_params) then break;
            cipher.get_ctx_params := _OSSL_FUNC_asym_cipher_get_ctx_params(fns);
            PostInc(gparamfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS:
        begin
            if Assigned(cipher.gettable_ctx_params) then break;
            cipher.gettable_ctx_params := _OSSL_FUNC_asym_cipher_gettable_ctx_params(fns);
            PostInc(gparamfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS:
        begin
            if Assigned(cipher.set_ctx_params) then break;
            cipher.set_ctx_params := _OSSL_FUNC_asym_cipher_set_ctx_params(fns);
            PostInc(sparamfncnt);
        end;
        OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS:
        begin
            if Assigned(cipher.settable_ctx_params) then break;
            cipher.settable_ctx_params := _OSSL_FUNC_asym_cipher_settable_ctx_params(fns);
            PostInc(sparamfncnt);
        end;
        end;
        Inc(fns);
    end;
    if (ctxfncnt <> 2)
         or  ( (encfncnt <> 0)  and  (encfncnt <> 2) )
         or  ( (decfncnt <> 0)  and  (decfncnt <> 2)  )
         or  ( (encfncnt <> 2)  and  (decfncnt <> 2) )
         or  ( (gparamfncnt <> 0)  and  (gparamfncnt <> 2) )
         or  ( (sparamfncnt <> 0)  and  (sparamfncnt <> 2) ) then
    begin
        {
         * In order to be a consistent set of functions we must have at least
         * a set of context functions (newctx and freectx) as well as a pair of
         * 'cipher' functions: (encrypt_init, encrypt) or
         * (decrypt_init decrypt). set_ctx_params and settable_ctx_params are
         * optional, but if one of them is present then the other one must also
         * be present. The same applies to get_ctx_params and
         * gettable_ctx_params. The dupctx function is optional.
         }
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        goto _err;
    end;
    Exit(cipher);
 _err:
    EVP_ASYM_CIPHER_free(cipher);
    Result := nil;
end;



function EVP_ASYM_CIPHER_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_ASYM_CIPHER;
begin
    Exit(evp_generic_fetch(ctx, OSSL_OP_ASYM_CIPHER, algorithm, properties,
                             evp_asym_cipher_from_algorithm,
                             @EVP_ASYM_CIPHER_up_ref,
                             @EVP_ASYM_CIPHER_free));
end;

function evp_pkey_asym_cipher_init(ctx : PEVP_PKEY_CTX; operation : integer;const params : POSSL_PARAM):integer;
var
    ret                : integer;
    provkey            : Pointer;
    cipher             : PEVP_ASYM_CIPHER;
    tmp_keymgmt        : PEVP_KEYMGMT;
    tmp_prov           : POSSL_PROVIDER;
    supported_ciph     : PUTF8Char;
    iter               : integer;
    tmp_keymgmt_tofree : PEVP_KEYMGMT;
    label _legacy, _err;
begin
    ret := 0;
    provkey := nil;
    cipher := nil;
    tmp_keymgmt := nil;
    tmp_prov := nil;
    supported_ciph := nil;
    if ctx = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := operation;
    ERR_set_mark;
    if evp_pkey_ctx_is_legacy(ctx) then
        goto _legacy;
    if ctx.pkey = nil then begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        goto _err;
    end;
    {
     * Try to derive the supported asym cipher from |ctx.keymgmt|.
     }
    if not ossl_assert( (ctx.pkey.keymgmt = nil)
                      or (ctx.pkey.keymgmt = ctx.keymgmt)) then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    supported_ciph := evp_keymgmt_util_query_operation_name(ctx.keymgmt,
                                                OSSL_OP_ASYM_CIPHER);
    if supported_ciph = nil then
    begin
        ERR_clear_last_mark;
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
    {
     * We perform two iterations:
     *
     * 1.  Do the normal asym cipher fetch, using the fetching data given by
     *     the EVP_PKEY_CTX.
     * 2.  Do the provider specific asym cipher fetch, from the same provider
     *     as |ctx.keymgmt|
     *
     * We then try to fetch the keymgmt from the same provider as the
     * asym cipher, and try to export |ctx.pkey| to that keymgmt (when
     * this keymgmt happens to be the same as |ctx.keymgmt|, the export
     * is a no-op, but we call it anyway to not complicate the code even
     * more).
     * If the export call succeeds (returns a non-nil provider key pointer),
     * we're done and can perform the operation itself.  If not, we perform
     * the second iteration, or jump to legacy.
     }
    iter := 1; provkey := nil;
    while (iter < 3)  and  (provkey = nil)  do
    begin
        {
         * If we're on the second iteration, free the results from the first.
         * They are nil on the first iteration, so no need to check what
         * iteration we're on.
         }
        EVP_ASYM_CIPHER_free(cipher);
        EVP_KEYMGMT_free(tmp_keymgmt);
        case iter of
            1:
            begin
                cipher := EVP_ASYM_CIPHER_fetch(ctx.libctx, supported_ciph,
                                               ctx.propquery);
                if cipher <> nil then tmp_prov := EVP_ASYM_CIPHER_get0_provider(cipher);
            end;
            2:
            begin
                tmp_prov := EVP_KEYMGMT_get0_provider(ctx.keymgmt);
                cipher := evp_asym_cipher_fetch_from_prov(POSSL_PROVIDER(tmp_prov),
                                                    supported_ciph, ctx.propquery);
                if cipher = nil then goto _legacy;
            end;
        end;
        if cipher = nil then continue;
        {
         * Ensure that the key is provided, either natively, or as a cached
         * export.  We start by fetching the keymgmt with the same name as
         * |ctx.pkey|, but from the provider of the asym cipher method, using
         * the same property query as when fetching the asym cipher method.
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
        inc(iter);
    end;
    if provkey = nil then
    begin
        EVP_ASYM_CIPHER_free(cipher);
        goto _legacy;
    end;
    ERR_pop_to_mark;
    { No more legacy from here down to legacy: }
    ctx.op.ciph.cipher := cipher;
    ctx.op.ciph.algctx := cipher.newctx(ossl_provider_ctx(cipher.prov));
    if ctx.op.ciph.algctx = nil then begin
        { The provider key can stay in the cache }
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        goto _err;
    end;
    case operation of
        EVP_PKEY_OP_ENCRYPT:
        begin
            if not Assigned(cipher.encrypt_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err;
            end;
            ret := cipher.encrypt_init(ctx.op.ciph.algctx, provkey, params);
        end;
        EVP_PKEY_OP_DECRYPT:
        begin
            if not Assigned(cipher.decrypt_init) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret := -2;
                goto _err;
            end;
            ret := cipher.decrypt_init(ctx.op.ciph.algctx, provkey, params);
        end;
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            goto _err;
        end;
    end;
    if ret <= 0 then goto _err;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Exit(1);
 _legacy:
    {
     * If we don't have the full support we need with provided methods,
     * let's go see if legacy does.
     }
    ERR_pop_to_mark;
    EVP_KEYMGMT_free(tmp_keymgmt);
    tmp_keymgmt := nil;
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.encrypt)) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    case ctx.operation of
        EVP_PKEY_OP_ENCRYPT:
        begin
            if not Assigned(ctx.pmeth.encrypt_init) then Exit(1);
            ret := ctx.pmeth.encrypt_init(ctx);
        end;
        EVP_PKEY_OP_DECRYPT:
        begin
            if not Assigned(ctx.pmeth.decrypt_init) then Exit(1);
            ret := ctx.pmeth.decrypt_init(ctx);
        end;
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            ret := -1;
        end;
    end;
 _err:
    if ret <= 0 then begin
        evp_pkey_ctx_free_old_ops(ctx);
        ctx.operation := EVP_PKEY_OP_UNDEFINED;
    end;
    EVP_KEYMGMT_free(tmp_keymgmt);
    Result := ret;
end;

function EVP_PKEY_encrypt_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_ENCRYPT, nil);
end;


function EVP_ASYM_CIPHER_up_ref( cipher : PEVP_ASYM_CIPHER):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(cipher.refcnt, ref, cipher.lock);
    Result := 1;
end;

procedure EVP_ASYM_CIPHER_free( cipher : PEVP_ASYM_CIPHER);
var
  i : integer;
begin
    if cipher = nil then Exit;
    CRYPTO_DOWN_REF(cipher.refcnt, i, cipher.lock);
    if i > 0 then Exit;
    OPENSSL_free(cipher.type_name);
    ossl_provider_free(cipher.prov);
    CRYPTO_THREAD_lock_free(cipher.lock);
    OPENSSL_free(cipher);
end;



function EVP_ASYM_CIPHER_get0_provider(const cipher : PEVP_ASYM_CIPHER):POSSL_PROVIDER;
begin
    Result := cipher.prov;
end;


end.
