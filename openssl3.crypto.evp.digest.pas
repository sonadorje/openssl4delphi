unit openssl3.crypto.evp.digest;

interface
uses OpenSSL.Api;

procedure EVP_MD_free( md : Pointer);
function EVP_MD_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_MD;
function evp_md_from_algorithm({const} name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_md_new:PEVP_MD;
procedure set_legacy_nid(const name : PUTF8Char; vlegacy_nid : Pointer);
function evp_md_cache_constants( md : PEVP_MD):integer;
function _evp_md_up_ref( md : Pointer):integer;
function EVP_MD_up_ref( md : PEVP_MD):integer;
function EVP_DigestInit_ex2(ctx : PEVP_MD_CTX;const _type : PEVP_MD; params : POSSL_PARAM):integer;
function evp_md_init_internal(ctx : PEVP_MD_CTX; _type : PEVP_MD; params : POSSL_PARAM; impl : PENGINE):integer;
procedure cleanup_old_md_data( ctx : PEVP_MD_CTX; force : integer);
function EVP_MD_CTX_get_params( ctx : PEVP_MD_CTX; params : POSSL_PARAM):integer;
function EVP_MD_gettable_ctx_params(const md : PEVP_MD):POSSL_PARAM;
function EVP_MD_CTX_set_params(ctx : PEVP_MD_CTX;const params : POSSL_PARAM):integer;
function EVP_MD_settable_ctx_params(const md : PEVP_MD):POSSL_PARAM;
function EVP_MD_CTX_new:PEVP_MD_CTX;
function EVP_DigestInit_ex(ctx : PEVP_MD_CTX;const &type : PEVP_MD; impl : PENGINE):integer;
function EVP_DigestUpdate(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
function EVP_DigestFinal_ex( ctx : PEVP_MD_CTX; md : PByte; isize : Puint32):integer;
procedure EVP_MD_CTX_free( ctx : PEVP_MD_CTX);
function EVP_Digest(const data : Pointer; count : size_t; md : PByte; size : Puint32;const &type : PEVP_MD; impl : PENGINE):integer;
function EVP_DigestFinalXOF( ctx : PEVP_MD_CTX; md : PByte; size : size_t):integer;
function EVP_DigestInit(ctx : PEVP_MD_CTX;const _type : PEVP_MD):integer;
function EVP_DigestFinal( ctx : PEVP_MD_CTX; md : PByte; size : Puint32):integer;
function EVP_MD_CTX_reset( ctx : PEVP_MD_CTX):integer;
function EVP_MD_CTX_copy_ex(_out : PEVP_MD_CTX;const _in : PEVP_MD_CTX):integer;
function evp_md_ctx_new_ex(pkey : PEVP_PKEY;const id : PASN1_OCTET_STRING; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_MD_CTX;
procedure evp_md_ctx_clear_digest( ctx : PEVP_MD_CTX; force : integer);
function EVP_MD_CTX_copy(_out : PEVP_MD_CTX;const _in : PEVP_MD_CTX):integer;
function EVP_Q_digest(libctx : POSSL_LIB_CTX;const name, propq : PUTF8Char; data : Pointer; datalen : size_t; md : PByte; mdlen : Psize_t):integer;

implementation

uses
   openssl3.include.internal.refcount,           openssl3.crypto.evp.evp_lib,
   openssl3.crypto.evp.evp_fetch,                openssl3.crypto.mem, openssl3.err,
   openssl3.crypto.core_algorithm,               OpenSSL3.openssl.core_dispatch,
   openssl3.crypto.provider_core,                openssl3.crypto.params,
   openssl3.crypto.evp.evp_utils,                openssl3.crypto.evp.keymgmt_meth,
   openssl3.crypto.evp.pmeth_lib,                openssl3.crypto.evp.m_sigver,
   openssl3.crypto.objects.obj_dat,              openssl3.crypto.objects.o_names,
   OpenSSL3.threads_none, OpenSSL3.common,       openssl3.crypto.evp,
   openssl3.crypto.engine.eng_init,              openssl3.crypto.engine.tb_digest;


function EVP_Q_digest(libctx : POSSL_LIB_CTX;const name, propq : PUTF8Char; data : Pointer; datalen : size_t; md : PByte; mdlen : Psize_t):integer;
var
  digest : PEVP_MD;
  temp : uint32;
  ret : integer;
begin
    digest := EVP_MD_fetch(libctx, name, propq);
    temp := 0;
    ret := 0;
    if digest <> nil then begin
        ret := EVP_Digest(data, datalen, md, @temp, digest, nil);
        EVP_MD_free(digest);
    end;
    if mdlen <> nil then
       mdlen^ := temp;
    Result := ret;
end;

function EVP_MD_CTX_copy(_out : PEVP_MD_CTX;const _in : PEVP_MD_CTX):integer;
begin
    EVP_MD_CTX_reset(_out);
    Result := EVP_MD_CTX_copy_ex(_out, _in);
end;

procedure evp_md_ctx_clear_digest( ctx : PEVP_MD_CTX; force : integer);
begin
    if ctx.algctx <> nil then
    begin
        if (ctx.digest <> nil)  and  (Assigned(ctx.digest.freectx)) then
            ctx.digest.freectx(ctx.algctx);
        ctx.algctx := nil;
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    end;
    { Code below to be removed when legacy support is dropped. }
    {
     * Don't assume ctx.md_data was cleaned in EVP_Digest_Final, because
     * sometimes only copies of the context are ever finalised.
     }
    cleanup_old_md_data(ctx, force);
    if force > 0 then ctx.digest := nil;
{$IF not defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ENGINE)}
    ENGINE_finish(ctx.engine);
    ctx.engine := nil;
{$ENDIF}
    { Non legacy code, this has to be later than the ctx.digest cleaning }
    EVP_MD_free(ctx.fetched_digest);
    ctx.fetched_digest := nil;
    ctx.reqdigest := nil;
end;


function evp_md_ctx_new_ex(pkey : PEVP_PKEY;const id : PASN1_OCTET_STRING; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_MD_CTX;
var
  ctx : PEVP_MD_CTX;
  pctx : PEVP_PKEY_CTX;
  label _err;
begin
    pctx := nil;
    ctx := EVP_MD_CTX_new();
    pctx := EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq);
    if (ctx =  nil) or  (pctx =  nil) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if (id <> nil)  and  (EVP_PKEY_CTX_set1_id(pctx, id.data, id.length) <= 0) then
        goto _err;
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
    Exit(ctx);
 _err:
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);
    Result := nil;
end;

function EVP_MD_CTX_copy_ex(_out : PEVP_MD_CTX;const _in : PEVP_MD_CTX):integer;
var
  tmp_buf : PByte;
  dctx    : TSHA_CTX;
  label _clone_pkey, _legacy;
begin
    if _in = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if _in.digest = nil then
    begin
        { copying uninitialized digest context }
        EVP_MD_CTX_reset(_out);
        if _out.fetched_digest <> nil then
           EVP_MD_free(_out.fetched_digest);
        _out^ := _in^;
        goto _clone_pkey;
    end;
    if (_in.digest.prov = nil)
             or  (_in.flags and EVP_MD_CTX_FLAG_NO_INIT <> 0) then
        goto _legacy;
    if not Assigned(_in.digest.dupctx) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX);
        Exit(0);
    end;
    EVP_MD_CTX_reset(_out);
    if _out.fetched_digest <> nil then EVP_MD_free(_out.fetched_digest);
    _out^ := _in^;
    { nil _out pointers in case of error }
    _out.pctx := nil;
    _out.algctx := nil;
    if _in.fetched_digest <> nil then
       EVP_MD_up_ref(_in.fetched_digest);
    if _in.algctx <> nil then
    begin

        _in.digest.dupctx(_in.algctx, _out.algctx);
        if _out.algctx = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX);
            Exit(0);
        end;
    end;
 _clone_pkey:
    { copied EVP_MD_CTX should free the copied TPEVP_PKEY_CTX }
    EVP_MD_CTX_clear_flags(_out, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
{$IFNDEF FIPS_MODULE}
    if _in.pctx <> nil then begin
        _out.pctx := EVP_PKEY_CTX_dup(_in.pctx);
        if _out.pctx = nil then begin
            ERR_raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX);
            EVP_MD_CTX_reset(_out);
            Exit(0);
        end;
    end;
{$ENDIF}
    Exit(1);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    { Make sure it's safe to copy a digest context using an TPENGINE }
    if (_in.engine <> nil)  and  (0>=ENGINE_init(_in.engine)) then  begin
        ERR_raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB);
        Exit(0);
    end;
{$ENDIF}
    if _out.digest = _in.digest then begin
        tmp_buf := _out.md_data;
        EVP_MD_CTX_set_flags(_out, EVP_MD_CTX_FLAG_REUSE);
    end
    else
        tmp_buf := nil;
    EVP_MD_CTX_reset(_out);
    memcpy(_out, _in, sizeof(_out^));
    { copied EVP_MD_CTX should free the copied TPEVP_PKEY_CTX }
    EVP_MD_CTX_clear_flags(_out, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    { Null these variables, since they are getting fixed up
     * properly below.  Anything else may cause a memleak and/or
     * double free if any of the memory allocations below fail
     }
    _out.md_data := nil;
    _out.pctx := nil;
    if (_in.md_data <> nil) and  (_out.digest.ctx_size > 0 ) then
    begin
        if tmp_buf <> nil then
            _out.md_data := tmp_buf
        else
        begin
            _out.md_data := OPENSSL_malloc(_out.digest.ctx_size);
            if _out.md_data = nil then begin
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
        end;
        memcpy(_out.md_data, _in.md_data, _out.digest.ctx_size);
    end;
    _out.update := _in.update;
{$IFNDEF FIPS_MODULE}
    if _in.pctx <> nil then
    begin
        _out.pctx := EVP_PKEY_CTX_dup(_in.pctx);
        if nil =_out.pctx then begin
            EVP_MD_CTX_reset(_out);
            Exit(0);
        end;
    end;
{$ENDIF}
    if Assigned(_out.digest.copy) then
       Exit(_out.digest.copy(_out, _in));
    Result := 1;
end;

function EVP_MD_CTX_reset( ctx : PEVP_MD_CTX):integer;
begin
    if ctx = nil then
       Exit(1);
{$IFNDEF FIPS_MODULE}
    {
     * pctx should be freed by the user of EVP_MD_CTX
     * if EVP_MD_CTX_FLAG_KEEP_PKEY_CTX is set
     }
    if 0>= EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX) then
    begin
        EVP_PKEY_CTX_free(ctx.pctx);
        ctx.pctx := nil;
    end;
{$ENDIF}
    //free ctx.algctx
    evp_md_ctx_clear_digest(ctx, 0);
    //OPENSSL_cleanse(ctx, sizeof( ctx^));
    ctx^ := default(TEVP_MD_CTX);
    Result := 1;
end;

function EVP_DigestFinal( ctx : PEVP_MD_CTX; md : PByte; size : Puint32):integer;
var
  ret : integer;
begin
    ret := EVP_DigestFinal_ex(ctx, md, size);
    EVP_MD_CTX_reset(ctx);
    Result := ret;
end;

function EVP_DigestInit(ctx : PEVP_MD_CTX;const _type : PEVP_MD):integer;
begin
    EVP_MD_CTX_reset(ctx);
    Result := evp_md_init_internal(ctx, _type, nil, nil);
end;

function EVP_DigestFinalXOF( ctx : PEVP_MD_CTX; md : PByte; size : size_t):integer;
var
  ret : integer;
  params : array[0..1] of TOSSL_PARAM;
  i : size_t;
  label _legacy;
begin
    ret := 0;
    i := 0;
    if ctx.digest = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM);
        Exit(0);
    end;
    if ctx.digest.prov = nil then goto _legacy ;
    if not Assigned(ctx.digest.dfinal) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
        Exit(0);
    end;
    params[PostInc(i)] := OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, @size);
    params[PostInc(i)] := OSSL_PARAM_construct_end();
    if EVP_MD_CTX_set_params(ctx, @params) > 0  then
        ret := ctx.digest.dfinal(ctx.algctx, md, @size, size);
    Exit(ret);

_legacy:
    if (ctx.digest.flags and EVP_MD_FLAG_XOF > 0)
         and  (size <= INT_MAX)
         and  (ctx.digest.md_ctrl(ctx, EVP_MD_CTRL_XOF_LEN, int (size), nil) > 0) then
    begin
        ret := ctx.digest.final(ctx, md);
        if Assigned(ctx.digest.cleanup) then begin
            ctx.digest.cleanup(ctx);
            EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
        end;
        OPENSSL_cleanse(ctx.md_data, ctx.digest.ctx_size);
    end
    else begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NOT_XOF_OR_INVALID_LENGTH);
    end;
    Result := ret;
end;

function EVP_Digest(const data : Pointer; count : size_t; md : PByte; size : Puint32;const &type : PEVP_MD; impl : PENGINE):integer;
var
  ctx : PEVP_MD_CTX;
  ret, t1,t2,t3 : integer;
begin
    ctx := EVP_MD_CTX_new();
    if ctx = nil then Exit(0);
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
    t1 := EVP_DigestInit_ex(ctx, &type, impl);
    t2 := EVP_DigestUpdate(ctx, data, count);
    t3 := EVP_DigestFinal_ex(ctx, md, size);
    ret := Int( (t1 > 0) and  (t2 > 0) and  (t3 > 0));
    EVP_MD_CTX_free(ctx);
    Result := ret;
end;


procedure EVP_MD_CTX_free( ctx : PEVP_MD_CTX);
begin
    if ctx = nil then Exit;
    EVP_MD_CTX_reset(ctx);
    ctx := nil;
    OPENSSL_free(ctx);
end;


function EVP_DigestFinal_ex( ctx : PEVP_MD_CTX; md : PByte; isize : Puint32):integer;
var
  ret, sz : integer;
  size, mdsize : size_t;
  label _legacy;
begin
    size := 0;
    mdsize := 0;
    if ctx.digest = nil then Exit(0);
    sz := EVP_MD_get_size(ctx.digest);
    if sz < 0 then Exit(0);
    mdsize := sz;
    if ctx.digest.prov = nil then
       goto _legacy ;
    if not Assigned(ctx.digest.dfinal) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
        Exit(0);
    end;
    ret := ctx.digest.dfinal(ctx.algctx, md, @size, mdsize);
    if isize <> nil then
    begin
        if size <= UINT_MAX then
        begin
          isize^ := int(size);
        end
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
            ret := 0;
        end;
    end;
    Exit(ret);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    assert(mdsize <= EVP_MAX_MD_SIZE);
    ret := ctx.digest.final(ctx, md);
    if isize <> nil then
       isize^ := mdsize;
    if Assigned(ctx.digest.cleanup) then
    begin
        ctx.digest.cleanup(ctx);
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    end;
    OPENSSL_cleanse(ctx.md_data, ctx.digest.ctx_size);
    Result := ret;
end;


function EVP_DigestUpdate(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
label _legacy;

begin
    if count = 0 then Exit(1);
    if (ctx.pctx <> nil)      and
       (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx.pctx)) and ( ctx.pctx.op.sig.algctx <> nil)  then
    begin
        {
         * Prior to OpenSSL 3.0 EVP_DigestSignUpdate() and
         * EVP_DigestVerifyUpdate() were just macros for EVP_DigestUpdate().
         * Some code calls EVP_DigestUpdate() directly even when initialised
         * with EVP_DigestSignInit_ex() or
         * EVP_DigestVerifyInit_ex(), so we detect that and redirect to
         * the correct EVP_Digest*Update() function
         }
        if ctx.pctx.operation = EVP_PKEY_OP_SIGNCTX then
            Exit(EVP_DigestSignUpdate(ctx, data, count));
        if ctx.pctx.operation = EVP_PKEY_OP_VERIFYCTX then
           Exit(EVP_DigestVerifyUpdate(ctx, data, count));
        ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
        Exit(0);
    end;
    if (ctx.digest = nil)
             or  (ctx.digest.prov = nil)
             or ( (ctx.flags and EVP_MD_CTX_FLAG_NO_INIT) <> 0)  then
        goto _legacy ;
    if not Assigned(ctx.digest.dupdate) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
        Exit(0);
    end;
    Exit(ctx.digest.dupdate(ctx.algctx, data, count));
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    Result := ctx.update(ctx, data, count);
end;

function EVP_DigestInit_ex(ctx : PEVP_MD_CTX;const &type : PEVP_MD; impl : PENGINE):integer;
begin
    Result := evp_md_init_internal(ctx, &type, nil, impl);
end;


function EVP_MD_CTX_new:PEVP_MD_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(TEVP_MD_CTX));
end;

function EVP_MD_settable_ctx_params(const md : PEVP_MD):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (md <> nil)  and  (Assigned(md.settable_ctx_params)) then
    begin
        provctx := ossl_provider_ctx(EVP_MD_get0_provider(md));
        Exit(md.settable_ctx_params(nil, provctx));
    end;
    Result := nil;
end;

function EVP_MD_CTX_set_params(ctx : PEVP_MD_CTX;const params : POSSL_PARAM):integer;
var
  pctx : PEVP_PKEY_CTX;
begin
    pctx := ctx.pctx;
    { If we have a pctx then we should try that first }
    if (pctx <> nil)
             and  ( (pctx.operation = EVP_PKEY_OP_VERIFYCTX)
                 or  (pctx.operation = EVP_PKEY_OP_SIGNCTX) )
             and  (pctx.op.sig.algctx <> nil)
             and  ( Assigned(pctx.op.sig.signature.set_ctx_md_params)) then
        Exit(pctx.op.sig.signature.set_ctx_md_params(pctx.op.sig.algctx,
                                                         params));
    if (ctx.digest <> nil)  and  (Assigned(ctx.digest.set_ctx_params)) then
       Exit(ctx.digest.set_ctx_params(ctx.algctx, params));
    Result := 0;
end;


function EVP_MD_gettable_ctx_params(const md : PEVP_MD):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (md <> nil)  and (Assigned( md.gettable_ctx_params)) then
    begin
        provctx := ossl_provider_ctx(EVP_MD_get0_provider(md));
        Exit(md.gettable_ctx_params(nil, provctx));
    end;
    Result := nil;
end;


function EVP_MD_CTX_get_params( ctx : PEVP_MD_CTX; params : POSSL_PARAM):integer;
var
  pctx : PEVP_PKEY_CTX;
begin
    pctx := ctx.pctx;
    { If we have a pctx then we should try that first }
    if (pctx <> nil)
             and  ( (pctx.operation = EVP_PKEY_OP_VERIFYCTX )
                 or (pctx.operation = EVP_PKEY_OP_SIGNCTX) )
             and  (pctx.op.sig.algctx <> nil)
             and  ( Assigned(pctx.op.sig.signature.get_ctx_md_params)) then
        Exit(pctx.op.sig.signature.get_ctx_md_params(pctx.op.sig.algctx,
                                                         params));
    if (ctx.digest <> nil)  and  ( Assigned(ctx.digest.get_params)) then
       Exit(ctx.digest.get_ctx_params(ctx.algctx, params));
    Result := 0;
end;

procedure cleanup_old_md_data( ctx : PEVP_MD_CTX; force : integer);
begin
    if ctx.digest <> nil then
    begin
        if ( Assigned(ctx.digest.cleanup))
                 and  (0>= EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED))then
            ctx.digest.cleanup(ctx);
        if (ctx.md_data <> nil)  and  (ctx.digest.ctx_size > 0)
            and ( (0>= EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE))  or  (force>0)) then
        begin
            OPENSSL_clear_free(ctx.md_data, ctx.digest.ctx_size);
            ctx.md_data := nil;
        end;
    end;
end;

function evp_md_init_internal(ctx : PEVP_MD_CTX; _type : PEVP_MD; params : POSSL_PARAM; impl : PENGINE):integer;
var
  tmpimpl : PENGINE;
  provmd, d : PEVP_MD;
  r : integer;
  s: PUTF8Char;
  label _skip_to_init, _legacy;
begin
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    tmpimpl := nil;
{$ENDIF}
{$IF not defined(FIPS_MODULE)}
    if (ctx.pctx <> nil)
             and  (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx.pctx))  and
             (ctx.pctx.op.sig.algctx <> nil) then
    begin
        {
         * Prior to OpenSSL 3.0 calling EVP_DigestInit_ex() on an mdctx
         * previously initialised with EVP_DigestSignInit() would retain
         * information about the key, and re-initialise for another sign
         * operation. So in that case we redirect to EVP_DigestSignInit()
         }
        if ctx.pctx.operation = EVP_PKEY_OP_SIGNCTX then
            Exit(EVP_DigestSignInit(ctx, nil, _type, impl, nil));
        if ctx.pctx.operation = EVP_PKEY_OP_VERIFYCTX then
           Exit(EVP_DigestVerifyInit(ctx, nil, _type, impl, nil));
        ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
        Exit(0);
    end;
{$ENDIF}
    EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    if ctx.algctx <> nil then
    begin
        if not ossl_assert(ctx.digest <> nil) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
        if Assigned(ctx.digest.freectx ) then
           ctx.digest.freectx(ctx.algctx);
        ctx.algctx := nil;
    end;
    if _type <> nil then
    begin
        ctx.reqdigest := _type;
    end
    else
    begin
        if ctx.digest = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_NO_DIGEST_SET);
            Exit(0);
        end;
        _type := ctx.digest;
    end;
    { Code below to be removed when legacy support is dropped. }
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    {
     * Whether it's nice or not, 'Inits" can be used on "Final''d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     }
    if (ctx.engine <> nil)
             and  (ctx.digest <> nil)
             and  (_type.&type = ctx.digest.&type) then
             goto _skip_to_init ;
    {
     * Ensure an ENGINE left lying around from last time is cleared (the
     * previous check attempted to avoid this if the same ENGINE and
     * EVP_MD could be used).
     }
    ENGINE_finish(ctx.engine);
    ctx.engine := nil;
    if impl = nil then
       tmpimpl := ENGINE_get_digest_engine(_type.&type);
{$ENDIF}
    {
     * If there are engines involved or EVP_MD_CTX_FLAG_NO_INIT is set then we
     * should use legacy handling for now.
     }
    if (impl <> nil)
{$IF not defined(OPENSSL_NO_ENGINE)}
    or (ctx.engine <> nil)
{$IF not defined(FIPS_MODULE)}
             or  (tmpimpl <> nil)
{$ENDIF}
{$ENDIF}
             or ( (ctx.flags and EVP_MD_CTX_FLAG_NO_INIT) <> 0 )
             or ( _type.origin = EVP_ORIG_METH) then
    begin
        if ctx.digest = ctx.fetched_digest then
            ctx.digest := nil;
        EVP_MD_free(ctx.fetched_digest);
        ctx.fetched_digest := nil;
        goto _legacy ;
    end;
    cleanup_old_md_data(ctx, 1);
    { Start of non-legacy code below }
    if _type.prov = nil then
    begin
{$IFDEF FIPS_MODULE}
        { We only do explicit fetches inside the FIPS module }
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
{$ELSE} { The nil digest is a special case }
        provmd := EVP_MD_fetch(nil,
                            get_result(_type.&type <> NID_undef , OBJ_nid2sn(_type.&type)
                                                              , 'NULL'), '');
        if provmd = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
        _type := provmd;
        EVP_MD_free(ctx.fetched_digest);
        ctx.fetched_digest := provmd;
{$ENDIF}
    end;
    if (ctx.algctx <> nil)  and  (ctx.digest <> nil)  and  (ctx.digest <> _type) then
    begin
        if Assigned(ctx.digest.freectx ) then
            ctx.digest.freectx(ctx.algctx);
        ctx.algctx := nil;
    end;
    if (_type.prov <> nil)  and  (ctx.fetched_digest <> _type) then
    begin
        if 0>= EVP_MD_up_ref(PEVP_MD(_type)) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
        EVP_MD_free(ctx.fetched_digest);
        ctx.fetched_digest := PEVP_MD (_type);
    end;
    ctx.digest := _type;
    if ctx.algctx = nil then
    begin
        ctx.algctx := ctx.digest.newctx(ossl_provider_ctx(_type.prov));
        if ctx.algctx = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
    end;
    if not Assigned(ctx.digest.dinit) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
    end;
    Exit(ctx.digest.dinit(ctx.algctx, params));
    { Code below to be removed when legacy support is dropped. }
 _legacy:
{$IF not defined(OPENSSL_NO_ENGINE)  and not defined(FIPS_MODULE)}
    if _type <> nil then
    begin
        if impl <> nil then
        begin
            if 0>= ENGINE_init(impl) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
                Exit(0);
            end;
        end
        else
        begin
            { Ask if an ENGINE is reserved for this job }
            impl := tmpimpl;
        end;
        if impl <> nil then
        begin
            { There's an ENGINE for this job ... (apparently) }
             d := ENGINE_get_digest(impl, _type.&type);
            if d = nil then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
                ENGINE_finish(impl);
                Exit(0);
            end;
            { We'll use the ENGINE's private digest definition }
            _type := d;
            {
             * Store the ENGINE functional reference so we know 'type' came
             * from an ENGINE and we need to release it when done.
             }
            ctx.engine := impl;
        end
        else
            ctx.engine := nil;
    end;
{$ENDIF}
    if ctx.digest <> _type then
    begin
        cleanup_old_md_data(ctx, 1);
        ctx.digest := _type;
        if (0>= (ctx.flags and EVP_MD_CTX_FLAG_NO_INIT) ) and  (_type.ctx_size>0) then
        begin
            ctx.update := _type.update;
            ctx.md_data := OPENSSL_zalloc(_type.ctx_size);
            if ctx.md_data = nil then
            begin
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
        end;
    end;
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
 _skip_to_init:
{$ENDIF}
{$IFNDEF FIPS_MODULE}
    if (ctx.pctx <> nil)
             and ( (not EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx.pctx )) or
                   (ctx.pctx.op.sig.signature = nil)) then
    begin
        r := EVP_PKEY_CTX_ctrl(ctx.pctx, -1, EVP_PKEY_OP_TYPE_SIG,
                              EVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
        if (r <= 0)  and  (r <> -2) then
            Exit(0);
    end;
{$ENDIF}
    if (ctx.flags and EVP_MD_CTX_FLAG_NO_INIT)>0 then
       Exit(1);
    Result := ctx.digest.init(ctx);
end;

function EVP_DigestInit_ex2(ctx : PEVP_MD_CTX;const _type : PEVP_MD; params : POSSL_PARAM):integer;
begin
    Result := evp_md_init_internal(ctx, _type, params, nil);
end;

function EVP_MD_up_ref( md : PEVP_MD):integer;
var
  ref : integer;
begin
    ref := 0;
    if md.origin = EVP_ORIG_DYNAMIC then
       CRYPTO_UP_REF(md.refcnt, ref, md.lock);
    Result := 1;
end;

function _evp_md_up_ref( md : Pointer):integer;
begin
    Result := EVP_MD_up_ref(PEVP_MD(md));
end;

function evp_md_cache_constants( md : PEVP_MD):integer;
var
  ok: Boolean;
  xof,algid_absent : integer;
  blksz, mdsize : size_t;
  params : array[0..4] of TOSSL_PARAM;
begin
    xof := 0; algid_absent := 0;
    blksz := 0;
    mdsize := 0;
    params[0] := OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, @blksz);
    params[1] := OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, @mdsize);
    params[2] := OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_XOF, @xof);
    params[3] := OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, @algid_absent);
    params[4] := OSSL_PARAM_construct_end();
    ok := evp_do_md_getparams(md, @params) > 0;
    if (mdsize > INT_MAX)  or  (blksz > INT_MAX) then
       ok := Boolean(0);
    if ok then
    begin
        md.block_size := int(blksz);
        md.md_size := int(mdsize);
        if xof > 0 then
           md.flags  := md.flags  or EVP_MD_FLAG_XOF;
        if algid_absent > 0 then
           md.flags  := md.flags  or EVP_MD_FLAG_DIGALGID_ABSENT;
    end;
    Result := Int(ok);
end;

procedure set_legacy_nid(const name : PUTF8Char; vlegacy_nid : Pointer);
var
    nid           : integer;
    legacy_nid    : PInteger;
    legacy_method : Pointer;
begin
    legacy_nid := vlegacy_nid;
    {
     * We use lowest level function to get the associated method, because
     * higher level functions such as EVP_get_digestbyname() have changed
     * to look at providers too.
     }
    legacy_method := OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH);
    if legacy_nid^ = -1 then { We found a clash already }
        exit;
    if legacy_method = nil then exit;
    nid := EVP_MD_nid(legacy_method);
    if (legacy_nid^ <> NID_undef)  and  (legacy_nid^ <> nid) then
    begin
        legacy_nid^ := -1;
        exit;
    end;
    legacy_nid^ := nid;
end;

function evp_md_new:PEVP_MD;
var
  md : PEVP_MD;
begin
    md := OPENSSL_zalloc(sizeof( md^));
    if md <> nil then
    begin
        md.lock := CRYPTO_THREAD_lock_new();
        if md.lock = nil then
        begin
            OPENSSL_free(md);
            Exit(nil);
        end;
        md.refcnt := 1;
    end;
    Result := md;
end;

function evp_md_from_algorithm({const} name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  fns : POSSL_DISPATCH;
  md : PEVP_MD;
  fncnt : integer;
begin
    fns := algodef._implementation;
    md := nil;
    fncnt := 0;
    { EVP_MD_fetch() will set the legacy NID if available }
    md := evp_md_new( );
    if md = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
{$IFNDEF FIPS_MODULE}
    md.&type := NID_undef;
    if  (0>= evp_names_do_all(prov, name_id, set_legacy_nid, @md.&type ))  or
        (md.&type = -1) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        EVP_MD_free(md);
        Exit(nil);
    end;
{$ENDIF}
    md.name_id := name_id;
    md.type_name := ossl_algorithm_get1_first_name(algodef);
    if md.type_name = nil then
    begin
        EVP_MD_free(md);
        Exit(nil);
    end;
    md.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_DIGEST_NEWCTX:
            if not Assigned(md.newctx) then
            begin
                md.newctx := _OSSL_FUNC_digest_newctx(fns);
                Inc(fncnt);
            end;

        OSSL_FUNC_DIGEST_INIT:
            if not Assigned(md.dinit) then
            begin
                md.dinit := _OSSL_FUNC_digest_init(fns);
                Inc(fncnt);
            end;

        OSSL_FUNC_DIGEST_UPDATE:
            if not Assigned(md.dupdate ) then
            begin
                md.dupdate := _OSSL_FUNC_digest_update(fns);
                Inc(fncnt);
            end;

        OSSL_FUNC_DIGEST_FINAL:
            if not Assigned(md.dfinal) then
            begin
                md.dfinal := _OSSL_FUNC_digest_final(fns);
                Inc(fncnt);
            end;

        OSSL_FUNC_DIGEST_DIGEST:
            if not Assigned(md.digest) then
               md.digest := _OSSL_FUNC_digest_digest(fns);
            { We don't increment fnct for this as it is stand alone }

        OSSL_FUNC_DIGEST_FREECTX:
            if not Assigned(md.freectx) then
            begin
                md.freectx := _OSSL_FUNC_digest_freectx(fns);
                Inc(fncnt);
            end;

        OSSL_FUNC_DIGEST_DUPCTX:
            if not Assigned(md.dupctx) then
               md.dupctx := _OSSL_FUNC_digest_dupctx(fns);

        OSSL_FUNC_DIGEST_GET_PARAMS:
            if not Assigned(md.get_params) then
               md.get_params := _OSSL_FUNC_digest_get_params(fns);

        OSSL_FUNC_DIGEST_SET_CTX_PARAMS:
            if not Assigned(md.set_ctx_params) then
               md.set_ctx_params := _OSSL_FUNC_digest_set_ctx_params(fns);

        OSSL_FUNC_DIGEST_GET_CTX_PARAMS:
            if not Assigned(md.get_ctx_params) then
               md.get_ctx_params := _OSSL_FUNC_digest_get_ctx_params(fns);

        OSSL_FUNC_DIGEST_GETTABLE_PARAMS:
            if not Assigned(md.gettable_params ) then
               md.gettable_params := _OSSL_FUNC_digest_gettable_params(fns);

        OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS:
            if not Assigned(md.settable_ctx_params) then
               md.settable_ctx_params := _OSSL_FUNC_digest_settable_ctx_params(fns);

        OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS:
            if not Assigned(md.gettable_ctx_params ) then
               md.gettable_ctx_params := _OSSL_FUNC_digest_gettable_ctx_params(fns);

        end;
        Inc(fns);
    end;
    if ( fncnt <> 0)  and  (fncnt <> 5)  or
       ( (fncnt = 0)  and  (not Assigned(md.digest)) )then
    begin
        {
         * In order to be a consistent set of functions we either need the
         * whole set of init/update/final etc functions or none of them.
         * The 'digest' function can standalone. We at least need one way to
         * generate digests.
         }
        EVP_MD_free(md);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    md.prov := prov;
    if prov <> nil then
       ossl_provider_up_ref(prov);
    if  0>= evp_md_cache_constants(md )then
    begin
        EVP_MD_free(md);
        ERR_raise(ERR_LIB_EVP, EVP_R_CACHE_CONSTANTS_FAILED);
        md := nil;
    end;
    Result := md;
end;



function EVP_MD_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_MD;
begin
    Result := evp_generic_fetch(ctx, OSSL_OP_DIGEST, algorithm, properties,
                          evp_md_from_algorithm, _evp_md_up_ref, evp_md_free);
end;

procedure EVP_MD_free( md : Pointer);
var
  i : integer;
begin
    if (md = nil)  or  (PEVP_MD(md).origin <> EVP_ORIG_DYNAMIC) then exit;
    CRYPTO_DOWN_REF(PEVP_MD(md).refcnt, i, PEVP_MD(md).lock);
    if i > 0 then exit;
    evp_md_free_int(md);
end;


end.
