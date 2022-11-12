unit openssl3.crypto.evp.pmeth_lib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  Tpmeth_fn = function(): PEVP_PKEY_METHOD ;
  Ppmeth_fn = ^Tpmeth_fn;


function EVP_PKEY_CTX_settable_params(const ctx : PEVP_PKEY_CTX):POSSL_PARAM;
function EVP_PKEY_CTX_new_from_name(libctx : POSSL_LIB_CTX;const name, propquery : PUTF8Char):PEVP_PKEY_CTX;
function int_ctx_new(libctx : POSSL_LIB_CTX; pkey : PEVP_PKEY; e : PENGINE; keytype, propquery : PUTF8Char; id : integer):PEVP_PKEY_CTX;
function evp_pkey_meth_find_added_by_application( &type : integer):PEVP_PKEY_METHOD;
function get_legacy_alg_type_from_keymgmt(const keymgmt : PEVP_KEYMGMT):integer;
procedure help_get_legacy_alg_type_from_keymgmt(const keytype : PUTF8Char; arg : Pointer);
procedure EVP_PKEY_meth_free( pmeth : PEVP_PKEY_METHOD);
function EVP_PKEY_meth_find( _type : integer):PEVP_PKEY_METHOD;
function OBJ_bsearch_pmeth_func( key : PPEVP_PKEY_METHOD; base : Tpmeth_fn; num : integer): Tpmeth_fn;
function pmeth_func_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
function pmeth_cmp(const a, b : PPEVP_PKEY_METHOD):integer;
function pmeth_func_cmp(const a : PPEVP_PKEY_METHOD; b : Ppmeth_fn):integer;
function EVP_PKEY_CTX_md(ctx : PEVP_PKEY_CTX; optype, cmd : integer;const md : PUTF8Char):integer;
function evp_pkey_ctx_set_params_strict( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
function EVP_PKEY_CTX_ctrl( ctx : PEVP_PKEY_CTX; keytype, optype, cmd, p1 : integer; p2 : Pointer):integer;
function EVP_PKEY_CTX_set_params(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
function evp_pkey_ctx_state(const ctx : PEVP_PKEY_CTX):integer;
function evp_pkey_ctx_store_cached_data(ctx : PEVP_PKEY_CTX; keytype, optype, cmd : integer;const name : PUTF8Char; data : Pointer; data_len : size_t):int;
function decode_cmd(cmd : integer;const name : PUTF8Char):integer;
procedure evp_pkey_ctx_free_cached_data(ctx : PEVP_PKEY_CTX; cmd : integer;const name : PUTF8Char);
function evp_pkey_ctx_ctrl_int( ctx : PEVP_PKEY_CTX; keytype, optype, cmd, p1 : integer; p2 : Pointer):integer;
function evp_pkey_ctx_get_params_strict( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
function EVP_PKEY_CTX_gettable_params(const ctx : PEVP_PKEY_CTX):POSSL_PARAM;
function EVP_PKEY_CTX_get_params( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
 procedure EVP_PKEY_CTX_free( ctx : PEVP_PKEY_CTX);
procedure evp_pkey_ctx_free_old_ops( ctx : PEVP_PKEY_CTX);
 procedure evp_pkey_ctx_free_all_cached_data( ctx : PEVP_PKEY_CTX);
function EVP_PKEY_CTX_is_a(ctx : PEVP_PKEY_CTX;const keytype : PUTF8Char):integer;
function EVP_PKEY_CTX_new_from_pkey(libctx : POSSL_LIB_CTX; pkey : PEVP_PKEY;const propquery : PUTF8Char):PEVP_PKEY_CTX;
function evp_pkey_ctx_use_cached_data( ctx : PEVP_PKEY_CTX):integer;
function EVP_PKEY_CTX_set_signature_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
function EVP_PKEY_CTX_get0_pkey( ctx : PEVP_PKEY_CTX):PEVP_PKEY;
function EVP_PKEY_CTX_new( pkey : PEVP_PKEY; e : PENGINE):PEVP_PKEY_CTX;
function EVP_PKEY_CTX_dup(const pctx : PEVP_PKEY_CTX):PEVP_PKEY_CTX;
function EVP_PKEY_CTX_get_signature_md(ctx : PEVP_PKEY_CTX;const md : PPEVP_MD):integer;
function evp_pkey_ctx_set_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD; fallback : integer;const param : PUTF8Char; op, ctrl : integer):integer;
function evp_pkey_ctx_ctrl_str_int(ctx : PEVP_PKEY_CTX;const name, value : PUTF8Char):int;
function EVP_PKEY_CTX_set1_id(ctx : PEVP_PKEY_CTX;const id : Pointer; len : integer):integer;

procedure evp_app_cleanup_int;
function EVP_PKEY_CTX_new_id( id : integer; e : PENGINE):PEVP_PKEY_CTX;

implementation
uses openssl3.crypto.evp, openssl3.crypto.provider_core,openssl3.crypto.evp.exchange,
      openssl3.crypto.evp.signature, openssl3.crypto.evp.asymcipher, OpenSSL3.Err,
      openssl3.crypto.evp.keymgmt_meth, openssl3.crypto.evp.kem,
      openssl3.crypto.evp.p_lib, OpenSSL3.common, openssl3.crypto.mem,
      openssl3.crypto.o_str, openssl3.crypto.engine.eng_init,
      openssl3.crypto.dh.dh_pmeth,  openssl3.crypto.rsa.rsa_pmeth,
      openssl3.crypto.dsa.dsa_pmeth, openssl3.crypto.ec.ec_pmeth,
      openssl3.providers.fips.fipsprov, openssl3.crypto.params,
      openssl3.crypto.evp.evp_lib,
      openssl3.crypto.evp.names, openssl3.crypto.bn.bn_lib,

      openssl3.crypto.ec.ecx_meth, openssl3.crypto.evp.ctrl_params_translate,
      openssl3.crypto.engine.tb_pkmeth, openssl3.crypto.objects.obj_dat;

var
  app_pkey_methods: Pstack_st_EVP_PKEY_METHOD  = nil;
  standard_methods: array[0..9] of Tpmeth_fn = (
        ossl_rsa_pkey_method,
    {$ifndef OPENSSL_NO_DH }
        ossl_dh_pkey_method,
    {$endif}
    {$ifndef OPENSSL_NO_DSA}
        ossl_dsa_pkey_method,
    {$endif}
    {$ifndef OPENSSL_NO_EC}
        ossl_ec_pkey_method,
    {$endif}
        ossl_rsa_pss_pkey_method,
    {$ifndef OPENSSL_NO_DH }
        ossl_dhx_pkey_method,
    {$endif}
    {$ifndef OPENSSL_NO_EC }
        ossl_ecx25519_pkey_method,
        ossl_ecx448_pkey_method,
    {$endif}
    {$ifndef OPENSSL_NO_EC}
        ossl_ed25519_pkey_method,
        ossl_ed448_pkey_method
    {$endif}
    );


function EVP_PKEY_CTX_new_id( id : integer; e : PENGINE):PEVP_PKEY_CTX;
begin
    Result := int_ctx_new(nil, nil, e, nil, nil, id);
end;

procedure evp_app_cleanup_int;
begin
    if app_pkey_methods <> nil then sk_EVP_PKEY_METHOD_pop_free(app_pkey_methods, EVP_PKEY_meth_free);
end;

function EVP_PKEY_CTX_set1_id(ctx : PEVP_PKEY_CTX;const id : Pointer; len : integer):integer;
begin
    Exit(EVP_PKEY_CTX_ctrl(ctx, -1, -1,
                             EVP_PKEY_CTRL_SET1_ID, int(len), Pointer(id)));
end;

function evp_pkey_ctx_ctrl_str_int(ctx : PEVP_PKEY_CTX;const name, value : PUTF8Char):int;
var
  ret : integer;
begin
    ret := 0;
    if ctx = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        Exit(-2);
    end;
    case (evp_pkey_ctx_state(ctx)) of
        EVP_PKEY_STATE_PROVIDER:
            Exit(evp_pkey_ctx_ctrl_str_to_param(ctx, name, value));
        EVP_PKEY_STATE_UNKNOWN,
        EVP_PKEY_STATE_LEGACY:
        begin
            if (ctx = nil)  or  (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.ctrl_str)) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
                Exit(-2);
            end;
            if strcmp(name, 'digest') = 0  then
                ret := EVP_PKEY_CTX_md(ctx,
                                      EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT,
                                      EVP_PKEY_CTRL_MD, value)
            else
                ret := ctx.pmeth.ctrl_str(ctx, name, value);
        end;
    end;
    Result := ret;
end;


function evp_pkey_ctx_set_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD; fallback : integer;const param : PUTF8Char; op, ctrl : integer):integer;
var
    md_params : array[0..1] of TOSSL_PARAM;
    p         : POSSL_PARAM;
    name      : PUTF8Char;
begin
    p := @md_params;
    if (ctx = nil)  or  (ctx.operation and op = 0)  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    if fallback > 0 then
       Exit(EVP_PKEY_CTX_ctrl(ctx, -1, op, ctrl, 0, Pointer(md)));
    if md = nil then begin
        name := '';
    end
    else
    begin
        name := EVP_MD_get0_name(md);
    end;
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(param,
                                            {
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             }
                                            PUTF8Char( name), 0);
    p^ := OSSL_PARAM_construct_end;
    Result := EVP_PKEY_CTX_set_params(ctx, @md_params);
end;



function EVP_PKEY_CTX_get_signature_md(ctx : PEVP_PKEY_CTX;const md : PPEVP_MD):integer;
var
    sig_md_params : array[0..1] of TOSSL_PARAM;
    p             : POSSL_PARAM;
    name          : array[0..79] of UTF8Char;
    tmp           : PEVP_MD;
begin
    p := @sig_md_params;
    { 80 should be big enough }
    name := '';
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    if ctx.op.sig.algctx = nil then
       Exit(EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,
                                 EVP_PKEY_CTRL_GET_MD, 0, Pointer(md)));
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                            name,
                                            sizeof(name));
    p^ := OSSL_PARAM_construct_end;
    if 0>=EVP_PKEY_CTX_get_params(ctx, @sig_md_params) then
        Exit(0);
    tmp := evp_get_digestbyname_ex(ctx.libctx, name);
    if tmp = nil then
       Exit(0);
    md^ := tmp;
    Result := 1;
end;


function EVP_PKEY_CTX_dup(const pctx : PEVP_PKEY_CTX):PEVP_PKEY_CTX;
var
    rctx        : PEVP_PKEY_CTX;
    tmp_keymgmt : PEVP_KEYMGMT;
    provkey     : Pointer;
    label _err;
begin
{$IFNDEF OPENSSL_NO_ENGINE}
    { Make sure it's safe to copy a pkey context using an PENGINE  }
    if (pctx.engine <> nil) and  (0>=ENGINE_init(pctx.engine)) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB);
        Exit(0);
    end;
{$ENDIF}
    rctx := OPENSSL_zalloc(sizeof( rctx^));
    if rctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if pctx.pkey <> nil then EVP_PKEY_up_ref(pctx.pkey);
    rctx.pkey := pctx.pkey;
    rctx.operation := pctx.operation;
    rctx.libctx := pctx.libctx;
    rctx.keytype := pctx.keytype;
    rctx.propquery := nil;
    if pctx.propquery <> nil then begin
        OPENSSL_strdup(rctx.propquery ,pctx.propquery);
        if rctx.propquery = nil then goto _err;
    end;
    rctx.legacy_keytype := pctx.legacy_keytype;
    if EVP_PKEY_CTX_IS_DERIVE_OP(pctx) then
    begin
        if pctx.op.kex.exchange <> nil then
        begin
            rctx.op.kex.exchange := pctx.op.kex.exchange;
            if 0>=EVP_KEYEXCH_up_ref(rctx.op.kex.exchange) then
                goto _err;
        end;
        if pctx.op.kex.algctx <> nil then
        begin
            if not ossl_assert(pctx.op.kex.exchange <> nil) then
                goto _err;
            rctx.op.kex.algctx := pctx.op.kex.exchange.dupctx(pctx.op.kex.algctx);
            if rctx.op.kex.algctx = nil then
            begin
                EVP_KEYEXCH_free(rctx.op.kex.exchange);
                rctx.op.kex.exchange := nil;
                goto _err;
            end;
            Exit(rctx);
        end;
    end
    else
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(pctx)) then
    begin
        if pctx.op.sig.signature <> nil then begin
            rctx.op.sig.signature := pctx.op.sig.signature;
            if 0>=EVP_SIGNATURE_up_ref(rctx.op.sig.signature ) then
                goto _err;
        end;
        if pctx.op.sig.algctx <> nil then begin
            if not ossl_assert(pctx.op.sig.signature <> nil) then
                goto _err;
            rctx.op.sig.algctx := pctx.op.sig.signature.dupctx(pctx.op.sig.algctx);
            if rctx.op.sig.algctx = nil then begin
                EVP_SIGNATURE_free(rctx.op.sig.signature);
                rctx.op.sig.signature := nil;
                goto _err;
            end;
            Exit(rctx);
        end;
    end
    else
    if (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(pctx)) then
    begin
        if pctx.op.ciph.cipher <> nil then begin
            rctx.op.ciph.cipher := pctx.op.ciph.cipher;
            if 0>=EVP_ASYM_CIPHER_up_ref(rctx.op.ciph.cipher ) then
                goto _err;
        end;
        if pctx.op.ciph.algctx <> nil then begin
            if not ossl_assert(pctx.op.ciph.cipher <> nil) then
                goto _err;
            rctx.op.ciph.algctx := pctx.op.ciph.cipher.dupctx(pctx.op.ciph.algctx);
            if rctx.op.ciph.algctx = nil then begin
                EVP_ASYM_CIPHER_free(rctx.op.ciph.cipher);
                rctx.op.ciph.cipher := nil;
                goto _err;
            end;
            Exit(rctx);
        end;
    end
    else
    if (EVP_PKEY_CTX_IS_KEM_OP(pctx)) then
    begin
        if pctx.op.encap.kem <> nil then begin
            rctx.op.encap.kem := pctx.op.encap.kem;
            if 0>=EVP_KEM_up_ref(rctx.op.encap.kem) then
                goto _err;
        end;
        if pctx.op.encap.algctx <> nil then begin
            if not ossl_assert(pctx.op.encap.kem <> nil) then
                goto _err;
            rctx.op.encap.algctx := pctx.op.encap.kem.dupctx(pctx.op.encap.algctx);
            if rctx.op.encap.algctx = nil then
            begin
                EVP_KEM_free(rctx.op.encap.kem);
                rctx.op.encap.kem := nil;
                goto _err;
            end;
            Exit(rctx);
        end;
    end
    else
    if (EVP_PKEY_CTX_IS_GEN_OP(pctx)) then
    begin
        { Not supported - This would need a gen_dupctx to work }
        goto _err;
    end;
    rctx.pmeth := pctx.pmeth;
{$IFNDEF OPENSSL_NO_ENGINE}
    rctx.engine := pctx.engine;
{$ENDIF}
    if pctx.peerkey <> nil then
       EVP_PKEY_up_ref(pctx.peerkey);
    rctx.peerkey := pctx.peerkey;
    if pctx.pmeth = nil then
    begin
        if rctx.operation = EVP_PKEY_OP_UNDEFINED then  begin
            tmp_keymgmt := pctx.keymgmt;
            provkey := evp_pkey_export_to_provider(pctx.pkey, pctx.libctx,
                                                  @tmp_keymgmt, pctx.propquery);
            if provkey = nil then
               goto _err;
            if 0>=EVP_KEYMGMT_up_ref(tmp_keymgmt) then
                goto _err;
            EVP_KEYMGMT_free(rctx.keymgmt);
            rctx.keymgmt := tmp_keymgmt;
            Exit(rctx);
        end;
    end
    else
    if (pctx.pmeth.copy(rctx, pctx) > 0) then
    begin
        Exit(rctx);
    end;
_err:
    rctx.pmeth := nil;
    EVP_PKEY_CTX_free(rctx);
    Result := nil;
end;




function EVP_PKEY_CTX_new( pkey : PEVP_PKEY; e : PENGINE):PEVP_PKEY_CTX;
begin
    Result := int_ctx_new(nil, pkey, e, nil, nil, -1);
end;




function EVP_PKEY_CTX_get0_pkey( ctx : PEVP_PKEY_CTX):PEVP_PKEY;
begin
    Result := ctx.pkey;
end;





function EVP_PKEY_CTX_set_signature_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
begin
    Exit(evp_pkey_ctx_set_md(ctx, md, Int(ctx.op.sig.algctx = nil),
                               OSSL_SIGNATURE_PARAM_DIGEST,
                               EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD));
end;



function evp_pkey_ctx_use_cached_data( ctx : PEVP_PKEY_CTX):integer;
var
  ret : integer;
  name : PUTF8Char;
  val : Pointer;
  len : size_t;
begin
    ret := 1;
    if (ret > 0) and  (ctx.cached_parameters.dist_id_set > 0) then
    begin
         name := ctx.cached_parameters.dist_id_name;
        val := ctx.cached_parameters.dist_id;
        len := ctx.cached_parameters.dist_id_len;
        if name <> nil then
           ret := evp_pkey_ctx_ctrl_str_int(ctx, name, val)
        else
           ret := evp_pkey_ctx_ctrl_int(ctx, -1, ctx.operation,
                                        EVP_PKEY_CTRL_SET1_ID,
                                        int(len), Pointer(val));
    end;
    Result := ret;
end;

function EVP_PKEY_CTX_new_from_pkey(libctx : POSSL_LIB_CTX; pkey : PEVP_PKEY;const propquery : PUTF8Char):PEVP_PKEY_CTX;
begin
    Result := int_ctx_new(libctx, pkey, nil, nil, propquery, -1);
end;



function EVP_PKEY_CTX_is_a(ctx : PEVP_PKEY_CTX;const keytype : PUTF8Char):integer;
begin
{$IFNDEF FIPS_MODULE}
    if evp_pkey_ctx_is_legacy(ctx) then
        Exit(int(ctx.pmeth.pkey_id = evp_pkey_name2type(keytype)));
{$ENDIF}
    Result := Int(EVP_KEYMGMT_is_a(ctx.keymgmt, keytype));
end;



procedure evp_pkey_ctx_free_all_cached_data( ctx : PEVP_PKEY_CTX);
begin
    evp_pkey_ctx_free_cached_data(ctx, EVP_PKEY_CTRL_SET1_ID, nil);
end;




procedure evp_pkey_ctx_free_old_ops( ctx : PEVP_PKEY_CTX);
begin
    if EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) then
    begin
        if (ctx.op.sig.algctx <> nil)  and  (ctx.op.sig.signature <> nil) then
            ctx.op.sig.signature.freectx(ctx.op.sig.algctx);
        EVP_SIGNATURE_free(ctx.op.sig.signature);
        ctx.op.sig.algctx := nil;
        ctx.op.sig.signature := nil;
    end
    else
    if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) then
    begin
        if (ctx.op.kex.algctx <> nil)  and  (ctx.op.kex.exchange <> nil) then
           ctx.op.kex.exchange.freectx(ctx.op.kex.algctx);
        EVP_KEYEXCH_free(ctx.op.kex.exchange);
        ctx.op.kex.algctx := nil;
        ctx.op.kex.exchange := nil;
    end
    else
    if (EVP_PKEY_CTX_IS_KEM_OP(ctx)) then
    begin
        if (ctx.op.encap.algctx <> nil)  and  (ctx.op.encap.kem <> nil) then
           ctx.op.encap.kem.freectx(ctx.op.encap.algctx);
        EVP_KEM_free(ctx.op.encap.kem);
        ctx.op.encap.algctx := nil;
        ctx.op.encap.kem := nil;
    end
    else
    if (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) then
    begin
        if (ctx.op.ciph.algctx <> nil)  and  (ctx.op.ciph.cipher <> nil) then
           ctx.op.ciph.cipher.freectx(ctx.op.ciph.algctx);
        EVP_ASYM_CIPHER_free(ctx.op.ciph.cipher);
        ctx.op.ciph.algctx := nil;
        ctx.op.ciph.cipher := nil;
    end
    else
    if (EVP_PKEY_CTX_IS_GEN_OP(ctx)) then
    begin
        if (ctx.op.keymgmt.genctx <> nil)  and  (ctx.keymgmt <> nil) then
           evp_keymgmt_gen_cleanup(ctx.keymgmt, ctx.op.keymgmt.genctx);
    end;
end;

procedure EVP_PKEY_CTX_free( ctx : PEVP_PKEY_CTX);
begin
    if ctx = nil then Exit;
    if (ctx.pmeth <> nil) and  (Assigned(ctx.pmeth.cleanup)) then
       ctx.pmeth.cleanup(ctx);
    evp_pkey_ctx_free_old_ops(ctx);
{$IFNDEF FIPS_MODULE}
    evp_pkey_ctx_free_all_cached_data(ctx);
{$ENDIF}
    EVP_KEYMGMT_free(ctx.keymgmt);
    OPENSSL_free(ctx.propquery);
    EVP_PKEY_free(ctx.pkey);
    EVP_PKEY_free(ctx.peerkey);
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    ENGINE_finish(ctx.engine);
{$ENDIF}
    BN_free(ctx.rsa_pubexp);
    OPENSSL_free(ctx);
end;




function EVP_PKEY_CTX_get_params( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
begin
    case (evp_pkey_ctx_state(ctx)) of
    EVP_PKEY_STATE_PROVIDER:
    begin
        if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx))  and  (ctx.op.kex.exchange <> nil)
             and  (Assigned(ctx.op.kex.exchange.get_ctx_params))then
            Exit(
                ctx.op.kex.exchange.get_ctx_params(ctx.op.kex.algctx,
                                                     params));
        if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) and  (ctx.op.sig.signature <> nil)
             and  (Assigned(ctx.op.sig.signature.get_ctx_params))then
            Exit(
                ctx.op.sig.signature.get_ctx_params(ctx.op.sig.algctx,
                                                      params));
        if (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) and  (ctx.op.ciph.cipher <> nil)
             and  (Assigned(ctx.op.ciph.cipher.get_ctx_params))then
            Exit(
                ctx.op.ciph.cipher.get_ctx_params(ctx.op.ciph.algctx,
                                                    params));
        if (EVP_PKEY_CTX_IS_KEM_OP(ctx))  and  (ctx.op.encap.kem <> nil)
             and  (Assigned(ctx.op.encap.kem.get_ctx_params))then
            Exit(
                ctx.op.encap.kem.get_ctx_params(ctx.op.encap.algctx,
                                                  params));
    end;
{$IFNDEF FIPS_MODULE}
    EVP_PKEY_STATE_UNKNOWN,
    EVP_PKEY_STATE_LEGACY:
        Exit(evp_pkey_ctx_get_params_to_ctrl(ctx, params));
{$ENDIF}
    end;
    Result := 0;
end;




function EVP_PKEY_CTX_gettable_params(const ctx : PEVP_PKEY_CTX):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx))  and  (ctx.op.kex.exchange <> nil)
             and  (Assigned(ctx.op.kex.exchange.gettable_ctx_params))  then
    begin
        provctx := ossl_provider_ctx(EVP_KEYEXCH_get0_provider(ctx.op.kex.exchange));
        Exit(ctx.op.kex.exchange.gettable_ctx_params(ctx.op.kex.algctx,
                                                         provctx));
    end;
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) and  (ctx.op.sig.signature <> nil)
             and  (Assigned(ctx.op.sig.signature.gettable_ctx_params))  then
    begin
        provctx := ossl_provider_ctx(
                      EVP_SIGNATURE_get0_provider(ctx.op.sig.signature));
        Exit(ctx.op.sig.signature.gettable_ctx_params(ctx.op.sig.algctx,
                                                          provctx));
    end;
    if (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) and  (ctx.op.ciph.cipher <> nil)
             and  (Assigned(ctx.op.ciph.cipher.gettable_ctx_params))  then
    begin
        provctx := ossl_provider_ctx(
                      EVP_ASYM_CIPHER_get0_provider(ctx.op.ciph.cipher));
        Exit(ctx.op.ciph.cipher.gettable_ctx_params(ctx.op.ciph.algctx,
                                                        provctx));
    end;
    if (EVP_PKEY_CTX_IS_KEM_OP(ctx))   and  (ctx.op.encap.kem <> nil)
         and  (Assigned(ctx.op.encap.kem.gettable_ctx_params))  then
    begin
        provctx := ossl_provider_ctx(EVP_KEM_get0_provider(ctx.op.encap.kem));
        Exit(ctx.op.encap.kem.gettable_ctx_params(ctx.op.encap.algctx,
                                                      provctx));
    end;
    Result := nil;
end;


function evp_pkey_ctx_get_params_strict( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
var
  gettable,
  p        : POSSL_PARAM;
begin
    if (ctx = nil)  or  (params = nil) then Exit(0);
    {
     * We only check for provider side EVP_PKEY_CTX.  For #legacy, we
     * depend on the translation that happens in EVP_PKEY_CTX_get_params()
     * call, and that the resulting ctrl call will return -2 if it doesn't
     * known the ctrl command number.
     }
    if evp_pkey_ctx_is_provided(ctx) then
    begin
         gettable := EVP_PKEY_CTX_gettable_params(ctx);
        p := params;
        while p.key <> nil do
        begin
            { Check the ctx actually understands this parameter }
            if OSSL_PARAM_locate_const(gettable, p.key) = nil  then
                Exit(-2);
            Inc(p);
        end;
    end;
    Result := EVP_PKEY_CTX_get_params(ctx, params);
end;


function evp_pkey_ctx_ctrl_int( ctx : PEVP_PKEY_CTX; keytype, optype, cmd, p1 : integer; p2 : Pointer):integer;
var
  ret : integer;
begin
    ret := 0;
    {
     * If the method has a |digest_custom| function, we can relax the
     * operation type check, since this can be called before the operation
     * is initialized.
     }
    if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.digest_custom)) then
    begin
        if ctx.operation = EVP_PKEY_OP_UNDEFINED then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_NO_OPERATION_SET);
            Exit(-1);
        end;
        if (optype <> -1)  and  (0>= (ctx.operation and optype) ) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
            Exit(-1);
        end;
    end;
    case (evp_pkey_ctx_state(ctx)) of
        EVP_PKEY_STATE_PROVIDER:
            Exit(evp_pkey_ctx_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2));
        EVP_PKEY_STATE_UNKNOWN,
        EVP_PKEY_STATE_LEGACY:
        begin
            if (ctx.pmeth = nil)  or  (not Assigned(ctx.pmeth.ctrl) ) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
                Exit(-2);
            end;
            if (keytype <> -1) and  (ctx.pmeth.pkey_id <> keytype) then
                Exit(-1);
            ret := ctx.pmeth.ctrl(ctx, cmd, p1, p2);
            if ret = -2 then
               ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        end;
    end;
    Result := ret;
end;



procedure evp_pkey_ctx_free_cached_data(ctx : PEVP_PKEY_CTX; cmd : integer;const name : PUTF8Char);
begin
    cmd := decode_cmd(cmd, name);
    case cmd of
        EVP_PKEY_CTRL_SET1_ID:
        begin
            OPENSSL_free(ctx.cached_parameters.dist_id);
            OPENSSL_free(ctx.cached_parameters.dist_id_name);
            ctx.cached_parameters.dist_id := nil;
            ctx.cached_parameters.dist_id_name := nil;
        end;
    end;
end;





function decode_cmd(cmd : integer;const name : PUTF8Char):integer;
begin
    if cmd = -1 then
    begin
        {
         * The consequence of the assertion not being true is that this
         * function will return -1, which will cause the calling functions
         * to signal that the command is unsupported...  in non-debug mode.
         }
        if ossl_assert(name <> nil) then
            if (strcmp(name, 'distid') = 0)  or  (strcmp(name, 'hexdistid') = 0) then
                cmd := EVP_PKEY_CTRL_SET1_ID;
    end;
    Result := cmd;
end;

function evp_pkey_ctx_store_cached_data(ctx : PEVP_PKEY_CTX; keytype, optype, cmd : integer;const name : PUTF8Char; data : Pointer; data_len : size_t):int;
begin
    {
     * Check that it's one of the supported commands.  The ctrl commands
     * number cases here must correspond to the cases in the bottom switch
     * in this function.
     }
    cmd := decode_cmd(cmd, name);
    case cmd of
      EVP_PKEY_CTRL_SET1_ID:
          //break;
      else
      begin
          ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
          Exit(-2);
      end;
    end;

    if keytype <> -1 then
    begin
        case (evp_pkey_ctx_state(ctx)) of
            EVP_PKEY_STATE_PROVIDER:
            begin
                if ctx.keymgmt = nil then
                begin
                    ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
                    Exit(-2);
                end;
                if not EVP_KEYMGMT_is_a(ctx.keymgmt,
                                      evp_pkey_type2name(keytype)) then
                begin
                    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
                    Exit(-1);
                end;
            end;
            EVP_PKEY_STATE_UNKNOWN,
            EVP_PKEY_STATE_LEGACY:
            begin
                if ctx.pmeth = nil then
                begin
                    ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
                    Exit(-2);
                end;
                if EVP_PKEY_type(ctx.pmeth.pkey_id) <> EVP_PKEY_type(keytype)  then
                begin
                    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
                    Exit(-1);
                end;
            end;
        end;
    end;
    if (optype <> -1)  and  ( (ctx.operation and optype) = 0)  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
        Exit(-1);
    end;

    case cmd of
        EVP_PKEY_CTRL_SET1_ID:
        begin
            evp_pkey_ctx_free_cached_data(ctx, cmd, name);
            if name <> nil then
            begin
                OPENSSL_strdup(ctx.cached_parameters.dist_id_name ,name);
                if ctx.cached_parameters.dist_id_name = nil then
                begin
                    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                    Exit(0);
                end;
            end;
            if data_len > 0 then
            begin
                ctx.cached_parameters.dist_id := OPENSSL_memdup(data, data_len);
                if ctx.cached_parameters.dist_id = nil then
                begin
                    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                    Exit(0);
                end;
            end;
            ctx.cached_parameters.dist_id_set := 1;
            ctx.cached_parameters.dist_id_len := data_len;
        end;
    end;
    Result := 1;
end;

function evp_pkey_ctx_state(const ctx : PEVP_PKEY_CTX):integer;
begin
    if ctx.operation = EVP_PKEY_OP_UNDEFINED then
       Exit(EVP_PKEY_STATE_UNKNOWN);
    if ( (EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) and  (ctx.op.kex.algctx <> nil) )
         or ( (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))
             and  (ctx.op.sig.algctx <> nil))
         or ( (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx))
             and  (ctx.op.ciph.algctx <> nil) )
         or ( (EVP_PKEY_CTX_IS_GEN_OP(ctx))
             and  (ctx.op.keymgmt.genctx <> nil))
         or ( (EVP_PKEY_CTX_IS_KEM_OP(ctx))
             and  (ctx.op.encap.algctx <> nil))  then
        Exit(EVP_PKEY_STATE_PROVIDER);
    Result := EVP_PKEY_STATE_LEGACY;
end;

function EVP_PKEY_CTX_set_params(ctx : PEVP_PKEY_CTX;const params : POSSL_PARAM):integer;
begin
    case evp_pkey_ctx_state(ctx) of
    EVP_PKEY_STATE_PROVIDER:
    begin
        if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) and  (ctx.op.kex.exchange <> nil)
             and  (Assigned(ctx.op.kex.exchange.set_ctx_params)) then
            Exit(ctx.op.kex.exchange.set_ctx_params(ctx.op.kex.algctx, params));
        if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) and  (ctx.op.sig.signature <> nil)
             and  (Assigned(ctx.op.sig.signature.set_ctx_params))  then
            Exit(ctx.op.sig.signature.set_ctx_params(ctx.op.sig.algctx, params));
        if (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx))  and  (ctx.op.ciph.cipher <> nil)
             and  (Assigned(ctx.op.ciph.cipher.set_ctx_params)) then
            Exit(ctx.op.ciph.cipher.set_ctx_params(ctx.op.ciph.algctx, params));
        if (EVP_PKEY_CTX_IS_GEN_OP(ctx)) and  (ctx.keymgmt <> nil)
             and  (Assigned(ctx.keymgmt.gen_set_params)) then
            Exit(evp_keymgmt_gen_set_params(ctx.keymgmt, ctx.op.keymgmt.genctx,
                                           params));
        if (EVP_PKEY_CTX_IS_KEM_OP(ctx)) and  (ctx.op.encap.kem <> nil)
             and  (Assigned(ctx.op.encap.kem.set_ctx_params))  then
            Exit(ctx.op.encap.kem.set_ctx_params(ctx.op.encap.algctx, params));
    end;
{$IFNDEF FIPS_MODULE}
    EVP_PKEY_STATE_UNKNOWN,
    EVP_PKEY_STATE_LEGACY:
        Exit(evp_pkey_ctx_set_params_to_ctrl(ctx, params));
{$ENDIF}
    end;
    Result := 0;
end;

function EVP_PKEY_CTX_ctrl( ctx : PEVP_PKEY_CTX; keytype, optype, cmd, p1 : integer; p2 : Pointer):integer;
var
  ret : integer;
begin
    ret := 0;
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        Exit(-2);
    end;
    { If unsupported, we don't want that reported here }
    ERR_set_mark();
    ret := evp_pkey_ctx_store_cached_data(ctx, keytype, optype,
                                         cmd, nil, p2, p1);
    if ret = -2 then
    begin
        ERR_pop_to_mark();
    end
    else
    begin
        ERR_clear_last_mark();
        {
         * If there was an error, there was an error.
         * If the operation isn't initialized yet, we also return, as
         * the saved values will be used then anyway.
         }
        if (ret < 1)  or  (ctx.operation = EVP_PKEY_OP_UNDEFINED) then
           Exit(ret);
    end;
    Result := evp_pkey_ctx_ctrl_int(ctx, keytype, optype, cmd, p1, p2);
end;

function evp_pkey_ctx_set_params_strict( ctx : PEVP_PKEY_CTX; params : POSSL_PARAM):integer;
var
  settable,
  p        : POSSL_PARAM;
begin
    if (ctx = nil)  or  (params = nil) then Exit(0);
    {
     * We only check for provider side EVP_PKEY_CTX.  For #legacy, we
     * depend on the translation that happens in EVP_PKEY_CTX_set_params()
     * call, and that the resulting ctrl call will return -2 if it doesn't
     * known the ctrl command number.
     }
    if evp_pkey_ctx_is_provided(ctx) then
    begin
         settable := EVP_PKEY_CTX_settable_params(ctx);
        p := params;
        while p.key <> nil do
        begin
            { Check the ctx actually understands this parameter }
            if OSSL_PARAM_locate_const(settable, p.key) = nil  then
                Exit(-2);
            Inc(p);
        end;
    end;
    Result := EVP_PKEY_CTX_set_params(ctx, params);
end;



function EVP_PKEY_CTX_md(ctx : PEVP_PKEY_CTX; optype, cmd : integer;const md : PUTF8Char):integer;
var
  m : PEVP_MD;
begin
    m := EVP_get_digestbyname(md);
    if (md = nil)  or  (m = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_DIGEST);
        Exit(0);
    end;
    Result := EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, 0, Pointer( m));
end;

function pmeth_func_cmp(const a : PPEVP_PKEY_METHOD; b : Ppmeth_fn):integer;
begin
    Result := a^.pkey_id - (b^()).pkey_id;
end;

function pmeth_cmp(const a, b : PPEVP_PKEY_METHOD):integer;
begin
    Result := (a^.pkey_id - b^.pkey_id);
end;

function pmeth_func_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a : PPEVP_PKEY_METHOD;
  b : Ppmeth_fn;
begin
   a := a_;
   b := b_;
   Result := pmeth_func_cmp(a, b);
end;

function OBJ_bsearch_pmeth_func( key : PPEVP_PKEY_METHOD; base : Tpmeth_fn; num : integer): Tpmeth_fn;
begin
   Result := Tpmeth_fn(OBJ_bsearch_(key, base, num, sizeof(Tpmeth_fn), pmeth_func_cmp_BSEARCH_CMP_FN));
end;



function EVP_PKEY_meth_find( _type : integer):PEVP_PKEY_METHOD;
var
  ret : Tpmeth_fn;
  t: PEVP_PKEY_METHOD ;
  tmp : TEVP_PKEY_METHOD;
begin
    t := evp_pkey_meth_find_added_by_application(_type);
    if t <> nil then
        Exit(t);
    tmp.pkey_id := _type;
    t := @tmp;
    ret := OBJ_bsearch_pmeth_func(@t, @standard_methods, Length(standard_methods));
    if (ret = nil)  or  (not Assigned(ret)) then
       Exit(nil);
    Result := ret();
end;

procedure EVP_PKEY_meth_free( pmeth : PEVP_PKEY_METHOD);
begin
    if (pmeth <> nil) and  ((pmeth.flags and EVP_PKEY_FLAG_DYNAMIC) > 0)  then
        OPENSSL_free(pmeth);
end;

procedure help_get_legacy_alg_type_from_keymgmt(const keytype : PUTF8Char; arg : Pointer);
var
  _type : PInteger;
begin
    _type := arg;
    if _type^ = NID_undef then
       _type^ := evp_pkey_name2type(keytype);
end;



function get_legacy_alg_type_from_keymgmt(const keymgmt : PEVP_KEYMGMT):integer;
var
  _type : integer;
begin
    _type := NID_undef;
    EVP_KEYMGMT_names_do_all(keymgmt, help_get_legacy_alg_type_from_keymgmt, @_type);
    Result := _type;
end;

function evp_pkey_meth_find_added_by_application( &type : integer):PEVP_PKEY_METHOD;
var
  idx : integer;

  tmp : TEVP_PKEY_METHOD;
begin
    if app_pkey_methods <> nil then
    begin
        tmp.pkey_id := &type;
        idx := sk_EVP_PKEY_METHOD_find(app_pkey_methods, @tmp);
        if idx >= 0 then
           Exit(sk_EVP_PKEY_METHOD_value(app_pkey_methods, idx));
    end;
    Result := nil;
end;

function int_ctx_new(libctx : POSSL_LIB_CTX; pkey : PEVP_PKEY; e : PENGINE; keytype, propquery : PUTF8Char; id : integer):PEVP_PKEY_CTX;
var
  ret       : PEVP_PKEY_CTX;
  pmeth,
  app_pmeth : PEVP_PKEY_METHOD;
  keymgmt   : PEVP_KEYMGMT;
  tmp_id    : integer;
  label common ;
begin
    ret := nil;
    pmeth := nil;
    app_pmeth := nil;
    keymgmt := nil;
    { Code below to be removed when legacy support is dropped. }
    { BEGIN legacy }
    if id = -1 then
    begin
        if (pkey <> nil)  and   (not evp_pkey_is_provided(pkey)) then
        begin
            id := pkey.&type;
        end
        else
        begin
            if pkey <> nil then
            begin
                { Must be provided if we get here }
                keytype := EVP_KEYMGMT_get0_name(pkey.keymgmt);
            end;
{$IFNDEF FIPS_MODULE}
            if keytype <> nil then
            begin
                id := evp_pkey_name2type(keytype);
                if id = NID_undef then id := -1;
            end;
{$ENDIF}
        end;
    end;
    { If no ID was found here, we can only resort to find a keymgmt }
    if id = -1 then
    begin
{$IFNDEF FIPS_MODULE}
        { Using engine with a key without id will not work }
        if e <> nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM);
            Exit(nil);
        end;
{$ENDIF}
        goto common;
    end;
{$IFNDEF FIPS_MODULE}
    {
     * Here, we extract what information we can for the purpose of
     * supporting usage with implementations from providers, to make
     * for a smooth transition from legacy stuff to provider based stuff.
     *
     * If an engine is given, this is entirely legacy, and we should not
     * pretend anything else, so we clear the name.
     }
    if e <> nil then keytype := nil;
    if (e = nil)  and  ( (pkey = nil)  or  (pkey.foreign = 0) )then
        keytype := OBJ_nid2sn(id);
{$ifndef OPENSSL_NO_ENGINE}
    if (e = nil)  and ( pkey <> nil) then
    begin
       if pkey.pmeth_engine <> nil then
          e := pkey.pmeth_engine
       else
          e := pkey.engine;
    end;
    { Try to find an ENGINE which implements this method }
    if e <> nil then
    begin
        if  0>= ENGINE_init(e) then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB);
            Exit(nil);
        end;
    end
    else
    begin
        e := ENGINE_get_pkey_meth_engine(id);
    end;
    {
     * If an ENGINE handled this method look it up. Otherwise use internal
     * tables.
     }
    if e <> nil then
       pmeth := ENGINE_get_pkey_meth(e, id)
    else
    if (pkey <> nil)  and  (pkey.foreign>0) then
       pmeth := EVP_PKEY_meth_find(id)
    else
{$endif}
        pmeth := evp_pkey_meth_find_added_by_application(id);
        app_pmeth := pmeth;
    { END legacy }
{$endif} { FIPS_MODULE }
 common:
    {
     * If there's no engine and no app supplied pmeth and there's a name, we try
     * fetching a provider implementation.
     }
    if (e = nil)  and  (app_pmeth = nil)  and  (keytype <> nil) then
    begin
        {
         * If |pkey| is given and is provided, we take a reference to its
         * keymgmt.  Otherwise, we fetch one for the keytype we got. This
         * is to ensure that operation init functions can access what they
         * need through this single pointer.
         }
        if (pkey <> nil)  and  (pkey.keymgmt <> nil) then
        begin
            if  0>= EVP_KEYMGMT_up_ref(pkey.keymgmt) then
                ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR)
            else
                keymgmt := pkey.keymgmt;
        end
        else
        begin
            keymgmt := EVP_KEYMGMT_fetch(libctx, keytype, propquery);
        end;
        if keymgmt = nil then Exit(nil);   { EVP_KEYMGMT_fetch() recorded an error }
{$IFNDEF FIPS_MODULE}
        {
         * Chase down the legacy NID, as that might be needed for diverse
         * purposes, such as ensure that EVP_PKEY_type() can return sensible
         * values. We go through all keymgmt names, because the keytype
         * that's passed to this function doesn't necessarily translate
         * directly.
         }
        if keymgmt <> nil then
        begin
            tmp_id := get_legacy_alg_type_from_keymgmt(keymgmt);
            if tmp_id <> NID_undef then
            begin
                if id = -1 then
                begin
                    id := tmp_id;
                end
                else
                begin
                    {
                     * It really really shouldn't differ.  If it still does,
                     * something is very wrong.
                     }
                    if  not ossl_assert(id = tmp_id) then
                    begin
                        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
                        EVP_KEYMGMT_free(keymgmt);
                        Exit(nil);
                    end;
                end;
            end;
        end;
{$ENDIF}
    end;
    if (pmeth = nil)  and  (keymgmt = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    end
    else
    begin
        ret := OPENSSL_zalloc(sizeof( ret^));
        if ret = nil then
           ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    end;
{$IF not defined(OPENSSL_NO_ENGINE)  and   not defined(FIPS_MODULE)}
    if (ret = nil)  or  (pmeth = nil)  and  (e <> nil) then
        ENGINE_finish(e);
{$ENDIF}
    if ret = nil then
    begin
        EVP_KEYMGMT_free(keymgmt);
        Exit(nil);
    end;
    if propquery <> nil then
    begin
        OPENSSL_strdup(ret.propquery ,propquery);
        if ret.propquery = nil then
        begin
            OPENSSL_free(ret);
            EVP_KEYMGMT_free(keymgmt);
            Exit(nil);
        end;
    end;
    ret.libctx := libctx;
    ret.keytype := keytype;
    ret.keymgmt := keymgmt;
    ret.legacy_keytype := id;
    ret.engine := e;
    ret.pmeth := pmeth;
    ret.operation := EVP_PKEY_OP_UNDEFINED;
    ret.pkey := pkey;
    if pkey <> nil then
       EVP_PKEY_up_ref(pkey);
    if (pmeth <> nil)  and  (Assigned(pmeth.init)) then
    begin
        if pmeth.init(ret) <= 0 then
        begin
            ret.pmeth := nil;
            EVP_PKEY_CTX_free(ret);
            Exit(nil);
        end;
    end;
    Result := ret;
end;

function EVP_PKEY_CTX_new_from_name(libctx : POSSL_LIB_CTX;const name, propquery : PUTF8Char):PEVP_PKEY_CTX;
begin
    Result := int_ctx_new(libctx, nil, nil, name, propquery, -1);
end;

function EVP_PKEY_CTX_settable_params(const ctx : PEVP_PKEY_CTX):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx))   and  (ctx.op.kex.exchange <> nil)
             and  ( Assigned(ctx.op.kex.exchange.settable_ctx_params))then
    begin
        provctx := ossl_provider_ctx(EVP_KEYEXCH_get0_provider(ctx.op.kex.exchange));
        Exit(ctx.op.kex.exchange.settable_ctx_params(ctx.op.kex.algctx,
                                                         provctx));
    end;
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) and  (ctx.op.sig.signature <> nil)
             and  (Assigned(ctx.op.sig.signature.settable_ctx_params )) then
    begin
        provctx := ossl_provider_ctx(
                      EVP_SIGNATURE_get0_provider(ctx.op.sig.signature));
        Exit(ctx.op.sig.signature.settable_ctx_params(ctx.op.sig.algctx,
                                                          provctx));
    end;
    if (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx))  and  (ctx.op.ciph.cipher <> nil)
             and  ( Assigned(ctx.op.ciph.cipher.settable_ctx_params )) then
    begin
        provctx := ossl_provider_ctx(
                      EVP_ASYM_CIPHER_get0_provider(ctx.op.ciph.cipher));
        Exit(ctx.op.ciph.cipher.settable_ctx_params(ctx.op.ciph.algctx,
                                                        provctx));
    end;
    if (EVP_PKEY_CTX_IS_GEN_OP(ctx))  and  (ctx.keymgmt <> nil)
             and  (Assigned(ctx.keymgmt.gen_settable_params )) then
    begin
        provctx := ossl_provider_ctx(EVP_KEYMGMT_get0_provider(ctx.keymgmt));
        Exit(ctx.keymgmt.gen_settable_params(ctx.op.keymgmt.genctx,
                                                 provctx));
    end;
    if (EVP_PKEY_CTX_IS_KEM_OP(ctx)) and  (ctx.op.encap.kem <> nil)
         and  (Assigned(ctx.op.encap.kem.settable_ctx_params)) then
    begin
        provctx := ossl_provider_ctx(EVP_KEM_get0_provider(ctx.op.encap.kem));
        Exit(ctx.op.encap.kem.settable_ctx_params(ctx.op.encap.algctx,
                                                      provctx));
    end;
    Result := nil;
end;


end.
