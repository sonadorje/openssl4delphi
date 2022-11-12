unit openssl3.crypto.evp.pmeth_gn;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

procedure evp_pkey_set_cb_translate( cb : PBN_GENCB; ctx : PEVP_PKEY_CTX);
function trans_cb( a, b : integer; gcb : PBN_GENCB):integer;
function EVP_PKEY_keygen_init( ctx : PEVP_PKEY_CTX):integer;
function gen_init( ctx : PEVP_PKEY_CTX; operation : integer):integer;
function EVP_PKEY_generate( ctx : PEVP_PKEY_CTX; ppkey : PPEVP_PKEY):integer;
function ossl_callback_to_pkey_gencb(const params : POSSL_PARAM; arg : Pointer):integer;
function EVP_PKEY_fromdata_init( ctx : PEVP_PKEY_CTX):integer;
function fromdata_init( ctx : PEVP_PKEY_CTX; operation : integer):integer;
function EVP_PKEY_fromdata( ctx : PEVP_PKEY_CTX; ppkey : PPEVP_PKEY; selection : integer; params : POSSL_PARAM):integer;
function EVP_PKEY_keygen( ctx : PEVP_PKEY_CTX; ppkey : PPEVP_PKEY):integer;

implementation

uses OpenSSL3.Err, openssl3.crypto.evp,  openssl3.crypto.evp.p_lib,
     openssl3.crypto.bn.bn_lib,          openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.params,             OpenSSL3.common,
     openssl3.crypto.evp.keymgmt_meth,   openssl3.crypto.evp.keymgmt_lib;

function EVP_PKEY_keygen( ctx : PEVP_PKEY_CTX; ppkey : PPEVP_PKEY):integer;
begin
    if ctx.operation <> EVP_PKEY_OP_KEYGEN then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
        Exit(-1);
    end;
    Result := EVP_PKEY_generate(ctx, ppkey);
end;


function EVP_PKEY_fromdata( ctx : PEVP_PKEY_CTX; ppkey : PPEVP_PKEY; selection : integer; params : POSSL_PARAM):integer;
var
    keydata        : Pointer;

    allocated_pkey : PEVP_PKEY;
begin
    keydata := nil;
    allocated_pkey := nil;
    if (ctx = nil)  or  (ctx.operation and EVP_PKEY_OP_FROMDATA  = 0) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end;
    if ppkey = nil then Exit(-1);
    if ppkey^ = nil then
    begin
        ppkey^ := EVP_PKEY_new;
        allocated_pkey := ppkey^;
    end;
    if ppkey^ = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    keydata := evp_keymgmt_util_fromdata( ppkey^, ctx.keymgmt, selection, params);
    if keydata = nil then begin
        if allocated_pkey <> nil then  begin
            ppkey^ := nil;
            EVP_PKEY_free(allocated_pkey);
        end;
        Exit(0);
    end;
    { keydata is cached in *ppkey, so we need not bother with it further }
    Result := 1;
end;


function fromdata_init( ctx : PEVP_PKEY_CTX; operation : integer):integer;
label _not_supported;
begin
    if (ctx = nil)  or  (ctx.keytype = nil) then
       goto _not_supported;
    evp_pkey_ctx_free_old_ops(ctx);
    if ctx.keymgmt = nil then goto _not_supported;
    ctx.operation := operation;
    Exit(1);
 _not_supported:
    if ctx <> nil then ctx.operation := EVP_PKEY_OP_UNDEFINED;
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    Result := -2;
end;


function EVP_PKEY_fromdata_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := fromdata_init(ctx, EVP_PKEY_OP_FROMDATA);
end;




function ossl_callback_to_pkey_gencb(const params : POSSL_PARAM; arg : Pointer):integer;
var
  ctx : PEVP_PKEY_CTX;
  param : POSSL_PARAM;
  p, n : integer;
begin
{$POINTERMATH ON}
    ctx := arg;
    param := nil;
    p := -1; n := -1;
    if not Assigned(ctx.pkey_gencb) then Exit(1);                { No callback?  That's fine }
    param := OSSL_PARAM_locate_const(params, OSSL_GEN_PARAM_POTENTIAL);
    if (param = nil) or  (0>=OSSL_PARAM_get_int(param, @p)) then
        Exit(0);
    param := OSSL_PARAM_locate_const(params, OSSL_GEN_PARAM_ITERATION);
    if (param = nil) or  (0>=OSSL_PARAM_get_int(param, @n)) then
        Exit(0);
    ctx.keygen_info[0] := p;
    ctx.keygen_info[1] := n;
    Result := ctx.pkey_gencb(ctx);
{$POINTERMATH OFF}
end;




function EVP_PKEY_generate( ctx : PEVP_PKEY_CTX; ppkey : PPEVP_PKEY):integer;
var
    ret            : integer;
    allocated_pkey : PEVP_PKEY;
    gentmp         : array[0..1] of integer;
    tmp_keymgmt    : PEVP_KEYMGMT;
    keydata        : Pointer;
    label _not_supported, _not_initialized, _legacy, _end, _not_accessible;
begin
    ret := 0;
    allocated_pkey := nil;
    { Legacy compatible keygen callback info, only used with provider impls }
    if ppkey = nil then Exit(-1);
    if ctx = nil then
       goto _not_supported;
    if ctx.operation and EVP_PKEY_OP_TYPE_GEN  = 0 then
       goto _not_initialized;
    if ppkey^ = nil then
    begin
       allocated_pkey := EVP_PKEY_new();
       ppkey^ := allocated_pkey;
    end;
    if ppkey^ = nil then begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    if ctx.op.keymgmt.genctx = nil then
       goto _legacy;
    {
     * Asssigning gentmp to ctx.keygen_info is something our legacy
     * implementations do.  Because the provider implementations aren't
     * allowed to reach into our EVP_PKEY_CTX, we need to provide similar
     * space for backward compatibility.  It's ok that we attach a local
     * variable, as it should only be useful in the calls down from here.
     * This is cleared as soon as it isn't useful any more, i.e. directly
     * after the evp_keymgmt_util_gen call.
     }
    ctx.keygen_info := @gentmp;
    ctx.keygen_info_count := 2;
    ret := 1;
    if ctx.pkey <> nil then
    begin
        tmp_keymgmt := ctx.keymgmt;
        keydata :=  evp_pkey_export_to_provider(ctx.pkey, ctx.libctx,
                                        @tmp_keymgmt, ctx.propquery);
        if tmp_keymgmt = nil then goto _not_supported;
        {
         * It's ok if keydata is nil here.  The backend is expected to deal
         * with that as it sees fit.
         }
        ret := evp_keymgmt_gen_set_template(ctx.keymgmt,
                                           ctx.op.keymgmt.genctx, keydata);
    end;
    {
     * the returned value from evp_keymgmt_util_gen is cached in *ppkey,
     * so we do not need to save it, just check it.
     }
    ret := Int( (ret > 0) and  (evp_keymgmt_util_gen( ppkey^, ctx.keymgmt, ctx.op.keymgmt.genctx,
                                 ossl_callback_to_pkey_gencb, ctx) <> nil) );
    ctx.keygen_info := nil;
{$IFNDEF FIPS_MODULE}
    { In case |*ppkey| was originally a legacy key }
    if ret > 0 then evp_pkey_free_legacy( ppkey^);
{$ENDIF}
    {
     * Because we still have legacy keys
     }
    ( ppkey^).&type := ctx.legacy_keytype;
    goto _end;

 _legacy:
{$IFDEF FIPS_MODULE}
    goto _not_supported;
{$ELSE }
     {* If we get here then we're using legacy paramgen/keygen. In that case
     * the pkey in ctx (if there is one) had better not be provided (because the
     * legacy methods may not know how to handle it). However we can only get
     * here if ctx.op.keymgmt.genctx = nil, but that should never be the case
     * if ctx.pkey is provided because we don't allow this when we initialise
     * the ctx.
     }
    if (ctx.pkey <> nil)  and  (not ossl_assert(not evp_pkey_is_provided(ctx.pkey ))) then
        goto _not_accessible;
    case ctx.operation of
        EVP_PKEY_OP_PARAMGEN:
            ret := ctx.pmeth.paramgen(ctx, ppkey^);
            //break;
        EVP_PKEY_OP_KEYGEN:
            ret := ctx.pmeth.keygen(ctx, ppkey^);
            //break;
        else
            goto _not_supported;
    end;
{$ENDIF}

 _end:
    if ret <= 0 then begin
        if allocated_pkey <> nil then
            ppkey^ := nil;
        EVP_PKEY_free(allocated_pkey);
    end;
    Exit(ret);

 _not_supported:
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    ret := -2;
    goto _end;

 _not_initialized:
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED);
    ret := -1;
    goto _end;

{$IFNDEF FIPS_MODULE}
 _not_accessible:
    ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_DOMAIN_PARAMETERS);
    ret := -1;
    goto _end;
{$ENDIF}
end;

function gen_init( ctx : PEVP_PKEY_CTX; operation : integer):integer;
var
  ret : integer;
  label _not_supported, _legacy, _end;
begin
    ret := 0;
    if ctx = nil then
       goto _not_supported;
    evp_pkey_ctx_free_old_ops(ctx);
    ctx.operation := operation;
    if (ctx.keymgmt = nil)  or  (not Assigned(ctx.keymgmt.gen_init)) then
       goto _legacy;
    case operation of
        EVP_PKEY_OP_PARAMGEN:
            ctx.op.keymgmt.genctx := evp_keymgmt_gen_init(ctx.keymgmt, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, nil);
            //break;
        EVP_PKEY_OP_KEYGEN:
            ctx.op.keymgmt.genctx := evp_keymgmt_gen_init(ctx.keymgmt, OSSL_KEYMGMT_SELECT_KEYPAIR, nil);
            //break;
    end;
    if ctx.op.keymgmt.genctx = nil then
       ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR)
    else
       ret := 1;
    goto _end;

 _legacy:
{$IFDEF FIPS_MODULE}
    goto _not_supported;
{$ELSE}
    if (ctx.pmeth = nil)
         or ( (operation = EVP_PKEY_OP_PARAMGEN) and  (Assigned(ctx.pmeth.paramgen)) )
         or ( (operation = EVP_PKEY_OP_KEYGEN)   and  (Assigned(ctx.pmeth.keygen)) ) then
        goto _not_supported;
    ret := 1;
    case operation of
        EVP_PKEY_OP_PARAMGEN:
        begin
            if Assigned(ctx.pmeth.paramgen_init) then
               ret := ctx.pmeth.paramgen_init(ctx);
        end;
        EVP_PKEY_OP_KEYGEN:
        begin
            if Assigned(ctx.pmeth.keygen_init) then
               ret := ctx.pmeth.keygen_init(ctx);
        end;
    end;
{$ENDIF}
 _end:
    if (ret <= 0)  and  (ctx <> nil) then
    begin
        evp_pkey_ctx_free_old_ops(ctx);
        ctx.operation := EVP_PKEY_OP_UNDEFINED;
    end;
    Exit(ret);
 _not_supported:
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    ret := -2;
    goto _end;
end;




function EVP_PKEY_keygen_init( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := gen_init(ctx, EVP_PKEY_OP_KEYGEN);
end;





function trans_cb( a, b : integer; gcb : PBN_GENCB):integer;
var
  ctx : PEVP_PKEY_CTX;
begin
{$POINTERMATH ON}
    ctx := BN_GENCB_get_arg(gcb);
    ctx.keygen_info[0] := a;
    ctx.keygen_info[1] := b;
    Result := ctx.pkey_gencb(ctx);
{$POINTERMATH OFF}
end;

procedure evp_pkey_set_cb_translate( cb : PBN_GENCB; ctx : PEVP_PKEY_CTX);
begin
    BN_GENCB_set(cb, trans_cb, ctx);
end;


end.
