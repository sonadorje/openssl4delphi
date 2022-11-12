unit openssl3.crypto.evp.pmeth_check;

interface
uses OpenSSL.Api;

function try_provided_check( ctx : PEVP_PKEY_CTX; selection, checktype : integer):integer;
  function evp_pkey_public_check_combined( ctx : PEVP_PKEY_CTX; checktype : integer):integer;
  function EVP_PKEY_public_check( ctx : PEVP_PKEY_CTX):integer;
  function EVP_PKEY_public_check_quick( ctx : PEVP_PKEY_CTX):integer;
  function evp_pkey_param_check_combined( ctx : PEVP_PKEY_CTX; checktype : integer):integer;
  function EVP_PKEY_param_check( ctx : PEVP_PKEY_CTX):integer;
  function EVP_PKEY_param_check_quick( ctx : PEVP_PKEY_CTX):integer;
  function EVP_PKEY_private_check( ctx : PEVP_PKEY_CTX):integer;
  function EVP_PKEY_check( ctx : PEVP_PKEY_CTX):integer;
  function EVP_PKEY_pairwise_check( ctx : PEVP_PKEY_CTX):integer;

implementation
uses openssl3.crypto.evp, OpenSSL3.Err,             openssl3.crypto.evp.p_lib,
     openssl3.crypto.evp.keymgmt_meth;

function try_provided_check( ctx : PEVP_PKEY_CTX; selection, checktype : integer):integer;
var
  keymgmt : PEVP_KEYMGMT;
  keydata : Pointer;
begin
    if evp_pkey_ctx_is_legacy(ctx) then
        Exit(-1);
    keymgmt := ctx.keymgmt;
    keydata := evp_pkey_export_to_provider(ctx.pkey, ctx.libctx,
                                          @keymgmt, ctx.propquery);
    if keydata = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
    end;
    Result := evp_keymgmt_validate(keymgmt, keydata, selection, checktype);
end;


function evp_pkey_public_check_combined( ctx : PEVP_PKEY_CTX; checktype : integer):integer;
var
  pkey : PEVP_PKEY;
  ok : integer;
  label _not_supported;
begin
    pkey := ctx.pkey;
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        Exit(0);
    end;
    ok := try_provided_check(ctx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, checktype);
    if ok <> -1 then
        Exit(ok);
    if pkey.&type = EVP_PKEY_NONE then goto _not_supported;
{$IFNDEF FIPS_MODULE}
    { legacy }
    { call customized public key check function first }
    if Assigned(ctx.pmeth.public_check) then
       Exit(ctx.pmeth.public_check(pkey));
    { use default public key check function in ameth }
    if (pkey.ameth = nil)  or  (not Assigned(pkey.ameth.pkey_public_check)) then
       goto _not_supported;
    Exit(pkey.ameth.pkey_public_check(pkey));
{$ENDIF}
 _not_supported:
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    Result := -2;
end;


function EVP_PKEY_public_check( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_public_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_FULL_CHECK);
end;


function EVP_PKEY_public_check_quick( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_public_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK);
end;


function evp_pkey_param_check_combined( ctx : PEVP_PKEY_CTX; checktype : integer):integer;
var
  pkey : PEVP_PKEY;
  ok : integer;
  label _not_supported;
begin
    pkey := ctx.pkey;
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        Exit(0);
    end;
    ok := try_provided_check(ctx, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                                 checktype);
    if (ok <> -1) then
        Exit(ok);
    if pkey.&type = EVP_PKEY_NONE then
       goto _not_supported;
{$IFNDEF FIPS_MODULE}
    { legacy }
    { call customized param check function first }
    if Assigned(ctx.pmeth.param_check) then
       Exit(ctx.pmeth.param_check(pkey));
    { use default param check function in ameth }
    if (pkey.ameth = nil)  or  (not Assigned(pkey.ameth.pkey_param_check)) then
        goto _not_supported;
    Exit(pkey.ameth.pkey_param_check(pkey));
{$ENDIF}
 _not_supported:
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    Result := -2;
end;


function EVP_PKEY_param_check( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_param_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_FULL_CHECK);
end;


function EVP_PKEY_param_check_quick( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := evp_pkey_param_check_combined(ctx, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK);
end;


function EVP_PKEY_private_check( ctx : PEVP_PKEY_CTX):integer;
var
  pkey : PEVP_PKEY;

  ok : integer;
begin
    pkey := ctx.pkey;
    if pkey = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        Exit(0);
    end;
    ok := try_provided_check(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                 OSSL_KEYMGMT_VALIDATE_FULL_CHECK);
    if (ok <> -1) then
        Exit(ok);
    { not supported for legacy keys }
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    Result := -2;
end;


function EVP_PKEY_check( ctx : PEVP_PKEY_CTX):integer;
begin
    Result := EVP_PKEY_pairwise_check(ctx);
end;


function EVP_PKEY_pairwise_check( ctx : PEVP_PKEY_CTX):integer;
var
  pkey : PEVP_PKEY;
  ok : integer;
  label _not_supported;
begin
    pkey := ctx.pkey;
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        Exit(0);
    end;
    ok := try_provided_check(ctx, OSSL_KEYMGMT_SELECT_KEYPAIR,
                                 OSSL_KEYMGMT_VALIDATE_FULL_CHECK);
    if (ok <> -1) then
        Exit(ok);
    if pkey.&type = EVP_PKEY_NONE then
       goto _not_supported;
{$IFNDEF FIPS_MODULE}
    { legacy }
    { call customized check function first }
    if Assigned(ctx.pmeth.check) then
       Exit(ctx.pmeth.check(pkey));
    { use default check function in ameth }
    if (pkey.ameth = nil)  or  (not Assigned(pkey.ameth.pkey_check)) then
       goto _not_supported;
    Exit(pkey.ameth.pkey_check(pkey));
{$ENDIF}
 _not_supported:
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    Result := -2;
end;


end.
