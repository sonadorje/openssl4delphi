unit openssl3.crypto.ec.ec_ctrl;

interface
uses OpenSSL.Api;

function EVP_PKEY_CTX_set_ec_paramgen_curve_nid( ctx : PEVP_PKEY_CTX; nid : integer):integer;
  function EVP_PKEY_CTX_set_ec_param_enc( ctx : PEVP_PKEY_CTX; param_enc : integer):integer;
 function EVP_PKEY_CTX_set_ecdh_kdf_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
 function EVP_PKEY_CTX_set_ecdh_cofactor_mode( ctx : PEVP_PKEY_CTX; cofactor_mode : integer):integer;
function evp_pkey_ctx_getset_ecdh_param_checks(const ctx : PEVP_PKEY_CTX):integer;


implementation
uses openssl3.crypto.evp.pmeth_lib, openssl3.crypto.evp,
     OpenSSL3.Err, openssl3.crypto.params;





function evp_pkey_ctx_getset_ecdh_param_checks(const ctx : PEVP_PKEY_CTX):integer;
begin
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_DERIVE_OP(ctx )) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    { If key type not EC return error }
    if (evp_pkey_ctx_is_legacy(ctx))  and  (ctx.pmeth <> nil)  and
       (ctx.pmeth.pkey_id <> EVP_PKEY_EC)  then
        Exit(-1);
    Result := 1;
end;




function EVP_PKEY_CTX_set_ecdh_cofactor_mode( ctx : PEVP_PKEY_CTX; cofactor_mode : integer):integer;
var
  ret : integer;

  params : array[0..1] of TOSSL_PARAM;

  p : POSSL_PARAM;
begin
    p := @params;
    ret := evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if ret <> 1 then Exit(ret);
    {
     * Valid input values are:
     *  * 0 for disable
     *  * 1 for enable
     *  * -1 for reset to default for associated priv key
     }
    if (cofactor_mode < -1)  or  (cofactor_mode > 1) then
    begin
        { Uses the same return value of pkey_ec_ctrl() }
        Exit(-2);
    end;
    PostInc(p)^ :=  OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
                                    @cofactor_mode);
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    ret := evp_pkey_ctx_set_params_strict(ctx, @params);
    if ret = -2 then
       ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
    Result := ret;
end;


function EVP_PKEY_CTX_set_ecdh_kdf_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
begin
    Exit(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE,
                             EVP_PKEY_CTRL_EC_KDF_MD, 0, Pointer(md)));
end;

function EVP_PKEY_CTX_set_ec_paramgen_curve_nid( ctx : PEVP_PKEY_CTX; nid : integer):integer;
begin
    Exit(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_OP_TYPE_GEN,
                             EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
                             nid, nil));
end;


function EVP_PKEY_CTX_set_ec_param_enc( ctx : PEVP_PKEY_CTX; param_enc : integer):integer;
begin
    Exit(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_OP_TYPE_GEN,
                             EVP_PKEY_CTRL_EC_PARAM_ENC, param_enc, nil));
end;


end.
