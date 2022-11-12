unit openssl3.crypto.dh.dh_ctrl;

interface
uses OpenSSL.Api;

function EVP_PKEY_CTX_set_dh_paramgen_prime_len( ctx : PEVP_PKEY_CTX; pbits : integer):integer;
 function EVP_PKEY_CTX_set_dh_paramgen_generator( ctx : PEVP_PKEY_CTX; gen : integer):integer;
function EVP_PKEY_CTX_set_dh_paramgen_subprime_len( ctx : PEVP_PKEY_CTX; qbits : integer):integer;
 function EVP_PKEY_CTX_set_dh_paramgen_type( ctx : PEVP_PKEY_CTX; typ : integer):integer;
function EVP_PKEY_CTX_set_dh_pad( ctx : PEVP_PKEY_CTX; pad : integer):integer;

function dh_paramgen_check( ctx : PEVP_PKEY_CTX):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.evp, openssl3.crypto.params,
     openssl3.crypto.evp.pmeth_lib;


function EVP_PKEY_CTX_set_dh_pad( ctx : PEVP_PKEY_CTX; pad : integer):integer;
var
    dh_pad_params : array[0..1] of TOSSL_PARAM;
    upad          : uint32;
begin
    upad := pad;
    { We use EVP_PKEY_CTX_ctrl return values }
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        Exit(-2);
    end;
    dh_pad_params[0] := OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, @upad);
    dh_pad_params[1] := OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @dh_pad_params);
end;



function EVP_PKEY_CTX_set_dh_paramgen_type( ctx : PEVP_PKEY_CTX; typ : integer):integer;
begin
    Exit(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                             EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, nil));
end;

function EVP_PKEY_CTX_set_dh_paramgen_subprime_len( ctx : PEVP_PKEY_CTX; qbits : integer):integer;
var
  ret : integer;
  params : array[0..1] of TOSSL_PARAM;
  p : POSSL_PARAM;
  bits2 : size_t;
begin
    p := @params;
    bits2 := qbits;
    ret := dh_paramgen_check(ctx);
    if ret  <= 0 then
        Exit(ret);
    PostInc(p)^ :=  OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, @bits2);
    p^ := OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @params);
end;



function EVP_PKEY_CTX_set_dh_paramgen_generator( ctx : PEVP_PKEY_CTX; gen : integer):integer;
var
  ret : integer;
  p   : POSSL_PARAM;
  params : array[0..1] of TOSSL_PARAM;
begin
    p := @params;
    ret := dh_paramgen_check(ctx);
    if ret  <= 0 then
        Exit(ret);
    PostInc(p)^ :=  OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_DH_GENERATOR, @gen);
    p^ := OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @params);
end;


function dh_paramgen_check( ctx : PEVP_PKEY_CTX):integer;
begin
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_GEN_OP(ctx)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    { If key type not DH return error }
    if (evp_pkey_ctx_is_legacy(ctx))  and  (ctx.pmeth.pkey_id <> EVP_PKEY_DH)
         and  (ctx.pmeth.pkey_id <> EVP_PKEY_DHX) then
        Exit(-1);
    Result := 1;
end;




function EVP_PKEY_CTX_set_dh_paramgen_prime_len( ctx : PEVP_PKEY_CTX; pbits : integer):integer;
var
  ret : integer;
  params : array[0..1] of TOSSL_PARAM;
  p : POSSL_PARAM;
  bits : size_t;
begin
    p := @params;
    bits := pbits;
    ret := dh_paramgen_check(ctx);
    if ret <= 0 then
        Exit(ret);
    PostInc(p)^ :=  OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, @bits);
    p^ := OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @params);
end;



end.
