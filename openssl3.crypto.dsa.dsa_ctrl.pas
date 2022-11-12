unit openssl3.crypto.dsa.dsa_ctrl;

interface
uses OpenSSL.Api;

function EVP_PKEY_CTX_set_dsa_paramgen_bits( ctx : PEVP_PKEY_CTX; nbits : integer):integer;
function EVP_PKEY_CTX_set_dsa_paramgen_q_bits( ctx : PEVP_PKEY_CTX; qbits : integer):integer;
function EVP_PKEY_CTX_set_dsa_paramgen_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;

function dsa_paramgen_check( ctx : PEVP_PKEY_CTX):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.evp, openssl3.crypto.params,
     openssl3.crypto.evp.pmeth_lib;






function EVP_PKEY_CTX_set_dsa_paramgen_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
begin
    Exit(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                             EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, Pointer(md)));
end;




function EVP_PKEY_CTX_set_dsa_paramgen_q_bits( ctx : PEVP_PKEY_CTX; qbits : integer):integer;
var
  ret : integer;
  p   : POSSL_PARAM;
  params : array[0..1] of TOSSL_PARAM;

  bits2 : size_t;
begin
    p := @params;
    bits2 := qbits;
    ret := dsa_paramgen_check(ctx);
    if ret  <= 0 then
        Exit(ret);
    PostInc(p)^ :=  OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, @bits2);
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    Result := EVP_PKEY_CTX_set_params(ctx, @params);
end;

function dsa_paramgen_check( ctx : PEVP_PKEY_CTX):integer;
begin
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_GEN_OP(ctx)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    { If key type not DSA return error }
    if (ctx.pmeth <> nil)  and  (ctx.pmeth.pkey_id <> EVP_PKEY_DSA) then
       Exit(-1);
    Result := 1;
end;


function EVP_PKEY_CTX_set_dsa_paramgen_bits( ctx : PEVP_PKEY_CTX; nbits : integer):integer;
var
  ret : integer;
  params : array[0..1] of TOSSL_PARAM;
  p : POSSL_PARAM;
  bits : size_t;
begin
    p := @params;
    bits := nbits;
    ret := dsa_paramgen_check(ctx);
    if ret  <= 0 then
        Exit(ret);
    PostInc(p)^ :=  OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, @bits);
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    Result := EVP_PKEY_CTX_set_params(ctx, @params);
end;

end.
