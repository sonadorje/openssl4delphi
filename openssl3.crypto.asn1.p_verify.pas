unit openssl3.crypto.asn1.p_verify;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function EVP_VerifyFinal(ctx : PEVP_MD_CTX;const sigbuf : PByte; siglen : uint32; pkey : PEVP_PKEY):integer;
function EVP_VerifyFinal_ex(ctx : PEVP_MD_CTX;const sigbuf : PByte; siglen : uint32; pkey : PEVP_PKEY; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;

implementation
uses openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.digest,

     OpenSSL3.Err, openssl3.crypto.evp.pmeth_lib, openssl3.crypto.evp.signature;

function EVP_VerifyFinal_ex(ctx : PEVP_MD_CTX;const sigbuf : PByte; siglen : uint32; pkey : PEVP_PKEY; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  m : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  m_len : uint32;
  i : integer;
  pkctx : PEVP_PKEY_CTX;
  rv : integer;
  tmp_ctx : PEVP_MD_CTX;
  label _err;
begin
    m_len := 0;
    i := 0;
    pkctx := nil;
    if EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_FINALISE) > 0 then
    begin
        if 0>=EVP_DigestFinal_ex(ctx, @m, @m_len) then
            goto _err;
    end
    else
    begin
        rv := 0;
        tmp_ctx := EVP_MD_CTX_new;
        if tmp_ctx = nil then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        rv := EVP_MD_CTX_copy_ex(tmp_ctx, ctx);
        if rv > 0 then
           rv := EVP_DigestFinal_ex(tmp_ctx, @m, @m_len);
        EVP_MD_CTX_free(tmp_ctx);
        if 0>=rv then Exit(0);
    end;
    i := -1;
    pkctx := EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq);
    if pkctx = nil then goto _err;
    if EVP_PKEY_verify_init(pkctx) <= 0  then
        goto _err;
    if EVP_PKEY_CTX_set_signature_md(pkctx, EVP_MD_CTX_get0_md(ctx))  <= 0  then
        goto _err;
    i := EVP_PKEY_verify(pkctx, sigbuf, siglen, @m, m_len);
 _err:
    EVP_PKEY_CTX_free(pkctx);
    Result := i;
end;

function EVP_VerifyFinal(ctx : PEVP_MD_CTX;const sigbuf : PByte; siglen : uint32; pkey : PEVP_PKEY):integer;
begin
    Result := EVP_VerifyFinal_ex(ctx, sigbuf, siglen, pkey, nil, nil);
end;

end.
