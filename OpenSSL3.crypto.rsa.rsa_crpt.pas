unit OpenSSL3.crypto.rsa.rsa_crpt;

interface
 uses OpenSSL.Api;

  function _RSA_bits(const r : PRSA):integer;
  function RSA_size(const r : PRSA):integer;
  function RSA_public_encrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
  function RSA_private_encrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
  function RSA_private_decrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
  function RSA_public_decrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
  function RSA_flags(const r : PRSA):integer;
  procedure RSA_blinding_off( rsa : PRSA);
  function RSA_blinding_on( rsa : PRSA; ctx : PBN_CTX):integer;
  function rsa_get_public_exp(const d, p, q : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
  function RSA_setup_blinding( rsa : PRSA; in_ctx : PBN_CTX):PBN_BLINDING;

implementation
uses openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_blind,
      openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_add,
      openssl3.crypto.bn.bn_mul, openssl3.crypto.bn.bn_gcd,
      OpenSSL3.Err;

function _RSA_bits(const r : PRSA):integer;
begin
    Result := BN_num_bits(r.n);
end;


function RSA_size(const r : PRSA):integer;
begin
    Result := BN_num_bytes(r.n);
end;


function RSA_public_encrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
begin
    Result := rsa.meth.rsa_pub_enc(flen, from, &to, rsa, padding);
end;


function RSA_private_encrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
begin
    Result := rsa.meth.rsa_priv_enc(flen, from, &to, rsa, padding);
end;


function RSA_private_decrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
begin
    Result := rsa.meth.rsa_priv_dec(flen, from, &to, rsa, padding);
end;


function RSA_public_decrypt(flen : integer;const from : PByte; &to : PByte; rsa : PRSA; padding : integer):integer;
begin
    Result := rsa.meth.rsa_pub_dec(flen, from, &to, rsa, padding);
end;


function RSA_flags(const r : PRSA):integer;
begin
    Result := get_result(r = nil , 0 , r.meth.flags);
end;


procedure RSA_blinding_off( rsa : PRSA);
begin
    BN_BLINDING_free(rsa.blinding);
    rsa.blinding := nil;
    rsa.flags := rsa.flags and (not RSA_FLAG_BLINDING);
    rsa.flags  := rsa.flags  or RSA_FLAG_NO_BLINDING;
end;


function RSA_blinding_on( rsa : PRSA; ctx : PBN_CTX):integer;
var
  ret : integer;
  label _err;
begin
    ret := 0;
    if rsa.blinding <> nil then
       RSA_blinding_off(rsa);
    rsa.blinding := RSA_setup_blinding(rsa, ctx);
    if rsa.blinding = nil then
       goto _err ;
    rsa.flags := rsa.flags  or RSA_FLAG_BLINDING;
    rsa.flags := rsa.flags and (not RSA_FLAG_NO_BLINDING);
    ret := 1;
 _err:
    Result := ret;
end;


function rsa_get_public_exp(const d, p, q : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
var
  ret, r0, r1, r2 : PBIGNUM;
  label _err;
begin
    ret := nil;
    if (d = nil)  or  (p = nil)  or  (q = nil) then
       Exit(nil);
    BN_CTX_start(ctx);
    r0 := BN_CTX_get(ctx);
    r1 := BN_CTX_get(ctx);
    r2 := BN_CTX_get(ctx);
    if r2 = nil then
       goto _err ;
    if 0>= BN_sub(r1, p, BN_value_one())  then
        goto _err ;
    if 0>= BN_sub(r2, q, BN_value_one()) then
        goto _err ;
    if 0>= BN_mul(r0, r1, r2, ctx)  then
        goto _err ;
    ret := BN_mod_inverse(nil, d, r0, ctx);
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;


function RSA_setup_blinding( rsa : PRSA; in_ctx : PBN_CTX): PBN_BLINDING;
var
  e : PBIGNUM;
  ctx : PBN_CTX;
  n : PBIGNUM;
  label _err;
begin
    result := nil;
    if in_ctx = nil then
    begin
       ctx := BN_CTX_new_ex(rsa.libctx);
        if ctx = nil then
            Exit(0);
    end
    else
    begin
        ctx := in_ctx;
    end;
    BN_CTX_start(ctx);
    e := BN_CTX_get(ctx);
    if e = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if rsa.e = nil then
    begin
        e := rsa_get_public_exp(rsa.d, rsa.p, rsa.q, ctx);
        if e = nil then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_NO_PUBLIC_EXPONENT);
            goto _err ;
        end;
    end
    else
    begin
        e := rsa.e;
    end;
    begin
        n := BN_new();
        if n = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        BN_with_flags(n, rsa.n, BN_FLG_CONSTTIME);
        result := BN_BLINDING_create_param(nil, e, n, ctx, rsa.meth.bn_mod_exp, rsa._method_mod_n);
        { We MUST free n before any further use of rsa.n }
        BN_free(n);
    end;
    if result = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto _err ;
    end;
    BN_BLINDING_set_current_thread(result);

 _err:
    BN_CTX_end(ctx);
    if ctx <> in_ctx then
       BN_CTX_free(ctx);
    if e <> rsa.e then
       BN_free(e);

end;

end.
