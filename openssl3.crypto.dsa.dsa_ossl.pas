unit openssl3.crypto.dsa.dsa_ossl;

interface
uses OpenSSL.Api;

function ossl_dsa_do_sign_int(const dgst : PByte; dlen : integer; dsa : PDSA):PDSA_SIG;
function dsa_sign_setup(dsa : PDSA; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM;const dgst : PByte; dlen : integer):integer;
function dsa_mod_inverse_fermat(const k, q : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
function DSA_get_default_method:PDSA_METHOD;
function dsa_do_sign(const dgst : PByte; dlen : integer; dsa : PDSA):PDSA_SIG;
 function dsa_sign_setup_no_digest( dsa : PDSA; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM):integer;
 function dsa_init( dsa : PDSA):integer;
 function dsa_finish( dsa : PDSA):integer;
 function DSA_OpenSSL:PDSA_METHOD;


implementation
uses openssl3.crypto.bn.bn_lib,openssl3.crypto.bn.bn_ctx, OpenSSL3.Err,
     openssl3.crypto.bn.bn_intern, openssl3.crypto.bn.bn_rand,
     openssl3.crypto.bn.bn_exp,  openssl3.crypto.dsa.dsa_sign,
     openssl3.crypto.bn.bn_mod, openssl3.crypto.bn.bn_gcd,
     openssl3.crypto.ffc.ffc_params,
     openssl3.crypto.bn.bn_mont, openssl3.crypto.bn.bn_add;

var
  openssl_dsa_meth: TDSA_METHOD  = (
    name: 'OpenSSL DSA method';
    dsa_do_sign: dsa_do_sign;
    dsa_sign_setup: dsa_sign_setup_no_digest;
    dsa_do_verify: dsa_do_verify;
    dsa_mod_exp: nil;                       (* dsa_mod_exp; *)
    bn_mod_exp: nil;                       (* dsa_bn_mod_exp; *)
    init: dsa_init;
    finish: dsa_finish;
    flags: DSA_FLAG_FIPS_METHOD;
    app_data: nil;
    dsa_paramgen: nil;
    dsa_keygen: nil
);
const
   default_DSA_method: PDSA_METHOD  = @openssl_dsa_meth;






function DSA_OpenSSL:PDSA_METHOD;
begin
    Result := @openssl_dsa_meth;
end;




function dsa_finish( dsa : PDSA):integer;
begin
    BN_MONT_CTX_free(dsa.method_mont_p);
    Result := 1;
end;



function dsa_init( dsa : PDSA):integer;
begin
    dsa.flags  := dsa.flags  or DSA_FLAG_CACHE_MONT_P;
    ossl_ffc_params_init(@dsa.params);
    Inc(dsa.dirty_cnt);
    Result := 1;
end;



function dsa_sign_setup_no_digest( dsa : PDSA; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM):integer;
begin
    Result := dsa_sign_setup(dsa, ctx_in, kinvp, rp, nil, 0);
end;




function dsa_do_sign(const dgst : PByte; dlen : integer; dsa : PDSA):PDSA_SIG;
begin
    Result := ossl_dsa_do_sign_int(dgst, dlen, dsa);
end;


function DSA_get_default_method:PDSA_METHOD;
begin
    Result := default_DSA_method;
end;



function dsa_mod_inverse_fermat(const k, q : PBIGNUM; ctx : PBN_CTX):PBIGNUM;
var
  res, r, e : PBIGNUM;
begin
    res := nil;
    r := BN_new();
    if r = nil then
        Exit(nil);
    BN_CTX_start(ctx);
    e := BN_CTX_get(ctx);
    if (e  <> nil)
             and  (BN_set_word(r, 2)>0)
             and  (BN_sub(e, q, r)>0)
             and  (BN_mod_exp_mont(r, k, e, q, ctx, nil)>0) then
        res := r
    else
        BN_free(r);
    BN_CTX_end(ctx);
    Result := res;
end;




function dsa_sign_setup(dsa : PDSA; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM;const dgst : PByte; dlen : integer):integer;
var
  ctx : PBN_CTX;
  k, kinv, l, r : PBIGNUM;
  ret, q_bits, q_words : integer;
  label _err;
begin
    ctx := nil;
    kinv := nil; r := rp^;
    ret := 0;
    if (nil = dsa.params.p)  or  (nil = dsa.params.q)  or  (nil = dsa.params.g) then
    begin
        ERR_raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS);
        Exit(0);
    end;
    { Reject obviously invalid parameters }
    if (BN_is_zero(dsa.params.p))  or  (BN_is_zero(dsa.params.q))
         or  (BN_is_zero(dsa.params.g))  then
    begin
        ERR_raise(ERR_LIB_DSA, DSA_R_INVALID_PARAMETERS);
        Exit(0);
    end;
    if dsa.priv_key = nil then
    begin
        ERR_raise(ERR_LIB_DSA, DSA_R_MISSING_PRIVATE_KEY);
        Exit(0);
    end;
    k := BN_new();
    l := BN_new();
    if (k = nil)  or  (l = nil) then goto _err ;
    if ctx_in = nil then
    begin
        { if you don't pass in ctx_in you get a default libctx }
        ctx := BN_CTX_new_ex(nil);
        if (ctx) = nil then
            goto _err ;
    end
    else
        ctx := ctx_in;
    { Preallocate space }
    q_bits := BN_num_bits(dsa.params.q);
    q_words := bn_get_top(dsa.params.q);
    if (nil = bn_wexpand(k, q_words + 2 )) or  (nil = bn_wexpand(l, q_words + 2))then
        goto _err ;
    { Get random k }
    repeat
        if dgst <> nil then
        begin
            {
             * We calculate k from SHA512(private_key + H(message) + random).
             * This protects the private key from a weak PRNG.
             }
            if (0>= BN_generate_dsa_nonce(k, dsa.params.q, dsa.priv_key, dgst,
                                       dlen, ctx)) then
                goto _err ;
        end
        else
        if (0>= BN_priv_rand_range_ex(k, dsa.params.q, 0, ctx)) then
            goto _err ;
    until not (BN_is_zero(k));
    BN_set_flags(k, BN_FLG_CONSTTIME);
    BN_set_flags(l, BN_FLG_CONSTTIME);
    if (dsa.flags and DSA_FLAG_CACHE_MONT_P)>0 then
    begin
        if nil =  BN_MONT_CTX_set_locked(@dsa.method_mont_p,
                                    dsa.lock, dsa.params.p, ctx) then
            goto _err ;
    end;
    { Compute r = (g^k mod p) mod q }
    {
     * We do not want timing information to leak the length of k, so we
     * compute G^k using an equivalent scalar of fixed bit-length.
     *
     * We unconditionally perform both of these additions to prevent a
     * small timing information leakage.  We then choose the sum that is
     * one bit longer than the modulus.
     *
     * There are some concerns about the efficacy of doing this.  More
     * specifically refer to the discussion starting with:
     *     https://github.com/openssl/openssl/pull/7486#discussion_r228323705
     * The fix is to rework BN so these gymnastics aren't required.
     }
    if (0>= BN_add(l, k, dsa.params.q ))  or  (0>= BN_add(k, l, dsa.params.q))then
        goto _err ;
    BN_consttime_swap(BN_is_bit_set(l, q_bits), k, l, q_words + 2);
    if Assigned(dsa.meth.bn_mod_exp ) then
    begin
            if (0>= dsa.meth.bn_mod_exp(dsa, r, dsa.params.g, k, dsa.params.p,
                                       ctx, dsa.method_mont_p)) then
                goto _err ;
    end
    else
    begin
            if 0>= BN_mod_exp_mont(r, dsa.params.g, k, dsa.params.p, ctx,
                                 dsa.method_mont_p ) then
                goto _err ;
    end;
    if 0>= BN_mod(r, r, dsa.params.q, ctx )then
        goto _err ;
    { Compute part of 's = inv(k) (m + xr) mod q' }
     kinv := dsa_mod_inverse_fermat(k, dsa.params.q, ctx);
    if kinv = nil then
        goto _err ;
    BN_clear_free( kinvp^);
    kinvp^ := kinv;
    kinv := nil;
    ret := 1;
 _err:
    if 0>= ret then ERR_raise(ERR_LIB_DSA, ERR_R_BN_LIB);
    if ctx <> ctx_in then BN_CTX_free(ctx);
    BN_clear_free(k);
    BN_clear_free(l);
    Result := ret;
end;

function ossl_dsa_do_sign_int(const dgst : PByte; dlen : integer; dsa : PDSA):PDSA_SIG;
var
  kinv, m, blind, blindm, tmp : PBIGNUM;

  ctx : PBN_CTX;

  reason : integer;

  ret : PDSA_SIG;

  rv : integer;
  label _err, _redo;
begin
    kinv := nil;
    ctx := nil;
    reason := ERR_R_BN_LIB;
    ret := nil;
    rv := 0;
    if (dsa.params.p = nil)
         or  (dsa.params.q = nil)
         or  (dsa.params.g = nil) then
    begin
        reason := DSA_R_MISSING_PARAMETERS;
        goto _err ;
    end;
    if dsa.priv_key = nil then
    begin
        reason := DSA_R_MISSING_PRIVATE_KEY;
        goto _err ;
    end;
    ret := DSA_SIG_new();
    if ret = nil then
       goto _err ;
    ret.r := BN_new();
    ret.s := BN_new();
    if (ret.r = nil)  or  (ret.s = nil) then
       goto _err ;
    ctx := BN_CTX_new_ex(dsa.libctx);
    if ctx = nil then
       goto _err ;
    m := BN_CTX_get(ctx);
    blind := BN_CTX_get(ctx);
    blindm := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    if tmp = nil then goto _err ;
 _redo:
    if 0>= dsa_sign_setup(dsa, ctx, @kinv, @ret.r, dgst, dlen) then
        goto _err ;
    if dlen > BN_num_bytes(dsa.params.q ) then
        {
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa.q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         }
        dlen := BN_num_bytes(dsa.params.q);
    if BN_bin2bn(dgst, dlen, m ) = nil then
        goto _err ;
    {
     * The normal signature calculation is:
     *
     *   s := k^-1 * (m + r * priv_key) mod q
     *
     * We will blind this to protect against side channel attacks
     *
     *   s := blind^-1 * k^-1 * (blind * m + blind * r * priv_key) mod q
     }
    { Generate a blinding value }
    repeat
        if 0>= BN_priv_rand_ex(blind, BN_num_bits(dsa.params.q) - 1,
                             BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx) then
            goto _err ;
    until not  (BN_is_zero(blind));
    BN_set_flags(blind, BN_FLG_CONSTTIME);
    BN_set_flags(blindm, BN_FLG_CONSTTIME);
    BN_set_flags(tmp, BN_FLG_CONSTTIME);
    { tmp := blind * priv_key * r mod q }
    if 0>= BN_mod_mul(tmp, blind, dsa.priv_key, dsa.params.q, ctx ) then
        goto _err ;
    if 0>= BN_mod_mul(tmp, tmp, ret.r, dsa.params.q, ctx ) then
        goto _err ;
    { blindm := blind * m mod q }
    if 0>= BN_mod_mul(blindm, blind, m, dsa.params.q, ctx ) then
        goto _err ;
    { s : = (blind * priv_key * r) + (blind * m) mod q }
    if 0>= BN_mod_add_quick(ret.s, tmp, blindm, dsa.params.q ) then
        goto _err ;
    { s := s * k^-1 mod q }
    if 0>= BN_mod_mul(ret.s, ret.s, kinv, dsa.params.q, ctx ) then
        goto _err ;
    { s:= s * blind^-1 mod q }
    if BN_mod_inverse(blind, blind, dsa.params.q, ctx)  = nil then
        goto _err ;
    if 0>= BN_mod_mul(ret.s, ret.s, blind, dsa.params.q, ctx ) then
        goto _err ;
    {
     * Redo if r or s is zero as required by FIPS 186-3: this is very
     * unlikely.
     }
    if (BN_is_zero(ret.r))  or  (BN_is_zero(ret.s))  then
        goto _redo ;
    rv := 1;
 _err:
    if rv = 0 then
    begin
        ERR_raise(ERR_LIB_DSA, reason);
        DSA_SIG_free(ret);
        ret := nil;
    end;
    BN_CTX_free(ctx);
    BN_clear_free(kinv);
    Result := ret;
end;


end.
