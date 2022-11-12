unit openssl3.crypto.ec.ecdsa_ossl;

interface
uses OpenSSL.Api;

function ossl_ecdsa_simple_sign_setup( eckey : PEC_KEY; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM):integer;
function ossl_ecdsa_simple_verify_sig(const dgst : PByte; dgst_len : integer;const sig : PECDSA_SIG; eckey : PEC_KEY):integer;
function ossl_ecdsa_sign(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32;const kinv, r : PBIGNUM; eckey : PEC_KEY):integer;

 function ecdsa_sign_setup(eckey : PEC_KEY; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM;const dgst : PByte; dlen : integer):integer;
 function ossl_ecdsa_simple_sign_sig(const dgst : PByte; dgst_len : integer;const in_kinv, in_r : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
 function ECDSA_do_sign_ex(const dgst : PByte; dlen : integer;const kinv, rp : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
 function ossl_ecdsa_sign_setup( eckey : PEC_KEY; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM):integer;
 function ossl_ecdsa_sign_sig(const dgst : PByte; dgst_len : integer;const in_kinv, in_r : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
 function ossl_ecdsa_verify(_type : integer;const dgst : PByte; dgst_len : integer;const sigbuf : PByte; sig_len : integer; eckey : PEC_KEY):integer;
 function ossl_ecdsa_verify_sig(const dgst : PByte; dgst_len : integer;const sig : PECDSA_SIG; eckey : PEC_KEY):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_mul,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.mem,
     openssl3.crypto.ec.ecdsa_vrf,
     openssl3.crypto.bn.bn_mont, openssl3.crypto.ec.ecdsa_sign,
     openssl3.crypto.ec.ec_asn1, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_rand, openssl3.crypto.bn.bn_mod;





function ossl_ecdsa_verify_sig(const dgst : PByte; dgst_len : integer;const sig : PECDSA_SIG; eckey : PEC_KEY):integer;
begin
    if not Assigned(eckey.group.meth.ecdsa_verify_sig) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA);
        Exit(0);
    end;
    Result := eckey.group.meth.ecdsa_verify_sig(dgst, dgst_len, sig, eckey);
end;

function ossl_ecdsa_verify(_type : integer;const dgst : PByte; dgst_len : integer;const sigbuf : PByte; sig_len : integer; eckey : PEC_KEY):integer;
var
  s : PECDSA_SIG;
  p, der : PByte;
  derlen, ret : integer;
  label _err;
begin
    p := sigbuf;
    der := nil;
    derlen := -1;
    ret := -1;
    s := ECDSA_SIG_new();
    if s = nil then Exit(ret);
    if d2i_ECDSA_SIG(@s, @p, sig_len) = nil  then
        goto _err ;
    { Ensure signature uses DER and doesn't have trailing garbage }
    derlen := i2d_ECDSA_SIG(s, @der);
    if (derlen <> sig_len)  or  (memcmp(sigbuf, der, derlen) <> 0) then
        goto _err ;
    ret := ECDSA_do_verify(dgst, dgst_len, s, eckey);
 _err:
    OPENSSL_free(Pointer(der));
    ECDSA_SIG_free(s);
    Result := ret;
end;




function ossl_ecdsa_sign_sig(const dgst : PByte; dgst_len : integer;const in_kinv, in_r : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
begin
    if not Assigned(eckey.group.meth.ecdsa_sign_sig) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA);
        Exit(nil);
    end;
    Exit(eckey.group.meth.ecdsa_sign_sig(dgst, dgst_len,
                                              in_kinv, in_r, eckey));
end;





function ossl_ecdsa_sign_setup( eckey : PEC_KEY; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM):integer;
begin
    if not Assigned(eckey.group.meth.ecdsa_sign_setup) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA);
        Exit(0);
    end;
    Result := eckey.group.meth.ecdsa_sign_setup(eckey, ctx_in, kinvp, rp);
end;




function ECDSA_do_sign_ex(const dgst : PByte; dlen : integer;const kinv, rp : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
begin
    if Assigned(eckey.meth.sign_sig) then
       Exit(eckey.meth.sign_sig(dgst, dlen, kinv, rp, eckey));
    ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
    Result := nil;
end;


function ossl_ecdsa_sign(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32;const kinv, r : PBIGNUM; eckey : PEC_KEY):integer;
var
  s : PECDSA_SIG;
begin
    s := ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if s = nil then
    begin
        siglen^ := 0;
        Exit(0);
    end;
    siglen^ := i2d_ECDSA_SIG(s, @sig);
    ECDSA_SIG_free(s);
    Result := 1;
end;





function ossl_ecdsa_simple_verify_sig(const dgst : PByte; dgst_len : integer;const sig : PECDSA_SIG; eckey : PEC_KEY):integer;
var
  ret, i : integer;
  ctx : PBN_CTX;
  order, u1, u2, m, X : PBIGNUM;
  point : PEC_POINT;
  group : PEC_GROUP;
  pub_key : PEC_POINT;
  label _err;
begin
    ret := -1;
    point := nil;
    { check input values }
    group := EC_KEY_get0_group(eckey);
    pub_key := EC_KEY_get0_public_key(eckey);
    if (eckey = nil)  or  (group = nil)  or
       (pub_key = nil)  or  (sig = nil) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        Exit(-1);
    end;
    if 0>= EC_KEY_can_sign(eckey ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        Exit(-1);
    end;
    ctx := BN_CTX_new_ex(eckey.libctx);
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    BN_CTX_start(ctx);
    u1 := BN_CTX_get(ctx);
    u2 := BN_CTX_get(ctx);
    m := BN_CTX_get(ctx);
    X := BN_CTX_get(ctx);
    if X = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    order := EC_GROUP_get0_order(group);
    if order = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    if (BN_is_zero(sig.r))  or  (BN_is_negative(sig.r)>0)  or
        (BN_ucmp(sig.r, order) >= 0)  or  (BN_is_zero(sig.s))  or
        (BN_is_negative(sig.s)>0)  or  (BN_ucmp(sig.s, order) >= 0)  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BAD_SIGNATURE);
        ret := 0;                { signature is invalid }
        goto _err ;
    end;
    { calculate tmp1 = inv(S) mod order }
    if 0>= ossl_ec_group_do_inverse_ord(group, u2, sig.s, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { digest . m }
    i := BN_num_bits(order);
    {
     * Need to truncate digest if it is too long: first truncate whole bytes.
     }
    if 8 * dgst_len > i then
       dgst_len := (i + 7) div 8;
    if nil = BN_bin2bn(dgst, dgst_len, m) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { If still too long truncate remaining bits with a shift }
    if (8 * dgst_len > i) and  (0>= BN_rshift(m, m, 8 - (i and $7)) )then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { u1 = m * tmp mod order }
    if 0>= BN_mod_mul(u1, m, u2, order, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { u2 = r * w mod q }
    if 0>= BN_mod_mul(u2, sig.r, u2, order, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    point := EC_POINT_new(group );
    if point = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if 0>= EC_POINT_mul(group, point, u1, pub_key, u2, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    if 0>= EC_POINT_get_affine_coordinates(group, point, X, nil, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    if 0>= BN_nnmod(u1, X, order, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    {  if the signature is correct u1 is equal to sig.r }
    ret := int(BN_ucmp(u1, sig.r) = 0);
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    Result := ret;
end;


function ossl_ecdsa_simple_sign_sig(const dgst : PByte; dgst_len : integer;const in_kinv, in_r : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
var
  ok, i    : integer;
  kinv,
  s,
  m,
  order,
  ckinv    : PBIGNUM;
  ctx      : PBN_CTX;
  group    : PEC_GROUP;
  ret      : PECDSA_SIG;
  priv_key : PBIGNUM;
  label _err;
begin
    ok := 0;
    kinv := nil;
    m := nil;
    ctx := nil;
    group := EC_KEY_get0_group(eckey);
    priv_key := EC_KEY_get0_private_key(eckey);
    if group = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if priv_key = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        Exit(nil);
    end;
    if 0>= EC_KEY_can_sign(eckey) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        Exit(nil);
    end;
    ret := ECDSA_SIG_new();
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.r := BN_new();
    ret.s := BN_new();
    if (ret.r = nil)  or  (ret.s = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    s := ret.s;
    ctx := BN_CTX_new_ex(eckey.libctx);
    m := BN_new();
    if (ctx =  nil) or  (m = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    order := EC_GROUP_get0_order(group);
    i := BN_num_bits(order);
    {
     * Need to truncate digest if it is too long: first truncate whole bytes.
     }
    if 8 * dgst_len > i then
       dgst_len := (i + 7) div 8;
    if nil = BN_bin2bn(dgst, dgst_len, m) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { If still too long, truncate remaining bits with a shift }
    if (8 * dgst_len > i )  and  (0>= BN_rshift(m, m, 8 - (i and $7)) ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    while Boolean(1) do
    begin
        if (in_kinv = nil)  or  (in_r = nil) then
        begin
            if 0>= ecdsa_sign_setup(eckey, ctx, @kinv, @ret.r, dgst, dgst_len) then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_ECDSA_LIB);
                goto _err ;
            end;
            ckinv := kinv;
        end
        else
        begin
            ckinv := in_kinv;
            if BN_copy(ret.r, in_r) = nil  then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
        end;
        {
         * With only one multiplicant being in Montgomery domain
         * multiplication yields real result without post-conversion.
         * Also note that all operations but last are performed with
         * zero-padded vectors. Last operation, BN_mod_mul_montgomery
         * below, returns user-visible value with removed zero padding.
         }
        if (0>= bn_to_mont_fixed_top(s, ret.r, group.mont_data, ctx))  or
           (0>= bn_mul_mont_fixed_top(s, s, priv_key, group.mont_data, ctx))  then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto _err ;
        end;
        if 0>= bn_mod_add_fixed_top(s, s, m, order) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto _err ;
        end;
        {
         * |s| can still be larger than modulus, because |m| can be. In
         * such case we count on Montgomery reduction to tie it up.
         }
        if (0>= bn_to_mont_fixed_top(s, s, group.mont_data, ctx)) or
           (0>= BN_mod_mul_montgomery(s, s, ckinv, group.mont_data, ctx))  then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto _err ;
        end;
        if BN_is_zero(s ) then
        begin
            {
             * if kinv and r have been supplied by the caller, don't
             * generate new kinv and r values
             }
            if (in_kinv <> nil)  and  (in_r <> nil) then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_NEED_NEW_SETUP_VALUES);
                goto _err ;
            end;
        end
        else
        begin
            { s <> 0 => we have a valid signature }
            break;
        end;
    end;

    ok := 1;
 _err:
    if 0>= ok then
    begin
        ECDSA_SIG_free(ret);
        ret := nil;
    end;
    BN_CTX_free(ctx);
    BN_clear_free(m);
    BN_clear_free(kinv);
    Result := ret;
end;

function ecdsa_sign_setup(eckey : PEC_KEY; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM;const dgst : PByte; dlen : integer):integer;
var
  ctx        : PBN_CTX;
  k,
  r,
  X,
  order      : PBIGNUM;
  tmp_point  : PEC_POINT;
  group      : PEC_GROUP;
  ret,
  order_bits : integer;
  priv_key   : PBIGNUM;
  label _err;
begin
    ctx := nil;
    k := nil;
    r := nil;
    X := nil;
    tmp_point := nil;
    ret := 0;
    group := EC_KEY_get0_group(eckey);
    if (eckey = nil)  or  (group = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    priv_key := EC_KEY_get0_private_key(eckey);
    if priv_key = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        Exit(0);
    end;
    if 0>= EC_KEY_can_sign(eckey) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        Exit(0);
    end;
    ctx := ctx_in;
    if ctx = nil then
    begin
        ctx := BN_CTX_new_ex(eckey.libctx);
        if (ctx = nil) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    k := BN_secure_new();        { this value is later returned in *kinvp }
    r := BN_new();               { this value is later returned in *rp }
    X := BN_new();
    if (k = nil)  or  (r = nil)  or  (X = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    tmp_point := EC_POINT_new(group);
    if tmp_point = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    order := EC_GROUP_get0_order(group);
    { Preallocate space }
    order_bits := BN_num_bits(order);
    if (0>= BN_set_bit(k, order_bits))  or  (0>= BN_set_bit(r, order_bits))
         or  (0>= BN_set_bit(X, order_bits)) then
        goto _err ;
    while (BN_is_zero(r)) do
    begin
        { get random k }
        while (BN_is_zero(k)) do
        begin
            if dgst <> nil then
            begin
                if (0>= BN_generate_dsa_nonce(k, order, priv_key,
                                           dgst, dlen, ctx)) then
                begin
                    ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                    goto _err ;
                end;
            end
            else
            begin
                if 0>= BN_priv_rand_range_ex(k, order, 0, ctx ) then
                begin
                    ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                    goto _err ;
                end;
            end;
        end;

        { compute r the x-coordinate of generator * k }
        if 0>= EC_POINT_mul(group, tmp_point, k, nil, nil, ctx) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
        if 0>= EC_POINT_get_affine_coordinates(group, tmp_point, X, nil, ctx )then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
        if 0>= BN_nnmod(r, X, order, ctx) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto _err ;
        end;
    end;

    { compute the inverse of k }
    if 0>= ossl_ec_group_do_inverse_ord(group, k, k, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { clear old values if necessary }
    BN_clear_free( rp^);
    BN_clear_free( kinvp^);
    { save the pre-computed values  }
    rp^ := r;
    kinvp^ := k;
    ret := 1;
 _err:
    if 0>= ret then
    begin
        BN_clear_free(k);
        BN_clear_free(r);
    end;
    if ctx <> ctx_in then BN_CTX_free(ctx);
    EC_POINT_free(tmp_point);
    BN_clear_free(X);
    Result := ret;
end;


function ossl_ecdsa_simple_sign_setup( eckey : PEC_KEY; ctx_in : PBN_CTX; kinvp, rp : PPBIGNUM):integer;
begin
    Result := ecdsa_sign_setup(eckey, ctx_in, kinvp, rp, nil, 0);
end;


end.
