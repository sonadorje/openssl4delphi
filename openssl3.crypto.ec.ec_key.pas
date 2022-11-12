unit openssl3.crypto.ec.ec_key;

interface
uses OpenSSL.Api, SysUtils;

function EC_KEY_decoded_from_explicit_params(const key : PEC_KEY):integer;
function ossl_ec_key_get0_propq(const key : PEC_KEY):PUTF8Char;
function ossl_ec_key_get_libctx(const key : PEC_KEY):POSSL_LIB_CTX;
function ossl_ec_key_public_check_quick(const eckey : PEC_KEY; ctx : PBN_CTX):integer;
function ec_key_public_range_check(ctx : PBN_CTX;const key : PEC_KEY):integer;
function ossl_ec_key_public_check(const eckey : PEC_KEY; ctx : PBN_CTX):integer;
function ossl_ec_key_private_check(const eckey : PEC_KEY):integer;
function ossl_ec_key_pairwise_check(const eckey : PEC_KEY; ctx : PBN_CTX):integer;
function EC_KEY_get0_public_key(const key : PEC_KEY):PEC_POINT;
function EC_KEY_new_ex(ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;
function EC_KEY_new_by_curve_name_ex(ctx : POSSL_LIB_CTX;const propq : PUTF8Char; nid : integer):PEC_KEY;
function EC_KEY_get0_private_key(const key : PEC_KEY):PBIGNUM;
function EC_KEY_get0_group(const key : PEC_KEY):PEC_GROUP;
 function ossl_ec_key_simple_priv2oct(const eckey : PEC_KEY; buf : PByte; len : size_t):size_t;
function ossl_ec_key_simple_oct2priv(eckey : PEC_KEY;const buf : PByte; len : size_t):integer;
function ossl_ec_key_simple_generate_key( eckey : PEC_KEY):integer;
function ossl_ec_key_simple_check_key(const eckey : PEC_KEY):integer;
function ossl_ec_key_simple_generate_public_key( eckey : PEC_KEY):integer;
function EC_KEY_get_flags(const key : PEC_KEY):integer;
function EC_KEY_can_sign(const eckey : PEC_KEY):integer;
 function EC_KEY_priv2buf(const eckey : PEC_KEY; pbuf : PPByte):size_t;
 function EC_KEY_key2buf(const key : PEC_KEY; form : point_conversion_form_t; pbuf : PPByte; ctx : PBN_CTX):size_t;
function EC_KEY_dup(const ec_key : PEC_KEY):PEC_KEY;
procedure EC_KEY_free( r : PEC_KEY);
procedure EC_KEY_set_flags( key : PEC_KEY; flags : integer);
procedure EC_KEY_clear_flags( key : PEC_KEY; flags : integer);
function EC_KEY_new:PEC_KEY;
function EC_KEY_set_group(key : PEC_KEY;const group : PEC_GROUP):integer;
function EC_KEY_generate_key( eckey : PEC_KEY):integer;
function ossl_ec_key_gen( eckey : PEC_KEY):integer;
procedure EC_KEY_set_conv_form( key : PEC_KEY; cform : point_conversion_form_t);
function EC_KEY_get_enc_flags(const key : PEC_KEY):uint32;
 procedure EC_KEY_set_enc_flags( key : PEC_KEY; flags : uint32);
 function EC_KEY_set_private_key(key : PEC_KEY;const priv_key : PBIGNUM):integer;
function EC_KEY_set_public_key_affine_coordinates( key : PEC_KEY; x, y : PBIGNUM):integer;
function EC_KEY_set_public_key(key : PEC_KEY;const pub_key : PEC_POINT):integer;
function EC_KEY_check_key(const eckey : PEC_KEY):integer;
 function EC_KEY_priv2oct(const eckey : PEC_KEY; buf : PByte; len : size_t):size_t;
 function ec_generate_key( eckey : PEC_KEY; pairwise_test : integer):integer;
 function ecdsa_keygen_pairwise_test( eckey : PEC_KEY; cb : POSSL_CALLBACK; cbarg : Pointer):integer;
function EC_KEY_oct2key(key : PEC_KEY;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
function EC_KEY_oct2priv(eckey : PEC_KEY;const buf : PByte; len : size_t):integer;
function EC_KEY_get_conv_form(const key : PEC_KEY):point_conversion_form_t;
 function EC_KEY_up_ref( r : PEC_KEY):integer;
 procedure ossl_ec_key_set0_libctx( key : PEC_KEY; libctx : POSSL_LIB_CTX);


implementation
uses  OpenSSL3.Err, openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.ec.ec_lib, openssl3.crypto.ec.ec_kmeth,
      openssl3.include.internal.refcount, openssl3.crypto.engine.eng_init,
      openssl3.crypto.ex_data, OpenSSL3.threads_none,
      openssl3.crypto.ec.ec_oct, openssl3.crypto.bn.bn_add,
      openssl3.crypto.mem,  openssl3.crypto.ec.ec_backend,
      openssl3.crypto.bn.bn_rand, openssl3.crypto.self_test_core,
      openssl3.crypto.ec.ecdsa_sign, openssl3.crypto.ec.ecdsa_vrf,
      openssl3.crypto.ec.ec_asn1, openssl3.providers.fips.self_test,
      openssl3.crypto.ec.ec_curve, openssl3.crypto.bn.bn_intern ;





procedure ossl_ec_key_set0_libctx( key : PEC_KEY; libctx : POSSL_LIB_CTX);
begin
    key.libctx := libctx;
    { Do we need to propagate this to the group? }
end;

function EC_KEY_up_ref( r : PEC_KEY):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(r.references, i, r.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('EC_KEY', r);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result(i > 1 , 1 , 0);
end;


function EC_KEY_get_conv_form(const key : PEC_KEY):point_conversion_form_t;
begin
    Result := key.conv_form;
end;

function EC_KEY_oct2priv(eckey : PEC_KEY;const buf : PByte; len : size_t):integer;
var
  ret : integer;
begin
    if (eckey.group = nil)  or  (eckey.group.meth = nil) then Exit(0);
    if not Assigned(eckey.group.meth.oct2priv) then begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    ret := eckey.group.meth.oct2priv(eckey, buf, len);
    if ret = 1 then PostInc(eckey.dirty_cnt);
    Result := ret;
end;

function EC_KEY_oct2key(key : PEC_KEY;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
begin
    if (key = nil)  or  (key.group = nil) then Exit(0);
    if key.pub_key = nil then key.pub_key := EC_POINT_new(key.group);
    if key.pub_key = nil then Exit(0);
    if EC_POINT_oct2point(key.group, key.pub_key, buf, len, ctx ) = 0 then
        Exit(0);
    PostInc(key.dirty_cnt);
    {
     * Save the point conversion form.
     * For non-custom curves the first octet of the buffer (excluding
     * the last significant bit) contains the point conversion form.
     * EC_POINT_oct2point has already performed sanity checking of
     * the buffer so we know it is valid.
     }
    if key.group.meth.flags and EC_FLAGS_CUSTOM_CURVE = 0 then
        key.conv_form := point_conversion_form_t(buf[0] and not $01);
    Result := 1;
end;




function ecdsa_keygen_pairwise_test( eckey : PEC_KEY; cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
    ret      : integer;
    dgst     : array[0..15] of Byte;
    dgst_len : integer;
    sig      : PECDSA_SIG;
    st       : POSSL_SELF_TEST;
    label _err;
begin
    ret := 0;
    FillChar(dgst, 16, 0);

    dgst_len := int (sizeof(dgst));
    sig := nil;
    st := nil;
    st := OSSL_SELF_TEST_new(cb, cbarg);
    if st = nil then Exit(0);
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_PCT,
                           OSSL_SELF_TEST_DESC_PCT_ECDSA);
    sig := ECDSA_do_sign(@dgst, dgst_len, eckey);
    if sig = nil then goto _err ;
    OSSL_SELF_TEST_oncorrupt_byte(st, @dgst);
    if ECDSA_do_verify(@dgst, dgst_len, sig, eckey) <> 1 then
        goto _err ;
    ret := 1;
_err:
    OSSL_SELF_TEST_onend(st, ret);
    OSSL_SELF_TEST_free(st);
    ECDSA_SIG_free(sig);
    Result := ret;
end;



function ec_generate_key( eckey : PEC_KEY; pairwise_test : integer):integer;
var
    ok       : integer;
    priv_key,
    tmp,
    order    : PBIGNUM;
    pub_key  : PEC_POINT;
    group    : PEC_GROUP;
    ctx      : PBN_CTX;
    sm2      : integer;
    cb       : POSSL_CALLBACK;
    cbarg    : Pointer;
    label _err;
begin
    ok := 0;
    priv_key := nil;
    tmp := nil;
    order := nil;
    pub_key := nil;
    group := eckey.group;
    ctx := BN_CTX_secure_new_ex(eckey.libctx);
    sm2 := get_result( (EC_KEY_get_flags(eckey) and EC_FLAG_SM2_RANGE)>0 , 1 , 0);
    if ctx = nil then goto _err ;
    if eckey.priv_key = nil then
    begin
        priv_key := BN_secure_new();
        if priv_key = nil then goto _err ;
    end
    else
        priv_key := eckey.priv_key;
    {
     * Steps (1-2): Check domain parameters and security strength.
     * These steps must be done by the user. This would need to be
     * stated in the security policy.
     }
    tmp := EC_GROUP_get0_order(group);
    if tmp = nil then goto _err ;
    {
     * Steps (3-7): priv_key = DRBG_RAND(order_n_bits) (range [1, n-1]).
     * Although this is slightly different from the standard, it is effectively
     * equivalent as it gives an unbiased result ranging from 1..n-1. It is also
     * faster as the standard needs to retry more often. Also doing
     * 1 + rand[0..n-2] would effect the way that tests feed dummy entropy into
     * rand so the simpler backward compatible method has been used here.
     }
    { range of SM2 private key is [1, n-1) }
    if sm2 > 0 then
    begin
        order := BN_new();
        if (order = nil)  or  (0>= BN_sub(order, tmp, BN_value_one)) then
            goto _err ;
    end
    else
    begin
        order := BN_dup(tmp);
        if order = nil then goto _err ;
    end;

    repeat
        if 0>= BN_priv_rand_range_ex(priv_key, order, 0, ctx) then
            goto _err ;
    until not BN_is_zero(priv_key);

    if eckey.pub_key = nil then
    begin
        pub_key := EC_POINT_new(group);
        if pub_key = nil then
           goto _err ;
    end
    else
        pub_key := eckey.pub_key;
    { Step (8) : pub_key = priv_key * G (where G is a point on the curve) }
    if 0>= EC_POINT_mul(group, pub_key, priv_key, nil, nil, ctx ) then
        goto _err ;
    eckey.priv_key := priv_key;
    eckey.pub_key := pub_key;
    priv_key := nil;
    pub_key := nil;
    Inc(eckey.dirty_cnt);
{$IFDEF FIPS_MODULE}
    pairwise_test := 1;
{$endif} { FIPS_MODULE }
    ok := 1;
    if pairwise_test > 0 then
    begin
        cb := nil;
        cbarg := nil;
        OSSL_SELF_TEST_get_callback(eckey.libctx, @cb, @cbarg);
        ok := ecdsa_keygen_pairwise_test(eckey, cb, cbarg);
    end;
_err:
    { Step (9): If there is an error return an invalid keypair. }
    if 0>= ok then
    begin
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_PCT);
        BN_clear(eckey.priv_key);
        if eckey.pub_key <> nil then EC_POINT_set_to_infinity(group, eckey.pub_key);
    end;
    EC_POINT_free(pub_key);
    BN_clear_free(priv_key);
    BN_CTX_free(ctx);
    BN_free(order);
    Result := ok;
end;




function EC_KEY_priv2oct(const eckey : PEC_KEY; buf : PByte; len : size_t):size_t;
begin
    if (eckey.group = nil)  or  (eckey.group.meth = nil) then Exit(0);
    if not Assigned(eckey.group.meth.priv2oct) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := eckey.group.meth.priv2oct(eckey, buf, len);
end;




function EC_KEY_check_key(const eckey : PEC_KEY):integer;
begin
    if (eckey = nil)  or  (eckey.group = nil)  or  (eckey.pub_key = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if not Assigned(eckey.group.meth.keycheck) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := eckey.group.meth.keycheck(eckey);
end;

function EC_KEY_set_public_key_affine_coordinates( key : PEC_KEY; x, y : PBIGNUM):integer;
var
  ctx : PBN_CTX;
  tx, ty : PBIGNUM;
  point : PEC_POINT;
  ok : integer;
  label _err;
begin
    ctx := nil;
    point := nil;
    ok := 0;
    if (key = nil)  or  (key.group = nil)  or  (x = nil)  or  (y = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(key.libctx);
    if ctx = nil then Exit(0);
    BN_CTX_start(ctx);
    point := EC_POINT_new(key.group);
    if point = nil then goto _err ;
    tx := BN_CTX_get(ctx);
    ty := BN_CTX_get(ctx);
    if ty = nil then goto _err ;
    if 0>= EC_POINT_set_affine_coordinates(key.group, point, x, y, ctx) then
        goto _err ;
    if 0>= EC_POINT_get_affine_coordinates(key.group, point, tx, ty, ctx) then
        goto _err ;
    {
     * Check if retrieved coordinates match originals. The range check is done
     * inside EC_KEY_check_key().
     }
    if (BN_cmp(x, tx)>0)  or  (BN_cmp(y, ty)>0)  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        goto _err ;
    end;
    { EC_KEY_set_public_key updates dirty_cnt }
    if 0>= EC_KEY_set_public_key(key, point ) then
        goto _err ;
    if EC_KEY_check_key(key) = 0  then
        goto _err ;
    ok := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    Exit(ok);
end;




function EC_KEY_set_public_key(key : PEC_KEY;const pub_key : PEC_POINT):integer;
begin
    if (Assigned(key.meth.set_public))
         and  (key.meth.set_public(key, pub_key) = 0)  then
        Exit(0);
    EC_POINT_free(key.pub_key);
    key.pub_key := EC_POINT_dup(pub_key, key.group);
    Inc(key.dirty_cnt);
    Result := get_result(key.pub_key = nil , 0 , 1);
end;




function EC_KEY_set_private_key(key : PEC_KEY;const priv_key : PBIGNUM):integer;
var
  fixed_top : integer;
  order,
  tmp_key   : PBIGNUM;
begin
    order := nil;
    tmp_key := nil;
    if (key.group = nil)  or  (key.group.meth = nil) then
        Exit(0);
    {
     * Not only should key.group be set, but it should also be in a valid
     * fully initialized state.
     *
     * Specifically, to operate in constant time, we need that the group order
     * is set, as we use its length as the fixed public size of any scalar used
     * as an EC private key.
     }
    order := EC_GROUP_get0_order(key.group);
    if (order = nil)  or  (BN_is_zero(order)) then
        Exit(0); { This should never happen }
    if (Assigned(key.group.meth.set_private))
         and  (key.group.meth.set_private(key, priv_key) = 0)  then
        Exit(0);
    if (Assigned(key.meth.set_private))
         and  (key.meth.set_private(key, priv_key) = 0) then
        Exit(0);
    {
     * We should never leak the bit length of the secret scalar in the key,
     * so we always set the `BN_FLG_CONSTTIME` flag on the internal `BIGNUM`
     * holding the secret scalar.
     *
     * This is important also because `BN_dup()` (and `BN_copy()`) do not
     * propagate the `BN_FLG_CONSTTIME` flag from the source `BIGNUM`, and
     * this brings an extra risk of inadvertently losing the flag, even when
     * the caller specifically set it.
     *
     * The propagation has been turned on and off a few times in the past
     * years because in some conditions has shown unintended consequences in
     * some code paths, so at the moment we can't fix this in the BN layer.
     *
     * In `EC_KEY_set_private_key()` we can work around the propagation by
     * manually setting the flag after `BN_dup()` as we know for sure that
     * inside the EC module the `BN_FLG_CONSTTIME` is always treated
     * correctly and should not generate unintended consequences.
     *
     * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
     * to preallocate the BIGNUM internal buffer to a fixed public size big
     * enough that operations performed during the processing never trigger
     * a realloc which would leak the size of the scalar through memory
     * accesses.
     *
     * Fixed Length
     * ------------
     *
     * The order of the large prime subgroup of the curve is our choice for
     * a fixed public size, as that is generally the upper bound for
     * generating a private key in EC cryptosystems and should fit all valid
     * secret scalars.
     *
     * For preallocating the BIGNUM storage we look at the number of 'words'
     * required for the internal representation of the order, and we
     * preallocate 2 extra 'words' in case any of the subsequent processing
     * might temporarily overflow the order length.
     }
    tmp_key := BN_dup(priv_key);
    if tmp_key = nil then Exit(0);
    BN_set_flags(tmp_key, BN_FLG_CONSTTIME);
    fixed_top := bn_get_top(order) + 2;
    if bn_wexpand(tmp_key, fixed_top) = nil  then
    begin
        BN_clear_free(tmp_key);
        Exit(0);
    end;
    BN_clear_free(key.priv_key);
    key.priv_key := tmp_key;
    Inc(key.dirty_cnt);
    Result := 1;
end;



procedure EC_KEY_set_enc_flags( key : PEC_KEY; flags : uint32);
begin
    key.enc_flag := flags;
end;

function EC_KEY_get_enc_flags(const key : PEC_KEY):uint32;
begin
    Result := key.enc_flag;
end;

procedure EC_KEY_set_conv_form( key : PEC_KEY; cform : point_conversion_form_t);
begin
    key.conv_form := cform;
    if key.group <> nil then
       EC_GROUP_set_point_conversion_form(key.group, cform);
end;


function ossl_ec_key_gen( eckey : PEC_KEY):integer;
var
  ret : integer;
begin
    ret := eckey.group.meth.keygen(eckey);
    if ret = 1 then
       Inc(eckey.dirty_cnt);
    Result := ret;
end;


function EC_KEY_generate_key( eckey : PEC_KEY):integer;
var
  ret : integer;
begin
    if (eckey = nil)  or  (eckey.group = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if Assigned(eckey.meth.keygen) then
    begin
        ret := eckey.meth.keygen(eckey);
        if ret = 1 then
           PostInc(eckey.dirty_cnt);
        Exit(ret);
    end;
    ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
    Result := 0;
end;



function EC_KEY_set_group(key : PEC_KEY;const group : PEC_GROUP):integer;
begin
    if (Assigned(key.meth.set_group))  and  (key.meth.set_group(key, group) = 0) then
        Exit(0);
    EC_GROUP_free(key.group);
    key.group := EC_GROUP_dup(group);
    if (key.group <> nil)  and  (EC_GROUP_get_curve_name(key.group) = NID_sm2) then
        EC_KEY_set_flags(key, EC_FLAG_SM2_RANGE);
    Inc(key.dirty_cnt);
    Result := get_result(key.group = nil , 0 , 1);
end;


function EC_KEY_new:PEC_KEY;
begin
    Result := ossl_ec_key_new_method_int(nil, nil, nil);
end;




procedure EC_KEY_clear_flags( key : PEC_KEY; flags : integer);
begin
    key.flags := key.flags and (not flags);
    PostInc(key.dirty_cnt);
end;



procedure EC_KEY_set_flags( key : PEC_KEY; flags : integer);
begin
    key.flags  := key.flags  or flags;
    Inc(key.dirty_cnt);
end;





procedure EC_KEY_free( r : PEC_KEY);
var
  i : integer;
begin
    if r = nil then Exit;
    CRYPTO_DOWN_REF(r.references, i, r.lock);
    REF_PRINT_COUNT('EC_KEY', r);
    if i > 0 then Exit;
    REF_ASSERT_ISNT(i < 0);
    if (Assigned(r.meth))  and  (Assigned(r.meth.finish)) then
        r.meth.finish(r);
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    ENGINE_finish(r.engine);
{$ENDIF}
    if (r.group <> nil) and  (Assigned(r.group.meth.keyfinish)) then
        r.group.meth.keyfinish(r);
{$IFNDEF FIPS_MODULE}
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EC_KEY, r, @r.ex_data);
{$ENDIF}
    CRYPTO_THREAD_lock_free(r.lock);
    EC_GROUP_free(r.group);
    EC_POINT_free(r.pub_key);
    BN_clear_free(r.priv_key);
    OPENSSL_free(Pointer(r.propq));
    OPENSSL_clear_free(Pointer( r), sizeof(TEC_KEY));
end;




function EC_KEY_dup(const ec_key : PEC_KEY):PEC_KEY;
begin
    Result := ossl_ec_key_dup(ec_key, OSSL_KEYMGMT_SELECT_ALL);
end;


function EC_KEY_key2buf(const key : PEC_KEY; form : point_conversion_form_t; pbuf : PPByte; ctx : PBN_CTX):size_t;
begin
    if (key = nil)  or  (key.pub_key = nil)  or  (key.group = nil) then
        Exit(0);
    Result := EC_POINT_point2buf(key.group, key.pub_key, form, pbuf, ctx);
end;




function EC_KEY_priv2buf(const eckey : PEC_KEY; pbuf : PPByte):size_t;
var
  len : size_t;

  buf : PByte;
begin
    len := EC_KEY_priv2oct(eckey, nil, 0);
    if len = 0 then Exit(0);
    buf := OPENSSL_malloc(len);
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    len := EC_KEY_priv2oct(eckey, buf, len);
    if len = 0 then
    begin
        OPENSSL_free(Pointer(buf));
        Exit(0);
    end;
    pbuf^ := buf;
    Result := len;
end;

function EC_KEY_can_sign(const eckey : PEC_KEY):integer;
begin
    if (eckey.group = nil)  or  (eckey.group.meth = nil)
         or  ( (eckey.group.meth.flags and EC_FLAGS_NO_SIGN) > 0 ) then
        Exit(0);
    Result := 1;
end;

function EC_KEY_get_flags(const key : PEC_KEY):integer;
begin
    Result := key.flags;
end;




function ossl_ec_key_simple_generate_public_key( eckey : PEC_KEY):integer;
var
  ret : integer;

  ctx : PBN_CTX;
begin
    ctx := BN_CTX_new_ex(eckey.libctx);
    if ctx = nil then Exit(0);
    {
     * See SP800-56AR3 5.6.1.2.2: Step (8)
     * pub_key = priv_key * G (where G is a point on the curve)
     }
    ret := EC_POINT_mul(eckey.group, eckey.pub_key, eckey.priv_key, nil,
                       nil, ctx);
    BN_CTX_free(ctx);
    if ret = 1 then
       Inc(eckey.dirty_cnt);
    Result := ret;
end;



function ossl_ec_key_simple_check_key(const eckey : PEC_KEY):integer;
var
  ok : integer;
  ctx : PBN_CTX;
  label _err;
begin
    ok := 0;
    ctx := nil;
    if eckey = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(eckey.libctx);
    if ctx =  nil then
        Exit(0);
    if 0>= ossl_ec_key_public_check(eckey, ctx) then
        goto _err ;
    if eckey.priv_key <> nil then
    begin
        if (0>= ossl_ec_key_private_check(eckey))
             or  (0>= ossl_ec_key_pairwise_check(eckey, ctx)) then
            goto _err ;
    end;
    ok := 1;
_err:
    BN_CTX_free(ctx);
    Result := ok;
end;


function ossl_ec_key_simple_generate_key( eckey : PEC_KEY):integer;
begin
    Result := ec_generate_key(eckey, 0);
end;



function ossl_ec_key_simple_oct2priv(eckey : PEC_KEY;const buf : PByte; len : size_t):integer;
begin
    if eckey.priv_key = nil then
       eckey.priv_key := BN_secure_new();
    if eckey.priv_key = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    eckey.priv_key := BN_bin2bn(buf, len, eckey.priv_key);
    if eckey.priv_key = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        Exit(0);
    end;
    PostInc(eckey.dirty_cnt);
    Result := 1;
end;




function ossl_ec_key_simple_priv2oct(const eckey : PEC_KEY; buf : PByte; len : size_t):size_t;
var
  buf_len : size_t;
begin
    buf_len := (EC_GROUP_order_bits(eckey.group) + 7) div 8;
    if eckey.priv_key = nil then Exit(0);
    if buf = nil then
       Exit(buf_len)
    else
    if (len < buf_len) then
        Exit(0);
    { Octetstring may need leading zeros if BN is to short }
    if BN_bn2binpad(eckey.priv_key, buf, buf_len) = -1  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    Result := buf_len;
end;




function EC_KEY_get0_group(const key : PEC_KEY):PEC_GROUP;
begin
    Result := key.group;
end;


function EC_KEY_get0_private_key(const key : PEC_KEY):PBIGNUM;
begin
    Result := key.priv_key;
end;



function EC_KEY_new_by_curve_name_ex(ctx : POSSL_LIB_CTX;const propq : PUTF8Char; nid : integer):PEC_KEY;
var
  ret : PEC_KEY;
begin
    ret := EC_KEY_new_ex(ctx, propq);
    if ret = nil then Exit(nil);
    ret.group := EC_GROUP_new_by_curve_name_ex(ctx, propq, nid);
    if ret.group = nil then
    begin
        EC_KEY_free(ret);
        Exit(nil);
    end;
    if ( Assigned(ret.meth.set_group) )
         and  (ret.meth.set_group(ret, ret.group) = 0)  then
    begin
        EC_KEY_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;





function EC_KEY_new_ex(ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;
begin
    Result := ossl_ec_key_new_method_int(ctx, propq, nil);
end;



function EC_KEY_get0_public_key(const key : PEC_KEY):PEC_POINT;
begin
    Result := key.pub_key;
end;




function ossl_ec_key_pairwise_check(const eckey : PEC_KEY; ctx : PBN_CTX):integer;
var
  ret : integer;

  point : PEC_POINT;
  label _err;
begin
    ret := 0;
    point := nil;
    if (eckey = nil)
        or  (eckey.group = nil)
        or  (eckey.pub_key = nil)
        or  (eckey.priv_key = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    point := EC_POINT_new(eckey.group);
    if point = nil then goto _err ;
    if  0>= EC_POINT_mul(eckey.group, point, eckey.priv_key, nil, nil, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    if EC_POINT_cmp(eckey.group, point, eckey.pub_key, ctx) <> 0  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        goto _err ;
    end;
    ret := 1;
_err:
    EC_POINT_free(point);
    Result := ret;
end;



function ossl_ec_key_private_check(const eckey : PEC_KEY):integer;
begin
    if (eckey = nil)  or  (eckey.group = nil)  or  (eckey.priv_key = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (BN_cmp(eckey.priv_key, BN_value_one ) < 0 )
         or  (BN_cmp(eckey.priv_key, eckey.group.order) >= 0)  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        Exit(0);
    end;
    Result := 1;
end;

function ossl_ec_key_public_check(const eckey : PEC_KEY; ctx : PBN_CTX):integer;
var
  ret : integer;
  point : PEC_POINT;
  order : PBIGNUM;
  label _err;
begin
    ret := 0;
    point := nil;
    order := nil;
    if  0>= ossl_ec_key_public_check_quick(eckey, ctx) then
        Exit(0);
    point := EC_POINT_new(eckey.group);
    if point = nil then Exit(0);
    order := eckey.group.order;
    if BN_is_zero(order) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto _err ;
    end;
    { 5.6.2.3.3 (Step 4) : pub_key * order is the point at infinity. }
    if  0>= EC_POINT_mul(eckey.group, point, nil, eckey.pub_key, order, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    if  0>= EC_POINT_is_at_infinity(eckey.group, point) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_WRONG_ORDER);
        goto _err ;
    end;
    ret := 1;
_err:
    EC_POINT_free(point);
    Result := ret;
end;




function ec_key_public_range_check(ctx : PBN_CTX;const key : PEC_KEY):integer;
var
  ret : integer;

  x, y : PBIGNUM;

  m : integer;
  label _err;
begin
    ret := 0;
    BN_CTX_start(ctx);
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    if y = nil then goto _err ;
    if  0>= EC_POINT_get_affine_coordinates(key.group, key.pub_key, x, y, ctx) then
        goto _err ;
    if EC_GROUP_get_field_type(key.group) = NID_X9_62_prime_field  then
    begin
        if (BN_is_negative(x)>0)
             or  (BN_cmp(x, key.group.field) >= 0)
             or  (BN_is_negative(y)>0)
             or  (BN_cmp(y, key.group.field) >= 0) then
        begin
            goto _err ;
        end;
    end
    else
    begin
        m := EC_GROUP_get_degree(key.group);
        if (BN_num_bits(x) > m)  or  (BN_num_bits(y) > m)  then
        begin
            goto _err ;
        end;
    end;
    ret := 1;
_err:
    BN_CTX_end(ctx);
    Result := ret;
end;


function ossl_ec_key_public_check_quick(const eckey : PEC_KEY; ctx : PBN_CTX):integer;
begin
    if (eckey = nil)  or  (eckey.group = nil)  or  (eckey.pub_key = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { 5.6.2.3.3 (Step 1): Q <> infinity }
    if EC_POINT_is_at_infinity(eckey.group, eckey.pub_key)>0  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        Exit(0);
    end;
    { 5.6.2.3.3 (Step 2) Test if the public key is in range }
    if  0>= ec_key_public_range_check(ctx, eckey) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        Exit(0);
    end;
    { 5.6.2.3.3 (Step 3) is the pub_key on the elliptic curve }
    if EC_POINT_is_on_curve(eckey.group, eckey.pub_key, ctx) <= 0  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        Exit(0);
    end;
    Result := 1;
end;





function ossl_ec_key_get0_propq(const key : PEC_KEY):PUTF8Char;
begin
    Result := key.propq;
end;

function ossl_ec_key_get_libctx(const key : PEC_KEY):POSSL_LIB_CTX;
begin
    Result := key.libctx;
end;



function EC_KEY_decoded_from_explicit_params(const key : PEC_KEY):integer;
begin
    if (key = nil)  or  (key.group = nil) then
       Exit(-1);
    Result := key.group.decoded_from_explicit_params;
end;


end.
