unit openssl3.crypto.ec.ecp_mont;

interface
uses OpenSSL.Api;

function ossl_ec_GFp_mont_group_init( group : PEC_GROUP):integer;
  procedure ossl_ec_GFp_mont_group_finish( group : PEC_GROUP);
  procedure ossl_ec_GFp_mont_group_clear_finish( group : PEC_GROUP);
  function ossl_ec_GFp_mont_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
  function ossl_ec_GFp_mont_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_mont_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_mont_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_mont_field_inv(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_mont_field_encode(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_mont_field_decode(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_mont_field_set_to_one(const group : PEC_GROUP; r : PBIGNUM; ctx : PBN_CTX):integer;


function EC_GFp_mont_method:PEC_METHOD;

implementation
uses OpenSSL3.crypto.ec.ecp_smpl, openssl3.crypto.ec.ec_lib,
     openssl3.crypto.ec.ec_key, openssl3.crypto.ec.ecdh_ossl,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
     OpenSSL3.Err, openssl3.crypto.bn.bn_add,
     openssl3.crypto.bn.bn_exp,
     openssl3.crypto.ec.ecdsa_ossl, openssl3.crypto.bn.bn_mont;

const ret: TEC_METHOD = (
        flags: EC_FLAGS_DEFAULT_OCT;
        field_type: NID_X9_62_prime_field;
        group_init: ossl_ec_GFp_mont_group_init;
        group_finish: ossl_ec_GFp_mont_group_finish;
        group_clear_finish: ossl_ec_GFp_mont_group_clear_finish;
        group_copy: ossl_ec_GFp_mont_group_copy;
        group_set_curve: ossl_ec_GFp_mont_group_set_curve;
        group_get_curve: ossl_ec_GFp_simple_group_get_curve;
        group_get_degree: ossl_ec_GFp_simple_group_get_degree;
        group_order_bits: ossl_ec_group_simple_order_bits;
        group_check_discriminant: ossl_ec_GFp_simple_group_check_discriminant;
        point_init: ossl_ec_GFp_simple_point_init;
        point_finish: ossl_ec_GFp_simple_point_finish;
        point_clear_finish: ossl_ec_GFp_simple_point_clear_finish;
        point_copy: ossl_ec_GFp_simple_point_copy;
        point_set_to_infinity: ossl_ec_GFp_simple_point_set_to_infinity;
        point_set_affine_coordinates: ossl_ec_GFp_simple_point_set_affine_coordinates;
        point_get_affine_coordinates: ossl_ec_GFp_simple_point_get_affine_coordinates;
        point_set_compressed_coordinates: nil;
        point2oct: nil;
        oct2point: nil;
        add: ossl_ec_GFp_simple_add;
        dbl: ossl_ec_GFp_simple_dbl;
        invert: ossl_ec_GFp_simple_invert;
        is_at_infinity: ossl_ec_GFp_simple_is_at_infinity;
        is_on_curve: ossl_ec_GFp_simple_is_on_curve;
        point_cmp: ossl_ec_GFp_simple_cmp;
        make_affine: ossl_ec_GFp_simple_make_affine;
        points_make_affine: ossl_ec_GFp_simple_points_make_affine;
        mul: nil { mul } ;
        precompute_mult: nil { precompute_mult } ;
        have_precompute_mult: nil { have_precompute_mult } ;
        field_mul: ossl_ec_GFp_mont_field_mul;
        field_sqr: ossl_ec_GFp_mont_field_sqr;
        field_div: nil { field_div } ;
        field_inv: ossl_ec_GFp_mont_field_inv;
        field_encode: ossl_ec_GFp_mont_field_encode;
        field_decode: ossl_ec_GFp_mont_field_decode;
        field_set_to_one: ossl_ec_GFp_mont_field_set_to_one;
        priv2oct: ossl_ec_key_simple_priv2oct;
        oct2priv: ossl_ec_key_simple_oct2priv;
        set_private: nil; { set private }
        keygen: ossl_ec_key_simple_generate_key;
        keycheck: ossl_ec_key_simple_check_key;
        keygenpub: ossl_ec_key_simple_generate_public_key;
        keycopy: nil; { keycopy }
        keyfinish: nil; { keyfinish }
        ecdh_compute_key: ossl_ecdh_simple_compute_key;
        ecdsa_sign_setup: ossl_ecdsa_simple_sign_setup;
        ecdsa_sign_sig: ossl_ecdsa_simple_sign_sig;
        ecdsa_verify_sig: ossl_ecdsa_simple_verify_sig;
        field_inverse_mod_ord: nil; { field_inverse_mod_ord }
        blind_coordinates: ossl_ec_GFp_simple_blind_coordinates;
        ladder_pre: ossl_ec_GFp_simple_ladder_pre;
        ladder_step: ossl_ec_GFp_simple_ladder_step;
        ladder_post: ossl_ec_GFp_simple_ladder_post
    );

function ossl_ec_GFp_mont_group_init( group : PEC_GROUP):integer;
var
  ok : integer;
begin
    ok := ossl_ec_GFp_simple_group_init(group);
    group.field_data1 := nil;
    group.field_data2 := nil;
    Result := ok;
end;


procedure ossl_ec_GFp_mont_group_finish( group : PEC_GROUP);
begin
    BN_MONT_CTX_free(group.field_data1);
    group.field_data1 := nil;
    BN_free(group.field_data2);
    group.field_data2 := nil;
    ossl_ec_GFp_simple_group_finish(group);
end;


procedure ossl_ec_GFp_mont_group_clear_finish( group : PEC_GROUP);
begin
    BN_MONT_CTX_free(group.field_data1);
    group.field_data1 := nil;
    BN_clear_free(group.field_data2);
    group.field_data2 := nil;
    ossl_ec_GFp_simple_group_clear_finish(group);
end;


function ossl_ec_GFp_mont_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
label _err;
begin
    BN_MONT_CTX_free(dest.field_data1);
    dest.field_data1 := nil;
    BN_clear_free(dest.field_data2);
    dest.field_data2 := nil;
    if 0>= ossl_ec_GFp_simple_group_copy(dest, src ) then
        Exit(0);
    if src.field_data1 <> nil then
    begin
        dest.field_data1 := BN_MONT_CTX_new();
        if dest.field_data1 = nil then Exit(0);
        if nil = BN_MONT_CTX_copy(dest.field_data1, src.field_data1) then
            goto _err ;
    end;
    if src.field_data2 <> nil then
    begin
        dest.field_data2 := BN_dup(src.field_data2);
        if dest.field_data2 = nil then
           goto _err ;
    end;
    Exit(1);
 _err:
    BN_MONT_CTX_free(dest.field_data1);
    dest.field_data1 := nil;
    Result := 0;
end;


function ossl_ec_GFp_mont_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;

  mont : PBN_MONT_CTX;

  one : PBIGNUM;

  ret : integer;
  label _err;
begin
    new_ctx := nil;
    mont := nil;
    one := nil;
    ret := 0;
    BN_MONT_CTX_free(group.field_data1);
    group.field_data1 := nil;
    BN_free(group.field_data2);
    group.field_data2 := nil;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    mont := BN_MONT_CTX_new();
    if mont = nil then goto _err ;
    if 0>= BN_MONT_CTX_set(mont, p, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    one := BN_new();
    if one = nil then goto _err ;
    if 0>= BN_to_montgomery(one, BN_value_one , mont, ctx) then
        goto _err ;
    group.field_data1 := mont;
    mont := nil;
    group.field_data2 := one;
    one := nil;
    ret := ossl_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);
    if 0>= ret then
    begin
        BN_MONT_CTX_free(group.field_data1);
        group.field_data1 := nil;
        BN_free(group.field_data2);
        group.field_data2 := nil;
    end;
 _err:
    BN_free(one);
    BN_CTX_free(new_ctx);
    BN_MONT_CTX_free(mont);
    Result := ret;
end;


function ossl_ec_GFp_mont_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.field_data1 = nil then begin
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        Exit(0);
    end;
    Result := BN_mod_mul_montgomery(r, a, b, group.field_data1, ctx);
end;


function ossl_ec_GFp_mont_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.field_data1 = nil then begin
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        Exit(0);
    end;
    Result := BN_mod_mul_montgomery(r, a, a, group.field_data1, ctx);
end;


function ossl_ec_GFp_mont_field_inv(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
var
  e : PBIGNUM;

  new_ctx : PBN_CTX;

  ret : integer;
  label _err;
begin
    e := nil;
    new_ctx := nil;
    ret := 0;
    if group.field_data1 = nil then Exit(0);
    if (ctx = nil) then
    begin
        new_ctx := BN_CTX_secure_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then
           Exit(0);
    end;
    BN_CTX_start(ctx);
    e := BN_CTX_get(ctx);
    if e = nil then
        goto _err ;
    { Inverse in constant time with Fermats Little Theorem }
    if 0>= BN_set_word(e, 2) then
        goto _err ;
    if 0>= BN_sub(e, group.field, e) then
        goto _err ;
    {-
     * Exponent e is public.
     * No need for scatter-gather or BN_FLG_CONSTTIME.
     }
    if 0>= BN_mod_exp_mont(r, a, e, group.field, ctx, group.field_data1) then
        goto _err ;
    { throw an error on zero }
    if BN_is_zero(r) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CANNOT_INVERT);
        goto _err ;
    end;
    ret := 1;
  _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_mont_field_encode(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.field_data1 = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        Exit(0);
    end;
    Result := BN_to_montgomery(r, a, PBN_MONT_CTX(group.field_data1), ctx);
end;


function ossl_ec_GFp_mont_field_decode(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.field_data1 = nil then begin
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        Exit(0);
    end;
    Result := BN_from_montgomery(r, a, group.field_data1, ctx);
end;


function ossl_ec_GFp_mont_field_set_to_one(const group : PEC_GROUP; r : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.field_data2 = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        Exit(0);
    end;
    if nil = BN_copy(r, group.field_data2 ) then
        Exit(0);
    Result := 1;
end;







function EC_GFp_mont_method:PEC_METHOD;
begin
      Result := @ret;
end;

end.
