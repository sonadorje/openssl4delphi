unit openssl3.crypto.ec.ecp_nist;

interface
uses OpenSSL.Api;

  function EC_GFp_nist_method:PEC_METHOD;
  function ossl_ec_GFp_nist_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
  function ossl_ec_GFp_nist_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_nist_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_nist_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  

implementation

uses OpenSSL3.crypto.ec.ecp_smpl, openssl3.crypto.ec.ec_lib,
     openssl3.crypto.ec.ec_key, openssl3.crypto.ec.ecdh_ossl,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_nist,
     OpenSSL3.Err, openssl3.crypto.bn.bn_mul,
     openssl3.crypto.bn.bn_sqr,
     openssl3.crypto.ec.ecdsa_ossl, openssl3.crypto.bn.bn_ctx;

const  ret: TEC_METHOD = (
        flags: EC_FLAGS_DEFAULT_OCT;
        field_type: NID_X9_62_prime_field;
        group_init: ossl_ec_GFp_simple_group_init;
        group_finish: ossl_ec_GFp_simple_group_finish;
        group_clear_finish: ossl_ec_GFp_simple_group_clear_finish;
        group_copy: ossl_ec_GFp_nist_group_copy;
        group_set_curve: ossl_ec_GFp_nist_group_set_curve;
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
        point2oct:  nil;
        oct2point: nil;
        add: ossl_ec_GFp_simple_add;
        dbl: ossl_ec_GFp_simple_dbl;
        invert: ossl_ec_GFp_simple_invert;
        is_at_infinity: ossl_ec_GFp_simple_is_at_infinity;
        is_on_curve: ossl_ec_GFp_simple_is_on_curve;
        point_cmp: ossl_ec_GFp_simple_cmp;
        make_affine: ossl_ec_GFp_simple_make_affine;
        points_make_affine: ossl_ec_GFp_simple_points_make_affine;
        mul: nil { mul }  ;
        precompute_mult: nil { precompute_mult } ;
        have_precompute_mult: nil { have_precompute_mult } ;
        field_mul: ossl_ec_GFp_nist_field_mul;
        field_sqr: ossl_ec_GFp_nist_field_sqr;
        field_div: nil { field_div } ;
        field_inv: ossl_ec_GFp_simple_field_inv;
        field_encode: nil { field_encode } ;
        field_decode: nil { field_decode } ;
        field_set_to_one:  nil;                      { field_set_to_one }
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




function EC_GFp_nist_method:PEC_METHOD;
begin
    Result := @ret;
end;




function ossl_ec_GFp_nist_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
  new_ctx : PBN_CTX;
  label _err;
begin
    ret := 0;
    new_ctx := nil;
    if ctx = nil then
    begin
       new_ctx := BN_CTX_new_ex(group.libctx);
       ctx := new_ctx;
       if (ctx = nil) then
            Exit(0);
    end;
    BN_CTX_start(ctx);
    if (BN_ucmp(BN_get0_nist_prime_192, p) = 0)  then
        group.field_mod_func := BN_nist_mod_192
    else if (BN_ucmp(BN_get0_nist_prime_224(), p) = 0) then
        group.field_mod_func := BN_nist_mod_224
    else if (BN_ucmp(BN_get0_nist_prime_256(), p) = 0) then
        group.field_mod_func := BN_nist_mod_256
    else if (BN_ucmp(BN_get0_nist_prime_384(), p) = 0) then
        group.field_mod_func := BN_nist_mod_384
    else if (BN_ucmp(BN_get0_nist_prime_521(), p) = 0) then
        group.field_mod_func := BN_nist_mod_521
    else
    begin
        ERR_raise(ERR_LIB_EC, EC_R_NOT_A_NIST_PRIME);
        goto _err ;
    end;
    ret := ossl_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_nist_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;

  ctx_new : PBN_CTX;
  label _err;
begin
    ret := 0;
    ctx_new := nil;
    if (nil = group)  or  (nil = r)  or  (nil = a)  or  (nil = b) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        goto _err ;
    end;
    if nil = ctx then
    begin
       ctx := BN_CTX_new_ex(group.libctx);
       ctx_new := ctx;
       if (ctx_new = nil) then
            goto _err ;
    end;
    if 0>= BN_mul(r, a, b, ctx ) then
        goto _err ;
    if 0>= group.field_mod_func(r, r, group.field, ctx) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_free(ctx_new);
    Result := ret;
end;


function ossl_ec_GFp_nist_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;

  ctx_new : PBN_CTX;
  label _err;
begin
    ret := 0;
    ctx_new := nil;
    if ( nil = group)  or  (nil= r)  or  (nil= a ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_PASSED_NULL_PARAMETER);
        goto _err ;
    end;
    if nil = ctx then
    begin
       ctx := BN_CTX_new_ex(group.libctx);
       ctx_new := ctx;
       if (ctx_new = nil) then
           goto _err ;
    end;
    if 0>= BN_sqr(r, a, ctx) then
        goto _err ;
    if 0>= group.field_mod_func(r, r, group.field, ctx) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_free(ctx_new);
    Result := ret;
end;




function ossl_ec_GFp_nist_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
begin
    dest.field_mod_func := src.field_mod_func;
    Result := ossl_ec_GFp_simple_group_copy(dest, src);
end;


end.
