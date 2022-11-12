unit openssl3.crypto.ec.ec2_smpl;

interface
uses OpenSSL.Api;

type
  Tfield_mul_func = function(const p1: PEC_GROUP;p2: PBIGNUM; const p3, p4: PBIGNUM ;p5: PBN_CTX  ):int;
  Tfield_sqr_func = function(const p1: PEC_GROUP;p2: PBIGNUM; const p3: PBIGNUM; p4: PBN_CTX  ):int;


  function ossl_ec_GF2m_simple_group_init( group : PEC_GROUP):integer;
  procedure ossl_ec_GF2m_simple_group_finish( group : PEC_GROUP);
  procedure ossl_ec_GF2m_simple_group_clear_finish( group : PEC_GROUP);
  function ossl_ec_GF2m_simple_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
  function ossl_ec_GF2m_simple_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_group_get_curve(const group : PEC_GROUP; p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_group_get_degree(const group : PEC_GROUP):integer;
  function ossl_ec_GF2m_simple_group_check_discriminant(const group : PEC_GROUP; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_point_init( point : PEC_POINT):integer;
  procedure ossl_ec_GF2m_simple_point_finish( point : PEC_POINT);
  procedure ossl_ec_GF2m_simple_point_clear_finish( point : PEC_POINT);
  function ossl_ec_GF2m_simple_point_copy(dest : PEC_POINT;const src : PEC_POINT):integer;
  function ossl_ec_GF2m_simple_point_set_to_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
  function ossl_ec_GF2m_simple_point_set_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x, y : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_point_get_affine_coordinates(const group : PEC_GROUP;const point : PEC_POINT; x, y : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_add(const group : PEC_GROUP; r : PEC_POINT;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_dbl(const group : PEC_GROUP; r : PEC_POINT;const a : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_invert(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_is_at_infinity(const group : PEC_GROUP;const point : PEC_POINT):integer;
  function ossl_ec_GF2m_simple_is_on_curve(const group : PEC_GROUP;const point : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_cmp(const group : PEC_GROUP;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_make_affine(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_points_make_affine(const group : PEC_GROUP; num : size_t; points : PPEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_field_div(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ec_GF2m_simple_ladder_pre(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ec_GF2m_simple_ladder_step(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ec_GF2m_simple_ladder_post(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ec_GF2m_simple_points_mul(const group : PEC_GROUP; r : PEC_POINT;const scalar : PBIGNUM; num : size_t;const points : PPEC_POINT;const scalars : PPBIGNUM; ctx : PBN_CTX):integer;
  function ec_GF2m_simple_field_inv(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function EC_GF2m_simple_method:PEC_METHOD;

implementation
 uses openssl3.crypto.ec.ec_lib, openssl3.crypto.ec.ec_key,
      openssl3.crypto.ec.ecdh_ossl, openssl3.crypto.ec.ecdsa_ossl,
      openssl3.crypto.bn.bn_intern, openssl3.crypto.bn.bn_gf2m,
      OpenSSL3.Err,  openssl3.crypto.bn.bn_rand,
      openssl3.crypto.ec.ec_mult,
      openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx;


const  ret: TEC_METHOD = (
        flags: EC_FLAGS_DEFAULT_OCT;
        field_type: NID_X9_62_characteristic_two_field;
        group_init: ossl_ec_GF2m_simple_group_init;
        group_finish: ossl_ec_GF2m_simple_group_finish;
        group_clear_finish: ossl_ec_GF2m_simple_group_clear_finish;
        group_copy: ossl_ec_GF2m_simple_group_copy;
        group_set_curve: ossl_ec_GF2m_simple_group_set_curve;
        group_get_curve: ossl_ec_GF2m_simple_group_get_curve;
        group_get_degree: ossl_ec_GF2m_simple_group_get_degree;
        group_order_bits: ossl_ec_group_simple_order_bits;
        group_check_discriminant: ossl_ec_GF2m_simple_group_check_discriminant;
        point_init: ossl_ec_GF2m_simple_point_init;
        point_finish: ossl_ec_GF2m_simple_point_finish;
        point_clear_finish: ossl_ec_GF2m_simple_point_clear_finish;
        point_copy: ossl_ec_GF2m_simple_point_copy;
        point_set_to_infinity: ossl_ec_GF2m_simple_point_set_to_infinity;
        point_set_affine_coordinates: ossl_ec_GF2m_simple_point_set_affine_coordinates;
        point_get_affine_coordinates: ossl_ec_GF2m_simple_point_get_affine_coordinates;
        point_set_compressed_coordinates: nil; { point_set_compressed_coordinates }
        point2oct: nil; { point2oct }
        oct2point: nil; { oct2point }
        add: ossl_ec_GF2m_simple_add;
        dbl: ossl_ec_GF2m_simple_dbl;
        invert: ossl_ec_GF2m_simple_invert;
        is_at_infinity: ossl_ec_GF2m_simple_is_at_infinity;
        is_on_curve: ossl_ec_GF2m_simple_is_on_curve;
        point_cmp: ossl_ec_GF2m_simple_cmp;
        make_affine: ossl_ec_GF2m_simple_make_affine;
        points_make_affine: ossl_ec_GF2m_simple_points_make_affine;
        mul: ec_GF2m_simple_points_mul;
        precompute_mult: nil; { precompute_mult }
        have_precompute_mult: nil; { have_precompute_mult }
        field_mul: ossl_ec_GF2m_simple_field_mul;
        field_sqr: ossl_ec_GF2m_simple_field_sqr;
        field_div: ossl_ec_GF2m_simple_field_div;
        field_inv: ec_GF2m_simple_field_inv;
        field_encode: nil; { field_encode }
        field_decode: nil; { field_decode }
        field_set_to_one: nil; { field_set_to_one }
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
        blind_coordinates: nil; { blind_coordinates }
        ladder_pre: ec_GF2m_simple_ladder_pre;
        ladder_step: ec_GF2m_simple_ladder_step;
        ladder_post: ec_GF2m_simple_ladder_post
    );


function ossl_ec_GF2m_simple_group_init( group : PEC_GROUP):integer;
begin
    group.field := BN_new();
    group.a := BN_new();
    group.b := BN_new();
    if (group.field = nil)  or  (group.a = nil)  or  (group.b = nil) then
    begin
        BN_free(group.field);
        BN_free(group.a);
        BN_free(group.b);
        Exit(0);
    end;
    Result := 1;
end;


procedure ossl_ec_GF2m_simple_group_finish( group : PEC_GROUP);
begin
    BN_free(group.field);
    BN_free(group.a);
    BN_free(group.b);
end;


procedure ossl_ec_GF2m_simple_group_clear_finish( group : PEC_GROUP);
begin
    BN_clear_free(group.field);
    BN_clear_free(group.a);
    BN_clear_free(group.b);
    group.poly[0] := 0;
    group.poly[1] := 0;
    group.poly[2] := 0;
    group.poly[3] := 0;
    group.poly[4] := 0;
    group.poly[5] := -1;
end;


function ossl_ec_GF2m_simple_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
begin
    if nil = BN_copy(dest.field, src.field ) then
        Exit(0);
    if nil = BN_copy(dest.a, src.a ) then
        Exit(0);
    if nil = BN_copy(dest.b, src.b) then
        Exit(0);
    dest.poly[0] := src.poly[0];
    dest.poly[1] := src.poly[1];
    dest.poly[2] := src.poly[2];
    dest.poly[3] := src.poly[3];
    dest.poly[4] := src.poly[4];
    dest.poly[5] := src.poly[5];
    if bn_wexpand(dest.a, int (dest.poly[0] + BN_BITS2 - 1 ) div BN_BITS2) =
        nil then
        Exit(0);
    if bn_wexpand(dest.b, int (dest.poly[0] + BN_BITS2 - 1 ) div BN_BITS2) =
        nil then
        Exit(0);
    bn_set_all_zero(dest.a);
    bn_set_all_zero(dest.b);
    Result := 1;
end;


function ossl_ec_GF2m_simple_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret, i : integer;
  label _err;
begin
    ret := 0;
    { group.field }
    if nil = BN_copy(group.field, p) then
        goto _err ;
    i := BN_GF2m_poly2arr(group.field, @group.poly, 6) - 1;
    if (i <> 5)  and  (i <> 3) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNSUPPORTED_FIELD);
        goto _err ;
    end;
    { group.a }
    if 0>= BN_GF2m_mod_arr(group.a, a, @group.poly ) then
        goto _err ;
    if bn_wexpand(group.a, int (group.poly[0] + BN_BITS2 - 1) div BN_BITS2)
        = nil then
        goto _err ;
    bn_set_all_zero(group.a);
    { group.b }
    if 0>= BN_GF2m_mod_arr(group.b, b, @group.poly ) then
        goto _err ;
    if bn_wexpand(group.b, int (group.poly[0] + BN_BITS2 - 1 ) div BN_BITS2)
        = nil then
        goto _err ;
    bn_set_all_zero(group.b);
    ret := 1;
 _err:
    Result := ret;
end;


function ossl_ec_GF2m_simple_group_get_curve(const group : PEC_GROUP; p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
  label _err;
begin
    ret := 0;
    if p <> nil then
    begin
        if nil = BN_copy(p, group.field) then
            Exit(0);
    end;
    if a <> nil then
    begin
        if nil = BN_copy(a, group.a) then
            goto _err ;
    end;
    if b <> nil then
    begin
        if nil = BN_copy(b, group.b) then
            goto _err ;
    end;
    ret := 1;
 _err:
    Result := ret;
end;


function ossl_ec_GF2m_simple_group_get_degree(const group : PEC_GROUP):integer;
begin
    Result := BN_num_bits(group.field) - 1;
end;


function ossl_ec_GF2m_simple_group_check_discriminant(const group : PEC_GROUP; ctx : PBN_CTX):integer;
var
  ret : integer;

  b : PBIGNUM;

  new_ctx : PBN_CTX;
  label _err;
begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx;
        if ctx = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
{$ENDIF}
    BN_CTX_start(ctx);
    b := BN_CTX_get(ctx);
    if b = nil then goto _err ;
    if 0>= BN_GF2m_mod_arr(b, group.b, @group.poly) then
        goto _err ;
    {
     * check the discriminant: y^2 + x*y = x^3 + a*x^2 + b is an elliptic
     * curve <=> b <> 0 (mod p)
     }
    if BN_is_zero(b) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;


function ossl_ec_GF2m_simple_point_init( point : PEC_POINT):integer;
begin
    point.X := BN_new();
    point.Y := BN_new();
    point.Z := BN_new();
    if (point.X = nil)  or  (point.Y = nil)  or  (point.Z = nil) then
    begin
        BN_free(point.X);
        BN_free(point.Y);
        BN_free(point.Z);
        Exit(0);
    end;
    Result := 1;
end;


procedure ossl_ec_GF2m_simple_point_finish( point : PEC_POINT);
begin
    BN_free(point.X);
    BN_free(point.Y);
    BN_free(point.Z);
end;


procedure ossl_ec_GF2m_simple_point_clear_finish( point : PEC_POINT);
begin
    BN_clear_free(point.X);
    BN_clear_free(point.Y);
    BN_clear_free(point.Z);
    point.Z_is_one := 0;
end;


function ossl_ec_GF2m_simple_point_copy(dest : PEC_POINT;const src : PEC_POINT):integer;
begin
    if nil = BN_copy(dest.X, src.X) then
        Exit(0);
    if nil = BN_copy(dest.Y, src.Y) then
        Exit(0);
    if nil = BN_copy(dest.Z, src.Z) then
        Exit(0);
    dest.Z_is_one := src.Z_is_one;
    dest.curve_name := src.curve_name;
    Result := 1;
end;


function ossl_ec_GF2m_simple_point_set_to_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
begin
    point.Z_is_one := 0;
    BN_zero(point.Z);
    Result := 1;
end;


function ossl_ec_GF2m_simple_point_set_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x, y : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
  label _err;
begin
    ret := 0;
    if (x = nil)  or  (y = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if nil = BN_copy(point.X, x) then
        goto _err ;
    BN_set_negative(point.X, 0);
    if nil = BN_copy(point.Y, y) then
        goto _err ;
    BN_set_negative(point.Y, 0);
    if nil = BN_copy(point.Z, BN_value_one) then
        goto _err ;
    BN_set_negative(point.Z, 0);
    point.Z_is_one := 1;
    ret := 1;
 _err:
    Result := ret;
end;


function ossl_ec_GF2m_simple_point_get_affine_coordinates(const group : PEC_GROUP;const point : PEC_POINT; x, y : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
  label _err;
begin
    ret := 0;
    if EC_POINT_is_at_infinity(group, point)>0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        Exit(0);
    end;
    if BN_cmp(point.Z, BN_value_one) > 0 then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if x <> nil then
    begin
        if nil = BN_copy(x, point.X) then
            goto _err ;
        BN_set_negative(x, 0);
    end;
    if y <> nil then
    begin
        if nil = BN_copy(y, point.Y) then
            goto _err ;
        BN_set_negative(y, 0);
    end;
    ret := 1;
 _err:
    Result := ret;
end;


function ossl_ec_GF2m_simple_add(const group : PEC_GROUP; r : PEC_POINT;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
var
  x0, y0, x1, y1, x2, y2, s, t : PBIGNUM;
  ret : integer;
  new_ctx : PBN_CTX;
  label _err;
begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if EC_POINT_is_at_infinity(group, a) > 0 then
    begin
        if 0>= EC_POINT_copy(r, b) then
            Exit(0);
        Exit(1);
    end;
    if EC_POINT_is_at_infinity(group, b) > 0 then
    begin
        if 0>= EC_POINT_copy(r, a) then
            Exit(0);
        Exit(1);
    end;
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
{$ENDIF}
    BN_CTX_start(ctx);
    x0 := BN_CTX_get(ctx);
    y0 := BN_CTX_get(ctx);
    x1 := BN_CTX_get(ctx);
    y1 := BN_CTX_get(ctx);
    x2 := BN_CTX_get(ctx);
    y2 := BN_CTX_get(ctx);
    s := BN_CTX_get(ctx);
    t := BN_CTX_get(ctx);
    if t = nil then goto _err ;
    if a.Z_is_one > 0 then
    begin
        if nil = BN_copy(x0, a.X) then
            goto _err ;
        if nil = BN_copy(y0, a.Y) then
            goto _err ;
    end
    else
    begin
        if 0 >= EC_POINT_get_affine_coordinates(group, a, x0, y0, ctx) then
            goto _err ;
    end;
    if b.Z_is_one > 0 then
    begin
        if nil = BN_copy(x1, b.X) then
            goto _err ;
        if nil = BN_copy(y1, b.Y) then
            goto _err ;
    end
    else
    begin
        if 0>= EC_POINT_get_affine_coordinates(group, b, x1, y1, ctx) then
            goto _err ;
    end;
    if BN_GF2m_cmp(x0, x1) >0 then
    begin
        if 0>= BN_GF2m_add(t, x0, x1) then
            goto _err ;
        if 0>= BN_GF2m_add(s, y0, y1) then
            goto _err ;
        if 0>= group.meth.field_div(group, s, s, t, ctx) then
            goto _err ;
        if 0>= group.meth.field_sqr(group, x2, s, ctx) then
            goto _err ;
        if 0>= BN_GF2m_add(x2, x2, group.a) then
            goto _err ;
        if 0>= BN_GF2m_add(x2, x2, s) then
            goto _err ;
        if 0>= BN_GF2m_add(x2, x2, t) then
            goto _err ;
    end
    else
    begin
        if (BN_GF2m_cmp(y0, y1)>0)  or  (BN_is_zero(x1)) then
        begin
            if 0>= EC_POINT_set_to_infinity(group, r) then
                goto _err ;
            ret := 1;
            goto _err ;
        end;
        if 0>= group.meth.field_div(group, s, y1, x1, ctx) then
            goto _err ;
        if 0>= BN_GF2m_add(s, s, x1) then
            goto _err ;
        if 0>= group.meth.field_sqr(group, x2, s, ctx) then
            goto _err ;
        if 0>= BN_GF2m_add(x2, x2, s) then
            goto _err ;
        if 0>= BN_GF2m_add(x2, x2, group.a) then
            goto _err ;
    end;
    if 0>= BN_GF2m_add(y2, x1, x2) then
        goto _err ;
    if 0>= group.meth.field_mul(group, y2, y2, s, ctx) then
        goto _err ;
    if 0>= BN_GF2m_add(y2, y2, x2) then
        goto _err ;
    if 0>= BN_GF2m_add(y2, y2, y1) then
        goto _err ;
    if 0>= EC_POINT_set_affine_coordinates(group, r, x2, y2, ctx) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;


function ossl_ec_GF2m_simple_dbl(const group : PEC_GROUP; r : PEC_POINT;const a : PEC_POINT; ctx : PBN_CTX):integer;
begin
    Result := ossl_ec_GF2m_simple_add(group, r, a, a, ctx);
end;


function ossl_ec_GF2m_simple_invert(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if (EC_POINT_is_at_infinity(group, point)>0) or ( BN_is_zero(point.Y)) then
        { point is its own inverse }
        Exit(1);
    if (not Assigned(group.meth.make_affine))
         or  (0>= group.meth.make_affine(group, point, ctx)) then
        Exit(0);
    Result := BN_GF2m_add(point.Y, point.X, point.Y);
end;


function ossl_ec_GF2m_simple_is_at_infinity(const group : PEC_GROUP;const point : PEC_POINT):integer;
begin
    Result := Int(BN_is_zero(point.Z));
end;


function ossl_ec_GF2m_simple_is_on_curve(const group : PEC_GROUP;const point : PEC_POINT; ctx : PBN_CTX):integer;
var
  ret : integer;

  lh, y2 : PBIGNUM;

  new_ctx : PBN_CTX;
  field_mul: Tfield_mul_func;
  field_sqr: Tfield_sqr_func;
  label _err;
begin
    ret := -1;

{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if EC_POINT_is_at_infinity(group, point) > 0 then
        Exit(1);
    field_mul := group.meth.field_mul;
    field_sqr := group.meth.field_sqr;
    { only support affine coordinates }
    if 0>= point.Z_is_one then Exit(-1);
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx;
        if ctx = nil then Exit(-1);
    end;
{$ENDIF}
    BN_CTX_start(ctx);
    y2 := BN_CTX_get(ctx);
    lh := BN_CTX_get(ctx);
    if lh = nil then goto _err ;
    {-
     * We have a curve defined by a Weierstrass equation
     *      y^2 + x*y = x^3 + a*x^2 + b.
     *  <=> x^3 + a*x^2 + x*y + b + y^2 = 0
     *  <=> ((x + a) * x + y) * x + b + y^2 = 0
     }
    if 0>= BN_GF2m_add(lh, point.X, group.a) then
        goto _err ;
    if 0>= field_mul(group, lh, lh, point.X, ctx) then
        goto _err ;
    if 0>= BN_GF2m_add(lh, lh, point.Y) then
        goto _err ;
    if 0>= field_mul(group, lh, lh, point.X, ctx) then
        goto _err ;
    if 0>= BN_GF2m_add(lh, lh, group.b) then
        goto _err ;
    if 0>= field_sqr(group, y2, point.Y, ctx) then
        goto _err ;
    if 0>= BN_GF2m_add(lh, lh, y2) then
        goto _err ;
    ret := Int(BN_is_zero(lh));
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;


function ossl_ec_GF2m_simple_cmp(const group : PEC_GROUP;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
var
  aX, aY, bX, bY : PBIGNUM;

  ret : integer;

  new_ctx : PBN_CTX;
  label _err;
begin
    ret := -1;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if EC_POINT_is_at_infinity(group, a) > 0 then
    begin
        Exit(get_result( EC_POINT_is_at_infinity(group, b) > 0, 0 , 1));
    end;
    if EC_POINT_is_at_infinity(group, b) > 0 then
        Exit(1);
    if (a.Z_is_one > 0)  and  (b.Z_is_one > 0) then
    begin
        Exit(get_result(( (BN_cmp(a.X, b.X) = 0)  and  (BN_cmp(a.Y, b.Y) = 0) ) , 0 , 1));
    end;
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx;
        if ctx = nil then Exit(-1);
    end;
{$ENDIF}
    BN_CTX_start(ctx);
    aX := BN_CTX_get(ctx);
    aY := BN_CTX_get(ctx);
    bX := BN_CTX_get(ctx);
    bY := BN_CTX_get(ctx);
    if bY = nil then goto _err ;
    if 0>= EC_POINT_get_affine_coordinates(group, a, aX, aY, ctx) then
        goto _err ;
    if 0>= EC_POINT_get_affine_coordinates(group, b, bX, bY, ctx) then
        goto _err ;
    ret := get_result( (BN_cmp(aX, bX) = 0)  and  (BN_cmp(aY, bY) = 0) , 0 , 1);
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;


function ossl_ec_GF2m_simple_make_affine(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
var
  x, y : PBIGNUM;

  ret : integer;

  new_ctx : PBN_CTX;
  label _err;
begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if (point.Z_is_one>0)  or  (EC_POINT_is_at_infinity(group, point)>0) then
        Exit(1);
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
{$ENDIF}
    BN_CTX_start(ctx);
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    if y = nil then goto _err ;
    if 0>= EC_POINT_get_affine_coordinates(group, point, x, y, ctx) then
        goto _err ;
    if nil = BN_copy(point.X, x) then
        goto _err ;
    if nil = BN_copy(point.Y, y) then
        goto _err ;
    if 0 >= BN_one(point.Z) then
        goto _err ;
    point.Z_is_one := 1;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;


function ossl_ec_GF2m_simple_points_make_affine(const group : PEC_GROUP; num : size_t; points : PPEC_POINT; ctx : PBN_CTX):integer;
var
  i : size_t;
begin
{$POINTERMATH ON}
    for i := 0 to num-1 do
    begin
        if 0>= group.meth.make_affine(group, points[i], ctx) then
            Exit(0);
    end;
    Result := 1;
{$POINTERMATH OFF}
end;


function ossl_ec_GF2m_simple_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
begin
    Result := BN_GF2m_mod_mul_arr(r, a, b, @group.poly, ctx);
end;


function ossl_ec_GF2m_simple_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
begin
    Result := BN_GF2m_mod_sqr_arr(r, a, @group.poly, ctx);
end;


function ossl_ec_GF2m_simple_field_div(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
begin
    Result := BN_GF2m_mod_div(r, a, b, group.field, ctx);
end;


function ec_GF2m_simple_ladder_pre(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
begin
    { if p is not affine, something is wrong }
    if p.Z_is_one = 0 then Exit(0);
    { s blinding: make sure lambda (s.Z here) is not zero }
    while (BN_is_zero(s.Z)) do
    begin
        if 0>= BN_priv_rand_ex(s.Z, BN_num_bits(group.field) - 1,
                             BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx)  then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            Exit(0);
        end;
    end;

    { if field_encode defined convert between representations }
    if (Assigned(group.meth.field_encode) )
         and (0>= group.meth.field_encode(group, s.Z, s.Z, ctx))
         or  (0>= group.meth.field_mul(group, s.X, p.X, s.Z, ctx)) then
        Exit(0);
    { r blinding: make sure lambda (r.Y here for storage) is not zero }
     while (BN_is_zero(r.Y)) do
     begin
        if 0>= BN_priv_rand_ex(r.Y, BN_num_bits(group.field) - 1,
                             BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx)  then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            Exit(0);
        end;
    end;

    if ( (Assigned(group.meth.field_encode))
          and  (0>= group.meth.field_encode(group, r.Y, r.Y, ctx)) )
         or  (0>= group.meth.field_sqr(group, r.Z, p.X, ctx))
         or  (0>= group.meth.field_sqr(group, r.X, r.Z, ctx))
         or  (0>= BN_GF2m_add(r.X, r.X, group.b))
         or  (0>= group.meth.field_mul(group, r.Z, r.Z, r.Y, ctx))
         or  (0>= group.meth.field_mul(group, r.X, r.X, r.Y, ctx))  then
        Exit(0);
    s.Z_is_one := 0;
    r.Z_is_one := 0;
    Result := 1;
end;


function ec_GF2m_simple_ladder_step(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if (0>= group.meth.field_mul(group, r.Y, r.Z, s.X, ctx))
         or  (0>= group.meth.field_mul(group, s.X, r.X, s.Z, ctx))
         or  (0>= group.meth.field_sqr(group, s.Y, r.Z, ctx))
         or  (0>= group.meth.field_sqr(group, r.Z, r.X, ctx))
         or  (0>= BN_GF2m_add(s.Z, r.Y, s.X))
         or  (0>= group.meth.field_sqr(group, s.Z, s.Z, ctx))
         or  (0>= group.meth.field_mul(group, s.X, r.Y, s.X, ctx))
         or  (0>= group.meth.field_mul(group, r.Y, s.Z, p.X, ctx))
         or  (0>= BN_GF2m_add(s.X, s.X, r.Y))
         or  (0>= group.meth.field_sqr(group, r.Y, r.Z, ctx))
         or  (0>= group.meth.field_mul(group, r.Z, r.Z, s.Y, ctx))
         or  (0>= group.meth.field_sqr(group, s.Y, s.Y, ctx))
         or  (0>= group.meth.field_mul(group, s.Y, s.Y, group.b, ctx))
         or  (0>= BN_GF2m_add(r.X, r.Y, s.Y)) then
        Exit(0);
    Result := 1;
end;


function ec_GF2m_simple_ladder_post(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
var
  ret : integer;
  t0, t1, t2 : PBIGNUM;
  label _err;
begin
    ret := 0;
    t2 := nil;
    if BN_is_zero(r.Z) then
        Exit(EC_POINT_set_to_infinity(group, r));
    if BN_is_zero(s.Z) then
    begin
        if (0>= EC_POINT_copy(r, p))
             or  (0>= EC_POINT_invert(group, r, ctx))  then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            Exit(0);
        end;
        Exit(1);
    end;
    BN_CTX_start(ctx);
    t0 := BN_CTX_get(ctx);
    t1 := BN_CTX_get(ctx);
    t2 := BN_CTX_get(ctx);
    if t2 = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if (0>= group.meth.field_mul(group, t0, r.Z, s.Z, ctx))
         or  (0>= group.meth.field_mul(group, t1, p.X, r.Z, ctx))
         or  (0>= BN_GF2m_add(t1, r.X, t1))
         or  (0>= group.meth.field_mul(group, t2, p.X, s.Z, ctx))
         or  (0>= group.meth.field_mul(group, r.Z, r.X, t2, ctx))
         or  (0>= BN_GF2m_add(t2, t2, s.X))
         or  (0>= group.meth.field_mul(group, t1, t1, t2, ctx))
         or  (0>= group.meth.field_sqr(group, t2, p.X, ctx))
         or  (0>= BN_GF2m_add(t2, p.Y, t2))
         or  (0>= group.meth.field_mul(group, t2, t2, t0, ctx))
         or  (0>= BN_GF2m_add(t1, t2, t1))
         or  (0>= group.meth.field_mul(group, t2, p.X, t0, ctx))
         or  (0>= group.meth.field_inv(group, t2, t2, ctx))
         or  (0>= group.meth.field_mul(group, t1, t1, t2, ctx))
         or  (0>= group.meth.field_mul(group, r.X, r.Z, t2, ctx))
         or  (0>= BN_GF2m_add(t2, p.X, r.X))
         or  (0>= group.meth.field_mul(group, t2, t2, t1, ctx))
         or  (0>= BN_GF2m_add(r.Y, p.Y, t2))
         or  (0>= BN_one(r.Z))  then
        goto _err ;
    r.Z_is_one := 1;
    { GF(2^m) field elements should always have BIGNUM.neg = 0 }
    BN_set_negative(r.X, 0);
    BN_set_negative(r.Y, 0);
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;


function ec_GF2m_simple_points_mul(const group : PEC_GROUP; r : PEC_POINT;const scalar : PBIGNUM; num : size_t;const points : PPEC_POINT;const scalars : PPBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
  t : PEC_POINT;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0;
    t := nil;
    {-
     * We limit use of the ladder only to the following cases:
     * - r := scalar * G
     *   Fixed point mul: scalar <> nil  and  num = 0;
     * - r := scalars[0] * points[0]
     *   Variable point mul: scalar = nil  and  num = 1;
     * - r := scalar * G + scalars[0] * points[0]
     *   used, e.g., in ECDSA verification: scalar <> nil  and  num = 1
     *
     * In any other case (num > 1) we use the default wNAF implementation.
     *
     * We also let the default implementation handle degenerate cases like group
     * order or cofactor set to 0.
     }
    if (num > 1)  or  (BN_is_zero(group.order)) or  (BN_is_zero(group.cofactor))  then
        Exit(ossl_ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx));
    if (scalar <> nil)  and  (num = 0) then { Fixed point multiplication }
        Exit(ossl_ec_scalar_mul_ladder(group, r, scalar, nil, ctx));
    if (scalar = nil)  and  (num = 1) then { Variable point multiplication }
        Exit(ossl_ec_scalar_mul_ladder(group, r, scalars[0], points[0], ctx));
    {-
     * Double point multiplication:
     *  r := scalar * G + scalars[0] * points[0]
     }
    t := EC_POINT_new(group);
    if t  = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if (0>= ossl_ec_scalar_mul_ladder(group, t, scalar, nil, ctx))  or
       (0>= ossl_ec_scalar_mul_ladder(group, r, scalars[0], points[0], ctx))
         or  (0>= EC_POINT_add(group, r, t, r, ctx)) then
        goto _err ;
    ret := 1;
 _err:
    EC_POINT_free(t);
    Result := ret;
{$POINTERMATH OFF}
end;


function ec_GF2m_simple_field_inv(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
    ret := BN_GF2m_mod_inv(r, a, group.field, ctx);
    if 0>= ret then
        ERR_raise(ERR_LIB_EC, EC_R_CANNOT_INVERT);
    Result := ret;
end;


function EC_GF2m_simple_method:PEC_METHOD;
begin
        Result := @ret;
end;

end.
