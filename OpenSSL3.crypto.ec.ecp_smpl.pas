unit OpenSSL3.crypto.ec.ecp_smpl;

interface
uses OpenSSL.Api;

type
  Tfield_mul_func = function (const p1: PEC_GROUP;p2: PBIGNUM; const p3, p4: PBIGNUM ;p5: PBN_CTX  ):int;
  Tfield_sqr_func = function(const p1: PEC_GROUP;p2: PBIGNUM; const p3: PBIGNUM; p4: PBN_CTX  ):int;

  function ossl_ec_GFp_simple_group_init( group : PEC_GROUP):integer;
  procedure ossl_ec_GFp_simple_group_finish( group : PEC_GROUP);
  procedure ossl_ec_GFp_simple_group_clear_finish( group : PEC_GROUP);
  function ossl_ec_GFp_simple_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
  function ossl_ec_GFp_simple_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_group_get_curve(const group : PEC_GROUP; p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_group_get_degree(const group : PEC_GROUP):integer;
  function ossl_ec_GFp_simple_group_check_discriminant(const group : PEC_GROUP; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_point_init( point : PEC_POINT):integer;
  procedure ossl_ec_GFp_simple_point_finish( point : PEC_POINT);
  procedure ossl_ec_GFp_simple_point_clear_finish( point : PEC_POINT);
  function ossl_ec_GFp_simple_point_copy(dest : PEC_POINT;const src : PEC_POINT):integer;
  function ossl_ec_GFp_simple_point_set_to_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
  function ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(const group : PEC_GROUP; point : PEC_POINT;const x, y, z : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp(const group : PEC_GROUP; point : PEC_POINT; x, y, z : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_point_set_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x, y : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_point_get_affine_coordinates(const group : PEC_GROUP; const point : PEC_POINT; x, y : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_add(const group : PEC_GROUP; r : PEC_POINT;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_dbl(const group : PEC_GROUP; r : PEC_POINT;const a : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_invert(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_is_at_infinity(const group : PEC_GROUP; const point : PEC_POINT):integer;
  function ossl_ec_GFp_simple_is_on_curve(const group : PEC_GROUP; const point : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_cmp(const group : PEC_GROUP;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_make_affine(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_points_make_affine(const group : PEC_GROUP; num : size_t; points : PPEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_field_inv(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_blind_coordinates(const group : PEC_GROUP; p : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_ladder_pre(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_ladder_step(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ossl_ec_GFp_simple_ladder_post(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;

implementation

uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_mod, openssl3.crypto.bn.bn_word,
     openssl3.crypto.bn.bn_asm, openssl3.crypto.bn.bn_add,
     openssl3.crypto.mem,  openssl3.crypto.bn.bn_rand,
     openssl3.crypto.bn.bn_gcd, openssl3.providers.fips.fipsprov,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.ec.ec_lib;



procedure ossl_ec_GFp_simple_group_finish( group : PEC_GROUP);
begin
    BN_free(group.field);
    BN_free(group.a);
    BN_free(group.b);
end;


procedure ossl_ec_GFp_simple_group_clear_finish( group : PEC_GROUP);
begin
    BN_clear_free(group.field);
    BN_clear_free(group.a);
    BN_clear_free(group.b);
end;


function ossl_ec_GFp_simple_group_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
begin
    if nil = BN_copy(dest.field, src.field ) then
        Exit(0);
    if nil = BN_copy(dest.a, src.a ) then
        Exit(0);
    if nil = BN_copy(dest.b, src.b ) then
        Exit(0);
    dest.a_is_minus3 := src.a_is_minus3;
    Result := 1;
end;


function ossl_ec_GFp_simple_group_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;

  new_ctx : PBN_CTX;

  tmp_a : PBIGNUM;
  label _err;
begin
    ret := 0;
    new_ctx := nil;
    { p must be a prime > 3 }
    if (BN_num_bits(p) <= 2)  or  (not BN_is_odd(p))  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        Exit(0);
    end;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    BN_CTX_start(ctx);
    tmp_a := BN_CTX_get(ctx);
    if tmp_a = nil then goto _err ;
    { group.field }
    if nil = BN_copy(group.field, p ) then
        goto _err ;
    BN_set_negative(group.field, 0);
    { group.a }
    if 0>= BN_nnmod(tmp_a, a, p, ctx ) then
        goto _err ;
    if Assigned(group.meth.field_encode) then
    begin
        if 0>= group.meth.field_encode(group, group.a, tmp_a, ctx) then
            goto _err ;
    end
    else
    if (nil = BN_copy(group.a, tmp_a)) then
        goto _err ;
    { group.b }
    if 0>= BN_nnmod(group.b, b, p, ctx ) then
        goto _err ;
    if Assigned(group.meth.field_encode) then
       if (0>= group.meth.field_encode(group, group.b, group.b, ctx)) then
            goto _err ;
    { group.a_is_minus3 }
    if 0>= BN_add_word(tmp_a, 3 ) then
        goto _err ;
    group.a_is_minus3 := int(0 = BN_cmp(tmp_a, group.field));
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_group_get_curve(const group : PEC_GROUP; p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;

  new_ctx : PBN_CTX;
  label _err;
begin
    ret := 0;
    new_ctx := nil;
    if p <> nil then
    begin
        if nil = BN_copy(p, group.field) then
            Exit(0);
    end;
    if (a <> nil)  or  (b <> nil) then
    begin
        if Assigned(group.meth.field_decode) then
        begin
            if ctx = nil then
            begin
                new_ctx := BN_CTX_new_ex(group.libctx);
                ctx := new_ctx;
                if ctx = nil then Exit(0);
            end;
            if a <> nil then
            begin
                if 0>= group.meth.field_decode(group, a, group.a, ctx) then
                    goto _err ;
            end;
            if b <> nil then
            begin
                if 0>= group.meth.field_decode(group, b, group.b, ctx) then
                    goto _err ;
            end;
        end
        else
        begin
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
        end;
    end;
    ret := 1;
 _err:
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_group_get_degree(const group : PEC_GROUP):integer;
begin
    Result := BN_num_bits(group.field);
end;


function ossl_ec_GFp_simple_group_check_discriminant(const group : PEC_GROUP; ctx : PBN_CTX):integer;
var
  ret : integer;

  a, b, order, tmp_1, tmp_2, p : PBIGNUM;

  new_ctx : PBN_CTX;
  label _err;
begin
    ret := 0;
    p := group.field;
    new_ctx := nil;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    BN_CTX_start(ctx);
    a := BN_CTX_get(ctx);
    b := BN_CTX_get(ctx);
    tmp_1 := BN_CTX_get(ctx);
    tmp_2 := BN_CTX_get(ctx);
    order := BN_CTX_get(ctx);
    if order = nil then goto _err ;
    if Assigned(group.meth.field_decode) then
    begin
        if 0>= group.meth.field_decode(group, a, group.a, ctx) then
            goto _err ;
        if 0>= group.meth.field_decode(group, b, group.b, ctx ) then
            goto _err ;
    end
    else
    begin
        if nil = BN_copy(a, group.a ) then
            goto _err ;
        if nil = BN_copy(b, group.b ) then
            goto _err ;
    end;
    {-
     * check the discriminant:
     * y^2 = x^3 + a*x + b is an elliptic curve <=> 4*a^3 + 27*b^2 <> 0 (mod p)
     * 0 =< a, b < p
     }
    if BN_is_zero(a ) then
    begin
        if BN_is_zero(b) then
            goto _err ;
    end
    else
    if (not BN_is_zero(b)) then
    begin
        if 0>= BN_mod_sqr(tmp_1, a, p, ctx ) then
            goto _err ;
        if 0>= BN_mod_mul(tmp_2, tmp_1, a, p, ctx ) then
            goto _err ;
        if 0>= BN_lshift(tmp_1, tmp_2, 2 ) then
            goto _err ;
        { tmp_1 = 4*a^3 }
        if 0>= BN_mod_sqr(tmp_2, b, p, ctx ) then
            goto _err ;
        if 0>= BN_mul_word(tmp_2, 27 ) then
            goto _err ;
        { tmp_2 = 27*b^2 }
        if 0>= BN_mod_add(a, tmp_1, tmp_2, p, ctx ) then
            goto _err ;
        if BN_is_zero(a ) then
            goto _err ;
    end;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_point_init( point : PEC_POINT):integer;
begin
    point.X := BN_new();
    point.Y := BN_new();
    point.Z := BN_new();
    point.Z_is_one := 0;
    if (point.X = nil)  or  (point.Y = nil)  or  (point.Z = nil) then
    begin
        BN_free(point.X);
        BN_free(point.Y);
        BN_free(point.Z);
        Exit(0);
    end;
    Result := 1;
end;


procedure ossl_ec_GFp_simple_point_finish( point : PEC_POINT);
begin
    BN_free(point.X);
    BN_free(point.Y);
    BN_free(point.Z);
end;


procedure ossl_ec_GFp_simple_point_clear_finish( point : PEC_POINT);
begin
    BN_clear_free(point.X);
    BN_clear_free(point.Y);
    BN_clear_free(point.Z);
    point.Z_is_one := 0;
end;


function ossl_ec_GFp_simple_point_copy(dest : PEC_POINT;const src : PEC_POINT):integer;
begin
    if nil = BN_copy(dest.X, src.X ) then
        Exit(0);
    if nil = BN_copy(dest.Y, src.Y ) then
        Exit(0);
    if nil = BN_copy(dest.Z, src.Z ) then
        Exit(0);
    dest.Z_is_one := src.Z_is_one;
    dest.curve_name := src.curve_name;
    Result := 1;
end;


function ossl_ec_GFp_simple_point_set_to_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
begin
    point.Z_is_one := 0;
    BN_zero(point.Z);
    Result := 1;
end;


function ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(const group : PEC_GROUP; point : PEC_POINT;const x, y, z : PBIGNUM; ctx : PBN_CTX):integer;
var
  new_ctx  : PBN_CTX;
  ret,
  Z_is_one : integer;
  label _err;
begin
    new_ctx := nil;
    ret := 0;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    if x <> nil then
    begin
        if 0>= BN_nnmod(point.X, x, group.field, ctx) then
            goto _err ;
        if Assigned(group.meth.field_encode) then
        begin
            if 0>= group.meth.field_encode(group, point.X, point.X, ctx) then
                goto _err ;
        end;
    end;
    if y <> nil then
    begin
        if 0>= BN_nnmod(point.Y, y, group.field, ctx) then
            goto _err ;
        if Assigned(group.meth.field_encode) then
        begin
            if 0>= group.meth.field_encode(group, point.Y, point.Y, ctx) then
                goto _err ;
        end;
    end;
    if z <> nil then
    begin
        if 0>= BN_nnmod(point.Z, z, group.field, ctx) then
            goto _err ;
        Z_is_one := Int(BN_is_one(point.Z));
        if Assigned(group.meth.field_encode) then
        begin
            if (Z_is_one>0)  and  (Assigned(group.meth.field_set_to_one)) then
            begin
                if 0>= group.meth.field_set_to_one(group, point.Z, ctx) then
                    goto _err ;
            end
            else
            begin
                if 0>= group.meth.field_encode(group, point.Z, point.Z, ctx ) then
                    goto _err ;
            end;
        end;
        point.Z_is_one := Z_is_one;
    end;
    ret := 1;
 _err:
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp(const group : PEC_GROUP; point : PEC_POINT; x, y, z : PBIGNUM; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;

  ret : integer;
  label _err;
begin
    new_ctx := nil;
    ret := 0;
    if Assigned(group.meth.field_decode) then
    begin
        if ctx = nil then
        begin
            new_ctx := BN_CTX_new_ex(group.libctx);
            ctx := new_ctx;
            if ctx = nil then Exit(0);
        end;
        if x <> nil then
        begin
            if 0>= group.meth.field_decode(group, x, point.X, ctx) then
                goto _err ;
        end;
        if y <> nil then
        begin
            if 0>= group.meth.field_decode(group, y, point.Y, ctx) then
                goto _err ;
        end;
        if z <> nil then
        begin
            if 0>= group.meth.field_decode(group, z, point.Z, ctx) then
                goto _err ;
        end;
    end
    else
    begin
        if x <> nil then
        begin
            if nil = BN_copy(x, point.X) then
                goto _err ;
        end;
        if y <> nil then
        begin
            if nil = BN_copy(y, point.Y) then
                goto _err ;
        end;
        if z <> nil then
        begin
            if nil = BN_copy(z, point.Z) then
                goto _err ;
        end;
    end;
    ret := 1;
 _err:
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_point_set_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x, y : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if (x = nil)  or  (y = nil) then
    begin
        {
         * unlike for projective coordinates, we do not tolerate this
         }
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Exit(EC_POINT_set_Jprojective_coordinates_GFp(group, point, x, y,
                                                    BN_value_one(), ctx));
end;


function ossl_ec_GFp_simple_point_get_affine_coordinates(const group : PEC_GROUP; const point : PEC_POINT; x, y : PBIGNUM; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;

  Z, Z_1, Z_2, Z_3, Z_ : PBIGNUM;

  ret : integer;
  label _err;
begin
    new_ctx := nil;
    ret := 0;
    if EC_POINT_is_at_infinity(group, point )>0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        Exit(0);
    end;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    BN_CTX_start(ctx);
    Z := BN_CTX_get(ctx);
    Z_1 := BN_CTX_get(ctx);
    Z_2 := BN_CTX_get(ctx);
    Z_3 := BN_CTX_get(ctx);
    if Z_3 = nil then goto _err ;
    { transform  (X, Y, Z)  into  (x, y) := (X/Z^2, Y/Z^3) }
    if Assigned(group.meth.field_decode) then
    begin
        if 0>= group.meth.field_decode(group, Z, point.Z, ctx) then
            goto _err ;
        Z_ := Z;
    end
    else
    begin
        Z_ := point.Z;
    end;
    if BN_is_one(Z_ ) then
    begin
        if Assigned(group.meth.field_decode) then
        begin
            if x <> nil then
            begin
                if 0>= group.meth.field_decode(group, x, point.X, ctx) then
                    goto _err ;
            end;
            if y <> nil then
            begin
                if 0>= group.meth.field_decode(group, y, point.Y, ctx) then
                    goto _err ;
            end;
        end
        else
        begin
            if x <> nil then
            begin
                if nil = BN_copy(x, point.X) then
                    goto _err ;
            end;
            if y <> nil then begin
                if nil = BN_copy(y, point.Y) then
                    goto _err ;
            end;
        end;
    end
    else
    begin
        if 0>= group.meth.field_inv(group, Z_1, Z_, ctx ) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto _err ;
        end;
        if not Assigned(group.meth.field_encode) then
        begin
            { field_sqr works on standard representation }
            if 0>= group.meth.field_sqr(group, Z_2, Z_1, ctx) then
                goto _err ;
        end
        else
        begin
            if 0>= BN_mod_sqr(Z_2, Z_1, group.field, ctx ) then
                goto _err ;
        end;
        if x <> nil then
        begin
            {
             * in the Montgomery case, field_mul will cancel out Montgomery
             * factor in X:
             }
            if 0>= group.meth.field_mul(group, x, point.X, Z_2, ctx) then
                goto _err ;
        end;
        if y <> nil then
        begin
            if not Assigned(group.meth.field_encode) then
            begin
                {
                 * field_mul works on standard representation
                 }
                if 0>= group.meth.field_mul(group, Z_3, Z_2, Z_1, ctx) then
                    goto _err ;
            end
            else
            begin
                if 0>= BN_mod_mul(Z_3, Z_2, Z_1, group.field, ctx ) then
                    goto _err ;
            end;
            {
             * in the Montgomery case, field_mul will cancel out Montgomery
             * factor in Y:
             }
            if 0>= group.meth.field_mul(group, y, point.Y, Z_3, ctx ) then
                goto _err ;
        end;
    end;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_add(const group : PEC_GROUP; r : PEC_POINT;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
var
  p : PBIGNUM;
  new_ctx : PBN_CTX;
  n0, n1, n2, n3, n4, n5, n6 : PBIGNUM;
  ret : integer;
  field_mul: Tfield_mul_func;
  field_sqr: Tfield_sqr_func;
  label _end;
begin

    new_ctx := nil;
    ret := 0;
    if a = b then Exit(EC_POINT_dbl(group, r, a, ctx));
    if EC_POINT_is_at_infinity(group, a )>0 then
        Exit(EC_POINT_copy(r, b));
    if EC_POINT_is_at_infinity(group, b ) >0 then
        Exit(EC_POINT_copy(r, a));
    field_mul := group.meth.field_mul;
    field_sqr := group.meth.field_sqr;
    p := group.field;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    BN_CTX_start(ctx);
    n0 := BN_CTX_get(ctx);
    n1 := BN_CTX_get(ctx);
    n2 := BN_CTX_get(ctx);
    n3 := BN_CTX_get(ctx);
    n4 := BN_CTX_get(ctx);
    n5 := BN_CTX_get(ctx);
    n6 := BN_CTX_get(ctx);
    if n6 = nil then goto _end ;
    {
     * Note that in this function we must not read components of 'a' or 'b'
     * once we have written the corresponding components of 'r'. ('r' might
     * be one of 'a' or 'b'.)
     }
    { n1, n2 }
    if b.Z_is_one > 0 then
    begin
        if nil = BN_copy(n1, a.X) then
            goto _end ;
        if nil = BN_copy(n2, a.Y ) then
            goto _end ;
        { n1 = X_a }
        { n2 = Y_a }
    end
    else
    begin
        if 0>= field_sqr(group, n0, b.Z, ctx ) then
            goto _end ;
        if 0>= field_mul(group, n1, a.X, n0, ctx ) then
            goto _end ;
        { n1 = X_a * Z_b^2 }
        if 0>= field_mul(group, n0, n0, b.Z, ctx ) then
            goto _end ;
        if 0>= field_mul(group, n2, a.Y, n0, ctx ) then
            goto _end ;
        { n2 = Y_a * Z_b^3 }
    end;
    { n3, n4 }
    if a.Z_is_one > 0 then
    begin
        if nil = BN_copy(n3, b.X) then
            goto _end ;
        if nil = BN_copy(n4, b.Y ) then
            goto _end ;
        { n3 = X_b }
        { n4 = Y_b }
    end
    else
    begin
        if 0>= field_sqr(group, n0, a.Z, ctx ) then
            goto _end ;
        if 0>= field_mul(group, n3, b.X, n0, ctx ) then
            goto _end ;
        { n3 = X_b * Z_a^2 }
        if 0>= field_mul(group, n0, n0, a.Z, ctx ) then
            goto _end ;
        if 0>= field_mul(group, n4, b.Y, n0, ctx ) then
            goto _end ;
        { n4 = Y_b * Z_a^3 }
    end;
    { n5, n6 }
    if 0>= BN_mod_sub_quick(n5, n1, n3, p ) then
        goto _end ;
    if 0>= BN_mod_sub_quick(n6, n2, n4, p ) then
        goto _end ;
    { n5 = n1 - n3 }
    { n6 = n2 - n4 }
    if BN_is_zero(n5 ) then
    begin
        if BN_is_zero(n6) then
        begin
            { a is the same point as b }
            BN_CTX_end(ctx);
            ret := EC_POINT_dbl(group, r, a, ctx);
            ctx := nil;
            goto _end ;
        end
        else
        begin
            { a is the inverse of b }
            BN_zero(r.Z);
            r.Z_is_one := 0;
            ret := 1;
            goto _end ;
        end;
    end;
    { 'n7', 'n8' }
    if 0>= BN_mod_add_quick(n1, n1, n3, p ) then
        goto _end ;
    if 0>= BN_mod_add_quick(n2, n2, n4, p ) then
        goto _end ;
    { 'n7' = n1 + n3 }
    { 'n8' = n2 + n4 }
    { Z_r }
    if (a.Z_is_one > 0)  and  (b.Z_is_one > 0 ) then
    begin
        if nil = BN_copy(r.Z, n5) then
            goto _end ;
    end
    else
    begin
        if a.Z_is_one > 0 then
        begin
            if nil = BN_copy(n0, b.Z) then
                goto _end ;
        end
        else
        if (b.Z_is_one>0) then
        begin
            if nil = BN_copy(n0, a.Z ) then
                goto _end ;
        end
        else
        begin
            if 0>= field_mul(group, n0, a.Z, b.Z, ctx ) then
                goto _end ;
        end;
        if 0>= field_mul(group, r.Z, n0, n5, ctx ) then
            goto _end ;
    end;
    r.Z_is_one := 0;
    { Z_r = Z_a * Z_b * n5 }
    { X_r }
    if 0>= field_sqr(group, n0, n6, ctx ) then
        goto _end ;
    if 0>= field_sqr(group, n4, n5, ctx ) then
        goto _end ;
    if 0>= field_mul(group, n3, n1, n4, ctx ) then
        goto _end ;
    if 0>= BN_mod_sub_quick(r.X, n0, n3, p ) then
        goto _end ;
    { X_r = n6^2 - n5^2 * 'n7' }
    { 'n9' }
    if 0>= BN_mod_lshift1_quick(n0, r.X, p ) then
        goto _end ;
    if 0>= BN_mod_sub_quick(n0, n3, n0, p ) then
        goto _end ;
    { n9 = n5^2 * 'n7' - 2 * X_r }
    { Y_r }
    if 0>= field_mul(group, n0, n0, n6, ctx ) then
        goto _end ;
    if 0>= field_mul(group, n5, n4, n5, ctx ) then
        goto _end ;               { now n5 is n5^3 }
    if 0>= field_mul(group, n1, n2, n5, ctx ) then
        goto _end ;
    if 0>= BN_mod_sub_quick(n0, n0, n1, p ) then
        goto _end ;
    if BN_is_odd(n0 ) then
        if 0>= BN_add(n0, n0, p) then
            goto _end ;
    { now  0 <= n0 < 2*p,  and n0 is even }
    if 0>= BN_rshift1(r.Y, n0 ) then
        goto _end ;
    { Y_r = (n6 * 'n9' - 'n8' * 'n5^3') / 2 }
    ret := 1;
 _end:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_dbl(const group : PEC_GROUP; r : PEC_POINT;const a : PEC_POINT; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;

  p, n0, n1, n2, n3 : PBIGNUM;

  ret : integer;
  field_mul: Tfield_mul_func;
  field_sqr: Tfield_sqr_func;
  label _err;
begin
   
    new_ctx := nil;
    ret := 0;
    if EC_POINT_is_at_infinity(group, a ) > 0 then
    begin
        BN_zero(r.Z);
        r.Z_is_one := 0;
        Exit(1);
    end;
    field_mul := group.meth.field_mul;
    field_sqr := group.meth.field_sqr;
    p := group.field;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    BN_CTX_start(ctx);
    n0 := BN_CTX_get(ctx);
    n1 := BN_CTX_get(ctx);
    n2 := BN_CTX_get(ctx);
    n3 := BN_CTX_get(ctx);
    if n3 = nil then goto _err ;
    {
     * Note that in this function we must not read components of 'a' once we
     * have written the corresponding components of 'r'. ('r' might the same
     * as 'a'.)
     }
    { n1 }
    if a.Z_is_one > 0 then
    begin
        if 0>= field_sqr(group, n0, a.X, ctx) then
            goto _err ;
        if 0>= BN_mod_lshift1_quick(n1, n0, p ) then
            goto _err ;
        if 0>= BN_mod_add_quick(n0, n0, n1, p ) then
            goto _err ;
        if 0>= BN_mod_add_quick(n1, n0, group.a, p ) then
            goto _err ;
        { n1 = 3 * X_a^2 + a_curve }
    end
    else
    if (group.a_is_minus3>0) then
    begin
        if 0>= field_sqr(group, n1, a.Z, ctx ) then
            goto _err ;
        if 0>= BN_mod_add_quick(n0, a.X, n1, p ) then
            goto _err ;
        if 0>= BN_mod_sub_quick(n2, a.X, n1, p ) then
            goto _err ;
        if 0>= field_mul(group, n1, n0, n2, ctx ) then
            goto _err ;
        if 0>= BN_mod_lshift1_quick(n0, n1, p ) then
            goto _err ;
        if 0>= BN_mod_add_quick(n1, n0, n1, p ) then
            goto _err ;
        {-
         * n1 = 3 * (X_a + Z_a^2) * (X_a - Z_a^2)
         *    = 3 * X_a^2 - 3 * Z_a^4
         }
    end
    else
    begin
        if 0>= field_sqr(group, n0, a.X, ctx ) then
            goto _err ;
        if 0>= BN_mod_lshift1_quick(n1, n0, p ) then
            goto _err ;
        if 0>= BN_mod_add_quick(n0, n0, n1, p ) then
            goto _err ;
        if 0>= field_sqr(group, n1, a.Z, ctx ) then
            goto _err ;
        if 0>= field_sqr(group, n1, n1, ctx ) then
            goto _err ;
        if 0>= field_mul(group, n1, n1, group.a, ctx ) then
            goto _err ;
        if 0>= BN_mod_add_quick(n1, n1, n0, p ) then
            goto _err ;
        { n1 = 3 * X_a^2 + a_curve * Z_a^4 }
    end;
    { Z_r }
    if a.Z_is_one > 0 then
    begin
        if nil = BN_copy(n0, a.Y) then
            goto _err ;
    end
    else
    begin
        if 0>= field_mul(group, n0, a.Y, a.Z, ctx ) then
            goto _err ;
    end;
    if 0>= BN_mod_lshift1_quick(r.Z, n0, p ) then
        goto _err ;
    r.Z_is_one := 0;
    { Z_r = 2 * Y_a * Z_a }
    { n2 }
    if 0>= field_sqr(group, n3, a.Y, ctx ) then
        goto _err ;
    if 0>= field_mul(group, n2, a.X, n3, ctx ) then
        goto _err ;
    if 0>= BN_mod_lshift_quick(n2, n2, 2, p ) then
        goto _err ;
    { n2 = 4 * X_a * Y_a^2 }
    { X_r }
    if 0>= BN_mod_lshift1_quick(n0, n2, p ) then
        goto _err ;
    if 0>= field_sqr(group, r.X, n1, ctx ) then
        goto _err ;
    if 0>= BN_mod_sub_quick(r.X, r.X, n0, p ) then
        goto _err ;
    { X_r = n1^2 - 2 * n2 }
    { n3 }
    if 0>= field_sqr(group, n0, n3, ctx ) then
        goto _err ;
    if 0>= BN_mod_lshift_quick(n3, n0, 3, p ) then
        goto _err ;
    { n3 = 8 * Y_a^4 }
    { Y_r }
    if 0>= BN_mod_sub_quick(n0, n2, r.X, p ) then
        goto _err ;
    if 0>= field_mul(group, n0, n1, n0, ctx ) then
        goto _err ;
    if 0>= BN_mod_sub_quick(r.Y, n0, n3, p ) then
        goto _err ;
    { Y_r = n1 * (n2 - X_r) - n3 }
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_invert(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if (EC_POINT_is_at_infinity(group, point)>0)  or ( BN_is_zero(point.Y)) then
        { point is its own inverse }
        Exit(1);
    Result := BN_usub(point.Y, group.field, point.Y);
end;


function ossl_ec_GFp_simple_is_at_infinity(const group : PEC_GROUP;const point : PEC_POINT):integer;
begin
    Result := Int(BN_is_zero(point.Z));
end;


function ossl_ec_GFp_simple_is_on_curve(const group : PEC_GROUP; const point : PEC_POINT; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;

  p, rh, tmp, Z4, Z6 : PBIGNUM;

  ret : integer;
  field_mul: Tfield_mul_func;
  field_sqr: Tfield_sqr_func;
  label _err;
begin
   
    new_ctx := nil;
    ret := -1;
    if EC_POINT_is_at_infinity(group, point ) >0 then
        Exit(1);
    field_mul := group.meth.field_mul;
    field_sqr := group.meth.field_sqr;
    p := group.field;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(-1);
    end;
    BN_CTX_start(ctx);
    rh := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    Z4 := BN_CTX_get(ctx);
    Z6 := BN_CTX_get(ctx);
    if Z6 = nil then goto _err ;
    {-
     * We have a curve defined by a Weierstrass equation
     *      y^2 = x^3 + a*x + b.
     * The point to consider is given in Jacobian projective coordinates
     * where  (X, Y, Z)  represents  (x, y) = (X/Z^2, Y/Z^3).
     * Substituting this and multiplying by  Z^6  transforms the above equation into
     *      Y^2 = X^3 + a*X*Z^4 + b*Z^6.
     * To test this, we add up the right-hand side in 'rh'.
     }
    { rh := X^2 }
    if 0>= field_sqr(group, rh, point.X, ctx ) then
        goto _err ;
    if 0>= point.Z_is_one then begin
        if 0>= field_sqr(group, tmp, point.Z, ctx) then
            goto _err ;
        if 0>= field_sqr(group, Z4, tmp, ctx ) then
            goto _err ;
        if 0>= field_mul(group, Z6, Z4, tmp, ctx ) then
            goto _err ;
        { rh := (rh + a*Z^4)*X }
        if group.a_is_minus3 > 0 then
        begin
            if 0>= BN_mod_lshift1_quick(tmp, Z4, p) then
                goto _err ;
            if 0>= BN_mod_add_quick(tmp, tmp, Z4, p ) then
                goto _err ;
            if 0>= BN_mod_sub_quick(rh, rh, tmp, p ) then
                goto _err ;
            if 0>= field_mul(group, rh, rh, point.X, ctx ) then
                goto _err ;
        end
        else
        begin
            if 0>= field_mul(group, tmp, Z4, group.a, ctx ) then
                goto _err ;
            if 0>= BN_mod_add_quick(rh, rh, tmp, p ) then
                goto _err ;
            if 0>= field_mul(group, rh, rh, point.X, ctx ) then
                goto _err ;
        end;
        { rh := rh + b*Z^6 }
        if 0>= field_mul(group, tmp, group.b, Z6, ctx ) then
            goto _err ;
        if 0>= BN_mod_add_quick(rh, rh, tmp, p ) then
            goto _err ;
    end
    else
    begin
        { point.Z_is_one }
        { rh := (rh + a)*X }
        if 0>= BN_mod_add_quick(rh, rh, group.a, p ) then
            goto _err ;
        if 0>= field_mul(group, rh, rh, point.X, ctx ) then
            goto _err ;
        { rh := rh + b }
        if 0>= BN_mod_add_quick(rh, rh, group.b, p ) then
            goto _err ;
    end;
    { 'lh' := Y^2 }
    if 0>= field_sqr(group, tmp, point.Y, ctx ) then
        goto _err ;
    ret := int(0 = BN_ucmp(tmp, rh));
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_cmp(const group : PEC_GROUP;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;

  tmp1, tmp2, Za23, Zb23 : PBIGNUM;
  tmp1_, tmp2_ : PBIGNUM;
  ret : integer;
  field_mul: Tfield_mul_func;
  field_sqr: Tfield_sqr_func;
  label _end;
begin
    {-
     * return values:
     *  -1   error
     *   0   equal (in affine coordinates)
     *   1   not equal
     }
    
    new_ctx := nil;

    ret := -1;
    if EC_POINT_is_at_infinity(group, a ) >0 then
    begin
        Exit(get_result(EC_POINT_is_at_infinity(group, b)>0 , 0 , 1));
    end;
    if EC_POINT_is_at_infinity(group, b ) > 0 then
        Exit(1);
    if (a.Z_is_one>0)  and  (b.Z_is_one>0) then
    begin
        Exit( get_result( (BN_cmp(a.X, b.X) = 0)  and  (BN_cmp(a.Y, b.Y) = 0)  , 0 , 1));
    end;
    field_mul := group.meth.field_mul;
    field_sqr := group.meth.field_sqr;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(-1);
    end;
    BN_CTX_start(ctx);
    tmp1 := BN_CTX_get(ctx);
    tmp2 := BN_CTX_get(ctx);
    Za23 := BN_CTX_get(ctx);
    Zb23 := BN_CTX_get(ctx);
    if Zb23 = nil then goto _end ;
    {-
     * We have to decide whether
     *     (X_a/Z_a^2, Y_a/Z_a^3) = (X_b/Z_b^2, Y_b/Z_b^3),
     * or equivalently, whether
     *     (X_a*Z_b^2, Y_a*Z_b^3) = (X_b*Z_a^2, Y_b*Z_a^3).
     }
    if 0>= b.Z_is_one then begin
        if 0>= field_sqr(group, Zb23, b.Z, ctx) then
            goto _end ;
        if 0>= field_mul(group, tmp1, a.X, Zb23, ctx ) then
            goto _end ;
        tmp1_ := tmp1;
    end
    else
        tmp1_ := a.X;
    if 0>= a.Z_is_one then
    begin
        if 0>= field_sqr(group, Za23, a.Z, ctx) then
            goto _end ;
        if 0>= field_mul(group, tmp2, b.X, Za23, ctx ) then
            goto _end ;
        tmp2_ := tmp2;
    end
    else
        tmp2_ := b.X;
    { compare  X_a*Z_b^2  with  X_b*Z_a^2 }
    if BN_cmp(tmp1_, tmp2_) <> 0  then
    begin
        ret := 1;                { points differ }
        goto _end ;
    end;
    if 0>= b.Z_is_one then begin
        if 0>= field_mul(group, Zb23, Zb23, b.Z, ctx) then
            goto _end ;
        if 0>= field_mul(group, tmp1, a.Y, Zb23, ctx ) then
            goto _end ;
        { tmp1_ = tmp1 }
    end
    else
        tmp1_ := a.Y;
    if 0>= a.Z_is_one then
    begin
        if 0>= field_mul(group, Za23, Za23, a.Z, ctx) then
            goto _end ;
        if 0>= field_mul(group, tmp2, b.Y, Za23, ctx ) then
            goto _end ;
        { tmp2_ = tmp2 }
    end
    else
        tmp2_ := b.Y;
    { compare  Y_a*Z_b^3  with  Y_b*Z_a^3 }
    if BN_cmp(tmp1_, tmp2_) <> 0  then
    begin
        ret := 1;                { points differ }
        goto _end ;
    end;
    { points are equal }
    ret := 0;
 _end:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_make_affine(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;
  x, y : PBIGNUM;
  ret : integer;
  label _err;
begin
    new_ctx := nil;
    ret := 0;
    if (point.Z_is_one>0)  or  (EC_POINT_is_at_infinity(group, point )>0) then
        Exit(1);
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    BN_CTX_start(ctx);
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    if y = nil then goto _err ;
    if 0>= EC_POINT_get_affine_coordinates(group, point, x, y, ctx ) then
        goto _err ;
    if 0>= EC_POINT_set_affine_coordinates(group, point, x, y, ctx ) then
        goto _err ;
    if 0>= point.Z_is_one then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_points_make_affine(const group : PEC_GROUP; num : size_t; points : PPEC_POINT; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;
  tmp, tmp_Z : PBIGNUM;
  prod_Z : PPBIGNUM;
  i : size_t;
  ret : integer;
  p : PEC_POINT;
  label _err;
begin
{$POINTERMATH ON}
    new_ctx := nil;
    prod_Z := nil;
    ret := 0;
    if num = 0 then Exit(1);
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(group.libctx);
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    tmp_Z := BN_CTX_get(ctx);
    if tmp_Z = nil then goto _err ;
    prod_Z := OPENSSL_malloc(num * sizeof(prod_Z[0]));
    if prod_Z = nil then goto _err ;
    for i := 0 to num-1 do begin
        prod_Z[i] := BN_new();
        if prod_Z[i] = nil then goto _err ;
    end;
    {
     * Set each prod_Z[i] to the product of points[0].Z .. points[i].Z,
     * skipping any zero-valued inputs (pretend that they're 1).
     }
    if not BN_is_zero(points[0].Z ) then
    begin
        if nil = BN_copy(prod_Z[0], points[0].Z) then
            goto _err ;
    end
    else
    begin
        if Assigned(group.meth.field_set_to_one ) then
        begin
            if 0>= group.meth.field_set_to_one(group, prod_Z[0], ctx) then
                goto _err ;
        end
        else
        begin
            if 0>= BN_one(prod_Z[0] ) then
                goto _err ;
        end;
    end;
    for i := 1 to num-1 do
    begin
        if not BN_is_zero(points[i].Z ) then
        begin
            if (0>= group.meth.field_mul(group, prod_Z[i], prod_Z[i - 1], points[i].Z,
                                ctx)) then
                goto _err ;
        end
        else
        begin
            if nil = BN_copy(prod_Z[i], prod_Z[i - 1] ) then
                goto _err ;
        end;
    end;
    {
     * Now use a single explicit inversion to replace every non-zero
     * points[i].Z by its inverse.
     }
    if 0>= group.meth.field_inv(group, tmp, prod_Z[num - 1], ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    if Assigned(group.meth.field_encode ) then
    begin
        {
         * In the Montgomery case, we just turned R*H (representing H) into
         * 1/(R*H), but we need R*(1/H) (representing 1/H); i.e. we need to
         * multiply by the Montgomery factor twice.
         }
        if 0>= group.meth.field_encode(group, tmp, tmp, ctx ) then
            goto _err ;
        if 0>= group.meth.field_encode(group, tmp, tmp, ctx ) then
            goto _err ;
    end;
    for i := num - 1 downto 1 do
    begin
        {
         * Loop invariant: tmp is the product of the inverses of points[0].Z
         * .. points[i].Z (zero-valued inputs skipped).
         }
        if not BN_is_zero(points[i].Z ) then
        begin
            {
             * Set tmp_Z to the inverse of points[i].Z (as product of Z
             * inverses 0 .. i, Z values 0 .. i - 1).
             }
            if (0>= group.meth.field_mul(group, tmp_Z, prod_Z[i - 1], tmp, ctx)) then
                goto _err ;
            {
             * Update tmp to satisfy the loop invariant for i - 1.
             }
            if 0>= group.meth.field_mul(group, tmp, tmp, points[i].Z, ctx ) then
                goto _err ;
            { Replace points[i].Z by its inverse. }
            if nil = BN_copy(points[i].Z, tmp_Z ) then
                goto _err ;
        end;
    end;
    if not BN_is_zero(points[0].Z ) then
    begin
        { Replace points[0].Z by its inverse. }
        if nil = BN_copy(points[0].Z, tmp) then
            goto _err ;
    end;
    { Finally, fix up the X and Y coordinates for all points. }
    for i := 0 to num-1 do
    begin
        p := @points[i];
        if not BN_is_zero(p.Z ) then
        begin
            { turn  (X, Y, 1/Z)  into  (X/Z^2, Y/Z^3, 1) }
            if 0>= group.meth.field_sqr(group, tmp, p.Z, ctx) then
                goto _err ;
            if 0>= group.meth.field_mul(group, p.X, p.X, tmp, ctx ) then
                goto _err ;
            if 0>= group.meth.field_mul(group, tmp, tmp, p.Z, ctx ) then
                goto _err ;
            if 0>= group.meth.field_mul(group, p.Y, p.Y, tmp, ctx ) then
                goto _err ;
            if Assigned(group.meth.field_set_to_one ) then
            begin
                if 0>= group.meth.field_set_to_one(group, p.Z, ctx) then
                    goto _err ;
            end
            else
            begin
                if 0>= BN_one(p.Z ) then
                    goto _err ;
            end;
            p.Z_is_one := 1;
        end;
    end;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    if prod_Z <> nil then
    begin
        for i := 0 to num-1 do
        begin
            if prod_Z[i] = nil then
                break;
            BN_clear_free(prod_Z[i]);
        end;
        OPENSSL_free(Pointer(prod_Z));
    end;
    Result := ret;
 {$POINTERMATH OFF}
end;


function ossl_ec_GFp_simple_field_mul(const group : PEC_GROUP; r : PBIGNUM;const a, b : PBIGNUM; ctx : PBN_CTX):integer;
begin
    Result := BN_mod_mul(r, a, b, group.field, ctx);
end;


function ossl_ec_GFp_simple_field_sqr(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
begin
    Result := BN_mod_sqr(r, a, group.field, ctx);
end;


function ossl_ec_GFp_simple_field_inv(const group : PEC_GROUP; r : PBIGNUM;const a : PBIGNUM; ctx : PBN_CTX):integer;
var
  e : PBIGNUM;

  new_ctx : PBN_CTX;

  ret : integer;
  label _err;
begin
    e := nil;
    new_ctx := nil;
    ret := 0;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_secure_new_ex(group.libctx ) ;
        ctx := new_ctx;
        if ctx= nil  then
           Exit(0);
    end;
    BN_CTX_start(ctx);
    e := BN_CTX_get(ctx );
    if e  = nil then
        goto _err ;
    while (BN_is_zero(e)) do
    begin
        if 0>= BN_priv_rand_range_ex(e, group.field, 0, ctx ) then
           goto _err ;
    end;

    { r := a * e }
    if 0>= group.meth.field_mul(group, r, a, e, ctx ) then
        goto _err ;
    { r := 1/(a * e) }
    if nil = BN_mod_inverse(r, r, group.field, ctx ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CANNOT_INVERT);
        goto _err ;
    end;
    { r := e/(a * e) = 1/a }
    if 0>= group.meth.field_mul(group, r, r, e, ctx ) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_blind_coordinates(const group : PEC_GROUP; p : PEC_POINT; ctx : PBN_CTX):integer;
var
  ret : integer;

  lambda, temp : PBIGNUM;
  label _end;
begin
    ret := 0;
    lambda := nil;
    temp := nil;
    BN_CTX_start(ctx);
    lambda := BN_CTX_get(ctx);
    temp := BN_CTX_get(ctx);
    if temp = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _end ;
    end;
    {-
     * Make sure lambda is not zero.
     * If the RNG fails, we cannot blind but nevertheless want
     * code to continue smoothly and not clobber the error stack.
     }
    while (BN_is_zero(lambda)) do
    begin
        ERR_set_mark();
        ret := BN_priv_rand_range_ex(lambda, group.field, 0, ctx);
        ERR_pop_to_mark();
        if ret = 0 then
        begin
            ret := 1;
            goto _end ;
        end;
    end;

    { if field_encode defined convert between representations }
    if ( (Assigned(group.meth.field_encode))
          and  (0>= group.meth.field_encode(group, lambda, lambda, ctx )) )
         or  (0>= group.meth.field_mul(group, p.Z, p.Z, lambda, ctx))
         or  (0>= group.meth.field_sqr(group, temp, lambda, ctx))
         or  (0>= group.meth.field_mul(group, p.X, p.X, temp, ctx))
         or  (0>= group.meth.field_mul(group, temp, temp, lambda, ctx))
         or  (0>= group.meth.field_mul(group, p.Y, p.Y, temp, ctx))  then
        goto _end ;
    p.Z_is_one := 0;
    ret := 1;
 _end:
    BN_CTX_end(ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_ladder_pre(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
var
  t1, t2, t3, t4, t5 : PBIGNUM;
begin
    t5 := nil;
    t1 := s.Z;
    t2 := r.Z;
    t3 := s.X;
    t4 := r.X;
    t5 := s.Y;
    if (0>= p.Z_is_one) { r := 2p }
         or  (0>= group.meth.field_sqr(group, t3, p.X, ctx))
         or  (0>= BN_mod_sub_quick(t4, t3, group.a, group.field))
         or  (0>= group.meth.field_sqr(group, t4, t4, ctx))
         or  (0>= group.meth.field_mul(group, t5, p.X, group.b, ctx))
         or  (0>= BN_mod_lshift_quick(t5, t5, 3, group.field))
        { r.X coord output }
         or  (0>= BN_mod_sub_quick(r.X, t4, t5, group.field))
         or  (0>= BN_mod_add_quick(t1, t3, group.a, group.field))
         or  (0>= group.meth.field_mul(group, t2, p.X, t1, ctx))
         or  (0>= BN_mod_add_quick(t2, group.b, t2, group.field))
        { r.Z coord output }
         or  (0>= BN_mod_lshift_quick(r.Z, t2, 2, group.field))  then
        Exit(0);
    { make sure lambda (r.Y here for storage) is not zero }
    while (BN_is_zero(r.Y)) do
    begin
        if 0>= BN_priv_rand_range_ex(r.Y, group.field, 0, ctx ) then
            Exit(0);
    end;

    { make sure lambda (s.Z here for storage) is not zero }
    while (BN_is_zero(s.Z)) do
    begin
        if 0>= BN_priv_rand_range_ex(s.Z, group.field, 0, ctx ) then
            Exit(0);
    end;

    { if field_encode defined convert between representations }
    if (Assigned(group.meth.field_encode))
         and ( (0>= group.meth.field_encode(group, r.Y, r.Y, ctx)) or
               (0>= group.meth.field_encode(group, s.Z, s.Z, ctx))) then
        Exit(0);
    { blind r and s independently }
    if (0>= group.meth.field_mul(group, r.Z, r.Z, r.Y, ctx))  or
       (0>= group.meth.field_mul(group, r.X, r.X, r.Y, ctx))   or
       (0>= group.meth.field_mul(group, s.X, p.X, s.Z, ctx))  then{ s := p }
        Exit(0);
    r.Z_is_one := 0;
    s.Z_is_one := 0;
    Result := 1;
end;


function ossl_ec_GFp_simple_ladder_step(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
var
  ret : integer;

  t0, t1, t2, t3, t4, t5, t6 : PBIGNUM;
  label _err;
begin
    ret := 0;
  t6 := nil;
    BN_CTX_start(ctx);
    t0 := BN_CTX_get(ctx);
    t1 := BN_CTX_get(ctx);
    t2 := BN_CTX_get(ctx);
    t3 := BN_CTX_get(ctx);
    t4 := BN_CTX_get(ctx);
    t5 := BN_CTX_get(ctx);
    t6 := BN_CTX_get(ctx);
    if (t6 = nil)
         or  (0>= group.meth.field_mul(group, t6, r.X, s.X, ctx))
         or  (0>= group.meth.field_mul(group, t0, r.Z, s.Z, ctx))
         or  (0>= group.meth.field_mul(group, t4, r.X, s.Z, ctx))
         or  (0>= group.meth.field_mul(group, t3, r.Z, s.X, ctx))
         or  (0>= group.meth.field_mul(group, t5, group.a, t0, ctx))
         or  (0>= BN_mod_add_quick(t5, t6, t5, group.field))
         or  (0>= BN_mod_add_quick(t6, t3, t4, group.field))
         or  (0>= group.meth.field_mul(group, t5, t6, t5, ctx))
         or  (0>= group.meth.field_sqr(group, t0, t0, ctx))
         or  (0>= BN_mod_lshift_quick(t2, group.b, 2, group.field))
         or  (0>= group.meth.field_mul(group, t0, t2, t0, ctx))
         or  (0>= BN_mod_lshift1_quick(t5, t5, group.field))
         or  (0>= BN_mod_sub_quick(t3, t4, t3, group.field) )
        { s.Z coord output }
         or  (0>= group.meth.field_sqr(group, s.Z, t3, ctx))
         or  (0>= group.meth.field_mul(group, t4, s.Z, p.X, ctx))
         or  (0>= BN_mod_add_quick(t0, t0, t5, group.field))
        { s.X coord output }
         or  (0>= BN_mod_sub_quick(s.X, t0, t4, group.field))
         or  (0>= group.meth.field_sqr(group, t4, r.X, ctx))
         or  (0>= group.meth.field_sqr(group, t5, r.Z, ctx))
         or  (0>= group.meth.field_mul(group, t6, t5, group.a, ctx))
         or  (0>= BN_mod_add_quick(t1, r.X, r.Z, group.field))
         or  (0>= group.meth.field_sqr(group, t1, t1, ctx))
         or  (0>= BN_mod_sub_quick(t1, t1, t4, group.field))
         or  (0>= BN_mod_sub_quick(t1, t1, t5, group.field))
         or  (0>= BN_mod_sub_quick(t3, t4, t6, group.field))
         or  (0>= group.meth.field_sqr(group, t3, t3, ctx))
         or  (0>= group.meth.field_mul(group, t0, t5, t1, ctx))
         or  (0>= group.meth.field_mul(group, t0, t2, t0, ctx))
        { r.X coord output }
         or  (0>= BN_mod_sub_quick(r.X, t3, t0, group.field))
         or  (0>= BN_mod_add_quick(t3, t4, t6, group.field))
         or  (0>= group.meth.field_sqr(group, t4, t5, ctx))
         or  (0>= group.meth.field_mul(group, t4, t4, t2, ctx))
         or  (0>= group.meth.field_mul(group, t1, t1, t3, ctx))
         or  (0>= BN_mod_lshift1_quick(t1, t1, group.field))
        { r.Z coord output }
         or  (0>= BN_mod_add_quick(r.Z, t4, t1, group.field)) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;


function ossl_ec_GFp_simple_ladder_post(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
var
  ret : integer;

  t0, t1, t2, t3, t4, t5, t6 : PBIGNUM;
  label _err;
begin
    ret := 0;
    t6 := nil;
    if BN_is_zero(r.Z ) then
        Exit(EC_POINT_set_to_infinity(group, r));
    if BN_is_zero(s.Z ) then
    begin
        if (0>= EC_POINT_copy(r, p) )  or
           (0>= EC_POINT_invert(group, r, ctx))then
            Exit(0);
        Exit(1);
    end;
    BN_CTX_start(ctx);
    t0 := BN_CTX_get(ctx);
    t1 := BN_CTX_get(ctx);
    t2 := BN_CTX_get(ctx);
    t3 := BN_CTX_get(ctx);
    t4 := BN_CTX_get(ctx);
    t5 := BN_CTX_get(ctx);
    t6 := BN_CTX_get(ctx);
    if (t6 = nil)
         or  (0>= BN_mod_lshift1_quick(t4, p.Y, group.field))
         or  (0>= group.meth.field_mul(group, t6, r.X, t4, ctx))
         or  (0>= group.meth.field_mul(group, t6, s.Z, t6, ctx))
         or  (0>= group.meth.field_mul(group, t5, r.Z, t6, ctx))
         or  (0>= BN_mod_lshift1_quick(t1, group.b, group.field))
         or  (0>= group.meth.field_mul(group, t1, s.Z, t1, ctx))
         or  (0>= group.meth.field_sqr(group, t3, r.Z, ctx))
         or  (0>= group.meth.field_mul(group, t2, t3, t1, ctx))
         or  (0>= group.meth.field_mul(group, t6, r.Z, group.a, ctx))
         or  (0>= group.meth.field_mul(group, t1, p.X, r.X, ctx))
         or  (0>= BN_mod_add_quick(t1, t1, t6, group.field))
         or  (0>= group.meth.field_mul(group, t1, s.Z, t1, ctx))
         or  (0>= group.meth.field_mul(group, t0, p.X, r.Z, ctx))
         or  (0>= BN_mod_add_quick(t6, r.X, t0, group.field))
         or  (0>= group.meth.field_mul(group, t6, t6, t1, ctx))
         or  (0>= BN_mod_add_quick(t6, t6, t2, group.field))
         or  (0>= BN_mod_sub_quick(t0, t0, r.X, group.field))
         or  (0>= group.meth.field_sqr(group, t0, t0, ctx))
         or  (0>= group.meth.field_mul(group, t0, t0, s.X, ctx))
         or  (0>= BN_mod_sub_quick(t0, t6, t0, group.field))
         or  (0>= group.meth.field_mul(group, t1, s.Z, t4, ctx))
         or  (0>= group.meth.field_mul(group, t1, t3, t1, ctx))
         or  ( (Assigned(group.meth.field_decode))
             and  (0>= group.meth.field_decode(group, t1, t1, ctx)) )
         or  (0>= group.meth.field_inv(group, t1, t1, ctx))
         or  ( (Assigned(group.meth.field_encode))
             and  (0>= group.meth.field_encode(group, t1, t1, ctx)) )
         or  (0>= group.meth.field_mul(group, r.X, t5, t1, ctx))
         or  (0>= group.meth.field_mul(group, r.Y, t0, t1, ctx))  then
        goto _err ;
    if Assigned(group.meth.field_set_to_one) then
    begin
        if 0>= group.meth.field_set_to_one(group, r.Z, ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_one(r.Z ) then
            goto _err ;
    end;
    r.Z_is_one := 1;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;

function ossl_ec_GFp_simple_group_init( group : PEC_GROUP):integer;
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
    group.a_is_minus3 := 0;
    Result := 1;
end;


end.
