unit openssl3.crypto.ec.ec_lib;
{$I config.inc}

interface
uses OpenSSL.Api;

function ossl_ec_group_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; meth : PEC_METHOD):PEC_GROUP;
function EC_GROUP_get_field_type(const group : PEC_GROUP):integer;
function EC_GROUP_new_from_params(const params : POSSL_PARAM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_GROUP;
function group_new_from_name(const p : POSSL_PARAM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_GROUP;
 function ossl_ec_group_set_params(group : PEC_GROUP;const params : POSSL_PARAM):integer;
function ec_group_explicit_to_named(const group : PEC_GROUP; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; ctx : PBN_CTX):PEC_GROUP;
function ossl_ec_group_do_inverse_ord(const group : PEC_GROUP; res : PBIGNUM;const x : PBIGNUM; ctx : PBN_CTX):integer;
function ec_field_inverse_mod_ord(const group : PEC_GROUP; r : PBIGNUM;const x : PBIGNUM; ctx : PBN_CTX):integer;
function ec_point_is_compat(const point : PEC_POINT; group : PEC_GROUP):integer;
function EC_POINT_set_to_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
function EC_POINT_set_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x, y : PBIGNUM; ctx : PBN_CTX):integer;
 function EC_POINT_is_at_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
function EC_POINT_get_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT; x, y : PBIGNUM; ctx : PBN_CTX):integer;
function BN_bn2bin(const a : PBIGNUM; &to : PByte):integer;
function EC_GROUP_get_curve_name(const group : PEC_GROUP):integer;
function EC_GROUP_get_seed_len(const group : PEC_GROUP):size_t;
 function EC_GROUP_get0_seed(const group : PEC_GROUP):PByte;
 function EC_GROUP_get0_cofactor(const group : PEC_GROUP):PBIGNUM;
 function EC_GROUP_get0_generator(const group : PEC_GROUP):PEC_POINT;
 function EC_GROUP_get_curve(const group : PEC_GROUP; p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  function EC_GROUP_get_order(const group : PEC_GROUP; order : PBIGNUM; ctx : PBN_CTX):integer;
 function EC_POINT_set_Jprojective_coordinates_GFp(const group : PEC_GROUP; point : PEC_POINT;const x, y, z : PBIGNUM; ctx : PBN_CTX):integer;
 function EC_POINT_dbl(const group : PEC_GROUP; r : PEC_POINT;const a : PEC_POINT; ctx : PBN_CTX):integer;
 function EC_POINT_copy(dest : PEC_POINT;const src : PEC_POINT):integer;
 function EC_POINT_invert(const group : PEC_GROUP; a : PEC_POINT; ctx : PBN_CTX):integer;
 function ossl_ec_group_simple_order_bits(const group : PEC_GROUP):integer;
 function EC_GROUP_get_cofactor(const group : PEC_GROUP; cofactor : PBIGNUM; ctx : PBN_CTX):integer;
 function EC_POINT_new(const group : PEC_GROUP):PEC_POINT;
 function EC_POINT_mul(const group : PEC_GROUP; r : PEC_POINT;const g_scalar : PBIGNUM; point : PEC_POINT; p_scalar : PBIGNUM; ctx : PBN_CTX):int;
 function EC_GROUP_get_degree(const group : PEC_GROUP):integer;
 procedure EC_POINT_clear_free( point : PEC_POINT);
 function EC_GROUP_get0_order(const group : PEC_GROUP):PBIGNUM;
 procedure EC_POINT_free( point : PEC_POINT);
  function EC_GROUP_get_asn1_flag(const group : PEC_GROUP):integer;
 function EC_GROUP_get_basis_type(const group : PEC_GROUP):integer;
 function EC_GROUP_get_trinomial_basis(const group : PEC_GROUP; k : Puint32):integer;
 function EC_GROUP_get_pentanomial_basis(const group : PEC_GROUP; k1, k2, k3 : Puint32):integer;
 function EC_GROUP_get_point_conversion_form(group : PEC_GROUP):point_conversion_form_t;
  function EC_GROUP_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
  procedure EC_GROUP_free( group : PEC_GROUP);
 function ec_point_ladder_pre(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ec_point_ladder_step(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
  function ec_point_ladder_post(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
 function EC_POINT_cmp(const group : PEC_GROUP; a, b : PEC_POINT; ctx : PBN_CTX):integer;
 function EC_POINT_add(const group : PEC_GROUP; r : PEC_POINT;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
 function ossl_ec_point_blind_coordinates(const group : PEC_GROUP; p : PEC_POINT; ctx : PBN_CTX):integer;
 procedure EC_GROUP_set_curve_name( group : PEC_GROUP; nid : integer);
 function EC_GROUP_set_generator(group : PEC_GROUP;const generator : PEC_POINT; order, cofactor : PBIGNUM):integer;
 function EC_GROUP_set_seed(group : PEC_GROUP;const p : PByte; len : size_t):size_t;
 procedure EC_GROUP_set_asn1_flag( group : PEC_GROUP; flag : integer);
 function EC_GROUP_dup(const a : PEC_GROUP):PEC_GROUP;
 function EC_GROUP_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
  function ec_guess_cofactor( group : PEC_GROUP):integer;
  function ec_precompute_mont_data( group : PEC_GROUP):integer;
 procedure EC_pre_comp_free( group : PEC_GROUP);
  function EC_POINT_is_on_curve(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
 procedure EC_GROUP_set_point_conversion_form( group : PEC_GROUP; form : point_conversion_form_t);
  function EC_POINT_dup(const a : PEC_POINT; group : PEC_GROUP):PEC_POINT;
 function EC_GROUP_order_bits(const group : PEC_GROUP):integer;
 function EC_GROUP_cmp(const a, b : PEC_GROUP; ctx : PBN_CTX):integer;
 function EC_GROUP_check_discriminant(const group : PEC_GROUP; ctx : PBN_CTX):integer;


implementation

uses OpenSSL3.Err, openssl3.crypto.ec.ec_kmeth, openssl3.crypto.engine.eng_init,
     openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.bn.bn_lib,
     OpenSSL3.crypto.params, openssl3.crypto.ec.ec_support,
     openssl3.crypto.ec.ec_curve, openssl3.crypto.ec.ec_backend,
     openssl3.crypto.bn.bn_mont, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_add,  openssl3.crypto.bn.bn_div,
     OpenSSL3.crypto.ec.ecp_smpl, openssl3.crypto.bn.bn_exp,
     openssl3.crypto.ec.ec_cvt,  openssl3.crypto.ec.ec_oct,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_mult;





function EC_GROUP_check_discriminant(const group : PEC_GROUP; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.group_check_discriminant) then begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := group.meth.group_check_discriminant(group, ctx);
end;




function EC_GROUP_cmp(const a, b : PEC_GROUP; ctx : PBN_CTX):integer;
var
  r : integer;
  a1, a2, a3, b1, b2, b3 : PBIGNUM;
  ctx_new : PBN_CTX;
  ao, bo, ac, bc : PBIGNUM;
  label _end;
begin
    r := 0;
{$IFNDEF FIPS_MODULE}
    ctx_new := nil;
{$ENDIF}
    { compare the field types }
    if EC_GROUP_get_field_type(a) <> EC_GROUP_get_field_type(b)  then
        Exit(1);
    { compare the curve name (if present in both) }
    if (EC_GROUP_get_curve_name(a) > 0) and  (EC_GROUP_get_curve_name(b) > 0)  and
       ( EC_GROUP_get_curve_name(a) <> EC_GROUP_get_curve_name(b))  then
        Exit(1);
    if a.meth.flags and EC_FLAGS_CUSTOM_CURVE > 0 then Exit(0);
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
       ctx := BN_CTX_new;
       ctx_new := ctx ;
    end;
{$ENDIF}
    if ctx = nil then Exit(-1);
    BN_CTX_start(ctx);
    a1 := BN_CTX_get(ctx);
    a2 := BN_CTX_get(ctx);
    a3 := BN_CTX_get(ctx);
    b1 := BN_CTX_get(ctx);
    b2 := BN_CTX_get(ctx);
    b3 := BN_CTX_get(ctx);
    if b3 = nil then begin
        BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
        BN_CTX_free(ctx_new);
{$ENDIF}
        Exit(-1);
    end;
    {
     * XXX This approach assumes that the external representation of curves
     * over the same field type is the same.
     }
    if (0>=a.meth.group_get_curve(a, a1, a2, a3, ctx)) or
       (0>=b.meth.group_get_curve(b, b1, b2, b3, ctx))  then
        r := 1;
    { return 1 if the curve parameters are different }
    if (r > 0)  or  (BN_cmp(a1, b1) <> 0)  or  (BN_cmp(a2, b2) <> 0)  or  (BN_cmp(a3, b3) <> 0)  then
        r := 1;
    { XXX EC_POINT_cmp assumes that the methods are equal }
    { return 1 if the generators are different }
    if (r > 0)  or  (EC_POINT_cmp(a, EC_GROUP_get0_generator(a) ,
                          EC_GROUP_get0_generator(b), ctx) <> 0) then
        r := 1;
    if 0>=r then begin
        { compare the orders }
        ao := EC_GROUP_get0_order(a);
        bo := EC_GROUP_get0_order(b);
        if (ao = nil)  or  (bo = nil) then begin
            { return an error if either order is nil }
            r := -1;
            goto _end;
        end;
        if BN_cmp(ao, bo) <> 0  then
        begin
            { return 1 if orders are different }
            r := 1;
            goto _end;
        end;
        {
         * It gets here if the curve parameters and generator matched.
         * Now check the optional cofactors (if both are present).
         }
        ac := EC_GROUP_get0_cofactor(a);
        bc := EC_GROUP_get0_cofactor(b);
        { Returns 1 (mismatch) if both cofactors are specified and different }
        if (not BN_is_zero(ac))  and  (not BN_is_zero(bc))  and  (BN_cmp(ac, bc) <> 0) then
            r := 1;
        { Returns 0 if the parameters matched }
    end;
_end:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(ctx_new);
{$ENDIF}
    Result := r;
end;




function EC_GROUP_order_bits(const group : PEC_GROUP):integer;
begin
    Result := group.meth.group_order_bits(group);
end;





function EC_POINT_dup(const a : PEC_POINT; group : PEC_GROUP):PEC_POINT;
var
  t : PEC_POINT;

  r : integer;
begin
    if a = nil then Exit(nil);
    t := EC_POINT_new(group);
    if t = nil then Exit(nil);
    r := EC_POINT_copy(t, a);
    if 0>= r then begin
        EC_POINT_free(t);
        Exit(nil);
    end;
    Result := t;
end;




procedure EC_GROUP_set_point_conversion_form( group : PEC_GROUP; form : point_conversion_form_t);
begin
    group.asn1_form := form;
end;




function EC_POINT_is_on_curve(const group : PEC_GROUP; point : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.is_on_curve) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Result := group.meth.is_on_curve(group, point, ctx);
end;




procedure EC_pre_comp_free( group : PEC_GROUP);
 procedure _break;
 begin
   //
 end;
begin
    case group.pre_comp_type of
    PCT_none:
        _break;
    PCT_nistz256:
{$IFDEF ECP_NISTZ256_ASM}
        EC_nistz256_pre_comp_free(group.pre_comp.nistz256);
{$ENDIF}
        _break;
{$IFNDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
    PCT_nistp224:
        EC_nistp224_pre_comp_free(group.pre_comp.nistp224);
        //break;
    PCT_nistp256:
        EC_nistp256_pre_comp_free(group.pre_comp.nistp256);
        //break;
    PCT_nistp521:
        EC_nistp521_pre_comp_free(group.pre_comp.nistp521);
        //break;
{$ELSE PCT_nistp224: }
    PCT_nistp256,
    PCT_nistp521:
        _break;
{$ENDIF}
    PCT_ec:
        EC_ec_pre_comp_free(group.pre_comp.ec);
        //break;
    end;
    group.pre_comp.ec := nil;
end;




function ec_precompute_mont_data( group : PEC_GROUP):integer;
var
  ctx : PBN_CTX;
  ret : integer;
  label _err;
begin
    ctx := BN_CTX_new_ex(group.libctx);
    ret := 0;
    BN_MONT_CTX_free(group.mont_data);
    group.mont_data := nil;
    if ctx = nil then goto _err ;
    group.mont_data := BN_MONT_CTX_new();
    if group.mont_data = nil then goto _err ;
    if 0>= BN_MONT_CTX_set(group.mont_data, group.order, ctx) then
    begin
        BN_MONT_CTX_free(group.mont_data);
        group.mont_data := nil;
        goto _err ;
    end;
    ret := 1;
 _err:
    BN_CTX_free(ctx);
    Result := ret;
end;



function ec_guess_cofactor( group : PEC_GROUP):integer;
var
  ret : integer;
  ctx : PBN_CTX;
  q : PBIGNUM;
  label _err;
begin
    ret := 0;
    ctx := nil;
    q := nil;
    {-
     * If the cofactor is too large, we cannot guess it.
     * The RHS of below is a strict overestimate of lg(4 * sqrt(q))
     }
    if BN_num_bits(group.order) <= (BN_num_bits(group.field) + 1) div 2 + 3  then
    begin
        { default to 0 }
        BN_zero(group.cofactor);
        { return success }
        Exit(1);
    end;
    ctx := BN_CTX_new_ex(group.libctx);
    if ctx = nil then
        Exit(0);
    BN_CTX_start(ctx);
    q := BN_CTX_get(ctx);
    if q =  nil then
        goto _err ;
    if group.meth.field_type = NID_X9_62_characteristic_two_field then
    begin
        BN_zero(q);
        if 0>= BN_set_bit(q, BN_num_bits(group.field) - 1)  then
            goto _err ;
    end
    else
    begin
        if nil = BN_copy(q, group.field) then
            goto _err ;
    end;
    { compute h = \lfloor (q + 1)/n \rceil = \lfloor (q + 1 + n/2)/n \rfloor }
    if (0>= BN_rshift1(group.cofactor, group.order)) { n/2 }
         or  (0>= BN_add(group.cofactor, group.cofactor, q)) { q + n/2 }
        { q + 1 + n/2 }
         or  (0>= BN_add(group.cofactor, group.cofactor, BN_value_one))
        { (q + 1 + n/2)/n }
         or  (0>= BN_div(group.cofactor, nil, group.cofactor, group.order, ctx))  then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ret;
end;




function EC_GROUP_copy(dest : PEC_GROUP;const src : PEC_GROUP):integer;
begin
    if not Assigned(dest.meth.group_copy) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if dest.meth <> src.meth then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if dest = src then Exit(1);
    dest.libctx := src.libctx;
    dest.curve_name := src.curve_name;
    { Copy precomputed }
    dest.pre_comp_type := src.pre_comp_type;
    case src.pre_comp_type of
        PCT_none:
            dest.pre_comp.ec := nil;
            //break;
        PCT_nistz256:
    {$IFDEF ECP_NISTZ256_ASM}
            dest.pre_comp.nistz256 := EC_nistz256_pre_comp_dup(src.pre_comp.nistz256);
    {$ENDIF}
           begin
            //break;
           end;
    {$IFNDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
        PCT_nistp224:
            dest.pre_comp.nistp224 := EC_nistp224_pre_comp_dup(src.pre_comp.nistp224);
            //break;
        PCT_nistp256:
            dest.pre_comp.nistp256 := EC_nistp256_pre_comp_dup(src.pre_comp.nistp256);
            //break;
        PCT_nistp521:
            dest.pre_comp.nistp521 := EC_nistp521_pre_comp_dup(src.pre_comp.nistp521);
            //break;
    {$ELSE}
        PCT_nistp224,
        PCT_nistp256,
        PCT_nistp521:
        begin
           //break;
        end;
    {$ENDIF}
        PCT_ec:
            dest.pre_comp.ec := EC_ec_pre_comp_dup(src.pre_comp.ec);
            //break;
    end;
    if src.mont_data <> nil then
    begin
        if dest.mont_data = nil then
        begin
            dest.mont_data := BN_MONT_CTX_new();
            if dest.mont_data = nil then Exit(0);
        end;
        if nil = BN_MONT_CTX_copy(dest.mont_data, src.mont_data) then
            Exit(0);
    end
    else
    begin
        { src.generator = nil }
        BN_MONT_CTX_free(dest.mont_data);
        dest.mont_data := nil;
    end;
    if src.generator <> nil then
    begin
        if dest.generator = nil then
        begin
            dest.generator := EC_POINT_new(dest);
            if dest.generator = nil then Exit(0);
        end;
        if 0>= EC_POINT_copy(dest.generator, src.generator ) then
            Exit(0);
    end
    else
    begin
        { src.generator = nil }
        EC_POINT_clear_free(dest.generator);
        dest.generator := nil;
    end;
    if (src.meth.flags and EC_FLAGS_CUSTOM_CURVE) = 0 then
    begin
        if nil = BN_copy(dest.order, src.order) then
            Exit(0);
        if nil = BN_copy(dest.cofactor, src.cofactor ) then
            Exit(0);
    end;
    dest.asn1_flag := src.asn1_flag;
    dest.asn1_form := src.asn1_form;
    dest.decoded_from_explicit_params := src.decoded_from_explicit_params;
    if src.seed <> nil then
    begin
        OPENSSL_free(Pointer(dest.seed));
        dest.seed := OPENSSL_malloc(src.seed_len);
        if dest.seed = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        if nil = memcpy(dest.seed, src.seed, src.seed_len) then
            Exit(0);
        dest.seed_len := src.seed_len;
    end
    else
    begin
        OPENSSL_free(Pointer(dest.seed));
        dest.seed := nil;
        dest.seed_len := 0;
    end;
    Result := dest.meth.group_copy(dest, src);
end;

function EC_GROUP_dup(const a : PEC_GROUP):PEC_GROUP;
var
  t : PEC_GROUP;
  ok : integer;
  label _err;
begin
    t := nil;
    ok := 0;
    if a = nil then Exit(nil);
    t := ossl_ec_group_new_ex(a.libctx, a.propq, a.meth );
    if t = nil then
        Exit(nil);
    if 0>= EC_GROUP_copy(t, a) then
        goto _err ;
    ok := 1;
 _err:
    if 0>= ok then
    begin
        EC_GROUP_free(t);
        Exit(nil);
    end;
        Result := t;
end;

procedure EC_GROUP_set_asn1_flag( group : PEC_GROUP; flag : integer);
begin
    group.asn1_flag := flag;
end;



function EC_GROUP_set_seed(group : PEC_GROUP;const p : PByte; len : size_t):size_t;
begin
    OPENSSL_free(group.seed);
    group.seed := nil;
    group.seed_len := 0;
    if (0>= len)  or  (nil = p) then
       Exit(1);
    group.seed := OPENSSL_malloc(len);
    if group.seed = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    memcpy(group.seed, p, len);
    group.seed_len := len;
    Result := len;
end;

function EC_GROUP_set_generator(group : PEC_GROUP;const generator : PEC_POINT; order, cofactor : PBIGNUM):integer;
begin
    if generator = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { require group.field >= 1 }
    if (group.field = nil)  or  (BN_is_zero(group.field))  or  (BN_is_negative(group.field)>0) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        Exit(0);
    end;
    {-
     * - require order >= 1
     * - enforce upper bound due to Hasse thm: order can be no more than one bit
     *   longer than field cardinality
     }
    if (order = nil)  or  (BN_is_zero(order)) or  (BN_is_negative(order) > 0)
         or  (BN_num_bits(order) > BN_num_bits(group.field) + 1)  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        Exit(0);
    end;
    {-
     * Unfortunately the cofactor is an optional field in many standards.
     * Internally, the lib uses 0 cofactor as a marker for 'unknown cofactor'.
     * So accept cofactor = nil or cofactor >= 0.
     }
    if (cofactor <> nil)  and  (BN_is_negative(cofactor)>0) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_COFACTOR);
        Exit(0);
    end;
    if group.generator = nil then
    begin
        group.generator := EC_POINT_new(group);
        if group.generator = nil then Exit(0);
    end;
    if 0>= EC_POINT_copy(group.generator, generator) then
        Exit(0);
    if nil = BN_copy(group.order, order) then
        Exit(0);
    { Either take the provided positive cofactor, or try to compute it }
    if (cofactor <> nil)  and  (not BN_is_zero(cofactor)) then
    begin
        if nil = BN_copy(group.cofactor, cofactor) then
            Exit(0);
    end
    else
    if (0>= ec_guess_cofactor(group)) then
    begin
        BN_zero(group.cofactor);
        Exit(0);
    end;
    {
     * Some groups have an order with
     * factors of two, which makes the Montgomery setup fail.
     * |group.mont_data| will be nil in this case.
     }
    if BN_is_odd(group.order) then
    begin
        Exit(ec_precompute_mont_data(group));
    end;
    BN_MONT_CTX_free(group.mont_data);
    group.mont_data := nil;
    Result := 1;
end;



procedure EC_GROUP_set_curve_name( group : PEC_GROUP; nid : integer);
begin
    group.curve_name := nid;
    group.asn1_flag := get_result((nid <> NID_undef)
        , OPENSSL_EC_NAMED_CURVE
        , OPENSSL_EC_EXPLICIT_CURVE);
end;




function ossl_ec_point_blind_coordinates(const group : PEC_GROUP; p : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.blind_coordinates) then Exit(1); { ignore if not implemented }
    Result := group.meth.blind_coordinates(group, p, ctx);
end;


function EC_POINT_add(const group : PEC_GROUP; r : PEC_POINT;const a, b : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.add) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if (0>= ec_point_is_compat(r, group))  or  (0>= ec_point_is_compat(a, group))
         or  (0>= ec_point_is_compat(b, group))  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Result := group.meth.add(group, r, a, b, ctx);
end;





function EC_POINT_cmp(const group : PEC_GROUP; a, b : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.point_cmp) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(-1);
    end;
    if (0>= ec_point_is_compat(a, group))  or  (0>= ec_point_is_compat(b, group))  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(-1);
    end;
    Result := group.meth.point_cmp(group, a, b, ctx);
end;




function ec_point_ladder_pre(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if Assigned(group.meth.ladder_pre) then
       Exit(group.meth.ladder_pre(group, r, s, p, ctx));
    if (0>= EC_POINT_copy(s, p))  or  (0>= EC_POINT_dbl(group, r, s, ctx)) then
        Exit(0);
    Result := 1;
end;


function ec_point_ladder_step(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if Assigned(group.meth.ladder_step) then
       Exit(group.meth.ladder_step(group, r, s, p, ctx));

    if (0>= EC_POINT_add(group, s, r, s, ctx))  or
       (0>= EC_POINT_dbl(group, r, r, ctx)) then
        Exit(0);
    Exit(1);
end;


function ec_point_ladder_post(const group : PEC_GROUP; r, s, p : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if Assigned(group.meth.ladder_post) then
       Exit(group.meth.ladder_post(group, r, s, p, ctx));
    Result := 1;
end;




procedure EC_GROUP_free( group : PEC_GROUP);
begin
    if nil = group then exit;
    if Assigned(group.meth.group_finish) then
       group.meth.group_finish(group);
    EC_pre_comp_free(group);
    BN_MONT_CTX_free(group.mont_data);
    EC_POINT_free(group.generator);
    BN_free(group.order);
    BN_free(group.cofactor);
    OPENSSL_free(group.seed);
    OPENSSL_free(group.propq);
    OPENSSL_free(group);
end;


function EC_GROUP_set_curve(group : PEC_GROUP;const p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.group_set_curve) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := group.meth.group_set_curve(group, p, a, b, ctx);
end;



function EC_GROUP_get_point_conversion_form( group : PEC_GROUP):point_conversion_form_t;
begin
    Result := group.asn1_form;
end;

function EC_GROUP_get_pentanomial_basis(const group : PEC_GROUP; k1, k2, k3 : Puint32):integer;
begin
    if group = nil then
       Exit(0);
    if (EC_GROUP_get_field_type(group) <> NID_X9_62_characteristic_two_field)
         or  (not ((group.poly[0] <> 0)  and  (group.poly[1] <> 0)
              and  (group.poly[2] <> 0)  and  (group.poly[3] <> 0)
              and  (group.poly[4] = 0))) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if k1 <> nil then k1^ := group.poly[3];
    if k2 <> nil then k2^ := group.poly[2];
    if k3 <> nil then k3^ := group.poly[1];
    Result := 1;
end;

function EC_GROUP_get_trinomial_basis(const group : PEC_GROUP; k : Puint32):integer;
begin
    if group = nil then Exit(0);
    if (EC_GROUP_get_field_type(group) <> NID_X9_62_characteristic_two_field)
         or  (not ((group.poly[0] <> 0)  and  (group.poly[1] <> 0)
              and  (group.poly[2] = 0)))  then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if k <> nil then
       k^ := group.poly[1];
    Result := 1;
end;





function EC_GROUP_get_basis_type(const group : PEC_GROUP):integer;
var
  i : integer;
begin
    if (EC_GROUP_get_field_type(group) <> NID_X9_62_characteristic_two_field) then
        { everything else is currently not supported }
        Exit(0);
    { Find the last non-zero element of group.poly[] }
    for i := 0 to int (Length(group.poly))-1  do
        if group.poly[i] <> 0 then
           continue;
    if i = 4 then
       Exit(NID_X9_62_ppBasis)
    else
    if (i = 2) then
        Exit(NID_X9_62_tpBasis)
    else
        { everything else is currently not supported }
        Result := 0;
end;



function EC_GROUP_get_asn1_flag(const group : PEC_GROUP):integer;
begin
    Result := group.asn1_flag;
end;




procedure EC_POINT_free( point : PEC_POINT);
begin
    if point = nil then exit;
    if Assigned(point.meth.point_finish) then
       point.meth.point_finish(point);
    OPENSSL_free(point);
end;



function EC_GROUP_get0_order(const group : PEC_GROUP):PBIGNUM;
begin
    Result := group.order;
end;



procedure EC_POINT_clear_free( point : PEC_POINT);
begin
    if point = nil then Exit;
    if Assigned(point.meth.point_clear_finish) then
       point.meth.point_clear_finish(point)
    else
    if Assigned(point.meth.point_finish) then
        point.meth.point_finish(point);
    OPENSSL_clear_free(Pointer(point), sizeof( point^));
end;




function EC_GROUP_get_degree(const group : PEC_GROUP):integer;
begin
    if not Assigned(group.meth.group_get_degree) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := group.meth.group_get_degree(group);
end;


function EC_POINT_mul(const group : PEC_GROUP; r : PEC_POINT;const g_scalar : PBIGNUM; point : PEC_POINT; p_scalar : PBIGNUM; ctx : PBN_CTX):int;
var
  ret : integer;
  num : size_t;
  new_ctx : PBN_CTX;
begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if (0>= ec_point_is_compat(r, group))  or
       ( (point <> nil)  and  (0>= ec_point_is_compat(point, group)))  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if (g_scalar = nil)  and  (p_scalar = nil) then
        Exit(EC_POINT_set_to_infinity(group, r));
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
       new_ctx := BN_CTX_secure_new();
       ctx := new_ctx;
    end;
{$ENDIF}
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    num := get_result( (point <> nil)  and  (p_scalar <> nil) , 1 , 0);
    if Assigned(group.meth.mul) then
       ret := group.meth.mul(group, r, g_scalar, num, @point, @p_scalar, ctx)
    else
        { use default }
        ret := ossl_ec_wNAF_mul(group, r, g_scalar, num, @point, @p_scalar, ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;




function EC_POINT_new(const group : PEC_GROUP):PEC_POINT;
var
  ret : PEC_POINT;
begin
    if group = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if not Assigned(group.meth.point_init) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(nil);
    end;
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.meth := group.meth;
    ret.curve_name := group.curve_name;
    if 0>= ret.meth.point_init(ret) then
    begin
        OPENSSL_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;



function EC_GROUP_get_cofactor(const group : PEC_GROUP; cofactor : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.cofactor = nil then Exit(0);
    if nil = BN_copy(cofactor, group.cofactor) then
        Exit(0);
    Result := int( not BN_is_zero(group.cofactor));
end;

function ossl_ec_group_simple_order_bits(const group : PEC_GROUP):integer;
begin
    if group.order = nil then Exit(0);
    Result := BN_num_bits(group.order);
end;



function EC_POINT_invert(const group : PEC_GROUP; a : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.invert) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(a, group) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Result := group.meth.invert(group, a, ctx);
end;



function EC_POINT_copy(dest : PEC_POINT;const src : PEC_POINT):integer;
begin
    if not Assigned(dest.meth.point_copy) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if (dest.meth <> src.meth)
             or  ( (dest.curve_name <> src.curve_name)
                  and  (dest.curve_name <> 0)
                  and  (src.curve_name <> 0) ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if dest = src then Exit(1);
    Result := dest.meth.point_copy(dest, src);
end;



function EC_POINT_dbl(const group : PEC_GROUP; r : PEC_POINT;const a : PEC_POINT; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.dbl) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if (0>= ec_point_is_compat(r, group))  or  (0>= ec_point_is_compat(a, group))  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Result := group.meth.dbl(group, r, a, ctx);
end;





function EC_POINT_set_Jprojective_coordinates_GFp(const group : PEC_GROUP; point : PEC_POINT;const x, y, z : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.meth.field_type <> NID_X9_62_prime_field then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Exit(ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(group, point,
                                                              x, y, z, ctx));
end;



function EC_GROUP_get_order(const group : PEC_GROUP; order : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if group.order = nil then Exit(0);
    if nil = BN_copy(order, group.order ) then
        Exit(0);
    Result := int( not BN_is_zero(order));
end;



function EC_GROUP_get_curve(const group : PEC_GROUP; p, a, b : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.group_get_curve) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := group.meth.group_get_curve(group, p, a, b, ctx);
end;


function EC_GROUP_get0_generator(const group : PEC_GROUP):PEC_POINT;
begin
    Result := group.generator;
end;




function EC_GROUP_get0_cofactor(const group : PEC_GROUP):PBIGNUM;
begin
    Result := group.cofactor;
end;




function EC_GROUP_get0_seed(const group : PEC_GROUP):PByte;
begin
    Result := group.seed;
end;




function EC_GROUP_get_seed_len(const group : PEC_GROUP):size_t;
begin
    Result := group.seed_len;
end;



function EC_GROUP_get_curve_name(const group : PEC_GROUP):integer;
begin
    Result := group.curve_name;
end;





function BN_bn2bin(const a : PBIGNUM; &to : PByte):integer;
begin
    Result := bn2binpad(a, &to, -1, BIG, UNSIGNED);
end;





function EC_POINT_get_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT; x, y : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.point_get_affine_coordinates ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if EC_POINT_is_at_infinity(group, point) > 0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        Exit(0);
    end;
    Result := group.meth.point_get_affine_coordinates(group, point, x, y, ctx);
end;




function EC_POINT_is_at_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
begin
    if not Assigned(group.meth.is_at_infinity) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Result := group.meth.is_at_infinity(group, point);
end;

function EC_POINT_set_affine_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x, y : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if not Assigned(group.meth.point_set_affine_coordinates) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if 0>= group.meth.point_set_affine_coordinates(group, point, x, y, ctx) then
        Exit(0);
    if EC_POINT_is_on_curve(group, point, ctx)  <= 0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        Exit(0);
    end;
    Result := 1;
end;





function EC_POINT_set_to_infinity(const group : PEC_GROUP; point : PEC_POINT):integer;
begin
    if not Assigned(group.meth.point_set_to_infinity) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if group.meth <> point.meth then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    Result := group.meth.point_set_to_infinity(group, point);
end;




function ec_point_is_compat(const point : PEC_POINT; group : PEC_GROUP):integer;
begin
    Result := Int( (group.meth = point.meth)
            and  (group.curve_name = 0)
                or ( point.curve_name = 0 )
                or ( group.curve_name = point.curve_name));
end;





function ec_field_inverse_mod_ord(const group : PEC_GROUP; r : PBIGNUM;const x : PBIGNUM; ctx : PBN_CTX):integer;
var
  e : PBIGNUM;

  ret : integer;

  new_ctx : PBN_CTX;
  label _err;
begin
    e := nil;
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if group.mont_data = nil then Exit(0);
{$IFNDEF FIPS_MODULE}
    if ctx = nil then
    begin
       new_ctx := BN_CTX_secure_new();
       ctx := new_ctx;
    end;
{$ENDIF}
    if ctx = nil then Exit(0);
    BN_CTX_start(ctx);
    e := BN_CTX_get(ctx );
    if e = nil then
        goto _err ;
    {-
     * We want inverse in constant time, therefore we utilize the fact
     * order must be prime and use Fermats Little Theorem instead.
     }
    if 0>= BN_set_word(e, 2)  then
        goto _err ;
    if 0>= BN_sub(e, group.order, e)  then
        goto _err ;
    {-
     * Exponent e is public.
     * No need for scatter-gather or BN_FLG_CONSTTIME.
     }
    if 0>= BN_mod_exp_mont(r, x, e, group.order, ctx, group.mont_data)  then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;



function ossl_ec_group_do_inverse_ord(const group : PEC_GROUP; res : PBIGNUM;const x : PBIGNUM; ctx : PBN_CTX):integer;
begin
    if Assigned(group.meth.field_inverse_mod_ord ) then
       Exit(group.meth.field_inverse_mod_ord(group, res, x, ctx))
    else
        Result := ec_field_inverse_mod_ord(group, res, x, ctx);
end;




function ec_group_explicit_to_named(const group : PEC_GROUP; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; ctx : PBN_CTX):PEC_GROUP;
var
    ret_group, dup      : PEC_GROUP;
    curve_name_nid : integer;
    point          : PEC_POINT;
    order          : PBIGNUM;
    no_seed        : Boolean;
    label _err;
begin
    ret_group := nil; dup := nil;
     point := EC_GROUP_get0_generator(group);
     order := EC_GROUP_get0_order(group);
    no_seed := (EC_GROUP_get0_seed(group) = nil);
    dup := EC_GROUP_dup(group);
    if  (dup  = nil)
             or  (EC_GROUP_set_seed(dup, nil, 0) <> 1)
             or  (0>= EC_GROUP_set_generator(dup, point, order, nil)) then
        goto _err ;
    curve_name_nid := ossl_ec_curve_nid_from_params(dup, ctx );
    if curve_name_nid  <> NID_undef then
    begin
        {
         * The input explicit parameters successfully matched one of the
         * built-in curves: often for built-in curves we have specialized
         * methods with better performance and hardening.
         *
         * In this case we replace the `EC_GROUP` created through explicit
         * parameters with one created from a named group.
         }
{$IFNDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
        {
         * NID_wap_wsg_idm_ecid_wtls12 and NID_secp224r1 are both aliases for
         * the same curve, we prefer the SECP nid when matching explicit
         * parameters as that is associated with a specialized EC_METHOD.
         }
        if curve_name_nid = NID_wap_wsg_idm_ecid_wtls12 then
            curve_name_nid := NID_secp224r1;
{$endif} { !def(OPENSSL_NO_EC_NISTP_64_GCC_128) }
        ret_group := EC_GROUP_new_by_curve_name_ex(libctx, propq, curve_name_nid);
        if ret_group = nil then
           goto _err ;
        {
         * Set the flag so that EC_GROUPs created from explicit parameters are
         * serialized using explicit parameters by default.
         }
        EC_GROUP_set_asn1_flag(ret_group, OPENSSL_EC_EXPLICIT_CURVE);
        {
         * If the input params do not contain the optional seed field we make
         * sure it is not added to the returned group.
         *
         * The seed field is not really used inside libcrypto anyway, and
         * adding it to parsed explicit parameter keys would alter their DER
         * encoding output (because of the extra field) which could impact
         * applications fingerprinting keys by their DER encoding.
         }
        if no_seed then
        begin
            if EC_GROUP_set_seed(ret_group, nil, 0) <> 1 then
                goto _err ;
        end;
    end
    else
    begin
        ret_group := PEC_GROUP ( group);
    end;
    EC_GROUP_free(dup);
    Exit(ret_group);
_err:
    EC_GROUP_free(dup);
    EC_GROUP_free(ret_group);
    Result := nil;
end;

function ossl_ec_group_set_params(group : PEC_GROUP;const params : POSSL_PARAM):integer;
var
  encoding_flag,
  format        : integer;
  p             : POSSL_PARAM;
begin
    encoding_flag := -1;
    format := -1;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if p <> nil then
    begin
        if  0>= ossl_ec_pt_format_param2id(p, @format) then
        begin
            ECerr(0, EC_R_INVALID_FORM);
            Exit(0);
        end;
        EC_GROUP_set_point_conversion_form(group, point_conversion_form_t(format));
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING);
    if p <> nil then
    begin
        if  0>= ossl_ec_encoding_param2id(p, @encoding_flag) then
        begin
            ECerr(0, EC_R_INVALID_FORM);
            Exit(0);
        end;
        EC_GROUP_set_asn1_flag(group, encoding_flag);
    end;
    { Optional seed }
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if p <> nil then
    begin
        { The seed is allowed to be nil }
        if (p.data_type <> OSSL_PARAM_OCTET_STRING )
             or (0>= EC_GROUP_set_seed(group, p.data, p.data_size)) then
        begin
            ECerr(0, EC_R_INVALID_SEED);
            Exit(0);
        end;
    end;
    Result := 1;
end;

function group_new_from_name(const p : POSSL_PARAM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_GROUP;
var
    ok: Boolean;
    nid         : integer;
    curve_name : PUTF8Char;
begin
    ok := False;
     curve_name := nil;
    case p.data_type of
      OSSL_PARAM_UTF8_STRING:
      begin
          { The OSSL_PARAM functions have no support for this }
          curve_name := p.data;
          ok := (curve_name <> nil);
      end;
      OSSL_PARAM_UTF8_PTR:
          ok := Boolean(OSSL_PARAM_get_utf8_ptr(p, @curve_name));

    end;
    if ok then
    begin
        nid := ossl_ec_curve_name2nid(curve_name);
        if nid = NID_undef then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            Exit(nil);
        end
        else
        begin
            Exit(EC_GROUP_new_by_curve_name_ex(libctx, propq, nid));
        end;
    end;
    Result := nil;
end;




function EC_GROUP_new_from_params(const params : POSSL_PARAM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_GROUP;
var
  ptmp,
  pa,
  pb             : POSSL_PARAM;

  ok             : integer;
  group,named_group          : PEC_GROUP;
  p, a, b, order, cofactor              : PBIGNUM;
  point          : PEC_POINT;
  field_bits,
  is_prime_field : integer;
  bnctx          : PBN_CTX;
  buf            : PByte;
  encoding_flag  : integer;
  label _err;
begin
    ok := 0;
    group := nil; named_group := nil;
    p := nil; a := nil; b := nil; order := nil; cofactor := nil;
    point := nil;
    field_bits := 0;
    is_prime_field := 1;
    bnctx := nil;
     buf := nil;
    encoding_flag := -1;
    { This is the simple named group case }
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if ptmp <> nil then
    begin
        group := group_new_from_name(ptmp, libctx, propq);
        if group <> nil then
        begin
            if 0>= ossl_ec_group_set_params(group, params) then
            begin
                EC_GROUP_free(group);
                group := nil;
            end;
        end;
        Exit(group);
    end;
    { If it gets here then we are trying explicit parameters }
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    BN_CTX_start(bnctx);
    p := BN_CTX_get(bnctx);
    a := BN_CTX_get(bnctx);
    b := BN_CTX_get(bnctx);
    order := BN_CTX_get(bnctx);
    if order = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE);
    if (ptmp = nil)  or  (ptmp.data_type <> OSSL_PARAM_UTF8_STRING) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        goto _err ;
    end;
    if strcasecmp(ptmp.data, SN_X9_62_prime_field) = 0  then
    begin
        is_prime_field := 1;
    end
    else
    if (strcasecmp(ptmp.data, SN_X9_62_characteristic_two_field) = 0) then
    begin
        is_prime_field := 0;
    end
    else
    begin
        { Invalid field }
        ERR_raise(ERR_LIB_EC, EC_R_UNSUPPORTED_FIELD);
        goto _err ;
    end;
    pa := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_A);
    if  0>= OSSL_PARAM_get_BN(pa, @a) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_A);
        goto _err ;
    end;
    pb := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_B);
    if  0>= OSSL_PARAM_get_BN(pb, @b ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_B);
        goto _err ;
    end;
    { extract the prime number or irreducible polynomial }
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_P);
    if  0>= OSSL_PARAM_get_BN(ptmp, @p ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_P);
        goto _err ;
    end;
    if is_prime_field>0 then
    begin
        if (BN_is_negative(p)>0)  or  (BN_is_zero(p)) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_P);
            goto _err ;
        end;
        field_bits := BN_num_bits(p);
        if field_bits > OPENSSL_ECC_MAX_FIELD_BITS then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_FIELD_TOO_LARGE);
            goto _err ;
        end;
        { create the EC_GROUP structure }
        group := EC_GROUP_new_curve_GFp(p, a, b, bnctx);
    end
    else
    begin
{$IFDEF OPENSSL_NO_EC2M}
        ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
        goto _err ;
{$ELSE} { create the EC_GROUP structure }
        group := EC_GROUP_new_curve_GF2m(p, a, b, nil);
        if group <> nil then
        begin
            field_bits := EC_GROUP_get_degree(group);
            if field_bits > OPENSSL_ECC_MAX_FIELD_BITS then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_FIELD_TOO_LARGE);
                goto _err ;
            end;
        end;
{$endif} { OPENSSL_NO_EC2M }
    end;
    if group = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    { Optional seed }
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if ptmp <> nil then
    begin
        if ptmp.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_SEED);
            goto _err ;
        end;
        if  0>= EC_GROUP_set_seed(group, ptmp.data, ptmp.data_size ) then
            goto _err ;
    end;
    { generator base poPInteger }
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GENERATOR);
    if (ptmp = nil)
         or  (ptmp.data_type <> OSSL_PARAM_OCTET_STRING) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
        goto _err ;
    end;
    buf := PByte(ptmp.data);
    point := EC_POINT_new(group );
    if point = nil then
        goto _err ;
    EC_GROUP_set_point_conversion_form(group,
                                       point_conversion_form_t( buf[0] and (not $01) ) );
    if 0>= EC_POINT_oct2point(group, point, buf, ptmp.data_size, bnctx ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
        goto _err ;
    end;
    { order }
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ORDER);
    if (0>= OSSL_PARAM_get_BN(ptmp, @order) ) or
       ( (BN_is_negative(order)>0)  or  (BN_is_zero(order)) )
         or  (BN_num_bits(order) > int(field_bits) + 1) then
    begin  { Hasse bound }
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto _err ;
    end;
    { Optional cofactor }
    ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_COFACTOR);
    if ptmp <> nil then
    begin
        cofactor := BN_CTX_get(bnctx);
        if (cofactor = nil)  or  (0>= OSSL_PARAM_get_BN(ptmp, @cofactor ) )then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_COFACTOR);
            goto _err ;
        end;
    end;
    { set the generator, order and cofactor (if present) }
    if 0>= EC_GROUP_set_generator(group, point, order, cofactor ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
        goto _err ;
    end;
    named_group := ec_group_explicit_to_named(group, libctx, propq, bnctx);
    if named_group = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_NAMED_GROUP_CONVERSION);
        goto _err ;
    end;
    if named_group = group then
    begin
        {
         * If we did(0>= find a named group then the encoding should be explicit
         * if it was specified
         }
        ptmp := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING);
        if (ptmp <> nil)
             and  (0>= ossl_ec_encoding_param2id(ptmp, @encoding_flag) ) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            goto _err ;
        end;
        if encoding_flag = OPENSSL_EC_NAMED_CURVE then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            goto _err ;
        end;
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
    end
    else
    begin
        EC_GROUP_free(group);
        group := named_group;
    end;
    ok := 1;
 _err:
    if (0>= ok) then
    begin
        EC_GROUP_free(group);
        group := nil;
    end;
    EC_POINT_free(point);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    Result := group;
end;

function EC_GROUP_get_field_type(const group : PEC_GROUP):integer;
begin
    Result := group.meth.field_type;
end;




function ossl_ec_group_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; meth : PEC_METHOD):PEC_GROUP;
var
  ret : PEC_GROUP;
  label _err;
begin
    if meth = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_SLOT_FULL);
        Exit(nil);
    end;
    if not Assigned(meth.group_init) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(nil);
    end;
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.libctx := libctx;
    if propq <> nil then
    begin
        OPENSSL_strdup(ret.propq, propq);
        if ret.propq = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    ret.meth := meth;
    if (ret.meth.flags and EC_FLAGS_CUSTOM_CURVE) = 0 then
    begin
        ret.order := BN_new();
        if ret.order = nil then goto _err ;
        ret.cofactor := BN_new();
        if ret.cofactor = nil then goto _err ;
    end;
    ret.asn1_flag := OPENSSL_EC_EXPLICIT_CURVE;
    ret.asn1_form := POINT_CONVERSION_UNCOMPRESSED;
    if  0>= meth.group_init(ret )then
        goto _err ;
    Exit(ret);
 _err:
    BN_free(ret.order);
    BN_free(ret.cofactor);
    OPENSSL_free(ret.propq);
    OPENSSL_free(ret);
    Result := nil;
end;


end.
