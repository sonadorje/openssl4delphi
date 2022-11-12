unit openssl3.crypto.ec.ecp_oct;

interface
uses OpenSSL.Api;

function ossl_ec_GFp_simple_set_compressed_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x_ : PBIGNUM; y_bit : integer; ctx : PBN_CTX):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_mod,
     openssl3.crypto.bn.bn_sqrt, openssl3.crypto.bn.bn_kron,
     openssl3.crypto.bn.bn_add,
     openssl3.crypto.bn.bn_sqr, openssl3.providers.fips.fipsprov;


function ossl_ec_GFp_simple_set_compressed_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x_ : PBIGNUM; y_bit : integer; ctx : PBN_CTX):integer;
var
  new_ctx : PBN_CTX;
  tmp1, tmp2, x, y : PBIGNUM;
  ret : integer;
  err : Cardinal;
  kron : integer;
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
    y_bit := int(y_bit <> 0);
    BN_CTX_start(ctx);
    tmp1 := BN_CTX_get(ctx);
    tmp2 := BN_CTX_get(ctx);
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    if y = nil then goto _err ;
    {-
     * Recover y.  We have a Weierstrass equation
     *     y^2 = x^3 + a*x + b,
     * so  y  is one of the square roots of  x^3 + a*x + b.
     }
    { tmp1 := x^3 }
    if 0>= BN_nnmod(x, x_, group.field, ctx) then
        goto _err ;
    if not Assigned(group.meth.field_decode) then
    begin
        { field_(sqr,mul) work on standard representation }
        if 0>= group.meth.field_sqr(group, tmp2, x_, ctx) then
            goto _err ;
        if 0>= group.meth.field_mul(group, tmp1, tmp2, x_, ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_mod_sqr(tmp2, x_, group.field, ctx) then
            goto _err ;
        if 0>= BN_mod_mul(tmp1, tmp2, x_, group.field, ctx) then
            goto _err ;
    end;
    { tmp1 := tmp1 + a*x }
    if group.a_is_minus3 >0 then
    begin
        if 0>= BN_mod_lshift1_quick(tmp2, x, group.field) then
            goto _err ;
        if 0>= BN_mod_add_quick(tmp2, tmp2, x, group.field) then
            goto _err ;
        if 0>= BN_mod_sub_quick(tmp1, tmp1, tmp2, group.field) then
            goto _err ;
    end
    else
    begin
        if Assigned(group.meth.field_decode) then
        begin
            if 0>= group.meth.field_decode(group, tmp2, group.a, ctx) then
                goto _err ;
            if 0>= BN_mod_mul(tmp2, tmp2, x, group.field, ctx) then
                goto _err ;
        end
        else
        begin
            { field_mul works on standard representation }
            if 0>= group.meth.field_mul(group, tmp2, group.a, x, ctx) then
                goto _err ;
        end;
        if 0>= BN_mod_add_quick(tmp1, tmp1, tmp2, group.field) then
            goto _err ;
    end;
    { tmp1 := tmp1 + b }
    if Assigned(group.meth.field_decode) then
    begin
        if 0>= group.meth.field_decode(group, tmp2, group.b, ctx) then
            goto _err ;
        if 0>= BN_mod_add_quick(tmp1, tmp1, tmp2, group.field) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_mod_add_quick(tmp1, tmp1, group.b, group.field) then
            goto _err ;
    end;
    ERR_set_mark();
    if nil = BN_mod_sqrt(y, tmp1, group.field, ctx) then
    begin
{$IFNDEF FIPS_MODULE}
        err := ERR_peek_last_error();
        if (ERR_GET_LIB(err) = ERR_LIB_BN)
             and  (ERR_GET_REASON(err) = BN_R_NOT_A_SQUARE) then
        begin
            ERR_pop_to_mark();
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_COMPRESSED_POINT);
        end
        else
{$ENDIF}
        begin
            ERR_clear_last_mark();
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        end;
        goto _err ;
    end;
    ERR_clear_last_mark();
    if Boolean(y_bit) <> BN_is_odd(y) then
    begin
        if BN_is_zero(y) then
        begin
            kron := BN_kronecker(x, group.field, ctx);
            if kron = -2 then goto _err ;
            if kron = 1 then
              ERR_raise(ERR_LIB_EC, EC_R_INVALID_COMPRESSION_BIT)
            else
                {
                 * BN_mod_sqrt() should have caught this error (not a square)
                 }
                ERR_raise(ERR_LIB_EC, EC_R_INVALID_COMPRESSED_POINT);
            goto _err ;
        end;
        if 0>= BN_usub(y, group.field, y)  then
            goto _err ;
    end;
    if Boolean(y_bit) <> BN_is_odd(y)  then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    if 0>= EC_POINT_set_affine_coordinates(group, point, x, y, ctx) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := ret;
end;





end.
