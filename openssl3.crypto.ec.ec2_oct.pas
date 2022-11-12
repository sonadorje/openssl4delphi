unit openssl3.crypto.ec.ec2_oct;

interface
uses OpenSSL.Api;

function ossl_ec_GF2m_simple_set_compressed_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x_ : PBIGNUM; y_bit : integer; ctx : PBN_CTX):integer;
  function ossl_ec_GF2m_simple_point2oct(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; buf : PByte; len : size_t; ctx : PBN_CTX):size_t;
  function ossl_ec_GF2m_simple_oct2point(const group : PEC_GROUP; point : PEC_POINT;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
  function EC_GROUP_get_degree(const group : PEC_GROUP):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ecp_oct,
     openssl3.crypto.ec.ec_oct,
     openssl3.crypto.bn.bn_gf2m, openssl3.providers.fips.fipsprov;





function EC_GROUP_get_degree(const group : PEC_GROUP):integer;
begin
    if not Assigned(group.meth.group_get_degree ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    Result := group.meth.group_get_degree(group);
end;

function ossl_ec_GF2m_simple_set_compressed_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x_ : PBIGNUM; y_bit : integer; ctx : PBN_CTX):integer;
var
  tmp, x, y, z : PBIGNUM;
  ret, z0 : integer;
  new_ctx : PBN_CTX;
  err : Cardinal;
  label _err;

begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx;
        if ctx = nil then Exit(0);
    end;
{$ENDIF}
    y_bit := get_result(y_bit <> 0 , 1 , 0);
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    z := BN_CTX_get(ctx);
    if z = nil then goto _err ;
    if 0>= BN_GF2m_mod_arr(x, x_, @group.poly) then
        goto _err ;
    if BN_is_zero(x)  then
    begin
        if 0>= BN_GF2m_mod_sqrt_arr(y, group.b, @group.poly, ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= group.meth.field_sqr(group, tmp, x, ctx ) then
            goto _err ;
        if 0>= group.meth.field_div(group, tmp, group.b, tmp, ctx ) then
            goto _err ;
        if 0>= BN_GF2m_add(tmp, group.a, tmp ) then
            goto _err ;
        if 0>= BN_GF2m_add(tmp, x, tmp ) then
            goto _err ;
        ERR_set_mark();
        if 0>= BN_GF2m_mod_solve_quad_arr(z, tmp, @group.poly, ctx ) then
        begin
{$IFNDEF FIPS_MODULE}
            err := ERR_peek_last_error();
            if (ERR_GET_LIB(err) = ERR_LIB_BN)
                 and  (ERR_GET_REASON(err) = BN_R_NO_SOLUTION)  then
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
        z0 := get_result(BN_is_odd(z), 1 , 0);
        if 0>= group.meth.field_mul(group, y, x, z, ctx ) then
            goto _err ;
        if z0 <> y_bit then
        begin
            if 0>= BN_GF2m_add(y, y, x) then
                goto _err ;
        end;
    end;
    if 0>= EC_POINT_set_affine_coordinates(group, point, x, y, ctx ) then
        goto _err ;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;


function ossl_ec_GF2m_simple_point2oct(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; buf : PByte; len : size_t; ctx : PBN_CTX):size_t;
var
    ret       : size_t;
    used_ctx  : integer;
    x,
    y,
    yxi       : PBIGNUM;
    field_len,
    i,
    skip      : size_t;
    new_ctx   : PBN_CTX;
    label _err;
begin
    used_ctx := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if (form <> POINT_CONVERSION_COMPRESSED)  and  (form <> POINT_CONVERSION_UNCOMPRESSED)
         and  (form <> POINT_CONVERSION_HYBRID)  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
        goto _err ;
    end;
    if EC_POINT_is_at_infinity(group, point) > 0 then
    begin
        { encodes to a single 0 octet }
        if buf <> nil then
        begin
            if len < 1 then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
                Exit(0);
            end;
            buf[0] := 0;
        end;
        Exit(1);
    end;
    { ret := required output buffer length }
    field_len := (EC_GROUP_get_degree(group) + 7) div 8;
    if form = POINT_CONVERSION_COMPRESSED then
       ret := 1 + field_len
    else
       ret := 1 + 2 * field_len;
    { if 'buf' is nil, just return required length }
    if buf <> nil then
    begin
        if len < ret then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
            goto _err ;
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
        used_ctx := 1;
        x := BN_CTX_get(ctx);
        y := BN_CTX_get(ctx);
        yxi := BN_CTX_get(ctx);
        if yxi = nil then goto _err ;
        if 0>= EC_POINT_get_affine_coordinates(group, point, x, y, ctx )then
            goto _err ;
        buf[0] := Byte(form);
        if (form <> POINT_CONVERSION_UNCOMPRESSED)  and  (not BN_is_zero(x)) then
        begin
            if 0>= group.meth.field_div(group, yxi, y, x, ctx) then
                goto _err ;
            if BN_is_odd(yxi) then
                Inc(buf[0]);
        end;
        i := 1;
        skip := field_len - BN_num_bytes(x);
        if skip > field_len then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
        while skip > 0 do
        begin
            buf[PostInc(i)] := 0;
            Dec(skip);
        end;
        skip := BN_bn2bin(x, buf + i);
        i  := i + skip;
        if i <> 1 + field_len then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
        if (form = POINT_CONVERSION_UNCOMPRESSED)  or
           (form = POINT_CONVERSION_HYBRID) then
        begin
            skip := field_len - BN_num_bytes(y);
            if skip > field_len then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
            while skip > 0 do
            begin
                buf[PostInc(i)] := 0;
                Dec(skip);
            end;
            skip := BN_bn2bin(y, buf + i);
            i  := i + skip;
        end;
        if i <> ret then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
    end;
    if used_ctx > 0 then
       BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Exit(ret);
 _err:
    if used_ctx > 0 then
       BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := 0;
end;


function ossl_ec_GF2m_simple_oct2point(const group : PEC_GROUP; point : PEC_POINT;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
var
    form      : point_conversion_form_t;
    y_bit,
    m         : integer;
    x,
    y,
    yxi       : PBIGNUM;
    field_len,
    enc_len   : size_t;
    ret       : integer;
    new_ctx   : PBN_CTX;
    label _err;
begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    new_ctx := nil;
{$ENDIF}
    if len = 0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    {
     * The first octet is the point conversion octet PC, see X9.62, page 4
     * and section 4.4.2.  It must be:
     *     $00          for the point at infinity
     *     $02 or $03  for compressed form
     *     $04          for uncompressed form
     *     $06 or $07  for hybrid form.
     * For compressed or hybrid forms, we store the last bit of buf[0] as
     * y_bit and clear it from buf[0] so as to obtain a POINT_CONVERSION_*.
     * We error if buf[0] contains any but the above values.
     }
    y_bit := buf[0] and 1;
    Int(form) := buf[0] and (not 1);
    if (Int(form) <> 0)  and  (form <> POINT_CONVERSION_COMPRESSED)
         and  (form <> POINT_CONVERSION_UNCOMPRESSED)
         and  (form <> POINT_CONVERSION_HYBRID) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
    if (Int(form) <> 0)  or  (form = POINT_CONVERSION_UNCOMPRESSED)  and
       (y_bit > 0) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
    { The point at infinity is represented by a single zero octet. }
    if Int(form) = 0 then
    begin
        if len <> 1 then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            Exit(0);
        end;
        Exit(EC_POINT_set_to_infinity(group, point));
    end;
    m := EC_GROUP_get_degree(group);
    field_len := (m + 7) div 8;
    if form = POINT_CONVERSION_COMPRESSED then
       enc_len := 1 + field_len
    else
       enc_len := 1 + 2 * field_len;
    if len <> enc_len then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
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
    x := BN_CTX_get(ctx);
    y := BN_CTX_get(ctx);
    yxi := BN_CTX_get(ctx);
    if yxi = nil then goto _err ;
    if nil = BN_bin2bn(buf + 1, field_len, x ) then
        goto _err ;
    if BN_num_bits(x) > m  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        goto _err ;
    end;
    if form = POINT_CONVERSION_COMPRESSED then
    begin
        if 0>= EC_POINT_set_compressed_coordinates(group, point, x, y_bit, ctx) then
            goto _err ;
    end
    else
    begin
        if nil = BN_bin2bn(buf + 1 + field_len, field_len, y) then
            goto _err ;
        if BN_num_bits(y) > m then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            goto _err ;
        end;
        if form = POINT_CONVERSION_HYBRID then
        begin
            {
             * Check that the form in the encoding was set correctly
             * according to X9.62 4.4.2.a, 4(c), see also first paragraph
             * of X9.62, 4.4.1.b.
             }
            if BN_is_zero(x) then
            begin
                if y_bit <> 0 then
                begin
                    ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                    goto _err ;
                end;
            end
            else
            begin
                if 0>= group.meth.field_div(group, yxi, y, x, ctx) then
                    goto _err ;
                if Boolean(y_bit) <> BN_is_odd(yxi) then
                begin
                    ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                    goto _err ;
                end;
            end;
        end;
        {
         * EC_POINT_set_affine_coordinates is responsible for checking that
         * the point is on the curve.
         }
        if 0>= EC_POINT_set_affine_coordinates(group, point, x, y, ctx ) then
            goto _err ;
    end;
    ret := 1;
 _err:
    BN_CTX_end(ctx);
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(new_ctx);
{$ENDIF}
    Result := ret;
end;




end.
