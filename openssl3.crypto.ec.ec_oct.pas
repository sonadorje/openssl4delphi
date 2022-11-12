unit openssl3.crypto.ec.ec_oct;

interface
uses OpenSSL.Api;

 function EC_POINT_point2buf(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; pbuf : PPByte; ctx : PBN_CTX):size_t;
 function ossl_ec_GFp_simple_oct2point(const group : PEC_GROUP; point : PEC_POINT;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
 function EC_POINT_set_compressed_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x : PBIGNUM; y_bit : integer; ctx : PBN_CTX):integer;
 function ossl_ec_GFp_simple_point2oct(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; buf : PByte; len : size_t; ctx : PBN_CTX):size_t;
 function EC_POINT_oct2point(const group : PEC_GROUP; point : PEC_POINT;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
 function EC_POINT_point2oct(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; buf : PByte; len : size_t; ctx : PBN_CTX):size_t;

implementation
uses OpenSSL3.Err, openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ecp_oct,
     openssl3.crypto.ec.ec2_oct, openssl3.crypto.mem;

function get_result(condition: Boolean;result1, result2: size_t): size_t;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;


function EC_POINT_oct2point(const group : PEC_GROUP; point : PEC_POINT;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
begin
    if (not Assigned(group.meth.oct2point))
         and  (0>= (group.meth.flags and EC_FLAGS_DEFAULT_OCT) ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if (group.meth.flags and EC_FLAGS_DEFAULT_OCT) > 0 then
    begin
        if group.meth.field_type = NID_X9_62_prime_field then
            Exit(ossl_ec_GFp_simple_oct2point(group, point, buf, len, ctx))
        else
{$IFDEF OPENSSL_NO_EC2M}
        begin
            ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
            Exit(0);
        end;
{$ELSE}
        Exit(ossl_ec_GF2m_simple_oct2point(group, point, buf, len, ctx));
{$ENDIF}
    end;
    Result := group.meth.oct2point(group, point, buf, len, ctx);
end;



function ossl_ec_GFp_simple_point2oct(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; buf : PByte; len : size_t; ctx : PBN_CTX):size_t;
var
    ret       : size_t;
    new_ctx   : PBN_CTX;
    used_ctx  : integer;
    x,
    y         : PBIGNUM;
    field_len,
    i,
    skip      : size_t;
    label _err;
begin
    new_ctx := nil;
    used_ctx := 0;
    if (form <> POINT_CONVERSION_COMPRESSED)  and  (form <> POINT_CONVERSION_UNCOMPRESSED)
         and  (form <> POINT_CONVERSION_HYBRID) then
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
    field_len := BN_num_bytes(group.field);
    ret := get_result(form = POINT_CONVERSION_COMPRESSED , 1 + field_len , 1 + 2 * field_len);
    { if 'buf' is nil, just return required length }
    if buf <> nil then
    begin
        if len < ret then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
            goto _err ;
        end;
        if ctx = nil then
        begin
            new_ctx := BN_CTX_new_ex(group.libctx);
            ctx := new_ctx;
            if ctx = nil then Exit(0);
        end;
        BN_CTX_start(ctx);
        used_ctx := 1;
        x := BN_CTX_get(ctx);
        y := BN_CTX_get(ctx);
        if y = nil then goto _err ;
        if 0>= EC_POINT_get_affine_coordinates(group, point, x, y, ctx) then
            goto _err ;
        if (form = POINT_CONVERSION_COMPRESSED)
              or  (form = POINT_CONVERSION_HYBRID)  and  (BN_is_odd(y))  then
            buf[0] := Byte(form) + 1
        else
            buf[0] := Byte(form);
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
        if (form = POINT_CONVERSION_UNCOMPRESSED)
             or  (form = POINT_CONVERSION_HYBRID) then
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
    BN_CTX_free(new_ctx);
    Exit(ret);
 _err:
    if used_ctx > 0 then
       BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    Result := 0;
end;





function EC_POINT_set_compressed_coordinates(const group : PEC_GROUP; point : PEC_POINT;const x : PBIGNUM; y_bit : integer; ctx : PBN_CTX):integer;
begin
    if (not Assigned(group.meth.point_set_compressed_coordinates))
         and  (0>= (group.meth.flags and EC_FLAGS_DEFAULT_OCT))  then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if (group.meth.flags and EC_FLAGS_DEFAULT_OCT)>0 then
    begin
        if group.meth.field_type = NID_X9_62_prime_field then
            Exit(ossl_ec_GFp_simple_set_compressed_coordinates(group, point, x,
                                                                 y_bit, ctx))
        else
{$IFDEF OPENSSL_NO_EC2M}
        begin
            ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
            Exit(0);
        end;
{$ELSE}
        Exit(ossl_ec_GF2m_simple_set_compressed_coordinates(group, point,
                                                                  x, y_bit, ctx));
{$ENDIF}
    end;
    Exit(group.meth.point_set_compressed_coordinates(group, point, x, y_bit, ctx));
end;



function ossl_ec_GFp_simple_oct2point(const group : PEC_GROUP; point : PEC_POINT;const buf : PByte; len : size_t; ctx : PBN_CTX):integer;
var
    form      : point_conversion_form_t;
    y_bit     : integer;
    new_ctx   : PBN_CTX;
    x,
    y         : PBIGNUM;

    field_len,
    enc_len   : size_t;
    ret       : integer;
    label _err;
begin
    new_ctx := nil;
    ret := 0;
    if len = 0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    form := point_conversion_form_t(buf[0]);
    y_bit := Int(form) and 1;
    Int(form) := Int(form) and (not 1);
    if (Int(form) <> 0 )  and  (form <> POINT_CONVERSION_COMPRESSED)
         and  (form <> POINT_CONVERSION_UNCOMPRESSED)
         and  (form <> POINT_CONVERSION_HYBRID) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
    if (Int(form) = 0 )  or  (form = POINT_CONVERSION_UNCOMPRESSED)  and ( y_bit>0) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
    if Int(form) = 0 then
    begin
        if len <> 1 then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            Exit(0);
        end;
        Exit(EC_POINT_set_to_infinity(group, point));
    end;
    field_len := BN_num_bytes(group.field);
    enc_len := get_result(form = POINT_CONVERSION_COMPRESSED , 1 + field_len , 1 + 2 * field_len);
    if len <> enc_len then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
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
    if nil = BN_bin2bn(buf + 1, field_len, x )then
        goto _err ;
    if BN_ucmp(x, group.field) >= 0  then
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
        if BN_ucmp(y, group.field) >= 0  then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            goto _err ;
        end;
        if form = POINT_CONVERSION_HYBRID then
        begin
            if Boolean(y_bit) <> BN_is_odd(y) then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                goto _err ;
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
    BN_CTX_free(new_ctx);
    Result := ret;
end;

function EC_POINT_point2oct(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; buf : PByte; len : size_t; ctx : PBN_CTX):size_t;
begin
    if (not Assigned(group.meth.point2oct) )
         and  (0>= (group.meth.flags and EC_FLAGS_DEFAULT_OCT) ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        Exit(0);
    end;
    if 0>= ec_point_is_compat(point, group ) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INCOMPATIBLE_OBJECTS);
        Exit(0);
    end;
    if (group.meth.flags and EC_FLAGS_DEFAULT_OCT)>0  then
    begin
        if group.meth.field_type = NID_X9_62_prime_field then
            Exit(ossl_ec_GFp_simple_point2oct(group, point, form, buf, len, ctx))
        else
{$IFDEF OPENSSL_NO_EC2M}
        begin
            ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
            Exit(0);
        end;
{$ELSE}
        Exit(ossl_ec_GF2m_simple_point2oct(group, point, form, buf, len, ctx));
{$ENDIF}
    end;
    Result := group.meth.point2oct(group, point, form, buf, len, ctx);
end;



function EC_POINT_point2buf(const group : PEC_GROUP; point : PEC_POINT; form : point_conversion_form_t; pbuf : PPByte; ctx : PBN_CTX):size_t;
var
  len : size_t;

  buf : PByte;
begin
    len := EC_POINT_point2oct(group, point, form, nil, 0, nil);
    if len = 0 then Exit(0);
    buf := OPENSSL_malloc(len);
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    len := EC_POINT_point2oct(group, point, form, buf, len, ctx);
    if len = 0 then
    begin
        OPENSSL_free(Pointer(buf));
        Exit(0);
    end;
    pbuf^ := buf;
    Result := len;
end;


end.
