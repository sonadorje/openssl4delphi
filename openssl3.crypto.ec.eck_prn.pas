unit openssl3.crypto.ec.eck_prn;

interface
uses OpenSSL.Api;

function ECPKParameters_print(bp : PBIO;const x : PEC_GROUP; off : integer):integer;
function print_bin(fp : PBIO;const name : PUTF8Char; buf : PByte; len : size_t; off : integer):int;

var
    gen_compressed   : PUTF8Char = 'Generator (compressed):';
    gen_uncompressed : PUTF8Char = 'Generator (uncompressed):';
    gen_hybrid       : PUTF8Char = 'Generator (hybrid):';

implementation
uses openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_lib,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.ec.ec_curve,
     openssl3.crypto.bn.bn_lib,  openssl3.crypto.ec.ec_oct,
     openssl3.crypto.asn1.t_pkey, OpenSSL3.Err,
     openssl3.crypto.mem,
     openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bio_print;


function print_bin(fp : PBIO;const name : PUTF8Char; buf : PByte; len : size_t; off : integer):int;
var
  i : size_t;
  str : array[0..(128 + 1 + 4)-1] of UTF8Char;
begin
    if buf = nil then Exit(1);
    if off > 0 then
    begin
        if off > 128 then
            off := 128;
        memset(@str, Ord(' '), off);
        if BIO_write(fp, @str, off) <= 0  then
            Exit(0);
    end
    else
    begin
        off := 0;
    end;
    if BIO_printf(fp, '%s', [name]) <= 0  then
        Exit(0);
    for i := 0 to len-1 do
    begin
        if i mod 15  = 0 then
        begin
            str[0] := #10;
            memset(@(str[1]), Ord(' '), off + 4);
            if BIO_write(fp, @str, off + 1 + 4) <= 0  then
                Exit(0);
        end;
        if BIO_printf(fp, '%02x%s', [buf[i], get_result(i + 1 = len , '' , ':')]) <= 0 then
            Exit(0);
    end;
    if BIO_write(fp, PUTF8Char(#10), 1) <= 0  then
        Exit(0);
    Result := 1;
end;

function ECPKParameters_print(bp : PBIO;const x : PEC_GROUP; off : integer):integer;
var
    ret, reason      : integer;
    ctx              : PBN_CTX;
    point            : PEC_POINT;
    p, a, b          : PBIGNUM;
    gen_buf          : PByte;
    order, cofactor  : PBIGNUM;
    seed             : PByte;
    seed_len,
    gen_buf_len         : size_t;
    nid              : integer;
    form_str,nname         : PUTF8Char;
    is_char_two      : integer;
    form             : point_conversion_form_t;
    tmp_nid,
    basis_type       : integer;
    label _err;
begin
    ret := 0; reason := ERR_R_BIO_LIB;
    ctx := nil;
    point := nil;
    p := nil; a := nil; b := nil;
    gen_buf := nil;
   order := nil; cofactor := nil;
    seed_len := 0; gen_buf_len := 0;
    if nil =x then begin
        reason := ERR_R_PASSED_NULL_PARAMETER;
        goto _err;
    end;
    ctx := BN_CTX_new;
    if ctx = nil then begin
        reason := ERR_R_MALLOC_FAILURE;
        goto _err;
    end;
    if EC_GROUP_get_asn1_flag(x) > 0 then  begin
        { the curve parameter are given by an asn1 OID }
        if 0>=BIO_indent(bp, off, 128) then
            goto _err;
        nid := EC_GROUP_get_curve_name(x);
        if nid = 0 then goto _err;
        if BIO_printf(bp, 'ASN1 OID: %s', [OBJ_nid2sn(nid)])  <= 0  then
            goto _err;
        if BIO_printf(bp, #10,[]) <= 0  then
            goto _err;
        nname := EC_curve_nid2nist(nid);
        if nname <> nil then
        begin
            if 0>=BIO_indent(bp, off, 128) then
                goto _err;
            if BIO_printf(bp, 'NIST CURVE: %s'#10, [nname]) <= 0  then
                goto _err;
        end;
    end
    else
    begin
        { explicit parameters }
        is_char_two := 0;
        tmp_nid := EC_GROUP_get_field_type(x);
        if tmp_nid = NID_X9_62_characteristic_two_field then
           is_char_two := 1;
        p := BN_new ();
        a := BN_new ();
        b := BN_new ();
        if (p = nil)  or  (a = nil)  or (b = nil) then
        begin
            reason := ERR_R_MALLOC_FAILURE;
            goto _err;
        end;
        if 0>=EC_GROUP_get_curve(x, p, a, b, ctx) then
        begin
            reason := ERR_R_EC_LIB;
            goto _err;
        end;
        point := EC_GROUP_get0_generator(x);
        if point = nil then
        begin
            reason := ERR_R_EC_LIB;
            goto _err;
        end;
        order := EC_GROUP_get0_order(x);
        cofactor := EC_GROUP_get0_cofactor(x);
        if order = nil then begin
            reason := ERR_R_EC_LIB;
            goto _err;
        end;
        form := EC_GROUP_get_point_conversion_form(x);
        gen_buf_len := EC_POINT_point2buf(x, point, form, @gen_buf, ctx);
        if gen_buf_len = 0 then begin
            reason := ERR_R_EC_LIB;
            goto _err;
        end;
        seed := EC_GROUP_get0_seed(x);
        if seed <> nil then
            seed_len := EC_GROUP_get_seed_len(x);
        if 0>=BIO_indent(bp, off, 128 ) then
            goto _err;
        { print the 'short name' of the field type }
        if BIO_printf(bp, 'Field Type: %s\n', [OBJ_nid2sn(tmp_nid)]) <= 0 then
            goto _err;
        if is_char_two > 0 then
        begin
            { print the 'short name' of the base type OID }
            basis_type := EC_GROUP_get_basis_type(x);
            if basis_type = 0 then goto _err;
            if 0>=BIO_indent(bp, off, 128 ) then
                goto _err;
            if BIO_printf(bp, 'Basis Type: %s\n',
                           [OBJ_nid2sn(basis_type)]) <= 0  then
                goto _err;
            { print the polynomial }
            if (p <> nil ) and  (0>=ASN1_bn_print(bp, 'Polynomial:', p, nil,
                                              off)) then
                goto _err;
        end
        else
        begin
            if (p <> nil)  and  (0>=ASN1_bn_print(bp, 'Prime:', p, nil, off)) then
                goto _err;
        end;
        if (a <> nil) and  (0>=ASN1_bn_print(bp, 'A:   ', a, nil, off)) then
            goto _err;
        if (b <> nil) and  (0>=ASN1_bn_print(bp, 'B:   ', b, nil, off)) then
            goto _err;
        if form = POINT_CONVERSION_COMPRESSED then
           form_str := gen_compressed
        else if (form = POINT_CONVERSION_UNCOMPRESSED) then
            form_str := gen_uncompressed
        else
            form_str := gen_hybrid;
        if (gen_buf <> nil)
             and  (0>=print_bin(bp, form_str, gen_buf, gen_buf_len, off)) then
            goto _err;
        if (order <> nil)   and  (0>=ASN1_bn_print(bp, 'Order: ', order, nil, off)) then
            goto _err;
        if (cofactor <> nil) and  (0>=ASN1_bn_print(bp, 'Cofactor: ', cofactor, nil, off)) then
            goto _err;
        if (seed <> nil)  and  (0>=print_bin(bp, 'Seed:', seed, seed_len, off)) then
            goto _err;
    end;
    ret := 1;
 _err:
    if 0>=ret then
       ERR_raise(ERR_LIB_EC, reason);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    OPENSSL_clear_free(Pointer(gen_buf), gen_buf_len);
    BN_CTX_free(ctx);
    Result := ret;
end;


end.
