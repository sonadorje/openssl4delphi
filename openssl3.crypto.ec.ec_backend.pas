unit openssl3.crypto.ec.ec_backend;

interface
uses OpenSSL.Api;

function ossl_ec_key_dup(const src : PEC_KEY; selection : integer):PEC_KEY;
 function ossl_ec_group_todata(const group : PEC_GROUP; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; bnctx : PBN_CTX; genbuf : PPByte):integer;
function ossl_ec_pt_format_id2name( id : integer):PUTF8Char;
function ec_param_encoding_id2name( id : integer):PUTF8Char;
function ec_group_explicit_todata(const group : PEC_GROUP; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM; bnctx : PBN_CTX; genbuf : PPByte):integer;
function ossl_ec_check_group_type_id2name( id : integer):PUTF8Char;
 function ossl_ec_group_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
function ossl_ec_pt_format_param2id(const p : POSSL_PARAM; id : PInteger):integer;
function ossl_ec_encoding_param2id(const p : POSSL_PARAM; id : PInteger):integer;

const  format_nameid_map: array[0..2] of TOSSL_ITEM= (
    ( id:int(POINT_CONVERSION_UNCOMPRESSED); ptr:OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED ),
    ( id:int(POINT_CONVERSION_COMPRESSED); ptr:OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED ),
    ( id:int(POINT_CONVERSION_HYBRID); ptr:OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID )
);
   encoding_nameid_map: array[0..1] of TOSSL_ITEM= (
    ( id: OPENSSL_EC_EXPLICIT_CURVE; ptr: OSSL_PKEY_EC_ENCODING_EXPLICIT ),
    ( id: OPENSSL_EC_NAMED_CURVE; ptr: OSSL_PKEY_EC_ENCODING_GROUP )
);
   check_group_type_nameid_map: array[0..2] of TOSSL_ITEM = (
    ( id: 0; ptr: OSSL_PKEY_EC_GROUP_CHECK_DEFAULT ),
    ( id: EC_FLAG_CHECK_NAMED_GROUP; ptr: OSSL_PKEY_EC_GROUP_CHECK_NAMED ),
    ( id: EC_FLAG_CHECK_NAMED_GROUP_NIST; ptr: OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST )
);
function ossl_ec_encoding_name2id(const name : PUTF8Char):integer;
 function ossl_ec_pt_format_name2id(const name : PUTF8Char):integer;
function ossl_ec_key_fromdata(ec : PEC_KEY;const params : POSSL_PARAM; include_private : integer):integer;
function ossl_ec_set_ecdh_cofactor_mode( ec : PEC_KEY; mode : integer):integer;
function ossl_ec_key_otherparams_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
 function ec_set_include_public( ec : PEC_KEY; include : integer):integer;
function ec_key_point_format_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
function ec_key_group_check_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
function ec_set_check_group_type_from_param(ec : PEC_KEY;const p : POSSL_PARAM):integer;
function ossl_ec_set_check_group_type_from_name(ec : PEC_KEY;const name : PUTF8Char):integer;
 function ec_check_group_type_name2id(const name : PUTF8Char):integer;
 function ossl_ec_key_is_foreign(const ec : PEC_KEY):integer;
function ossl_ec_key_param_from_x509_algor(const palg : PX509_ALGOR; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;
 function ossl_ec_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;

function ossl_x509_algor_is_sm2(const palg : PX509_ALGOR):integer;

implementation


uses OpenSSL3.Err, openssl3.crypto.ec.ec_kmeth, openssl3.crypto.engine.eng_init,
     openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_ctx,       openssl3.crypto.asn1.p8_pkey,
     openssl3.crypto.param_build_set, openssl3.crypto.params,
     openssl3.crypto.ec.ec_support, openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ec_oct,     openssl3.crypto.ex_data,
     openssl3.crypto.asn1.x_algor,  openssl3.crypto.ec.ec_asn1,
     openssl3.crypto.ec.ec_curve,   openssl3.crypto.objects.obj_dat,
     openssl3.crypto.bn.bn_intern,  openssl3.crypto.mem, openssl3.crypto.o_str;



function ossl_x509_algor_is_sm2(const palg : PX509_ALGOR):integer;
var
  ptype : integer;
  pval : Pointer;
  str : PASN1_STRING;
  der : PByte;
  derlen : integer;
  group : PEC_GROUP;
  ret : integer;
begin
    ptype := 0;
    pval := nil;
    X509_ALGOR_get0(nil, @ptype, @pval, palg);
    if ptype = V_ASN1_OBJECT then
       Exit(Int(OBJ_obj2nid(PASN1_OBJECT(pval)) = NID_sm2));
    if ptype = V_ASN1_SEQUENCE then begin
        str := pval;
        der := str.data;
        derlen := str.length;
        group := d2i_ECPKParameters(nil, @der, derlen);
        if group = nil then
            ret := 0
        else
            ret := Int(EC_GROUP_get_curve_name(group) = NID_sm2);
        EC_GROUP_free(group);
        Exit(ret);
    end;
    Result := 0;
end;



function ossl_ec_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;
var
  p : PByte;
  pklen : integer;
  eckey : PEC_KEY;
  palg : PX509_ALGOR;
  label _err;
begin
    p := nil;
    eckey := nil;
    if 0>=PKCS8_pkey_get0(nil, @p, @pklen, @palg, p8inf) then
        Exit(0);
    eckey := ossl_ec_key_param_from_x509_algor(palg, libctx, propq);
    if eckey = nil then goto _err;
    { We have parameters now set private key }
    if nil =d2i_ECPrivateKey(@eckey, @p, pklen) then  begin
        ERR_raise(ERR_LIB_EC, EC_R_DECODE_ERROR);
        goto _err;
    end;
    Exit(eckey);
 _err:
    EC_KEY_free(eckey);
    Result := nil;
end;




function ossl_ec_key_param_from_x509_algor(const palg : PX509_ALGOR; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;
var
  ptype : integer;
  pval : Pointer;
  eckey : PEC_KEY;
  group : PEC_GROUP;
  pstr : PASN1_STRING;
  pm : PByte;
  pmlen : integer;
  poid : PASN1_OBJECT;
  label _ecerr;
begin
    ptype := 0;
    pval := nil;
    eckey := nil;
    group := nil;
    X509_ALGOR_get0(nil, @ptype, @pval, palg);
    eckey := EC_KEY_new_ex(libctx, propq);
    if eckey = nil then  begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _ecerr;
    end;
    if ptype = V_ASN1_SEQUENCE then
    begin
         pstr := pval;
        pm := pstr.data;
        pmlen := pstr.length;
        if d2i_ECParameters(@eckey, @pm, pmlen) = nil  then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_DECODE_ERROR);
            goto _ecerr;
        end;
    end
    else
    if (ptype = V_ASN1_OBJECT) then
    begin
         poid := pval;
        {
         * type = V_ASN1_OBJECT => the parameters are given by an asn1 OID
         }
        group := EC_GROUP_new_by_curve_name_ex(libctx, propq, OBJ_obj2nid(poid));
        if group = nil then goto _ecerr;
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        if EC_KEY_set_group(eckey, group ) = 0 then
            goto _ecerr;
        EC_GROUP_free(group);
    end
    else
    begin
        ERR_raise(ERR_LIB_EC, EC_R_DECODE_ERROR);
        goto _ecerr;
    end;
    Exit(eckey);
 _ecerr:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    Result := nil;
end;

function ossl_ec_key_is_foreign(const ec : PEC_KEY):integer;
begin
{$IFNDEF FIPS_MODULE}
    if (ec.engine <> nil)  or  (EC_KEY_get_method(ec) <> EC_KEY_OpenSSL) then
        Exit(1);
{$ENDIF}
    Exit(0);
end;


function ec_check_group_type_name2id(const name : PUTF8Char):integer;
var
  i,
  sz                          : size_t;
begin
    { Return the default value if there is no name }
    if name = nil then Exit(0);
    sz := Length(check_group_type_nameid_map);
    for i := 0  to sz-1 do
    begin
        if strcasecmp(name, check_group_type_nameid_map[i].ptr) = 0  then
            Exit(check_group_type_nameid_map[i].id);
    end;
    Result := -1;
end;

function ossl_ec_set_check_group_type_from_name(ec : PEC_KEY;const name : PUTF8Char):integer;
var
  flags : integer;
begin
    flags := ec_check_group_type_name2id(name);
    if flags = -1 then Exit(0);
    EC_KEY_clear_flags(ec, EC_FLAG_CHECK_NAMED_GROUP_MASK);
    EC_KEY_set_flags(ec, flags);
    Result := 1;
end;




function ec_set_check_group_type_from_param(ec : PEC_KEY;const p : POSSL_PARAM):integer;
var
  name : PUTF8Char;

  status : Boolean;
begin
   name := nil;
    status := Boolean(0);
    case p.data_type of
    OSSL_PARAM_UTF8_STRING:
    begin
        name := p.data;
        status := (name <> nil);
    end;
    OSSL_PARAM_UTF8_PTR:
        status := Boolean(OSSL_PARAM_get_utf8_ptr(p, @name));
       // break;
    end;
    if status then
       Exit(ossl_ec_set_check_group_type_from_name(ec, name));
    Result := 0;
end;




function ec_key_group_check_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE);
    if p <> nil then
      Exit(ec_set_check_group_type_from_param(ec, p));
    Result := 1;
end;

function ec_key_point_format_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;

  format : integer;
begin
    format := -1;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if p <> nil then
    begin
        if  0>= ossl_ec_pt_format_param2id(p, @format) then
        begin
            ECerr(0, EC_R_INVALID_FORM);
            Exit(0);
        end;
        EC_KEY_set_conv_form(ec, point_conversion_form_t(format));
    end;
    Result := 1;
end;


function ec_set_include_public( ec : PEC_KEY; include : integer):integer;
var
  flags : integer;
begin
    flags := EC_KEY_get_enc_flags(ec);
    if  0>= include then
        flags  := flags  or EC_PKEY_NO_PUBKEY
    else
        flags := flags and (not EC_PKEY_NO_PUBKEY);
    EC_KEY_set_enc_flags(ec, flags);
    Result := 1;
end;

function ossl_ec_key_otherparams_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;

  mode, include : integer;
begin
    if ec = nil then Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p <> nil) then
    begin
        if  (0>= OSSL_PARAM_get_int(p, @mode) )
             or (0>= ossl_ec_set_ecdh_cofactor_mode(ec, mode))  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
    if p <> nil then
    begin
        include := 1;
        if  (0>= OSSL_PARAM_get_int(p, @include) ) or
            (0>= ec_set_include_public(ec, include)) then
            Exit(0);
    end;
    if  0>= ec_key_point_format_fromdata(ec, params) then
        Exit(0);
    if  0>= ec_key_group_check_fromdata(ec, params) then
        Exit(0);
    Result := 1;
end;


function ossl_ec_set_ecdh_cofactor_mode( ec : PEC_KEY; mode : integer):integer;
var
    ecg      : PEC_GROUP;

    cofactor : PBIGNUM;
begin
     ecg := EC_KEY_get0_group(ec);
    {
     * mode can be only 0 for disable, or 1 for enable here.
     *
     * This is in contrast with the same parameter on an ECDH EVP_PKEY_CTX that
     * also supports mode = -1 with the meaning of "reset to the default for
     * the associated key".
     }
    if (mode < 0)  or  (mode > 1) then
       Exit(0);
    cofactor := EC_GROUP_get0_cofactor(ecg);
    if cofactor = nil  then
        Exit(0);
    { ECDH cofactor mode has no effect if cofactor is 1 }
    if BN_is_one(cofactor) then
        Exit(1);
    if mode = 1 then
       EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH)
    else
    if (mode = 0) then
       EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH);
    Result := 1;
end;




function ossl_ec_key_fromdata(ec : PEC_KEY;const params : POSSL_PARAM; include_private : integer):integer;
var
  param_priv_key,
  param_pub_key  : POSSL_PARAM;
  ctx            : PBN_CTX;
  priv_key       : PBIGNUM;
  order          : PBIGNUM;
  pub_key        : PByte;
  pub_key_len    : size_t;
  ecg            : PEC_GROUP;
  pub_point      : PEC_POINT;
  ok,
  fixed_words    : integer;
  label _err;
begin
    param_priv_key := nil;
    param_pub_key := nil;
    ctx := nil;
    priv_key := nil;
    pub_key := nil;
    ecg := nil;
    pub_point := nil;
    ok := 0;
    ecg := EC_KEY_get0_group(ec);
    if ecg = nil then Exit(0);
    param_pub_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if include_private >0 then
       param_priv_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
    if ctx = nil then
       goto _err ;
    if param_pub_key <> nil then
    begin
       pub_point := EC_POINT_new(ecg);
       if ( 0>= OSSL_PARAM_get_octet_string(param_pub_key, Pointer(pub_key), 0, @pub_key_len) )
             or  (pub_point = nil )
             or  (0>= EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx)) then
        goto _err ;
    end;
    if (param_priv_key <> nil)  and  (include_private>0) then
    begin
        {
         * Key import/export should never leak the bit length of the secret
         * scalar in the key.
         *
         * For this reason, on export we use padded BIGNUMs with fixed length.
         *
         * When importing we also should make sure that, even if short lived,
         * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
         * soon as possible, so that any processing of this BIGNUM might opt for
         * constant time implementations in the backend.
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
         * For padding on export we just use the bit length of the order
         * converted to bytes (rounding up).
         *
         * For preallocating the BIGNUM storage we look at the number of 'words'
         * required for the internal representation of the order, and we
         * preallocate 2 extra 'words' in case any of the subsequent processing
         * might temporarily overflow the order length.
         }
        order := EC_GROUP_get0_order(ecg);
        if (order = nil)  or  (BN_is_zero(order) )  then
            goto _err ;
        fixed_words := bn_get_top(order) + 2;
        priv_key := BN_secure_new();
        if priv_key = nil then
            goto _err ;
        if bn_wexpand(priv_key, fixed_words) = nil then
            goto _err ;
        BN_set_flags(priv_key, BN_FLG_CONSTTIME);
        if  0>= OSSL_PARAM_get_BN(param_priv_key, @priv_key) then
            goto _err ;
    end;
    if (priv_key <> nil)
         and (0>= EC_KEY_set_private_key(ec, priv_key))  then
        goto _err ;
    if (pub_point <> nil)
         and  (0>= EC_KEY_set_public_key(ec, pub_point) ) then
        goto _err ;
    ok := 1;
 _err:
    BN_CTX_free(ctx);
    BN_clear_free(priv_key);
    OPENSSL_free(Pointer(pub_key));
    EC_POINT_free(Pointer(pub_point));
    Result := ok;
end;






function ossl_ec_pt_format_name2id(const name : PUTF8Char):integer;
var
  i,
  sz                : size_t;
begin
    { Return the default value if there is no name }
    if name = nil then
       Exit(int(POINT_CONVERSION_UNCOMPRESSED));
    sz := Length(format_nameid_map);
    for i := 0 to sz-1 do
    begin
        if strcasecmp(name, format_nameid_map[i].ptr) = 0  then
            Exit(format_nameid_map[i].id);
    end;
    Result := -1;
end;




function ossl_ec_encoding_name2id(const name : PUTF8Char):integer;
var
  i,
  sz                  : size_t;

begin
    { Return the default value if there is no name }
    if name = nil then
       Exit(OPENSSL_EC_NAMED_CURVE);
    sz := Length(encoding_nameid_map);
    for i := 0  to sz-1 do
    begin
        if strcasecmp(name, encoding_nameid_map[i].ptr) = 0  then
            Exit(encoding_nameid_map[i].id);
    end;
    Result := -1;
end;



function ossl_ec_encoding_param2id(const p : POSSL_PARAM; id : PInteger):integer;
var
  name : PUTF8Char;

  status:Boolean;
  i : integer;
begin
     name := nil;
    status := Boolean(0);
    case p.data_type of
        OSSL_PARAM_UTF8_STRING:
        begin
            { The OSSL_PARAM functions have no support for this }
            name := p.data;
            status := (name <> nil);
        end;
        OSSL_PARAM_UTF8_PTR:
            status := Boolean(OSSL_PARAM_get_utf8_ptr(p, @name));
            //break;
    end;
    if status then
    begin
        i := ossl_ec_encoding_name2id(name);
        if i >= 0 then
        begin
            id^ := i;
            Exit(1);
        end;
    end;
    Result := 0;
end;


function ossl_ec_pt_format_param2id(const p : POSSL_PARAM; id : PInteger):integer;
var
  name : PUTF8Char;
  status: Boolean;
   i : integer;
begin
     name := nil;
    status := Boolean(0);
    case p.data_type of
      OSSL_PARAM_UTF8_STRING:
      begin
          { The OSSL_PARAM functions have no support for this }
          name := p.data;
          status := (name <> nil);
      end;
      OSSL_PARAM_UTF8_PTR:
          status := Boolean(OSSL_PARAM_get_utf8_ptr(p, @name));
          //break;
    end;
    if status then
    begin
        i := ossl_ec_pt_format_name2id(name);
        if i >= 0 then
        begin
            id^ := i;
            Exit(1);
        end;
    end;
    Result := 0;
end;

function ossl_ec_group_fromdata(ec : PEC_KEY;const params : POSSL_PARAM):integer;
var
  ok : integer;

  group : PEC_GROUP;
  label _err;
begin
    ok := 0;
    group := nil;
    if ec = nil then Exit(0);
     group := EC_GROUP_new_from_params(params, ossl_ec_key_get_libctx(ec),
                                      ossl_ec_key_get0_propq(ec));
    if  0>= EC_KEY_set_group(ec, group) then
        goto _err ;
    ok := 1;
_err:
    EC_GROUP_free(group);
    Result := ok;
end;

function ossl_ec_check_group_type_id2name( id : integer):PUTF8Char;
var
  i,
  sz                          : size_t;
begin
   sz := Length(check_group_type_nameid_map);
    for i := 0  to sz-1 do
    begin
        if id = int (check_group_type_nameid_map[i].id) then
            Exit(check_group_type_nameid_map[i].ptr);
    end;
    Result := nil;
end;




function ec_group_explicit_todata(const group : PEC_GROUP; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM; bnctx : PBN_CTX; genbuf : PPByte):integer;
var
  ret, fid   : integer;
  field_type : PUTF8Char;
  param,
  param_p,
  param_a,
  param_b    : POSSL_PARAM;
  p,
  a,
  b,
  order      : PBIGNUM;
  genbuf_len : size_t;
  genpt      : PEC_POINT;
  genform    : point_conversion_form_t;
  cofactor   : PBIGNUM;
  seed       : PByte;
  seed_len   : size_t;
 label _err;
begin
    ret := 0;
    param := nil;
     param_p := nil;
     param_a := nil;
     param_b := nil;
    fid := EC_GROUP_get_field_type(group);
    if fid = NID_X9_62_prime_field then
    begin
        field_type := SN_X9_62_prime_field;
    end
    else
    if (fid = NID_X9_62_characteristic_two_field) then
    begin
{$IFDEF OPENSSL_NO_EC2M}
        ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
        goto _err ;
{$ELSE}
        field_type := SN_X9_62_characteristic_two_field;
{$ENDIF}
    end
    else
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        Exit(0);
    end;
    param_p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_P);
    param_a := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_A);
    param_b := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_B);
    if (tmpl <> nil)  or  (param_p <> nil)  or  (param_a <> nil)  or
       (param_b <> nil) then
    begin
        p := BN_CTX_get(bnctx);
        a := BN_CTX_get(bnctx);
        b := BN_CTX_get(bnctx);
        if b = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if  0>= EC_GROUP_get_curve(group, p, a, b, bnctx ) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            goto _err ;
        end;
        if ( 0>= ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_P, p) ) or
           (0>= ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_A, a) )   or
           (0>= ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_B, b)) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    param := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ORDER);
    if (tmpl <> nil)  or  (param <> nil) then
    begin
         order := EC_GROUP_get0_order(group);
        if order = nil then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
            goto _err ;
        end;
        if 0>= ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_ORDER,
                                    order )then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    param := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE);
    if (tmpl <> nil)  or  (param <> nil) then
    begin
        if (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                              OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                              field_type))then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    param := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GENERATOR);
    if (tmpl <> nil)  or  (param <> nil) then
    begin
         genpt := EC_GROUP_get0_generator(group);
        genform := EC_GROUP_get_point_conversion_form(group);
        if genpt = nil then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
            goto _err ;
        end;
        genbuf_len := EC_POINT_point2buf(group, genpt, genform, genbuf, bnctx);
        if genbuf_len = 0 then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
            goto _err ;
        end;
        if  0>= ossl_param_build_set_octet_string(tmpl, params,
                                               OSSL_PKEY_PARAM_EC_GENERATOR,
                                               genbuf^, genbuf_len ) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    param := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_COFACTOR);
    if (tmpl <> nil)  or  (param <> nil) then
    begin
         cofactor := EC_GROUP_get0_cofactor(group);
        if (cofactor <> nil)
             and (0>= ossl_param_build_set_bn(tmpl, params,
                                        OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    param := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if (tmpl <> nil)  or  (param <> nil) then
    begin
        seed := EC_GROUP_get0_seed(group);
        seed_len := EC_GROUP_get_seed_len(group);
        if (seed <> nil)
             and  (seed_len > 0)
             and   (0>= ossl_param_build_set_octet_string(tmpl, params,
                                                  OSSL_PKEY_PARAM_EC_SEED,
                                                  seed, seed_len )) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    ret := 1;
_err:
    Result := ret;
end;





function ec_param_encoding_id2name( id : integer):PUTF8Char;
var
  i,
  sz                  : size_t;
begin
   sz := Length(encoding_nameid_map);
    for i := 0  to sz-1 do
    begin
        if id = int(encoding_nameid_map[i].id)  then
            Exit(encoding_nameid_map[i].ptr);
    end;
    Result := nil;
end;
function ossl_ec_pt_format_id2name( id : integer):PUTF8Char;
var
  i,
  sz                : size_t;
begin
    sz := Length(format_nameid_map);
    for i := 0 to sz-1 do
    begin
        if id = int (format_nameid_map[i].id) then
            Exit(format_nameid_map[i].ptr);
    end;
    Result := nil;
end;


function ossl_ec_group_todata(const group : PEC_GROUP; tmpl : POSSL_PARAM_BLD; params : POSSL_PARAM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; bnctx : PBN_CTX; genbuf : PPByte):integer;
var
  ret, curve_nid, encoding_flag           : integer;
  encoding_name,
  pt_form_name  : PUTF8Char;
  genform       : point_conversion_form_t;
  curve_name    : PUTF8Char;
  label _err;
begin
    ret := 0;
    if group = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    genform := EC_GROUP_get_point_conversion_form(group);
    pt_form_name := ossl_ec_pt_format_id2name(Int(genform));
    if (pt_form_name = nil)
         or  (0>= ossl_param_build_set_utf8_string(
                tmpl, params,
                OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, pt_form_name)) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
        Exit(0);
    end;
    encoding_flag := EC_GROUP_get_asn1_flag(group) and OPENSSL_EC_NAMED_CURVE;
    encoding_name := ec_param_encoding_id2name(encoding_flag);
    if (encoding_name = nil)
         or (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_ENCODING,
                                             encoding_name) )then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
    curve_nid := EC_GROUP_get_curve_name(group);
    {
     * Get the explicit parameters in these two cases:
     * - We do not have a template, i.e. specific parameters are requested
     * - The curve is not a named curve
     }
    if (tmpl = nil)  or  (curve_nid = NID_undef) then
       if ( 0>= ec_group_explicit_todata(group, tmpl, params, bnctx, genbuf)) then
            goto _err ;
    if curve_nid <> NID_undef then
    begin
        { Named curve }
       curve_name := OSSL_EC_curve_nid2name(curve_nid);
        if (curve_name = nil )
             or  (0>= ossl_param_build_set_utf8_string(tmpl, params,
                                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                                 curve_name) ) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            goto _err ;
        end;
    end;
    ret := 1;
_err:
    Result := ret;
end;

function ossl_ec_key_dup(const src : PEC_KEY; selection : integer):PEC_KEY;
var
  ret : PEC_KEY;
  label _err;
begin
    if src = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    ret := ossl_ec_key_new_method_int(src.libctx, src.propq,
                                          src.engine) ;
    if (ret = nil) then
        Exit(nil);
    { copy the parameters }
    if (src.group <> nil)
         and ( (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0) then
    begin
        ret.group := ossl_ec_group_new_ex(src.libctx, src.propq,
                                          src.group.meth);
        if (ret.group = nil)
             or  (0>= EC_GROUP_copy(ret.group, src.group) ) then
            goto _err ;
        if src.meth <> nil then
        begin
{$IF not defined(OPENSSL_NO_ENGINE)  and   not defined(FIPS_MODULE)}
            if (src.engine <> nil)  and ( ENGINE_init(src.engine) = 0 )then
                goto _err ;
            ret.engine := src.engine;
{$ENDIF}
            ret.meth := src.meth;
        end;
    end;
    {  copy the public key }
    if (src.pub_key <> nil)
         and ( (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
    begin
        if ret.group = nil then
            { no parameter-less keys allowed }
            goto _err ;
        ret.pub_key := EC_POINT_new(ret.group);
        if (ret.pub_key = nil)
             or (0>= EC_POINT_copy(ret.pub_key, src.pub_key) ) then
                goto _err ;
    end;
    { copy the private key }
    if (src.priv_key <> nil)
         and ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)  then
    begin
        if ret.group = nil then
            { no parameter-less keys allowed }
            goto _err ;
        ret.priv_key := BN_new();
        if (ret.priv_key = nil)  or (nil = BN_copy(ret.priv_key, src.priv_key) ) then
            goto _err ;
        if ( Assigned(ret.group.meth.keycopy))
             and ( ret.group.meth.keycopy(ret, src) = 0)  then
            goto _err ;
    end;
    { copy the rest }
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS ) <> 0 then
    begin
        ret.enc_flag := src.enc_flag;
        ret.conv_form := src.conv_form;
    end;
    ret.version := src.version;
    ret.flags := src.flags;
{$IFNDEF FIPS_MODULE}
    if  0>= CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EC_KEY,
                            @ret.ex_data, @src.ex_data) then
        goto _err ;
{$ENDIF}
    if (ret.meth <> nil)  and  ( not Assigned(ret.meth.copy)) then
    begin
        if (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) <> OSSL_KEYMGMT_SELECT_KEYPAIR then
            goto _err ;
        if ret.meth.copy(ret, src) = 0 then
            goto _err ;
    end;
    Exit(ret);
 _err:
    EC_KEY_free(ret);
    Result := nil;
end;


end.
