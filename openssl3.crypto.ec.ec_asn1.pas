unit openssl3.crypto.ec.ec_asn1;

interface
uses OpenSSL.Api;

type
  ecpk_parameters_type_t = (
    ECPKPARAMETERS_TYPE_NAMED = 0,
    ECPKPARAMETERS_TYPE_EXPLICIT,
    ECPKPARAMETERS_TYPE_IMPLICIT
) ;

 function i2d_ECPrivateKey(const a : Pointer; _out : PPByte):integer;
 function EC_PRIVATEKEY_new:PEC_PRIVATEKEY;
 function EC_PRIVATEKEY_it:PASN1_ITEM;
  procedure EC_PRIVATEKEY_free( a : PEC_PRIVATEKEY);
 function i2d_EC_PRIVATEKEY(const a : PEC_PRIVATEKEY; _out : PPByte):integer;
 function ECPKPARAMETERS_it:PASN1_ITEM;
 function ECPARAMETERS_it:PASN1_ITEM;
  function X9_62_FIELDID_it:PASN1_ITEM;
  function X9_62_CURVE_it:PASN1_ITEM;
 function X9_62_FIELDID_adb:PASN1_ITEM;
 function X9_62_CHARACTERISTIC_TWO_it:PASN1_ITEM;
 function X9_62_CHARACTERISTIC_TWO_adb:PASN1_ITEM;
 function X9_62_PENTANOMIAL_it:PASN1_ITEM;
 function i2d_ECParameters(const a : Pointer;_out : PPByte):integer;
 function i2d_ECPKParameters(const a : PEC_GROUP;_out : PPByte):integer;
 function _i2d_ECPKPARAMETERS(const a : PECPKPARAMETERS; _out : PPByte):integer;

 function ECPKPARAMETERS_new:PECPKPARAMETERS;
  procedure ECPKPARAMETERS_free( a : PECPKPARAMETERS);
  procedure ECPARAMETERS_free(a : PECPARAMETERS);
  function ECPARAMETERS_new:PECPARAMETERS;
 function ec_asn1_group2fieldid(const group : PEC_GROUP; field : PX9_62_FIELDID):integer;
 function X9_62_CHARACTERISTIC_TWO_new:PX9_62_CHARACTERISTIC_TWO;

 function EC_GROUP_get_ecpkparameters(const group : PEC_GROUP; params : PECPKPARAMETERS):PECPKPARAMETERS;
 function EC_GROUP_get_ecparameters(const group : PEC_GROUP; params : PECPARAMETERS): PECPARAMETERS;
 function X9_62_PENTANOMIAL_new: PX9_62_PENTANOMIAL;
 function ec_asn1_group2curve(const group : PEC_GROUP; curve : PX9_62_CURVE):integer;
 function ECDSA_SIG_new:PECDSA_SIG;
 procedure ECDSA_SIG_free( sig : PECDSA_SIG);
  function ECDSA_size(const ec : PEC_KEY):integer;
 function i2d_ECDSA_SIG(const sig : PECDSA_SIG; ppout : PPByte):integer;
 function d2i_ECDSA_SIG(psig : PPECDSA_SIG;const ppin : PPByte; len : long):PECDSA_SIG;
 function i2o_ECPublicKey(const a : PEC_KEY; _out : PPByte):integer;
 function d2i_ECParameters( a : PPEC_KEY;const _in : PPByte; len : long):PEC_KEY;
 function d2i_ECPKParameters(a : PPEC_GROUP;const _in : PPByte; len : long):PEC_GROUP;
 function EC_GROUP_new_from_ecpkparameters(const params : PECPKPARAMETERS):PEC_GROUP;
 function EC_GROUP_new_from_ecparameters(const params : PECPARAMETERS):PEC_GROUP;
 function o2i_ECPublicKey(a : PPEC_KEY;const _in : PPByte; len : long):PEC_KEY;

 function _d2i_ECPKPARAMETERS(a : PPECPKPARAMETERS;const _in : PPByte; len : long):PECPKPARAMETERS;
 function d2i_ECPrivateKey(a : PPEC_KEY;const _in : PPByte; len : long):PEC_KEY;


var
  EC_PRIVATEKEY_seq_tt: array[0..3] of TASN1_TEMPLATE ;
  ECPKPARAMETERS_ch_tt: array[0..2] of TASN1_TEMPLATE ;
  ECPARAMETERS_seq_tt : array[0..5] of TASN1_TEMPLATE ;
  X9_62_FIELDID_seq_tt: array[0..1] of TASN1_TEMPLATE ;
  X9_62_CURVE_seq_tt  : array[0..2] of TASN1_TEMPLATE ;
  X9_62_FIELDID_adbtbl: array[0..2] of TASN1_ADB_TABLE;
  fieldID_def_tt      : array[0..0] of TASN1_TEMPLATE ;
  char_two_def_tt     : array[0..0] of TASN1_TEMPLATE ;
  X9_62_CHARACTERISTIC_TWO_seq_tt: array[0..2] of TASN1_TEMPLATE ;
  X9_62_PENTANOMIAL_seq_tt       : array[0..2] of TASN1_TEMPLATE ;
  X9_62_CHARACTERISTIC_TWO_adbtbl: array[0..2] of TASN1_ADB_TABLE;

function d2i_EC_PRIVATEKEY(a : PPEC_PRIVATEKEY;const &in : PPByte; len : long):PEC_PRIVATEKEY;
function ECDSA_SIG_set0( sig : PECDSA_SIG; r, s : PBIGNUM):int;
procedure ECDSA_SIG_get0(const sig : PECDSA_SIG; pr, ps : PPBIGNUM);



implementation

uses openssl3.crypto.asn1.tasn_enc, OpenSSL3.Err, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.mem, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.tasn_fre,  openssl3.crypto.ec.ec_lib,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.asn1.a_int, openssl3.crypto.asn1.a_octet,
     openssl3.crypto.asn1.a_bitstr, openssl3.crypto.ec.ec_oct,
     openssl3.crypto.ec.ec_key, openssl3.crypto.asn1.x_int64,
     openssl3.crypto.packet, openssl3.crypto.buffer.buffer,
     openssl3.crypto.asn1_dsa, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.ec.ec_curve, openssl3.crypto.ec.ec_cvt,
     openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.a_object;





procedure ECDSA_SIG_get0(const sig : PECDSA_SIG; pr, ps : PPBIGNUM);
begin
    if pr <> nil then pr^ := sig.r;
    if ps <> nil then ps^ := sig.s;
end;




function ECDSA_SIG_set0( sig : PECDSA_SIG; r, s : PBIGNUM):int;
begin
    if (r = nil)  or  (s = nil) then Exit(0);
    BN_clear_free(sig.r);
    BN_clear_free(sig.s);
    sig.r := r;
    sig.s := s;
    Result := 1;
end;




function d2i_EC_PRIVATEKEY(a : PPEC_PRIVATEKEY;const &in : PPByte; len : long):PEC_PRIVATEKEY;
begin
 Result := PEC_PRIVATEKEY (ASN1_item_d2i(PPASN1_VALUE(a), &in, len, EC_PRIVATEKEY_it));
end;


function d2i_ECPrivateKey(a : PPEC_KEY;const _in : PPByte; len : long):PEC_KEY;
var
    ret         : PEC_KEY;
    priv_key    : PEC_PRIVATEKEY;
    p           : PByte;
    pkey        : PASN1_OCTET_STRING;
    pub_oct     : PByte;
    pub_oct_len : integer;
    label _err;
begin
    ret := nil;
    priv_key := nil;
     p := _in^;
     priv_key := d2i_EC_PRIVATEKEY(nil, @p, len);
    if priv_key = nil then
        Exit(nil);
    if (a = nil)  or  (a^ = nil) then
    begin
        ret := EC_KEY_new();
        if (ret = nil) then  begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
    end
    else
        ret := a^;
    if priv_key.parameters <> nil then
    begin
        EC_GROUP_free(ret.group);
        ret.group := EC_GROUP_new_from_ecpkparameters(priv_key.parameters);
        if (ret.group <> nil)
             and  (priv_key.parameters.&type = Int(ECPKPARAMETERS_TYPE_EXPLICIT)) then
             ret.group.decoded_from_explicit_params := 1;
    end;
    if ret.group = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err;
    end;
    ret.version := priv_key.version;
    if priv_key.privateKey <> nil then begin
        pkey := priv_key.privateKey;
        if EC_KEY_oct2priv(ret, ASN1_STRING_get0_data(pkey),
                            ASN1_STRING_length(pkey)) = 0  then
            goto _err;
    end
    else begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        goto _err;
    end;
    if EC_GROUP_get_curve_name(ret.group) = NID_sm2  then
        EC_KEY_set_flags(ret, EC_FLAG_SM2_RANGE);
    EC_POINT_clear_free(ret.pub_key);
    ret.pub_key := EC_POINT_new(ret.group);
    if ret.pub_key = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err;
    end;
    if priv_key.publicKey <> nil then
    begin
        pub_oct := ASN1_STRING_get0_data(priv_key.publicKey);
        pub_oct_len := ASN1_STRING_length(priv_key.publicKey);
        if 0>=EC_KEY_oct2key(ret, pub_oct, pub_oct_len, nil) then  begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err;
        end;
    end
    else
    begin
        if (not Assigned(ret.group.meth.keygenpub))
             or  (ret.group.meth.keygenpub(ret) = 0) then
                goto _err;
        { Remember the original private-key-only encoding. }
        ret.enc_flag  := ret.enc_flag  or EC_PKEY_NO_PUBKEY;
    end;
    if a <> nil then a^ := ret;
    EC_PRIVATEKEY_free(priv_key);
    _in^ := p;
    PostInc(ret.dirty_cnt);
    Exit(ret);
 _err:
    if (a = nil)  or  (a^ <> ret) then
       EC_KEY_free(ret);
    EC_PRIVATEKEY_free(priv_key);
    Result := nil;
end;




function o2i_ECPublicKey(a : PPEC_KEY;const _in : PPByte; len : long):PEC_KEY;
var
  ret : PEC_KEY;
begin
    ret := nil;
    if (a = nil)  or  (a^ = nil)  or  (a^.group = nil) then
    begin
        {
         * sorry, but a EC_GROUP-structure is necessary to set the public key
         }
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ret := a^;
    { EC_KEY_opt2key updates dirty_cnt }
    if 0>=EC_KEY_oct2key(ret, _in^, len, nil) then begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        Exit(0);
    end;
    _in^  := _in^ + len;
    Result := ret;
end;




function EC_GROUP_new_from_ecparameters(const params : PECPARAMETERS):PEC_GROUP;
var
  ok, tmp          : integer;
  ret,
  dup         : PEC_GROUP;
  p,  a, b    : PBIGNUM;
  point       : PEC_POINT;
  field_bits  : long;
  curve_name  : integer;
  ctx         : PBN_CTX;
  char_two    : PX9_62_CHARACTERISTIC_TWO;
  tmp_long    : long;
  penta       : PX9_62_PENTANOMIAL;
  named_group : PEC_GROUP;
  label _err;
begin
    ok := 0;
    ret := nil;
    dup := nil;
    p := nil;
    a := nil;
    b := nil;
    point := nil;
    curve_name := NID_undef;
    ctx := nil;
    if (params.fieldID = nil)
             or  (params.fieldID.fieldType = nil)
             or  (params.fieldID.p.ptr = nil)then begin
        ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
        goto _err;
    end;
    {
     * Now extract the curve parameters a and b. Note that, although SEC 1
     * specifies the length of their encodings, historical versions of OpenSSL
     * encoded them incorrectly, so we must accept any length for backwards
     * compatibility.
     }
    if (params.curve = nil)
             or  (params.curve.a = nil)  or  (params.curve.a.data = nil)
             or  (params.curve.b = nil)  or  (params.curve.b.data = nil) then begin
        ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
        goto _err;
    end;
    a := BN_bin2bn(params.curve.a.data, params.curve.a.length, nil);
    if a = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err;
    end;
    b := BN_bin2bn(params.curve.b.data, params.curve.b.length, nil);
    if b = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err;
    end;
    { get the field parameters }
    tmp := OBJ_obj2nid(params.fieldID.fieldType);
    if tmp = NID_X9_62_characteristic_two_field then
{$ifdef OPENSSL_NO_EC2M}
    begin
        ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
        goto_err;
    end;
{$ELSE}
   begin
        char_two := params.fieldID.p.char_two;
        field_bits := char_two.m;
        if field_bits > OPENSSL_ECC_MAX_FIELD_BITS then begin
            ERR_raise(ERR_LIB_EC, EC_R_FIELD_TOO_LARGE);
            goto _err;
        end;
         p := BN_new();
        if p = nil then  begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        { get the base type }
        tmp := OBJ_obj2nid(char_two.&type);
        if tmp = NID_X9_62_tpBasis then
        begin
            if nil =char_two.p.tpBasis then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
                goto _err;
            end;
            tmp_long := ASN1_INTEGER_get(char_two.p.tpBasis);
            if not ( (char_two.m > tmp_long)  and  (tmp_long > 0) )  then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_INVALID_TRINOMIAL_BASIS);
                goto _err;
            end;
            { create the polynomial }
            if 0>=BN_set_bit(p, int(char_two.m)) then
                goto _err;
            if 0>=BN_set_bit(p, int(tmp_long)) then
                goto _err;
            if 0>=BN_set_bit(p, 0) then
                goto _err;
        end
        else
        if (tmp = NID_X9_62_ppBasis) then
        begin
            penta := char_two.p.ppBasis;
            if penta = nil then begin
                ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
                goto _err;
            end;
            if not ( (char_two.m > penta.k3)  and  (penta.k3 > penta.k2)
                  and  (penta.k2 > penta.k1)  and  (penta.k1 > 0) ) then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_INVALID_PENTANOMIAL_BASIS);
                goto _err;
            end;
            { create the polynomial }
            if 0>=BN_set_bit(p, int(char_two.m)) then
                goto _err;
            if 0>=BN_set_bit(p, int(penta.k1)) then
                goto _err;
            if 0>=BN_set_bit(p, int(penta.k2)) then
                goto _err;
            if 0>=BN_set_bit(p, int(penta.k3)) then
                goto _err;
            if 0>=BN_set_bit(p, 0) then
                goto _err;
        end
        else
        if (tmp = NID_X9_62_onBasis) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_NOT_IMPLEMENTED);
            goto _err;
        end
        else begin                 { error }
            ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
            goto _err;
        end;
        { create the EC_GROUP structure }
        ret := EC_GROUP_new_curve_GF2m(p, a, b, nil);
    end
{$ENDIF}
    else if (tmp = NID_X9_62_prime_field) then
    begin
        { we have a curve over a prime field }
        { extract the prime number }
        if params.fieldID.p.prime = nil then begin
            ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
            goto _err;
        end;
        p := ASN1_INTEGER_to_BN(params.fieldID.p.prime, nil);
        if p = nil then begin
            ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
            goto _err;
        end;
        if (BN_is_negative(p)>0) or  (BN_is_zero(p))  then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
            goto _err;
        end;
        field_bits := BN_num_bits(p);
        if field_bits > OPENSSL_ECC_MAX_FIELD_BITS then begin
            ERR_raise(ERR_LIB_EC, EC_R_FIELD_TOO_LARGE);
            goto _err;
        end;
        { create the EC_GROUP structure }
        ret := EC_GROUP_new_curve_GFp(p, a, b, nil);
    end
    else
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        goto _err;
    end;
    if ret = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err;
    end;
    { extract seed (optional) }
    if params.curve.seed <> nil then
    begin
        OPENSSL_free(Pointer(ret.seed));
        ret.seed := OPENSSL_malloc(params.curve.seed.length);
        if ret.seed = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        memcpy(ret.seed, params.curve.seed.data,
               params.curve.seed.length);
        ret.seed_len := params.curve.seed.length;
    end;
    if (params.order = nil)
             or  (params.base = nil)
             or  (params.base.data = nil)
             or  (params.base.length = 0) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
        goto _err;
    end;
    point := EC_POINT_new(ret);
    if point = nil then
        goto _err;
    { set the point conversion form }
    EC_GROUP_set_point_conversion_form(ret, point_conversion_form_t
                                       (params.base.data[0] and not $01));
    { extract the ec poPInteger /
    if 0>=EC_POINT_oct2point(ret, point, params.base.data,
                            params.base.length, nil then ) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto_err;
    }
    { extract the order }
    a := ASN1_INTEGER_to_BN(params.order, a );
    if a = nil then  begin
        ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
        goto _err;
    end;
    if (BN_is_negative(a)>0) or  (BN_is_zero(a)) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto _err;
    end;
    if BN_num_bits(a) > int(field_bits + 1)  then begin  { Hasse bound }
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto _err;
    end;
    { extract the cofactor (optional) }
    if params.cofactor = nil then begin
        BN_free(b);
        b := nil;
    end
    else
    begin
        b := ASN1_INTEGER_to_BN(params.cofactor, b);
        if (b = nil) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
            goto _err;
        end;
    end;
    { set the generator, order and cofactor (if present) }
    if 0>=EC_GROUP_set_generator(ret, point, a, b) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err;
    end;
    {
     * Check if the explicit parameters group just created matches one of the
     * built-in curves.
     *
     * We create a copy of the group just built, so that we can remove optional
     * fields for the lookup: we do this to avoid the possibility that one of
     * the optional parameters is used to force the library into using a less
     * performant and less secure EC_METHOD instead of the specialized one.
     * In any case, `seed` is not really used in any computation, while a
     * cofactor different from the one in the built-in table is just
     * mathematically wrong anyway and should not be used.
     }
    ctx := BN_CTX_new();
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err;
    end;
    dup := EC_GROUP_dup(ret);
    if (dup = nil )
             or  (EC_GROUP_set_seed(dup, nil, 0) <> 1)
             or  (0>=EC_GROUP_set_generator(dup, point, a, nil)) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err;
    end;
    curve_name := ossl_ec_curve_nid_from_params(dup, ctx);
    if curve_name <> NID_undef then
    begin
        {
         * The input explicit parameters successfully matched one of the
         * built-in curves: often for built-in curves we have specialized
         * methods with better performance and hardening.
         *
         * In this case we replace the `EC_GROUP` created through explicit
         * parameters with one created from a named group.
         }
        named_group := nil;
{$IFNDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
        {
         * NID_wap_wsg_idm_ecid_wtls12 and NID_secp224r1 are both aliases for
         * the same curve, we prefer the SECP nid when matching explicit
         * parameters as that is associated with a specialized EC_METHOD.
         }
        if curve_name = NID_wap_wsg_idm_ecid_wtls12 then
           curve_name := NID_secp224r1;
{$endif} { !def(OPENSSL_NO_EC_NISTP_64_GCC_128) }
        named_group := EC_GROUP_new_by_curve_name(curve_name);
        if named_group = nil then  begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err;
        end;
        EC_GROUP_free(ret);
        ret := named_group;
        {
         * Set the flag so that EC_GROUPs created from explicit parameters are
         * serialized using explicit parameters by default.
         }
        EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE);
        {
         * If the input params do not contain the optional seed field we make
         * sure it is not added to the returned group.
         *
         * The seed field is not really used inside libcrypto anyway, and
         * adding it to parsed explicit parameter keys would alter their DER
         * encoding output (because of the extra field) which could impact
         * applications fingerprinting keys by their DER encoding.
         }
        if params.curve.seed = nil then
        begin
            if EC_GROUP_set_seed(ret, nil, 0) <> 1 then
                goto _err;
        end;
    end;
    ok := 1;
 _err:
    if 0>=ok then begin
        EC_GROUP_free(ret);
        ret := nil;
    end;
    EC_GROUP_free(dup);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_POINT_free(point);
    BN_CTX_free(ctx);
    Result := ret;
end;

function EC_GROUP_new_from_ecpkparameters(const params : PECPKPARAMETERS):PEC_GROUP;
var
  ret : PEC_GROUP;

  tmp : integer;
begin
    ret := nil;
    tmp := 0;
    if params = nil then begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        Exit(nil);
    end;
    if params.&type = Int(ECPKPARAMETERS_TYPE_NAMED) then
    begin
        { the curve is given by an OID }
        tmp := OBJ_obj2nid(params.value.named_curve);
        ret := EC_GROUP_new_by_curve_name(tmp);
        if ret = nil then  begin
            ERR_raise(ERR_LIB_EC, EC_R_EC_GROUP_NEW_BY_NAME_FAILURE);
            Exit(nil);
        end;
        EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_NAMED_CURVE);
    end
    else
    if params.&type = Int(ECPKPARAMETERS_TYPE_EXPLICIT) then
    begin
        { the parameters are given by an ECPARAMETERS structure }
        ret := EC_GROUP_new_from_ecparameters(params.value.parameters);
        if nil =ret then begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            Exit(nil);
        end;
        EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE);
    end
    else if params.&type = Int(ECPKPARAMETERS_TYPE_IMPLICIT) then
    begin
        { implicit parameters inherited from CA - unsupported }
        Exit(nil);
    end
    else
    begin
        ERR_raise(ERR_LIB_EC, EC_R_ASN1_ERROR);
        Exit(nil);
    end;
    Result := ret;
end;

function _d2i_ECPKPARAMETERS(a : PPECPKPARAMETERS;const _in : PPByte; len : long):PECPKPARAMETERS;
begin
   Result := PECPKPARAMETERS(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ECPKPARAMETERS_it));
end;


function d2i_ECPKParameters(a : PPEC_GROUP;const _in : PPByte; len : long):PEC_GROUP;
var
  group : PEC_GROUP;
  params : PECPKPARAMETERS;
  p : PByte;
begin
    group := nil;
    params := nil;
     p := _in^;
    params := _d2i_ECPKPARAMETERS(nil, @p, len);
    if params = nil then  begin
        ECPKPARAMETERS_free(params);
        Exit(nil);
    end;
    group := EC_GROUP_new_from_ecpkparameters(params);
    if group = nil then  begin
        ECPKPARAMETERS_free(params);
        Exit(nil);
    end;
    if params.&type = Int(ECPKPARAMETERS_TYPE_EXPLICIT) then
       group.decoded_from_explicit_params := 1;
    if a <> nil then begin
        EC_GROUP_free( a^);
        a^ := group;
    end;
    ECPKPARAMETERS_free(params);
    _in^ := p;
    Result := group;
end;

function d2i_ECParameters(a : PPEC_KEY;const _in : PPByte; len : long):PEC_KEY;
var
  ret : PEC_KEY;
begin
    if (_in = nil)  or  (_in^ = nil) then begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if (a = nil)  or  (a^ = nil) then
    begin
        ret := EC_KEY_new;
        if (ret = nil) then  begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else
        ret := a^;

    if nil =d2i_ECPKParameters(@ret.group, _in, len) then
    begin
        if (a = nil)  or  (a^ <> ret) then
             EC_KEY_free(ret)
        else
            PostInc(ret.dirty_cnt);
        Exit(nil);
    end;
    if EC_GROUP_get_curve_name(ret.group) = NID_sm2  then
        EC_KEY_set_flags(ret, EC_FLAG_SM2_RANGE);
    PostInc(ret.dirty_cnt);
    if a <> nil then a^ := ret;
    Result := ret;
end;



function i2o_ECPublicKey(const a : PEC_KEY; _out : PPByte):integer;
var
    buf_len    : size_t;

    new_buffer : integer;
begin
    buf_len := 0;
    new_buffer := 0;
    if a = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    buf_len := EC_POINT_point2oct(a.group, a.pub_key,
                                 a.conv_form, nil, 0, nil);
    if (_out = nil)  or  (buf_len = 0) then { _out = nil => just return the length of the octet string }
        Exit(buf_len);
    if _out = nil then begin
       _out := OPENSSL_malloc(buf_len);
        if ( _out = nil) then  begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        new_buffer := 1;
    end;
    if 0>=EC_POINT_point2oct(a.group, a.pub_key, a.conv_form,
                            _out^, buf_len, nil ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        if new_buffer > 0 then
        begin
            OPENSSL_free(_out);
            _out := nil;
        end;
        Exit(0);
    end;
    if 0>=new_buffer then
       _out^  := _out^ + buf_len;
    Result := buf_len;
end;




function d2i_ECDSA_SIG(psig : PPECDSA_SIG;const ppin : PPByte; len : long):PECDSA_SIG;
var
  sig : PECDSA_SIG;
begin
    if len < 0 then Exit(nil);
    if (psig <> nil)  and  (psig^ <> nil) then
    begin
        sig := psig^;
    end
    else
    begin
        sig := ECDSA_SIG_new();
        if sig = nil then Exit(nil);
    end;
    if sig.r = nil then sig.r := BN_new();
    if sig.s = nil then sig.s := BN_new();
    if (sig.r = nil)  or  (sig.s = nil)
         or  (ossl_decode_der_dsa_sig(sig.r, sig.s, ppin, size_t( len)) = 0) then
    begin
        if (psig = nil)  or  (psig^ = nil) then
            ECDSA_SIG_free(sig);
        Exit(nil);
    end;
    if (psig <> nil)  and  (psig^ = nil) then
        psig^ := sig;
    Result := sig;
end;


function i2d_ECDSA_SIG(const sig : PECDSA_SIG; ppout : PPByte):integer;
var
    buf         : PBUF_MEM;
    encoded_len : size_t;
    pkt         : TWPACKET;
begin
    buf := nil;
    if ppout = nil then
    begin
        if 0>= WPACKET_init_null(@pkt, 0) then
            Exit(-1);
    end
    else
    if ( ppout^ = nil) then
    begin
        buf := BUF_MEM_new();
        if (buf = nil)
                 or  (0>= WPACKET_init_len(@pkt, buf, 0)) then
        begin
            BUF_MEM_free(buf);
            Exit(-1);
        end;
    end
    else
    begin
        if 0>= WPACKET_init_static_len(@pkt, ppout^, SIZE_MAX, 0) then
            Exit(-1);
    end;
    if (0>= ossl_encode_der_dsa_sig(@pkt, sig.r, sig.s)) or
       (0>= WPACKET_get_total_written(@pkt, @encoded_len))
             or  (0>= WPACKET_finish(@pkt))  then
    begin
        BUF_MEM_free(buf);
        WPACKET_cleanup(@pkt);
        Exit(-1);
    end;
    if ppout <> nil then
    begin
        if ppout^ = nil then
        begin
            ppout^ := PByte( buf.data);
            buf.data := nil;
            BUF_MEM_free(buf);
        end
        else
        begin
            ppout^  := ppout^ + encoded_len;
        end;
    end;
    Result := int (encoded_len);
end;





function ECDSA_size(const ec : PEC_KEY):integer;
var
  ret : integer;
  sig : TECDSA_SIG;
  group : PEC_GROUP;
  bn : PBIGNUM;
begin
    if ec = nil then Exit(0);
    group := EC_KEY_get0_group(ec);
    if group = nil then Exit(0);
    bn := EC_GROUP_get0_order(group);
    if bn = nil then Exit(0);
    sig.r := PBIGNUM(bn);
    sig.s := PBIGNUM(bn);

    ret := i2d_ECDSA_SIG(@sig, nil);
    if ret < 0 then ret := 0;
    Result := ret;
end;




procedure ECDSA_SIG_free( sig : PECDSA_SIG);
begin
    if sig = nil then Exit;
    BN_clear_free(sig.r);
    BN_clear_free(sig.s);
    OPENSSL_free(Pointer(sig));
end;




function ECDSA_SIG_new:PECDSA_SIG;
var
  sig : PECDSA_SIG;
begin
    sig := OPENSSL_zalloc(sizeof( sig^));
    if sig = nil then
       ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    Result := sig;
end;


function ec_asn1_group2curve(const group : PEC_GROUP; curve : PX9_62_CURVE):integer;
var
  ok : integer;

  tmp_1, tmp_2 : PBIGNUM;

  a_buf, b_buf : PByte;

  len : size_t;
  label _err;
begin
    ok := 0;
    tmp_1 := nil;
    tmp_2 := nil;
    a_buf := nil;
    b_buf := nil;
    if (nil = group)  or  (nil = curve)  or  (nil = curve.a)  or  (nil = curve.b) then
       Exit(0);
    tmp_1 := BN_new();
    tmp_2 := BN_new();
    if (tmp_1 = nil)  or  (tmp_2 = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    { get a and b }
    if 0>= EC_GROUP_get_curve(group, nil, tmp_1, tmp_2, nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    {
     * Per SEC 1, the curve coefficients must be padded up to size. See C.2's
     * definition of Curve, C.1's definition of FieldElement, and 2.3.5's
     * definition of how to encode the field elements.
     }
    len := size_t( EC_GROUP_get_degree(group) + 7) div 8;
    a_buf := OPENSSL_malloc(len);
    b_buf := OPENSSL_malloc(len);
    if (a_buf = nil)or  (b_buf = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if (BN_bn2binpad(tmp_1, a_buf, len) < 0)
         or  (BN_bn2binpad(tmp_2, b_buf, len) < 0) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    { set a and b }
    if (0>= ASN1_OCTET_STRING_set(curve.a, a_buf, len)) or
       (0>= ASN1_OCTET_STRING_set(curve.b, b_buf, len))  then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
        goto _err ;
    end;
    { set the seed (optional) }
    if group.seed <> nil  then
    begin
        if nil = curve.seed then
        begin
            curve.seed := ASN1_BIT_STRING_new();
            if (curve.seed =  nil) then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
        end;
        curve.seed.flags := curve.seed.flags and not (ASN1_STRING_FLAG_BITS_LEFT or $07);
        curve.seed.flags  := curve.seed.flags  or ASN1_STRING_FLAG_BITS_LEFT;
        if 0>= ASN1_BIT_STRING_set(curve.seed, group.seed,
                                 int (group.seed_len)) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
            goto _err ;
        end;
    end
    else
    begin
        ASN1_BIT_STRING_free(curve.seed);
        curve.seed := nil;
    end;
    ok := 1;
 _err:
    OPENSSL_free(Pointer(a_buf));
    OPENSSL_free(Pointer(b_buf));
    BN_free(tmp_1);
    BN_free(tmp_2);
    Result := ok;
end;



function X9_62_PENTANOMIAL_new: PX9_62_PENTANOMIAL;
begin
  RESULT := PX9_62_PENTANOMIAL(ASN1_item_new(X9_62_PENTANOMIAL_it));
end;




function X9_62_CHARACTERISTIC_TWO_new:PX9_62_CHARACTERISTIC_TWO;
begin
 Result := PX9_62_CHARACTERISTIC_TWO(ASN1_item_new(X9_62_CHARACTERISTIC_TWO_it));
end;




function ec_asn1_group2fieldid(const group : PEC_GROUP; field : PX9_62_FIELDID):integer;
var
    ok, nid         : integer;
    tmp        : PBIGNUM;
    field_type : integer;
    char_two   : PX9_62_CHARACTERISTIC_TWO;
    k,
    k1,
    k2,
    k3         : uint32;
    label _err;
begin
    ok := 0;
    tmp := nil;
    if (group = nil)  or  (field = nil) then Exit(0);
    { clear the old values (if necessary) }
    ASN1_OBJECT_free(field.fieldType);
    ASN1_TYPE_free(field.p.other);
    nid := EC_GROUP_get_field_type(group);
    { set OID for the field }
    field.fieldType := OBJ_nid2obj(nid);
    if field.fieldType = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_OBJ_LIB);
        goto _err ;
    end;
    if nid = NID_X9_62_prime_field then
    begin
        tmp := BN_new();
        if (tmp = nil) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        { the parameters are specified by the prime number p }
        if 0>= EC_GROUP_get_curve(group, tmp, nil, nil, nil ) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
        { set the prime number }
        field.p.prime := BN_to_ASN1_INTEGER(tmp, nil);
        if field.p.prime = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
            goto _err ;
        end;
    end
    else
    if (nid = NID_X9_62_characteristic_two_field) then
{$IFDEF OPENSSL_NO_EC2M}
    begin
        ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
        goto _err ;
    end;
{$ELSE}
    begin
        field.p.char_two := X9_62_CHARACTERISTIC_TWO_new();
        char_two := field.p.char_two;
        if char_two = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        char_two.m := long(EC_GROUP_get_degree(group));
        field_type := EC_GROUP_get_basis_type(group);
        if field_type = 0 then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
        { set base type OID }
        char_two.&type := OBJ_nid2obj(field_type);
        if char_two.&type  = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_OBJ_LIB);
            goto _err ;
        end;
        if field_type = NID_X9_62_tpBasis then
        begin
            if 0>= EC_GROUP_get_trinomial_basis(group, @k) then
                goto _err ;
            char_two.p.tpBasis := ASN1_INTEGER_new();
            if char_two.p.tpBasis = nil then begin
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            if 0>= ASN1_INTEGER_set(char_two.p.tpBasis, long(k)) then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
                goto _err ;
            end;
        end
        else
        if (field_type = NID_X9_62_ppBasis) then
        begin
            if 0>= EC_GROUP_get_pentanomial_basis(group, @k1, @k2, @k3) then
                goto _err ;
            char_two.p.ppBasis := X9_62_PENTANOMIAL_new();
            if char_two.p.ppBasis = nil then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            { set k? values }
            char_two.p.ppBasis.k1 := long(k1);
            char_two.p.ppBasis.k2 := long(k2);
            char_two.p.ppBasis.k3 := long(k3);
        end
        else
        begin                 { field_type = NID_X9_62_onBasis }
            { for ONB the parameters are (asn1) nil }
            char_two.p.onBasis := ASN1_NULL_new();
            if char_two.p.onBasis = nil then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
        end;
    end
{$ENDIF}
    else
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNSUPPORTED_FIELD);
        goto _err ;
    end;
    ok := 1;
 _err:
    BN_free(tmp);
    Result := ok;
end;


function ECPARAMETERS_new:PECPARAMETERS;
begin
 Result := PECPARAMETERS(ASN1_item_new(ECPARAMETERS_it));
end;



function EC_GROUP_get_ecparameters(const group : PEC_GROUP; params : PECPARAMETERS): PECPARAMETERS;
var
  len : size_t;

  ret : PECPARAMETERS;

  tmp : PBIGNUM;

  buffer : PByte;

  point : PEC_POINT;

  form : point_conversion_form_t;

  orig : PASN1_INTEGER;
  label _err;
begin
    len := 0;
    ret := nil;
    buffer := nil;
     point := nil;
    if params = nil then
    begin
        ret := ECPARAMETERS_new();
        if ret = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end
    else
        ret := params;
    { set the version (always one) }
    ret.version := long($1);
    { set the fieldID }
    if 0>= ec_asn1_group2fieldid(group, ret.fieldID ) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    { set the curve }
    if 0>= ec_asn1_group2curve(group, ret.curve) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    { set the base poPInteger }
    point := EC_GROUP_get0_generator(group);
    if point = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
        goto _err ;
    end;
    form := EC_GROUP_get_point_conversion_form(group);
    len := EC_POINT_point2buf(group, point, form, @buffer, nil);
    if len = 0 then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    ret.base := ASN1_OCTET_STRING_new( );
    if (ret.base = nil)  and  (ret.base = nil) then
    begin
        OPENSSL_free(Pointer(buffer));
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    ASN1_STRING_set0(PASN1_STRING(ret.base), buffer, len);
    { set the order }
    tmp := EC_GROUP_get0_order(group);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    orig := ret.order;
    ret.order := BN_to_ASN1_INTEGER(tmp, orig);
    if ret.order = nil then
    begin
        ret.order := orig;
        ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
        goto _err ;
    end;
    { set the cofactor (optional) }
    tmp := EC_GROUP_get0_cofactor(group);
    if tmp <> nil then
    begin
        orig := ret.cofactor;
        ret.cofactor := BN_to_ASN1_INTEGER(tmp, orig);
        if ret.cofactor = nil then
        begin
            ret.cofactor := orig;
            ERR_raise(ERR_LIB_EC, ERR_R_ASN1_LIB);
            goto _err ;
        end;
    end;
    Exit(ret);
 _err:
    if params = nil then ECPARAMETERS_free(ret);
    Result := nil;
end;

procedure ECPARAMETERS_free( a : PECPARAMETERS);
begin
   ASN1_item_free(PASN1_VALUE( a), (ECPARAMETERS_it));
end;


procedure ECPKPARAMETERS_free( a : PECPKPARAMETERS);
begin
   ASN1_item_free(PASN1_VALUE( a), (ECPKPARAMETERS_it));
end;




function ECPKPARAMETERS_new:PECPKPARAMETERS;
begin
 Result := PECPKPARAMETERS(ASN1_item_new(ECPKPARAMETERS_it));
end;



function EC_GROUP_get_ecpkparameters(const group : PEC_GROUP; params : PECPKPARAMETERS):PECPKPARAMETERS;
var
  ok, tmp : integer;

  ret : PECPKPARAMETERS;

  asn1obj : PASN1_OBJECT;
begin
    ok := 1;
    ret := params;
    if ret = nil then
    begin
        ret := ECPKPARAMETERS_new();
        if ret = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else
    begin
        if ret.&type = Int(ECPKPARAMETERS_TYPE_NAMED) then
           ASN1_OBJECT_free(ret.value.named_curve)
        else
        if (ret.&type = Int(ECPKPARAMETERS_TYPE_EXPLICIT))
                  and ( ret.value.parameters <> nil) then
            ECPARAMETERS_free(ret.value.parameters);
    end;
    if EC_GROUP_get_asn1_flag(group) = OPENSSL_EC_NAMED_CURVE then
    begin
        {
         * use the asn1 OID to describe the elliptic curve parameters
         }
        tmp := EC_GROUP_get_curve_name(group);
        if tmp > 0 then
        begin
            asn1obj := OBJ_nid2obj(tmp);
            if (asn1obj = nil)  or  (OBJ_length(asn1obj) = 0)  then
            begin
                ASN1_OBJECT_free(asn1obj);
                ERR_raise(ERR_LIB_EC, EC_R_MISSING_OID);
                ok := 0;
            end
            else
            begin
                ret.&type := Int(ECPKPARAMETERS_TYPE_NAMED);
                ret.value.named_curve := asn1obj;
            end;
        end
        else
            { we don't know the nid => ERROR }
            ok := 0;
    end
    else
    begin
        { use the ECPARAMETERS structure }
        ret.&type := Int(ECPKPARAMETERS_TYPE_EXPLICIT);
        ret.value.parameters := EC_GROUP_get_ecparameters(group, nil);
        if (ret.value.parameters = nil) then
            ok := 0;
    end;
    if 0>= ok then
    begin
        ECPKPARAMETERS_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;

function _i2d_ECPKPARAMETERS(const a : PECPKPARAMETERS; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ECPKPARAMETERS_it);
end;

function i2d_ECPKParameters(const a : PEC_GROUP;_out : PPByte):integer;
var
  ret : integer;
  tmp : PECPKPARAMETERS;
begin
    ret := 0;
    tmp := EC_GROUP_get_ecpkparameters(a, nil);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_GROUP2PKPARAMETERS_FAILURE);
        Exit(0);
    end;
    ret := _i2d_ECPKPARAMETERS(tmp, _out );
    if ret = 0 then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_I2D_ECPKPARAMETERS_FAILURE);
        ECPKPARAMETERS_free(tmp);
        Exit(0);
    end;
    ECPKPARAMETERS_free(tmp);
    Result := ret;
end;

function i2d_ECParameters(const a : Pointer; _out : PPByte):integer;
begin
    if a = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    Result := i2d_ECPKParameters(PEC_KEY(a).group, _out);
end;




function X9_62_PENTANOMIAL_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @X9_62_PENTANOMIAL_seq_tt,
                 sizeof(X9_62_PENTANOMIAL_seq_tt) div sizeof(TASN1_TEMPLATE),
                 Pointer(0) , sizeof(TX9_62_PENTANOMIAL), 'X9_62_PENTANOMIAL');
  result := @local_it;
end;





function X9_62_CHARACTERISTIC_TWO_adb:PASN1_ITEM;
var
  internal_adb : TASN1_ADB;
begin
  internal_adb := get_ASN1_ADB(0, size_t(@PX9_62_CHARACTERISTIC_TWO(0).&type), nil,
                      @X9_62_CHARACTERISTIC_TWO_adbtbl,
                      sizeof(X9_62_CHARACTERISTIC_TWO_adbtbl) div sizeof(TASN1_ADB_TABLE),
                      @char_two_def_tt, Pointer(0));
  result := PASN1_ITEM(@internal_adb);
end;




function X9_62_CHARACTERISTIC_TWO_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @X9_62_CHARACTERISTIC_TWO_seq_tt,
              sizeof(X9_62_CHARACTERISTIC_TWO_seq_tt) div sizeof(TASN1_TEMPLATE),
              Pointer(0) , sizeof(TX9_62_CHARACTERISTIC_TWO),
               'X9_62_CHARACTERISTIC_TWO');
  Result := @local_it;
end;




function X9_62_FIELDID_adb:PASN1_ITEM;
var
  internal_adb : TASN1_ADB;
begin
  internal_adb := get_ASN1_ADB( 0, size_t(@PX9_62_FIELDID(0).fieldType),
                  nil, @X9_62_FIELDID_adbtbl,
                  sizeof(X9_62_FIELDID_adbtbl) div sizeof(TASN1_ADB_TABLE),
                  @fieldID_def_tt, Pointer(0));
   result := PASN1_ITEM(@internal_adb);
end;




function X9_62_CURVE_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @X9_62_CURVE_seq_tt,
     sizeof(X9_62_CURVE_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
     sizeof(TX9_62_CURVE), 'X9_62_CURVE');
  Exit(@local_it);
end;


function X9_62_FIELDID_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @X9_62_FIELDID_seq_tt,
      sizeof(X9_62_FIELDID_seq_tt) div sizeof(TASN1_TEMPLATE),
      Pointer(0) , sizeof(X9_62_FIELDID), 'X9_62_FIELDID');
   exit(@local_it);
end;


function ECPARAMETERS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @ECPARAMETERS_seq_tt,
     sizeof(ECPARAMETERS_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
     sizeof(TECPARAMETERS), 'ECPARAMETERS');
  result := @local_it;
end;


function ECPKPARAMETERS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($2, size_t(@PECPKPARAMETERS(0).&type) ,
                      @ECPKPARAMETERS_ch_tt,
                     sizeof(ECPKPARAMETERS_ch_tt) div sizeof(TASN1_TEMPLATE),
                     Pointer(0) , sizeof(TECPKPARAMETERS),
                      'ECPKPARAMETERS');
   result := @local_it;
end;

procedure EC_PRIVATEKEY_free( a : PEC_PRIVATEKEY);
begin
  ASN1_item_free(PASN1_VALUE(a), EC_PRIVATEKEY_it);
end;


function i2d_EC_PRIVATEKEY(const a : PEC_PRIVATEKEY; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, EC_PRIVATEKEY_it);
end;

function EC_PRIVATEKEY_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it :=get_ASN1_ITEM( $1, 16, @EC_PRIVATEKEY_seq_tt,
       sizeof(EC_PRIVATEKEY_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
       sizeof(TEC_PRIVATEKEY), 'EC_PRIVATEKEY');

   Result := @local_it;
end;


function EC_PRIVATEKEY_new:PEC_PRIVATEKEY;
begin
   result := PEC_PRIVATEKEY(ASN1_item_new(EC_PRIVATEKEY_it));
end;



function i2d_ECPrivateKey(const a : Pointer; _out : PPByte):integer;
var
    ret, ok      : integer;
    priv, pub     : PByte;
    privlen, publen  : size_t;
    priv_key : PEC_PRIVATEKEY;
    label _err;
begin
    ret := 0; ok := 0;
    priv := nil; pub := nil;
    privlen := 0; publen := 0;
    priv_key := nil;
    if (a = nil)  or  (PEC_KEY(a).group = nil)  or
        ( (0>= (PEC_KEY(a).enc_flag and EC_PKEY_NO_PUBKEY)) and  (PEC_KEY(a).pub_key = nil) )  then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        goto _err ;
    end;
    priv_key := EC_PRIVATEKEY_new();
    if priv_key  = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    priv_key.version := PEC_KEY(a).version;
    privlen := EC_KEY_priv2buf(a, @priv);
    if privlen = 0 then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    ASN1_STRING_set0(PASN1_STRING(priv_key.privateKey), priv, privlen);
    priv := nil;
    if 0>= (PEC_KEY(a).enc_flag and EC_PKEY_NO_PARAMETERS)  then
    begin
        priv_key.parameters :=  EC_GROUP_get_ecpkparameters(PEC_KEY(a).group,
                                        priv_key.parameters);
        if (priv_key.parameters = nil) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
    end;
    if 0>= (PEC_KEY(a).enc_flag and EC_PKEY_NO_PUBKEY)  then
    begin
        priv_key.publicKey := ASN1_BIT_STRING_new();
        if priv_key.publicKey = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        publen := EC_KEY_key2buf(a, PEC_KEY(a).conv_form, @pub, nil);
        if publen = 0 then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto _err ;
        end;
        priv_key.publicKey.flags := priv_key.publicKey.flags and (not (ASN1_STRING_FLAG_BITS_LEFT or $07));
        priv_key.publicKey.flags := priv_key.publicKey.flags  or ASN1_STRING_FLAG_BITS_LEFT;
        ASN1_STRING_set0(PASN1_STRING(priv_key.publicKey), pub, publen);
        pub := nil;
    end;
    ret := i2d_EC_PRIVATEKEY(priv_key, _out);
    if ret  = 0 then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto _err ;
    end;
    ok := 1;
 _err:
    OPENSSL_clear_free(Pointer(priv), privlen);
    OPENSSL_free(Pointer(pub));
    EC_PRIVATEKEY_free(priv_key);
    Result := get_result(ok >0, ret , 0);
end;


initialization

EC_PRIVATEKEY_seq_tt[0] := get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@PEC_PRIVATEKEY(0).version), 'version', INT32_it );
EC_PRIVATEKEY_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PEC_PRIVATEKEY(0).privateKey)), 'privateKey', ASN1_OCTET_STRING_it );
EC_PRIVATEKEY_seq_tt[2] := get_ASN1_TEMPLATE( (($2 shl 3) or ($2 shl 6))  or  $1, 0, size_t(@PEC_PRIVATEKEY(0).parameters), 'parameters', ECPKPARAMETERS_it );
EC_PRIVATEKEY_seq_tt[3] := get_ASN1_TEMPLATE( (($2 shl 3) or ($2 shl 6))  or  $1, 1, size_t(@PEC_PRIVATEKEY(0).publicKey), 'publicKey', ASN1_BIT_STRING_it );

ECPKPARAMETERS_ch_tt[0] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPKPARAMETERS(0).value.named_curve)), 'value.named_curve', ASN1_OBJECT_it );
ECPKPARAMETERS_ch_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPKPARAMETERS(0).value.parameters)), 'value.parameters', ECPARAMETERS_it );
ECPKPARAMETERS_ch_tt[2] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPKPARAMETERS(0).value.implicitlyCA)), 'value.implicitlyCA', ASN1_NULL_it );

ECPARAMETERS_seq_tt[0] := get_ASN1_TEMPLATE( (($1 shl 12)), 0, (size_t(@PECPARAMETERS(0).version)), 'version', INT32_it );
ECPARAMETERS_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPARAMETERS(0).fieldID)), 'fieldID', X9_62_FIELDID_it );
ECPARAMETERS_seq_tt[2] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPARAMETERS(0).curve)), 'curve', X9_62_CURVE_it );
ECPARAMETERS_seq_tt[3] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPARAMETERS(0).base)), 'base', ASN1_OCTET_STRING_it );
ECPARAMETERS_seq_tt[4] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PECPARAMETERS(0).order)), 'order', ASN1_INTEGER_it );
ECPARAMETERS_seq_tt[5] := get_ASN1_TEMPLATE( (($1)), 0, (size_t(@PECPARAMETERS(0).cofactor)), 'cofactor', ASN1_INTEGER_it );

X9_62_FIELDID_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PX9_62_FIELDID(0).fieldType)), 'fieldType', ASN1_OBJECT_it );
X9_62_FIELDID_seq_tt[1] := get_ASN1_TEMPLATE( ($1 shl 8), -1, 0, 'X9_62_FIELDID', X9_62_FIELDID_adb );

X9_62_CURVE_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PX9_62_CURVE(0).a)), 'a', ASN1_OCTET_STRING_it );
X9_62_CURVE_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PX9_62_CURVE(0).b)), 'b', ASN1_OCTET_STRING_it );
X9_62_CURVE_seq_tt[2] := get_ASN1_TEMPLATE( $1, 0, (size_t(@PX9_62_CURVE(0).seed)), 'seed', ASN1_BIT_STRING_it );

X9_62_FIELDID_adbtbl[0] := get_ASN1_ADB_TABLE(406, get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_FIELDID(0).p.prime), 'p.prime', ASN1_INTEGER_it));
X9_62_FIELDID_adbtbl[1] := get_ASN1_ADB_TABLE(407, get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_FIELDID(0).p.char_two), 'p.char_two', X9_62_CHARACTERISTIC_TWO_it) );

fieldID_def_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_FIELDID(0).p.other), 'p.other', ASN1_ANY_it);


X9_62_CHARACTERISTIC_TWO_seq_tt[0] := get_ASN1_TEMPLATE( (($1 shl 12)), 0, (size_t(@PX9_62_CHARACTERISTIC_TWO(0).m)), 'm', INT32_it );
X9_62_CHARACTERISTIC_TWO_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, (size_t(@PX9_62_CHARACTERISTIC_TWO(0).&type)), 'type', ASN1_OBJECT_it );
X9_62_CHARACTERISTIC_TWO_seq_tt[2] := get_ASN1_TEMPLATE( ($1 shl 8), -1, 0, 'X9_62_CHARACTERISTIC_TWO', X9_62_CHARACTERISTIC_TWO_adb );

X9_62_CHARACTERISTIC_TWO_adbtbl[0] := get_ASN1_ADB_TABLE(681, get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_CHARACTERISTIC_TWO(0).p.onBasis), 'p.onBasis', ASN1_NULL_it ));
X9_62_CHARACTERISTIC_TWO_adbtbl[1] := get_ASN1_ADB_TABLE(682, get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_CHARACTERISTIC_TWO(0).p.tpBasis), 'p.tpBasis', ASN1_INTEGER_it ));
X9_62_CHARACTERISTIC_TWO_adbtbl[2] := get_ASN1_ADB_TABLE(683, get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_CHARACTERISTIC_TWO(0).p.ppBasis), 'p.ppBasis', X9_62_PENTANOMIAL_it ));

char_two_def_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@PX9_62_CHARACTERISTIC_TWO(0).p.other), 'p.other', ASN1_ANY_it);


X9_62_PENTANOMIAL_seq_tt[0] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX9_62_PENTANOMIAL(0).k1), 'k1', INT32_it );
X9_62_PENTANOMIAL_seq_tt[1] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX9_62_PENTANOMIAL(0).k2), 'k2', INT32_it );
X9_62_PENTANOMIAL_seq_tt[2] := get_ASN1_TEMPLATE( ($1 shl 12), 0, size_t(@PX9_62_PENTANOMIAL(0).k3), 'k3', INT32_it );
end.
