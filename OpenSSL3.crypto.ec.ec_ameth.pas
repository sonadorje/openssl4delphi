unit OpenSSL3.crypto.ec.ec_ameth;

interface
uses OpenSSL.Api;

type
  ec_print_t = (
    EC_KEY_PRINT_PRIVATE,
    EC_KEY_PRINT_PUBLIC,
    EC_KEY_PRINT_PARAM
  ) ;

  function eckey_param2type(pptype : PInteger; ppval : PPointer;const ec_key : PEC_KEY):integer;
  function eckey_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
  function eckey_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
  function eckey_pub_cmp(const a, b : PEVP_PKEY):integer;
  function eckey_priv_decode_ex(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function eckey_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
  function int_ec_size(const pkey : PEVP_PKEY):integer;
  function ec_bits(const pkey : PEVP_PKEY):integer;
  function ec_security_bits(const pkey : PEVP_PKEY):integer;
  function ec_missing_parameters(const pkey : PEVP_PKEY):integer;
  function ec_copy_parameters(_to : PEVP_PKEY;const from : PEVP_PKEY):integer;
  function ec_cmp_parameters(const a, b : PEVP_PKEY):integer;
  procedure int_ec_free( pkey : PEVP_PKEY);
  function do_EC_KEY_print(bp : PBIO;const x : PEC_KEY; off : integer; ktype : ec_print_t):integer;
  function eckey_param_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
  function eckey_param_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
  function eckey_param_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function eckey_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function eckey_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function old_ec_priv_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
  function old_ec_priv_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
  function ec_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
  function ec_pkey_check(const pkey : PEVP_PKEY):integer;
  function ec_pkey_public_check(const pkey : PEVP_PKEY):integer;
  function ec_pkey_param_check(const pkey : PEVP_PKEY):integer;
  function ec_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
  function ec_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function ec_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function ec_pkey_copy( _to, from : PEVP_PKEY):integer;
  function EC_KEY_print(bp : PBIO;const x : PEC_KEY; off : integer):integer;
  function ECParameters_print(bp : PBIO;const x : PEC_KEY):integer;

const
  ossl_eckey_asn1_meth: TEVP_PKEY_ASN1_METHOD = (
    pkey_id: EVP_PKEY_EC;
    pkey_base_id: EVP_PKEY_EC;
    pkey_flags: 0;
    pem_str: 'EC';
    info: 'OpenSSL EC algorithm';
    pub_decode: eckey_pub_decode;
    pub_encode: eckey_pub_encode;
    pub_cmp: eckey_pub_cmp;
    pub_print: eckey_pub_print;
    priv_decode: nil;
    priv_encode: eckey_priv_encode;
    priv_print: eckey_priv_print;
    pkey_size: int_ec_size;
    pkey_bits: ec_bits;
    pkey_security_bits: ec_security_bits;
    param_decode: eckey_param_decode;
    param_encode: eckey_param_encode;
    param_missing: ec_missing_parameters;
    param_copy: ec_copy_parameters;
    param_cmp: ec_cmp_parameters;
    param_print: eckey_param_print;
    sig_print: nil;
    pkey_free: int_ec_free;
    pkey_ctrl: ec_pkey_ctrl;
    old_priv_decode: old_ec_priv_decode;
    old_priv_encode: old_ec_priv_encode;
    item_verify: nil; item_sign: nil; siginf_set: nil;
    pkey_check: ec_pkey_check;
    pkey_public_check: ec_pkey_public_check;
    pkey_param_check: ec_pkey_param_check;
    set_priv_key: nil; set_pub_key: nil; get_priv_key: nil; get_pub_key: nil;
    dirty_cnt: ec_pkey_dirty_cnt;
    export_to: ec_pkey_export_to;
    import_from: ec_pkey_import_from;
    copy: ec_pkey_copy;
    priv_decode_ex: eckey_priv_decode_ex
);

ossl_sm2_asn1_meth: TEVP_PKEY_ASN1_METHOD  = (
   pkey_id: EVP_PKEY_SM2;
   pkey_base_id: EVP_PKEY_EC;
   pkey_flags: ASN1_PKEY_ALIAS
);

function ossl_ec_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEC_KEY;

implementation
uses OpenSSL3.Err, openssl3.crypto.ec.ec_key, openssl3.crypto.ec.ec_lib,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.a_object,
     openssl3.crypto.mem, openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.ec.ec_backend, openssl3.crypto.evp,
     OpenSSL3.common,  openssl3.crypto.evp.p_legacy,
     openssl3.crypto.params_dup,  openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.bn.bn_ctx,  openssl3.crypto.ec.ec_oct,
     OpenSSL3.crypto.ec.ec_check,   openssl3.crypto.param_build,
     openssl3.crypto.ec.eck_prn,    openssl3.crypto.evp.p_lib,
     openssl3.crypto.asn1.p8_pkey,  openssl3.crypto.bio.bio_lib,
     openssl3.crypto.bio.bio_print,  openssl3.crypto.asn1.t_pkey,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.ec.ec_asn1;






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

function eckey_param2type(pptype : PInteger; ppval : PPointer;const ec_key : PEC_KEY):integer;
var
  group : PEC_GROUP;
  nid : integer;
  asn1obj : PASN1_OBJECT;
  pstr : PASN1_STRING;
begin
    group := EC_KEY_get0_group(ec_key);
    if (ec_key = nil)  or  (group = nil) then begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        Exit(0);
    end;
    if (EC_GROUP_get_asn1_flag(group) > 0)  and  (nid = EC_GROUP_get_curve_name(group)) then
        { we have a 'named curve' => just set the OID }
    begin
        asn1obj := OBJ_nid2obj(nid);
        if (asn1obj = nil)  or  (OBJ_length(asn1obj) = 0)  then
        begin
            ASN1_OBJECT_free(asn1obj);
            ERR_raise(ERR_LIB_EC, EC_R_MISSING_OID);
            Exit(0);
        end;
        ppval^ := asn1obj;
        pptype^ := V_ASN1_OBJECT;
    end
    else
    begin                     { explicit parameters }
        pstr := nil;
        pstr := ASN1_STRING_new();
        if pstr = nil then Exit(0);
        pstr.length := i2d_ECParameters(ec_key, @pstr.data);
        if pstr.length <= 0 then begin
            ASN1_STRING_free(pstr);
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            Exit(0);
        end;
        ppval^ := pstr;
        pptype^ := V_ASN1_SEQUENCE;
    end;
    Result := 1;
end;


function eckey_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
var
  ec_key : PEC_KEY;
  pval : Pointer;
  ptype : integer;
  penc, p, _out : PByte;
  penclen : integer;
  label _err;
begin
     ec_key := pkey.pkey.ec;
    pval := nil;
    penc := nil;
    if 0>=eckey_param2type(@ptype, @pval, ec_key) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        Exit(0);
    end;
    _out := nil;
    penclen := i2o_ECPublicKey(ec_key, @_out);
    if penclen <= 0 then goto _err;
    penc := OPENSSL_malloc(penclen);
    if penc = nil then goto _err;
    p := penc;
    penclen := i2o_ECPublicKey(ec_key, @p);
    if penclen <= 0 then goto _err;
    if X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_EC) ,
                               ptype, pval, penc, penclen) > 0 then
        Exit(1);
 _err:
    if ptype = V_ASN1_OBJECT then
       ASN1_OBJECT_free(pval)
    else
        ASN1_STRING_free(pval);
    OPENSSL_free(penc);
    Result := 0;
end;


function eckey_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
var
  p : PByte;
  pklen : integer;
  eckey : PEC_KEY;
  palg : PX509_ALGOR;
  libctx : POSSL_LIB_CTX;
  propq : PUTF8Char;
  label _ecerr;
begin
     p := nil;
    eckey := nil;
    libctx := nil;
     propq := nil;
    if (0>=ossl_x509_PUBKEY_get0_libctx(@libctx, @propq, pubkey))  or
       (0>=X509_PUBKEY_get0_param(nil, @p, @pklen, @palg, pubkey))  then
        Exit(0);
    eckey := ossl_ec_key_param_from_x509_algor(palg, libctx, propq);
    if nil =eckey then Exit(0);
    { We have parameters now set public key }
    if nil = o2i_ECPublicKey(@eckey, @p, pklen) then  begin
        ERR_raise(ERR_LIB_EC, EC_R_DECODE_ERROR);
        goto _ecerr;
    end;
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    Exit(1);
 _ecerr:
    EC_KEY_free(eckey);
    Result := 0;
end;


function eckey_pub_cmp(const a, b : PEVP_PKEY):integer;
var
  r : integer;
  group : PEC_GROUP;
  pa, pb : PEC_POINT;
begin
     group := EC_KEY_get0_group(b.pkey.ec);
     pa := EC_KEY_get0_public_key(a.pkey.ec);
     pb := EC_KEY_get0_public_key(b.pkey.ec);
    if (group = nil)  or  (pa = nil)  or  (pb = nil) then
       Exit(-2);
    r := EC_POINT_cmp(group, pa, pb, nil);
    if r = 0 then Exit(1);
    if r = 1 then Exit(0);
    Result := -2;
end;


function eckey_priv_decode_ex(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;
  eckey : PEC_KEY;
begin
    ret := 0;
    eckey := ossl_ec_key_from_pkcs8(p8, libctx, propq);
    if eckey <> nil then begin
        ret := 1;
        EVP_PKEY_assign_EC_KEY(pkey, eckey);
    end;
    Result := ret;
end;


function eckey_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
var
  ec_key    : TEC_KEY;
  ep,
  p         : PByte;
  eplen,
  ptype     : integer;
  pval      : Pointer;
  old_flags : uint32;
begin
    ec_key := (pkey.pkey.ec)^;
    if 0>=eckey_param2type(@ptype, @pval, @ec_key) then  begin
        ERR_raise(ERR_LIB_EC, EC_R_DECODE_ERROR);
        Exit(0);
    end;
    { set the private key }
    {
     * do not include the parameters in the SEC1 private key see PKCS#11
     * 12.11
     }
    old_flags := EC_KEY_get_enc_flags(@ec_key);
    EC_KEY_set_enc_flags(@ec_key, old_flags or EC_PKEY_NO_PARAMETERS);

    eplen := i2d_ECPrivateKey(@ec_key, nil);
    if 0>=eplen then begin
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        Exit(0);
    end;
    ep := OPENSSL_malloc(eplen);
    if ep = nil then begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    p := ep;
    if 0>=i2d_ECPrivateKey(@ec_key, @p) then  begin
        OPENSSL_free(ep);
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        Exit(0);
    end;
    if 0>=PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey) , 0,
                         ptype, pval, ep, eplen)  then
    begin
        OPENSSL_free(ep);
        Exit(0);
    end;
    Result := 1;
end;


function int_ec_size(const pkey : PEVP_PKEY):integer;
begin
    Result := ECDSA_size(pkey.pkey.ec);
end;


function ec_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := EC_GROUP_order_bits(EC_KEY_get0_group(pkey.pkey.ec));
end;


function ec_security_bits(const pkey : PEVP_PKEY):integer;
var
  ecbits : integer;
begin
    ecbits := ec_bits(pkey);
    if ecbits >= 512 then Exit(256);
    if ecbits >= 384 then Exit(192);
    if ecbits >= 256 then Exit(128);
    if ecbits >= 224 then Exit(112);
    if ecbits >= 160 then Exit(80);
    Result := ecbits div 2;
end;


function ec_missing_parameters(const pkey : PEVP_PKEY):integer;
begin
    if (pkey.pkey.ec = nil)  or  (EC_KEY_get0_group(pkey.pkey.ec) = nil) then
        Exit(1);
    Result := 0;
end;


function ec_copy_parameters(_to : PEVP_PKEY;const from : PEVP_PKEY):integer;
var
  group : PEC_GROUP;
  label _err;
begin
    group := EC_GROUP_dup(EC_KEY_get0_group(from.pkey.ec));
    if group = nil then Exit(0);
    if _to.pkey.ec = nil then begin
        _to.pkey.ec := EC_KEY_new;
        if _to.pkey.ec = nil then goto _err;
    end;
    if EC_KEY_set_group(_to.pkey.ec, group ) = 0 then
        goto _err;
    EC_GROUP_free(group);
    Exit(1);
 _err:
    EC_GROUP_free(group);
    Result := 0;
end;


function ec_cmp_parameters(const a, b : PEVP_PKEY):integer;
var
  group_a, group_b : PEC_GROUP;
begin
    group_a := EC_KEY_get0_group(a.pkey.ec);
    group_b := EC_KEY_get0_group(b.pkey.ec);
    if (group_a = nil)  or  (group_b = nil) then Exit(-2);
    if EC_GROUP_cmp(group_a, group_b, nil) > 0 then
        Exit(0)
    else
        Result := 1;
end;


procedure int_ec_free( pkey : PEVP_PKEY);
begin
    EC_KEY_free(pkey.pkey.ec);
end;


function do_EC_KEY_print(bp : PBIO;const x : PEC_KEY; off : integer; ktype : ec_print_t):integer;
var
  ecstr : PUTF8Char;
  priv, pub : PByte;
  privlen, publen : size_t;
  ret : integer;
  group : PEC_GROUP;
  label _err;
begin
    priv := nil; pub := nil;
    privlen := 0; publen := 0;
    ret := 0;
    group := EC_KEY_get0_group(x);
    if (x = nil)  or  (group = nil) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (ktype <> EC_KEY_PRINT_PARAM)  and  (EC_KEY_get0_public_key(x) <> nil)  then
    begin
        publen := EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), @pub, nil);
        if publen = 0 then goto _err;
    end;
    if (ktype = EC_KEY_PRINT_PRIVATE)  and  (EC_KEY_get0_private_key(x) <> nil)  then
    begin
        privlen := EC_KEY_priv2buf(x, @priv);
        if privlen = 0 then goto _err;
    end;
    if ktype = EC_KEY_PRINT_PRIVATE then
       ecstr := 'Private-Key'
    else if (ktype = EC_KEY_PRINT_PUBLIC) then
        ecstr := 'Public-Key'
    else
        ecstr := 'ECDSA-Parameters';
    if 0>=BIO_indent(bp, off, 128) then
        goto _err;
    if BIO_printf(bp, '%s: (%d bit then \n', [ecstr,
                   EC_GROUP_order_bits(group)]) <= 0 then
        goto _err;
    if privlen <> 0 then begin
        if BIO_printf(bp, '%*spriv:'#10, [off, '']) <= 0 then
            goto _err;
        if ASN1_buf_print(bp, priv, privlen, off + 4 )= 0 then
            goto _err;
    end;
    if publen <> 0 then begin
        if BIO_printf(bp, '%*spub:\n', [off, '']) <= 0 then
            goto _err;
        if ASN1_buf_print(bp, pub, publen, off + 4 ) = 0 then
            goto _err;
    end;
    if 0>=ECPKParameters_print(bp, group, off) then
        goto _err;
    ret := 1;
 _err:
    if 0>=ret then ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
    OPENSSL_clear_free(Pointer(priv), privlen);
    OPENSSL_free(pub);
    Result := ret;
end;


function eckey_param_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
var
  eckey : PEC_KEY;
begin
    eckey := d2i_ECParameters(nil, pder, derlen);
    if eckey = nil then
        Exit(0);
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    Result := 1;
end;


function eckey_param_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
begin
    Result := i2d_ECParameters(pkey.pkey.ec, pder);
end;


function eckey_param_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_EC_KEY_print(bp, pkey.pkey.ec, indent, EC_KEY_PRINT_PARAM);
end;


function eckey_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_EC_KEY_print(bp, pkey.pkey.ec, indent, EC_KEY_PRINT_PUBLIC);
end;


function eckey_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_EC_KEY_print(bp, pkey.pkey.ec, indent, EC_KEY_PRINT_PRIVATE);
end;


function old_ec_priv_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
var
  ec : PEC_KEY;
begin
    ec := d2i_ECPrivateKey(nil, pder, derlen);
    if ec = nil then
        Exit(0);
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    Result := 1;
end;


function old_ec_priv_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
begin
    Result := i2d_ECPrivateKey(pkey.pkey.ec, pder);
end;


function ec_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
begin
    case op of
        ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        begin
            if EVP_PKEY_get_id(pkey) = EVP_PKEY_SM2  then
            begin
                { For SM2, the only valid digest-alg is SM3 }
                PInteger(arg2)^ := NID_sm3;
                Exit( 2);            { Make it mandatory }
            end;
            PInteger(arg2)^ := NID_sha256;
            Exit(1);
        end;
        ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
        begin
            { We should only be here if we have a legacy key }
            if not ossl_assert(evp_pkey_is_legacy(pkey))  then
                Exit(0);
            Exit(EC_KEY_oct2key(evp_pkey_get0_EC_KEY_int(pkey), arg2, arg1, nil));
        end;
        ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
            Exit(EC_KEY_key2buf(EVP_PKEY_get0_EC_KEY(pkey),
                                  POINT_CONVERSION_UNCOMPRESSED, arg2, nil));
        else
            Exit(-2);
    end;
end;


function ec_pkey_check(const pkey : PEVP_PKEY):integer;
var
  eckey : PEC_KEY;
begin
    eckey := pkey.pkey.ec;
    { stay consistent to what EVP_PKEY_check demands }
    if eckey.priv_key = nil then begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        Exit(0);
    end;
    Result := EC_KEY_check_key(eckey);
end;


function ec_pkey_public_check(const pkey : PEVP_PKEY):integer;
var
  eckey : PEC_KEY;
begin
    eckey := pkey.pkey.ec;
    {
     * Note: it unnecessary to check eckey.pub_key here since
     * it will be checked in EC_KEY_check_key. In fact, the
     * EC_KEY_check_key mainly checks the public key, and checks
     * the private key optionally (only if there is one). So if
     * someone passes a whole EC key (public + private), this
     * will also work...
     }
    Result := EC_KEY_check_key(eckey);
end;


function ec_pkey_param_check(const pkey : PEVP_PKEY):integer;
var
  eckey : PEC_KEY;
begin
    eckey := pkey.pkey.ec;
    { stay consistent to what EVP_PKEY_check demands }
    if eckey.group = nil then begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        Exit(0);
    end;
    Result := EC_GROUP_check(eckey.group, nil);
end;


function ec_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
begin
    Result := pkey.pkey.ec.dirty_cnt;
end;


function ec_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    eckey              : PEC_KEY;
    ecg                : PEC_GROUP;
    pub_key_buf,gen_buf        : PByte;
    pub_key_buflen     : size_t;
    tmpl               : POSSL_PARAM_BLD;
    params             : POSSL_PARAM;
    priv_key           : PBIGNUM;
    pub_point          : PEC_POINT;
    selection,
    rv                 : integer;
    bnctx              : PBN_CTX;
    sz                 : size_t;
    ecbits,
    ecdh_cofactor_mode : integer;
    label _err;
begin
     eckey := nil;
     ecg := nil;
    pub_key_buf := nil; gen_buf := nil;
    params := nil;
     priv_key := nil;
     pub_point := nil;
    selection := 0;
    rv := 0;
    bnctx := nil;
    eckey := from.pkey.ec;
    ecg   := EC_KEY_get0_group(eckey);
    if (from = nil)
             or  (eckey = nil)
             or  (ecg = nil) then
        Exit(0);
    tmpl := OSSL_PARAM_BLD_new;
    if tmpl = nil then Exit(0);
    {
     * EC_POINT_point2buf can generate random numbers in some
     * implementations so we need to ensure we use the correct libctx.
     }
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then goto _err;
    BN_CTX_start(bnctx);
    { export the domain parameters }
    if 0>=ossl_ec_group_todata(ecg, tmpl, nil, libctx, propq, bnctx, @gen_buf) then
        goto _err;
    selection  := selection  or OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    priv_key := EC_KEY_get0_private_key(eckey);
    pub_point := EC_KEY_get0_public_key(eckey);
    if pub_point <> nil then
    begin
        { convert pub_point to a octet string according to the SECG standard }
        pub_key_buflen := EC_POINT_point2buf(ecg, pub_point,
                                                 POINT_CONVERSION_COMPRESSED,
                                                 @pub_key_buf, bnctx);
        if (pub_key_buflen  = 0 )
             or  (0>=OSSL_PARAM_BLD_push_octet_string(tmpl,
                                                 OSSL_PKEY_PARAM_PUB_KEY,
                                                 pub_key_buf,
                                                 pub_key_buflen)) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    end;
    if priv_key <> nil then begin
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
        ecbits := EC_GROUP_order_bits(ecg);
        if ecbits <= 0 then goto _err;
        sz := (ecbits + 7) div 8;
        if 0>=OSSL_PARAM_BLD_push_BN_pad(tmpl,
                                        OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv_key, sz) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        {
         * The ECDH Cofactor Mode is defined only if the EC_KEY actually
         * contains a private key, so we check for the flag and export it only
         * in this case.
         }
        ecdh_cofactor_mode := get_result(EC_KEY_get_flags(eckey) and EC_FLAG_COFACTOR_ECDH > 0 , 1 , 0);
        { Export the ECDH_COFACTOR_MODE parameter }
        if 0>=OSSL_PARAM_BLD_push_int(tmpl,
                                     OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                     ecdh_cofactor_mode) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
    end;
    params := OSSL_PARAM_BLD_to_param(tmpl);
    { We export, the provider imports }
    rv := importer(to_keydata, selection, params);
 _err:
    OSSL_PARAM_BLD_free(tmpl);
    OSSL_PARAM_free(params);
    OPENSSL_free(pub_key_buf);
    OPENSSL_free(gen_buf);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    Result := rv;
end;


function ec_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
var
  pctx : PEVP_PKEY_CTX;
  pkey : PEVP_PKEY;
  ec : PEC_KEY;
begin
    pctx := vpctx;
    pkey := EVP_PKEY_CTX_get0_pkey(pctx);
    ec := EC_KEY_new_ex(pctx.libctx, pctx.propquery);
    if ec = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if (0>=ossl_ec_group_fromdata(ec, params)) or
       (0>=ossl_ec_key_otherparams_fromdata(ec, params))
         or  (0>=ossl_ec_key_fromdata(ec, params, 1))
         or  (0>=EVP_PKEY_assign_EC_KEY(pkey, ec))  then
    begin
        EC_KEY_free(ec);
        Exit(0);
    end;
    Result := 1;
end;


function ec_pkey_copy( _to, from : PEVP_PKEY):integer;
var
  eckey, dupkey : PEC_KEY;

  ret : integer;
begin
    eckey := from.pkey.ec;
    dupkey := nil;
    if eckey <> nil then begin
        dupkey := EC_KEY_dup(eckey);
        if dupkey = nil then Exit(0);
    end
    else
    begin
        { necessary to properly copy empty SM2 keys }
        Exit(EVP_PKEY_set_type(_to, from.&type));
    end;
    ret := EVP_PKEY_assign_EC_KEY(_to, dupkey);
    if 0>=ret then EC_KEY_free(dupkey);
    Result := ret;
end;


function EC_KEY_print(bp : PBIO;const x : PEC_KEY; off : integer):integer;
var
  _private : integer;
begin
    _private := Int( EC_KEY_get0_private_key(x) <> nil);
    Exit(do_EC_KEY_print(bp, x, off,
               ec_print_t(get_result(_private > 0 , 0{EC_KEY_PRINT_PRIVATE} , 1{EC_KEY_PRINT_PUBLIC}))));
end;


function ECParameters_print(bp : PBIO;const x : PEC_KEY):integer;
begin
    Result := do_EC_KEY_print(bp, x, 4, EC_KEY_PRINT_PARAM);
end;


end.
