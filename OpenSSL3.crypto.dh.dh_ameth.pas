unit OpenSSL3.crypto.dh.dh_ameth;

interface
uses OpenSSL.Api;

function dh_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
 function dh_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
function dh_pub_cmp(const a, b : PEVP_PKEY):integer;
function dh_param_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function dh_public_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function dh_private_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
function dh_priv_decode(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO):integer;
  function dh_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
 function int_dh_size(const pkey : PEVP_PKEY):integer;
  function dh_bits(const pkey : PEVP_PKEY):integer;
  function dh_security_bits(const pkey : PEVP_PKEY):integer;
  function dh_cmp_parameters(const a, b : PEVP_PKEY):integer;
  function int_dh_param_copy(_to : PDH;const from : PDH; is_x942 : integer):integer;
 function dh_param_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
  function dh_param_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
 function dh_missing_parameters(const a : PEVP_PKEY):integer;
  function dh_copy_parameters(&to : PEVP_PKEY;const from : PEVP_PKEY):integer;
   procedure int_dh_free( pkey : PEVP_PKEY);
  function dh_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
  function dh_pkey_public_check(const pkey : PEVP_PKEY):integer;
 function dh_pkey_param_check(const pkey : PEVP_PKEY):integer;
  function dh_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
  function dh_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function dh_pkey_import_from_type(const params : POSSL_PARAM; vpctx : Pointer; &type : integer):integer;
  function dh_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function dhx_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function dh_pkey_copy( &to, from : PEVP_PKEY):integer;

const  ossl_dh_asn1_meth: TEVP_PKEY_ASN1_METHOD = (
    pkey_id: EVP_PKEY_DH;
    pkey_base_id: EVP_PKEY_DH;
    pkey_flags: 0;
    pem_str: 'DH';
    info: 'OpenSSL PKCS#3 DH method';

    pub_decode: dh_pub_decode;
    pub_encode: dh_pub_encode;
    pub_cmp: dh_pub_cmp;
    pub_print: dh_public_print;

    priv_decode: dh_priv_decode;
    priv_encode: dh_priv_encode;
    priv_print: dh_private_print;

    pkey_size: int_dh_size;
    pkey_bits: dh_bits;
    pkey_security_bits: dh_security_bits;

    param_decode: dh_param_decode;
    param_encode: dh_param_encode;
    param_missing: dh_missing_parameters;
    param_copy: dh_copy_parameters;
    param_cmp: dh_cmp_parameters;
    param_print: dh_param_print;
    sig_print: nil;

    pkey_free: int_dh_free;
    pkey_ctrl: dh_pkey_ctrl;

    old_priv_decode: nil; old_priv_encode: nil;
    item_verify: nil; item_sign: nil; siginf_set: nil;
    pkey_check: nil;

    pkey_public_check: dh_pkey_public_check;
    pkey_param_check: dh_pkey_param_check;
    set_priv_key: nil; set_pub_key: nil; get_priv_key: nil; get_pub_key: nil;

    dirty_cnt: dh_pkey_dirty_cnt;
    export_to: dh_pkey_export_to;
    import_from: dh_pkey_import_from;
    copy: dh_pkey_copy
);

 ossl_dhx_asn1_meth: TEVP_PKEY_ASN1_METHOD = (
    pkey_id: EVP_PKEY_DH;
    pkey_base_id: EVP_PKEY_DH;
    pkey_flags: 0;
    pem_str: 'X9.42 DH';
    info: 'OpenSSL X9.42 DH method';
    pub_decode: dh_pub_decode;
    pub_encode: dh_pub_encode;
    pub_cmp: dh_pub_cmp;
    pub_print: dh_public_print;
    priv_decode: dh_priv_decode;
    priv_encode: dh_priv_encode;
    priv_print: dh_private_print;
    pkey_size: int_dh_size;
    pkey_bits: dh_bits;
    pkey_security_bits: dh_security_bits;
    param_decode: dh_param_decode;
    param_encode: dh_param_encode;
    param_missing: dh_missing_parameters;
    param_copy: dh_copy_parameters;
    param_cmp: dh_cmp_parameters;
    param_print: dh_param_print;
    sig_print: nil;
    pkey_free: int_dh_free;
    pkey_ctrl: dh_pkey_ctrl;
    old_priv_decode: nil; old_priv_encode: nil; item_verify: nil; item_sign: nil; siginf_set: nil;
    pkey_check: nil;
    pkey_public_check: dh_pkey_public_check;
    pkey_param_check: dh_pkey_param_check;
    set_priv_key: nil; set_pub_key: nil; get_priv_key: nil; get_pub_key: nil;
    dirty_cnt: dh_pkey_dirty_cnt;
    export_to: dh_pkey_export_to;
    import_from: dh_pkey_import_from;
    copy: dh_pkey_copy
);

function d2i_dhp(const pkey : PEVP_PKEY; pp : PPByte; length : long):PDH;
 function i2d_dhp(const pkey : PEVP_PKEY; a : PDH; pp : PPByte):integer;
function do_dh_print(bp : PBIO;const x : PDH; indent, ptype : integer):integer;

implementation
uses
   openssl3.crypto.dh.dh_check, openssl3.crypto.dh.dh_lib,
   openssl3.crypto.evp.pmeth_lib, OpenSSL3.Err,
   OpenSSL3.common, openssl3.crypto.evp, openssl3.crypto.mem,
   openssl3.crypto.asn1.p8_pkey,  openssl3.crypto.objects.obj_dat,
   openssl3.crypto.asn1.t_pkey,  openssl3.crypto.bn.bn_lib,
   openssl3.crypto.asn1.a_int, openssl3.crypto.asn1.tasn_typ,
   openssl3.crypto.ffc.ffc_params, openssl3.crypto.asn1.asn1_lib,
   openssl3.crypto.dh.dh_key,  openssl3.crypto.dh.dh_asn1,
   openssl3.crypto.x509.x_pubkey,  openssl3.crypto.asn1.x_algor,
   openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bio_print,
   openssl3.crypto.dh.dh_backend, openssl3.crypto.evp.p_lib,
   openssl3.crypto.param_build, openssl3.crypto.params_dup;





function do_dh_print(bp : PBIO;const x : PDH; indent, ptype : integer):integer;
var
  reason   : integer;
  ktype    : PUTF8Char;
  priv_key,
  pub_key  : PBIGNUM;
  label _err;
begin
    reason := ERR_R_BUF_LIB;
    ktype := nil;
    if ptype = 2 then
       priv_key := x.priv_key
    else
        priv_key := nil;
    if ptype > 0 then
       pub_key := x.pub_key
    else
        pub_key := nil;
    if (x.params.p = nil)  or ( (ptype = 2)  and  (priv_key = nil) )  or
       ( (ptype > 0)  and  (pub_key = nil))  then
    begin
        reason := ERR_R_PASSED_NULL_PARAMETER;
        goto _err;
    end;
    if ptype = 2 then
       ktype := 'DH Private-Key'
    else if (ptype = 1) then
        ktype := 'DH Public-Key'
    else
        ktype := 'DH Parameters';
    if (0>=BIO_indent(bp, indent, 128))  or
       (BIO_printf(bp, '%s: (%d bit)\n', [ktype, _DH_bits(x)]) <= 0) then
        goto _err;
    indent  := indent + 4;
    if 0>=ASN1_bn_print(bp, 'private-key:', priv_key, nil, indent) then
        goto _err;
    if 0>=ASN1_bn_print(bp, 'public-key:', pub_key, nil, indent) then
        goto _err;
    if 0>=ossl_ffc_params_print(bp, @x.params, indent) then
        goto _err;
    if x.length <> 0 then
    begin
        if (0>=BIO_indent(bp, indent, 128))
                 or  (BIO_printf(bp, 'recommended-private-length: %d bits\n',
                              [int(x.length)]) <= 0)  then
            goto _err;
    end;
    Exit(1);
 _err:
    ERR_raise(ERR_LIB_DH, reason);
    Result := 0;
end;

function i2d_dhp(const pkey : PEVP_PKEY; a : PDH; pp : PPByte):integer;
begin
    if pkey.ameth = @ossl_dhx_asn1_meth then
       Exit(i2d_DHxparams(a, pp));
    Result := i2d_DHparams(a, pp);
end;


function d2i_dhp(const pkey : PEVP_PKEY; pp : PPByte; length : long):PDH;
var
  dh : PDH;

  is_dhx : integer;
begin
    dh := nil;
    is_dhx := int(pkey.ameth = @ossl_dhx_asn1_meth);
    if is_dhx > 0 then
       dh := d2i_DHxparams(nil, pp, length)
    else
       dh := d2i_DHparams(nil, pp, length);
    Result := dh;
end;

function dh_pkey_param_check(const pkey : PEVP_PKEY):integer;
var
  dh : PDH;
begin
    dh := pkey.pkey.dh;
    Result := DH_check_ex(dh);
end;


function dh_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
begin
    Result := pkey.pkey.dh.dirty_cnt;
end;


function dh_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    dh        : PDH;
    tmpl      : POSSL_PARAM_BLD;
    p,g,q         : PBIGNUM;
    l         : long;
    pub_key,
    priv_key  : PBIGNUM;
    params    : POSSL_PARAM;
    selection,
    rv        : integer;
    label _err;
begin
    dh := from.pkey.dh;
    p := DH_get0_p(dh); g := DH_get0_g(dh); q := DH_get0_q(dh);
    l := DH_get_length(dh);
    pub_key := DH_get0_pub_key(dh);
    priv_key := DH_get0_priv_key(dh);
    params := nil;
    selection := 0;
    rv := 0;
    if (p = nil)  or  (g = nil) then Exit(0);
    tmpl := OSSL_PARAM_BLD_new;
    if tmpl = nil then Exit(0);
    if (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, p)) or
       (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, g))  then
        goto _err;
    if q <> nil then begin
        if 0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, q) then
            goto _err;
    end;
    selection  := selection  or OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    if l > 0 then begin
        if 0>=OSSL_PARAM_BLD_push_long(tmpl, OSSL_PKEY_PARAM_DH_PRIV_LEN, l) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
    end;
    if pub_key <> nil then begin
        if 0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, pub_key) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    end;
    if priv_key <> nil then begin
        if (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY,
                                    priv_key)) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    end;
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if params = nil then
        goto _err;
    { We export, the provider imports }
    rv := importer(to_keydata, selection, params);
    OSSL_PARAM_free(params);
_err:
    OSSL_PARAM_BLD_free(tmpl);
    Result := rv;
end;


function dh_pkey_import_from_type(const params : POSSL_PARAM; vpctx : Pointer; &type : integer):integer;
var
  pctx : PEVP_PKEY_CTX;
  pkey : PEVP_PKEY;
  dh : PDH;
begin
    pctx := vpctx;
    pkey := EVP_PKEY_CTX_get0_pkey(pctx);
    dh := ossl_dh_new_ex(pctx.libctx);
    if dh = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
    DH_set_flags(dh, get_result(&type = EVP_PKEY_DH , DH_FLAG_TYPE_DH , DH_FLAG_TYPE_DHX));
    if (0>=ossl_dh_params_fromdata(dh, params))  or  (0>=ossl_dh_key_fromdata(dh, params))
         or  (0>=EVP_PKEY_assign(pkey, &type, dh))  then
    begin
        DH_free(dh);
        Exit(0);
    end;
    Result := 1;
end;


function dh_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := dh_pkey_import_from_type(params, vpctx, EVP_PKEY_DH);
end;


function dhx_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := dh_pkey_import_from_type(params, vpctx, EVP_PKEY_DHX);
end;


function dh_pkey_copy( &to, from : PEVP_PKEY):integer;
var
  dh, dupkey : PDH;
  ret : integer;
begin
    dh := from.pkey.dh;
    dupkey := nil;
    if dh <> nil then begin
        dupkey := ossl_dh_dup(dh, OSSL_KEYMGMT_SELECT_ALL);
        if dupkey = nil then Exit(0);
    end;
    ret := EVP_PKEY_assign(&to, from.&type, dupkey);
    if 0>=ret then DH_free(dupkey);
    Result := ret;
end;



function dh_pkey_public_check(const pkey : PEVP_PKEY):integer;
var
  dh : PDH;
begin
    dh := pkey.pkey.dh;
    if dh.pub_key = nil then begin
        ERR_raise(ERR_LIB_DH, DH_R_MISSING_PUBKEY);
        Exit(0);
    end;
    Result := DH_check_pub_key_ex(dh, dh.pub_key);
end;



function dh_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
begin
    case op of
    ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
    begin
        { We should only be here if we have a legacy key }
        if not ossl_assert(evp_pkey_is_legacy(pkey ))  then
            Exit(0);
        Exit(ossl_dh_buf2key(evp_pkey_get0_DH_int(pkey), arg2, arg1));
    end;
    ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
        Exit(ossl_dh_key2buf(EVP_PKEY_get0_DH(pkey), arg2, 0, 1));
    else
        Exit(-2);
    end;
end;



procedure int_dh_free( pkey : PEVP_PKEY);
begin
    DH_free(pkey.pkey.dh);
end;



function dh_copy_parameters(&to : PEVP_PKEY;const from : PEVP_PKEY):integer;
begin
    if &to.pkey.dh = nil then begin
        &to.pkey.dh := DH_new;
        if &to.pkey.dh = nil then Exit(0);
    end;
    Exit(int_dh_param_copy(&to.pkey.dh, from.pkey.dh,
                             Int(from.ameth = @ossl_dhx_asn1_meth)));
end;



function dh_missing_parameters(const a : PEVP_PKEY):integer;
begin
    Result := int( (a.pkey.dh = nil)
         or  (a.pkey.dh.params.p = nil)
         or  (a.pkey.dh.params.g = nil) );
end;

function dh_param_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
var
  dh : PDH;
begin
    dh := d2i_dhp(pkey, pder, derlen);
    if dh = nil then
        Exit(0);
    PostInc(dh.dirty_cnt);
    EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, dh);
    Result := 1;
end;


function dh_param_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
begin
    Result := i2d_dhp(pkey, pkey.pkey.dh, pder);
end;



function int_dh_size(const pkey : PEVP_PKEY):integer;
begin
    Result := DH_size(pkey.pkey.dh);
end;


function dh_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := _DH_bits(pkey.pkey.dh);
end;


function dh_security_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := _DH_security_bits(pkey.pkey.dh);
end;


function dh_cmp_parameters(const a, b : PEVP_PKEY):integer;
begin
    Exit(ossl_ffc_params_cmp(@a.pkey.dh.params, @b.pkey.dh.params,
                               Int(a.ameth <> @ossl_dhx_asn1_meth)));
end;


function int_dh_param_copy(_to : PDH;const from : PDH; is_x942 : integer):integer;
begin
    if is_x942 = -1 then
       is_x942 := int(from.params.q <> nil);
    if 0>=ossl_ffc_params_copy(@_to.params, @from.params) then
        Exit(0);
    if 0>=is_x942 then _to.length := from.length;
    PostInc(_to.dirty_cnt);
    Result := 1;
end;


function dh_priv_decode(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO):integer;
var
  ret : integer;
  dh : PDH;
begin
    ret := 0;
    dh := ossl_dh_key_from_pkcs8(p8, nil, nil);
    if dh <> nil then begin
        ret := 1;
        EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, dh);
    end;
    Result := ret;
end;


function dh_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
var
  params : PASN1_STRING;
  prkey : PASN1_INTEGER;
  dp : PByte;
  dplen : integer;
  label _err;
begin
    params := nil;
    prkey := nil;
    dp := nil;
    params := ASN1_STRING_new;
    if params = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    params.length := i2d_dhp(pkey, pkey.pkey.dh, @params.data);
    if params.length <= 0 then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    params.&type := V_ASN1_SEQUENCE;
    { Get private key into integer }
    prkey := BN_to_ASN1_INTEGER(pkey.pkey.dh.priv_key, nil);
    if prkey = nil then begin
        ERR_raise(ERR_LIB_DH, DH_R_BN_ERROR);
        goto _err;
    end;
    dplen := i2d_ASN1_INTEGER(prkey, @dp);
    ASN1_STRING_clear_free(prkey);
    prkey := nil;
    if 0>=PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey.ameth.pkey_id) , 0,
                         V_ASN1_SEQUENCE, params, dp, dplen) then
        goto _err;
    Exit(1);
 _err:
    OPENSSL_free(dp);
    ASN1_STRING_free(params);
    ASN1_STRING_clear_free(prkey);
    Result := 0;
end;


function dh_param_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_dh_print(bp, pkey.pkey.dh, indent, 0);
end;


function dh_public_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_dh_print(bp, pkey.pkey.dh, indent, 1);
end;


function dh_private_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_dh_print(bp, pkey.pkey.dh, indent, 2);
end;


function dh_pub_cmp(const a, b : PEVP_PKEY):integer;
begin
    if dh_cmp_parameters(a, b )= 0 then
        Exit(0);
    if BN_cmp(b.pkey.dh.pub_key, a.pkey.dh.pub_key) <> 0  then
        Exit(0)
    else
        Result := 1;
end;



function dh_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
var
  dh : PDH;
  ptype : integer;
  penc : PByte;
  penclen : integer;
  str : PASN1_STRING;
  pub_key : PASN1_INTEGER;
  label _err;
begin
    penc := nil;
    pub_key := nil;
    dh := pkey.pkey.dh;
    str := ASN1_STRING_new;
    if str = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    str.length := i2d_dhp(pkey, dh, @str.data);
    if str.length <= 0 then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    ptype := V_ASN1_SEQUENCE;
    pub_key := BN_to_ASN1_INTEGER(dh.pub_key, nil);
    if pub_key = nil then
       goto _err;
    penclen := i2d_ASN1_INTEGER(pub_key, @penc);
    ASN1_INTEGER_free(pub_key);
    if penclen <= 0 then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey.ameth.pkey_id) ,
                               ptype, str, penc, penclen)>0  then
        Exit(1);
 _err:
    OPENSSL_free(penc);
    ASN1_STRING_free(str);
    Result := 0;
end;



function dh_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
var
  p,
  pm         : PByte;
  pklen,
  pmlen,
  ptype      : integer;

  pval       : Pointer;
  pstr       : PASN1_STRING;
  palg       : PX509_ALGOR;
  public_key : PASN1_INTEGER;
  dh         : PDH;
  label _err;
begin
    public_key := nil;
    dh := nil;
    if 0>=X509_PUBKEY_get0_param(nil, @p, @pklen, @palg, pubkey) then
        Exit(0);
    X509_ALGOR_get0(nil, @ptype, @pval, palg);
    if ptype <> V_ASN1_SEQUENCE then begin
        ERR_raise(ERR_LIB_DH, DH_R_PARAMETER_ENCODING_ERROR);
        goto _err;
    end;
    pstr := pval;
    pm := pstr.data;
    pmlen := pstr.length;
    dh := d2i_dhp(pkey, @pm, pmlen);
    if dh = nil then  begin
        ERR_raise(ERR_LIB_DH, DH_R_DECODE_ERROR);
        goto _err;
    end;
    public_key := d2i_ASN1_INTEGER(nil, @p, pklen );
    if public_key = nil then  begin
        ERR_raise(ERR_LIB_DH, DH_R_DECODE_ERROR);
        goto _err;
    end;
    { We have parameters now set public key }
    dh.pub_key := ASN1_INTEGER_to_BN(public_key, nil );
    if dh.pub_key = nil then  begin
        ERR_raise(ERR_LIB_DH, DH_R_BN_DECODE_ERROR);
        goto _err;
    end;
    ASN1_INTEGER_free(public_key);
    EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, dh);
    Exit(1);
 _err:
    ASN1_INTEGER_free(public_key);
    DH_free(dh);
    Result := 0;
end;


end.
