unit OpenSSL3.crypto.dsa.dsa_ameth;

interface
uses OpenSSL.Api;

 function dsa_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
  function dsa_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
  function dsa_priv_decode(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO):integer;
  function dsa_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
  function int_dsa_size(const pkey : PEVP_PKEY):integer;
  function dsa_bits(const pkey : PEVP_PKEY):integer;
  function dsa_security_bits(const pkey : PEVP_PKEY):integer;
  function dsa_missing_parameters(const pkey : PEVP_PKEY):integer;
  function dsa_copy_parameters(_to : PEVP_PKEY;const from : PEVP_PKEY):integer;
  function dsa_cmp_parameters(const a, b : PEVP_PKEY):integer;
  function dsa_pub_cmp(const a, b : PEVP_PKEY):integer;
  procedure int_dsa_free( pkey : PEVP_PKEY);
  function do_dsa_print(bp : PBIO;const x : PDSA; off, ptype : integer):integer;
  function dsa_param_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
  function dsa_param_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
  function dsa_param_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function dsa_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function dsa_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function old_dsa_priv_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
  function old_dsa_priv_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
  function dsa_sig_print(bp : PBIO;const sigalg : PX509_ALGOR;const sig : PASN1_STRING; indent : integer; pctx : PASN1_PCTX):integer;
  function dsa_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
  function dsa_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
  function dsa_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function dsa_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function dsa_pkey_copy( &to, from : PEVP_PKEY):integer;

const  ossl_dsa_asn1_meths: array[0..4] of TEVP_PKEY_ASN1_METHOD = (

    (
     pkey_id: EVP_PKEY_DSA2;
     pkey_base_id: EVP_PKEY_DSA;
     pkey_flags: ASN1_PKEY_ALIAS
     ),

    (
     pkey_id: EVP_PKEY_DSA1;
     pkey_base_id: EVP_PKEY_DSA;
     pkey_flags: ASN1_PKEY_ALIAS
     ),

    (
     pkey_id: EVP_PKEY_DSA4;
     pkey_base_id: EVP_PKEY_DSA;
     pkey_flags: ASN1_PKEY_ALIAS
     ),

    (
     pkey_id: EVP_PKEY_DSA3;
     pkey_base_id: EVP_PKEY_DSA;
     pkey_flags: ASN1_PKEY_ALIAS
     ),

    (
     pkey_id: EVP_PKEY_DSA;
     pkey_base_id: EVP_PKEY_DSA;
     pkey_flags: 0;

     pem_str: 'DSA';
     info: 'OpenSSL DSA method';

     pub_decode: dsa_pub_decode;
     pub_encode: dsa_pub_encode;
     pub_cmp:dsa_pub_cmp;
     pub_print: dsa_pub_print;

     priv_decode: dsa_priv_decode;
     priv_encode: dsa_priv_encode;
     priv_print: dsa_priv_print;

     pkey_size: int_dsa_size;
     pkey_bits: dsa_bits;
     pkey_security_bits: dsa_security_bits;

     param_decode: dsa_param_decode;
     param_encode: dsa_param_encode;
     param_missing: dsa_missing_parameters;
     param_copy: dsa_copy_parameters;
     param_cmp: dsa_cmp_parameters;
     param_print: dsa_param_print;
     sig_print: dsa_sig_print;

     pkey_free: int_dsa_free;
     pkey_ctrl: dsa_pkey_ctrl;
     old_priv_decode: old_dsa_priv_decode;
     old_priv_encode: old_dsa_priv_encode;

     item_verify: nil; item_sign: nil; siginf_set: nil;
     pkey_check: nil;  pkey_public_check: nil; pkey_param_check: nil;
     set_priv_key: nil; set_pub_key: nil; get_priv_key: nil; get_pub_key: nil;

     dirty_cnt: dsa_pkey_dirty_cnt;
     export_to: dsa_pkey_export_to;
     import_from: dsa_pkey_import_from;
     copy: dsa_pkey_copy
    )
);



implementation
uses

   openssl3.crypto.evp.pmeth_lib, OpenSSL3.Err,
   OpenSSL3.common, openssl3.crypto.evp, openssl3.crypto.mem,
   openssl3.crypto.asn1.p8_pkey,  openssl3.crypto.objects.obj_dat,
   openssl3.crypto.asn1.t_pkey,  openssl3.crypto.bn.bn_lib,
   openssl3.crypto.asn1.a_int, openssl3.crypto.asn1.tasn_typ,
   openssl3.crypto.ffc.ffc_params, openssl3.crypto.asn1.asn1_lib,
   openssl3.crypto.dsa.dsa_asn1,  openssl3.crypto.dsa.dsa_lib,
   openssl3.crypto.x509.x_pubkey,  openssl3.crypto.asn1.x_algor,
   openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bio_print,
   openssl3.crypto.dsa.dsa_sign, openssl3.crypto.t_x509,
   openssl3.crypto.evp.p_lib,  OpenSSL3.crypto.dsa.dsa_backend,
   openssl3.crypto.param_build, openssl3.crypto.params_dup;

function dsa_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
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
  dsa        : PDSA;
  label _err;
begin
    public_key := nil;
    dsa := nil;
    if 0>=X509_PUBKEY_get0_param(nil, @p, @pklen, @palg, pubkey) then
        Exit(0);
    X509_ALGOR_get0(nil, @ptype, @pval, palg);
    if ptype = V_ASN1_SEQUENCE then begin
        pstr := pval;
        pm := pstr.data;
        pmlen := pstr.length;
        dsa := d2i_DSAparams(nil, @pm, pmlen);
        if dsa = nil then  begin
            ERR_raise(ERR_LIB_DSA, DSA_R_DECODE_ERROR);
            goto _err;
        end;
    end
    else
    if ((ptype = V_ASN1_NULL)  or  (ptype = V_ASN1_UNDEF)) then
    begin
        dsa := DSA_new;
        if dsa = nil then  begin
            ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
    end
    else
    begin
        ERR_raise(ERR_LIB_DSA, DSA_R_PARAMETER_ENCODING_ERROR);
        goto _err;
    end;
    public_key := d2i_ASN1_INTEGER(nil, @p, pklen);
    if public_key = nil then  begin
        ERR_raise(ERR_LIB_DSA, DSA_R_DECODE_ERROR);
        goto _err;
    end;
    dsa.pub_key := ASN1_INTEGER_to_BN(public_key, nil);
    if dsa.pub_key = nil then  begin
        ERR_raise(ERR_LIB_DSA, DSA_R_BN_DECODE_ERROR);
        goto _err;
    end;
    PostInc(dsa.dirty_cnt);
    ASN1_INTEGER_free(public_key);
    EVP_PKEY_assign_DSA(pkey, dsa);
    Exit(1);
 _err:
    ASN1_INTEGER_free(public_key);
    DSA_free(dsa);
    Exit(0);
end;


function dsa_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
var
  dsa : PDSA;
  ptype : integer;
  penc : PByte;
  penclen : integer;
  str : PASN1_STRING;
  pubint : PASN1_INTEGER;
  aobj : PASN1_OBJECT;
  label _err;
begin
    penc := nil;
    str := nil;
    pubint := nil;
    dsa := pkey.pkey.dsa;
    if (pkey.save_parameters > 0)
         and  (dsa.params.p <> nil)
         and  (dsa.params.q <> nil)
         and  (dsa.params.g <> nil) then
    begin
        str := ASN1_STRING_new;
        if str = nil then begin
            ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        str.length := i2d_DSAparams(dsa, @str.data);
        if str.length <= 0 then begin
            ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        ptype := V_ASN1_SEQUENCE;
    end
    else
        ptype := V_ASN1_UNDEF;
    pubint := BN_to_ASN1_INTEGER(dsa.pub_key, nil);
    if pubint = nil then begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    penclen := i2d_ASN1_INTEGER(pubint, @penc);
    ASN1_INTEGER_free(pubint);
    if penclen <= 0 then begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    aobj := OBJ_nid2obj(EVP_PKEY_DSA);
    if aobj = nil then goto _err;
    if X509_PUBKEY_set0_param(pk, aobj, ptype, str, penc, penclen) > 0 then
        Exit(1);
 _err:
    OPENSSL_free(penc);
    ASN1_STRING_free(str);
    Result := 0;
end;


function dsa_priv_decode(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO):integer;
var
  ret : integer;
  dsa : PDSA;
begin
    ret := 0;
    dsa := ossl_dsa_key_from_pkcs8(p8, nil, nil);
    if dsa <> nil then begin
        ret := 1;
        EVP_PKEY_assign_DSA(pkey, dsa);
    end;
    Result := ret;
end;


function dsa_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
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
    if (pkey.pkey.dsa  = nil) or  (pkey.pkey.dsa.priv_key = nil) then begin
        ERR_raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS);
        goto _err;
    end;
    params := ASN1_STRING_new;
    if params = nil then begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    params.length := i2d_DSAparams(pkey.pkey.dsa, @params.data);
    if params.length <= 0 then begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    params.&type := V_ASN1_SEQUENCE;
    { Get private key into integer }
    prkey := BN_to_ASN1_INTEGER(pkey.pkey.dsa.priv_key, nil);
    if prkey = nil then begin
        ERR_raise(ERR_LIB_DSA, DSA_R_BN_ERROR);
        goto _err;
    end;
    dplen := i2d_ASN1_INTEGER(prkey, @dp);
    ASN1_STRING_clear_free(prkey);
    prkey := nil;
    if 0>=PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dsa ) , 0,
                         V_ASN1_SEQUENCE, params, dp, dplen) then
        goto _err;
    Exit(1);
 _err:
    OPENSSL_free(dp);
    ASN1_STRING_free(params);
    ASN1_STRING_clear_free(prkey);
    Result := 0;
end;


function int_dsa_size(const pkey : PEVP_PKEY):integer;
begin
    Result := DSA_size(pkey.pkey.dsa);
end;


function dsa_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := _DSA_bits(pkey.pkey.dsa);
end;


function dsa_security_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := _DSA_security_bits(pkey.pkey.dsa);
end;


function dsa_missing_parameters(const pkey : PEVP_PKEY):integer;
var
  dsa : PDSA;
begin
    dsa := pkey.pkey.dsa;
    Result := Int( (dsa = nil)
         or  (dsa.params.p = nil)
         or  (dsa.params.q = nil)
         or  (dsa.params.g = nil));
end;


function dsa_copy_parameters(_to : PEVP_PKEY;const from : PEVP_PKEY):integer;
begin
    if _to.pkey.dsa = nil then
    begin
        _to.pkey.dsa := DSA_new;
        if _to.pkey.dsa = nil then Exit(0);
    end;
    if 0>=ossl_ffc_params_copy(@_to.pkey.dsa.params, @from.pkey.dsa.params) then
        Exit(0);
    PostInc(_to.pkey.dsa.dirty_cnt);
    Result := 1;
end;


function dsa_cmp_parameters(const a, b : PEVP_PKEY):integer;
begin
    Result := ossl_ffc_params_cmp(@a.pkey.dsa.params, @b.pkey.dsa.params, 1);
end;


function dsa_pub_cmp(const a, b : PEVP_PKEY):integer;
begin
    Result := Int(BN_cmp(b.pkey.dsa.pub_key, a.pkey.dsa.pub_key) = 0);
end;


procedure int_dsa_free( pkey : PEVP_PKEY);
begin
    DSA_free(pkey.pkey.dsa);
end;


function do_dsa_print(bp : PBIO;const x : PDSA; off, ptype : integer):integer;
var
    ret      : integer;
    ktype    : PUTF8Char;
    priv_key,
    pub_key  : PBIGNUM;
    mod_len  : integer;
    label _err;
begin
    ret := 0;
    ktype := nil;
    mod_len := 0;
    if x.params.p <> nil then mod_len := _DSA_bits(x);
    if ptype = 2 then
       priv_key := x.priv_key
    else
        priv_key := nil;
    if ptype > 0 then
       pub_key := x.pub_key
    else
        pub_key := nil;
    if ptype = 2 then
       ktype := 'Private-Key'
    else if (ptype = 1) then
        ktype := 'Public-Key'
    else
        ktype := 'DSA-Parameters';
    if priv_key <> nil then
    begin
        if 0>=BIO_indent(bp, off, 128) then
            goto _err;
        if BIO_printf(bp, '%s: (%d bit then \n', [ktype, mod_len]) <= 0 then
            goto _err;
    end
    else
    begin
        if BIO_printf(bp, 'Public-Key: (%d bit then \n', [mod_len]) <= 0 then
            goto _err;
    end;
    if 0>=ASN1_bn_print(bp, 'priv:', priv_key, nil, off ) then
        goto _err;
    if 0>=ASN1_bn_print(bp, 'pub: ', pub_key, nil, off) then
        goto _err;
    if 0>=ossl_ffc_params_print(bp, @x.params, off) then
        goto _err;
    ret := 1;
 _err:
    Result := ret;
end;


function dsa_param_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
var
  dsa : PDSA;
begin
    dsa := d2i_DSAparams(nil, pder, derlen);
    if dsa = nil then
        Exit(0);
    PostInc(dsa.dirty_cnt);
    EVP_PKEY_assign_DSA(pkey, dsa);
    Result := 1;
end;


function dsa_param_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
begin
    Result := i2d_DSAparams(pkey.pkey.dsa, pder);
end;


function dsa_param_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_dsa_print(bp, pkey.pkey.dsa, indent, 0);
end;


function dsa_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_dsa_print(bp, pkey.pkey.dsa, indent, 1);
end;


function dsa_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := do_dsa_print(bp, pkey.pkey.dsa, indent, 2);
end;


function old_dsa_priv_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
var
  dsa : PDSA;
begin
    dsa := d2i_DSAPrivateKey(nil, pder, derlen);
    if dsa = nil then  begin
        ERR_raise(ERR_LIB_DSA, ERR_R_DSA_LIB);
        Exit(0);
    end;
    PostInc(dsa.dirty_cnt);
    EVP_PKEY_assign_DSA(pkey, dsa);
    Result := 1;
end;


function old_dsa_priv_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
begin
    Result := i2d_DSAPrivateKey(pkey.pkey.dsa, pder);
end;


function dsa_sig_print(bp : PBIO;const sigalg : PX509_ALGOR; const sig : PASN1_STRING; indent : integer; pctx : PASN1_PCTX):integer;
var
  dsa_sig : PDSA_SIG;
  p : PByte;
  rv : integer;
  r, s : PBIGNUM;
  label _err;
begin
    if sig = nil then begin
        if BIO_puts(bp, #10) <= 0 then
            Exit(0)
        else
            Exit(1);
    end;
    p := sig.data;
    dsa_sig := d2i_DSA_SIG(nil, @p, sig.length);
    if dsa_sig <> nil then
    begin
        rv := 0;
        DSA_SIG_get0(dsa_sig, @r, @s);
        if BIO_write(bp, PUTF8Char(#10), 1) <> 1  then
            goto _err;
        if 0>=ASN1_bn_print(bp, 'r:   ', r, nil, indent) then
            goto _err;
        if 0>=ASN1_bn_print(bp, 's:   ', s, nil, indent) then
            goto _err;
        rv := 1;
 _err:
        DSA_SIG_free(dsa_sig);
        Exit(rv);
    end;
    if BIO_puts(bp, #10) <= 0 then
        Exit(0);
    Result := X509_signature_dump(bp, sig, indent);
end;


function dsa_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
begin
    case op of
      ASN1_PKEY_CTRL_DEFAULT_MD_NID:
      begin
          PInteger(arg2)^ := NID_sha256;
          Exit(1);
      end
      else
          Exit(-2);
    end;
end;


function dsa_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
begin
    Result := pkey.pkey.dsa.dirty_cnt;
end;


function dsa_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    dsa       : PDSA;
    tmpl      : POSSL_PARAM_BLD;
    p, g,
    q, pub_key,
    priv_key  : PBIGNUM;
    params    : POSSL_PARAM;
    selection,
    rv        : integer;
    label _err;
begin
    dsa := from.pkey.dsa;
    p := DSA_get0_p(dsa); g := DSA_get0_g(dsa);
    q := DSA_get0_q(dsa); pub_key := DSA_get0_pub_key(dsa);
     priv_key := DSA_get0_priv_key(dsa);
    selection := 0;
    rv := 0;
    if (p = nil)  or  (q = nil)  or  (g = nil) then
       Exit(0);
    tmpl := OSSL_PARAM_BLD_new;
    if tmpl = nil then Exit(0);
    if (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, p)) or
       (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, q))    or
       (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, g))   then
        goto _err;
    selection  := selection  or OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    if pub_key <> nil then begin
        if (0>=OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                    pub_key)) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    end;
    if priv_key <> nil then
    begin
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


function dsa_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
var
  pctx : PEVP_PKEY_CTX;

  pkey : PEVP_PKEY;

  dsa : PDSA;
begin
    pctx := vpctx;
    pkey := EVP_PKEY_CTX_get0_pkey(pctx);
    dsa := ossl_dsa_new(pctx.libctx);
    if dsa = nil then begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if (0>=ossl_dsa_ffc_params_fromdata(dsa, params))or
       (0>=ossl_dsa_key_fromdata(dsa, params))    or
       (0>=EVP_PKEY_assign_DSA(pkey, dsa))  then
    begin
        DSA_free(dsa);
        Exit(0);
    end;
    Result := 1;
end;


function dsa_pkey_copy( &to, from : PEVP_PKEY):integer;
var
  dsa, dupkey : PDSA;
  ret : integer;
begin
    dsa := from.pkey.dsa;
    dupkey := nil;
    if dsa <> nil then begin
        dupkey := ossl_dsa_dup(dsa, OSSL_KEYMGMT_SELECT_ALL);
        if dupkey = nil then Exit(0);
    end;
    ret := EVP_PKEY_assign_DSA(&to, dupkey);
    if 0>=ret then DSA_free(dupkey);
    Result := ret;
end;


end.
