unit OpenSSL3.crypto.rsa.rsa_ameth;

interface
uses OpenSSL.Api;

function rsa_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
function rsa_param_encode(const pkey : PEVP_PKEY; pstr : PPASN1_STRING; pstrtype : PInteger):integer;
function rsa_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
function rsa_pub_cmp(const a, b : PEVP_PKEY):integer;
  function old_rsa_priv_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
  function old_rsa_priv_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
  function rsa_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
  function rsa_priv_decode(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO):integer;
  function int_rsa_size(const pkey : PEVP_PKEY):integer;
  function rsa_bits(const pkey : PEVP_PKEY):integer;
  function rsa_security_bits(const pkey : PEVP_PKEY):integer;
  procedure int_rsa_free( pkey : PEVP_PKEY);

  function pkey_rsa_print(bp : PBIO;const pkey : PEVP_PKEY; off, priv : integer):integer;
  function rsa_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function rsa_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function rsa_sig_print(bp : PBIO;const sigalg : PX509_ALGOR;const sig : PASN1_STRING; indent : integer; pctx : PASN1_PCTX):integer;
  function rsa_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
  function ossl_rsa_ctx_to_pss_string( pkctx : PEVP_PKEY_CTX):PASN1_STRING;
  function ossl_rsa_pss_to_ctx(ctx : PEVP_MD_CTX; pkctx : PEVP_PKEY_CTX;const sigalg : PX509_ALGOR; pkey : PEVP_PKEY):integer;
  function rsa_pss_verify_param(pmd, pmgf1md : PPEVP_MD; psaltlen, ptrailerField : PInteger):integer;
  function ossl_rsa_pss_get_param(pss: PRSA_PSS_PARAMS; const pmd, pmgf1md : PPEVP_MD; psaltlen : PInteger):integer;
  function rsa_item_verify(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer;const sigalg : PX509_ALGOR;const sig : PASN1_BIT_STRING; pkey : PEVP_PKEY):integer;
  function rsa_item_sign(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer; alg1, alg2 : PX509_ALGOR; sig : PASN1_BIT_STRING):integer;
  function rsa_sig_info_set(siginf : PX509_SIG_INFO;const sigalg : PX509_ALGOR;const sig : PASN1_STRING):integer;
  function rsa_pkey_check(const pkey : PEVP_PKEY):integer;
  function rsa_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
  function rsa_int_export_to(const from : PEVP_PKEY; rsa_type : integer; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function rsa_int_import_from(const params : POSSL_PARAM; vpctx : Pointer; rsa_type : integer):integer;
  function rsa_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function rsa_pss_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function rsa_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function rsa_pss_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function rsa_pkey_copy( _to, from : PEVP_PKEY):integer;
  function ossl_rsa_pss_params_create(sigmd, mgf1md : PEVP_MD; saltlen : integer):PRSA_PSS_PARAMS;
  function rsa_pss_param_print( bp : PBIO; pss_key: Integer; pss: PRSA_PSS_PARAMS; indent : integer):integer;
  function X509_PUBKEY_set0_param( pub : PX509_PUBKEY; aobj : PASN1_OBJECT; ptype : integer; pval : Pointer; penc : PByte; penclen : integer):integer;

const  ossl_rsa_asn1_meths: array[0..1] of TEVP_PKEY_ASN1_METHOD = (
    (
     pkey_id: EVP_PKEY_RSA;
     pkey_base_id: EVP_PKEY_RSA;
     pkey_flags: ASN1_PKEY_SIGPARAM_NULL;
     pem_str: 'RSA';
     info: 'OpenSSL RSA method';
     pub_decode: rsa_pub_decode;
     pub_encode: rsa_pub_encode;
     pub_cmp: rsa_pub_cmp;
     pub_print: rsa_pub_print;
     priv_decode: rsa_priv_decode;
     priv_encode: rsa_priv_encode;
     priv_print: rsa_priv_print;
     pkey_size: int_rsa_size;
     pkey_bits: rsa_bits;
     pkey_security_bits: rsa_security_bits;
     param_decode: nil;
     param_encode: nil;
     param_missing: nil;
     param_copy: nil;
     param_cmp: nil;
     param_print: nil;
     sig_print: rsa_sig_print;
     pkey_free: int_rsa_free;
     pkey_ctrl: rsa_pkey_ctrl;
     old_priv_decode: old_rsa_priv_decode;
     old_priv_encode: old_rsa_priv_encode;
     item_verify: rsa_item_verify;
     item_sign: rsa_item_sign;
     siginf_set: rsa_sig_info_set;
     pkey_check: rsa_pkey_check;
     pkey_public_check: nil;
     pkey_param_check: nil;
     set_priv_key: nil;
     set_pub_key: nil;
     get_priv_key: nil;
     get_pub_key: nil;
     dirty_cnt: rsa_pkey_dirty_cnt;
     export_to: rsa_pkey_export_to;
     import_from: rsa_pkey_import_from;
     copy: rsa_pkey_copy
    ),
    (
     pkey_id: EVP_PKEY_RSA2;
     pkey_base_id: EVP_PKEY_RSA;
     pkey_flags: ASN1_PKEY_ALIAS
    )
);

 ossl_rsa_pss_asn1_meth: TEVP_PKEY_ASN1_METHOD = (
     pkey_id: EVP_PKEY_RSA_PSS;
     pkey_base_id: EVP_PKEY_RSA_PSS;
     pkey_flags: ASN1_PKEY_SIGPARAM_NULL;
     pem_str: 'RSA-PSS';
     info: 'OpenSSL RSA-PSS method';
     pub_decode: rsa_pub_decode;
     pub_encode: rsa_pub_encode;
     pub_cmp: rsa_pub_cmp;
     pub_print: rsa_pub_print;
     priv_decode: rsa_priv_decode;
     priv_encode: rsa_priv_encode;
     priv_print: rsa_priv_print;
     pkey_size: int_rsa_size;
     pkey_bits: rsa_bits;
     pkey_security_bits: rsa_security_bits;
     param_decode: nil;
     param_encode: nil;
     param_missing: nil;
     param_copy: nil;
     param_cmp: nil;
     param_print: nil;
     sig_print: rsa_sig_print;
     pkey_free: int_rsa_free;
     pkey_ctrl: rsa_pkey_ctrl;
     old_priv_decode: nil; old_priv_encode: nil;
     item_verify: rsa_item_verify;
     item_sign: rsa_item_sign;
     siginf_set: rsa_sig_info_set;
     pkey_check: rsa_pkey_check;
     pkey_public_check: nil; pkey_param_check: nil;
     set_priv_key: nil; set_pub_key: nil; get_priv_key: nil; get_pub_key: nil;
     dirty_cnt: rsa_pkey_dirty_cnt;
     export_to: rsa_pss_pkey_export_to;
     import_from: rsa_pss_pkey_import_from;
     copy: rsa_pkey_copy
);
function sk_RSA_PRIME_INFO_num(const sk : Pstack_st_RSA_PRIME_INFO):integer;
function rsa_ctx_to_pss( pkctx : PEVP_PKEY_CTX):PRSA_PSS_PARAMS;

implementation

uses OpenSSL3.crypto.rsa.rsa_crpt, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.a_int,
     openssl3.crypto.asn1.p8_pkey, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.x_algor, openssl3.crypto.evp.p_lib,
     OpenSSL3.Err, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.evp,   openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.bio.bio_print, openssl3.crypto.asn1.f_int,
     openssl3.crypto.bio.bio_lib, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.rsa.rsa_backend, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.stack, openssl3.crypto.rsa.rsa_local,
     openssl3.crypto.asn1.t_pkey, openssl3.crypto.t_x509,
     openssl3.crypto.mem,
     openssl3.crypto.param_build, openssl3.crypto.params_dup,
     openssl3.crypto.asn1.asn_pack,  openssl3.crypto.evp.m_sigver,
     openssl3.crypto.evp.evp_lib,  openssl3.crypto.evp.pmeth_lib,
     OpenSSL3.crypto.x509.x509_set, openssl3.crypto.rsa.rsa_chk,
     OpenSSL3.crypto.rsa.rsa_asn1, openssl3.crypto.rsa.rsa_pss;





function X509_PUBKEY_set0_param( pub : PX509_PUBKEY; aobj : PASN1_OBJECT; ptype : integer; pval : Pointer; penc : PByte; penclen : integer):integer;
begin
    if 0>=X509_ALGOR_set0(pub.algor, aobj, ptype, pval) then
        Exit(0);
    if penc <> nil then begin
        OPENSSL_free(pub.public_key.data);
        pub.public_key.data := penc;
        pub.public_key.length := penclen;
        { Set number of unused bits to zero }
        pub.public_key.flags := pub.public_key.flags and not (ASN1_STRING_FLAG_BITS_LEFT or $07);
        pub.public_key.flags := pub.public_key.flags  or ASN1_STRING_FLAG_BITS_LEFT;
    end;
    Result := 1;
end;




function rsa_ctx_to_pss( pkctx : PEVP_PKEY_CTX):PRSA_PSS_PARAMS;
var
  sigmd, mgf1md : PEVP_MD;
  pk : PEVP_PKEY;
  saltlen : integer;
begin
    pk := EVP_PKEY_CTX_get0_pkey(pkctx);
    if EVP_PKEY_CTX_get_signature_md(pkctx, @sigmd) <= 0  then
        Exit(nil);
    if EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, @mgf1md) <= 0  then
        Exit(nil);
    if 0>=EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, @saltlen ) then
        Exit(nil);
    if saltlen = -1 then begin
        saltlen := EVP_MD_get_size(sigmd);
    end
    else
    if (saltlen = -2)  or  (saltlen = -3) then begin
        saltlen := EVP_PKEY_get_size(pk) - EVP_MD_get_size(sigmd) - 2;
        if EVP_PKEY_get_bits(pk) and $7 = 1 then
            PostDec(saltlen);
        if saltlen < 0 then Exit(nil);
    end;
    Result := ossl_rsa_pss_params_create(sigmd, mgf1md, saltlen);
end;

function sk_RSA_PRIME_INFO_num(const sk : Pstack_st_RSA_PRIME_INFO):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK( sk));
end;


function ossl_rsa_pss_params_create(sigmd, mgf1md : PEVP_MD; saltlen : integer):PRSA_PSS_PARAMS;
var
  pss : PRSA_PSS_PARAMS;
  label _err;
begin
    pss := RSA_PSS_PARAMS_new();
    if pss = nil then goto _err ;
    if saltlen <> 20 then
    begin
        pss.saltLength := ASN1_INTEGER_new();
        if pss.saltLength = nil then
           goto _err ;
        if 0>= ASN1_INTEGER_set(pss.saltLength, saltlen ) then
           goto _err ;
    end;
    if 0>= ossl_x509_algor_new_from_md(@pss.hashAlgorithm, sigmd) then
        goto _err ;
    if mgf1md = nil then
       mgf1md := sigmd;
    if 0>= ossl_x509_algor_md_to_mgf1(@pss.maskGenAlgorithm, mgf1md) then
        goto _err ;
    if 0>= ossl_x509_algor_new_from_md(@pss.maskHash, mgf1md) then
        goto _err ;
    Exit(pss);
 _err:
    RSA_PSS_PARAMS_free(pss);
    Result := nil;
end;


function rsa_pub_cmp(const a, b : PEVP_PKEY):integer;
begin
    {
     * Don't check the public/private key, this is mostly for smart
     * cards.
     }
    if ( (RSA_flags(a.pkey.rsa) and RSA_METHOD_FLAG_NO_CHECK) > 0)
             or ( (RSA_flags(b.pkey.rsa) and RSA_METHOD_FLAG_NO_CHECK)>0) then
    begin
        Exit(1);
    end;
    if (BN_cmp(b.pkey.rsa.n, a.pkey.rsa.n) <> 0)
         or  (BN_cmp(b.pkey.rsa.e, a.pkey.rsa.e) <> 0)  then
        Exit(0);
    Result := 1;
end;


function old_rsa_priv_decode(pkey : PEVP_PKEY;const pder : PPByte; derlen : integer):integer;
var
  rsa : PRSA;
begin
    rsa := d2i_RSAPrivateKey(nil, pder, derlen );
    if rsa = nil then
        Exit(0);
    EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, rsa);
    Result := 1;
end;


function old_rsa_priv_encode(const pkey : PEVP_PKEY; pder : PPByte):integer;
begin
    Result := i2d_RSAPrivateKey(pkey.pkey.rsa, pder);
end;


function rsa_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
var
  rk : PByte;
  rklen : integer;
  str : PASN1_STRING;
  strtype : integer;
begin
    rk := nil;
    if 0>= rsa_param_encode(pkey, @str, @strtype)  then
        Exit(0);
    rklen := i2d_RSAPrivateKey(pkey.pkey.rsa, @rk);
    if rklen <= 0 then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(str);
        Exit(0);
    end;
    if 0>= PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey.ameth.pkey_id) , 0,
                         strtype, str, rk, rklen) then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(str);
        Exit(0);
    end;
    Result := 1;
end;


function rsa_priv_decode(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO):integer;
var
  ret : integer;
  rsa : PRSA;
begin
    ret := 0;
    rsa := ossl_rsa_key_from_pkcs8(p8, nil, nil);
    if rsa <> nil then
    begin
        ret := 1;
        EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, rsa);
    end;
    Result := ret;
end;


function int_rsa_size(const pkey : PEVP_PKEY):integer;
begin
    Result := RSA_size(pkey.pkey.rsa);
end;


function rsa_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := BN_num_bits(pkey.pkey.rsa.n);
end;


function rsa_security_bits(const pkey : PEVP_PKEY):integer;
begin
    Result := _RSA_security_bits(pkey.pkey.rsa);
end;


procedure int_rsa_free( pkey : PEVP_PKEY);
begin
    RSA_free(pkey.pkey.rsa);
end;


function rsa_pss_param_print( bp : PBIO; pss_key: Integer; pss: PRSA_PSS_PARAMS; indent : integer):integer;
var
    rv       : integer;
    maskHash : PX509_ALGOR;
    label _err;
begin
    rv := 0;
    maskHash := nil;
    if 0>= BIO_indent(bp, indent, 128) then
        goto _err ;
    if pss_key > 0 then
    begin
        if pss = nil then
        begin
            if BIO_puts(bp, 'No PSS parameter restrictions'#10) <= 0 then
                Exit(0);
            Exit(1);
        end
        else
        begin
            if BIO_puts(bp, 'PSS parameter restrictions:') <= 0  then
                Exit(0);
        end;
    end
    else
    if (pss = nil) then
    begin
        if BIO_puts(bp, '(INVALID PSS PARAMETERS)'#10) <= 0  then
            Exit(0);
        Exit(1);
    end;
    if BIO_puts(bp, #10) <= 0  then
        goto _err ;
    if pss_key > 0 then
       indent  := indent + 2;
    if 0>= BIO_indent(bp, indent, 128) then
        goto _err ;
    if BIO_puts(bp, 'Hash Algorithm: ') <= 0  then
        goto _err ;
    if pss.hashAlgorithm <> nil then
    begin
        if i2a_ASN1_OBJECT(bp, pss.hashAlgorithm.algorithm) <= 0 then
            goto _err ;
    end
    else
    if (BIO_puts(bp, 'sha1 (default)') <= 0) then
    begin
        goto _err ;
    end;
    if BIO_puts(bp, #10) <= 0  then
        goto _err ;
    if 0>= BIO_indent(bp, indent, 128) then
        goto _err ;
    if BIO_puts(bp, 'Mask Algorithm: ') <= 0  then
        goto _err ;
    if pss.maskGenAlgorithm <> nil then
    begin
        if i2a_ASN1_OBJECT(bp, pss.maskGenAlgorithm.algorithm) <= 0 then
            goto _err ;
        if BIO_puts(bp, ' with ') <= 0  then
            goto _err ;
        maskHash := ossl_x509_algor_mgf1_decode(pss.maskGenAlgorithm);
        if maskHash <> nil then
        begin
            if i2a_ASN1_OBJECT(bp, maskHash.algorithm) <= 0 then
                goto _err ;
        end
        else
        if (BIO_puts(bp, 'INVALID') <= 0) then
        begin
            goto _err ;
        end;
    end
    else
    if (BIO_puts(bp, 'mgf1 with sha1 (default)') <= 0) then
    begin
        goto _err ;
    end;
    BIO_puts(bp, #10);
    if 0>= BIO_indent(bp, indent, 128) then
        goto _err ;
    if BIO_printf(bp, '%s Salt Length: 0x', [get_result(pss_key >0 , 'Minimum' , '')]) <= 0  then
        goto _err ;
    if pss.saltLength <> nil then
    begin
        if i2a_ASN1_INTEGER(bp, pss.saltLength) <= 0 then
            goto _err ;
    end
    else
    if (BIO_puts(bp, '14 (default)') <= 0) then
    begin
        goto _err ;
    end;
    BIO_puts(bp, #10);
    if 0>= BIO_indent(bp, indent, 128) then
        goto _err ;
    if BIO_puts(bp, 'Trailer Field: 0x') <= 0  then
        goto _err ;
    if pss.trailerField <> nil then
    begin
        if i2a_ASN1_INTEGER(bp, pss.trailerField) <= 0 then
            goto _err ;
    end
    else
    if (BIO_puts(bp, '01 (default)') <= 0) then
    begin
        goto _err ;
    end;
    BIO_puts(bp, #10);
    rv := 1;
 _err:
    X509_ALGOR_free(maskHash);
    Exit(rv);
end;


function pkey_rsa_print(bp : PBIO;const pkey : PEVP_PKEY; off, priv : integer):integer;
var
  x : PRSA;
  str, s : PUTF8Char;
  ret, i, mod_len,ex_primes : integer;
  bn : PBIGNUM;
  pinfo : PRSA_PRIME_INFO;
  j : integer;
  label _err;
begin
     x := pkey.pkey.rsa;
    ret := 0; mod_len := 0;
    if x.n <> nil then
       mod_len := BN_num_bits(x.n);
    ex_primes := sk_RSA_PRIME_INFO_num(x.prime_infos);
    if 0>= BIO_indent(bp, off, 128 ) then
        goto _err ;
    if BIO_printf(bp, '%s ', [get_result( pkey_is_pss(pkey),  'RSA-PSS' , 'RSA')]) <= 0 then
        goto _err ;
    if (priv>0)  and  (x.d <> nil) then
    begin
        if BIO_printf(bp, 'Private-Key: (%d bit, %d primes )'#10,
                       [mod_len, get_result(ex_primes <= 0 , 2 , ex_primes + 2)]) <= 0 then
            goto _err ;
        str := 'modulus:';
        s := 'publicExponent:';
    end
    else
    begin
        if BIO_printf(bp, 'Public-Key: (%d bit)'#10, [mod_len]) <= 0 then
            goto _err ;
        str := 'Modulus:';
        s := 'Exponent:';
    end;
    if 0>= ASN1_bn_print(bp, str, x.n, nil, off) then
        goto _err ;
    if 0>= ASN1_bn_print(bp, s, x.e, nil, off) then
        goto _err ;
    if priv > 0 then
    begin
        if 0>= ASN1_bn_print(bp, 'privateExponent:', x.d, nil, off) then
            goto _err ;
        if 0>= ASN1_bn_print(bp, 'prime1:', x.p, nil, off ) then
            goto _err ;
        if 0>= ASN1_bn_print(bp, 'prime2:', x.q, nil, off ) then
            goto _err ;
        if 0>= ASN1_bn_print(bp, 'exponent1:', x.dmp1, nil, off ) then
            goto _err ;
        if 0>= ASN1_bn_print(bp, 'exponent2:', x.dmq1, nil, off ) then
            goto _err ;
        if 0>= ASN1_bn_print(bp, 'coefficient:', x.iqmp, nil, off ) then
            goto _err ;
        for i := 0 to sk_RSA_PRIME_INFO_num(x.prime_infos)-1 do begin
            { print multi-prime info }
            bn := nil;
            pinfo := sk_RSA_PRIME_INFO_value(x.prime_infos, i);
            for j := 0 to 2 do
            begin
                if 0>= BIO_indent(bp, off, 128 ) then
                    goto _err ;
                case j of
                    0:
                    begin
                        if BIO_printf(bp, 'prime%d:', [i + 3]) <= 0  then
                            goto _err ;
                        bn := pinfo.r;
                    end;
                    1:
                    begin
                        if BIO_printf(bp, 'exponent%d:', [i + 3]) <= 0  then
                            goto _err ;
                        bn := pinfo.d;
                    end;
                    2:
                    begin
                        if BIO_printf(bp, 'coefficient%d:', [i + 3]) <= 0  then
                            goto _err ;
                        bn := pinfo.t;
                    end;
                    else
                    begin
                      //
                    end;
                end;
                if 0>= ASN1_bn_print(bp, '', bn, nil, off ) then
                    goto _err ;
            end;
        end;
    end;
    if (pkey_is_pss(pkey))  and  (0>= rsa_pss_param_print(bp, 1, x.pss, off)) then
        goto _err ;
    ret := 1;
 _err:
    Result := ret;
end;


function rsa_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer;ctx : PASN1_PCTX):integer;
begin
    Result := pkey_rsa_print(bp, pkey, indent, 0);
end;


function rsa_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := pkey_rsa_print(bp, pkey, indent, 1);
end;


function rsa_sig_print(bp : PBIO;const sigalg : PX509_ALGOR;const sig : PASN1_STRING; indent : integer;pctx : PASN1_PCTX):integer;
var
  rv : integer;
  pss: PRSA_PSS_PARAMS;
begin
    if OBJ_obj2nid(sigalg.algorithm ) = EVP_PKEY_RSA_PSS then
    begin
        pss := ossl_rsa_pss_decode(sigalg);
        rv := rsa_pss_param_print(bp, 0, pss, indent);
        RSA_PSS_PARAMS_free(pss);
        if 0>= rv then Exit(0);
    end
    else
    if (BIO_puts(bp, #10) <= 0) then
    begin
        Exit(0);
    end;
    if sig <> nil then
       Exit(X509_signature_dump(bp, sig, indent));
    Result := 1;
end;


function rsa_pkey_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
var
  md,
  mgf1md      : PEVP_MD;
  min_saltlen : integer;
begin
    case op of
      ASN1_PKEY_CTRL_DEFAULT_MD_NID:
      begin
          if pkey.pkey.rsa.pss <> nil then
          begin
              if (0>= ossl_rsa_pss_get_param(pkey.pkey.rsa.pss, @md, @mgf1md,
                                          @min_saltlen)) then
              begin
                  ERR_raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR);
                  Exit(0);
              end;
              PInteger(arg2)^ := EVP_MD_get_type(md);
              { Return of 2 indicates this MD is mandatory }
              Exit(2);
          end;
          PInteger(arg2)^ := NID_sha256;
          Exit(1);
      end
      else
          Exit(-2);
    end;
end;


function ossl_rsa_ctx_to_pss_string( pkctx : PEVP_PKEY_CTX):PASN1_STRING;
var
  os : PASN1_STRING;
  pss: PRSA_PSS_PARAMS;
begin
    pss := rsa_ctx_to_pss(pkctx);
    if pss = nil then
       Exit(nil);
    os := ASN1_item_pack(pss, RSA_PSS_PARAMS_it, nil);
    RSA_PSS_PARAMS_free(pss);
    Result := os;
end;


function ossl_rsa_pss_to_ctx(ctx : PEVP_MD_CTX; pkctx : PEVP_PKEY_CTX;const sigalg : PX509_ALGOR; pkey : PEVP_PKEY):integer;
var
  rv, saltlen : integer;
  pss: PRSA_PSS_PARAMS;
  mgf1md, md, checkmd : PEVP_MD;
  label _err;
begin
    rv := -1;
    mgf1md := nil; md := nil;

    { Sanity check: make sure it is PSS }
    if OBJ_obj2nid(sigalg.algorithm) <> EVP_PKEY_RSA_PSS  then  begin
        ERR_raise(ERR_LIB_RSA, RSA_R_UNSUPPORTED_SIGNATURE_TYPE);
        Exit(-1);
    end;
    { Decode PSS parameters }
    pss := ossl_rsa_pss_decode(sigalg);
    if 0>= ossl_rsa_pss_get_param(pss, @md, @mgf1md, @saltlen) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PSS_PARAMETERS);
        goto _err ;
    end;
    { We have all parameters now set up context }
    if pkey <> nil then begin
        if 0>= EVP_DigestVerifyInit(ctx, @pkctx, md, nil, pkey) then
            goto _err ;
    end
    else
    begin
        if EVP_PKEY_CTX_get_signature_md(pkctx, @checkmd) <= 0  then
            goto _err ;
        if EVP_MD_get_type(md) <> EVP_MD_get_type(checkmd)  then begin
            ERR_raise(ERR_LIB_RSA, RSA_R_DIGEST_DOES_NOT_MATCH);
            goto _err ;
        end;
    end;
    if EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING )  <= 0 then
        goto _err ;
    if EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) <= 0  then
        goto _err ;
    if EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0  then
        goto _err ;
    { Carry on }
    rv := 1;
 _err:
    RSA_PSS_PARAMS_free(pss);
    Result := rv;
end;


function rsa_pss_verify_param(pmd, pmgf1md : PPEVP_MD; psaltlen, ptrailerField : PInteger):integer;
begin
    if (psaltlen <> nil)  and  (psaltlen^ < 0) then begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_SALT_LENGTH);
        Exit(0);
    end;
    {
     * low-level routines support only trailer field $bc (value 1) and
     * PKCS#1 says we should reject any other value anyway.
     }
    if (ptrailerField <> nil)  and  (ptrailerField^ <> 1) then begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_TRAILER);
        Exit(0);
    end;
    Result := 1;
end;


function ossl_rsa_pss_get_param(pss: PRSA_PSS_PARAMS; const pmd, pmgf1md : PPEVP_MD; psaltlen : PInteger):integer;
 var
  trailerField : integer;
begin
    {
     * Callers do not care about the trailer field, and yet, we must
     * pass it from get_param to verify_param, since the latter checks
     * its value.
     *
     * When callers start caring, it's a simple thing to add another
     * argument to this function.
     }
    trailerField := 0;
    Result := Int( (ossl_rsa_pss_get_param_unverified(pss, pmd, pmgf1md, psaltlen,
                                             @trailerField) >0)
         and  (rsa_pss_verify_param(pmd, pmgf1md, psaltlen, @trailerField) > 0) );
end;


function rsa_item_verify(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer;const sigalg : PX509_ALGOR;const sig : PASN1_BIT_STRING; pkey : PEVP_PKEY):integer;
begin
    { Sanity check: make sure it is PSS }
    if OBJ_obj2nid(sigalg.algorithm) <> EVP_PKEY_RSA_PSS  then begin
        ERR_raise(ERR_LIB_RSA, RSA_R_UNSUPPORTED_SIGNATURE_TYPE);
        Exit(-1);
    end;
    if ossl_rsa_pss_to_ctx(ctx, nil, sigalg, pkey ) > 0 then  begin
        { Carry on }
        Exit(2);
    end;
    Result := -1;
end;


function rsa_item_sign(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer; alg1, alg2 : PX509_ALGOR; sig : PASN1_BIT_STRING):integer;
var
  pad_mode : integer;
  pkctx    : PEVP_PKEY_CTX;
  os1,
  os2      : PASN1_STRING;
  label _err;
begin
    pkctx := EVP_MD_CTX_get_pkey_ctx(ctx);
    if EVP_PKEY_CTX_get_rsa_padding(pkctx, @pad_mode) <= 0  then
        Exit(0);
    if pad_mode = RSA_PKCS1_PADDING then Exit(2);
    if pad_mode = RSA_PKCS1_PSS_PADDING then begin
        os1 := ossl_rsa_ctx_to_pss_string(pkctx);
        if os1 = nil then Exit(0);
        { Duplicate parameters if we have to }
        if alg2 <> nil then begin
            os2 := ASN1_STRING_dup(os1);
            if os2 = nil then goto _err ;
            if 0>= X509_ALGOR_set0(alg2, OBJ_nid2obj(EVP_PKEY_RSA_PSS) ,
                                 V_ASN1_SEQUENCE, os2)  then
            begin
                ASN1_STRING_free(os2);
                goto _err ;
            end;
        end;
        if 0>= X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_RSA_PSS ) ,
                             V_ASN1_SEQUENCE, os1) then
            goto _err ;
        Exit(3);
    _err:
        ASN1_STRING_free(os1);
        Exit(0);
    end;
    Result := 2;
end;


function rsa_sig_info_set( siginf : PX509_SIG_INFO;const sigalg : PX509_ALGOR;const sig : PASN1_STRING):integer;
var
  rv, mdnid, saltlen : integer;
  flags : uint32;
  mgf1md, md : PEVP_MD;
  pss: PRSA_PSS_PARAMS;
  secbits : integer;
  label _err;
begin
    rv := 0;
    mgf1md := nil; md := nil;

    { Sanity check: make sure it is PSS }
    if OBJ_obj2nid(sigalg.algorithm) <> EVP_PKEY_RSA_PSS  then
        Exit(0);
    { Decode PSS parameters }
    pss := ossl_rsa_pss_decode(sigalg);
    if 0>= ossl_rsa_pss_get_param(pss, @md, @mgf1md, @saltlen) then
        goto _err ;
    mdnid := EVP_MD_get_type(md);
    {
     * For TLS need SHA256, SHA384 or SHA512, digest and MGF1 digest must
     * match and salt length must equal digest size
     }
    if ( (mdnid = NID_sha256)  or  (mdnid = NID_sha384)  or  (mdnid = NID_sha512) ) and
        (mdnid = EVP_MD_get_type(mgf1md))
             and  (saltlen = EVP_MD_get_size(md)) then
        flags := X509_SIG_INFO_TLS
    else
        flags := 0;
    { Note: security bits half number of digest bits }
    secbits := EVP_MD_get_size(md) * 4;
    {
     * SHA1 and MD5 are known to be broken. Reduce security bits so that
     * they're no longer accepted at security level 1. The real values don't
     * really matter as long as they're lower than 80, which is our security
     * level 1.
     * https://eprint.iacr.org/2020/014 puts a chosen-prefix attack for SHA1 at
     * 2^63.4
     * https://documents.epfl.ch/users/l/le/lenstra/public/papers/lat.pdf
     * puts a chosen-prefix attack for MD5 at 2^39.
     }
    if mdnid = NID_sha1 then
       secbits := 64
    else if (mdnid = NID_md5_sha1) then
        secbits := 68
    else if (mdnid = NID_md5) then
        secbits := 39;
    X509_SIG_INFO_set(siginf, mdnid, EVP_PKEY_RSA_PSS, secbits, flags);
    rv := 1;
_err:
    RSA_PSS_PARAMS_free(pss);
    Result := rv;
end;


function rsa_pkey_check(const pkey : PEVP_PKEY):integer;
begin
    Result := RSA_check_key_ex(pkey.pkey.rsa, nil);
end;


function rsa_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
begin
    Result := pkey.pkey.rsa.dirty_cnt;
end;


function rsa_int_export_to(const from : PEVP_PKEY; rsa_type : integer; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    rsa          : PRSA;
    tmpl         : POSSL_PARAM_BLD;
    params       : POSSL_PARAM;
    selection,
    rv           : integer;
    md,mgf1md           : PEVP_MD;
    md_nid,
    mgf1md_nid,
    saltlen,
    trailerfield : integer;
    pss_params   : TRSA_PSS_PARAMS_30;
    label _err;
begin
    rsa := from.pkey.rsa;
    tmpl := OSSL_PARAM_BLD_new();
    params := nil;
    selection := 0;
    rv := 0;
    if tmpl = nil then Exit(0);
    { Public parameters must always be present }
    if (RSA_get0_n(rsa) = nil)  or  (RSA_get0_e(rsa) = nil)   then
        goto _err ;
    if 0>= ossl_rsa_todata(rsa, tmpl, nil) then
        goto _err ;
    selection  := selection  or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    if RSA_get0_d(rsa) <> nil  then
        selection  := selection  or OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if rsa.pss <> nil then begin
         md := nil; mgf1md := nil;
        if 0>= ossl_rsa_pss_get_param_unverified(rsa.pss, @md, @mgf1md,
                                               @saltlen, @trailerfield) then
            goto _err ;
        md_nid := EVP_MD_get_type(md);
        mgf1md_nid := EVP_MD_get_type(mgf1md);
        if (0>= ossl_rsa_pss_params_30_set_defaults(@pss_params))  or
           (0>= ossl_rsa_pss_params_30_set_hashalg(@pss_params, md_nid))
             or  (0>= ossl_rsa_pss_params_30_set_maskgenhashalg(@pss_params,
                                                          mgf1md_nid))
             or  (0>= ossl_rsa_pss_params_30_set_saltlen(@pss_params, saltlen))
             or  (0>= ossl_rsa_pss_params_30_todata(@pss_params, tmpl, nil)) then
            goto _err ;
        selection  := selection  or OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
    end;
    params := OSSL_PARAM_BLD_to_param(tmpl);
    if params = nil then
        goto _err ;
    { We export, the provider imports }
    rv := importer(to_keydata, selection, params);
 _err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    Result := rv;
end;


function rsa_int_import_from(const params : POSSL_PARAM; vpctx : Pointer; rsa_type : integer):integer;
var
    pctx             : PEVP_PKEY_CTX;
    pkey             : PEVP_PKEY;
    rsa              : PRSA;
    rsa_pss_params   : TRSA_PSS_PARAMS_30;
    pss_defaults_set,
    ok,
    mdnid,
    mgf1mdnid,
    saltlen          : integer;
    md,
    mgf1md           : PEVP_MD;
    label _err;
begin
    pctx := vpctx;
    pkey := EVP_PKEY_CTX_get0_pkey(pctx);
    rsa := ossl_rsa_new_with_ctx(pctx.libctx);
    FillChar(rsa_pss_params, SizeOf(TRSA_PSS_PARAMS_30), 0);
    pss_defaults_set := 0;
    ok := 0;
    if rsa = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
    RSA_set_flags(rsa, rsa_type);
    if 0>= ossl_rsa_pss_params_30_fromdata(@rsa_pss_params, @pss_defaults_set,
                                         params, pctx.libctx ) then
        goto _err ;
    case rsa_type of
    RSA_FLAG_TYPE_RSA:
    begin    {
         * Were PSS parameters filled in?
         * In that case, something's wrong
         }
        if 0>= ossl_rsa_pss_params_30_is_unrestricted(@rsa_pss_params) then
            goto _err ;
    end;
    RSA_FLAG_TYPE_RSASSAPSS:
    begin    {
         * Were PSS parameters filled in?  In that case, create the old
         * RSA_PSS_PARAMS structure.  Otherwise, this is an unrestricted key.
         }
        if 0>= ossl_rsa_pss_params_30_is_unrestricted(@rsa_pss_params) then
        begin
            { Create the older RSA_PSS_PARAMS from RSA_PSS_PARAMS_30 data }
            mdnid := ossl_rsa_pss_params_30_hashalg(@rsa_pss_params);
            mgf1mdnid := ossl_rsa_pss_params_30_maskgenhashalg(@rsa_pss_params);
            saltlen := ossl_rsa_pss_params_30_saltlen(@rsa_pss_params);
            md := EVP_get_digestbynid(mdnid);
            mgf1md := EVP_get_digestbynid(mgf1mdnid);
            rsa.pss := ossl_rsa_pss_params_create(md, mgf1md, saltlen);
            if (rsa.pss = nil) then
                goto _err ;
        end;
    end;
    else
        { RSA key sub-types we don't know how to handle yet }
        goto _err ;
    end;
    if 0>= ossl_rsa_fromdata(rsa, params) then
        goto _err ;
    case rsa_type of
    RSA_FLAG_TYPE_RSA:
        ok := EVP_PKEY_assign_RSA(pkey, rsa);
        //break;
    RSA_FLAG_TYPE_RSASSAPSS:
        ok := EVP_PKEY_assign(pkey, EVP_PKEY_RSA_PSS, rsa);
        //break;
    end;
 _err:
    if 0>= ok then RSA_free(rsa);
    Result := ok;
end;


function rsa_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    Exit(rsa_int_export_to(from, RSA_FLAG_TYPE_RSA, to_keydata, importer, libctx, propq));
end;


function rsa_pss_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    Exit(rsa_int_export_to(from, RSA_FLAG_TYPE_RSASSAPSS, to_keydata,
                             importer, libctx, propq));
end;


function rsa_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := rsa_int_import_from(params, vpctx, RSA_FLAG_TYPE_RSA);
end;


function rsa_pss_pkey_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := rsa_int_import_from(params, vpctx, RSA_FLAG_TYPE_RSASSAPSS);
end;


function rsa_pkey_copy( _to, from : PEVP_PKEY):integer;
var
  rsa, dupkey : PRSA;

  ret : integer;
begin
    rsa := from.pkey.rsa;
    dupkey := nil;
    if rsa <> nil then begin
        dupkey := ossl_rsa_dup(rsa, OSSL_KEYMGMT_SELECT_ALL);
        if dupkey = nil then Exit(0);
    end;
    ret := EVP_PKEY_assign(_to, from.&type, dupkey);
    if 0>= ret then RSA_free(dupkey);
    Result := ret;
end;



function rsa_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
var
  penc : PByte;
  penclen : integer;
  str : PASN1_STRING;
  strtype : integer;
begin
    penc := nil;
    if 0>= rsa_param_encode(pkey, @str, @strtype) then
        Exit(0);
    penclen := i2d_RSAPublicKey(pkey.pkey.rsa, @penc);
    if penclen <= 0 then Exit(0);
    if X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey.ameth.pkey_id) ,
                               strtype, str, penc, penclen) > 0 then
        Exit(1);
    OPENSSL_free(penc);
    Result := 0;
end;



function rsa_param_encode(const pkey : PEVP_PKEY; pstr : PPASN1_STRING; pstrtype : PInteger):integer;
var
  rsa : PRSA;
begin
    rsa := pkey.pkey.rsa;
    pstr^ := nil;
    { If RSA it's just nil type }
    if RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) <> RSA_FLAG_TYPE_RSASSAPSS  then
    begin
        pstrtype^ := V_ASN1_NULL;
        Exit(1);
    end;
    { If no PSS parameters we omit parameters entirely }
    if rsa.pss = nil then begin
        pstrtype^ := V_ASN1_UNDEF;
        Exit(1);
    end;
    { Encode PSS parameters }
    if ASN1_item_pack(rsa.pss, RSA_PSS_PARAMS_it , pstr) = nil  then
        Exit(0);
    pstrtype^ := V_ASN1_SEQUENCE;
    Result := 1;
end;


function rsa_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
var
  p : PByte;
  pklen : integer;
  alg : PX509_ALGOR;
  rsa : PRSA;
begin
    rsa := nil;
    if 0>= X509_PUBKEY_get0_param(nil, @p, @pklen, @alg, pubkey) then
        Exit(0);
    rsa := d2i_RSAPublicKey(nil, @p, pklen);
    if rsa = nil then
        Exit(0);
    if 0>= ossl_rsa_param_decode(rsa, alg) then  begin
        RSA_free(rsa);
        Exit(0);
    end;
    RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
    case pkey.ameth.pkey_id of
    EVP_PKEY_RSA:
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA);
        //break;
    EVP_PKEY_RSA_PSS:
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS);
        //break;
    else
        { Leave the type bits zero }
        begin
           //break;
        end;
    end;
    if 0>= EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, rsa) then
    begin
        RSA_free(rsa);
        Exit(0);
    end;
    Result := 1;
end;


end.
