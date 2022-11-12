unit openssl3.crypto.ec.ecx_meth;

interface
 uses OpenSSL.Api;

function pkey_ecx_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
function pkey_ecx_derive25519( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):int;
 function pkey_ecx_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
function pkey_ecx_derive448( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
function pkey_ecd_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
function pkey_ecd_digestsign25519(ctx : PEVP_MD_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
function pkey_ecd_digestverify25519(ctx : PEVP_MD_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
 function pkey_ecd_digestsign448(ctx : PEVP_MD_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
 function pkey_ecd_digestverify448(ctx : PEVP_MD_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function ecx_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
  function ecx_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
  function ecx_pub_cmp(const a, b : PEVP_PKEY):integer;
  function ecx_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function ecx_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
  function ecx_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
  function ecx_size(const pkey : PEVP_PKEY):integer;
  function ecx_bits(const pkey : PEVP_PKEY):integer;
  function ecx_security_bits(const pkey : PEVP_PKEY):integer;
  procedure ecx_free( pkey : PEVP_PKEY);
  function ecx_cmp_parameters(const a, b : PEVP_PKEY):integer;
  function ecx_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
  function ecx_set_priv_key(pkey : PEVP_PKEY;const priv : PByte; len : size_t):integer;
  function ecx_set_pub_key(pkey : PEVP_PKEY;const pub : PByte; len : size_t):integer;
  function ecx_get_priv_key(const pkey : PEVP_PKEY; priv : PByte; len : Psize_t):integer;
  function ecx_get_pub_key(const pkey : PEVP_PKEY; pub : PByte; len : Psize_t):integer;
  function ecx_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
  function ecx_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer;importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function ecx_generic_import_from(const params : POSSL_PARAM; vpctx : Pointer; keytype : integer):integer;
  function ecx_pkey_copy( _to, from : PEVP_PKEY):integer;
  function x25519_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function ecx_priv_decode_ex(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function x448_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function ecd_size25519(const pkey : PEVP_PKEY):integer;
  function ecd_size448(const pkey : PEVP_PKEY):integer;
  function ecd_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
  function ecd_item_verify(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer;const sigalg : PX509_ALGOR;const str : PASN1_BIT_STRING; pkey : PEVP_PKEY):integer;
  function ecd_item_sign25519(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer; alg1, alg2 : PX509_ALGOR; str : PASN1_BIT_STRING):integer;
  function ecd_sig_info_set25519(siginf : PX509_SIG_INFO;const alg : PX509_ALGOR;const sig : PASN1_STRING):integer;
  function ed25519_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
  function ecd_item_sign448(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer; alg1, alg2 : PX509_ALGOR; str : PASN1_BIT_STRING):integer;
  function ecd_sig_info_set448(siginf : PX509_SIG_INFO;const alg : PX509_ALGOR;const sig : PASN1_STRING):integer;
  function ed448_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;


const  ecx25519_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_X25519;
    flags: 0;
    init: nil;
    copy: nil;
    cleanup: nil;
    paramgen_init: nil;
    paramgen: nil;
    keygen_init: nil;
    keygen: pkey_ecx_keygen;
    sign_init: nil;
    sign: nil;
    verify_init: nil;
    verify: nil;
    verify_recover_init: nil;
    verify_recover: nil;
    signctx_init: nil;
    signctx: nil;
    verifyctx_init: nil;
    verifyctx: nil;
    encrypt_init: nil;
    encrypt: nil;
    decrypt_init: nil;
    decrypt: nil;
    derive_init: nil;
    derive: pkey_ecx_derive25519;
    ctrl: pkey_ecx_ctrl;
    ctrl_str: nil
);
  ecx448_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_X448;
    flags: 0;
    init: nil;
    copy: nil;
    cleanup: nil;
    paramgen_init: nil;
    paramgen: nil;
    keygen_init: nil;
    keygen: pkey_ecx_keygen;
    sign_init: nil;
    sign: nil;
    verify_init: nil;
    verify: nil;
    verify_recover_init: nil;
    verify_recover: nil;
    signctx_init: nil;
    signctx: nil;
    verifyctx_init: nil;
    verifyctx: nil;
    encrypt_init: nil;
    encrypt: nil;
    decrypt_init: nil;
    decrypt: nil;
    derive_init: nil;
    derive: pkey_ecx_derive448;
    ctrl: pkey_ecx_ctrl;
    ctrl_str: nil
);

 ed25519_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_ED25519;
    flags: EVP_PKEY_FLAG_SIGCTX_CUSTOM;
    init: nil;
    copy: nil;
    cleanup: nil;
    paramgen_init: nil;
    paramgen: nil;
    keygen_init: nil;
    keygen: pkey_ecx_keygen;
    sign_init: nil;
    sign: nil;
    verify_init: nil;
    verify: nil;
    verify_recover_init: nil;
    verify_recover: nil;
    signctx_init: nil;
    signctx: nil;
    verifyctx_init: nil;
    verifyctx: nil;
    encrypt_init: nil;
    encrypt: nil;
    decrypt_init: nil;
    decrypt: nil;
    derive_init: nil;
    derive: nil;
    ctrl: pkey_ecd_ctrl;
    ctrl_str: nil;
    digestsign: pkey_ecd_digestsign25519 ;
    digestverify: pkey_ecd_digestverify25519;
);

 ed448_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_ED448;
    flags: EVP_PKEY_FLAG_SIGCTX_CUSTOM;
    init: nil;
    copy: nil;
    cleanup: nil;
    paramgen_init: nil;
    paramgen: nil;
    keygen_init: nil;
    keygen: pkey_ecx_keygen;
    sign_init: nil;
    sign: nil;
    verify_init: nil;
    verify: nil;
    verify_recover_init: nil;
    verify_recover: nil;
    signctx_init: nil;
    signctx: nil;
    verifyctx_init: nil;
    verifyctx: nil;
    encrypt_init: nil;
    encrypt: nil;
    decrypt_init: nil;
    decrypt: nil;
    derive_init: nil;
    derive: nil;
    ctrl: pkey_ecd_ctrl;
    ctrl_str: nil;
    digestsign: pkey_ecd_digestsign448 ;
    digestverify: pkey_ecd_digestverify448;
);

 ossl_ecx25519_asn1_meth: TEVP_PKEY_ASN1_METHOD  = (
    pkey_id: EVP_PKEY_X25519;
    pkey_base_id: EVP_PKEY_X25519;
    pkey_flags: 0;
    pem_str: 'X25519';
    info: 'OpenSSL X25519 algorithm';
    pub_decode: ecx_pub_decode;
    pub_encode: ecx_pub_encode;
    pub_cmp: ecx_pub_cmp;
    pub_print: ecx_pub_print;
    priv_decode: nil;
    priv_encode: ecx_priv_encode;
    priv_print: ecx_priv_print;
    pkey_size: ecx_size;
    pkey_bits: ecx_bits;
    pkey_security_bits: ecx_security_bits;
    param_decode: nil;
    param_encode: nil;
    param_missing: nil;
    param_copy: nil;
    param_cmp: ecx_cmp_parameters;
    param_print: nil;
    sig_print: nil;
    pkey_free: ecx_free;
    pkey_ctrl: ecx_ctrl;
    old_priv_decode: nil; old_priv_encode: nil;
    item_verify: nil; item_sign: nil; siginf_set: nil;
    pkey_check: nil;
    pkey_public_check: nil;
    pkey_param_check: nil;
    set_priv_key: ecx_set_priv_key;
    set_pub_key: ecx_set_pub_key;
    get_priv_key: ecx_get_priv_key;
    get_pub_key: ecx_get_pub_key;
    dirty_cnt: ecx_pkey_dirty_cnt;
    export_to: ecx_pkey_export_to;
    import_from: x25519_import_from;
    copy: ecx_pkey_copy;
    priv_decode_ex: ecx_priv_decode_ex
);

 ossl_ecx448_asn1_meth: TEVP_PKEY_ASN1_METHOD  = (
    pkey_id: EVP_PKEY_X448;
    pkey_base_id: EVP_PKEY_X448;
    pkey_flags: 0;
    pem_str: 'X448';
    info: 'OpenSSL X448 algorithm';

    pub_decode: ecx_pub_decode;
    pub_encode: ecx_pub_encode;
    pub_cmp: ecx_pub_cmp;
    pub_print: ecx_pub_print;

    priv_decode: nil;
    priv_encode: ecx_priv_encode;
    priv_print: ecx_priv_print;

    pkey_size: ecx_size;
    pkey_bits: ecx_bits;
    pkey_security_bits: ecx_security_bits;

    param_decode: nil;
    param_encode: nil;
    param_missing: nil;
    param_copy: nil;
    param_cmp: ecx_cmp_parameters;
    param_print: nil; sig_print: nil;

    pkey_free: ecx_free;
    pkey_ctrl: ecx_ctrl;
    old_priv_decode: nil;
    old_priv_encode: nil;

    item_verify: nil; item_sign: nil; siginf_set: nil;
    pkey_check: nil;

    pkey_public_check: nil;
    pkey_param_check: nil;

    set_priv_key: ecx_set_priv_key;
    set_pub_key: ecx_set_pub_key;
    get_priv_key: ecx_get_priv_key;
    get_pub_key: ecx_get_pub_key;
    dirty_cnt: ecx_pkey_dirty_cnt;
    export_to: ecx_pkey_export_to;
    import_from: x448_import_from;
    copy: ecx_pkey_copy;

    priv_decode_ex: ecx_priv_decode_ex
);

ossl_ed25519_asn1_meth: TEVP_PKEY_ASN1_METHOD  = (
    pkey_id: EVP_PKEY_ED25519;
    pkey_base_id: EVP_PKEY_ED25519;
    pkey_flags: 0;
    pem_str: 'ED25519';
    info: 'OpenSSL ED25519 algorithm';

    pub_decode: ecx_pub_decode;
    pub_encode: ecx_pub_encode;
    pub_cmp: ecx_pub_cmp;
    pub_print: ecx_pub_print;

    priv_decode: nil;
    priv_encode: ecx_priv_encode;
    priv_print: ecx_priv_print;

    pkey_size: ecd_size25519;
    pkey_bits: ecx_bits;
    pkey_security_bits: ecx_security_bits;

    param_decode: nil;
    param_encode: nil;
    param_missing: nil;
    param_copy: nil;
    param_cmp: ecx_cmp_parameters;
    param_print: nil;
    sig_print: nil;

    pkey_free: ecx_free;
    pkey_ctrl: ecd_ctrl;
    old_priv_decode: nil; old_priv_encode: nil;
    item_verify: ecd_item_verify;
    item_sign: ecd_item_sign25519;
    siginf_set: ecd_sig_info_set25519;

    pkey_check: nil;
    pkey_public_check: nil;
    pkey_param_check: nil;

    set_priv_key: ecx_set_priv_key;
    set_pub_key: ecx_set_pub_key;
    get_priv_key: ecx_get_priv_key;
    get_pub_key: ecx_get_pub_key;
    dirty_cnt: ecx_pkey_dirty_cnt;
    export_to: ecx_pkey_export_to;
    import_from: ed25519_import_from;
    copy: ecx_pkey_copy;

    priv_decode_ex: ecx_priv_decode_ex
);

 ossl_ed448_asn1_meth: TEVP_PKEY_ASN1_METHOD  = (
    pkey_id: EVP_PKEY_ED448;
    pkey_base_id: EVP_PKEY_ED448;
    pkey_flags: 0;
    pem_str: 'ED448';
    info: 'OpenSSL ED448 algorithm';

    pub_decode: ecx_pub_decode;
    pub_encode: ecx_pub_encode;
    pub_cmp: ecx_pub_cmp;
    pub_print: ecx_pub_print;

    priv_decode: nil;
    priv_encode: ecx_priv_encode;
    priv_print: ecx_priv_print;

    pkey_size: ecd_size448;
    pkey_bits: ecx_bits;
    pkey_security_bits: ecx_security_bits;

    param_decode: nil;
    param_encode: nil;
    param_missing: nil;
    param_copy: nil;
    param_cmp: ecx_cmp_parameters;
    param_print: nil;
    sig_print: nil;

    pkey_free: ecx_free;
    pkey_ctrl: ecd_ctrl;
    old_priv_decode: nil; old_priv_encode: nil;
    item_verify: ecd_item_verify;
    item_sign: ecd_item_sign448;
    siginf_set: ecd_sig_info_set448;

    pkey_check: nil;
    pkey_public_check: nil;
    pkey_param_check: nil;

    set_priv_key: ecx_set_priv_key;
    set_pub_key: ecx_set_pub_key;
    get_priv_key: ecx_get_priv_key;
    get_pub_key: ecx_get_pub_key;
    dirty_cnt: ecx_pkey_dirty_cnt;
    export_to: ecx_pkey_export_to;
    import_from: ed448_import_from;
    copy: ecx_pkey_copy;

    priv_decode_ex: ecx_priv_decode_ex
);

function ossl_ecx25519_pkey_method:PEVP_PKEY_METHOD;
function validate_ecx_derive(ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t;const privkey, pubkey : PPByte):integer;
 function ossl_ecx448_pkey_method:PEVP_PKEY_METHOD;
function ossl_ed25519_pkey_method:PEVP_PKEY_METHOD;
function ossl_ed448_pkey_method:PEVP_PKEY_METHOD;
function ecx_key_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX; op : ecx_key_op_t):integer;
function ecd_item_sign( alg1, alg2 : PX509_ALGOR; nid : integer):integer;



implementation
uses OpenSSL3.Err, openssl3.crypto.evp.p_lib, openssl3.crypto.ec.curve25519,
     openssl3.crypto.ec.curve448, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.param_build,  openssl3.crypto.params_dup,
     openssl3.crypto.evp.pmeth_lib, openssl3.crypto.ec.ecx_key,
     openssl3.crypto.o_str,  openssl3.crypto.objects.obj_dat,
     openssl3.crypto.bio.bio_print,  openssl3.crypto.asn1.t_pkey,
     openssl3.crypto.asn1.tasn_typ,  openssl3.crypto.asn1.p8_pkey,
     openssl3.crypto.mem,  openssl3.crypto.cpuid,
     openssl3.crypto.asn1.x_algor,   openssl3.crypto.evp.m_sigver,
     openssl3.crypto.x509.x_pubkey,  OpenSSL3.crypto.x509.x509_set,
     openssl3.crypto.provider_core, openssl3.crypto.evp.keymgmt_meth,
     openssl3.crypto.ec.ecx_backend, openssl3.crypto.ec.curve25519.eddsa;


function ed448_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := ecx_generic_import_from(params, vpctx, EVP_PKEY_ED448);
end;





function ecd_sig_info_set448(siginf : PX509_SIG_INFO;const alg : PX509_ALGOR;const sig : PASN1_STRING):integer;
begin
    X509_SIG_INFO_set(siginf, NID_undef, NID_ED448, X448_SECURITY_BITS,
                      X509_SIG_INFO_TLS);
    Result := 1;
end;


function ecd_item_sign448(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer; alg1, alg2 : PX509_ALGOR; str : PASN1_BIT_STRING):integer;
begin
    Result := ecd_item_sign(alg1, alg2, NID_ED448);
end;




function ecd_item_sign( alg1, alg2 : PX509_ALGOR; nid : integer):integer;
begin
    { Note that X509_ALGOR_set0(..., ..., V_ASN1_UNDEF, ...) cannot fail }
    { Set algorithms identifiers }
    X509_ALGOR_set0(alg1, OBJ_nid2obj(nid), V_ASN1_UNDEF, nil);
    if alg2 <> nil then
       X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_UNDEF, nil);
    { Algorithm identifiers set: carry on as normal }
    Result := 3;
end;




function ed25519_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := ecx_generic_import_from(params, vpctx, EVP_PKEY_ED25519);
end;



function ecd_sig_info_set25519(siginf : PX509_SIG_INFO;const alg : PX509_ALGOR;const sig : PASN1_STRING):integer;
begin
    X509_SIG_INFO_set(siginf, NID_undef, NID_ED25519, X25519_SECURITY_BITS,
                      X509_SIG_INFO_TLS);
    Result := 1;
end;




function ecd_item_sign25519(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const asn : Pointer; alg1, alg2 : PX509_ALGOR; str : PASN1_BIT_STRING):integer;
begin
    Result := ecd_item_sign(alg1, alg2, NID_ED25519);
end;




function ecd_item_verify(ctx : PEVP_MD_CTX;const it : PASN1_ITEM;const  asn : Pointer;const  sigalg : PX509_ALGOR;const  str : PASN1_BIT_STRING; pkey : PEVP_PKEY):integer;
var
  obj : PASN1_OBJECT;
  ptype, nid : integer;
begin
    { Sanity check: make sure it is ED25519/ED448 with absent parameters }
    X509_ALGOR_get0(@obj, @ptype, nil, sigalg);
    nid := OBJ_obj2nid(obj);
    if (nid <> NID_ED25519)  and  (nid <> NID_ED448)  or  (ptype <> V_ASN1_UNDEF) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        Exit(0);
    end;
    if 0>=EVP_DigestVerifyInit(ctx, nil, nil, nil, pkey) then
        Exit(0);
    Result := 2;
end;




function ecd_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
begin
    case op of
    ASN1_PKEY_CTRL_DEFAULT_MD_NID:
    begin
        { We currently only support Pure EdDSA which takes no digest }
        PInteger(arg2)^ := NID_undef;
        Exit(2);
    end
    else
        Exit(-2);
    end;
end;



function ecd_size25519(const pkey : PEVP_PKEY):integer;
begin
    Result := ED25519_SIGSIZE;
end;


function ecd_size448(const pkey : PEVP_PKEY):integer;
begin
    Result := ED448_SIGSIZE;
end;




function x448_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := ecx_generic_import_from(params, vpctx, EVP_PKEY_X448);
end;




function ecx_key_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX; op : ecx_key_op_t):integer;
var
  ecxkey : PECX_KEY;
  nm : PUTF8Char;
begin
     ecxkey := pkey.pkey.ecx;
    nm := OBJ_nid2ln(pkey.ameth.pkey_id);
    if op = KEY_OP_PRIVATE then
    begin
        if (ecxkey = nil)  or  (ecxkey.privkey = nil) then  begin
            if BIO_printf(bp, '%*s<INVALID PRIVATE KEY>\n', [indent, '']) <= 0 then
                Exit(0);
            Exit(1);
        end;
        if BIO_printf(bp, '%*s%s Private-Key:\n', [indent, '', nm]) <= 0  then
            Exit(0);
        if BIO_printf(bp, '%*spriv:\n', [indent, '']) <= 0  then
            Exit(0);
        if ASN1_buf_print(bp, ecxkey.privkey, KEYLEN(pkey) ,
                           indent + 4) = 0 then
            Exit(0);
    end
    else
    begin
        if ecxkey = nil then begin
            if BIO_printf(bp, '%*s<INVALID PUBLIC KEY>'#10, [indent, '']) <= 0 then
                Exit(0);
            Exit(1);
        end;
        if BIO_printf(bp, '%*s%s Public-Key:'#10, [indent, '', nm]) <= 0  then
            Exit(0);
    end;
    if BIO_printf(bp, '%*spub:\n', [indent, '']) <= 0  then
        Exit(0);
    if ASN1_buf_print(bp, @ecxkey.pubkey, KEYLEN(pkey) ,
                       indent + 4) = 0  then
        Exit(0);
    Result := 1;
end;



function ecx_priv_decode_ex(pkey : PEVP_PKEY;const p8 : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;
  ecx : PECX_KEY;
begin
    ret := 0;
    ecx := ossl_ecx_key_from_pkcs8(p8, libctx, propq);
    if ecx <> nil then begin
        ret := 1;
        EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, ecx);
    end;
    Result := ret;
end;




function ecx_pkey_dirty_cnt(const pkey : PEVP_PKEY):size_t;
begin
    {
     * We provide no mechanism to 'update' an ECX key once it has been set,
     * therefore we do not have to maintain a dirty count.
     }
    Result := 1;
end;


function ecx_pkey_export_to(const from : PEVP_PKEY; to_keydata : Pointer; importer : TOSSL_FUNC_keymgmt_import_fn; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    key       : PECX_KEY;
    tmpl      : POSSL_PARAM_BLD;
    params    : POSSL_PARAM;
    selection,
    rv        : integer;
    label _err;
begin
     key := from.pkey.ecx;
    tmpl := OSSL_PARAM_BLD_new;
    params := nil;
    selection := 0;
    rv := 0;
    if tmpl = nil then Exit(0);
    { A key must at least have a public part }
    if 0>=OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                          @key.pubkey, key.keylen) then
        goto _err;
    selection  := selection  or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    if key.privkey <> nil then
    begin
        if (0>=OSSL_PARAM_BLD_push_octet_string(tmpl,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key.privkey, key.keylen)) then
            goto _err;
        selection  := selection  or OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    end;
    params := OSSL_PARAM_BLD_to_param(tmpl);
    { We export, the provider imports }
    rv := importer(to_keydata, selection, params);
 _err:
    OSSL_PARAM_BLD_free(tmpl);
    OSSL_PARAM_free(params);
    Result := rv;
end;


function ecx_generic_import_from(const params : POSSL_PARAM; vpctx : Pointer; keytype : integer):integer;
var
  pctx : PEVP_PKEY_CTX;
  pkey : PEVP_PKEY;
  ecx : PECX_KEY;
begin
    pctx := vpctx;
    pkey := EVP_PKEY_CTX_get0_pkey(pctx);
    ecx := ossl_ecx_key_new(pctx.libctx, KEYNID2TYPE(keytype), 0,
                                    pctx.propquery);
    if ecx = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if (0>=ossl_ecx_key_fromdata(ecx, params, 1))  or
       (0>=EVP_PKEY_assign(pkey, keytype, ecx)) then
    begin
        ossl_ecx_key_free(ecx);
        Exit(0);
    end;
    Result := 1;
end;


function ecx_pkey_copy( _to, from : PEVP_PKEY):integer;
var
  ecx, dupkey : PECX_KEY;

  ret : integer;
begin
    ecx := from.pkey.ecx; dupkey := nil;
    if ecx <> nil then
    begin
        dupkey := ossl_ecx_key_dup(ecx, OSSL_KEYMGMT_SELECT_ALL);
        if dupkey = nil then Exit(0);
    end;
    ret := EVP_PKEY_assign(_to, from.&type, dupkey);
    if 0>=ret then
       ossl_ecx_key_free(dupkey);
    Result := ret;
end;


function x25519_import_from(const params : POSSL_PARAM; vpctx : Pointer):integer;
begin
    Result := ecx_generic_import_from(params, vpctx, EVP_PKEY_X25519);
end;


function ecx_set_priv_key(pkey : PEVP_PKEY;const priv : PByte; len : size_t):integer;
var
  libctx : POSSL_LIB_CTX;
  ecx : PECX_KEY;
begin
    libctx := nil;
    ecx := nil;
    if pkey.keymgmt <> nil then
       libctx := ossl_provider_libctx(EVP_KEYMGMT_get0_provider(pkey.keymgmt));
    ecx := ossl_ecx_key_op(nil, priv, len, pkey.ameth.pkey_id,
                          KEY_OP_PRIVATE, libctx, nil);
    if ecx <> nil then
    begin
        EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, ecx);
        Exit(1);
    end;
    Result := 0;
end;


function ecx_set_pub_key(pkey : PEVP_PKEY;const pub : PByte; len : size_t):integer;
var
  libctx : POSSL_LIB_CTX;

  ecx : PECX_KEY;
begin
    libctx := nil;
    ecx := nil;
    if pkey.keymgmt <> nil then
       libctx := ossl_provider_libctx(EVP_KEYMGMT_get0_provider(pkey.keymgmt));
    ecx := ossl_ecx_key_op(nil, pub, len, pkey.ameth.pkey_id,
                          KEY_OP_PUBLIC, libctx, nil);
    if ecx <> nil then begin
        EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, ecx);
        Exit(1);
    end;
    Result := 0;
end;


function ecx_get_priv_key(const pkey : PEVP_PKEY; priv : PByte; len : Psize_t):integer;
var
  key : PECX_KEY;
begin
    key := pkey.pkey.ecx;
    if priv = nil then begin
        len^ := KEYLENID(pkey.ameth.pkey_id);
        Exit(1);
    end;
    if (key = nil)
             or  (key.privkey = nil)
             or  (len^ < size_t(KEYLENID(pkey.ameth.pkey_id))) then
        Exit(0);
    len^ := KEYLENID(pkey.ameth.pkey_id);
    memcpy(priv, key.privkey, len^);
    Result := 1;
end;


function ecx_get_pub_key(const pkey : PEVP_PKEY; pub : PByte; len : Psize_t):integer;
var
  key : PECX_KEY;
begin
    key := pkey.pkey.ecx;
    if pub = nil then begin
        len^ := KEYLENID(pkey.ameth.pkey_id);
        Exit(1);
    end;
    if (key = nil)
             or  (len^ < size_t(KEYLENID(pkey.ameth.pkey_id))) then
        Exit(0);
    len^ := KEYLENID(pkey.ameth.pkey_id);
    memcpy(pub, @key.pubkey, len^);
    Result := 1;
end;

function ecx_ctrl( pkey : PEVP_PKEY; op : integer; arg1 : long; arg2 : Pointer):integer;
var
  ecx : PECX_KEY;
  ppt : PPByte;
begin
    case op of
    ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
    begin
        ecx := ossl_ecx_key_op(nil, arg2, arg1, pkey.ameth.pkey_id,
                                       KEY_OP_PUBLIC, nil, nil);
        if ecx <> nil then begin
            EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, ecx);
            Exit(1);
        end;
        Exit(0);
    end;
    ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
    begin
        if pkey.pkey.ecx <> nil then
        begin
            ppt := arg2;
            ppt^ := OPENSSL_memdup(@pkey.pkey.ecx.pubkey, KEYLEN(pkey));
            if ppt^ <> nil then Exit(KEYLEN(pkey));
        end;
        Exit(0);
    end
    else
        Exit(-2);
    end;
end;





function ecx_cmp_parameters(const a, b : PEVP_PKEY):integer;
begin
    Result := 1;
end;





function ecx_size(const pkey : PEVP_PKEY):integer;
begin
    Result := KEYLEN(pkey);
end;


function ecx_bits(const pkey : PEVP_PKEY):integer;
begin
    if IS25519(pkey.ameth.pkey_id) then
    begin
        Exit(X25519_BITS);
    end
    else
    if (ISX448(pkey.ameth.pkey_id)) then
    begin
        Exit(X448_BITS);
    end
    else
    begin
        Exit(ED448_BITS);
    end;
end;


function ecx_security_bits(const pkey : PEVP_PKEY):integer;
begin
    if IS25519(pkey.ameth.pkey_id) then  begin
        Exit(X25519_SECURITY_BITS)
    end
    else begin
        Exit(X448_SECURITY_BITS);
    end;
end;


procedure ecx_free( pkey : PEVP_PKEY);
begin
    ossl_ecx_key_free(pkey.pkey.ecx);
end;

function ecx_priv_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := ecx_key_print(bp, pkey, indent, ctx, KEY_OP_PRIVATE);
end;

function ecx_priv_encode(p8 : PPKCS8_PRIV_KEY_INFO;const pkey : PEVP_PKEY):integer;
var
  ecxkey : PECX_KEY;
  oct : TASN1_OCTET_STRING;
  penc : PByte;
  penclen : integer;
begin
    ecxkey := pkey.pkey.ecx;
    penc := nil;
    if (ecxkey = nil)  or  (ecxkey.privkey = nil) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        Exit(0);
    end;
    oct.data := ecxkey.privkey;
    oct.length := KEYLEN(pkey);
    oct.flags := 0;
    penclen := i2d_ASN1_OCTET_STRING(@oct, @penc);
    if penclen < 0 then begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>=PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey.ameth.pkey_id), 0,
                         V_ASN1_UNDEF, nil, penc, penclen) then
    begin
        OPENSSL_clear_free(Pointer(penc), penclen);
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;




function ecx_pub_print(bp : PBIO;const pkey : PEVP_PKEY; indent : integer; ctx : PASN1_PCTX):integer;
begin
    Result := ecx_key_print(bp, pkey, indent, ctx, KEY_OP_PUBLIC);
end;

function ecx_pub_cmp(const a, b : PEVP_PKEY):integer;
var
  akey, bkey : PECX_KEY;
begin
    akey := a.pkey.ecx;
    bkey := b.pkey.ecx;
    if (akey = nil)  or  (bkey = nil) then
       Exit(-2);
    Result := Int(CRYPTO_memcmp(@akey.pubkey, @bkey.pubkey, KEYLEN(a)) = 0);
end;




function ecx_pub_encode(pk : PX509_PUBKEY;const pkey : PEVP_PKEY):integer;
var
  ecxkey : PECX_KEY;
  penc : PByte;
begin
    ecxkey := pkey.pkey.ecx;
    if ecxkey = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_KEY);
        Exit(0);
    end;
    penc := OPENSSL_memdup(@ecxkey.pubkey, KEYLEN(pkey));
    if penc = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>=X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey.ameth.pkey_id) ,
                                V_ASN1_UNDEF, nil, penc, KEYLEN(pkey)) then begin
        OPENSSL_free(penc);
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;



function ecx_pub_decode(pkey : PEVP_PKEY;const pubkey : PX509_PUBKEY):integer;
var
  p : PByte;
  pklen : integer;
  palg : PX509_ALGOR;
  ecx : PECX_KEY;
  ret : integer;
begin
    ret := 0;
    if 0>=X509_PUBKEY_get0_param(nil, @p, @pklen, @palg, pubkey) then
        Exit(0);
    ecx := ossl_ecx_key_op(palg, p, pklen, pkey.ameth.pkey_id,
                          KEY_OP_PUBLIC, nil, nil);
    if ecx <> nil then begin
        ret := 1;
        EVP_PKEY_assign(pkey, pkey.ameth.pkey_id, ecx);
    end;
    Result := ret;
end;



function pkey_ecd_digestverify448(ctx : PEVP_MD_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  edkey : PECX_KEY;
begin
    edkey := evp_pkey_get_legacy(EVP_MD_CTX_get_pkey_ctx(ctx).pkey);
    if siglen <> ED448_SIGSIZE then Exit(0);
    Exit(ossl_ed448_verify(edkey.libctx, tbs, tbslen, sig, @edkey.pubkey,
                             nil, 0, edkey.propq));
end;




function pkey_ecd_digestsign448(ctx : PEVP_MD_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  edkey : PECX_KEY;
begin
     edkey := evp_pkey_get_legacy(EVP_MD_CTX_get_pkey_ctx(ctx).pkey);
    if sig = nil then
    begin
        siglen^ := ED448_SIGSIZE;
        Exit(1);
    end;
    if siglen^ < ED448_SIGSIZE then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if ossl_ed448_sign(edkey.libctx, sig, tbs, tbslen, @edkey.pubkey,
                        edkey.privkey, nil, 0, edkey.propq) = 0  then
        Exit(0);
    siglen^ := ED448_SIGSIZE;
    Result := 1;
end;





function ossl_ed448_pkey_method:PEVP_PKEY_METHOD;
begin
{$IFDEF S390X_EC_ASM}
    if OPENSSL_s39$cap_P.pcc[1] and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_ED448 then  and  OPENSSL_s39$cap_P.kdsa[0] and S390X_CAPBIT(S390X_EDDSA_SIGN_ED448)
         and  OPENSSL_s39$cap_P.kdsa[0] and S390X_CAPBIT(S390X_EDDSA_VERIFY_ED448))
        Exit(&ed448_s390x_pkey_meth);
{$ENDIF}
    Result := @ed448_pkey_meth;
end;




function pkey_ecd_digestverify25519(ctx : PEVP_MD_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  edkey : PECX_KEY;
begin
   edkey := evp_pkey_get_legacy(EVP_MD_CTX_get_pkey_ctx(ctx).pkey);
    if siglen <> ED25519_SIGSIZE then Exit(0);
    Exit(ossl_ed25519_verify(tbs, tbslen, sig, @edkey.pubkey,
                               edkey.libctx, edkey.propq));
end;


function pkey_ecd_digestsign25519(ctx : PEVP_MD_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  edkey : PECX_KEY;
begin
    edkey := evp_pkey_get_legacy(EVP_MD_CTX_get_pkey_ctx(ctx).pkey);
    if sig = nil then
    begin
        siglen^ := ED25519_SIGSIZE;
        Exit(1);
    end;
    if siglen^ < ED25519_SIGSIZE then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if ossl_ed25519_sign(sig, tbs, tbslen, @edkey.pubkey, @edkey.privkey, nil,
                          nil) = 0  then
        Exit(0);
    siglen^ := ED25519_SIGSIZE;
    Result := 1;
end;




function pkey_ecd_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
begin
    case _type of
    EVP_PKEY_CTRL_MD:
    begin
        { Only nil allowed as digest }
        if (p2 = nil)  or  (PEVP_MD( p2) = EVP_md_null)  then
            Exit(1);
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_DIGEST_TYPE);
        Exit(0);
    end;
    EVP_PKEY_CTRL_DIGESTINIT:
        Exit(1);
    end;
    Result := -2;
end;




function ossl_ed25519_pkey_method:PEVP_PKEY_METHOD;
begin
{$IFDEF S390X_EC_ASM}
    if OPENSSL_s39$cap_P.pcc[1] and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_ED25519 then  and  OPENSSL_s39$cap_P.kdsa[0] and S390X_CAPBIT(S390X_EDDSA_SIGN_ED25519)
         and  OPENSSL_s39$cap_P.kdsa[0]
            and S390X_CAPBIT(S390X_EDDSA_VERIFY_ED25519))
        Exit(&ed25519_s390x_pkey_meth);
{$ENDIF}
    Result := @ed25519_pkey_meth;
end;




function pkey_ecx_derive448( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
var
  privkey, pubkey : PByte;
begin
    if (0>= validate_ecx_derive(ctx, key, keylen, @privkey, @pubkey)) or
      ( (key <> nil)  and  (ossl_x448(key, privkey, pubkey) = 0)) then
        Exit(0);
    keylen^ := X448_KEYLEN;
    Result := 1;
end;




function ossl_ecx448_pkey_method:PEVP_PKEY_METHOD;
begin
{$IFDEF S390X_EC_ASM}
    if OPENSSL_s39$cap_P.pcc[1] and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X448 then )
        Exit(&ecx448_s390x_pkey_meth);
{$ENDIF}
    Result := @ecx448_pkey_meth;
end;


function validate_ecx_derive(ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t;const privkey, pubkey : PPByte):integer;
var
  ecxkey, peerkey : PECX_KEY;
begin

    if (ctx.pkey = nil)  or  (ctx.peerkey = nil) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_KEYS_NOT_SET);
        Exit(0);
    end;
    ecxkey := evp_pkey_get_legacy(ctx.pkey);
    peerkey := evp_pkey_get_legacy(ctx.peerkey);
    if (ecxkey = nil)  or  (ecxkey.privkey = nil) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        Exit(0);
    end;
    if peerkey = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PEER_KEY);
        Exit(0);
    end;
    privkey^ := ecxkey.privkey;
    pubkey^  := @peerkey.pubkey;
    Result := 1;
end;



function pkey_ecx_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
begin
    { Only need to handle peer key for derivation }
    if _type = EVP_PKEY_CTRL_PEER_KEY then
       Exit(1);
    Result := -2;
end;



function pkey_ecx_derive25519( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):int;
var
  privkey, pubkey : PByte;
begin
    if (0>= validate_ecx_derive(ctx, key, keylen, @privkey, @pubkey)) or
       ( (key <> nil)  and  (ossl_x25519(key, privkey, pubkey) = 0))  then
        Exit(0);
    keylen^ := X25519_KEYLEN;
    Result := 1;
end;


function pkey_ecx_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  ecx : PECX_KEY;
begin
     ecx := ossl_ecx_key_op(nil, nil, 0, ctx.pmeth.pkey_id,
                                   KEY_OP_PUBLIC, nil, nil);
    if ecx <> nil then
    begin
        EVP_PKEY_assign(pkey, ctx.pmeth.pkey_id, ecx);
        Exit(1);
    end;
    Result := 0;
end;



function ossl_ecx25519_pkey_method:PEVP_PKEY_METHOD;
begin
{$IFDEF S390X_EC_ASM}
    if OPENSSL_s39$cap_P.pcc[1] and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X25519 then )
        Exit(&ecx25519_s390x_pkey_meth);
{$ENDIF}
    Result := @ecx25519_pkey_meth;
end;


end.
