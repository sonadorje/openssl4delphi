unit openssl3.crypto.self_test_kats;

interface
 uses OpenSSL.Api, SysUtils, openssl3.crypto.self_test_data;

 const
dgst : array[0..31] of byte = (
    $7f, $83, $b1, $65, $7f, $f1, $fc, $53, $b9, $2d, $c1, $81, $48, $a1,
    $d6, $5d, $fc, $2d, $4b, $1f, $a3, $d6, $77, $28, $4a, $dd, $d2, $00,
    $12, $6d, $90, $69 );

function SELF_TEST_kats( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_digests( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_ciphers( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_asym_ciphers( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_kdfs( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_drbgs( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_kas( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_signatures( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;

function self_test_digest( t : PST_KAT_DIGEST; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_cipher(t : PST_KAT_CIPHER; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function cipher_init(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; t : PST_KAT_CIPHER; enc : integer):integer;
function self_test_asym_cipher(const t : PST_KAT_ASYM_CIPHER; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function add_params(bld : POSSL_PARAM_BLD;params : PST_KAT_PARAM; ctx : PBN_CTX):integer;
function self_test_kdf(const t : PST_KAT_KDF; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_drbg(t : PST_KAT_DRBG; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
function self_test_ka(const t : PST_KAT_KAS; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;


function self_test_sign(const t : PST_KAT_SIGN; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;

implementation

uses openssl3.crypto.evp.digest,        openssl3.crypto.self_test_core,
     openssl3.crypto.bn.bn_ctx,         openssl3.crypto.param_build,
     openssl3.crypto.bn.bn_lib,         openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.evp.pmeth_gn,      openssl3.crypto.evp,
     openssl3.crypto.evp.asymcipher,    openssl3.crypto.evp.p_lib,
     openssl3.crypto.params_dup,        openssl3.crypto.evp.kdf_meth,
     openssl3.crypto.evp.kdf_lib,       openssl3.crypto.params,
     openssl3.crypto.evp.signature,
     openssl3.crypto.evp.evp_rand,      openssl3.crypto.evp.exchange,
     openssl3.crypto.evp.evp_enc,       openssl3.crypto.evp.evp_lib;





function self_test_sign(const t : PST_KAT_SIGN; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret        : integer;
  params,
  params_sig : POSSL_PARAM;
  bld        : POSSL_PARAM_BLD;
  sctx,kctx  : PEVP_PKEY_CTX;
  pkey       : PEVP_PKEY;
  sig        : array[0..255] of Byte;
  bnctx      : PBN_CTX;
  siglen     : size_t;
  typ        : PUTF8Char;
  label _err ;
begin
    ret := 0;
    params := nil;
    params_sig := nil;
    bld := nil;
    sctx := nil; kctx := nil;
    pkey := nil;
    bnctx := nil;
    siglen := sizeof(sig);
    typ := OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;
    if t.sig_expected = nil then
       typ := OSSL_SELF_TEST_TYPE_PCT_SIGNATURE;
    OSSL_SELF_TEST_onbegin(st, typ, t.desc);
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then goto _err;
    bld := OSSL_PARAM_BLD_new;
    if bld = nil then goto _err;
    if 0>=add_params(bld, t.key, bnctx) then
        goto _err;
    params := OSSL_PARAM_BLD_to_param(bld);
    { Create a EVP_PKEY_CTX to load the DSA key into }
    kctx := EVP_PKEY_CTX_new_from_name(libctx, t.algorithm, '');
    if (kctx = nil)  or  (params = nil) then goto _err;
    if (EVP_PKEY_fromdata_init(kctx) <= 0)
         or  (EVP_PKEY_fromdata(kctx, @pkey, EVP_PKEY_KEYPAIR, params) <= 0) then
        goto _err;
    { Create a EVP_PKEY_CTX to use for the signing operation }
    sctx := EVP_PKEY_CTX_new_from_pkey(libctx, pkey, nil);
    if (sctx = nil) or (EVP_PKEY_sign_init(sctx) <= 0)  then
        goto _err;
    { set signature parameters }
    if 0>=OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_SIGNATURE_PARAM_DIGEST,
                                         t.mdalgorithm,
                                         Length(t.mdalgorithm) + 1) then
        goto _err;
    params_sig := OSSL_PARAM_BLD_to_param(bld);
    if EVP_PKEY_CTX_set_params(sctx, params_sig) <= 0 then
        goto _err;
    if (EVP_PKEY_sign(sctx, @sig, @siglen, @dgst, sizeof(dgst)) <= 0)
         or  (EVP_PKEY_verify_init(sctx) <= 0 )
         or  (EVP_PKEY_CTX_set_params(sctx, params_sig) <= 0)  then
        goto _err;
    {
     * Used by RSA, for other key types where the signature changes, we
     * can only use the verify.
     }
    if (t.sig_expected <> nil)
         and ( (siglen <> t.sig_expected_len)
             or (memcmp(@sig, t.sig_expected, t.sig_expected_len) <> 0)) then
        goto _err;
    OSSL_SELF_TEST_oncorrupt_byte(st, @sig);
    if EVP_PKEY_verify(sctx, @sig, siglen, @dgst, sizeof(dgst)) <= 0  then
        goto _err;
    ret := 1;
_err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_free(params_sig);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    Result := ret;
end;


function self_test_ka(const t : PST_KAT_KAS; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
    ret         : integer;
    kactx,
    dctx        : PEVP_PKEY_CTX;
    pkey        : PEVP_PKEY;
    peerkey     : PEVP_PKEY;
    params,
    params_peer : POSSL_PARAM;
    secret      : array[0..255] of Byte;
    secret_len  : size_t;
    bld         : POSSL_PARAM_BLD;
    bnctx       : PBN_CTX;
    label _err;
begin
    ret := 0;
    kactx := nil;
    dctx := nil;
    pkey := nil;
    peerkey := nil;
    params := nil;
    params_peer := nil;
    secret_len := sizeof(secret);
    bld := nil;
    bnctx := nil;
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KA, t.desc);
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then goto _err;
    bld := OSSL_PARAM_BLD_new;
    if bld = nil then goto _err;
    if (0>=add_params(bld, t.key_group, bnctx))  or
       (0>=add_params(bld, t.key_host_data, bnctx)) then
        goto _err;
    params := OSSL_PARAM_BLD_to_param(bld);
    if (0>=add_params(bld, t.key_group, bnctx))  or
       (0>=add_params(bld, t.key_peer_data, bnctx)) then
        goto _err;
    params_peer := OSSL_PARAM_BLD_to_param(bld);
    if (params = nil)  or  (params_peer = nil) then
       goto _err;
    { Create a EVP_PKEY_CTX to load the DH keys into }
    kactx := EVP_PKEY_CTX_new_from_name(libctx, t.algorithm, '');
    if kactx = nil then goto _err;
    if (EVP_PKEY_fromdata_init(kactx) <= 0 )
         or  (EVP_PKEY_fromdata(kactx, @pkey, EVP_PKEY_KEYPAIR, params) <= 0) then
        goto _err;
    if (EVP_PKEY_fromdata_init(kactx) <= 0 )
         or  (EVP_PKEY_fromdata(kactx, @peerkey, EVP_PKEY_KEYPAIR, params_peer) <= 0) then
        goto _err;
    { Create a EVP_PKEY_CTX to perform key derivation }
    dctx := EVP_PKEY_CTX_new_from_pkey(libctx, pkey, nil);
    if dctx = nil then goto _err;
    if (EVP_PKEY_derive_init(dctx) <= 0)
         or  (EVP_PKEY_derive_set_peer(dctx, peerkey) <= 0 )
         or  (EVP_PKEY_derive(dctx, @secret, @secret_len) <= 0) then
        goto _err;
    OSSL_SELF_TEST_oncorrupt_byte(st, @secret);
    if (secret_len <> t.expected_len)
         or  (memcmp(@secret, t.expected, t.expected_len) <> 0)  then
        goto _err;
    ret := 1;
_err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(kactx);
    EVP_PKEY_CTX_free(dctx);
    OSSL_PARAM_free(params_peer);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    Result := ret;
end;



function self_test_drbg(t : PST_KAT_DRBG; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret                   : integer;
  _out                  : array[0..255] of Byte;
  rand                  : PEVP_RAND;
  test,
  drbg                  : PEVP_RAND_CTX;
  strength              : uint32;
  prediction_resistance : integer;
  drbg_params           : array of TOSSL_PARAM;
  label _err;
begin
    ret := 0;
    test := nil;
    drbg := nil;
    strength := 256;
    prediction_resistance := 1;
    drbg_params := [OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END];

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_DRBG, t.desc);
    rand := EVP_RAND_fetch(libctx, 'TEST-RAND', nil);
    if rand = nil then goto _err;
    test := EVP_RAND_CTX_new(rand, nil);
    EVP_RAND_free(rand);
    if test = nil then goto _err;
    drbg_params[0] := OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
                                               @strength);
    if 0>=EVP_RAND_CTX_set_params(test, @drbg_params) then
        goto _err;
    rand := EVP_RAND_fetch(libctx, t.algorithm, nil);
    if rand = nil then goto _err;
    drbg := EVP_RAND_CTX_new(rand, test);
    EVP_RAND_free(rand);
    if drbg = nil then goto _err;
    strength := EVP_RAND_get_strength(drbg);
    drbg_params[0] := OSSL_PARAM_construct_utf8_string(t.param_name,
                                                      t.param_value, 0);
    { This is only used by HMAC-DRBG but it is ignored by the others }
    drbg_params[1] := OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, 'HMAC', 0);
    if 0>=EVP_RAND_CTX_set_params(drbg, @drbg_params )then
        goto _err;
    drbg_params[0] := OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                          Pointer(t.entropyin),
                                          t.entropyinlen);
    drbg_params[1] := OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE,
                                          Pointer(t.nonce), t.noncelen);
    if 0>=EVP_RAND_instantiate(test, strength, 0, nil, 0, @drbg_params ) then
        goto _err;
    if 0>=EVP_RAND_instantiate(drbg, strength, 0, t.persstr, t.persstrlen, nil) then
        goto _err;
    drbg_params[0] := OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                          Pointer(t.entropyinpr1),
                                          t.entropyinpr1len);
    if 0>=EVP_RAND_CTX_set_params(test, @drbg_params) then
        goto _err;
    if 0>=EVP_RAND_generate(drbg, @_out, t.expectedlen, strength,
                           prediction_resistance,
                           t.entropyaddin1, t.entropyaddin1len) then
        goto _err;
    drbg_params[0] := OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                         Pointer(t.entropyinpr2),
                                         t.entropyinpr2len);
    if 0>=EVP_RAND_CTX_set_params(test, @drbg_params) then
        goto _err;
    {
     * This calls ossl_prov_drbg_reseed internally when
     * prediction_resistance = 1
     }
    if 0>=EVP_RAND_generate(drbg, @_out, t.expectedlen, strength,
                           prediction_resistance,
                           t.entropyaddin2, t.entropyaddin2len) then
        goto _err;
    OSSL_SELF_TEST_oncorrupt_byte(st, @_out);
    if memcmp(@_out, t.expected, t.expectedlen) <> 0  then
        goto _err;
    if 0>=EVP_RAND_uninstantiate(drbg) then
        goto _err;
    {
     * Check that the DRBG data has been zeroized after
     * ossl_prov_drbg_uninstantiate.
     }
    if 0>=EVP_RAND_verify_zeroization(drbg) then
        goto _err;
    ret := 1;
_err:
    EVP_RAND_CTX_free(drbg);
    EVP_RAND_CTX_free(test);
    OSSL_SELF_TEST_onend(st, ret);
    Result := ret;
end;



function self_test_kdf(const t : PST_KAT_KDF; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret : integer;
  _out : array[0..127] of Byte;
  kdf : PEVP_KDF;
  ctx : PEVP_KDF_CTX;
  bnctx : PBN_CTX;
  params : POSSL_PARAM;
  bld : POSSL_PARAM_BLD;
  label _err;
begin
    ret := 0;
    kdf := nil;
    ctx := nil;
    bnctx := nil;
    params := nil;
    bld := nil;
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KDF, t.desc);
    bld := OSSL_PARAM_BLD_new;
    if bld = nil then goto _err;
    kdf := EVP_KDF_fetch(libctx, t.algorithm, '');
    if kdf = nil then goto _err;
    ctx := EVP_KDF_CTX_new(kdf);
    if ctx = nil then goto _err;
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then goto _err;
    if 0>=add_params(bld, t.params, bnctx )then
        goto _err;
    params := OSSL_PARAM_BLD_to_param(bld);
    if params = nil then goto _err;
    if t.expected_len > sizeof(_out) then
        goto _err;
    if EVP_KDF_derive(ctx, @_out, t.expected_len, params) <= 0  then
        goto _err;
    OSSL_SELF_TEST_oncorrupt_byte(st, @_out);
    if memcmp(@_out, t.expected,  t.expected_len) <> 0  then
        goto _err;
    ret := 1;
_err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    BN_CTX_free(bnctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    Result := ret;
end;


function add_params(bld : POSSL_PARAM_BLD; params : PST_KAT_PARAM; ctx : PBN_CTX):integer;
var
  ret : integer;
  p : PST_KAT_PARAM;
  bn : PBIGNUM;
  label _err ;
begin
    ret := 0;
    if params = nil then Exit(1);
    p := params;
    while p.data <> nil do
    begin
        case p.&type of
            OSSL_PARAM_UNSIGNED_INTEGER:
            begin
                bn := BN_CTX_get(ctx);
                if (bn = nil)
                     or  (BN_bin2bn(p.data, p.data_len, bn) = nil)
                     or  (0>=OSSL_PARAM_BLD_push_BN(bld, p.name, bn))  then
                    goto _err;
                //break;
            end;
            OSSL_PARAM_UTF8_STRING:
            begin
                if 0>=OSSL_PARAM_BLD_push_utf8_string(bld, p.name, p.data,
                                                     p.data_len) then
                    goto _err;
                //break;
            end;
            OSSL_PARAM_OCTET_STRING:
            begin
                if 0>=OSSL_PARAM_BLD_push_octet_string(bld, p.name, p.data,
                                                      p.data_len) then
                    goto _err;
                //break;
            end;
            OSSL_PARAM_INTEGER:
            begin
                if 0>=OSSL_PARAM_BLD_push_int(bld, p.name, PInteger(p.data)^) then
                    goto _err;
                //break;
            end;
            else
            begin
               //break;
            end;

        end;
        Inc(p);
    end;
    ret := 1;
_err:
    Result := ret;
end;

function self_test_asym_cipher(const t : PST_KAT_ASYM_CIPHER; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret        : integer;
  keyparams,
  initparams : POSSL_PARAM;
  keybld     : POSSL_PARAM_BLD;
  initbld    : POSSL_PARAM_BLD;
  encctx     : PEVP_PKEY_CTX;
  keyctx     : PEVP_PKEY_CTX;
  key        : PEVP_PKEY;
  bnctx      : PBN_CTX;
  _out       : array[0..255] of Byte;
  outlen     : size_t;
  label _err;
begin
    ret := 0;
    keyparams := nil;
    initparams := nil;
    keybld := nil;
    initbld := nil;
    encctx := nil;
    keyctx := nil;
    key := nil;
    bnctx := nil;
    outlen := sizeof(_out);
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_ASYM_CIPHER, t.desc);
    bnctx := BN_CTX_new_ex(libctx);
    if bnctx = nil then goto _err;
    { Load a public or private key from data }
    keybld := OSSL_PARAM_BLD_new;
    if (keybld = nil)
         or  (0>=add_params(keybld, t.key, bnctx)) then
        goto _err;
    keyparams := OSSL_PARAM_BLD_to_param(keybld);
    keyctx := EVP_PKEY_CTX_new_from_name(libctx, t.algorithm, nil);
    if (keyctx = nil)  or  (keyparams = nil) then goto _err;
    if (EVP_PKEY_fromdata_init(keyctx) <= 0)
         or  (EVP_PKEY_fromdata(keyctx, @key, EVP_PKEY_KEYPAIR, keyparams) <= 0)  then
        goto _err;
    { Create a EVP_PKEY_CTX to use for the encrypt or decrypt operation }
    encctx := EVP_PKEY_CTX_new_from_pkey(libctx, key, nil);
    if (encctx = nil)
         or ( (t.encrypt > 0)  and  (EVP_PKEY_encrypt_init(encctx) <= 0) )
         or ( (0>=t.encrypt ) and  (EVP_PKEY_decrypt_init(encctx) <= 0) )  then
        goto _err;
    { Add any additional parameters such as padding }
    if t.postinit <> nil then
    begin
        initbld := OSSL_PARAM_BLD_new;
        if initbld = nil then goto _err;
        if 0>=add_params(initbld, t.postinit, bnctx )then
            goto _err;
        initparams := OSSL_PARAM_BLD_to_param(initbld);
        if initparams = nil then goto _err;
        if EVP_PKEY_CTX_set_params(encctx, initparams) <= 0 then
            goto _err;
    end;
    if t.encrypt > 0 then
    begin
        if (EVP_PKEY_encrypt(encctx, @_out, @outlen,
                             t._in, t.in_len) <= 0) then
            goto _err;
    end
    else
    begin
        if EVP_PKEY_decrypt(encctx, @_out, @outlen,
                             t._in, t.in_len) <= 0 then
            goto _err;
    end;
    { Check the KAT }
    OSSL_SELF_TEST_oncorrupt_byte(st, @_out);
    if (outlen <> t.expected_len )
         or  (memcmp(@_out, t.expected, t.expected_len) <> 0)  then
        goto _err;
    ret := 1;
_err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(encctx);
    EVP_PKEY_CTX_free(keyctx);
    OSSL_PARAM_free(keyparams);
    OSSL_PARAM_BLD_free(keybld);
    OSSL_PARAM_free(initparams);
    OSSL_PARAM_BLD_free(initbld);
    OSSL_SELF_TEST_onend(st, ret);
    Result := ret;
end;

function cipher_init(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; t : PST_KAT_CIPHER; enc : integer):integer;
var
  in_tag : PByte;

  pad, tmp : integer;
begin
    in_tag := nil;
    pad := 0;
    { Flag required for Key wrapping }
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if t.tag = nil then begin
        { Use a normal cipher init }
        Exit( Int( (EVP_CipherInit_ex(ctx, cipher, nil, t.key, t.iv, enc) > 0)
                and  (EVP_CIPHER_CTX_set_padding(ctx, pad) > 0) ));
    end;
    { The authenticated cipher init }
    if 0>=enc then in_tag := PByte(t.tag);
    Result := Int( (EVP_CipherInit_ex(ctx, cipher, nil, nil, nil, enc) > 0)
            and  (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, t.iv_len, nil) > 0)
            and ( (in_tag = nil)
                or  (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, t.tag_len,
                                      in_tag) > 0) )
            and  (EVP_CipherInit_ex(ctx, nil, nil, t.key, t.iv, enc) > 0)
            and  (EVP_CIPHER_CTX_set_padding(ctx, pad) > 0)
            and  (EVP_CipherUpdate(ctx, nil, @tmp, t.aad, t.aad_len) > 0) );
end;




function self_test_cipher(t : PST_KAT_CIPHER; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret, encrypt, len, ct_len, pt_len : integer;
  ctx : PEVP_CIPHER_CTX;
  cipher : PEVP_CIPHER;
  ct_buf, pt_buf : array[0..255] of Byte;
  tag : array[0..15] of Byte;
  label _err ;
begin
    ret := 0;
    encrypt := 1;
    len := 0;
    ct_len := 0;
    pt_len := 0;
    ctx := nil;
    cipher := nil;
    FillChar(ct_buf, 256, 0);
    FillChar(pt_buf, 256, 0);

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_CIPHER, t.base.desc);
    ctx := EVP_CIPHER_CTX_new;
    if ctx = nil then goto _err;
    cipher := EVP_CIPHER_fetch(libctx, t.base.algorithm, nil);
    if cipher = nil then goto _err;
    { Encrypt plain text message }
    if t.mode and CIPHER_MODE_ENCRYPT <> 0 then
    begin
        if (0>=cipher_init(ctx, cipher, t, encrypt))
                 or  (0>=EVP_CipherUpdate(ctx, @ct_buf, @len, t.base.pt,
                                     t.base.pt_len))
                 or  (0>=EVP_CipherFinal_ex(ctx, PByte(@ct_buf) + len, @ct_len)) then
            goto _err;
        OSSL_SELF_TEST_oncorrupt_byte(st, @ct_buf);
        ct_len  := ct_len + len;
        if (ct_len <> int(t.base.expected_len) )
             or  (memcmp(t.base.expected, @ct_buf, ct_len) <> 0)  then
            goto _err;
        if t.tag <> nil then
        begin
            FillChar(tag, 16, 0);
            if (0>=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, t.tag_len,
                                     @tag))   or  (memcmp(@tag, t.tag, t.tag_len) <> 0) then
                goto _err;
        end;
    end;
    { Decrypt cipher text }
    if t.mode and CIPHER_MODE_DECRYPT  <> 0 then
    begin
        if (0>=cipher_init(ctx, cipher, t,  not encrypt))
               and  (EVP_CipherUpdate(ctx, @pt_buf, @len,
                                  t.base.expected, t.base.expected_len) > 0)
               and  (EVP_CipherFinal_ex(ctx, Pbyte(@pt_buf) + len, @pt_len)>0) then
            goto _err;
        OSSL_SELF_TEST_oncorrupt_byte(st, @pt_buf);
        pt_len  := pt_len + len;
        if (pt_len <> int(t.base.pt_len))
                 or  (memcmp(@pt_buf, t.base.pt, pt_len) <> 0)  then
            goto _err;
    end;
    ret := 1;
_err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ret);
    Result := ret;
end;


function self_test_digest( t : PST_KAT_DIGEST; st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ok : integer;
  _out : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  out_len : uint32;
  ctx : PEVP_MD_CTX;
  md : PEVP_MD;
  label _err;
begin
    ok := 0;
    out_len := 0;
    ctx := EVP_MD_CTX_new;
    md := EVP_MD_fetch(libctx, t.algorithm, nil);
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_DIGEST, t.desc);
    if (ctx = nil)
             or  (md = nil)
             or  (0>=EVP_DigestInit_ex(ctx, md, nil))
             or  (0>=EVP_DigestUpdate(ctx, t.pt, t.pt_len))
             or  (0>=EVP_DigestFinal(ctx, @_out, @out_len)) then
        goto _err;
    { Optional corruption }
    OSSL_SELF_TEST_oncorrupt_byte(st, @_out);
    if (out_len <> t.expected_len)
             or  (memcmp(@_out, t.expected, out_len) <> 0) then
        goto _err;
    ok := 1;
_err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ok);
    Result := ok;
end;

function self_test_digests( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  i, ret : integer;
begin
    ret := 1;
    for i := 0 to Length(st_kat_digest_tests)-1 do
    begin
        if 0>=self_test_digest(@st_kat_digest_tests[i], st, libctx) then
            ret := 0;
    end;
    Result := ret;
end;


function self_test_ciphers( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  i, ret : integer;
begin
    ret := 1;
    for i := 0 to Length(st_kat_cipher_tests)-1 do
    begin
        if 0>=self_test_cipher(@st_kat_cipher_tests[i], st, libctx) then
            ret := 0;
    end;
    Result := ret;
end;


function self_test_asym_ciphers( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  i, ret : integer;
begin
    ret := 1;
    for i := 0 to Length(st_kat_asym_cipher_tests) - 1 do
    begin
        if 0>=self_test_asym_cipher(@st_kat_asym_cipher_tests[i], st, libctx) then
            ret := 0;
    end;
    Result := ret;
end;


function self_test_kdfs( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  i, ret : integer;
begin
    ret := 1;
    for i := 0 to Length(st_kat_kdf_tests) -1 do
    begin
        if 0>=self_test_kdf(@st_kat_kdf_tests[i], st, libctx) then
            ret := 0;
    end;
    Result := ret;
end;


function self_test_drbgs( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  i, ret : integer;
begin
    ret := 1;
    for i := 0 to Length(st_kat_drbg_tests) -1 do
    begin
        if 0>=self_test_drbg(@st_kat_drbg_tests[i], st, libctx) then
            ret := 0;
    end;
    Result := ret;
end;


function self_test_kas( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret, i : integer;
begin
    ret := 1;
{$IF not defined(OPENSSL_NO_DH)  or  not defined(OPENSSL_NO_EC)}
    for i := 0 to Length(st_kat_kas_tests)-1 do
    begin
        if 0>=self_test_ka(@st_kat_kas_tests[i], st, libctx) then
            ret := 0;
    end;
{$ENDIF}
    Result := ret;
end;


function self_test_signatures( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  i, ret : integer;
begin
    ret := 1;
    for i := 0 to Length(st_kat_sign_tests)-1 do
    begin
        if 0>=self_test_sign(@st_kat_sign_tests[i], st, libctx) then
            ret := 0;
    end;
    Result := ret;
end;


function SELF_TEST_kats( st : POSSL_SELF_TEST; libctx : POSSL_LIB_CTX):integer;
var
  ret : integer;
begin
    ret := 1;
    if 0>=self_test_digests(st, libctx) then
        ret := 0;
    if 0>=self_test_ciphers(st, libctx ) then
        ret := 0;
    if 0>=self_test_signatures(st, libctx ) then
        ret := 0;
    if 0>=self_test_kdfs(st, libctx ) then
        ret := 0;
    if 0>=self_test_drbgs(st, libctx ) then
        ret := 0;
    if 0>=self_test_kas(st, libctx ) then
        ret := 0;
    if 0>=self_test_asym_ciphers(st, libctx ) then
        ret := 0;
    Result := ret;
end;


end.
