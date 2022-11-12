unit openssl3.crypto.evp.p5_crpt2;

interface
uses OpenSSL.Api;

function ossl_pkcs5_pbkdf2_hmac_ex(pass : PUTF8Char; passlen : integer;salt : PByte; saltlen, iter : integer;const digest : PEVP_MD; keylen : integer; _out : PByte; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function PKCS5_v2_PBE_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function PKCS5_v2_PBE_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER; const md : PEVP_MD; en_de : integer):integer;
function PKCS5_v2_PBKDF2_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER; const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function PKCS5_v2_PBKDF2_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER; const md : PEVP_MD; en_de : integer):integer;
function PKCS5_PBKDF2_HMAC_SHA1(const pass : PUTF8Char; passlen : integer;const salt : PByte; saltlen, iter, keylen : integer; _out : PByte):integer;

implementation
uses
   openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.kdf_meth,
   openssl3.crypto.evp.kdf_lib, openssl3.crypto.params,
   OpenSSL3.Err,                  openssl3.crypto.evp.evp_pbe,
   openssl3.crypto.evp.digest,    openssl3.crypto.asn1.a_type,
   OpenSSL3.common,               openssl3.crypto.asn1.p5_pbev2,
   openssl3.crypto.evp.evp_enc,   openssl3.crypto.evp.names,
   openssl3.crypto.asn1.a_int,    openssl3.crypto.mem,
   openssl3.crypto.objects.obj_dat, openssl3.providers.fips.fipsprov,
   openssl3.crypto.bio.bio_print, openssl3.crypto.bio.bio_dump;


function PKCS5_PBKDF2_HMAC_SHA1(const pass : PUTF8Char; passlen : integer;const salt : PByte; saltlen, iter, keylen : integer; _out : PByte):integer;
var
  digest : PEVP_MD;
begin
    Result := 0;
    digest := EVP_MD_fetch(nil, SN_sha1, nil);
    if digest <> nil then
        Result := ossl_pkcs5_pbkdf2_hmac_ex(pass, passlen, salt, saltlen, iter,
                                      digest, keylen, _out, nil, nil);
    EVP_MD_free(digest);

end;



function PKCS5_v2_PBE_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER; const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    pbe2         : PPBE2PARAM;

    ciph_name    : array[0..79] of UTF8Char;

  cipher,
  cipher_fetch : PEVP_CIPHER;

    kdf          : TEVP_PBE_KEYGEN_EX;

    rv           : integer;
    label _err;
begin
    pbe2 := nil;
    cipher := nil;
    cipher_fetch := nil;
    rv := 0;
    pbe2 := ASN1_TYPE_unpack_sequence(PBE2PARAM_it, param);
    if pbe2 = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto _err ;
    end;
    { See if we recognise the key derivation function }
    if 0>= EVP_PBE_find_ex(EVP_PBE_TYPE_KDF, OBJ_obj2nid(pbe2.keyfunc.algorithm) ,
                         nil, nil, nil, @kdf)  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        goto _err ;
    end;
    {
     * lets see if we recognise the encryption algorithm.
     }
    if OBJ_obj2txt(@ciph_name, sizeof(ciph_name) , pbe2.encryption.algorithm, 0) <= 0  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
        goto _err ;
    end;
    ERR_set_mark();
    cipher_fetch := EVP_CIPHER_fetch(libctx, ciph_name, propq);
    cipher := cipher_fetch;
    { Fallback to legacy method }
    if (cipher = nil) then
       cipher := EVP_get_cipherbyname(ciph_name);
    if cipher = nil then
    begin
        ERR_clear_last_mark();
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
        goto _err ;
    end;
    ERR_pop_to_mark();
    { Fixup cipher based on AlgorithmIdentifier }
    if 0>= EVP_CipherInit_ex(ctx, cipher, nil, nil, nil, en_de) then
        goto _err ;
    if EVP_CIPHER_asn1_to_param(ctx, pbe2.encryption.parameter) < 0  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
        goto _err ;
    end;
    rv := kdf(ctx, pass, passlen, pbe2.keyfunc.parameter, nil, nil, en_de, libctx, propq);
 _err:
    EVP_CIPHER_free(cipher_fetch);
    PBE2PARAM_free(pbe2);
    Result := rv;
end;


function PKCS5_v2_PBE_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
begin
    Result := PKCS5_v2_PBE_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de, nil, nil);
end;


function PKCS5_v2_PBKDF2_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  saltlen,
  iter,
  t,
  rv          : integer;
  key         : array[0..EVP_MAX_KEY_LENGTH-1] of Byte;
  keylen      : uint32;
  prf_nid,
  hmac_md_nid : integer;
  kdf         : PPBKDF2PARAM;
  salt        : PByte;
  prfmd,
  prfmd_fetch : PEVP_MD;
  label _err;
begin

    rv := 0;
    keylen := 0;
    kdf := nil;
    prfmd := nil;
    prfmd_fetch := nil;
    if EVP_CIPHER_CTX_get0_cipher(ctx) = nil  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        goto _err ;
    end;
    keylen := EVP_CIPHER_CTX_get_key_length(ctx);
    assert(keylen <= sizeof(key));
    { Decode parameter }
    kdf := ASN1_TYPE_unpack_sequence(PBKDF2PARAM_it, param);
    if kdf = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto _err ;
    end;
    t := EVP_CIPHER_CTX_get_key_length(ctx);
    if t < 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
        goto _err ;
    end;
    keylen := t;
    { Now check the parameters of the kdf }
    if (kdf.keylength <> nil ) and  (ASN1_INTEGER_get(kdf.keylength) <> int( keylen))  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH);
        goto _err ;
    end;
    if kdf.prf <> nil then
        prf_nid := OBJ_obj2nid(kdf.prf.algorithm)
    else
        prf_nid := NID_hmacWithSHA1;
    if 0>= EVP_PBE_find(EVP_PBE_TYPE_PRF, prf_nid, nil, @hmac_md_nid, 0) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF);
        goto _err ;
    end;
    prfmd_fetch := EVP_MD_fetch(libctx, OBJ_nid2sn(hmac_md_nid), propq);
    prfmd := prfmd_fetch;
    if prfmd = nil then
       prfmd := EVP_get_digestbynid(hmac_md_nid);
    if prfmd = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF);
        goto _err ;
    end;
    if kdf.salt._type <> V_ASN1_OCTET_STRING then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_SALT_TYPE);
        goto _err ;
    end;
    { it seems that its all OK }
    salt := kdf.salt.value.octet_string.data;
    saltlen := kdf.salt.value.octet_string.length;
    iter := ASN1_INTEGER_get(kdf.iter);
    if 0>= ossl_pkcs5_pbkdf2_hmac_ex(pass, passlen, salt, saltlen, iter, prfmd,
                                   keylen, @key, libctx, propq) then
        goto _err ;
    rv := EVP_CipherInit_ex(ctx, nil, nil, @key, nil, en_de);
 _err:
    OPENSSL_cleanse(@key, keylen);
    PBKDF2PARAM_free(kdf);
    EVP_MD_free(prfmd_fetch);
    Result := rv;
end;


function PKCS5_v2_PBKDF2_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const c : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
begin
    Exit(PKCS5_v2_PBKDF2_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de,
                                       nil, nil));
end;

function ossl_pkcs5_pbkdf2_hmac_ex(pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, iter : integer;const digest : PEVP_MD; keylen : integer; _out : PByte; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  empty : PUTF8Char;
  rv ,mode: integer;
  kdf : PEVP_KDF;
  kctx : PEVP_KDF_CTX;
  mdname : PUTF8Char;
  params : array[0..5] of TOSSL_PARAM;
  trc_out: PBIO;
  p : POSSL_PARAM;
begin
    empty := '';
    rv := 1; mode := 1;
    mdname := EVP_MD_get0_name(digest);

    { Keep documented behaviour. }
    if pass = nil then
    begin
        pass := empty;
        passlen := 0;
    end
    else
    if (passlen = -1) then
    begin
        passlen := Length(pass);
    end;
    if (salt = nil)  and  (saltlen = 0) then
       salt := PByte (empty);
    kdf := EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, propq);
    kctx := EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if kctx = nil then Exit(0);
    params[0] := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, pass, size_t(passlen));
    params[1] := OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, @mode);
    params[2] := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, saltlen);
    params[3] := OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, @iter);
    params[4] := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdname, 0);
    params[5] := OSSL_PARAM_construct_end();
    p := @params;
    if EVP_KDF_derive(kctx, _out, keylen, p) <> 1   then
        rv := 0;
    EVP_KDF_CTX_free(kctx);
    //OSSL_TRACE_BEGIN(PKCS5V2)
    begin
        trc_out := nil;
        BIO_printf(trc_out, 'Password:'#10, []);
        BIO_hex_string(trc_out, 0, passlen, pass, passlen);
        BIO_printf(trc_out, ''#10,[]);
        BIO_printf(trc_out, 'Salt:'#10, []);
        BIO_hex_string(trc_out, 0, saltlen, salt, saltlen);
        BIO_printf(trc_out, ''#10, []);
        BIO_printf(trc_out, 'Iteration count %d'#10, [iter]);
        BIO_printf(trc_out, 'Key:'#10,[]);
        BIO_hex_string(trc_out, 0, keylen, _out, keylen);
        BIO_printf(trc_out, ''#10, []);
    end;
 //OSSL_TRACE_END(PKCS5V2);
    Result := rv;
end;


end.
