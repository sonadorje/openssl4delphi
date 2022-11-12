unit openssl3.crypto.evp.p5_crpt;

interface
uses OpenSSL.Api, SysUtils;

 function PKCS5_PBE_keyivgen(cctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER; const md : PEVP_MD; en_de : integer):integer;
 function PKCS5_PBE_keyivgen_ex(cctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER; const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;

implementation

uses openssl3.crypto.stack, openssl3.crypto.objects.obj_dat,
     OpenSSL3.Err, openssl3.crypto.evp.evp_enc,
     openssl3.crypto.evp.kdf_lib, openssl3.crypto.params,
     openssl3.crypto.asn1.a_int,   openssl3.crypto.mem,
     openssl3.crypto.asn1.a_type,  openssl3.crypto.asn1.p5_pbe,
     openssl3.crypto.evp.evp_lib,  openssl3.crypto.evp.kdf_meth,
     openssl3.crypto.evp, openssl3.crypto.evp.digest;





function PKCS5_PBE_keyivgen_ex(cctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  md_tmp : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  key, iv : array[0..(EVP_MAX_KEY_LENGTH)-1] of Byte;

  ivl, kl : integer;

  pbe : PPBEPARAM;

  saltlen, iter : integer;

  salt : PByte;

  mdsize, rv : integer;

  kdf : PEVP_KDF;

  kctx : PEVP_KDF_CTX;

  params : array[0..4] of TOSSL_PARAM;
  p      : POSSL_PARAM ;
  mdname : PUTF8Char;
  label _err;
begin

    pbe := nil;
    rv := 0;
    kctx := nil;

    mdname := EVP_MD_name(md);
    { Extract useful info from parameter }
    if (param = nil)  or  (param._type <> V_ASN1_SEQUENCE)  or
        (param.value.sequence = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        Exit(0);
    end;
    pbe := ASN1_TYPE_unpack_sequence(PBEPARAM_it, param);
    if pbe = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        Exit(0);
    end;
    ivl := EVP_CIPHER_get_iv_length(cipher);
    if (ivl < 0)  or  (ivl > 16) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_IV_LENGTH);
        goto _err ;
    end;
    kl := EVP_CIPHER_get_key_length(cipher);
    if (kl < 0)  or  (kl > int( sizeof(md_tmp))) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
        goto _err ;
    end;
    if pbe.iter = nil  then
       iter := 1
    else
        iter := ASN1_INTEGER_get(pbe.iter);
    salt := pbe.salt.data;
    saltlen := pbe.salt.length;
    if pass = nil then
       passlen := 0
    else
    if (passlen = -1) then
        passlen := Length(pass);
    mdsize := EVP_MD_get_size(md);
    if mdsize < 0 then goto _err ;
    kdf := EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF1, propq);
    kctx := EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if kctx = nil then goto _err ;
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             PUTF8Char(  pass), size_t( passlen));
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             salt, saltlen);
    PostInc(p)^ := OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, @iter);
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            PUTF8Char(  mdname), 0);
    p^ := OSSL_PARAM_construct_end();
    if EVP_KDF_derive(kctx, @md_tmp, mdsize, @params) <> 1  then
        goto _err ;
    memcpy(@key, @md_tmp, kl);
    memcpy(@iv, PByte(@ md_tmp) + (16 - ivl), ivl);
    if 0>= EVP_CipherInit_ex(cctx, cipher, nil, @key, @iv, en_de) then
        goto _err ;
    OPENSSL_cleanse(@md_tmp, EVP_MAX_MD_SIZE);
    OPENSSL_cleanse(@key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(@iv, EVP_MAX_IV_LENGTH);
    rv := 1;
 _err:
    EVP_KDF_CTX_free(kctx);
    PBEPARAM_free(pbe);
    Result := rv;
end;




function PKCS5_PBE_keyivgen(cctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
begin
    Exit(PKCS5_PBE_keyivgen_ex(cctx, pass, passlen, param, cipher, md, en_de,
                                 nil, nil));
end;



end.
