unit openssl3.crypto.evp.p12_crpt;

interface
uses OpenSSL.Api;

function PKCS12_PBE_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
function PKCS12_PBE_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;

implementation
uses
   openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.kdf_meth,
   openssl3.crypto.evp.kdf_lib, openssl3.crypto.params,
   OpenSSL3.Err,  openssl3.crypto.evp.evp_pbe,
   openssl3.crypto.evp.evp_enc,    openssl3.crypto.mem,
   openssl3.crypto.asn1.p5_pbe,    openssl3.crypto.asn1.a_int,
   openssl3.crypto.pkcs12.p12_key, openssl3.crypto.asn1.a_type,
   openssl3.crypto.bio.bio_print, openssl3.crypto.bio.bio_dump;


function PKCS12_PBE_keyivgen_ex(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER;const md : PEVP_MD; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  pbe : PPBEPARAM;
  saltlen, iter, ret : integer;
  salt : PByte;
  key,iv : array[0..(EVP_MAX_KEY_LENGTH)-1] of Byte;
  piv : PByte;
begin

    piv := @iv;
    if cipher = nil then Exit(0);
    { Extract useful info from parameter }
    pbe := ASN1_TYPE_unpack_sequence(PBEPARAM_it, param);
    if pbe = nil then
    begin
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
        Exit(0);
    end;
    if pbe.iter = nil then
       iter := 1
    else
        iter := ASN1_INTEGER_get(pbe.iter);
    salt := pbe.salt.data;
    saltlen := pbe.salt.length;
    if 0>= PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, PKCS12_KEY_ID,
                                iter, EVP_CIPHER_get_key_length(cipher) ,
                                @key, md,
                                libctx, propq) then
    begin
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_KEY_GEN_ERROR);
        PBEPARAM_free(pbe);
        Exit(0);
    end;
    if EVP_CIPHER_get_iv_length(cipher) > 0  then
    begin
        if (0>= PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, PKCS12_IV_ID,
                                    iter, EVP_CIPHER_get_iv_length(cipher),
                                    @iv, md,
                                    libctx, propq)) then
        begin
            ERR_raise(ERR_LIB_PKCS12, PKCS12_R_IV_GEN_ERROR);
            PBEPARAM_free(pbe);
            Exit(0);
        end;
    end
    else
    begin
        piv := nil;
    end;
    PBEPARAM_free(pbe);
    ret := EVP_CipherInit_ex(ctx, cipher, nil, @key, piv, en_de);
    OPENSSL_cleanse(@key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(@iv, EVP_MAX_IV_LENGTH);
    Result := ret;
end;



function PKCS12_PBE_keyivgen(ctx : PEVP_CIPHER_CTX;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE;const cipher : PEVP_CIPHER;const md : PEVP_MD; en_de : integer):integer;
begin
    Exit(PKCS12_PBE_keyivgen_ex(ctx, pass, passlen, param, cipher, md, en_de,
                                  nil, nil));
end;


end.
