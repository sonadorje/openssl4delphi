unit openssl3.crypto.pkcs12.p12_p8e;

interface
 uses OpenSSL.Api;

function PKCS8_encrypt_ex(pbe_nid : integer;const cipher : PEVP_CIPHER; pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, iter : integer; p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509_SIG;
function PKCS8_set0_pbe_ex(const pass : PUTF8Char; passlen : integer; p8inf : PPKCS8_PRIV_KEY_INFO; pbe : PX509_ALGOR; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509_SIG;
function PKCS8_encrypt(pbe_nid : integer;const cipher : PEVP_CIPHER; pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, iter : integer; p8inf : PPKCS8_PRIV_KEY_INFO):PX509_SIG;

implementation
uses OpenSSL3.Err, openssl3.crypto.asn1.p5_pbev2, openssl3.crypto.asn1.p5_pbe,
     openssl3.crypto.asn1.p8_pkey,    openssl3.crypto.asn1.tasn_typ,
     openssl3.providers.fips.fipsprov, openssl3.crypto.evp.evp_pbe,
     openssl3.crypto.asn1.x_algor,
     openssl3.crypto.pkcs12.p12_decr, openssl3.crypto.mem;


function PKCS8_encrypt(pbe_nid : integer;const cipher : PEVP_CIPHER; pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, iter : integer; p8inf : PPKCS8_PRIV_KEY_INFO):PX509_SIG;
begin
    Result := PKCS8_encrypt_ex(pbe_nid, cipher, pass, passlen, salt, saltlen, iter, p8inf, nil, nil);
end;


function PKCS8_set0_pbe_ex(const pass : PUTF8Char; passlen : integer; p8inf : PPKCS8_PRIV_KEY_INFO; pbe : PX509_ALGOR; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509_SIG;
var
  p8 : PX509_SIG;
  enckey : PASN1_OCTET_STRING;
begin
    enckey := PKCS12_item_i2d_encrypt_ex(pbe, PKCS8_PRIV_KEY_INFO_it,
                                   pass, passlen, p8inf, 1, ctx, propq);
    if nil = enckey then
    begin
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR);
        Exit(nil);
    end;
    p8 := OPENSSL_zalloc(sizeof( p8^));
    if p8 = nil then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        ASN1_OCTET_STRING_free(enckey);
        Exit(nil);
    end;
    p8.algor := pbe;
    p8.digest := enckey;
    Result := p8;
end;

function PKCS8_encrypt_ex(pbe_nid : integer;const cipher : PEVP_CIPHER; pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, iter : integer; p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PX509_SIG;
var
  p8 : PX509_SIG;

  pbe : PX509_ALGOR;
begin
    p8 := nil;
    if pbe_nid = -1 then
    begin
        if cipher = nil then
        begin
            ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
            Exit(nil);
        end;
        pbe := PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, nil, -1,
                                   libctx);
    end
    else
    begin
        ERR_set_mark();
        if EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, nil, nil, 0)>0 then
        begin
            ERR_clear_last_mark();
            if cipher = nil then
            begin
                ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
                Exit(nil);
            end;
            pbe := PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, nil,
                                       pbe_nid, libctx);
        end
        else
        begin
            ERR_pop_to_mark();
            pbe := PKCS5_pbe_set_ex(pbe_nid, iter, salt, saltlen, libctx);
        end;
    end;
    if pbe = nil then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB);
        Exit(nil);
    end;
    p8 := PKCS8_set0_pbe_ex(pass, passlen, p8inf, pbe, libctx, propq);
    if p8 = nil then
    begin
        X509_ALGOR_free(pbe);
        Exit(nil);
    end;
    Result := p8;
end;


end.
