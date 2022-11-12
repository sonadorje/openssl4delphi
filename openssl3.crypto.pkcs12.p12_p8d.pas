unit openssl3.crypto.pkcs12.p12_p8d;

interface
uses openssl.api;

function PKCS8_decrypt_ex(const p8 : PX509_SIG; pass : PUTF8Char; passlen : integer; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PPKCS8_PRIV_KEY_INFO;
function PKCS8_decrypt(const p8 : PX509_SIG; pass : PUTF8Char; passlen : integer):PPKCS8_PRIV_KEY_INFO;

implementation
uses openssl3.crypto.asn1.x_sig,            openssl3.crypto.pkcs12.p12_decr,
     openssl3.crypto.asn1.p8_pkey;

function PKCS8_decrypt_ex(const p8 : PX509_SIG; pass : PUTF8Char; passlen : integer; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):PPKCS8_PRIV_KEY_INFO;
var
  dalg : PX509_ALGOR;
  doct : PASN1_OCTET_STRING;
begin
    X509_SIG_get0(p8, @dalg, @doct);
    Exit(PKCS12_item_decrypt_d2i_ex(dalg,
                                   PKCS8_PRIV_KEY_INFO_it, pass,
                                   passlen, doct, 1, ctx, propq));
end;


function PKCS8_decrypt(const p8 : PX509_SIG; pass : PUTF8Char; passlen : integer):PPKCS8_PRIV_KEY_INFO;
begin
    Result := PKCS8_decrypt_ex(p8, pass, passlen, nil, nil);
end;


end.
