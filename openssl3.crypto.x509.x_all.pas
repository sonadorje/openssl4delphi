unit openssl3.crypto.x509.x_all;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;



function i2d_X509_PUBKEY_bio(bp : PBIO;const xpk : PX509_PUBKEY):integer;
function X509_digest(const cert : PX509; md : PEVP_MD; data : PByte; len : Puint32):integer;
function X509_CRL_digest(const data : PX509_CRL; _type : PEVP_MD; md : PByte; len : Puint32):integer;
function X509_verify( a : PX509; r : PEVP_PKEY):integer;
 function X509_CRL_sign(x : PX509_CRL; pkey : PEVP_PKEY;const md : PEVP_MD):integer;
function i2d_PKCS8_PRIV_KEY_INFO_bio(bp : PBIO;const p8inf : PPKCS8_PRIV_KEY_INFO):integer;
function i2d_PKCS8_bio(bp : PBIO;const p8 : PX509_SIG):integer;

implementation
uses openssl3.crypto.mem, openssl3.crypto.o_str, OpenSSL3.include.openssl.asn1,
     openssl3.crypto.asn1.a_i2d_fp, openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.asn1.x_algor,  openssl3.crypto.asn1.a_verify,
     openssl3.crypto.asn1.a_sign,  openssl3.crypto.asn1.p8_pkey,
     openssl3.crypto.asn1.x_sig,
     openssl3.crypto.x509.x_x509,  OpenSSL3.Err, openssl3.crypto.x509.x_crl,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.asn1.a_digest;






function i2d_PKCS8_bio(bp : PBIO;const p8 : PX509_SIG):integer;
begin
    if Boolean(1) then
       Exit(ASN1_i2d_bio(@i2d_X509_SIG, bp, p8))
    else
       Exit(ASN1_i2d_bio(nil, bp, PX509_SIG(0)));

    //Result := ASN1_i2d_bio_of(X509_SIG, i2d_X509_SIG, bp, p8);
end;

function i2d_PKCS8_PRIV_KEY_INFO_bio(bp : PBIO;const p8inf : PPKCS8_PRIV_KEY_INFO):integer;
type
  Tx_all_i2d = function(const p1: PPKCS8_PRIV_KEY_INFO; p2: PPByte): int;
  Px_all_i2d = ^Tx_all_i2d;
var
  p1: Pointer;
begin

    if Boolean(1) then
       p1 := p8inf
    else
       p1 := nil;
    if Boolean(1) then
       Exit(ASN1_i2d_bio(@i2d_PKCS8_PRIV_KEY_INFO, bp, p1))
    else
       Exit(ASN1_i2d_bio(nil, bp, p1));

    //return (ASN1_i2d_bio(((i2d_of_void*) (1 ? i2d_PKCS8_PRIV_KEY_INFO : ((int (*)(const PKCS8_PRIV_KEY_INFO *,unsigned char **))0))), bp, ((void*) (1 ? p8inf : (const PKCS8_PRIV_KEY_INFO*)0))));
end;



function X509_CRL_sign(x : PX509_CRL; pkey : PEVP_PKEY;const md : PEVP_MD):integer;
begin
    x.crl.enc.modified := 1;
    Exit(ASN1_item_sign_ex(X509_CRL_INFO_it, @x.crl.sig_alg,
                             @x.sig_alg, @x.signature, @x.crl, nil,
                             pkey, md, x.libctx, x.propq));
end;




function X509_verify( a : PX509; r : PEVP_PKEY):integer;
begin
    if X509_ALGOR_cmp(@a.sig_alg, @a.cert_info.signature)>0 then
        Exit(0);
    Exit(ASN1_item_verify_ex(X509_CINF_it, @a.sig_alg,
                               @a.signature, @a.cert_info,
                               a.distinguishing_id, r, a.libctx, a.propq));
end;




function X509_CRL_digest(const data : PX509_CRL; _type : PEVP_MD; md : PByte; len : Puint32):integer;
begin
    if _type = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (EVP_MD_is_a(_type, SN_sha1))  and ( (data.flags and EXFLAG_SET) <> 0 )
             and ( (data.flags and EXFLAG_NO_FINGERPRINT) = 0)  then
    begin
        if len <> nil then
           len^ := sizeof(data.sha1_hash);
        memcpy(md, @data.sha1_hash, sizeof(data.sha1_hash));
        Exit(1);
    end;
    Exit(ossl_asn1_item_digest_ex(X509_CRL_it, _type, PUTF8Char( data),
                                    md, len, data.libctx, data.propq));
end;




function X509_digest(const cert : PX509; md : PEVP_MD; data : PByte; len : Puint32):integer;
begin
    if (EVP_MD_is_a(md, SN_sha1))  and ( (cert.ex_flags and EXFLAG_SET) <> 0)
             and ( (cert.ex_flags and EXFLAG_NO_FINGERPRINT) = 0)  then
    begin
        { Asking for SHA1 and we already computed it. }
        if len <> nil then
            len^ := sizeof(cert.sha1_hash);
        memcpy(data, @cert.sha1_hash, sizeof(cert.sha1_hash));
        Exit(1);
    end;
    Exit(ossl_asn1_item_digest_ex(X509_it, md, PUTF8Char( cert),
                                    data, len, cert.libctx, cert.propq));
end;



//x_all.i
function i2d_X509_PUBKEY_bio(bp : PBIO;const xpk : PX509_PUBKEY):integer;
var
  _i2d: Ti2d_of_void;
  _x: Pointer;
begin
   if true then
     _i2d := i2d_X509_PUBKEY
   else
     _i2d := nil;
   if true then
      _x:= xpk
   else
      _x := nil;
   Result := ASN1_i2d_bio(_i2d, bp, _x);
end;




end.
