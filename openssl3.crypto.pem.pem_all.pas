unit openssl3.crypto.pem.pem_all;

interface
uses OpenSSL.Api;

function PEM_read_bio_X509_PUBKEY( bp : PBIO; x : PPX509_PUBKEY; cb : Tpem_password_cb; u : Pointer):PX509_PUBKEY;
function PEM_read_X509_PUBKEY( fp : PFILE; x : PPX509_PUBKEY; cb : Tpem_password_cb; u : Pointer):PX509_PUBKEY;
function PEM_write_bio_X509_PUBKEY(&out : PBIO;const x : PX509_PUBKEY):integer;
function PEM_write_X509_PUBKEY(_out : PFILE;const x : PX509_PUBKEY):integer;
function PEM_write_bio_RSAPrivateKey(_out : PBIO;const x : PRSA; enc : PEVP_CIPHER; kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
function PEM_read_bio_RSAPublicKey( bp : PBIO; x : PPRSA; cb : Tpem_password_cb; u : Pointer):PRSA;
function PEM_write_bio_PUBKEY(_out : PBIO;const x : PEVP_PKEY):integer;
function PEM_write_bio_RSAPublicKey(&out : PBIO;const x : PRSA):integer;
function PEM_read_bio_RSAPrivateKey( bp : PBIO; rsa : PPRSA; cb : Tpem_password_cb; u : Pointer):PRSA;
function pkey_get_rsa( key : PEVP_PKEY; rsa : PPRSA):PRSA;
function PEM_read_bio_RSA_PUBKEY( bp : PBIO; x : PPRSA; cb : Tpem_password_cb; u : Pointer):PRSA;
function PEM_write_PUBKEY(_out : PFILE;const x : PEVP_PKEY):integer;

implementation
 uses openssl3.crypto.pem.pem_oth,         openssl3.crypto.x509.x_pubkey,
      openssl3.crypto.pem.pem_lib,         OpenSSL3.crypto.rsa.rsa_asn1,
      openssl3.crypto.pem.pem_pkey,        openssl3.crypto.evp.p_legacy,
      openssl3.crypto.evp.p_lib,           openssl3.crypto.rsa.rsa_lib,
      openssl3.crypto.encode_decode.encoder_lib,
      openssl3.crypto.encode_decode.encoder_meth,
      openssl3.crypto.encode_decode.encoder_pkey;





function PEM_write_PUBKEY(_out : PFILE;const x : PEVP_PKEY):integer;
var
  ret : integer;
  ctx : POSSL_ENCODER_CTX;
  label _legacy;
begin
   ret := 0;
   ctx := OSSL_ENCODER_CTX_new_for_pkey(x, ( $04 or $80) or $02, 'PEM', 'SubjectPublicKeyInfo', (Pointer(0)));
  if OSSL_ENCODER_CTX_get_num_encoders(ctx)  = 0 then
  begin
     OSSL_ENCODER_CTX_free(ctx);
     goto _legacy;
  end;

  ret := OSSL_ENCODER_to_fp(ctx, _out);
  OSSL_ENCODER_CTX_free(ctx);
  Exit(ret);

_legacy:
  Result := PEM_ASN1_write(@i2d_PUBKEY, 'PUBLIC KEY', _out, x, Pointer(0) , Pointer(0) , 0, Pointer(0) , Pointer(0) );
end;

function PEM_read_bio_RSA_PUBKEY( bp : PBIO; x : PPRSA; cb : Tpem_password_cb; u : Pointer):PRSA;
begin
    Result := PEM_ASN1_read_bio(@d2i_RSA_PUBKEY, 'PUBLIC KEY', bp,  PPointer(x), cb, u);
end;

function pkey_get_rsa( key : PEVP_PKEY; rsa : PPRSA):PRSA;
var
  rtmp : PRSA;
begin
    if nil = key then Exit(nil);
    rtmp := EVP_PKEY_get1_RSA(key);
    EVP_PKEY_free(key);
    if nil = rtmp then Exit(nil);
    if rsa <> nil then
    begin
        RSA_free(rsa^);
        rsa^ := rtmp;
    end;
    Result := rtmp;
end;

function PEM_read_bio_RSAPrivateKey( bp : PBIO; rsa : PPRSA; cb : Tpem_password_cb; u : Pointer):PRSA;
var
  pktmp : PEVP_PKEY;
begin //pktmp.pkey.ptr is a PRSA
    pktmp := PEM_read_bio_PrivateKey(bp, nil, cb, u);
    Result := pkey_get_rsa(pktmp, rsa);
end;

function PEM_write_bio_RSAPublicKey(&out : PBIO;const x : PRSA):integer;
begin
   Result := PEM_ASN1_write_bio(i2d_RSAPublicKey, 'RSA PUBLIC KEY', out, x, Pointer(0) ,Pointer(0) ,0,Pointer(0) ,Pointer(0) );
end;


function PEM_write_bio_PUBKEY(_out : PBIO;const x : PEVP_PKEY):integer;
var
  ret : integer;
  ctx : POSSL_ENCODER_CTX;
  label _legacy;
begin
  ret := 0;
  ctx := OSSL_ENCODER_CTX_new_for_pkey(x, ( ( ( $04 or $80) ) or $02 ), 'PEM', 'SubjectPublicKeyInfo', (Pointer(0) ));
  if OSSL_ENCODER_CTX_get_num_encoders(ctx) = 0  then
  begin
     OSSL_ENCODER_CTX_free(ctx);
     goto _legacy;
  end;

  ret := OSSL_ENCODER_to_bio(ctx, _out);
  OSSL_ENCODER_CTX_free(ctx);
  Exit(ret);

_legacy:
  Exit(PEM_ASN1_write_bio(i2d_PUBKEY, 'PUBLIC KEY', _out, x,
       Pointer(0) , Pointer(0) , 0, Pointer(0) , Pointer(0)) );
end;


function PEM_read_bio_RSAPublicKey( bp : PBIO; x : PPRSA; cb : Tpem_password_cb; u : Pointer):PRSA;
begin
   Result := PEM_ASN1_read_bio(@d2i_RSAPublicKey, 'RSA PUBLIC KEY', bp,  PPointer(x), cb, u);
end;




function PEM_write_bio_RSAPrivateKey(_out : PBIO;const x : PRSA; enc : PEVP_CIPHER; kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
begin
   Result := PEM_ASN1_write_bio(i2d_RSAPrivateKey, 'RSA PRIVATE KEY', _out, x, enc, kstr, klen, cb, u);
end;


function PEM_read_bio_X509_PUBKEY( bp : PBIO; x : PPX509_PUBKEY; cb : Tpem_password_cb; u : Pointer):PX509_PUBKEY;
begin
  result := PEM_ASN1_read_bio(@d2i_X509_PUBKEY, 'PUBLIC KEY', bp,  PPointer( x), cb, u);
end;


function PEM_read_X509_PUBKEY( fp : PFILE; x : PPX509_PUBKEY; cb : Tpem_password_cb; u : Pointer):PX509_PUBKEY;
begin
 result := PEM_ASN1_read(@d2i_X509_PUBKEY, 'PUBLIC KEY', fp,  PPointer( x), cb, u);
end;


function PEM_write_bio_X509_PUBKEY(&out : PBIO;const x : PX509_PUBKEY):integer;
begin
 result := PEM_ASN1_write_bio(i2d_X509_PUBKEY, 'PUBLIC KEY', out, x, Pointer(0) ,Pointer(0) ,0,Pointer(0) ,Pointer(0) );
end;

//pem_all.i
function PEM_write_X509_PUBKEY(_out : PFILE;const x : PX509_PUBKEY):integer;
begin
   result := PEM_ASN1_write(i2d_X509_PUBKEY, 'PUBLIC KEY', _out, x, Pointer(0) , Pointer(0) , 0, Pointer(0) , Pointer(0) );
end;


end.
