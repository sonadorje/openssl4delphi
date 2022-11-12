unit openssl3.crypto.pem.pem_pk8;

interface
uses OpenSSL.Api;

function PEM_read_bio_PKCS8_PRIV_KEY_INFO( bp : PBIO; x : PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u : Pointer):PPKCS8_PRIV_KEY_INFO;
function PEM_read_PKCS8_PRIV_KEY_INFO( fp : PFILE; x : PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u : Pointer):PPKCS8_PRIV_KEY_INFO;
function PEM_write_bio_PKCS8_PRIV_KEY_INFO(&out : PBIO;const x : PPKCS8_PRIV_KEY_INFO):integer;
function PEM_write_PKCS8_PRIV_KEY_INFO(&out : PFILE;const x : PPKCS8_PRIV_KEY_INFO):integer;

function PEM_read_bio_PKCS8( bp : PBIO; x : PPX509_SIG; cb : Tpem_password_cb; u : Pointer):PX509_SIG;
function PEM_read_PKCS8( fp : PFILE; x : PPX509_SIG; cb : Tpem_password_cb; u : Pointer):PX509_SIG;
function PEM_write_bio_PKCS8(&out : PBIO;const x : PX509_SIG):integer;
function PEM_write_PKCS8(&out : PFILE;const x : PX509_SIG):integer;
function PEM_write_bio_PKCS8PrivateKey(bp : PBIO;const x : PEVP_PKEY;const enc : PEVP_CIPHER;const kstr : PUTF8Char; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
function do_pk8pkey(bp : PBIO;const x : PEVP_PKEY; isder, nid : integer;const enc : PEVP_CIPHER; kstr : PUTF8Char; klen : integer; cb : Tpem_password_cb; u : Pointer;const propq : PUTF8Char):integer;

implementation
uses openssl3.crypto.pem.pem_oth,                openssl3.crypto.asn1.p8_pkey,
     openssl3.crypto.pem.pem_lib,                openssl3.crypto.asn1.x_sig,
     openssl3.crypto.evp.evp_lib,                openssl3.crypto.evp.evp_pkey,
     openssl3.crypto.pkcs12.p12_p8e,             openssl3.crypto.mem,
     openssl3.crypto.encode_decode.encoder_lib,  OpenSSL3.Err,
     openssl3.crypto.encode_decode.encoder_pkey, openssl3.crypto.x509.x_all,
     openssl3.crypto.encode_decode.encoder_meth ;




function do_pk8pkey(bp : PBIO;const x : PEVP_PKEY; isder, nid : integer;const enc : PEVP_CIPHER; kstr : PUTF8Char; klen : integer; cb : Tpem_password_cb; u : Pointer;const propq : PUTF8Char):integer;
var
  ret : integer;
  outtype : PUTF8Char;
  ctx : POSSL_ENCODER_CTX;
  ukstr : PByte;
  p8 : PX509_SIG;
  p8inf : PPKCS8_PRIV_KEY_INFO;
  buf : array[0..(PEM_BUFSIZE)-1] of UTF8Char;
  label _legacy_end;
begin
    ret := 0;
    outtype := get_result(isder > 0, 'DER' , 'PEM');
    ctx := OSSL_ENCODER_CTX_new_for_pkey(x, OSSL_KEYMGMT_SELECT_ALL,
                                      outtype, 'PrivateKeyInfo', propq);
    if ctx = nil then Exit(0);
    {
     * If no keystring or callback is set, OpenSSL traditionally uses the
     * user's cb argument as a password string, or if that's nil, it falls
     * back on PEM_def_callback.
     }
    if (kstr = nil)  and  (not Assigned(cb)) then
    begin
        if u <> nil then
        begin
            kstr := u;
            klen := Length(kstr);
        end
        else
        begin
            cb := PEM_def_callback;
        end;
    end;
    {
     * NOTE: There is no attempt to do a EVP_CIPHER_fetch using the nid,
     * since the nid is a PBE algorithm which can't be fetched currently.
     * (e.g. NID_pbe_WithSHA1And2_Key_TripleDES_CBC). Just use the legacy
     * path if the NID is passed.
     }
    if (nid = -1)  and  (OSSL_ENCODER_CTX_get_num_encoders(ctx) <> 0) then
    begin
        ret := 1;
        if enc <> nil then
        begin
            ret := 0;
            if OSSL_ENCODER_CTX_set_cipher(ctx, EVP_CIPHER_get0_name(enc) , nil) > 0 then
            begin
                ukstr := PByte(StrToBytes(kstr));
                {
                 * Try to pass the passphrase if one was given, or the
                 * passphrase callback if one was given.  If none of them
                 * are given and that's wrong, we rely on the _to_bio
                 * call to generate errors.
                 }
                ret := 1;
                if (kstr <> nil)
                     and  (0>=OSSL_ENCODER_CTX_set_passphrase(ctx, ukstr, klen)) then
                    ret := 0
                else
                if (Assigned(cb)) and  (0>=OSSL_ENCODER_CTX_set_pem_password_cb(ctx, cb, u)) then
                    ret := 0;
            end;
        end;
        ret := ret  and  OSSL_ENCODER_to_bio(ctx, bp);
    end
    else
    begin
        ret := 0;
        p8inf := EVP_PKEY2PKCS8(x);
        if p8inf = nil then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_ERROR_CONVERTING_PRIVATE_KEY);
            goto _legacy_end;
        end;
        if (enc <> nil)  or  (nid <> -1) then
        begin
            if kstr = nil then
            begin
                klen := cb(@buf, PEM_BUFSIZE, 1, u);
                if klen < 0 then begin
                    ERR_raise(ERR_LIB_PEM, PEM_R_READ_KEY);
                    goto _legacy_end;
                end;
                kstr := buf;
            end;
            p8 := PKCS8_encrypt(nid, enc, kstr, klen, nil, 0, 0, p8inf);
            if kstr = buf then
               OPENSSL_cleanse(@buf, klen);
            if p8 = nil then
               goto _legacy_end;
            if isder > 0 then
               ret := i2d_PKCS8_bio(bp, p8)
            else
                ret := PEM_write_bio_PKCS8(bp, p8);
            X509_SIG_free(p8);
        end
        else
        begin
            if isder > 0 then
               ret := i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf)
            else
                ret := PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp, p8inf);
        end;
_legacy_end:
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    end;
    OSSL_ENCODER_CTX_free(ctx);
    Result := ret;
end;

function PEM_write_bio_PKCS8PrivateKey(bp : PBIO;const x : PEVP_PKEY;const enc : PEVP_CIPHER;const kstr : PUTF8Char; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
begin
    Result := do_pk8pkey(bp, x, 0, -1, enc, kstr, klen, cb, u, nil);
end;

function PEM_read_bio_PKCS8( bp : PBIO; x : PPX509_SIG; cb : Tpem_password_cb; u : Pointer):PX509_SIG;
begin
   Result := PEM_ASN1_read_bio(@d2i_X509_SIG, 'ENCRYPTED PRIVATE KEY', bp,  PPointer(x), cb, u);
end;


function PEM_read_PKCS8( fp : PFILE; x : PPX509_SIG; cb : Tpem_password_cb; u : Pointer):PX509_SIG;
begin
   Result := PEM_ASN1_read(@d2i_X509_SIG, 'ENCRYPTED PRIVATE KEY', fp,  PPointer(x), cb, u);
end;


function PEM_write_bio_PKCS8(&out : PBIO;const x : PX509_SIG):integer;
begin
   Result := PEM_ASN1_write_bio((@i2d_X509_SIG), 'ENCRYPTED PRIVATE KEY', &out, x, Pointer(0) ,Pointer(0) ,0,Pointer(0) ,Pointer(0) );
end;


function PEM_write_PKCS8(&out : PFILE;const x : PX509_SIG):integer;
begin
   Result := PEM_ASN1_write((@i2d_X509_SIG), 'ENCRYPTED PRIVATE KEY', out, x, Pointer(0) , Pointer(0) , 0, Pointer(0) , Pointer(0) );
end;

function PEM_read_bio_PKCS8_PRIV_KEY_INFO( bp : PBIO; x : PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u : Pointer):PPKCS8_PRIV_KEY_INFO;
begin
   result :=PEM_ASN1_read_bio(@d2i_PKCS8_PRIV_KEY_INFO, 'PRIVATE KEY', bp,  PPointer(x), cb, u);
end;


function PEM_read_PKCS8_PRIV_KEY_INFO( fp : PFILE; x : PPPKCS8_PRIV_KEY_INFO; cb: Tpem_password_cb; u : Pointer):PPKCS8_PRIV_KEY_INFO;
begin
   result := PEM_ASN1_read(@d2i_PKCS8_PRIV_KEY_INFO, 'PRIVATE KEY', fp,  PPointer(x), cb, u);
end;


function PEM_write_bio_PKCS8_PRIV_KEY_INFO(&out : PBIO;const x : PPKCS8_PRIV_KEY_INFO):integer;
begin
   result :=PEM_ASN1_write_bio(@i2d_PKCS8_PRIV_KEY_INFO, 'PRIVATE KEY', &out, x, Pointer(0) ,Pointer(0) ,0,Pointer(0) ,Pointer(0) );
end;


function PEM_write_PKCS8_PRIV_KEY_INFO(&out : PFILE;const x : PPKCS8_PRIV_KEY_INFO):integer;
begin
   result :=PEM_ASN1_write(@i2d_PKCS8_PRIV_KEY_INFO, 'PRIVATE KEY', out, x, Pointer(0) , Pointer(0) , 0, Pointer(0) , Pointer(0) );
end;

end.
