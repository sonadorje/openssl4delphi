unit openssl3.crypto.pem.pem_pkey;

interface
uses openssl.api;


function PEM_write_bio_PrivateKey(_out : PBIO;const x : PEVP_PKEY; enc : PEVP_CIPHER; kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
function PEM_write_bio_PrivateKey_ex(_out : PBIO;const x : PEVP_PKEY; enc : PEVP_CIPHER; kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function PEM_write_bio_PrivateKey_traditional(bp : PBIO;{const} x : PEVP_PKEY;const enc : PEVP_CIPHER;const kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
function PEM_read_bio_PrivateKey( bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer):PEVP_PKEY;
function PEM_read_bio_PrivateKey_ex(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function pem_read_bio_key(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; selection : integer):PEVP_PKEY;
function pem_read_bio_key_legacy(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; selection : integer):PEVP_PKEY;
function pem_read_bio_key_decoder(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; selection : integer):PEVP_PKEY;
function PEM_read_bio_PUBKEY( bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer):PEVP_PKEY;
function PEM_read_bio_PUBKEY_ex(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function PEM_write_PrivateKey(_out : PFILE;const x : PEVP_PKEY;const enc : PEVP_CIPHER;const kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
function PEM_write_PrivateKey_ex(_out : PFILE;const x : PEVP_PKEY; enc : PEVP_CIPHER;
                                 const kstr : PByte; klen : integer; cb : Tpem_password_cb;
                                 u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
implementation

uses openssl3.crypto.encode_decode.encoder_pkey,   openssl3.crypto.encode_decode.encoder_lib,
     openssl3.crypto.evp.p_lib,                    openssl3.crypto.encode_decode.encoder_meth,
     openssl3.crypto.pem.pem_lib,                  openssl3.crypto.evp.evp_lib,
     openssl3.crypto.pem.pem_pk8,                  openssl3.crypto.evp,
     openssl3.crypto.asn1.i2d_evp,                 openssl3.crypto.bio.bio_lib,
     openssl3.crypto.bio.bf_readbuff,              openssl3.providers.fips.fipsprov,
     openssl3.crypto.asn1.p8_pkey,                 openssl3.crypto.evp.evp_pkey,
     openssl3.crypto.asn1.x_sig,                   openssl3.crypto.pkcs12.p12_p8d,
     openssl3.crypto.mem,                          openssl3.crypto.asn1.ameth_lib,
     openssl3.crypto.asn1.d2i_pr,                  openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.mem_sec,                      openssl3.crypto.passphrase,
     openssl3.crypto.evp.keymgmt_lib,              openssl3.crypto.encode_decode.decoder_meth,
     openssl3.crypto.encode_decode.decoder_pkey,   openssl3.crypto.encode_decode.decoder_lib,
     OpenSSL3.Err,                                 openssl3.crypto.bio.bio_print,
     openssl3.crypto.bio.bss_file;


function PEM_write_PrivateKey_ex(_out : PFILE;const x : PEVP_PKEY; enc : PEVP_CIPHER;
                                 const kstr : PByte; klen : integer; cb : Tpem_password_cb;
                                 u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  b : PBIO;
  ret : integer;
begin
    b := BIO_new_fp(_out, BIO_NOCLOSE);
    if b = nil then  begin
        ERR_raise(ERR_LIB_PEM, ERR_R_BUF_LIB);
        Exit(0);
    end;
    ret := PEM_write_bio_PrivateKey_ex(b, x, enc, kstr, klen, cb, u,
                                      libctx, propq);
    BIO_free(b);
    Exit(ret);
end;


function PEM_write_PrivateKey(_out : PFILE;const x : PEVP_PKEY;const enc : PEVP_CIPHER;const kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
begin
    Result := PEM_write_PrivateKey_ex(_out, x, enc, kstr, klen, cb, u, Pointer(0) , Pointer(0) );
end;

function PEM_read_bio_PUBKEY_ex(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
begin
    Exit(pem_read_bio_key(bp, x, cb, u, libctx, propq, EVP_PKEY_PUBLIC_KEY));
end;

function PEM_read_bio_PUBKEY( bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer):PEVP_PKEY;
begin
    Result := PEM_read_bio_PUBKEY_ex(bp, x, cb, u, nil, nil);
end;


function pem_read_bio_key_decoder(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; selection : integer):PEVP_PKEY;
var
  pkey : PEVP_PKEY;
  dctx : POSSL_DECODER_CTX;
  pos, newpos : integer;
  label _err;
begin
    pkey := nil;
    dctx := nil;
    pos := BIO_tell(bp);
    if pos < 0 then
        { We can depend on BIO_tell thanks to the BIO_f_readbuffer }
        Exit(nil);
    dctx := OSSL_DECODER_CTX_new_for_pkey(@pkey, 'PEM', nil, nil,
                                         selection, libctx, propq);
    if dctx = nil then Exit(nil);
    if not Assigned(cb) then
       cb := PEM_def_callback;
    if 0>=OSSL_DECODER_CTX_set_pem_password_cb(dctx, cb, u) then
        goto _err;
    ERR_set_mark;

    while (0 >= OSSL_DECODER_from_bio(dctx, bp))  or  (pkey = nil) do
    begin
        newpos := BIO_tell(bp);
        if (BIO_eof(bp) <> 0)  or  (newpos < 0)  or  (newpos <= pos) then
        begin
            ERR_clear_last_mark;
            goto _err;
        end
        else
        begin
            if ERR_GET_REASON(ERR_peek_error) = ERR_R_UNSUPPORTED  then
            begin
                { unsupported PEM data, try again }
                ERR_pop_to_mark;
                ERR_set_mark;
            end
            else
            begin
                { other error, bail out }
                ERR_clear_last_mark;
                goto _err;
            end;
            pos := newpos;
        end;
    end;
    ERR_pop_to_mark;
    if 0 >= evp_keymgmt_util_has(pkey, selection) then
    begin
        EVP_PKEY_free(pkey);
        pkey := nil;
        ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_KEY_COMPONENTS);
        goto _err;
    end;
    if x <> nil then
    begin
        EVP_PKEY_free(x^);
        x^ := pkey;
    end;
 _err:
    OSSL_DECODER_CTX_free(dctx);
    Result := pkey;
end;

function pem_read_bio_key_legacy(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; selection : integer):PEVP_PKEY;
var
  nm         : PUTF8Char;
  p, data    : PByte;
  len        : long;
  slen       : integer;
  ret        : PEVP_PKEY;
  pem_string : PUTF8Char;
  p8inf      : PPKCS8_PRIV_KEY_INFO;
  p8         : PX509_SIG;
  klen       : integer;
  psbuf      : array[0..(PEM_BUFSIZE)-1] of byte;
  ameth      : PEVP_PKEY_ASN1_METHOD;
  label _p8err, _err;
begin
    nm := nil;
    p := nil;
    data := nil;
    ret := nil;
    ERR_set_mark;  { not interested in PEM read errors }
    if selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY > 0 then
    begin
        if 0 >= PEM_bytes_read_bio_secmem(@data, @len, @nm, PEM_STRING_EVP_PKEY, bp, cb, u) then
        begin
            ERR_pop_to_mark;
            Exit(nil);
        end;
    end
    else
    begin
        pem_string := PEM_STRING_PARAMETERS;
        if selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY > 0 then
           pem_string := PEM_STRING_PUBLIC;
        if 0 >= PEM_bytes_read_bio(@data, @len, @nm, pem_string, bp, cb, u) then
        begin
            ERR_pop_to_mark;
            Exit(nil);
        end;
    end;

    ERR_clear_last_mark;
    p := data;
    if strcmp(nm, PEM_STRING_PKCS8INF) = 0 then
    begin
        p8inf := d2i_PKCS8_PRIV_KEY_INFO(nil, @p, len);
        if p8inf = nil then
            goto _p8err;
        ret := evp_pkcs82pkey_legacy(p8inf, libctx, propq);
        if x <> nil then
        begin
            EVP_PKEY_free( x^);
            x^ := ret;
        end;
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    end
    else
    if (strcmp(nm, PEM_STRING_PKCS8) = 0) then
    begin
        p8 := d2i_X509_SIG(nil, @p, len);
        if p8 = nil then
           goto _p8err;
        if Assigned(cb) then
           klen := cb(@psbuf, PEM_BUFSIZE, 0, u)
        else
           klen := PEM_def_callback(@psbuf, PEM_BUFSIZE, 0, u);
        if klen < 0 then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ);
            X509_SIG_free(p8);
            goto _err;
        end;
        p8inf := PKCS8_decrypt(p8, @psbuf, klen);
        X509_SIG_free(p8);
        OPENSSL_cleanse(@psbuf, klen);
        if p8inf = nil then
           goto _p8err;
        ret := evp_pkcs82pkey_legacy(p8inf, libctx, propq);
        if x <> nil then
        begin
            EVP_PKEY_free( x^);
            x^ := ret;
        end;
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    end
    else
    begin
        slen := ossl_pem_check_suffix(nm, 'PRIVATE KEY');
        if (slen > 0) then
        begin
            ameth := EVP_PKEY_asn1_find_str(nil, nm, slen);
            if (ameth = nil) or (not Assigned(ameth.old_priv_decode)) then
               goto _p8err;
            ret := ossl_d2i_PrivateKey_legacy(ameth.pkey_id, x, @p, len, libctx, propq);
        end
        else
        if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) > 0 then
        begin
            ret := ossl_d2i_PUBKEY_legacy(x, @p, len);
        end
        else
        begin
            slen := ossl_pem_check_suffix(nm, 'PARAMETERS');
            if (slen > 0) then
            begin
                ret := EVP_PKEY_new;
                if ret = nil then goto _err;
                if (0 >= EVP_PKEY_set_type_str(ret, nm, slen)) or
                   (Assigned(ret.ameth.param_decode) = False) or
                   (0 >= ret.ameth.param_decode(ret, @p, len))  then
                begin
                    EVP_PKEY_free(ret);
                    ret := nil;
                    goto _err;
                end;
                if x <> nil then
                begin
                    EVP_PKEY_free( x^);
                    x^ := ret;
                end;
            end;
        end;
    end;

 _p8err:
    if (ret = nil)  and  (ERR_peek_last_error = 0) then { ensure some error is reported but do not hide the real one }
        ERR_raise(ERR_LIB_PEM, ERR_R_ASN1_LIB);

 _err:
    OPENSSL_secure_free(nm);
    OPENSSL_secure_clear_free(data, len);
    Result := ret;
end;


function pem_read_bio_key(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; selection : integer):PEVP_PKEY;
var
  ret : PEVP_PKEY;
  new_bio : PBIO;
  pos : integer;
  pwdata : ossl_passphrase_data_st;
  label _err;

  function get_ret: PEVP_PKEY;
  begin   //ret.pkey.ptr is PRSA
     ret := pem_read_bio_key_legacy(bp, x, ossl_pw_pem_password, @pwdata,
                                    libctx, propq, selection);
     Result := ret;
  end;
begin
    ret := nil;
    new_bio := nil;
    pwdata := default(ossl_passphrase_data_st);
    pos := BIO_tell(bp);
    if pos < 0 then
    begin
        new_bio := BIO_new(BIO_f_readbuffer);
        if new_bio = nil then Exit(nil);
        bp := BIO_push(new_bio, bp);
        pos := BIO_tell(bp);
    end;
    if not Assigned(cb) then
       cb := PEM_def_callback;
    if (0 >= ossl_pw_set_pem_password_cb(@pwdata, cb, u)) or
       (0 >= ossl_pw_enable_passphrase_caching(@pwdata)) then
        goto _err;
    ERR_set_mark;
    ret := pem_read_bio_key_decoder(bp, x, ossl_pw_pem_password, @pwdata,
                                   libctx, propq, selection);
    if (ret = nil) and ( (BIO_seek(bp, pos) < 0) or  (get_ret = nil) ) then
        ERR_clear_last_mark
    else
        ERR_pop_to_mark;

 _err:
    ossl_pw_clear_passphrase_data(@pwdata);
    if new_bio <> nil then
    begin
        BIO_pop(new_bio);
        BIO_free(new_bio);
    end;
    Result := ret;
end;

function PEM_read_bio_PrivateKey_ex(bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
begin
    Result := pem_read_bio_key(bp, x, cb, u, libctx, propq, EVP_PKEY_KEYPAIR);
end;

function PEM_read_bio_PrivateKey( bp : PBIO; x : PPEVP_PKEY; cb : Tpem_password_cb; u : Pointer):PEVP_PKEY;
begin
    Result := PEM_read_bio_PrivateKey_ex(bp, x, cb, u, nil, nil);
end;

function PEM_write_bio_PrivateKey_traditional(bp : PBIO;{const} x : PEVP_PKEY;const enc : PEVP_CIPHER;const kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
var
  pem_str : array[0..79] of UTF8Char;
  copy : PEVP_PKEY;
  ret : integer;
begin
    copy := nil;
    if (evp_pkey_is_assigned(x)) and  (evp_pkey_is_provided(x))
         and  (evp_pkey_copy_downgraded(@copy, x) > 0) then
        x := copy;
    if (x.ameth = nil)  or  (not Assigned(x.ameth.old_priv_encode)) then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        Exit(0);
    end;
    BIO_snprintf(pem_str, 80, '%s PRIVATE KEY', [x.ameth.pem_str]);
    ret := PEM_ASN1_write_bio(i2d_PrivateKey,
                             pem_str, bp, x, enc, kstr, klen, cb, u);
    EVP_PKEY_free(copy);
    Result := ret;
end;

function PEM_write_bio_PrivateKey_ex(_out : PBIO;const x : PEVP_PKEY; enc : PEVP_CIPHER; kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;
  ctx : POSSL_ENCODER_CTX;
  label _legacy;
begin
    ret := 0;
   ctx := OSSL_ENCODER_CTX_new_for_pkey(x, ( ( ( ( $04 or $80) ) or $02 ) or $01 ), 'PEM', 'PrivateKeyInfo', propq);
   if OSSL_ENCODER_CTX_get_num_encoders(ctx) = 0  then
    begin
       OSSL_ENCODER_CTX_free(ctx);
       goto _legacy;
    end;

    ret := 1;
    if (kstr = Pointer(0))  and  (not Assigned(cb))  then
    begin
      if (u <> Pointer(0) ) then
      begin
          kstr := u;
          klen := length(PAnsiChar(kstr));
      end
      else
      begin
         cb := PEM_def_callback;
      end;
    end;
    if enc <> Pointer(0) then
    begin
       ret := 0;
       if OSSL_ENCODER_CTX_set_cipher(ctx, EVP_CIPHER_get0_name(enc) , Pointer(0)) > 0 then
       begin
          ret := 1;
          if (kstr <> Pointer(0)) and  (0>=OSSL_ENCODER_CTX_set_passphrase(ctx, kstr, klen)) then
             ret := 0
          else
          if (Assigned(cb))   and  (0>=OSSL_ENCODER_CTX_set_pem_password_cb(ctx, cb, u)) then
              ret := 0;
       end;
    end;
    if 0>=ret then
    begin
        OSSL_ENCODER_CTX_free(ctx);
        Exit(0);
    end;

   ret := OSSL_ENCODER_to_bio(ctx, _out);
   OSSL_ENCODER_CTX_free(ctx);
   Exit( ret);

_legacy:
      if (x.ameth = Pointer(0))  or  (Assigned(x.ameth.priv_encode) ) then
          Exit(PEM_write_bio_PKCS8PrivateKey(_out, x, enc,
                                               PUTF8Char (kstr), klen, cb, u));
      Result := PEM_write_bio_PrivateKey_traditional(_out, x, enc, kstr, klen, cb, u);
end;

function PEM_write_bio_PrivateKey(_out : PBIO;const x : PEVP_PKEY; enc : PEVP_CIPHER; kstr : PByte; klen : integer; cb : Tpem_password_cb; u : Pointer):integer;
begin
    Exit(PEM_write_bio_PrivateKey_ex(_out, x, enc, kstr, klen, cb, u, nil , nil) );
end;

end.
