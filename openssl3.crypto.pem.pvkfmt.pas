unit openssl3.crypto.pem.pvkfmt;

interface
uses OpenSSL.Api;

const
   PVK_SALTLEN  = $10;
   MS_PVKMAGIC  = $b0b5f11e;
   MS_PUBLICKEYBLOB        = $6;
   MS_PRIVATEKEYBLOB       = $7;
   MS_RSA1MAGIC            = $31415352;
   MS_RSA2MAGIC            = $32415352;
   MS_DSS1MAGIC            = $31535344;
   MS_DSS2MAGIC            = $32535344;

   MS_KEYALG_RSA_KEYX      = $a400;
   MS_KEYALG_DSS_SIGN      = $2200;

   MS_KEYTYPE_KEYX         = $1;
   MS_KEYTYPE_SIGN         = $2;
   PVK_MAX_KEYLEN          = 102400;
   PVK_MAX_SALTLEN         = 10240;
function i2b_PVK_bio_ex(&out : PBIO;const pk : PEVP_PKEY; enclevel : integer; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function i2b_PVK(&out : PPByte;const pk : PEVP_PKEY; enclevel : integer; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function do_i2b(&out : PPByte;const pk : PEVP_PKEY; ispub : integer):integer;
function check_bitlen_rsa(const rsa : PRSA; ispub : integer; pmagic : Puint32):integer;
function check_bitlen_dsa(const dsa : PDSA; ispub : integer; pmagic : Puint32):integer;
 function ossl_blob_length( bitlen : unsigned; isdss, ispub : integer):integer;
procedure write_ledword( &out : PPByte; dw : uint32);
procedure write_rsa(_out : PPByte;const rsa : PRSA; ispub : integer);
 procedure write_lebn(&out : PPByte;const bn : PBIGNUM; len : integer);
procedure write_dsa(&out : PPByte;const dsa : PDSA; ispub : integer);
 function derive_pvk_key(key : PByte; keylen : size_t;const salt : PByte; saltlen : uint32;const pass : PByte; passlen : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function i2b_PrivateKey_bio(&out : PBIO;const pk : PEVP_PKEY):integer;
  function i2b_PublicKey_bio(&out : PBIO;const pk : PEVP_PKEY):integer;
 function do_i2b_bio(&out : PBIO;const pk : PEVP_PKEY; ispub : integer):integer;
function read_ledword(const _in : PPByte):uint32;

function ossl_do_blob_header(const _in : PPByte; length : uint32; pmagic, pbitlen : Puint32; pisdss, pispub : PInteger):integer;
function ossl_b2i_DSA_after_header(const _in : PPByte; bitlen : uint32; ispub : integer):PDSA;
function read_lebn({const} _in : PPByte; nbyte : uint32; r : PPBIGNUM):integer;
function ossl_b2i_RSA_after_header(const _in : PPByte; bitlen : uint32; ispub : integer):PRSA;
function b2i_DSA_PVK_bio_ex(_in : PBIO; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PDSA;
 function do_PVK_key_bio(_in : PBIO; cb : Tpem_password_cb; u : Pointer; isdss, ispub : PInteger; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):Pointer;
function ossl_do_PVK_header(const _in : PPByte; length : uint32; skip_magic : integer; psaltlen, pkeylen : Puint32):integer;
function do_PVK_body_key(const _in : PPByte; saltlen, keylen : uint32; cb : Tpem_password_cb; u : Pointer; isdss, ispub : PInteger; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):Pointer;
function do_b2i_key(const _in : PPByte; length : uint32; isdss, ispub : PInteger):Pointer;
function b2i_RSA_PVK_bio_ex(_in : PBIO; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PRSA;

implementation


uses OpenSSL3.Err,
     openssl3.crypto.bio.bio_print, openssl3.crypto.mem,
     openssl3.crypto.evp.p_lib,     openssl3.crypto.bn.bn_lib,
     openssl3.crypto.rand.rand_lib, openssl3.crypto.evp.kdf_meth,
     openssl3.crypto.evp.kdf_lib,   openssl3.crypto.evp.evp_enc,
     openssl3.crypto.dsa.dsa_lib,   OpenSSL3.crypto.rsa.rsa_crpt,
     openssl3.crypto.rsa.rsa_lib,   openssl3.crypto.evp.p_legacy,
     openssl3.crypto.pem.pem_lib,   openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_exp,     openssl3.crypto.bio.bio_lib,
     openssl3.crypto.params;



function b2i_RSA_PVK_bio_ex(_in : PBIO; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PRSA;
var
  isdss, ispub : integer;
begin
    isdss := 0;
    ispub := 0;
    Result := do_PVK_key_bio(_in, cb, u, @isdss, @ispub, libctx, propq);
end;


function do_b2i_key(const _in : PPByte; length : uint32; isdss, ispub : PInteger):Pointer;
var
  p : PByte;
  bitlen, magic : uint32;
  key : Pointer;
begin
     p := _in^;
    key := nil;
    if ossl_do_blob_header(@p, length, @magic, @bitlen, isdss, ispub) <= 0  then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_KEYBLOB_HEADER_PARSE_ERROR);
        Exit(nil);
    end;
    length  := length - 16;
    if length < ossl_blob_length(bitlen, isdss^, ispub^) then  begin
        ERR_raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT);
        Exit(nil);
    end;
    if (0>=isdss^) then
       key := ossl_b2i_RSA_after_header(@p, bitlen, ispub^)
{$IFNDEF OPENSSL_NO_DSA}
    else
        key := ossl_b2i_DSA_after_header(@p, bitlen, ispub^);
{$ENDIF}
    if key = nil then begin
        ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        Exit(nil);
    end;
    Result := key;
end;



function do_PVK_body_key(const _in : PPByte; saltlen, keylen : uint32; cb : Tpem_password_cb; u : Pointer; isdss, ispub : PInteger; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):Pointer;
var
  p,
  enctmp    : PByte;
  keybuf    : array[0..19] of Byte;
  key       : Pointer;
  rc4       : PEVP_CIPHER;
  cctx      : PEVP_CIPHER_CTX;
  magic     : uint32;
  psbuf     : array[0..(PEM_BUFSIZE)-1] of byte;
  enctmplen,
  inlen     : integer;
  q         : PByte;
  label _err;
begin
    p := _in^;
    enctmp := nil;
    key := nil;
{$IFNDEF OPENSSL_NO_RC4}
    rc4 := nil;
{$ENDIF}
    cctx := EVP_CIPHER_CTX_new;
    if cctx = nil then begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if saltlen > 0 then begin
{$IFNDEF OPENSSL_NO_RC4}
        if Assigned(cb) then
            inlen := cb(@psbuf, PEM_BUFSIZE, 0, u)
        else
            inlen := PEM_def_callback(@psbuf, PEM_BUFSIZE, 0, u);
        if inlen < 0 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ);
            goto _err;
        end;
        enctmp := OPENSSL_malloc(keylen + 8);
        if enctmp = nil then begin
            ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        if 0>=derive_pvk_key(@keybuf, sizeof(keybuf), p, saltlen,
                            PByte(@psbuf), inlen, libctx, propq) then
            goto _err;
        p  := p + saltlen;
        { Copy BLOBHEADER across, decrypt rest }
        memcpy(enctmp, p, 8);
        p  := p + 8;
        if keylen < 8 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT);
            goto _err;
        end;
        inlen := keylen - 8;
        q := enctmp + 8;
        rc4 := EVP_CIPHER_fetch(libctx, 'RC4', propq);
        if rc4 = nil then
            goto _err;
        if 0>=EVP_DecryptInit_ex(cctx, rc4, nil, @keybuf, nil) then
            goto _err;
        if 0>=EVP_DecryptUpdate(cctx, q, @enctmplen, p, inlen) then
            goto _err;
        if 0>=EVP_DecryptFinal_ex(cctx, q + enctmplen, @enctmplen) then
            goto _err;
        magic := read_ledword(PPByte(@q));
        if (magic <> MS_RSA2MAGIC)  and  (magic <> MS_DSS2MAGIC) then
        begin
            q := enctmp + 8;
            memset(PByte(@keybuf) + 5, 0, 11);
            if 0>=EVP_DecryptInit_ex(cctx, rc4, nil, @keybuf, nil) then
                goto _err;
            if 0>=EVP_DecryptUpdate(cctx, q, @enctmplen, p, inlen) then
                goto _err;
            if 0>=EVP_DecryptFinal_ex(cctx, q + enctmplen, @enctmplen) then
                goto _err;
            magic := read_ledword(PPByte(@q));
            if (magic <> MS_RSA2MAGIC)  and  (magic <> MS_DSS2MAGIC) then begin
                ERR_raise(ERR_LIB_PEM, PEM_R_BAD_DECRYPT);
                goto _err;
            end;
        end;
        p := enctmp;
{$ELSE ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_CIPHER);}
        goto_err;
{$ENDIF}
    end;
    key := do_b2i_key(@p, keylen, isdss, ispub);
 _err:
    EVP_CIPHER_CTX_free(cctx);
{$IFNDEF OPENSSL_NO_RC4}
    EVP_CIPHER_free(rc4);
{$ENDIF}
    if enctmp <> nil then begin
        OPENSSL_cleanse(@keybuf, sizeof(keybuf));
        OPENSSL_free(Pointer(enctmp));
    end;
    Result := key;
end;



function ossl_do_PVK_header(const _in : PPByte; length : uint32; skip_magic : integer; psaltlen, pkeylen : Puint32):integer;
var
    p            : PByte;

  pvk_magic,
  is_encrypted : uint32;
begin
     p := _in^;
    if skip_magic > 0 then
    begin
        if length < 20 then  begin
            ERR_raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT);
            Exit(0);
        end;
    end
    else
    begin
        if length < 24 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT);
            Exit(0);
        end;
        pvk_magic := read_ledword(@p);
        if pvk_magic <> MS_PVKMAGIC then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER);
            Exit(0);
        end;
    end;
    { Skip reserved }
    p  := p + 4;
    {
     * keytype =
     }
    read_ledword(@p);
    is_encrypted := read_ledword(@p);
    psaltlen^ := read_ledword(@p);
    pkeylen^ := read_ledword(@p);
    if (pkeylen^ > PVK_MAX_KEYLEN)  or  (psaltlen^ > PVK_MAX_SALTLEN) then Exit(0);
    if (is_encrypted > 0)  and  (psaltlen^ = 0) then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_INCONSISTENT_HEADER);
        Exit(0);
    end;
    _in^ := p;
    Result := 1;
end;




function do_PVK_key_bio(_in : PBIO; cb : Tpem_password_cb; u : Pointer; isdss, ispub : PInteger; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):Pointer;
var
  pvk_hdr : array[0..23] of Byte;
  p, buf : PByte;
  buflen : integer;
  key : Pointer;
  saltlen, keylen : uint32;
  label _err;
begin
    buf := nil;
    key := nil;
    if BIO_read(_in, @pvk_hdr, 24) <> 24  then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_PVK_DATA_TOO_SHORT);
        Exit(nil);
    end;
    p := @pvk_hdr;
    if 0>=ossl_do_PVK_header(@p, 24, 0, @saltlen, @keylen) then
        Exit(0);
    buflen := int(keylen) + saltlen;
    buf := OPENSSL_malloc(buflen);
    if buf = nil then begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    p := buf;
    if BIO_read(_in, buf, buflen) <> buflen  then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_PVK_DATA_TOO_SHORT);
        goto _err;
    end;
    key := do_PVK_body_key(@p, saltlen, keylen, cb, u, isdss, ispub, libctx, propq);
 _err:
    OPENSSL_clear_free(Pointer(buf), buflen);
    Result := key;
end;

function b2i_DSA_PVK_bio_ex(_in : PBIO; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PDSA;
var
  isdss, ispub : integer;
begin
    isdss := 1;
    ispub := 0;
    Result := do_PVK_key_bio(_in, cb, u, @isdss, @ispub, libctx, propq);
end;


function ossl_b2i_RSA_after_header(const _in : PPByte; bitlen : uint32; ispub : integer):PRSA;
var
  pin : PByte;
  e, n, d, p, q, dmp1, dmq1, iqmp : PBIGNUM;
  rsa : PRSA;
  nbyte, hnbyte : uint32;
  label _memerr;
begin
    pin := _in^;
    e := nil;
    n := nil;
    d := nil;
    p := nil;
    q := nil;
    dmp1 := nil;
    dmq1 := nil;
    iqmp := nil;
    rsa := nil;
    nbyte := (bitlen + 7)  shr  3;
    hnbyte := (bitlen + 15)  shr  4;
    rsa := RSA_new;
    if rsa = nil then goto _memerr;
    e := BN_new;
    if e = nil then goto _memerr;
    if 0>=BN_set_word(e, read_ledword(@pin)) then
        goto _memerr;
    if 0>=read_lebn(@pin, nbyte, @n ) then
        goto _memerr;
    if 0>=ispub then begin
        if 0>=read_lebn(@pin, hnbyte, @p) then
            goto _memerr;
        if 0>=read_lebn(@pin, hnbyte, @q) then
            goto _memerr;
        if 0>=read_lebn(@pin, hnbyte, @dmp1) then
            goto _memerr;
        if 0>=read_lebn(@pin, hnbyte, @dmq1) then
            goto _memerr;
        if 0>=read_lebn(@pin, hnbyte, @iqmp) then
            goto _memerr;
        if 0>=read_lebn(@pin, nbyte, @d) then
            goto _memerr;
        if 0>=RSA_set0_factors(rsa, p, q) then
            goto _memerr;
        p := nil; q := nil;
        if 0>=RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) then
            goto _memerr;
        dmp1 := nil; dmq1 := nil; iqmp := nil;
    end;
    if 0>=RSA_set0_key(rsa, n, e, d) then
        goto _memerr;
    n := nil; e := nil; d := nil;
    _in^ := pin;
    Exit(rsa);
 _memerr:
    ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
    BN_free(e);
    BN_free(n);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(d);
    RSA_free(rsa);
    Result := nil;
end;


function read_lebn({const} _in : PPByte; nbyte : uint32; r : PPBIGNUM):integer;
begin
    r^ := BN_lebin2bn( _in^, nbyte, nil);
    if r^ = nil then Exit(0);
    _in^  := _in^ + nbyte;
    Result := 1;
end;



function ossl_b2i_DSA_after_header(const _in : PPByte; bitlen : uint32; ispub : integer):PDSA;
var
  p        : PByte;
  dsa      : PDSA;
  ctx      : PBN_CTX;

  pbn,
  qbn,
  gbn,
  priv_key,
  pub_key  : PBIGNUM;
  nbyte    : uint32;
  label _memerr;
begin
    p := _in^;
    dsa := nil;
    ctx := nil;
    pbn := nil;
    qbn := nil;
    gbn := nil;
    priv_key := nil;
    pub_key := nil;
    nbyte := (bitlen + 7)  shr  3;
    dsa := DSA_new;
    if dsa = nil then goto _memerr;
    if 0>=read_lebn(@p, nbyte, @pbn) then
        goto _memerr;
    if 0>=read_lebn(@p, 20, @qbn) then
        goto _memerr;
    if 0>=read_lebn(@p, nbyte, @gbn) then
        goto _memerr;
    if ispub > 0 then
    begin
        if 0>=read_lebn(@p, nbyte, @pub_key) then
            goto _memerr;
    end
    else
    begin
        if 0>=read_lebn(@p, 20, @priv_key) then
            goto _memerr;
        { Set constant time flag before public key calculation }
        BN_set_flags(priv_key, BN_FLG_CONSTTIME);
        { Calculate public key }
        pub_key := BN_new;
        if pub_key = nil then goto _memerr;
        ctx := BN_CTX_new();
        if ctx = nil then
            goto _memerr;
        if 0>=BN_mod_exp(pub_key, gbn, priv_key, pbn, ctx) then
            goto _memerr;
        BN_CTX_free(ctx);
        ctx := nil;
    end;
    if 0>=DSA_set0_pqg(dsa, pbn, qbn, gbn) then
        goto _memerr;
    pbn := nil; qbn := nil; gbn := nil;
    if 0>=DSA_set0_key(dsa, pub_key, priv_key) then
        goto _memerr;
    pub_key := nil; priv_key := nil;
    _in^ := p;
    Exit(dsa);
 _memerr:
    ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
    DSA_free(dsa);
    BN_free(pbn);
    BN_free(qbn);
    BN_free(gbn);
    BN_free(pub_key);
    BN_free(priv_key);
    BN_CTX_free(ctx);
    Result := nil;
end;

function read_ledword(const _in : PPByte):uint32;
var
  p : PByte;
  ret : uint32;
begin
     p := _in^;
    ret := uint32( PostInc(p)^);
    ret  := ret  or uint32( PostInc(p)^ shl 8);
    ret  := ret  or uint32( PostInc(p)^ shl 16);
    ret  := ret  or uint32( PostInc(p)^ shl 24);
    _in^ := p;
    Result := ret;
end;




function ossl_do_blob_header(const _in : PPByte; length : uint32; pmagic, pbitlen : Puint32; pisdss, pispub : PInteger):integer;
var
  p : PByte;
begin
    p := _in^;
    if length < 16 then Exit(0);
    { bType }
    case  p^ of
        MS_PUBLICKEYBLOB:
        begin
            if pispub^ = 0 then begin
                ERR_raise(ERR_LIB_PEM, PEM_R_EXPECTING_PRIVATE_KEY_BLOB);
                Exit(0);
            end;
            pispub^ := 1;
        end;
        MS_PRIVATEKEYBLOB:
        begin
            if pispub^ = 1 then begin
                ERR_raise(ERR_LIB_PEM, PEM_R_EXPECTING_PUBLIC_KEY_BLOB);
                Exit(0);
            end;
            pispub^ := 0;
        end;
        else
            Exit(0);
    end;
    Inc(p);
    { Version }
    if PostInc(p)^ <> $2  then  begin
        ERR_raise(ERR_LIB_PEM, PEM_R_BAD_VERSION_NUMBER);
        Exit(0);
    end;
    { Ignore reserved, aiKeyAlg }
    p  := p + 6;
    pmagic^ := read_ledword(@p);
    pbitlen^ := read_ledword(@p);
    { Consistency check for private vs public }
    case  pmagic^ of
    MS_DSS1MAGIC,
    MS_RSA1MAGIC:
    begin
        if pispub^ = 0 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_EXPECTING_PRIVATE_KEY_BLOB);
            Exit(0);
        end;
    end;
    MS_DSS2MAGIC,
    MS_RSA2MAGIC:
        if pispub^ = 1 then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_EXPECTING_PUBLIC_KEY_BLOB);
            Exit(0);
        end;
        //break;
    else
        ERR_raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER);
        Exit(-1);
    end;
    { Check that we got the expected type }
    case  pmagic^ of
    MS_DSS1MAGIC,
    MS_DSS2MAGIC:
    begin
        if pisdss^ = 0 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_EXPECTING_DSS_KEY_BLOB);
            Exit(0);
        end;
        pisdss^ := 1;
    end;
    MS_RSA1MAGIC,
    MS_RSA2MAGIC:
    begin
        if pisdss^ = 1 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_EXPECTING_RSA_KEY_BLOB);
            Exit(0);
        end;
        pisdss^ := 0;
    end;
    else
        ERR_raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER);
        Exit(-1);
    end;
    _in^ := p;
    Result := 1;
end;



function do_i2b_bio(&out : PBIO;const pk : PEVP_PKEY; ispub : integer):integer;
var
  tmp : PByte;
  outlen, wrlen : integer;
begin
    tmp := nil;
    outlen := do_i2b(@tmp, pk, ispub);
    if outlen < 0 then Exit(-1);
    wrlen := BIO_write(out, tmp, outlen);
    OPENSSL_free(Pointer(tmp));
    if wrlen = outlen then Exit(outlen);
    Result := -1;
end;




function i2b_PrivateKey_bio(&out : PBIO;const pk : PEVP_PKEY):integer;
begin
    Result := do_i2b_bio(out, pk, 0);
end;


function i2b_PublicKey_bio(&out : PBIO;const pk : PEVP_PKEY):integer;
begin
    Result := do_i2b_bio(out, pk, 1);
end;




function derive_pvk_key(key : PByte; keylen : size_t;const salt : PByte; saltlen : uint32;const pass : PByte; passlen : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  kdf : PEVP_KDF;

  ctx : PEVP_KDF_CTX;

  params : array[0..4] of TOSSL_PARAM;

  p : POSSL_PARAM;

  rv : integer;
begin
    p := @params;
    kdf := EVP_KDF_fetch(libctx, 'PVKKDF', propq);
    if kdf = nil then
        Exit(0);
    ctx := EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if ctx = nil then Exit(0);
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             Pointer( salt), saltlen);
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             Pointer( pass), passlen);
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha1, 0);
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES,
                                            PUTF8Char(  propq), 0);
    p^ := OSSL_PARAM_construct_end();
    rv := EVP_KDF_derive(ctx, key, keylen, @params);
    EVP_KDF_CTX_free(ctx);
    Result := rv;
end;



procedure write_dsa(&out : PPByte;const dsa : PDSA; ispub : integer);
var
  nbyte : integer;

  p,q,g, pub_key,priv_key : PBIGNUM;
begin
    p := nil; q := nil; g := nil;
     pub_key := nil; priv_key := nil;
    DSA_get0_pqg(dsa, @p, @q, @g);
    DSA_get0_key(dsa, @pub_key, @priv_key);
    nbyte := BN_num_bytes(p);
    write_lebn(out, p, nbyte);
    write_lebn(out, q, 20);
    write_lebn(out, g, nbyte);
    if ispub >0 then
       write_lebn(out, pub_key, nbyte)
    else
        write_lebn(out, priv_key, 20);
    { Set 'invalid' for seed structure values }
    memset( out^, $ff, 24);
    out^  := out^ + 24;
    exit;
end;





procedure write_lebn(&out : PPByte;const bn : PBIGNUM; len : integer);
begin
    BN_bn2lebinpad(bn, out^, len);
    out^  := out^ + len;
end;


procedure write_rsa(_out : PPByte;const rsa : PRSA; ispub : integer);
var
  nbyte, hnbyte : integer;
  n, d, e, p, q, iqmp, dmp1, dmq1 : PBIGNUM;
begin
    nbyte := RSA_size(rsa);
    hnbyte := (_RSA_bits(rsa) + 15)  shr  4;
    RSA_get0_key(rsa, @n, @e, @d);
    write_lebn(_out, e, 4);
    write_lebn(_out, n, nbyte);
    if ispub>0 then exit;
    RSA_get0_factors(rsa, @p, @q);
    RSA_get0_crt_params(rsa, @dmp1, @dmq1, @iqmp);
    write_lebn(_out, p, hnbyte);
    write_lebn(_out, q, hnbyte);
    write_lebn(_out, dmp1, hnbyte);
    write_lebn(_out, dmq1, hnbyte);
    write_lebn(_out, iqmp, hnbyte);
    write_lebn(_out, d, nbyte);
end;


procedure write_ledword( &out : PPByte; dw : uint32);
var
  p : PByte;
begin
    p := &out^;
    PostInc(p)^ := dw and $ff;
    PostInc(p)^ := (dw  shr  8) and $ff;
    PostInc(p)^ := (dw  shr  16) and $ff;
    PostInc(p)^ := (dw  shr  24) and $ff;
    &out^ := p;
end;

function ossl_blob_length( bitlen : uint32; isdss, ispub : integer):integer;
var
  nbyte, hnbyte : uint32;
begin
    nbyte := (bitlen + 7)  shr  3;
    hnbyte := (bitlen + 15)  shr  4;
    if isdss>0 then
    begin
        {
         * Expected length: 20 for q + 3 components bitlen each + 24 for seed
         * structure.
         }
        if ispub>0 then
            Exit(44 + 3 * nbyte)
        {
         * Expected length: 20 for q, priv, 2 bitlen components + 24 for seed
         * structure.
         }
        else
            Exit(64 + 2 * nbyte);
    end
    else
    begin
        { Expected length: 4 for 'e' + 'n' }
        if ispub>0 then
           Exit(4 + nbyte)
        else
            {
             * Expected length: 4 for 'e' and 7 other components. 2
             * components are bitlen size, 5 are bitlen/2
             }
            Exit(4 + 2 * nbyte + 5 * hnbyte);
    end;
end;



function check_bitlen_dsa(const dsa : PDSA; ispub : integer; pmagic : Puint32):integer;
var
  bitlen : integer;

  p, q, g, pub_key,priv_key : PBIGNUM;
  label _badkey;
begin
     p := nil; q := nil; g := nil;
     pub_key := nil; priv_key := nil;
    DSA_get0_pqg(dsa, @p, @q, @g);
    DSA_get0_key(dsa, @pub_key, @priv_key);
    bitlen := BN_num_bits(p);
    if ( ((bitlen and 7)>0)  or  (BN_num_bits(q) <> 160) )
         or  (BN_num_bits(g) > bitlen) then
        goto _badkey ;
    if ispub>0 then
    begin
        if BN_num_bits(pub_key) > bitlen then
            goto _badkey ;
        pmagic^ := MS_DSS1MAGIC;
    end
    else
    begin
        if BN_num_bits(priv_key ) > 160 then
            goto _badkey ;
        pmagic^ := MS_DSS2MAGIC;
    end;
    Exit(bitlen);
 _badkey:
    ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_KEY_COMPONENTS);
    Result := 0;
end;



function check_bitlen_rsa(const rsa : PRSA; ispub : integer; pmagic : Puint32):integer;
var
  nbyte, hnbyte, bitlen : integer;

  e, d, p, q, iqmp, dmp1, dmq1 : PBIGNUM;
  label _badkey;
begin
    RSA_get0_key(rsa, nil, @e, nil);
    if BN_num_bits(e) > 32  then
        goto _badkey ;
    bitlen := _RSA_bits(rsa);
    nbyte := RSA_size(rsa);
    hnbyte := (bitlen + 15)  shr  4;
    if ispub>0 then
    begin
        pmagic^ := MS_RSA1MAGIC;
        Exit(bitlen);
    end
    else
    begin
        pmagic^ := MS_RSA2MAGIC;
        {
         * For private key each component must fit within nbyte or hnbyte.
         }
        RSA_get0_key(rsa, nil, nil, @d);
        if BN_num_bytes(d) > nbyte  then
            goto _badkey ;
        RSA_get0_factors(rsa, @p, @q);
        RSA_get0_crt_params(rsa, @dmp1, @dmq1, @iqmp);
        if (BN_num_bytes(iqmp) > hnbyte)
             or  (BN_num_bytes(p) > hnbyte)
             or  (BN_num_bytes(q) > hnbyte)
             or  (BN_num_bytes(dmp1) > hnbyte)
             or  (BN_num_bytes(dmq1) > hnbyte)  then
            goto _badkey ;
    end;
    Exit(bitlen);
 _badkey:
    ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_KEY_COMPONENTS);
    Result := 0;
end;

function do_i2b(&out : PPByte;const pk : PEVP_PKEY; ispub : integer):integer;
var
  p : PByte;
  bitlen,
  magic, keyalg : uint32;
  outlen,noinc : integer;
  label _end;
begin
    bitlen := 0; magic := 0; keyalg := 0;
    outlen := -1; noinc := 0;
    if EVP_PKEY_is_a(pk, 'RSA') then
    begin
        bitlen := check_bitlen_rsa(EVP_PKEY_get0_RSA(pk), ispub, @magic);
        keyalg := MS_KEYALG_RSA_KEYX;
{$IFNDEF OPENSSL_NO_DSA}
    end
    else
    if (EVP_PKEY_is_a(pk, 'DSA')) then
    begin
        bitlen := check_bitlen_dsa(EVP_PKEY_get0_DSA(pk), ispub, @magic);
        keyalg := MS_KEYALG_DSS_SIGN;
{$ENDIF}
    end;
    if bitlen = 0 then
    begin
        goto _end ;
    end;
    outlen := 16 + ossl_blob_length(bitlen, get_result( keyalg = MS_KEYALG_DSS_SIGN , 1 , 0), ispub);
    if &out = nil then goto _end ;
    if Assigned(&out^) then
       p := &out^
    else
    begin
        p := OPENSSL_malloc(outlen);
        if p = nil then
        begin
            ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
            outlen := -1;
            goto _end ;
        end;
        &out^ := p;
        noinc := 1;
    end;
    if ispub >0 then
       PostInc(p)^ := MS_PUBLICKEYBLOB
    else
       PostInc(p)^ := MS_PRIVATEKEYBLOB;

    PostInc(p)^ := $2;
    PostInc(p)^ := 0;
    PostInc(p)^ := 0;
    write_ledword(@p, keyalg);
    write_ledword(@p, magic);
    write_ledword(@p, bitlen);
    if keyalg = MS_KEYALG_RSA_KEYX then
       write_rsa(@p, EVP_PKEY_get0_RSA(pk), ispub)
{$IFNDEF OPENSSL_NO_DSA}
    else
        write_dsa(@p, EVP_PKEY_get0_DSA(pk), ispub);
{$ENDIF}
    if 0>= noinc then
      &out^  := &out^ + outlen;
 _end:
    Result := outlen;
end;


function i2b_PVK(&out : PPByte;const pk : PEVP_PKEY; enclevel : integer; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret,
  outlen, pklen    : integer;
  p ,start        : PByte;
  cctx      : PEVP_CIPHER_CTX;
  salt      : PByte;
  rc4       : PEVP_CIPHER;
  psbuf     : array[0..(PEM_BUFSIZE)-1] of byte;
  keybuf    : array[0..19] of Byte;

  enctmplen,
  inlen     : integer;
  label _error;
begin
    ret := -1;
    outlen := 24;
    p := nil; start := nil;
    cctx := nil;
{$IFNDEF OPENSSL_NO_RC4}
    salt := nil;
    rc4 := nil;
{$ENDIF}
    if enclevel>0 then
       outlen  := outlen + PVK_SALTLEN;
    pklen := do_i2b(nil, pk, 0);
    if pklen < 0 then Exit(-1);
    outlen  := outlen + pklen;
    if out = nil then Exit(outlen);
    if out^ <> nil then
    begin
        p := out^;
    end
    else
    begin
        p := OPENSSL_malloc(outlen);
        start := p;
        if p = nil then
        begin
            ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
            Exit(-1);
        end;
    end;
    cctx := EVP_CIPHER_CTX_new();
    if cctx = nil then
       goto _error ;
    write_ledword(@p, MS_PVKMAGIC);
    write_ledword(@p, 0);
    if EVP_PKEY_get_id(pk) = EVP_PKEY_RSA  then
        write_ledword(@p, MS_KEYTYPE_KEYX)
{$IFNDEF OPENSSL_NO_DSA}
    else
        write_ledword(@p, MS_KEYTYPE_SIGN);
{$ENDIF}
    write_ledword(@p, get_result(enclevel >0, 1 , 0) );
    write_ledword(@p, get_result(enclevel >0, PVK_SALTLEN , 0) );
    write_ledword(@p, pklen);
    if enclevel>0 then
    begin
{$IFNDEF OPENSSL_NO_RC4}
        if RAND_bytes_ex(libctx, p, PVK_SALTLEN, 0) <= 0 then
            goto _error ;
        salt := p;
        p  := p + PVK_SALTLEN;
{$ENDIF}
    end;
    do_i2b(@p, pk, 0);
    if enclevel <> 0 then
    begin
{$IFNDEF OPENSSL_NO_RC4}
        if Assigned(cb) then
            inlen := cb(@psbuf, PEM_BUFSIZE, 1, u)
        else
            inlen := PEM_def_callback(@psbuf, PEM_BUFSIZE, 1, u);
        if inlen <= 0 then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ);
            goto _error ;
        end;
        if 0>= derive_pvk_key(@keybuf, sizeof(keybuf) , salt, PVK_SALTLEN,
                            PByte(@ psbuf), inlen, libctx, propq) then
            goto _error ;
        rc4 := EVP_CIPHER_fetch(libctx, 'RC4', propq);
        if rc4  = nil then
            goto _error ;
        if enclevel = 1 then
           memset( PByte(@keybuf) + 5, 0, 11);
        p := salt + PVK_SALTLEN + 8;
        if 0>= EVP_EncryptInit_ex(cctx, rc4, nil, @keybuf, nil) then
            goto _error ;
        OPENSSL_cleanse(@keybuf, 20);
        if 0>= EVP_EncryptUpdate(cctx, p, @enctmplen, p, pklen - 8) then
            goto _error ;
        if 0>= EVP_EncryptFinal_ex(cctx, p + enctmplen, @enctmplen) then
            goto _error ;
{$ELSE} ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_CIPHER);
        goto _error ;
{$ENDIF}
    end;
    if out^ = nil then
       out^ := start;
    ret := outlen;
 _error:
    EVP_CIPHER_CTX_free(cctx);
{$IFNDEF OPENSSL_NO_RC4}
    EVP_CIPHER_free(rc4);
{$ENDIF}
    if out^ = nil then
       OPENSSL_free(Pointer(start));
    Result := ret;
end;

function i2b_PVK_bio_ex(&out : PBIO;const pk : PEVP_PKEY; enclevel : integer; cb : Tpem_password_cb; u : Pointer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  tmp : PByte;

  outlen, wrlen : integer;
begin
    tmp := nil;
    outlen := i2b_PVK(@tmp, pk, enclevel, cb, u, libctx, propq);
    if outlen < 0 then Exit(-1);
    wrlen := BIO_write(&out, tmp, outlen);
    OPENSSL_free(Pointer(tmp));
    if wrlen = outlen then
    begin
        Exit(outlen);
    end;
    ERR_raise(ERR_LIB_PEM, PEM_R_BIO_WRITE_FAILURE);
    Result := -1;
end;


end.
