unit openssl3.crypto.pkcs12.p12_key;

interface
uses OpenSSL.Api;

 function PKCS12_key_gen_asc_ex(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function PKCS12_key_gen_asc(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD):integer;
  function PKCS12_key_gen_utf8_ex(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function PKCS12_key_gen_utf8(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD):integer;
  function PKCS12_key_gen_uni_ex(pass : PByte; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function PKCS12_key_gen_uni(pass : PByte; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD):integer;
   function OPENSSL_utf82uni(const asc : PUTF8Char; asclen : integer; uni : PPByte; unilen : PInteger):PByte;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.evp.kdf_meth,
     openssl3.crypto.evp.kdf_lib, openssl3.crypto.params,
     openssl3.crypto.asn1.a_utf8,
     openssl3.crypto.bio.bio_dump, openssl3.crypto.pkcs12.p12_utl,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.bio.bio_print;






function OPENSSL_utf82uni(const asc : PUTF8Char; asclen : integer; uni : PPByte; unilen : PInteger):PByte;
var
  ulen,
  i, j        : integer;

  unitmp,
  ret      : PByte;
  utf32chr : Cardinal;
  hi, lo       : uint32;
begin
    utf32chr := 0;
    if asclen = -1 then asclen := Length(asc);
    ulen := 0; i := 0;
    while i < asclen do begin
        j := UTF8_getc(PByte(asc+i), asclen-i, @utf32chr);
        {
         * Following condition is somewhat opportunistic is sense that
         * decoding failure is used as *indirect* indication that input
         * string might in fact be extended ASCII/ANSI/ISO-8859-X. The
         * fallback is taken in hope that it would allow to process
         * files created with previous OpenSSL version, which used the
         * naive OPENSSL_asc2uni all along. It might be worth noting
         * that probability of false positive depends on language. In
         * cases covered by ISO Latin 1 probability is very low, because
         * any printable non-ASCII alphabet letter followed by another
         * or any ASCII character will trigger failure and fallback.
         * In other cases situation can be intensified by the fact that
         * English letters are not part of alternative keyboard layout,
         * but even then there should be plenty of pairs that trigger
         * decoding failure...
         }
        if j < 0 then Exit(OPENSSL_asc2uni(asc, asclen, uni, unilen));
        if utf32chr > $10FFFF then { UTF-16 cap }
            Exit(nil);
        if utf32chr >= $10000 then { pair of UTF-16 characters }
            ulen  := ulen + (2*2)
        else                            { or just one }
            ulen  := ulen + 2;
         i := i+j;
    end;
    ulen  := ulen + 2;
    ret := OPENSSL_malloc(ulen);
    if ret = nil then  begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    { re-run the loop writing down UTF-16 characters in big-endian order }
    unitmp := ret; i := 0;
    while i < asclen do
    begin
        j := UTF8_getc(PByte(asc+i), asclen-i, @utf32chr);
        if utf32chr >= $10000 then begin       { pair if UTF-16 characters }
            utf32chr  := utf32chr - $10000;
            hi := $D800 + (utf32chr shr 10);
            lo := $DC00 + (utf32chr and $3ff);
            PostInc(unitmp)^ := Byte(hi shr 8);
            PostInc(unitmp)^ := Byte(hi);
            PostInc(unitmp)^ := Byte(lo shr 8);
            PostInc(unitmp)^ := Byte(lo);
        end
        else begin                         { or just one }
            PostInc(unitmp)^ := Byte(utf32chr shr 8);
            PostInc(unitmp)^ := Byte(utf32chr);
        end;
        i := i+ j;
    end;
    { Make result double null terminated }
    PostInc(unitmp)^ := 0;
    PostInc(unitmp)^ := 0;
    if unilen <> nil then unilen^ := ulen;
    if uni <> nil then uni^ := ret;
    Result := ret;
end;

function PKCS12_key_gen_asc_ex(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;
  unipass : PByte;
  uniplen : integer;
begin
    if pass = nil then
    begin
        unipass := nil;
        uniplen := 0;
    end
    else
    if (nil = OPENSSL_asc2uni(pass, passlen, @unipass, @uniplen)) then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ret := PKCS12_key_gen_uni_ex(unipass, uniplen, salt, saltlen, id, iter,
                                n, &out, md_type, ctx, propq);
    OPENSSL_clear_free(Pointer(unipass), uniplen);
    Result := Int(ret > 0);
end;


function PKCS12_key_gen_asc(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD):integer;
begin
    Exit(PKCS12_key_gen_asc_ex(pass, passlen, salt, saltlen, id, iter, n, &out, md_type, nil, nil));
end;


function PKCS12_key_gen_utf8_ex(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD; ctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : integer;

  unipass : PByte;

  uniplen : integer;
begin
    if pass = nil then
    begin
        unipass := nil;
        uniplen := 0;
    end
    else
    if (nil = OPENSSL_utf82uni(pass, passlen, @unipass, @uniplen)) then
    begin
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ret := PKCS12_key_gen_uni_ex(unipass, uniplen, salt, saltlen, id, iter,
                                n, &out, md_type, ctx, propq);
    OPENSSL_clear_free(Pointer(unipass), uniplen);
    Result := Int(ret > 0);
end;


function PKCS12_key_gen_utf8(const pass : PUTF8Char; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD):integer;
begin
    Exit(PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, id, iter, n,
                                  out, md_type, nil, nil));
end;


function PKCS12_key_gen_uni_ex(pass : PByte; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  res : integer;

  kdf : PEVP_KDF;

  ctx : PEVP_KDF_CTX;

  params : array[0..5] of TOSSL_PARAM;
  trc_out : PBIO ;
  p : POSSL_PARAM;
begin
    res := 0;
    p := @params;
    if n <= 0 then Exit(0);
    kdf := EVP_KDF_fetch(libctx, 'PKCS12KDF', propq);
    if kdf = nil then Exit(0);
    ctx := EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if ctx = nil then Exit(0);
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            PUTF8Char(  EVP_MD_get0_name(md_type)),
                                            0);
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             pass, passlen);
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             salt, saltlen);
    PostInc(p)^ := OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS12_ID, @id);
    PostInc(p)^ := OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, @iter);
    p^ := OSSL_PARAM_construct_end();
    trc_out := nil;
    BIO_printf(trc_out, 'PKCS12_key_gen_uni_ex(): ID %d, ITER %d'#10, [id, iter]);
    BIO_printf(trc_out, 'Password (length %d):'#10, [passlen]);
    BIO_hex_string(trc_out, 0, passlen, pass, passlen);
    BIO_printf(trc_out, #10,[]);
    BIO_printf(trc_out, 'Salt (length %d):'#10, [saltlen]);
    BIO_hex_string(trc_out, 0, saltlen, salt, saltlen);
    BIO_printf(trc_out, #10,[]);


    if EVP_KDF_derive(ctx, out, size_t( n), @params) >0 then
    begin
        res := 1;
        trc_out := nil;
        BIO_printf(trc_out, 'Output KEY (length %d)'#10, [n]);
        BIO_hex_string(trc_out, 0, n, out, n);
        BIO_printf(trc_out, #10, []);

    end;
    EVP_KDF_CTX_free(ctx);
    Result := res;
end;


function PKCS12_key_gen_uni(pass : PByte; passlen : integer; salt : PByte; saltlen, id, iter, n : integer; &out : PByte;const md_type : PEVP_MD):integer;
begin
    Exit(PKCS12_key_gen_uni_ex(pass, passlen, salt, saltlen, id, iter, n, out, md_type, nil, nil));

end;


end.
