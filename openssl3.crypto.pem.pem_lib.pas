unit openssl3.crypto.pem.pem_lib;

interface
uses OpenSSL.Api, SysUtils;

type
  Theader_status = (
    MAYBE_HEADER,
    IN_HEADER,
    POST_HEADER
  );

const
    LINESIZE = 255;
    MIN_LENGTH = 4;
    BEGINSTR: PUTF8Char ='-----BEGIN ';
    ENDSTR  : PUTF8Char ='-----END ';
    TAILSTR : PUTF8Char ='-----'#10;

    PROC_TYPE = 'Proc-Type:';
    ENCRYPTED = 'ENCRYPTED';
    DEK_INFO  = 'DEK-Info:';
var
    TAILLEN ,
    ENDLEN  ,
    BEGINLEN: int;



function pem_bytes_read_bio_flags(pdata : PPByte; plen : Plong; pnm : PPUTF8Char;const name : PUTF8Char; bp : PBIO; cb : Tpem_password_cb; u : Pointer; flags : uint32):integer;
procedure pem_free( p : Pointer; flags : uint32; num : size_t);
function PEM_read_bio_ex( bp : PBIO; name_out, header : PPUTF8Char; data : PPByte; len_out : Plong; flags : uint32):integer;
function get_name( bp : PBIO;out name : PUTF8Char; flags : uint32):integer;
function pem_malloc( num : integer; flags : uint32):Pointer;
function sanitize_line( linebuf : PUTF8Char; len : integer; flags : uint32; first_call : integer):integer;
function get_header_and_data( bp : PBIO; header, data : PPBIO; name : PUTF8Char; flags : uint32):integer;
function ossl_pem_check_suffix(const pem_str, suffix : PUTF8Char):integer;
function check_pem(const nm, name : PUTF8Char):integer;
function PEM_ASN1_write_bio(i2d : Ti2d_of_void;const name : PUTF8Char; bp : PBIO;const x : Pointer;
                            const enc : PEVP_CIPHER;{const} kstr : PByte; klen : integer;
                            callback : Tpem_password_cb; u : Pointer):integer;
function PEM_def_callback( buf : PUTF8Char; num, rwflag : integer; userdata : Pointer):integer;
function PEM_bytes_read_bio(pdata : PPByte; plen : Plong; pnm : PPUTF8Char;const name : PUTF8Char; bp : PBIO; cb : Tpem_password_cb; u : Pointer):integer;
function PEM_ASN1_read(d2i : Td2i_of_void;const name : PUTF8Char; fp : PFILE; x : PPointer; cb : Tpem_password_cb; u : Pointer):Pointer;
function PEM_ASN1_write(i2d : Ti2d_of_void;const name : PUTF8Char; fp : PFILE;const x : Pointer; enc : PEVP_CIPHER; kstr : PByte; klen : integer; callback : Tpem_password_cb; u : Pointer):int;
procedure PEM_proc_type( buf : PUTF8Char; _type : integer);
procedure PEM_dek_info(buf : PUTF8Char;const _type : PUTF8Char; len : integer;const str : PUTF8Char);
function PEM_write_bio(bp : PBIO;const name, header : PUTF8Char; data : PByte; len : long):integer;
function PEM_get_EVP_CIPHER_INFO(header : PUTF8Char;cipher : PEVP_CIPHER_INFO):integer;
function load_iv( fromp : PPUTF8Char; _to : PByte; num : integer):integer;
function PEM_do_header( cipher : PEVP_CIPHER_INFO; data : PByte; plen : Plong; callback : Tpem_password_cb; u : Pointer):integer;
function PEM_read_bio( bp : PBIO; name, header : PPUTF8Char; data : PPByte; len : Plong):integer;
function PEM_bytes_read_bio_secmem(pdata : PPByte; plen : Plong; pnm : PPUTF8Char;const name : PUTF8Char; bp : PBIO; cb : Tpem_password_cb; u : Pointer):integer;

implementation


uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF}
     openssl3.crypto.mem, OpenSSL3.Err,        openssl3.crypto.mem_sec,
     openssl3.crypto.pem.pem_oth,              openssl3.crypto.evp.evp_lib,
     openssl3.crypto.bio.bio_lib,              openssl3.crypto.bio.bss_file,
     openssl3.crypto.evp.evp_key,              openssl3.crypto.rand.rand_lib,
     openssl3.crypto.evp.legacy_md5,           openssl3.crypto.bio.bio_print,
     openssl3.crypto.evp.evp_enc,              openssl3.crypto.evp.encode,
     openssl3.crypto.asn1.ameth_lib,           openssl3.crypto.engine.eng_init,
     openssl3.crypto.bio.bss_mem,              openssl3.crypto.evp.names,
     openssl3.crypto.o_str,                    OpenSSL3.common,
     openssl3.crypto.ctype;



function PEM_bytes_read_bio_secmem(pdata : PPByte; plen : Plong; pnm : PPUTF8Char;const name : PUTF8Char; bp : PBIO; cb : Tpem_password_cb; u : Pointer):integer;
begin
    Result := pem_bytes_read_bio_flags(pdata, plen, pnm, name, bp, cb, u,
                                    PEM_FLAG_SECURE or PEM_FLAG_EAY_COMPATIBLE);
end;


function PEM_read_bio( bp : PBIO; name, header : PPUTF8Char; data : PPByte; len : Plong):integer;
begin
    Result := PEM_read_bio_ex(bp, name, header, data, len, PEM_FLAG_EAY_COMPATIBLE);
end;

function PEM_do_header( cipher : PEVP_CIPHER_INFO; data : PByte; plen : Plong; callback : Tpem_password_cb; u : Pointer):integer;
var
  ok, keylen : integer;
  len : long;
  ilen : integer;
  ctx : PEVP_CIPHER_CTX;
  key : array[0..(EVP_MAX_KEY_LENGTH)-1] of Byte;
  buf : array[0..(PEM_BUFSIZE)-1] of UTF8Char;
begin
    len := plen^;
    ilen := int(len);
{$IF LONG_MAX > INT_MAX}
    { Check that we did not truncate the length }
    if len > INT_MAX then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_HEADER_TOO_LONG);
        Exit(0);
    end;
{$ENDIF}
    if cipher.cipher = nil then
       Exit(1);
    if not Assigned(callback) then
       keylen := PEM_def_callback(buf, PEM_BUFSIZE, 0, u)
    else
        keylen := callback(buf, PEM_BUFSIZE, 0, u);
    if keylen < 0 then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ);
        Exit(0);
    end;
{$IFDEF CHARSET_EBCDIC}
    { Convert the pass phrase from EBCDIC }
    ebcdic2ascii(buf, buf, keylen);
{$ENDIF}
    if 0>= EVP_BytesToKey(cipher.cipher, EVP_md5, @cipher.iv[0],
                        PByte(@buf), keylen, 1, @key, nil) then
        Exit(0);
    ctx := EVP_CIPHER_CTX_new();
    if ctx = nil then Exit(0);
    ok := EVP_DecryptInit_ex(ctx, cipher.cipher, nil, @key, @cipher.iv[0]);
    if ok > 0 then
       ok := EVP_DecryptUpdate(ctx, data, @ilen, data, ilen);
    if ok > 0 then
    begin
        { Squirrel away the length of data decrypted so far. }
        plen^ := ilen;
        ok := EVP_DecryptFinal_ex(ctx, @data[ilen], @ilen);
    end;
    if ok > 0 then
       plen^  := plen^ + ilen
    else
       ERR_raise(ERR_LIB_PEM, PEM_R_BAD_DECRYPT);

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(PUTF8Char(@buf), sizeof(buf));
    OPENSSL_cleanse(PUTF8Char(@key), sizeof(key));
    Result := ok;
end;

function load_iv( fromp : PPUTF8Char; _to : PByte; num : integer):integer;
var
  v, i : integer;
  from : PUTF8Char;
begin
    from := fromp^;
    for i := 0 to num-1 do
        _to[i] := 0;
    num  := num  * 2;
    for i := 0 to num-1 do
    begin
        v := OPENSSL_hexchar2int(from^);
        if v < 0 then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_IV_CHARS);
            Exit(0);
        end;
        Inc(from);
        _to[i div 2]  := _to[i div 2]  or (v  shl  long((not (i and 1)) * 4));
    end;
    fromp^ := from;
    Result := 1;
end;


function PEM_get_EVP_CIPHER_INFO(header : PUTF8Char;cipher : PEVP_CIPHER_INFO):integer;
var
    enc          : PEVP_CIPHER;
    ivlen        : integer;
    dekinfostart : PUTF8Char;
    c :UTF8Char;
begin
    enc := nil;
    cipher.cipher := nil;
    memset(@cipher.iv, 0, sizeof(cipher.iv));
    if (header = nil)  or  ( header^ = #0)  or  ( header^ = #10) then
        Exit(1);
    if 0>= CHECK_AND_SKIP_PREFIX(header, PROC_TYPE) then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_NOT_PROC_TYPE);
        Exit(0);
    end;
    header  := header + (strspn(header, ' '#9));
    if (PostInc(header)^  <> '4')  or  (PostInc(header)^ <> ',')then
        Exit(0);
    header  := header + (strspn(header, ' '#9));
    { We expect 'ENCRYPTED' followed by optional white-space + line break }
    if (0>= CHECK_AND_SKIP_PREFIX(header, ENCRYPTED))  or
       (strspn(header, ' '#9#13#10) = 0) then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_NOT_ENCRYPTED);
        Exit(0);
    end;
    header  := header + (strspn(header, ' '#9#13));
    if PostInc(header)^  <> #10 then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_SHORT_HEADER);
        Exit(0);
    end;
    {-
     * https://tools.ietf.org/html/rfc1421#section-4.6.1.3
     * We expect 'DEK-Info: algo[,hex-parameters]'
     }
    if 0>= CHECK_AND_SKIP_PREFIX(header, DEK_INFO) then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_NOT_DEK_INFO);
        Exit(0);
    end;
    header  := header + (strspn(header, ' '#9));
    {
     * DEK-INFO is a comma-separated combination of algorithm name and optional
     * parameters.
     }
    dekinfostart := header;
    header  := header + strcspn(header, ' '#9',');
    c := header^;
    header^ := #0;
    enc := EVP_get_cipherbyname(dekinfostart);
    cipher.cipher := enc;
    header^ := c;
    header  := header + (strspn(header, ' '#9));
    if enc = nil then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_ENCRYPTION);
        Exit(0);
    end;
    ivlen := EVP_CIPHER_get_iv_length(enc);
    if (ivlen > 0)  and  (PostInc(header)^ <> ',') then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_MISSING_DEK_IV);
        Exit(0);
    end
    else
    if (ivlen = 0)  and  (header^ = ',') then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_UNEXPECTED_DEK_IV);
        Exit(0);
    end;
    if 0>= load_iv(@header, @cipher.iv,
                   EVP_CIPHER_get_iv_length(enc)) then
        Exit(0);
    Result := 1;
end;

function PEM_write_bio(bp : PBIO;const name, header : PUTF8Char; data : PByte; len : long):integer;
var
  nlen, n, i, j, outl : integer;
  buf : PByte;
  ctx : PEVP_ENCODE_CTX;
  reason, retval : integer;
  label _err;
begin
    buf := nil;
    ctx := EVP_ENCODE_CTX_new();
    reason := ERR_R_BUF_LIB;
    retval := 0;
    if ctx = nil then
    begin
        reason := ERR_R_MALLOC_FAILURE;
        goto _err ;
    end;
    EVP_EncodeInit(ctx);
    nlen := Length(name);
    if (BIO_write(bp, PUTF8Char('-----BEGIN '), 11) <> 11)   or
        (BIO_write(bp, name, nlen) <> nlen)  or
        (BIO_write(bp, PUTF8Char('-----'#10), 6) <> 6)  then
        goto _err ;
    i := Length(header);
    if i > 0 then
    begin
        if (BIO_write(bp, header, i) <> i)  or  (BIO_write(bp, PUTF8Char(#10), 1) <> 1) then
            goto _err ;
    end;
    buf := OPENSSL_malloc(PEM_BUFSIZE * 8);
    if buf = nil then
    begin
        reason := ERR_R_MALLOC_FAILURE;
        goto _err ;
    end;
    i := 0; j := 0;
    while len > 0 do
    begin
        n := int (get_result(len > PEM_BUFSIZE * 5, PEM_BUFSIZE * 5 , len));
        if 0>= EVP_EncodeUpdate(ctx, buf, @outl, @data[j], n)  then
            goto _err ;
        if (outl > 0)  and  (BIO_write(bp, PUTF8Char(buf), outl) <> outl) then
            goto _err ;
        i  := i + outl;
        len  := len - n;
        j  := j + n;
    end;
    EVP_EncodeFinal(ctx, buf, @outl);
    if (outl > 0)  and  (BIO_write(bp, PUTF8Char(buf), outl) <> outl) then
        goto _err ;
    if (BIO_write(bp, PUTF8Char('-----END '), 9) <> 9)   or
        (BIO_write(bp, name, nlen) <> nlen)  or
        (BIO_write(bp, PUTF8Char('-----'#10), 6) <> 6)  then
        goto _err ;
    retval := i + outl;
 _err:
    if retval = 0 then
       ERR_raise(ERR_LIB_PEM, reason);
    EVP_ENCODE_CTX_free(ctx);
    OPENSSL_clear_free(Pointer(buf), PEM_BUFSIZE * 8);
    Result := retval;
end;

procedure PEM_dek_info(buf : PUTF8Char;const _type : PUTF8Char; len : integer;const str : PUTF8Char);
var
  i : long;
  p : PUTF8Char;
  j, n : integer;
begin
    p := buf + Length(buf);
    j := PEM_BUFSIZE - size_t(p - buf);
    n := BIO_snprintf(p, j, 'DEK-Info: %s,', [_type]);
    if n > 0 then
    begin
        j  := j - n;
        p  := p + n;
        for i := 0 to len-1 do
        begin
            n := BIO_snprintf(p, j, '%02X', [$ff and Ord(str[i])]);
            if n <= 0 then exit;
            j  := j - n;
            p  := p + n;
        end;
        if j > 1 then
           p := #10;
    end;
end;

procedure PEM_proc_type( buf : PUTF8Char; _type : integer);
var
  str, p : PUTF8Char;
begin
    p := buf + Length(buf);
    if _type = PEM_TYPE_ENCRYPTED then
       str := 'ENCRYPTED'
    else if (_type = PEM_TYPE_MIC_CLEAR) then
        str := 'MIC-CLEAR'
    else if (_type = PEM_TYPE_MIC_ONLY) then
        str := 'MIC-ONLY'
    else
        str := 'BAD-TYPE';
    BIO_snprintf(p, PEM_BUFSIZE - size_t(p - buf), 'Proc-Type: 4,%s'#10, [str]);
end;

function PEM_def_callback( buf : PUTF8Char; num, rwflag : integer; userdata : Pointer):integer;
var
  i, min_len : integer;
  prompt : PUTF8Char;
begin
    { We assume that the user passes a default password as userdata }
    if userdata <> nil then
    begin
        i := Length(PUTF8Char(userdata));
        i := get_result(i > num,  num , i);
        memcpy(buf, userdata, i);
        Exit(i);
    end;
    prompt := EVP_get_pw_prompt();
    if prompt = nil then
       prompt := 'Enter PEM pass phrase:';
    {
     * rwflag = 0 means decryption
     * rwflag = 1 means encryption
     *
     * We assume that for encryption, we want a minimum length, while for
     * decryption, we cannot know any minimum length, so we assume zero.
     }
    min_len := get_result(rwflag>0 , MIN_LENGTH , 0);
    i := EVP_read_pw_string_min(buf, min_len, num, prompt, rwflag);
    if i <> 0 then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_PROBLEMS_GETTING_PASSWORD);
        memset(buf, 0, uint32( num));
        Exit(-1);
    end;
    Result := Length(buf);
end;

function PEM_ASN1_write(i2d : Ti2d_of_void;const name : PUTF8Char; fp : PFILE;const x : Pointer; enc : PEVP_CIPHER; kstr : PByte; klen : integer; callback : Tpem_password_cb; u : Pointer):int;
var
  b : PBIO;
  ret : integer;
begin
    b := BIO_new(BIO_s_file);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_BUF_LIB);
        Exit(0);
    end;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret := PEM_ASN1_write_bio(i2d, name, b, x, enc, kstr, klen, callback, u);
    BIO_free(b);
    Result := ret;
end;

function PEM_ASN1_write_bio(i2d : Ti2d_of_void;const name : PUTF8Char; bp : PBIO;const x : Pointer;
                            const enc : PEVP_CIPHER;{const} kstr : PByte; klen : integer;
                            callback : Tpem_password_cb; u : Pointer):integer;
var
  ctx : PEVP_CIPHER_CTX;
  dsize, i, j, ret : integer;
  p, data : PByte;
  objstr : PUTF8Char;
  buf : array[0..(PEM_BUFSIZE)-1] of byte;
  key : array[0..(EVP_MAX_KEY_LENGTH)-1] of Byte;
  iv :  array[0..(EVP_MAX_IV_LENGTH)-1] of Byte;
  label _err;
begin
    ctx := nil;
    dsize := 0; i := 0; j := 0; ret := 0;
    data := nil;
    objstr := nil;
    if enc <> nil then
    begin
        objstr := EVP_CIPHER_get0_name(enc);
        if (objstr = nil)  or  (EVP_CIPHER_get_iv_length(enc) = 0)
                 or  (EVP_CIPHER_get_iv_length(enc) > int (sizeof(iv)))
                   {
                    * Check 'Proc-Type: 4,Encrypted\nDEK-Info: objstr,hex-iv\n'
                    * fits into buf
                    }
                 or ( Length(objstr) + 23 + 2 * EVP_CIPHER_get_iv_length(enc) + 13
                   > sizeof(buf))  then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_CIPHER);
            goto _err ;
        end;
    end;

    dsize := i2d(x, nil);
    if dsize <= 0 then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_ASN1_LIB);
        dsize := 0;
        goto _err ;
    end;
    { dsize + 8 bytes are needed }
    { actually it needs the cipher block size extra... }
    data := OPENSSL_malloc(uint32( dsize + 20));
    if data = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    p := data;
    i := i2d(x, @p);
    if enc <> nil then
    begin
        if kstr = nil then
        begin
            if not Assigned(callback) then
                klen := PEM_def_callback(@buf, PEM_BUFSIZE, 1, u)
            else
                klen := callback(@buf, PEM_BUFSIZE, 1, u);
            if klen <= 0 then
            begin
                ERR_raise(ERR_LIB_PEM, PEM_R_READ_KEY);
                goto _err ;
            end;
{$IFDEF CHARSET_EBCDIC}
            { Convert the pass phrase from EBCDIC }
            ebcdic2ascii(buf, buf, klen);
{$ENDIF}
            kstr := @buf;
        end;
        { Generate a salt }
        if RAND_bytes(@iv, EVP_CIPHER_get_iv_length(enc))  <= 0  then
            goto _err ;
        {
         * The 'iv' is used as the iv and as a salt.  It is NOT taken from
         * the BytesToKey function
         }
        if 0>= EVP_BytesToKey(enc, EVP_md5 , @iv, kstr, klen, 1, @key, nil)  then
            goto _err ;
        if kstr = PByte(@ buf) then
           OPENSSL_cleanse(@buf, PEM_BUFSIZE);
        buf[0] := Ord(#0);
        PEM_proc_type(@buf, PEM_TYPE_ENCRYPTED);
        PEM_dek_info(@buf, objstr, EVP_CIPHER_get_iv_length(enc), PUTF8Char(@iv));
        { k=Length(buf); }
        ret := 1;
        ctx := EVP_CIPHER_CTX_new();

        if  (ctx = nil)
             or  (0>= EVP_EncryptInit_ex(ctx, enc, nil, @key, @iv))
             or  (0>= EVP_EncryptUpdate(ctx, data, @j, data, i))
             or  (0>= EVP_EncryptFinal_ex(ctx, @data[j], @i)) then
            ret := 0;
        if ret = 0 then goto _err ;
        i  := i + j;
    end
    else
    begin
        ret := 1;
        buf[0] := Ord(#0);
    end;
    i := PEM_write_bio(bp, name, @buf, data, i);
    if i <= 0 then ret := 0;
 _err:
    OPENSSL_cleanse(@key, sizeof(key));
    OPENSSL_cleanse(@iv, sizeof(iv));
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(@buf, PEM_BUFSIZE);
    OPENSSL_clear_free(Pointer(data), uint32( dsize));
    Result := ret;
end;



function PEM_ASN1_read(d2i : Td2i_of_void;const name : PUTF8Char; fp : PFILE; x : PPointer; cb : Tpem_password_cb; u : Pointer):Pointer;
var
  b : PBIO;

  ret : Pointer;
begin
    b := BIO_new(BIO_s_file);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_BUF_LIB);
        Exit(0);
    end;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret := PEM_ASN1_read_bio(d2i, name, b, x, cb, u);
    BIO_free(b);
    Result := ret;
end;




function ossl_pem_check_suffix(const pem_str, suffix : PUTF8Char):integer;
var
  pem_len,
  suffix_len : integer;
  p          : PUTF8Char;
begin
    pem_len := Length(pem_str);
    suffix_len := Length(suffix);
    if suffix_len + 1 >= pem_len then Exit(0);
    p := pem_str + pem_len - suffix_len;
    if strcmp(p, suffix)>0 then
        Exit(0);
    Dec(p);
    if p^ <> ' ' then Exit(0);
    Result := p - pem_str;
end;




function check_pem(const nm, name : PUTF8Char):integer;
var
  slen : integer;
  ameth: PEVP_PKEY_ASN1_METHOD;
  e : PENGINE;

  r : integer;
begin
    { Normal matching nm and name }
    if strcmp(nm, name ) = 0 then
        Exit(1);
    { Make PEM_STRING_EVP_PKEY match any private key }
    if strcmp(name, PEM_STRING_EVP_PKEY )= 0 then
    begin
        if strcmp(nm, PEM_STRING_PKCS8) = 0 then
            Exit(1);
        if strcmp(nm, PEM_STRING_PKCS8INF ) = 0 then
            Exit(1);
        slen := ossl_pem_check_suffix(nm, 'PRIVATE KEY');
        if slen > 0 then begin
            {
             * NB: ENGINE implementations won't contain a deprecated old
             * private key decode function so don't look for them.
             }
            ameth := EVP_PKEY_asn1_find_str(nil, nm, slen);
            if (Assigned(ameth))  and  ( Assigned(ameth.old_priv_decode) ) then
               Exit(1);
        end;
        Exit(0);
    end;
    if strcmp(name, PEM_STRING_PARAMETERS ) = 0 then
    begin
        slen := ossl_pem_check_suffix(nm, 'PARAMETERS');
        if slen > 0 then
        begin
            ameth := EVP_PKEY_asn1_find_str(@e, nm, slen);
            if ameth <> nil then
            begin
                if Assigned(ameth.param_decode) then
                    r := 1
                else
                    r := 0;
{$IFNDEF OPENSSL_NO_ENGINE}
                ENGINE_finish(e);
{$ENDIF}
                Exit(r);
            end;
        end;
        Exit(0);
    end;
    { If reading DH parameters handle X9.42 DH format too }
    if ( strcmp(nm, PEM_STRING_DHXPARAMS) = 0)
         and  (strcmp(name, PEM_STRING_DHPARAMS) = 0)  then
        Exit(1);
    { Permit older strings }
    if (strcmp(nm, PEM_STRING_X509_OLD) = 0)
         and  (strcmp(name, PEM_STRING_X509) = 0)  then
        Exit(1);
    if (strcmp(nm, PEM_STRING_X509_REQ_OLD ) = 0)
         and  (strcmp(name, PEM_STRING_X509_REQ) = 0) then
        Exit(1);
    { Allow normal certs to be read as trusted certs }
    if (strcmp(nm, PEM_STRING_X509) = 0)
         and  (strcmp(name, PEM_STRING_X509_TRUSTED) = 0) then
        Exit(1);
    if (strcmp(nm, PEM_STRING_X509_OLD ) = 0)
         and  (strcmp(name, PEM_STRING_X509_TRUSTED) = 0) then
        Exit(1);
    { Some CAs use PKCS#7 with CERTIFICATE headers }
    if (strcmp(nm, PEM_STRING_X509 ) = 0)
         and  (strcmp(name, PEM_STRING_PKCS7) = 0)  then
        Exit(1);
    if (strcmp(nm, PEM_STRING_PKCS7_SIGNED) = 0 )
         and  (strcmp(name, PEM_STRING_PKCS7) = 0) then
        Exit(1);
{$IFNDEF OPENSSL_NO_CMS}
    if (strcmp(nm, PEM_STRING_X509) = 0)
         and  (strcmp(name, PEM_STRING_CMS) = 0) then
        Exit(1);
    { Allow CMS to be read from PKCS#7 headers }
    if (strcmp(nm, PEM_STRING_PKCS7) = 0)
         and  (strcmp(name, PEM_STRING_CMS) = 0) then
        Exit(1);
{$ENDIF}
    Result := 0;
end;

function get_header_and_data( bp : PBIO; header, data : PPBIO; name : PUTF8Char; flags : uint32):integer;
var
  tmp        : PBIO;
  linebuf,
  p          : PUTF8Char;
  len, line,
  ret, _end,
  prev_partial_line_read,
  partial_line_read         : integer;
  got_header : Theader_status;
  dbgcount,
  flags_mask : uint32;
  namelen    : size_t;
  bbm :PBIO_BUF_MEM;
  bm: PBUF_MEM;
  label _err;
begin
    tmp := header^;
    ret := 0; _end := 0; prev_partial_line_read := 0; partial_line_read := 0;
    { 0 if not seen (yet), 1 if reading header, 2 if finished header }
    got_header := MAYBE_HEADER;
    { Need to hold trailing NUL (accounted for by BIO_gets() and the newline
     * that will be added by sanitize_line() (the extra '1'). }
    linebuf := pem_malloc(LINESIZE + 1, flags);
    if linebuf = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    line := 0; dbgcount := 0;
    while true do
    begin
        flags_mask := not UINT32(0);
        len := BIO_gets(bp, linebuf, LINESIZE);
        if len <= 0 then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_END_LINE);
            goto _err ;
        end;
        {
         * Check if line has been read completely or if only part of the line
         * has been read. Keep the previous value to ignore newlines that
         * appear due to reading a line up until the char before the newline.
         }
        prev_partial_line_read := partial_line_read;
        partial_line_read := Int( (len = LINESIZE-1)  and  (linebuf[LINESIZE-2] <> #10));
        if got_header = MAYBE_HEADER then
        begin
            if memchr(linebuf, ':', len) <> nil then
                got_header := IN_HEADER;
        end;
        if (HAS_PREFIX(linebuf, ENDSTR))  or  (got_header = IN_HEADER)  then
            flags_mask := flags_mask and (not PEM_FLAG_ONLY_B64);
        len := sanitize_line(linebuf, len, flags and flags_mask, 0);
        { Check for end of header. }
        if linebuf[0] = #10 then
        begin
            {
             * If previous line has been read only partially this newline is a
             * regular newline at the end of a line and not an empty line.
             }
            if 0>= prev_partial_line_read then
            begin
                if got_header = POST_HEADER then
                begin
                    { Another blank line is an error. }
                    ERR_raise(ERR_LIB_PEM, PEM_R_BAD_END_LINE);
                    goto _err ;
                end;
                got_header := POST_HEADER;
                tmp := data^;
            end;
            continue;
        end;
        { Check for end of stream (which means there is no header). }
        p := linebuf;
        if CHECK_AND_SKIP_PREFIX(p, ENDSTR )>0 then
        begin
            namelen := Strlen(name);
            if (strncmp(p, name, namelen) <> 0)  or
                 (not HAS_PREFIX(p + namelen, TAILSTR)) then
            begin
                ERR_raise(ERR_LIB_PEM, PEM_R_BAD_END_LINE);
                goto _err ;
            end;
            if got_header = MAYBE_HEADER then
            begin
                header^ := data^;
                data^ := tmp;
            end;
            break;
        end
        else
        if (_end > 0) then
        begin
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_END_LINE);
            goto _err ;
        end;
        { Else, a line of text -- could be header or data; we don't
          know yet.  Just pass it through.
         }

        if BIO_puts(tmp, linebuf) < 0 then
            goto _err ;
        {
         * Only encrypted files need the line length check applied.
         }
        if got_header = POST_HEADER then
        begin
            { 65 includes the trailing newline }
            if len > 65 then
                goto _err ;
            if len < 65 then _end := 1;
        end;
        Inc(line);
    end; //-->while true do
    header^.ptrinfo := tmp.ptrinfo;
    data^.ptrinfo := tmp.ptrinfo;
    // Added by Administrator 2022-09-24 15:44:03
    {
    if bp.ptrinfo.Name = 'POSSL_CORE_BIO' then
    begin
       bbm := POSSL_CORE_BIO(bp.ptr).bio.ptr;
       bm := bbm.buf;
       bm.data := @bm.buffer[0];
    end;
    if bp.ptrinfo.Name = 'PBIO_BUF_MEM' then
    begin
       bbm := PBIO_BUF_MEM(bp.ptr);
       bm := bbm.buf;
       bm.data := @bm.buffer[0];
    end; }
    ret := 1;

_err:
    pem_free(linebuf, flags, LINESIZE + 1);
    Result := ret;
end;

function sanitize_line( linebuf : PUTF8Char; len : integer; flags : uint32; first_call : integer):integer;
var
  i : integer;
const // 1d arrays
  utf8_bom : array[0..2] of Byte = (
    $EF, $BB, $BF );
begin
    if first_call>0 then
    begin
        { Other BOMs imply unsupported multibyte encoding,
         * so don't strip them and let the error raise }

        if (len > 3)  and  (memcmp(linebuf, @utf8_bom, 3)= 0)  then
        begin
            memmove(linebuf, linebuf + 3, len - 3);
            linebuf[len - 3] := Chr(0);
            len  := len - 3;
        end;
    end;
    if (flags and PEM_FLAG_EAY_COMPATIBLE)>0 then
    begin
        { Strip trailing whitespace }
        while (len >= 0)  and  (linebuf[len] <= ' ') do
            Dec(len);
        { Go back to whitespace before applying uniform line ending. }
        Inc(len);
    end
    else
    if (flags and PEM_FLAG_ONLY_B64)>0 then
    begin
        for i := 0 to len-1 do
        begin
            if (not ossl_isbase64(linebuf[i]) )  or  (linebuf[i] = #10)
                 or  (linebuf[i] = #13)  then
                break;
        end;
        len := i;
    end
    else
    begin
        { EVP_DecodeBlock strips leading and trailing whitespace, so just strip
         * control characters in-place and let everything through. }
        for i := 0 to len-1 do
        begin
            if (linebuf[i] = #10)  or  (linebuf[i] = #13) then break;
            if ossl_iscntrl(linebuf[i] ) then
                linebuf[i] := ' ';
        end;
        len := i;
    end;
    { The caller allocated LINESIZE+1, so this is safe. }
    linebuf[PostInc(len)] := #10;
    linebuf[len] := #0;
    Result := len;
end;

function pem_malloc( num : integer; flags : uint32):Pointer;
begin
    if (flags and PEM_FLAG_SECURE) >0 then
       Exit(OPENSSL_secure_malloc(num))
    else
       Result := OPENSSL_malloc(num);
end;

function get_name( bp : PBIO;out name : PUTF8Char; flags : uint32):integer;
var
  linebuf    : PUTF8Char;
  ret,
  len,
  first_call : integer;
  label _err;
begin
    ret := 0;
    first_call := 1;
    {
     * Need to hold trailing NUL (accounted for by BIO_gets() and the newline
     * that will be added by sanitize_line() (the extra '1').
     }
    linebuf := pem_malloc(LINESIZE + 1, flags);
    if linebuf = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    while true do
    begin
        len := BIO_gets(bp, linebuf, LINESIZE);
        if len <= 0 then begin
            ERR_raise(ERR_LIB_PEM, PEM_R_NO_START_LINE);
            goto _err ;
        end;
        { Strip trailing garbage and standardize ending. }
        len := sanitize_line(linebuf, len, (flags and (not PEM_FLAG_ONLY_B64)), first_call);
        first_call := 0;
        { Allow leading empty or non-matching lines. }
       if  (HAS_PREFIX(linebuf, BEGINSTR) = false)
                or  (len < TAILLEN)
                or  (HAS_PREFIX(linebuf + len - TAILLEN, TAILSTR) = False) then
           Continue
       else
           Break;
    end;
    linebuf[len - TAILLEN] := #0;
    len := len - BEGINLEN - TAILLEN + 1;
    name := pem_malloc(len, flags);
    if name = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    memcpy( name, linebuf + BEGINLEN, len);
    ret := 1;
_err:
    pem_free(linebuf, flags, LINESIZE + 1);
    Result := ret;
end;

function PEM_read_bio_ex( bp : PBIO; name_out, header : PPUTF8Char; data : PPByte; len_out : Plong; flags : uint32):integer;
var
  ctx       : PEVP_ENCODE_CTX;
  bmeth     : PBIO_METHOD;
  headerB,
  dataB     : PBIO;
  name      : PUTF8Char;
  len, up, fin,
  taillen,
  headerlen,
  ret       : integer;
  buf_mem   : PBUF_MEM;
  pp, pm: Pointer;
  label _end;
begin
    ctx := nil;
    headerB := nil;
    dataB := nil;
    name := nil;
    ret := 0;
    len_out^ := 0;
    name_out^ := nil; header^ := nil;
    data^ := nil;
    if ( (flags and PEM_FLAG_EAY_COMPATIBLE)>0 )  and ( (flags and PEM_FLAG_ONLY_B64)>0 ) then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_PASSED_INVALID_ARGUMENT);
        goto _end ;
    end;
    if (flags and PEM_FLAG_SECURE)>0 then
        bmeth :=  BIO_s_secmem()
    else
        bmeth :=  BIO_s_mem();

    headerB := BIO_new(bmeth);
    dataB := BIO_new(bmeth);
    
    if (headerB = nil)  or  (dataB = nil) then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _end ;
    end;
    if 0>= get_name(bp, name, flags) then
        goto _end ;
    if 0>= get_header_and_data(bp, @headerB, @dataB, name, flags) then
        goto _end ;

    BIO_get_mem_ptr(dataB, @buf_mem);
    buf_mem.data := @buf_mem.buffer[0];
    len := buf_mem.length;
    { There was no data in the PEM file }
    if len = 0 then goto _end ;

    ctx := EVP_ENCODE_CTX_new();
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _end ;
    end;

    EVP_DecodeInit(ctx);
    up := EVP_DecodeUpdate(ctx, @buf_mem.buffer[0], @len,  PByte(buf_mem.data), len);
    fin := EVP_DecodeFinal(ctx,  @buf_mem.buffer[len],  @taillen);

    if (up < 0 ) or (fin < 0) then
    begin
        ERR_raise(ERR_LIB_PEM, PEM_R_BAD_BASE64_DECODE);
        goto _end ;
    end;
    len  := len + taillen;
    buf_mem.length := len;

    headerlen := BIO_get_mem_data(headerB, nil);
    header^ := pem_malloc(headerlen + 1, flags);
    data^ := pem_malloc(len, flags);
    if (header^ = nil)  or  (data^ = nil) then
    begin
        pem_free( header^, flags, 0);
        pem_free( data^, flags, 0);
        goto _end ;
    end;
    BIO_read(headerB, header^, headerlen);
    header^[headerlen] := #0;
    BIO_read(dataB, data^, len);
    len_out^ := len;
    name_out^ := name;
    name := nil;
    ret := 1;

_end:
    EVP_ENCODE_CTX_free(ctx);
    pem_free(name, flags, 0);
    if headerB.ptrinfo.Name = 'PBIO_BUF_MEM' then
    begin
       if PBIO_BUF_MEM(headerB.ptr).buf.length > 0 then
          SetLength(PBIO_BUF_MEM(headerB.ptr).buf.buffer, 0);
       if PBIO_BUF_MEM(dataB.ptr).buf.length > 0 then
          SetLength(PBIO_BUF_MEM(dataB.ptr).buf.buffer, 0);
    end;
    BIO_free(headerB);
    BIO_free(dataB);
    Result := ret;
end;




procedure pem_free( p : Pointer; flags : uint32; num : size_t);
begin
    if (flags and PEM_FLAG_SECURE)> 0 then
       OPENSSL_secure_clear_free(p, num)
    else
        OPENSSL_free(p);
end;

function pem_bytes_read_bio_flags(pdata : PPByte; plen : Plong; pnm : PPUTF8Char;const name : PUTF8Char; bp : PBIO; cb : Tpem_password_cb; u : Pointer; flags : uint32):integer;
var
  cipher : TEVP_CIPHER_INFO;
  nm, header : PUTF8Char;
  data : PByte;
  len : long;
  ret : integer;
  label _err;
begin
    nm := nil;
    header := nil;
    data := nil;
    len := 0;
    ret := 0;
    repeat
        pem_free(nm, flags, 0);
        pem_free(header, flags, 0);
        pem_free(data, flags, len);
        if 0>= PEM_read_bio_ex(bp, @nm, @header, @data, @len, flags) then
        begin
            if ERR_GET_REASON(ERR_peek_error) = PEM_R_NO_START_LINE then
                ERR_add_error_data(2, ['Expecting: ', name]);
            Exit(0);
        end;
    until not (0>= check_pem(nm, name));

    if 0>= PEM_get_EVP_CIPHER_INFO(header, @cipher) then
        goto _err ;
    if 0>= PEM_do_header(@cipher, data, @len, cb, u) then
        goto _err ;
    pdata^ := data;
    plen^ := len;
    if pnm <> nil then pnm^ := nm;
    ret := 1;

 _err:
    if (0>= ret)  or  (pnm = nil) then
       pem_free(nm, flags, 0);
    pem_free(header, flags, 0);
    if 0>= ret then pem_free(data, flags, len);
    Result := ret;
end;


function PEM_bytes_read_bio(pdata : PPByte; plen : Plong; pnm : PPUTF8Char;const name : PUTF8Char; bp : PBIO; cb : Tpem_password_cb; u : Pointer):integer;
begin
    Exit(pem_bytes_read_bio_flags(pdata, plen, pnm, name, bp, cb, u,
                                    PEM_FLAG_EAY_COMPATIBLE));
end;

initialization
  TAILLEN  := int(StrSize(TAILSTR) - 1);
  ENDLEN   := int(StrSize(ENDSTR) - 1);
  BEGINLEN := int(StrSize(BEGINSTR) - 1);


end.
