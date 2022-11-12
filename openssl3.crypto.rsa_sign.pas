unit openssl3.crypto.rsa_sign;
{$I config.inc}
interface
 uses OpenSSL.Api;

 const
 SSL_SIG_LENGTH = 36;
 ASN1_SEQUENCE = $30;
 ASN1_OCTET_STRING = $04;
 ASN1_NULL = $05;
 ASN1_OID = $06;
 digestinfo_mdc2_der: array[0..13] of Byte = (
    ASN1_SEQUENCE, $0c + MDC2_DIGEST_LENGTH,
      ASN1_SEQUENCE, $08,
        ASN1_OID, $04, 2 * 40 + 5, 8, 3, 101,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, MDC2_DIGEST_LENGTH
);
 digestinfo_sha1_der: array[0..14] of Byte = (
    ASN1_SEQUENCE, $0d + SHA_DIGEST_LENGTH,
      ASN1_SEQUENCE, $09,
        ASN1_OID, $05, 1 * 40 + 3, 14, 3, 2, 26,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA_DIGEST_LENGTH
);



digestinfo_sha256_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA256_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $01,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA256_DIGEST_LENGTH
);

digestinfo_sha384_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA384_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $02,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA384_DIGEST_LENGTH
);

digestinfo_sha512_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA512_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $03,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA512_DIGEST_LENGTH
);
digestinfo_sha224_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA224_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $04,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA224_DIGEST_LENGTH
);
digestinfo_sha512_224_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA224_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $05,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA224_DIGEST_LENGTH
);
digestinfo_sha512_256_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA256_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $07,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA256_DIGEST_LENGTH
);
digestinfo_sha3_224_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA224_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $08,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA224_DIGEST_LENGTH
);
digestinfo_sha3_256_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA256_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $06,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA256_DIGEST_LENGTH
);
digestinfo_sha3_384_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA384_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $09,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA384_DIGEST_LENGTH
);
digestinfo_sha3_512_der: array[0..18] of Byte = (
    ASN1_SEQUENCE, $11 + SHA512_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0d,
        ASN1_OID, $09, 2 * 40 + 16, $86, $48, 1, 101, 3, 4, 2, $0a,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, SHA512_DIGEST_LENGTH
);

 digestinfo_md4_der: array[0..17] of Byte = (
    ASN1_SEQUENCE, $10 + MD4_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0c,
        ASN1_OID, $08, 1 * 40 + 2, $86, $48, $86, $f7, $0d, 2, $03,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, MD4_DIGEST_LENGTH
);
digestinfo_md5_der: array[0..17] of Byte = (
    ASN1_SEQUENCE, $10 + MD5_DIGEST_LENGTH,
      ASN1_SEQUENCE, $0c,
        ASN1_OID, $08, 1 * 40 + 2, $86, $48, $86, $f7, $0d, 2, $05,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, MD5_DIGEST_LENGTH
);
digestinfo_ripemd160_der: array[0..14] of Byte = (
    ASN1_SEQUENCE, $0d + RIPEMD160_DIGEST_LENGTH,
      ASN1_SEQUENCE, $09,
        ASN1_OID, $05, 1 * 40 + 3, 36, 3, 2, 1,
        ASN1_NULL, $00,
      ASN1_OCTET_STRING, RIPEMD160_DIGEST_LENGTH
);

function _RSA_sign(_type : integer;const m : PByte; m_len : uint32; sigret : PByte; siglen : Puint32; rsa : PRSA):integer;
 function encode_pkcs1(_out : PPByte; out_len : Psize_t; _type : integer;const m : PByte; m_len : size_t):integer;
function ossl_rsa_digestinfo_encoding( md_nid : integer; len : Psize_t):PByte;
function ossl_rsa_verify(_type : integer; m : PByte; m_len : uint32; rm : PByte; prm_len : Psize_t;const sigbuf : PByte; siglen : size_t; rsa : PRSA):integer;
function digest_sz_from_nid( nid : integer):integer;
function _RSA_verify(&type : integer;const m : PByte; m_len : uint32;const sigbuf : PByte; siglen : uint32; rsa : PRSA):integer;

implementation

uses OpenSSL3.Err, openssl3.crypto.mem;





function _RSA_verify(&type : integer;const m : PByte; m_len : uint32;const sigbuf : PByte; siglen : uint32; rsa : PRSA):integer;
begin
    if Assigned(rsa.meth.rsa_verify) then
       Exit(rsa.meth.rsa_verify(&type, m, m_len, sigbuf, siglen, rsa));
    Result := ossl_rsa_verify(&type, m, m_len, nil, nil, sigbuf, siglen, rsa);
end;




function return(sz: size_t):size_t;
begin
   Result := sz;
end;

function digest_sz_from_nid( nid : integer):integer;

begin
    case nid of
{$IFNDEF FIPS_MODULE}
{$IFNDEF OPENSSL_NO_MDC2}
    NID_mdc2: return(MDC2_DIGEST_LENGTH);

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD2}
    NID_md2: return(MD2_DIGEST_LENGTH);
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
    NID_md4: return(MD4_DIGEST_LENGTH);
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
    NID_md5: return(MD5_DIGEST_LENGTH);
{$ENDIF}
{$IFNDEF OPENSSL_NO_RMD160}
    NID_ripemd160: return(RIPEMD160_DIGEST_LENGTH);
{$ENDIF}
{$ENDIF}
    NID_sha1: return(SHA_DIGEST_LENGTH);
    NID_sha224: return(SHA224_DIGEST_LENGTH);
    NID_sha256: return(SHA256_DIGEST_LENGTH);
    NID_sha384: return(SHA384_DIGEST_LENGTH);
    NID_sha512: return(SHA512_DIGEST_LENGTH);
    NID_sha512_224: return(SHA224_DIGEST_LENGTH);
    NID_sha512_256: return(SHA256_DIGEST_LENGTH);
    NID_sha3_224: return(SHA224_DIGEST_LENGTH);
    NID_sha3_256: return(SHA256_DIGEST_LENGTH);
    NID_sha3_384: return(SHA384_DIGEST_LENGTH);
    NID_sha3_512: return(SHA512_DIGEST_LENGTH);
    else
        Exit(0);
    end;
end;

function ossl_rsa_verify(_type : integer; m : PByte; m_len : uint32; rm : PByte; prm_len : Psize_t;const sigbuf : PByte; siglen : size_t; rsa : PRSA):integer;
var
  len,
  ret         : integer;

  decrypt_len,
  encoded_len : size_t;
  decrypt_buf,encoded : PByte;
  label _err;
begin
    ret := 0;
    encoded_len := 0;
    decrypt_buf := nil; encoded := nil;
    if siglen <> size_t(RSA_size(rsa)) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_WRONG_SIGNATURE_LENGTH);
        Exit(0);
    end;
    { Recover the encoded digest. }
    decrypt_buf := OPENSSL_malloc(siglen);
    if decrypt_buf = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    len := RSA_public_decrypt(int(siglen), sigbuf, decrypt_buf, rsa,
                             RSA_PKCS1_PADDING);
    if len <= 0 then goto _err ;
    decrypt_len := len;
{$IFNDEF FIPS_MODULE}
    if _type = NID_md5_sha1 then
    begin
        {
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         }
        if decrypt_len <> SSL_SIG_LENGTH then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
            goto _err ;
        end;
        if rm <> nil then
        begin
            memcpy(rm, decrypt_buf, SSL_SIG_LENGTH);
            prm_len^ := SSL_SIG_LENGTH;
        end
        else
        begin
            if m_len <> SSL_SIG_LENGTH then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
                goto _err ;
            end;
            if memcmp(decrypt_buf, m, SSL_SIG_LENGTH) <> 0  then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
                goto _err ;
            end;
        end;
    end
    else
    if (_type = NID_mdc2)  and  (decrypt_len = 2 + 16)
       and  (decrypt_buf[0] = $04)  and  (decrypt_buf[1] = $10) then
    begin
        {
         * Oddball MDC2 case: signature can be OCTET STRING. check for correct
         * tag and length octets.
         }
        if rm <> nil then
        begin
            memcpy(rm, decrypt_buf + 2, 16);
            prm_len^ := 16;
        end
        else
        begin
            if m_len <> 16 then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
                goto _err ;
            end;
            if memcmp(m, decrypt_buf + 2, 16) <> 0  then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
                goto _err ;
            end;
        end;
    end
    else
{$endif} { FIPS_MODULE }
    begin
        {
         * If recovering the digest, extract a digest-sized output from the end
         * of |decrypt_buf| for |encode_pkcs1|, then compare the decryption
         * output as in a standard verification.
         }
        if rm <> nil then
        begin
            len := digest_sz_from_nid(_type);
            if len <= 0 then goto _err ;
            m_len := Uint32 (len);
            if m_len > decrypt_len then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);
                goto _err ;
            end;
            m := decrypt_buf + decrypt_len - m_len;
        end;
        { Construct the encoded digest and ensure it matches. }
        if 0>= encode_pkcs1(@encoded, @encoded_len, _type, m, m_len) then
            goto _err ;
        if (encoded_len <> decrypt_len)
                 or  (memcmp(encoded, decrypt_buf, encoded_len) <> 0) then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
            goto _err ;
        end;
        { Output the recovered digest. }
        if rm <> nil then begin
            memcpy(rm, m, m_len);
            prm_len^ := m_len;
        end;
    end;
    ret := 1;
_err:
    OPENSSL_clear_free(encoded, encoded_len);
    OPENSSL_clear_free(decrypt_buf, siglen);
    Result := ret;
end;



function ossl_rsa_digestinfo_encoding( md_nid : integer; len : Psize_t):PByte;
begin
    case md_nid of
{$IFNDEF FIPS_MODULE}
{$IFNDEF OPENSSL_NO_MDC2}

    NID_mdc2:
    begin
      len^ := sizeof(digestinfo_mdc2_der);
      exit( @digestinfo_mdc2_der);
    end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD2}

    NID_md2:
    begin
      len^ := sizeof(digestinfo_md2_der);
      exit( digestinfo_md2_der);
    end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}

    NID_md4:
    begin
      len^ := sizeof(digestinfo_md4_der);
      exit( @digestinfo_md4_der);
    end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}

    NID_md5:
    begin
      len^ := sizeof(digestinfo_md5_der);
      exit( @digestinfo_md5_der);
    end;
{$ENDIF}
{$IFNDEF OPENSSL_NO_RMD160}

    NID_ripemd160:
    begin
      len^ := sizeof(digestinfo_ripemd160_der);
      exit( @digestinfo_ripemd160_der);
    end;
{$ENDIF}
{$endif} { FIPS_MODULE }

    NID_sha1:
    begin
      len^ := sizeof(digestinfo_sha1_der);
      exit( @digestinfo_sha1_der);
    end;

    NID_sha224:
    begin
      len^ := sizeof(digestinfo_sha224_der);
      exit( @digestinfo_sha224_der);
    end;

    NID_sha256:
    begin
      len^ := sizeof(digestinfo_sha256_der);
      exit( @digestinfo_sha256_der);
    end;

    NID_sha384:
    begin
      len^ := sizeof(digestinfo_sha384_der);
      exit( @digestinfo_sha384_der);
    end;

    NID_sha512:
    begin
      len^ := sizeof(digestinfo_sha512_der);
      exit( @digestinfo_sha512_der);
    end;

    NID_sha512_224:
    begin
      len^ := sizeof(digestinfo_sha512_224_der);
      exit( @digestinfo_sha512_224_der);
    end;

    NID_sha512_256:
    begin
      len^ := sizeof(digestinfo_sha512_256_der);
      exit( @digestinfo_sha512_256_der);
    end;

    NID_sha3_224:
    begin
      len^ := sizeof(digestinfo_sha3_224_der);
      exit( @digestinfo_sha3_224_der);
    end;

    NID_sha3_256:
    begin
      len^ := sizeof(digestinfo_sha3_256_der);
      exit( @digestinfo_sha3_256_der);
    end;

    NID_sha3_384:
    begin
      len^ := sizeof(digestinfo_sha3_384_der);
      exit( @digestinfo_sha3_384_der);
    end;

    NID_sha3_512:
    begin
      len^ := sizeof(digestinfo_sha3_512_der);
      exit( @digestinfo_sha3_512_der);
    end;
    else
        Exit(nil);
    end;
end;




function encode_pkcs1(_out : PPByte; out_len : Psize_t; _type : integer;const m : PByte; m_len : size_t):integer;
var
  di_prefix_len,
  dig_info_len  : size_t;

  di_prefix,
  dig_info      : PByte;
begin
    if _type = NID_undef then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_ALGORITHM_TYPE);
        Exit(0);
    end;
    di_prefix := ossl_rsa_digestinfo_encoding(_type, @di_prefix_len);
    if di_prefix = nil then
    begin
        ERR_raise(ERR_LIB_RSA,
                  RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
        Exit(0);
    end;
    dig_info_len := di_prefix_len + m_len;
    dig_info := OPENSSL_malloc(dig_info_len);
    if dig_info = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    memcpy(dig_info, di_prefix, di_prefix_len);
    memcpy(dig_info + di_prefix_len, m, m_len);
    _out^ := dig_info;
    out_len^ := dig_info_len;
    Result := 1;
end;

function _RSA_sign(_type : integer;const m : PByte; m_len : uint32; sigret : PByte; siglen : Puint32; rsa : PRSA):integer;
var
  encrypt_len,
  ret         : integer;

    encoded_len : size_t;

  tmps,
  encoded     : PByte;
  label _err;
begin
    ret := 0;
    encoded_len := 0;
    tmps := nil;
    encoded := nil;
{$IFNDEF FIPS_MODULE}
    if Assigned(rsa.meth.rsa_sign) then
       Exit(rsa.meth.rsa_sign(_type, m, m_len, sigret, siglen, rsa));
{$endif} { FIPS_MODULE }
    { Compute the encoded digest. }
    if _type = NID_md5_sha1 then
    begin
        {
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         }
        if m_len <> SSL_SIG_LENGTH then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
            Exit(0);
        end;
        encoded_len := SSL_SIG_LENGTH;
        encoded := m;
    end
    else
    begin
        if 0>= encode_pkcs1(@tmps, @encoded_len, _type, m, m_len) then
            goto _err ;
        encoded := tmps;
    end;
    if encoded_len + RSA_PKCS1_PADDING_SIZE > size_t (RSA_size(rsa)) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto _err ;
    end;
    encrypt_len := RSA_private_encrypt(int(encoded_len), encoded, sigret, rsa,
                                      RSA_PKCS1_PADDING);
    if encrypt_len <= 0 then goto _err ;
    siglen^ := encrypt_len;
    ret := 1;
_err:
    OPENSSL_clear_free(tmps, encoded_len);
    Result := ret;
end;


end.
