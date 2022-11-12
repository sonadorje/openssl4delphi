unit OpenSSL3.crypto.ct.ct_b64;

interface
uses OpenSSL.Api;


  function ct_base64_decode(const _in : PUTF8Char; _out : PPByte):integer;
  function SCT_new_from_base64(version : Byte;const logid_base64 : PUTF8Char; entry_type : ct_log_entry_type_t; timestamp : uint64;const extensions_base64, signature_base64 : PUTF8Char):PSCT;
  function CTLOG_new_from_base64_ex(ct_log : PPCTLOG;const pkey_base64, name : PUTF8Char; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function CTLOG_new_from_base64(ct_log : PPCTLOG;const pkey_base64, name : PUTF8Char):integer;


implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.evp.encode,
     OpenSSL3.crypto.ct.ct_sct, OpenSSL3.crypto.ct.ct_oct,
     openssl3.crypto.evp.p_lib,
     openssl3.crypto.x509.x_pubkey, OpenSSL3.crypto.ct.ct_log ;





function ct_base64_decode(const _in : PUTF8Char; _out : PPByte):integer;
var
  inlen : size_t;
  outlen, i : integer;
  outbuf : PByte;
  label _err;
begin
    inlen := Length(_in);
    outbuf := nil;
    if inlen = 0 then begin
        _out^ := nil;
        Exit(0);
    end;
    outlen := (inlen div 4) * 3;
    outbuf := OPENSSL_malloc(outlen);
    if outbuf = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    outlen := EVP_DecodeBlock(outbuf, PByte( _in), inlen);
    if outlen < 0 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_BASE64_DECODE_ERROR);
        goto _err ;
    end;
    { Subtract padding bytes from |outlen|.  Any more than 2 is malformed. }
    i := 0;
    while _in[PreDec(inlen)] = '=' do
    begin
        PreDec(outlen);
        if PreInc(i)> 2  then
            goto _err ;
    end;
    _out^ := outbuf;
    Exit(outlen);
_err:
    OPENSSL_free(outbuf);
    Result := -1;
end;


function SCT_new_from_base64(version : Byte;const logid_base64 : PUTF8Char; entry_type : ct_log_entry_type_t; timestamp : uint64;const extensions_base64, signature_base64 : PUTF8Char):PSCT;
var
  sct : PSCT;
  dec, p : PByte;
  declen : integer;
  label _err;
begin
    sct := SCT_new();
    dec := nil;
    p := nil;
    if sct = nil then begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    {
     * RFC6962 section 4.1 says we ' MUST NOT expect this to be 0' , but we
     * can only construct SCT versions that have been defined.
     }
    if 0>= SCT_set_version(sct, sct_version_t(version) ) then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_UNSUPPORTED_VERSION);
        goto _err ;
    end;
    declen := ct_base64_decode(logid_base64, @dec);
    if declen < 0 then
    begin
        ERR_raise(ERR_LIB_CT, X509_R_BASE64_DECODE_ERROR);
        goto _err ;
    end;
    if 0>= SCT_set0_log_id(sct, dec, declen) then
        goto _err ;
    dec := nil;
    declen := ct_base64_decode(extensions_base64, @dec);
    if declen < 0 then
    begin
        ERR_raise(ERR_LIB_CT, X509_R_BASE64_DECODE_ERROR);
        goto _err ;
    end;
    SCT_set0_extensions(sct, dec, declen);
    dec := nil;
    declen := ct_base64_decode(signature_base64, @dec);
    if declen < 0 then
    begin
        ERR_raise(ERR_LIB_CT, X509_R_BASE64_DECODE_ERROR);
        goto _err ;
    end;
    p := dec;
    if o2i_SCT_signature(sct, @p, declen) <= 0  then
        goto _err ;
    OPENSSL_free(dec);
    dec := nil;
    SCT_set_timestamp(sct, timestamp);
    if 0>= SCT_set_log_entry_type(sct, entry_type ) then
        goto _err ;
    Exit(sct);
 _err:
    OPENSSL_free(dec);
    SCT_free(sct);
    Result := nil;
end;


function CTLOG_new_from_base64_ex(ct_log : PPCTLOG;const pkey_base64, name : PUTF8Char; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    pkey_der     : PByte;
    pkey_der_len : integer;
    p            : PByte;
    pkey         : PEVP_PKEY;
begin
    pkey_der := nil;
    pkey := nil;
    if ct_log = nil then begin
        ERR_raise(ERR_LIB_CT, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    pkey_der_len := ct_base64_decode(pkey_base64, @pkey_der);
    if pkey_der_len < 0 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_INVALID_KEY);
        Exit(0);
    end;
    p := pkey_der;
    pkey := d2i_PUBKEY_ex(nil, @p, pkey_der_len, libctx, propq);
    OPENSSL_free(pkey_der);
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_INVALID_KEY);
        Exit(0);
    end;
    ct_log^ := CTLOG_new_ex(pkey, name, libctx, propq);
    if ct_log^ = nil then
    begin
        EVP_PKEY_free(pkey);
        Exit(0);
    end;
    Result := 1;
end;


function CTLOG_new_from_base64(ct_log : PPCTLOG;const pkey_base64, name : PUTF8Char):integer;
begin
    Result := CTLOG_new_from_base64_ex(ct_log, pkey_base64, name, nil, nil);
end;


end.
