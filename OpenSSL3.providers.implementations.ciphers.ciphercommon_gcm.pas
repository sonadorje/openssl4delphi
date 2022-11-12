unit OpenSSL3.providers.implementations.ciphers.ciphercommon_gcm;

interface
uses OpenSSL.Api;

procedure ossl_gcm_initctx(provctx : Pointer; ctx : PPROV_GCM_CTX; keybits : size_t;const hw : PPROV_GCM_HW);
function ossl_gcm_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
function gcm_cipher_internal(ctx : PPROV_GCM_CTX; _out : PByte; padlen : Psize_t;const _in : PByte; len : size_t):integer;
function gcm_tls_cipher(ctx : PPROV_GCM_CTX; _out : PByte; padlen : Psize_t;{const} _in : PByte; len : size_t):integer;
function getivgen( ctx : PPROV_GCM_CTX; _out : PByte; olen : size_t):integer;
procedure ctr64_inc( counter : PByte);
function setivinv( ctx : PPROV_GCM_CTX; _in : PByte; inl : size_t):integer;
function gcm_iv_generate( ctx : PPROV_GCM_CTX; offset : integer):integer;
function ossl_gcm_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
function ossl_gcm_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
function ossl_gcm_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function ossl_gcm_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function gcm_tls_init( dat : PPROV_GCM_CTX; aad : PByte; aad_len : size_t):integer;
function gcm_tls_iv_set_fixed( ctx : PPROV_GCM_CTX; iv : PByte; len : size_t):integer;
function ossl_gcm_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
function ossl_gcm_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
function gcm_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;

implementation
uses OpenSSL3.providers.common.provider_ctx,       OpenSSL3.Err,
     openssl3.crypto.rand.rand_lib,                openssl3.crypto.params,
     openssl3.providers.prov_running,              openssl3.crypto.mem;

function gcm_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
  ctx : PPROV_GCM_CTX;
begin
    ctx := PPROV_GCM_CTX(vctx);
    if not ossl_prov_is_running then Exit(0);
    ctx.enc := enc;
    if iv <> nil then
    begin
        if (ivlen = 0)  or  (ivlen > sizeof(ctx.iv)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        ctx.ivlen := ivlen;
        memcpy(@ctx.iv, iv, ivlen);
        ctx.iv_state := IV_STATE_BUFFERED;
    end;
    if key <> nil then
    begin
        if keylen <> ctx.keylen then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>=ctx.hw.setkey(ctx, key, ctx.keylen) then
            Exit(0);
    end;
    Result := ossl_gcm_set_ctx_params(ctx, params);
end;

function ossl_gcm_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := gcm_init(vctx, key, keylen, iv, ivlen, params, 1);
end;


function ossl_gcm_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := gcm_init(vctx, key, keylen, iv, ivlen, params, 0);
end;


function gcm_tls_iv_set_fixed( ctx : PPROV_GCM_CTX; iv : PByte; len : size_t):integer;
begin
    { Special case: -1 length restores whole IV }
    if len = size_t(-1) then
    begin
        memcpy(@ctx.iv, iv, ctx.ivlen);
        ctx.iv_gen := 1;
        ctx.iv_state := IV_STATE_BUFFERED;
        Exit(1);
    end;
    { Fixed field must be at least 4 bytes and invocation field at least 8 }
    if (len < EVP_GCM_TLS_FIXED_IV_LEN) or
       (ctx.ivlen - int(len) < EVP_GCM_TLS_EXPLICIT_IV_LEN) then
            Exit(0);
    if len > 0 then memcpy(@ctx.iv, iv, len);
    if (ctx.enc > 0)
         and  (RAND_bytes_ex(ctx.libctx, PByte(@ctx.iv) + len, ctx.ivlen - len, 0) <= 0)  then
            Exit(0);
    ctx.iv_gen := 1;
    ctx.iv_state := IV_STATE_BUFFERED;
    Result := 1;
end;


function gcm_tls_init( dat : PPROV_GCM_CTX; aad : PByte; aad_len : size_t):integer;
var
  buf : PByte;
  len : size_t;
begin
    if (not ossl_prov_is_running)  or  (aad_len <> EVP_AEAD_TLS1_AAD_LEN) then
       Exit(0);
    { Save the aad for later use. }
    buf := @dat.buf;
    memcpy(buf, aad, aad_len);
    dat.tls_aad_len := aad_len;
    dat.tls_enc_records := 0;
    len := buf[aad_len - 2] shl 8 or buf[aad_len - 1];
    { Correct length for explicit iv. }
    if len < EVP_GCM_TLS_EXPLICIT_IV_LEN then Exit(0);
    len  := len - EVP_GCM_TLS_EXPLICIT_IV_LEN;
    { If decrypting correct for tag too. }
    if 0>=dat.enc then begin
        if len < EVP_GCM_TLS_TAG_LEN then
            Exit(0);
        len  := len - EVP_GCM_TLS_TAG_LEN;
    end;
    buf[aad_len - 2] := Byte(len  shr  8);
    buf[aad_len - 1] := Byte(len and $ff);
    { Extra padding: tag appended to record. }
    Result := EVP_GCM_TLS_TAG_LEN;
end;



function ossl_gcm_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_GCM_CTX;
  p : POSSL_PARAM;
  sz : size_t;
  vp : Pointer;
begin
    ctx := PPROV_GCM_CTX(vctx);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then
    begin
        vp := @ctx.buf;
        if 0>=OSSL_PARAM_get_octet_string(p, vp, EVP_GCM_TLS_TAG_LEN, @sz )then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if (sz = 0)  or  (ctx.enc > 0) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            Exit(0);
        end;
        ctx.taglen := sz;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if p <> nil then
    begin
        if 0>=OSSL_PARAM_get_size_t(p, @sz) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if (sz = 0)  or  (sz > sizeof(ctx.iv)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        ctx.ivlen := sz;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        sz := gcm_tls_init(ctx, p.data, p.data_size);
        if sz = 0 then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_AAD);
            Exit(0);
        end;
        ctx.tls_aad_pad_sz := sz;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if gcm_tls_iv_set_fixed(ctx, p.data, p.data_size) = 0  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
    if p <> nil then
    begin
        if (p.data = nil)
             or  (p.data_type <> OSSL_PARAM_OCTET_STRING)
             or  (0>=setivinv(ctx, p.data, p.data_size)) then
            Exit(0);
    end;
    Result := 1;
end;


function ossl_gcm_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_GCM_CTX;
  p : POSSL_PARAM;
  sz, taglen : size_t;
begin
    ctx := PPROV_GCM_CTX(vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.ivlen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.keylen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if p <> nil then
    begin
        taglen := get_result(ctx.taglen <> UNINITIALISED_SIZET , ctx.taglen , GCM_TAG_MAX_SIZE);
        if 0>=OSSL_PARAM_set_size_t(p, taglen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if p <> nil then
    begin
        if ctx.iv_state = IV_STATE_UNINITIALISED then
            Exit(0);
        if ctx.ivlen > p.data_size then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        if (0>=OSSL_PARAM_set_octet_string(p, @ctx.iv, ctx.ivlen)) and
           (0>=OSSL_PARAM_set_octet_ptr(p, @ctx.iv, ctx.ivlen))  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if p <> nil then begin
        if ctx.iv_state = IV_STATE_UNINITIALISED then
            Exit(0);
        if ctx.ivlen > p.data_size then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        if (0>=OSSL_PARAM_set_octet_string(p, @ctx.iv, ctx.ivlen)) and
           (0>=OSSL_PARAM_set_octet_ptr(p, @ctx.iv, ctx.ivlen))  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.tls_aad_pad_sz)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then
    begin
        sz := p.data_size;
        if (sz = 0)
             or  (sz > EVP_GCM_TLS_TAG_LEN)
             or  (0>=ctx.enc)
             or  (ctx.taglen = UNINITIALISED_SIZET) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            Exit(0);
        end;
        if 0>=OSSL_PARAM_set_octet_string(p, @ctx.buf, sz) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
    if p <> nil then
    begin
        if (p.data = nil)
             or  (p.data_type <> OSSL_PARAM_OCTET_STRING )
             or  (0>=getivgen(ctx, p.data, p.data_size))  then
            Exit(0);
    end;
    Result := 1;
end;

function ossl_gcm_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_GCM_CTX;
begin
    ctx := PPROV_GCM_CTX(vctx);
    if not ossl_prov_is_running then Exit(0);
    if outsize < inl then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if gcm_cipher_internal(ctx, _out, outl, _in, inl) <= 0  then
        Exit(0);
    outl^ := inl;
    Result := 1;
end;




function ossl_gcm_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : PPROV_GCM_CTX;

  i : integer;
begin
    ctx := PPROV_GCM_CTX (vctx);
    if not ossl_prov_is_running then Exit(0);
    i := gcm_cipher_internal(ctx, _out, outl, nil, 0);
    if i <= 0 then Exit(0);
    outl^ := 0;
    Result := 1;
end;


function gcm_iv_generate( ctx : PPROV_GCM_CTX; offset : integer):integer;
var
  sz : integer;
begin
    sz := ctx.ivlen - offset;
    { Must be at least 96 bits }
    if (sz <= 0)  or  (ctx.ivlen < GCM_IV_DEFAULT_SIZE) then
       Exit(0);
    { Use DRBG to generate random iv }
    if RAND_bytes_ex(ctx.libctx, PByte(@ctx.iv) + offset, sz, 0 ) <= 0 then
        Exit(0);
    ctx.iv_state := IV_STATE_BUFFERED;
    ctx.iv_gen_rand := 1;
    Result := 1;
end;


function setivinv( ctx : PPROV_GCM_CTX; _in : PByte; inl : size_t):integer;
begin
    if (0>=ctx.iv_gen)
         or  (0>=ctx.key_set)
         or  (ctx.enc > 0) then
         Exit(0);
    memcpy(PByte(@ctx.iv) + ctx.ivlen - inl, _in, inl);
    if 0>=ctx.hw.setiv(ctx, @ctx.iv, ctx.ivlen) then
        Exit(0);
    ctx.iv_state := IV_STATE_COPIED;
    Result := 1;
end;




procedure ctr64_inc( counter : PByte);
var
  n : integer;
  c : Byte;
begin
    n := 8;
    repeat
        PreDec(n);
        c := counter[n];
        Inc(c);
        counter[n] := c;
        if c > 0 then exit;
    until not (n > 0);
end;



function getivgen( ctx : PPROV_GCM_CTX; _out : PByte; olen : size_t):integer;
begin
    if (0>=ctx.iv_gen)
         or  (0>=ctx.key_set)
         or  (0>=ctx.hw.setiv(ctx, @ctx.iv, ctx.ivlen)) then
        Exit(0);
    if (olen = 0)  or  (olen > ctx.ivlen) then
       olen := ctx.ivlen;
    memcpy(_out, PByte(@ctx.iv) + ctx.ivlen - olen, olen);
    {
     * Invocation field will be at least 8 bytes in size and so no need
     * to check wrap around or increment more than last 8 bytes.
     }
    ctr64_inc(PByte(@ctx.iv) + ctx.ivlen - 8);
    ctx.iv_state := IV_STATE_COPIED;
    Result := 1;
end;


function gcm_tls_cipher(ctx : PPROV_GCM_CTX; _out : PByte; padlen : Psize_t;{const} _in : PByte; len : size_t):integer;
var
  rv : integer;
  arg, plen : size_t;
  tag : PByte;
  label _err;
begin
    rv := 0;
    arg := EVP_GCM_TLS_EXPLICIT_IV_LEN;
    plen := 0;
    tag := nil;
    if (not ossl_prov_is_running)  or  (0>=ctx.key_set) then
        goto _err;
    { Encrypt/decrypt must be performed in place }
    if (_out <> _in)  or  (len < EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) then
        goto _err;
    {
     * Check for too many keys as per FIPS 140-2 IG A.5 'Key/IV Pair Uniqueness
     * Requirements from SP 800-38D'.  The requirements is for one party to the
     * communication to fail after 2^64 - 1 keys.  We do this on the encrypting
     * side only.
     }
    Inc(ctx.tls_enc_records);
    if (ctx.enc > 0)  and  (ctx.tls_enc_records = 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_TOO_MANY_RECORDS);
        goto _err;
    end;
    {
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     }
    if ctx.enc > 0 then
    begin
        if 0>=getivgen(ctx, _out, arg) then
            goto _err;
    end
    else
    begin
        if 0>=setivinv(ctx, _out, arg) then
            goto _err;
    end;
    { Fix buffer and length to point to payload }
    _in  := _in + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    _out  := _out + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len  := len - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);
    tag := get_result(ctx.enc > 0, _out + len , PByte(_in) + len);
    if 0>=ctx.hw.oneshot(ctx, @ctx.buf, ctx.tls_aad_len, _in, len, _out, tag,
                          EVP_GCM_TLS_TAG_LEN) then
    begin
        if 0>=ctx.enc then
            OPENSSL_cleanse(_out, len);
        goto _err;
    end;
    if ctx.enc > 0 then
       plen :=  len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN
    else
        plen := len;
    rv := 1;
_err:
    ctx.iv_state := IV_STATE_FINISHED;
    ctx.tls_aad_len := UNINITIALISED_SIZET;
    padlen^ := plen;
    Result := rv;
end;

function gcm_cipher_internal(ctx : PPROV_GCM_CTX; _out : PByte; padlen : Psize_t;const _in : PByte; len : size_t):integer;
var
  olen : size_t;
  rv : integer;
  hw : PPROV_GCM_HW;
  label _err, _finish;
begin
    olen := 0;
    rv := 0;
    hw := ctx.hw;
    if ctx.tls_aad_len <> UNINITIALISED_SIZET then
       Exit(gcm_tls_cipher(ctx, _out, padlen, _in, len));
    if (0>=ctx.key_set)  or  (ctx.iv_state = IV_STATE_FINISHED) then
       goto _err;
    {
     * FIPS requires generation of AES-GCM IV's inside the FIPS module.
     * The IV can still be set externally (the security policy will state that
     * this is not FIPS compliant). There are some applications
     * where setting the IV externally is the only option available.
     }
    if ctx.iv_state = IV_STATE_UNINITIALISED then
    begin
        if (0>=ctx.enc)  or  (0>=gcm_iv_generate(ctx, 0)) then
            goto _err;
    end;
    if ctx.iv_state = IV_STATE_BUFFERED then
    begin
        if 0>=hw.setiv(ctx, @ctx.iv, ctx.ivlen) then
            goto _err;
        ctx.iv_state := IV_STATE_COPIED;
    end;
    if _in <> nil then
    begin
        {  The input is AAD if out is nil }
        if _out = nil then
        begin
            if 0>=hw.aadupdate(ctx, _in, len) then
                goto _err;
        end
        else
        begin
            { The input is ciphertext OR plaintext }
            if 0>=hw.cipherupdate(ctx, _in, len, _out) then
                goto _err;
        end;
    end
    else
    begin
        { The tag must be set before actually decrypting data }
        if (0>=ctx.enc)  and  (ctx.taglen = UNINITIALISED_SIZET) then
             goto _err;
        if 0>=hw.cipherfinal(ctx, @ctx.buf) then
            goto _err;
        ctx.iv_state := IV_STATE_FINISHED; { Don't reuse the IV }
        goto _finish;
    end;
    olen := len;
_finish:
    rv := 1;
_err:
    padlen^ := olen;
    Result := rv;
end;


function ossl_gcm_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_GCM_CTX;
begin
    ctx := PPROV_GCM_CTX (vctx);
    if inl = 0 then begin
        outl^ := 0;
        Exit(1);
    end;
    if outsize < inl then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if gcm_cipher_internal(ctx, _out, outl, _in, inl )  <= 0 then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    Result := 1;
end;
procedure ossl_gcm_initctx(provctx : Pointer; ctx : PPROV_GCM_CTX; keybits : size_t;const hw : PPROV_GCM_HW);
begin
    ctx.pad := 1;
    ctx.mode := EVP_CIPH_GCM_MODE;
    ctx.taglen := UNINITIALISED_SIZET;
    ctx.tls_aad_len := UNINITIALISED_SIZET;
    ctx.ivlen := (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    ctx.keylen := keybits div 8;
    ctx.hw := hw;
    ctx.libctx := PROV_LIBCTX_OF(provctx);
end;

end.
