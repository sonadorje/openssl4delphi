unit OpenSSL3.providers.implementations.ciphers.ciphercommon_ccm;

interface
 uses OpenSSL.Api;

procedure ossl_ccm_initctx(ctx : PPROV_CCM_CTX; keybits : size_t;const hw : PPROV_CCM_HW);

function ossl_ccm_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function ossl_ccm_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function ossl_ccm_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function ossl_ccm_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
  function ossl_ccm_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function ccm_set_iv( ctx : PPROV_CCM_CTX; mlen : size_t):integer;
function ccm_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
function ccm_get_ivlen( ctx : PPROV_CCM_CTX):size_t;
function ossl_ccm_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function ccm_tls_init( ctx : PPROV_CCM_CTX; aad : PByte; alen : size_t):integer;
function ccm_tls_iv_set_fixed( ctx : PPROV_CCM_CTX; fixed : PByte; flen : size_t):integer;
function ccm_cipher_internal(ctx : PPROV_CCM_CTX; _out : PByte; padlen : Psize_t;const _in : PByte; len : size_t):integer;

function ccm_tls_cipher(ctx : PPROV_CCM_CTX; _out : PByte; padlen : Psize_t;{const} _in : PByte; len : size_t):integer;
function ossl_ccm_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;

implementation

uses openssl3.providers.fips.self_test, OpenSSL3.Err, openssl3.crypto.params;




function ossl_ccm_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_CCM_CTX;
  p : POSSL_PARAM;
  m : size_t;
begin
    ctx := PPROV_CCM_CTX(vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ccm_get_ivlen(ctx)))  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if p <> nil then begin
        m := ctx.m;
        if 0>=OSSL_PARAM_set_size_t(p, m ) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if p <> nil then
    begin
        if ccm_get_ivlen(ctx) > p.data_size then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        if (0>=OSSL_PARAM_set_octet_string(p, @ctx.iv, p.data_size))  and
           (0>=OSSL_PARAM_set_octet_ptr(p, @ctx.iv, p.data_size)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if p <> nil then begin
        if ccm_get_ivlen(ctx) > p.data_size then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        if (0>=OSSL_PARAM_set_octet_string(p, @ctx.iv, p.data_size))  and
           (0>=OSSL_PARAM_set_octet_ptr(p, @ctx.iv, p.data_size)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.keylen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.tls_aad_pad_sz)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then begin
        if (0>=ctx.enc)  or  (0>=ctx.tag_set) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            Exit(0);
        end;
        if p.data_type <> OSSL_PARAM_OCTET_STRING then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            Exit(0);
        end;
        if 0>=ctx.hw.gettag(ctx, p.data, p.data_size) then
            Exit(0);
        ctx.tag_set := 0;
        ctx.iv_set := 0;
        ctx.len_set := 0;
    end;
    Result := 1;
end;



function ccm_tls_cipher(ctx : PPROV_CCM_CTX; _out : PByte; padlen : Psize_t;{const} _in : PByte; len : size_t):integer;
var
  rv : integer;

  olen : size_t;
  label _err;
begin
    rv := 0;
    olen := 0;
    if not ossl_prov_is_running then goto _err;
    { Encrypt/decrypt must be performed in place }
    if (_in = nil)  or  (_out <> _in)  or  (len < EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx.m) then
       goto _err;
    { If encrypting set explicit IV from sequence number (start of AAD) }
    if ctx.enc > 0 then
       memcpy(_out, @ctx.buf, EVP_CCM_TLS_EXPLICIT_IV_LEN);
    { Get rest of IV from explicit IV }
    memcpy(PByte(@ctx.iv) + EVP_CCM_TLS_FIXED_IV_LEN, _in, EVP_CCM_TLS_EXPLICIT_IV_LEN);
    { Correct length value }
    len  := len - (EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx.m);
    if 0>=ccm_set_iv(ctx, len) then
        goto _err;
    { Use saved AAD }
    if 0>=ctx.hw.setaad(ctx, @ctx.buf, ctx.tls_aad_len) then
        goto _err;
    { Fix buffer to point to payload }
    _in  := _in + EVP_CCM_TLS_EXPLICIT_IV_LEN;
    _out  := _out + EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if ctx.enc > 0  then
    begin
        if 0>=ctx.hw.auth_encrypt(ctx, _in, _out, len,  _out + len, ctx.m) then
            goto _err;
        olen := len + EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx.m;
    end
    else
    begin
        if 0>=ctx.hw.auth_decrypt(ctx, _in, _out, len,
                                   PByte(_in) + len, ctx.m) then
            goto _err;
        olen := len;
    end;
    rv := 1;
_err:
    padlen^ := olen;
    Result := rv;
end;



function ccm_cipher_internal(ctx : PPROV_CCM_CTX; _out : PByte; padlen : Psize_t;const _in : PByte; len : size_t):integer;
var
  rv : integer;
  olen : size_t;
  hw : PPROV_CCM_HW;
  label _finish, _err;
begin
    rv := 0;
    olen := 0;
    hw := ctx.hw;
    { If no key set, return error }
    if 0>=ctx.key_set then Exit(0);
    if ctx.tls_aad_len <> UNINITIALISED_SIZET then
       Exit(ccm_tls_cipher(ctx, _out, padlen, _in, len));
    { EVP_*Final doesn't return any data }
    if (_in = nil)  and  (_out <> nil) then goto _finish;
    if 0>=ctx.iv_set then goto _err;
    if _out = nil then
    begin
        if _in = nil then  begin
            if 0>=ccm_set_iv(ctx, len) then
                goto _err;
        end
        else
        begin
            { If we have AAD, we need a message length }
            if (0>=ctx.len_set)  and  (len > 0) then goto _err;
            if 0>=hw.setaad(ctx, _in, len) then
                goto _err;
        end;
    end
    else
    begin
        { If not set length yet do it }
        if (0>=ctx.len_set)  and  (0>=ccm_set_iv(ctx, len)) then
            goto _err;
        if ctx.enc > 0 then
        begin
            if 0>=hw.auth_encrypt(ctx, _in, _out, len, nil, 0) then
                goto _err;
            ctx.tag_set := 1;
        end
        else
        begin
            { The tag must be set before actually decrypting data }
            if 0>=ctx.tag_set then goto _err;
            if 0>=hw.auth_decrypt(ctx, _in, _out, len, @ctx.buf, ctx.m) then
                goto _err;
            { Finished - reset flags so calling this method again will fail }
            ctx.iv_set := 0;
            ctx.tag_set := 0;
            ctx.len_set := 0;
        end;
    end;
    olen := len;
_finish:
    rv := 1;
_err:
    padlen^ := olen;
    Result := rv;
end;


function ccm_tls_iv_set_fixed( ctx : PPROV_CCM_CTX; fixed : PByte; flen : size_t):integer;
begin
    if flen <> EVP_CCM_TLS_FIXED_IV_LEN then Exit(0);
    { Copy to first part of the iv. }
    memcpy(@ctx.iv, fixed, flen);
    Result := 1;
end;




function ccm_tls_init( ctx : PPROV_CCM_CTX; aad : PByte; alen : size_t):integer;
var
  len : size_t;
begin
    if (not ossl_prov_is_running)  or  (alen <> EVP_AEAD_TLS1_AAD_LEN) then
       Exit(0);
    { Save the aad for later use. }
    memcpy(@ctx.buf, aad, alen);
    ctx.tls_aad_len := alen;
    len := ctx.buf[alen - 2] shl 8 or ctx.buf[alen - 1];
    if len < EVP_CCM_TLS_EXPLICIT_IV_LEN then Exit(0);
    { Correct length for explicit iv. }
    len  := len - EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if 0>=ctx.enc then
    begin
        if len < ctx.m then
            Exit(0);
        { Correct length for tag. }
        len  := len - ctx.m;
    end;
    ctx.buf[alen - 2] := Byte(len  shr  8);
    ctx.buf[alen - 1] := Byte(len and $ff);
    { Extra padding: tag appended to record. }
    Result := ctx.m;
end;


function ossl_ccm_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CCM_CTX;
  p : POSSL_PARAM;
  sz, ivlen : size_t;
begin
    ctx := PPROV_CCM_CTX(vctx);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if (p.data_size and 1 > 0) or  (p.data_size < 4)  or  (p.data_size > 16) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            Exit(0);
        end;
        if p.data <> nil then
        begin
            if ctx.enc > 0 then  begin
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                Exit(0);
            end;
            memcpy(@ctx.buf, p.data, p.data_size);
            ctx.tag_set := 1;
        end;
        ctx.m := p.data_size;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if p <> nil then
    begin
        if 0>=OSSL_PARAM_get_size_t(p, @sz) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        ivlen := 15 - sz;
        if (ivlen < 2)  or  (ivlen > 8) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        ctx.l := ivlen;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_OCTET_STRING then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        sz := ccm_tls_init(ctx, p.data, p.data_size);
        if sz = 0 then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
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
        if ccm_tls_iv_set_fixed(ctx, p.data, p.data_size) = 0  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
    end;
    Result := 1;
end;



function ccm_get_ivlen( ctx : PPROV_CCM_CTX):size_t;
begin
    Result := 15 - ctx.l;
end;


function ccm_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
  ctx : PPROV_CCM_CTX;
begin
    ctx := PPROV_CCM_CTX (vctx);
    if not ossl_prov_is_running then Exit(0);
    ctx.enc := enc;
    if iv <> nil then
    begin
        if ivlen <> ccm_get_ivlen(ctx) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            Exit(0);
        end;
        memcpy(@ctx.iv, iv, ivlen);
        ctx.iv_set := 1;
    end;
    if key <> nil then
    begin
        if keylen <> ctx.keylen then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>=ctx.hw.setkey(ctx, key, keylen) then
            Exit(0);
    end;
    Result := ossl_ccm_set_ctx_params(ctx, params);
end;



function ossl_ccm_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := ccm_init(vctx, key, keylen, iv, ivlen, params, 1);
end;


function ossl_ccm_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := ccm_init(vctx, key, keylen, iv, ivlen, params, 0);
end;


function ossl_ccm_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_CCM_CTX;
begin
    ctx := PPROV_CCM_CTX (vctx);
    if outsize < inl then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>=ccm_cipher_internal(ctx, _out, outl, _in, inl) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    Result := 1;
end;


function ossl_ccm_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : PPROV_CCM_CTX;

  i : integer;
begin
    ctx := PPROV_CCM_CTX (vctx);
    if not ossl_prov_is_running then Exit(0);
    i := ccm_cipher_internal(ctx, _out, outl, nil, 0);
    if i <= 0 then Exit(0);
    outl^ := 0;
    Result := 1;
end;


function ossl_ccm_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_CCM_CTX;
begin
    ctx := PPROV_CCM_CTX (vctx);
    if not ossl_prov_is_running then Exit(0);
    if outsize < inl then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if ccm_cipher_internal(ctx, _out, outl, _in, inl) <= 0  then
        Exit(0);
    outl^ := inl;
    Result := 1;
end;


function ccm_set_iv( ctx : PPROV_CCM_CTX; mlen : size_t):integer;
var
  hw : PPROV_CCM_HW;
begin
    hw := ctx.hw;
    if 0>=hw.setiv(ctx, @ctx.iv, ccm_get_ivlen(ctx) , mlen) then
        Exit(0);
    ctx.len_set := 1;
    Result := 1;
end;



procedure ossl_ccm_initctx(ctx : PPROV_CCM_CTX; keybits : size_t;const hw : PPROV_CCM_HW);
begin
    ctx.keylen := keybits div 8;
    ctx.key_set := 0;
    ctx.iv_set := 0;
    ctx.tag_set := 0;
    ctx.len_set := 0;
    ctx.l := 8;
    ctx.m := 12;
    ctx.tls_aad_len := UNINITIALISED_SIZET;
    ctx.hw := hw;
end;


end.
