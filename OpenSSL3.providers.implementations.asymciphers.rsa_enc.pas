unit OpenSSL3.providers.implementations.asymciphers.rsa_enc;

interface
uses OpenSSL.Api, SysUtils;

  function rsa_newctx( provctx : Pointer):Pointer;
  function rsa_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
  function rsa_encrypt_init( vprsactx, vrsa : Pointer; params : POSSL_PARAM):integer;
  function rsa_decrypt_init( vprsactx, vrsa : Pointer; params : POSSL_PARAM):integer;
  function rsa_encrypt(vprsactx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
  function rsa_decrypt(vprsactx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
  procedure rsa_freectx( vprsactx : Pointer);
  function rsa_dupctx( vprsactx : Pointer):Pointer;
  function rsa_get_ctx_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
  function rsa_gettable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
  function rsa_set_ctx_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
  function rsa_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;

const ossl_rsa_asym_cipher_functions: array[0..11] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_ASYM_CIPHER_NEWCTX; method:(code:@rsa_newctx; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT; method:(code:@rsa_encrypt_init; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_ENCRYPT; method:(code:@rsa_encrypt; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT; method:(code:@rsa_decrypt_init; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_DECRYPT; method:(code:@rsa_decrypt; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_FREECTX; method:(code:@rsa_freectx; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_DUPCTX; method:(code:@rsa_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS;
      method:(code:@rsa_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS;
      method:(code:@rsa_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS;
      method:(code:@rsa_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS;
      method:(code:@rsa_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

 padding_item: array[0..5] of TOSSL_ITEM = (
    (id:  RSA_PKCS1_PADDING;        ptr: OSSL_PKEY_RSA_PAD_MODE_PKCSV15 ),
    (id:  RSA_NO_PADDING;           ptr: OSSL_PKEY_RSA_PAD_MODE_NONE ),
    (id:  RSA_PKCS1_OAEP_PADDING;   ptr: OSSL_PKEY_RSA_PAD_MODE_OAEP ), // Correct spelling first */
    (id:  RSA_PKCS1_OAEP_PADDING;   ptr: 'oeap'),
    (id:  RSA_X931_PADDING;         ptr: OSSL_PKEY_RSA_PAD_MODE_X931 ),
    (id:  0;                        ptr: nil )
);

implementation
uses  OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.providers.fips.self_test, OpenSSL3.openssl.params,
     OpenSSL3.providers.common.der.der_rsa_sig, openssl3.crypto.rsa.rsa_pss,
     OpenSSL3.providers.common.der.der_rsa_key, openssl3.crypto.rsa.rsa_lib,
     OpenSSL3.providers.common.securitycheck_default,
     openssl3.crypto.rsa_schemes, openssl3.crypto.rsa.rsa_sign,
     OpenSSL3.crypto.rsa.rsa_crpt,
     openssl3.crypto.rsa.rsa_saos, openssl3.crypto.rsa.rsa_oaep,
     openssl3.crypto.rsa.rsa_pk1, openssl3.internal.constant_time;

var
  known_gettable_ctx_params: array[0..6] of TOSSL_PARAM ;
  known_settable_ctx_params: array[0..7] of TOSSL_PARAM ;

function rsa_newctx( provctx : Pointer):Pointer;
var
  prsactx : PPROV_RSA_CTX;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    prsactx := OPENSSL_zalloc(sizeof(TPROV_RSA_CTX));
    if prsactx = nil then Exit(nil);
    prsactx.libctx := PROV_LIBCTX_OF(provctx);
    Result := prsactx;
end;


function rsa_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if (not ossl_prov_is_running)  or  (prsactx = nil)  or  (vrsa = nil) then
        Exit(0);
    if 0>= ossl_rsa_check_key(prsactx.libctx, vrsa, operation) then
        Exit(0);
    if 0>= RSA_up_ref(vrsa) then
        Exit(0);
    RSA_free(prsactx.rsa);
    prsactx.rsa := vrsa;
    prsactx.operation := operation;
    case (RSA_test_flags(prsactx.rsa, RSA_FLAG_TYPE_MASK)) of
        RSA_FLAG_TYPE_RSA:
            prsactx.pad_mode := RSA_PKCS1_PADDING;
            //break;
        else
        begin
            { This should not happen due to the check above }
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
    end;
    Result := rsa_set_ctx_params(prsactx, params);
end;


function rsa_encrypt_init( vprsactx, vrsa : Pointer; params : POSSL_PARAM):integer;
begin
    Result := rsa_init(vprsactx, vrsa, params, EVP_PKEY_OP_ENCRYPT);
end;


function rsa_decrypt_init( vprsactx, vrsa : Pointer; params : POSSL_PARAM):integer;
begin
    Result := rsa_init(vprsactx, vrsa, params, EVP_PKEY_OP_DECRYPT);
end;


function rsa_encrypt(vprsactx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX2;
  ret : integer;
  len : size_t;
  rsasize : integer;
  tbuf : PByte;
begin
    prsactx := PPROV_RSA_CTX2 ( vprsactx);
    if not ossl_prov_is_running then
        Exit(0);
    if out = nil then
    begin
        len := RSA_size(prsactx.rsa);
        if len = 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            Exit(0);
        end;
        outlen^ := len;
        Exit(1);
    end;
    if prsactx.pad_mode = RSA_PKCS1_OAEP_PADDING then
    begin
        rsasize := RSA_size(prsactx.rsa);
        tbuf := OPENSSL_malloc(rsasize);
        if tbuf = nil then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        if prsactx.oaep_md = nil then
        begin
            OPENSSL_free(Pointer(tbuf));
            prsactx.oaep_md := EVP_MD_fetch(prsactx.libctx, 'SHA-1', nil);
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        ret := ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(prsactx.libctx, tbuf,
                                                    rsasize, &in, inlen,
                                                    prsactx.oaep_label,
                                                    prsactx.oaep_labellen,
                                                    prsactx.oaep_md,
                                                    prsactx.mgf1_md);
        if 0>= ret then
        begin
            OPENSSL_free(Pointer(tbuf));
            Exit(0);
        end;
        ret := RSA_public_encrypt(rsasize, tbuf, out, prsactx.rsa,
                                 RSA_NO_PADDING);
        OPENSSL_free(Pointer(tbuf));
    end
    else
    begin
        ret := RSA_public_encrypt(inlen, &in, out, prsactx.rsa,
                                 prsactx.pad_mode);
    end;
    { A ret value of 0 is not an error }
    if ret < 0 then Exit(ret);
    outlen^ := ret;
    Result := 1;
end;


function rsa_decrypt(vprsactx : Pointer; &out : PByte; outlen : Psize_t; outsize : size_t;const &in : PByte; inlen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX2;

  ret : integer;

  len : size_t;

  tbuf : PByte;
begin
    prsactx := PPROV_RSA_CTX2 ( vprsactx);
    len := RSA_size(prsactx.rsa);
    if not ossl_prov_is_running then
        Exit(0);
    if prsactx.pad_mode = RSA_PKCS1_WITH_TLS_PADDING then
    begin
        if out = nil then
        begin
            outlen^ := SSL_MAX_MASTER_KEY_LENGTH;
            Exit(1);
        end;
        if outsize < SSL_MAX_MASTER_KEY_LENGTH then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            Exit(0);
        end;
    end
    else
    begin
        if out = nil then
        begin
            if len = 0 then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                Exit(0);
            end;
            outlen^ := len;
            Exit(1);
        end;
        if outsize < len then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            Exit(0);
        end;
    end;
    if (prsactx.pad_mode = RSA_PKCS1_OAEP_PADDING)
             or  (prsactx.pad_mode = RSA_PKCS1_WITH_TLS_PADDING) then
    begin
        tbuf := OPENSSL_malloc(len);
        if (tbuf = nil) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        ret := RSA_private_decrypt(inlen, &in, tbuf, prsactx.rsa,
                                  RSA_NO_PADDING);
        {
         * With no padding then, on success ret should be len, otherwise an
         * error occurred (non-constant time)
         }
        if ret <> int(len)  then
        begin
            OPENSSL_free(Pointer(tbuf));
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
            Exit(0);
        end;
        if prsactx.pad_mode = RSA_PKCS1_OAEP_PADDING then
        begin
            if prsactx.oaep_md = nil then
            begin
                prsactx.oaep_md := EVP_MD_fetch(prsactx.libctx, 'SHA-1', nil);
                if prsactx.oaep_md = nil then
                begin
                    OPENSSL_free(Pointer(tbuf));
                    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                    Exit(0);
                end;
            end;
            ret := RSA_padding_check_PKCS1_OAEP_mgf1(out, outsize, tbuf,
                                                    len, len,
                                                    prsactx.oaep_label,
                                                    prsactx.oaep_labellen,
                                                    prsactx.oaep_md,
                                                    prsactx.mgf1_md);
        end
        else
        begin
            { RSA_PKCS1_WITH_TLS_PADDING }
            if prsactx.client_version <= 0 then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_TLS_CLIENT_VERSION);
                OPENSSL_free(Pointer(tbuf));
                Exit(0);
            end;
            ret := ossl_rsa_padding_check_PKCS1_type_2_TLS(
                        prsactx.libctx, out, outsize, tbuf, len,
                        prsactx.client_version, prsactx.alt_version);
        end;
        OPENSSL_free(Pointer(tbuf));
    end
    else
    begin
        ret := RSA_private_decrypt(inlen, &in, out, prsactx.rsa,
                                  prsactx.pad_mode);
    end;
    outlen^ := constant_time_select_s(constant_time_msb_s(ret), outlen^, ret);
    ret := constant_time_select_int(constant_time_msb(ret), 0, 1);
    Result := ret;
end;


procedure rsa_freectx( vprsactx : Pointer);
var
  prsactx : PPROV_RSA_CTX2;
begin
    prsactx := PPROV_RSA_CTX2( vprsactx);
    RSA_free(prsactx.rsa);
    EVP_MD_free(prsactx.oaep_md);
    EVP_MD_free(prsactx.mgf1_md);
    OPENSSL_free(Pointer(prsactx.oaep_label));
    OPENSSL_free(Pointer(prsactx));
end;


function rsa_dupctx( vprsactx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_RSA_CTX2;
begin
    srcctx := PPROV_RSA_CTX2 ( vprsactx);
    if not ossl_prov_is_running then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    if (dstctx.rsa <> nil)  and  (0>= RSA_up_ref(dstctx.rsa)) then
    begin
        OPENSSL_free(Pointer(dstctx));
        Exit(nil);
    end;
    if (dstctx.oaep_md <> nil)  and  (0>= EVP_MD_up_ref(dstctx.oaep_md)) then
    begin
        RSA_free(dstctx.rsa);
        OPENSSL_free(Pointer(dstctx));
        Exit(nil);
    end;
    if (dstctx.mgf1_md <> nil)  and  (0>= EVP_MD_up_ref(dstctx.mgf1_md)) then
    begin
        RSA_free(dstctx.rsa);
        EVP_MD_free(dstctx.oaep_md);
        OPENSSL_free(Pointer(dstctx));
        Exit(nil);
    end;
    Result := dstctx;
end;


function rsa_get_ctx_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
var
  prsactx : PPROV_RSA_CTX2;
  p : POSSL_PARAM;
  i : integer;
  word : PUTF8Char;
  mgf1_md : PEVP_MD;
begin
    prsactx := PPROV_RSA_CTX2 ( vprsactx);
    if prsactx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if p <> nil then
       case p.data_type of
        OSSL_PARAM_INTEGER:  { Support for legacy pad mode number }
            if 0>= OSSL_PARAM_set_int(p, prsactx.pad_mode) then
                Exit(0);
            //break;
        OSSL_PARAM_UTF8_STRING:
            begin
             word := nil;
                i := 0;
                while (padding_item[i].id <> 0) do
                begin
                    if prsactx.pad_mode = int( padding_item[i].id) then
                    begin
                        word := padding_item[i].ptr;
                        break;
                    end;
                    Inc(i);
                end;
                if word <> nil then
                begin
                    if 0>= OSSL_PARAM_set_utf8_string(p, word) then
                        Exit(0);
                end
                else
                begin
                    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                end;
            end;
            //break;
        else
            Exit(0);
        end;
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_string(p, get_result(prsactx.oaep_md = nil
                                                    , ''
                                                    , EVP_MD_get0_name(prsactx.oaep_md)) ))then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if p <> nil then
    begin
        if prsactx.mgf1_md = nil then
           mgf1_md :=  prsactx.oaep_md
        else
           mgf1_md := prsactx.mgf1_md;

        if 0>= OSSL_PARAM_set_utf8_string(p, get_result(mgf1_md = nil
                                           , ''
                                           , EVP_MD_get0_name(mgf1_md))) then
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p <> nil)  and
         (0>= OSSL_PARAM_set_octet_ptr(p, prsactx.oaep_label,
                                  prsactx.oaep_labellen) )  then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p <> nil)  and
       (0>= OSSL_PARAM_set_uint(p, prsactx.client_version)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p <> nil)  and
       (0>= OSSL_PARAM_set_uint(p, prsactx.alt_version ))then
        Exit(0);
    Result := 1;
end;


function rsa_gettable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params;
end;


function rsa_set_ctx_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
var
  prsactx        : PPROV_RSA_CTX2;
  p              : POSSL_PARAM;
  mdname         : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8Char;
  mdprops        : array[0..(OSSL_MAX_PROPQUERY_SIZE)-1] of UTF8Char;
  str            : PUTF8Char;
  pad_mode,
  i              : integer;
  tmp_label      : Pointer;
  tmp_labellen   : size_t;
  client_version,
  alt_version    : uint32;
begin
    prsactx := PPROV_RSA_CTX2 ( vprsactx);
    FillChar(mdprops, SizeOf(mdprops), #0 );

    str := mdname;
    if prsactx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(mdname)) then
            Exit(0);
        str := mdprops;
        p := OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if p <> nil then
        begin
            if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(mdprops)) then
                Exit(0);
        end;
        EVP_MD_free(prsactx.oaep_md);
        prsactx.oaep_md := EVP_MD_fetch(prsactx.libctx, mdname, mdprops);
        if prsactx.oaep_md = nil then Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if p <> nil then
    begin
        pad_mode := 0;
        case p.data_type of
        OSSL_PARAM_INTEGER:  { Support for legacy pad mode number }
            if 0>= OSSL_PARAM_get_int(p, @pad_mode) then
                Exit(0);
            //break;
        OSSL_PARAM_UTF8_STRING:
            begin
                if p.data = nil then Exit(0);
                i := 0;
                while padding_item[i].id <> 0 do
                begin
                    if strcmp(p.data, padding_item[i].ptr) = 0  then
                    begin
                        pad_mode := padding_item[i].id;
                        break;
                    end;
                    Inc(i);
                end;
            end;
            //break;
        else
            Exit(0);
        end;
        {
         * PSS padding is for signatures only so is not compatible with
         * asymmetric cipher use.
         }
        if pad_mode = RSA_PKCS1_PSS_PADDING then Exit(0);
        if (pad_mode = RSA_PKCS1_OAEP_PADDING)  and  (prsactx.oaep_md = nil) then
        begin
            prsactx.oaep_md := EVP_MD_fetch(prsactx.libctx, 'SHA1', mdprops);
            if prsactx.oaep_md = nil then Exit(0);
        end;
        prsactx.pad_mode := pad_mode;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if p <> nil then begin
        if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(mdname)) then
            Exit(0);
        str := mdprops;
        p := OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if p <> nil then
        begin
            if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(mdprops)) then
                Exit(0);
        end
        else
        begin
            str := nil;
        end;
        EVP_MD_free(prsactx.mgf1_md);
        prsactx.mgf1_md := EVP_MD_fetch(prsactx.libctx, mdname, str);
        if prsactx.mgf1_md = nil then Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if p <> nil then begin
        tmp_label := nil;
        if 0>= OSSL_PARAM_get_octet_string(p, tmp_label, 0, @tmp_labellen) then
            Exit(0);
        OPENSSL_free(Pointer(prsactx.oaep_label));
        prsactx.oaep_label := PByte( tmp_label);
        prsactx.oaep_labellen := tmp_labellen;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @client_version) then
            Exit(0);
        prsactx.client_version := client_version;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @alt_version) then
            Exit(0);
        prsactx.alt_version := alt_version;
    end;
    Result := 1;
end;


function rsa_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params;
end;

initialization
  known_gettable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, nil, 0);
  known_gettable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, nil, 0);
  known_gettable_ctx_params[2] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, nil, 0);
  known_gettable_ctx_params[3] :=  OSSL_PARAM_DEFN(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR, nil, 0);
  known_gettable_ctx_params[4] := _OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, nil);
  known_gettable_ctx_params[5] := _OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, nil);
  known_gettable_ctx_params[6] := OSSL_PARAM_END;

  known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, nil, 0);
  known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, nil, 0);
  known_settable_ctx_params[2] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, nil, 0);
  known_settable_ctx_params[3] := _OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, nil, 0);
  known_settable_ctx_params[4] := _OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, nil, 0);
  known_settable_ctx_params[5] := _OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, nil);
  known_settable_ctx_params[6] := _OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, nil);
  known_settable_ctx_params[7] := OSSL_PARAM_END;
end.
