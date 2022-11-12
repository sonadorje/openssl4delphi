unit openssl3.providers.implementations.encode_decode.decode_epki2pki;

interface
uses OpenSSL.Api;

type
epki2pki_ctx_st = record
  provctx : PPROV_CTX;
end;

Pepki2pki_ctx_st = ^epki2pki_ctx_st;

  function epki2pki_newctx( provctx : Pointer):Pointer;
  procedure epki2pki_freectx( vctx : Pointer);
  function epki2pki_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;

  const ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions: array[0..3] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_DECODER_NEWCTX; method:(code:@epki2pki_newctx; data:nil)),
    (function_id:  OSSL_FUNC_DECODER_FREECTX; method:(code:@epki2pki_freectx; data:nil)),
    (function_id:  OSSL_FUNC_DECODER_DECODE; method:(code:@epki2pki_decode; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) ));

implementation
uses  openssl3.crypto.bio.bio_prov, openssl3.crypto.pem.pem_lib,
      openssl3.crypto.params,       openssl3.crypto.asn1.a_d2i_fp,
      openssl3.crypto.asn1.x_sig,   OpenSSL3.Err,
      openssl3.crypto.objects.obj_dat,
      openssl3.crypto.pkcs12.p12_decr,  OpenSSL3.providers.common.provider_ctx,
      openssl3.providers.fips.fipsprov, openssl3.crypto.asn1.p8_pkey,
      openssl3.crypto.bio.bio_lib,  openssl3.crypto.mem;

function epki2pki_newctx( provctx : Pointer):Pointer;
var
  ctx : Pepki2pki_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then ctx.provctx := provctx;
    Result := ctx;
end;


procedure epki2pki_freectx( vctx : Pointer);
var
  ctx : Pepki2pki_ctx_st;
begin
    ctx := vctx;
    OPENSSL_free(ctx);
end;


function epki2pki_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  ctx         : Pepki2pki_ctx_st;
  mem         : PBUF_MEM;
  der,
  pder        : PByte;
  der_len     : long;
  p8          : PX509_SIG;
  p8inf       : PPKCS8_PRIV_KEY_INFO;
  alg         : PX509_ALGOR;
  _in         : PBIO;
  ok          : Boolean;
  pbuf        : array[0..1023] of byte;
  plen        : size_t;
  new_der     : PByte;
  new_der_len : integer;
  keytype     : array[0..(OSSL_MAX_NAME_SIZE)-1] of byte;
  params      : array[0..4] of TOSSL_PARAM;
  P: POSSL_PARAM;
  objtype     : integer;
  oct: PASN1_OCTET_STRING;
begin
    ctx := vctx;
    mem := nil;
    der := nil;
    pder := nil;
    der_len := 0;
    p8 := nil;
    p8inf := nil;
    alg := nil;
    _in := ossl_bio_new_from_core_bio(ctx.provctx, cin);
    ok := Boolean(0);
    if _in = nil then Exit(0);
    ok := asn1_d2i_read_bio(_in, @mem) >= 0;
    BIO_free(_in);
    { We return 'empty handed'.  This is not an error. }
    if not ok then Exit(1);
    der := PByte(mem.data);
    pder := der;
    der_len := long(mem.length);
    OPENSSL_free(mem);
    ok := Boolean(1);                      { Assume good }
    ERR_set_mark;
    p8 := d2i_X509_SIG(nil, @pder, der_len );
    if p8 <> nil then
    begin
        plen := 0;
        ERR_clear_last_mark;
        if 0>=pw_cb(@pbuf, sizeof(pbuf), @plen, nil, pw_cbarg) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PASSPHRASE);
            ok := Boolean(0);
        end
        else
        begin
            new_der := nil;
            new_der_len := 0;
            X509_SIG_get0(p8, @alg, @oct);
            if nil =PKCS12_pbe_crypt_ex(alg, @pbuf, plen,
                                     oct.data, oct.length,
                                     @new_der, @new_der_len, 0,
                                     PROV_LIBCTX_OF(ctx.provctx) , nil) then
            begin
                ok := Boolean(0);
            end
            else
            begin
                OPENSSL_free(der);
                der := new_der;
                der_len := new_der_len;
            end;
            alg := nil;
        end;
        X509_SIG_free(p8);
    end
    else
    begin
        ERR_pop_to_mark;
    end;
    ERR_set_mark;
    pder := der;
    p8inf := d2i_PKCS8_PRIV_KEY_INFO(nil, @pder, der_len);
    ERR_pop_to_mark;
    if (p8inf <> nil)  and  (PKCS8_pkey_get0(nil, nil, nil, @alg, p8inf) > 0) then
    begin
        {
         * We have something and recognised it as PrivateKeyInfo, so let's
         * pass all the applicable data to the callback.
         }
        p := @params;
        objtype := OSSL_OBJECT_PKEY;
        OBJ_obj2txt(@keytype, sizeof(keytype), alg.algorithm, 0);
        PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                @keytype, 0);
        PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                'PrivateKeyInfo', 0);
        PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                 der, der_len);
        PostInc(p)^ := OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @objtype);
        p^ := OSSL_PARAM_construct_end;
        ok := Boolean(data_cb(@params, data_cbarg));
    end;
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    OPENSSL_free(der);
    Result := Int(ok);
end;


end.
