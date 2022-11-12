unit openssl3.providers.implementations.encode_decode.decode_spki2typespki;

interface
uses OpenSSL.Api;

type
  spki2typespki_ctx_st = record
    provctx : PPROV_CTX;
  end;
  Pspki2typespki_ctx_st = ^spki2typespki_ctx_st;

  function spki2typespki_newctx( provctx : Pointer):Pointer;
  procedure spki2typespki_freectx( vctx : Pointer);
  function spki2typespki_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;

  const ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions: array[0..3] of TOSSL_DISPATCH = (
    (function_id:  1; method:(code:@spki2typespki_newctx; data:nil)),
    (function_id:  2; method:(code:@spki2typespki_freectx; data:nil)),
    (function_id:  11; method:(code:@spki2typespki_decode; data:nil)),
    (function_id:  0; method:(code:nil; data:nil)) );

implementation
uses openssl3.crypto.mem,          openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.asn1.x_algor, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.ec.ec_backend,
     OpenSSL3.providers.common.provider_ctx, openssl3.crypto.params,
     openssl3.providers.implementations.encode_decode.endecoder_common;

function spki2typespki_newctx( provctx : Pointer):Pointer;
var
  ctx : Pspki2typespki_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then ctx.provctx := provctx;
    Result := ctx;
end;


procedure spki2typespki_freectx( vctx : Pointer);
var
  ctx : Pspki2typespki_ctx_st;
begin
    ctx := vctx;
    OPENSSL_free(ctx);
end;


function spki2typespki_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  ctx      : Pspki2typespki_ctx_st;
  der,
  derp     : PByte;
  len      : long;
  ok,
  objtype  : integer;
  xpub     : PX509_PUBKEY;
  algor    : PX509_ALGOR;
  oid      : PASN1_OBJECT;
  params   : array[0..4] of TOSSL_PARAM;
  dataname : array[0..OSSL_MAX_NAME_SIZE-1] of UTF8Char ;
  p: POSSL_PARAM;
  label _end;
begin
    ctx := vctx;
    ok := 0;
    objtype := OSSL_OBJECT_PKEY;
    xpub := nil;
    algor := nil;
    oid := nil;
    p := @params;
    if 0>=ossl_read_der(ctx.provctx, cin, @der, @len) then
        Exit(1);
    derp := der;
    xpub := ossl_d2i_X509_PUBKEY_INTERNAL(PPByte(@derp), len,
                                         PROV_LIBCTX_OF(ctx.provctx));
    if xpub = nil then begin
        { We return 'empty handed'.  This is not an error. }
        ok := 1;
        goto _end;
    end;
    if 0>=X509_PUBKEY_get0_param(nil, nil, nil, @algor, xpub) then
        goto _end;
    X509_ALGOR_get0(@oid, nil, nil, algor);
{$IFNDEF OPENSSL_NO_EC}
    { SM2 abuses the EC oid, so this could actually be SM2 }
    if (OBJ_obj2nid(oid) = NID_X9_62_id_ecPublicKey)
             and  (ossl_x509_algor_is_sm2(algor) > 0 ) then
        strcpy(dataname, 'SM2')
    else
{$ENDIF}
    if OBJ_obj2txt(dataname, sizeof(dataname), oid, 0) <= 0 then
        goto _end;
    ossl_X509_PUBKEY_INTERNAL_free(xpub);
    xpub := nil;
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                            dataname, 0);
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                            'SubjectPublicKeyInfo',
                                            0);
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der, len);
    PostInc(p)^ := OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @objtype);
    p^ := OSSL_PARAM_construct_end;
    ok := data_cb(@params, data_cbarg);
 _end:
    ossl_X509_PUBKEY_INTERNAL_free(xpub);
    OPENSSL_free(der);
    Result := ok;
end;


end.
