unit openssl3.providers.implementations.encode_decode.decode_pvk2key;

interface
uses OpenSSL.Api;

type

  Pkeytype_desc_st = ^keytype_desc_st;
  pvk2key_ctx_st = record
    provctx: PPROV_CTX;
    desc: Pkeytype_desc_st;
    selection: Integer;
  end;
  Ppvk2key_ctx_st = ^pvk2key_ctx_st;

  Tcheck_key_fn = function(p1: Pointer; ctx: Ppvk2key_ctx_st): Integer;

  Tadjust_key_fn = procedure(p1: Pointer; ctx: Ppvk2key_ctx_st);

  Tb2i_PVK_of_bio_pw_fn = function(&in: PBIO; cb: Tpem_password_cb; u: Pointer; libctx: POSSL_LIB_CTX; const propq: PUTF8Char): Pointer;
  Pb2i_PVK_of_bio_pw_fn = ^Tb2i_PVK_of_bio_pw_fn;

  Tfree_key_fn = procedure(p1: Pointer);
  Pfree_key_fn = ^Tfree_key_fn;

  keytype_desc_st = record
    &type: Integer;
    name: PUTF8Char;
    fns: POSSL_DISPATCH;
    read_private_key: Tb2i_PVK_of_bio_pw_fn;
    adjust_key: Tadjust_key_fn;
    free_key: Tfree_key_fn;
  end;


  function pvk2key_newctx(provctx : Pointer;const desc : Pkeytype_desc_st):Ppvk2key_ctx_st;
  procedure pvk2key_freectx( vctx : Pointer);
  function pvk2key_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
  function pvk2key_export_object(vctx : Pointer;const reference : Pointer; reference_sz : size_t; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;
  procedure rsa_adjust( key : Pointer; ctx : Ppvk2key_ctx_st);

  function pvk2dsa_newctx( provctx : Pointer):Pointer;
  function pvk2rsa_newctx( provctx : Pointer):Pointer;


  const  ossl_pvk_to_dsa_decoder_functions: array[0..4] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@pvk2dsa_newctx; data:nil)),
(function_id:  2; method:(code:@pvk2key_freectx; data:nil)),
(function_id:  11; method:(code:@pvk2key_decode; data:nil)),
(function_id:  20; method:(code:@pvk2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_pvk_to_rsa_decoder_functions: array[0..4] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@pvk2rsa_newctx; data:nil)),
(function_id:  2; method:(code:@pvk2key_freectx; data:nil)),
(function_id:  11; method:(code:@pvk2key_decode; data:nil)),
(function_id:  20; method:(code:@pvk2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

var
  pvk2dsa_desc, pvk2rsa_desc:keytype_desc_st;

implementation
uses openssl3.crypto.mem,          openssl3.crypto.bio.bio_prov,
     OpenSSL3.Err,                 openssl3.providers.fips.fipsprov,
     openssl3.crypto.bio.bio_lib,  openssl3.crypto.params,
     openssl3.crypto.passphrase,   OpenSSL3.providers.common.provider_ctx,
     openssl3.crypto.rsa.rsa_lib,  openssl3.crypto.dsa.dsa_lib,
     openssl3.crypto.pem.pvkfmt,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     openssl3.providers.implementations.encode_decode.endecoder_common;





function pvk2dsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(pvk2key_newctx(provctx, @pvk2dsa_desc));
end;


function pvk2rsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(pvk2key_newctx(provctx, @pvk2rsa_desc));
end;

function  get_keytype_desc_st(
    _type: Integer;
    name: PUTF8Char;
    fns: POSSL_DISPATCH;
    read_private_key: Tb2i_PVK_of_bio_pw_fn;
    adjust_key: Tadjust_key_fn;
    free_key: Tfree_key_fn):keytype_desc_st;
begin
    Result.&type:=_type;
    Result.name:=name;
    Result.fns:= fns;
    Result.read_private_key:=read_private_key;
    Result.adjust_key:=adjust_key;
    Result.free_key:=free_key;
end;

function pvk2key_newctx(provctx : Pointer;const desc : Pkeytype_desc_st):Ppvk2key_ctx_st;
var
  ctx : Ppvk2key_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then begin
        ctx.provctx := provctx;
        ctx.desc := desc;
    end;
    Result := ctx;
end;


procedure pvk2key_freectx( vctx : Pointer);
var
  ctx : Ppvk2key_ctx_st;
begin
    ctx := vctx;
    OPENSSL_free(ctx);
end;


function pvk2key_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
    ctx         : Ppvk2key_ctx_st;
    _in         : PBIO;
    key         : Pointer;
    ok          : integer;
    pwdata      : ossl_passphrase_data_st;
    err,
    lib,
    reason      : integer;
    params      : array[0..3] of TOSSL_PARAM;
    object_type : integer;
    label _end, _next;
begin
    ctx := vctx;
    _in := ossl_bio_new_from_core_bio(ctx.provctx, cin);
    key := nil;
    ok := 0;
    if _in = nil then Exit(0);
    ctx.selection := selection;
    if ( (selection = 0)
          or  (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY <> 0) )
         and  (Assigned(ctx.desc.read_private_key))  then
    begin
        memset(@pwdata, 0, sizeof(pwdata));
        if 0>=ossl_pw_set_ossl_passphrase_cb(@pwdata, pw_cb, pw_cbarg) then
            goto _end;
        key := ctx.desc.read_private_key(_in, ossl_pw_pvk_password, @pwdata,
                                          PROV_LIBCTX_OF(ctx.provctx), nil);
        {
         * Because the PVK API doesn't have a separate decrypt call, we need
         * to check the error queue for certain well known errors that are
         * considered fatal and which we pass through, while the rest gets
         * thrown away.
         }
        err := ERR_peek_last_error;
        lib := ERR_GET_LIB(err);
        reason := ERR_GET_REASON(err);
        if (lib = ERR_LIB_PEM)
             and ( (reason = PEM_R_BAD_PASSWORD_READ) or
                   (reason = PEM_R_BAD_DECRYPT) ) then
        begin
            ERR_clear_last_mark;
            goto _end;
        end;
        if (selection <> 0)  and  (key = nil) then
           goto _next;
    end;
    if (key <> nil)  and  (Assigned(ctx.desc.adjust_key)) then
       ctx.desc.adjust_key(key, ctx);
 _next:
    {
     * Indicated that we successfully decoded something, or not at all.
     * Ending up 'empty handed' is not an error.
     }
    ok := 1;
    {
     * We free resources here so it's not held up during the callback, because
     * we know the process is recursive and the allocated chunks of memory
     * add up.
     }
    BIO_free(_in);
    _in := nil;
    if key <> nil then
    begin
        object_type := OSSL_OBJECT_PKEY;
        params[0] := OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @object_type);
        params[1] := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             PUTF8Char( ctx.desc.name), 0);
        { The address of the key becomes the octet string }
        params[2] := OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              @key, sizeof(key));
        params[3] := OSSL_PARAM_construct_end;
        ok := data_cb(@params, data_cbarg);
    end;
 _end:
    BIO_free(_in);
    ctx.desc.free_key(key);
    Result := ok;
end;


function pvk2key_export_object(vctx : Pointer;const reference : Pointer; reference_sz : size_t; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;
var
  ctx : Ppvk2key_ctx_st;
  _export : TOSSL_FUNC_keymgmt_export_fn;
  keydata : Pointer;
begin
    ctx := vctx;
    _export := ossl_prov_get_keymgmt_export(ctx.desc.fns);
    if (reference_sz = sizeof(keydata)) and  (Assigned(_export)) then
    begin
        { The contents of the reference is the address to our object }
        keydata := PPointer(reference)^;
        Exit(_export(keydata, ctx.selection, export_cb, export_cbarg));
    end;
    Result := 0;
end;


procedure rsa_adjust( key : Pointer; ctx : Ppvk2key_ctx_st);
begin
    ossl_rsa_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;

initialization
  pvk2dsa_desc := get_keytype_desc_st
     ( 116, 'DSA', @ossl_dsa_keymgmt_functions,
       Pb2i_PVK_of_bio_pw_fn(@b2i_DSA_PVK_bio_ex)^, Pointer(0) , Pfree_key_fn(@DSA_free)^ );



  pvk2rsa_desc := get_keytype_desc_st
     ( 6, 'RSA', @ossl_rsa_keymgmt_functions,
      Pb2i_PVK_of_bio_pw_fn(@b2i_RSA_PVK_bio_ex)^, rsa_adjust, Pfree_key_fn(@RSA_free)^ );


end.
