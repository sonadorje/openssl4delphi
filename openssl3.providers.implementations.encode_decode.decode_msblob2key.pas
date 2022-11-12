unit openssl3.providers.implementations.encode_decode.decode_msblob2key;

interface
uses OpenSSL.Api;

type
  Pkeytype_desc_st = ^keytype_desc_st;
  Pmsblob2key_ctx_st = ^msblob2key_ctx_st;
  Tb2i_of_void_fn = function(&in: PPByte; bitlen: Cardinal; ispub: Integer): Pointer;
  Pb2i_of_void_fn = ^Tb2i_of_void_fn;
  
  Tadjust_key_fn = procedure(p1: Pointer; ctx: Pmsblob2key_ctx_st);

  Tfree_key_fn = procedure(p1: Pointer);
  Pfree_key_fn = ^Tfree_key_fn;

  msblob2key_ctx_st = record
    provctx: PPROV_CTX;
    desc: Pkeytype_desc_st;
    selection: Integer;
  end;

  keytype_desc_st = record
    &type: Integer;
    name: PUTF8Char;
    fns: POSSL_DISPATCH;
    read_private_key: Tb2i_of_void_fn;
    read_public_key: Tb2i_of_void_fn;
    adjust_key: Tadjust_key_fn;
    free_key: Tfree_key_fn;
  end;

function msblob2key_newctx(provctx : Pointer;const desc : Pkeytype_desc_st):Pmsblob2key_ctx_st;
  procedure msblob2key_freectx( vctx : Pointer);
  function msblob2key_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
  function msblob2key_export_object(vctx : Pointer;const reference : Pointer; reference_sz : size_t; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;

  function msblob2dsa_newctx( provctx : Pointer):Pointer;
  function msblob2rsa_newctx( provctx : Pointer):Pointer;

  const  ossl_msblob_to_dsa_decoder_functions: array[0..4] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@msblob2dsa_newctx; data:nil)),
(function_id:  2; method:(code:@msblob2key_freectx; data:nil)),
(function_id:  11; method:(code:@msblob2key_decode; data:nil)),
(function_id:  20; method:(code:@msblob2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_msblob_to_rsa_decoder_functions: array[0..4] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@msblob2rsa_newctx; data:nil)),
(function_id:  2; method:(code:@msblob2key_freectx; data:nil)),
(function_id:  11; method:(code:@msblob2key_decode; data:nil)),
(function_id:  20; method:(code:@msblob2key_export_object; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

var
  mstype2dsa_desc, mstype2rsa_desc: keytype_desc_st;
  
implementation
uses openssl3.crypto.mem, openssl3.crypto.bio.bio_prov, OpenSSL3.Err,
     openssl3.crypto.bio.bio_lib, openssl3.providers.fips.fipsprov,
     openssl3.crypto.pem.pvkfmt,  openssl3.crypto.passphrase,
     openssl3.crypto.params,      openssl3.crypto.dsa.dsa_lib,
     openssl3.crypto.rsa.rsa_lib, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     openssl3.providers.implementations.encode_decode.endecoder_common;

procedure rsa_adjust( key : Pointer; ctx : Pmsblob2key_ctx_st);
begin
    ossl_rsa_set0_libctx(key, PROV_LIBCTX_OF(ctx.provctx));
end;

function  get_keytype_desc_st(
    _type: Integer;
    name: PUTF8Char;
    fns: POSSL_DISPATCH;
    read_private_key: Tb2i_of_void_fn;
    read_public_key: Tb2i_of_void_fn;
    adjust_key: Tadjust_key_fn;
    free_key: Tfree_key_fn):keytype_desc_st;
begin
    Result.&type:=_type;
    Result.name:=name;
    Result.fns:= fns;
    Result.read_private_key:=read_private_key;
    Result.read_public_key:=read_public_key;
    Result.adjust_key:=adjust_key;
    Result.free_key:=free_key;
end;

function msblob2dsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(msblob2key_newctx(provctx, @mstype2dsa_desc));
end;


function msblob2rsa_newctx( provctx : Pointer):Pointer;
begin
 Exit(msblob2key_newctx(provctx, @mstype2rsa_desc));
end;

function msblob2key_newctx(provctx : Pointer;const desc : Pkeytype_desc_st):Pmsblob2key_ctx_st;
var
  ctx : Pmsblob2key_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then begin
        ctx.provctx := provctx;
        ctx.desc := desc;
    end;
    Result := ctx;
end;


procedure msblob2key_freectx( vctx : Pointer);
var
  ctx : Pmsblob2key_ctx_st;
begin
    ctx := vctx;
    OPENSSL_free(Pointer(ctx));
end;


function msblob2key_decode( vctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  ctx         : Pmsblob2key_ctx_st;
  _in         : PBIO;
  p           : PByte;
  hdr_buf     : array[0..15] of Byte;
  buf         : PByte;

  bitlen,
  magic,
  length      : uint32;
  isdss,
  ispub       : integer;

  key         : Pointer;
  ok          : integer;
  pwdata      : ossl_passphrase_data_st;
  params      : array[0..3] of TOSSL_PARAM;
  object_type : integer;
  label _next, _end;
begin
    ctx := vctx;
    _in := ossl_bio_new_from_core_bio(ctx.provctx, cin);
    buf := nil;
    isdss := -1;
    ispub := -1;
    key := nil;
    ok := 0;
    if _in = nil then Exit(0);
    if BIO_read(_in, @hdr_buf, 16) <> 16  then begin
        ERR_raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT);
        goto _next;
    end;
    ERR_set_mark;
    p := @hdr_buf;
    ok := Int(ossl_do_blob_header(@p, 16, @magic, @bitlen, @isdss, @ispub) > 0);
    ERR_pop_to_mark;
    if 0>=ok then goto _next;
    ctx.selection := selection;
    ok := 0;                      { Assume that we fail }
    if (isdss > 0)  and  (ctx.desc.&type <> EVP_PKEY_DSA) or
       ( (0>=isdss)  and  (ctx.desc.&type <> EVP_PKEY_RSA) ) then
        goto _next;
    length := ossl_blob_length(bitlen, isdss, ispub);
    if length > BLOB_MAX_LENGTH then begin
        ERR_raise(ERR_LIB_PEM, PEM_R_HEADER_TOO_LONG);
        goto _next;
    end;
    buf := OPENSSL_malloc(length);
    if buf = nil then begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _end;
    end;
    p := buf;
    if BIO_read(_in, buf, length) <> int(length)  then begin
        ERR_raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT);
        goto _next;
    end;
    if ( (selection = 0)
          or  (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY  <> 0) )
         and  (0 >= ispub )
         and  (Assigned(ctx.desc.read_private_key)) then
    begin
        memset(@pwdata, 0, sizeof(pwdata));
        if 0>=ossl_pw_set_ossl_passphrase_cb(@pwdata, pw_cb, pw_cbarg) then
            goto _end;
        p := buf;
        key := ctx.desc.read_private_key(@p, bitlen, ispub);
        if (selection <> 0)  and  (key = nil) then goto _next;
    end;
    if (key = nil)  and ( (selection = 0)
          or  (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY <> 0) )
         and  (ispub > 0)
         and  (Assigned(ctx.desc.read_public_key))  then
    begin
        p := buf;
        key := ctx.desc.read_public_key(@p, bitlen, ispub);
        if (selection <> 0)  and  (key = nil) then goto _next;
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
    OPENSSL_free(buf);
    BIO_free(_in);
    buf := nil;
    _in := nil;
    if key <> nil then begin
        object_type := OSSL_OBJECT_PKEY;
        params[0] := OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @object_type);
        params[1] := OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             ctx.desc.name, 0);
        { The address of the key becomes the octet string }
        params[2] := OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &key, sizeof(key));
        params[3] := OSSL_PARAM_construct_end;
        ok := data_cb(@params, data_cbarg);
    end;
 _end:
    BIO_free(_in);
    OPENSSL_free(buf);
    ctx.desc.free_key(key);
    Result := ok;
end;


function msblob2key_export_object(vctx : Pointer;const reference : Pointer; reference_sz : size_t; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;
var
  ctx : Pmsblob2key_ctx_st;
  _export : TOSSL_FUNC_keymgmt_export_fn;
  keydata : Pointer;
begin
    ctx := vctx;
    _export := ossl_prov_get_keymgmt_export(ctx.desc.fns);

    if (reference_sz = sizeof(keydata))  and  (Assigned(_export)) then
    begin
        { The contents of the reference is the address to our object }
        keydata := PPointer(reference)^;
        Exit(_export(keydata, ctx.selection, export_cb, export_cbarg));
    end;
    Result := 0;
end;

initialization
   mstype2dsa_desc := get_keytype_desc_st
      ( 116, 'DSA', @ossl_dsa_keymgmt_functions, 
        Pb2i_of_void_fn(@ossl_b2i_DSA_after_header)^, 
        Pb2i_of_void_fn(@ossl_b2i_DSA_after_header)^, Pointer(0) , Pfree_key_fn(@DSA_free)^ );

 

   mstype2rsa_desc := get_keytype_desc_st
      ( 6, 'RSA', @ossl_rsa_keymgmt_functions, 
        Pb2i_of_void_fn(@ossl_b2i_RSA_after_header)^, 
        Pb2i_of_void_fn(@ossl_b2i_RSA_after_header)^, rsa_adjust, Pfree_key_fn(@DSA_free)^ );



end.
