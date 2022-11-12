unit openssl3.providers.implementations.storemgmt.file_store_any2obj;

interface
uses OpenSSL.Api;

function any2obj_newctx( provctx : Pointer):Pointer;
  procedure any2obj_freectx( vctx : Pointer);
  function any2obj_decode_final( provctx : Pointer; objtype : integer; mem : PBUF_MEM; data_cb : POSSL_CALLBACK; data_cbarg : Pointer):integer;
  function der2obj_decode( provctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
  function msblob2obj_decode( provctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
  function pvk2obj_decode( provctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;


const
 der_to_obj_decoder_functions: array[0..3] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@any2obj_newctx; data:nil)),
(function_id:  2; method:(code:@any2obj_freectx; data:nil)),
(function_id:  11; method:(code:@der2obj_decode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

msblob_to_obj_decoder_functions: array[0..3] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@any2obj_newctx; data:nil)),
(function_id:  2; method:(code:@any2obj_freectx; data:nil)),
(function_id:  11; method:(code:@msblob2obj_decode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

pvk_to_obj_decoder_functions: array[0..3] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@any2obj_newctx; data:nil)),
(function_id:  2; method:(code:@any2obj_freectx; data:nil)),
(function_id:  11; method:(code:@pvk2obj_decode; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const ossl_any_to_obj_algorithm: array[0..3] of TOSSL_ALGORITHM  = (
    ( algorithm_names: 'obj'; property_definition   :'input=DER';    _implementation: @der_to_obj_decoder_functions ),
    ( algorithm_names: 'obj'; property_definition   :'input=MSBLOB'; _implementation: @msblob_to_obj_decoder_functions ),
    ( algorithm_names: 'obj'; property_definition   :'input=PVK';    _implementation: @pvk_to_obj_decoder_functions ),
    ( algorithm_names: nil;   property_definition   :nil; _implementation: nil )
);

implementation
uses openssl3.crypto.params,        openssl3.crypto.buffer.buffer,
     openssl3.crypto.asn1.a_d2i_fp, openssl3.crypto.bio.bio_lib,
     OpenSSL3.Err,                  openssl3.crypto.pem.pvkfmt,
     openssl3.crypto.bio.bio_prov,  openssl3.providers.fips.fipsprov;


function any2obj_newctx( provctx : Pointer):Pointer;
begin
    Result := provctx;
end;


procedure any2obj_freectx( vctx : Pointer);
begin

end;


function any2obj_decode_final( provctx : Pointer; objtype : integer; mem : PBUF_MEM; data_cb : POSSL_CALLBACK; data_cbarg : Pointer):integer;
var
  ok : integer;

  params : array[0..2] of TOSSL_PARAM;
begin
    {
     * 1 indicates that we successfully decoded something, or not at all.
     * Ending up 'empty handed' is not an error.
     }
    ok := 1;
    if mem <> nil then begin
        params[0] := OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, @objtype);
        params[1] := OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                              mem.data, mem.length);
        params[2] := OSSL_PARAM_construct_end;
        ok := data_cb(@params, data_cbarg);
        BUF_MEM_free(mem);
    end;
    Result := ok;
end;


function der2obj_decode( provctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  _in : PBIO;
  mem : PBUF_MEM;
  ok : integer;
begin
    _in := ossl_bio_new_from_core_bio(provctx, cin);
    mem := nil;
    if _in = nil then Exit(0);
    ERR_set_mark;
    ok := int(asn1_d2i_read_bio(_in, @mem) >= 0);
    ERR_pop_to_mark;
    if (0>=ok)  and  (mem <> nil) then
    begin
        BUF_MEM_free(mem);
        mem := nil;
    end;
    BIO_free(_in);
    { any2obj_decode_final frees |mem| for us }
    Exit(any2obj_decode_final(provctx, OSSL_OBJECT_UNKNOWN, mem,
                                data_cb, data_cbarg));
end;


function msblob2obj_decode( provctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  _in : PBIO;
  mem : PBUF_MEM;
  mem_len, mem_want : size_t;
  p : PByte;
  bitlen, magic : uint32;
  isdss, ispub, ok : integer;
  label _err, _next;
begin
    _in := ossl_bio_new_from_core_bio(provctx, cin);
    mem := nil;
    mem_len := 0;
    isdss := -1;
    ispub := -1;
    ok := 0;
    if _in = nil then goto _err;
    mem := BUF_MEM_new();
    mem_want := 16;               { The size of the MSBLOB header }
    if (mem = nil)
         or  (0>=BUF_MEM_grow(mem, mem_want)) then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    ERR_set_mark;
    ok := Int(BIO_read(_in, @mem.data[0], mem_want) = int(mem_want));
    mem_len  := mem_len + mem_want;
    ERR_pop_to_mark;
    if 0>=ok then goto _next;
    ERR_set_mark;
    p := PByte(@mem.data[0]);
    ok := Int(ossl_do_blob_header(@p, 16, @magic, @bitlen, @isdss, @ispub) > 0);
    ERR_pop_to_mark;
    if 0>=ok then goto _next;
    ok := 0;
    mem_want := ossl_blob_length(bitlen, isdss, ispub);
    if 0>=BUF_MEM_grow(mem, mem_len + mem_want) then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    ERR_set_mark;
    ok := Int(BIO_read(_in, @mem.data[mem_len], mem_want) = int(mem_want));
    mem_len  := mem_len + mem_want;
    ERR_pop_to_mark;
 _next:
    { Free resources we no longer need. }
    BIO_free(_in);
    if (0>=ok)  and  (mem <> nil) then
    begin
        BUF_MEM_free(mem);
        mem := nil;
    end;
    { any2obj_decode_final frees |mem| for us }
    Exit(any2obj_decode_final(provctx, OSSL_OBJECT_PKEY, mem,
                                data_cb, data_cbarg));
 _err:
    BIO_free(_in);
    BUF_MEM_free(mem);
    Result := 0;
end;


function pvk2obj_decode( provctx : Pointer; cin : POSSL_CORE_BIO; selection : integer; data_cb : POSSL_CALLBACK; data_cbarg : Pointer; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  _in : PBIO;
  mem : PBUF_MEM;
  mem_len, mem_want : size_t;
  p : PByte;
  saltlen, keylen : uint32;
  ok : integer;
  label _err, _next;
begin
    _in := ossl_bio_new_from_core_bio(provctx, cin);
    mem := nil;
    mem_len := 0;
    ok := 0;
    if _in = nil then goto _err;
    mem_want := 24;               { The size of the PVK header }
    mem := BUF_MEM_new();
    if (mem = nil ) or  (0>=BUF_MEM_grow(mem, mem_want)) then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    ERR_set_mark;
    ok := Int(BIO_read(_in, @mem.data[0], mem_want) = int(mem_want));
    mem_len  := mem_len + mem_want;
    ERR_pop_to_mark;
    if 0>=ok then goto _next;
    ERR_set_mark;
    p := PByte(@mem.data[0]);
    ok := Int(ossl_do_PVK_header(@p, 24, 0, @saltlen, @keylen) > 0);
    ERR_pop_to_mark;
    if 0>=ok then goto _next;
    ok := 0;
    mem_want := saltlen + keylen;
    if 0>=BUF_MEM_grow(mem, mem_len + mem_want) then
    begin
        ERR_raise(ERR_LIB_PEM, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    ERR_set_mark;
    ok := Int(BIO_read(_in, @mem.data[mem_len], mem_want) = int(mem_want));
    mem_len  := mem_len + mem_want;
    ERR_pop_to_mark;
 _next:
    { Free resources we no longer need. }
    BIO_free(_in);
    if (0>=ok)  and  (mem <> nil) then
    begin
        BUF_MEM_free(mem);
        mem := nil;
    end;
    { any2obj_decode_final frees |mem| for us }
    Exit(any2obj_decode_final(provctx, OSSL_OBJECT_PKEY, mem,
                                data_cb, data_cbarg));
 _err:
    BIO_free(_in);
    BUF_MEM_free(mem);
    Result := 0;
end;

end.
