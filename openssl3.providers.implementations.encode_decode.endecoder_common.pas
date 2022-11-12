unit openssl3.providers.implementations.encode_decode.endecoder_common;

interface
uses OpenSSL.Api,
     openssl3.crypto.md5.md5_dgst;

function ossl_prov_import_key(const fns : POSSL_DISPATCH; provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
function ossl_prov_get_keymgmt_new(fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_new_fn;
function _OSSL_FUNC_keymgmt_new(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_new_fn;
function ossl_prov_get_keymgmt_free( fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_free_fn;
function _OSSL_FUNC_keymgmt_free(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_free_fn;
function ossl_prov_get_keymgmt_import( fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_fn;
 function _OSSL_FUNC_keymgmt_import(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_fn;
 procedure ossl_prov_free_key(const fns : POSSL_DISPATCH; key : Pointer);
function ossl_read_der( provctx : PPROV_CTX; cin : POSSL_CORE_BIO; data : PPByte; len : Plong):integer;
function ossl_prov_get_keymgmt_export({const} fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;

implementation
uses openssl3.crypto.params,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.asn1.a_d2i_fp,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.mem_sec,
     openssl3.crypto.bio.bio_lib, OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.hmac.hmac, OpenSSL3.common,

     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params,
     openssl3.crypto.bio.bio_prov;


function ossl_prov_get_keymgmt_export({const} fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;
begin
    { Pilfer the keymgmt dispatch table }
    while fns.function_id <> 0 do
    begin
        if fns.function_id = OSSL_FUNC_KEYMGMT_EXPORT then
           Exit(_OSSL_FUNC_keymgmt_export(fns));
        Inc(fns);
    end;
    Result := nil;
end;




function ossl_read_der( provctx : PPROV_CTX; cin : POSSL_CORE_BIO; data : PPByte; len : Plong):integer;
var
  mem : PBUF_MEM;
  _in : PBIO;
  ok : integer;
begin
    mem := nil;
    _in := ossl_bio_new_from_core_bio(provctx, cin);
    if _in = nil then Exit(0);
    ok := int(asn1_d2i_read_bio(_in, @mem) >= 0);
    if ok > 0 then begin
        data^ := PByte(mem.data);
        len^ := long(mem.length);
        OPENSSL_free(mem);
    end;
    BIO_free(_in);
    Result := ok;
end;




procedure ossl_prov_free_key(const fns : POSSL_DISPATCH; key : Pointer);
var
  kmgmt_free : TOSSL_FUNC_keymgmt_free_fn;
begin
    kmgmt_free := ossl_prov_get_keymgmt_free(fns);
    if Assigned(kmgmt_free) then
       kmgmt_free(key);
end;





function _OSSL_FUNC_keymgmt_import(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_fn;
begin
    Result := TOSSL_FUNC_keymgmt_import_fn (opf._function);
end;


function ossl_prov_get_keymgmt_import( fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_fn;
begin
    { Pilfer the keymgmt dispatch table }
    while fns.function_id <> 0 do
    begin
        if fns.function_id = OSSL_FUNC_KEYMGMT_IMPORT then
           Exit(_OSSL_FUNC_keymgmt_import(fns));
        Inc(fns);
    end;
    Result := nil;
end;




function _OSSL_FUNC_keymgmt_free(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_free_fn;
begin
   Result := TOSSL_FUNC_keymgmt_free_fn(opf._function);
end;



function ossl_prov_get_keymgmt_free( fns : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_free_fn;
begin
    { Pilfer the keymgmt dispatch table }
    while fns.function_id <> 0 do
    begin
        if fns.function_id = OSSL_FUNC_KEYMGMT_FREE then
           Exit(_OSSL_FUNC_keymgmt_free(fns));
        Inc(fns);
    end;
    Result := nil;
end;





function _OSSL_FUNC_keymgmt_new(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_new_fn;
begin
    Result := TOSSL_FUNC_keymgmt_new_fn(opf._function);
end;




function ossl_prov_get_keymgmt_new(fns : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_new_fn;
begin
    { Pilfer the keymgmt dispatch table }
    while fns.function_id <> 0 do
    begin
        if fns.function_id = OSSL_FUNC_KEYMGMT_NEW then
           Exit(_OSSL_FUNC_keymgmt_new(fns));
        Inc(fns);
    end;
    Result := nil;
end;



function ossl_prov_import_key(const fns : POSSL_DISPATCH; provctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
var
    kmgmt_new    : TOSSL_FUNC_keymgmt_new_fn;

    kmgmt_free   : TOSSL_FUNC_keymgmt_free_fn;

    kmgmt_import : TOSSL_FUNC_keymgmt_import_fn;

    key          : Pointer;
begin
    kmgmt_new := ossl_prov_get_keymgmt_new(fns);
    kmgmt_free := ossl_prov_get_keymgmt_free(fns);
    kmgmt_import := ossl_prov_get_keymgmt_import(fns);

    key := nil;
    if Assigned(kmgmt_new)  and  Assigned(kmgmt_import)  and  Assigned(kmgmt_free) then
    begin
        key := kmgmt_new(provctx);
        if (key  = nil)
             or  (0>= kmgmt_import(key, selection, params)) then
        begin
            kmgmt_free(key);
            key := nil;
        end;
    end;
    Result := key;
end;




end.
