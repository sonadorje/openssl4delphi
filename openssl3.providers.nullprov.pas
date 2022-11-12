unit openssl3.providers.nullprov;

interface
uses OpenSSL.Api;

function ossl_null_provider_init(const handle : POSSL_CORE_HANDLE; _in : POSSL_DISPATCH;var _out : POSSL_DISPATCH; provctx : PPointer):integer;
function null_gettable_params(const prov : POSSL_PROVIDER):POSSL_PARAM;
function null_get_params(const provctx : POSSL_PROVIDER; params : POSSL_PARAM):integer;
function null_query( prov : POSSL_PROVIDER; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;

const null_dispatch_table: array[0..3] of TOSSL_DISPATCH = (
    (function_id:   OSSL_FUNC_PROVIDER_GETTABLE_PARAMS; method:(code:@null_gettable_params; data:nil)),
    (function_id:   OSSL_FUNC_PROVIDER_GET_PARAMS; method:(code:@null_get_params; data:nil)),
    (function_id:   OSSL_FUNC_PROVIDER_QUERY_OPERATION; method:(code:@null_query; data:nil)),
    (function_id:  0; method:(code:nil; data:nil)));

var
   null_param_types: array of TOSSL_PARAM ;

implementation
uses openssl3.crypto.params, OpenSSL3.openssl.params,
     openssl3.providers.fips.self_test;

function null_gettable_params(const prov : POSSL_PROVIDER):POSSL_PARAM;
begin
    Result := @null_param_types[0];
end;


function null_get_params(const provctx : POSSL_PROVIDER; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, 'OpenSSL Null Provider')) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_int(p, Int(ossl_prov_is_running))) then
        Exit(0);
    Result := 1;
end;


function null_query( prov : POSSL_PROVIDER; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;
begin
    no_cache^ := 0;
    Result := nil;
end;



function ossl_null_provider_init(const handle : POSSL_CORE_HANDLE; _in : POSSL_DISPATCH;var _out : POSSL_DISPATCH; provctx : PPointer):integer;
begin
    _out := @null_dispatch_table;
    { Could be anything - we don't use it }
    provctx^ := Pointer(handle);
    Result := 1;
end;

initialization
  null_param_types := [
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, nil, 0),
    OSSL_PARAM_END
];
end.
