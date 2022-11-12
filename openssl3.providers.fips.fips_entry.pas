unit openssl3.providers.fips.fips_entry;

interface
uses OpenSSL.Api;

function OSSL_provider_init(const handle : POSSL_CORE_HANDLE;{const} _in : POSSL_DISPATCH; _out : PPOSSL_DISPATCH;var provctx : Pointer):integer;

implementation
uses openssl3.providers.fips.fipsprov;

function OSSL_provider_init(const handle : POSSL_CORE_HANDLE;{const} _in : POSSL_DISPATCH; _out : PPOSSL_DISPATCH;var provctx : Pointer):integer;
begin
    Result := OSSL_provider_init_int(handle, _in, _out, provctx);
end;


end.
