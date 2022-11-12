unit openssl3.crypto.provider.provider_predefined;

interface
uses OpenSSL.Api, openssl3.crypto.provider.defltprov,
     openssl3.providers.baseprov, openssl3.providers.nullprov;

const
  ossl_predefined_providers: array[0..3] of TOSSL_PROVIDER_INFO = (
{$ifdef FIPS_MODULE}
    ( name:'fips'; path:nil; init:ossl_fips_intern_provider_init;parameters: nil;is_fallback: 1 ),
{$else}
    ( name:'default'; path: nil; init: ossl_default_provider_init;parameters: nil;is_fallback: 1 ),
{$ifdef STATIC_LEGACY}
    ( name:'legacy'; path: nil; init:ossl_legacy_provider_init;parameters: nil;is_fallback: 0 ),
{$endif}
    ( name:'base'; path: nil; init: ossl_base_provider_init;parameters: nil;is_fallback: 0 ),
    ( name:'nil'; path: nil; init:ossl_null_provider_init;parameters: nil;is_fallback: 0 ),
{$endif}
    ( name:nil; path: nil; init: nil;parameters: nil;is_fallback: 0 )
);
implementation

end.
