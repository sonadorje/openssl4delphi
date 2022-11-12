unit openssl3.crypto.conf.conf_mall;

interface
uses OpenSSL.Api;

procedure OPENSSL_load_builtin_modules;

implementation
uses openssl3.crypto.asn1.asn_moid,        openssl3.crypto.asn1.asn_mstbl,
     openssl3.crypto.conf.conf_ssl,        openssl3.crypto.provider_conf,
     openssl3.crypto.rand.rand_lib,
     openssl3.crypto.engine.eng_cnf,       openssl3.crypto.evp.evp_cnf;

procedure OPENSSL_load_builtin_modules;
begin
    { Add builtin modules here }
    ASN1_add_oid_module();
    ASN1_add_stable_module();
{$IFNDEF OPENSSL_NO_ENGINE}
    ENGINE_add_conf_module();
{$ENDIF}
    EVP_add_alg_module();
    ossl_config_add_ssl_module();
    ossl_provider_add_conf_module();
    ossl_random_add_conf_module();
end;


end.
