unit openssl3.crypto.x509.standard_exts;

interface
uses OpenSSL.Api,
     OpenSSL3.crypto.x509.v3_bitst, OpenSSL3.crypto.x509.v3_ia5,
     OpenSSL3.crypto.x509.v3_san  , OpenSSL3.crypto.x509.v3_bcons,
     OpenSSL3.crypto.x509.v3_skid , OpenSSL3.crypto.x509.v3_pku,
     OpenSSL3.crypto.x509.v3_pci,   OpenSSL3.crypto.x509.v3_ncons,
     OpenSSL3.crypto.x509.v3_info,  OpenSSL3.crypto.x509.v3_pcons,
     OpenSSL3.crypto.x509.v3_akid,  OpenSSL3.crypto.x509.v3_crld,
     OpenSSL3.crypto.x509.v3_ocsp,  OpenSSL3.crypto.x509.v3_sxnet,
     OpenSSL3.crypto.x509.v3_extku, OpenSSL3.crypto.x509.v3_enum,
     OpenSSL3.crypto.x509.v3_addr,  OpenSSL3.crypto.x509.v3_asid,
     OpenSSL3.crypto.x509.v3_pmaps, OpenSSL3.crypto.ct.ct_x509v3,
     OpenSSL3.crypto.x509.v3_utf8,  OpenSSL3.crypto.x509.v3_ist,
     OpenSSL3.crypto.x509.v3_admis, OpenSSL3.crypto.x509.v3_tlsf,
     OpenSSL3.crypto.x509.v3_int,   OpenSSL3.crypto.x509.v3_cpols ;

const
  standard_exts: array[0..48] of PX509V3_EXT_METHOD = (
    @ossl_v3_nscert,
    @ossl_v3_ns_ia5_list[0],
    @ossl_v3_ns_ia5_list[1],
    @ossl_v3_ns_ia5_list[2],
    @ossl_v3_ns_ia5_list[3],
    @ossl_v3_ns_ia5_list[4],
    @ossl_v3_ns_ia5_list[5],
    @ossl_v3_ns_ia5_list[6],
    @ossl_v3_skey_id,
    @ossl_v3_key_usage,
    @ossl_v3_pkey_usage_period,
    @ossl_v3_alt[0],
    @ossl_v3_alt[1],
    @ossl_v3_bcons,
    @ossl_v3_crl_num,
    @ossl_v3_cpols,
    @ossl_v3_akey_id,
    @ossl_v3_crld,
    @ossl_v3_ext_ku,
    @ossl_v3_delta_crl,
    @ossl_v3_crl_reason,
{$ifndef OPENSSL_NO_OCSP}
    @ossl_v3_crl_invdate,
{$endif}
    @ossl_v3_sxnet,
    @ossl_v3_info,
{$ifndef OPENSSL_NO_RFC3779}
    @ossl_v3_addr,
    @ossl_v3_asid,
{$endif}
{$ifndef OPENSSL_NO_OCSP}
    @ossl_v3_ocsp_nonce,
    @ossl_v3_ocsp_crlid,
    @ossl_v3_ocsp_accresp,
    @ossl_v3_ocsp_nocheck,
    @ossl_v3_ocsp_acutoff,
    @ossl_v3_ocsp_serviceloc,
{$endif}
    @ossl_v3_sinfo,
    @ossl_v3_policy_constraints,
{$ifndef OPENSSL_NO_OCSP}
    @ossl_v3_crl_hold,
{$endif}
    @ossl_v3_pci,
    @ossl_v3_name_constraints,
    @ossl_v3_policy_mappings,
    @ossl_v3_inhibit_anyp,
    @ossl_v3_idp,
    @ossl_v3_alt[2],
    @ossl_v3_freshest_crl,
{$ifndef OPENSSL_NO_CT}
    @ossl_v3_ct_scts[0],
    @ossl_v3_ct_scts[1],
    @ossl_v3_ct_scts[2],
{$endif}
    @ossl_v3_utf8_list[0],
    @ossl_v3_issuer_sign_tool,
    @ossl_v3_tls_feature,
    @ossl_v3_ext_admission
);

implementation

end.
