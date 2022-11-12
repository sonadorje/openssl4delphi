unit openssl3.crypto.err.err_all;

interface
uses OpenSSL.Api;

function ossl_err_load_crypto_strings:integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_err, openssl3.crypto.rsa.rsa_err,
     openssl3.crypto.buffer.buf_err,          openssl3.crypto.objects.obj_err,
     openssl3.crypto.pem.pem_err,             openssl3.crypto.dsa.dsa_err,
     openssl3.crypto.x509.x509_err,           openssl3.crypto.asn1.asn1_err,
     openssl3.crypto.x509.v3err,              openssl3.crypto.pkcs12.pk12err,
     openssl3.crypto.pkcs7.pkcs7err,          openssl3.crypto.rand.randerr,
     openssl3.crypto.ec.ec_err,               openssl3.crypto.bio.bio_err,
     openssl3.crypto.dso.dso_err,             openssl3.crypto.ts.ts_err,
     openssl3.crypto.engine.eng_err,          openssl3.crypto.http.http_err,
     openssl3.crypto.ocsp.ocsp_err,           openssl3.crypto.ui.ui_err,
     openssl3.crypto.cms.cms_err,             openssl3.crypto.crmf.crmf_err,
     openssl3.crypto.conf.conf_err,           openssl3.crypto.comp.comp_err,
     openssl3.crypto.cmp.cmp_err,             openssl3.crypto.ct.ct_err,
     openssl3.crypto.store.store_err,         openssl3.crypto.property_.property_err,
     openssl3.crypto.ess.ess_err,             openssl3.crypto.async.async_err,
     openssl3.provider.common.provider_err,   openssl3.crypto.cpt_err,
     openssl3.crypto.dh.dh_err              , openssl3.crypto.evp.evp_err;

function ossl_err_load_crypto_strings:integer;
var
  e: array[0..34] of Byte;
  I: Integer;
begin

{$IFNDEF OPENSSL_NO_ERR}
         e[0] :=ossl_err_load_ERR_strings; { include error strings for SYSerr }
         e[1] :=ossl_err_load_BN_strings;
         e[2] :=ossl_err_load_RSA_strings;
{$IFNDEF OPENSSL_NO_DH}
         e[3] :=ossl_err_load_DH_strings;
{$ENDIF}
         e[4] :=ossl_err_load_EVP_strings;
         e[5] :=ossl_err_load_BUF_strings;
         e[6] :=ossl_err_load_OBJ_strings;
         e[7] :=ossl_err_load_PEM_strings;
{$IFNDEF OPENSSL_NO_DSA}
         e[8] :=ossl_err_load_DSA_strings;
{$ENDIF}
         e[9]  :=ossl_err_load_X509_strings;
         e[10] :=ossl_err_load_ASN1_strings;
         e[11] :=ossl_err_load_CONF_strings;
         e[12] := _ossl_err_load_CRYPTO_strings;
{$IFNDEF OPENSSL_NO_COMP}
         e[13] :=ossl_err_load_COMP_strings;
{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
         e[14] :=ossl_err_load_EC_strings;
{$ENDIF}
        { skip ossl_err_load_SSL_strings() because it is not in this library }
         e[15] :=ossl_err_load_BIO_strings;
         e[16] :=ossl_err_load_PKCS7_strings;
         e[17] :=ossl_err_load_X509V3_strings;
         e[18] :=ossl_err_load_PKCS12_strings;
         e[19] :=ossl_err_load_RAND_strings;
         e[20] :=ossl_err_load_DSO_strings;
{$IFNDEF OPENSSL_NO_TS}
         e[21] :=ossl_err_load_TS_strings;
{$ENDIF}
{$IFNDEF OPENSSL_NO_ENGINE}
         e[22] :=ossl_err_load_ENGINE_strings;
{$ENDIF}
         e[23] :=ossl_err_load_HTTP_strings;
{$IFNDEF OPENSSL_NO_OCSP}
         e[24] :=ossl_err_load_OCSP_strings;
{$ENDIF}
         e[25] :=ossl_err_load_UI_strings;
{$IFNDEF OPENSSL_NO_CMS}
         e[26] :=ossl_err_load_CMS_strings;
{$ENDIF}
{$IFNDEF OPENSSL_NO_CRMF}
         e[27] :=ossl_err_load_CRMF_strings;
         e[28] :=ossl_err_load_CMP_strings;
{$ENDIF}
{$IFNDEF OPENSSL_NO_CT}
         e[29] :=ossl_err_load_CT_strings;
{$ENDIF}
         e[30] :=ossl_err_load_ESS_strings;
         e[31] :=ossl_err_load_ASYNC_strings;
         e[32] :=ossl_err_load_OSSL_STORE_strings;
         e[33] :=ossl_err_load_PROP_strings;
         e[34] :=ossl_err_load_PROV_strings;
{$ENDIF}
   for I := Low(e) to High(e) do
      if e[I] = 0 then
         Exit(0);

   Result := 1;
end;


end.
