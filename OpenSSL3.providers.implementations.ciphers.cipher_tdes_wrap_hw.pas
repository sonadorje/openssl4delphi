unit OpenSSL3.providers.implementations.ciphers.cipher_tdes_wrap_hw;

interface
uses OpenSSL.Api;

 function ossl_prov_cipher_hw_tdes_wrap_cbc:PPROV_CIPHER_HW;


implementation
uses OpenSSL3.providers.implementations.ciphers.cipher_tdes_hw;

const
  wrap_cbc : TPROV_CIPHER_HW = (init: ossl_cipher_hw_tdes_ede3_initkey; cipher: ossl_cipher_hw_tdes_cbc; copyctx: ossl_cipher_hw_tdes_copyctx );

function ossl_prov_cipher_hw_tdes_wrap_cbc:PPROV_CIPHER_HW;
begin
 Result := @wrap_cbc;
end;

end.
