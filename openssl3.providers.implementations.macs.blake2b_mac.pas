unit openssl3.providers.implementations.macs.blake2b_mac;

interface
uses OpenSSL.Api,
     openssl3.providers.implementations.digests.digestcommon,
     openssl3.providers.implementations.digests.blake2_impl,
     openssl3.crypto.md5.md5_dgst;

type
   BLAKE2_CTX    = TBLAKE2B_CTX;
   BLAKE2_PARAM  = TBLAKE2B_PARAM ;

var
   I: Int;
   ossl_blake2bmac_functions: array[0..10] of TOSSL_DISPATCH ;

implementation
uses openssl3.crypto.params, openssl3.crypto.sha.sha3,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, openssl3.providers.implementations.digests.blake2b_prov;


initialization

//BLAKE2_CTX           := BLAKE2B_CTX;
//BLAKE2_PARAM         = BLAKE2B_PARAM ;
BLAKE2_KEYBYTES      := BLAKE2B_KEYBYTES ;
BLAKE2_OUTBYTES      := BLAKE2B_OUTBYTES ;
BLAKE2_PERSONALBYTES := BLAKE2B_PERSONALBYTES ;
BLAKE2_SALTBYTES     := BLAKE2B_SALTBYTES ;
BLAKE2_BLOCKBYTES    := BLAKE2B_BLOCKBYTES;

BLAKE2_PARAM_INIT              := ossl_blake2b_param_init;
BLAKE2_INIT_KEY                := ossl_blake2b_init_key;
BLAKE2_UPDATE                  := ossl_blake2b_update;
BLAKE2_FINAL                   := ossl_blake2b_final;
BLAKE2_PARAM_SET_DIGEST_LENGTH := ossl_blake2b_param_set_digest_length;
BLAKE2_PARAM_SET_KEY_LENGTH    := ossl_blake2b_param_set_key_length;
BLAKE2_PARAM_SET_PERSONAL      := ossl_blake2b_param_set_personal;
BLAKE2_PARAM_SET_SALT          := ossl_blake2b_param_set_salt;

for I := Low(BLAKE2_FUNCTIONS) to High(BLAKE2_FUNCTIONS)-1 do
    ossl_blake2bmac_functions[I] := BLAKE2_FUNCTIONS[I]

end.
