unit OpenSSL3.providers.implementations.ciphers.cipher_camellia_hw;

interface
uses OpenSSL.Api;

function cipher_hw_camellia_initkey(dat : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
function ossl_prov_cipher_hw_camellia_cbc( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_camellia_ecb( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_camellia_ofb128( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_camellia_cfb128( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_camellia_cfb1( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_camellia_cfb8( keybits : size_t):PPROV_CIPHER_HW;
  function ossl_prov_cipher_hw_camellia_ctr( keybits : size_t):PPROV_CIPHER_HW;

 procedure cipher_hw_camellia_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);

implementation
uses openssl3.crypto.camellia.cmll_misc, OpenSSL3.Err,
     openssl3.crypto.camellia.cmll_cbc,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw;




const
 camellia_cbc: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_cbc; copyctx: cipher_hw_camellia_copyctx );
 camellia_ecb: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_ecb; copyctx: cipher_hw_camellia_copyctx );
camellia_ofb128: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_ofb128; copyctx: cipher_hw_camellia_copyctx );
camellia_cfb128: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_cfb128; copyctx: cipher_hw_camellia_copyctx );
camellia_cfb1: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_cfb1; copyctx: cipher_hw_camellia_copyctx );
camellia_cfb8: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_cfb8; copyctx: cipher_hw_camellia_copyctx );
camellia_ctr: TPROV_CIPHER_HW =
(init:  cipher_hw_camellia_initkey; cipher: ossl_cipher_hw_generic_ctr; copyctx: cipher_hw_camellia_copyctx );


procedure cipher_hw_camellia_copyctx(dst : PPROV_CIPHER_CTX;const src : PPROV_CIPHER_CTX);
var
  sctx, dctx : PPROV_CAMELLIA_CTX;
begin
   sctx := PPROV_CAMELLIA_CTX(src);
   dctx := PPROV_CAMELLIA_CTX(dst);
   dctx^ := sctx^;
   dst.ks := @dctx.ks.ks;
end;


function ossl_prov_cipher_hw_camellia_cbc( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_cbc;
end;


function ossl_prov_cipher_hw_camellia_ecb( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_ecb;
end;


function ossl_prov_cipher_hw_camellia_ofb128( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_ofb128;
end;


function ossl_prov_cipher_hw_camellia_cfb128( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_cfb128;
end;


function ossl_prov_cipher_hw_camellia_cfb1( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_cfb1;
end;


function ossl_prov_cipher_hw_camellia_cfb8( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_cfb8;
end;


function ossl_prov_cipher_hw_camellia_ctr( keybits : size_t):PPROV_CIPHER_HW;
begin
  Result := @camellia_ctr;
end;

function cipher_hw_camellia_initkey(dat : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t):integer;
var
  ret, mode : integer;
  adat : PPROV_CAMELLIA_CTX;
  ks : PCAMELLIA_KEY;
begin
    mode := dat.mode;
    adat := PPROV_CAMELLIA_CTX(dat);
    ks := @adat.ks.ks;
    dat.ks := ks;
    ret := Camellia_set_key(key, keylen * 8, ks);
    if ret < 0 then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        Exit(0);
    end;
    if (dat.enc > 0)  or ( (mode <> EVP_CIPH_ECB_MODE)  and  (mode <> EVP_CIPH_CBC_MODE) ) then
    begin
        dat.block := Pblock128_f(@Camellia_encrypt)^;
        if mode = EVP_CIPH_CBC_MODE then
           dat.stream.cbc := Pcbc128_f(@Camellia_cbc_encrypt)^
        else
           dat.stream.cbc := nil;
    end
    else
    begin
        dat.block := Pblock128_f(@Camellia_decrypt)^;
        if mode = EVP_CIPH_CBC_MODE then
           dat.stream.cbc := Pcbc128_f(@Camellia_cbc_encrypt)^
        else
           dat.stream.cbc := nil;
    end;
    Result := 1;
end;

end.
