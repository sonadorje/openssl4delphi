unit OpenSSL3.providers.implementations.exchange.kdf_exch;

interface
uses OpenSSL.Api;

type
  TPROV_KDF_CTX = record
    provctx : Pointer;
    kdfctx : PEVP_KDF_CTX;
    kdfdata : PKDF_DATA;
  end;
  PPROV_KDF_CTX = ^TPROV_KDF_CTX;

function kdf_newctx(const kdfname : PUTF8Char; provctx : Pointer):Pointer;
  function kdf_init(vpkdfctx, vkdf : Pointer;const params : POSSL_PARAM):integer;
  function kdf_derive( vpkdfctx : Pointer; secret : PByte; secretlen : Psize_t; outlen : size_t):integer;
  procedure kdf_freectx( vpkdfctx : Pointer);
  function kdf_dupctx( vpkdfctx : Pointer):Pointer;
  function kdf_set_ctx_params(vpkdfctx : Pointer;const params : POSSL_PARAM):integer;
  function kdf_settable_ctx_params(vpkdfctx, provctx : Pointer;const kdfname : PUTF8Char):POSSL_PARAM;

  function kdf_tls1_prf_newctx( provctx : Pointer):Pointer;
  function kdf_hkdf_newctx( provctx : Pointer):Pointer;
  function kdf_scrypt_newctx( provctx : Pointer):Pointer;
  function kdf_tls1_prf_settable_ctx_params( vpkdfctx, provctx : Pointer):POSSL_PARAM;
  function kdf_hkdf_settable_ctx_params( vpkdfctx, provctx : Pointer):POSSL_PARAM;
  function kdf_scrypt_settable_ctx_params( vpkdfctx, provctx : Pointer):POSSL_PARAM;


const
   ossl_kdf_tls1_prf_keyexch_functions: array[0..7] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@kdf_tls1_prf_newctx; data:nil)),
(function_id:  2; method:(code:@kdf_init; data:nil)),
(function_id:  3; method:(code:@kdf_derive; data:nil)),
(function_id:  5; method:(code:@kdf_freectx; data:nil)),
(function_id:  6; method:(code:@kdf_dupctx; data:nil)),
(function_id:  7; method:(code:@kdf_set_ctx_params; data:nil)),
(function_id:  8; method:(code:@kdf_tls1_prf_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 ossl_kdf_hkdf_keyexch_functions: array[0..7] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@kdf_hkdf_newctx; data:nil)),
(function_id:  2; method:(code:@kdf_init; data:nil)),
(function_id:  3; method:(code:@kdf_derive; data:nil)),
(function_id:  5; method:(code:@kdf_freectx; data:nil)),
(function_id:  6; method:(code:@kdf_dupctx; data:nil)),
(function_id:  7; method:(code:@kdf_set_ctx_params; data:nil)),
(function_id:  8; method:(code:@kdf_hkdf_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

 ossl_kdf_scrypt_keyexch_functions: array[0..7] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@kdf_scrypt_newctx; data:nil)),
(function_id:  2; method:(code:@kdf_init; data:nil)),
(function_id:  3; method:(code:@kdf_derive; data:nil)),
(function_id:  5; method:(code:@kdf_freectx; data:nil)),
(function_id:  6; method:(code:@kdf_dupctx; data:nil)),
(function_id:  7; method:(code:@kdf_set_ctx_params; data:nil)),
(function_id:  8; method:(code:@kdf_scrypt_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses openssl3.providers.fips.self_test,   openssl3.crypto.mem,
     openssl3.crypto.evp.kdf_lib,         OpenSSL3.providers.implementations.kdf_legacy_kmgmt,
     openssl3.crypto.evp.kdf_meth,        OpenSSL3.providers.common.provider_ctx;





function kdf_tls1_prf_settable_ctx_params( vpkdfctx, provctx : Pointer):POSSL_PARAM;
begin
   Result := kdf_settable_ctx_params(vpkdfctx, provctx, 'TLS1-PRF');
end;


function kdf_hkdf_settable_ctx_params( vpkdfctx, provctx : Pointer):POSSL_PARAM;
begin
   Result := kdf_settable_ctx_params(vpkdfctx, provctx, 'HKDF');
end;


function kdf_scrypt_settable_ctx_params( vpkdfctx, provctx : Pointer):POSSL_PARAM;
begin
   Result := kdf_settable_ctx_params(vpkdfctx, provctx, 'SCRYPT');
end;



function kdf_tls1_prf_newctx( provctx : Pointer):Pointer;
begin
   Result := kdf_newctx('TLS1-PRF', provctx);
end;


function kdf_hkdf_newctx( provctx : Pointer):Pointer;
begin
   Result := kdf_newctx('HKDF', provctx);
end;


function kdf_scrypt_newctx( provctx : Pointer):Pointer;
begin
   Result := kdf_newctx('SCRYPT', provctx);
end;

function kdf_newctx(const kdfname : PUTF8Char; provctx : Pointer):Pointer;
var
  kdfctx : PPROV_KDF_CTX;
  kdf : PEVP_KDF;
  label _err ;
begin
    kdf := nil;
    if not ossl_prov_is_running then Exit(nil);
    kdfctx := OPENSSL_zalloc(sizeof(TPROV_KDF_CTX));
    if kdfctx = nil then Exit(nil);
    kdfctx.provctx := provctx;
    kdf := EVP_KDF_fetch( ossl_prov_ctx_get0_libctx(provctx), kdfname, nil);
    if kdf = nil then goto _err;
    kdfctx.kdfctx := EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if kdfctx.kdfctx = nil then goto _err;
    Exit(kdfctx);
_err:
    OPENSSL_free(kdfctx);
    Result := nil;
end;


function kdf_init(vpkdfctx, vkdf : Pointer;const params : POSSL_PARAM):integer;
var
  pkdfctx : PPROV_KDF_CTX;
begin
    pkdfctx := PPROV_KDF_CTX(vpkdfctx);
    if (not ossl_prov_is_running)
             or  (pkdfctx = nil)
             or  (vkdf = nil)
             or  (0>=ossl_kdf_data_up_ref(vkdf)) then
        Exit(0);
    pkdfctx.kdfdata := vkdf;
    Result := kdf_set_ctx_params(pkdfctx, params);
end;


function kdf_derive( vpkdfctx : Pointer; secret : PByte; secretlen : Psize_t; outlen : size_t):integer;
var
  pkdfctx : PPROV_KDF_CTX;
begin
    pkdfctx := PPROV_KDF_CTX(vpkdfctx);
    if not ossl_prov_is_running then Exit(0);
    if secret = nil then begin
        secretlen^ := EVP_KDF_CTX_get_kdf_size(pkdfctx.kdfctx);
        Exit(1);
    end;
    Result := EVP_KDF_derive(pkdfctx.kdfctx, secret, outlen, nil);
end;


procedure kdf_freectx( vpkdfctx : Pointer);
var
  pkdfctx : PPROV_KDF_CTX;
begin
    pkdfctx := PPROV_KDF_CTX(vpkdfctx);
    EVP_KDF_CTX_free(pkdfctx.kdfctx);
    ossl_kdf_data_free(pkdfctx.kdfdata);
    OPENSSL_free(pkdfctx);
end;


function kdf_dupctx( vpkdfctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_KDF_CTX;
begin
    srcctx := PPROV_KDF_CTX(vpkdfctx);
    if not ossl_prov_is_running then Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    dstctx.kdfctx := EVP_KDF_CTX_dup(srcctx.kdfctx);
    if dstctx.kdfctx = nil then begin
        OPENSSL_free(dstctx);
        Exit(nil);
    end;
    if 0>=ossl_kdf_data_up_ref(dstctx.kdfdata) then
    begin
        EVP_KDF_CTX_free(dstctx.kdfctx);
        OPENSSL_free(dstctx);
        Exit(nil);
    end;
    Result := dstctx;
end;


function kdf_set_ctx_params(vpkdfctx : Pointer;const params : POSSL_PARAM):integer;
var
  pkdfctx : PPROV_KDF_CTX;
begin
    pkdfctx := PPROV_KDF_CTX(vpkdfctx);
    Result := EVP_KDF_CTX_set_params(pkdfctx.kdfctx, params);
end;


function kdf_settable_ctx_params(vpkdfctx, provctx : Pointer;const kdfname : PUTF8Char):POSSL_PARAM;
var
  kdf : PEVP_KDF;
  params : POSSL_PARAM;
begin
    kdf := EVP_KDF_fetch(PROV_LIBCTX_OF(provctx), kdfname,
                                 nil);
    if kdf = nil then Exit(nil);
    params := EVP_KDF_settable_ctx_params(kdf);
    EVP_KDF_free(kdf);
    Result := params;
end;


end.
