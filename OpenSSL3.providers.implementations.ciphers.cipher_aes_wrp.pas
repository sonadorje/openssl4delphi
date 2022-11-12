unit OpenSSL3.providers.implementations.ciphers.cipher_aes_wrp;

interface
uses OpenSSL.Api, OpenSSL3.providers.implementations.ciphers.ciphercommon;

const
  AES_WRAP_PAD_IVLEN   = 4;
  AES_WRAP_NOPAD_IVLEN = 8;
  WRAP_FLAGS           = (PROV_CIPHER_FLAG_CUSTOM_IV);
  WRAP_FLAGS_INV       = (WRAP_FLAGS or PROV_CIPHER_FLAG_INVERSE_CIPHER) ;

function aes_wrap_newctx( kbits, blkbits, ivbits : size_t; mode : uint32; flags : uint64):Pointer;
  procedure aes_wrap_freectx( vctx : Pointer);
  function aes_wrap_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
  function aes_wrap_einit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_wrap_dinit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function aes_wrap_cipher_internal(vctx : Pointer; _out : PByte;const _in : PByte; inlen : size_t):integer;
  function aes_wrap_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
  function aes_wrap_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
  function aes_wrap_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function CRYPTO_128_unwrap(key : Pointer;{const} iv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;

function aes_256_wrap_get_params( params : POSSL_PARAM):integer;
  function aes_256wrap_newctx( provctx : Pointer):Pointer;
  function aes_192_wrap_get_params( params : POSSL_PARAM):integer;
  function aes_192wrap_newctx( provctx : Pointer):Pointer;
  function aes_128_wrap_get_params( params : POSSL_PARAM):integer;
  function aes_128wrap_newctx( provctx : Pointer):Pointer;
  function aes_256_wrappad_get_params( params : POSSL_PARAM):integer;
  function aes_256wrappad_newctx( provctx : Pointer):Pointer;
  function aes_192_wrappad_get_params( params : POSSL_PARAM):integer;
  function aes_192wrappad_newctx( provctx : Pointer):Pointer;
  function aes_128_wrappad_get_params( params : POSSL_PARAM):integer;
  function aes_128wrappad_newctx( provctx : Pointer):Pointer;
  function aes_256_wrapinv_get_params( params : POSSL_PARAM):integer;
  function aes_256wrapinv_newctx( provctx : Pointer):Pointer;
  function aes_192_wrapinv_get_params( params : POSSL_PARAM):integer;
  function aes_192wrapinv_newctx( provctx : Pointer):Pointer;
  function aes_128_wrapinv_get_params( params : POSSL_PARAM):integer;
  function aes_128wrapinv_newctx( provctx : Pointer):Pointer;
  function aes_256_wrappadinv_get_params( params : POSSL_PARAM):integer;
  function aes_256wrappadinv_newctx( provctx : Pointer):Pointer;
  function aes_192_wrappadinv_get_params( params : POSSL_PARAM):integer;
  function aes_192wrappadinv_newctx( provctx : Pointer):Pointer;
  function aes_128_wrappadinv_get_params( params : POSSL_PARAM):integer;
  function aes_128wrappadinv_newctx( provctx : Pointer):Pointer;


const  ossl_aes256wrap_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_256wrap_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_256_wrap_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes192wrap_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_192wrap_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_192_wrap_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes128wrap_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_128wrap_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_128_wrap_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

const  ossl_aes256wrappad_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_256wrappad_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_256_wrappad_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes192wrappad_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_192wrappad_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_192_wrappad_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes128wrappad_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_128wrappad_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_128_wrappad_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes256wrapinv_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_256wrapinv_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_256_wrapinv_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes192wrapinv_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_192wrapinv_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_192_wrapinv_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes128wrapinv_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_128wrapinv_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_128_wrapinv_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes256wrappadinv_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_256wrappadinv_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_256_wrappadinv_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes192wrappadinv_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_192wrappadinv_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_192_wrappadinv_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) ) ;

const  ossl_aes128wrappadinv_functions: array[0..12] of TOSSL_DISPATCH = (
(function_id:  1; method:(code:@aes_128wrappadinv_newctx; data:nil)),
(function_id:  2; method:(code:@aes_wrap_einit; data:nil)),
(function_id:  3; method:(code:@aes_wrap_dinit; data:nil)),
(function_id:  4; method:(code:@aes_wrap_cipher; data:nil)),
(function_id:  5; method:(code:@aes_wrap_final; data:nil)),
(function_id:  7; method:(code:@aes_wrap_freectx; data:nil)),
(function_id:  9; method:(code:@aes_128_wrappadinv_get_params; data:nil)),
(function_id:  12; method:(code:@ossl_cipher_generic_gettable_params; data:nil)),
(function_id:  10; method:(code:@ossl_cipher_generic_get_ctx_params; data:nil)),
(function_id:  11; method:(code:@aes_wrap_set_ctx_params; data:nil)),
(function_id:  13; method:(code:@ossl_cipher_generic_gettable_ctx_params; data:nil)),
(function_id:  14; method:(code:@ossl_cipher_generic_settable_ctx_params; data:nil)),
(function_id:  0; method:(code:nil; data:nil)) );

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem, OpenSSL3.Err,
     openssl3.crypto.modes.wrap128 ,    openssl3.crypto.cpuid,
     openssl3.crypto.aes.aes_core,      openssl3.crypto.params;




function aes_256_wrap_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, ($0002), 256, 64, 8 * 8));
end;


function aes_256wrap_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(256, 64, 8 * 8, $10002, ($0002)));
end;


function aes_192_wrap_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, ($0002), 192, 64, 8 * 8));
end;


function aes_192wrap_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(192, 64, 8 * 8, $10002, ($0002)));
end;


function aes_128_wrap_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, ($0002), 128, 64, 8 * 8));
end;


function aes_128wrap_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(128, 64, 8 * 8, $10002, ($0002)));
end;


function aes_256_wrappad_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, ($0002), 256, 64, 4 * 8));
end;


function aes_256wrappad_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(256, 64, 4 * 8, $10002, ($0002)));
end;


function aes_192_wrappad_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, ($0002), 192, 64, 4 * 8));
end;


function aes_192wrappad_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(192, 64, 4 * 8, $10002, ($0002)));
end;


function aes_128_wrappad_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, ($0002), 128, 64, 4 * 8));
end;


function aes_128wrappad_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(128, 64, 4 * 8, $10002, ($0002)));
end;


function aes_256_wrapinv_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, (($0002) or $0200), 256, 64, 8 * 8));
end;


function aes_256wrapinv_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(256, 64, 8 * 8, $10002, (($0002) or $0200)));
end;


function aes_192_wrapinv_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, (($0002) or $0200), 192, 64, 8 * 8));
end;


function aes_192wrapinv_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(192, 64, 8 * 8, $10002, (($0002) or $0200)));
end;


function aes_128_wrapinv_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, (($0002) or $0200), 128, 64, 8 * 8));
end;


function aes_128wrapinv_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(128, 64, 8 * 8, $10002, (($0002) or $0200)));
end;


function aes_256_wrappadinv_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, (($0002) or $0200), 256, 64, 4 * 8));
end;


function aes_256wrappadinv_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(256, 64, 4 * 8, $10002, (($0002) or $0200)));
end;


function aes_192_wrappadinv_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, (($0002) or $0200), 192, 64, 4 * 8));
end;


function aes_192wrappadinv_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(192, 64, 4 * 8, $10002, (($0002) or $0200)));
end;


function aes_128_wrappadinv_get_params( params : POSSL_PARAM):integer;
begin
 Exit(ossl_cipher_generic_get_params(params, $10002, (($0002) or $0200), 128, 64, 4 * 8));
end;


function aes_128wrappadinv_newctx( provctx : Pointer):Pointer;
begin
 Exit(aes_wrap_newctx(128, 64, 4 * 8, $10002, (($0002) or $0200)));
end;



function CRYPTO_128_unwrap(key : Pointer;{const} iv : PByte;var _out : PByte;const _in : PByte; inlen : size_t; block : block128_f):size_t;
var
  ret : size_t;
  got_iv : array[0..7] of Byte;
begin
    ret := crypto_128_unwrap_raw(key, @got_iv, _out, _in, inlen, block);
    if ret = 0 then Exit(0);
    if nil =iv then iv := @default_iv;
    if CRYPTO_memcmp(@got_iv, iv, 8) > 0 then  begin
        OPENSSL_cleanse(_out, ret);
        Exit(0);
    end;
    Result := ret;
end;

function aes_wrap_newctx( kbits, blkbits, ivbits : size_t; mode : uint32; flags : uint64):Pointer;
var
  wctx : PPROV_AES_WRAP_CTX;
  ctx : PPROV_CIPHER_CTX;
begin
    if not ossl_prov_is_running then Exit(nil);
    wctx := OPENSSL_zalloc(sizeof( wctx^));
    ctx := PPROV_CIPHER_CTX (wctx);
    if ctx <> nil then begin
        ossl_cipher_generic_initkey(ctx, kbits, blkbits, ivbits, mode, flags,
                                    nil, nil);
        ctx.pad := int(ctx.ivlen = AES_WRAP_PAD_IVLEN);
    end;
    Result := wctx;
end;


procedure aes_wrap_freectx( vctx : Pointer);
var
  wctx : PPROV_AES_WRAP_CTX;
begin
    wctx := PPROV_AES_WRAP_CTX(vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX (vctx));
    OPENSSL_clear_free(Pointer(wctx),  sizeof( wctx^));
end;


function aes_wrap_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
    ctx                   : PPROV_CIPHER_CTX;
    wctx                  : PPROV_AES_WRAP_CTX;
    use_forward_transform : integer;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    wctx := PPROV_AES_WRAP_CTX(vctx);
    if not ossl_prov_is_running then
       Exit(0);
    ctx.enc := enc;
    if ctx.pad > 0 then
    begin
       if enc > 0 then
          wctx.wrapfn :=  CRYPTO_128_wrap_pad
       else
          wctx.wrapfn :=  CRYPTO_128_unwrap_pad;
    end
    else
    begin
       if enc > 0 then
          wctx.wrapfn := CRYPTO_128_wrap
       else
          wctx.wrapfn := CRYPTO_128_unwrap;
    end;
    if iv <> nil then
    begin
        if 0>=ossl_cipher_generic_initiv(ctx, iv, ivlen) then
            Exit(0);
    end;
    if key <> nil then
    begin
        if keylen <> ctx.keylen then  begin
           ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
           Exit(0);
        end;
        {
         * See SP800-38F : Section 5.1
         * The forward and inverse transformations for the AES block
         * cipher¡ªcalled ¡°cipher¡± and ¡°inverse  cipher¡± are informally known as
         * the AES encryption and AES decryption functions, respectively.
         * If the designated cipher function for a key-wrap algorithm is chosen
         * to be the AES decryption function, then CIPH-1K will be the AES
         * encryption function.
         }
        if ctx.inverse_cipher = 0 then
           use_forward_transform := ctx.enc
        else
            use_forward_transform := not ctx.enc;
        if use_forward_transform > 0 then
        begin
            AES_set_encrypt_key(key, keylen * 8, @wctx.ks.ks);
            ctx.block := {block128_f}AES_encrypt;
        end
        else
        begin
            AES_set_decrypt_key(key, keylen * 8, @wctx.ks.ks);
            ctx.block := {block128_fend}AES_decrypt;
        end;
    end;
    Result := aes_wrap_set_ctx_params(ctx, params);
end;


function aes_wrap_einit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := aes_wrap_init(ctx, key, keylen, iv, ivlen, params, 1);
end;


function aes_wrap_dinit(ctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := aes_wrap_init(ctx, key, keylen, iv, ivlen, params, 0);
end;


function aes_wrap_cipher_internal(vctx : Pointer; _out : PByte;const _in : PByte; inlen : size_t):integer;
var
  ctx : PPROV_CIPHER_CTX;
  wctx : PPROV_AES_WRAP_CTX;
  rv : size_t;
  pad : integer;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    wctx := PPROV_AES_WRAP_CTX(vctx);
    pad := ctx.pad;
    { No final operation so always return zero length }
    if _in = nil then Exit(0);
    { Input length must always be non-zero }
    if inlen = 0 then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        Exit(-1);
    end;
    { If decrypting need at least 16 bytes and multiple of 8 }
    if (0>=ctx.enc)  and ( (inlen < 16)  or  (inlen and $7 > 0) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        Exit(-1);
    end;
    { If not padding input must be multiple of 8 }
    if (0>=pad)  and  (inlen and $7 > 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        Exit(-1);
    end;
    if _out = nil then
    begin
        if ctx.enc > 0 then
        begin
            { If padding round up to multiple of 8 }
            if pad > 0 then
                inlen := (inlen + 7) div 8 * 8;
            { 8 byte prefix }
            Exit(inlen + 8);
        end
        else
        begin
            {
             * If not padding output will be exactly 8 bytes smaller than
             * input. If padding it will be at least 8 bytes smaller but we
             * don't know how much.
             }
            Exit(inlen - 8);
        end;
    end;
    if ctx.iv_set > 0 then
       rv := wctx.wrapfn(@wctx.ks.ks, @ctx.iv , _out, _in,
                      inlen, ctx.block)
    else
       rv := wctx.wrapfn(@wctx.ks.ks, nil, _out, _in,
                      inlen, ctx.block);
    if 0>=rv then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(-1);
    end;
    if rv > INT_MAX then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
        Exit(-1);
    end;
    Result := int(rv);
end;


function aes_wrap_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
begin
    if not ossl_prov_is_running then
       Exit(0);
    outl^ := 0;
    Result := 1;
end;


function aes_wrap_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_AES_WRAP_CTX;

  len : size_t;
begin
    ctx := PPROV_AES_WRAP_CTX(vctx);
    if not ossl_prov_is_running then Exit(0);
    if inl = 0 then begin
        outl^ := 0;
        Exit(1);
    end;
    if outsize < inl then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    len := aes_wrap_cipher_internal(ctx, _out, _in, inl);
    if len <= 0 then Exit(0);
    outl^ := len;
    Result := 1;
end;


function aes_wrap_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p : POSSL_PARAM;
  keylen : size_t;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    keylen := 0;
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if p <> nil then
    begin
        if 0>=OSSL_PARAM_get_size_t(p, @keylen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        if ctx.keylen <> keylen then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
    end;
    Result := 1;
end;



end.
