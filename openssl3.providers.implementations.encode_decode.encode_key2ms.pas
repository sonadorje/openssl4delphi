unit openssl3.providers.implementations.encode_decode.encode_key2ms;

interface
uses OpenSSL.Api;

type
   Tevp_pkey_set1_fn = function(evp_key: PEVP_PKEY; const key : Pointer):integer;

function key2ms_newctx( provctx : Pointer):Pkey2ms_ctx_st;
  procedure key2ms_freectx( vctx : Pointer);
function key2ms_does_selection( vctx : Pointer; selection : integer):integer;
function rsa2msblob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa2msblob_free_object( key : Pointer);
  function rsa2msblob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const  ossl_rsa_to_msblob_encoder_functions: array[0..6] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2ms_newctx; data:nil)),
 (function_id:  2; method:(code:@key2ms_freectx; data:nil)),
  (function_id:  10; method:(code:@key2ms_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa2msblob_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa2msblob_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa2msblob_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function rsa2pvk_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa2pvk_free_object( key : Pointer);
  function rsa2pvk_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
 function key2pvk_settable_ctx_params( provctx : Pointer):POSSL_PARAM;
 function key2pvk_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;

 const ossl_rsa_to_pvk_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2ms_newctx; data:nil)),
 (function_id:  2; method:(code:@key2ms_freectx; data:nil)),
 (function_id:  6; method:(code:@key2pvk_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2pvk_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@key2ms_does_selection; data:nil)),
 (function_id:  20; method:(code:@rsa2pvk_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa2pvk_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa2pvk_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function dsa2msblob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa2msblob_free_object( key : Pointer);
  function dsa2msblob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_dsa_to_msblob_encoder_functions: array[0..6] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2ms_newctx; data:nil)),
 (function_id:  2; method:(code:@key2ms_freectx; data:nil)),
  (function_id:  10; method:(code:@key2ms_does_selection; data:nil)),
 (function_id:  20; method:(code:@dsa2msblob_import_object; data:nil)),
 (function_id:  21; method:(code:@dsa2msblob_free_object; data:nil)),
 (function_id:  11; method:(code:@dsa2msblob_encode; data:nil)),
 (function_id:  0;  method:(code:nil; data:nil)) );

 function dsa2pvk_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa2pvk_free_object( key : Pointer);
  function dsa2pvk_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_dsa_to_pvk_encoder_functions: array[0..8] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2ms_newctx; data:nil)),
 (function_id:  2; method:(code:@key2ms_freectx; data:nil)),
 (function_id:  6; method:(code:@key2pvk_settable_ctx_params; data:nil)),
 (function_id:  5; method:(code:@key2pvk_set_ctx_params; data:nil)),
 (function_id:  10; method:(code:@key2ms_does_selection; data:nil)),
 (function_id:  20; method:(code:@dsa2pvk_import_object; data:nil)),
 (function_id:  21; method:(code:@dsa2pvk_free_object; data:nil)),
 (function_id:  11; method:(code:@dsa2pvk_encode; data:nil)),
 (function_id:  0;  method:(code:nil; data:nil)) );

 function key2msblob_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO; set1_key : Tevp_pkey_set1_fn; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
 function write_msblob( ctx : Pkey2ms_ctx_st; cout : POSSL_CORE_BIO; pkey : PEVP_PKEY; ispub : integer):integer;
  function write_pvk( ctx : Pkey2ms_ctx_st; cout : POSSL_CORE_BIO; pkey : PEVP_PKEY):integer;
 function key2pvk_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO; set1_key : Tevp_pkey_set1_fn; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;

implementation
uses openssl3.crypto.mem, openssl3.crypto.passphrase, openssl3.crypto.evp.evp_enc,
     openssl3.providers.common.provider_ctx, openssl3.crypto.params,
     OpenSSL3.Err, openssl3.crypto.bio.bio_prov,
     openssl3.providers.implementations.encode_decode.endecoder_common,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.common.der.der_rsa_key,
     openssl3.crypto.bio.bio_print, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.rsa.rsa_pss,   openssl3.crypto.packet,
     openssl3.crypto.bio.bio_lib,
     openssl3.crypto.dsa.dsa_asn1, openssl3.crypto.ec.ec_asn1,
     openssl3.openssl.params,      OpenSSL3.crypto.rsa.rsa_asn1,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.pem.pvkfmt,
     openssl3.crypto.evp.p_legacy, openssl3.crypto.evp.p_lib;





function dsa2pvk_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
  Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx, selection, params));
end;


procedure dsa2pvk_free_object( key : Pointer);
begin
  ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa2pvk_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2pvk_encode(vctx, key, selection, cout, EVP_PKEY_set1_DSA, cb, cbarg);
end;



function dsa2msblob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
 Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx, selection, params));
end;


procedure dsa2msblob_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa2msblob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   result := key2msblob_encode(vctx, key, selection, cout, EVP_PKEY_set1_DSA, cb, cbarg);
end;



function key2pvk_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO; set1_key : Tevp_pkey_set1_fn; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  ctx : Pkey2ms_ctx_st;

  pkey : PEVP_PKEY;

  ok : integer;
begin
    ctx := vctx;
    pkey := nil;
    ok := 0;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) = 0 then
        Exit(0);                { Error }
    pkey := EVP_PKEY_new();
    if (pkey <> nil)  and  (set1_key(pkey, key)>0)
         and ( ( not Assigned(pw_cb) )
             or  (ossl_pw_set_ossl_passphrase_cb(@ctx.pwdata, pw_cb, pw_cbarg)>0) ) then
        ok := write_pvk(ctx, cout, pkey);
    EVP_PKEY_free(pkey);
    Result := ok;
end;




function key2pvk_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : Pkey2ms_ctx_st;

  p : POSSL_PARAM;
begin
    ctx := vctx;
    p := OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_ENCRYPT_LEVEL);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @ctx.pvk_encr_level)) then
        Exit(0);
    Result := 1;
end;


var
  settables : array of TOSSL_PARAM;
function key2pvk_settable_ctx_params( provctx : Pointer):POSSL_PARAM;
begin
   settables  := [
        _OSSL_PARAM_int(OSSL_ENCODER_PARAM_ENCRYPT_LEVEL, nil),
        OSSL_PARAM_END
  ];
    Result := @settables[0];
end;



function rsa2pvk_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx, selection, params));
end;


procedure rsa2pvk_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa2pvk_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2pvk_encode(vctx, key, selection, cout, EVP_PKEY_set1_RSA, cb, cbarg);
end;




function write_msblob( ctx : Pkey2ms_ctx_st; cout : POSSL_CORE_BIO; pkey : PEVP_PKEY; ispub : integer):integer;
var
  &out : PBIO;

  ret : integer;
begin
    &out := ossl_bio_new_from_core_bio(ctx.provctx, cout);
    if &out = nil then Exit(0);
    ret := get_result(ispub >0, i2b_PublicKey_bio(&out, pkey) , i2b_PrivateKey_bio(&out, pkey) );
    BIO_free(&out);
    Result := ret;
end;


function write_pvk( ctx : Pkey2ms_ctx_st; cout : POSSL_CORE_BIO; pkey : PEVP_PKEY):integer;
var
  &out : PBIO;
  ret : integer;
  libctx : POSSL_LIB_CTX;
begin
    &out := nil;
    libctx := PROV_LIBCTX_OF(ctx.provctx);
    &out := ossl_bio_new_from_core_bio(ctx.provctx, cout);
    if &out = nil then Exit(0);
    ret := i2b_PVK_bio_ex(&out, pkey, ctx.pvk_encr_level,
                         ossl_pw_pvk_password, @ctx.pwdata, libctx, nil);
    BIO_free(&out);
    Result := ret;
end;





function key2msblob_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO;set1_key : Tevp_pkey_set1_fn; pw_cb : TOSSL_PASSPHRASE_CALLBACK; pw_cbarg : Pointer):integer;
var
  ctx : Pkey2ms_ctx_st;

  ispub : integer;

  pkey : PEVP_PKEY;

  ok : integer;
begin
    ctx := vctx;
    ispub := -1;
    pkey := nil;
    ok := 0;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        ispub := 0
    else if ((selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
        ispub := 1
    else
        exit( 0);                { Error }
    pkey := EVP_PKEY_new();
    if (pkey  <> nil)  and  (set1_key(pkey, key)>0) then
        ok := write_msblob(ctx, cout, pkey, ispub);
    EVP_PKEY_free(pkey);
    Result := ok;
end;



function rsa2msblob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
 Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx, selection, params));
end;


procedure rsa2msblob_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa2msblob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := key2msblob_encode(vctx, key, selection, cout, EVP_PKEY_set1_RSA, cb, cbarg);
end;

function key2ms_does_selection( vctx : Pointer; selection : integer):integer;
begin
    Result := Int( (selection and OSSL_KEYMGMT_SELECT_KEYPAIR) <> 0);
end;

function key2ms_newctx( provctx : Pointer):Pkey2ms_ctx_st;
var
  ctx : Pkey2ms_ctx_st;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx <> nil then
    begin
        ctx.provctx := provctx;
        { This is the strongest encryption level }
        ctx.pvk_encr_level := 2;
    end;
    Result := ctx;
end;


procedure key2ms_freectx( vctx : Pointer);
var
  ctx : Pkey2ms_ctx_st;
begin
    ctx := vctx;
    ossl_pw_clear_passphrase_data(@ctx.pwdata);
    OPENSSL_free(Pointer(ctx));
end;
end.
