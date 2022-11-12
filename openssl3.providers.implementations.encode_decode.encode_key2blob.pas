unit openssl3.providers.implementations.encode_decode.encode_key2blob;

interface
uses OpenSSL.Api;

  function ec2blob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec2blob_free_object( key : Pointer);
  function ec2blob_does_selection( ctx : Pointer; selection : integer):integer;
  function ec2blob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function key2blob_newctx( provctx : Pointer):Pointer;
  procedure key2blob_freectx( vctx : Pointer);

const ossl_ec_to_blob_encoder_functions: array[0..6] of TOSSL_DISPATCH  = (
 (function_id:  1; method:(code:@key2blob_newctx; data:nil)),
 (function_id:  2; method:(code:@key2blob_freectx; data:nil)),
 (function_id:  10; method:(code:@ec2blob_does_selection; data:nil)),
 (function_id:  20; method:(code:@ec2blob_import_object; data:nil)),
 (function_id:  21; method:(code:@ec2blob_free_object; data:nil)),
 (function_id:  11; method:(code:@ec2blob_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function sm22blob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm22blob_free_object( key : Pointer);
  function sm22blob_does_selection( ctx : Pointer; selection : integer):integer;
  function sm22blob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const  ossl_sm2_to_blob_encoder_functions: array[0..6] of TOSSL_DISPATCH  = (
 (function_id:  1; method:(code:@key2blob_newctx; data:nil)),
 (function_id:  2; method:(code:@key2blob_freectx; data:nil)),
 (function_id:  10; method:(code:@sm22blob_does_selection; data:nil)),
 (function_id:  20; method:(code:@sm22blob_import_object; data:nil)),
 (function_id:  21; method:(code:@sm22blob_free_object; data:nil)),
 (function_id:  11; method:(code:@sm22blob_encode; data:nil)),
 (function_id:  0; method:(code:nil; data:nil)) );

 function key2blob_check_selection( selection, selection_mask : integer):integer;
 function key2blob_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO):integer;
 function write_blob( provctx : Pointer; cout : POSSL_CORE_BIO; data : Pointer; len : integer):integer;

implementation
uses OpenSSL3.Err,openssl3.crypto.mem,       openssl3.crypto.passphrase,
     openssl3.providers.common.provider_ctx, openssl3.crypto.params,
     openssl3.crypto.evp.evp_enc,            openssl3.crypto.bio.bio_prov,
     openssl3.crypto.dsa.dsa_asn1,           openssl3.crypto.ec.ec_asn1,
     openssl3.crypto.bio.bio_print,          openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.rsa.rsa_pss,            openssl3.crypto.packet,
     OpenSSL3.crypto.rsa.rsa_asn1,           openssl3.openssl.params,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.common.der.der_rsa_key,
     openssl3.providers.implementations.encode_decode.endecoder_common,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     openssl3.crypto.bio.bio_lib,            openssl3.crypto.asn1.asn1_lib;


function sm22blob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx, selection, params));
end;


procedure sm22blob_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm22blob_does_selection( ctx : Pointer; selection : integer):integer;
begin
 Exit(key2blob_check_selection(selection, ( ( ( $04 or $80) ) or $02 )));
end;


function sm22blob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2blob_encode(vctx, key, selection, cout);
end;





function write_blob( provctx : Pointer; cout : POSSL_CORE_BIO; data : Pointer; len : integer):integer;
var
  &out : PBIO;
  ret : integer;
begin
    &out := ossl_bio_new_from_core_bio(provctx, cout);
    if &out = nil then Exit(0);
    ret := BIO_write(&out, data, len);
    BIO_free(&out);
    Result := ret;
end;

function key2blob_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO):integer;
var
    pubkey_len,ok : integer;
    pubkey     : PByte;
begin
    pubkey_len := 0; ok := 0;
    pubkey := nil;
    pubkey_len := i2o_ECPublicKey(key, @pubkey);
    if (pubkey_len > 0)  and  (pubkey <> nil) then
       ok := write_blob(vctx, cout, pubkey, pubkey_len);
    OPENSSL_free(Pointer(pubkey));
    Result := ok;
end;

function key2blob_check_selection( selection, selection_mask : integer):integer;
var
  checks : array of integer;

  i : size_t;

  check1, check2 : integer;
begin
    {
     * The selections are kinda sorta 'levels', i.e. each selection given
     * here is assumed to include those following.
     }
    checks := [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    ];

    { The decoder implementations made here support guessing }
    if selection = 0 then Exit(1);
    for i := 0 to Length(checks)-1 do
    begin
        check1 := Int( (selection and checks[i]) <> 0);
        check2 := Int( (selection_mask and checks[i]) <> 0);
        {
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         }
        if check1>0 then Exit(check2);
    end;
    { This should be dead code, but just to be safe... }
    Result := 0;
end;




function key2blob_newctx( provctx : Pointer):Pointer;
begin
    Result := provctx;
end;


procedure key2blob_freectx( vctx : Pointer);
begin
  //nothing
end;


function ec2blob_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
 Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx, selection, params));
end;


procedure ec2blob_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec2blob_does_selection( ctx : Pointer; selection : integer):integer;
begin
   Exit(key2blob_check_selection(selection, ( ( ( $04 or $80) ) or $02 )));
end;


function ec2blob_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Exit(key2blob_encode(vctx, key, selection, cout));
end;

end.
