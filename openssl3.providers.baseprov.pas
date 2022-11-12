unit openssl3.providers.baseprov;

interface
uses OpenSSL.Api;

  function ossl_base_provider_init(const handle : POSSL_CORE_HANDLE; _in : POSSL_DISPATCH; var _out : POSSL_DISPATCH; provctx : PPointer):integer;
  function base_gettable_params( provctx : Pointer):POSSL_PARAM;
  function base_get_params( provctx : Pointer; params : POSSL_PARAM):integer;
  function base_query( provctx : Pointer; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;

 procedure base_teardown( provctx : Pointer);

 const base_dispatch_table: array[0..4] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_PROVIDER_TEARDOWN; method:(code:@base_teardown; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GETTABLE_PARAMS; method:(code:@base_gettable_params; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_GET_PARAMS; method:(code:@base_get_params; data:nil)),
    (function_id:  OSSL_FUNC_PROVIDER_QUERY_OPERATION; method:(code:@base_query; data:nil)),
    (function_id:  0; method:(code:nil; data:nil)));
 var
  c_gettable_params: TOSSL_FUNC_core_gettable_params_fn  = nil;
  c_get_params: TOSSL_FUNC_core_get_params_fn  = nil;
  base_encoder, base_decoder, base_store: array of TOSSL_ALGORITHM;
  base_param_types: array of TOSSL_PARAM;

implementation
uses openssl3.crypto.bio.bio_prov, OpenSSL3.openssl.core_dispatch,
     openssl3.providers.fips.self_test,      openssl3.crypto.bio.bio_meth,
     OpenSSL3.providers.common.provider_ctx, openssl3.crypto.params,
     OpenSSL3.openssl.params,
     openssl3.providers.implementations.encode_decode.encode_key2any,
     openssl3.providers.implementations.encode_decode.encode_key2blob,
     openssl3.providers.implementations.encode_decode.encode_key2ms,
     openssl3.providers.implementations.encode_decode.decode_der2key,
     openssl3.providers.implementations.encode_decode.decode_msblob2key,
     openssl3.providers.implementations.encode_decode.decode_pvk2key,
     openssl3.providers.implementations.encode_decode.decode_spki2typespki,
     openssl3.providers.implementations.encode_decode.decode_pem2der,
     openssl3.providers.implementations.encode_decode.decode_epki2pki,
     openssl3.providers.implementations.storemgmt.file_store,
     openssl3.providers.implementations.encode_decode.encode_key2text;


function base_query( provctx : Pointer; operation_id : integer; no_cache : PInteger):POSSL_ALGORITHM;
begin
    no_cache^ := 0;
    case operation_id of
    OSSL_OP_ENCODER:
        Exit(@base_encoder[0]);
    OSSL_OP_DECODER:
        Exit(@base_decoder[0]);
    OSSL_OP_STORE:
        Exit(@base_store[0]);
    end;
    Result := nil;
end;

function base_get_params( provctx : Pointer; params : POSSL_PARAM):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p <> nil) and  (0>=OSSL_PARAM_set_utf8_ptr(p, 'OpenSSL Base Provider') ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_int(p, Int(ossl_prov_is_running)) ) then
        Exit(0);
    Result := 1;
end;


function base_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @base_param_types[0];
end;


procedure base_teardown( provctx : Pointer);
begin
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
end;

function ossl_base_provider_init(const handle : POSSL_CORE_HANDLE; _in : POSSL_DISPATCH; var _out : POSSL_DISPATCH; provctx : PPointer):integer;
var
    c_get_libctx : TOSSL_FUNC_core_get_libctx_fn;
    corebiometh  : PBIO_METHOD;
begin
    c_get_libctx := nil;
    if 0>=ossl_prov_bio_from_dispatch(_in) then
        Exit(0);
    while _in.function_id <> 0 do
    begin
        case _in.function_id of
        OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params := _OSSL_FUNC_core_gettable_params(_in);
            //break;
        OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params := _OSSL_FUNC_core_get_params(_in);
            //break;
        OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx := _OSSL_FUNC_core_get_libctx(_in);
            //break;
        else
            { Just ignore anything we don't understand }
            begin
              //break;
            end;
        end;
        Inc(_in);
    end;
    if not Assigned(c_get_libctx) then Exit(0);
    {
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     }
    provctx^ := ossl_prov_ctx_new();
    corebiometh := ossl_bio_prov_init_bio_method;
    if ( provctx^ = nil) or  (corebiometh = nil) then
    begin
        ossl_prov_ctx_free( provctx^);
        provctx^ := nil;
        Exit(0);
    end;
    ossl_prov_ctx_set0_libctx( provctx^, POSSL_LIB_CTX (c_get_libctx(handle)));
    ossl_prov_ctx_set0_handle( provctx^, handle);
    ossl_prov_ctx_set0_core_bio_method( provctx^, corebiometh);
    _out := @base_dispatch_table;
    Result := 1;
end;

initialization
    base_encoder := [

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=text', @ossl_rsa_to_text_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=text', @ossl_rsapss_to_text_encoder_functions ),

get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=text', @ossl_dh_to_text_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=text', @ossl_dhx_to_text_encoder_functions ),


get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=text', @ossl_dsa_to_text_encoder_functions ),


get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=text', @ossl_ec_to_text_encoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=text', @ossl_ed25519_to_text_encoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=text', @ossl_ed448_to_text_encoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=text', @ossl_x25519_to_text_encoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=text', @ossl_x448_to_text_encoder_functions ),

get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=text', @ossl_sm2_to_text_encoder_functions ),

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=der,structure=type-specific', @ossl_rsa_to_type_specific_keypair_der_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pem,structure=type-specific', @ossl_rsa_to_type_specific_keypair_pem_encoder_functions ),


get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=der,structure=type-specific', @ossl_dh_to_type_specific_params_der_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=pem,structure=type-specific', @ossl_dh_to_type_specific_params_pem_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=der,structure=type-specific', @ossl_dhx_to_type_specific_params_der_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=pem,structure=type-specific', @ossl_dhx_to_type_specific_params_pem_encoder_functions ),


get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=der,structure=type-specific', @ossl_dsa_to_type_specific_der_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=pem,structure=type-specific', @ossl_dsa_to_type_specific_pem_encoder_functions ),



get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=der,structure=type-specific', @ossl_ec_to_type_specific_no_pub_der_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=pem,structure=type-specific', @ossl_ec_to_type_specific_no_pub_pem_encoder_functions ),

get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=blob', @ossl_ec_to_blob_encoder_functions ),

get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=der,structure=type-specific', @ossl_sm2_to_type_specific_no_pub_der_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=pem,structure=type-specific', @ossl_sm2_to_type_specific_no_pub_pem_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=blob', @ossl_sm2_to_blob_encoder_functions ),

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=msblob', @ossl_rsa_to_msblob_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pvk', @ossl_rsa_to_pvk_encoder_functions ),

get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=msblob', @ossl_dsa_to_msblob_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=pvk', @ossl_dsa_to_pvk_encoder_functions ),

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_rsa_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_rsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_rsa_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_rsa_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_rsa_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_rsa_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_rsapss_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_rsapss_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_rsapss_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_rsapss_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_rsapss_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_rsapss_to_SubjectPublicKeyInfo_pem_encoder_functions ),


get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_dh_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_dh_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_dh_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_dh_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_dh_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_dh_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_dhx_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_dhx_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_dhx_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_dhx_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_dhx_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_dhx_to_SubjectPublicKeyInfo_pem_encoder_functions ),



get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_dsa_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_dsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_dsa_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_dsa_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_dsa_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_dsa_to_SubjectPublicKeyInfo_pem_encoder_functions ),



get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_ec_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_ec_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_ec_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_ec_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_ec_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_ec_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_x25519_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_x25519_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_x25519_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_x25519_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_x25519_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_x25519_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_x448_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_x448_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_x448_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_x448_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_x448_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_x448_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_ed25519_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_ed25519_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_ed25519_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_ed25519_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_ed25519_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_ed25519_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=der,structure=EncryptedPrivateKeyInfo', @ossl_ed448_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_ed448_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=der,structure=PrivateKeyInfo', @ossl_ed448_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=pem,structure=PrivateKeyInfo', @ossl_ed448_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=der,structure=SubjectPublicKeyInfo', @ossl_ed448_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,output=pem,structure=SubjectPublicKeyInfo', @ossl_ed448_to_SubjectPublicKeyInfo_pem_encoder_functions ),


get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=der,structure=EncryptedPrivateKeyInfo', @ossl_sm2_to_EncryptedPrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=pem,structure=EncryptedPrivateKeyInfo', @ossl_sm2_to_EncryptedPrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=der,structure=PrivateKeyInfo', @ossl_sm2_to_PrivateKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=pem,structure=PrivateKeyInfo', @ossl_sm2_to_PrivateKeyInfo_pem_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=der,structure=SubjectPublicKeyInfo', @ossl_sm2_to_SubjectPublicKeyInfo_der_encoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,output=pem,structure=SubjectPublicKeyInfo', @ossl_sm2_to_SubjectPublicKeyInfo_pem_encoder_functions ),

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=der,structure=rsa', @ossl_rsa_to_RSA_der_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pem,structure=rsa', @ossl_rsa_to_RSA_pem_encoder_functions ),


get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=der,structure=dh', @ossl_dh_to_DH_der_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=pem,structure=dh', @ossl_dh_to_DH_pem_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=der,structure=dhx', @ossl_dhx_to_DHX_der_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=pem,structure=dhx', @ossl_dhx_to_DHX_pem_encoder_functions ),


get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=der,structure=dsa', @ossl_dsa_to_DSA_der_encoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,output=pem,structure=dsa', @ossl_dsa_to_DSA_pem_encoder_functions ),


get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=der,structure=ec', @ossl_ec_to_EC_der_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=pem,structure=ec', @ossl_ec_to_EC_pem_encoder_functions ),

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=der,structure=pkcs1', @ossl_rsa_to_PKCS1_der_encoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,output=pem,structure=pkcs1', @ossl_rsa_to_PKCS1_pem_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=der,structure=pkcs1', @ossl_rsapss_to_PKCS1_der_encoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,output=pem,structure=pkcs1', @ossl_rsapss_to_PKCS1_pem_encoder_functions ),


get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=der,structure=pkcs3', @ossl_dh_to_PKCS3_der_encoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,output=pem,structure=pkcs3', @ossl_dh_to_PKCS3_pem_encoder_functions ),

get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=der,structure=X9.42', @ossl_dhx_to_X9_42_der_encoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,output=pem,structure=X9.42', @ossl_dhx_to_X9_42_pem_encoder_functions ),

get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=der,structure=X9.62', @ossl_ec_to_X9_62_der_encoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,output=pem,structure=X9.62', @ossl_ec_to_X9_62_pem_encoder_functions ),

get_ALGORITHM( nil, nil, nil )

];

base_decoder := [
get_ALGORITHM( 'DH', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_dh_decoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_dh_decoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,input=der,structure=type-specific', @ossl_type_specific_params_der_to_dh_decoder_functions ),
get_ALGORITHM( 'DH', 'provider=base,fips=yes,input=der,structure=dh', @ossl_DH_der_to_dh_decoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_dhx_decoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_dhx_decoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,input=der,structure=type-specific', @ossl_type_specific_params_der_to_dhx_decoder_functions ),
get_ALGORITHM( 'DHX', 'provider=base,fips=yes,input=der,structure=dhx', @ossl_DHX_der_to_dhx_decoder_functions ),


get_ALGORITHM( 'DSA', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_dsa_decoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_dsa_decoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,input=der,structure=type-specific', @ossl_type_specific_der_to_dsa_decoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,input=der,structure=dsa', @ossl_DSA_der_to_dsa_decoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,input=msblob', @ossl_msblob_to_dsa_decoder_functions ),
get_ALGORITHM( 'DSA', 'provider=base,fips=yes,input=pvk', @ossl_pvk_to_dsa_decoder_functions ),


get_ALGORITHM( 'EC', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_ec_decoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_ec_decoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,input=der,structure=type-specific', @ossl_type_specific_no_pub_der_to_ec_decoder_functions ),
get_ALGORITHM( 'EC', 'provider=base,fips=yes,input=der,structure=ec', @ossl_EC_der_to_ec_decoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_ed25519_decoder_functions ),
get_ALGORITHM( 'ED25519', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_ed25519_decoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_ed448_decoder_functions ),
get_ALGORITHM( 'ED448', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_ed448_decoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_x25519_decoder_functions ),
get_ALGORITHM( 'X25519', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_x25519_decoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_x448_decoder_functions ),
get_ALGORITHM( 'X448', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_x448_decoder_functions ),

get_ALGORITHM( 'SM2', 'provider=base,fips=no,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_sm2_decoder_functions ),
get_ALGORITHM( 'SM2', 'provider=base,fips=no,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_sm2_decoder_functions ),

get_ALGORITHM( 'RSA', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_rsa_decoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_rsa_decoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,input=der,structure=type-specific', @ossl_type_specific_keypair_der_to_rsa_decoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,input=der,structure=rsa', @ossl_RSA_der_to_rsa_decoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,input=der,structure=PrivateKeyInfo', @ossl_PrivateKeyInfo_der_to_rsapss_decoder_functions ),
get_ALGORITHM( 'RSA-PSS', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_rsapss_decoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,input=msblob', @ossl_msblob_to_rsa_decoder_functions ),
get_ALGORITHM( 'RSA', 'provider=base,fips=yes,input=pvk', @ossl_pvk_to_rsa_decoder_functions ),

get_ALGORITHM( 'DER', 'provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo', @ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions ),
get_ALGORITHM( 'DER', 'provider=base,fips=yes,input=pem', @ossl_pem_to_der_decoder_functions ),

get_ALGORITHM( 'DER', 'provider=base,fips=yes,input=der,structure=EncryptedPrivateKeyInfo', @ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions ),
get_ALGORITHM( nil, nil, nil)

];

base_store := [
get_ALGORITHM( 'file', 'provider=base,fips=yes', @ossl_file_store_functions ),
get_ALGORITHM( nil, nil, nil)
];

  base_param_types := [
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, nil, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, nil, 0),
    OSSL_PARAM_END
 ];
end.
