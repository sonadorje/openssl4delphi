unit openssl3.providers.implementations.encode_decode.encode_key2text;

interface
uses OpenSSL.Api, SysUtils;

type
   Tkey2text_func = function (_out : PBIO;const key : Pointer; selection : integer):integer;

  function rsa2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsa2text_free_object( key : Pointer);
  function rsa2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function key2text_newctx( provctx : Pointer):Pointer;
  procedure key2text_freectx( vctx : Pointer);
  function key2text_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO; key2text : Tkey2text_func; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  function rsapss2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure rsapss2text_free_object( key : Pointer);
  function rsapss2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  function dh2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dh2text_free_object( key : Pointer);
  function dh2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
  function dhx2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dhx2text_free_object( key : Pointer);
  function dhx2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  function dsa2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure dsa2text_free_object( key : Pointer);
  function dsa2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_rsa_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@rsa2text_import_object; data:nil)),
 (function_id:  21; method:(code:@rsa2text_free_object; data:nil)),
 (function_id:  11; method:(code:@rsa2text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil)) );

const ossl_rsapss_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
	(function_id:  1; method:(code:@key2text_newctx; data:nil)),
	(function_id:  2; method:(code:@key2text_freectx; data:nil)),
	(function_id:  20; method:(code:@rsapss2text_import_object; data:nil)),
	(function_id:  21; method:(code:@rsapss2text_free_object; data:nil)),
	(function_id:  11; method:(code:@rsapss2text_encode; data:nil)),
	(function_id:  0; method:(code:@rsa2text_encode; data:nil)) );

const ossl_dh_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@dh2text_import_object; data:nil)),
 (function_id:  21; method:(code:@dh2text_free_object; data:nil)),
 (function_id:  11; method:(code:@dh2text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil)) );

const ossl_dhx_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@dhx2text_import_object; data:nil)),
 (function_id:  21; method:(code:@dhx2text_free_object; data:nil)),
 (function_id:  11; method:(code:@dhx2text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil)) );

const  ossl_dsa_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@dsa2text_import_object; data:nil)),
 (function_id:  21; method:(code:@dsa2text_free_object; data:nil)),
 (function_id:  11; method:(code:@dsa2text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil)) );


function ec2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ec2text_free_object( key : Pointer);
  function ec2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_ec_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@ec2text_import_object; data:nil)),
 (function_id:  21; method:(code:@ec2text_free_object; data:nil)),
 (function_id:  11; method:(code:@ec2text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil))  );

 function ed255192text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed255192text_free_object( key : Pointer);
  function ed255192text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_ed25519_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@ed255192text_import_object; data:nil)),
 (function_id:  21; method:(code:@ed255192text_free_object; data:nil)),
 (function_id:  11; method:(code:@ed255192text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil))  );

 function ed4482text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure ed4482text_free_object( key : Pointer);
  function ed4482text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

const ossl_ed448_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@ed4482text_import_object; data:nil)),
 (function_id:  21; method:(code:@ed4482text_free_object; data:nil)),
 (function_id:  11; method:(code:@ed4482text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil))  );

 function x255192text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x255192text_free_object( key : Pointer);
  function x255192text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

  const ossl_x25519_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@x255192text_import_object; data:nil)),
 (function_id:  21; method:(code:@x255192text_free_object; data:nil)),
 (function_id:  11; method:(code:@x255192text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil))  );

  function x4482text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure x4482text_free_object( key : Pointer);
  function x4482text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_x448_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@x4482text_import_object; data:nil)),
 (function_id:  21; method:(code:@x4482text_free_object; data:nil)),
 (function_id:  11; method:(code:@x4482text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil))  );

  function sm22text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
  procedure sm22text_free_object( key : Pointer);
  function sm22text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;

 const ossl_sm2_to_text_encoder_functions: array[0..5] of TOSSL_DISPATCH = (
 (function_id:  1; method:(code:@key2text_newctx; data:nil)),
 (function_id:  2; method:(code:@key2text_freectx; data:nil)),
 (function_id:  20; method:(code:@sm22text_import_object; data:nil)),
 (function_id:  21; method:(code:@sm22text_free_object; data:nil)),
 (function_id:  11; method:(code:@sm22text_encode; data:nil)),
 (function_id:  0; method:(code:@rsa2text_encode; data:nil))  );

 procedure ossl_prov_free_key(const fns : POSSL_DISPATCH; key : Pointer);
 function rsa_to_text( _out : PBIO; const key : Pointer; selection : integer):integer;
 function print_labeled_bignum(_out : PBIO;_label : PUTF8Char; bn : PBIGNUM):integer;
 function dh_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
 function ffc_params_to_text(_out : PBIO;const ffc : PFFC_PARAMS):integer;
 function print_labeled_buf(_out : PBIO;const _label : PUTF8Char; buf : PByte; buflen : size_t):integer;
 function dsa_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
 function ec_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
 function ec_param_to_text(&out : PBIO;const group : PEC_GROUP; libctx : POSSL_LIB_CTX):integer;
 function ec_param_explicit_to_text(&out : PBIO;const group : PEC_GROUP; libctx : POSSL_LIB_CTX):integer;
 function ec_param_explicit_curve_to_text(&out : PBIO;const group : PEC_GROUP; ctx : PBN_CTX):integer;
 function ec_param_explicit_gen_to_text(&out : PBIO;const group : PEC_GROUP; ctx : PBN_CTX):integer;
 function ecx_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;

implementation
uses openssl3.crypto.params, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.mem, openssl3.providers.fips.self_test,
     OpenSSL3.Err, OpenSSL3.providers.common.provider_util,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.bio.bio_print,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.mem_sec,
     OpenSSL3.common,             openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.bn.bn_intern, openssl3.crypto.ec.ec_oct,
     OpenSSL3.providers.implementations.keymgmt.rsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dh_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.dsa_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ec_kmgmt,
     OpenSSL3.providers.implementations.keymgmt.ecx_kmgmt,
     openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params,
     openssl3.crypto.bio.bio_prov, OpenSSL3.crypto.rsa.rsa_backend,
     openssl3.providers.implementations.encode_decode.endecoder_common,
     openssl3.crypto.dh.dh_lib,  openssl3.crypto.ffc.ffc_dh,
     openssl3.crypto.dsa.dsa_lib,  openssl3.crypto.ec.ec_key,
     openssl3.crypto.bn.bn_ctx,  openssl3.crypto.ec.ec_lib,
     openssl3.crypto.bn.bn_conv,  openssl3.crypto.bio.bio_lib,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.ec.ec_curve,
     openssl3.crypto.rsa.rsa_pss, openssl3.crypto.rsa_schemes;


const LABELED_BUF_PRINT_WIDTH  =  15;





function sm22text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_sm2_keymgmt_functions, ctx, selection, params));
end;


procedure sm22text_free_object( key : Pointer);
begin
 ossl_prov_free_key(@ossl_sm2_keymgmt_functions, key);
end;


function sm22text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
  if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
 Result := key2text_encode(vctx, key, selection, cout, ec_to_text, cb, cbarg);
end;




function x4482text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_x448_keymgmt_functions, ctx, selection, params));
end;


procedure x4482text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_x448_keymgmt_functions, key);
end;


function x4482text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2text_encode(vctx, key, selection, cout, ecx_to_text, cb, cbarg);
end;


function x255192text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_x25519_keymgmt_functions, ctx, selection, params));
end;


procedure x255192text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_x25519_keymgmt_functions, key);
end;


function x255192text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := key2text_encode(vctx, key, selection, cout, ecx_to_text, cb, cbarg);
end;





function ed4482text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_ed448_keymgmt_functions, ctx, selection, params));
end;


procedure ed4482text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_ed448_keymgmt_functions, key);
end;


function ed4482text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := key2text_encode(vctx, key, selection, cout, ecx_to_text, cb, cbarg);
end;


function ecx_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
var
    ecx        : PECX_KEY;

    type_label : PUTF8Char;
begin
     ecx := key;
     type_label := nil;
    if (_out = nil)  or  (ecx = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        if ecx.privkey = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            Exit(0);
        end;
        case ecx.&type of
        ECX_KEY_TYPE_X25519:
            type_label := 'X25519 Private-Key';
            //break;
        ECX_KEY_TYPE_X448:
            type_label := 'X448 Private-Key';
            //break;
        ECX_KEY_TYPE_ED25519:
            type_label := 'ED25519 Private-Key';
            //break;
        ECX_KEY_TYPE_ED448:
            type_label := 'ED448 Private-Key';
            //break;
        end;
    end
    else
    if ((selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
    begin
        { ecx.pubkey is an array, not a pointer... }
        if 0>= ecx.haspubkey then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
            Exit(0);
        end;
        case ecx.&type of
        ECX_KEY_TYPE_X25519:
            type_label := 'X25519 Public-Key';
            //break;
        ECX_KEY_TYPE_X448:
            type_label := 'X448 Public-Key';
            //break;
        ECX_KEY_TYPE_ED25519:
            type_label := 'ED25519 Public-Key';
            //break;
        ECX_KEY_TYPE_ED448:
            type_label := 'ED448 Public-Key';
            //break;
        end;
    end;
    if BIO_printf(_out, '%s:'#10, [type_label]) <= 0  then
        Exit(0);
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0)
         and  (0>= print_labeled_buf(_out, 'priv:', ecx.privkey, ecx.keylen))  then
        Exit(0);
    if ( (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0)
         and  (0>= print_labeled_buf(_out, 'pub:', @ecx.pubkey, ecx.keylen)) then
        Exit(0);
    Result := 1;
end;



function ed255192text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_ed25519_keymgmt_functions, ctx, selection, params));
end;


procedure ed255192text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_ed25519_keymgmt_functions, key);
end;


function ed255192text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := key2text_encode(vctx, key, selection, cout, ecx_to_text, cb, cbarg);
end;

function ec_param_explicit_gen_to_text(&out : PBIO;const group : PEC_GROUP; ctx : PBN_CTX):integer;
var
  ret : integer;

  buflen : size_t;

  form : point_conversion_form_t;

  point : PEC_POINT;

  glabel : PUTF8Char;

  buf : PByte;
begin
     point := nil;
     glabel := nil;
    buf := nil;
    form := EC_GROUP_get_point_conversion_form(group);
    point := EC_GROUP_get0_generator(group);
    if point = nil then Exit(0);
    case form of
    POINT_CONVERSION_COMPRESSED:
       glabel := 'Generator (compressed):';
       //break;
    POINT_CONVERSION_UNCOMPRESSED:
        glabel := 'Generator (uncompressed):';
        //break;
    POINT_CONVERSION_HYBRID:
        glabel := 'Generator (hybrid):';
        //break;
    else
        Exit(0);
    end;
    buflen := EC_POINT_point2buf(group, point, form, @buf, ctx);
    if buflen = 0 then Exit(0);
    ret := print_labeled_buf(&out, glabel, buf, buflen);
    OPENSSL_clear_free(Pointer(buf), buflen);
    Result := ret;
end;




function ec_param_explicit_curve_to_text(&out : PBIO;const group : PEC_GROUP; ctx : PBN_CTX):integer;
var
    plabel     : PUTF8Char;

    p ,a, b         : PBIGNUM;

    basis_type : integer;
begin
    plabel := 'Prime:';
    p := nil; a := nil; b := nil;
    p := BN_CTX_get(ctx);
    a := BN_CTX_get(ctx);
    b := BN_CTX_get(ctx);
    if (b = nil)
         or  (0>= EC_GROUP_get_curve(group, p, a, b, ctx) )then
        Exit(0);
    if EC_GROUP_get_field_type(group) = NID_X9_62_characteristic_two_field  then
    begin
        basis_type := EC_GROUP_get_basis_type(group);
        { print the 'short name' of the base type OID }
        if (basis_type = NID_undef)
             or  (BIO_printf(&out, 'Basis Type: %s'#10, [OBJ_nid2sn(basis_type)]) <= 0 ) then
            Exit(0);
        plabel := 'Polynomial:';
    end;
    Exit(Int( (print_labeled_bignum(&out, plabel, p)>0)
         and  (print_labeled_bignum(&out, 'A:   ', a)>0)
         and  (print_labeled_bignum(&out, 'B:   ', b)>0)));
end;



function ec_param_explicit_to_text(&out : PBIO;const group : PEC_GROUP; libctx : POSSL_LIB_CTX):integer;
var
    ret,
    tmp_nid  : integer;
    ctx      : PBN_CTX;
    order,
    cofactor : PBIGNUM;
    seed     : PByte;
    seed_len : size_t;
    label _err;
begin
    ret := 0;
    ctx := nil;
    order := nil; cofactor := nil;
    seed_len := 0;
    ctx := BN_CTX_new_ex(libctx);
    if ctx = nil then Exit(0);
    BN_CTX_start(ctx);
    tmp_nid := EC_GROUP_get_field_type(group);
    order := EC_GROUP_get0_order(group);
    if order = nil then goto _err ;
    seed := EC_GROUP_get0_seed(group);
    if seed <> nil then seed_len := EC_GROUP_get_seed_len(group);
    cofactor := EC_GROUP_get0_cofactor(group);
    { print the 'short name' of the field type }
    if (BIO_printf(out, 'Field Type: %s'#10, [OBJ_nid2sn(tmp_nid)] )<= 0)
         or  (0>= ec_param_explicit_curve_to_text(&out, group, ctx) )
         or  (0>= ec_param_explicit_gen_to_text(&out, group, ctx))
         or  (0>= print_labeled_bignum(&out, 'Order: ', order))
         or  ( (cofactor <> nil)
             and  (0>= print_labeled_bignum(&out, 'Cofactor: ', cofactor)) )
         or  ( (seed <> nil)
             and  (0>= print_labeled_buf(&out, 'Seed:', seed, seed_len)) )  then
        goto _err ;
    ret := 1;
_err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ret;
end;



function ec_param_to_text(&out : PBIO;const group : PEC_GROUP; libctx : POSSL_LIB_CTX):integer;
var
  curve_nid : integer;
  curve_name: PUTF8Char;
begin
    if (EC_GROUP_get_asn1_flag(group) and OPENSSL_EC_NAMED_CURVE) > 0  then
    begin
        curve_nid := EC_GROUP_get_curve_name(group);
        { Explicit parameters }
        if curve_nid = NID_undef then Exit(0);
        if BIO_printf(out, '%s: %s'#10, ['ASN1 OID', OBJ_nid2sn(curve_nid)]) <= 0  then
            Exit(0);
        curve_name := EC_curve_nid2nist(curve_nid);
        Exit(Int( (curve_name = nil)
                 or  (BIO_printf(&out, '%s: %s'#10, ['NIST CURVE', curve_name]) > 0)));
    end
    else
    begin
        Exit(ec_param_explicit_to_text(&out, group, libctx));
    end;
end;

function ec_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
var
    ec         : PEC_KEY;
    type_label : PUTF8Char;
    priv,
    pub        : PByte;
    priv_len,
    pub_len   : size_t;
    group      : PEC_GROUP;
    ret        : integer;
    priv_key   : PBIGNUM;
    pub_pt     : PEC_POINT;
    label _err;
begin
    ec := key;
    type_label := nil;
    priv := nil;
    pub := nil;
    priv_len := 0; pub_len := 0;
    ret := 0;
    if (_out = nil)  or  (ec = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    group := EC_KEY_get0_group(ec );
    if group = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        Exit(0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        type_label := 'Private-Key'
    else if ((selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
        type_label := 'Public-Key'
    else if ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0) then
        type_label := 'EC-Parameters';
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY)  <> 0 then
    begin
       priv_key := EC_KEY_get0_private_key(ec);
        if priv_key = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            goto _err ;
        end;
        priv_len := EC_KEY_priv2buf(ec, @priv);
        if priv_len = 0 then goto _err ;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 then
    begin
     pub_pt := EC_KEY_get0_public_key(ec);
        if pub_pt = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
            goto _err ;
        end;
        pub_len := EC_KEY_key2buf(ec, EC_KEY_get_conv_form(ec), @pub, nil);
        if pub_len = 0 then goto _err ;
    end;
    if BIO_printf(_out, '%s: (%d bit )'#10, [type_label,
                   EC_GROUP_order_bits(group)]) <= 0 then
        goto _err ;
    if (priv <> nil)
         and  (0>= print_labeled_buf(_out, 'priv:', priv, priv_len)) then
        goto _err ;
    if (pub <> nil)
         and  (0>= print_labeled_buf(_out, 'pub:', pub, pub_len)) then
        goto _err ;
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0 then
        ret := ec_param_to_text(_out, group, ossl_ec_key_get_libctx(ec));
_err:
    OPENSSL_clear_free(Pointer(priv), priv_len);
    OPENSSL_free(pub);
    Result := ret;
end;

function ec2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_ec_keymgmt_functions, ctx, selection, params));
end;


procedure ec2text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_ec_keymgmt_functions, key);
end;


function ec2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2text_encode(vctx, key, selection, cout, ec_to_text, cb, cbarg);
end;


function dsa_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
var
    dsa        : PDSA;
    type_label : PUTF8Char;
    priv_key,
    pub_key   : PBIGNUM;
    params     : PFFC_PARAMS;
    p          : PBIGNUM;
begin
     dsa := key;
     type_label := nil;
     priv_key := nil; pub_key := nil;
     params := nil;
     p := nil;
    if (_out = nil)  or  (dsa = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
        type_label := 'Private-Key'
    else if ((selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
        type_label := 'Public-Key'
    else if ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0) then
        type_label := 'DSA-Parameters';
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        priv_key := DSA_get0_priv_key(dsa);
        if priv_key = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            Exit(0);
        end;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
    begin
        pub_key := DSA_get0_pub_key(dsa);
        if pub_key = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
            Exit(0);
        end;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
    begin
        params := ossl_dsa_get0_params(PDSA  (dsa));
        if params = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_PARAMETERS);
            Exit(0);
        end;
    end;
    p := DSA_get0_p(dsa);
    if p = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        Exit(0);
    end;
    if BIO_printf(_out, '%s: (%d bit )'#10, [type_label, BN_num_bits(p)]) <= 0 then
        Exit(0);
    if (priv_key <> nil)
         and  (0>= print_labeled_bignum(_out, 'priv:', priv_key)) then
        Exit(0);
    if (pub_key <> nil)
         and  (0>= print_labeled_bignum(_out, 'pub: ', pub_key)) then
        Exit(0);
    if (params <> nil)
         and  (0>= ffc_params_to_text(_out, params)) then
        Exit(0);
    Result := 1;
end;




function dsa2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_dsa_keymgmt_functions, ctx, selection, params));
end;


procedure dsa2text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_dsa_keymgmt_functions, key);
end;


function dsa2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2text_encode(vctx, key, selection, cout, dsa_to_text, cb, cbarg);
end;



function dhx2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_dhx_keymgmt_functions, ctx, selection, params));
end;


procedure dhx2text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_dhx_keymgmt_functions, key);
end;


function dhx2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2text_encode(vctx, key, selection, cout, dh_to_text, cb, cbarg);
end;

{$if not defined(OPENSSL_NO_DH) or not defined(OPENSSL_NO_DSA) or not defined(OPENSSL_NO_EC) }
function print_labeled_buf(_out : PBIO;const _label : PUTF8Char; buf : PByte; buflen : size_t):integer;
var
  i : size_t;
begin
    if BIO_printf(_out, '%s'#10, [_label]) <= 0  then
        Exit(0);
    for i := 0 to buflen-1 do
    begin
        if i mod LABELED_BUF_PRINT_WIDTH  = 0 then
        begin
            if (i > 0)  and  (BIO_printf(_out, ''#10, []) <= 0) then
                Exit(0);
            if BIO_printf(_out, '    ',[] ) <= 0 then
                Exit(0);
        end;
        if BIO_printf(_out, '%02x%s', [buf[i],
                               get_result(i = buflen - 1 , '' , ':')]) <= 0 then
            Exit(0);
    end;
    if BIO_printf(_out, ''#10,[]) <= 0  then
        Exit(0);
    Result := 1;
end;
{$ENDIF}

{$if not defined(OPENSSL_NO_DH) or not defined(OPENSSL_NO_DSA)}
function ffc_params_to_text(_out : PBIO;const ffc : PFFC_PARAMS):integer;
var
  group : PDH_NAMED_GROUP;
  name : PUTF8Char;
  label _err;
begin
    if ffc.nid <> NID_undef then
    begin
{$IFNDEF OPENSSL_NO_DH}
         group := ossl_ffc_uid_to_dh_named_group(ffc.nid);
         name := ossl_ffc_named_group_get_name(group);
        if name = nil then goto _err ;
        if BIO_printf(_out, 'GROUP: %s'#10, [name]) <= 0  then
            goto _err ;
        Exit(1);
{$ELSE} { How could this be? We should not have a nid in a no-dh build. }
        goto _err ;
{$ENDIF}
    end;
    if 0>= print_labeled_bignum(_out, 'P:   ', ffc.p )then
        goto _err ;
    if ffc.q <> nil then
    begin
        if 0>= print_labeled_bignum(_out, 'Q:   ', ffc.q) then
            goto _err ;
    end;
    if 0>= print_labeled_bignum(_out, 'G:   ', ffc.g) then
        goto _err ;
    if ffc.j <> nil then
    begin
        if 0>= print_labeled_bignum(_out, 'J:   ', ffc.j) then
            goto _err ;
    end;
    if ffc.seed <> nil then
    begin
        if 0>= print_labeled_buf(_out, 'SEED:', ffc.seed, ffc.seedlen) then
            goto _err ;
    end;
    if ffc.gindex <> -1 then
    begin
        if BIO_printf(_out, 'gindex: %d'#10, [ffc.gindex]) <= 0 then
            goto _err ;
    end;
    if ffc.pcounter <> -1 then
    begin
        if BIO_printf(_out, 'pcounter: %d'#10, [ffc.pcounter]) <= 0 then
            goto _err ;
    end;
    if ffc.h <> 0 then
    begin
        if BIO_printf(_out, 'h: %d'#10, [ffc.h]) <= 0 then
            goto _err ;
    end;
    Exit(1);
_err:
    Result := 0;
end;
{$ENDIF}


{$ifndef OPENSSL_NO_DH}
function dh_to_text(_out : PBIO;const key : Pointer; selection : integer):integer;
var
    dh         : PDH;

    type_label : PUTF8Char;

    priv_key,
    pub_key   : PBIGNUM;

    params     : PFFC_PARAMS;

    p          : PBIGNUM;
begin
     dh := key;
     type_label := nil;
     priv_key := nil; pub_key := nil;
     params := nil;
     p := nil;
    if (_out = nil)  or  (dh = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
        type_label := 'DH Private-Key'
    else if ((selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
        type_label := 'DH Public-Key'
    else if ((selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) <> 0) then
        type_label := 'DH Parameters' ;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        priv_key := DH_get0_priv_key(dh);
        if priv_key = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
            Exit(0);
        end;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) <> 0 then
    begin
        pub_key := DH_get0_pub_key(dh);
        if pub_key = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
            Exit(0);
        end;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS ) <> 0 then
    begin
        params := ossl_dh_get0_params(PDH(dh));
        if params = nil then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_PARAMETERS);
            Exit(0);
        end;
    end;
    p := DH_get0_p(dh);
    if p = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        Exit(0);
    end;
    if BIO_printf(_out, '%s: (%d bit )'#10, [type_label, BN_num_bits(p)]) <= 0 then
        Exit(0);
    if (priv_key <> nil)
         and  (0>= print_labeled_bignum(_out, 'private-key:', priv_key)) then
        Exit(0);
    if (pub_key <> nil)
         and  (0>= print_labeled_bignum(_out, 'public-key:', pub_key)) then
        Exit(0);
    if (params <> nil)
         and  (0>= ffc_params_to_text(_out, params) )then
        Exit(0);
    Result := 1;
end;
{$ENDIF}



function dh2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_dh_keymgmt_functions, ctx, selection, params));
end;


procedure dh2text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_dh_keymgmt_functions, key);
end;


function dh2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
   Result := key2text_encode(vctx, key, selection, cout, dh_to_text, cb, cbarg);
end;



function rsapss2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if key_abstract <> nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    Result := key2text_encode(vctx, key, selection, cout, rsa_to_text, cb, cbarg);
end;




function rsapss2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Result := ossl_prov_import_key(@ossl_rsapss_keymgmt_functions, ctx, selection, params);
end;


procedure rsapss2text_free_object( key : Pointer);
begin
    ossl_prov_free_key(@ossl_rsapss_keymgmt_functions, key);
end;

function print_labeled_bignum(_out : PBIO; _label : PUTF8Char; bn : PBIGNUM):integer;
var
  ret,
  use_sep        : integer;
  hex_str,
  p              : PUTF8Char;
  spaces         : array[0..5-1] of UTF8Char;
  post_label_spc,
  neg            : PUTF8Char;
  bytes          : integer;
  words          : PBN_ULONG;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0;
    use_sep := 0;
    hex_str := nil;
     spaces := '    ';
     post_label_spc := ' ';
     neg := '';
    if bn = nil then Exit(0);
    if _label = nil then
    begin
        _label := '';
        post_label_spc := '';
    end;
    if BN_is_zero(bn) then
        Exit(BIO_printf(_out, '%s%s0'#10, [_label, post_label_spc]));
    if BN_num_bytes(bn) <= BN_BYTES  then
    begin
        words := bn_get_words(bn);
        if BN_is_negative(bn)>0 then
            neg := '-';
        Exit(BIO_printf(_out, '%s%s%s" BN_FMTu " (%s0x" BN_FMTx ")'#10,
                       [_label, post_label_spc, neg, words[0], neg, words[0] ]));
    end;
    hex_str := BN_bn2hex(bn);
    p := hex_str;
    if p^ = '-' then
    begin
        Inc(p);
        neg := ' (Negative)';
    end;
    if BIO_printf(_out, '%s%s\n', [_label, neg])  <= 0 then
        goto _err ;
    { Keep track of how many bytes we have printed out so far }
    bytes := 0;
    if BIO_printf(_out, '%s', [spaces]) <= 0  then
        goto _err ;
    { Add a leading 00 if the top bit is set }
    if p^ >= '8' then
    begin
        if BIO_printf(_out, '%02x', [0]) <= 0 then
            goto _err ;
        Inc(bytes);
        use_sep := 1;
    end;
    while p^ <> #0 do
    begin
        { Do a newline after every 15 hex bytes + add the space indent }
        if (bytes mod 15 = 0)  and  (bytes > 0) then
        begin
            if BIO_printf(_out, ':'#10'%s', [spaces]) <= 0 then
                goto _err ;
            use_sep := 0; { The first byte on the next line doesnt have a : }
        end;
        if BIO_printf(_out, '%s%c%c', [get_result(use_sep>0 , ':' , ''),
                       lowercase(p[0]) , LowerCase(p[1])]) <= 0 then
            goto _err ;
        Inc(bytes);
        p  := p + 2;
        use_sep := 1;
    end;
    if BIO_printf(_out, #10,[]) <= 0  then
        goto _err ;
    ret := 1;
_err:
    OPENSSL_free(hex_str);
    Result := ret;
{$POINTERMATH OFF}
end;

function rsa_to_text( _out : PBIO; const key : Pointer; selection : integer):integer;
var
    rsa                : PRSA;

  type_label,
  modulus_label,
  exponent_label     : PUTF8Char;

  rsa_d,
  rsa_n,
  rsa_e              : PBIGNUM;

  factors,
  exps,
  coeffs             : Pstack_st_BIGNUM_const;

  primes             : integer;
  pss_params         : PRSA_PSS_PARAMS_30;

  ret,
  i,
  hashalg_nid,
  maskgenalg_nid,
  maskgenhashalg_nid,
  saltlen,
  trailerfield       : integer;
  s: string;
  label _err;
begin
     rsa := key;
     type_label := 'RSA key';
     modulus_label := nil;
     exponent_label := nil;
     rsa_d := nil;
   rsa_n := nil;
   rsa_e := nil;
    factors := nil;
    exps := nil;
    coeffs := nil;
     pss_params := ossl_rsa_get0_pss_params_30(PRSA(rsa));
    ret := 0;
    if (_out = nil)  or  (rsa = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        goto _err ;
    end;
    factors := sk_BIGNUM_const_new_null();
    exps := sk_BIGNUM_const_new_null();
    coeffs := sk_BIGNUM_const_new_null();
    if (factors = nil)  or  (exps = nil)  or  (coeffs = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        type_label := 'Private-Key';
        modulus_label := 'modulus:';
        exponent_label := 'publicExponent:';
    end
    else
    if ((selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0) then
    begin
        type_label := 'Public-Key';
        modulus_label := 'Modulus:';
        exponent_label := 'Exponent:';
    end;
    RSA_get0_key(rsa, @rsa_n, @rsa_e, @rsa_d);
    ossl_rsa_get0_all_params(PRSA(rsa), factors, exps, coeffs);
    primes := sk_BIGNUM_const_num(factors);
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 then
    begin

        if BIO_printf(_out, '%s: (%d bit, %d primes then '#10,
                       [type_label, BN_num_bits(rsa_n), primes] ) <= 0 then
            goto _err ;
    end
    else
    begin
        if BIO_printf(_out, '%s: (%d bit then '#10,
                       [type_label, BN_num_bits(rsa_n)]) <= 0 then
            goto _err ;
    end;
    if 0>= print_labeled_bignum(_out, modulus_label, rsa_n) then
        goto _err ;
    if 0>= print_labeled_bignum(_out, exponent_label, rsa_e) then
        goto _err ;
    if (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) <> 0 then
    begin
        if 0>= print_labeled_bignum(_out, 'privateExponent:', rsa_d) then
            goto _err ;
        if 0>= print_labeled_bignum(_out, 'prime1:',
                                  sk_BIGNUM_const_value(factors, 0 )) then
            goto _err ;
        if 0>= print_labeled_bignum(_out, 'prime2:',
                                  sk_BIGNUM_const_value(factors, 1 )) then
            goto _err ;
        if 0>= print_labeled_bignum(_out, 'exponent1:',
                                  sk_BIGNUM_const_value(exps, 0 )) then
            goto _err ;
        if 0>= print_labeled_bignum(_out, 'exponent2:',
                                  sk_BIGNUM_const_value(exps, 1 )) then
            goto _err ;
        if 0>= print_labeled_bignum(_out, 'coefficient:',
                                  sk_BIGNUM_const_value(coeffs, 0 )) then
            goto _err ;
        for i := 2 to sk_BIGNUM_const_num(factors)-1 do begin
            if BIO_printf(_out, 'prime%d:', [i + 1]) <= 0 then
                goto _err ;
            if 0>= print_labeled_bignum(_out, nil,
                                      sk_BIGNUM_const_value(factors, i )) then
                goto _err ;
            if BIO_printf(_out, 'exponent%d:', [i + 1]) <= 0  then
                goto _err ;
            if 0>= print_labeled_bignum(_out, nil,
                                      sk_BIGNUM_const_value(exps, i )) then
                goto _err ;
            if BIO_printf(_out, 'coefficient%d:', [i + 1]) <= 0  then
                goto _err ;
            if 0>= print_labeled_bignum(_out, nil,
                                      sk_BIGNUM_const_value(coeffs, i - 1 )) then
                goto _err ;
        end;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) <> 0 then
    begin
        case (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) of
        RSA_FLAG_TYPE_RSA:
            if 0>= ossl_rsa_pss_params_30_is_unrestricted(pss_params) then
            begin
                if BIO_printf(_out, '(INVALID PSS PARAMETERS)'#10, []) <= 0 then
                    goto _err ;
            end;
            //break;
        RSA_FLAG_TYPE_RSASSAPSS:
            if ossl_rsa_pss_params_30_is_unrestricted(pss_params) >0 then
            begin
                if BIO_printf(_out, 'No PSS parameter restrictions'#10, []) <= 0 then
                    goto _err ;
            end
            else
            begin
                hashalg_nid := ossl_rsa_pss_params_30_hashalg(pss_params);
                maskgenalg_nid :=
                    ossl_rsa_pss_params_30_maskgenalg(pss_params);
                maskgenhashalg_nid :=
                    ossl_rsa_pss_params_30_maskgenhashalg(pss_params);
                saltlen := ossl_rsa_pss_params_30_saltlen(pss_params);
                trailerfield :=
                    ossl_rsa_pss_params_30_trailerfield(pss_params);
                if BIO_printf(_out, 'PSS parameter restrictions:'#10,[]) <= 0  then
                    goto _err ;
                if BIO_printf(_out, '  Hash Algorithm: %s%s'#10,
                               [ossl_rsa_oaeppss_nid2name(hashalg_nid) ,
                               get_result(hashalg_nid = NID_sha1
                                , ' (default)' , '')]) <= 0  then
                    goto _err ;
                if BIO_printf(_out, '  Mask Algorithm: %s with %s%s'#10,
                              [ ossl_rsa_mgf_nid2name(maskgenalg_nid),
                               ossl_rsa_oaeppss_nid2name(maskgenhashalg_nid),
                              get_result ( (maskgenalg_nid = NID_mgf1)
                                 and  (maskgenhashalg_nid = NID_sha1)
                                , ' (default)' , '')]) <= 0  then
                    goto _err ;
                if BIO_printf(_out, '  Minimum Salt Length: %d%s'#10,
                              [ saltlen,
                               get_result(saltlen = 20 , ' (default)' , '')]) <= 0  then
                    goto _err ;
                if BIO_printf(_out, '  Trailer Field: 0x%x%s'#10,
                               [trailerfield,
                               get_result(trailerfield = 1 , ' (default )' , '')]) <= 0  then
                    goto _err ;
            end;
            //break;
        end;
    end;
    ret := 1;
 _err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    Result := ret;
end;



procedure ossl_prov_free_key(const fns : POSSL_DISPATCH; key : Pointer);
var
  kmgmt_free : TOSSL_FUNC_keymgmt_free_fn;
begin
    kmgmt_free := ossl_prov_get_keymgmt_free(fns);
    if Assigned(kmgmt_free) then
       kmgmt_free(key);
end;





function key2text_newctx( provctx : Pointer):Pointer;
begin
    Result := provctx;
end;


procedure key2text_freectx( vctx : Pointer);
begin

end;


function key2text_encode(vctx : Pointer;const key : Pointer; selection : integer; cout : POSSL_CORE_BIO; key2text : Tkey2text_func; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
var
  _out : PBIO;

  ret : integer;
begin
    _out := ossl_bio_new_from_core_bio(vctx, cout);
    if _out = nil then Exit(0);
    ret := key2text(_out, key, selection);
    BIO_free(_out);
    Result := ret;
end;


function rsa2text_import_object(ctx : Pointer; selection : integer;const params : POSSL_PARAM):Pointer;
begin
   Exit(ossl_prov_import_key(@ossl_rsa_keymgmt_functions, ctx, selection, params));
end;


procedure rsa2text_free_object( key : Pointer);
begin
   ossl_prov_free_key(@ossl_rsa_keymgmt_functions, key);
end;


function rsa2text_encode(vctx : Pointer; cout : POSSL_CORE_BIO;const key : Pointer; key_abstract : POSSL_PARAM; selection : integer;cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
   if (key_abstract <> nil) then
   begin
      ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
      Exit(0);
   end;
   result := key2text_encode(vctx, key, selection, cout, rsa_to_text, cb, cbarg);
end;


initialization



end.
