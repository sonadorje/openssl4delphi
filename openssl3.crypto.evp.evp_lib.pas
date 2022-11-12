unit openssl3.crypto.evp.evp_lib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api, SysUtils;

type
  sk_OP_CACHE_ELEM_freefunc = procedure(a: POP_CACHE_ELEM);
  Tupdate_func = function (ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
  Tinit_func   = function (ctx : PEVP_MD_CTX):integer;
  Tfinal_func  = function (ctx : PEVP_MD_CTX; md : PByte):integer;

function EVP_MD_get_type(const md : PEVP_MD):integer;
function EVP_CIPHER_get_type(const cipher : PEVP_CIPHER):integer;
function EVP_CIPHER_get_nid(const cipher : PEVP_CIPHER):integer;
function EVP_MD_get_size(const md : PEVP_MD):integer;
procedure evp_md_free_int( md : PEVP_MD);
function EVP_MD_nid(const md : PEVP_MD):integer;
 function EVP_MD_get0_name(const md : PEVP_MD):PUTF8Char;
 function EVP_MD_get_block_size(const md : PEVP_MD):integer;
 function evp_cipher_cache_constants( cipher : PEVP_CIPHER):integer;
 function EVP_CIPHER_get0_provider(const cipher : PEVP_CIPHER):POSSL_PROVIDER;
 function EVP_CIPHER_is_a(const cipher : PEVP_CIPHER; name : PUTF8Char):Boolean;
 function EVP_CIPHER_get0_name(const cipher : PEVP_CIPHER):PUTF8Char;
 function EVP_CIPHER_get_key_length(const cipher : PEVP_CIPHER):integer;
 function EVP_CIPHER_CTX_get_key_length(const ctx : PEVP_CIPHER_CTX):integer;
 function EVP_CIPHER_CTX_get_block_size(const ctx : PEVP_CIPHER_CTX):integer;
 function EVP_CIPHER_get_block_size(const cipher : PEVP_CIPHER):integer;
 function EVP_MD_get_flags(const md : PEVP_MD):Cardinal;
 function EVP_MD_is_a(const md : PEVP_MD; name : PUTF8Char):Boolean;
 function EVP_MD_get0_provider(const md : PEVP_MD):POSSL_PROVIDER;
 function EVP_MD_CTX_get0_md_data(const ctx : PEVP_MD_CTX):Pointer;
 function EVP_CIPHER_CTX_get0_cipher(const ctx : PEVP_CIPHER_CTX):PEVP_CIPHER;
 function EVP_CIPHER_get_mode(const cipher : PEVP_CIPHER):integer;
  function EVP_CIPHER_get_flags(const cipher : PEVP_CIPHER):Cardinal;
 function EVP_CIPHER_get_iv_length(const cipher : PEVP_CIPHER):integer;
 function EVP_CIPHER_CTX_is_encrypting(const ctx : PEVP_CIPHER_CTX):integer;
 function EVP_MD_CTX_get_pkey_ctx(const ctx : PEVP_MD_CTX):PEVP_PKEY_CTX;
 function init( ctx : PEVP_MD_CTX):integer;
 function update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
 function _final( ctx : PEVP_MD_CTX; md : PByte):integer;
 function EVP_md_null:PEVP_MD;
 procedure sk_OP_CACHE_ELEM_pop_free(sk: Pstack_st_OP_CACHE_ELEM; freefunc : sk_OP_CACHE_ELEM_freefunc);
 function sk_OP_CACHE_ELEM_num(const sk : Pstack_st_OP_CACHE_ELEM):integer;
 function sk_OP_CACHE_ELEM_value(const sk : Pstack_st_OP_CACHE_ELEM; idx : integer):POP_CACHE_ELEM;
 function sk_OP_CACHE_ELEM_new_null:Pstack_st_OP_CACHE_ELEM;
 function sk_OP_CACHE_ELEM_push( sk : Pstack_st_OP_CACHE_ELEM; ptr : POP_CACHE_ELEM):integer;
 function EVP_MD_CTX_test_flags(const ctx : PEVP_MD_CTX; flags : integer):integer;
 function EVP_MD_CTX_get0_md(const ctx : PEVP_MD_CTX):PEVP_MD;
 //procedure M_check_autoarg( ctx : PEVP_PKEY_CTX; arg : PByte; arglen : Psize_t; err : integer);
 function EVP_CIPHER_CTX_test_flags(const ctx : PEVP_CIPHER_CTX; flags : integer):integer;
 function EVP_CIPHER_CTX_get_iv_length(const ctx : PEVP_CIPHER_CTX):integer;
 procedure EVP_MD_CTX_set_flags( ctx : PEVP_MD_CTX; flags : integer);
 procedure EVP_MD_CTX_set_pkey_ctx( ctx : PEVP_MD_CTX; pctx : PEVP_PKEY_CTX);
 procedure EVP_MD_CTX_clear_flags( ctx : PEVP_MD_CTX; flags : integer);
 function EVP_CIPHER_param_to_asn1( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE):integer;
 function evp_cipher_param_to_asn1_ex( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
 function evp_cipher_set_asn1_aead_params( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
 function EVP_CIPHER_set_asn1_iv( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE):integer;
 function EVP_CIPHER_CTX_original_iv(const ctx : PEVP_CIPHER_CTX):PByte;
 function EVP_CIPHER_asn1_to_param( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE):integer;
 function evp_cipher_asn1_to_param_ex( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
 function evp_cipher_get_asn1_aead_params( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
 function EVP_CIPHER_get_asn1_iv( ctx : PEVP_CIPHER_CTX; _type : PASN1_TYPE):integer;
  function EVP_Cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;const _in : PByte; inl : uint32):integer;

function EVP_CIPHER_CTX_get_cipher_data(const ctx : PEVP_CIPHER_CTX):Pointer;
function EVP_CIPHER_CTX_get_num(const ctx : PEVP_CIPHER_CTX):integer;
function EVP_CIPHER_CTX_set_num( ctx : PEVP_CIPHER_CTX; num : integer):integer;
function EVP_CIPHER_CTX_buf_noconst( ctx : PEVP_CIPHER_CTX):PByte;

procedure EVP_MD_meth_free( md : PEVP_MD);

const  null_md: TEVP_MD = (
    &type: NID_undef;
    pkey_type: NID_undef;
    md_size: 0;
    flags: 0;
    origin: EVP_ORIG_GLOBAL;
    init: init;
    update: update;
    &final: _final;
    copy: nil;
    cleanup: nil;
    block_size: 0;
    ctx_size: sizeof(PEVP_MD)
);
EVP_CIPHER_CTX_key_length: function(const ctx : PEVP_CIPHER_CTX):integer =  EVP_CIPHER_CTX_get_key_length;

function EVP_MD_meth_new( md_type, pkey_type : integer):PEVP_MD;
function EVP_MD_meth_set_result_size( md : PEVP_MD; resultsize : integer):integer;
function EVP_MD_meth_set_input_blocksize( md : PEVP_MD; blocksize : integer):integer;
function EVP_MD_meth_set_app_datasize( md : PEVP_MD; datasize : integer):integer;
function EVP_MD_meth_set_flags( md : PEVP_MD; flags : Cardinal):integer;
function EVP_MD_meth_set_init( md : PEVP_MD; init : Tinit_func):integer;
function EVP_MD_meth_set_update( md : PEVP_MD; update : Tupdate_func):integer;
function EVP_MD_meth_set_final( md : PEVP_MD; final : Tfinal_func):integer;
procedure EVP_CIPHER_CTX_set_flags( ctx : PEVP_CIPHER_CTX; flags : integer);
function evp_cipher_ctx_enable_use_bits( ctx : PEVP_CIPHER_CTX; enable : uint32):integer;
function evp_pkey_keygen(libctx : POSSL_LIB_CTX;const name, propq : PUTF8Char; params : POSSL_PARAM):PEVP_PKEY;

const
   EVP_CIPHER_CTX_iv_length: function(const ctx : PEVP_CIPHER_CTX):integer =  EVP_CIPHER_CTX_get_iv_length;

implementation

uses OpenSSL3.Err,OpenSSL3.common,       openssl3.crypto.evp.digest,
     openssl3.crypto.mem,                openssl3.crypto.provider_core,
     openssl3.crypto.evp.evp_utils,      openssl3.crypto.params,
     openssl3.crypto.evp.evp_enc,        openssl3.crypto.evp.evp_fetch,
     openssl3.crypto.objects.obj_dat,    OpenSSL3.threads_none,
     openssl3.crypto.evp.pmeth_lib,      openssl3.crypto.asn1.a_type,
     openssl3.crypto.asn1.evp_asn1,      openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.a_object,      openssl3.crypto.stack,
     openssl3.crypto.evp.pmeth_gn;


function evp_pkey_keygen(libctx : POSSL_LIB_CTX;const name, propq : PUTF8Char; params : POSSL_PARAM):PEVP_PKEY;
var
  pkey : PEVP_PKEY;
  ctx : PEVP_PKEY_CTX;
begin
    pkey := nil;
    ctx := EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    if (ctx <> nil) and  (EVP_PKEY_keygen_init(ctx) > 0)
             and  (EVP_PKEY_CTX_set_params(ctx, params) > 0)  then
        EVP_PKEY_generate(ctx, @pkey);
    EVP_PKEY_CTX_free(ctx);
    Result := pkey;
end;




function evp_cipher_ctx_enable_use_bits( ctx : PEVP_CIPHER_CTX; enable : uint32):integer;
var
  params :array of TOSSL_PARAM;
begin
    params := [OSSL_PARAM_END, OSSL_PARAM_END];
    params[0] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_USE_BITS, @enable);
    Result := EVP_CIPHER_CTX_set_params(ctx, @params);
end;



procedure EVP_CIPHER_CTX_set_flags( ctx : PEVP_CIPHER_CTX; flags : integer);
var
  oldflags : integer;
begin
    oldflags := ctx.flags;
    ctx.flags  := ctx.flags  or flags;
    if ( (oldflags  xor  ctx.flags) and EVP_CIPH_FLAG_LENGTH_BITS) <> 0 then
        evp_cipher_ctx_enable_use_bits(ctx, 1);
end;


function EVP_MD_meth_set_flags( md : PEVP_MD; flags : Cardinal):integer;
begin
    if md.flags <> 0 then Exit(0);
    md.flags := flags;
    Result := 1;
end;


function EVP_MD_meth_set_init( md : PEVP_MD; init : Tinit_func):integer;
begin
    if Assigned(md.init) then Exit(0);
    md.init := init;
    Result := 1;
end;


function EVP_MD_meth_set_update( md : PEVP_MD; update : Tupdate_func):integer;
begin
    if Assigned(md.update) then Exit(0);
    md.update := update;
    Result := 1;
end;


function EVP_MD_meth_set_final( md : PEVP_MD; final : Tfinal_func):integer;
begin
    if Assigned(md.final) then Exit(0);
    md.final := final;
    Result := 1;
end;



function EVP_MD_meth_set_app_datasize( md : PEVP_MD; datasize : integer):integer;
begin
    if md.ctx_size <> 0 then Exit(0);
    md.ctx_size := datasize;
    Result := 1;
end;



function EVP_MD_meth_set_input_blocksize( md : PEVP_MD; blocksize : integer):integer;
begin
    if md.block_size <> 0 then Exit(0);
    md.block_size := blocksize;
    Result := 1;
end;


function EVP_MD_meth_set_result_size( md : PEVP_MD; resultsize : integer):integer;
begin
    if md.md_size <> 0 then Exit(0);
    md.md_size := resultsize;
    Result := 1;
end;



function EVP_MD_meth_new( md_type, pkey_type : integer):PEVP_MD;
var
  md : PEVP_MD;
begin
    md := evp_md_new;
    if md <> nil then
    begin
        md.&type := md_type;
        md.pkey_type := pkey_type;
        md.origin := EVP_ORIG_METH;
    end;
    Result := md;
end;


procedure EVP_MD_meth_free( md : PEVP_MD);
begin
    if (md = nil)  or  (md.origin <> EVP_ORIG_METH) then
       Exit;
    evp_md_free_int(md);
end;


function EVP_CIPHER_CTX_buf_noconst( ctx : PEVP_CIPHER_CTX):PByte;
begin
    Result := @ctx.buf;
end;





function EVP_CIPHER_CTX_set_num( ctx : PEVP_CIPHER_CTX; num : integer):integer;
var
  ok : integer;
  n : uint32;
  params : array of TOSSL_PARAM;
begin
    n := uint32(num);
    params := [OSSL_PARAM_END, OSSL_PARAM_END];
    params[0] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_NUM, @n);
    ok := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params);
    if ok <> 0 then
       ctx.num := int(n);
    Result := Int(ok <> 0);
end;



function EVP_CIPHER_CTX_get_num(const ctx : PEVP_CIPHER_CTX):integer;
var
  ok : integer;
  v : uint32;
  params : array of TOSSL_PARAM;
begin
    v := uint32(ctx.num);
    params := [  OSSL_PARAM_END, OSSL_PARAM_END ];
    params[0] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_NUM, @v);
    ok := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
    Result := get_result(ok <> 0 , int(v) , EVP_CTRL_RET_UNSUPPORTED);
end;



function EVP_CIPHER_CTX_get_cipher_data(const ctx : PEVP_CIPHER_CTX):Pointer;
begin
    Result := ctx.cipher_data;
end;




function EVP_Cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;const _in : PByte; inl : uint32):integer;
var
    ret       : integer;

  outl,
  blocksize : size_t;
begin
    if ctx.cipher.prov <> nil then begin
        {
         * If the provided implementation has a ccipher function, we use it,
         * and translate its return value like this: 0 => -1, 1 => outlen
         *
         * Otherwise, we call the cupdate function if in <> nil, or cfinal
         * if in = nil.  Regardless of which, we return what we got.
         }
        ret := -1;
        outl := 0;
        blocksize := EVP_CIPHER_CTX_get_block_size(ctx);
        if Assigned(ctx.cipher.ccipher) then
           ret := get_result(ctx.cipher.ccipher(ctx.algctx, _out, @outl,
                                        inl + get_result(blocksize = 1 , 0 , blocksize),
                                        _in, size_t(inl)) > 0, int(outl) , -1)
        else if (_in <> nil) then
            ret := ctx.cipher.cupdate(ctx.algctx, _out, @outl,
                                       inl + get_result(blocksize = 1 , 0 , blocksize),
                                       _in, size_t(inl))
        else
            ret := ctx.cipher.cfinal(ctx.algctx, _out, @outl,
                                     get_result(blocksize = 1 , 0 , blocksize));
        Exit(ret);
    end;
    Result := ctx.cipher.do_cipher(ctx, _out, _in, inl);
end;

function EVP_CIPHER_get_asn1_iv( ctx : PEVP_CIPHER_CTX; _type : PASN1_TYPE):integer;
var
  i : integer;
  l : uint32;
  iv : array[0..(EVP_MAX_IV_LENGTH)-1] of Byte;
begin
    i := 0;
    if _type <> nil then
    begin
        l := EVP_CIPHER_CTX_get_iv_length(ctx);
        if not ossl_assert(l <= sizeof(iv))  then
            Exit(-1);
        i := ASN1_TYPE_get_octetstring(_type, @iv, l);
        if i <> int(l) then
           Exit(-1);
        if 0>=EVP_CipherInit_ex(ctx, nil, nil, nil, @iv, -1) then
            Exit(-1);
    end;
    Result := i;
end;

function evp_cipher_get_asn1_aead_params( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
var
  i : integer;
  tl : long;
  iv : array[0..(EVP_MAX_IV_LENGTH)-1] of Byte;
begin
    i := 0;
    if (_type = nil)  or  (asn1_params = nil) then Exit(0);
    i := ossl_asn1_type_get_octetstring_int(_type, @tl, nil, EVP_MAX_IV_LENGTH);
    if i <= 0 then Exit(-1);
    ossl_asn1_type_get_octetstring_int(_type, @tl, @iv, i);
    memcpy(@asn1_params.iv, @iv, i);
    asn1_params.iv_len := i;
    Result := i;
end;

function evp_cipher_asn1_to_param_ex( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
var
  ret : integer;
  cipher : PEVP_CIPHER;
  params : array[0..2] of TOSSL_PARAM;
  p: POSSL_PARAM;
  der : PByte;
  derl : integer;
begin
    ret := -1;
    cipher := c.cipher;
    {
     * For legacy implementations, we detect custom AlgorithmIdentifier
     * parameter handling by checking if there the function pointer
     * cipher.get_asn1_parameters is set.  We know that this pointer
     * is nil for provided implementations.
     *
     * Otherwise, for any implementation, we check the flag
     * EVP_CIPH_FLAG_CUSTOM_ASN1.  If it isn't set, we apply
     * default AI parameter creation.
     *
     * Otherwise, for provided implementations, we get the AI parameter
     * in DER encoded form from the implementation by requesting the
     * appropriate OSSL_PARAM and converting the result to a ASN1_TYPE.
     *
     * If none of the above applies, this operation is unsupported.
     }
    if Assigned(cipher.get_asn1_parameters) then
    begin
        ret := cipher.get_asn1_parameters(c, _type);
    end
    else
    if ((EVP_CIPHER_get_flags(cipher) and EVP_CIPH_FLAG_CUSTOM_ASN1) = 0) then
    begin
        case (EVP_CIPHER_get_mode(cipher)) of
          EVP_CIPH_WRAP_MODE:
              ret := 1;
              //break;
          EVP_CIPH_GCM_MODE:
              ret := evp_cipher_get_asn1_aead_params(c, _type, asn1_params);
              //break;
          EVP_CIPH_CCM_MODE,
          EVP_CIPH_XTS_MODE,
          EVP_CIPH_OCB_MODE:
              ret := -2;
              //break;
          else
              ret := EVP_CIPHER_get_asn1_iv(c, _type);
        end;
    end
    else if (cipher.prov <> nil) then
    begin
        p := @params;
        der := nil;
        derl := -1;
        derl := i2d_ASN1_TYPE(_type, @der);
        if derl >= 0 then
        begin
            PostInc(p)^ := OSSL_PARAM_construct_octet_string(
                        OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS,
                        der, size_t(derl));
            p^ := OSSL_PARAM_construct_end;
            if EVP_CIPHER_CTX_set_params(c, @params) > 0 then
                ret := 1;
            OPENSSL_free(der);
        end;
    end
    else begin
        ret := -2;
    end;
    if ret = -2 then
       ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER)
    else if (ret <= 0) then
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
    if ret < -1 then ret := -1;
    Result := ret;
end;




function EVP_CIPHER_asn1_to_param( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE):integer;
begin
    Result := evp_cipher_asn1_to_param_ex(c, _type, nil);
end;

function EVP_CIPHER_CTX_original_iv(const ctx : PEVP_CIPHER_CTX):PByte;
var
  ok : integer;
  v : PByte;
  params : array of TOSSL_PARAM;
begin
    v := @ctx.oiv;
    params := [OSSL_PARAM_END, OSSL_PARAM_END];

    params[0] := OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_IV,
                                        PPointer(@v), sizeof(ctx.oiv));
    ok := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
    Result := get_result(ok <> 0 , v , nil);
end;



function EVP_CIPHER_set_asn1_iv( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE):integer;
var
  i : integer;
  j : uint32;
  oiv : PByte;
begin
    i := 0;
    oiv := nil;
    if _type <> nil then begin
        oiv := PByte(EVP_CIPHER_CTX_original_iv(c));
        j := EVP_CIPHER_CTX_get_iv_length(c);
        assert(j <= sizeof(c.iv));
        i := ASN1_TYPE_set_octetstring(_type, oiv, j);
    end;
    Result := i;
end;


function evp_cipher_set_asn1_aead_params( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
begin
    if (&type = nil)  or  (asn1_params = nil) then
       Exit(0);
    Exit(ossl_asn1_type_set_octetstring_int(&type, asn1_params.tag_len,
                                              @asn1_params.iv,
                                              asn1_params.iv_len));
end;

function evp_cipher_param_to_asn1_ex( c : PEVP_CIPHER_CTX; _type : PASN1_TYPE; asn1_params : Pevp_cipher_aead_asn1_params):integer;
var
  ret : integer;
  cipher : PEVP_CIPHER;
  params : array[0..2] of TOSSL_PARAM;
  p : POSSL_PARAM;
  der, derp : PByte;
  label _err;
begin
    ret := -1;
    cipher := c.cipher;
    {
     * For legacy implementations, we detect custom AlgorithmIdentifier
     * parameter handling by checking if the function pointer
     * cipher.set_asn1_parameters is set.  We know that this pointer
     * is nil for provided implementations.
     *
     * Otherwise, for any implementation, we check the flag
     * EVP_CIPH_FLAG_CUSTOM_ASN1.  If it isn't set, we apply
     * default AI parameter extraction.
     *
     * Otherwise, for provided implementations, we convert |type| to
     * a DER encoded blob and pass to the implementation in OSSL_PARAM
     * form.
     *
     * If none of the above applies, this operation is unsupported.
     }
    if Assigned(cipher.set_asn1_parameters) then begin
        ret := cipher.set_asn1_parameters(c, _type);
    end
    else
    if ((EVP_CIPHER_get_flags(cipher) and EVP_CIPH_FLAG_CUSTOM_ASN1) = 0) then
    begin
        case (EVP_CIPHER_get_mode(cipher)) of
          EVP_CIPH_WRAP_MODE:
          begin
              if EVP_CIPHER_is_a(cipher, SN_id_smime_alg_CMS3DESwrap) then
                  ASN1_TYPE_set(_type, V_ASN1_NULL, nil);
              ret := 1;
          end;
          EVP_CIPH_GCM_MODE:
              ret := evp_cipher_set_asn1_aead_params(c, _type, asn1_params);
              //break;
          EVP_CIPH_CCM_MODE,
          EVP_CIPH_XTS_MODE,
          EVP_CIPH_OCB_MODE:
              ret := -2;
              //break;
          else
              ret := EVP_CIPHER_set_asn1_iv(c, _type);
        end;
    end
    else if (cipher.prov <> nil) then
    begin
         p := @params;
        der := nil;
        {
         * We make two passes, the first to get the appropriate buffer size,
         * and the second to get the actual value.
         }
        PostInc(p)^ := OSSL_PARAM_construct_octet_string(
                       OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS,
                       nil, 0);
        p^ := OSSL_PARAM_construct_end;
        if 0>=EVP_CIPHER_CTX_get_params(c, @params) then
            goto _err;
        { ... but, we should get a return size too! }
        der := OPENSSL_malloc(params[0].return_size);
        if (OSSL_PARAM_modified(@params) > 0) and  (params[0].return_size <> 0)
             and  (der <> nil)  then
        begin
            params[0].data := der;
            params[0].data_size := params[0].return_size;
            OSSL_PARAM_set_all_unmodified(@params);
            derp := der;
            if (EVP_CIPHER_CTX_get_params(c, @params) > 0)  and
               (OSSL_PARAM_modified(@params) > 0) and
               (d2i_ASN1_TYPE(@_type, PPByte(@derp),
                                 params[0].return_size) <> nil)  then
            begin
                ret := 1;
            end;
            OPENSSL_free(der);
        end;
    end
    else begin
        ret := -2;
    end;
 _err:
    if ret = -2 then
       ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER)
    else if (ret <= 0) then
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
    if ret < -1 then
       ret := -1;
    Result := ret;
end;




function EVP_CIPHER_param_to_asn1( c : PEVP_CIPHER_CTX; &type : PASN1_TYPE):integer;
begin
    Result := evp_cipher_param_to_asn1_ex(c, &type, nil);
end;

procedure EVP_MD_CTX_clear_flags( ctx : PEVP_MD_CTX; flags : integer);
begin
    ctx.flags := ctx.flags and  (not flags);
end;



procedure EVP_MD_CTX_set_pkey_ctx( ctx : PEVP_MD_CTX; pctx : PEVP_PKEY_CTX);
begin
    {
     * it's reasonable to set nil pctx (a.k.a clear the ctx.pctx), so
     * we have to deal with the cleanup job here.
     }
    if 0>=EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX) then
        EVP_PKEY_CTX_free(ctx.pctx);
    ctx.pctx := pctx;
    if pctx <> nil then begin
        { make sure pctx is not freed when destroying PEVP_MD_CTX }
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    end
    else begin
        EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    end;
end;

procedure EVP_MD_CTX_set_flags( ctx : PEVP_MD_CTX; flags : integer);
begin
    ctx.flags  := ctx.flags  or flags;
end;

function EVP_CIPHER_CTX_get_iv_length(const ctx : PEVP_CIPHER_CTX):integer;
var
  rv, len : integer;
  v : size_t;
  params : array[0..1] of TOSSL_PARAM;
  label _legacy;
begin
    len := EVP_CIPHER_get_iv_length(ctx.cipher);
    v := len;
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;

    params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, @v);
    rv := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
    if rv = EVP_CTRL_RET_UNSUPPORTED then goto _legacy;
    Exit(get_result(rv <> 0 , int(v) , -1));
    { Code below to be removed when legacy support is dropped. }
_legacy:
    if EVP_CIPHER_get_flags(ctx.cipher) and EVP_CIPH_CUSTOM_IV_LENGTH <> 0 then
    begin
        rv := EVP_CIPHER_CTX_ctrl(PEVP_CIPHER_CTX(ctx), EVP_CTRL_GET_IVLEN, 0, @len);
        Result := get_result(rv = 1 , len , -1);
    end;
    Result := len;
end;



function EVP_CIPHER_CTX_test_flags(const ctx : PEVP_CIPHER_CTX; flags : integer):integer;
begin
    Result := ctx.flags and flags;
end;

{
procedure M_check_autoarg( ctx : PEVP_PKEY_CTX; arg : PByte; arglen : Psize_t; err : integer);
var
  pksize : size_t;
begin
    if ctx.pmeth.flags and EVP_PKEY_FLAG_AUTOARGLEN > 0 then
    begin
        pksize := size_t(EVP_PKEY_get_size(ctx.pkey));
        if pksize = 0 then begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); //ckerr_ignore
            exit( 0);
        end;
        if arg = nil then begin
            arglen^ := pksize;
            exit( 1);
        end;
        if arglen^ < pksize then begin
            ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL); //ckerr_ignore
            exit( 0);
        end;
    end;
end;
}

function EVP_MD_CTX_get0_md(const ctx : PEVP_MD_CTX):PEVP_MD;
begin
    if ctx = nil then Exit(nil);
    Result := ctx.reqdigest;
end;




function EVP_MD_CTX_test_flags(const ctx : PEVP_MD_CTX; flags : integer):integer;
begin
    Result := ctx.flags and flags;
end;



function sk_OP_CACHE_ELEM_push( sk : Pstack_st_OP_CACHE_ELEM; ptr : POP_CACHE_ELEM):integer;
begin
   Exit(OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_OP_CACHE_ELEM_new_null:Pstack_st_OP_CACHE_ELEM;
begin
   Exit(Pstack_st_OP_CACHE_ELEM(OPENSSL_sk_new_null));
end;


function sk_OP_CACHE_ELEM_value(const sk : Pstack_st_OP_CACHE_ELEM; idx : integer):POP_CACHE_ELEM;
begin
   Exit(POP_CACHE_ELEM(OPENSSL_sk_value(POPENSSL_STACK( sk), idx)));
end;




function sk_OP_CACHE_ELEM_num(const sk : Pstack_st_OP_CACHE_ELEM):integer;
begin
 Exit(OPENSSL_sk_num(POPENSSL_STACK( sk)));
end;




procedure sk_OP_CACHE_ELEM_pop_free(sk: Pstack_st_OP_CACHE_ELEM; freefunc : sk_OP_CACHE_ELEM_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;


function init( ctx : PEVP_MD_CTX):integer;
begin
    Result := 1;
end;


function update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
    Result := 1;
end;


function _final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
    Result := 1;
end;


function EVP_MD_CTX_get_pkey_ctx(const ctx : PEVP_MD_CTX):PEVP_PKEY_CTX;
begin
    Result := ctx.pctx;
end;

function EVP_md_null:PEVP_MD;
begin
    Result := @null_md;
end;

function EVP_CIPHER_CTX_is_encrypting(const ctx : PEVP_CIPHER_CTX):integer;
begin
    Result := ctx.encrypt;
end;





function EVP_CIPHER_get_iv_length(const cipher : PEVP_CIPHER):integer;
begin
    Result := cipher.iv_len;
end;



function EVP_CIPHER_get_flags(const cipher : PEVP_CIPHER):Cardinal;
begin
    Result := cipher.flags;
end;

function EVP_CIPHER_get_mode(const cipher : PEVP_CIPHER):integer;
begin
    Result := EVP_CIPHER_get_flags(cipher) and EVP_CIPH_MODE;
end;



function EVP_CIPHER_CTX_get0_cipher(const ctx : PEVP_CIPHER_CTX):PEVP_CIPHER;
begin
    if ctx = nil then Exit(nil);
    Result := ctx.cipher;
end;



function EVP_MD_CTX_get0_md_data(const ctx : PEVP_MD_CTX):Pointer;
begin
    Result := ctx.md_data;
end;

function EVP_MD_get0_provider(const md : PEVP_MD):POSSL_PROVIDER;
begin
    Result := md.prov;
end;



function EVP_MD_is_a(const md : PEVP_MD; name : PUTF8Char):Boolean;
begin
    if md.prov <> nil then Exit(evp_is_a(md.prov, md.name_id, nil, name));
    Result := evp_is_a(nil, 0, EVP_MD_get0_name(md), name);
end;



function EVP_MD_get_flags(const md : PEVP_MD):Cardinal;
begin
    Result := md.flags;
end;





function EVP_CIPHER_get_block_size(const cipher : PEVP_CIPHER):integer;
begin
    Result := cipher.block_size;
end;



function EVP_CIPHER_CTX_get_block_size(const ctx : PEVP_CIPHER_CTX):integer;
begin
    Result := EVP_CIPHER_get_block_size(ctx.cipher);
end;

function EVP_CIPHER_CTX_get_key_length(const ctx : PEVP_CIPHER_CTX):integer;
var
  ok : integer;
  v : size_t;
  params : array[0..1] of TOSSL_PARAM;
begin
    v := ctx.key_len;
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;
    params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, @v);
    ok := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
    Result := get_result(ok <> 0 , int(v) , EVP_CTRL_RET_UNSUPPORTED);
end;



function EVP_CIPHER_get_key_length(const cipher : PEVP_CIPHER):integer;
begin
    Result := cipher.key_len;
end;


function EVP_CIPHER_get0_name(const cipher : PEVP_CIPHER):PUTF8Char;
begin
    if cipher.type_name <> nil then Exit(cipher.type_name);
{$IFNDEF FIPS_MODULE}
    Exit(OBJ_nid2sn(EVP_CIPHER_get_nid(cipher)));
{$ELSE Exit(nil);}
{$ENDIF}
end;



function EVP_CIPHER_is_a(const cipher : PEVP_CIPHER; name : PUTF8Char):Boolean;
begin
    if cipher.prov <> nil then
       Exit(evp_is_a(cipher.prov, cipher.name_id, nil, name));
    Result := evp_is_a(nil, 0, EVP_CIPHER_get0_name(cipher), name);
end;

function EVP_CIPHER_get0_provider(const cipher : PEVP_CIPHER):POSSL_PROVIDER;
begin
    Result := cipher.prov;
end;

function evp_cipher_cache_constants( cipher : PEVP_CIPHER):integer;
var
  ok: Boolean;
  aead,
  custom_iv, cts, multiblock, randkey : integer;
  ivlen, blksz, keylen : size_t;
  mode : uint32;
  params : array[0..9] of TOSSL_PARAM;
  p: POSSL_PARAM;
begin
    aead := 0; custom_iv := 0; cts := 0; multiblock := 0; randkey := 0;
    ivlen := 0;
    blksz := 0;
    keylen := 0;
    mode := 0;
    params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, @blksz);
    params[1] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, @ivlen);
    params[2] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, @keylen);
    params[3] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_MODE, @mode);
    params[4] := OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD, @aead);
    params[5] := OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CUSTOM_IV, @custom_iv);
    params[6] := OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CTS, @cts);
    params[7] := OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, @multiblock);
    params[8] := OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, @randkey);
    params[9] := OSSL_PARAM_construct_end();
    ok := evp_do_ciph_getparams(cipher, @params) > 0;
    if ok then
    begin
        cipher.block_size := blksz;
        cipher.iv_len := ivlen;
        cipher.key_len := keylen;
        cipher.flags := mode;
        if aead >0 then
           cipher.flags  := cipher.flags  or EVP_CIPH_FLAG_AEAD_CIPHER;
        if custom_iv >0 then
           cipher.flags  := cipher.flags  or EVP_CIPH_CUSTOM_IV;
        if cts>0 then
           cipher.flags  := cipher.flags  or EVP_CIPH_FLAG_CTS;
        if multiblock>0 then
           cipher.flags  := cipher.flags  or EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK;
        if Assigned(cipher.ccipher ) then
           cipher.flags  := cipher.flags  or EVP_CIPH_FLAG_CUSTOM_CIPHER;
        if randkey>0 then
           cipher.flags  := cipher.flags  or EVP_CIPH_RAND_KEY;

        p := EVP_CIPHER_gettable_ctx_params(cipher);
        if nil <> OSSL_PARAM_locate_const(p , OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS) then
            cipher.flags  := cipher.flags  or EVP_CIPH_FLAG_CUSTOM_ASN1;
    end;
    Result := Int(ok);
end;

function EVP_MD_get_block_size(const md : PEVP_MD):integer;
begin
    if md = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL);
        Exit(-1);
    end;
    Result := md.block_size;
end;



function EVP_MD_get0_name(const md : PEVP_MD):PUTF8Char;
begin
    if md = nil then Exit(nil);
    if md.type_name <> nil then Exit(md.type_name);
{$IFNDEF FIPS_MODULE}
    Exit(OBJ_nid2sn(EVP_MD_nid(md)));
{$ELSE Exit(nil);}
{$ENDIF}
end;

function EVP_MD_nid(const md : PEVP_MD):integer;
begin
  Result := EVP_MD_get_type(md);
end;


procedure evp_md_free_int( md : PEVP_MD);
begin
    OPENSSL_free(md.type_name);
    ossl_provider_free(md.prov);
    CRYPTO_THREAD_lock_free(md.lock);
    OPENSSL_free(md);
end;

function EVP_MD_get_size(const md : PEVP_MD):integer;
begin
    if md = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL);
        Exit(-1);
    end;
    Result := md.md_size;
end;


function EVP_CIPHER_get_nid(const cipher : PEVP_CIPHER):integer;
begin
    Result := cipher.nid;
end;

function EVP_CIPHER_get_type(const cipher : PEVP_CIPHER):integer;
var
  nid : integer;
  otmp : PASN1_OBJECT;
begin
    nid := EVP_CIPHER_get_nid(cipher);
    case nid of
    NID_rc2_cbc,
    NID_rc2_64_cbc,
    NID_rc2_40_cbc:
        Exit(NID_rc2_cbc);
    NID_rc4,
    NID_rc4_40:
        Exit(NID_rc4);
    NID_aes_128_cfb128,
    NID_aes_128_cfb8,
    NID_aes_128_cfb1:
        Exit(NID_aes_128_cfb128);
    NID_aes_192_cfb128,
    NID_aes_192_cfb8,
    NID_aes_192_cfb1:
        Exit(NID_aes_192_cfb128);
    NID_aes_256_cfb128,
    NID_aes_256_cfb8,
    NID_aes_256_cfb1:
        Exit(NID_aes_256_cfb128);
    NID_des_cfb64,
    NID_des_cfb8,
    NID_des_cfb1:
        Exit(NID_des_cfb64);
    NID_des_ede3_cfb64,
    NID_des_ede3_cfb8,
    NID_des_ede3_cfb1:
        Exit(NID_des_cfb64);
    else
{$IFDEF FIPS_MODULE}
        Exit(NID_undef);
{$ELSE} begin
            { Check it has an OID and it is valid }
            otmp := OBJ_nid2obj(nid);
            //Writeln(Format('evp_lib.EVP_CIPHER_get_type.otmp: sn=%s, nid=%d', [otmp.sn, otmp.nid]));
            if OBJ_get0_data(otmp)  = nil then
                nid := NID_undef;
            ASN1_OBJECT_free(otmp);
            Exit(nid);
        end;
{$ENDIF}
    end;
end;

function EVP_MD_get_type(const md : PEVP_MD):integer;
begin
    Result := md.&type;
end;

end.
