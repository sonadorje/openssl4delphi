unit openssl3.crypto.ec.ec_kmeth;

interface
uses OpenSSL.Api;

type
   TKDF_func = function(const &in : Pointer; inlen : size_t; &out : Pointer; outlen : Psize_t):Pointer;

function ossl_ec_key_new_method_int(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; engine : PENGINE):PEC_KEY;
function ECDH_compute_key(_out : Pointer; outlen : size_t;const pub_key : PEC_POINT; eckey : PEC_KEY; KDF: TKDF_func):integer;
function EC_KEY_get_default_method:PEC_KEY_METHOD;
function EC_KEY_get_method(const key : PEC_KEY):PEC_KEY_METHOD;
function EC_KEY_OpenSSL:PEC_KEY_METHOD;

implementation

uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.o_str,
     OpenSSL3.threads_none, openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ecdh_ossl, openssl3.crypto.ec.ecdsa_ossl,
     openssl3.crypto.ex_data,
     openssl3.crypto.engine.eng_init, openssl3.crypto.engine.tb_eckey;

const
    openssl_ec_key_method: TEC_KEY_METHOD  = (
        name: 'OpenSSL EC_KEY method';
        flags: 0;
        init: nil;
        finish: nil;
        copy: nil;
        set_group: nil;
        set_private: nil;
        set_public: nil;
        keygen: ossl_ec_key_gen;
        compute_key: ossl_ecdh_compute_key;
        sign: ossl_ecdsa_sign;
        sign_setup: ossl_ecdsa_sign_setup;
        sign_sig: ossl_ecdsa_sign_sig;
        verify: ossl_ecdsa_verify;
        verify_sig: ossl_ecdsa_verify_sig
    );
    default_ec_key_meth: PEC_KEY_METHOD  = @openssl_ec_key_method;


function EC_KEY_OpenSSL:PEC_KEY_METHOD;
begin
    Result := @openssl_ec_key_method;
end;





function EC_KEY_get_method(const key : PEC_KEY):PEC_KEY_METHOD;
begin
    Result := key.meth;
end;

function EC_KEY_get_default_method:PEC_KEY_METHOD;
begin
    Result := default_ec_key_meth;
end;

function ECDH_compute_key(_out : Pointer; outlen : size_t;const pub_key : PEC_POINT; eckey : PEC_KEY; KDF: TKDF_func):integer;
var
  sec : PByte;
  seclen : size_t;
begin
    sec := nil;
    if not Assigned(eckey.meth.compute_key) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
        Exit(0);
    end;
    if outlen > INT_MAX then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_OUTPUT_LENGTH);
        Exit(0);
    end;
    if 0>= eckey.meth.compute_key(@sec, @seclen, pub_key, eckey) then
        Exit(0);
    if Assigned(KDF) then
    begin
        KDF(sec, seclen, _out, @outlen);
    end
    else
    begin
        if outlen > seclen then
           outlen := seclen;
        memcpy(_out, sec, outlen);
    end;
    OPENSSL_clear_free(Pointer(sec), seclen);
    Result := outlen;
end;


function ossl_ec_key_new_method_int(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; engine : PENGINE):PEC_KEY;
var
  ret : PEC_KEY;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.libctx := libctx;
    if propq <> nil then
    begin
         OPENSSL_strdup(ret.propq, propq);
        if ret.propq = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    ret.references := 1;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    ret.meth := EC_KEY_get_default_method();
{$IF not defined(OPENSSL_NO_ENGINE)  and   not defined(FIPS_MODULE)}
    if Assigned(engine) then
    begin
        if  0>= ENGINE_init(engine) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
        ret.engine := engine;
    end
    else
        ret.engine := ENGINE_get_default_EC();
    if ret.engine <> nil then
    begin
        ret.meth := ENGINE_get_EC(ret.engine);
        if ret.meth = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
    end;
{$ENDIF}
    ret.version := 1;
    ret.conv_form := POINT_CONVERSION_UNCOMPRESSED;
{ No ex_data inside the FIPS provider }
{$IFNDEF FIPS_MODULE}
    if  0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EC_KEY, ret, @ret.ex_data) then
    begin
        goto _err ;
    end;
{$ENDIF}
    if (Assigned(ret.meth.init))  and  (ret.meth.init(ret) = 0) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_INIT_FAIL);
        goto _err ;
    end;
    Exit(ret);
 _err:
    EC_KEY_free(ret);
    Result := nil;
end;


end.
