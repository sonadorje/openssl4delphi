unit openssl3.crypto.ec.ecx_key;

interface
uses OpenSSL.Api;

function ossl_ecx_key_up_ref( key : PECX_KEY):integer;
procedure ossl_ecx_key_free( key : PECX_KEY);
 function ossl_ecx_key_allocate_privkey( key : PECX_KEY):PByte;
 function ossl_ecx_key_new(libctx : POSSL_LIB_CTX; _type : TECX_KEY_TYPE; haspubkey : integer;const propq : PUTF8Char):PECX_KEY;
 procedure ossl_ecx_key_set0_libctx( key : PECX_KEY; libctx : POSSL_LIB_CTX);

implementation
uses  OpenSSL3.Err, openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.ec.ec_lib, openssl3.crypto.ec.ec_kmeth,
      openssl3.crypto.ec.ec_curve, openssl3.crypto.evp.keymgmt_meth,
      openssl3.include.internal.refcount, openssl3.crypto.mem,
      OpenSSL3.threads_none,
      openssl3.crypto.mem_sec, openssl3.crypto.o_str ;





procedure ossl_ecx_key_set0_libctx( key : PECX_KEY; libctx : POSSL_LIB_CTX);
begin
    key.libctx := libctx;
end;




function ossl_ecx_key_new(libctx : POSSL_LIB_CTX; _type : TECX_KEY_TYPE; haspubkey : integer;const propq : PUTF8Char):PECX_KEY;
var
  ret : PECX_KEY;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then Exit(nil);
    ret.libctx := libctx;
    ret.haspubkey := haspubkey;
    case _type of
    ECX_KEY_TYPE_X25519:
        ret.keylen := X25519_KEYLEN;
        //break;
    ECX_KEY_TYPE_X448:
        ret.keylen := X448_KEYLEN;
        //break;
    ECX_KEY_TYPE_ED25519:
        ret.keylen := ED25519_KEYLEN;
        //break;
    ECX_KEY_TYPE_ED448:
        ret.keylen := ED448_KEYLEN;
        //break;
    end;
    ret.&type := _type;
    ret.references := 1;
    if propq <> nil then
    begin
        OPENSSL_strdup(ret.propq, propq);
        if ret.propq = nil then goto _err ;
    end;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then goto _err ;
    Exit(ret);
_err:
    ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    Result := nil;
end;

function ossl_ecx_key_allocate_privkey( key : PECX_KEY):PByte;
begin
    key.privkey := OPENSSL_secure_zalloc(key.keylen);
    Result := key.privkey;
end;

procedure ossl_ecx_key_free( key : PECX_KEY);
var
  i : integer;
begin
    if key = nil then exit;
    CRYPTO_DOWN_REF(key.references, i, key.lock);
    REF_PRINT_COUNT('ECX_KEY', key);
    if i > 0 then exit;
    REF_ASSERT_ISNT(i < 0);
    OPENSSL_free(key.propq);
    OPENSSL_secure_clear_free(key.privkey, key.keylen);
    CRYPTO_THREAD_lock_free(key.lock);
    OPENSSL_free(key);
end;



function ossl_ecx_key_up_ref( key : PECX_KEY):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(key.references, i, key.lock ) <= 0 then
        Exit(0);
    REF_PRINT_COUNT('ECX_KEY', key);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result((i > 1) , 1 , 0);
end;





end.
