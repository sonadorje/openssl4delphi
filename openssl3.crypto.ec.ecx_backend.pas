unit openssl3.crypto.ec.ecx_backend;

interface
uses OpenSSL.Api;

function ossl_ecx_key_dup(const key : PECX_KEY; selection : integer):PECX_KEY;
function ossl_ecx_key_fromdata(ecx : PECX_KEY;const params : POSSL_PARAM; include_private : integer):int;
function ossl_ecx_public_from_private( key : PECX_KEY):integer;
function ossl_ecx_key_op(const palg : PX509_ALGOR; p : PByte; plen, id : integer; op : ecx_key_op_t; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PECX_KEY;
function ossl_ecx_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PECX_KEY;
function KEYNID2TYPE(id: int):TECX_KEY_TYPE ;
function IS25519(id: int): Boolean;
function  KEYLENID(id: int): Int;
function KEYLEN(p: PEVP_PKEY): size_t;
function ISX448(id: int): Boolean;

implementation

uses OpenSSL3.Err, openssl3.crypto.ec.ec_kmeth, openssl3.crypto.engine.eng_init,
     openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.param_build_set, openssl3.crypto.params,
     openssl3.crypto.ec.ec_support, openssl3.crypto.ec.ecx_key,
     openssl3.crypto.bn.bn_intern, openssl3.crypto.mem,
     openssl3.crypto.o_str, openssl3.crypto.mem_sec,
     openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.p8_pkey, openssl3.crypto.asn1.tasn_typ,
     OpenSSL3.threads_none, openssl3.crypto.asn1.x_algor,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.ec.curve25519, openssl3.crypto.ec.curve448,
     openssl3.crypto.ec.curve25519.eddsa;

function ISX448(id: int): Boolean;
begin
   Result :=  ((id) = EVP_PKEY_X448)
end;

function KEYLEN(p: PEVP_PKEY): size_t;
begin
   Result :=  KEYLENID(p.ameth.pkey_id)
end;

function IS25519(id: int): Boolean;
begin
    Result := (id = 1034{EVP_PKEY_X25519}) or (id = 1087{EVP_PKEY_ED25519})
end;

function  KEYNID2TYPE(id: int):TECX_KEY_TYPE ;
begin
    if IS25519(id) then
    begin
       if id = EVP_PKEY_X25519 then
          Result := ECX_KEY_TYPE_X25519
       else
          Result := ECX_KEY_TYPE_ED25519
    end
    else
    begin
       if id = EVP_PKEY_X448 then
          Result := ECX_KEY_TYPE_X448
       else
          Result := ECX_KEY_TYPE_ED448
    end;
end;

function ossl_ecx_key_from_pkcs8(const p8inf : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PECX_KEY;
var
  ecx : PECX_KEY;
  p : PByte;
  plen : integer;
  oct : PASN1_OCTET_STRING;
  palg : PX509_ALGOR;
begin
    ecx := nil;
    oct := nil;
    if 0>=PKCS8_pkey_get0(nil, @p, @plen, @palg, p8inf) then
        Exit(0);
    oct := d2i_ASN1_OCTET_STRING(nil, @p, plen);
    if oct = nil then begin
        p := nil;
        plen := 0;
    end
    else begin
        p := ASN1_STRING_get0_data(oct);
        plen := ASN1_STRING_length(oct);
    end;
    {
     * EVP_PKEY_NONE means that ecx_key_op has to figure out the key type
     * on its own.
     }
    ecx := ossl_ecx_key_op(palg, p, plen, EVP_PKEY_NONE, KEY_OP_PRIVATE,
                          libctx, propq);
    ASN1_OCTET_STRING_free(oct);
    Result := ecx;
end;


function  KEYLENID(id: int): Int;
begin
   Result := get_result(IS25519(id) , X25519_KEYLEN
                 , get_result(id = EVP_PKEY_X448 , X448_KEYLEN, ED448_KEYLEN))
end;

{
function  KEYNID2TYPE(id: int): int;
begin
    Result := get_result(IS25519(id) , get_result(id = EVP_PKEY_X25519 , Int(ECX_KEY_TYPE_X25519), Int(ECX_KEY_TYPE_ED25519) )
                                     , get_result(id = EVP_PKEY_X448 , Int(ECX_KEY_TYPE_X448), Int(ECX_KEY_TYPE_ED448)) )
end;
}

function ossl_ecx_key_op(const palg : PX509_ALGOR; p : PByte; plen, id : integer; op : ecx_key_op_t; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PECX_KEY;
var
  key : PECX_KEY;
  privkey, pubkey : PByte;
  ptype : integer;
  label _err;
begin
    key := nil;
    if op <> KEY_OP_KEYGEN then
    begin
        if palg <> nil then
        begin
            { Algorithm parameters must be absent }
            X509_ALGOR_get0(nil, @ptype, nil, palg);
            if ptype <> V_ASN1_UNDEF then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                Exit(0);
            end;
            if id = EVP_PKEY_NONE then
               id := OBJ_obj2nid(palg.algorithm)
            else
            if (id <> OBJ_obj2nid(palg.algorithm)) then
            begin
                ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                Exit(0);
            end;
        end;
        if (p = nil)  or  (id = EVP_PKEY_NONE)  or  (plen <> KEYLENID(id)) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
            Exit(0);
        end;
    end;
    key := ossl_ecx_key_new(libctx, TECX_KEY_TYPE(KEYNID2TYPE(id)), 1, propq);
    if key = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    pubkey := @key.pubkey;
    if op = KEY_OP_PUBLIC then
    begin
        memcpy(pubkey, p, plen);
    end
    else
    begin
        privkey := ossl_ecx_key_allocate_privkey(key);
        if privkey = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if op = KEY_OP_KEYGEN then
        begin
            if id <> EVP_PKEY_NONE then
            begin
                if RAND_priv_bytes_ex(libctx, privkey, KEYLENID(id), 0) <= 0 then
                    goto _err ;
                if id = EVP_PKEY_X25519 then
                begin
                    privkey[0] := privkey[0] and 248;
                    privkey[X25519_KEYLEN - 1] := privkey[X25519_KEYLEN - 1] and 127;
                    privkey[X25519_KEYLEN - 1]  := privkey[X25519_KEYLEN - 1]  or 64;
                end
                else
                if (id = EVP_PKEY_X448) then
                begin
                    privkey[0] := privkey[0] and 252;
                    privkey[X448_KEYLEN - 1]  := privkey[X448_KEYLEN - 1]  or 128;
                end;
            end;
        end
        else
        begin
            memcpy(privkey, p, KEYLENID(id));
        end;
        if 0>= ossl_ecx_public_from_private(key ) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_FAILED_MAKING_PUBLIC_KEY);
            goto _err ;
        end;
    end;
    Exit(key);
 _err:
    ossl_ecx_key_free(key);
    Result := nil;
end;



function ossl_ecx_public_from_private( key : PECX_KEY):integer;
begin
    case key.&type of
    ECX_KEY_TYPE_X25519:
        ossl_x25519_public_from_private(@key.pubkey, key.privkey);
        //break;
    ECX_KEY_TYPE_ED25519:
        if 0>= ossl_ed25519_public_from_private(key.libctx, @key.pubkey,
                                              key.privkey, key.propq) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_FAILED_MAKING_PUBLIC_KEY);
            Exit(0);
        end;
        //break;
    ECX_KEY_TYPE_X448:
        ossl_x448_public_from_private(@key.pubkey, key.privkey);
        //break;
    ECX_KEY_TYPE_ED448:
        if 0>= ossl_ed448_public_from_private(key.libctx, @key.pubkey,
                                            key.privkey, key.propq )then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_FAILED_MAKING_PUBLIC_KEY);
            Exit(0);
        end;
        //break;
    end;
    Result := 1;
end;




function ossl_ecx_key_fromdata(ecx : PECX_KEY;const params : POSSL_PARAM; include_private : integer):int;
var
    privkeylen,
    pubkeylen     : size_t;

    param_priv_key,
    param_pub_key : POSSL_PARAM;

    pubkey         : PByte;
begin
    privkeylen := 0; pubkeylen := 0;
    param_priv_key := nil;
    if ecx = nil then Exit(0);
    param_pub_key := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if include_private>0 then
       param_priv_key :=  OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (param_pub_key = nil)  and  (param_priv_key = nil) then Exit(0);
    if param_priv_key <> nil then
    begin
        if (0>= OSSL_PARAM_get_octet_string(param_priv_key,
                                          Pointer(ecx.privkey), ecx.keylen,
                                         @privkeylen))then
            Exit(0);
        if privkeylen <> ecx.keylen then
        begin
            {
             * Invalid key length. We will clear what we've received now. We
             * can't leave it to ossl_ecx_key_free() because that will call
             * OPENSSL_secure_clear_free() and assume the correct key length
             }
            OPENSSL_secure_clear_free(ecx.privkey, privkeylen);
            ecx.privkey := nil;
            Exit(0);
        end;
    end;
    pubkey := @ecx.pubkey;
    if (param_pub_key <> nil)
         and  (0>= OSSL_PARAM_get_octet_string(param_pub_key,
                                         Pointer( pubkey),
                                         sizeof(ecx.pubkey) , @pubkeylen))then
        Exit(0);
    if (param_pub_key <> nil)  and  (pubkeylen <> ecx.keylen)  then
        Exit(0);
    if (param_pub_key = nil)  and  (0>= ossl_ecx_public_from_private(ecx)) then
        Exit(0);
    ecx.haspubkey := 1;
    Result := 1;
end;

function ossl_ecx_key_dup(const key : PECX_KEY; selection : integer):PECX_KEY;
var
  ret : PECX_KEY;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then begin
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    ret.libctx := key.libctx;
    ret.haspubkey := key.haspubkey;
    ret.keylen := key.keylen;
    ret.&type := key.&type;
    ret.references := 1;
    if key.propq <> nil then
    begin
        OPENSSL_strdup(ret.propq, key.propq);
        if ret.propq = nil then goto _err ;
    end;
    if (selection and OSSL_KEYMGMT_SELECT_PUBLIC_KEY) <> 0 then
        memcpy(@ret.pubkey, @key.pubkey, sizeof(ret.pubkey));
    if ( (selection and OSSL_KEYMGMT_SELECT_PRIVATE_KEY) <> 0 )
         and ( key.privkey <> nil)  then
    begin
        if ossl_ecx_key_allocate_privkey(ret) = nil then
            goto _err ;
        memcpy(ret.privkey, key.privkey, ret.keylen);
    end;
    Exit(ret);
_err:
    ossl_ecx_key_free(ret);
    ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    Result := nil;
end;




end.
