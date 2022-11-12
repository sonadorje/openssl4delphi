unit openssl3.crypto.evp.evp_pkey;

interface
uses OpenSSL.Api, SysUtils;

function EVP_PKEY_get0_type_name(const key : PEVP_PKEY):PUTF8Char;
function EVP_PKEY2PKCS8(const pkey : PEVP_PKEY):PPKCS8_PRIV_KEY_INFO;
function evp_pkcs82pkey_legacy(const p8 : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;

implementation

uses openssl3.crypto.evp.keymgmt_meth,      openssl3.crypto.asn1.ameth_lib,
     openssl3.crypto.evp,                   openssl3.crypto.asn1.p8_pkey,
     openssl3.crypto.mem,                   OpenSSL3.Err,
     openssl3.crypto.evp.p_lib,             openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.a_object,
     openssl3.crypto.encode_decode.encoder_meth,
     openssl3.crypto.encode_decode.encoder_pkey,
     openssl3.crypto.encode_decode.encoder_lib;





function evp_pkcs82pkey_legacy(const p8 : PPKCS8_PRIV_KEY_INFO; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
var
  pkey : PEVP_PKEY;
  obj_tmp : array[0..79] of UTF8Char;
  algoid: PASN1_OBJECT ;
  label _error;
begin
    pkey := nil;
    if 0>=PKCS8_pkey_get0(@algoid, nil, nil, nil, p8) then
        Exit(nil);
    pkey := EVP_PKEY_new;
    if  pkey = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>=EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))  then
    begin
        i2t_ASN1_OBJECT(obj_tmp, 80, algoid);
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM,
                       Format('TYPE=%s', [obj_tmp]));
        goto _error;
    end;
    if Assigned(pkey.ameth.priv_decode_ex) then
    begin
        if 0>=pkey.ameth.priv_decode_ex(pkey, p8, libctx, propq) then
            goto _error;
    end
    else
    if Assigned(pkey.ameth.priv_decode) then
    begin
        if 0>=pkey.ameth.priv_decode(pkey, p8) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_PRIVATE_KEY_DECODE_ERROR);
            goto _error;
        end;
    end
    else
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_METHOD_NOT_SUPPORTED);
        goto _error;
    end;
    Exit(pkey);

 _error:
    EVP_PKEY_free(pkey);
    Result := nil;
end;

function EVP_PKEY2PKCS8(const pkey : PEVP_PKEY):PPKCS8_PRIV_KEY_INFO;
var
    p8        : PPKCS8_PRIV_KEY_INFO;
    ctx       : POSSL_ENCODER_CTX;
    selection : integer;
    der       : PByte;
    pp        : PByte;
    derlen    : size_t;
    label _error, _end;
begin
    p8 := nil;
    ctx := nil;
    {
     * The implementation for provider-native keys is to encode the
     * key to a DER encoded PKCS#8 structure, then convert it to a
     * PKCS8_PRIV_KEY_INFO with good old d2i functions.
     }
    if evp_pkey_is_provided(pkey) then
    begin
        selection := OSSL_KEYMGMT_SELECT_ALL;
        der := nil;
        derlen := 0;
        ctx := OSSL_ENCODER_CTX_new_for_pkey(pkey, selection,
                                                 'DER', 'PrivateKeyInfo',
                                                 nil);
        if (ctx = nil) or  (0>=OSSL_ENCODER_to_data(ctx, @der, @derlen)) then
            goto _error;
        pp := der;
        p8 := d2i_PKCS8_PRIV_KEY_INFO(nil, @pp, long(derlen));
        OPENSSL_free(der);
        if p8 = nil then
           goto _error;
    end
    else
    begin
        p8 := PKCS8_PRIV_KEY_INFO_new;
        if p8  = nil then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        if pkey.ameth <> nil then
        begin
            if Assigned(pkey.ameth.priv_encode) then
            begin
                if 0>=pkey.ameth.priv_encode(p8, pkey) then
                begin
                    ERR_raise(ERR_LIB_EVP, EVP_R_PRIVATE_KEY_ENCODE_ERROR);
                    goto _error;
                end;
            end
            else
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_METHOD_NOT_SUPPORTED);
                goto _error;
            end;
        end
        else
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
            goto _error;
        end;
    end;
    goto _end;
 _error:
    PKCS8_PRIV_KEY_INFO_free(p8);
    p8 := nil;
 _end:
    OSSL_ENCODER_CTX_free(ctx);
    Exit(p8);
end;

function EVP_PKEY_get0_type_name(const key : PEVP_PKEY):PUTF8Char;
var
  ameth : PEVP_PKEY_ASN1_METHOD;
  name : PUTF8Char;
begin
     name := nil;
    if key.keymgmt <> nil then
       Exit(EVP_KEYMGMT_get0_name(key.keymgmt));
    { Otherwise fallback to legacy }
    ameth := EVP_PKEY_get0_asn1(key);
    if ameth <> nil then
       EVP_PKEY_asn1_get0_info(nil, nil, nil, nil, @name, ameth);
    Result := name;
end;

end.
