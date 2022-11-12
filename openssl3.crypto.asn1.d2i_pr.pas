unit openssl3.crypto.asn1.d2i_pr;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api;

function d2i_PrivateKey_decoder(keytype : integer; a : PPEVP_PKEY;const pp : PPByte; _length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function ossl_d2i_PrivateKey_legacy(keytype : integer; a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function d2i_PrivateKey_ex(keytype : integer; a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function d2i_PrivateKey(_type : integer; a : PPEVP_PKEY;const pp : PPByte; length : long):PEVP_PKEY;
function d2i_AutoPrivateKey_legacy(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function d2i_AutoPrivateKey_ex(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function d2i_AutoPrivateKey(a : PPEVP_PKEY;const pp : PPByte; length : long):PEVP_PKEY;

implementation
uses  openssl3.crypto.evp.p_lib,                    openssl3.crypto.encode_decode.decoder_pkey,
      openssl3.crypto.evp.keymgmt_lib,              OpenSSL3.Err,
      openssl3.crypto.asn1.p8_pkey,                 openssl3.crypto.evp.evp_pkey,
      openssl3.crypto.engine.eng_init,              openssl3.crypto.encode_decode.decoder_meth,
      openssl3.crypto.asn1.tasn_typ,                OpenSSL3.include.openssl.asn1,
      openssl3.crypto.encode_decode.decoder_lib,    openssl3.providers.fips.fipsprov;

function d2i_PrivateKey_decoder(keytype : integer; a : PPEVP_PKEY;const pp : PPByte; _length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
const
   input_structures: array[0..2] of PUTF8Char  = ('type-specific', 'PrivateKeyInfo', nil);

var
    dctx             : POSSL_DECODER_CTX;
    len              : size_t;
    pkey,bak_a       : PEVP_PKEY;
    ppkey            : PPEVP_PKEY;
    key_name         : PUTF8Char;
    i, ret           : integer;
    p                : PByte;
    label _err;
begin
    dctx := nil;
    len := _length;
    pkey := nil; bak_a := nil;
    ppkey := @pkey;
    key_name := nil;

    if keytype <> EVP_PKEY_NONE then
    begin
        key_name := evp_pkey_type2name(keytype);
        if key_name = nil then Exit(nil);
    end;
    for i := 0 to Length(input_structures)-1 do
    begin
         p := pp^; bak_a := a^;
        if (a <> nil)  and  (bak_a <> nil) then
            ppkey := a;
        dctx := OSSL_DECODER_CTX_new_for_pkey(ppkey, 'DER',
                                             input_structures[i], key_name,
                                             EVP_PKEY_KEYPAIR, libctx, propq);
        if a <> nil then a^ := bak_a;
        if dctx = nil then continue;
        ret := OSSL_DECODER_from_data(dctx, pp, @len);
        OSSL_DECODER_CTX_free(dctx);
        if ret > 0 then
        begin
            if ( ppkey^ <> nil)
                 and  (evp_keymgmt_util_has( ppkey^, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) > 0 ) then
            begin
                if a <> nil then
                    a^ := ppkey^;
                Exit(@ppkey);
            end;
            pp^ := p;
            goto _err;
        end;
    end;
    { Fall through to error if all decodes failed }
_err:
    if ppkey <> a then
       EVP_PKEY_free( ppkey^);
    Result := nil;
end;


function ossl_d2i_PrivateKey_legacy(keytype : integer; a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
var
  ret : PEVP_PKEY;
  p : PByte;
  tmp : PEVP_PKEY;
  p8 : PPKCS8_PRIV_KEY_INFO;
  label _err;
begin
    p := pp^;
    if (a = nil)  or  (a^ = nil) then
    begin
        ret := EVP_PKEY_new;
        if ret = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
            Exit(nil);
        end;
    end
    else
    begin
        ret := a^;
{$IFNDEF OPENSSL_NO_ENGINE}
        ENGINE_finish(ret.engine);
        ret.engine := nil;
{$ENDIF}
    end;
    if 0>=EVP_PKEY_set_type(ret, keytype) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto _err;
    end;
    ERR_set_mark;
    if (not Assigned(ret.ameth.old_priv_decode))  or
       (0 >= ret.ameth.old_priv_decode(ret, @p, length)) then
    begin
        if (Assigned(ret.ameth.priv_decode)) or
           (Assigned(ret.ameth.priv_decode_ex)) then
        begin
            p8 := nil;
            p8 := d2i_PKCS8_PRIV_KEY_INFO(nil, @p, length);
            if p8 = nil then begin
                ERR_clear_last_mark;
                goto _err;
            end;
            tmp := evp_pkcs82pkey_legacy(p8, libctx, propq);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if tmp = nil then
            begin
                ERR_clear_last_mark;
                goto _err;
            end;
            EVP_PKEY_free(ret);
            ret := tmp;
            ERR_pop_to_mark;
            if EVP_PKEY_type(keytype) <> EVP_PKEY_get_base_id(ret)  then
                goto _err;
        end
        else
        begin
            ERR_clear_last_mark;
            ERR_raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB);
            goto _err;
        end;
    end
    else
    begin
      ERR_clear_last_mark;
    end;
    pp^ := p;
    if a <> nil then a^ := ret;
    Exit(ret);

 _err:
    if (a = nil)  or  (a^ <> ret) then
       EVP_PKEY_free(ret);
    Result := nil;
end;


function d2i_PrivateKey_ex(keytype : integer; a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
var
  ret : PEVP_PKEY;
begin
    ret := d2i_PrivateKey_decoder(keytype, a, pp, length, libctx, propq);
    { try the legacy path if the decoder failed }
    if ret = nil then
       ret := ossl_d2i_PrivateKey_legacy(keytype, a, pp, length, libctx, propq);
    Result := ret;
end;


function d2i_PrivateKey(_type : integer; a : PPEVP_PKEY;const pp : PPByte; length : long):PEVP_PKEY;
begin
    Result := d2i_PrivateKey_ex(_type, a, pp, length, nil, nil);
end;


function d2i_AutoPrivateKey_legacy(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
var
  inkey : Pstack_st_ASN1_TYPE;
  keytype : integer;
  p8 : PPKCS8_PRIV_KEY_INFO;
  ret : PEVP_PKEY;
  p: PByte;
begin
    p := pp^;
    {
     * Dirty trick: read in the ASN1 data into a STACK_OF(ASN1_TYPE): by
     * analyzing it we can determine the passed structure: this assumes the
     * input is surrounded by an ASN1 SEQUENCE.
     }
    inkey := d2i_ASN1_SEQUENCE_ANY(nil, @p, length);
    p := pp^;
    {
     * Since we only need to discern 'traditional format' RSA and DSA keys we
     * can just count the elements.
     }
    if sk_ASN1_TYPE_num(inkey) = 6 then
    begin
        keytype := EVP_PKEY_DSA;
    end
    else
    if (sk_ASN1_TYPE_num(inkey) = 4) then
    begin
        keytype := EVP_PKEY_EC;
    end
    else
    if (sk_ASN1_TYPE_num(inkey) = 3) then begin  { This seems to be PKCS8, not
                                              * traditional format }
        p8 := d2i_PKCS8_PRIV_KEY_INFO(nil, @p, length);
        sk_ASN1_TYPE_pop_free(inkey, ASN1_TYPE_free);
        if p8 = nil then begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
            Exit(nil);
        end;
        ret := evp_pkcs82pkey_legacy(p8, libctx, propq);
        PKCS8_PRIV_KEY_INFO_free(p8);
        if ret = nil then Exit(nil);
        pp^ := p;
        if a <> nil then begin
            a^ := ret;
        end;
        Exit(ret);
    end
    else
    begin
        keytype := EVP_PKEY_RSA;
    end;
    sk_ASN1_TYPE_pop_free(inkey, ASN1_TYPE_free);
    Result := ossl_d2i_PrivateKey_legacy(keytype, a, pp, length, libctx, propq);
end;


function d2i_AutoPrivateKey_ex(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
var
  ret : PEVP_PKEY;
begin
    ret := d2i_PrivateKey_decoder(EVP_PKEY_NONE, a, pp, length, libctx, propq);
    { try the legacy path if the decoder failed }
    if ret = nil then
       ret := d2i_AutoPrivateKey_legacy(a, pp, length, libctx, propq);
    Result := ret;
end;


function d2i_AutoPrivateKey(a : PPEVP_PKEY;const pp : PPByte; length : long):PEVP_PKEY;
begin
    Result := d2i_AutoPrivateKey_ex(a, pp, length, nil, nil);
end;



end.
