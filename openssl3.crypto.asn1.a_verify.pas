unit openssl3.crypto.asn1.a_verify;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

function ASN1_verify(i2d: Ti2d_of_void; a : PX509_ALGOR; signature : PASN1_BIT_STRING; data : PUTF8Char; pkey : PEVP_PKEY):integer;
  function ASN1_item_verify(const it : PASN1_ITEM; alg : PX509_ALGOR; signature : PASN1_BIT_STRING; data : Pointer; pkey : PEVP_PKEY):integer;
  function ASN1_item_verify_ex(const it : PASN1_ITEM; alg : PX509_ALGOR; signature : PASN1_BIT_STRING; data : Pointer; id : PASN1_OCTET_STRING; pkey : PEVP_PKEY; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function ASN1_item_verify_ctx(const it : PASN1_ITEM; alg : PX509_ALGOR; signature : PASN1_BIT_STRING; data : Pointer; ctx : PEVP_MD_CTX):integer;
  
implementation
uses openssl3.crypto.evp.digest, OpenSSL3.Err, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.p_verify, openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.objects.obj_xref,
     openssl3.crypto.evp.p_lib,  OpenSSL3.crypto.rsa.rsa_ameth,
     openssl3.crypto.evp.m_sigver, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.evp.names , openssl3.crypto.evp, openssl3.crypto.mem;



function ASN1_verify(i2d: Ti2d_of_void; a : PX509_ALGOR; signature : PASN1_BIT_STRING; data : PUTF8Char; pkey : PEVP_PKEY):integer;
var
  ctx : PEVP_MD_CTX;
  _type : PEVP_MD;
  p, buf_in : PByte;
  ret, i, inl : integer;
  label _err;
begin
    ctx := EVP_MD_CTX_new;
    buf_in := nil;
    ret := -1;
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    i := OBJ_obj2nid(a.algorithm);
    _type := EVP_get_digestbyname(OBJ_nid2sn(i));
    if _type = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
        goto _err;
    end;
    if (signature.&type = V_ASN1_BIT_STRING)  and ( (signature.flags and $7)>0 ) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        goto _err;
    end;

    inl := i2d(data, nil);
    if inl <= 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    buf_in := OPENSSL_malloc(uint32(inl));
    if buf_in = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    p := buf_in;
    i2d(data, @p);
    ret := Int( (EVP_VerifyInit_ex(ctx, _type, nil)>0)  and
                (EVP_VerifyUpdate(ctx, PByte(buf_in), inl)>0) );
    OPENSSL_clear_free(Pointer(buf_in), uint32(inl));
    if 0>=ret then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        goto _err;
    end;
    ret := -1;
    if EVP_VerifyFinal(ctx, PByte(signature.data),
                        uint32(signature.length), pkey) <= 0  then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        ret := 0;
        goto _err;
    end;
    ret := 1;
 _err:
    EVP_MD_CTX_free(ctx);
    Result := ret;
end;


function ASN1_item_verify(const it : PASN1_ITEM; alg : PX509_ALGOR; signature : PASN1_BIT_STRING; data : Pointer; pkey : PEVP_PKEY):integer;
begin
    Result := ASN1_item_verify_ex(it, alg, signature, data, nil, pkey, nil, nil);
end;


function ASN1_item_verify_ex(const it : PASN1_ITEM; alg : PX509_ALGOR; signature : PASN1_BIT_STRING; data : Pointer; id : PASN1_OCTET_STRING; pkey : PEVP_PKEY; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ctx : PEVP_MD_CTX;

  rv : integer;
begin
    rv := -1;
    ctx := evp_md_ctx_new_ex(pkey, id, libctx, propq);
    if ctx  <> nil then
    begin
        rv := ASN1_item_verify_ctx(it, alg, signature, data, ctx);
        EVP_PKEY_CTX_free(EVP_MD_CTX_get_pkey_ctx(ctx));
        EVP_MD_CTX_free(ctx);
    end;
    Result := rv;
end;


function ASN1_item_verify_ctx(const it : PASN1_ITEM; alg : PX509_ALGOR; signature : PASN1_BIT_STRING; data : Pointer; ctx : PEVP_MD_CTX):integer;
var
  pkey : PEVP_PKEY;
  buf_in : PByte;
  ret, mdnid, pknid, inl : integer;
  inll : size_t;
  _type : PEVP_MD;
  label _err;
begin
    buf_in := nil;
    ret := -1; inl := 0;
    inll := 0;
    pkey := EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if (signature.&type = V_ASN1_BIT_STRING)  and  ((signature.flags and $7) > 0) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        Exit(-1);
    end;
    { Convert signature OID into digest and public key OIDs }
    if 0>=OBJ_find_sigid_algs(OBJ_obj2nid(alg.algorithm) , @mdnid, @pknid) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
        goto _err;
    end;
    if (mdnid = NID_undef)  and  (evp_pkey_is_legacy(pkey)) then
    begin
        if (pkey.ameth = nil)  or  (not Assigned(pkey.ameth.item_verify)) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
            goto _err;
        end;
        ret := pkey.ameth.item_verify(ctx, it, data, alg, signature, pkey);
        {
         * Return values meaning:
         * <=0: error.
         *   1: method does everything.
         *   2: carry on as normal, method has called EVP_DigestVerifyInit
         }
        if ret <= 0 then ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        if ret <= 1 then goto _err;
    end
    else
    begin
        _type := nil;
        {
         * We don't yet have the ability for providers to be able to handle
         * X509_ALGOR style parameters. Fortunately the only one that needs this
         * so far is RSA-PSS, so we just special case this for now. In some
         * future version of OpenSSL we should push this to the provider.
         }
        if (mdnid = NID_undef)  and  (pknid = EVP_PKEY_RSA_PSS) then
        begin
            if (not EVP_PKEY_is_a(pkey, 'RSA'))  and  (not EVP_PKEY_is_a(pkey, 'RSA-PSS')) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_PUBLIC_KEY_TYPE);
                goto _err;
            end;
            { This function also calls EVP_DigestVerifyInit }
            if ossl_rsa_pss_to_ctx(ctx, nil, alg, pkey )  <= 0 then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
                goto _err;
            end;
        end
        else
        begin
            { Check public key OID matches public key type }
            if not EVP_PKEY_is_a(pkey, OBJ_nid2sn(pknid) ) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_PUBLIC_KEY_TYPE);
                goto _err;
            end;
            if mdnid <> NID_undef then
            begin
                _type := EVP_get_digestbynid(mdnid);
                if _type = nil then
                begin
                    ERR_raise(ERR_LIB_ASN1,
                              ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
                    goto _err;
                end;
            end;
            {
             * Note that some algorithms (notably Ed25519 and Ed448) may allow
             * a nil digest value.
             }
            if 0>=EVP_DigestVerifyInit(ctx, nil, _type, nil, pkey) then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
                ret := 0;
                goto _err;
            end;
        end;
    end;
    inl := ASN1_item_i2d(data, @buf_in, it);
    if inl <= 0 then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    if buf_in = nil then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    inll := inl;
    ret := EVP_DigestVerify(ctx, signature.data, size_t(signature.length),
                           buf_in, inl);
    if ret <= 0 then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        goto _err;
    end;
    ret := 1;
 _err:
    OPENSSL_clear_free(Pointer(buf_in), inll);
    Result := ret;
end;


end.
