unit openssl3.crypto.asn1.a_sign;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ASN1_sign(i2d : Ti2d_of_void; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING; data : PUTF8Char; pkey : PEVP_PKEY;const _type : PEVP_MD):integer;
  function ASN1_item_sign(const it : PASN1_ITEM; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING;const data : Pointer; pkey : PEVP_PKEY;const md : PEVP_MD):integer;
  function ASN1_item_sign_ex(const it : PASN1_ITEM; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING;const data : Pointer; id : PASN1_OCTET_STRING; pkey : PEVP_PKEY;const md : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function ASN1_item_sign_ctx(const it : PASN1_ITEM; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING;const data : Pointer; ctx : PEVP_MD_CTX):integer;

implementation
uses openssl3.crypto.evp.digest, OpenSSL3.Err,  openssl3.crypto.asn1.a_object,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.mem,
     openssl3.crypto.evp.p_lib,  openssl3.crypto.evp,
     openssl3.crypto.evp.m_sigver,  openssl3.crypto.params,
     openssl3.crypto.asn1.p_sign,
     openssl3.crypto.asn1.x_algor,  openssl3.crypto.objects.obj_xref,
     openssl3.crypto.evp.evp_lib,  openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.tasn_typ;


function ASN1_sign(i2d : Ti2d_of_void; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING; data : PUTF8Char; pkey : PEVP_PKEY;const _type : PEVP_MD):integer;
var
  ctx : PEVP_MD_CTX;
  p, buf_in, buf_out : PByte;
  i, inl, outl : integer;
  inll, outll : size_t;
  a : PX509_ALGOR;

  label _err;
begin
    ctx := EVP_MD_CTX_new;
    buf_in := nil; buf_out := nil;
    inl := 0; outl := 0;
    inll := 0; outll := 0;
    if ctx = nil then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    for i := 0 to 1 do
    begin
        if i = 0 then
           a := algor1
        else
            a := algor2;
        if a = nil then continue;
        if _type.pkey_type = NID_dsaWithSHA1 then
        begin
            {
             * special case: RFC 2459 tells us to omit 'parameters' with
             * id-dsa-with-sha1
             }
            ASN1_TYPE_free(a.parameter);
            a.parameter := nil;
        end
        else
        if ((a.parameter = nil)  or
                   (a.parameter._type <> V_ASN1_NULL)) then
        begin
            ASN1_TYPE_free(a.parameter);
            a.parameter := ASN1_TYPE_new();
            if a.parameter = nil then
                goto _err;
            a.parameter._type := V_ASN1_NULL;
        end;
        ASN1_OBJECT_free(a.algorithm);
        a.algorithm := OBJ_nid2obj(_type.pkey_type);
        if a.algorithm = nil then begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_OBJECT_TYPE);
            goto _err;
        end;
        if a.algorithm.length = 0 then begin
            ERR_raise(ERR_LIB_ASN1,
                      ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
            goto _err;
        end;
    end;

    inl := i2d(data, nil);
    if inl <= 0 then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    inll := size_t(inl);
    buf_in := OPENSSL_malloc(inll);
    outl := EVP_PKEY_get_size(pkey);
    outll := outl ;
    buf_out := OPENSSL_malloc(outll);
    if (buf_in = nil)  or  (buf_out = nil) then begin
        outl := 0;
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    p := buf_in;
    i2d(data, @p);
    if (0>=EVP_SignInit_ex(ctx, _type, nil))  or
       (0>=EVP_SignUpdate(ctx, PByte(buf_in), inl))   or
       (0>=EVP_SignFinal(ctx, PByte(buf_out), Puint32(@outl), pkey))  then
    begin
        outl := 0;
        ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        goto _err;
    end;
    OPENSSL_free(signature.data);
    signature.data := buf_out;
    buf_out := nil;
    signature.length := outl;
    {
     * In the interests of compatibility, I'll make sure that the bit string
     * has a 'not-used bits' value of 0
     }
    signature.flags := signature.flags and  not (ASN1_STRING_FLAG_BITS_LEFT or $07);
    signature.flags  := signature.flags  or ASN1_STRING_FLAG_BITS_LEFT;
 _err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_clear_free(Pointer( buf_in), inll);
    OPENSSL_clear_free(Pointer( buf_out), outll);
    Result := outl;
end;

function ASN1_item_sign(const it : PASN1_ITEM; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING;const data : Pointer; pkey : PEVP_PKEY;const md : PEVP_MD):integer;
begin
    Exit(ASN1_item_sign_ex(it, algor1, algor2, signature, data, nil, pkey,
                             md, nil, nil));
end;


function ASN1_item_sign_ex(const it : PASN1_ITEM; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING;const data : Pointer; id : PASN1_OCTET_STRING; pkey : PEVP_PKEY;const md : PEVP_MD; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  rv : integer;
  ctx : PEVP_MD_CTX;
  label _err;
begin
    rv := 0;
    ctx := evp_md_ctx_new_ex(pkey, id, libctx, propq);
    if ctx = nil then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    { We can use the non _ex variant here since the pkey is already setup }
    if 0>=EVP_DigestSignInit(ctx, nil, md, nil, pkey ) then
        goto _err;
    rv := ASN1_item_sign_ctx(it, algor1, algor2, signature, data, ctx);
 _err:
    EVP_PKEY_CTX_free(EVP_MD_CTX_get_pkey_ctx(ctx));
    EVP_MD_CTX_free(ctx);
    Result := rv;
end;


function ASN1_item_sign_ctx(const it : PASN1_ITEM; algor1, algor2 : PX509_ALGOR; signature : PASN1_BIT_STRING;const data : Pointer; ctx : PEVP_MD_CTX):integer;
var
    md        : PEVP_MD;
    pkey      : PEVP_PKEY;
    buf_in, buf_out    : PByte;
    inl, outl, outll   : size_t;
    signid,
    paramtype,
    buf_len,
    rv,
    pkey_id   : integer;
    pctx      : PEVP_PKEY_CTX;
    params    : array[0..1] of TOSSL_PARAM;
    aid       : array[0..127] of Byte;
    aid_len   : size_t;
    pp        : PByte;
    label _err;
begin
    buf_in := nil; buf_out := nil;
    inl := 0; outl := 0; outll := 0;
    buf_len := 0;
    md := EVP_MD_CTX_get0_md(ctx);
    pkey := EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    if pkey = nil then begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_CONTEXT_NOT_INITIALISED);
        goto _err;
    end;
    if pkey.ameth = nil then begin
        pctx := EVP_MD_CTX_get_pkey_ctx(ctx);
        aid_len := 0;
        if (pctx = nil)
             or  (not EVP_PKEY_CTX_IS_SIGNATURE_OP(pctx )) then  begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_CONTEXT_NOT_INITIALISED);
            goto _err;
        end;
        params[0] := OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                                              @aid, sizeof(aid));
        params[1] := OSSL_PARAM_construct_end;
        if EVP_PKEY_CTX_get_params(pctx, @params) <= 0  then
            goto _err;
        aid_len := params[0].return_size;
        if aid_len = 0 then  begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
            goto _err;
        end;
        if algor1 <> nil then begin
           pp := @aid;
            if d2i_X509_ALGOR(@algor1, @pp, aid_len) = nil  then  begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
                goto _err;
            end;
        end;
        if algor2 <> nil then begin
             pp := @aid;
            if d2i_X509_ALGOR(@algor2, @pp, aid_len)= nil  then  begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
                goto _err;
            end;
        end;
        rv := 3;
    end
    else
    if Assigned(pkey.ameth.item_sign) then
    begin
        rv := pkey.ameth.item_sign(ctx, it, data, algor1, algor2, signature);
        if rv = 1 then outl := signature.length;
        {-
         * Return value meanings:
         * <=0: error.
         *   1: method does everything.
         *   2: carry on as normal.
         *   3: ASN1 method sets algorithm identifiers: just sign.
         }
        if rv <= 0 then ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        if rv <= 1 then goto _err;
    end
    else begin
        rv := 2;
    end;
    if rv = 2 then
    begin
        if md = nil then  begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_CONTEXT_NOT_INITIALISED);
            goto _err;
        end;
        pkey_id := {$IFNDEF OPENSSL_NO_SM2}
            get_result(EVP_PKEY_get_id(pkey) = NID_sm2 , NID_sm2 ,
{$ENDIF}
            pkey.ameth.pkey_id);
        if 0>=OBJ_find_sigid_by_algs(@signid, EVP_MD_nid(md) , pkey_id) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
            goto _err;
        end;
        paramtype := get_result(pkey.ameth.pkey_flags and ASN1_PKEY_SIGPARAM_NULL > 0,
            V_ASN1_NULL , V_ASN1_UNDEF);
        if (algor1 <> nil)
             and  (0>=X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, nil))  then
            goto _err;
        if (algor2 <> nil)
             and  (0>=X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, nil)) then
            goto _err;
    end;
    buf_len := ASN1_item_i2d(data, @buf_in, it);
    if buf_len <= 0 then begin
        outl := 0;
        ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
        goto _err;
    end;
    inl := buf_len;
    if 0>=EVP_DigestSign(ctx, nil, @outll, buf_in, inl) then
    begin
        outl := 0;
        ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        goto _err;
    end;
    outl := outll;
    buf_out := OPENSSL_malloc(outll);
    if (buf_in = nil)  or  (buf_out = nil) then begin
        outl := 0;
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    if 0>=EVP_DigestSign(ctx, buf_out, @outl, buf_in, inl ) then begin
        outl := 0;
        ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
        goto _err;
    end;
    OPENSSL_free(signature.data);
    signature.data := buf_out;
    buf_out := nil;
    signature.length := outl;
    {
     * In the interests of compatibility, I'll make sure that the bit string
     * has a 'not-used bits' value of 0
     }
    signature.flags := signature.flags and not (ASN1_STRING_FLAG_BITS_LEFT or $07);
    signature.flags  := signature.flags  or ASN1_STRING_FLAG_BITS_LEFT;
 _err:
    OPENSSL_clear_free(Pointer( buf_in), inl);
    OPENSSL_clear_free(Pointer( buf_out), outll);
    Result := outl;
end;


end.
