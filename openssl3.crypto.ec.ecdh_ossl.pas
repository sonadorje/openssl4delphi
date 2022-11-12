unit openssl3.crypto.ec.ecdh_ossl;

interface
uses OpenSSL.Api;

 function ossl_ecdh_simple_compute_key(pout : PPByte; poutlen : Psize_t;const pub_key : PEC_POINT;const ecdh : PEC_KEY):integer;
 function ossl_ecdh_compute_key(psec : PPByte; pseclen : Psize_t;const pub_key : PEC_POINT;const ecdh : PEC_KEY):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_mul,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.mem,
     openssl3.crypto.ec.ec_asn1;






function ossl_ecdh_compute_key(psec : PPByte; pseclen : Psize_t;const pub_key : PEC_POINT;const ecdh : PEC_KEY):integer;
begin
    if not Assigned(ecdh.group.meth.ecdh_compute_key) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_ECDH);
        Exit(0);
    end;
    Result := ecdh.group.meth.ecdh_compute_key(psec, pseclen, pub_key, ecdh);
end;


function ossl_ecdh_simple_compute_key(pout : PPByte; poutlen : Psize_t;const pub_key : PEC_POINT;const ecdh : PEC_KEY):integer;
var
    ctx      : PBN_CTX;
    tmp      : PEC_POINT;
    x,
    priv_key : PBIGNUM;
    group    : PEC_GROUP;
    ret      : integer;
    buflen,
    len      : size_t;
    buf      : PByte;
    label _err;
begin
    tmp := nil;
    x := nil;
    ret := 0;
    buf := nil;
    ctx := BN_CTX_new_ex(ecdh.libctx);
    if ctx = nil then
        goto _err ;
    BN_CTX_start(ctx);
    x := BN_CTX_get(ctx);
    if x = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    priv_key := EC_KEY_get0_private_key(ecdh);
    if priv_key = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY);
        goto _err ;
    end;
    group := EC_KEY_get0_group(ecdh);
    {
     * Step(1) - Compute the point tmp = cofactor * owners_private_key
     *                                   * peer_public_key.
     }
    if (EC_KEY_get_flags(ecdh) and EC_FLAG_COFACTOR_ECDH)>0  then
    begin
        if (0>= EC_GROUP_get_cofactor(group, x, nil))   or
           (0>= BN_mul(x, x, priv_key, ctx)) then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        priv_key := x;
    end;
    tmp := EC_POINT_new(group);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if 0>= EC_POINT_mul(group, tmp, nil, pub_key, priv_key, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_ARITHMETIC_FAILURE);
        goto _err ;
    end;
    {
     * Step(2) : If point tmp is at infinity then clear intermediate values and
     * exit. Note: getting affine coordinates returns 0 if point is at infinity.
     * Step(3a) : Get x-coordinate of point x = tmp.x
     }
    if 0>= EC_POINT_get_affine_coordinates(group, tmp, x, nil, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_ARITHMETIC_FAILURE);
        goto _err ;
    end;
    {
     * Step(3b) : convert x to a byte string, using the field-element-to-byte
     * string conversion routine defined in Appendix C.2
     }
    buflen := (EC_GROUP_get_degree(group) + 7) div 8;
    len := BN_num_bytes(x);
    if len > buflen then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    buf := OPENSSL_malloc(buflen);
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    memset(buf, 0, buflen - len);
    if len <> size_t( BN_bn2bin(x, buf + buflen - len )) then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto _err ;
    end;
    pout^ := buf;
    poutlen^ := buflen;
    buf := nil;
    ret := 1;
 _err:
    { Step(4) : Destroy all intermediate calculations }
    BN_clear(x);
    EC_POINT_clear_free(tmp);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_free(Pointer(buf));
    Result := ret;
end;


end.
