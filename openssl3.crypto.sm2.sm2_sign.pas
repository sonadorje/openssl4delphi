unit openssl3.crypto.sm2.sm2_sign;

interface
uses OpenSSL.Api;

function ossl_sm2_internal_sign(const dgst : PByte; dgstlen : integer; sig : PByte; siglen : Puint32; eckey : PEC_KEY):integer;
function sm2_sig_gen(const key : PEC_KEY; e : PBIGNUM):PECDSA_SIG;
function ossl_sm2_compute_z_digest(&out : PByte;const digest : PEVP_MD; id : PByte; id_len : size_t; key : PEC_KEY):integer;
function sm2_sig_verify(const key : PEC_KEY; sig : PECDSA_SIG; e : PBIGNUM):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_ctx,
      openssl3.crypto.ec.ec_key, openssl3.crypto.bn.bn_rand,
      openssl3.crypto.bn.bn_add, openssl3.crypto.ec.ec_lib,
      openssl3.crypto.ec.ec_asn1,
      openssl3.crypto.evp.digest, openssl3.crypto.bn.bn_mod,
      openssl3.crypto.mem;


function sm2_sig_verify(const key : PEC_KEY; sig : PECDSA_SIG; e : PBIGNUM):integer;
var
  ret : integer;
  group : PEC_GROUP;
  order : PBIGNUM;
  ctx : PBN_CTX;
  pt : PEC_POINT;
  t, x1, r, s : PBIGNUM;
  libctx : POSSL_LIB_CTX;
  label _done;
begin
    ret := 0;
    group := EC_KEY_get0_group(key);
    order := EC_GROUP_get0_order(group);
    ctx := nil;
    pt := nil;
    t := nil;
    x1 := nil;
    r := nil;
    s := nil;
    libctx := ossl_ec_key_get_libctx(key);
    ctx := BN_CTX_new_ex(libctx);
    pt := EC_POINT_new(group);
    if (ctx = nil)  or  (pt = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    BN_CTX_start(ctx);
    t := BN_CTX_get(ctx);
    x1 := BN_CTX_get(ctx);
    if x1 = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    {
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: verify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA  or  M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
     }
    ECDSA_SIG_get0(sig, @r, @s);
    if (BN_cmp(r, BN_value_one) < 0)
             or  (BN_cmp(s, BN_value_one()) < 0)
             or  (BN_cmp(order, r) <= 0)
             or  (BN_cmp(order, s) <= 0)  then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_BAD_SIGNATURE);
        goto _done ;
    end;
    if 0>= BN_mod_add(t, r, s, order, ctx)  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto _done ;
    end;
    if BN_is_zero(t)  then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_BAD_SIGNATURE);
        goto _done ;
    end;
    if (0>= EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key) , t, ctx))
       or  (0>= EC_POINT_get_affine_coordinates(group, pt, x1, nil, ctx))  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto _done ;
    end;
    if 0>= BN_mod_add(t, e, x1, order, ctx) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto _done ;
    end;
    if BN_cmp(r, t ) = 0 then
        ret := 1;
 _done:
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    Result := ret;
end;




function ossl_sm2_compute_z_digest(&out : PByte;const digest : PEVP_MD; id : PByte; id_len : size_t; key : PEC_KEY):integer;
var
  rc : integer;

  group : PEC_GROUP;

  ctx : PBN_CTX;

  hash : PEVP_MD_CTX;

  p, a, b, xG, yG, xA, yA : PBIGNUM;

  p_bytes : integer;

  buf : PByte;

  entl : uint16;

  e_byte : byte;
  label _done;
begin
    rc := 0;
    group := EC_KEY_get0_group(key);
    ctx := nil;
    hash := nil;
    p := nil;
    a := nil;
    b := nil;
    xG := nil;
    yG := nil;
    xA := nil;
    yA := nil;
    p_bytes := 0;
     buf := nil;
    entl := 0;
    e_byte := 0;
    hash := EVP_MD_CTX_new();
    ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
    if (hash = nil)  or  (ctx = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    p := BN_CTX_get(ctx);
    a := BN_CTX_get(ctx);
    b := BN_CTX_get(ctx);
    xG := BN_CTX_get(ctx);
    yG := BN_CTX_get(ctx);
    xA := BN_CTX_get(ctx);
    yA := BN_CTX_get(ctx);
    if yA = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    if 0>= EVP_DigestInit(hash, digest)  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    { Z = h(ENTL  or  ID  or  a  or  b  or  xG  or  yG  or  xA  or  yA) }
    if id_len >= (UINT16_MAX div 8)  then
    begin
        { too large }
        ERR_raise(ERR_LIB_SM2, SM2_R_ID_TOO_LARGE);
        goto _done ;
    end;
    entl := uint16(8 * id_len);
    e_byte := entl  shr  8;
    if 0>= EVP_DigestUpdate(hash, @e_byte, 1) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    e_byte := entl and $FF;
    if 0>= EVP_DigestUpdate(hash, @e_byte, 1) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    if (id_len > 0)  and  (0>= EVP_DigestUpdate(hash, id, id_len) )then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    if 0>= EC_GROUP_get_curve(group, p, a, b, ctx) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto _done ;
    end;
    p_bytes := BN_num_bytes(p);
    buf := OPENSSL_zalloc(p_bytes);
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    if (BN_bn2binpad(a, buf, p_bytes) < 0)
             or  (0>= EVP_DigestUpdate(hash, buf, p_bytes))
             or  (BN_bn2binpad(b, buf, p_bytes) < 0)
             or  (0>= EVP_DigestUpdate(hash, buf, p_bytes))
             or  (0>= EC_POINT_get_affine_coordinates(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx))
             or  (BN_bn2binpad(xG, buf, p_bytes) < 0)
             or  (0>= EVP_DigestUpdate(hash, buf, p_bytes))
             or  (BN_bn2binpad(yG, buf, p_bytes) < 0)
             or  (0>= EVP_DigestUpdate(hash, buf, p_bytes))
             or  (0>= EC_POINT_get_affine_coordinates(group,
                                                EC_KEY_get0_public_key(key),
                                                xA, yA, ctx))
             or  (BN_bn2binpad(xA, buf, p_bytes) < 0)
             or  (0>= EVP_DigestUpdate(hash, buf, p_bytes))
             or  (BN_bn2binpad(yA, buf, p_bytes) < 0)
             or  (0>= EVP_DigestUpdate(hash, buf, p_bytes))
             or  (0>= EVP_DigestFinal(hash, &out, nil))  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    rc := 1;
 _done:
    OPENSSL_free(Pointer(buf));
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    Result := rc;
end;




function sm2_sig_gen(const key : PEC_KEY; e : PBIGNUM):PECDSA_SIG;
var
  dA : PBIGNUM;

  group : PEC_GROUP;

  order : PBIGNUM;

  sig : PECDSA_SIG;

  kG : PEC_POINT;

  ctx : PBN_CTX;

  k, rk, r, s, x1, tmp : PBIGNUM;

  libctx : POSSL_LIB_CTX;
  label _done;
begin
     dA := EC_KEY_get0_private_key(key);
     group := EC_KEY_get0_group(key);
     order := EC_GROUP_get0_order(group);
    sig := nil;
    kG := nil;
    ctx := nil;
    k := nil;
    rk := nil;
    r := nil;
    s := nil;
    x1 := nil;
    tmp := nil;
    libctx := ossl_ec_key_get_libctx(key);
    kG := EC_POINT_new(group);
    ctx := BN_CTX_new_ex(libctx);
    if (kG = nil)  or  (ctx = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    BN_CTX_start(ctx);
    k := BN_CTX_get(ctx);
    rk := BN_CTX_get(ctx);
    x1 := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    {
     * These values are returned and so should not be allocated out of the
     * context
     }
    r := BN_new();
    s := BN_new();
    if (r = nil)  or  (s = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    {
     * A4: Compute (x1,y1)=[k]G, and convert the type of data x1 to be integer
     *     as specified in clause 4.2.8 of GM/T 0003.1-2012;
     * A7: Convert the type of data (r,s) to be bit strings according to the details
     *     in clause 4.2.2 of GM/T 0003.1-2012. Then the signature of message M is (r,s).
     }
    while true do
    begin
        if 0>= BN_priv_rand_range_ex(k, order, 0, ctx)  then
        begin
            ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
            goto _done ;
        end;
        if (0>= EC_POINT_mul(group, kG, k, nil, nil, ctx ))  or
           (0>= EC_POINT_get_affine_coordinates(group, kG, x1, nil, ctx))
                 or  (0>= BN_mod_add(r, e, x1, order, ctx)) then
        begin
            ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
            goto _done ;
        end;
        { try again if r = 0 or r+k = n }
        if BN_is_zero(r)  then
            continue;
        if 0>= BN_add(rk, r, k) then
        begin
            ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
            goto _done ;
        end;
        if BN_cmp(rk, order) = 0  then
            continue;
        if (0>= BN_add(s, dA, BN_value_one))
                 or  (0>= ossl_ec_group_do_inverse_ord(group, s, s, ctx) )
                 or  (0>= BN_mod_mul(tmp, dA, r, order, ctx))
                 or  (0>= BN_sub(tmp, k, tmp))
                 or  (0>= BN_mod_mul(s, s, tmp, order, ctx))  then
        begin
            ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
            goto _done ;
        end;
        { try again if s = 0 }
        if BN_is_zero(s)  then
            continue;
        sig := ECDSA_SIG_new();
        if sig = nil then
        begin
            ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
            goto _done ;
        end;
         { takes ownership of r and s }
        ECDSA_SIG_set0(sig, r, s);
        break;
    end;
 _done:
    if sig = nil then
    begin
        BN_free(r);
        BN_free(s);
    end;
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    Result := sig;
end;

function ossl_sm2_internal_sign(const dgst : PByte; dgstlen : integer; sig : PByte; siglen : Puint32; eckey : PEC_KEY):integer;
var
  e : PBIGNUM;

  s : PECDSA_SIG;

  sigleni, ret : integer;
  label _done;
begin
    e := nil;
    s := nil;
    ret := -1;
    e := BN_bin2bn(dgst, dgstlen, nil);
    if e = nil then
    begin
       ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
       goto _done ;
    end;
    s := sm2_sig_gen(eckey, e);
    if s = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    sigleni := i2d_ECDSA_SIG(s, @sig);
    if sigleni < 0 then
    begin
       ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
       goto _done ;
    end;
    siglen^ := (Uint32 (sigleni));
    ret := 1;
 _done:
    ECDSA_SIG_free(s);
    BN_free(e);
    Result := ret;
end;


end.
