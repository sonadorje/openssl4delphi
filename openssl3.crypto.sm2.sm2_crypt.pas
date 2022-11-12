unit openssl3.crypto.sm2.sm2_crypt;

interface
uses OpenSSL.Api;

function ossl_sm2_ciphertext_size(const key : PEC_KEY; digest : PEVP_MD; msg_len : size_t; ct_size : Psize_t):integer;

function ec_field_size(const group : PEC_GROUP):size_t;
function ossl_sm2_encrypt(const key : PEC_KEY; digest : PEVP_MD; msg : PByte; msg_len : size_t; ciphertext_buf : PByte; ciphertext_len : Psize_t):integer;
 function ossl_sm2_decrypt(const key : PEC_KEY; digest : PEVP_MD; ciphertext : PByte; ciphertext_len : size_t; ptext_buf : PByte; ptext_len : Psize_t):integer;
  function d2i_SM2_Ciphertext(a : PPSM2_Ciphertext;const &in : PPByte; len : long):PSM2_Ciphertext;
  function i2d_SM2_Ciphertext( a : PSM2_Ciphertext; _out : PPByte):integer;
  function SM2_Ciphertext_new:PSM2_Ciphertext;
  procedure SM2_Ciphertext_free( a : PSM2_Ciphertext);
  function SM2_Ciphertext_it:PASN1_ITEM;
  function ossl_sm2_plaintext_size(const ct : PByte; ct_size : size_t; pt_size : Psize_t):integer;

 var
   SM2_Ciphertext_seq_tt: array[0..3] of TASN1_TEMPLATE ;

implementation
uses openssl3.crypto.bn.bn_lib, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_rand, OpenSSL3.Err,
     openssl3.crypto.ec.ec_key, openssl3.crypto.ec.ecdh_kdf,
     openssl3.crypto.ec.ec_lib,  openssl3.crypto.evp.digest,
     openssl3.crypto.cpuid, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.a_octet,
     openssl3.crypto.asn1.tasn_enc,  openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.mem, OpenSSL3.openssl.asn1t;






function ossl_sm2_plaintext_size(const ct : PByte; ct_size : size_t; pt_size : Psize_t):integer;
var
  sm2_ctext : PSM2_Ciphertext;
begin
    sm2_ctext := nil;
    sm2_ctext := d2i_SM2_Ciphertext(nil, @ct, ct_size);
    if sm2_ctext = nil then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        Exit(0);
    end;
    pt_size^ := sm2_ctext.C2.length;
    SM2_Ciphertext_free(sm2_ctext);
    Result := 1;
end;


function SM2_Ciphertext_it:PASN1_ITEM;
const
   local_it: TASN1_ITEM = (
       itype:         ASN1_ITYPE_SEQUENCE;
       utype:         V_ASN1_SEQUENCE;
       templates:@SM2_Ciphertext_seq_tt;
       tcount:         sizeof(SM2_Ciphertext_seq_tt) div sizeof(TASN1_TEMPLATE);
       funcs:         nil;
       size:         sizeof(TSM2_Ciphertext);
       sname:        'SM2_Ciphertext'
               );
begin
    Result := @local_it;
end;

function d2i_SM2_Ciphertext(a : PPSM2_Ciphertext;const &in : PPByte; len : long):PSM2_Ciphertext;
begin
   Exit(PSM2_Ciphertext ( ASN1_item_d2i(PPASN1_VALUE ( a), &in, len, SM2_Ciphertext_it)));
end;


function i2d_SM2_Ciphertext( a : PSM2_Ciphertext; _out : PPByte):integer;
begin
    Exit(ASN1_item_i2d(PASN1_VALUE( a), _out, SM2_Ciphertext_it));
end;


function SM2_Ciphertext_new:PSM2_Ciphertext;
begin
   Result := PSM2_Ciphertext ( ASN1_item_new(SM2_Ciphertext_it));
end;


procedure SM2_Ciphertext_free( a : PSM2_Ciphertext);
begin
   ASN1_item_free(PASN1_VALUE(a), SM2_Ciphertext_it);
end;

function ossl_sm2_encrypt(const key : PEC_KEY; digest : PEVP_MD; msg : PByte; msg_len : size_t; ciphertext_buf : PByte; ciphertext_len : Psize_t):integer;
var
    rc,ciphertext_leni             : integer;
    i              : size_t;
    ctx            : PBN_CTX;

  k,
  x1,
  y1,
  x2,
  y2             : PBIGNUM;
  hash           : PEVP_MD_CTX;
  ctext_struct   : PSM2_Ciphertext;
  group          : PEC_GROUP;
  order          : PBIGNUM;
  P,
  kG,
  kP             : PEC_POINT;
  msg_mask,
  x2y2,
  C3             : PByte;
  field_size     : size_t;

  C3_size        : integer;
  fetched_digest : PEVP_MD;
  libctx         : POSSL_LIB_CTX;
  propq          : PUTF8Char;
  label _done;
begin
    rc := 0;
    ctx := nil;
    k := nil;
    x1 := nil;
    y1 := nil;
    x2 := nil;
    y2 := nil;
    hash := EVP_MD_CTX_new();
    group := EC_KEY_get0_group(key);
    order := EC_GROUP_get0_order(group);
    P := EC_KEY_get0_public_key(key);
    kG := nil;
    kP := nil;
     msg_mask := nil;
     x2y2 := nil;
     C3 := nil;
     C3_size := EVP_MD_get_size(digest);
    fetched_digest := nil;
    libctx := ossl_ec_key_get_libctx(key);
     propq := ossl_ec_key_get0_propq(key);
    { nil these before any 'goto_done ' }
    ctext_struct.C2 := nil;
    ctext_struct.C3 := nil;
    if (hash = nil)  or  (C3_size <= 0) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    field_size := ec_field_size(group);
    if field_size = 0 then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    kG := EC_POINT_new(group);
    kP := EC_POINT_new(group);
    ctx := BN_CTX_new_ex(libctx);
    if (kG = nil)  or  (kP = nil)  or  (ctx = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    BN_CTX_start(ctx);
    k := BN_CTX_get(ctx);
    x1 := BN_CTX_get(ctx);
    x2 := BN_CTX_get(ctx);
    y1 := BN_CTX_get(ctx);
    y2 := BN_CTX_get(ctx);
    if y2 = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto _done ;
    end;
    x2y2 := OPENSSL_zalloc(2 * field_size);
    C3 := OPENSSL_zalloc(C3_size);
    if (x2y2 = nil)  or  (C3 = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    memset(ciphertext_buf, 0, ciphertext_len^);
    if 0>= BN_priv_rand_range_ex(k, order, 0, ctx)  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    if (0>= EC_POINT_mul(group, kG, k, nil, nil, ctx))
             or  (0>= EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx))
             or  (0>= EC_POINT_mul(group, kP, nil, P, k, ctx))
             or  (0>= EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto _done ;
    end;
    if (BN_bn2binpad(x2, x2y2, field_size) < 0)
             or  (BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0)  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    msg_mask := OPENSSL_zalloc(msg_len);
    if msg_mask = nil then
    begin
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto _done ;
   end;
    { X9.63 with no salt happens to match the KDF used in SM2 }
    if 0>= ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, nil, 0,
                             digest, libctx, propq )then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    i := 0;
    while i <> msg_len do
    begin
        msg_mask[i] := msg_mask[i] xor (msg[i]);
        Inc(i);
    end;
    fetched_digest := EVP_MD_fetch(libctx, EVP_MD_get0_name(digest), propq);
    if fetched_digest = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    if (EVP_DigestInit(hash, fetched_digest) = 0)
             or  (EVP_DigestUpdate(hash, x2y2, field_size) = 0 )
             or  (EVP_DigestUpdate(hash, msg, msg_len) = 0)
             or  (EVP_DigestUpdate(hash, x2y2 + field_size, field_size) = 0)
             or  (EVP_DigestFinal(hash, C3, nil) = 0)  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    ctext_struct.C1x := x1;
    ctext_struct.C1y := y1;
    ctext_struct.C3 := ASN1_OCTET_STRING_new();
    ctext_struct.C2 := ASN1_OCTET_STRING_new();
    if (ctext_struct.C3 = nil)  or  (ctext_struct.C2 = nil) then
    begin
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto _done ;
    end;
    if (0>= ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size))  or
       (0>= ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len))  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    ciphertext_leni := i2d_SM2_Ciphertext(&ctext_struct, @ciphertext_buf);
    { Ensure cast to size_t is safe }
    if ciphertext_leni < 0 then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    ciphertext_len^ := size_t( ciphertext_leni);
    rc := 1;
 _done:
    EVP_MD_free(fetched_digest);
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(Pointer(msg_mask));
    OPENSSL_free(Pointer(x2y2));
    OPENSSL_free(Pointer(C3));
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    Result := rc;
end;


function ossl_sm2_decrypt(const key : PEC_KEY; digest : PEVP_MD; ciphertext : PByte; ciphertext_len : size_t; ptext_buf : PByte; ptext_len : Psize_t):integer;
var
  rc, i       : integer;
  ctx         : PBN_CTX;
  group       : PEC_GROUP;
  C1          : PEC_POINT;
  sm2_ctext   : PSM2_Ciphertext;
  x2,
  y2          : PBIGNUM;
  x2y2,
  computed_C3 : PByte;
  field_size  : size_t;
  hash_size   : integer;
  msg_mask,
  C2, C3          : PByte;

  msg_len     : integer;
  hash        : PEVP_MD_CTX;
  libctx      : POSSL_LIB_CTX;
  propq       : PUTF8Char;
  label _done;
begin
    rc := 0;
    ctx := nil;
     group := EC_KEY_get0_group(key);
    C1 := nil;
    sm2_ctext := nil;
    x2 := nil;
    y2 := nil;
     x2y2 := nil;
     computed_C3 := nil;
    field_size := ec_field_size(group);
     hash_size := EVP_MD_get_size(digest);
     msg_mask := nil;
      C2 := nil;
      C3 := nil;
    msg_len := 0;
    hash := nil;
    libctx := ossl_ec_key_get_libctx(key);
     propq := ossl_ec_key_get0_propq(key);
    if (field_size = 0)  or  (hash_size <= 0) then
      goto _done ;
    memset(ptext_buf, $FF, ptext_len^);
    sm2_ctext := d2i_SM2_Ciphertext(nil, @ciphertext, ciphertext_len);
    if sm2_ctext = nil then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_ASN1_ERROR);
        goto _done ;
    end;
    if sm2_ctext.C3.length <> hash_size then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto _done ;
    end;
    C2 := sm2_ctext.C2.data;
    C3 := sm2_ctext.C3.data;
    msg_len := sm2_ctext.C2.length;
    if ptext_len^ < size_t( msg_len) then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_BUFFER_TOO_SMALL);
        goto _done ;
    end;
    ctx := BN_CTX_new_ex(libctx);
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    BN_CTX_start(ctx);
    x2 := BN_CTX_get(ctx);
    y2 := BN_CTX_get(ctx);
    if y2 = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto _done ;
    end;
    msg_mask := OPENSSL_zalloc(msg_len);
    x2y2 := OPENSSL_zalloc(2 * field_size);
    computed_C3 := OPENSSL_zalloc(hash_size);
    if (msg_mask = nil)  or  (x2y2 = nil)  or  (computed_C3 = nil) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    C1 := EC_POINT_new(group);
    if C1 = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    if (0>= EC_POINT_set_affine_coordinates(group, C1, sm2_ctext.C1x,
                                         sm2_ctext.C1y, ctx))  or
       (0>= EC_POINT_mul(group, C1, nil, C1, EC_KEY_get0_private_key(key), ctx))
             or  (0>= EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto _done ;
    end;
    if (BN_bn2binpad(x2, x2y2, field_size)  < 0)
             or  (BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0 )
             or  (0>= ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size,
                                    nil, 0, digest, libctx, propq)) then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto _done ;
    end;
    i := 0;
    while i <> msg_len do
    begin
        ptext_buf[i] := C2[i]  xor  msg_mask[i];
        Inc(i);
    end;
    hash := EVP_MD_CTX_new();
    if hash = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    if (0>= EVP_DigestInit(hash, digest)) or
       (0>= EVP_DigestUpdate(hash, x2y2, field_size))
             or  (0>= EVP_DigestUpdate(hash, ptext_buf, msg_len))
             or  (0>= EVP_DigestUpdate(hash, x2y2 + field_size, field_size))
             or  (0>= EVP_DigestFinal(hash, computed_C3, nil))  then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto _done ;
    end;
    if CRYPTO_memcmp(computed_C3, C3, hash_size) <> 0  then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_DIGEST);
        goto _done ;
    end;
    rc := 1;
    ptext_len^ := msg_len;
 _done:
    if rc = 0 then
       memset(ptext_buf, 0, ptext_len^);
    OPENSSL_free(Pointer(msg_mask));
    OPENSSL_free(Pointer(x2y2));
    OPENSSL_free(Pointer(computed_C3));
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    EVP_MD_CTX_free(hash);
    Result := rc;
end;

function ec_field_size(const group : PEC_GROUP):size_t;
var
  p,
  a,
  b          : PBIGNUM;

    field_size : size_t;
    label _done;
begin
    { Is there some simpler way to do this? }
    p := BN_new();
    a := BN_new();
    b := BN_new();
    field_size := 0;
    if (p = nil)  or  (a = nil)  or  (b = nil) then
       goto _done ;
    if 0>= EC_GROUP_get_curve(group, p, a, b, nil) then
        goto _done ;
    field_size := (BN_num_bits(p) + 7) div 8;
 _done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    Result := field_size;
end;



function ossl_sm2_ciphertext_size(const key : PEC_KEY; digest : PEVP_MD; msg_len : size_t; ct_size : Psize_t):integer;
var
    field_size : size_t;

    md_size    : integer;

    sz         : size_t;
begin
    field_size := ec_field_size(EC_KEY_get0_group(key));
     md_size := EVP_MD_get_size(digest);
    if (field_size = 0)  or  (md_size < 0) then Exit(0);

    sz := 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
         + ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);

    ct_size^ := ASN1_object_size(1, sz, V_ASN1_SEQUENCE);
    Result := 1;
end;

initialization

  SM2_Ciphertext_seq_tt[0] :=ASN1_SIMPLE(TypeInfo(TSM2_Ciphertext), 'C1x', TypeInfo(TBIGNUM));
  SM2_Ciphertext_seq_tt[1] :=ASN1_SIMPLE(TypeInfo(TSM2_Ciphertext), 'C1y', TypeInfo(TBIGNUM));
  SM2_Ciphertext_seq_tt[2] :=ASN1_SIMPLE(TypeInfo(TSM2_Ciphertext), 'C3', TypeInfo(TASN1_OCTET_STRING));
  SM2_Ciphertext_seq_tt[3] :=ASN1_SIMPLE(TypeInfo(TSM2_Ciphertext), 'C2', TypeInfo(TASN1_OCTET_STRING));
end.
