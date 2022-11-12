unit openssl3.crypto.rsa.rsa_ossl;

interface
uses OpenSSL.Api;

procedure RSA_set_default_method(const meth : PRSA_METHOD);
function RSA_get_default_method:PRSA_METHOD;
function RSA_PKCS1_OpenSSL:PRSA_METHOD;
function RSA_null_method:PRSA_METHOD;
function rsa_ossl_public_encrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
function rsa_get_blinding( rsa : PRSA; local : PInteger; ctx : PBN_CTX):PBN_BLINDING;
function rsa_blinding_convert( b : PBN_BLINDING; f, unblind : PBIGNUM; ctx : PBN_CTX):integer;
function rsa_blinding_invert( b : PBN_BLINDING; f, unblind : PBIGNUM; ctx : PBN_CTX):integer;
function rsa_ossl_private_encrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
function rsa_ossl_private_decrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
function rsa_ossl_public_decrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
function rsa_ossl_mod_exp(r0 : PBIGNUM;const _I : PBIGNUM; rsa : PRSA; ctx : PBN_CTX):integer;
function rsa_ossl_init( rsa : PRSA):integer;
function rsa_ossl_finish( rsa : PRSA):integer;
function sk_RSA_PRIME_INFO_num(const sk: Pstack_st_RSA_PRIME_INFO):integer;
function sk_RSA_PRIME_INFO_value(const sk : Pstack_st_RSA_PRIME_INFO; idx : integer):PRSA_PRIME_INFO;


implementation
uses openssl3.crypto.bn.bn_exp,     openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_ctx,     OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.rsa.rsa_none,  openssl3.crypto.bn.bn_mont,
     OpenSSL3.threads_none,         OpenSSL3.crypto.rsa.rsa_crpt,
     openssl3.crypto.bn.bn_intern,  openssl3.crypto.stack,
     openssl3.crypto.bn.bn_add,     openssl3.internal.constant_time,
     openssl3.crypto.bn.bn_blind,   OpenSSL3.crypto.rsa.rsa_x931,
     openssl3.crypto.bn.bn_mod,     openssl3.crypto.bn.bn_mul,
     openssl3.crypto.rsa.rsa_pk1,   openssl3.crypto.rsa.rsa_oaep;

const
   rsa_pkcs1_ossl_meth: TRSA_METHOD = (
    name: 'OpenSSL PKCS#1 RSA';
    rsa_pub_enc: rsa_ossl_public_encrypt;
    rsa_pub_dec: rsa_ossl_public_decrypt;     (* signature verification *)
    rsa_priv_enc: rsa_ossl_private_encrypt;    (* signing *)
    rsa_priv_dec: rsa_ossl_private_decrypt;
    rsa_mod_exp: rsa_ossl_mod_exp;
    bn_mod_exp: BN_mod_exp_mont;            (* XXX probably we should not use Montgomery
                                 * if e == 3 *)
    init: rsa_ossl_init;
    finish: rsa_ossl_finish;
    flags: RSA_FLAG_FIPS_METHOD;       (* flags *)
    app_data: nil;
    rsa_sign: nil;                          (* rsa_sign *)
    rsa_verify: nil;                          (* rsa_verify *)
    rsa_keygen: nil;                       (* rsa_keygen *)
    rsa_multi_prime_keygen: nil                        (* rsa_multi_prime_keygen *)
);

var
    default_RSA_meth: PRSA_METHOD = @rsa_pkcs1_ossl_meth;

function sk_RSA_PRIME_INFO_value(const sk : Pstack_st_RSA_PRIME_INFO; idx : integer):PRSA_PRIME_INFO;
begin
   result := PRSA_PRIME_INFO(OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;

function sk_RSA_PRIME_INFO_num(const sk: Pstack_st_RSA_PRIME_INFO):integer;
begin
   result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;

procedure RSA_set_default_method(const meth : PRSA_METHOD);
begin
    default_RSA_meth := meth;
end;


function RSA_get_default_method:PRSA_METHOD;
begin
    Result := default_RSA_meth;
end;


function RSA_PKCS1_OpenSSL:PRSA_METHOD;
begin
    Result := @rsa_pkcs1_ossl_meth;
end;


function RSA_null_method:PRSA_METHOD;
begin
    Result := nil;
end;


function rsa_ossl_public_encrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
var
  f, ret : PBIGNUM;
  i, num, r : integer;
  buf : PByte;
  ctx : PBN_CTX;
  label _err;
begin
    num := 0; r := -1;
    buf := nil;
    ctx := nil;
    if BN_num_bits(rsa.n) > OPENSSL_RSA_MAX_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_MODULUS_TOO_LARGE);
        Exit(-1);
    end;
    if BN_ucmp(rsa.n, rsa.e) <= 0  then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
        Exit(-1);
    end;
    { for large moduli, enforce exponent limit }
    if BN_num_bits(rsa.n) > OPENSSL_RSA_SMALL_MODULUS_BITS  then
    begin
        if BN_num_bits(rsa.e) > OPENSSL_RSA_MAX_PUBEXP_BITS then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
            Exit(-1);
        end;
    end;
    ctx := BN_CTX_new_ex(rsa.libctx);
    if ctx =  nil then
        goto _err ;
    BN_CTX_start(ctx);
    f := BN_CTX_get(ctx);
    ret := BN_CTX_get(ctx);
    num := BN_num_bytes(rsa.n);
    buf := OPENSSL_malloc(num);
    if (ret = nil)  or  (buf = nil) then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    case padding of
        RSA_PKCS1_PADDING:
            i := ossl_rsa_padding_add_PKCS1_type_2_ex(rsa.libctx, buf, num, from, flen);
            //break;
        RSA_PKCS1_OAEP_PADDING:
            i := ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(rsa.libctx, buf, num,
                                                        from, flen, nil, 0,
                                                        nil, nil);
            //break;
        RSA_NO_PADDING:
            i := RSA_padding_add_none(buf, num, from, flen);
            //break;
        else
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            goto _err ;
        end;
    end;
    if i <= 0 then goto _err ;
    if BN_bin2bn(buf, num, f)= nil  then
        goto _err ;
    if BN_ucmp(f, rsa.n ) >= 0 then
    begin
        { usually the padding functions would catch this }
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto _err ;
    end;
    if (rsa.flags and RSA_FLAG_CACHE_PUBLIC) > 0 then
       if (nil = BN_MONT_CTX_set_locked(@rsa._method_mod_n, rsa.lock, rsa.n, ctx)) then
          goto _err ;
    if 0>= rsa.meth.bn_mod_exp(ret, f, rsa.e, rsa.n, ctx, rsa._method_mod_n) then
       goto _err ;
    {
     * BN_bn2binpad puts in leading 0 bytes if the number is less than
     * the length of the modulus.
     }
    r := BN_bn2binpad(ret, _to, num);

 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_clear_free(buf, num);
    Result := r;
end;


function rsa_get_blinding( rsa : PRSA; local : PInteger; ctx : PBN_CTX):PBN_BLINDING;
  label _err;
begin
    if 0>= CRYPTO_THREAD_write_lock(rsa.lock) then
        Exit(nil);
    if rsa.blinding = nil then
    begin
        rsa.blinding := RSA_setup_blinding(rsa, ctx);
    end;
    result := rsa.blinding;
    if result = nil then
       goto _err ;
    if BN_BLINDING_is_current_thread(result) >0 then
    begin
        { rsa.blinding is ours! }
        local^ := 1;
    end
    else
    begin
        { resort to rsa.mt_blinding instead }
        {
         * instructs rsa_blinding_convert(), rsa_blinding_invert() that the
         * BN_BLINDING is shared, meaning that accesses require locks, and
         * that the blinding factor must be stored outside the BN_BLINDING
         }
        local^ := 0;
        if rsa.mt_blinding = nil then
        begin
            rsa.mt_blinding := RSA_setup_blinding(rsa, ctx);
        end;
        result := rsa.mt_blinding;
    end;

 _err:
    CRYPTO_THREAD_unlock(rsa.lock);

end;


function rsa_blinding_convert( b : PBN_BLINDING; f, unblind : PBIGNUM; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
    if unblind = nil then
    begin
        {
         * Local blinding: store the unblinding factor in BN_BLINDING.
         }
        Exit(BN_BLINDING_convert_ex(f, nil, b, ctx));
    end
    else
    begin
        {
         * Shared blinding: store the unblinding factor outside BN_BLINDING.
         }
        BN_BLINDING_lock(b);
        ret := BN_BLINDING_convert_ex(f, unblind, b, ctx);
        BN_BLINDING_unlock(b);
        Exit(ret);
    end;
end;


function rsa_blinding_invert( b : PBN_BLINDING; f, unblind : PBIGNUM; ctx : PBN_CTX):integer;
begin
    {
     * For local blinding, unblind is set to nil, and BN_BLINDING_invert_ex
     * will use the unblinding factor stored in BN_BLINDING. If BN_BLINDING
     * is shared between threads, unblind must be non-null:
     * BN_BLINDING_invert_ex will then use the local unblinding factor, and
     * will only read the modulus from BN_BLINDING. In both cases it's safe
     * to access the blinding without a lock.
     }
    Result := BN_BLINDING_invert_ex(f, unblind, b, ctx);
end;


function rsa_ossl_private_encrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
var
  f,
  ret,
  res            : PBIGNUM;
  i,
  num,
  r              : integer;
  buf            : PByte;
  ctx            : PBN_CTX;
  local_blinding : integer;
  unblind        : PBIGNUM;
  blinding       : PBN_BLINDING;
  d              : PBIGNUM;
  function get_unblind :PBIGNUM;
  begin
     unblind := BN_CTX_get(ctx);
     Result := unblind;
  end;
  label _err;
begin
    num := 0;
    r := -1;
    buf := nil;
    ctx := nil;
    local_blinding := 0;
    {
     * Used only if the blinding structure is shared. A non-nil unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     }
    unblind := nil;
    blinding := nil;
    ctx := BN_CTX_new_ex(rsa.libctx) ;
    if ctx = nil then
        goto _err ;
    BN_CTX_start(ctx);
    f := BN_CTX_get(ctx);
    ret := BN_CTX_get(ctx);
    num := BN_num_bytes(rsa.n);
    buf := OPENSSL_malloc(num);
    //SetLength(buf, num);
    if (ret = nil)  or  (buf = nil) then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    case padding of
        RSA_PKCS1_PADDING:
            i := RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
            //break;
        RSA_X931_PADDING:
            i := RSA_padding_add_X931(buf, num, from, flen);
            //break;
        RSA_NO_PADDING:
            i := RSA_padding_add_none(buf, num, from, flen);
            //break;
        else
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            goto _err ;
        end;
    end;
    if i <= 0 then goto _err ;
    if BN_bin2bn(buf, num, f) = nil  then
        goto _err ;
    if BN_ucmp(f, rsa.n) >= 0  then
    begin
        { usually the padding functions would catch this }
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto _err ;
    end;
    if (rsa.flags and RSA_FLAG_CACHE_PUBLIC) > 0 then
       if nil = BN_MONT_CTX_set_locked(@rsa._method_mod_n, rsa.lock, rsa.n, ctx) then
            goto _err ;
    if 0>= (rsa.flags and RSA_FLAG_NO_BLINDING) then
    begin //err at here
        blinding := rsa_get_blinding(rsa, @local_blinding, ctx);
        if blinding = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
    end;

    if blinding <> nil then
    begin

        if (0>= local_blinding)  and  (get_unblind = nil) then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if 0>= rsa_blinding_convert(blinding, f, unblind, ctx) then
            goto _err ;
    end;

    if (rsa.flags and RSA_FLAG_EXT_PKEY > 0)  or
       (rsa.version = RSA_ASN1_VERSION_MULTI)  or
        ((rsa.p <> nil)  and (rsa.q <> nil)  and
         (rsa.dmp1 <> nil)  and  (rsa.dmq1 <> nil)  and  (rsa.iqmp <> nil)) then
    begin
        if 0>= rsa.meth.rsa_mod_exp(ret, f, rsa, ctx) then
            goto _err ;
    end
    else
    begin
        d := BN_new();
        if d = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if rsa.d = nil then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_MISSING_PRIVATE_KEY);
            BN_free(d);
            goto _err ;
        end;
        BN_with_flags(d, rsa.d, BN_FLG_CONSTTIME);
        if 0>= rsa.meth.bn_mod_exp(ret, f, d, rsa.n, ctx,
                                   rsa._method_mod_n) then
        begin
            BN_free(d);
            goto _err ;
        end;
        { We MUST free d before any further use of rsa.d }
        BN_free(d);
    end;
    if blinding <> nil then
       if (0>= rsa_blinding_invert(blinding, ret, unblind, ctx)) then
            goto _err ;
    if padding = RSA_X931_PADDING then
    begin
        if 0>= BN_sub(f, rsa.n, ret) then
            goto _err ;
        if BN_cmp(ret, f)  > 0 then
            res := f
        else
            res := ret;
    end
    else
    begin
        res := ret;
    end;
    {
     * BN_bn2binpad puts in leading 0 bytes if the number is less than
     * the length of the modulus.
     }
    r := BN_bn2binpad(res, _to, num);
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_clear_free(buf, num);
    Result := r;
end;


function rsa_ossl_private_decrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
var
  f, ret, d      : PBIGNUM;
  j, num, r      : integer;
  buf            : PByte;
  ctx            : PBN_CTX;
  local_blinding : integer;
  unblind        : PBIGNUM;
  blinding       : PBN_BLINDING;
  function get_unblind :PBIGNUM;
  begin
     unblind := BN_CTX_get(ctx);
     Exit(unblind);
  end;
  label _err;
begin
    num := 0;
    r := -1;
    buf := nil;
    ctx := nil;
    local_blinding := 0;
    {
     * Used only if the blinding structure is shared. A non-nil unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     }
    unblind := nil;
    blinding := nil;
    ctx := BN_CTX_new_ex(rsa.libctx);
    if ctx = nil then
        goto _err ;
    BN_CTX_start(ctx);
    f := BN_CTX_get(ctx);
    ret := BN_CTX_get(ctx);
    num := BN_num_bytes(rsa.n);
    buf := OPENSSL_malloc(num);
    //SetLength(buf, num);
    if (ret = nil)  or  (buf = nil) then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    {
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     }
    if flen > num then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_GREATER_THAN_MOD_LEN);
        goto _err ;
    end;
    { make data into a big number }
    if BN_bin2bn(from, int(flen), f) = nil  then
        goto _err ;
    if BN_ucmp(f, rsa.n) >= 0  then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto _err ;
    end;
    if (0>= (rsa.flags and RSA_FLAG_NO_BLINDING )) then
    begin
        blinding := rsa_get_blinding(rsa, @local_blinding, ctx);
        if blinding = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR);
            goto _err ;
        end;
    end;
    if blinding <> nil then
    begin
        if (0>= local_blinding)  and  (get_unblind = nil) then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if 0>= rsa_blinding_convert(blinding, f, unblind, ctx) then
            goto _err ;  //ctx.pool.current.vals   结果与vc一致
        
    end;
    { do the decrypt }

    if  (rsa.flags and RSA_FLAG_EXT_PKEY >0 )  or
        (rsa.version = RSA_ASN1_VERSION_MULTI)  or
        ( (rsa.p <> nil)  and  (rsa.q <> nil)  and
          (rsa.dmp1 <> nil)  and  (rsa.dmq1 <> nil)  and  (rsa.iqmp <> nil)) then
    begin
        if 0>= rsa.meth.rsa_mod_exp(ret, f, rsa, ctx) then
            goto _err ;
        {$IFDEF DEBUG}
        //writeln('rsa_ossl.rsa_ossl_private_decrypt: rsa.meth.rsa_mod_exp');
        //print_bn_ctx(ctx);
        {$ENDIF}
    end
    else
    begin
        d := BN_new();
        if d = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if rsa.d = nil then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_MISSING_PRIVATE_KEY);
            BN_free(d);
            goto _err ;
        end;
        BN_with_flags(d, rsa.d, BN_FLG_CONSTTIME);
        if (rsa.flags and RSA_FLAG_CACHE_PUBLIC) > 0 then
           if nil = BN_MONT_CTX_set_locked(@rsa._method_mod_n, rsa.lock, rsa.n, ctx) then
           begin
                BN_free(d);
                goto _err ;
           end;
        if 0>= rsa.meth.bn_mod_exp(ret, f, d, rsa.n, ctx, rsa._method_mod_n) then
        begin
            BN_free(d);
            goto _err ;
        end;
        { We MUST free d before any further use of rsa.d }
        BN_free(d);
    end;

    if blinding <> nil then
       if (0>= rsa_blinding_invert(blinding, ret, unblind, ctx)) then
            goto _err ;

    j := BN_bn2binpad(ret, buf, num);
    if j < 0 then goto _err ;
    case padding of
        RSA_PKCS1_PADDING:
            r := RSA_padding_check_PKCS1_type_2(_to, num, buf, j, num);
            //break;
        RSA_PKCS1_OAEP_PADDING:
            r := RSA_padding_check_PKCS1_OAEP(_to, num, buf, j, num, nil, 0);
            //break;
        RSA_NO_PADDING:
            memcpy(_to, buf, int(r = j));
            //break;
        else
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            goto _err ;
        end;
    end;
{$IFNDEF FIPS_MODULE}
    {
     * This trick doesn't work in the FIPS provider because libcrypto manages
     * the error stack. Instead we opt not to put an error on the stack at all
     * in case of padding failure in the FIPS provider.
     }
    ERR_raise(ERR_LIB_RSA, RSA_R_PADDING_CHECK_FAILED);
    err_clear_last_constant_time(1 and not constant_time_msb(r));
{$ENDIF}

 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_clear_free(buf, num);
    //SetLength(buf, 0);
    Result := r;
end;


function rsa_ossl_public_decrypt(flen : integer;const from : PByte; _to : PByte; rsa : PRSA; padding : integer):integer;
var
  f, ret : PBIGNUM;
  i, num, r : integer;
  buf : PByte;
  ctx : PBN_CTX;
  label _err;
begin
{$POINTERMATH ON}
    num := 0;
    r := -1;
    buf := nil;
    ctx := nil;
    if BN_num_bits(rsa.n) > OPENSSL_RSA_MAX_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_MODULUS_TOO_LARGE);
        Exit(-1);
    end;
    if BN_ucmp(rsa.n, rsa.e) <= 0  then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
        Exit(-1);
    end;
    { for large moduli, enforce exponent limit }
    if BN_num_bits(rsa.n) > OPENSSL_RSA_SMALL_MODULUS_BITS  then
    begin
        if BN_num_bits(rsa.e) > OPENSSL_RSA_MAX_PUBEXP_BITS then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
            Exit(-1);
        end;
    end;
    ctx := BN_CTX_new_ex(rsa.libctx);
    if ctx = nil then
        goto _err ;
    BN_CTX_start(ctx);
    f := BN_CTX_get(ctx);
    ret := BN_CTX_get(ctx);
    num := BN_num_bytes(rsa.n);
    buf := OPENSSL_malloc(num);
    if (ret = nil)  or  (buf = nil) then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    {
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     }
    if flen > num then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_GREATER_THAN_MOD_LEN);
        goto _err ;
    end;
    if BN_bin2bn(from, flen, f) = nil  then
        goto _err ;
    if BN_ucmp(f, rsa.n) >= 0 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto _err ;
    end;
    if (rsa.flags and RSA_FLAG_CACHE_PUBLIC) > 0 then
       if (nil = BN_MONT_CTX_set_locked(@rsa._method_mod_n, rsa.lock,
                                    rsa.n, ctx)) then
            goto _err ;
    if 0>= rsa.meth.bn_mod_exp(ret, f, rsa.e, rsa.n, ctx,
                               rsa._method_mod_n) then
        goto _err ;
    if (padding = RSA_X931_PADDING)  and  ((bn_get_words(ret)[0] and $f) <> 12) then
        if (0>= BN_sub(ret, rsa.n, ret))  then
            goto _err ;
    i := BN_bn2binpad(ret, buf, num);
    if i < 0 then goto _err ;
    case padding of
        RSA_PKCS1_PADDING:
            r := RSA_padding_check_PKCS1_type_1(_to, num, buf, i, num);
            //break;
        RSA_X931_PADDING:
            r := RSA_padding_check_X931(_to, num, buf, i, num);
            //break;
        RSA_NO_PADDING:
            memcpy(_to, buf, int(r = i));
            //break;
        else
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            goto _err ;
        end;
    end;
    if r < 0 then
       ERR_raise(ERR_LIB_RSA, RSA_R_PADDING_CHECK_FAILED);
 _err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_clear_free(Pointer(buf), num);
    Result := r;
 {$POINTERMATH OFF}
end;

// Added by Administrator 2022-09-21 09:26:51
function get_mont_ctx(ctx : PBN_CTX; rsa : PRSA; factor: PBIGNUM; tp: byte): PBN_MONT_CTX;
begin
   case tp of
      0:
      begin
         BN_with_flags(factor, rsa.p, BN_FLG_CONSTTIME);
         //ctx.pool.current.vals same as vc++
         Result := BN_MONT_CTX_set_locked(@rsa._method_mod_p, rsa.lock, factor, ctx);
      end;
      1:
      begin
         BN_with_flags(factor, rsa.q, BN_FLG_CONSTTIME);
         //ctx.pool.current.vals same as vc++
         Result := BN_MONT_CTX_set_locked(@rsa._method_mod_q, rsa.lock, factor, ctx);
      end;
   end;
end;

function rsa_ossl_mod_exp(r0 : PBIGNUM;const _I : PBIGNUM; rsa : PRSA; ctx : PBN_CTX):integer;
var
  r1, r2,
  m1, vrfy  : PBIGNUM;
  smooth    : Boolean;
  ret,i, t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,
  ex_primes : integer;
  pinfo     : PRSA_PRIME_INFO;
  factor, d,
  c, dmq1,
  dmp1, di, cc,
  pr1, pr2  : PBIGNUM;
  m: array[0..RSA_MAX_PRIME_NUM - 2-1] of PBIGNUM;
  function get_ex_primes :int;
  begin
     ex_primes := sk_RSA_PRIME_INFO_num(rsa.prime_infos);
     Exit(ex_primes);
  end;
  label _err, _tail;
begin
    ret := 0;
    smooth := Boolean(0);
{$IFNDEF FIPS_MODULE}

    ex_primes := 0;
{$ENDIF}
    BN_CTX_start(ctx);
    r1 := BN_CTX_get(ctx);
{$IFNDEF FIPS_MODULE}
    r2 := BN_CTX_get(ctx);
{$ENDIF}
    m1 := BN_CTX_get(ctx);
    vrfy := BN_CTX_get(ctx);
    if vrfy = nil then goto _err ;
{$IFNDEF FIPS_MODULE}
    //满足rsa.version = RSA_ASN1_VERSION_MULTI才执行get_ex_primes
    if (rsa.version = RSA_ASN1_VERSION_MULTI) and
       ( (get_ex_primes <= 0) or  (ex_primes > RSA_MAX_PRIME_NUM - 2))  then
        goto _err ;
{$ENDIF}
    if (rsa.flags and RSA_FLAG_CACHE_PRIVATE)>0 then
    begin
        factor := BN_new();
        if factor = nil then goto _err ;
        {
         * Make sure BN_mod_inverse in Montgomery initialization uses the
         * BN_FLG_CONSTTIME flag
         }
        if (nil = get_mont_ctx(ctx, rsa, factor, 0)) or
           (nil = get_mont_ctx(ctx, rsa, factor, 1)) then
        begin
            BN_free(factor);
            goto _err ;
        end;
       
{$IFNDEF FIPS_MODULE}
        for i := 0 to ex_primes-1 do
        begin
            pinfo := sk_RSA_PRIME_INFO_value(rsa.prime_infos, i);
            BN_with_flags(factor, pinfo.r, BN_FLG_CONSTTIME);
            if nil = BN_MONT_CTX_set_locked(@pinfo.m, rsa.lock, factor, ctx) then
            begin
                BN_free(factor);
                goto _err ;
            end;
        end;
{$ENDIF}
        {
         * We MUST free |factor| before any further use of the prime factors
         }
        //BN_free(factor);
        Assert(@rsa.meth.bn_mod_exp = @BN_mod_exp_mont);
        smooth := (@rsa.meth.bn_mod_exp = @BN_mod_exp_mont)
{$IFNDEF FIPS_MODULE}
                  and  (ex_primes = 0)
{$ENDIF}
                  and  (BN_num_bits(rsa.q) = BN_num_bits(rsa.p));
    end;
    if (rsa.flags and RSA_FLAG_CACHE_PUBLIC) > 0 then
       ////ctx.pool.current.vals same as vc++
       if nil = BN_MONT_CTX_set_locked(@rsa._method_mod_n, rsa.lock, rsa.n, ctx) then
            goto _err ;


    if smooth then
    begin
        {
         * Conversion from Montgomery domain, a.k.a. Montgomery reduction,
         * accepts values in [0-m*2^w) range. w is m's bit width rounded up
         * to limb width. So that at the very least if |I| is fully reduced,
         * i.e. less than p*q, we can count on from-to round to perform
         * below modulo operations on |I|. Unlike BN_mod it's constant time.
         }
           { m1 = I moq q }
        t1 := bn_from_mont_fixed_top(m1, _I, rsa._method_mod_q, ctx);
        t2 := bn_to_mont_fixed_top(m1, m1, rsa._method_mod_q, ctx);
        t3 := bn_from_mont_fixed_top(r1, _I, rsa._method_mod_p, ctx);
        t4 := bn_to_mont_fixed_top(r1, r1, rsa._method_mod_p, ctx);
        t5 := BN_mod_exp_mont_consttime_x2(m1, m1, rsa.dmq1, rsa.q,
                                             rsa._method_mod_q,
                                             r1, r1, rsa.dmp1, rsa.p,
                                             rsa._method_mod_p,
                                             ctx);
        t6 := bn_mod_sub_fixed_top(r1, r1, m1, rsa.p);
        t7 := bn_to_mont_fixed_top(r1, r1, rsa._method_mod_p, ctx);
        t8 := bn_mul_mont_fixed_top(r1, r1, rsa.iqmp, rsa._method_mod_p, ctx);
        t9 := bn_mul_fixed_top(r0, r1, rsa.q, ctx);
        t10 := bn_mod_add_fixed_top(r0, r0, m1, rsa.n);
        if (0 >= t1) or  (0 >= t2)
            { r1 = I mod p }
             or  (0 >= t3) or  (0 >= t4)
            {
             * Use parallel exponentiations optimization if possible,
             * otherwise fallback to two sequential exponentiations:
             *    m1 = m1^dmq1 mod q
             *    r1 = r1^dmp1 mod p
             }
             or  (0 >= t5)
            { r1 = (r1 - m1) mod p }
            {
             * bn_mod_sub_fixed_top is not regular modular subtraction,
             * it can tolerate subtrahend to be larger than modulus, but
             * not bit-wise wider. This makes up for uncommon q>p case,
             * when |m1| can be larger than |rsa.p|.
             }
             or  (0 >= t6)
            { r1 = r1 * iqmp mod p }
             or  (0 >= t7)
             or  (0 >= t8)
            { r0 = r1 * q + m1 }
             or  (0 >= t9)
             or  (0 >= t10) then
                goto _err ;

      
        goto _tail ;
    end;

    { compute I mod q }
    begin
        c := BN_new();
        if c = nil then
           goto _err ;
        BN_with_flags(c, _I, BN_FLG_CONSTTIME);
        if 0>= BN_mod(r1, c, rsa.q, ctx) then
        begin
            BN_free(c);
            goto _err ;
        end;

        begin
            dmq1 := BN_new();
            if dmq1 = nil then
            begin
                BN_free(c);
                goto _err ;
            end;
            BN_with_flags(dmq1, rsa.dmq1, BN_FLG_CONSTTIME);
            { compute r1^dmq1 mod q }
            if 0>= rsa.meth.bn_mod_exp(m1, r1, dmq1, rsa.q, ctx,
                                       rsa._method_mod_q )then
            begin
                BN_free(c);
                BN_free(dmq1);
                goto _err ;
            end;
            { We MUST free dmq1 before any further use of rsa.dmq1 }
            BN_free(dmq1);
        end;
        { compute I mod p }
        if 0>= BN_mod(r1, c, rsa.p, ctx) then
        begin
            BN_free(c);
            goto _err ;
        end;
        { We MUST free c before any further use of I }
        BN_free(c);
    end;
    begin
        dmp1 := BN_new();
        if dmp1 = nil then goto _err ;
        BN_with_flags(dmp1, rsa.dmp1, BN_FLG_CONSTTIME);
        { compute r1^dmp1 mod p }
        if 0>= rsa.meth.bn_mod_exp(r0, r1, dmp1, rsa.p, ctx,
                                   rsa._method_mod_p) then
        begin
            BN_free(dmp1);
            goto _err ;
        end;
        { We MUST free dmp1 before any further use of rsa.dmp1 }
        BN_free(dmp1);
    end;
{$IFNDEF FIPS_MODULE}
    if ex_primes > 0 then
    begin
        di := BN_new(); cc := BN_new();
        if (cc = nil)  or  (di = nil) then
        begin
            BN_free(cc);
            BN_free(di);
            goto _err ;
        end;
        for i := 0 to ex_primes-1 do
        begin
            { prepare m_i }
             m[i] := BN_CTX_get(ctx);
            if m[i] = nil then
            begin
                BN_free(cc);
                BN_free(di);
                goto _err ;
            end;
            pinfo := sk_RSA_PRIME_INFO_value(rsa.prime_infos, i);
            { prepare c and d_i }
            BN_with_flags(cc, _I, BN_FLG_CONSTTIME);
            BN_with_flags(di, pinfo.d, BN_FLG_CONSTTIME);
            if 0>= BN_mod(r1, cc, pinfo.r, ctx) then
            begin
                BN_free(cc);
                BN_free(di);
                goto _err ;
            end;
            { compute r1 ^ d_i mod r_i }
            if 0>= rsa.meth.bn_mod_exp(m[i], r1, di, pinfo.r, ctx, pinfo.m ) then
            begin
                BN_free(cc);
                BN_free(di);
                goto _err ;
            end;
        end;
        BN_free(cc);
        BN_free(di);
    end;
{$ENDIF}
    if 0>= BN_sub(r0, r0, m1 ) then
        goto _err ;
    {
     * This will help stop the size of r0 increasing, which does affect the
     * multiply if it optimised for a power of 2 size
     }
    if BN_is_negative(r0 ) > 0 then
        if 0>= BN_add(r0, r0, rsa.p) then
            goto _err ;
    if 0>= BN_mul(r1, r0, rsa.iqmp, ctx) then
        goto _err ;
    begin
        pr1 := BN_new();
        if pr1 = nil then goto _err ;
        BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);
        if 0>= BN_mod(r0, pr1, rsa.p, ctx) then
        begin
            BN_free(pr1);
            goto _err ;
        end;
        { We MUST free pr1 before any further use of r1 }
        BN_free(pr1);
    end;
    {
     * If p < q it is occasionally possible for the correction of adding 'p'
     * if r0 is negative above to leave the result still negative. This can
     * break the private key operations: the following second correction
     * should *always* correct this rare occurrence. This will *never* happen
     * with OpenSSL generated keys because they ensure p > q [steve]
     }
    if BN_is_negative(r0 ) > 0 then
        if 0>= BN_add(r0, r0, rsa.p) then
            goto _err ;
    if 0>= BN_mul(r1, r0, rsa.q, ctx) then
        goto _err ;
    if 0>= BN_add(r0, r1, m1) then
        goto _err ;
{$IFNDEF FIPS_MODULE}
    { add m_i to m in multi-prime case }
    if ex_primes > 0 then
    begin
        pr2 := BN_new();
        if pr2 = nil then goto _err ;
        for i := 0 to ex_primes-1 do
        begin
            pinfo := sk_RSA_PRIME_INFO_value(rsa.prime_infos, i);
            if 0>= BN_sub(r1, m[i], r0) then
            begin
                BN_free(pr2);
                goto _err ;
            end;
            if 0>= BN_mul(r2, r1, pinfo.t, ctx) then
            begin
                BN_free(pr2);
                goto _err ;
            end;
            BN_with_flags(pr2, r2, BN_FLG_CONSTTIME);
            if 0>= BN_mod(r1, pr2, pinfo.r, ctx) then
            begin
                BN_free(pr2);
                goto _err ;
            end;
            if BN_is_negative(r1 ) >0 then
                if 0>= BN_add(r1, r1, pinfo.r) then
                begin
                    BN_free(pr2);
                    goto _err ;
                end;
            if 0>= BN_mul(r1, r1, pinfo.pp, ctx) then
            begin
                BN_free(pr2);
                goto _err ;
            end;
            if 0>= BN_add(r0, r0, r1) then
            begin
                BN_free(pr2);
                goto _err ;
            end;
        end;
        BN_free(pr2);
    end;
{$ENDIF}

 _tail:
    if (rsa.e <> nil)  and  (rsa.n <> nil) then
    begin
        if @rsa.meth.bn_mod_exp = @BN_mod_exp_mont then
        begin
            if (0>= BN_mod_exp_mont(vrfy, r0, rsa.e, rsa.n, ctx, rsa._method_mod_n)) then
                goto _err ;
        end
        else
        begin
            bn_correct_top(r0);
            if 0>= rsa.meth.bn_mod_exp(vrfy, r0, rsa.e, rsa.n, ctx,
                                       rsa._method_mod_n) then
                goto _err ;
        end;
        {
         * If 'I' was greater than (or equal to) rsa.n, the operation will
         * be equivalent to using 'I mod n'. However, the result of the
         * verify will *always* be less than 'n' so we don't check for
         * absolute equality, just congruency.
         }
        if 0>= BN_sub(vrfy, vrfy, _I) then
            goto _err ;
        if BN_is_zero(vrfy)  then
        begin
            bn_correct_top(r0);
            ret := 1;
            goto _err ;   { not actually error }
        end;
        if 0>= BN_mod(vrfy, vrfy, rsa.n, ctx )then
            goto _err ;
        if BN_is_negative(vrfy) > 0 then
            if 0>= BN_add(vrfy, vrfy, rsa.n) then
                goto _err ;
        if not BN_is_zero(vrfy) then
        begin
            {
             * 'I' and 'vrfy' aren't congruent mod n. Don't leak
             * miscalculated CRT output, just do a raw (slower) mod_exp and
             * return that instead.
             }
            d := BN_new();
            if d = nil then goto _err ;
            BN_with_flags(d, rsa.d, BN_FLG_CONSTTIME);
            if 0>= rsa.meth.bn_mod_exp(r0, _I, d, rsa.n, ctx, rsa._method_mod_n ) then
            begin
                BN_free(d);
                goto _err ;
            end;
            { We MUST free d before any further use of rsa.d }
            BN_free(d);
        end;
    end;
    {
     * It's unfortunate that we have to bn_correct_top(r0). What hopefully
     * saves the day is that correction is highly unlike, and private key
     * operations are customarily performed on blinded message. Which means
     * that attacker won't observe correlation with chosen plaintext.
     * Secondly, remaining code would still handle it in same computational
     * time and even conceal memory access pattern around corrected top.
     }
    bn_correct_top(r0);
    ret := 1;

 _err:
    BN_CTX_end(ctx);
    Result := ret;
end;


function rsa_ossl_init( rsa : PRSA):integer;
begin
    rsa.flags  := rsa.flags  or (RSA_FLAG_CACHE_PUBLIC or RSA_FLAG_CACHE_PRIVATE);
    Result := 1;
end;


function rsa_ossl_finish( rsa : PRSA):integer;
var
  i : integer;

  pinfo : PRSA_PRIME_INFO;
begin
{$IFNDEF FIPS_MODULE}
    for i := 0 to sk_RSA_PRIME_INFO_num(rsa.prime_infos)-1 do begin
        pinfo := sk_RSA_PRIME_INFO_value(rsa.prime_infos, i);
        BN_MONT_CTX_free(pinfo.m);
    end;
{$ENDIF}
    BN_MONT_CTX_free(rsa._method_mod_n);
    BN_MONT_CTX_free(rsa._method_mod_p);
    BN_MONT_CTX_free(rsa._method_mod_q);
    Result := 1;
end;

end.
