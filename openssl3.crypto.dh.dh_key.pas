unit openssl3.crypto.dh.dh_key;

interface
uses  OpenSSL.Api;

const
{$ifdef FIPS_MODULE}
   MIN_STRENGTH = 112;
{$else}
   MIN_STRENGTH = 80;
{$endif}

function ossl_dh_key2buf(const dh : PDH; pbuf_out : PPByte; size : size_t; alloc : integer):size_t;
function ossl_dh_generate_public_key(ctx : PBN_CTX;const dh : PDH; priv_key : PBIGNUM; pub_key : PBIGNUM):integer;
function ossl_dh_buf2key(dh : PDH;const buf : PByte; len : size_t):integer;
function DH_get_default_method:PDH_METHOD;
function generate_key( dh : PDH):integer;
function ossl_dh_compute_key(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
function dh_bn_mod_exp(const dh : PDH; r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX; m_ctx : PBN_MONT_CTX):integer;
 function dh_init( dh : PDH):integer;
  function dh_finish( dh : PDH):integer;
  procedure DH_get0_key(const dh : PDH; pub_key, priv_key : PPBIGNUM);
 function DH_generate_key( dh : PDH):integer;
 function DH_compute_key_padded(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
 function DH_compute_key(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
 function DH_OpenSSL:PDH_METHOD;


implementation

uses {$IFDEF MSWINDOWS}libc.win,{$ENDIF} OpenSSL3.common,openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.bn.bn_mont,  openssl3.crypto.dh.dh_lib,
     openssl3.crypto.dh.dh_group_params, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_word,
     openssl3.crypto.ffc.ffc_params_validate,
     openssl3.crypto.ffc.ffc_key_generate, openssl3.crypto.bn.bn_rand,
     openssl3.crypto.ffc.ffc_params, openssl3.crypto.bn.bn_exp;

var
   dh_ossl: TDH_METHOD = (
    name: 'OpenSSL DH Method';
    generate_key: generate_key;
    compute_key: ossl_dh_compute_key;
    bn_mod_exp: dh_bn_mod_exp;
    init: dh_init;
    finish: dh_finish;
    flags: DH_FLAG_FIPS_METHOD;
    app_data: nil;
    generate_params:nil
   );

  default_DH_method: PDH_METHOD  = @dh_ossl;






function DH_OpenSSL:PDH_METHOD;
begin
    Result := @dh_ossl;
end;




function DH_compute_key(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
var
  ret, i : integer;
  npad, mask: size_t;
begin
    ret := 0;
    npad := 0; mask := 1;
{$IFDEF FIPS_MODULE}
    ret := ossl_dh_compute_key(key, pub_key, dh);
{$ELSE}
    ret := dh.meth.compute_key(key, pub_key, dh);
{$ENDIF}
    if ret <= 0 then Exit(ret);
    { count leading zero bytes, yet still touch all bytes }
    for i := 0 to ret-1 do
    begin
        mask := mask and (not key[i]);
        npad  := npad + mask;
    end;
    { unpad key }
    ret  := ret - npad;
    { key-dependent memory access, potentially leaking npad / ret }
    memmove(key, key + npad, ret);
    { key-dependent memory access, potentially leaking npad / ret }
    memset(key + ret, 0, npad);
    Result := ret;
end;


function DH_compute_key_padded(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
var
  rv, pad : integer;
begin
    { rv is constant unless compute_key is external }
{$IFDEF FIPS_MODULE}
    rv := ossl_dh_compute_key(key, pub_key, dh);
{$ELSE}
    rv := dh.meth.compute_key(key, pub_key, dh);
{$ENDIF}
    if rv <= 0 then
       Exit(rv);
    pad := BN_num_bytes(dh.params.p) - rv;
    { pad is constant (zero) unless compute_key is external }
    if pad > 0 then
    begin
        memmove(key + pad, key, rv);
        memset(key, 0, pad);
    end;
    Result := rv + pad;
end;



function DH_generate_key( dh : PDH):integer;
begin
{$IFDEF FIPS_MODULE}
    Exit(generate_key(dh));
{$ELSE}
    Exit(dh.meth.generate_key(dh));
{$ENDIF}
end;



procedure DH_get0_key(const dh : PDH; pub_key, priv_key : PPBIGNUM);
begin
    if pub_key <> nil then
       pub_key^ := dh.pub_key;
    if priv_key <> nil then
       priv_key^ := dh.priv_key;
end;


function dh_init( dh : PDH):integer;
begin
    dh.flags  := dh.flags  or DH_FLAG_CACHE_MONT_P;
    ossl_ffc_params_init(@dh.params);
    Inc(dh.dirty_cnt);
    Result := 1;
end;


function dh_finish( dh : PDH):integer;
begin
    BN_MONT_CTX_free(dh.method_mont_p);
    Result := 1;
end;

function dh_bn_mod_exp(const dh : PDH; r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX; m_ctx : PBN_MONT_CTX):integer;
begin
    Result := BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
end;



function ossl_dh_compute_key(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
var
  ctx : PBN_CTX;
  mont : PBN_MONT_CTX;
  z, pminus1 : PBIGNUM;
  ret : integer;
  label _err;
begin
    ctx := nil;
    mont := nil;
    z := nil;
    ret := -1;
    if BN_num_bits(dh.params.p) > OPENSSL_DH_MAX_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        goto _err ;
    end;
    if BN_num_bits(dh.params.p) < DH_MIN_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(dh.libctx);
    if ctx = nil then goto _err ;
    BN_CTX_start(ctx);
    pminus1 := BN_CTX_get(ctx);
    z := BN_CTX_get(ctx);
    if z = nil then goto _err ;
    if dh.priv_key = nil then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_NO_PRIVATE_VALUE);
        goto _err ;
    end;
    if (dh.flags and DH_FLAG_CACHE_MONT_P)>0 then
    begin
        mont := BN_MONT_CTX_set_locked(@dh.method_mont_p,
                                      dh.lock, dh.params.p, ctx);
        BN_set_flags(dh.priv_key, BN_FLG_CONSTTIME);
        if nil = mont then
           goto _err ;
    end;
    { (Step 1) Z = pub_key^priv_key mod p }
    if 0>= dh.meth.bn_mod_exp(dh, z, pub_key, dh.priv_key, dh.params.p, ctx,
                              mont) then
    begin
        ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);
        goto _err ;
    end;
    { (Step 2) Error if z <= 1 or z = p - 1 }
    if (BN_copy(pminus1, dh.params.p)  = nil )
         or  (0>= BN_sub_word(pminus1, 1))
         or  (BN_cmp(z, BN_value_one) <= 0 )
         or  (BN_cmp(z, pminus1) = 0) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_SECRET);
        goto _err ;
    end;
    { return the padded key, i.e. same number of bytes as the modulus }
    ret := BN_bn2binpad(z, key, BN_num_bytes(dh.params.p));
 _err:
    BN_clear(z); { (Step 2) destroy intermediate values }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ret;
end;




function generate_key( dh : PDH):integer;
var
  ok,
  generate_new_key : integer;
  l                : uint32;
  ctx              : PBN_CTX;
  pub_key,
  priv_key         : PBIGNUM;
  max_strength     : integer;
  label _err;
begin
    ok := 0;
    generate_new_key := 0;
{$IFNDEF FIPS_MODULE}
{$ENDIF}
    ctx := nil;
    pub_key := nil;
    priv_key := nil;
    if BN_num_bits(dh.params.p) > OPENSSL_DH_MAX_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        Exit(0);
    end;
    if BN_num_bits(dh.params.p) < DH_MIN_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(dh.libctx);
    if ctx = nil then goto _err ;
    if dh.priv_key = nil then
    begin
        priv_key := BN_secure_new();
        if priv_key = nil then
           goto _err ;
        generate_new_key := 1;
    end
    else
    begin
        priv_key := dh.priv_key;
    end;
    if dh.pub_key = nil then
    begin
        pub_key := BN_new();
        if pub_key = nil then
           goto _err ;
    end
    else
    begin
        pub_key := dh.pub_key;
    end;
    if generate_new_key>0 then
    begin
        { Is it an approved safe prime ?}
        if DH_get_nid(dh) <> NID_undef then
        begin
            max_strength :=  ossl_ifc_ffc_compute_security_bits(BN_num_bits(dh.params.p));
            if (dh.params.q = nil)    or
               (dh.length > BN_num_bits(dh.params.q)) then
                goto _err ;
            { dh.length = maximum bit length of generated private key }
            if 0>= ossl_ffc_generate_private_key(ctx, @dh.params, dh.length,
                                               max_strength, priv_key) then
                goto _err ;
        end
        else
        begin
{$IFDEF FIPS_MODULE}
            if dh.params.q = nil then
               goto _err ;
{$ELSE} if dh.params.q = nil then
        begin
                { secret exponent length, must satisfy 2^(l-1) <= p }
                if (dh.length <> 0)
                     and  (dh.length >= BN_num_bits(dh.params.p)) then
                    goto _err ;
                l := get_result(dh.length >0, dh.length , BN_num_bits(dh.params.p) - 1);
                if 0>= BN_priv_rand_ex(priv_key, l, BN_RAND_TOP_ONE,
                                     BN_RAND_BOTTOM_ANY, 0, ctx) then
                    goto _err ;
                {
                 * We handle just one known case where g is a quadratic non-residue:
                 * for g = 2: p % 8 = 3
                 }
                if (BN_is_word(dh.params.g, DH_GENERATOR_2)) and
                   (0>= BN_is_bit_set(dh.params.p, 2))  then
                begin
                    { clear bit 0, since it won't be a secret anyway }
                    if 0>= BN_clear_bit(priv_key, 0) then
                        goto _err ;
                end;
            end
            else
{$ENDIF}
            begin
                { Do a partial check for invalid p, q, g }
                if 0>= ossl_ffc_params_simple_validate(dh.libctx, @dh.params,
                                                     FFC_PARAM_TYPE_DH, nil) then
                    goto _err ;
                {
                 * For FFC FIPS 186-4 keygen
                 * security strength s = 112,
                 * Max Private key size N = len(q)
                 }
                if 0>= ossl_ffc_generate_private_key(ctx, @dh.params,
                                                   BN_num_bits(dh.params.q) ,
                                                   MIN_STRENGTH,
                                                   priv_key)  then
                    goto _err ;
            end;
        end;
    end;
    if 0>= ossl_dh_generate_public_key(ctx, dh, priv_key, pub_key) then
        goto _err ;
    dh.pub_key := pub_key;
    dh.priv_key := priv_key;
    Inc(dh.dirty_cnt);
    ok := 1;
 _err:
    if ok <> 1 then
       ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);
    if pub_key <> dh.pub_key then
       BN_free(pub_key);
    if priv_key <> dh.priv_key then
       BN_free(priv_key);
    BN_CTX_free(ctx);
    Result := ok;
end;


function DH_get_default_method:PDH_METHOD;
begin
    Result := default_DH_method;
end;


function ossl_dh_buf2key(dh : PDH;const buf : PByte; len : size_t):integer;
var
    err_reason : integer;
    pubkey     : PBIGNUM;
    p_size     : size_t;
    p          : PBIGNUM;
    label _Err;
begin
    err_reason := DH_R_BN_ERROR;
    pubkey := nil;
    pubkey := BN_bin2bn(buf, len, nil);
    if pubkey =  nil then
        goto _err ;
    DH_get0_pqg(dh, @p, nil, nil);
    p_size := BN_num_bytes(p );
    if (p = nil)  or  (p_size = 0) then
    begin
        err_reason := DH_R_NO_PARAMETERS_SET;
        goto _err ;
    end;
    {
     * As per Section 4.2.8.1 of RFC 8446 fail if DHE's
     * public key is of size not equal to size of p
     }
    if (BN_is_zero(pubkey)) or  (p_size <> len) then
    begin
        err_reason := DH_R_INVALID_PUBKEY;
        goto _err ;
    end;
    if DH_set0_key(dh, pubkey, nil) <> 1   then
        goto _err ;
    Exit(1);
_err:
    ERR_raise(ERR_LIB_DH, err_reason);
    BN_free(pubkey);
    Result := 0;
end;

function ossl_dh_generate_public_key(ctx : PBN_CTX;const dh : PDH; priv_key : PBIGNUM; pub_key : PBIGNUM):integer;
var
  ret : integer;

  prk : PBIGNUM;

  mont : PBN_MONT_CTX;

  pmont : PPBN_MONT_CTX;
  label _err;
begin
    ret := 0;
    prk := BN_new();
    mont := nil;
    if prk = nil then Exit(0);
    if (dh.flags and DH_FLAG_CACHE_MONT_P)>0 then
    begin
        {
         * We take the input DH as const, but we lie, because in some cases we
         * want to get a hold of its Montgomery context.
         *
         * We cast to remove the const qualifier in this case, it should be
         * fine...
         }
        pmont := PPBN_MONT_CTX ( @dh.method_mont_p);
        mont := BN_MONT_CTX_set_locked(pmont, dh.lock, dh.params.p, ctx);
        if mont = nil then goto _err ;
    end;
    BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
    { pub_key = g^priv_key mod p }
    if  0>= dh.meth.bn_mod_exp(dh, pub_key, dh.params.g, prk, dh.params.p,
                              ctx, mont )then
        goto _err ;
    ret := 1;
_err:
    BN_clear_free(prk);
    Result := ret;
end;





function  BN_num_bytes(a: PBIGNUM): Integer;
begin
  Result := ((BN_num_bits(a)+7) div 8);
end;

function ossl_dh_key2buf(const dh : PDH; pbuf_out : PPByte; size : size_t; alloc : integer):size_t;
var
  pubkey : PBIGNUM;

  pbuf : Pbyte;

  p : PBIGNUM;

  p_size : integer;
begin
    pbuf := nil;
    DH_get0_pqg(dh, @p, nil, nil);
    DH_get0_key(dh, @pubkey, nil);
    p_size := BN_num_bytes(p);
    if (p = nil)  or  (pubkey = nil )
             or  (p_size =  0)
             or  (BN_num_bytes(pubkey) = 0) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY);
        Exit(0);
    end;
    if (pbuf_out <> nil)  and  ( (alloc>0)  or  (pbuf_out^ <> nil)  )then
    begin
        if  0>= alloc then
        begin
            if size >= size_t(p_size) then
                pbuf := pbuf_out^;
        end
        else
        begin
            pbuf := OPENSSL_malloc(p_size);
        end;
        if pbuf = nil then
        begin
            ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        {
         * As per Section 4.2.8.1 of RFC 8446 left pad public
         * key with zeros to the size of p
         }
        if BN_bn2binpad(pubkey, pbuf, p_size) < 0then
        begin
            if alloc>0 then
                OPENSSL_free(Pointer(pbuf));
            ERR_raise(ERR_LIB_DH, DH_R_BN_ERROR);
            Exit(0);
        end;
        pbuf_out^ := pbuf;
    end;
    Result := p_size;
end;

end.
