unit OpenSSL3.providers.implementations.signature.sm2_sig;

interface
uses OpenSSL.Api, SysUtils;

function sm2sig_set_mdname(psm2ctx : PPROV_SM2_CTX;const mdname : PUTF8Char):integer;
  function sm2sig_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
  function sm2sig_signature_init(vpsm2ctx, ec : Pointer;const params : POSSL_PARAM):integer;
  function sm2sig_sign(vpsm2ctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
  function sm2sig_verify(vpsm2ctx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  procedure free_md( ctx : PPROV_SM2_CTX);
  function sm2sig_digest_signverify_init(vpsm2ctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM):integer;
  function sm2sig_compute_z_digest( ctx : PPROV_SM2_CTX):integer;
  function sm2sig_digest_signverify_update(vpsm2ctx : Pointer;const data : PByte; datalen : size_t):integer;
  function sm2sig_digest_sign_final( vpsm2ctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
  function sm2sig_digest_verify_final(vpsm2ctx : Pointer;const sig : PByte; siglen : size_t):integer;
  procedure sm2sig_freectx( vpsm2ctx : Pointer);
  function sm2sig_dupctx( vpsm2ctx : Pointer):Pointer;
  function sm2sig_get_ctx_params( vpsm2ctx : Pointer; params : POSSL_PARAM):integer;
  function sm2sig_gettable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
  function sm2sig_set_ctx_params(vpsm2ctx : Pointer;const params : POSSL_PARAM):integer;
  function sm2sig_settable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
  function sm2sig_get_ctx_md_params( vpsm2ctx : Pointer; params : POSSL_PARAM):integer;
  function sm2sig_gettable_ctx_md_params( vpsm2ctx : Pointer):POSSL_PARAM;
  function sm2sig_set_ctx_md_params(vpsm2ctx : Pointer;const params : POSSL_PARAM):integer;
  function sm2sig_settable_ctx_md_params( vpsm2ctx : Pointer):POSSL_PARAM;

const
   ossl_sm2_signature_functions: array[0..21] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_SIGNATURE_NEWCTX; method:(code:@sm2sig_newctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN_INIT; method:(code:@sm2sig_signature_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN; method:(code:@sm2sig_sign; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY_INIT; method:(code:@sm2sig_signature_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY; method:(code:@sm2sig_verify; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT;
      method:(code:@sm2sig_digest_signverify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE;
      method:(code:@sm2sig_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL;
      method:(code:@sm2sig_digest_sign_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT;
      method:(code:@sm2sig_digest_signverify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE;
      method:(code:@sm2sig_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL;
      method:(code:@sm2sig_digest_verify_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_FREECTX; method:(code:@sm2sig_freectx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DUPCTX; method:(code:@sm2sig_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS; method:(code:@sm2sig_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS;
      method:(code:@sm2sig_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS; method:(code:@sm2sig_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS;
      method:(code:@sm2sig_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS;
      method:(code:@sm2sig_get_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS;
      method:(code:@sm2sig_gettable_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS;
      method:(code:@sm2sig_set_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS;
      method:(code:@sm2sig_settable_ctx_md_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

function ossl_sm2_internal_verify(const dgst : PByte; dgstlen : integer;const sig : PByte; sig_len : integer; eckey : PEC_KEY):integer;

var
   known_gettable_ctx_params,
   known_settable_ctx_params: array of TOSSL_PARAM ;

implementation
uses OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.providers.fips.self_test, OpenSSL3.openssl.params,
     OpenSSL3.providers.common.securitycheck_default, openssl3.crypto.ec.ecx_key,
     OpenSSL3.providers.common.der.der_ecx_key,openssl3.crypto.ec.ec_key,
     OpenSSL3.providers.implementations.exchange.ecx_exch,
     openssl3.crypto.ec.curve25519, openssl3.crypto.ec.curve25519.eddsa,
     OpenSSL3.providers.common.der.der_ec_sig, openssl3.crypto.sm2.sm2_sign,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.ec.ec_lib,  openssl3.crypto.ec.ec_asn1,
     openssl3.crypto.sm2.der_sm2_sig;







function ossl_sm2_internal_verify(const dgst : PByte; dgstlen : integer;const sig : PByte; sig_len : integer; eckey : PEC_KEY):integer;
var
  s : PECDSA_SIG;

  e : PBIGNUM;

  p, der : PByte;

  derlen, ret : integer;
  label _done;
begin
    s := nil;
    e := nil;
    p := sig;
    der := nil;
    derlen := -1;
    ret := -1;
    s := ECDSA_SIG_new();
    if s = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto _done ;
    end;
    if d2i_ECDSA_SIG(@s, @p, sig_len) = nil  then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto _done ;
    end;
    { Ensure signature uses DER and doesn't have trailing garbage }
    derlen := i2d_ECDSA_SIG(s, @der);
    if (derlen <> sig_len)  or  (memcmp(sig, der, derlen) <> 0) then
    begin
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto _done ;
    end;
    e := BN_bin2bn(dgst, dgstlen, nil);
    if e = nil then
    begin
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto _done ;
    end;
    ret := sm2_sig_verify(eckey, s, e);
 _done:
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    Result := ret;
end;

function sm2sig_set_mdname(psm2ctx : PPROV_SM2_CTX;const mdname : PUTF8Char):integer;
var
  pc: PUTF8Char;
begin
    if psm2ctx.md = nil then { We need an SM3 md to compare with }
        psm2ctx.md := EVP_MD_fetch(psm2ctx.libctx, psm2ctx.mdname,
                                   psm2ctx.propq);
    if psm2ctx.md = nil then Exit(0);
    if mdname = nil then Exit(1);
    if (Length(mdname ) >= sizeof(psm2ctx.mdname))
         or  (not EVP_MD_is_a(psm2ctx.md, mdname)) then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                   Format('digest=%s', [mdname]));
        Exit(0);
    end;
    pc := @psm2ctx.mdname;
    OPENSSL_strlcpy(pc{psm2ctx.mdname}, mdname, sizeof(psm2ctx.mdname));
    Result := 1;
end;


function sm2sig_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
var
  ctx : PPROV_SM2_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof(TPROV_SM2_CTX));
    if ctx = nil then Exit(nil);
    ctx.libctx := PROV_LIBCTX_OF(provctx);
    OPENSSL_strdup(ctx.propq ,propq);
    if (propq <> nil)  and  (ctx.propq = nil) then
    begin
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.mdsize := SM3_DIGEST_LENGTH;
    ctx.mdname := OSSL_DIGEST_NAME_SM3;
    Result := ctx;
end;


function sm2sig_signature_init(vpsm2ctx, ec : Pointer;const params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if (not ossl_prov_is_running)  or  (psm2ctx = nil) then
        Exit(0);
    if (ec = nil)  and  (psm2ctx.ec = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if ec <> nil then
    begin
        if 0>= EC_KEY_up_ref(ec) then
            Exit(0);
        EC_KEY_free(psm2ctx.ec);
        psm2ctx.ec := ec;
    end;
    Result := sm2sig_set_ctx_params(psm2ctx, params);
end;


function sm2sig_sign(vpsm2ctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ctx : PPROV_SM2_CTX;

  ret : integer;

  sltmp : uint32;

  ecsize : size_t;
begin
    ctx := PPROV_SM2_CTX ( vpsm2ctx);
    { SM2 uses ECDSA_size as well }
    ecsize := ECDSA_size(ctx.ec);
    if sig = nil then
    begin
        siglen^ := ecsize;
        Exit(1);
    end;
    if sigsize < size_t( ecsize) then
       Exit(0);
    if (ctx.mdsize <> 0)  and  (tbslen <> ctx.mdsize) then
       Exit(0);
    ret := ossl_sm2_internal_sign(tbs, tbslen, sig, @sltmp, ctx.ec);
    if ret <= 0 then
       Exit(0);
    siglen^ := sltmp;
    Result := 1;
end;


function sm2sig_verify(vpsm2ctx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ctx : PPROV_SM2_CTX;
begin
    ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if (ctx.mdsize <> 0)  and  (tbslen <> ctx.mdsize) then
       Exit(0);
    Result := ossl_sm2_internal_verify(tbs, tbslen, sig, siglen, ctx.ec);
end;


procedure free_md( ctx : PPROV_SM2_CTX);
begin
    EVP_MD_CTX_free(ctx.mdctx);
    EVP_MD_free(ctx.md);
    ctx.mdctx := nil;
    ctx.md := nil;
end;


function sm2sig_digest_signverify_init(vpsm2ctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_SM2_CTX;

  md_nid : integer;

  pkt : TWPACKET;

  ret : integer;
  label _error;
begin
    ctx := PPROV_SM2_CTX ( vpsm2ctx);
    ret := 0;
    if (0>= sm2sig_signature_init(vpsm2ctx, ec, params))  or
       (0>= sm2sig_set_mdname(ctx, mdname)) then
        Exit(ret);
    if ctx.mdctx = nil then
    begin
        ctx.mdctx := EVP_MD_CTX_new();
        if ctx.mdctx = nil then
           goto _error ;
    end;
    md_nid := EVP_MD_get_type(ctx.md);
    {
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     }
    ctx.aid_len := 0;
    if (WPACKET_init_der(@pkt, @ctx.aid_buf, sizeof(ctx.aid_buf))>0)
         and  (ossl_DER_w_algorithmIdentifier_SM2_with_MD(@pkt, -1, ctx.ec, md_nid)>0)
         and  (WPACKET_finish(@pkt)>0)  then
    begin
        WPACKET_get_total_written(@pkt, @ctx.aid_len);
        ctx.aid := WPACKET_get_curr(@pkt);
    end;
    WPACKET_cleanup(@pkt);
    if 0>= EVP_DigestInit_ex2(ctx.mdctx, ctx.md, params ) then
        goto _error ;
    ctx.flag_compute_z_digest := 1;
    ret := 1;
 _error:
    Result := ret;
end;


function sm2sig_compute_z_digest( ctx : PPROV_SM2_CTX):integer;
var
  z : PByte;

  ret : integer;
begin
     z := nil;
    ret := 1;
    if ctx.flag_compute_z_digest>0 then
    begin
        { Only do this once }
        ctx.flag_compute_z_digest := 0;
        z := OPENSSL_zalloc(ctx.mdsize );
        if (z  = nil)
            { get hashed prefix 'z' of tbs message }
             or  (0>= ossl_sm2_compute_z_digest(z, ctx.md, ctx.id, ctx.id_len,
                                          ctx.ec))
             or  (0>= EVP_DigestUpdate(ctx.mdctx, z, ctx.mdsize)) then
            ret := 0;
        OPENSSL_free(z);
    end;
    Result := ret;
end;


function sm2sig_digest_signverify_update(vpsm2ctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  psm2ctx : PPROV_SM2_CTX;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if (psm2ctx = nil)  or  (psm2ctx.mdctx = nil) then Exit(0);
    Result := int( (sm2sig_compute_z_digest(psm2ctx)>0)
         and  (EVP_DigestUpdate(psm2ctx.mdctx, data, datalen)>0));
end;


function sm2sig_digest_sign_final( vpsm2ctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
var
  psm2ctx : PPROV_SM2_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    dlen := 0;
    if (psm2ctx = nil)  or  (psm2ctx.mdctx = nil) then
        Exit(0);
    {
     * If sig is nil then we're just finding out the sig size. Other fields
     * are ignored. Defer to sm2sig_sign.
     }
    if sig <> nil then
    begin
        if (0>= (sm2sig_compute_z_digest(psm2ctx) ))
               and  (EVP_DigestFinal_ex(psm2ctx.mdctx, @digest, @dlen)>0) then
            Exit(0);
    end;
    Result := sm2sig_sign(vpsm2ctx, sig, siglen, sigsize, @digest, size_t( dlen));
end;


function sm2sig_digest_verify_final(vpsm2ctx : Pointer;const sig : PByte; siglen : size_t):integer;
var
  psm2ctx : PPROV_SM2_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    dlen := 0;
    if (psm2ctx = nil)
         or  (psm2ctx.mdctx = nil)
         or  (EVP_MD_get_size(psm2ctx.md) > int(sizeof(digest)) )  then
        Exit(0);
    if (0>= (sm2sig_compute_z_digest(psm2ctx))) and
       (EVP_DigestFinal_ex(psm2ctx.mdctx, @digest, @dlen)>0) then
        Exit(0);
    Result := sm2sig_verify(vpsm2ctx, sig, siglen, @digest, size_t( dlen));
end;


procedure sm2sig_freectx( vpsm2ctx : Pointer);
var
  ctx : PPROV_SM2_CTX;
begin
    ctx := PPROV_SM2_CTX ( vpsm2ctx);
    free_md(ctx);
    EC_KEY_free(ctx.ec);
    OPENSSL_free(ctx.id);
    OPENSSL_free(ctx);
end;


function sm2sig_dupctx( vpsm2ctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_SM2_CTX;
  label _err;
begin
    srcctx := PPROV_SM2_CTX ( vpsm2ctx);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    dstctx.ec := nil;
    dstctx.md := nil;
    dstctx.mdctx := nil;
    if (srcctx.ec <> nil)  and  (0>= EC_KEY_up_ref(srcctx.ec)) then
        goto _err ;
    dstctx.ec := srcctx.ec;
    if (srcctx.md <> nil)  and  (0>= EVP_MD_up_ref(srcctx.md) ) then
        goto _err ;
    dstctx.md := srcctx.md;
    if srcctx.mdctx <> nil then
    begin
        dstctx.mdctx := EVP_MD_CTX_new();
        if (dstctx.mdctx = nil)       or
           (0>= EVP_MD_CTX_copy_ex(dstctx.mdctx, srcctx.mdctx)) then
            goto _err ;
    end;
    if srcctx.id <> nil then
    begin
        dstctx.id := OPENSSL_malloc(srcctx.id_len);
        if dstctx.id = nil then
           goto _err ;
        dstctx.id_len := srcctx.id_len;
        memcpy(dstctx.id, srcctx.id, srcctx.id_len);
    end;
    Exit(dstctx);
 _err:
    sm2sig_freectx(dstctx);
    Result := nil;
end;


function sm2sig_get_ctx_params( vpsm2ctx : Pointer; params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX;

  p : POSSL_PARAM;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if psm2ctx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p <> nil)    and
       (0>= OSSL_PARAM_set_octet_string(p, psm2ctx.aid, psm2ctx.aid_len)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, psm2ctx.mdsize)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_string(p, get_result(psm2ctx.md = nil
                                                    , psm2ctx.mdname
                                                    , EVP_MD_get0_name(psm2ctx.md)) ))then
        Exit(0);
    Result := 1;
end;


function sm2sig_gettable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params[0];
end;


function sm2sig_set_ctx_params(vpsm2ctx : Pointer;const params : POSSL_PARAM):integer;
var
    psm2ctx   : PPROV_SM2_CTX;
    mdsize    : size_t;
    tmp_id    : Pointer;
    tmp_idlen : size_t;
    p         : POSSL_PARAM;
    mdname, pc    : PUTF8Char;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if psm2ctx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if p <> nil then
    begin
        tmp_id := nil;
        {
         * If the 'z' digest has already been computed, the ID is set too late
         }
        if 0>= psm2ctx.flag_compute_z_digest then
           Exit(0);
        if 0>= OSSL_PARAM_get_octet_string(p, tmp_id, 0, @tmp_idlen )then
            Exit(0);
        OPENSSL_free(psm2ctx.id);
        psm2ctx.id := tmp_id;
        psm2ctx.id_len := tmp_idlen;
    end;
    {
     * The following code checks that the size is the same as the SM3 digest
     * size returning an error otherwise.
     * If there is ever any different digest algorithm allowed with SM2
     * this needs to be adjusted accordingly.
     }
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p <> nil)  and ( (0>= OSSL_PARAM_get_size_t(p, @mdsize)) or
         ( mdsize <> psm2ctx.mdsize)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if p <> nil then
    begin
        mdname := nil;
        if 0>= OSSL_PARAM_get_utf8_string(p, @mdname, 0 )then
            Exit(0);
        if 0>= sm2sig_set_mdname(psm2ctx, mdname) then
        begin
            OPENSSL_free(mdname);
            Exit(0);
        end;
        OPENSSL_free(mdname);
    end;
    Result := 1;
end;


function sm2sig_settable_ctx_params( vpsm2ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params[0];
end;


function sm2sig_get_ctx_md_params( vpsm2ctx : Pointer; params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if psm2ctx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_get_params(psm2ctx.mdctx, params);
end;


function sm2sig_gettable_ctx_md_params( vpsm2ctx : Pointer):POSSL_PARAM;
var
  psm2ctx : PPROV_SM2_CTX;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if psm2ctx.md = nil then Exit(0);
    Result := EVP_MD_gettable_ctx_params(psm2ctx.md);
end;


function sm2sig_set_ctx_md_params(vpsm2ctx : Pointer;const params : POSSL_PARAM):integer;
var
  psm2ctx : PPROV_SM2_CTX;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if psm2ctx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_set_params(psm2ctx.mdctx, params);
end;


function sm2sig_settable_ctx_md_params( vpsm2ctx : Pointer):POSSL_PARAM;
var
  psm2ctx : PPROV_SM2_CTX;
begin
    psm2ctx := PPROV_SM2_CTX ( vpsm2ctx);
    if psm2ctx.md = nil then Exit(0);
    Result := EVP_MD_settable_ctx_params(psm2ctx.md);
end;

initialization
  known_gettable_ctx_params := [
    _OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, nil, 0),
    _OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, nil),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    OSSL_PARAM_END
  ];

 known_settable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, nil),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, nil, 0),
    OSSL_PARAM_END
 ];

end.
