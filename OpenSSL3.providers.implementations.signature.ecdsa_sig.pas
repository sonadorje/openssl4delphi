unit OpenSSL3.providers.implementations.signature.ecdsa_sig;
{$I  config.inc}

interface
uses OpenSSL.Api, SysUtils;


{$ifdef S390X_EC_ASM}
  function s390x_ed25519_digestsign(const edkey : PECX_KEY; sig : PByte;const tbs : PByte; tbslen : size_t):integer;
  function s390x_ed448_digestsign(const edkey : PECX_KEY; sig : PByte;const tbs : PByte; tbslen : size_t):integer;
  function s390x_ed25519_digestverify(const edkey : PECX_KEY; sig, tbs : PByte; tbslen : size_t):integer;
  function s390x_ed448_digestverify(const edkey : PECX_KEY; sig, tbs : PByte; tbslen : size_t):integer;
{$ENDIF}
  function ecdsa_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
  function ecdsa_sign_init(vctx, ec : Pointer;const params : POSSL_PARAM):integer;
  function ecdsa_verify_init(vctx, ec : Pointer;const params : POSSL_PARAM):integer;
  function ecdsa_digest_sign_init(vctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM):integer;
  function ecdsa_digest_signverify_update(vctx : Pointer;const data : PByte; datalen : size_t):integer;
  function ecdsa_digest_sign_final( vctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
  function ecdsa_digest_verify_init(vctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM):integer;
  function ecdsa_digest_verify_final(vctx : Pointer;const sig : PByte; siglen : size_t):integer;
  procedure ecdsa_freectx( vctx : Pointer);
  function ecdsa_dupctx( vctx : Pointer):Pointer;
  function ecdsa_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function ecdsa_gettable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
  function ecdsa_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function ecdsa_settable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
  function ecdsa_get_ctx_md_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function ecdsa_set_ctx_md_params(vctx : Pointer;const params : POSSL_PARAM):integer;
  function ecdsa_settable_ctx_md_params( vctx : Pointer):POSSL_PARAM;
  function ecdsa_gettable_ctx_md_params( vctx : Pointer):POSSL_PARAM;
  function ecdsa_verify(vctx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function ecdsa_sign(vctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;

const
 ossl_ecdsa_signature_functions: array[0..21] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_SIGNATURE_NEWCTX; method:(code:@ecdsa_newctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN_INIT; method:(code:@ecdsa_sign_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN; method:(code:@ecdsa_sign; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY_INIT; method:(code:@ecdsa_verify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY; method:(code:@ecdsa_verify; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT;
      method:(code:@ecdsa_digest_sign_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE;
      method:(code:@ecdsa_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL;
      method:(code:@ecdsa_digest_sign_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT;
      method:(code:@ecdsa_digest_verify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE;
      method:(code:@ecdsa_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL;
      method:(code:@ecdsa_digest_verify_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_FREECTX; method:(code:@ecdsa_freectx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DUPCTX; method:(code:@ecdsa_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS; method:(code:@ecdsa_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS;
      method:(code:@ecdsa_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS; method:(code:@ecdsa_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS;
      method:(code:@ecdsa_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS;
      method:(code:@ecdsa_get_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS;
      method:(code:@ecdsa_gettable_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS;
      method:(code:@ecdsa_set_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS;
      method:(code:@ecdsa_settable_ctx_md_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);
function ecdsa_setup_md(ctx : PPROV_ECDSA_CTX; mdname, mdprops : PUTF8Char):integer;
function ecdsa_digest_signverify_init(vctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM; operation : integer):integer;
 function ecdsa_signverify_init(vctx, ec : Pointer;const params : POSSL_PARAM; operation : integer):integer;

var
   settable_ctx_params_no_digest,
   known_gettable_ctx_params,
   settable_ctx_params: array of TOSSL_PARAM ;

implementation
uses OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.providers.fips.self_test, OpenSSL3.openssl.params,
     OpenSSL3.providers.common.securitycheck_default, openssl3.crypto.ec.ecx_key,
     OpenSSL3.providers.common.der.der_ecx_key,openssl3.crypto.bn.bn_lib,
     OpenSSL3.providers.implementations.exchange.ecx_exch,
     openssl3.crypto.ec.ec_asn1,    openssl3.crypto.ec.ecdsa_sign,
     openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.curve25519, openssl3.crypto.ec.curve25519.eddsa,
     OpenSSL3.providers.common.der.der_ec_sig, openssl3.crypto.ec.ecdsa_vrf;


function ecdsa_sign(vctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ctx : PPROV_ECDSA_CTX;
  ret : integer;
  sltmp : uint32;
  ecsize : size_t;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    ecsize := ECDSA_size(ctx.ec);
    if not ossl_prov_is_running then
        Exit(0);
    if sig = nil then
    begin
        siglen^ := ecsize;
        Exit(1);
    end;
{$IF not defined(OPENSSL_NO_ACVP_TESTS)}
    if ctx.kattest  and  (0>= ECDSA_sign_setup(ctx.ec, nil, &ctx.kinv, &ctx.r then )
        Exit(0);
{$ENDIF}
    if sigsize < size_t( ecsize) then
       Exit(0);
    if (ctx.mdsize <> 0)  and  (tbslen <> ctx.mdsize) then
       Exit(0);
    ret := ECDSA_sign_ex(0, tbs, tbslen, sig, @sltmp, ctx.kinv, ctx.r, ctx.ec);
    if ret <= 0 then Exit(0);
    siglen^ := sltmp;
    Result := 1;
end;







function ecdsa_signverify_init(vctx, ec : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if (not ossl_prov_is_running )  or  (ctx = nil)then
        Exit(0);
    if (ec = nil)  and  (ctx.ec = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if ec <> nil then
    begin
        if 0>= ossl_ec_check_key(ctx.libctx, ec, Int( operation = EVP_PKEY_OP_SIGN)) then
            Exit(0);
        if 0>= EC_KEY_up_ref(ec) then
            Exit(0);
        EC_KEY_free(ctx.ec);
        ctx.ec := ec;
    end;
    ctx.operation := operation;
    if 0>= ecdsa_set_ctx_params(ctx, params )then
        Exit(0);
    Result := 1;
end;




function ecdsa_digest_signverify_init(vctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  ctx : PPROV_ECDSA_CTX;
  label _error;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if not ossl_prov_is_running then
        Exit(0);
    if (0>= ecdsa_signverify_init(vctx, ec, params, operation))  or
       (0>= ecdsa_setup_md(ctx, mdname, nil)) then
        Exit(0);
    ctx.flag_allow_md := 0;
    if ctx.mdctx = nil then
    begin
        ctx.mdctx := EVP_MD_CTX_new();
        if ctx.mdctx = nil then
           goto _error ;
    end;
    if 0>= EVP_DigestInit_ex2(ctx.mdctx, ctx.md, params)  then
        goto _error ;
    Exit(1);
_error:
    EVP_MD_CTX_free(ctx.mdctx);
    ctx.mdctx := nil;
    Result := 0;
end;



function ecdsa_verify(vctx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if (not ossl_prov_is_running )  or  ( (ctx.mdsize <> 0)  and  (tbslen <> ctx.mdsize))then
        Exit(0);
    Result := _ECDSA_verify(0, tbs, tbslen, sig, siglen, ctx.ec);
end;



function ecdsa_setup_md(ctx : PPROV_ECDSA_CTX; mdname, mdprops : PUTF8Char):integer;
var
    md           : PEVP_MD;
    mdname_len   : size_t;
    md_nid,
    sha1_allowed : integer;
    pkt          : TWPACKET;
    pc: PUTF8Char;
begin
    md := nil;
    if mdname = nil then Exit(1);
    mdname_len := Length(mdname);
    if mdname_len >= sizeof(ctx.mdname) then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                     Format('%s exceeds name buffer length', [mdname]));
        Exit(0);
    end;
    if mdprops = nil then
       mdprops := ctx.propq;
    md := EVP_MD_fetch(ctx.libctx, mdname, mdprops);
    if md = nil then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                      Format( '%s could not be fetched', [mdname]));
        Exit(0);
    end;
    sha1_allowed := int(ctx.operation <> EVP_PKEY_OP_SIGN);
    md_nid := ossl_digest_get_approved_nid_with_sha1(ctx.libctx, md,
                                                    sha1_allowed);
    if md_nid < 0 then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                      Format( 'digest=%s', [mdname]));
        EVP_MD_free(md);
        Exit(0);
    end;
    if 0>= ctx.flag_allow_md then
    begin
        if (ctx.mdname[0] <> #0)  and  (not EVP_MD_is_a(md, ctx.mdname)) then
        begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                           Format('digest %s <> %s', [mdname, ctx.mdname]));
            EVP_MD_free(md);
            Exit(0);
        end;
        EVP_MD_free(md);
        Exit(1);
    end;
    EVP_MD_CTX_free(ctx.mdctx);
    EVP_MD_free(ctx.md);
    ctx.aid_len := 0;
    if (WPACKET_init_der(@pkt, @ctx.aid_buf, sizeof(ctx.aid_buf ))>0)
         and  (ossl_DER_w_algorithmIdentifier_ECDSA_with_MD(@pkt, -1, ctx.ec,
                                                        md_nid)>0)
         and ( WPACKET_finish(@pkt)>0)  then
    begin
        WPACKET_get_total_written(@pkt, @ctx.aid_len);
        ctx.aid := WPACKET_get_curr(@pkt);
    end;
    WPACKET_cleanup(@pkt);
    ctx.mdctx := nil;
    ctx.md := md;
    ctx.mdsize := EVP_MD_get_size(ctx.md);
    pc := @ctx.mdname;
    OPENSSL_strlcpy(pc{ctx.mdname}, mdname, sizeof(ctx.mdname));
    Result := 1;
end;




function ecdsa_gettable_ctx_md_params( vctx : Pointer):POSSL_PARAM;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if ctx.md = nil then Exit(0);
    Result := EVP_MD_gettable_ctx_params(ctx.md);
end;




function ecdsa_settable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if (ctx <> nil)  and  (0>= ctx.flag_allow_md) then
       Exit(@settable_ctx_params_no_digest[0]);
    Result := @settable_ctx_params[0];
end;


function ecdsa_get_ctx_md_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if ctx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_get_params(ctx.mdctx, params);
end;


function ecdsa_set_ctx_md_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if ctx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_set_params(ctx.mdctx, params);
end;


function ecdsa_settable_ctx_md_params( vctx : Pointer):POSSL_PARAM;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if ctx.md = nil then Exit(0);
    Result := EVP_MD_settable_ctx_params(ctx.md);
end;

function ecdsa_gettable_ctx_params( vctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params[0];
end;


function ecdsa_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_ECDSA_CTX;
  p : POSSL_PARAM;
  mdsize : size_t;
  mdname : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8Char;
  pmdname, pmdprops: PUTF8Char;
  mdprops : array[0..(OSSL_MAX_PROPQUERY_SIZE)-1] of UTF8Char;
  propsp: POSSL_PARAM  ;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    mdsize := 0;
    if ctx = nil then Exit(0);
    if params = nil then Exit(1);
{$IF not defined(OPENSSL_NO_ACVP_TESTS)}
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_KAT);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_uint(p, @ctx.kattest)) then
        Exit(0);
{$ENDIF}
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if p <> nil then
    begin
        mdname := ''; pmdname := @mdname;
        mdprops := ''; pmdprops := @mdprops;
        propsp :=
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);
        if 0>= OSSL_PARAM_get_utf8_string(p, @pmdname, sizeof(mdname)) then
            Exit(0);
        if (propsp <> nil)
             and  (0>= OSSL_PARAM_get_utf8_string(propsp, @pmdprops, sizeof(mdprops)) )then
            Exit(0);
        if 0>= ecdsa_setup_md(ctx, mdname, mdprops)  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p <> nil) then
    begin
        if (0>= OSSL_PARAM_get_size_t(p, @mdsize))
             or  ( (0>= ctx.flag_allow_md)  and ( mdsize <> ctx.mdsize)) then
            Exit(0);
        ctx.mdsize := mdsize;
    end;
    Result := 1;
end;





function ecdsa_dupctx( vctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_ECDSA_CTX;
  label _err;
begin
    srcctx := PPROV_ECDSA_CTX( vctx);
    if not ossl_prov_is_running then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    dstctx.ec := nil;
    dstctx.md := nil;
    dstctx.mdctx := nil;
    dstctx.propq := nil;
    if (srcctx.ec <> nil)  and  (0>= EC_KEY_up_ref(srcctx.ec)) then
        goto _err ;
    { Test KATS should not need to be supported }
    if (srcctx.kinv <> nil)  or  (srcctx.r <> nil) then
       goto _err ;
    dstctx.ec := srcctx.ec;
    if (srcctx.md <> nil)  and  (0>= EVP_MD_up_ref(srcctx.md))  then
        goto _err ;
    dstctx.md := srcctx.md;
    if srcctx.mdctx <> nil then
    begin
        dstctx.mdctx := EVP_MD_CTX_new();
        if (dstctx.mdctx = nil)
                 or  (0>= EVP_MD_CTX_copy_ex(dstctx.mdctx, srcctx.mdctx)) then
            goto _err ;
    end;
    if srcctx.propq <> nil then
    begin
        OPENSSL_strdup(dstctx.propq ,srcctx.propq);
        if dstctx.propq = nil then
           goto _err ;
    end;
    Exit(dstctx);
 _err:
    ecdsa_freectx(dstctx);
    Result := nil;
end;


function ecdsa_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_ECDSA_CTX;

  p : POSSL_PARAM;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if ctx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_octet_string(p, ctx.aid, ctx.aid_len) ) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, ctx.mdsize)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_string(p, get_result(ctx.md = nil
                                                    , ctx.mdname
                                                    , EVP_MD_get0_name(ctx.md ))))then
        Exit(0);
    Result := 1;
end;



procedure ecdsa_freectx( vctx : Pointer);
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    OPENSSL_free(ctx.propq);
    EVP_MD_CTX_free(ctx.mdctx);
    EVP_MD_free(ctx.md);
    ctx.propq := nil;
    ctx.mdctx := nil;
    ctx.md := nil;
    ctx.mdsize := 0;
    EC_KEY_free(ctx.ec);
    BN_clear_free(ctx.kinv);
    BN_clear_free(ctx.r);
    OPENSSL_free(ctx);
end;




function ecdsa_digest_verify_final(vctx : Pointer;const sig : PByte; siglen : size_t):integer;
var
  ctx : PPROV_ECDSA_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    dlen := 0;
    if (not ossl_prov_is_running ) or  (ctx = nil)  or  (ctx.mdctx = nil) then
        Exit(0);
    if 0>= EVP_DigestFinal_ex(ctx.mdctx, @digest, @dlen) then
        Exit(0);
    ctx.flag_allow_md := 1;
    Result := ecdsa_verify(ctx, sig, siglen, @digest, size_t( dlen));
end;




function ecdsa_digest_verify_init(vctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM):integer;
begin
    Exit(ecdsa_digest_signverify_init(vctx, mdname, ec, params,
                                        EVP_PKEY_OP_VERIFY));
end;




function ecdsa_digest_sign_final( vctx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
var
  ctx : PPROV_ECDSA_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    dlen := 0;
    if (not ossl_prov_is_running ) or  (ctx = nil)  or  (ctx.mdctx = nil)then
        Exit(0);
    {
     * If sig is nil then we're just finding out the sig size. Other fields
     * are ignored. Defer to ecdsa_sign.
     }
    if (sig <> nil)
         and  (0>= EVP_DigestFinal_ex(ctx.mdctx, @digest, @dlen)) then
        Exit(0);
    ctx.flag_allow_md := 1;
    Result := ecdsa_sign(vctx, sig, siglen, sigsize, @digest, size_t( dlen));
end;




function ecdsa_digest_signverify_update(vctx : Pointer;const data : PByte; datalen : size_t):integer;
var
  ctx : PPROV_ECDSA_CTX;
begin
    ctx := PPROV_ECDSA_CTX( vctx);
    if (ctx = nil)  or  (ctx.mdctx = nil) then
       Exit(0);
    Result := EVP_DigestUpdate(ctx.mdctx, data, datalen);
end;




function ecdsa_digest_sign_init(vctx : Pointer;const mdname : PUTF8Char; ec : Pointer;const params : POSSL_PARAM):integer;
begin
    Exit(ecdsa_digest_signverify_init(vctx, mdname, ec, params,
                                        EVP_PKEY_OP_SIGN));
end;




function ecdsa_verify_init(vctx, ec : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_VERIFY);
end;




function ecdsa_sign_init(vctx, ec : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_SIGN);
end;



function ecdsa_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
var
  ctx : PPROV_ECDSA_CTX;
begin
    if not ossl_prov_is_running then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof(TPROV_ECDSA_CTX));
    if ctx = nil then Exit(nil);
    ctx.flag_allow_md := 1;
    ctx.libctx := PROV_LIBCTX_OF(provctx);
    OPENSSL_strdup(ctx.propq ,propq);
    if (propq <> nil)  and  (ctx.propq = nil) then
    begin
        OPENSSL_free(ctx);
        ctx := nil;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    end;
    Result := ctx;
end;


initialization
   settable_ctx_params_no_digest := [
    _OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, nil),
    OSSL_PARAM_END
    ];

   settable_ctx_params := [
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    _OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, nil),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, nil, 0),
    _OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, nil),
    OSSL_PARAM_END
   ];

   known_gettable_ctx_params := [
    _OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, nil, 0),
    _OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, nil),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    OSSL_PARAM_END
  ];
end.
