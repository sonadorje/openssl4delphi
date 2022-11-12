unit OpenSSL3.providers.implementations.signature.dsa_sig;

interface
 uses OpenSSL.Api, SysUtils;

 function dsa_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
 function dsa_setup_md(ctx : PPROV_DSA_CTX; mdname, mdprops : PUTF8Char):integer;
  function dsa_signverify_init(vpdsactx, vdsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
  function dsa_sign_init(vpdsactx, vdsa : Pointer;const params : POSSL_PARAM):integer;
  function dsa_verify_init(vpdsactx, vdsa : Pointer;const params : POSSL_PARAM):integer;
  function dsa_sign(vpdsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
  function dsa_verify(vpdsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function dsa_digest_signverify_init(vpdsactx : Pointer;const mdname : PUTF8Char; vdsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
  function dsa_digest_sign_init(vpdsactx : Pointer;const mdname : PUTF8Char; vdsa : Pointer;const params : POSSL_PARAM):integer;
  function dsa_digest_verify_init(vpdsactx : Pointer;const mdname : PUTF8Char; vdsa : Pointer;const params : POSSL_PARAM):integer;
  function dsa_digest_signverify_update(vpdsactx : Pointer;const data : PByte; datalen : size_t):integer;
  function dsa_digest_sign_final( vpdsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
  function dsa_digest_verify_final(vpdsactx : Pointer;const sig : PByte; siglen : size_t):integer;
  procedure dsa_freectx( vpdsactx : Pointer);
  function dsa_dupctx( vpdsactx : Pointer):Pointer;
  function dsa_get_ctx_params( vpdsactx : Pointer; params : POSSL_PARAM):integer;
  function dsa_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
  function dsa_set_ctx_params(vpdsactx : Pointer;const params : POSSL_PARAM):integer;
  function dsa_settable_ctx_params( vpdsactx, provctx : Pointer):POSSL_PARAM;
  function dsa_get_ctx_md_params( vpdsactx : Pointer; params : POSSL_PARAM):integer;
  function dsa_gettable_ctx_md_params( vpdsactx : Pointer):POSSL_PARAM;
  function dsa_set_ctx_md_params(vpdsactx : Pointer;const params : POSSL_PARAM):integer;
  function dsa_settable_ctx_md_params( vpdsactx : Pointer):POSSL_PARAM;

const
   ossl_dsa_signature_functions: array[0..21] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_SIGNATURE_NEWCTX; method:(code:@dsa_newctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN_INIT; method:(code:@dsa_sign_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN; method:(code:@dsa_sign; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY_INIT; method:(code:@dsa_verify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY; method:(code:@dsa_verify; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT;
      method:(code:@dsa_digest_sign_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE;
      method:(code:@dsa_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL;
      method:(code:@dsa_digest_sign_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT;
      method:(code:@dsa_digest_verify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE;
      method:(code:@dsa_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL;
      method:(code:@dsa_digest_verify_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_FREECTX; method:(code:@dsa_freectx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DUPCTX; method:(code:@dsa_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS; method:(code:@dsa_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS;
      method:(code:@dsa_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS; method:(code:@dsa_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS;
      method:(code:@dsa_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS;
      method:(code:@dsa_get_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS;
      method:(code:@dsa_gettable_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS;
      method:(code:@dsa_set_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS;
      method:(code:@dsa_settable_ctx_md_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);
function dsa_get_md_size(const pdsactx : PPROV_DSA_CTX):size_t;
function ossl_dsa_sign_int(&type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; dsa : PDSA):integer;

var
  known_gettable_ctx_params,
  settable_ctx_params,
  settable_ctx_params_no_digest: array of TOSSL_PARAM ;

implementation
uses  OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     OpenSSL3.providers.common.der.der_dsa_sig, openssl3.providers.fips.self_test,
     openssl3.crypto.dsa.dsa_ossl, openssl3.crypto.dsa.dsa_sign,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     OpenSSL3.openssl.params, openssl3.crypto.dsa.dsa_lib;


function ossl_dsa_sign_int(&type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; dsa : PDSA):integer;
var
  s : PDSA_SIG;
begin
    { legacy case uses the method table }
    if (dsa.libctx = nil)  or  (dsa.meth <> DSA_get_default_method)  then
        s := DSA_do_sign(dgst, dlen, dsa)
    else
        s := ossl_dsa_do_sign_int(dgst, dlen, dsa);
    if s = nil then
    begin
        siglen^ := 0;
        Exit(0);
    end;
    siglen^ := i2d_DSA_SIG(s, @sig);
    DSA_SIG_free(s);
    Result := 1;
end;




function dsa_get_md_size(const pdsactx : PPROV_DSA_CTX):size_t;
begin
    if pdsactx.md <> nil then Exit(EVP_MD_get_size(pdsactx.md));
    Result := 0;
end;



function dsa_setup_md(ctx : PPROV_DSA_CTX; mdname, mdprops : PUTF8Char):integer;
var
    sha1_allowed : Boolean;
    pkt          : TWPACKET;
    md           : PEVP_MD;
    md_nid       : integer;
    mdname_len   : size_t;
    pc: PUTF8Char;
begin
    if mdprops = nil then
       mdprops := ctx.propq;
    if mdname <> nil then
    begin
        sha1_allowed := (ctx.operation <> EVP_PKEY_OP_SIGN);
        md := EVP_MD_fetch(ctx.libctx, mdname, mdprops);
        md_nid := ossl_digest_get_approved_nid_with_sha1(ctx.libctx, md,
                                                            Int(sha1_allowed));
        mdname_len := Length(mdname);
        if (md = nil)  or  (md_nid < 0) then
        begin
            if md = nil then
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               Format('%s could not be fetched', [mdname]));
            if md_nid < 0 then ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                              Format( 'digest=%s', [mdname]));
            if mdname_len >= sizeof(ctx.mdname )then
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                              Format('%s exceeds name buffer length', [mdname]));
            EVP_MD_free(md);
            Exit(0);
        end;
        if 0>= ctx.flag_allow_md then
        begin
            if (ctx.mdname[0] <> #0)  and  (not EVP_MD_is_a(md, ctx.mdname)) then
            begin
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                              Format( 'digest %s <> %s', [mdname, ctx.mdname]));
                EVP_MD_free(md);
                Exit(0);
            end;
            EVP_MD_free(md);
            Exit(1);
        end;
        EVP_MD_CTX_free(ctx.mdctx);
        EVP_MD_free(ctx.md);
        {
         * We do not care about DER writing errors.
         * All it really means is that for some reason, there's no
         * AlgorithmIdentifier to be had, but the operation itself is
         * still valid, just as long as it's not used to construct
         * anything that needs an AlgorithmIdentifier.
         }
        ctx.aid_len := 0;
        if (WPACKET_init_der(@pkt, @ctx.aid_buf, sizeof(ctx.aid_buf)) >0)
             and  (ossl_DER_w_algorithmIdentifier_DSA_with_MD(@pkt, -1, ctx.dsa,
                                                          md_nid))
             and  (WPACKET_finish(@pkt)>0)  then
        begin
            WPACKET_get_total_written(@pkt, @ctx.aid_len);
            ctx.aid := WPACKET_get_curr(@pkt);
        end;
        WPACKET_cleanup(@pkt);
        ctx.mdctx := nil;
        ctx.md := md;
        pc := @ctx.mdname;
        OPENSSL_strlcpy(pc{ctx.mdname}, mdname, sizeof(ctx.mdname));
    end;
    Result := 1;
end;


function dsa_signverify_init(vpdsactx, vdsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := PPROV_DSA_CTX  (vpdsactx);
    if (not ossl_prov_is_running)  or  (pdsactx = nil) then
        Exit(0);
    if (vdsa = nil)  and  (pdsactx.dsa = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if vdsa <> nil then
    begin
        if (0>= ossl_dsa_check_key(pdsactx.libctx, vdsa,
                                Int(operation = EVP_PKEY_OP_SIGN)) ) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>= DSA_up_ref(vdsa )then
            Exit(0);
        DSA_free(pdsactx.dsa);
        pdsactx.dsa := vdsa;
    end;
    pdsactx.operation := operation;
    if 0>= dsa_set_ctx_params(pdsactx, params )then
        Exit(0);
    Result := 1;
end;


function dsa_sign_init(vpdsactx, vdsa : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := dsa_signverify_init(vpdsactx, vdsa, params, EVP_PKEY_OP_SIGN);
end;


function dsa_verify_init(vpdsactx, vdsa : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := dsa_signverify_init(vpdsactx, vdsa, params, EVP_PKEY_OP_VERIFY);
end;


function dsa_sign(vpdsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  pdsactx : PPROV_DSA_CTX;

  ret : integer;

  sltmp : uint32;

  dsasize, mdsize : size_t;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    dsasize := DSA_size(pdsactx.dsa);
    mdsize := dsa_get_md_size(pdsactx);
    if not ossl_prov_is_running()  then
        Exit(0);
    if sig = nil then
    begin
        siglen^ := dsasize;
        Exit(1);
    end;
    if sigsize < (size_t(dsasize)) then
        Exit(0);
    if (mdsize <> 0)  and  (tbslen <> mdsize) then Exit(0);
    ret := ossl_dsa_sign_int(0, tbs, tbslen, sig, @sltmp, pdsactx.dsa);
    if ret <= 0 then Exit(0);
    siglen^ := sltmp;
    Result := 1;
end;


function dsa_verify(vpdsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  pdsactx : PPROV_DSA_CTX;

  mdsize : size_t;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    mdsize := dsa_get_md_size(pdsactx);
    if (not ossl_prov_is_running) or  ( (mdsize <> 0)  and  (tbslen <> mdsize)) then
        Exit(0);
    Result := _DSA_verify(0, tbs, tbslen, sig, siglen, pdsactx.dsa);
end;


function dsa_digest_signverify_init(vpdsactx : Pointer;const mdname : PUTF8Char; vdsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  pdsactx : PPROV_DSA_CTX;
  label _error;
begin
    pdsactx := PPROV_DSA_CTX ( vpdsactx);
    if not ossl_prov_is_running() then
        Exit(0);
    if 0>= dsa_signverify_init(vpdsactx, vdsa, params, operation ) then
        Exit(0);
    if 0>= dsa_setup_md(pdsactx, mdname, nil ) then
        Exit(0);
    pdsactx.flag_allow_md := 0;
    if pdsactx.mdctx = nil then
    begin
        pdsactx.mdctx := EVP_MD_CTX_new();
        if pdsactx.mdctx = nil then
          goto _error ;
    end;
    if 0>= EVP_DigestInit_ex2(pdsactx.mdctx, pdsactx.md, params ) then
        goto _error ;
    Exit(1);
 _error:
    EVP_MD_CTX_free(pdsactx.mdctx);
    pdsactx.mdctx := nil;
    Result := 0;
end;


function dsa_digest_sign_init(vpdsactx : Pointer;const mdname : PUTF8Char; vdsa : Pointer;const params : POSSL_PARAM):integer;
begin
    Exit(dsa_digest_signverify_init(vpdsactx, mdname, vdsa, params,
                                      EVP_PKEY_OP_SIGN));
end;


function dsa_digest_verify_init(vpdsactx : Pointer;const mdname : PUTF8Char; vdsa : Pointer;const params : POSSL_PARAM):integer;
begin
    Exit(dsa_digest_signverify_init(vpdsactx, mdname, vdsa, params,
                                      EVP_PKEY_OP_VERIFY));
end;


function dsa_digest_signverify_update(vpdsactx : Pointer;const data : PByte; datalen : size_t):integer;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := (PPROV_DSA_CTX (vpdsactx));
    if (pdsactx = nil)  or  (pdsactx.mdctx = nil) then Exit(0);
    Result := EVP_DigestUpdate(pdsactx.mdctx, data, datalen);
end;


function dsa_digest_sign_final( vpdsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
var
  pdsactx : PPROV_DSA_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    dlen := 0;
    if (not ossl_prov_is_running)  or  (pdsactx = nil)  or  (pdsactx.mdctx = nil) then
        Exit(0);
    {
     * If sig is nil then we're just finding out the sig size. Other fields
     * are ignored. Defer to dsa_sign.
     }
    if sig <> nil then
    begin
        {
         * There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in DSA.
         }
        if 0>= EVP_DigestFinal_ex(pdsactx.mdctx, @digest, @dlen) then
            Exit(0);
    end;
    pdsactx.flag_allow_md := 1;
    Result := dsa_sign(vpdsactx, sig, siglen, sigsize, @digest, size_t(dlen));
end;


function dsa_digest_verify_final(vpdsactx : Pointer;const sig : PByte; siglen : size_t):integer;
var
  pdsactx : PPROV_DSA_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    dlen := 0;
    if (not ossl_prov_is_running)  or ( pdsactx = nil)  or  (pdsactx.mdctx = nil)then
        Exit(0);
    {
     * There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in DSA.
     }
    if 0>= EVP_DigestFinal_ex(pdsactx.mdctx, @digest, @dlen) then
        Exit(0);
    pdsactx.flag_allow_md := 1;
    Result := dsa_verify(vpdsactx, sig, siglen, @digest, size_t(dlen));
end;


procedure dsa_freectx( vpdsactx : Pointer);
var
  ctx : PPROV_DSA_CTX;
begin
    ctx := (PPROV_DSA_CTX  (vpdsactx));
    OPENSSL_free(Pointer(ctx.propq));
    EVP_MD_CTX_free(ctx.mdctx);
    EVP_MD_free(ctx.md);
    ctx.propq := nil;
    ctx.mdctx := nil;
    ctx.md := nil;
    DSA_free(ctx.dsa);
    OPENSSL_free(Pointer(ctx));
end;


function dsa_dupctx( vpdsactx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_DSA_CTX;
  label _err;
begin
    srcctx := (PPROV_DSA_CTX  (vpdsactx));
    if not ossl_prov_is_running() then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    dstctx.dsa := nil;
    dstctx.md := nil;
    dstctx.mdctx := nil;
    dstctx.propq := nil;
    if (srcctx.dsa <> nil)  and  (0>= DSA_up_ref(srcctx.dsa)) then
        goto _err ;
    dstctx.dsa := srcctx.dsa;
    if (srcctx.md <> nil)  and  (0>= EVP_MD_up_ref(srcctx.md)) then
        goto _err ;
    dstctx.md := srcctx.md;
    if srcctx.mdctx <> nil then
    begin
        dstctx.mdctx := EVP_MD_CTX_new();
        if (dstctx.mdctx = nil )
                 or  (0>= EVP_MD_CTX_copy_ex(dstctx.mdctx, srcctx.mdctx) )  then
            goto _err ;
    end;
    if srcctx.propq <> nil then
    begin
         OPENSSL_strdup(dstctx.propq ,srcctx.propq);
        if dstctx.propq = nil then goto _err ;
    end;
    Exit(dstctx);
 _err:
    dsa_freectx(dstctx);
    Result := nil;
end;


function dsa_get_ctx_params( vpdsactx : Pointer; params : POSSL_PARAM):integer;
var
  pdsactx : PPROV_DSA_CTX;

  p : POSSL_PARAM;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if pdsactx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_octet_string(p, pdsactx.aid, pdsactx.aid_len)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_string(p, pdsactx.mdname)) then
        Exit(0);
    Result := 1;
end;


function dsa_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params[0];
end;


function dsa_set_ctx_params(vpdsactx : Pointer;const params : POSSL_PARAM):integer;
var
  pdsactx : PPROV_DSA_CTX;
  p : POSSL_PARAM;
  mdname : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8char;
  mdprops : array[0..(OSSL_MAX_PROPQUERY_SIZE)-1] of UTF8char;
  pmdname, pmdprops: PUTF8Char;
  propsp : POSSL_PARAM;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if pdsactx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if p <> nil then
    begin
        FillChar(mdname, sizeof(mdname),#0);
        pmdname := @mdname;
        FillChar(mdprops,SizeOf(mdprops), #0);
        pmdprops := @mdprops;
        propsp :=
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);
        if 0>= OSSL_PARAM_get_utf8_string(p, @pmdname, sizeof(mdname))  then
            Exit(0);
        if (propsp <> nil)   and
           (0>= OSSL_PARAM_get_utf8_string(propsp, @pmdprops, sizeof(mdprops))) then
            Exit(0);
        if 0>= dsa_setup_md(pdsactx, mdname, mdprops)  then
            Exit(0);
    end;
    Result := 1;
end;


function dsa_settable_ctx_params( vpdsactx, provctx : Pointer):POSSL_PARAM;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if (pdsactx <> nil)  and  (0>= pdsactx.flag_allow_md )then
       Exit(@settable_ctx_params_no_digest[0]);
    Result := @settable_ctx_params[0];
end;


function dsa_get_ctx_md_params( vpdsactx : Pointer; params : POSSL_PARAM):integer;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if pdsactx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_get_params(pdsactx.mdctx, params);
end;


function dsa_gettable_ctx_md_params( vpdsactx : Pointer):POSSL_PARAM;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if pdsactx.md = nil then Exit(0);
    Result := EVP_MD_gettable_ctx_params(pdsactx.md);
end;


function dsa_set_ctx_md_params(vpdsactx : Pointer;const params : POSSL_PARAM):integer;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if pdsactx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_set_params(pdsactx.mdctx, params);
end;


function dsa_settable_ctx_md_params( vpdsactx : Pointer):POSSL_PARAM;
var
  pdsactx : PPROV_DSA_CTX;
begin
    pdsactx := (PPROV_DSA_CTX  (vpdsactx));
    if pdsactx.md = nil then Exit(0);
    Result := EVP_MD_settable_ctx_params(pdsactx.md);
end;





function dsa_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
var
  pdsactx : PPROV_DSA_CTX;
begin
    if not ossl_prov_is_running( )then
        Exit(nil);
    pdsactx := OPENSSL_zalloc(sizeof(TPROV_DSA_CTX));
    if pdsactx = nil then Exit(nil);
    pdsactx.libctx := PROV_LIBCTX_OF(provctx);
    pdsactx.flag_allow_md := 1;
    OPENSSL_strdup(pdsactx.propq ,propq);
    if (propq <> nil)  and  (pdsactx.propq =nil) then
    begin
        OPENSSL_free(pdsactx);
        pdsactx := nil;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    end;
    Result := pdsactx;
end;

initialization
  known_gettable_ctx_params := [
    _OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    OSSL_PARAM_END
];
 settable_ctx_params_no_digest := [
    OSSL_PARAM_END
];
  settable_ctx_params := [
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, nil, 0),
    OSSL_PARAM_END
];
end.
