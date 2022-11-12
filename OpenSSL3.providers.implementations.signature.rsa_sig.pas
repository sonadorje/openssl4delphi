unit OpenSSL3.providers.implementations.signature.rsa_sig;

interface
uses OpenSSL.Api, SysUtils;

function rsa_get_md_size(const prsactx : PPROV_RSA_CTX):size_t;
function rsa_check_padding(const prsactx : PPROV_RSA_CTX; mdname, mgf1_mdname : PUTF8Char; mdnid : integer):integer;
function rsa_check_parameters( prsactx : PPROV_RSA_CTX; min_saltlen : integer):integer;
function rsa_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
function rsa_pss_compute_saltlen( ctx : PPROV_RSA_CTX):integer;
function rsa_generate_signature_aid( ctx : PPROV_RSA_CTX; aid_buf : PByte; buf_len : size_t; aid_len : Psize_t):PByte;
function rsa_setup_md(ctx : PPROV_RSA_CTX; mdname, mdprops : PUTF8Char):integer;
function rsa_setup_mgf1_md(ctx : PPROV_RSA_CTX; mdname, mdprops : PUTF8Char):integer;
function rsa_signverify_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
function setup_tbuf( ctx : PPROV_RSA_CTX):integer;
procedure clean_tbuf( ctx : PPROV_RSA_CTX);
procedure free_tbuf( ctx : PPROV_RSA_CTX);
function rsa_sign_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
function rsa_sign(vprsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
function rsa_verify_recover_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
function rsa_verify_recover(vprsactx : Pointer; rout : PByte; routlen : Psize_t; routsize : size_t;const sig : PByte; siglen : size_t):integer;
function rsa_verify_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
function rsa_verify(vprsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
function rsa_digest_signverify_init(vprsactx : Pointer;const mdname : PUTF8Char; vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
function rsa_digest_signverify_update(vprsactx : Pointer;const data : PByte; datalen : size_t):integer;
function rsa_digest_sign_init(vprsactx : Pointer;const mdname : PUTF8Char; vrsa : Pointer;const params : POSSL_PARAM):integer;
function rsa_digest_sign_final( vprsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
function rsa_digest_verify_init(vprsactx : Pointer;const mdname : PUTF8Char; vrsa : Pointer;const params : POSSL_PARAM):integer;
function rsa_digest_verify_final(vprsactx : Pointer;const sig : PByte; siglen : size_t):integer;
procedure rsa_freectx( vprsactx : Pointer);
function rsa_dupctx( vprsactx : Pointer):Pointer;
function rsa_get_ctx_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
function rsa_gettable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
function rsa_set_ctx_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
function rsa_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
function rsa_get_ctx_md_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
function rsa_gettable_ctx_md_params( vprsactx : Pointer):POSSL_PARAM;
function rsa_set_ctx_md_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
function rsa_settable_ctx_md_params( vprsactx : Pointer):POSSL_PARAM;

const  ossl_rsa_signature_functions: array[0..23] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_SIGNATURE_NEWCTX; method:(code:@rsa_newctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN_INIT; method:(code:@rsa_sign_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SIGN; method:(code:@rsa_sign; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY_INIT; method:(code:@rsa_verify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY; method:(code:@rsa_verify; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT;
      method:(code:@rsa_verify_recover_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER;
      method:(code:@rsa_verify_recover; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT;
      method:(code:@rsa_digest_sign_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE;
      method:(code:@rsa_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL;
      method:(code:@rsa_digest_sign_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT;
      method:(code:@rsa_digest_verify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE;
      method:(code:@rsa_digest_signverify_update; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL;
      method:(code:@rsa_digest_verify_final; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_FREECTX; method:(code:@rsa_freectx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DUPCTX; method:(code:@rsa_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS; method:(code:@rsa_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS;
      method:(code:@rsa_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS; method:(code:@rsa_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS;
      method:(code:@rsa_settable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS;
      method:(code:@rsa_get_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS;
      method:(code:@rsa_gettable_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS;
      method:(code:@rsa_set_ctx_md_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS;
      method:(code:@rsa_settable_ctx_md_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);


  padding_item: array[0..4] of TOSSL_ITEM = (
    (id:  RSA_PKCS1_PADDING;        ptr: OSSL_PKEY_RSA_PAD_MODE_PKCSV15 ),
    (id:  RSA_NO_PADDING;           ptr: OSSL_PKEY_RSA_PAD_MODE_NONE ),
    (id:  RSA_X931_PADDING;         ptr: OSSL_PKEY_RSA_PAD_MODE_X931 ),
    (id:  RSA_PKCS1_PSS_PADDING;    ptr: OSSL_PKEY_RSA_PAD_MODE_PSS ),
    (id:  0;                        ptr: nil     )
);
 var
   known_gettable_ctx_params, settable_ctx_params,
   settable_ctx_params_no_digest: array of TOSSL_PARAM ;

 //function rsa_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;

implementation
uses  OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.providers.fips.self_test, OpenSSL3.openssl.params,
     OpenSSL3.providers.common.der.der_rsa_sig, openssl3.crypto.rsa.rsa_pss,
     OpenSSL3.providers.common.der.der_rsa_key, openssl3.crypto.rsa.rsa_lib,
     OpenSSL3.providers.common.securitycheck_default,
     OpenSSL3.crypto.rsa.rsa_crpt, openssl3.crypto.bio.bio_print,
     openssl3.crypto.rsa_schemes,  openssl3.crypto.rsa.rsa_sign,
     openssl3.crypto.rsa.rsa_saos, OpenSSL3.crypto.rsa.rsa_x931;

function rsa_pss_restricted(const prsactx : PPROV_RSA_CTX): Boolean;
begin
  Result := (prsactx.min_saltlen <> -1)
end;

function rsa_get_md_size(const prsactx : PPROV_RSA_CTX):size_t;
begin
    if prsactx.md <> nil then
       Exit(EVP_MD_get_size(prsactx.md));
    Result := 0;
end;


function rsa_check_padding(const prsactx : PPROV_RSA_CTX; mdname, mgf1_mdname : PUTF8Char; mdnid : integer):integer;
begin
    case prsactx.pad_mode of
        RSA_NO_PADDING:
            if (mdname <> nil)  or  (mdnid <> NID_undef) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
                Exit(0);
            end;

        RSA_X931_PADDING:
            if RSA_X931_hash_id(mdnid)= -1  then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_X931_DIGEST);
                Exit(0);
            end;

        RSA_PKCS1_PSS_PADDING:
            if rsa_pss_restricted(prsactx)  then
                if (mdname <> nil)  and  (not EVP_MD_is_a(prsactx.md, mdname))
                     or ( (mgf1_mdname <> nil)
                         and  (not EVP_MD_is_a(prsactx.mgf1_md, mgf1_mdname))) then
                begin
                    ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
                    Exit(0);
                end;

        else
            begin
              //
            end;
    end;
    Result := 1;
end;


function rsa_check_parameters( prsactx : PPROV_RSA_CTX; min_saltlen : integer):integer;
var
  max_saltlen : integer;
begin
    if prsactx.pad_mode = RSA_PKCS1_PSS_PADDING then
    begin
        { See if minimum salt length exceeds maximum possible }
        max_saltlen := RSA_size(prsactx.rsa) - EVP_MD_get_size(prsactx.md);
        if (_RSA_bits(prsactx.rsa) and $7) = 1 then
           Dec(max_saltlen);
        if (min_saltlen < 0)  or  (min_saltlen > max_saltlen) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            Exit(0);
        end;
        prsactx.min_saltlen := min_saltlen;
    end;
    Result := 1;
end;


function rsa_newctx(provctx : Pointer;const propq : PUTF8Char):Pointer;
var
    prsactx    : PPROV_RSA_CTX;

    propq_copy : PUTF8Char;
begin
    prsactx := nil;
    propq_copy := nil;
    if not ossl_prov_is_running( )then
        Exit(nil);
    prsactx := OPENSSL_zalloc(sizeof(TPROV_RSA_CTX) );
    OPENSSL_strdup(propq_copy ,propq);
    if (prsactx = nil)
         or ( (propq <> nil)
             and  (propq_copy = nil)) then
    begin
        OPENSSL_free(Pointer(prsactx));
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    prsactx.libctx := PROV_LIBCTX_OF(provctx);
    prsactx.flag_allow_md := 1;
    prsactx.propq := propq_copy;
    { Maximum for sign, auto for verify }
    prsactx.saltlen := RSA_PSS_SALTLEN_AUTO;
    prsactx.min_saltlen := -1;
    Result := prsactx;
end;


function rsa_pss_compute_saltlen( ctx : PPROV_RSA_CTX):integer;
var
  saltlen : integer;
begin
    saltlen := ctx.saltlen;
    if saltlen = RSA_PSS_SALTLEN_DIGEST then
    begin
        saltlen := EVP_MD_get_size(ctx.md);
    end
    else
    if (saltlen = RSA_PSS_SALTLEN_AUTO)  or  (saltlen = RSA_PSS_SALTLEN_MAX) then
    begin
        saltlen := RSA_size(ctx.rsa) - EVP_MD_get_size(ctx.md) - 2;
        if (_RSA_bits(ctx.rsa) and $7) = 1 then
            Dec(saltlen);
    end;
    if saltlen < 0 then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(-1);
    end
    else
    if (saltlen < ctx.min_saltlen) then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL,
                     Format('minimum salt length: %d, actual salt length: %d',
                       [ctx.min_saltlen, saltlen]));
        Exit(-1);
    end;
    Result := saltlen;
end;


function rsa_generate_signature_aid( ctx : PPROV_RSA_CTX; aid_buf : PByte; buf_len : size_t; aid_len : Psize_t):PByte;
var
    pkt        : TWPACKET;

    aid        : PByte;

    saltlen    : integer;

    pss_params : TRSA_PSS_PARAMS_30;

    ret        : integer;
    label _cleanup;
begin
    aid := nil;
    if 0>= WPACKET_init_der(@pkt, aid_buf, buf_len)  then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;

    case ctx.pad_mode of
    RSA_PKCS1_PADDING:
    begin
        ret := ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption(@pkt, -1,
                                                                 ctx.mdnid);
        if ret > 0 then
        begin
            //break;
        end
        else if (ret = 0) then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto _cleanup ;
        end;
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       Format('Algorithm ID generation - md NID: %d',
                       [ctx.mdnid]) );
        goto _cleanup ;
    end;
    RSA_PKCS1_PSS_PADDING:
    begin

        saltlen := rsa_pss_compute_saltlen(ctx);
        if saltlen < 0 then
           goto _cleanup ;
        if (0>= ossl_rsa_pss_params_30_set_defaults(@pss_params))  or
           (0>= ossl_rsa_pss_params_30_set_hashalg(@pss_params, ctx.mdnid))
             or  (0>= ossl_rsa_pss_params_30_set_maskgenhashalg(@pss_params,
                                                          ctx.mgf1_mdnid))
             or  (0>= ossl_rsa_pss_params_30_set_saltlen(@pss_params, saltlen))
             or  (0>= ossl_DER_w_algorithmIdentifier_RSA_PSS(@pkt, -1,
                                                       RSA_FLAG_TYPE_RSASSAPSS,
                                                       @pss_params))  then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto _cleanup ;
        end;
    end;
    else
    begin
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                      Format( 'Algorithm ID generation - pad mode: %d',
                       [ctx.pad_mode]));
        goto _cleanup ;
    end;
    end;
    if WPACKET_finish(@pkt)>0  then
    begin
        WPACKET_get_total_written(@pkt, aid_len);
        aid := WPACKET_get_curr(@pkt);
    end;
 _cleanup:
    WPACKET_cleanup(@pkt);
    Result := aid;
end;


function rsa_setup_md(ctx : PPROV_RSA_CTX; mdname, mdprops : PUTF8Char):integer;
var
  md           : PEVP_MD;
  sha1_allowed : Boolean;
  md_nid       : integer;
  mdname_len   : size_t;
  pc: PUTF8Char;
begin
    if mdprops = nil then mdprops := ctx.propq;
    if mdname <> nil then
    begin
        md := EVP_MD_fetch(ctx.libctx, mdname, mdprops);
        sha1_allowed := (ctx.operation <> EVP_PKEY_OP_SIGN);
        md_nid := ossl_digest_rsa_sign_get_md_nid(ctx.libctx, md,
                                                     Int(sha1_allowed));
        mdname_len := Length(mdname);
        if (md = nil)
             or  (md_nid <= 0)
             or ( (0>= rsa_check_padding(ctx, mdname, nil, md_nid))  or
                  (mdname_len >= sizeof(ctx.mdname)) ) then
        begin
            if md = nil then
               ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                              Format( '%s could not be fetched', [mdname]));
            if md_nid <= 0 then
               ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                             Format('digest=%s', [mdname]));
            if mdname_len >= sizeof(ctx.mdname) then
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
        if 0>= ctx.mgf1_md_set then
        begin
            if 0>= EVP_MD_up_ref(md) then
            begin
                EVP_MD_free(md);
                Exit(0);
            end;
            EVP_MD_free(ctx.mgf1_md);
            ctx.mgf1_md := md;
            ctx.mgf1_mdnid := md_nid;
            pc := @ctx.mgf1_mdname;
            OPENSSL_strlcpy(pc{ctx.mgf1_mdname}, mdname, sizeof(ctx.mgf1_mdname));
        end;
        EVP_MD_CTX_free(ctx.mdctx);
        EVP_MD_free(ctx.md);
        ctx.mdctx := nil;
        ctx.md := md;
        ctx.mdnid := md_nid;
        pc := ctx.mdname;
        OPENSSL_strlcpy(pc{ctx.mdname}, mdname, sizeof(ctx.mdname));
    end;
    Result := 1;
end;


function rsa_setup_mgf1_md(ctx : PPROV_RSA_CTX; mdname, mdprops : PUTF8Char):integer;
var
  len : size_t;
  md : PEVP_MD;
  mdnid : integer;
  pc: PUTF8Char ;
begin
    md := nil;
    if mdprops = nil then mdprops := ctx.propq;
    md := EVP_MD_fetch(ctx.libctx, mdname, mdprops );
    if md = nil then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                      Format( '%s could not be fetched', [mdname]));
        Exit(0);
    end;
    { The default for mgf1 is SHA1 - so allow SHA1 }
    mdnid := ossl_digest_rsa_sign_get_md_nid(ctx.libctx, md, 1);
    if (mdnid  <= 0)
         or  (0>= rsa_check_padding(ctx, nil, mdname, mdnid)) then
    begin
        if mdnid <= 0 then
            ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                          Format( 'digest=%s', [mdname]));
        EVP_MD_free(md);
        Exit(0);
    end;
    pc := @ctx.mgf1_mdname;
    len := OPENSSL_strlcpy(pc{ctx.mgf1_mdname}, mdname, sizeof(ctx.mgf1_mdname));
    if len >= sizeof(ctx.mgf1_mdname )then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                      Format( '%s exceeds name buffer length', [mdname]));
        EVP_MD_free(md);
        Exit(0);
    end;
    EVP_MD_free(ctx.mgf1_md);
    ctx.mgf1_md := md;
    ctx.mgf1_mdnid := mdnid;
    ctx.mgf1_md_set := 1;
    Result := 1;
end;


function rsa_signverify_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  prsactx     : PPROV_RSA_CTX;
  pss         : PRSA_PSS_PARAMS_30;
  pc: PUTF8Char;
  md_nid,
  mgf1md_nid,
  min_saltlen : integer;
  mdname,
  mgf1mdname  : PUTF8Char;
  len         : size_t;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if (not ossl_prov_is_running)   or  (prsactx = nil)then
        Exit(0);
    if (vrsa = nil)  and  (prsactx.rsa = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if vrsa <> nil then
    begin
        if 0>= ossl_rsa_check_key(prsactx.libctx, vrsa, operation) then
            Exit(0);
        if 0>= RSA_up_ref(vrsa) then
            Exit(0);
        RSA_free(prsactx.rsa);
        prsactx.rsa := vrsa;
    end;
    prsactx.operation := operation;
    { Maximum for sign, auto for verify }
    prsactx.saltlen := RSA_PSS_SALTLEN_AUTO;
    prsactx.min_saltlen := -1;
    case (RSA_test_flags(prsactx.rsa, RSA_FLAG_TYPE_MASK)) of
    RSA_FLAG_TYPE_RSA:
        prsactx.pad_mode := RSA_PKCS1_PADDING;
        //break;
    RSA_FLAG_TYPE_RSASSAPSS:
    begin
        prsactx.pad_mode := RSA_PKCS1_PSS_PADDING;
        begin
             pss := ossl_rsa_get0_pss_params_30(prsactx.rsa);
            if 0>= ossl_rsa_pss_params_30_is_unrestricted(pss) then
            begin
                md_nid := ossl_rsa_pss_params_30_hashalg(pss);
                mgf1md_nid := ossl_rsa_pss_params_30_maskgenhashalg(pss);
                min_saltlen := ossl_rsa_pss_params_30_saltlen(pss);
                mdname := ossl_rsa_oaeppss_nid2name(md_nid);
                mgf1mdname := ossl_rsa_oaeppss_nid2name(mgf1md_nid);
                if mdname = nil then
                begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                   format('PSS restrictions lack hash algorithm',[]));
                    Exit(0);
                end;
                if mgf1mdname = nil then
                begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                   'PSS restrictions lack MGF1 hash algorithm');
                    Exit(0);
                end;
                pc := @prsactx.mdname;
                len := OPENSSL_strlcpy(pc{prsactx.mdname}, mdname,
                                      sizeof(prsactx.mdname));
                if len >= sizeof(prsactx.mdname) then
                begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                   Format('hash algorithm name too long',[]));
                    Exit(0);
                end;
                pc:= @prsactx.mgf1_mdname;
                len := OPENSSL_strlcpy(pc{prsactx.mgf1_mdname}, mgf1mdname,
                                      sizeof(prsactx.mgf1_mdname));
                if len >= sizeof(prsactx.mgf1_mdname) then
                begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                  Format( 'MGF1 hash algorithm name too long',[]));
                    Exit(0);
                end;
                prsactx.saltlen := min_saltlen;
                { call rsa_setup_mgf1_md before rsa_setup_md to avoid duplication }
                if (0>= rsa_setup_mgf1_md(prsactx, mgf1mdname, prsactx.propq))  or
                   (0>= rsa_setup_md(prsactx, mdname, prsactx.propq))
                     or  (0>= rsa_check_parameters(prsactx, min_saltlen))  then
                    Exit(0);
            end;
        end;
    end;
    else
    begin
        ERR_raise(ERR_LIB_RSA, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(0);
    end;
    end;
    if 0>= rsa_set_ctx_params(prsactx, params )then
        Exit(0);
    Result := 1;
end;


function setup_tbuf( ctx : PPROV_RSA_CTX):integer;
begin
    if ctx.tbuf <> nil then Exit(1);
    ctx.tbuf := OPENSSL_malloc(RSA_size(ctx.rsa));
    if ctx.tbuf  = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;


procedure clean_tbuf( ctx : PPROV_RSA_CTX);
begin
    if ctx.tbuf <> nil then OPENSSL_cleanse(ctx.tbuf, RSA_size(ctx.rsa));
end;


procedure free_tbuf( ctx : PPROV_RSA_CTX);
begin
    clean_tbuf(ctx);
    OPENSSL_free(Pointer(ctx.tbuf));
    ctx.tbuf := nil;
end;


function rsa_sign_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running() then
        Exit(0);
    Result := rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
end;


function rsa_sign(vprsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX;

  ret : integer;

  rsasize, mdsize : size_t;

  sltmp : uint32;
  label _end;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    rsasize := RSA_size(prsactx.rsa);
    mdsize := rsa_get_md_size(prsactx);
    if not ossl_prov_is_running then
        Exit(0);
    if sig = nil then
    begin
        siglen^ := rsasize;
        Exit(1);
    end;
    if sigsize < rsasize then
    begin
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                      Format( 'is %zu, should be at least %zu', [sigsize, rsasize]));
        Exit(0);
    end;
    if mdsize <> 0 then
    begin
        if tbslen <> mdsize then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
            Exit(0);
        end;
{$IFNDEF FIPS_MODULE}
        if EVP_MD_is_a(prsactx.md, OSSL_DIGEST_NAME_MDC2)  then
        begin
            if prsactx.pad_mode <> RSA_PKCS1_PADDING then
            begin
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                              Format( 'only PKCS#1 padding supported with MDC2',[]));
                Exit(0);
            end;
            ret := RSA_sign_ASN1_OCTET_STRING(0, tbs, tbslen, sig, @sltmp,
                                             prsactx.rsa);
            if ret <= 0 then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                Exit(0);
            end;
            ret := sltmp;
            goto _end ;
        end;
{$ENDIF}
        case prsactx.pad_mode of
        RSA_X931_PADDING:
        begin
            if size_t(RSA_size(prsactx.rsa)) < tbslen + 1 then
            begin
                ERR_raise_data(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL,
                             Format(  'RSA key size = %d, expected minimum = %d',
                               [RSA_size(prsactx.rsa), tbslen + 1]));
                Exit(0);
            end;
            if 0>= setup_tbuf(prsactx)  then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            memcpy(prsactx.tbuf, tbs, tbslen);
            prsactx.tbuf[tbslen] := RSA_X931_hash_id(prsactx.mdnid);
            ret := RSA_private_encrypt(tbslen + 1, prsactx.tbuf,
                                      sig, prsactx.rsa, RSA_X931_PADDING);
            clean_tbuf(prsactx);
        end;
        RSA_PKCS1_PADDING:
        begin
            ret := _RSA_sign(prsactx.mdnid, tbs, tbslen, sig, @sltmp,
                           prsactx.rsa);
            if ret <= 0 then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                Exit(0);
            end;
            ret := sltmp;
        end;

        RSA_PKCS1_PSS_PADDING:
        begin
            { Check PSS restrictions }
            if rsa_pss_restricted(prsactx ) then
            begin
                case prsactx.saltlen of
                RSA_PSS_SALTLEN_DIGEST:
                    if prsactx.min_saltlen > EVP_MD_get_size(prsactx.md) then
                    begin
                        ERR_raise_data(ERR_LIB_PROV,
                                       PROV_R_PSS_SALTLEN_TOO_SMALL,
                                      Format( 'minimum salt length set to %d, '+
                                       'but the digest only gives %d',
                                       [prsactx.min_saltlen,
                                       EVP_MD_get_size(prsactx.md)]));
                        Exit(0);
                    end;
                    { FALLTHRU }
                else
                    if (prsactx.saltlen >= 0)
                         and  (prsactx.saltlen < prsactx.min_saltlen) then
                    begin
                        ERR_raise_data(ERR_LIB_PROV,
                                       PROV_R_PSS_SALTLEN_TOO_SMALL,
                                     Format('minimum salt length set to %d, but the'+
                                       'actual salt length is only set to %d',
                                       [prsactx.min_saltlen,
                                       prsactx.saltlen]));
                        Exit(0);
                    end;

                end;
            end;
            if 0>= setup_tbuf(prsactx )then
                Exit(0);
            if 0>= RSA_padding_add_PKCS1_PSS_mgf1(prsactx.rsa,
                                                prsactx.tbuf, tbs,
                                                prsactx.md, prsactx.mgf1_md,
                                                prsactx.saltlen  )then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                Exit(0);
            end;
            ret := RSA_private_encrypt(RSA_size(prsactx.rsa), prsactx.tbuf,
                                      sig, prsactx.rsa, RSA_NO_PADDING);
            clean_tbuf(prsactx);
        end;
        else
        begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                       Format('Only X.931, PKCS#1 v1.5 or PSS padding allowed',[]));
            Exit(0);
        end;
        end;
    end
    else
    begin
        ret := RSA_private_encrypt(tbslen, tbs, sig, prsactx.rsa,
                                  prsactx.pad_mode);
    end;
{$IFNDEF FIPS_MODULE}
 _end:
{$ENDIF}
    if ret <= 0 then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
        Exit(0);
    end;
    siglen^ := ret;
    Result := 1;
end;


function rsa_verify_recover_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running( )then
        Exit(0);
    Exit(rsa_signverify_init(vprsactx, vrsa, params,
                               EVP_PKEY_OP_VERIFYRECOVER));
end;


function rsa_verify_recover(vprsactx : Pointer; rout : PByte; routlen : Psize_t; routsize : size_t;const sig : PByte; siglen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX;

  ret : integer;

  sltmp : size_t;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if not ossl_prov_is_running() then
        Exit(0);
    if rout = nil then
    begin
        routlen^ := RSA_size(prsactx.rsa);
        Exit(1);
    end;
    if prsactx.md <> nil then
    begin
      case prsactx.pad_mode of
        RSA_X931_PADDING:
        begin
            if 0>= setup_tbuf(prsactx) then
                Exit(0);
            ret := RSA_public_decrypt(siglen, sig, prsactx.tbuf, prsactx.rsa,
                                     RSA_X931_PADDING);
            if ret < 1 then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                Exit(0);
            end;
            Dec(ret);
            if prsactx.tbuf[ret] <> RSA_X931_hash_id(prsactx.mdnid)  then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
                Exit(0);
            end;
            if ret <> EVP_MD_get_size(prsactx.md)  then
            begin
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                          Format('Should be %d, but got %d',
                               [EVP_MD_get_size(prsactx.md), ret]));
                Exit(0);
            end;
            routlen^ := ret;
            if rout <> prsactx.tbuf then
            begin
                if routsize < size_t(ret) then
                begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                                 Format('buffer size is %d, should be %d',
                                   [routsize, ret]));
                    Exit(0);
                end;
                memcpy(rout, prsactx.tbuf, ret);
            end;
        end;
        RSA_PKCS1_PADDING:
        begin
            ret := ossl_rsa_verify(prsactx.mdnid, nil, 0, rout, @sltmp,
                                  sig, siglen, prsactx.rsa);
            if ret <= 0 then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                Exit(0);
            end;
            ret := sltmp;
        end;

        else
        begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           'Only X.931 or PKCS#1 v1.5 padding allowed');
            Exit(0);
        end;
      end;
    end
    else
    begin
        ret := RSA_public_decrypt(siglen, sig, rout, prsactx.rsa,
                                 prsactx.pad_mode);
        if ret < 0 then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
            Exit(0);
        end;
    end;
    routlen^ := ret;
    Result := 1;
end;


function rsa_verify_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running( )then
        Exit(0);
    Result := rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);
end;


function rsa_verify(vprsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX;

  rslen : size_t;

  ret : integer;

  mdsize : size_t;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if not ossl_prov_is_running() then
        Exit(0);
    if prsactx.md <> nil then
    begin
      case prsactx.pad_mode of
        RSA_PKCS1_PADDING:
        begin
            if 0>= _RSA_verify(prsactx.mdnid, tbs, tbslen, sig, siglen,
                            prsactx.rsa) then
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                Exit(0);
            end;
            Exit(1);
        end;
        RSA_X931_PADDING:
        begin
            if 0>= setup_tbuf(prsactx)  then
                Exit(0);
            if rsa_verify_recover(prsactx, prsactx.tbuf, @rslen, 0,
                                   sig, siglen)<= 0 then
                Exit(0);
        end;
        RSA_PKCS1_PSS_PADDING:
            begin
                {
                 * We need to check this for the RSA_verify_PKCS1_PSS_mgf1()
                 * call
                 }
                mdsize := rsa_get_md_size(prsactx);
                if tbslen <> mdsize then begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                                 Format(  'Should be %d, but got %d',
                                   [mdsize, tbslen]));
                    Exit(0);
                end;
                if 0>= setup_tbuf(prsactx )then
                    Exit(0);
                ret := RSA_public_decrypt(siglen, sig, prsactx.tbuf,
                                         prsactx.rsa, RSA_NO_PADDING);
                if ret <= 0 then begin
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    Exit(0);
                end;
                ret := RSA_verify_PKCS1_PSS_mgf1(prsactx.rsa, tbs,
                                                prsactx.md, prsactx.mgf1_md,
                                                prsactx.tbuf,
                                                prsactx.saltlen);
                if ret <= 0 then begin
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    Exit(0);
                end;
                Exit(1);
            end;
        else
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           'Only X.931, PKCS#1 v1.5 or PSS padding allowed');
            Exit(0);
        end;
    end
    else
    begin
        if 0>= setup_tbuf(prsactx) then
            Exit(0);
        rslen := RSA_public_decrypt(siglen, sig, prsactx.tbuf, prsactx.rsa,
                                   prsactx.pad_mode);
        if rslen = 0 then
        begin
            ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
            Exit(0);
        end;
    end;
    if (rslen <> tbslen)  or  (memcmp(tbs, prsactx.tbuf, rslen)>0) then
        Exit(0);
    Result := 1;
end;


function rsa_digest_signverify_init(vprsactx : Pointer;const mdname : PUTF8Char; vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  prsactx : PPROV_RSA_CTX;
  label _error;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if not ossl_prov_is_running() then
        Exit(0);
    if 0>= rsa_signverify_init(vprsactx, vrsa, params, operation) then
        Exit(0);
    if (mdname <> nil)
        { was rsa_setup_md already called in rsa_signverify_init( then ? }
         and  ( (mdname[0] = #0)  or  (strcasecmp(prsactx.mdname, mdname) <> 0))
         and  (0>= rsa_setup_md(prsactx, mdname, prsactx.propq))then
        Exit(0);
    prsactx.flag_allow_md := 0;
    if prsactx.mdctx = nil then
    begin
        prsactx.mdctx := EVP_MD_CTX_new();
        if prsactx.mdctx = nil then
           goto _error ;
    end;
    if 0>= EVP_DigestInit_ex2(prsactx.mdctx, prsactx.md, params) then
        goto _error ;
    Exit(1);
 _error:
    EVP_MD_CTX_free(prsactx.mdctx);
    prsactx.mdctx := nil;
    Result := 0;
end;


function rsa_digest_signverify_update(vprsactx : Pointer;const data : PByte; datalen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if (prsactx = nil)  or  (prsactx.mdctx = nil) then Exit(0);
    Result := EVP_DigestUpdate(prsactx.mdctx, data, datalen);
end;


function rsa_digest_sign_init(vprsactx : Pointer;const mdname : PUTF8Char; vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running( )then
        Exit(0);
    Exit(rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                      params, EVP_PKEY_OP_SIGN));
end;


function rsa_digest_sign_final( vprsactx : Pointer; sig : PByte; siglen : Psize_t; sigsize : size_t):integer;
var
  prsactx : PPROV_RSA_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    dlen := 0;
    if (not ossl_prov_is_running) or  (prsactx = nil) then
        Exit(0);
    prsactx.flag_allow_md := 1;
    if prsactx.mdctx = nil then Exit(0);
    {
     * If sig is nil then we're just finding out the sig size. Other fields
     * are ignored. Defer to rsa_sign.
     }
    if sig <> nil then
    begin
        {
         * The digests used here are all known (see rsa_get_md_nid()), so they
         * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
         }
        if 0>= EVP_DigestFinal_ex(prsactx.mdctx, @digest, @dlen) then
            Exit(0);
    end;
    Result := rsa_sign(vprsactx, sig, siglen, sigsize, @digest, size_t(dlen));
end;


function rsa_digest_verify_init(vprsactx : Pointer;const mdname : PUTF8Char; vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    if not ossl_prov_is_running()  then
        Exit(0);
    Exit(rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                      params, EVP_PKEY_OP_VERIFY));
end;


function rsa_digest_verify_final(vprsactx : Pointer;const sig : PByte; siglen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX;

  digest : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  dlen : uint32;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    dlen := 0;
    if not ossl_prov_is_running()  then
        Exit(0);
    if prsactx = nil then Exit(0);
    prsactx.flag_allow_md := 1;
    if prsactx.mdctx = nil then Exit(0);
    {
     * The digests used here are all known (see rsa_get_md_nid()), so they
     * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
     }
    if 0>= EVP_DigestFinal_ex(prsactx.mdctx, @digest, @dlen )then
        Exit(0);
    Result := rsa_verify(vprsactx, sig, siglen, @digest, size_t(dlen));
end;


procedure rsa_freectx( vprsactx : Pointer);
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if prsactx = nil then exit;
    EVP_MD_CTX_free(prsactx.mdctx);
    EVP_MD_free(prsactx.md);
    EVP_MD_free(prsactx.mgf1_md);
    OPENSSL_free(Pointer(prsactx.propq));
    free_tbuf(prsactx);
    RSA_free(prsactx.rsa);
    OPENSSL_clear_free(Pointer(prsactx), sizeof( prsactx^));
end;


function rsa_dupctx( vprsactx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_RSA_CTX;
  label _err;
begin
    srcctx := PPROV_RSA_CTX ( vprsactx);
    if not ossl_prov_is_running() then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    dstctx^ := srcctx^;
    dstctx.rsa := nil;
    dstctx.md := nil;
    dstctx.mdctx := nil;
    dstctx.tbuf := nil;
    dstctx.propq := nil;
    if (srcctx.rsa <> nil)  and  (0>= RSA_up_ref(srcctx.rsa)) then
        goto _err ;
    dstctx.rsa := srcctx.rsa;
    if (srcctx.md <> nil)  and  (0>= EVP_MD_up_ref(srcctx.md) ) then
        goto _err ;
    dstctx.md := srcctx.md;
    if (srcctx.mgf1_md <> nil)  and  (0>= EVP_MD_up_ref(srcctx.mgf1_md) ) then
        goto _err ;
    dstctx.mgf1_md := srcctx.mgf1_md;
    if srcctx.mdctx <> nil then
    begin
        dstctx.mdctx := EVP_MD_CTX_new();
        if (dstctx.mdctx = nil)
                 or  (0>= EVP_MD_CTX_copy_ex(dstctx.mdctx, srcctx.mdctx) ) then
            goto _err ;
    end;
    if srcctx.propq <> nil then
    begin
        OPENSSL_strdup(dstctx.propq ,srcctx.propq);
        if dstctx.propq = nil then goto _err ;
    end;
    Exit(dstctx);
 _err:
    rsa_freectx(dstctx);
    Result := nil;
end;


function rsa_get_ctx_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
var
  prsactx : PPROV_RSA_CTX;

  p : POSSL_PARAM;

  aid_buf : array[0..127] of Byte;

  aid : PByte;

  aid_len : size_t;

  i : integer;

  word, value : PUTF8Char;

  len : integer;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if prsactx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if p <> nil then
    begin
        { The Algorithm Identifier of the combined signature algorithm }
        aid := rsa_generate_signature_aid(prsactx, @aid_buf,
                                         sizeof(aid_buf), @aid_len);
        if (aid = nil)  or  (0>= OSSL_PARAM_set_octet_string(p, aid, aid_len)) then
            Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if p <> nil then
    case p.data_type of
        OSSL_PARAM_INTEGER:
            if 0>= OSSL_PARAM_set_int(p, prsactx.pad_mode) then
                Exit(0);
            //break;
        OSSL_PARAM_UTF8_STRING:
        begin
            word := nil;
            i := 0;
            while (padding_item[i].id <> 0) do
            begin
                if prsactx.pad_mode = int(padding_item[i].id) then
                begin
                    word := padding_item[i].ptr;
                    break;
                end;
                Inc(i);
            end;
            if word <> nil then
            begin
                if 0>= OSSL_PARAM_set_utf8_string(p, word) then
                    Exit(0);
            end
            else
            begin
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            end;
        end;

        else
            Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_string(p, prsactx.mdname )) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_utf8_string(p, prsactx.mgf1_mdname )) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if p <> nil then
    begin
        if p.data_type = OSSL_PARAM_INTEGER then
        begin
            if 0>= OSSL_PARAM_set_int(p, prsactx.saltlen) then
                Exit(0);
        end
        else
        if (p.data_type = OSSL_PARAM_UTF8_STRING) then
        begin
             value := nil;
            case prsactx.saltlen of
            RSA_PSS_SALTLEN_DIGEST:
                value := OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;

            RSA_PSS_SALTLEN_MAX:
                value := OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;

            RSA_PSS_SALTLEN_AUTO:
                value := OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;

            else
                begin
                    len := BIO_snprintf(p.data, p.data_size, '%d',
                                           [prsactx.saltlen]);
                    if len <= 0 then Exit(0);
                    p.return_size := len;

                end;
            end;
            if (value <> nil)
                 and  (0>= OSSL_PARAM_set_utf8_string(p, value )) then
                Exit(0);
        end;
    end;
    Result := 1;
end;


function rsa_gettable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params[0];
end;


function rsa_set_ctx_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
var
    prsactx        : PPROV_RSA_CTX;
    pad_mode,
    saltlen        : integer;
    mdname         : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8Char;
    pmdname        : PUTF8Char;
    mdprops        : array[0..(OSSL_MAX_PROPQUERY_SIZE)-1] of UTF8Char;
    pmdprops       : PUTF8Char;
    mgf1mdname     : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8Char;
    pmgf1mdname    : PUTF8Char;
    mgf1mdprops    : array[0..(OSSL_MAX_PROPQUERY_SIZE)-1] of byte;
    pmgf1mdprops   : PUTF8Char;
    propsp,p       : POSSL_PARAM;
    err_extra_text : PUTF8Char;
    i              : integer;
    label _bad_pad, _cont;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    mdname := '';
    pmdname := nil;
    Fillchar (mdprops, OSSL_MAX_PROPQUERY_SIZE-1, #0);
    pmdprops := nil;
    Fillchar (mgf1mdname, OSSL_MAX_NAME_SIZE-1,#0);
    pmgf1mdname := nil;
    Fillchar (mgf1mdprops, OSSL_MAX_PROPQUERY_SIZE-1, #0);
    pmgf1mdprops := nil;
    if prsactx = nil then Exit(0);
    if params = nil then Exit(1);
    pad_mode := prsactx.pad_mode;
    saltlen := prsactx.saltlen;
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if p <> nil then
    begin
         propsp := OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);
        pmdname := mdname;
        if 0>= OSSL_PARAM_get_utf8_string(p, @pmdname, sizeof(mdname)) then
            Exit(0);
        if propsp <> nil then
        begin
            pmdprops := mdprops;
            if 0>= OSSL_PARAM_get_utf8_string(propsp, @pmdprops, sizeof(mdprops))  then
                Exit(0);
        end;
    end;

    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if p <> nil then
    begin
      err_extra_text := nil;
      case p.data_type of
        OSSL_PARAM_INTEGER:  { Support for legacy pad mode number }
            if 0>= OSSL_PARAM_get_int(p, @pad_mode )then
                Exit(0);

        OSSL_PARAM_UTF8_STRING:
        begin
            if p.data = nil then Exit(0);
            i := 0;
            while ( padding_item[i].id <> 0)do
            begin
                if strcmp(p.data, padding_item[i].ptr) = 0 then
                begin
                    pad_mode := padding_item[i].id;
                    break;
                end;
                Inc(i);
            end;
        end;

        else
            Exit(0);
      end;

      case pad_mode of
        RSA_PKCS1_OAEP_PADDING:
        begin
            {
             * OAEP padding is for asymmetric cipher only so is not compatible
             * with signature use.
             }
            err_extra_text := 'OAEP padding not allowed for signing / verifying';
            goto _bad_pad ;
        end;
        RSA_PKCS1_PSS_PADDING:
            if (prsactx.operation >0)
                 and ( (EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY) = 0) then
            begin
                err_extra_text := 'PSS padding only allowed for sign and verify operations';
                goto _bad_pad ;
            end;

        RSA_PKCS1_PADDING:
        begin
            err_extra_text := 'PKCS#1 padding not allowed with RSA-PSS';
            goto _cont ;
        end;
        RSA_NO_PADDING:
        begin
            err_extra_text := 'No padding not allowed with RSA-PSS';
            goto _cont ;
        end;
        RSA_X931_PADDING:
        begin
            err_extra_text := 'X.931 padding not allowed with RSA-PSS';
        _cont:
            if RSA_test_flags(prsactx.rsa,
                               RSA_FLAG_TYPE_MASK) = RSA_FLAG_TYPE_RSA  then
            begin
              //
            end;
            { FALLTHRU }
        end;
        else
        begin
        _bad_pad:
            if err_extra_text = nil then
               ERR_raise(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE)
            else
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE,
                               err_extra_text);
            Exit(0);
        end;
      end;
    end;

    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if p <> nil then
    begin
        if pad_mode <> RSA_PKCS1_PSS_PADDING then
        begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                          Format( 'PSS saltlen can only be specified if '+
                           'PSS padding has been specified first',[]));
            Exit(0);
        end;
        case p.data_type of
        OSSL_PARAM_INTEGER:  { Support for legacy pad mode number }
            if 0>= OSSL_PARAM_get_int(p, @saltlen )then
                Exit(0);

        OSSL_PARAM_UTF8_STRING:
        begin
            if strcmp(p.data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST)= 0 then
                saltlen := RSA_PSS_SALTLEN_DIGEST
            else if (strcmp(p.data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) = 0)  then
                saltlen := RSA_PSS_SALTLEN_MAX
            else if (strcmp(p.data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) = 0) then
                saltlen := RSA_PSS_SALTLEN_AUTO
            else
                saltlen := StrToInt(PUTF8Char(p.data));
        end;
        else
            Exit(0);
        end;
        {
         * RSA_PSS_SALTLEN_MAX seems curiously named in this check.
         * Contrary to what it's name suggests, it's the currently
         * lowest saltlen number possible.
         }
        if saltlen < RSA_PSS_SALTLEN_MAX then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            Exit(0);
        end;
        if rsa_pss_restricted(prsactx )then
        begin
            case saltlen of
                RSA_PSS_SALTLEN_AUTO:
                if prsactx.operation = EVP_PKEY_OP_VERIFY then
                begin
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH,
                                   'Cannot use autodetected salt length');
                    Exit(0);
                end;
                //break;
                RSA_PSS_SALTLEN_DIGEST:
                if prsactx.min_saltlen > EVP_MD_get_size(prsactx.md)  then
                begin
                    ERR_raise_data(ERR_LIB_PROV,
                                   PROV_R_PSS_SALTLEN_TOO_SMALL,
                                  Format( 'Should be more than %d, but would be '+
                                   'set to match digest size (%d)',
                                   [prsactx.min_saltlen,
                                   EVP_MD_get_size(prsactx.md)]));
                    Exit(0);
                end;
                //break;
                else
                if (saltlen >= 0)  and  (saltlen < prsactx.min_saltlen) then
                begin
                    ERR_raise_data(ERR_LIB_PROV,
                                   PROV_R_PSS_SALTLEN_TOO_SMALL,
                                 Format(  'Should be more than %d, '+
                                   'but would be set to %d',
                                   [prsactx.min_saltlen, saltlen]));
                    Exit(0);
                end;
            end;
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if p <> nil then
    begin
        propsp := OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);
        pmgf1mdname := mgf1mdname;
        if 0>= OSSL_PARAM_get_utf8_string(p, @pmgf1mdname, sizeof(mgf1mdname)) then
            Exit(0);
        if propsp <> nil then
        begin
            pmgf1mdprops := @mgf1mdprops;
            if 0>= OSSL_PARAM_get_utf8_string(propsp,
                              @pmgf1mdprops, sizeof(mgf1mdprops)) then
                Exit(0);
        end;
        if pad_mode <> RSA_PKCS1_PSS_PADDING then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            Exit(0);
        end;
    end;
    prsactx.saltlen := saltlen;
    prsactx.pad_mode := pad_mode;
    if (prsactx.md = nil)  and  (pmdname = nil)
         and  (pad_mode = RSA_PKCS1_PSS_PADDING) then
         pmdname := RSA_DEFAULT_DIGEST_NAME;
    if (pmgf1mdname <> nil)
         and  (0>= rsa_setup_mgf1_md(prsactx, pmgf1mdname, pmgf1mdprops)) then
        Exit(0);
    if pmdname <> nil then
    begin
        if 0>= rsa_setup_md(prsactx, pmdname, pmdprops) then
            Exit(0);
    end
    else
    begin
        if 0>= rsa_check_padding(prsactx, nil, nil, prsactx.mdnid) then
            Exit(0);
    end;
    Result := 1;
end;


function rsa_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if (prsactx <> nil)  and  (0>= prsactx.flag_allow_md) then
       Exit(@settable_ctx_params_no_digest[0]);
    Result := @settable_ctx_params[0];
end;


function rsa_get_ctx_md_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if prsactx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_get_params(prsactx.mdctx, params);
end;


function rsa_gettable_ctx_md_params( vprsactx : Pointer):POSSL_PARAM;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if prsactx.md = nil then Exit(0);
    Result := EVP_MD_gettable_ctx_params(prsactx.md);
end;


function rsa_set_ctx_md_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if prsactx.mdctx = nil then Exit(0);
    Result := EVP_MD_CTX_set_params(prsactx.mdctx, params);
end;


function rsa_settable_ctx_md_params( vprsactx : Pointer):POSSL_PARAM;
var
  prsactx : PPROV_RSA_CTX;
begin
    prsactx := PPROV_RSA_CTX ( vprsactx);
    if prsactx.md = nil then Exit(0);
    Result := EVP_MD_settable_ctx_params(prsactx.md);
end;

 initialization
   known_gettable_ctx_params := [
    _OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nil, 0),
    OSSL_PARAM_END
];
  settable_ctx_params_no_digest := [
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nil, 0),
    OSSL_PARAM_END
];
 settable_ctx_params := [
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nil, 0),
    OSSL_PARAM_END
];
end.
