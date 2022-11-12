unit OpenSSL3.providers.implementations.signature.eddsa_sig;
{$I  config.inc}

interface
uses OpenSSL.Api, SysUtils;

function eddsa_newctx(provctx : Pointer;const propq_unused : PUTF8Char):Pointer;
  function eddsa_digest_signverify_init(vpeddsactx : Pointer;const mdname : PUTF8Char; vedkey : Pointer;const params : POSSL_PARAM):integer;
  function ed25519_digest_sign(vpeddsactx : Pointer; sigret : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
  function ed448_digest_sign(vpeddsactx : Pointer; sigret : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
  function ed25519_digest_verify(vpeddsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function ed448_digest_verify(vpeddsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  procedure eddsa_freectx( vpeddsactx : Pointer);
  function eddsa_dupctx( vpeddsactx : Pointer):Pointer;
  function eddsa_get_ctx_params( vpeddsactx : Pointer; params : POSSL_PARAM):integer;
  function eddsa_gettable_ctx_params( vpeddsactx, provctx : Pointer):POSSL_PARAM;
{$ifdef S390X_EC_ASM}
  function s390x_ed25519_digestsign(const edkey : PECX_KEY; sig : PByte;const tbs : PByte; tbslen : size_t):integer;
  function s390x_ed448_digestsign(const edkey : PECX_KEY; sig : PByte;const tbs : PByte; tbslen : size_t):integer;
  function s390x_ed25519_digestverify(const edkey : PECX_KEY; sig, tbs : PByte; tbslen : size_t):integer;
  function s390x_ed448_digestverify(const edkey : PECX_KEY; sig, tbs : PByte; tbslen : size_t):integer;
{$ENDIF}


const ossl_ed25519_signature_functions: array[0..9] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_SIGNATURE_NEWCTX; method:(code:@eddsa_newctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT;
      method:(code:@eddsa_digest_signverify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN;
      method:(code:@ed25519_digest_sign; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT;
      method:(code:@eddsa_digest_signverify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY;
      method:(code:@ed25519_digest_verify; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_FREECTX; method:(code:@eddsa_freectx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DUPCTX; method:(code:@eddsa_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS; method:(code:@eddsa_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS;
      method:(code:@eddsa_gettable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);
 ossl_ed448_signature_functions: array[0..9] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_SIGNATURE_NEWCTX; method:(code:@eddsa_newctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT;
      method:(code:@eddsa_digest_signverify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_SIGN;
      method:(code:@ed448_digest_sign; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT;
      method:(code:@eddsa_digest_signverify_init; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY;
      method:(code:@ed448_digest_verify; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_FREECTX; method:(code:@eddsa_freectx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_DUPCTX; method:(code:@eddsa_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS; method:(code:@eddsa_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS;
      method:(code:@eddsa_gettable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);

var
  known_gettable_ctx_params: array of TOSSL_PARAM ;

implementation
uses OpenSSL3.providers.common.securitycheck, openssl3.providers.common.provider_ctx,
     OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.packet,
     openssl3.crypto.evp.digest, openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     openssl3.providers.fips.self_test, OpenSSL3.openssl.params,
     OpenSSL3.providers.common.securitycheck_default, openssl3.crypto.ec.ecx_key,
     OpenSSL3.providers.common.der.der_ecx_key,
     OpenSSL3.providers.implementations.exchange.ecx_exch,
     openssl3.crypto.ec.curve25519, openssl3.crypto.ec.curve25519.eddsa,
     OpenSSL3.providers.common.der.der_ec_sig;





function eddsa_newctx(provctx : Pointer;const propq_unused : PUTF8Char):Pointer;
var
  peddsactx : PPROV_EDDSA_CTX;
begin
    if not ossl_prov_is_running() then
        Exit(nil);
    peddsactx := OPENSSL_zalloc(sizeof(TPROV_EDDSA_CTX));
    if peddsactx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    peddsactx.libctx := PROV_LIBCTX_OF(provctx);
    Result := peddsactx;
end;


function eddsa_digest_signverify_init(vpeddsactx : Pointer;const mdname : PUTF8Char; vedkey : Pointer;const params : POSSL_PARAM):integer;
var
    peddsactx : PPROV_EDDSA_CTX;

    edkey     : PECX_KEY;

    pkt       : TWPACKET;

    ret       : Boolean;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
    edkey := PECX_KEY(vedkey);
    if not ossl_prov_is_running() then
        Exit(0);
    if (mdname <> nil)  and  (mdname[0] <> #0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        Exit(0);
    end;
    if edkey = nil then
    begin
        if peddsactx.key <> nil then
            { there is nothing to do on reinit }
            Exit(1);
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        Exit(0);
    end;
    if 0>= ossl_ecx_key_up_ref(edkey)  then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    {
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     }
    peddsactx.aid_len := 0;
    ret := Boolean(WPACKET_init_der(@pkt, @peddsactx.aid_buf, sizeof(peddsactx.aid_buf)));
    case edkey.&type of
    ECX_KEY_TYPE_ED25519:
        ret := (ret)  and  (ossl_DER_w_algorithmIdentifier_ED25519(@pkt, -1, edkey)>0);
        //break;
    ECX_KEY_TYPE_ED448:
        ret := (ret)  and  (ossl_DER_w_algorithmIdentifier_ED448(@pkt, -1, edkey)>0);
        //break;
    else
    begin
        { Should never happen }
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ossl_ecx_key_free(edkey);
        Exit(0);
    end;
    end;
    if (ret)  and  (WPACKET_finish(@pkt)>0) then
    begin
        WPACKET_get_total_written(@pkt, @peddsactx.aid_len);
        peddsactx.aid := WPACKET_get_curr(@pkt);
    end;
    WPACKET_cleanup(@pkt);
    peddsactx.key := edkey;
    Result := 1;
end;


function ed25519_digest_sign(vpeddsactx : Pointer; sigret : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
var
    peddsactx : PPROV_EDDSA_CTX;

    edkey     : PECX_KEY;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
    edkey := peddsactx.key;
    if not ossl_prov_is_running() then
        Exit(0);
    if sigret = nil then
    begin
        siglen^ := ED25519_SIGSIZE;
        Exit(1);
    end;
    if sigsize < ED25519_SIGSIZE then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
{$IFDEF S390X_EC_ASM}
    if S390X_CAN_SIGN(ED25519 then )
        Exit(s390x_ed25519_digestsign(edkey, sigret, tbs, tbslen));
{$endif} { S390X_EC_ASM }
    if ossl_ed25519_sign(sigret, tbs, tbslen, @edkey.pubkey,
              edkey.privkey, peddsactx.libctx, nil) = 0  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        Exit(0);
    end;
    siglen^ := ED25519_SIGSIZE;
    Result := 1;
end;


function ed448_digest_sign(vpeddsactx : Pointer; sigret : PByte; siglen : Psize_t; sigsize : size_t;const tbs : PByte; tbslen : size_t):integer;
var
    peddsactx : PPROV_EDDSA_CTX;

    edkey     : PECX_KEY;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
    edkey := peddsactx.key;
    if not ossl_prov_is_running() then
        Exit(0);
    if sigret = nil then
    begin
        siglen^ := ED448_SIGSIZE;
        Exit(1);
    end;
    if sigsize < ED448_SIGSIZE then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
{$IFDEF S390X_EC_ASM}
    if S390X_CAN_SIGN(ED448 then )
        Exit(s390x_ed448_digestsign(edkey, sigret, tbs, tbslen));
{$endif} { S390X_EC_ASM }
    if ossl_ed448_sign(peddsactx.libctx, sigret, tbs, tbslen,
               @edkey.pubkey,{32}
               edkey.privkey{32}, nil, 0, edkey.propq) = 0  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        Exit(0);
    end;
    siglen^ := ED448_SIGSIZE;
    Result := 1;
end;


function ed25519_digest_verify(vpeddsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
    peddsactx : PPROV_EDDSA_CTX;

    edkey     : PECX_KEY;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
     edkey := peddsactx.key;
    if (not ossl_prov_is_running) or  (siglen <> ED25519_SIGSIZE) then
        Exit(0);
{$IFDEF S390X_EC_ASM}
    if S390X_CAN_SIGN(ED25519 then )
        Exit(s390x_ed25519_digestverify(edkey, sig, tbs, tbslen));
{$endif} { S390X_EC_ASM }
    Exit(ossl_ed25519_verify(tbs, tbslen, sig, @edkey.pubkey,
                               peddsactx.libctx, edkey.propq));
end;


function ed448_digest_verify(vpeddsactx : Pointer;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
    peddsactx : PPROV_EDDSA_CTX;

    edkey     : PECX_KEY;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
     edkey := peddsactx.key;
    if (not ossl_prov_is_running)  or  (siglen <> ED448_SIGSIZE) then
        Exit(0);
{$IFDEF S390X_EC_ASM}
    if S390X_CAN_SIGN(ED448)  then
        Exit(s390x_ed448_digestverify(edkey, sig, tbs, tbslen));
{$endif} { S390X_EC_ASM }
    Exit(ossl_ed448_verify(peddsactx.libctx, tbs, tbslen, sig, @edkey.pubkey,
                             nil, 0, edkey.propq));
end;


procedure eddsa_freectx( vpeddsactx : Pointer);
var
  peddsactx : PPROV_EDDSA_CTX;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
    ossl_ecx_key_free(peddsactx.key);
    OPENSSL_free(Pointer(peddsactx));
end;


function eddsa_dupctx( vpeddsactx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_EDDSA_CTX;
  label _err;
begin
    srcctx := PPROV_EDDSA_CTX ( vpeddsactx);
    if not ossl_prov_is_running()  then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    dstctx.key := nil;
    if (srcctx.key <> nil)  and  (0>= ossl_ecx_key_up_ref(srcctx.key)) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    dstctx.key := srcctx.key;
    Exit(dstctx);
 _err:
    eddsa_freectx(dstctx);
    Result := nil;
end;


function eddsa_get_ctx_params( vpeddsactx : Pointer; params : POSSL_PARAM):integer;
var
    peddsactx : PPROV_EDDSA_CTX;

    p         : POSSL_PARAM;
begin
    peddsactx := PPROV_EDDSA_CTX ( vpeddsactx);
    if peddsactx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_octet_string(p, peddsactx.aid,
                                                  peddsactx.aid_len) ) then
        Exit(0);
    Result := 1;
end;


function eddsa_gettable_ctx_params( vpeddsactx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params[0];
end;

{$ifdef S390X_EC_ASM}
function s390x_ed25519_digestsign(const edkey : PECX_KEY; sig : PByte;const tbs : PByte; tbslen : size_t):integer;
var
  rc : integer;

  sig : array[0..63] of Byte;

  priv : array[0..31] of Byte;

  buff : array[0..511] of uint64;
begin
    union begin
        struct begin
        end;
 ed25519;
    end;
 param;
    memset(&param, 0, sizeof(param));
    memcpy(param.ed25519.priv, edkey.privkey, sizeof(param.ed25519.priv));
    rc := s390x_kdsa(S390X_EDDSA_SIGN_ED25519, &param.ed25519, tbs, tbslen);
    OPENSSL_cleanse(param.ed25519.priv, sizeof(param.ed25519.priv));
    if rc <> 0 then Exit(0);
    s390x_flip_endian32(sig, param.ed25519.sig);
    s390x_flip_endian32(sig + 32, param.ed25519.sig + 32);
    Result := 1;
end;


function s390x_ed448_digestsign(const edkey : PECX_KEY; sig : PByte;const tbs : PByte; tbslen : size_t):integer;
var
  rc : integer;
  sig : array[0..127] of Byte;
  priv : array[0..63] of Byte;
  buff : array[0..511] of uint64;
begin
    union begin
        struct begin
        end;
 ed448;
    end;
 param;
    memset(&param, 0, sizeof(param));
    memcpy(param.ed448.priv + 64 - 57, edkey.privkey, 57);
    rc := s390x_kdsa(S390X_EDDSA_SIGN_ED448, &param.ed448, tbs, tbslen);
    OPENSSL_cleanse(param.ed448.priv, sizeof(param.ed448.priv));
    if rc <> 0 then Exit(0);
    s390x_flip_endian64(param.ed448.sig, param.ed448.sig);
    s390x_flip_endian64(param.ed448.sig + 64, param.ed448.sig + 64);
    memcpy(sig, param.ed448.sig, 57);
    memcpy(sig + 57, param.ed448.sig + 64, 57);
    Result := 1;
end;


function s390x_ed25519_digestverify(const edkey : PECX_KEY; sig, tbs : PByte; tbslen : size_t):integer;
var
  sig : array[0..63] of Byte;

  pub : array[0..31] of Byte;

  buff : array[0..511] of uint64;
begin
    union begin
        struct begin
        end;
 ed25519;
    end;
 param;
    memset(&param, 0, sizeof(param));
    s390x_flip_endian32(param.ed25519.sig, sig);
    s390x_flip_endian32(param.ed25519.sig + 32, sig + 32);
    s390x_flip_endian32(param.ed25519.pub, edkey.pubkey);
    Exit(s390x_kdsa(S390X_EDDSA_VERIFY_ED25519,);
                      &param.ed25519, tbs, tbslen) = 0 ? 1 : 0;
end;


function s390x_ed448_digestverify(const edkey : PECX_KEY; sig, tbs : PByte; tbslen : size_t):integer;
var
  sig : array[0..127] of Byte;

  pub : array[0..63] of Byte;

  buff : array[0..511] of uint64;
begin
    union begin
        struct begin
        end;
 ed448;
    end;
 param;
    memset(&param, 0, sizeof(param));
    memcpy(param.ed448.sig, sig, 57);
    s390x_flip_endian64(param.ed448.sig, param.ed448.sig);
    memcpy(param.ed448.sig + 64, sig + 57, 57);
    s390x_flip_endian64(param.ed448.sig + 64, param.ed448.sig + 64);
    memcpy(param.ed448.pub, edkey.pubkey, 57);
    s390x_flip_endian64(param.ed448.pub, param.ed448.pub);
    Exit(s390x_kdsa(S390X_EDDSA_VERIFY_ED448,);
                      &param.ed448, tbs, tbslen) = 0 ? 1 : 0;
end;
{$endif}

initialization
   known_gettable_ctx_params := [
    _OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, nil, 0),
    OSSL_PARAM_END
   ];
end.
