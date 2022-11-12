unit OpenSSL3.providers.implementations.exchange.ecx_exch;

interface
uses OpenSSL.Api, SysUtils;
function x25519_newctx( provctx : Pointer):Pointer;
  function x448_newctx( provctx : Pointer):Pointer;
  function ecx_init(vecxctx, vkey : Pointer;const params : POSSL_PARAM):integer;
  function ecx_set_peer( vecxctx, vkey : Pointer):integer;
  function ecx_derive( vecxctx : Pointer; secret : PByte; secretlen : Psize_t; outlen : size_t):integer;
  procedure ecx_freectx( vecxctx : Pointer);
  function ecx_dupctx( vecxctx : Pointer):Pointer;

const ossl_x25519_keyexch_functions: array[0..6] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYEXCH_NEWCTX; method:(code:@x25519_newctx ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_INIT; method:(code:@ecx_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_DERIVE; method:(code:@ecx_derive ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_SET_PEER; method:(code:@ecx_set_peer ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_FREECTX; method:(code:@ecx_freectx ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_DUPCTX; method:(code:@ecx_dupctx ;data:nil)),
    (function_id: 0; method:(code:nil ;data:nil))
);

  ossl_x448_keyexch_functions: array[0..6] of TOSSL_DISPATCH = (
    (function_id: OSSL_FUNC_KEYEXCH_NEWCTX; method:(code:@x448_newctx ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_INIT; method:(code:@ecx_init ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_DERIVE; method:(code:@ecx_derive ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_SET_PEER; method:(code:@ecx_set_peer ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_FREECTX; method:(code:@ecx_freectx ;data:nil)),
    (function_id: OSSL_FUNC_KEYEXCH_DUPCTX; method:(code:@ecx_dupctx ;data:nil)),
    (function_id: 0; method:(code:nil ;data:nil))
);

function ecx_newctx( provctx : Pointer; keylen : size_t):Pointer;



implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.dh.dh_lib,
     OpenSSL3.Err, openssl3.crypto.ffc.ffc_params,openssl3.crypto.mem_sec,
     openssl3.crypto.dh.dh_kdf, openssl3.crypto.mem,openssl3.crypto.params,
     openssl3.crypto.evp.digest, openssl3.crypto.o_str,openssl3.crypto.bn.bn_lib,
     OpenSSL3.providers.common.securitycheck, openssl3.crypto.evp.evp_lib,
     openssl3.providers.common.provider_ctx,OpenSSL3.openssl.params,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ecx_key, openssl3.include.internal.refcount,
     openssl3.crypto.ec.ecdh_kdf, OpenSSL3.common, openssl3.crypto.ec.curve25519,
     openssl3.crypto.ec.curve448;

function ecx_newctx( provctx : Pointer; keylen : size_t):Pointer;
var
  ctx : PPROV_ECX_CTX;
begin
    if not ossl_prov_is_running()  then
        Exit(nil);
    ctx := OPENSSL_zalloc(sizeof(TPROV_ECX_CTX));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.keylen := keylen;
    Result := ctx;
end;

function x25519_newctx( provctx : Pointer):Pointer;
begin
    Result := ecx_newctx(provctx, X25519_KEYLEN);
end;


function x448_newctx( provctx : Pointer):Pointer;
begin
    Result := ecx_newctx(provctx, X448_KEYLEN);
end;


function ecx_init(vecxctx, vkey : Pointer;const params : POSSL_PARAM):integer;
var
  ecxctx : PPROV_ECX_CTX;

  key : PECX_KEY;
begin
    ecxctx := PPROV_ECX_CTX  (vecxctx);
    key := vkey;
    if not ossl_prov_is_running( ) then
        Exit(0);
    if (ecxctx = nil)
             or  (key = nil)
             or  (key.keylen <> ecxctx.keylen)
             or  (0>= ossl_ecx_key_up_ref(key)) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    ossl_ecx_key_free(ecxctx.key);
    ecxctx.key := key;
    Result := 1;
end;


function ecx_set_peer( vecxctx, vkey : Pointer):integer;
var
  ecxctx : PPROV_ECX_CTX;

  key : PECX_KEY;
begin
    ecxctx := PPROV_ECX_CTX  (vecxctx);
    key := vkey;
    if not ossl_prov_is_running(  )then
        Exit(0);
    if (ecxctx = nil)
             or  (key = nil)
             or  (key.keylen <> ecxctx.keylen)
             or  (0>= ossl_ecx_key_up_ref(key)) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    ossl_ecx_key_free(ecxctx.peerkey);
    ecxctx.peerkey := key;
    Result := 1;
end;


function ecx_derive( vecxctx : Pointer; secret : PByte; secretlen : Psize_t; outlen : size_t):integer;
var
  ecxctx : PPROV_ECX_CTX;
begin
    ecxctx := (PPROV_ECX_CTX  (vecxctx));
    if not ossl_prov_is_running()  then
        Exit(0);
    if (ecxctx.key = nil)
             or  (ecxctx.key.privkey = nil)
             or  (ecxctx.peerkey = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        Exit(0);
    end;
    if not ossl_assert( (ecxctx.keylen = X25519_KEYLEN)
             or  (ecxctx.keylen = X448_KEYLEN )) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        Exit(0);
    end;
    if secret = nil then
    begin
        secretlen^ := ecxctx.keylen;
        Exit(1);
    end;
    if outlen < ecxctx.keylen then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if ecxctx.keylen = X25519_KEYLEN then
    begin
{$IFDEF S390X_EC_ASM}
        if (OPENSSL_s39$cap_P.pcc[1]
                and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X25519)) begin
            if (s390x_x25519_mul(secret, ecxctx.peerkey.pubkey,
                                 ecxctx.key.privkey) = 0) begin
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
                Exit(0);
            end;
        end;
 else
{$ENDIF}
        if ossl_x25519(secret,  ecxctx.key.privkey,
                        @ecxctx.peerkey.pubkey )= 0  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
            Exit(0);
        end;
    end
   else
   begin
{$IFDEF S390X_EC_ASM}
        if OPENSSL_s39$cap_P.pcc[1]
                and S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X448)  then
        begin
            if (s390x_x448_mul(secret, ecxctx.peerkey.pubkey,
                               ecxctx.key.privkey) = 0) begin
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
                Exit(0);
            end;
        end;
 else
{$ENDIF}
        if ossl_x448(secret{56},
                     ecxctx.key.privkey,{56}
                     @ecxctx.peerkey.pubkey ) = 0  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
            Exit(0);
        end;
    end;
    secretlen^ := ecxctx.keylen;
    Result := 1;
end;


procedure ecx_freectx( vecxctx : Pointer);
var
  ecxctx : PPROV_ECX_CTX;
begin
    ecxctx := PPROV_ECX_CTX  (vecxctx);
    ossl_ecx_key_free(ecxctx.key);
    ossl_ecx_key_free(ecxctx.peerkey);
    OPENSSL_free(ecxctx);
end;


function ecx_dupctx( vecxctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_ECX_CTX;
begin
    srcctx := PPROV_ECX_CTX  (vecxctx);
    if not ossl_prov_is_running() then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    dstctx^ := srcctx^;
    if (dstctx.key <> nil)  and  (0>= ossl_ecx_key_up_ref(dstctx.key ))then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(dstctx);
        Exit(nil);
    end;
    if (dstctx.peerkey <> nil)  and  (0>= ossl_ecx_key_up_ref(dstctx.peerkey) ) then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ossl_ecx_key_free(dstctx.key);
        OPENSSL_free(dstctx);
        Exit(nil);
    end;
    Result := dstctx;
end;

end.
