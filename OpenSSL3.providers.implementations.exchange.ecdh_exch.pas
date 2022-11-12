unit OpenSSL3.providers.implementations.exchange.ecdh_exch;

interface
uses OpenSSL.Api, SysUtils;

  function ecdh_settable_ctx_params( vpecdhctx, provctx : Pointer):POSSL_PARAM;
  function ecdh_newctx( provctx : Pointer):Pointer;
  function ecdh_init(vpecdhctx, vecdh : Pointer;const params : POSSL_PARAM):Boolean;
  function ecdh_match_params(const priv, peer : PEC_KEY):Boolean;
  function ecdh_set_peer( vpecdhctx, vecdh : Pointer):integer;
  procedure ecdh_freectx( vpecdhctx : Pointer);
  function ecdh_dupctx( vpecdhctx : Pointer):Pointer;
  function ecdh_set_ctx_params(vpecdhctx : Pointer;const params : POSSL_PARAM):integer;
  function ecdh_get_ctx_params( vpecdhctx : Pointer; params : POSSL_PARAM):integer;
  function ecdh_gettable_ctx_params( vpecdhctx, provctx : Pointer):POSSL_PARAM;
  function ecdh_size(const k : PEC_KEY):size_t;
  function ecdh_plain_derive( vpecdhctx : Pointer; secret : PByte; psecretlen : Psize_t; outlen : size_t):integer;
  function ecdh_X9_63_kdf_derive( vpecdhctx : Pointer; secret : PByte; psecretlen : Psize_t; outlen : size_t):integer;
  function ecdh_derive( vpecdhctx : Pointer; secret : PByte; psecretlen : Psize_t; outlen : size_t):integer;

const
  ossl_ecdh_keyexch_functions: array[0..10] of TOSSL_DISPATCH = (
    ( function_id:OSSL_FUNC_KEYEXCH_NEWCTX; method:(code:@ecdh_newctx ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_INIT; method:(code:@ecdh_init ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_DERIVE; method:(code:@ecdh_derive ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_SET_PEER; method:(code:@ecdh_set_peer ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_FREECTX; method:(code:@ecdh_freectx ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_DUPCTX; method:(code:@ecdh_dupctx ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS; method:(code:@ecdh_set_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS;
      method:(code:@ecdh_settable_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS; method:(code:@ecdh_get_ctx_params ;data:nil)),
    ( function_id:OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS;
      method:(code:@ecdh_gettable_ctx_params ;data:nil)),
    ( function_id:0; method:(code:nil ;data:nil))
);

var
  known_settable_ctx_params,
  known_gettable_ctx_params: array of TOSSL_PARAM ;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.dh.dh_lib,
     OpenSSL3.Err, openssl3.crypto.ffc.ffc_params,openssl3.crypto.mem_sec,
     openssl3.crypto.dh.dh_kdf, openssl3.crypto.mem,openssl3.crypto.params,
     openssl3.crypto.evp.digest, openssl3.crypto.o_str,openssl3.crypto.bn.bn_lib,
     OpenSSL3.providers.common.securitycheck, openssl3.crypto.evp.evp_lib,
     openssl3.providers.common.provider_ctx,OpenSSL3.openssl.params,
     openssl3.crypto.ec.ec_lib, openssl3.crypto.ec.ec_kmeth,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_key,
     openssl3.crypto.ec.ecdh_kdf;


function ecdh_settable_ctx_params( vpecdhctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_ctx_params[0];
end;

function ecdh_newctx( provctx : Pointer):Pointer;
var
  pectx : PPROV_ECDH_CTX;
begin
    if not ossl_prov_is_running()  then
        Exit(nil);
    pectx := OPENSSL_zalloc(sizeof( pectx^));
    if pectx = nil then Exit(nil);
    pectx.libctx := PROV_LIBCTX_OF(provctx);
    pectx.cofactor_mode := -1;
    pectx.kdf_type := PROV_ECDH_KDF_NONE;
    Result := Pointer (pectx);
end;


function ecdh_init(vpecdhctx, vecdh : Pointer;const params : POSSL_PARAM):Boolean;
var
  pecdhctx : PPROV_ECDH_CTX;
begin
    pecdhctx := PPROV_ECDH_CTX ( vpecdhctx);
    if (not ossl_prov_is_running)  or ( pecdhctx = nil)
             or  (vecdh = nil)
             or  (0>= EC_KEY_up_ref(vecdh))then
        Exit(False);
    EC_KEY_free(pecdhctx.k);
    pecdhctx.k := vecdh;
    pecdhctx.cofactor_mode := -1;
    pecdhctx.kdf_type := PROV_ECDH_KDF_NONE;
    Exit( (ecdh_set_ctx_params(pecdhctx, params)>0)
            and  (ossl_ec_check_key(pecdhctx.libctx, vecdh, 1)>0) );
end;


function ecdh_match_params(const priv, peer : PEC_KEY):Boolean;
var
  ret        : Boolean;
  ctx        : PBN_CTX;
  group_priv,
  group_peer : PEC_GROUP;
begin
    ctx := nil;
    group_priv := EC_KEY_get0_group(priv);
    group_peer := EC_KEY_get0_group(peer);
    ctx := BN_CTX_new_ex(ossl_ec_key_get_libctx(priv));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(False);
    end;
    ret := (group_priv <> nil)
           and  (group_peer <> nil)
           and  (EC_GROUP_cmp(group_priv, group_peer, ctx) = 0);
    if not ret then
       ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    BN_CTX_free(ctx);
    Result := ret;
end;


function ecdh_set_peer( vpecdhctx, vecdh : Pointer):integer;
var
  pecdhctx : PPROV_ECDH_CTX;
begin
    pecdhctx := PPROV_ECDH_CTX ( vpecdhctx);
    if (not ossl_prov_is_running)  or  (pecdhctx = nil)
             or  (vecdh = nil)
             or  (not ecdh_match_params(pecdhctx.k, vecdh))
             or  (0>= ossl_ec_check_key(pecdhctx.libctx, vecdh, 1))
             or  (0>= EC_KEY_up_ref(vecdh))  then
        Exit(0);
    EC_KEY_free(pecdhctx.peerk);
    pecdhctx.peerk := vecdh;
    Result := 1;
end;


procedure ecdh_freectx( vpecdhctx : Pointer);
var
  pecdhctx : PPROV_ECDH_CTX;
begin
    pecdhctx := PPROV_ECDH_CTX ( vpecdhctx);
    EC_KEY_free(pecdhctx.k);
    EC_KEY_free(pecdhctx.peerk);
    EVP_MD_free(pecdhctx.kdf_md);
    OPENSSL_clear_free(Pointer(pecdhctx.kdf_ukm), pecdhctx.kdf_ukmlen);
    OPENSSL_free(pecdhctx);
end;


function ecdh_dupctx( vpecdhctx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_ECDH_CTX;
  label _err;
begin
    srcctx := PPROV_ECDH_CTX ( vpecdhctx);
    if not ossl_prov_is_running(  ) then
        Exit(nil);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    { clear all pointers }
    dstctx.k := nil;
    dstctx.peerk := nil;
    dstctx.kdf_md := nil;
    dstctx.kdf_ukm := nil;
    { up-ref all ref-counted objects referenced in dstctx }
    if (srcctx.k <> nil)  and  (0>= EC_KEY_up_ref(srcctx.k)) then
        goto _err
    else
        dstctx.k := srcctx.k;
    if (srcctx.peerk <> nil)  and  (0>= EC_KEY_up_ref(srcctx.peerk))  then
        goto _err
    else
        dstctx.peerk := srcctx.peerk;
    if (srcctx.kdf_md <> nil)  and  (0>= EVP_MD_up_ref(srcctx.kdf_md)) then
        goto _err
    else
        dstctx.kdf_md := srcctx.kdf_md;
    { Duplicate UKM data if present }
    if (srcctx.kdf_ukm <> nil)  and  (srcctx.kdf_ukmlen > 0) then
    begin
        dstctx.kdf_ukm := OPENSSL_memdup(srcctx.kdf_ukm,
                                         srcctx.kdf_ukmlen);
        if dstctx.kdf_ukm = nil then goto _err ;
    end;
    Exit(dstctx);
 _err:
    ecdh_freectx(dstctx);
    Result := nil;
end;


function ecdh_set_ctx_params(vpecdhctx : Pointer;const params : POSSL_PARAM):integer;
var
    name       : array[0..79] of UTF8Char;
    str        : PUTF8Char;
    pectx      : PPROV_ECDH_CTX;
    p          : POSSL_PARAM;
    mode       : integer;
    mdprops    : array[0..79] of UTF8Char;

    outlen     : size_t;

    tmp_ukm    : Pointer;

    tmp_ukmlen : size_t;
begin
    FillChar(name, SizeOf(Name),  #0);

    str := nil;
    pectx := PPROV_ECDH_CTX ( vpecdhctx);
    if pectx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_int(p, @mode) then
            Exit(0);
        if (mode < -1)  or  (mode > 1) then Exit(0);
        pectx.cofactor_mode := mode;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if p <> nil then
    begin
        str := name;
        if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(name )) then
            Exit(0);
        if name[0] = #0 then
           pectx.kdf_type := PROV_ECDH_KDF_NONE
        else if (strcmp(name, OSSL_KDF_NAME_X963KDF) = 0) then
            pectx.kdf_type := PROV_ECDH_KDF_X9_63
        else
            Exit(0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if p <> nil then
    begin
        FillChar(mdprops, SizeOf(mdprops),  #0);
        str := name;
        if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(name)) then
            Exit(0);
        str := @mdprops;
        p := OSSL_PARAM_locate_const(params,
                                    OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
        if p <> nil then
        begin
            if 0>= OSSL_PARAM_get_utf8_string(p, @str, sizeof(mdprops)) then
                Exit(0);
        end;
        EVP_MD_free(pectx.kdf_md);
        pectx.kdf_md := EVP_MD_fetch(pectx.libctx, name, mdprops);
        if pectx.kdf_md = nil then Exit(0);
        if not ossl_digest_is_allowed(pectx.libctx, pectx.kdf_md ) then
        begin
            EVP_MD_free(pectx.kdf_md);
            pectx.kdf_md := nil;
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_size_t(p, @outlen) then
            Exit(0);
        pectx.kdf_outlen := outlen;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if p <> nil then
    begin
        tmp_ukm := nil;
        if 0>= OSSL_PARAM_get_octet_string(p, &tmp_ukm, 0, @tmp_ukmlen) then
            Exit(0);
        OPENSSL_free(pectx.kdf_ukm);
        pectx.kdf_ukm := tmp_ukm;
        pectx.kdf_ukmlen := tmp_ukmlen;
    end;
    Result := 1;
end;


function ecdh_get_ctx_params( vpecdhctx : Pointer; params : POSSL_PARAM):integer;
var
    pectx    : PPROV_ECDH_CTX;

    p        : POSSL_PARAM;

    mode     : integer;

    kdf_type : PUTF8Char;
begin
    kdf_type := nil;
    pectx := PPROV_ECDH_CTX ( vpecdhctx);
    if pectx = nil then Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if p <> nil then
    begin
        mode := pectx.cofactor_mode;
        if mode = -1 then
        begin
            { check what is the default for pecdhctx.k }
            mode := get_result(EC_KEY_get_flags(pectx.k) and EC_FLAG_COFACTOR_ECDH >0, 1 , 0);
        end;
        if 0>= OSSL_PARAM_set_int(p, mode ) then
            Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if p <> nil then
    begin
        case pectx.kdf_type of
            PROV_ECDH_KDF_NONE:
                kdf_type := '';
                //break;
            PROV_ECDH_KDF_X9_63:
                kdf_type := OSSL_KDF_NAME_X963KDF;
                //break;
            else
                Exit(0);
        end;
        if 0>= OSSL_PARAM_set_utf8_string(p, kdf_type)  then
            Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p <> nil)
             and  (0>= OSSL_PARAM_set_utf8_string(p, get_result( pectx.kdf_md = nil
                                           , ''
                                           , EVP_MD_get0_name(pectx.kdf_md) )))then
    begin
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, pectx.kdf_outlen)) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p <> nil)  and
         (0>= OSSL_PARAM_set_octet_ptr(p, pectx.kdf_ukm, pectx.kdf_ukmlen))  then
        Exit(0);
    Result := 1;
end;


function ecdh_gettable_ctx_params( vpecdhctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_ctx_params[0];
end;


function ecdh_size(const k : PEC_KEY):size_t;
var
  degree : size_t;

  group : PEC_GROUP;
begin
    degree := 0;
    group := EC_KEY_get0_group(k );
    if (k = nil)
             or  (group = nil)then
        Exit(0);
    degree := EC_GROUP_get_degree(group);
    Result := (degree + 7) div 8;
end;


function ecdh_plain_derive( vpecdhctx : Pointer; secret : PByte; psecretlen : Psize_t; outlen : size_t):integer;
var
  pecdhctx          : PPROV_ECDH_CTX;
  retlen,
  ret               : integer;
  ecdhsize,
  size              : size_t;
  ppubkey           : PEC_POINT;
  privk             : PEC_KEY;
  group             : PEC_GROUP;
  cofactor          : PBIGNUM;
  key_cofactor_mode : integer;
  label _end;
begin
    pecdhctx := PPROV_ECDH_CTX ( vpecdhctx);
    ret := 0;
     ppubkey := nil;
    privk := nil;
    if (pecdhctx.k = nil)  or  (pecdhctx.peerk = nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        Exit(0);
    end;
    ecdhsize := ecdh_size(pecdhctx.k);
    if secret = nil then
    begin
        psecretlen^ := ecdhsize;
        Exit(1);
    end;
    group := EC_KEY_get0_group(pecdhctx.k);
    cofactor := EC_GROUP_get0_cofactor(group);
    if (group = nil)
             or  (cofactor = nil) then
        Exit(0);
    {
     * NB: unlike PKCS#3 DH, if outlen is less than maximum size this is not
     * an error, the result is truncated.
     }
    size := get_result( outlen < ecdhsize , outlen , ecdhsize);
    {
     * The ctx.cofactor_mode flag has precedence over the
     * cofactor_mode flag set on ctx.k.
     *
     * - if ctx.cofactor_mode = -1, use ctx.k directly
     * - if ctx.cofactor_mode = key_cofactor_mode, use ctx.k directly
     * - if ctx.cofactor_mode <> key_cofactor_mode:
     *     - if ctx.k.cofactor = 1, the cofactor_mode flag is irrelevant, use
     *          ctx.k directly
     *     - if ctx.k.cofactor <> 1, use a duplicate of ctx.k with the flag
     *          set to ctx.cofactor_mode
     }
    key_cofactor_mode := get_result(
          (EC_KEY_get_flags(pecdhctx.k) and EC_FLAG_COFACTOR_ECDH) >0, 1 , 0);
    if (pecdhctx.cofactor_mode <> -1)
             and  (pecdhctx.cofactor_mode <> key_cofactor_mode)
             and  (not BN_is_one(cofactor)) then
    begin
        privk := EC_KEY_dup(pecdhctx.k);
        if (privk =  nil) then
            Exit(0);
        if pecdhctx.cofactor_mode = 1 then
           EC_KEY_set_flags(privk, EC_FLAG_COFACTOR_ECDH)
        else
            EC_KEY_clear_flags(privk, EC_FLAG_COFACTOR_ECDH);
    end
    else
    begin
        privk := pecdhctx.k;
    end;
    ppubkey := EC_KEY_get0_public_key(pecdhctx.peerk);
    retlen := ECDH_compute_key(secret, size, ppubkey, privk, nil);
    if retlen <= 0 then goto _end ;
    psecretlen^ := retlen;
    ret := 1;
 _end:
    if privk <> pecdhctx.k then EC_KEY_free(privk);
    Result := ret;
end;


function ecdh_X9_63_kdf_derive( vpecdhctx : Pointer; secret : PByte; psecretlen : Psize_t; outlen : size_t):integer;
var
    pecdhctx : PPROV_ECDH_CTX;

    stmp     : PByte;

    stmplen  : size_t;

    ret      : integer;
    label _err;
begin
    pecdhctx := PPROV_ECDH_CTX ( vpecdhctx);
    stmp := nil;
    ret := 0;
    if secret = nil then
    begin
        psecretlen^ := pecdhctx.kdf_outlen;
        Exit(1);
    end;
    if pecdhctx.kdf_outlen > outlen then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>= ecdh_plain_derive(vpecdhctx, nil, @stmplen, 0)  then
        Exit(0);
    stmp := OPENSSL_secure_malloc(stmplen );
    if stmp =  nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>= ecdh_plain_derive(vpecdhctx, stmp, @stmplen, stmplen )  then
        goto _err ;
    { Do KDF stuff }
    if 0>= ossl_ecdh_kdf_X9_63(secret, pecdhctx.kdf_outlen,
                             stmp, stmplen,
                             pecdhctx.kdf_ukm,
                             pecdhctx.kdf_ukmlen,
                             pecdhctx.kdf_md,
                             pecdhctx.libctx, nil)  then
        goto _err ;
    psecretlen^ := pecdhctx.kdf_outlen;
    ret := 1;
 _err:
    OPENSSL_secure_clear_free(stmp, stmplen);
    Result := ret;
end;


function ecdh_derive( vpecdhctx : Pointer; secret : PByte; psecretlen : Psize_t; outlen : size_t):integer;
var
  pecdhctx : PPROV_ECDH_CTX;
begin
    pecdhctx := PPROV_ECDH_CTX ( vpecdhctx);
    case pecdhctx.kdf_type of
        PROV_ECDH_KDF_NONE:
            Exit(ecdh_plain_derive(vpecdhctx, secret, psecretlen, outlen));
        PROV_ECDH_KDF_X9_63:
            Exit(ecdh_X9_63_kdf_derive(vpecdhctx, secret, psecretlen, outlen));
        else
            begin
              //
            end;;
    end;
    Result := 0;
end;






initialization
  known_settable_ctx_params := [
    _OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, nil),
    _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, nil, 0),
    _OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, nil),
    _OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, nil, 0),
    OSSL_PARAM_END
];
 known_gettable_ctx_params := [
    _OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, nil),
    _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, nil, 0),
    _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, nil, 0),
    _OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, nil),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR,
                    nil, 0),
    OSSL_PARAM_END
];
end.
