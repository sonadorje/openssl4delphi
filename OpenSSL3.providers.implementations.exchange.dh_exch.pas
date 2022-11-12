unit OpenSSL3.providers.implementations.exchange.dh_exch;

interface

uses
  OpenSSL.Api, SysUtils;

function dh_newctx(provctx: Pointer): Pointer;
function dh_init(vpdhctx, vdh: Pointer; const params: POSSL_PARAM): Boolean;
function dh_derive(vpdhctx: Pointer; secret: PByte; psecretlen: Psize_t; outlen: size_t): integer;
procedure dh_freectx(vpdhctx: Pointer);
function dh_dupctx(vpdhctx: Pointer): Pointer;
function dh_set_ctx_params(vpdhctx: Pointer; const params: POSSL_PARAM): integer;
function dh_settable_ctx_params(vpdhctx, provctx: Pointer): POSSL_PARAM;
function dh_gettable_ctx_params(vpdhctx, provctx: Pointer): POSSL_PARAM;
function dh_get_ctx_params(vpdhctx: Pointer; params: POSSL_PARAM): integer;
function dh_set_peer(vpdhctx, vdh: Pointer): integer;

const
  ossl_dh_keyexch_functions: array[0..10] of TOSSL_DISPATCH = ((
    function_id: OSSL_FUNC_KEYEXCH_NEWCTX;
    method: (
    code: @dh_newctx;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_INIT;
    method: (
    code: @dh_init;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_DERIVE;
    method: (
    code: @dh_derive;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_SET_PEER;
    method: (
    code: @dh_set_peer;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_FREECTX;
    method: (
    code: @dh_freectx;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_DUPCTX;
    method: (
    code: @dh_dupctx;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS;
    method: (
    code: @dh_set_ctx_params;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS;
    method: (
    code: @dh_settable_ctx_params;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS;
    method: (
    code: @dh_get_ctx_params;
    data: nil
  )
  ), (
    function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS;
    method: (
    code: @dh_gettable_ctx_params;
    data: nil
  )
  ), (
    function_id: 0;
    method: (
    code: nil;
    data: nil
  )
  ));

function dh_match_params(priv, peer: PDH): integer;
function dh_plain_derive(vpdhctx: Pointer; secret: PByte; secretlen: Psize_t; outlen: size_t): integer;
function dh_X9_42_kdf_derive(vpdhctx: Pointer; secret: PByte; secretlen: Psize_t; outlen: size_t): integer;

var
  known_settable_ctx_params, known_gettable_ctx_params: array of TOSSL_PARAM;

implementation

uses
  openssl3.providers.fips.self_test, openssl3.crypto.dh.dh_lib, OpenSSL3.Err,
  openssl3.crypto.ffc.ffc_params, openssl3.crypto.mem_sec,
  openssl3.crypto.dh.dh_kdf, openssl3.crypto.mem, openssl3.crypto.params,
  openssl3.crypto.evp.digest, openssl3.crypto.o_str, openssl3.crypto.dh.dh_key,
  OpenSSL3.providers.common.securitycheck, openssl3.crypto.evp.evp_lib,
  openssl3.providers.common.provider_ctx, OpenSSL3.openssl.params;

function dh_X9_42_kdf_derive(vpdhctx: Pointer; secret: PByte; secretlen: Psize_t; outlen: size_t): integer;
var
  pdhctx: PPROV_DH_CTX;
  stmp: PByte;
  stmplen: size_t;
  ret: integer;
label
  _err;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  stmp := nil;
  ret := 0;
  if secret = nil then
  begin
    secretlen^ := pdhctx.kdf_outlen;
    Exit(1);
  end;
  if pdhctx.kdf_outlen > outlen then
  begin
    ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
    Exit(0);
  end;
  if 0 >= dh_plain_derive(pdhctx, nil, @stmplen, 0) then
    Exit(0);
  stmp := OPENSSL_secure_malloc(stmplen);
  if stmp = nil then
  begin
    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    Exit(0);
  end;
  if 0 >= dh_plain_derive(pdhctx, stmp, @stmplen, stmplen) then
    goto _err;
    { Do KDF stuff }
  if pdhctx.kdf_type = PROV_DH_KDF_X9_42_ASN1 then
  begin
    if (0 >= ossl_dh_kdf_X9_42_asn1(secret, pdhctx.kdf_outlen, stmp, stmplen, pdhctx.kdf_cekalg, pdhctx.kdf_ukm, pdhctx.kdf_ukmlen, pdhctx.kdf_md, pdhctx.libctx, nil)) then
      goto _err;
  end;
  secretlen^ := pdhctx.kdf_outlen;
  ret := 1;
_err:
  OPENSSL_secure_clear_free(stmp, stmplen);
  Result := ret;
end;

function dh_plain_derive(vpdhctx: Pointer; secret: PByte; secretlen: Psize_t; outlen: size_t): integer;
var
  pdhctx: PPROV_DH_CTX;
  ret: integer;
  dhsize: size_t;
  pub_key: PBIGNUM;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  pub_key := nil;
  if (pdhctx.dh = nil) or (pdhctx.dhpeer = nil) then
  begin
    ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
    Exit(0);
  end;
  dhsize := size_t(DH_size(pdhctx.dh));
  if secret = nil then
  begin
    secretlen^ := dhsize;
    Exit(1);
  end;
  if outlen < dhsize then
  begin
    ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
    Exit(0);
  end;
  DH_get0_key(pdhctx.dhpeer, @pub_key, nil);
  if pdhctx.pad > 0 then
    ret := DH_compute_key_padded(secret, pub_key, pdhctx.dh)
  else
    ret := DH_compute_key(secret, pub_key, pdhctx.dh);
  if ret <= 0 then
    Exit(0);
  secretlen^ := ret;
  Result := 1;
end;

function dh_match_params(priv, peer: PDH): integer;
var
  ret: Boolean;
  dhparams_priv, dhparams_peer: PFFC_PARAMS;
begin
  dhparams_priv := ossl_dh_get0_params(priv);
  dhparams_peer := ossl_dh_get0_params(peer);
  ret := (dhparams_priv <> nil) and (dhparams_peer <> nil) and (ossl_ffc_params_cmp(dhparams_priv, dhparams_peer, 1) > 0);
  if not ret then
    ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
  Result := Int(ret);
end;

function dh_set_peer(vpdhctx, vdh: Pointer): integer;
var
  pdhctx: PPROV_DH_CTX;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  if (not ossl_prov_is_running) or (pdhctx = nil) or (vdh = nil) or (0 >= dh_match_params(vdh, pdhctx.dh)) or (0 >= DH_up_ref(vdh)) then
    Exit(0);
  DH_free(pdhctx.dhpeer);
  pdhctx.dhpeer := vdh;
  Result := 1;
end;

function dh_derive(vpdhctx: Pointer; secret: PByte; psecretlen: Psize_t; outlen: size_t): integer;
var
  pdhctx: PPROV_DH_CTX;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  if not ossl_prov_is_running() then
    Exit(0);
  case pdhctx.kdf_type of
    PROV_DH_KDF_NONE:
      Exit(dh_plain_derive(pdhctx, secret, psecretlen, outlen));
    PROV_DH_KDF_X9_42_ASN1:
      Exit(dh_X9_42_kdf_derive(pdhctx, secret, psecretlen, outlen));
  else
    begin
          //
    end;

  end;
  Result := 0;
end;

procedure dh_freectx(vpdhctx: Pointer);
var
  pdhctx: PPROV_DH_CTX;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  OPENSSL_free(pdhctx.kdf_cekalg);
  DH_free(pdhctx.dh);
  DH_free(pdhctx.dhpeer);
  EVP_MD_free(pdhctx.kdf_md);
  OPENSSL_clear_free(Pointer(pdhctx.kdf_ukm), pdhctx.kdf_ukmlen);
  OPENSSL_free(pdhctx);
end;

function dh_dupctx(vpdhctx: Pointer): Pointer;
var
  srcctx, dstctx: PPROV_DH_CTX;
label
  _err;
begin
  srcctx := PPROV_DH_CTX(vpdhctx);
  if not ossl_prov_is_running() then
    Exit(nil);
  dstctx := OPENSSL_zalloc(sizeof(srcctx^));
  if dstctx = nil then
    Exit(nil);
  dstctx^ := srcctx^;
  dstctx.dh := nil;
  dstctx.dhpeer := nil;
  dstctx.kdf_md := nil;
  dstctx.kdf_ukm := nil;
  dstctx.kdf_cekalg := nil;
  if (srcctx.dh <> nil) and (0 >= DH_up_ref(srcctx.dh)) then
    goto _err
  else
    dstctx.dh := srcctx.dh;
  if (srcctx.dhpeer <> nil) and (0 >= DH_up_ref(srcctx.dhpeer)) then
    goto _err
  else
    dstctx.dhpeer := srcctx.dhpeer;
  if (srcctx.kdf_md <> nil) and (0 >= EVP_MD_up_ref(srcctx.kdf_md)) then
    goto _err
  else
    dstctx.kdf_md := srcctx.kdf_md;
    { Duplicate UKM data if present }
  if (srcctx.kdf_ukm <> nil) and (srcctx.kdf_ukmlen > 0) then
  begin
    dstctx.kdf_ukm := OPENSSL_memdup(srcctx.kdf_ukm, srcctx.kdf_ukmlen);
    if dstctx.kdf_ukm = nil then
      goto _err;
  end;
  OPENSSL_strdup(dstctx.kdf_cekalg, srcctx.kdf_cekalg);
  Exit(dstctx);
_err:
  dh_freectx(dstctx);
  Result := nil;
end;

function dh_set_ctx_params(vpdhctx: Pointer; const params: POSSL_PARAM): integer;
var
  pdhctx: PPROV_DH_CTX;
  pad: uint32;
  name: array[0..79] of UTF8Char;
  str: PUTF8Char;
  mdprops: array[0..79] of UTF8char;
  outlen: size_t;
  tmp_ukm: Pointer;
  p: POSSL_PARAM;
  tmp_ukmlen: size_t;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  Fillchar(name, SizeOf(name), #0);
  str := nil;
  if pdhctx = nil then
    Exit(0);
  if params = nil then
    Exit(1);
  p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
  if p <> nil then
  begin
    str := @name;
    if 0 >= OSSL_PARAM_get_utf8_string(p, @str, sizeof(name)) then
      Exit(0);
    if name[0] = #0 then
      pdhctx.kdf_type := PROV_DH_KDF_NONE
    else if (strcmp(name, OSSL_KDF_NAME_X942KDF_ASN1) = 0) then
      pdhctx.kdf_type := PROV_DH_KDF_X9_42_ASN1
    else
      Exit(0);
  end;
  p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
  if p <> nil then
  begin
    Fillchar(mdprops, SizeOf(mdprops), #0);

    str := name;
    if 0 >= OSSL_PARAM_get_utf8_string(p, @str, sizeof(name)) then
      Exit(0);
    str := @mdprops;
    p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
    if p <> nil then
    begin
      if 0 >= OSSL_PARAM_get_utf8_string(p, @str, sizeof(mdprops)) then
        Exit(0);
    end;
    EVP_MD_free(pdhctx.kdf_md);
    pdhctx.kdf_md := EVP_MD_fetch(pdhctx.libctx, name, mdprops);
    if pdhctx.kdf_md = nil then
      Exit(0);
    if not ossl_digest_is_allowed(pdhctx.libctx, pdhctx.kdf_md) then
    begin
      EVP_MD_free(pdhctx.kdf_md);
      pdhctx.kdf_md := nil;
      Exit(0);
    end;
  end;
  p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
  if p <> nil then
  begin
    if 0 >= OSSL_PARAM_get_size_t(p, @outlen) then
      Exit(0);
    pdhctx.kdf_outlen := outlen;
  end;
  p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
  if p <> nil then
  begin
    tmp_ukm := nil;
    OPENSSL_free(pdhctx.kdf_ukm);
    pdhctx.kdf_ukm := nil;
    pdhctx.kdf_ukmlen := 0;
        { ukm is an optional field so it can be nil }
    if (p.data <> nil) and (p.data_size <> 0) then
    begin
      if 0 >= OSSL_PARAM_get_octet_string(p, tmp_ukm, 0, @tmp_ukmlen) then
        Exit(0);
      pdhctx.kdf_ukm := tmp_ukm;
      pdhctx.kdf_ukmlen := tmp_ukmlen;
    end;
  end;
  p := OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD);
  if p <> nil then
  begin
    if 0 >= OSSL_PARAM_get_uint(p, @pad) then
      Exit(0);
    pdhctx.pad := get_result(pad > 0, 1, 0);
  end;
  p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG);
  if p <> nil then
  begin
    str := name;
    if 0 >= OSSL_PARAM_get_utf8_string(p, @str, sizeof(name)) then
      Exit(0);
    OPENSSL_strdup(pdhctx.kdf_cekalg, name);
  end;
  Result := 1;
end;

function dh_settable_ctx_params(vpdhctx, provctx: Pointer): POSSL_PARAM;
begin
  Result := @known_settable_ctx_params[0];
end;

function dh_gettable_ctx_params(vpdhctx, provctx: Pointer): POSSL_PARAM;
begin
  Result := @known_gettable_ctx_params[0];
end;

function dh_get_ctx_params(vpdhctx: Pointer; params: POSSL_PARAM): integer;
var
  pdhctx: PPROV_DH_CTX;
  p: POSSL_PARAM;
  kdf_type: PUTF8Char;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  if pdhctx = nil then
    Exit(0);
  p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
  if p <> nil then
  begin
    kdf_type := nil;
    case pdhctx.kdf_type of
      PROV_DH_KDF_NONE:
        kdf_type := '';
                //break;
      PROV_DH_KDF_X9_42_ASN1:
        kdf_type := OSSL_KDF_NAME_X942KDF_ASN1;
                //break;
    else
      Exit(0);
    end;
    if 0 >= OSSL_PARAM_set_utf8_string(p, kdf_type) then
      Exit(0);
  end;
  p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
  if (p <> nil) and (0 >= OSSL_PARAM_set_utf8_string(p, get_result(pdhctx.kdf_md = nil, '', EVP_MD_get0_name(pdhctx.kdf_md)))) then
  begin
    Exit(0);
  end;
  p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
  if (p <> nil) and (0 >= OSSL_PARAM_set_size_t(p, pdhctx.kdf_outlen)) then
    Exit(0);
  p := OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
  if (p <> nil) and (0 >= OSSL_PARAM_set_octet_ptr(p, pdhctx.kdf_ukm, pdhctx.kdf_ukmlen)) then
    Exit(0);
  p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_CEK_ALG);
  if (p <> nil) and (0 >= OSSL_PARAM_set_utf8_string(p, get_result(pdhctx.kdf_cekalg = nil, '', pdhctx.kdf_cekalg))) then
    Exit(0);
  Result := 1;
end;

function dh_init(vpdhctx, vdh: Pointer; const params: POSSL_PARAM): Boolean;
var
  pdhctx: PPROV_DH_CTX;
begin
  pdhctx := PPROV_DH_CTX(vpdhctx);
  if (not ossl_prov_is_running) or (pdhctx = nil) or (vdh = nil) or (0 >= DH_up_ref(vdh)) then
    Exit(False);
  DH_free(pdhctx.dh);
  pdhctx.dh := vdh;
  pdhctx.kdf_type := PROV_DH_KDF_NONE;
  Result := (dh_set_ctx_params(pdhctx, params) > 0) and (ossl_dh_check_key(pdhctx.libctx, vdh) > 0);
end;

function dh_newctx(provctx: Pointer): Pointer;
var
  pdhctx: PPROV_DH_CTX;
begin
  if not ossl_prov_is_running() then
    Exit(nil);
  pdhctx := OPENSSL_zalloc(sizeof(PROV_DH_CTX));
  if pdhctx = nil then
    Exit(nil);
  pdhctx.libctx := PROV_LIBCTX_OF(provctx);
  pdhctx.kdf_type := PROV_DH_KDF_NONE;
  Result := pdhctx;
end;

initialization
  known_settable_ctx_params := [_OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, nil), _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, nil, 0), _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, nil, 0), _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, nil, 0), _OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, nil), _OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, nil, 0), _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, nil, 0), OSSL_PARAM_END];
  known_gettable_ctx_params := [_OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, nil, 0), _OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, nil, 0), _OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, nil), OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, nil, 0), _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, nil, 0), OSSL_PARAM_END];

end.

