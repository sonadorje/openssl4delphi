unit OpenSSL3.providers.implementations.ciphers.cipher_tdes_common;

interface
uses OpenSSL.Api;

function ossl_tdes_newctx(provctx : Pointer; mode : integer; kbits, blkbits, ivbits : size_t; flags : uint64;const hw : PPROV_CIPHER_HW):Pointer;
  function ossl_tdes_dupctx( ctx : Pointer):Pointer;
  procedure ossl_tdes_freectx( vctx : Pointer);
  function tdes_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
  function ossl_tdes_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function ossl_tdes_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
  function ossl_tdes_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
  function tdes_generatekey( ctx : PPROV_CIPHER_CTX; ptr : Pointer):integer;
  function ossl_tdes_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;

var
  ossl_tdes_known_gettable_ctx_params: array of TOSSL_PARAM;

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem, OpenSSL3.Err,
     openssl3.crypto.params,            openssl3.crypto.rand.rand_lib,
     openssl3.crypto.des.set_key,       OpenSSL3.openssl.params,
     OpenSSL3.providers.implementations.ciphers.ciphercommon;




function ossl_tdes_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
   Result := @ossl_tdes_known_gettable_ctx_params[0];
end;

function tdes_generatekey( ctx : PPROV_CIPHER_CTX; ptr : Pointer):integer;
var
  deskey : PDES_cblock;

  kl : size_t;
begin
{$POINTERMATH ON}
    deskey := ptr;
    kl := ctx.keylen;
    if (kl = 0)  or  (RAND_priv_bytes_ex(ctx.libctx, ptr, kl, 0) <= 0) then
        Exit(0);
    DES_set_odd_parity(deskey);
    if kl >= 16 then
       DES_set_odd_parity(deskey + 1);
    if kl >= 24 then begin
        DES_set_odd_parity(deskey + 2);
        Exit(1);
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

function ossl_tdes_newctx(provctx : Pointer; mode : integer; kbits, blkbits, ivbits : size_t; flags : uint64;const hw : PPROV_CIPHER_HW):Pointer;
var
  tctx : PPROV_TDES_CTX;
begin
    if not ossl_prov_is_running then Exit(nil);
    tctx := OPENSSL_zalloc(sizeof( tctx^));
    if tctx <> nil then
       ossl_cipher_generic_initkey(tctx, kbits, blkbits, ivbits, mode, flags,
                                    hw, provctx);
    Result := tctx;
end;


function ossl_tdes_dupctx( ctx : Pointer):Pointer;
var
  _in, ret : PPROV_TDES_CTX;
begin
    _in := PPROV_TDES_CTX(ctx);
    if not ossl_prov_is_running then Exit(nil);
    ret := OPENSSL_malloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    _in.base.hw.copyctx(@ret.base, @_in.base);
    Result := ret;
end;


procedure ossl_tdes_freectx( vctx : Pointer);
var
  ctx : PPROV_TDES_CTX;
begin
    ctx := PPROV_TDES_CTX(vctx);
    ossl_cipher_generic_reset_ctx(PPROV_CIPHER_CTX (vctx));
    OPENSSL_clear_free(Pointer(ctx),  sizeof( ctx^));
end;


function tdes_init(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
var
  ctx : PPROV_CIPHER_CTX;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    if not ossl_prov_is_running then Exit(0);
    ctx.num := 0;
    ctx.bufsz := 0;
    ctx.enc := enc;
    if iv <> nil then
    begin
        if 0>=ossl_cipher_generic_initiv(ctx, iv, ivlen) then
            Exit(0);
    end
    else
    if (ctx.iv_set > 0)
                and ( (ctx.mode = EVP_CIPH_CBC_MODE)
                    or  (ctx.mode = EVP_CIPH_CFB_MODE)
                    or  (ctx.mode = EVP_CIPH_OFB_MODE)) then
    begin
        { reset IV to keep compatibility with 1.1.1 }
        memcpy(@ctx.iv, @ctx.oiv, ctx.ivlen);
    end;
    if key <> nil then begin
        if keylen <> ctx.keylen then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        if 0>=ctx.hw.init(ctx, key, ctx.keylen) then
            Exit(0);
    end;
    Result := ossl_cipher_generic_set_ctx_params(ctx, params);
end;


function ossl_tdes_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := tdes_init(vctx, key, keylen, iv, ivlen, params, 1);
end;


function ossl_tdes_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := tdes_init(vctx, key, keylen, iv, ivlen, params, 0);
end;


function ossl_tdes_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p : POSSL_PARAM;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    if 0>=ossl_cipher_generic_get_ctx_params(vctx, params) then
        Exit(0);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_RANDOM_KEY);
    if (p <> nil)  and  (0>=tdes_generatekey(ctx, p.data)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        Exit(0);
    end;
    Result := 1;
end;

initialization
  ossl_tdes_known_gettable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
    _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY, nil, 0),
    OSSL_PARAM_END
 ];
end.
