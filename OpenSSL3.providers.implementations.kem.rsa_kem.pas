unit OpenSSL3.providers.implementations.kem.rsa_kem;

interface
uses OpenSSL.Api;

function name2id(const name : PUTF8Char; map : POSSL_ITEM; sz : size_t):integer;
  function rsakem_opname2id(const name : PUTF8Char):integer;
  function rsakem_newctx( provctx : Pointer):Pointer;
  procedure rsakem_freectx( vprsactx : Pointer);
  function rsakem_dupctx( vprsactx : Pointer):Pointer;
  function rsakem_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
  function rsakem_encapsulate_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
  function rsakem_decapsulate_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
  function rsakem_get_ctx_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
  function rsakem_gettable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
  function rsakem_set_ctx_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
  function rsakem_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
  function rsasve_gen_rand_bytes( rsa_pub : PRSA; &out : PByte; outlen : integer):integer;
  function rsasve_generate( prsactx : PPROV_RSA_CTX3; &out : PByte; outlen : Psize_t; secret : PByte; secretlen : Psize_t):integer;
  function rsasve_recover(prsactx : PPROV_RSA_CTX3; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
  function rsakem_generate( vprsactx : Pointer; &out : PByte; outlen : Psize_t; secret : PByte; secretlen : Psize_t):integer;
  function rsakem_recover(vprsactx : Pointer; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;

const  ossl_rsa_asym_kem_functions: array[0..11] of TOSSL_DISPATCH = (
    (function_id:  OSSL_FUNC_KEM_NEWCTX; method:(code:@rsakem_newctx; data:nil)),
    (function_id:  OSSL_FUNC_KEM_ENCAPSULATE_INIT;
      method:(code:@rsakem_encapsulate_init; data:nil)),
    (function_id:  OSSL_FUNC_KEM_ENCAPSULATE; method:(code:@rsakem_generate; data:nil)),
    (function_id:  OSSL_FUNC_KEM_DECAPSULATE_INIT;
      method:(code:@rsakem_decapsulate_init; data:nil)),
    (function_id:  OSSL_FUNC_KEM_DECAPSULATE; method:(code:@rsakem_recover; data:nil)),
    (function_id:  OSSL_FUNC_KEM_FREECTX; method:(code:@rsakem_freectx; data:nil)),
    (function_id:  OSSL_FUNC_KEM_DUPCTX; method:(code:@rsakem_dupctx; data:nil)),
    (function_id:  OSSL_FUNC_KEM_GET_CTX_PARAMS;
      method:(code:@rsakem_get_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS;
      method:(code:@rsakem_gettable_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_KEM_SET_CTX_PARAMS;
      method:(code:@rsakem_set_ctx_params; data:nil)),
    (function_id:  OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS;
      method:(code:@rsakem_settable_ctx_params; data:nil)),
    (function_id:  0; method:(code:nil; data:nil) )
);
 KEM_OP_RSASVE   =    0;
 KEM_OP_UNDEFINED  = -1;
 rsakem_opname_id_map:array[0..0] of TOSSL_ITEM = (
    ( id: KEM_OP_RSASVE; ptr: OSSL_KEM_PARAM_OPERATION_RSASVE )
);

var
  known_gettable_rsakem_ctx_params: array[0..0] of TOSSL_PARAM;
  known_settable_rsakem_ctx_params: array[0..1] of TOSSL_PARAM;

implementation
uses openssl3.crypto.mem, openssl3.providers.common.provider_ctx,
     OpenSSL3.providers.common.securitycheck, openssl3.crypto.params,
     OpenSSL3.crypto.rsa.rsa_crpt,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.bn.bn_lib,  openssl3.crypto.bn.bn_word,
     openssl3.crypto.bn.bn_prime, openssl3.crypto.bn.bn_rand,
     OpenSSL3.Err, OpenSSL3.openssl.params;

function name2id(const name : PUTF8Char; map : POSSL_ITEM; sz : size_t):integer;
var
  i : size_t;

begin
{$POINTERMATH ON}
    if name = nil then Exit(-1);
    for i := 0 to sz-1 do
    begin
        if strcasecmp(map[i].ptr, name) = 0  then
            Exit(map[i].id);
    end;
    Result := -1;
{$POINTERMATH OFF}
end;


function rsakem_opname2id(const name : PUTF8Char):integer;
begin
    Result := name2id(name, @rsakem_opname_id_map, Length(rsakem_opname_id_map));
end;


function rsakem_newctx( provctx : Pointer):Pointer;
var
  prsactx : PPROV_RSA_CTX3;
begin
    prsactx := OPENSSL_zalloc(sizeof(TPROV_RSA_CTX3));
    if prsactx = nil then Exit(nil);
    prsactx.libctx := PROV_LIBCTX_OF(provctx);
    prsactx.op := KEM_OP_UNDEFINED;
    Result := prsactx;
end;


procedure rsakem_freectx( vprsactx : Pointer);
var
  prsactx : PPROV_RSA_CTX3;
begin
    prsactx := PPROV_RSA_CTX3 ( vprsactx);
    RSA_free(prsactx.rsa);
    OPENSSL_free(Pointer(prsactx));
end;


function rsakem_dupctx( vprsactx : Pointer):Pointer;
var
  srcctx, dstctx : PPROV_RSA_CTX3;
begin
    srcctx := PPROV_RSA_CTX3 ( vprsactx);
    dstctx := OPENSSL_zalloc(sizeof( srcctx^));
    if dstctx = nil then Exit(nil);
    dstctx^ := srcctx^;
    if (dstctx.rsa <> nil)  and  (0>= RSA_up_ref(dstctx.rsa)) then
    begin
        OPENSSL_free(Pointer(dstctx));
        Exit(nil);
    end;
    Result := dstctx;
end;


function rsakem_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM; operation : integer):integer;
var
  prsactx : PPROV_RSA_CTX3;
begin
    prsactx := PPROV_RSA_CTX3 ( vprsactx);
    if (prsactx = nil)  or  (vrsa = nil) then Exit(0);
    if 0>= ossl_rsa_check_key(prsactx.libctx, vrsa, operation) then
        Exit(0);
    if 0>= RSA_up_ref(vrsa) then
        Exit(0);
    RSA_free(prsactx.rsa);
    prsactx.rsa := vrsa;
    Result := rsakem_set_ctx_params(prsactx, params);
end;


function rsakem_encapsulate_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := rsakem_init(vprsactx, vrsa, params, EVP_PKEY_OP_ENCAPSULATE);
end;


function rsakem_decapsulate_init(vprsactx, vrsa : Pointer;const params : POSSL_PARAM):integer;
begin
    Result := rsakem_init(vprsactx, vrsa, params, EVP_PKEY_OP_DECAPSULATE);
end;


function rsakem_get_ctx_params( vprsactx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_RSA_CTX3;
begin
    ctx := PPROV_RSA_CTX3 ( vprsactx);
    Result := Int(ctx <> nil);
end;


function rsakem_gettable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_gettable_rsakem_ctx_params;
end;


function rsakem_set_ctx_params(vprsactx : Pointer;const params : POSSL_PARAM):integer;
var
  prsactx : PPROV_RSA_CTX3;
  p: POSSL_PARAM;
  op : integer;
begin
    prsactx := PPROV_RSA_CTX3 ( vprsactx);
    if prsactx = nil then Exit(0);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_OPERATION);
    if p <> nil then begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        op := rsakem_opname2id(p.data);
        if op < 0 then Exit(0);
        prsactx.op := op;
    end;
    Result := 1;
end;


function rsakem_settable_ctx_params( vprsactx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @known_settable_rsakem_ctx_params;
end;


function rsasve_gen_rand_bytes( rsa_pub : PRSA; &out : PByte; outlen : integer):integer;
var
  ret : integer;

  bnctx : PBN_CTX;

  z, nminus3 : PBIGNUM;
begin
    ret := 0;
    bnctx := BN_CTX_secure_new_ex(ossl_rsa_get0_libctx(rsa_pub));
    if bnctx = nil then Exit(0);
    {
     * Generate a random in the range 1 < z < (n ¨C 1).
     * Since BN_priv_rand_range_ex() returns a value in range 0 <= r < max
     * We can achieve this by adding 2.. but then we need to subtract 3 from
     * the upper bound i.e: 2 + (0 <= r < (n - 3))
     }
    BN_CTX_start(bnctx);
    nminus3 := BN_CTX_get(bnctx);
    z := BN_CTX_get(bnctx);
    ret := Int( (z <> nil)
            and  (BN_copy(nminus3, RSA_get0_n(rsa_pub)) <> nil)
            and  (BN_sub_word(nminus3, 3) >0)
            and  (BN_priv_rand_range_ex(z, nminus3, 0, bnctx)>0)
            and  (BN_add_word(z, 2)>0)
            and  (BN_bn2binpad(z, out, outlen) = outlen));
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    Result := ret;
end;


function rsasve_generate( prsactx : PPROV_RSA_CTX3; &out : PByte; outlen : Psize_t; secret : PByte; secretlen : Psize_t):integer;
var
  ret : integer;
  nlen : size_t;
begin
    { Step (1): nlen = Ceil(len(n)/8) }
    nlen := RSA_size(prsactx.rsa);
    if out = nil then
    begin
        if nlen = 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            Exit(0);
        end;
        if (outlen = nil)  and  (secretlen = nil) then
           Exit(0);
        if outlen <> nil then
           outlen^ := nlen;
        if secretlen <> nil then
           secretlen^ := nlen;
        Exit(1);
    end;
    {
     * Step (2): Generate a random byte string z of nlen bytes where
     *            1 < z < n - 1
     }
    if 0>= rsasve_gen_rand_bytes(prsactx.rsa, secret, nlen )then
        Exit(0);
    { Step(3): out = RSAEP((n,e), z) }
    ret := RSA_public_encrypt(nlen, secret, out, prsactx.rsa, RSA_NO_PADDING);
    if ret >0 then
    begin
        ret := 1;
        if outlen <> nil then
           outlen^ := nlen;
        if secretlen <> nil then
           secretlen^ := nlen;
    end
    else
    begin
        OPENSSL_cleanse(secret, nlen);
    end;
    Result := ret;
end;


function rsasve_recover(prsactx : PPROV_RSA_CTX3; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
var
  nlen : size_t;
begin
    { Step (1): get the byte length of n }
    nlen := RSA_size(prsactx.rsa);
    if out = nil then
    begin
        if nlen = 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            Exit(0);
        end;
        outlen^ := nlen;
        Exit(1);
    end;
    { Step (2): check the input ciphertext 'inlen' matches the nlen }
    if inlen <> nlen then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        Exit(0);
    end;
    { Step (3): out = RSADP((n,d), in) }
    Result := int(RSA_private_decrypt(inlen, &in, out, prsactx.rsa, RSA_NO_PADDING) > 0);
end;


function rsakem_generate( vprsactx : Pointer; &out : PByte; outlen : Psize_t; secret : PByte; secretlen : Psize_t):integer;
var
  prsactx : PPROV_RSA_CTX3;
begin
    prsactx := PPROV_RSA_CTX3 ( vprsactx);
    case prsactx.op of
        KEM_OP_RSASVE:
            Exit(rsasve_generate(prsactx, out, outlen, secret, secretlen));
        else
            Exit(-2);
    end;
end;


function rsakem_recover(vprsactx : Pointer; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
var
  prsactx : PPROV_RSA_CTX3;
begin
    prsactx := PPROV_RSA_CTX3 ( vprsactx);
    case prsactx.op of
        KEM_OP_RSASVE:
            Exit(rsasve_recover(prsactx, out, outlen, &in, inlen));
        else
            Exit(-2);
    end;
end;

initialization
  known_gettable_rsakem_ctx_params[0] :=  OSSL_PARAM_END;
  known_settable_rsakem_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, nil, 0);
  known_settable_rsakem_ctx_params[0] := OSSL_PARAM_END;

end.
