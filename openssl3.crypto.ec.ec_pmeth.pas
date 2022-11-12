unit openssl3.crypto.ec.ec_pmeth;

interface
uses OpenSSL.Api, SysUtils;

 function ossl_ec_pkey_method:PEVP_PKEY_METHOD;
 function pkey_ec_init( ctx : PEVP_PKEY_CTX):integer;
  function pkey_ec_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
  procedure pkey_ec_cleanup( ctx : PEVP_PKEY_CTX);
  function pkey_ec_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
  function pkey_ec_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function pkey_ec_derive( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
  function pkey_ec_kdf_derive( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
  function pkey_ec_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
  function pkey_ec_paramgen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
  function pkey_ec_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
  function pkey_ec_ctrl_str(ctx : PEVP_PKEY_CTX;const _type, value : PUTF8Char):integer;


 const  ec_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_EC;
    flags: 0;
    init: pkey_ec_init;
    copy: pkey_ec_copy;
    cleanup: pkey_ec_cleanup;
    paramgen_init: nil;
    paramgen: pkey_ec_paramgen;
    keygen_init: nil;
    keygen: pkey_ec_keygen;
    sign_init: nil;
    sign: pkey_ec_sign;
    verify_init: nil;
    verify: pkey_ec_verify;
    verify_recover_init: nil;
    verify_recover: nil;
    signctx_init: nil;
    signctx: nil;
    verifyctx_init: nil;
    verifyctx: nil;
    encrypt_init: nil;
    encrypt: nil;
    decrypt_init: nil;
    decrypt: nil;

    derive_init: nil;
{$ifndef OPENSSL_NO_EC}
    derive: pkey_ec_kdf_derive;
{$ELSE}
    derive: nil;
{$ENDIF}
    ctrl: pkey_ec_ctrl;
    ctrl_str: pkey_ec_ctrl_str
);

implementation
uses OpenSSL3.Err, openssl3.crypto.ec.ec_curve, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.ec.ec_ctrl, openssl3.crypto.evp.names,
     openssl3.crypto.mem, openssl3.crypto.ec.ec_lib,
     OpenSSL3.common, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.evp.p_lib,
     openssl3.crypto.evp, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.ec.ecdsa_sign, openssl3.crypto.ec.ecdsa_vrf,
     openssl3.crypto.evp.p_legacy, openssl3.crypto.ec.ec_asn1,
     openssl3.crypto.ec.ec_kmeth, openssl3.crypto.ec.ecdh_kdf,
     openssl3.crypto.ec.ec_key, openssl3.crypto.o_str;







function pkey_ec_ctrl_str(ctx : PEVP_PKEY_CTX;const _type, value : PUTF8Char):integer;
var
  nid,
  param_enc,
  co_mode   : integer;
  md: PEVP_MD;
begin
    if strcmp(_type, 'ec_paramgen_curve' ) = 0 then
    begin
        nid := EC_curve_nist2nid(value);
        if nid = NID_undef then nid := OBJ_sn2nid(value);
        if nid = NID_undef then nid := OBJ_ln2nid(value);
        if nid = NID_undef then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            Exit(0);
        end;
        Exit(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid));
    end
    else
    if (strcmp(_type, 'ec_param_enc') = 0) then
    begin
        if strcmp(value, 'explicit') = 0  then
            param_enc := 0
        else if (strcmp(value, 'named_curve') = 0)  then
            param_enc := OPENSSL_EC_NAMED_CURVE
        else
            Exit(-2);
        Exit(EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc));
    end
    else
    if (strcmp(_type, 'ecdh_kdf_md') = 0)  then
    begin
        md := EVP_get_digestbyname(value);
        if md = nil then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_DIGEST);
            Exit(0);
        end;
        Exit(EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md));
    end
    else
    if (strcmp(_type, 'ecdh_cofactor_mode') = 0)  then
    begin
        co_mode := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode));
    end;
    Result := -2;
end;


function pkey_ec_init( ctx : PEVP_PKEY_CTX):integer;
var
  dctx : PEC_PKEY_CTX;
begin
    dctx := OPENSSL_zalloc(sizeof(dctx^ ));
    if dctx = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    dctx.cofactor_mode := -1;
    dctx.kdf_type := EVP_PKEY_ECDH_KDF_NONE;
    ctx.data := dctx;
    Result := 1;
end;


function pkey_ec_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
var
  dctx, sctx : PEC_PKEY_CTX;
begin
    if 0>= pkey_ec_init(dst ) then
        Exit(0);
    sctx := src.data;
    dctx := dst.data;
    if sctx.gen_group <> nil then
    begin
        dctx.gen_group := EC_GROUP_dup(sctx.gen_group);
        if nil = dctx.gen_group then
           Exit(0);
    end;
    dctx.md := sctx.md;
    if sctx.co_key <> nil then
    begin
        dctx.co_key := EC_KEY_dup(sctx.co_key);
        if nil = dctx.co_key then Exit(0);
    end;
    dctx.kdf_type := sctx.kdf_type;
    dctx.kdf_md := sctx.kdf_md;
    dctx.kdf_outlen := sctx.kdf_outlen;
    if sctx.kdf_ukm <> nil then
    begin
        dctx.kdf_ukm := OPENSSL_memdup(sctx.kdf_ukm, sctx.kdf_ukmlen);
        if nil = dctx.kdf_ukm then
           Exit(0);
    end
    else
        dctx.kdf_ukm := nil;
    dctx.kdf_ukmlen := sctx.kdf_ukmlen;
    Result := 1;
end;


procedure pkey_ec_cleanup( ctx : PEVP_PKEY_CTX);
var
  dctx : PEC_PKEY_CTX;
begin
    dctx := ctx.data;
    if dctx <> nil then
    begin
        EC_GROUP_free(dctx.gen_group);
        EC_KEY_free(dctx.co_key);
        OPENSSL_free(Pointer(dctx.kdf_ukm));
        OPENSSL_free(Pointer(dctx));
        ctx.data := nil;
    end;
end;


function pkey_ec_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret, _type : integer;
  sltmp : uint32;
  dctx : PEC_PKEY_CTX;
  ec : PEC_KEY;
  sig_sz : integer;
begin
    dctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    ec := PEC_KEY(EVP_PKEY_get0_EC_KEY(ctx.pkey));
     sig_sz := ECDSA_size(ec);
    { ensure cast to size_t is safe }
    if not ossl_assert(sig_sz > 0)   then
        Exit(0);
    if sig = nil then
    begin
        siglen^ := size_t( sig_sz);
        Exit(1);
    end;
    if siglen^ < size_t( sig_sz) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    _type := get_result((dctx.md <> nil) , EVP_MD_get_type(dctx.md) , NID_sha1);
    ret := _ECDSA_sign(_type, tbs, tbslen, sig, @sltmp, ec);
    if ret <= 0 then Exit(ret);
    siglen^ := size_t( sltmp);
    Result := 1;
end;


function pkey_ec_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret, _type : integer;

  dctx : PEC_PKEY_CTX;

  ec : PEC_KEY;
begin
    dctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    ec := PEC_KEY(EVP_PKEY_get0_EC_KEY(ctx.pkey));
    if dctx.md <> nil then
       _type := EVP_MD_get_type(dctx.md)
    else
       _type := NID_sha1;
    ret := _ECDSA_verify(_type, tbs, tbslen, sig, siglen, ec);
    Result := ret;
end;


function pkey_ec_derive( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
var
    ret      : integer;
    outlen   : size_t;
    pubkey   : PEC_POINT;
    eckey,
    eckeypub : PEC_KEY;
    dctx     : PEC_PKEY_CTX;
    group    : PEC_GROUP;
begin
     pubkey := nil;
    dctx := ctx.data;
    if (ctx.pkey = nil)  or  (ctx.peerkey = nil) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_KEYS_NOT_SET);
        Exit(0);
    end;
    eckeypub := EVP_PKEY_get0_EC_KEY(ctx.peerkey);
    if eckeypub = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_KEYS_NOT_SET);
        Exit(0);
    end;
    if dctx.co_key <> nil then
       eckey :=  dctx.co_key
    else
       eckey := PEC_KEY(EVP_PKEY_get0_EC_KEY(ctx.pkey));
    if nil = key then
    begin
        group := EC_KEY_get0_group(eckey);
        if group = nil then Exit(0);
        keylen^ := (EC_GROUP_get_degree(group) + 7) div 8;
        Exit(1);
    end;
    pubkey := EC_KEY_get0_public_key(eckeypub);
    {
     * NB: unlike PKCS#3 DH, if *outlen is less than maximum size this is not
     * an error, the result is truncated.
     }
    outlen := keylen^;
    ret := ECDH_compute_key(key, outlen, pubkey, eckey, nil);
    if ret <= 0 then Exit(0);
    keylen^ := ret;
    Result := 1;
end;


function pkey_ec_kdf_derive( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
var
  dctx : PEC_PKEY_CTX;
  ktmp : PByte;
  ktmplen : size_t;
  rv : integer;
  label _err;
begin
    dctx := ctx.data;
    ktmp := nil;
    rv := 0;
    if dctx.kdf_type = EVP_PKEY_ECDH_KDF_NONE then
       Exit(pkey_ec_derive(ctx, key, keylen));
    if nil = key then
    begin
        keylen^ := dctx.kdf_outlen;
        Exit(1);
    end;
    if keylen^ <> dctx.kdf_outlen then Exit(0);
    if 0>= pkey_ec_derive(ctx, nil, @ktmplen) then
        Exit(0);
    ktmp := OPENSSL_malloc(ktmplen) ;
    if ktmp =  nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>= pkey_ec_derive(ctx, ktmp, @ktmplen) then
        goto _err ;
    { Do KDF stuff }
    if 0>= ossl_ecdh_kdf_X9_63(key, keylen^, ktmp, ktmplen,
                             dctx.kdf_ukm, dctx.kdf_ukmlen, dctx.kdf_md,
                             ctx.libctx, ctx.propquery ) then
        goto _err ;
    rv := 1;
 _err:
    OPENSSL_clear_free(Pointer(ktmp), ktmplen);
    Result := rv;
end;


function pkey_ec_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
const
    nids: array[0..10] of int = (
             NID_sha1
            , NID_ecdsa_with_SHA1
            , NID_sha224
            , NID_sha256
            , NID_sha384
            , NID_sha512
            , NID_sha3_224
            , NID_sha3_256
            , NID_sha3_384
            , NID_sha3_512
            , NID_sm3);
var
  dctx : PEC_PKEY_CTX;
  group : PEC_GROUP;
  ec_key : PEC_KEY;

  function NidInArray(nid : int) : Boolean;
  var
    n: int;
  begin
    for n in nids do
    begin
      if nid = n then
      begin
         Exit(true);
      end;
    end;
    result := false;
  end;
begin
    dctx := ctx.data;
    case _type of
    EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
    begin
        group := EC_GROUP_new_by_curve_name(p1);
        if group = nil then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            Exit(0);
        end;
        EC_GROUP_free(dctx.gen_group);
        dctx.gen_group := group;
        Exit(1);
    end;
    EVP_PKEY_CTRL_EC_PARAM_ENC:
    begin
        if nil = dctx.gen_group then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_NO_PARAMETERS_SET);
            Exit(0);
        end;
        EC_GROUP_set_asn1_flag(dctx.gen_group, p1);
        Exit(1);
    end;
{$IFNDEF OPENSSL_NO_EC}
    EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
    begin
        if p1 = -2 then
        begin
            if dctx.cofactor_mode <> -1 then
                Exit(dctx.cofactor_mode)
            else
            begin
                ec_key := EVP_PKEY_get0_EC_KEY(ctx.pkey);
                Exit(get_result( (EC_KEY_get_flags(ec_key) and EC_FLAG_COFACTOR_ECDH) > 0, 1 , 0));
            end;
        end
        else if (p1 < -1)  or  (p1 > 1) then
            Exit(-2);
        dctx.cofactor_mode := p1;
        if p1 <> -1 then
        begin
            ec_key := PEC_KEY(EVP_PKEY_get0_EC_KEY(ctx.pkey));
            {
             * We discarded the 'const' above. This will only work if the key is
             * a 'real' legacy key, and not a cached copy of a provided key
             }
            if evp_pkey_is_provided(ctx.pkey) then
            begin
                ERR_raise(ERR_LIB_EC, ERR_R_UNSUPPORTED);
                Exit(0);
            end;
            if nil = ec_key.group then Exit(-2);
            { If cofactor is 1 cofactor mode does nothing }
            if BN_is_one(ec_key.group.cofactor) then
                Exit(1);
            if nil = dctx.co_key then
            begin
                dctx.co_key := EC_KEY_dup(ec_key);
                if nil = dctx.co_key then Exit(0);
            end;
            if p1 > 0 then
               EC_KEY_set_flags(dctx.co_key, EC_FLAG_COFACTOR_ECDH)
            else
                EC_KEY_clear_flags(dctx.co_key, EC_FLAG_COFACTOR_ECDH);
        end
        else
        begin
            EC_KEY_free(dctx.co_key);
            dctx.co_key := nil;
        end;
        Exit(1);
    end;
{$ENDIF}
    EVP_PKEY_CTRL_EC_KDF_TYPE:
    begin
        if p1 = -2 then Exit(dctx.kdf_type);
        if (p1 <> EVP_PKEY_ECDH_KDF_NONE)  and  (p1 <> EVP_PKEY_ECDH_KDF_X9_63) then
           Exit(-2);
        dctx.kdf_type := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_EC_KDF_MD:
    begin
        dctx.kdf_md := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_EC_KDF_MD:
    begin
        PPEVP_MD( p2)^ := dctx.kdf_md;
        Exit(1);
    end;
    EVP_PKEY_CTRL_EC_KDF_OUTLEN:
    begin
        if p1 <= 0 then Exit(-2);
        dctx.kdf_outlen := size_t( p1);
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
    begin
        PInteger(p2)^ := dctx.kdf_outlen;
        Exit(1);
    end;
    EVP_PKEY_CTRL_EC_KDF_UKM:
    begin
        OPENSSL_free(Pointer(dctx.kdf_ukm));
        dctx.kdf_ukm := p2;
        if p2 <> nil then
           dctx.kdf_ukmlen := p1
        else
            dctx.kdf_ukmlen := 0;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_EC_KDF_UKM:
    begin
        PPByte( p2)^ := dctx.kdf_ukm;
        Exit(dctx.kdf_ukmlen);
    end;
    EVP_PKEY_CTRL_MD:
    begin
        if  not NidInArray(EVP_MD_get_type(PEVP_MD(p2))) then
        begin
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_DIGEST_TYPE);
            Exit(0);
        end;
        dctx.md := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_MD:
    begin
        PPEVP_MD( p2)^ := dctx.md;
        Exit(1);
    end;
    EVP_PKEY_CTRL_PEER_KEY,
        { Default behaviour is OK }
    EVP_PKEY_CTRL_DIGESTINIT,
    EVP_PKEY_CTRL_PKCS7_SIGN,
    EVP_PKEY_CTRL_CMS_SIGN:
        Exit(1);
    else
        Exit(-2);
    end;
end;


function pkey_ec_paramgen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  ec : PEC_KEY;
  dctx : PEC_PKEY_CTX;
  ret : integer;
begin
    ec := nil;
    dctx := ctx.data;
    if dctx.gen_group = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_NO_PARAMETERS_SET);
        Exit(0);
    end;
    ec := EC_KEY_new();
    if ec = nil then Exit(0);
    ret := EC_KEY_set_group(ec, dctx.gen_group);
    if (0>= ret )   or
       (not ossl_assert(ret = EVP_PKEY_assign_EC_KEY(pkey, ec))) then
        EC_KEY_free(ec);
    Result := ret;
end;


function pkey_ec_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  ec : PEC_KEY;

  dctx : PEC_PKEY_CTX;

  ret : integer;
begin
    ec := nil;
    dctx := ctx.data;
    if (ctx.pkey = nil)  and  (dctx.gen_group = nil) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_NO_PARAMETERS_SET);
        Exit(0);
    end;
    ec := EC_KEY_new();
    if ec = nil then Exit(0);
    if not ossl_assert(EVP_PKEY_assign_EC_KEY(pkey, ec)>0)  then
    begin
        EC_KEY_free(ec);
        Exit(0);
    end;
    { Note: if error is returned, we count on caller to free pkey.pkey.ec }
    if ctx.pkey <> nil then
       ret := EVP_PKEY_copy_parameters(pkey, ctx.pkey)
    else
        ret := EC_KEY_set_group(ec, dctx.gen_group);
    Result := get_result(ret>0,  EC_KEY_generate_key(ec) , 0);
end;



function ossl_ec_pkey_method:PEVP_PKEY_METHOD;
begin
    Result := @ec_pkey_meth;
end;

end.
