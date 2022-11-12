unit openssl3.crypto.dh.dh_pmeth;

interface
uses  OpenSSL.Api, SysUtils;

const
{$ifdef FIPS_MODULE}
   MIN_STRENGTH = 112;
{$else}
   MIN_STRENGTH = 80;
{$endif}

 function ossl_dh_key2buf(const dh : PDH; pbuf_out : PPByte; size : size_t; alloc : integer):size_t;
 function ossl_dh_generate_public_key(ctx : PBN_CTX;const dh : PDH; priv_key : PBIGNUM; pub_key : PBIGNUM):integer;
 function ossl_dh_buf2key(dh : PDH;const buf : PByte; len : size_t):integer;

 function generate_key(dh : PDH):integer;
 function ossl_dh_compute_key(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
 function dh_bn_mod_exp(const dh : PDH; r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX; m_ctx : PBN_MONT_CTX):integer;
 function dh_init( dh : PDH):integer;
 function dh_finish( dh : PDH):integer;
 procedure DH_get0_key(const dh : PDH; pub_key, priv_key : PPBIGNUM);
 function ossl_dh_pkey_method:PEVP_PKEY_METHOD;
 function pkey_dh_init( ctx : PEVP_PKEY_CTX):integer;
 function pkey_dh_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
 procedure pkey_dh_cleanup( ctx : PEVP_PKEY_CTX);
 function pkey_dh_paramgen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
 function pkey_dh_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
 function pkey_dh_derive( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
 function pkey_dh_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
 function pkey_dh_ctrl_str(ctx : PEVP_PKEY_CTX;const _type, value : PUTF8Char):integer;
 function ffc_params_generate( libctx : POSSL_LIB_CTX; dctx : PDH_PKEY_CTX; pcb : PBN_GENCB):PDH;

 const  dh_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_DH;
    flags: 0;
    init: pkey_dh_init;
    copy: pkey_dh_copy;
    cleanup: pkey_dh_cleanup;
    paramgen_init: nil;
    paramgen: pkey_dh_paramgen;
    keygen_init: nil;
    keygen: pkey_dh_keygen;
    sign_init: nil;
    sign: nil;
    verify_init: nil;
    verify: nil;
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
    derive: pkey_dh_derive;
    ctrl: pkey_dh_ctrl;
    ctrl_str: pkey_dh_ctrl_str
);

const  dhx_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_DHX;
    flags: 0;
    init: pkey_dh_init;
    copy: pkey_dh_copy;
    cleanup: pkey_dh_cleanup;
    paramgen_init: nil;
    paramgen: pkey_dh_paramgen;
    keygen_init: nil;
    keygen: pkey_dh_keygen;
    sign_init: nil;
    sign: nil;
    verify_init: nil;
    verify: nil;
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
    derive: pkey_dh_derive;
    ctrl: pkey_dh_ctrl;
    ctrl_str: pkey_dh_ctrl_str
);

function ossl_dhx_pkey_method:PEVP_PKEY_METHOD;

implementation

uses openssl3.crypto.bn.bn_lib, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.crypto.bn.bn_mont,  openssl3.crypto.dh.dh_lib,
     openssl3.crypto.dh.dh_ctrl, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.dh.dh_group_params, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_word,
     openssl3.crypto.evp.p_lib, openssl3.crypto.dh.dh_key,
     openssl3.crypto.ffc.ffc_params_generate,
     openssl3.crypto.o_str,
     openssl3.crypto.evp, openssl3.crypto.objects.obj_lib,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.dh.dh_gen,
     openssl3.crypto.dh.dh_kdf,  openssl3.crypto.evp.pmeth_gn,
     openssl3.crypto.ffc.ffc_params_validate, openssl3.crypto.asn1.a_object,
     openssl3.crypto.ffc.ffc_key_generate, openssl3.crypto.bn.bn_rand,
     openssl3.crypto.ffc.ffc_params, openssl3.crypto.bn.bn_exp;





function ossl_dhx_pkey_method:PEVP_PKEY_METHOD;
begin
    Result := @dhx_pkey_meth;
end;

function ffc_params_generate( libctx : POSSL_LIB_CTX; dctx : PDH_PKEY_CTX; pcb : PBN_GENCB):PDH;
var
  ret          : PDH;
  rv,
  res,
  prime_len,
  subprime_len : integer;
begin
    rv := 0;
    prime_len := dctx.prime_len;
    subprime_len := dctx.subprime_len;
    if dctx.paramgen_type > DH_PARAMGEN_TYPE_FIPS_186_4 then
       Exit(nil);
    ret := DH_new();
    if ret = nil then
       Exit(nil);
    if subprime_len = -1 then
    begin
        if prime_len >= 2048 then
           subprime_len := 256
        else
           subprime_len := 160;
    end;
    if dctx.md <> nil then
       ossl_ffc_set_digest(@ret.params, EVP_MD_get0_name(dctx.md), nil);
{$IFNDEF FIPS_MODULE}
    if dctx.paramgen_type = DH_PARAMGEN_TYPE_FIPS_186_2 then
       rv := ossl_ffc_params_FIPS186_2_generate(libctx, @ret.params,
                                                FFC_PARAM_TYPE_DH,
                                                prime_len, subprime_len, @res,
                                                pcb)
    else
{$ENDIF}
    { For FIPS we always use the DH_PARAMGEN_TYPE_FIPS_186_4 generator }
    if dctx.paramgen_type >= DH_PARAMGEN_TYPE_FIPS_186_2 then
       rv := ossl_ffc_params_FIPS186_4_generate(libctx, @ret.params,
                                               FFC_PARAM_TYPE_DH,
                                               prime_len, subprime_len, @res,
                                               pcb);
    if rv <= 0 then
    begin
        DH_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;


function pkey_dh_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
var
  dctx : PDH_PKEY_CTX;
begin
    dctx := ctx.data;
    case _type of
    EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN:
    begin
        if p1 < 256 then
           Exit(-2);
        dctx.prime_len := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN:
    begin
        if dctx.paramgen_type = DH_PARAMGEN_TYPE_GENERATOR then
           Exit(-2);
        dctx.subprime_len := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_PAD:
    begin
        dctx.pad := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR:
    begin
        if dctx.paramgen_type <> DH_PARAMGEN_TYPE_GENERATOR then
           Exit(-2);
        dctx.generator := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_PARAMGEN_TYPE:
    begin
{$IFDEF OPENSSL_NO_DSA}
        if p1 <> DH_PARAMGEN_TYPE_GENERATOR then
           Exit(-2);
{$ELSE} if (p1 < 0)  or  (p1 > 2) then
           Exit(-2);
{$ENDIF}
        dctx.paramgen_type := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_RFC5114:
    begin
        if (p1 < 1)  or  (p1 > 3)  or  (dctx.param_nid <> NID_undef) then
           Exit(-2);
        dctx.param_nid := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_NID:
    begin
        if (p1 <= 0)  or  (dctx.param_nid <> NID_undef) then
           Exit(-2);
        dctx.param_nid := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_PEER_KEY:
        { Default behaviour is OK }
        Exit(1);
    EVP_PKEY_CTRL_DH_KDF_TYPE:
    begin
        if p1 = -2 then
           Exit(dctx.kdf_type);
        if (p1 <> EVP_PKEY_DH_KDF_NONE)  and  (p1 <> EVP_PKEY_DH_KDF_X9_42) then
           Exit(-2);
        dctx.kdf_type := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_KDF_MD:
    begin
        dctx.kdf_md := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_DH_KDF_MD:
    begin
        PPEVP_MD(p2)^ := dctx.kdf_md;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_KDF_OUTLEN:
    begin
        if p1 <= 0 then Exit(-2);
        dctx.kdf_outlen := size_t( p1);
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN:
    begin
        PInteger(p2)^ := dctx.kdf_outlen;
        Exit(1);
    end;
    EVP_PKEY_CTRL_DH_KDF_UKM:
    begin
        OPENSSL_free(dctx.kdf_ukm);
        dctx.kdf_ukm := p2;
        if p2 <> nil then
           dctx.kdf_ukmlen := p1
        else
            dctx.kdf_ukmlen := 0;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_DH_KDF_UKM:
    begin
        PPByte(p2)^ := dctx.kdf_ukm;
        Exit(dctx.kdf_ukmlen);
    end;
    EVP_PKEY_CTRL_DH_KDF_OID:
    begin
        ASN1_OBJECT_free(dctx.kdf_oid);
        dctx.kdf_oid := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_DH_KDF_OID:
    begin
        PPASN1_OBJECT(p2)^ := dctx.kdf_oid;
        Exit(1);
    end
    else
        Exit(-2);
    end;
end;


function pkey_dh_ctrl_str(ctx : PEVP_PKEY_CTX;const _type, value : PUTF8Char):integer;
var
  dctx : PDH_PKEY_CTX;
  id : integer;
  nid, len, typ, pad : integer;
begin
    if strcmp(_type, 'dh_paramgen_prime_len' ) = 0 then
    begin
        len := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len));
    end;
    if strcmp(_type, 'dh_rfc5114' ) = 0 then
    begin
        dctx := ctx.data;
        id := StrToInt(value);
        if (id < 0)  or  (id > 3) then Exit(-2);
        dctx.param_nid := id;
        Exit(1);
    end;
    if strcmp(_type, 'dh_param' ) = 0 then
    begin
        dctx := ctx.data;
        nid := OBJ_sn2nid(value);
        if nid = NID_undef then
        begin
            ERR_raise(ERR_LIB_DH, DH_R_INVALID_PARAMETER_NAME);
            Exit(-2);
        end;
        dctx.param_nid := nid;
        Exit(1);
    end;
    if strcmp(_type, 'dh_paramgen_generator' ) = 0 then
    begin
        len := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, len));
    end;
    if strcmp(_type, 'dh_paramgen_subprime_len' ) = 0 then
    begin
        len := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len));
    end;
    if strcmp(_type, 'dh_paramgen_type' ) = 0 then
    begin
        typ := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ));
    end;
    if strcmp(_type, 'dh_pad' ) = 0 then
    begin
        pad := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dh_pad(ctx, pad));
    end;
    Result := -2;
end;



function pkey_dh_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  dctx : PDH_PKEY_CTX;

  dh : PDH;
begin
    dctx := ctx.data;
    dh := nil;
    if (ctx.pkey = nil)  and  (dctx.param_nid = NID_undef) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_NO_PARAMETERS_SET);
        Exit(0);
    end;
    if dctx.param_nid <> NID_undef then
       dh := DH_new_by_nid(dctx.param_nid)
    else
        dh := DH_new();
    if dh = nil then
       Exit(0);
    EVP_PKEY_assign(pkey, ctx.pmeth.pkey_id, dh);
    { Note: if error return, pkey is freed by parent routine }
    if (ctx.pkey <> nil)  and  (0>= EVP_PKEY_copy_parameters(pkey, ctx.pkey)) then
        Exit(0);
    Result := DH_generate_key(PDH(EVP_PKEY_get0_DH(pkey)));
end;


function pkey_dh_derive( ctx : PEVP_PKEY_CTX; key : PByte; keylen : Psize_t):integer;
var
  ret : integer;
  dh, dhpub : PDH;
  dctx : PDH_PKEY_CTX;
  dhpubbn : PBIGNUM;
  Z : PByte;
  Zlen : size_t;
  label _err;
begin
    dctx := ctx.data;
    if (ctx.pkey = nil)  or  (ctx.peerkey = nil) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_KEYS_NOT_SET);
        Exit(0);
    end;
    dh := PDH(EVP_PKEY_get0_DH(ctx.pkey));
    dhpub := EVP_PKEY_get0_DH(ctx.peerkey);
    if dhpub = nil then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_KEYS_NOT_SET);
        Exit(0);
    end;
    dhpubbn := dhpub.pub_key;
    if dctx.kdf_type = EVP_PKEY_DH_KDF_NONE then
    begin
        if key = nil then
        begin
            keylen^ := DH_size(dh);
            Exit(1);
        end;
        if dctx.pad > 0 then
           ret := DH_compute_key_padded(key, dhpubbn, dh)
        else
           ret := DH_compute_key(key, dhpubbn, dh);
        if ret < 0 then
           Exit(ret);
        keylen^ := ret;
        Exit(1);
    end
    else
    if (dctx.kdf_type = EVP_PKEY_DH_KDF_X9_42) then
    begin
        Z := nil;
        Zlen := 0;
        if (0>= dctx.kdf_outlen)  or  (nil = dctx.kdf_oid) then
           Exit(0);
        if key = nil then
        begin
            keylen^ := dctx.kdf_outlen;
            Exit(1);
        end;
        if keylen^ <> dctx.kdf_outlen then
           Exit(0);
        ret := 0;
        Zlen := DH_size(dh);
        if Zlen  <= 0 then
            Exit(0);
        Z := OPENSSL_malloc(Zlen);
        if Z = nil then
        begin
            ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        if DH_compute_key_padded(Z, dhpubbn, dh ) <= 0 then
            goto _err ;
        if 0>= DH_KDF_X9_42(key, keylen^, Z, Zlen, dctx.kdf_oid,
                          dctx.kdf_ukm, dctx.kdf_ukmlen, dctx.kdf_md ) then
            goto _err ;
        keylen^ := dctx.kdf_outlen;
        ret := 1;
 _err:
        OPENSSL_clear_free(Pointer(Z), Zlen);
        Exit(ret);
    end;
    Result := 0;
end;



function pkey_dh_paramgen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  dh : PDH;

  dctx : PDH_PKEY_CTX;

  pcb : PBN_GENCB;

  ret, _type : integer;
begin
    dh := nil;
    dctx := ctx.data;
    pcb := nil;
    {
     * Look for a safe prime group for key establishment. Which uses
     * either RFC_3526 (modp_XXXX) or RFC_7919 (ffdheXXXX).
     * RFC_5114 is also handled here for param_nid = (1..3)
     }
    if dctx.param_nid <> NID_undef then
    begin
        _type := get_result( dctx.param_nid <= 3 , EVP_PKEY_DHX , EVP_PKEY_DH);
        dh := DH_new_by_nid(dctx.param_nid);
        if dh = nil then
            Exit(0);
        EVP_PKEY_assign(pkey, _type, dh);
        Exit(1);
    end;
    if Assigned(ctx.pkey_gencb) then
    begin
        pcb := BN_GENCB_new();
        if pcb = nil then
           Exit(0);
        evp_pkey_set_cb_translate(pcb, ctx);
    end;
{$IFDEF FIPS_MODULE}
    dctx.paramgen_type := DH_PARAMGEN_TYPE_FIPS_186_4;
{$endif} { FIPS_MODULE }
    if dctx.paramgen_type >= DH_PARAMGEN_TYPE_FIPS_186_2 then
    begin
        dh := ffc_params_generate(nil, dctx, pcb);
        BN_GENCB_free(pcb);
        if dh = nil then Exit(0);
        EVP_PKEY_assign(pkey, EVP_PKEY_DHX, dh);
        Exit(1);
    end;
    dh := DH_new();
    if dh = nil then
    begin
        BN_GENCB_free(pcb);
        Exit(0);
    end;
    ret := DH_generate_parameters_ex(dh, dctx.prime_len, dctx.generator, pcb);
    BN_GENCB_free(pcb);
    if ret > 0 then
       EVP_PKEY_assign_DH(pkey, dh)
    else
       DH_free(dh);
    Result := ret;
end;





procedure pkey_dh_cleanup( ctx : PEVP_PKEY_CTX);
var
  dctx : PDH_PKEY_CTX;
begin
    dctx := ctx.data;
    if dctx <> nil then
    begin
        OPENSSL_free(dctx.kdf_ukm);
        ASN1_OBJECT_free(dctx.kdf_oid);
        OPENSSL_free(dctx);
    end;
end;


function pkey_dh_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
var
  dctx, sctx : PDH_PKEY_CTX;
begin
    if 0>= pkey_dh_init(dst ) then
        Exit(0);
    sctx := src.data;
    dctx := dst.data;
    dctx.prime_len := sctx.prime_len;
    dctx.subprime_len := sctx.subprime_len;
    dctx.generator := sctx.generator;
    dctx.paramgen_type := sctx.paramgen_type;
    dctx.pad := sctx.pad;
    dctx.md := sctx.md;
    dctx.param_nid := sctx.param_nid;
    dctx.kdf_type := sctx.kdf_type;
    dctx.kdf_oid := OBJ_dup(sctx.kdf_oid);
    if dctx.kdf_oid = nil then
       Exit(0);
    dctx.kdf_md := sctx.kdf_md;
    if sctx.kdf_ukm <> nil then
    begin
        dctx.kdf_ukm := OPENSSL_memdup(sctx.kdf_ukm, sctx.kdf_ukmlen);
        if dctx.kdf_ukm = nil then
           Exit(0);
        dctx.kdf_ukmlen := sctx.kdf_ukmlen;
    end;
    dctx.kdf_outlen := sctx.kdf_outlen;
    Result := 1;
end;

function pkey_dh_init( ctx : PEVP_PKEY_CTX):integer;
var
  dctx : PDH_PKEY_CTX;
begin
    dctx := OPENSSL_zalloc(sizeof(dctx^ ));
    if dctx =  nil then
    begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    dctx.prime_len := 2048;
    dctx.subprime_len := -1;
    dctx.generator := 2;
    dctx.kdf_type := EVP_PKEY_DH_KDF_NONE;
    ctx.data := dctx;
    ctx.keygen_info := @dctx.gentmp;
    ctx.keygen_info_count := 2;
    Result := 1;
end;

function ossl_dh_pkey_method:PEVP_PKEY_METHOD;
begin
    Result := @dh_pkey_meth;
end;



procedure DH_get0_key(const dh : PDH; pub_key, priv_key : PPBIGNUM);
begin
    if pub_key <> nil then
       pub_key^ := dh.pub_key;
    if priv_key <> nil then
       priv_key^ := dh.priv_key;
end;


function dh_init( dh : PDH):integer;
begin
    dh.flags  := dh.flags  or DH_FLAG_CACHE_MONT_P;
    ossl_ffc_params_init(@dh.params);
    Inc(dh.dirty_cnt);
    Result := 1;
end;


function dh_finish( dh : PDH):integer;
begin
    BN_MONT_CTX_free(dh.method_mont_p);
    Result := 1;
end;

function dh_bn_mod_exp(const dh : PDH; r : PBIGNUM;const a, p, m : PBIGNUM; ctx : PBN_CTX; m_ctx : PBN_MONT_CTX):integer;
begin
    Result := BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
end;



function ossl_dh_compute_key(key : PByte;const pub_key : PBIGNUM; dh : PDH):integer;
var
  ctx : PBN_CTX;
  mont : PBN_MONT_CTX;
  z, pminus1 : PBIGNUM;
  ret : integer;
  label _err;
begin
    ctx := nil;
    mont := nil;
    z := nil;
    ret := -1;
    if BN_num_bits(dh.params.p) > OPENSSL_DH_MAX_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        goto _err ;
    end;
    if BN_num_bits(dh.params.p) < DH_MIN_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(dh.libctx);
    if ctx = nil then goto _err ;
    BN_CTX_start(ctx);
    pminus1 := BN_CTX_get(ctx);
    z := BN_CTX_get(ctx);
    if z = nil then goto _err ;
    if dh.priv_key = nil then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_NO_PRIVATE_VALUE);
        goto _err ;
    end;
    if (dh.flags and DH_FLAG_CACHE_MONT_P)>0 then
    begin
        mont := BN_MONT_CTX_set_locked(@dh.method_mont_p,
                                      dh.lock, dh.params.p, ctx);
        BN_set_flags(dh.priv_key, BN_FLG_CONSTTIME);
        if nil = mont then
           goto _err ;
    end;
    { (Step 1) Z = pub_key^priv_key mod p }
    if 0>= dh.meth.bn_mod_exp(dh, z, pub_key, dh.priv_key, dh.params.p, ctx,
                              mont) then
    begin
        ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);
        goto _err ;
    end;
    { (Step 2) Error if z <= 1 or z = p - 1 }
    if (BN_copy(pminus1, dh.params.p)  = nil )
         or  (0>= BN_sub_word(pminus1, 1))
         or  (BN_cmp(z, BN_value_one) <= 0 )
         or  (BN_cmp(z, pminus1) = 0) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_SECRET);
        goto _err ;
    end;
    { return the padded key, i.e. same number of bytes as the modulus }
    ret := BN_bn2binpad(z, key, BN_num_bytes(dh.params.p));
 _err:
    BN_clear(z); { (Step 2) destroy intermediate values }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ret;
end;




function generate_key( dh : PDH):integer;
var
  ok,
  generate_new_key : integer;
  l                : uint32;
  ctx              : PBN_CTX;
  pub_key,
  priv_key         : PBIGNUM;
  max_strength     : integer;
  label _err;
begin
    ok := 0;
    generate_new_key := 0;
{$IFNDEF FIPS_MODULE}
{$ENDIF}
    ctx := nil;
    pub_key := nil;
    priv_key := nil;
    if BN_num_bits(dh.params.p) > OPENSSL_DH_MAX_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        Exit(0);
    end;
    if BN_num_bits(dh.params.p) < DH_MIN_MODULUS_BITS  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        Exit(0);
    end;
    ctx := BN_CTX_new_ex(dh.libctx);
    if ctx = nil then goto _err ;
    if dh.priv_key = nil then
    begin
        priv_key := BN_secure_new();
        if priv_key = nil then
           goto _err ;
        generate_new_key := 1;
    end
    else
    begin
        priv_key := dh.priv_key;
    end;
    if dh.pub_key = nil then
    begin
        pub_key := BN_new();
        if pub_key = nil then
           goto _err ;
    end
    else
    begin
        pub_key := dh.pub_key;
    end;
    if generate_new_key>0 then
    begin
        { Is it an approved safe prime ?}
        if DH_get_nid(dh) <> NID_undef then
        begin
            max_strength :=  ossl_ifc_ffc_compute_security_bits(BN_num_bits(dh.params.p));
            if (dh.params.q = nil)    or
               (dh.length > BN_num_bits(dh.params.q)) then
                goto _err ;
            { dh.length = maximum bit length of generated private key }
            if 0>= ossl_ffc_generate_private_key(ctx, @dh.params, dh.length,
                                               max_strength, priv_key) then
                goto _err ;
        end
        else
        begin
{$IFDEF FIPS_MODULE}
            if dh.params.q = nil then
               goto _err ;
{$ELSE} if dh.params.q = nil then
        begin
                { secret exponent length, must satisfy 2^(l-1) <= p }
                if (dh.length <> 0)
                     and  (dh.length >= BN_num_bits(dh.params.p)) then
                    goto _err ;
                l := get_result(dh.length >0, dh.length , BN_num_bits(dh.params.p) - 1);
                if 0>= BN_priv_rand_ex(priv_key, l, BN_RAND_TOP_ONE,
                                     BN_RAND_BOTTOM_ANY, 0, ctx) then
                    goto _err ;
                {
                 * We handle just one known case where g is a quadratic non-residue:
                 * for g = 2: p % 8 = 3
                 }
                if (BN_is_word(dh.params.g, DH_GENERATOR_2)) and
                   (0>= BN_is_bit_set(dh.params.p, 2))  then
                begin
                    { clear bit 0, since it won't be a secret anyway }
                    if 0>= BN_clear_bit(priv_key, 0) then
                        goto _err ;
                end;
            end
            else
{$ENDIF}
            begin
                { Do a partial check for invalid p, q, g }
                if 0>= ossl_ffc_params_simple_validate(dh.libctx, @dh.params,
                                                     FFC_PARAM_TYPE_DH, nil) then
                    goto _err ;
                {
                 * For FFC FIPS 186-4 keygen
                 * security strength s = 112,
                 * Max Private key size N = len(q)
                 }
                if 0>= ossl_ffc_generate_private_key(ctx, @dh.params,
                                                   BN_num_bits(dh.params.q) ,
                                                   MIN_STRENGTH,
                                                   priv_key)  then
                    goto _err ;
            end;
        end;
    end;
    if 0>= ossl_dh_generate_public_key(ctx, dh, priv_key, pub_key) then
        goto _err ;
    dh.pub_key := pub_key;
    dh.priv_key := priv_key;
    Inc(dh.dirty_cnt);
    ok := 1;
 _err:
    if ok <> 1 then
       ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);
    if pub_key <> dh.pub_key then
       BN_free(pub_key);
    if priv_key <> dh.priv_key then
       BN_free(priv_key);
    BN_CTX_free(ctx);
    Result := ok;
end;


function ossl_dh_buf2key(dh : PDH;const buf : PByte; len : size_t):integer;
var
    err_reason : integer;
    pubkey     : PBIGNUM;
    p_size     : size_t;
    p          : PBIGNUM;
    label _Err;
begin
    err_reason := DH_R_BN_ERROR;
    pubkey := nil;
    pubkey := BN_bin2bn(buf, len, nil);
    if pubkey =  nil then
        goto _err ;
    DH_get0_pqg(dh, @p, nil, nil);
    p_size := BN_num_bytes(p );
    if (p = nil)  or  (p_size = 0) then
    begin
        err_reason := DH_R_NO_PARAMETERS_SET;
        goto _err ;
    end;
    {
     * As per Section 4.2.8.1 of RFC 8446 fail if DHE's
     * public key is of size not equal to size of p
     }
    if (BN_is_zero(pubkey)) or  (p_size <> len) then
    begin
        err_reason := DH_R_INVALID_PUBKEY;
        goto _err ;
    end;
    if DH_set0_key(dh, pubkey, nil) <> 1   then
        goto _err ;
    Exit(1);
_err:
    ERR_raise(ERR_LIB_DH, err_reason);
    BN_free(pubkey);
    Result := 0;
end;

function ossl_dh_generate_public_key(ctx : PBN_CTX;const dh : PDH; priv_key : PBIGNUM; pub_key : PBIGNUM):integer;
var
  ret : integer;

  prk : PBIGNUM;

  mont : PBN_MONT_CTX;

  pmont : PPBN_MONT_CTX;
  label _err;
begin
    ret := 0;
    prk := BN_new();
    mont := nil;
    if prk = nil then Exit(0);
    if (dh.flags and DH_FLAG_CACHE_MONT_P)>0 then
    begin
        {
         * We take the input DH as const, but we lie, because in some cases we
         * want to get a hold of its Montgomery context.
         *
         * We cast to remove the const qualifier in this case, it should be
         * fine...
         }
        pmont := PPBN_MONT_CTX ( @dh.method_mont_p);
        mont := BN_MONT_CTX_set_locked(pmont, dh.lock, dh.params.p, ctx);
        if mont = nil then goto _err ;
    end;
    BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
    { pub_key = g^priv_key mod p }
    if  0>= dh.meth.bn_mod_exp(dh, pub_key, dh.params.g, prk, dh.params.p,
                              ctx, mont )then
        goto _err ;
    ret := 1;
_err:
    BN_clear_free(prk);
    Result := ret;
end;





function  BN_num_bytes(a: PBIGNUM): Integer;
begin
  Result := ((BN_num_bits(a)+7) div 8);
end;

function ossl_dh_key2buf(const dh : PDH; pbuf_out : PPByte; size : size_t; alloc : integer):size_t;
var
  pubkey : PBIGNUM;

  pbuf : Pbyte;

  p : PBIGNUM;

  p_size : integer;
begin
    pbuf := nil;
    DH_get0_pqg(dh, @p, nil, nil);
    DH_get0_key(dh, @pubkey, nil);
    p_size := BN_num_bytes(p);
    if (p = nil)  or  (pubkey = nil )
             or  (p_size =  0)
             or  (BN_num_bytes(pubkey) = 0) then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY);
        Exit(0);
    end;
    if (pbuf_out <> nil)  and  ( (alloc>0)  or  (pbuf_out^ <> nil)  )then
    begin
        if  0>= alloc then
        begin
            if size >= size_t(p_size) then
                pbuf := pbuf_out^;
        end
        else
        begin
            pbuf := OPENSSL_malloc(p_size);
        end;
        if pbuf = nil then
        begin
            ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        {
         * As per Section 4.2.8.1 of RFC 8446 left pad public
         * key with zeros to the size of p
         }
        if BN_bn2binpad(pubkey, pbuf, p_size) < 0then
        begin
            if alloc>0 then
                OPENSSL_free(pbuf);
            ERR_raise(ERR_LIB_DH, DH_R_BN_ERROR);
            Exit(0);
        end;
        pbuf_out^ := pbuf;
    end;
    Result := p_size;
end;

end.
