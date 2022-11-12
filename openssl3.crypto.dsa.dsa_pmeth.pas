unit openssl3.crypto.dsa.dsa_pmeth;

interface
uses OpenSSL.Api, SysUtils;

  function ossl_dsa_pkey_method:PEVP_PKEY_METHOD;
  function pkey_dsa_init( ctx : PEVP_PKEY_CTX):integer;
  function pkey_dsa_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
  procedure pkey_dsa_cleanup( ctx : PEVP_PKEY_CTX);
  function pkey_dsa_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
  function pkey_dsa_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function pkey_dsa_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
  function pkey_dsa_ctrl_str(ctx : PEVP_PKEY_CTX;const _type, value : PUTF8Char):integer;
  function pkey_dsa_paramgen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
  function pkey_dsa_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;

const  dsa_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_DSA;
    flags: EVP_PKEY_FLAG_AUTOARGLEN;
    init: pkey_dsa_init;
    copy: pkey_dsa_copy;
    cleanup: pkey_dsa_cleanup;
    paramgen_init: nil;
    paramgen: pkey_dsa_paramgen;
    keygen_init: nil;
    keygen: pkey_dsa_keygen;
    sign_init: nil;
    sign: pkey_dsa_sign;
    verify_init: nil;
    verify: pkey_dsa_verify;
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
    derive: nil;
    ctrl: pkey_dsa_ctrl;
    ctrl_str: pkey_dsa_ctrl_str
);



implementation
uses openssl3.crypto.mem, openssl3.crypto.evp.p_lib, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.dsa.dsa_sign, OpenSSL3.Err, openssl3.crypto.dsa.dsa_ctrl,
     openssl3.crypto.evp.names, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.evp, openssl3.crypto.dsa.dsa_key,
     openssl3.crypto.ffc.ffc_params, openssl3.crypto.ffc.ffc_params_generate,
     openssl3.crypto.evp.pmeth_gn, openssl3.crypto.dsa.dsa_lib;

function pkey_dsa_init( ctx : PEVP_PKEY_CTX):integer;
var
  dctx : PDSA_PKEY_CTX;
begin
    dctx := OPENSSL_malloc(sizeof(dctx^));
    if dctx = nil then Exit(0);
    dctx.nbits := 2048;
    dctx.qbits := 224;
    dctx.pmd := nil;
    dctx.md := nil;
    ctx.data := dctx;
    ctx.keygen_info := @dctx.gentmp;
    ctx.keygen_info_count := 2;
    Result := 1;
end;


function pkey_dsa_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
var
  dctx, sctx : PDSA_PKEY_CTX;
begin
    if 0>= pkey_dsa_init(dst ) then
        Exit(0);
    sctx := src.data;
    dctx := dst.data;
    dctx.nbits := sctx.nbits;
    dctx.qbits := sctx.qbits;
    dctx.pmd := sctx.pmd;
    dctx.md := sctx.md;
    Result := 1;
end;


procedure pkey_dsa_cleanup( ctx : PEVP_PKEY_CTX);
var
  dctx : PDSA_PKEY_CTX;
begin
    dctx := ctx.data;
    OPENSSL_free(dctx);
end;


function pkey_dsa_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret : integer;

  sltmp : uint32;

  dctx : PDSA_PKEY_CTX;

  dsa : PDSA;
begin
    dctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    dsa := PDSA( EVP_PKEY_get0_DSA(ctx.pkey));
    if (dctx.md <> nil)  and  (tbslen <> size_t( EVP_MD_get_size(dctx.md))) then
        Exit(0);
    ret := DSA_sign(0, tbs, tbslen, sig, @sltmp, dsa);
    if ret <= 0 then
       Exit(ret);
    siglen^ := sltmp;
    Result := 1;
end;


function pkey_dsa_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret : integer;

  dctx : PDSA_PKEY_CTX;

  dsa : PDSA;
begin
    dctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    dsa := PDSA( EVP_PKEY_get0_DSA(ctx.pkey));
    if (dctx.md <> nil)  and  (tbslen <> size_t( EVP_MD_get_size(dctx.md))) then
        Exit(0);
    ret := _DSA_verify(0, tbs, tbslen, sig, siglen, dsa);
    Result := ret;
end;


function pkey_dsa_ctrl( ctx : PEVP_PKEY_CTX; _type, p1 : integer; p2 : Pointer):integer;
var
  dctx : PDSA_PKEY_CTX;
begin
    dctx := ctx.data;
    case _type of
        EVP_PKEY_CTRL_DSA_PARAMGEN_BITS:
        begin
            if p1 < 256 then Exit(-2);
            dctx.nbits := p1;
            Exit(1);
        end;
        EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS:
        begin
            if (p1 <> 160)  and  (p1 <> 224)  and  (p1>0)  and  (p1 <> 256) then
               Exit(-2);
            dctx.qbits := p1;
            Exit(1);
        end;
        EVP_PKEY_CTRL_DSA_PARAMGEN_MD:
        begin
            if (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha1)  and
               (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha224)  and
               (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha256)  then
            begin
                ERR_raise(ERR_LIB_DSA, DSA_R_INVALID_DIGEST_TYPE);
                Exit(0);
            end;
            dctx.pmd := p2;
            Exit(1);
        end;
        EVP_PKEY_CTRL_MD:
        begin
            if  (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha1  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_dsa  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_dsaWithSHA  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha224  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha256  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha384  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha512  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha3_224  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha3_256  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha3_384  ) and
                (EVP_MD_get_type(PEVP_MD( p2)) <> NID_sha3_512) then
            begin
                ERR_raise(ERR_LIB_DSA, DSA_R_INVALID_DIGEST_TYPE);
                Exit(0);
            end;
            dctx.md := p2;
            Exit(1);
        end;
        EVP_PKEY_CTRL_GET_MD:
        begin
            PPEVP_MD(p2)^ := dctx.md;
            Exit(1);
        end;
        EVP_PKEY_CTRL_DIGESTINIT,
        EVP_PKEY_CTRL_PKCS7_SIGN,
        EVP_PKEY_CTRL_CMS_SIGN:
            Exit(1);
        EVP_PKEY_CTRL_PEER_KEY:
        begin
            ERR_raise(ERR_LIB_DSA, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            Exit(-2);
        end
        else
            Exit(-2);
    end;
end;


function pkey_dsa_ctrl_str(ctx : PEVP_PKEY_CTX;const _type, value : PUTF8Char):integer;
var
  nbits, qbits : integer;

  md : PEVP_MD;
begin
    if strcmp(_type, 'dsa_paramgen_bits') = 0  then
    begin
        nbits := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits));
    end;
    if strcmp(_type, 'dsa_paramgen_q_bits') =0 then
    begin
        qbits := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits));
    end;
    if strcmp(_type, 'dsa_paramgen_md') =0 then
    begin
         md := EVP_get_digestbyname(value);
        if md = nil then
        begin
            ERR_raise(ERR_LIB_DSA, DSA_R_INVALID_DIGEST_TYPE);
            Exit(0);
        end;
        Exit(EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md));
    end;
    Result := -2;
end;


function pkey_dsa_paramgen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  dsa : PDSA;

  dctx : PDSA_PKEY_CTX;

  pcb : PBN_GENCB;

  ret, res : integer;
begin
    dsa := nil;
    dctx := ctx.data;
    if Assigned(ctx.pkey_gencb) then
    begin
        pcb := BN_GENCB_new();
        if pcb = nil then
           Exit(0);
        evp_pkey_set_cb_translate(pcb, ctx);
    end
    else
        pcb := nil;
    dsa := DSA_new();
    if dsa = nil then
    begin
        BN_GENCB_free(pcb);
        Exit(0);
    end;
    if dctx.md <> nil then
       ossl_ffc_set_digest(@dsa.params, EVP_MD_get0_name(dctx.md), nil);
    ret := ossl_ffc_params_FIPS186_4_generate(nil, @dsa.params,
                                             FFC_PARAM_TYPE_DSA, dctx.nbits,
                                             dctx.qbits, @res, pcb);
    BN_GENCB_free(pcb);
    if ret > 0 then
       EVP_PKEY_assign_DSA(pkey, dsa)
    else
        DSA_free(dsa);
    Result := ret;
end;


function pkey_dsa_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  dsa : PDSA;
begin
    dsa := nil;
    if ctx.pkey = nil then
    begin
        ERR_raise(ERR_LIB_DSA, DSA_R_NO_PARAMETERS_SET);
        Exit(0);
    end;
    dsa := DSA_new();
    if dsa = nil then Exit(0);
    EVP_PKEY_assign_DSA(pkey, dsa);
    { Note: if error return, pkey is freed by parent routine }
    if 0>= EVP_PKEY_copy_parameters(pkey, ctx.pkey )then
        Exit(0);
    Result := DSA_generate_key(PDSA( EVP_PKEY_get0_DSA(pkey)));
end;




function ossl_dsa_pkey_method:PEVP_PKEY_METHOD;
begin
    Result := @dsa_pkey_meth;
end;


end.
