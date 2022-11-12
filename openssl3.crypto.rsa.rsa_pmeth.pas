unit openssl3.crypto.rsa.rsa_pmeth;

interface
uses OpenSSL.Api, SysUtils;

function ossl_rsa_pkey_method:PEVP_PKEY_METHOD;
function pkey_rsa_init( ctx : PEVP_PKEY_CTX):integer;
function pkey_rsa_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
procedure pkey_rsa_cleanup( ctx : PEVP_PKEY_CTX);
  function pkey_rsa_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
  function pkey_rsa_verifyrecover(ctx : PEVP_PKEY_CTX; rout : PByte; routlen : Psize_t;const sig : PByte; siglen : size_t):integer;
  function pkey_rsa_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
  function pkey_rsa_encrypt(ctx : PEVP_PKEY_CTX; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
  function pkey_rsa_decrypt(ctx : PEVP_PKEY_CTX; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
  function check_padding_md(const md : PEVP_MD; padding : integer):integer;
  function pkey_rsa_ctrl( ctx : PEVP_PKEY_CTX; &type, p1 : integer; p2 : Pointer):integer;
  function pkey_rsa_ctrl_str(ctx : PEVP_PKEY_CTX;const &type, value : PUTF8Char):integer;
  function rsa_set_pss_param( rsa : PRSA; ctx : PEVP_PKEY_CTX):integer;
  function pkey_rsa_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
  function pkey_pss_init( ctx : PEVP_PKEY_CTX):integer;
  function setup_tbuf( ctx : PRSA_PKEY_CTX; pk : PEVP_PKEY_CTX):integer;
  function ossl_rsa_pss_pkey_method:PEVP_PKEY_METHOD;


const
  rsa_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id:EVP_PKEY_RSA;
    flags: EVP_PKEY_FLAG_AUTOARGLEN;
    init: pkey_rsa_init;
    copy: pkey_rsa_copy;
    cleanup: pkey_rsa_cleanup;
    paramgen_init: nil; paramgen: nil;
    keygen_init: nil;
    keygen: pkey_rsa_keygen;
    sign_init: nil;
    sign: pkey_rsa_sign;
    verify_init: nil;
    verify: pkey_rsa_verify;
    verify_recover_init: nil;
    verify_recover: pkey_rsa_verifyrecover;
    signctx_init: nil;
    signctx: nil;
    verifyctx_init: nil;
    verifyctx: nil;
    encrypt_init: nil;
    encrypt: pkey_rsa_encrypt;
    decrypt_init: nil;
    decrypt: pkey_rsa_decrypt;
    derive_init: nil;
    derive: nil;
    ctrl: pkey_rsa_ctrl;
    ctrl_str: pkey_rsa_ctrl_str
);
 const  rsa_pss_pkey_meth: TEVP_PKEY_METHOD = (
    pkey_id: EVP_PKEY_RSA_PSS;
    flags: EVP_PKEY_FLAG_AUTOARGLEN;
    init: pkey_rsa_init;
    copy: pkey_rsa_copy;
    cleanup: pkey_rsa_cleanup;

    paramgen_init: nil; paramgen: nil;

    keygen_init: nil;
    keygen: pkey_rsa_keygen;

    sign_init: pkey_pss_init;
    sign: pkey_rsa_sign;

    verify_init: pkey_pss_init;
    verify: pkey_rsa_verify;

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

    ctrl: pkey_rsa_ctrl;
    ctrl_str: pkey_rsa_ctrl_str
);

implementation
uses openssl3.crypto.mem, openssl3.crypto.bn.bn_lib, openssl3.crypto.evp.p_legacy,
     openssl3.crypto.evp.evp_lib, OpenSSL3.Err, openssl3.crypto.rsa.rsa_saos,
     OpenSSL3.crypto.rsa.rsa_crpt, OpenSSL3.crypto.rsa.rsa_x931,
     OpenSSL3.crypto.rsa.rsa_oaep, openssl3.internal.constant_time,
     openssl3.crypto.evp.legacy_sha, openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.bn.bn_conv, openssl3.crypto.evp.pmeth_lib,
     openssl3.crypto.o_str, OpenSSL3.crypto.rsa.rsa_ameth,
     openssl3.crypto.evp.p_lib,
     openssl3.crypto.evp.pmeth_gn, OpenSSL3.crypto.rsa.rsa_gen,
     OpenSSL3.crypto.rsa.rsa_sign, openssl3.crypto.rsa.rsa_pss;



function rsa_pss_restricted(rctx: PRSA_PKEY_CTX): Boolean;
begin
  Result := (rctx.min_saltlen <> -1)
end;


function setup_tbuf( ctx : PRSA_PKEY_CTX; pk : PEVP_PKEY_CTX):integer;
begin
    if ctx.tbuf <> nil then Exit(1);
    ctx.tbuf :=  OPENSSL_malloc(RSA_size(EVP_PKEY_get0_RSA(pk.pkey )));
    if (ctx.tbuf = nil)  then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;

procedure pkey_rsa_cleanup( ctx : PEVP_PKEY_CTX);
var
  rctx : PRSA_PKEY_CTX;
begin
    rctx := ctx.data;
    if rctx <> nil then
    begin
        BN_free(rctx.pub_exp);
        OPENSSL_free(rctx.tbuf);
        OPENSSL_free(rctx.oaep_label);
        OPENSSL_free(rctx);
    end;
end;


function pkey_rsa_sign(ctx : PEVP_PKEY_CTX; sig : PByte; siglen : Psize_t;const tbs : PByte; tbslen : size_t):integer;
var
  ret : integer;
  rctx : PRSA_PKEY_CTX;
  rsa : PRSA;
  sltmp : uint32;
begin
    rctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    rsa := PRSA( EVP_PKEY_get0_RSA(ctx.pkey));
    if rctx.md <> nil then
    begin
        if tbslen <> size_t( EVP_MD_get_size(rctx.md)) then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);
            Exit(-1);
        end;
        if EVP_MD_get_type(rctx.md) = NID_mdc2 then
        begin
            if rctx.pad_mode <> RSA_PKCS1_PADDING then
                Exit(-1);
            ret := RSA_sign_ASN1_OCTET_STRING(0, tbs, tbslen, sig, @sltmp, rsa);
            if ret <= 0 then Exit(ret);
            ret := sltmp;
        end
        else
        if (rctx.pad_mode = RSA_X931_PADDING) then
        begin
            if size_t( RSA_size(rsa)) < tbslen + 1  then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
                Exit(-1);
            end;
            if 0>= setup_tbuf(rctx, ctx) then
            begin
                ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
                Exit(-1);
            end;
            memcpy(rctx.tbuf, tbs, tbslen);
            rctx.tbuf[tbslen] := RSA_X931_hash_id(EVP_MD_get_type(rctx.md));
            ret := RSA_private_encrypt(tbslen + 1, rctx.tbuf,
                                      sig, rsa, RSA_X931_PADDING);
        end
        else
        if (rctx.pad_mode = RSA_PKCS1_PADDING) then
        begin
            ret := _RSA_sign(EVP_MD_get_type(rctx.md),
                           tbs, tbslen, sig, @sltmp, rsa);
            if ret <= 0 then Exit(ret);
            ret := sltmp;
        end
        else
        if (rctx.pad_mode = RSA_PKCS1_PSS_PADDING) then
        begin
            if 0>= setup_tbuf(rctx, ctx ) then
                Exit(-1);
            if 0>= RSA_padding_add_PKCS1_PSS_mgf1(rsa,
                                                rctx.tbuf, tbs,
                                                rctx.md, rctx.mgf1md,
                                                rctx.saltlen ) then
                Exit(-1);
            ret := RSA_private_encrypt(RSA_size(rsa), rctx.tbuf,
                                      sig, rsa, RSA_NO_PADDING);
        end
        else
        begin
            Exit(-1);
        end;
    end
    else
    begin
        ret := RSA_private_encrypt(tbslen, tbs, sig, rsa, rctx.pad_mode);
    end;
    if ret < 0 then
       Exit(ret);
    siglen^ := ret;
    Result := 1;
end;


function pkey_rsa_verifyrecover(ctx : PEVP_PKEY_CTX; rout : PByte; routlen : Psize_t;const sig : PByte; siglen : size_t):integer;
var
  ret : integer;

  rctx : PRSA_PKEY_CTX;

  rsa : PRSA;

  sltmp : size_t;
begin
    rctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    rsa := PRSA( EVP_PKEY_get0_RSA(ctx.pkey));
    if rctx.md <> nil then
    begin
        if rctx.pad_mode = RSA_X931_PADDING then
        begin
            if 0>= setup_tbuf(rctx, ctx) then
                Exit(-1);
            ret := RSA_public_decrypt(siglen, sig, rctx.tbuf, rsa,
                                     RSA_X931_PADDING);
            if ret < 1 then Exit(0);
            PostDec(ret);
            if rctx.tbuf[ret] <> RSA_X931_hash_id(EVP_MD_get_type(rctx.md))  then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_ALGORITHM_MISMATCH);
                Exit(0);
            end;
            if ret <> EVP_MD_get_size(rctx.md)  then
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);
                Exit(0);
            end;
            if rout <> nil then
               memcpy(rout, rctx.tbuf, ret);
        end
        else
        if (rctx.pad_mode = RSA_PKCS1_PADDING) then
        begin
            ret := ossl_rsa_verify(EVP_MD_get_type(rctx.md),
                                  nil, 0, rout, @sltmp,
                                  sig, siglen, rsa);
            if ret <= 0 then Exit(0);
            ret := sltmp;
        end
        else
        begin
            Exit(-1);
        end;
    end
    else
    begin
        ret := RSA_public_decrypt(siglen, sig, rout, rsa, rctx.pad_mode);
    end;
    if ret < 0 then
       Exit(ret);
    routlen^ := ret;
    Result := 1;
end;


function pkey_rsa_verify(ctx : PEVP_PKEY_CTX;const sig : PByte; siglen : size_t;const tbs : PByte; tbslen : size_t):integer;
var
  rctx : PRSA_PKEY_CTX;

  rsa : PRSA;

  rslen : size_t;

  ret : integer;
begin
    rctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    rsa := PRSA( EVP_PKEY_get0_RSA(ctx.pkey));
    if rctx.md <> nil then
    begin
        if rctx.pad_mode = RSA_PKCS1_PADDING then
            Exit(_RSA_verify(EVP_MD_get_type(rctx.md), tbs, tbslen,
                              sig, siglen, rsa));
        if tbslen <> size_t( EVP_MD_get_size(rctx.md)) then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);
            Exit(-1);
        end;
        if rctx.pad_mode = RSA_X931_PADDING then
        begin
            if pkey_rsa_verifyrecover(ctx, nil, @rslen, sig, siglen) <= 0 then
                Exit(0);
        end
        else
        if (rctx.pad_mode = RSA_PKCS1_PSS_PADDING) then
        begin
            if 0>= setup_tbuf(rctx, ctx) then
                Exit(-1);
            ret := RSA_public_decrypt(siglen, sig, rctx.tbuf,
                                     rsa, RSA_NO_PADDING);
            if ret <= 0 then Exit(0);
            ret := RSA_verify_PKCS1_PSS_mgf1(rsa, tbs,
                                            rctx.md, rctx.mgf1md,
                                            rctx.tbuf, rctx.saltlen);
            if ret <= 0 then Exit(0);
            Exit(1);
        end
        else
        begin
            Exit(-1);
        end;
    end
    else
    begin
        if 0>= setup_tbuf(rctx, ctx ) then
            Exit(-1);
        rslen := RSA_public_decrypt(siglen, sig, rctx.tbuf,
                                   rsa, rctx.pad_mode);
        if rslen = 0 then Exit(0);
    end;
    if (rslen <> tbslen) or  (memcmp(tbs, rctx.tbuf, rslen)>0) then
        Exit(0);
    Exit(1);
end;


function pkey_rsa_encrypt(ctx : PEVP_PKEY_CTX; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
var
  ret : integer;

  rctx : PRSA_PKEY_CTX;

  rsa : PRSA;

  klen : integer;
begin
    rctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    rsa := PRSA( EVP_PKEY_get0_RSA(ctx.pkey));
    if rctx.pad_mode = RSA_PKCS1_OAEP_PADDING then
    begin
        klen := RSA_size(rsa);
        if 0>= setup_tbuf(rctx, ctx) then
            Exit(-1);
        if 0>= RSA_padding_add_PKCS1_OAEP_mgf1(rctx.tbuf, klen,
                                             &in, inlen,
                                             rctx.oaep_label,
                                             rctx.oaep_labellen,
                                             rctx.md, rctx.mgf1md ) then
            Exit(-1);
        ret := RSA_public_encrypt(klen, rctx.tbuf, out, rsa, RSA_NO_PADDING);
    end
    else
    begin
        ret := RSA_public_encrypt(inlen, &in, out, rsa, rctx.pad_mode);
    end;
    if ret < 0 then
       Exit(ret);
    outlen^ := ret;
    Result := 1;
end;


function pkey_rsa_decrypt(ctx : PEVP_PKEY_CTX; &out : PByte; outlen : Psize_t;const &in : PByte; inlen : size_t):integer;
var
  ret : integer;

  rctx : PRSA_PKEY_CTX;

  rsa : PRSA;
begin
    rctx := ctx.data;
    {
     * Discard const. Its marked as const because this may be a cached copy of
     * the 'real' key. These calls don't make any modifications that need to
     * be reflected back in the 'original' key.
     }
    rsa := PRSA( EVP_PKEY_get0_RSA(ctx.pkey));
    if rctx.pad_mode = RSA_PKCS1_OAEP_PADDING then
    begin
        if 0>= setup_tbuf(rctx, ctx) then
            Exit(-1);
        ret := RSA_private_decrypt(inlen, &in, rctx.tbuf, rsa, RSA_NO_PADDING);
        if ret <= 0 then Exit(ret);
        ret := RSA_padding_check_PKCS1_OAEP_mgf1(out, ret, rctx.tbuf,
                                                ret, ret,
                                                rctx.oaep_label,
                                                rctx.oaep_labellen,
                                                rctx.md, rctx.mgf1md);
    end
    else
    begin
        ret := RSA_private_decrypt(inlen, &in, out, rsa, rctx.pad_mode);
    end;
    outlen^ := constant_time_select_s(constant_time_msb_s(ret), outlen^, ret);
    ret := constant_time_select_int(constant_time_msb(ret), ret, 1);
    Result := ret;
end;


function check_padding_md(const md : PEVP_MD; padding : integer):integer;
var
  mdnid : integer;
begin
    if nil = md then Exit(1);
    mdnid := EVP_MD_get_type(md);
    if padding = RSA_NO_PADDING then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING_MODE);
        Exit(0);
    end;
    if padding = RSA_X931_PADDING then
    begin
        if RSA_X931_hash_id(mdnid) = -1 then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_X931_DIGEST);
            Exit(0);
        end;
    end
    else
    begin
        case mdnid of
            { List of all supported RSA digests }
            NID_sha1,
            NID_sha224,
            NID_sha256,
            NID_sha384,
            NID_sha512,
            NID_sha512_224,
            NID_sha512_256,
            NID_md5,
            NID_md5_sha1,
            NID_md2,
            NID_md4,
            NID_mdc2,
            NID_ripemd160,
            NID_sha3_224,
            NID_sha3_256,
            NID_sha3_384,
            NID_sha3_512:
                Exit(1);
            else
            begin
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST);
                Exit(0);
            end;
        end;
    end;
    Result := 1;
end;


function pkey_rsa_ctrl( ctx : PEVP_PKEY_CTX; &type, p1 : integer; p2 : Pointer):integer;
var
  rctx : PRSA_PKEY_CTX;
  label _bad_pad;
begin
    rctx := ctx.data;
    case &type of
    EVP_PKEY_CTRL_RSA_PADDING:
    begin
        if (p1 >= RSA_PKCS1_PADDING)  and  (p1 <= RSA_PKCS1_PSS_PADDING) then
        begin
            if 0>= check_padding_md(rctx.md, p1) then
                Exit(0);
            if p1 = RSA_PKCS1_PSS_PADDING then
            begin
                if (0>= (ctx.operation and
                      (EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY))) then
                    goto _bad_pad ;
                if nil = rctx.md then
                   rctx.md := EVP_sha1();
            end
            else
            if (pkey_ctx_is_pss(ctx)>0) then
            begin
                goto _bad_pad ;
            end;
            if p1 = RSA_PKCS1_OAEP_PADDING then
            begin
                if 0>= (ctx.operation and EVP_PKEY_OP_TYPE_CRYPT) then
                    goto _bad_pad ;
                if nil = rctx.md then
                   rctx.md := EVP_sha1();
            end;
            rctx.pad_mode := p1;
            Exit(1);
        end;
 _bad_pad:
        ERR_raise(ERR_LIB_RSA, RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        Exit(-2);
    end;
    EVP_PKEY_CTRL_GET_RSA_PADDING:
    begin
        PInteger(p2)^ := rctx.pad_mode;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
    EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
    begin
        if rctx.pad_mode <> RSA_PKCS1_PSS_PADDING then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PSS_SALTLEN);
            Exit(-2);
        end;
        if &type = EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN then
        begin
            PInteger(p2)^ := rctx.saltlen;
        end
        else
        begin
            if p1 < RSA_PSS_SALTLEN_MAX then Exit(-2);
            if rsa_pss_restricted(rctx) then
            begin
                if (p1 = RSA_PSS_SALTLEN_AUTO)
                     and ( ctx.operation = EVP_PKEY_OP_VERIFY) then
                begin
                    ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PSS_SALTLEN);
                    Exit(-2);
                end;
                if (p1 = RSA_PSS_SALTLEN_DIGEST)
                      and  (rctx.min_saltlen > EVP_MD_get_size(rctx.md) )
                     or ( (p1 >= 0)  and  (p1 < rctx.min_saltlen))  then
                begin
                    ERR_raise(ERR_LIB_RSA, RSA_R_PSS_SALTLEN_TOO_SMALL);
                    Exit(0);
                end;
            end;
            rctx.saltlen := p1;
        end;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
    begin
        if p1 < RSA_MIN_MODULUS_BITS then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
            Exit(-2);
        end;
        rctx.nbits := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
    begin
        if (p2 = nil)  or  (not BN_is_odd(PBIGNUM(p2)))  or ( BN_is_one(PBIGNUM(p2)))   then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
            Exit(-2);
        end;
        BN_free(rctx.pub_exp);
        rctx.pub_exp := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES:
    begin
        if (p1 < RSA_DEFAULT_PRIME_NUM)  or  (p1 > RSA_MAX_PRIME_NUM) then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_KEY_PRIME_NUM_INVALID);
            Exit(-2);
        end;
        rctx.primes := p1;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_OAEP_MD,
    EVP_PKEY_CTRL_GET_RSA_OAEP_MD:
    begin
        if rctx.pad_mode <> RSA_PKCS1_OAEP_PADDING then begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING_MODE);
            Exit(-2);
        end;
        if &type = EVP_PKEY_CTRL_GET_RSA_OAEP_MD then
           PPEVP_MD(p2)^ := rctx.md
        else
            rctx.md := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_MD:
    begin
        if 0>= check_padding_md(p2, rctx.pad_mode) then
            Exit(0);
        if rsa_pss_restricted(rctx)  then
        begin
            if EVP_MD_get_type(rctx.md) = EVP_MD_get_type(p2) then
                Exit(1);
            ERR_raise(ERR_LIB_RSA, RSA_R_DIGEST_NOT_ALLOWED);
            Exit(0);
        end;
        rctx.md := p2;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_MD:
    begin
        PPEVP_MD(p2)^ := rctx.md;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_MGF1_MD,
    EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
    begin
        if (rctx.pad_mode <> RSA_PKCS1_PSS_PADDING)
             and  (rctx.pad_mode <> RSA_PKCS1_OAEP_PADDING) then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MGF1_MD);
            Exit(-2);
        end;
        if &type = EVP_PKEY_CTRL_GET_RSA_MGF1_MD then
        begin
            if rctx.mgf1md <> nil then
                PPEVP_MD(p2)^ := rctx.mgf1md
            else
               PPEVP_MD(p2)^ := rctx.md;
        end
        else
        begin
            if rsa_pss_restricted(rctx) then
            begin
                if EVP_MD_get_type(rctx.mgf1md) = EVP_MD_get_type(p2) then
                    Exit(1);
                ERR_raise(ERR_LIB_RSA, RSA_R_MGF1_DIGEST_NOT_ALLOWED);
                Exit(0);
            end;
            rctx.mgf1md := p2;
        end;
        Exit(1);
    end;
    EVP_PKEY_CTRL_RSA_OAEP_LABEL:
    begin
        if rctx.pad_mode <> RSA_PKCS1_OAEP_PADDING then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING_MODE);
            Exit(-2);
        end;
        OPENSSL_free(rctx.oaep_label);
        if (p2 <> nil) and  (p1 > 0) then
        begin
            rctx.oaep_label := p2;
            rctx.oaep_labellen := p1;
        end
        else
        begin
            rctx.oaep_label := nil;
            rctx.oaep_labellen := 0;
        end;
        Exit(1);
    end;
    EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL:
    begin
        if rctx.pad_mode <> RSA_PKCS1_OAEP_PADDING then
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING_MODE);
            Exit(-2);
        end;
        PPByte(p2)^ := rctx.oaep_label;
        Exit(rctx.oaep_labellen);
    end;
    EVP_PKEY_CTRL_DIGESTINIT,
    EVP_PKEY_CTRL_PKCS7_SIGN,
{$IFNDEF OPENSSL_NO_CMS}
    EVP_PKEY_CTRL_CMS_SIGN:
{$ENDIF}
    Exit(1);
    EVP_PKEY_CTRL_PKCS7_ENCRYPT,
    EVP_PKEY_CTRL_PKCS7_DECRYPT,
{$IFNDEF OPENSSL_NO_CMS}
    EVP_PKEY_CTRL_CMS_DECRYPT,
    EVP_PKEY_CTRL_CMS_ENCRYPT:
{$ENDIF}
    if 0>= pkey_ctx_is_pss(ctx )then
        Exit(1);
    { fall through }
    EVP_PKEY_CTRL_PEER_KEY:
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        Exit(-2);
    end
    else
        Exit(-2);
    end;
end;


function pkey_rsa_ctrl_str(ctx : PEVP_PKEY_CTX;const &type, value : PUTF8Char):integer;
var
  pm, saltlen, nbits, ret : integer;
  pubexp : PBIGNUM;
  nprimes : integer;
  lab : PByte;
  lablen : long;

begin
    if value = nil then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_VALUE_MISSING);
        Exit(0);
    end;
    if strcmp(&type, 'rsa_padding_mode') = 0  then
    begin
        if strcmp(value, 'pkcs1') = 0 then
        begin
            pm := RSA_PKCS1_PADDING;
        end
        else if (strcmp(value, 'none') = 0)  then
        begin
                  pm := RSA_NO_PADDING;
        end
        else if (strcmp(value, 'oeap') = 0)  then
        begin
                  pm := RSA_PKCS1_OAEP_PADDING;
        end
        else if (strcmp(value, 'oaep') = 0)  then
        begin
                  pm := RSA_PKCS1_OAEP_PADDING;
        end
        else if (strcmp(value, 'x931') = 0)  then
        begin
                  pm := RSA_X931_PADDING;
        end
        else if (strcmp(value, 'pss') = 0)  then
        begin
                  pm := RSA_PKCS1_PSS_PADDING;
        end
        else
        begin
            ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE);
            Exit(-2);
        end;
        Exit(EVP_PKEY_CTX_set_rsa_padding(ctx, pm));
    end;
    if strcmp(&type, 'rsa_pss_saltlen')  = 0 then
    begin
        if 0>= strcmp(value, 'digest') then
            saltlen := RSA_PSS_SALTLEN_DIGEST
        else if (0>= strcmp(value, 'max'))then
            saltlen := RSA_PSS_SALTLEN_MAX
        else if (0>= strcmp(value, 'auto'))then
            saltlen := RSA_PSS_SALTLEN_AUTO
        else
            saltlen := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen));
    end;
    if strcmp(&type, 'rsa_keygen_bits') = 0  then
    begin
        nbits := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits));
    end;
    if strcmp(&type, 'rsa_keygen_pubexp') = 0 then
    begin
        pubexp := nil;
        if 0>= BN_asc2bn(@pubexp, value) then
            Exit(0);
        ret := EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, pubexp);
        BN_free(pubexp);
        Exit(ret);
    end;
    if strcmp(&type, 'rsa_keygen_primes') = 0 then
    begin
        nprimes := StrToInt(value);
        Exit(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, nprimes));
    end;
    if strcmp(&type, 'rsa_mgf1_md') = 0 then
        Exit(EVP_PKEY_CTX_md(ctx,
                               EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT,
                               EVP_PKEY_CTRL_RSA_MGF1_MD, value));
    if pkey_ctx_is_pss(ctx) > 0 then
    begin
        if strcmp(&type, 'rsa_pss_keygen_mgf1_md') = 0 then
            Exit(EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_KEYGEN,
                                   EVP_PKEY_CTRL_RSA_MGF1_MD, value));
        if strcmp(&type, 'rsa_pss_keygen_md') = 0 then
            Exit(EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_KEYGEN,
                                   EVP_PKEY_CTRL_MD, value));
        if strcmp(&type, 'rsa_pss_keygen_saltlen') = 0 then
        begin
            saltlen := StrToInt(value);
            Exit(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, saltlen));
        end;
    end;
    if strcmp(&type, 'rsa_oaep_md') = 0 then
        Exit(EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_TYPE_CRYPT,
                               EVP_PKEY_CTRL_RSA_OAEP_MD, value));
    if strcmp(&type, 'rsa_oaep_label') = 0 then
    begin
        lab := OPENSSL_hexstr2buf(value, @lablen);
        if nil = lab then Exit(0);
        ret := EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lab, lablen);
        if ret <= 0 then OPENSSL_free(lab);
        Exit(ret);
    end;
    Result := -2;
end;


function rsa_set_pss_param( rsa : PRSA; ctx : PEVP_PKEY_CTX):integer;
var
  rctx : PRSA_PKEY_CTX;
begin
    rctx := ctx.data;
    if 0>= pkey_ctx_is_pss(ctx) then
        Exit(1);
    { If all parameters are default values don't set pss }
    if (rctx.md = nil)  and  (rctx.mgf1md = nil)  and  (rctx.saltlen = -2) then
       Exit(1);
    rsa.pss := ossl_rsa_pss_params_create(rctx.md, rctx.mgf1md,
                                       get_result(rctx.saltlen = -2
                                          , 0 , rctx.saltlen));
    if rsa.pss = nil then
       Exit(0);
    Result := 1;
end;


function pkey_rsa_keygen( ctx : PEVP_PKEY_CTX; pkey : PEVP_PKEY):integer;
var
  rsa : PRSA;

  rctx : PRSA_PKEY_CTX;

  pcb : PBN_GENCB;

  ret : integer;
begin
    rsa := nil;
    rctx := ctx.data;
    if rctx.pub_exp = nil then
    begin
        rctx.pub_exp := BN_new();
        if (rctx.pub_exp = nil)  or  (0>= BN_set_word(rctx.pub_exp, RSA_F4)) then
            Exit(0);
    end;
    rsa := RSA_new();
    if rsa = nil then Exit(0);
    if Assigned(ctx.pkey_gencb) then
    begin
        pcb := BN_GENCB_new();
        if pcb = nil then
        begin
            RSA_free(rsa);
            Exit(0);
        end;
        evp_pkey_set_cb_translate(pcb, ctx);
    end
    else
    begin
        pcb := nil;
    end;
    ret := RSA_generate_multi_prime_key(rsa, rctx.nbits, rctx.primes,
                                       rctx.pub_exp, pcb);
    BN_GENCB_free(pcb);
    if (ret > 0)  and  (0>= rsa_set_pss_param(rsa, ctx)) then
    begin
        RSA_free(rsa);
        Exit(0);
    end;
    if ret > 0 then
       EVP_PKEY_assign(pkey, ctx.pmeth.pkey_id, rsa)
    else
        RSA_free(rsa);
    Result := ret;
end;


function pkey_pss_init( ctx : PEVP_PKEY_CTX):integer;
var
    rsa         : PRSA;

    rctx        : PRSA_PKEY_CTX;

  md,
  mgf1md      : PEVP_MD;

  min_saltlen,
  max_saltlen : integer;
begin
    rctx := ctx.data;
    { Should never happen }
    if 0>= pkey_ctx_is_pss(ctx ) then
        Exit(0);
    rsa := EVP_PKEY_get0_RSA(ctx.pkey);
    { If no restrictions just return }
    if rsa.pss = nil then Exit(1);
    { Get and check parameters }
    if 0>= ossl_rsa_pss_get_param(rsa.pss, @md, @mgf1md, @min_saltlen ) then
        Exit(0);
    { See if minimum salt length exceeds maximum possible }
    max_saltlen := RSA_size(rsa) - EVP_MD_get_size(md);
    if (_RSA_bits(rsa) and $7) = 1 then
        Dec(max_saltlen);
    if min_saltlen > max_saltlen then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_SALT_LENGTH);
        Exit(0);
    end;
    rctx.min_saltlen := min_saltlen;
    {
     * Set PSS restrictions as defaults: we can then block any attempt to
     * use invalid values in pkey_rsa_ctrl
     }
    rctx.md := md;
    rctx.mgf1md := mgf1md;
    rctx.saltlen := min_saltlen;
    Result := 1;
end;


function ossl_rsa_pss_pkey_method:PEVP_PKEY_METHOD;
begin
    Result := @rsa_pss_pkey_meth;
end;



function pkey_rsa_copy(dst : PEVP_PKEY_CTX;const src : PEVP_PKEY_CTX):integer;
var
  dctx, sctx : PRSA_PKEY_CTX;
begin
    if 0>= pkey_rsa_init(dst )then
        Exit(0);
    sctx := src.data;
    dctx := dst.data;
    dctx.nbits := sctx.nbits;
    if sctx.pub_exp <> nil then
    begin
        dctx.pub_exp := BN_dup(sctx.pub_exp);
        if nil = dctx.pub_exp then
           Exit(0);
    end;
    dctx.pad_mode := sctx.pad_mode;
    dctx.md := sctx.md;
    dctx.mgf1md := sctx.mgf1md;
    dctx.saltlen := sctx.saltlen;
    if sctx.oaep_label <> nil then
    begin
        OPENSSL_free(dctx.oaep_label);
        dctx.oaep_label := OPENSSL_memdup(sctx.oaep_label, sctx.oaep_labellen);
        if nil = dctx.oaep_label then
           Exit(0);
        dctx.oaep_labellen := sctx.oaep_labellen;
    end;
    Result := 1;
end;







function pkey_rsa_init( ctx : PEVP_PKEY_CTX):integer;
var
  rctx : PRSA_PKEY_CTX;
begin
    rctx := OPENSSL_zalloc(sizeof( rctx^));
    if rctx = nil then Exit(0);
    rctx.nbits := 2048;
    rctx.primes := RSA_DEFAULT_PRIME_NUM;
    if pkey_ctx_is_pss(ctx)>0 then
        rctx.pad_mode := RSA_PKCS1_PSS_PADDING
    else
        rctx.pad_mode := RSA_PKCS1_PADDING;
    { Maximum for sign, auto for verify }
    rctx.saltlen := RSA_PSS_SALTLEN_AUTO;
    rctx.min_saltlen := -1;
    ctx.data := rctx;
    ctx.keygen_info := @rctx.gentmp;
    ctx.keygen_info_count := 2;
    Result := 1;
end;

function ossl_rsa_pkey_method:PEVP_PKEY_METHOD;
begin
    Result := @rsa_pkey_meth;
end;

end.
