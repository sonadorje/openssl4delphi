unit openssl3.crypto.rsa.rsa_lib;

interface
 uses OpenSSL.Api;

function ossl_rsa_new_with_ctx( libctx : POSSL_LIB_CTX):PRSA;
function rsa_new_intern( engine : PENGINE; libctx : POSSL_LIB_CTX):PRSA;

function ossl_rsa_get0_all_params( r : PRSA; primes, exps, coeffs : Pstack_st_BIGNUM_const):integer;
 function ossl_rsa_get0_libctx( r : PRSA):POSSL_LIB_CTX;
function ossl_rsa_set0_all_params(r : PRSA;const primes, exps, coeffs : Pstack_st_BIGNUM):integer;
function ossl_rsa_get0_pss_params_30( r : PRSA):PRSA_PSS_PARAMS_30;
function RSA_up_ref( r : PRSA):integer;
function ossl_ifc_ffc_compute_security_bits( n : integer):uint16;
function RSA_get0_dmp1(const r : PRSA):PBIGNUM;
function RSA_get0_dmq1(const r : PRSA):PBIGNUM;
function RSA_get_multi_prime_extra_count(const r : PRSA):integer;
 function RSA_get0_multi_prime_factors(const r : PRSA; primes : PPBIGNUM):integer;
 function RSA_get0_multi_prime_crt_params(const r : PRSA; exps, coeffs : PPBIGNUM):integer;
 function RSA_get0_p(const r : PRSA):PBIGNUM;
 function RSA_get0_q(const r : PRSA):PBIGNUM;
function RSA_get0_iqmp(const r : PRSA):PBIGNUM;
function RSA_get0_n(const r : PRSA):PBIGNUM;
function RSA_get0_e(const r : PRSA):PBIGNUM;
function RSA_get0_d(const r : PRSA):PBIGNUM;
function pkey_ctx_is_pss(ctx: PEVP_PKEY_CTX): Integer;
function EVP_PKEY_CTX_set_rsa_padding( ctx : PEVP_PKEY_CTX; pad_mode : integer):integer;
function EVP_PKEY_CTX_set_rsa_pss_saltlen( ctx : PEVP_PKEY_CTX; saltlen : integer):integer;
function EVP_PKEY_CTX_set_rsa_keygen_bits( ctx : PEVP_PKEY_CTX; bits : integer):integer;
function EVP_PKEY_CTX_set1_rsa_keygen_pubexp( ctx : PEVP_PKEY_CTX; pubexp : PBIGNUM):integer;
function EVP_PKEY_CTX_set_rsa_keygen_primes( ctx : PEVP_PKEY_CTX; primes : integer):integer;
function EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen( ctx : PEVP_PKEY_CTX; saltlen : integer):integer;
function EVP_PKEY_CTX_set0_rsa_oaep_label( ctx : PEVP_PKEY_CTX; &label : Pointer; llen : integer):integer;
 function RSA_new:PRSA;
 procedure RSA_free( r : PRSA);
 function RSA_set0_key( r : PRSA; n, e, d : PBIGNUM):integer;
 procedure RSA_get0_key(const r : PRSA; n, e, d : PPBIGNUM);
 function RSA_get_method(const rsa : PRSA):PRSA_METHOD;
 function RSA_set_method(rsa : PRSA;const meth : PRSA_METHOD):integer;
 function RSA_pkey_ctx_ctrl( ctx : PEVP_PKEY_CTX; optype, cmd, p1 : integer; p2 : Pointer):integer;
 function ilog_e( v : uint64):uint32;
 function mul2( a, b : uint64):uint64;
 function icbrt64( x : uint64):uint64;
 function RSA_set0_factors( r : PRSA; p, q : PBIGNUM):integer;
 function RSA_set0_crt_params( r : PRSA; dmp1, dmq1, iqmp : PBIGNUM):integer;
 function ossl_rsa_set0_pss_params( r : PRSA; pss : PRSA_PSS_PARAMS):integer;
  function RSA_get0_pss_params(const r : PRSA):PRSA_PSS_PARAMS;
  procedure RSA_clear_flags( r : PRSA; flags : integer);
  procedure RSA_set_flags( r : PRSA; flags : integer);
  function _RSA_security_bits(const rsa : PRSA):integer;
  function EVP_PKEY_CTX_get_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;const md : PPEVP_MD):integer;
  function EVP_PKEY_CTX_get_rsa_pss_saltlen( ctx : PEVP_PKEY_CTX; saltlen : PInteger):integer;
  function EVP_PKEY_CTX_set_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
  function EVP_PKEY_CTX_get_rsa_padding( ctx : PEVP_PKEY_CTX; pad_mode : PInteger):integer;
  function RSA_test_flags(const r : PRSA; flags : integer):integer;
  procedure RSA_get0_factors(const r : PRSA; p, q : PPBIGNUM);
  procedure RSA_get0_crt_params(const r : PRSA;  dmp1, dmq1, iqmp : PPBIGNUM);
   procedure ossl_rsa_set0_libctx( r : PRSA; libctx : POSSL_LIB_CTX);

 const
   log_2: uint32  = $02c5c8;
   scale: uint32 = 1 shl 18;
   log_e: uint32 = $05c551;
   c1_923: uint32 = $07b126;
   c4_690: uint32 = $12c28f;
   cbrt_scale: uint32 = 1 shl (2 * 18 div 3);


implementation
uses
      openssl3.crypto.mem, OpenSSL3.Err, OpenSSL3.crypto.rsa.rsa_backend,
      openssl3.crypto.rsa.rsa_local, OpenSSL3.common, OpenSSL3.crypto.rsa.rsa_mp,
      openssl3.include.internal.refcount, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.ex_data, OpenSSL3.threads_none,
      openssl3.crypto.params, openssl3.crypto.rsa.rsa_ossl,
      openssl3.crypto.evp,   openssl3.crypto.evp.pmeth_lib,
      openssl3.crypto.rsa.rsa_asn1,  openssl3.crypto.bn.bn_blind,
      OpenSSL3.crypto.engine.eng_init, openssl3.crypto.engine.tb_rsa;





procedure ossl_rsa_set0_libctx( r : PRSA; libctx : POSSL_LIB_CTX);
begin
    r.libctx := libctx;
end;

procedure RSA_get0_crt_params(const r : PRSA; dmp1, dmq1, iqmp : PPBIGNUM);
begin
    if dmp1 <> nil then dmp1^ := r.dmp1;
    if dmq1 <> nil then dmq1^ := r.dmq1;
    if iqmp <> nil then iqmp^ := r.iqmp;
end;




procedure RSA_get0_factors(const r : PRSA; p, q : PPBIGNUM);
begin
    if p <> nil then p^ := r.p;
    if q <> nil then q^ := r.q;
end;

function EVP_PKEY_CTX_get_rsa_padding( ctx : PEVP_PKEY_CTX; pad_mode : PInteger):integer;
begin
    Exit(RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, pad_mode));
end;



function RSA_test_flags(const r : PRSA; flags : integer):integer;
begin
    Result := r.flags and flags;
end;




function EVP_PKEY_CTX_set_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;const md : PEVP_MD):integer;
begin
    Exit(RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_RSA_MGF1_MD, 0, Pointer(md)));
end;



function EVP_PKEY_CTX_get_rsa_pss_saltlen( ctx : PEVP_PKEY_CTX; saltlen : PInteger):integer;
begin
    {
     * Because of circumstances, the optype is updated from:
     *
     * EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY
     *
     * to:
     *
     * EVP_PKEY_OP_TYPE_SIG
     }
    Exit(RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG,
                             EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, saltlen));
end;




function EVP_PKEY_CTX_get_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;const md : PPEVP_MD):integer;
begin
    Exit(RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, Pointer(md)));
end;

function _RSA_security_bits(const rsa : PRSA):integer;
var
  bits,
  ex_primes : integer;
begin
    bits := BN_num_bits(rsa.n);
{$IFNDEF FIPS_MODULE}
    if rsa.version = RSA_ASN1_VERSION_MULTI then
    begin
        { This ought to mean that we have private key at hand. }
        ex_primes := sk_RSA_PRIME_INFO_num(rsa.prime_infos);
        if (ex_primes <= 0)  or  (ex_primes + 2 > ossl_rsa_multip_cap(bits)) then
            Exit(0);
    end;
{$ENDIF}
    Result := ossl_ifc_ffc_compute_security_bits(bits);
end;



procedure RSA_set_flags( r : PRSA; flags : integer);
begin
    r.flags  := r.flags  or flags;
end;

procedure RSA_clear_flags( r : PRSA; flags : integer);
begin
    r.flags := r.flags and (not flags);
end;


function RSA_get0_pss_params(const r : PRSA):PRSA_PSS_PARAMS;
begin
{$IFDEF FIPS_MODULE}
    Exit(nil);
{$ELSE}
    Exit(r.pss);
{$ENDIF}
end;

function ossl_rsa_set0_pss_params( r : PRSA; pss : PRSA_PSS_PARAMS):integer;
begin
{$IFDEF FIPS_MODULE}
    Exit(0);
{$ELSE}
    RSA_PSS_PARAMS_free(r.pss);
    r.pss := pss;
    Exit(1);
{$ENDIF}
end;




function RSA_set0_crt_params( r : PRSA; dmp1, dmq1, iqmp : PBIGNUM):integer;
begin
    { If the fields dmp1, dmq1 and iqmp in r are nil, the corresponding input
     * parameters MUST be non-nil.
     }
    if ( (r.dmp1 = nil)  and  (dmp1 = nil) )
         or ( (r.dmq1 = nil)  and  (dmq1 = nil) )
         or ( (r.iqmp = nil)  and  (iqmp = nil) ) then
        Exit(0);
    if dmp1 <> nil then
    begin
        BN_clear_free(r.dmp1);
        r.dmp1 := dmp1;
        BN_set_flags(r.dmp1, BN_FLG_CONSTTIME);
    end;
    if dmq1 <> nil then
    begin
        BN_clear_free(r.dmq1);
        r.dmq1 := dmq1;
        BN_set_flags(r.dmq1, BN_FLG_CONSTTIME);
    end;
    if iqmp <> nil then
    begin
        BN_clear_free(r.iqmp);
        r.iqmp := iqmp;
        BN_set_flags(r.iqmp, BN_FLG_CONSTTIME);
    end;
    Inc(r.dirty_cnt);
    Result := 1;
end;




function RSA_set0_factors( r : PRSA; p, q : PBIGNUM):integer;
begin
    { If the fields p and q in r are nil, the corresponding input
     * parameters MUST be non-nil.
     }
    if (r.p = nil)  and  (p = nil)  or ( (r.q = nil)  and  (q = nil) ) then
        Exit(0);
    if p <> nil then
    begin
        BN_clear_free(r.p);
        r.p := p;
        BN_set_flags(r.p, BN_FLG_CONSTTIME);
    end;
    if q <> nil then
    begin
        BN_clear_free(r.q);
        r.q := q;
        BN_set_flags(r.q, BN_FLG_CONSTTIME);
    end;
    Inc(r.dirty_cnt);
    Result := 1;
end;

function icbrt64( x : uint64):uint64;
var
  r, b : uint64;
  s : integer;
begin
    r := 0;
    s := 63;
    while s >= 0 do
    begin
        r  := r shl 1;
        b := 3 * r * (r + 1) + 1;
        if (x  shr  s) >= b then
        begin
            x  := x - (b  shl  s);
            Inc(r);
        end;
        s := s - 3;
    end;
    Result := r * cbrt_scale;
end;



function mul2( a, b : uint64):uint64;
begin
    Result := a * b div scale;
end;



function ilog_e( v : uint64):uint32;
var
  i, r : uint32;
begin
    r := 0;
    {
     * Scale down the value into the range 1 .. 2.
     *
     * If fractional numbers need to be processed, another loop needs
     * to go here that checks v < scale and if so multiplies it by 2 and
     * reduces r by scale.  This also means making r signed.
     }
    while v >= 2 * scale do
    begin
        v  := v shr 1;
        r  := r + scale;
    end;
    i := scale div 2;
    while i <> 0 do
    begin
        v := mul2(v, v);
        if v >= 2 * scale then
        begin
            v  := v shr 1;
            r  := r + i;
        end;
        i := i div 2;
    end;
    r := (r * uint64( scale)) div log_e;
    Result := r;
end;





function RSA_pkey_ctx_ctrl( ctx : PEVP_PKEY_CTX; optype, cmd, p1 : integer; p2 : Pointer):integer;
begin
    { If key type not RSA or RSA-PSS return error }
    if (ctx <> nil)  and  (ctx.pmeth <> nil)
         and  (ctx.pmeth.pkey_id <> EVP_PKEY_RSA)
         and  (ctx.pmeth.pkey_id <> EVP_PKEY_RSA_PSS) then
         Exit(-1);
     Result := EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
end;




function RSA_get_method(const rsa : PRSA):PRSA_METHOD;
begin
    Result := rsa.meth;
end;


function RSA_set_method(rsa : PRSA;const meth : PRSA_METHOD):integer;
var
  mtmp : PRSA_METHOD;
begin
    {
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     }
    mtmp := rsa.meth;
    if Assigned(mtmp.finish) then
       mtmp.finish(rsa);
{$IFNDEF OPENSSL_NO_ENGINE}
    ENGINE_finish(rsa.engine);
    rsa.engine := nil;
{$ENDIF}
    rsa.meth := meth;
    if Assigned(meth.init) then
       meth.init(rsa);
    Result := 1;
end;



procedure RSA_get0_key(const r : PRSA; n, e, d : PPBIGNUM);
begin
    if n <> nil then n^ := r.n;
    if e <> nil then e^ := r.e;
    if d <> nil then d^ := r.d;
end;



function RSA_set0_key( r : PRSA; n, e, d : PBIGNUM):integer;
begin
    { If the fields n and e in r are nil, the corresponding input
     * parameters MUST be non-nil for n and e.  d may be
     * left nil (in case only the public key is used).
     }
    if ( (r.n = nil)  and  (n = nil) )  or ( (r.e = nil)  and  (e = nil) ) then
        Exit(0);
    if n <> nil then
    begin
        BN_free(r.n);
        r.n := n;
    end;
    if e <> nil then
    begin
        BN_free(r.e);
        r.e := e;
    end;
    if d <> nil then
    begin
        BN_clear_free(r.d);
        r.d := d;
        BN_set_flags(r.d, BN_FLG_CONSTTIME);
    end;
    Inc(r.dirty_cnt);
    Result := 1;
end;





procedure RSA_free( r : PRSA);
var
  i : integer;
begin
    if r = nil then exit;
    CRYPTO_DOWN_REF(r.references, i, r.lock);
    REF_PRINT_COUNT('RSA', r);
    if i > 0 then exit;
    REF_ASSERT_ISNT(i < 0);
    if (r.meth <> nil)  and  (Assigned(r.meth.finish)) then
       r.meth.finish(r);
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    ENGINE_finish(r.engine);
{$ENDIF}
{$IFNDEF FIPS_MODULE}
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, @r.ex_data);
{$ENDIF}
    CRYPTO_THREAD_lock_free(r.lock);
    BN_free(r.n);
    BN_free(r.e);
    BN_clear_free(r.d);
    BN_clear_free(r.p);
    BN_clear_free(r.q);
    BN_clear_free(r.dmp1);
    BN_clear_free(r.dmq1);
    BN_clear_free(r.iqmp);
{$IF defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ACVP_TESTS)}
    ossl_rsa_acvp_test_free(r.acvp_test);
{$ENDIF}
{$IFNDEF FIPS_MODULE}
    RSA_PSS_PARAMS_free(r.pss);
    sk_RSA_PRIME_INFO_pop_free(r.prime_infos, ossl_rsa_multip_info_free);
{$ENDIF}
    BN_BLINDING_free(r.blinding);
    BN_BLINDING_free(r.mt_blinding);
    OPENSSL_free(Pointer(r));
end;

function RSA_new:PRSA;
begin
    Result := rsa_new_intern(nil, nil);
end;

function EVP_PKEY_CTX_set0_rsa_oaep_label( ctx : PEVP_PKEY_CTX; &label : Pointer; llen : integer):integer;
var
    rsa_params : array[0..1] of TOSSL_PARAM;

    p          : POSSL_PARAM;
begin
    p := @rsa_params;
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx) ) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    { If key type not RSA return error }
    if 0>= EVP_PKEY_CTX_is_a(ctx, 'RSA') then
        Exit(-1);
    { Cast away the const. This is read only so should be safe }
    PostInc(p)^ :=  OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                             Pointer(&label), size_t( llen));
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    if 0>= evp_pkey_ctx_set_params_strict(ctx, @rsa_params) then
        Exit(0);
    { Ownership is supposed to be transferred to the callee. }
    OPENSSL_free(&label);
    Result := 1;
end;

function EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen( ctx : PEVP_PKEY_CTX; saltlen : integer):integer;
var
    pad_params : array[0..1] of TOSSL_PARAM;

    p          : POSSL_PARAM;
begin

    p := @pad_params;
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_GEN_OP(ctx)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    if 0>= EVP_PKEY_CTX_is_a(ctx, 'RSA-PSS') then
        Exit(-1);
    PostInc(p)^ :=  OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                    @saltlen);
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @pad_params);
end;




function EVP_PKEY_CTX_set_rsa_keygen_primes( ctx : PEVP_PKEY_CTX; primes : integer):integer;
var
  params : array[0..1] of TOSSL_PARAM;

  p : POSSL_PARAM;

  primes2 : size_t;
begin
    p := @params;
    primes2 := primes;
    if (ctx = nil)  or  (not EVP_PKEY_CTX_IS_GEN_OP(ctx)) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    { If key type not RSA return error }
    if (0>= EVP_PKEY_CTX_is_a(ctx, 'RSA'))  and  (0>= EVP_PKEY_CTX_is_a(ctx, 'RSA-PSS')) then
        Exit(-1);
    PostInc(p)^ :=  OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, @primes2);
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @params);
end;




function EVP_PKEY_CTX_set1_rsa_keygen_pubexp( ctx : PEVP_PKEY_CTX; pubexp : PBIGNUM):integer;
var
  ret : integer;
begin
    ret := 0;
    {
     * When we're dealing with a provider, there's no need to duplicate
     * pubexp, as it gets copied when transforming to an OSSL_PARAM anyway.
     }
    if evp_pkey_ctx_is_legacy(ctx ) then
    begin
        pubexp := BN_dup(pubexp);
        if pubexp = nil then Exit(0);
    end;
    ret := EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
                            EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp);
    if (evp_pkey_ctx_is_legacy(ctx))  and  (ret <= 0)  then
        BN_free(pubexp);
    Result := ret;
end;




function EVP_PKEY_CTX_set_rsa_keygen_bits( ctx : PEVP_PKEY_CTX; bits : integer):integer;
var
  params : array[0..1] of TOSSL_PARAM;
  p: POSSL_PARAM;
  bits2 : size_t;
begin
    p := @params;
    bits2 := bits;
    if (ctx = nil ) or  (not EVP_PKEY_CTX_IS_GEN_OP(ctx ))  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        { Uses the same return values as EVP_PKEY_CTX_ctrl }
        Exit(-2);
    end;
    { If key type not RSA return error }
    if (0>= EVP_PKEY_CTX_is_a(ctx, 'RSA'))  and  (0>= EVP_PKEY_CTX_is_a(ctx, 'RSA-PSS'))  then
        Exit(-1);
    PostInc(p)^ :=  OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, @bits2);
    PostInc(p)^ :=  OSSL_PARAM_construct_end();
    Result := evp_pkey_ctx_set_params_strict(ctx, @params);
end;





function EVP_PKEY_CTX_set_rsa_pss_saltlen( ctx : PEVP_PKEY_CTX; saltlen : integer):integer;
begin
    {
     * For some reason, the optype was set to this:
     *
     * EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY
     *
     * However, we do use RSA-PSS with the whole gamut of diverse signature
     * and verification operations, so the optype gets upgraded to this:
     *
     * EVP_PKEY_OP_TYPE_SIG
     }
    Exit(RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG,
                             EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltlen, nil));
end;




function EVP_PKEY_CTX_set_rsa_padding( ctx : PEVP_PKEY_CTX; pad_mode : integer):integer;
begin
    Exit(RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad_mode, nil));
end;

function pkey_ctx_is_pss(ctx: PEVP_PKEY_CTX): Integer;
begin
   Result := int(ctx.pmeth.pkey_id = EVP_PKEY_RSA_PSS)
end;



function RSA_get0_d(const r : PRSA):PBIGNUM;
begin
    Result := r.d;
end;





function RSA_get0_e(const r : PRSA):PBIGNUM;
begin
    Result := r.e;
end;





function RSA_get0_n(const r : PRSA):PBIGNUM;
begin
    Result := r.n;
end;




function RSA_get0_iqmp(const r : PRSA):PBIGNUM;
begin
    Result := r.iqmp;
end;

function RSA_get0_p(const r : PRSA):PBIGNUM;
begin
    Result := r.p;
end;


function RSA_get0_q(const r : PRSA):PBIGNUM;
begin
    Result := r.q;
end;


function RSA_get0_multi_prime_crt_params(const r : PRSA; exps, coeffs : PPBIGNUM):integer;
var
  pnum : integer;
  pinfo : PRSA_PRIME_INFO;
  i : integer;
begin
{$POINTERMATH ON}
    pnum := RSA_get_multi_prime_extra_count(r);
    if pnum = 0 then
        Exit(0);
    { return other primes }
    if (exps <> nil)  or  (coeffs <> nil) then
    begin
        { it's the user's job to guarantee the buffer length }
        for i := 0 to pnum-1 do
        begin
            pinfo := sk_RSA_PRIME_INFO_value(r.prime_infos, i);
            if exps <> nil then
               exps[i] := pinfo.d;
            if coeffs <> nil then
               coeffs[i] := pinfo.t;
        end;
    end;
    Result := 1;
{$POINTERMATH OFF}
end;




function RSA_get_multi_prime_extra_count(const r : PRSA):integer;
var
  pnum : integer;
begin
    pnum := sk_RSA_PRIME_INFO_num(r.prime_infos);
    if pnum <= 0 then
       pnum := 0;
    Result := pnum;
end;


function RSA_get0_multi_prime_factors(const r : PRSA; primes : PPBIGNUM):integer;
var
  pnum, i : integer;
  pinfo : PRSA_PRIME_INFO;
begin
{$POINTERMATH ON}
    pnum := RSA_get_multi_prime_extra_count(r);
    if pnum =  0 then
        Exit(0);
    {
     * return other primes
     * it's caller's responsibility to allocate oth_primes[pnum]
     }
    for i := 0 to pnum-1 do
    begin
        pinfo := sk_RSA_PRIME_INFO_value(r.prime_infos, i);
        primes[i] := pinfo.r;
    end;
    Result := 1;
{$POINTERMATH OFF}
end;

function RSA_get0_dmq1(const r : PRSA):PBIGNUM;
begin
    Result := r.dmq1;
end;




function RSA_get0_dmp1(const r : PRSA):PBIGNUM;
begin
    Result := r.dmp1;
end;




function ossl_ifc_ffc_compute_security_bits( n : integer):uint16;
var
  x : uint64;
  lx : uint32;
  y, cap : uint16;
begin
    {
     * Look for common values as listed in standards.
     * These values are not exactly equal to the results from the formulae in
     * the standards but are defined to be canonical.
     }
    case n of
    2048:       { SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 }
        Exit(112);
    3072:       { SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 }
        Exit(128);
    4096:       { SP 800-56B rev 2 Appendix D }
        Exit(152);
    6144:       { SP 800-56B rev 2 Appendix D }
        Exit(176);
    7680:       { FIPS 140-2 IG 7.5 }
        Exit(192);
    8192:       { SP 800-56B rev 2 Appendix D }
        Exit(200);
    15360:      { FIPS 140-2 IG 7.5 }
        Exit(256);
    end;
    {
     * The first incorrect result (i.e. not accurate or off by one low) occurs
     * for n = 699668.  The true value here is 1200.  Instead of using this n
     * as the check threshold, the smallest n such that the correct result is
     * 1200 is used instead.
     }
    if n >= 687737 then Exit(1200);
    if n < 8 then Exit(0);
    {
     * To ensure that the output is non-decreasing with respect to n,
     * a cap needs to be applied to the two values where the function over
     * estimates the strength (according to the above fast path).
     }
    if n <= 7680 then
       cap := 192
    else
    if (n <= 15360) then
        cap := 256
    else
        cap := 1200;
    x := n * uint64( log_2);
    lx := ilog_e(x);
    y := uint16((mul2(c1_923, icbrt64(mul2(mul2(x, lx), lx))) - c4_690)
                   div log_2);
    y := (y + 4) and (not 7);
    if y > cap then
       y := cap;
    Result := y;
end;



function RSA_up_ref( r : PRSA):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(r.references, i, r.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('RSA', r);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result(i > 1 , 1 , 0);
end;

function ossl_rsa_set0_all_params(r : PRSA;const primes, exps, coeffs : Pstack_st_BIGNUM):integer;
var
  prime_infos,
  old_infos   : Pstack_st_RSA_PRIME_INFO;

  pnum,
  i           : integer;

  prime,
  exp,
  coeff       : PBIGNUM;
  pinfo       : PRSA_PRIME_INFO;
  label _err;
begin
{$IFNDEF FIPS_MODULE}
    old_infos := nil;
{$ENDIF}
    if (primes = nil)  or  (exps = nil)  or  (coeffs = nil) then Exit(0);
    pnum := sk_BIGNUM_num(primes);
    if (pnum < 2)  or
       (pnum <> sk_BIGNUM_num(exps) )  or  (pnum <> sk_BIGNUM_num(coeffs) + 1)  then
        Exit(0);
    if  (0>= RSA_set0_factors(r, sk_BIGNUM_value(primes, 0),
                          sk_BIGNUM_value(primes, 1)) )
         or (0>= RSA_set0_crt_params(r, sk_BIGNUM_value(exps, 0),
                                sk_BIGNUM_value(exps, 1),
                                sk_BIGNUM_value(coeffs, 0)))  then
        Exit(0);
{$IFNDEF FIPS_MODULE}
    old_infos := r.prime_infos;
{$ENDIF}
    if pnum > 2 then
    begin
{$IFNDEF FIPS_MODULE}
        prime_infos := sk_RSA_PRIME_INFO_new_reserve(nil, pnum);
        if prime_infos = nil then Exit(0);
        for i := 2 to pnum-1 do begin
            prime := sk_BIGNUM_value(primes, i);
            exp := sk_BIGNUM_value(exps, i);
            coeff := sk_BIGNUM_value(coeffs, i - 1);
            pinfo := nil;
            if not ossl_assert( (prime <> nil)  and ( exp <> nil)  and (coeff <> nil) ) then
                goto _err ;
            { Using ossl_rsa_multip_info_new() is wasteful, so allocate directly }
            pinfo := OPENSSL_zalloc(sizeof(pinfo^));
            if pinfo = nil then
            begin
                ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            pinfo.r := prime;
            pinfo.d := exp;
            pinfo.t := coeff;
            BN_set_flags(pinfo.r, BN_FLG_CONSTTIME);
            BN_set_flags(pinfo.d, BN_FLG_CONSTTIME);
            BN_set_flags(pinfo.t, BN_FLG_CONSTTIME);
            sk_RSA_PRIME_INFO_push(prime_infos, pinfo);
        end;
        r.prime_infos := prime_infos;
        if  0>= ossl_rsa_multip_calc_product(r ) then
        begin
            r.prime_infos := old_infos;
            goto _err ;
        end;
{$ELSE}
    Exit(0);
{$ENDIF}
    end;
{$IFNDEF FIPS_MODULE}
    if old_infos <> nil then
    begin
        {
         * This is hard to deal with, since the old infos could
         * also be set by this function and r, d, t should not
         * be freed in that case. So currently, stay consistent
         * with other *set0* functions: just free it...
         }
        sk_RSA_PRIME_INFO_pop_free(old_infos, ossl_rsa_multip_info_free);
    end;
{$ENDIF}
    r.version := get_result(pnum > 2 , RSA_ASN1_VERSION_MULTI , RSA_ASN1_VERSION_DEFAULT);
    Inc(r.dirty_cnt);
    Exit(1);
{$IFNDEF FIPS_MODULE}
 _err:
    { r, d, t should not be freed }
    sk_RSA_PRIME_INFO_pop_free(prime_infos, ossl_rsa_multip_info_free_ex);
    Exit(0);
{$ENDIF}
end;

function ossl_rsa_get0_libctx( r : PRSA):POSSL_LIB_CTX;
begin
    Result := r.libctx;
end;

function ossl_rsa_get0_all_params( r : PRSA; primes, exps, coeffs : Pstack_st_BIGNUM_const):integer;
var
  pinfo : PRSA_PRIME_INFO;

  i, pnum : integer;
begin
{$IFNDEF FIPS_MODULE}
{$ENDIF}
    if r = nil then Exit(0);
    { If |p| is nil, there are no CRT parameters }
    if RSA_get0_p(r) = nil  then
        Exit(1);
    sk_BIGNUM_const_push(primes, RSA_get0_p(r));
    sk_BIGNUM_const_push(primes, RSA_get0_q(r));
    sk_BIGNUM_const_push(exps, RSA_get0_dmp1(r));
    sk_BIGNUM_const_push(exps, RSA_get0_dmq1(r));
    sk_BIGNUM_const_push(coeffs, RSA_get0_iqmp(r));
{$IFNDEF FIPS_MODULE}
    pnum := RSA_get_multi_prime_extra_count(r);
    for i := 0 to pnum-1 do begin
        pinfo := sk_RSA_PRIME_INFO_value(r.prime_infos, i);
        sk_BIGNUM_const_push(primes, pinfo.r);
        sk_BIGNUM_const_push(exps, pinfo.d);
        sk_BIGNUM_const_push(coeffs, pinfo.t);
    end;
{$ENDIF}
    Result := 1;
end;

function ossl_rsa_get0_pss_params_30( r : PRSA):PRSA_PSS_PARAMS_30;
begin
    Result := @r.pss_params;
end;

function rsa_new_intern( engine : PENGINE; libctx : POSSL_LIB_CTX):PRSA;
var
  ret : PRSA;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.references := 1;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    ret.libctx := libctx;
    ret.meth := RSA_get_default_method();
{$IF not defined(OPENSSL_NO_ENGINE)  and   not defined(FIPS_MODULE)}
    ret.flags := ret.meth.flags and (not RSA_FLAG_NON_FIPS_ALLOW);
    if Assigned(engine) then
    begin
        if  0>= ENGINE_init(engine) then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
        ret.engine := engine;
    end
    else
    begin
        ret.engine := ENGINE_get_default_RSA();
    end;
    if Assigned(ret.engine) then
    begin
        ret.meth := ENGINE_get_RSA(ret.engine);
        if ret.meth = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
    end;
{$ENDIF}
    ret.flags := ret.meth.flags and (not RSA_FLAG_NON_FIPS_ALLOW);
{$IFNDEF FIPS_MODULE}
    if  0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, @ret.ex_data )then
    begin
        goto _err ;
    end;
{$ENDIF}
    if ( Assigned(ret.meth.init) )  and   (0>= ret.meth.init(ret) )then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_INIT_FAIL);
        goto _err ;
    end;
    Exit(ret);
 _err:
    RSA_free(ret);
    Result := nil;
end;

function ossl_rsa_new_with_ctx( libctx : POSSL_LIB_CTX):PRSA;
begin
    Result := rsa_new_intern(nil, libctx);
end;

end.
