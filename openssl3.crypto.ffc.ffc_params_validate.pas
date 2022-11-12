unit openssl3.crypto.ffc.ffc_params_validate;

interface
uses OpenSSL.Api;

function ossl_ffc_params_validate_unverifiable_g(ctx : PBN_CTX; mont : PBN_MONT_CTX;const p, q, g : PBIGNUM; tmp : PBIGNUM; ret : PInteger):integer;
function ossl_ffc_params_simple_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; paramstype : integer; res : PInteger):integer;
function ossl_ffc_params_FIPS186_2_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; &type : integer; res : PInteger; cb : PBN_GENCB):integer;
function ossl_ffc_params_FIPS186_2_gen_verify( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; mode, &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
 function default_mdname( N : size_t):PUTF8Char;
 function ossl_ffc_params_FIPS186_4_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; &type : integer; res : PInteger; cb : PBN_GENCB):integer;
 function ossl_ffc_params_full_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; paramstype : integer; res : PInteger):integer;

implementation
uses openssl3.crypto.bn.bn_lib, openssl3.crypto.ffc.ffc_params,
     openssl3.crypto.evp.digest, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.ffc.ffc_params_generate, OpenSSL3.Err,
     openssl3.crypto.bn.bn_mont, openssl3.crypto.bn.bn_add,
     openssl3.crypto.bn.bn_div, openssl3.crypto.bn.bn_exp,
     openssl3.crypto.bn.bn_prime, openssl3.crypto.bn.bn_shift;


function ossl_ffc_params_full_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; paramstype : integer; res : PInteger):integer;
var
  tmpres, ret : integer;

  ctx : PBN_CTX;
begin
    tmpres := 0;
    if params = nil then Exit(0);
    if res = nil then
       res := @tmpres;
{$IFDEF FIPS_MODULE}
    Exit(ossl_ffc_params_FIPS186_4_validate(libctx, params, paramstype,
                                              res, nil);
{$ELSE}
    if params.seed <> nil then
    begin
        if (params.flags and FFC_PARAM_FLAG_VALIDATE_LEGACY)>0 then
            Exit(ossl_ffc_params_FIPS186_2_validate(libctx, params, paramstype,
                                                      res, nil))
        else
            Exit(ossl_ffc_params_FIPS186_4_validate(libctx, params, paramstype,
                                                      res, nil));
    end
    else
    begin
        ret := 0;
        ret := ossl_ffc_params_simple_validate(libctx, params, paramstype, res);
        if ret>0 then
        begin
            ctx := BN_CTX_new_ex(libctx);
            if ctx = nil then
                Exit(0);
            if BN_check_prime(params.q, ctx, nil) <> 1 then
            begin
{$IFNDEF OPENSSL_NO_DSA}
                ERR_raise(ERR_LIB_DSA, DSA_R_Q_NOT_PRIME);
{$ENDIF}
                ret := 0;
            end;
            if (ret>0)  and  (BN_check_prime(params.p, ctx, nil) <> 1)  then
            begin
{$IFNDEF OPENSSL_NO_DSA}
                ERR_raise(ERR_LIB_DSA, DSA_R_P_NOT_PRIME);
{$ENDIF}
                ret := 0;
            end;
            BN_CTX_free(ctx);
        end;
        Exit(ret);
    end;
{$ENDIF}
end;




function ossl_ffc_params_FIPS186_4_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; &type : integer; res : PInteger; cb : PBN_GENCB):integer;
var
  L, N : size_t;
begin
    if (params = nil)  or  (params.p = nil)  or  (params.q = nil) then
       Exit(FFC_PARAM_RET_STATUS_FAILED);
    { A.1.1.3 Step (1..2) : L = len(p), N = len(q) }
    L := BN_num_bits(params.p);
    N := BN_num_bits(params.q);
    Exit(ossl_ffc_params_FIPS186_4_gen_verify(libctx, PFFC_PARAMS ( params),
                                                FFC_PARAM_MODE_VERIFY, &type,
                                                L, N, res, cb));
end;

function default_mdname( N : size_t):PUTF8Char;
begin
    if N = 160 then
       Exit('SHA1')
    else if (N = 224) then
        Exit('SHA-224')
    else if (N = 256) then
        Exit('SHA-256');
    Result := nil;
end;




function ossl_ffc_params_FIPS186_2_gen_verify( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; mode, &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
var
  ok       : integer;
  seed,
  buf      : array[0..(SHA256_DIGEST_LENGTH)-1] of Byte;
  r0,
  test,
  tmp,
  g,
  q,
  p        : PBIGNUM;
  mont     : PBN_MONT_CTX;
  md       : PEVP_MD;
  qsize    : size_t;
  n0, m,
  counter,
  pcounter,
  use_random_seed,
  rv       : integer;
  ctx      : PBN_CTX;
  hret     : integer;
  seed_in  : PByte;
  seed_len : size_t;
  verify   : Boolean;
  flags    : uint32;
  def_name : PUTF8Char;
  label _err, _pass, _g_only;
begin
    ok := FFC_PARAM_RET_STATUS_FAILED;
    g := nil;
    q := nil;
    p := nil;
    mont := nil;
    md := nil;
    n0 := 0; m := 0;
    counter := 0; pcounter := 0;
    ctx := nil;
    hret := -1;
    seed_in := params.seed;
    seed_len := params.seedlen;
    verify := (mode = FFC_PARAM_MODE_VERIFY);
    flags := get_result(verify , params.flags , 0);
    res^ := 0;
    if params.mdname <> nil then
    begin
        md := EVP_MD_fetch(libctx, params.mdname, params.mdprops);
    end
    else
    begin
        if N = 0 then
           N := get_result(L >= 2048 , SHA256_DIGEST_LENGTH , SHA_DIGEST_LENGTH) * 8;
        def_name := default_mdname(N);
        if def_name = nil then
        begin
            res^ := FFC_CHECK_INVALID_Q_VALUE;
            goto _err ;
        end;
        md := EVP_MD_fetch(libctx, def_name, params.mdprops);
    end;
    if md = nil then goto _err ;
    if N = 0 then
       N := EVP_MD_get_size(md) * 8;
    qsize := N  shr  3;
    {
     * The original spec allowed L = 512 + 64*j (j = 0.. 8)
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
     * says that 512 can be used for legacy verification.
     }
    if L < 512 then begin
        res^ := FFC_CHECK_BAD_LN_PAIR;
        goto _err ;
    end;
    if (qsize <> SHA_DIGEST_LENGTH)
         and  (qsize <> SHA224_DIGEST_LENGTH)
         and  (qsize <> SHA256_DIGEST_LENGTH )then
    begin
        { invalid q size }
        res^ := FFC_CHECK_INVALID_Q_VALUE;
        goto _err ;
    end;
    L := (L + 63) div 64 * 64;
    if seed_in <> nil then
    begin
        if seed_len < qsize then
        begin
            res^ := FFC_CHECK_INVALID_SEED_SIZE;
            goto _err ;
        end;
        { Only consume as much seed as is expected. }
        if seed_len > qsize then seed_len := qsize;
        memcpy(@seed, seed_in, seed_len);
    end;
    ctx := BN_CTX_new_ex(libctx);
    if ctx = nil then goto _err ;
    BN_CTX_start(ctx);
    r0 := BN_CTX_get(ctx);
    g := BN_CTX_get(ctx);
    q := BN_CTX_get(ctx);
    p := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    test := BN_CTX_get(ctx);
    if test = nil then goto _err ;
    if  0>= BN_lshift(test, BN_value_one, L - 1)   then
        goto _err ;
    if  not verify then
    begin
        { For generation: p and q must both be nil or NON-nil }
        if (params.p <> nil) <> (params.q <> nil) then
        begin
            res^ := FFC_CHECK_INVALID_PQ;
            goto _err ;
        end;
    end
    else
    begin
        if (flags and FFC_PARAM_FLAG_VALIDATE_PQ)  <> 0 then
        begin
            { Validation of p,q requires seed and counter to be valid }
            if (seed_in = nil)  or  (params.pcounter < 0) then
            begin
                res^ := FFC_CHECK_MISSING_SEED_OR_COUNTER;
                goto _err ;
            end;
        end;
        if (flags and FFC_PARAM_FLAG_VALIDATE_G ) <> 0 then
        begin
            { validation of g also requires g to be set }
            if params.g = nil then
            begin
                res^ := FFC_CHECK_INVALID_G;
                goto _err ;
            end;
        end;
    end;
    if (params.p <> nil)  and  ((flags and FFC_PARAM_FLAG_VALIDATE_PQ) = 0)  then
    begin
        { p and q already exists so only generate g }
        p := params.p;
        q := params.q;
        goto _g_only ;
        { otherwise fall thru to validate p and q }
    end;
    use_random_seed := int(seed_in = nil);
    while true do
    begin
        if  0>= generate_q_fips186_2(ctx, q, @md, @buf, @seed, qsize,
                                  use_random_seed, @m, res, cb)  then
            goto _err ;
        if  0>= BN_GENCB_call(cb, 2, 0 )then
            goto _err ;
        if  0>= BN_GENCB_call(cb, 3, 0)  then
            goto _err ;
        { step 6 }
        n := (L - 1) div 160;
        counter := 4 * L - 1; { Was 4096 }
        { Validation requires the counter to be supplied }
        if verify then
        begin
            if params.pcounter > counter then
            begin
                res^ := FFC_CHECK_INVALID_COUNTER;
                goto _err ;
            end;
            counter := params.pcounter;
        end;
        rv := generate_p(ctx, md, counter, n, @buf, qsize, q, p, L, cb,
                        @pcounter, res);
        if rv > 0 then break; { found it }
        if rv = -1 then goto _err ;
        { This is what the old code did - probably not a good idea! }
        use_random_seed := 1;
    end;
    if  0>= BN_GENCB_call(cb, 2, 1)  then
        goto _err ;
    if verify then begin
        if pcounter <> counter then
        begin
            res^ := FFC_CHECK_COUNTER_MISMATCH;
            goto _err ;
        end;
        if BN_cmp(p, params.p)  <> 0 then
        begin
            res^ := FFC_CHECK_P_MISMATCH;
            goto _err ;
        end;
    end;
    { If validating p and q only then skip the g validation test }
    if (flags and FFC_PARAM_FLAG_VALIDATE_PQG) = FFC_PARAM_FLAG_VALIDATE_PQ then
        goto _pass ;
_g_only:
    mont := BN_MONT_CTX_new( );
    if mont = nil then
        goto _err ;
    if  0>= BN_MONT_CTX_set(mont, p, ctx)  then
        goto _err ;
    if  not verify then
    begin
        { We now need to generate g }
        { set test = p - 1 }
        if  0>= BN_sub(test, p, BN_value_one) then
            goto _err ;
        { Set r0 = (p - 1) / q }
        if  0>= BN_div(r0, nil, test, q, ctx) then
            goto _err ;
        if  0>= generate_unverifiable_g(ctx, mont, g, tmp, p, r0, test, @hret )then
            goto _err ;
    end
    else
    if ((flags and FFC_PARAM_FLAG_VALIDATE_G) <> 0)
                and (0>= ossl_ffc_params_validate_unverifiable_g(ctx, mont, p, q,
                                   params.g, tmp,
                                   res)) then
    begin
        goto _err ;
    end;
    if  0>= BN_GENCB_call(cb, 3, 1) then
        goto _err ;
    if  not verify then
    begin
        if p <> params.p then
        begin
            BN_free(params.p);
            params.p := BN_dup(p);
        end;
        if q <> params.q then
        begin
            BN_free(params.q);
            params.q := BN_dup(q);
        end;
        if g <> params.g then
        begin
            BN_free(params.g);
            params.g := BN_dup(g);
        end;
        if (params.p = nil)  or  (params.q = nil)  or  (params.g = nil) then
           goto _err ;
        if  0>= ossl_ffc_params_set_validate_params(params, @seed, qsize, pcounter ) then
            goto _err ;
        params.h := hret;
    end;
_pass:
    if (flags and FFC_PARAM_FLAG_VALIDATE_G) <> 0 then
        ok := FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
    else
        ok := FFC_PARAM_RET_STATUS_SUCCESS;
_err:
    if ctx <> nil then
       BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
    EVP_MD_free(md);
    Result := ok;
end;



function ossl_ffc_params_FIPS186_2_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; &type : integer; res : PInteger; cb : PBN_GENCB):integer;
var
  L, N : size_t;
begin
    if (params = nil)  or  (params.p = nil)  or  (params.q = nil) then
    begin
        res^ := FFC_CHECK_INVALID_PQ;
        Exit(FFC_PARAM_RET_STATUS_FAILED);
    end;
    { A.1.1.3 Step (1..2) : L = len(p), N = len(q) }
    L := BN_num_bits(params.p);
    N := BN_num_bits(params.q);
    Exit(ossl_ffc_params_FIPS186_2_gen_verify(libctx, PFFC_PARAMS(params),
                                                FFC_PARAM_MODE_VERIFY, &type,
                                                L, N, res, cb));
end;

function ossl_ffc_params_simple_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; paramstype : integer; res : PInteger):integer;
var
  ret,
  tmpres    : integer;

    tmpparams : TFFC_PARAMS;
begin
    tmpres := 0;
    FillChar(tmpparams, SizeOf(TFFC_PARAMS), 0);

    if params = nil then Exit(0);
    if res = nil then
       res := @tmpres;
    if  0>= ossl_ffc_params_copy(@tmpparams, params ) then
        Exit(0);
    tmpparams.flags := FFC_PARAM_FLAG_VALIDATE_G;
    tmpparams.gindex := FFC_UNVERIFIABLE_GINDEX;
{$IFNDEF FIPS_MODULE}
    if (params.flags and FFC_PARAM_FLAG_VALIDATE_LEGACY)>0 then
       ret := ossl_ffc_params_FIPS186_2_validate(libctx, @tmpparams, paramstype,
                                                 res, nil)
    else
{$ENDIF}
        ret := ossl_ffc_params_FIPS186_4_validate(libctx, @tmpparams, paramstype,
                                                 res, nil);
{$IFNDEF OPENSSL_NO_DH}
    if (ret = FFC_PARAM_RET_STATUS_FAILED)
         and  ( (res^ and FFC_ERROR_NOT_SUITABLE_GENERATOR) <> 0)  then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_NOT_SUITABLE_GENERATOR);
    end;
{$ENDIF}
    ossl_ffc_params_cleanup(@tmpparams);
    Result := Int(ret <> FFC_PARAM_RET_STATUS_FAILED);
end;

function ossl_ffc_params_validate_unverifiable_g(ctx : PBN_CTX; mont : PBN_MONT_CTX;const p, q, g : PBIGNUM; tmp : PBIGNUM; ret : PInteger):integer;
begin
    {
     * A.2.2 Step (1) AND
     * A.2.4 Step (2)
     * Verify that 2 <= g <= (p - 1)
     }
    if (BN_cmp(g, BN_value_one) <= 0 ) or  (BN_cmp(g, p) >= 0)  then
    begin
        ret^  := ret^  or FFC_ERROR_NOT_SUITABLE_GENERATOR;
        Exit(0);
    end;
    {
     * A.2.2 Step (2) AND
     * A.2.4 Step (3)
     * Check g^q mod p = 1
     }
    if  0>= BN_mod_exp_mont(tmp, g, q, p, ctx, mont) then
        Exit(0);
    if BN_cmp(tmp, BN_value_one) <> 0  then
    begin
        ret^  := ret^  or FFC_ERROR_NOT_SUITABLE_GENERATOR;
        Exit(0);
    end;
    Result := 1;
end;


end.
