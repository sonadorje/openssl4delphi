unit openssl3.crypto.ffc.ffc_params_generate;

interface
uses OpenSSL.Api;

function ossl_ffc_params_FIPS186_2_generate( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
function ossl_ffc_params_FIPS186_2_gen_verify( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; mode, &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
function default_mdname( N : size_t):PUTF8Char;
function generate_q_fips186_2(ctx : PBN_CTX; q : PBIGNUM;const evpmd : PEVP_MD; buf, seed : PByte; qsize : size_t; generate_seed : integer; retm, res : PInteger; cb : PBN_GENCB):integer;
function generate_p(ctx : PBN_CTX;const evpmd : PEVP_MD; max_counter, n : integer; buf : PByte; buf_len : size_t;const q : PBIGNUM; p : PBIGNUM; L : integer; cb : PBN_GENCB; counter, res : PInteger):integer;
function generate_unverifiable_g(ctx : PBN_CTX; mont : PBN_MONT_CTX; g, hbn : PBIGNUM;const p, e, pm1 : PBIGNUM; hret : PInteger):integer;
 function ossl_ffc_params_FIPS186_4_generate( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
function ossl_ffc_params_FIPS186_4_gen_verify( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; mode, &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
function ffc_validate_LN( L, N : size_t; &type, verify : integer):integer;
function generate_q_fips186_4(ctx : PBN_CTX; q : PBIGNUM;const evpmd : PEVP_MD; qsize : integer; seed : PByte; seedlen : size_t; generate_seed : integer; retm, res : PInteger; cb : PBN_GENCB):integer;
function generate_canonical_g(ctx : PBN_CTX; mont : PBN_MONT_CTX;const evpmd : PEVP_MD; g, tmp : PBIGNUM;const p, e : PBIGNUM; gindex : integer; seed : PByte; seedlen : size_t):integer;
function ossl_ffc_params_validate_unverifiable_g(ctx : PBN_CTX; mont : PBN_MONT_CTX;const p, q, g : PBIGNUM; tmp : PBIGNUM; ret : PInteger):integer;
function ossl_ffc_params_simple_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; paramstype : integer; res : PInteger):integer;
function ossl_ffc_params_FIPS186_2_validate(libctx : POSSL_LIB_CTX;const params : PFFC_PARAMS; &type : integer; res : PInteger; cb : PBN_GENCB):integer;


implementation
uses
  openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.param_build_set,
  openssl3.crypto.ffc.ffc_dh, openssl3.crypto.evp.digest, openssl3.crypto.evp.evp_lib
  ,openssl3.crypto.bn.bn_ctx, openssl3.crypto.rand.rand_lib,
  openssl3.crypto.bn.bn_prime,  openssl3.crypto.bn.bn_exp,
  openssl3.crypto.bn.bn_div,
  openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_add, openssl3.crypto.bn.bn_word,
  openssl3.crypto.ffc.ffc_params_validate, openssl3.crypto.ffc.ffc_params,
  OpenSSL3.Err, openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_mont;

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
function generate_canonical_g(ctx : PBN_CTX; mont : PBN_MONT_CTX;const evpmd : PEVP_MD; g, tmp : PBIGNUM;const p, e : PBIGNUM; gindex : integer; seed : PByte; seedlen : size_t):integer;
const // 1d arrays
  ggen : array[0..3] of Byte = (
    $67, $67, $65, $6e );
var
  ret, counter : integer;

  md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  mctx : PEVP_MD_CTX;

  mdsize : integer;
begin
    ret := 0;
    counter := 1;
    mctx := nil;
    mdsize := EVP_MD_get_size(evpmd);
    if mdsize <= 0 then Exit(0);
    mctx := EVP_MD_CTX_new();
    if mctx = nil then Exit(0);
   {
    * A.2.3 Step (4) and (5)
    * A.2.4 Step (6) and (7)
    * counter = 0; counter += 1
    }
    counter := 1;
    while ( counter <= $FFFF) do
    begin
        {
         * A.2.3 Step (7) and (8) and (9)
         * A.2.4 Step (9) and (10) and (11)
         * W = Hash(seed  or  'ggen'  or  index  or  counter)
         * g = W^e % p
         }

        md[0] := Byte(gindex and $ff);
        md[1] := Byte((counter  shr  8) and $ff);
        md[2] := Byte(counter and $ff);
        if (0>= EVP_DigestInit_ex(mctx, evpmd, nil))  or
           (0>= EVP_DigestUpdate(mctx, seed, seedlen))
                 or  (0>= EVP_DigestUpdate(mctx, @ggen, sizeof(ggen)) )
                 or  (0>= EVP_DigestUpdate(mctx, @md, 3))
                 or  (0>= EVP_DigestFinal_ex(mctx, @md, nil))
                 or  (BN_bin2bn(@md, mdsize, tmp) = nil)
                 or  (0>= BN_mod_exp_mont(g, tmp, e, p, ctx, mont))  then
                    break; { exit on failure }
        {
         * A.2.3 Step (10)
         * A.2.4 Step (12)
         * Found a value for g if (g >= 2)
         }
        if BN_cmp(g, BN_value_one) > 0 then
        begin
            ret := 1;
            break; { found g }
        end;
        Inc(counter);
    end;
    EVP_MD_CTX_free(mctx);
    Result := ret;
end;




function generate_q_fips186_4(ctx : PBN_CTX; q : PBIGNUM;const evpmd : PEVP_MD; qsize : integer; seed : PByte; seedlen : size_t; generate_seed : integer; retm, res : PInteger; cb : PBN_GENCB):integer;
var
  ret, m, r : integer;

  md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  mdsize : integer;

  pmd : PByte;

  libctx : POSSL_LIB_CTX;
  label _err;
begin
{$POINTERMATH ON}
    ret := 0;
    m := retm^;
    mdsize := EVP_MD_get_size(evpmd);
    libctx := ossl_bn_get_libctx(ctx);
    { find q }
    while True do
    begin
        if  0>= BN_GENCB_call(cb, 0, PostInc(m)) then
            goto _err ;
        { A.1.1.2 Step (5) : generate seed with size seed_len }
        if (generate_seed>0)
                 and  (RAND_bytes_ex(libctx, seed, seedlen, 0) < 0) then
            goto _err ;
        {
         * A.1.1.2 Step (6) AND
         * A.1.1.3 Step (7)
         * U = Hash(seed) % (2^(N-1))
         }
        if  0>= EVP_Digest(seed, seedlen, @md, nil, evpmd, nil) then
            goto _err ;
        { Take least significant bits of md }
        if mdsize > qsize then
           pmd := PByte(@md) + mdsize - qsize
        else
           pmd := @md;
        if mdsize < qsize then
           memset(PByte(@md) + mdsize, 0, qsize - mdsize);
        {
         * A.1.1.2 Step (7) AND
         * A.1.1.3 Step (8)
         * q = U + 2^(N-1) + (1 - U %2) (This sets top and bottom bits)
         }
        pmd[0]  := pmd[0]  or $80;
        pmd[qsize-1]  := pmd[qsize-1]  or $01;
        if not Assigned(BN_bin2bn(pmd, qsize, q )) then
            goto _err ;
        {
         * A.1.1.2 Step (8) AND
         * A.1.1.3 Step (9)
         * Test if q is prime
         }
        r := BN_check_prime(q, ctx, cb);
        if r > 0 then
        begin
            ret := 1;
            goto _err ;
        end;
        {
         * A.1.1.3 Step (9) : If the provided seed didn't produce a prime q
         * return an error.
         }
        if  0>= generate_seed then
        begin
            res^  := res^  or FFC_CHECK_Q_NOT_PRIME;
            goto _err ;
        end;
        if r <> 0 then goto _err ;
        { A.1.1.2 Step (9) : if q is not prime, try another q }
    end;
_err:
    retm^ := m;
    Result := ret;
{$POINTERMATH OFF}
end;



function ffc_validate_LN( L, N : size_t; &type, verify : integer):integer;
begin
    if &type = FFC_PARAM_TYPE_DH then
    begin
        { Allow legacy 1024/160 in non fips mode }
        if (L = 1024)  and  (N = 160) then
            Exit(80);
        { Valid DH L,N parameters from SP800-56Ar3 5.5.1 Table 1 }
        if (L = 2048)  and  ( (N = 224)  or  (N = 256) )  then
            Exit(112);
{$IFNDEF OPENSSL_NO_DH}
        ERR_raise(ERR_LIB_DH, DH_R_BAD_FFC_PARAMETERS);
{$ENDIF}
    end
    else
    if (&type = FFC_PARAM_TYPE_DSA) then
    begin
        if (L >= 3072)  and  (N >= 256) then Exit(128);
        if (L >= 2048)  and  (N >= 224) then Exit(112);
        if (L >= 1024)  and  (N >= 160) then Exit(80);
{$IFNDEF OPENSSL_NO_DSA}
        ERR_raise(ERR_LIB_DSA, DSA_R_BAD_FFC_PARAMETERS);
{$ENDIF}
    end;
    Result := 0;
end;



function ossl_ffc_params_FIPS186_4_gen_verify( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; mode, &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
var
    ok          : integer;
    seed, seed_tmp        : PByte;

  mdsize,
  counter,
  pcounter,r     : integer;
  seedlen     : size_t;
  tmp,
  pm1,
  e,
  test,
  g,q,p           : PBIGNUM;
  mont        : PBN_MONT_CTX;
  n0, m, qsize, hret,
  canonical_g : integer;
  ctx         : PBN_CTX;
  mctx        : PEVP_MD_CTX;
  md          : PEVP_MD;
  verify      : Boolean;
  flags       : uint32;
  def_name    : PUTF8Char;
  label _err, _pass, _g_only;
begin
    ok := FFC_PARAM_RET_STATUS_FAILED;
    seed := nil; seed_tmp := nil;
    counter := 0; pcounter := 0; r := 0;
    seedlen := 0;
    g := nil; q := nil; p := nil;
    mont := nil;
    n0 := 0; m := 0;
    canonical_g := 0; hret := 0;
    ctx := nil;
    mctx := nil;
    md := nil;
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
    mdsize := EVP_MD_get_size(md);
    if mdsize <= 0 then goto _err ;
    if N = 0 then
       N := mdsize * 8;
    qsize := N  shr  3;
    {
     * A.1.1.2 Step (1) AND
     * A.1.1.3 Step (3)
     * Check that the L,N pair is an acceptable pair.
     }
    if (L <= N)  or   (0>= ffc_validate_LN(L, N, &type, Int(verify) ))then
    begin
        res^ := FFC_CHECK_BAD_LN_PAIR;
        goto _err ;
    end;
    mctx := EVP_MD_CTX_new();
    if mctx = nil then goto _err ;
    ctx := BN_CTX_new_ex(libctx);
    if ctx = nil then
        goto _err ;
    BN_CTX_start(ctx);
    g := BN_CTX_get(ctx);
    pm1 := BN_CTX_get(ctx);
    e := BN_CTX_get(ctx);
    test := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    if tmp = nil then goto _err ;
    seedlen := params.seedlen;
    if seedlen = 0 then
       seedlen := size_t(mdsize);
    { If the seed was passed in - use this value as the seed }
    if params.seed <> nil then
       seed := params.seed;
    if  not verify then
    begin
        { For generation: p and q must both be nil or NON-nil }
        if (params.p = nil) <> (params.q = nil) then
        begin
            res^ := FFC_CHECK_INVALID_PQ;
            goto _err ;
        end;
    end
    else
    begin
        { Validation of p,q requires seed and counter to be valid }
        if (flags and FFC_PARAM_FLAG_VALIDATE_PQ ) <> 0 then
        begin
            if (seed = nil)  or  (params.pcounter < 0) then
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
    {
     * If p and q are passed in and
     *   validate_flags = 0 then skip the generation of PQ.
     *   validate_flags = VALIDATE_G then also skip the validation of PQ.
     }
    if (params.p <> nil)  and  ((flags and FFC_PARAM_FLAG_VALIDATE_PQ) = 0) then
    begin
        { p and q already exists so only generate g }
        p := params.p;
        q := params.q;
        goto _g_only ;
        { otherwise fall thru to validate p and q }
    end;
    { p and q will be used for generation and validation }
    p := BN_CTX_get(ctx);
    q := BN_CTX_get(ctx);
    if q = nil then goto _err ;
    {
     * A.1.1.2 Step (2) AND
     * A.1.1.3 Step (6)
     * Return invalid if seedlen  < N
     }
    if seedlen * 8 < N then
    begin
        res^ := FFC_CHECK_INVALID_SEED_SIZE;
        goto _err ;
    end;
    seed_tmp := OPENSSL_malloc(seedlen);
    if seed_tmp = nil then goto _err ;
    if seed = nil then
    begin
        { Validation requires the seed to be supplied }
        if verify then
        begin
            res^ := FFC_CHECK_MISSING_SEED_OR_COUNTER;
            goto _err ;
        end;
        { if the seed is not supplied then alloc a seed buffer }
        seed := OPENSSL_malloc(seedlen);
        if seed = nil then goto _err ;
    end;
    { A.1.1.2 Step (11): max loop count = 4L - 1 }
    counter := 4 * L - 1;
    { Validation requires the counter to be supplied }
    if verify then
    begin
        { A.1.1.3 Step (4) : if (counter > (4L -1)) return INVALID }
        if params.pcounter > counter then  begin
            res^ := FFC_CHECK_INVALID_COUNTER;
            goto _err ;
        end;
        counter := params.pcounter;
    end;
    {
     * A.1.1.2 Step (3) AND
     * A.1.1.3 Step (10)
     * n = floor(L / hash_outlen) - 1
     }
    n := (L - 1) div (mdsize  shl  3);
    { Calculate 2^(L-1): Used in step A.1.1.2 Step (11.3) }
    if  0>= BN_lshift(test, BN_value_one , L - 1)  then
        goto _err ;
    while True do
    begin
        if  0>= generate_q_fips186_4(ctx, q, md, qsize, seed, seedlen,
                                  Int(seed <> params.seed), @m, res, cb) then
            goto _err ;
        { A.1.1.3 Step (9): Verify that q matches the expected value }
        if (verify)  and  (BN_cmp(q, params.q) <> 0)  then
        begin
            res^ := FFC_CHECK_Q_MISMATCH;
            goto _err ;
        end;
        if  0>= BN_GENCB_call(cb, 2, 0) then
            goto _err ;
        if  0>= BN_GENCB_call(cb, 3, 0 ) then
            goto _err ;
        memcpy(seed_tmp, seed, seedlen);
        r := generate_p(ctx, md, counter, n, seed_tmp, seedlen, q, p, L,
                       cb, @pcounter, res);
        if r > 0 then break; { found p }
        if r < 0 then goto _err ;
        {
         * A.1.1.3 Step (14):
         * If we get here we failed to get a p for the given seed. If the
         * seed is not random then it needs to fail (as it will always fail).
         }
        if seed = params.seed then begin
            res^ := FFC_CHECK_P_NOT_PRIME;
            goto _err ;
        end;
    end;
    if  0>= BN_GENCB_call(cb, 2, 1)  then
        goto _err ;
    {
     * Gets here if we found p.
     * A.1.1.3 Step (14): return error if i <> counter OR computed_p <> known_p.
     }
    if (verify)  and  ( (pcounter <> counter)  or  (BN_cmp(p, params.p) <> 0) ) then
        goto _err ;
    { If validating p and q only then skip the g validation test }
    if (flags and FFC_PARAM_FLAG_VALIDATE_PQG ) = FFC_PARAM_FLAG_VALIDATE_PQ then
        goto _pass ;
_g_only:
    mont := BN_MONT_CTX_new( );
    if mont = nil then
        goto _err ;
    if  0>= BN_MONT_CTX_set(mont, p, ctx) then
        goto _err ;
    if ( (flags and FFC_PARAM_FLAG_VALIDATE_G ) <> 0 )
         and (0>= ossl_ffc_params_validate_unverifiable_g(ctx, mont, p, q, params.g,
                                                    tmp, res))then
        goto _err ;
    {
     * A.2.1 Step (1) AND
     * A.2.3 Step (3) AND
     * A.2.4 Step (5)
     * e = (p - 1) / q (i.e- Cofactor 'e' is given by p = q * e + 1)
     }
    if  (0>= BN_sub(pm1, p, BN_value_one) )  and  (BN_div(e, nil, pm1, q, ctx)>0) then
        goto _err ;
    { Canonical g requires a seed and index to be set }
    if (seed <> nil)  and  (params.gindex <> FFC_UNVERIFIABLE_GINDEX) then
    begin
        canonical_g := 1;
        if  0>= generate_canonical_g(ctx, mont, md, g, tmp, p, e,
                                  params.gindex, seed, seedlen )then
        begin
            res^ := FFC_CHECK_INVALID_G;
            goto _err ;
        end;
        { A.2.4 Step (13): Return valid if computed_g = g }
        if (verify)  and  (BN_cmp(g, params.g) <> 0)  then
        begin
            res^ := FFC_CHECK_G_MISMATCH;
            goto _err ;
        end;
    end
    else
    if ( not verify) then
    begin
        if  0>= generate_unverifiable_g(ctx, mont, g, tmp, p, e, pm1, @hret) then
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
        if  0>= ossl_ffc_params_set_validate_params(params, seed, seedlen,
                                                 pcounter)  then
            goto _err ;
        params.h := hret;
    end;
_pass:
    if ((flags and FFC_PARAM_FLAG_VALIDATE_G)  <> 0)  and  (canonical_g = 0) then
        { Return for the case where g is partially valid }
        ok := FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
    else
        ok := FFC_PARAM_RET_STATUS_SUCCESS;
_err:
    if seed <> params.seed then
         OPENSSL_free(Pointer(seed));
    OPENSSL_free(Pointer(seed_tmp));
    if ctx <> nil then BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont);
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
    Result := ok;
end;




function ossl_ffc_params_FIPS186_4_generate( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
begin
    Exit(ossl_ffc_params_FIPS186_4_gen_verify(libctx, params,
                                                FFC_PARAM_MODE_GENERATE,
                                                &type, L, N, res, cb));
end;




function generate_unverifiable_g(ctx : PBN_CTX; mont : PBN_MONT_CTX; g, hbn : PBIGNUM;const p, e, pm1 : PBIGNUM; hret : PInteger):integer;
var
  h : integer;
begin
    h := 2;
    { Step (2): choose h (where 1 < h)}
    if  0>= BN_set_word(hbn, h)  then
        Exit(0);
    while True do
    begin
        { Step (3): g = h^e % p }
        if  0>= BN_mod_exp_mont(g, hbn, e, p, ctx, mont)  then
            Exit(0);
        { Step (4): Finish if g > 1 }
        if BN_cmp(g, BN_value_one) > 0 then
            break;
        { Step (2) Choose any h in the range 1 < h < (p-1) }
        if  (0>= BN_add_word(hbn, 1)) or ( BN_cmp(hbn, pm1) >= 0)   then
            Exit(0);
        Inc(h);
    end;
    hret^ := h;
    Result := 1;
end;



function generate_p(ctx : PBN_CTX;const evpmd : PEVP_MD; max_counter, n : integer; buf : PByte; buf_len : size_t;const q : PBIGNUM; p : PBIGNUM; L : integer; cb : PBN_GENCB; counter, res : PInteger):integer;
var
  ret, i, j, k, r : integer;

  md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  mdsize : integer;

  W, X, tmp, c, test : PBIGNUM;
  label _err;
begin
    ret := -1;
    BN_CTX_start(ctx);
    W := BN_CTX_get(ctx);
    X := BN_CTX_get(ctx);
    c := BN_CTX_get(ctx);
    test := BN_CTX_get(ctx);
    tmp := BN_CTX_get(ctx);
    if tmp = nil then goto _err ;
    if  0>= BN_lshift(test, BN_value_one() , L - 1)   then
        goto _err ;
    mdsize := EVP_MD_get_size(evpmd);
    if mdsize <= 0 then goto _err ;
    { A.1.1.2 Step (10) AND
     * A.1.1.2 Step (12)
     * offset = 1 (this is handled below)
     }
    {
     * A.1.1.2 Step (11) AND
     * A.1.1.3 Step (13)
     }
    for i := 0 to max_counter do
    begin
        if (i <> 0)  and  (0>= BN_GENCB_call(cb, 0, i) ) then
            goto _err ;
        BN_zero(W);
        { seed_tmp buffer contains 'seed + offset - 1' }
        for j := 0 to n do
        begin
            { obtain 'seed + offset + j' by incrementing by 1: }
            k := int(buf_len) - 1;
            while ( k >= 0) do
            begin
                inc(buf[k]);
                if buf[k] <> 0 then break;
                Dec(k);
            end;
            {
             * A.1.1.2 Step (11.1) AND
             * A.1.1.3 Step (13.1)
             * tmp = V(j) = Hash((seed + offset + j) % 2^seedlen)
             }
            if (0>= EVP_Digest(buf, buf_len, @md, nil, evpmd, nil))  or
               (BN_bin2bn(@md, mdsize, tmp) = nil)
                    {
                     * A.1.1.2 Step (11.2)
                     * A.1.1.3 Step (13.2)
                     * W += V(j) * 2^(outlen * j)
                     }
                     or   (0>= BN_lshift(tmp, tmp, (mdsize  shl  3) * j))
                     or   (0>= BN_add(W, W, tmp))  then
                goto _err ;
        end;
        {
         * A.1.1.2 Step (11.3) AND
         * A.1.1.3 Step (13.3)
         * X = W + 2^(L-1) where W < 2^(L-1)
         }
        if (0>=BN_mask_bits(W, L - 1))  or  (nil = BN_copy(X, W))
                 or  (0>= BN_add(X, X, test))
                {
                 * A.1.1.2 Step (11.4) AND
                 * A.1.1.3 Step (13.4)
                 * c = X mod 2q
                 }
                 or  (0>=BN_lshift1(tmp, q))
                 or  (0>=BN_mod(c, X, tmp, ctx))
                {
                 * A.1.1.2 Step (11.5) AND
                 * A.1.1.3 Step (13.5)
                 * p = X - (c - 1)
                 }
                 or  (0>=BN_sub(tmp, c, BN_value_one))
                 or  (0>=BN_sub(p, X, tmp)) then
            goto _err ;
        {
         * A.1.1.2 Step (11.6) AND
         * A.1.1.3 Step (13.6)
         * if (p < 2 ^ (L-1)) continue
         * This makes sure the top bit is set.
         }
        if BN_cmp(p, test)  >= 0then
        begin
            {
             * A.1.1.2 Step (11.7) AND
             * A.1.1.3 Step (13.7)
             * Test if p is prime
             * (This also makes sure the bottom bit is set)
             }
            r := BN_check_prime(p, ctx, cb);
            { A.1.1.2 Step (11.8) : Return if p is prime }
            if r > 0 then
            begin
                counter^ := i;
                ret := 1;   { return success }
                goto _err ;
            end;
            if r <> 0 then goto _err ;
        end;
        { Step (11.9) : offset = offset + n + 1 is done auto-magically }
    end;
    { No prime P found }
    ret := 0;
    res^  := res^  or FFC_CHECK_P_NOT_PRIME;
_err:
    BN_CTX_end(ctx);
    Result := ret;
end;



function generate_q_fips186_2(ctx : PBN_CTX; q : PBIGNUM;const evpmd : PEVP_MD; buf, seed : PByte; qsize : size_t; generate_seed : integer; retm, res : PInteger; cb : PBN_GENCB):integer;
var
  buf2, md : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  i, r, ret, m : integer;

  libctx : POSSL_LIB_CTX;
  label _err;
begin
    ret := 0; m := retm^;
    libctx := ossl_bn_get_libctx(ctx);
    { find q }
    while True do
    begin
        { step 1 }
        if  0>= BN_GENCB_call(cb, 0, PostInc(m))  then
            goto _err ;
        if (generate_seed  and  RAND_bytes_ex(libctx, seed, qsize, 0 )) <= 0 then
            goto _err ;
        memcpy(buf, seed, qsize);
        memcpy(@buf2, seed, qsize);
        { precompute 'SEED + 1' for step 7: }
        i := int(qsize) - 1;
        while ( i >= 0) do
        begin
            Inc(buf[i]);
            if buf[i] <> 0 then break;
            Dec(i);
        end;
        { step 2 }
        if 0>= EVP_Digest(seed, qsize, @md, nil, evpmd, nil ) then
            goto _err ;
        if 0>= EVP_Digest(buf, qsize, @buf2, nil, evpmd, nil ) then
            goto _err ;
        for i := 0 to int(qsize)-1 do
            md[i]  := md[i] xor (buf2[i]);
        { step 3 }
        md[0]  := md[0]  or $80;
        md[qsize - 1]  := md[qsize - 1]  or $01;
        if  not Assigned(BN_bin2bn(@md, int(qsize), q))  then
            goto _err ;
        { step 4 }
        r := BN_check_prime(q, ctx, cb);
        if r > 0 then
        begin
            { Found a prime }
            ret := 1;
            goto _err ;
        end;
        if r <> 0 then goto _err ; { Exit if error }
        { Try another iteration if it wasn't prime - was in old code.. }
        generate_seed := 1;
    end;
_err:
    retm^ := m;
    Result := ret;
end;




function default_mdname( N : size_t):PUTF8Char;
begin
    if N = 160 then Exit('SHA1')
    else
    if (N = 224) then
        Exit('SHA-224')
    else
    if (N = 256) then
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
  pcounter, use_random_seed,
  rv       : integer;
  ctx      : PBN_CTX;
  hret     : integer;
  seed_in  : PByte;
  seed_len : size_t;
  verify   : Boolean;
  flags    : uint32;
  def_name : PUTF8Char;
  label _err, _g_only, _pass;
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
    if md = nil then
       goto _err ;
    if N = 0 then
       N := EVP_MD_get_size(md) * 8;
    qsize := N  shr  3;
    {
     * The original spec allowed L = 512 + 64*j (j = 0.. 8)
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
     * says that 512 can be used for legacy verification.
     }
    if L < 512 then
    begin
        res^ := FFC_CHECK_BAD_LN_PAIR;
        goto _err ;
    end;
    if (qsize <> SHA_DIGEST_LENGTH)
         and  (qsize <> SHA224_DIGEST_LENGTH)
         and  (qsize <> SHA256_DIGEST_LENGTH) then
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
        if seed_len > qsize then
           seed_len := qsize;
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
    if  0>= BN_lshift(test, BN_value_one(), L - 1) then
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
        if (flags and FFC_PARAM_FLAG_VALIDATE_PQ ) <> 0 then
        begin
            { Validation of p,q requires seed and counter to be valid }
            if (seed_in = nil)  or  (params.pcounter < 0) then
            begin
                res^ := FFC_CHECK_MISSING_SEED_OR_COUNTER;
                goto _err ;
            end;
        end;
        if (flags and FFC_PARAM_FLAG_VALIDATE_G) <> 0 then
        begin
            { validation of g also requires g to be set }
            if params.g = nil then
            begin
                res^ := FFC_CHECK_INVALID_G;
                goto _err ;
            end;
        end;
    end;
    if (params.p <> nil)  and  ((flags and FFC_PARAM_FLAG_VALIDATE_PQ ) = 0) then
    begin
        { p and q already exists so only generate g }
        p := params.p;
        q := params.q;
        goto _g_only ;
        { otherwise fall thru to validate p and q }
    end;
    use_random_seed := int(seed_in = nil);
    while True do
    begin
        if  0>= generate_q_fips186_2(ctx, q, md, @buf, @seed, qsize,
                                  use_random_seed, @m, res, cb)  then
            goto _err ;
        if  0>= BN_GENCB_call(cb, 2, 0 ) then
            goto _err ;
        if  0>= BN_GENCB_call(cb, 3, 0 ) then
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
    if verify then
    begin
        if pcounter <> counter then
        begin
            res^ := FFC_CHECK_COUNTER_MISMATCH;
            goto _err ;
        end;
        if BN_cmp(p, params.p) <> 0 then
        begin
            res^ := FFC_CHECK_P_MISMATCH;
            goto _err ;
        end;
    end;
    { If validating p and q only then skip the g validation test }
    if (flags and FFC_PARAM_FLAG_VALIDATE_PQG ) = FFC_PARAM_FLAG_VALIDATE_PQ then
        goto _pass ;
_g_only:
    mont := BN_MONT_CTX_new( );
    if mont = nil then
        goto _err ;
    if  0>= BN_MONT_CTX_set(mont, p, ctx ) then
        goto _err ;
    if  not verify then
    begin
        { We now need to generate g }
        { set test = p - 1 }
        if  0>= BN_sub(test, p, BN_value_one) then
            goto _err ;
        { Set r0 = (p - 1) / q }
        if  0>= BN_div(r0, nil, test, q, ctx ) then
            goto _err ;
        if  0>= generate_unverifiable_g(ctx, mont, g, tmp, p, r0, test, @hret ) then
            goto _err ;
    end
    else
    if ( (flags and FFC_PARAM_FLAG_VALIDATE_G) <> 0)
                and   (0>= ossl_ffc_params_validate_unverifiable_g(ctx, mont, p, q,
                                                           params.g, tmp,
                                                           res)) then
    begin
        goto _err ;
    end;
    if  0>= BN_GENCB_call(cb, 3, 1 ) then
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
        if 0>= ossl_ffc_params_set_validate_params(params, @seed, qsize, pcounter ) then
           goto _err ;
        params.h := hret;
    end;
_pass:
    if (flags and FFC_PARAM_FLAG_VALIDATE_G ) <> 0 then
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

function ossl_ffc_params_FIPS186_2_generate( libctx : POSSL_LIB_CTX; params : PFFC_PARAMS; &type : integer; L, N : size_t; res : PInteger; cb : PBN_GENCB):integer;
begin
    if  0>= ossl_ffc_params_FIPS186_2_gen_verify(libctx, params,
                                              FFC_PARAM_MODE_GENERATE,
                                              &type, L, N, res, cb )then
        Exit(0);
    ossl_ffc_params_enable_flags(params, FFC_PARAM_FLAG_VALIDATE_LEGACY, 1);
    Result := 1;
end;


end.
