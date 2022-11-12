unit openssl3.crypto.dh.dh_gen;

interface
uses OpenSSL.Api;

function ossl_dh_get_named_group_uid_from_size( pbits : integer):integer;
function ossl_dh_generate_ffc_parameters( dh : PDH; &type, pbits, qbits : integer; cb : PBN_GENCB):integer;
function DH_generate_parameters_ex( ret : PDH; prime_len, generator : integer; cb : PBN_GENCB):integer;
function dh_builtin_genparams( ret : PDH; prime_len, generator : integer; cb : PBN_GENCB):integer;

implementation
uses openssl3.crypto.ffc.ffc_params_generate, OpenSSL3.Err,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_prime;






function dh_builtin_genparams( ret : PDH; prime_len, generator : integer; cb : PBN_GENCB):integer;
var
  t1, t2 : PBIGNUM;
  g, ok : integer;
  ctx : PBN_CTX;
  label _err;
begin
    ok := -1;
    ctx := nil;
    if prime_len > OPENSSL_DH_MAX_MODULUS_BITS then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        Exit(0);
    end;
    if prime_len < DH_MIN_MODULUS_BITS then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        Exit(0);
    end;
    ctx := BN_CTX_new();
    if ctx = nil then
       goto _err ;
    BN_CTX_start(ctx);
    t1 := BN_CTX_get(ctx);
    t2 := BN_CTX_get(ctx);
    if t2 = nil then
       goto _err ;
    { Make sure 'ret' has the necessary elements }
    if (ret.params.p = nil)  then
    begin
        ret.params.p := BN_new();
        if ret.params.p = nil then
          goto _err ;
    end;
    if (ret.params.g = nil)  then
    begin
        ret.params.g := BN_new();
        if (ret.params.g = nil)  then
           goto _err ;
    end;
    if generator <= 1 then
    begin
        ERR_raise(ERR_LIB_DH, DH_R_BAD_GENERATOR);
        goto _err ;
    end;
    if generator = DH_GENERATOR_2 then
    begin
        if 0>= BN_set_word(t1, 24) then
            goto _err ;
        if 0>= BN_set_word(t2, 23 )  then
            goto _err ;
        g := 2;
    end
    else
    if (generator = DH_GENERATOR_5) then
    begin
        if 0>= BN_set_word(t1, 60 )  then
            goto _err ;
        if 0>= BN_set_word(t2, 59 )  then
            goto _err ;
        g := 5;
    end
    else
    begin
        {
         * in the general case, don't worry if 'generator' is a generator or
         * not: since we are using safe primes, it will generate either an
         * order-q or an order-2q group, which both is OK
         }
        if 0>= BN_set_word(t1, 12 )  then
            goto _err ;
        if 0>= BN_set_word(t2, 11 )  then
            goto _err ;
        g := generator;
    end;
    if 0>= BN_generate_prime_ex(ret.params.p, prime_len, 1, t1, t2, cb )  then
        goto _err ;
    if 0>= BN_GENCB_call(cb, 3, 0 )  then
        goto _err ;
    if 0>= BN_set_word(ret.params.g, g )  then
        goto _err ;
    Inc(ret.dirty_cnt);
    ok := 1;
 _err:
    if ok = -1 then
    begin
        ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);
        ok := 0;
    end;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    Result := ok;
end;


function DH_generate_parameters_ex( ret : PDH; prime_len, generator : integer; cb : PBN_GENCB):integer;
begin
{$IFDEF FIPS_MODULE}
    if generator <> 2 then
       Exit(0);
    Exit(dh_gen_named_group(ret.libctx, ret, prime_len));
{$ELSE}
   if Assigned(ret.meth.generate_params) then
      Exit(ret.meth.generate_params(ret, prime_len, generator, cb));
    Exit(dh_builtin_genparams(ret, prime_len, generator, cb));
{$endif} { FIPS_MODULE }
end;

function ossl_dh_generate_ffc_parameters( dh : PDH; &type, pbits, qbits : integer; cb : PBN_GENCB):integer;
var
  ret, res : integer;
begin
{$IFNDEF FIPS_MODULE}
    if &type = DH_PARAMGEN_TYPE_FIPS_186_2 then
       ret := ossl_ffc_params_FIPS186_2_generate(dh.libctx, @dh.params,
                                                 FFC_PARAM_TYPE_DH,
                                                 pbits, qbits, @res, cb)
    else
{$ENDIF}
        ret := ossl_ffc_params_FIPS186_4_generate(dh.libctx, @dh.params,
                                                 FFC_PARAM_TYPE_DH,
                                                 pbits, qbits, @res, cb);
    if ret > 0 then
       Inc(dh.dirty_cnt);
    Result := ret;
end;

function ossl_dh_get_named_group_uid_from_size( pbits : integer):integer;
var
  nid : integer;
begin
    {
     * Just choose an approved safe prime group.
     * The alternative to this is to generate FIPS186-4 domain parameters i.e.
     * return dh_generate_ffc_parameters(ret, prime_len, 0, nil, cb);
     * As the FIPS186-4 generated params are for backwards compatibility,
     * the safe prime group should be used as the default.
     }
    case pbits of
    2048:
        nid := NID_ffdhe2048;

    3072:
        nid := NID_ffdhe3072;

    4096:
        nid := NID_ffdhe4096;

    6144:
        nid := NID_ffdhe6144;

    8192:
        nid := NID_ffdhe8192;

    { unsupported prime_len }
    else
        Exit(NID_undef);
    end;
    Result := nid;
end;

end.
