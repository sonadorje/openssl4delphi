unit openssl3.crypto.dsa.dsa_key;

interface
uses OpenSSL.Api, SysUtils;

{$ifdef FIPS_MODULE}
  const MIN_STRENGTH = 112;
{$else}
  const MIN_STRENGTH = 80;
{$endif}

 function ossl_dsa_generate_public_key(ctx : PBN_CTX;const dsa : PDSA; priv_key : PBIGNUM; pub_key : PBIGNUM):integer;
 function DSA_generate_key( dsa : PDSA):integer;
 function dsa_keygen( dsa : PDSA; pairwise_test : integer):integer;
 function dsa_keygen_pairwise_test( dsa : PDSA; cb : POSSL_CALLBACK; cbarg : Pointer):integer;


implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.ex_data,
     openssl3.crypto.ffc.ffc_backend, openssl3.crypto.bn.bn_lib,
     openssl3.crypto.ffc.ffc_key_generate, openssl3.providers.fips.self_test,
     openssl3.crypto.self_test_core, openssl3.crypto.dsa.dsa_sign,
     openssl3.crypto.bn.bn_exp,
     openssl3.crypto.bn.bn_ctx, openssl3.crypto.ffc.ffc_params_validate;






function dsa_keygen_pairwise_test( dsa : PDSA; cb : POSSL_CALLBACK; cbarg : Pointer):integer;
var
    ret      : integer;
    dgst     : array[0..15] of Byte;
    dgst_len : uint32;
    sig      : PDSA_SIG;
    st       : POSSL_SELF_TEST;
    label _err;
begin
    ret := 0;
    FillChar(dgst, 16, 0);
    dgst_len := uint32( sizeof(dgst));
    sig := nil;
    st := nil;
    st := OSSL_SELF_TEST_new(cb, cbarg);
    if st = nil then goto _err ;
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_PCT,
                           OSSL_SELF_TEST_DESC_PCT_DSA);
    sig := DSA_do_sign(@dgst, int (dgst_len), dsa);
    if sig = nil then goto _err ;
    OSSL_SELF_TEST_oncorrupt_byte(st, @dgst);
    if DSA_do_verify(@dgst, dgst_len, sig, dsa) <> 1  then
        goto _err ;
    ret := 1;
_err:
    OSSL_SELF_TEST_onend(st, ret);
    OSSL_SELF_TEST_free(st);
    DSA_SIG_free(sig);
    Result := ret;
end;




function dsa_keygen( dsa : PDSA; pairwise_test : integer):integer;
var
    ok       : integer;
    ctx      : PBN_CTX;
    pub_key,
    priv_key : PBIGNUM;
    cb       : POSSL_CALLBACK;
    cbarg    : Pointer;
    label _err;
begin
    ok := 0;
    ctx := nil;
    pub_key := nil;
    priv_key := nil;
    ctx := BN_CTX_new_ex(dsa.libctx);
    if ctx =  nil then
        goto _err ;
    if dsa.priv_key = nil then
    begin
        priv_key := BN_secure_new();
        if priv_key  = nil then
            goto _err ;
    end
    else
    begin
        priv_key := dsa.priv_key;
    end;
    { Do a partial check for invalid p, q, g }
    if 0>= ossl_ffc_params_simple_validate(dsa.libctx, @dsa.params,
                                         FFC_PARAM_TYPE_DSA, nil) then
        goto _err ;
    {
     * For FFC FIPS 186-4 keygen
     * security strength s = 112,
     * Max Private key size N = len(q)
     }
    if 0>= ossl_ffc_generate_private_key(ctx, @dsa.params,
                                       BN_num_bits(dsa.params.q ) ,
                                       MIN_STRENGTH, priv_key) then
        goto _err ;
    if dsa.pub_key = nil then
    begin
        pub_key := BN_new();
        if pub_key = nil then
            goto _err ;
    end
    else
    begin
        pub_key := dsa.pub_key;
    end;
    if 0>= ossl_dsa_generate_public_key(ctx, dsa, priv_key, pub_key) then
        goto _err ;
    dsa.priv_key := priv_key;
    dsa.pub_key := pub_key;
{$IFDEF FIPS_MODULE}
    pairwise_test := 1;
{$endif} { FIPS_MODULE }
    ok := 1;
    if pairwise_test > 0 then
    begin
        cb := nil;
        cbarg := nil;
        OSSL_SELF_TEST_get_callback(dsa.libctx, @cb, @cbarg);
        ok := dsa_keygen_pairwise_test(dsa, cb, cbarg);
        if 0>= ok then
        begin
            ossl_set_error_state(OSSL_SELF_TEST_TYPE_PCT);
            BN_free(dsa.pub_key);
            BN_clear_free(dsa.priv_key);
            dsa.pub_key := nil;
            dsa.priv_key := nil;
            BN_CTX_free(ctx);
            Exit(ok);
        end;
    end;
    Inc(dsa.dirty_cnt);
 _err:
    if pub_key <> dsa.pub_key then
       BN_free(pub_key);
    if priv_key <> dsa.priv_key then
       BN_free(priv_key);
    BN_CTX_free(ctx);
    Result := ok;
end;





function DSA_generate_key( dsa : PDSA):integer;
begin
{$IFNDEF FIPS_MODULE}
    if Assigned(dsa.meth.dsa_keygen) then
       Exit(dsa.meth.dsa_keygen(dsa));
{$ENDIF}
    Result := dsa_keygen(dsa, 0);
end;



function ossl_dsa_generate_public_key(ctx : PBN_CTX;const dsa : PDSA; priv_key : PBIGNUM; pub_key : PBIGNUM):integer;
var
  ret : integer;

  prk : PBIGNUM;
  label _err;
begin
    ret := 0;
    prk := BN_new();
    if prk = nil then Exit(0);
    BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
    { pub_key = g ^ priv_key mod p }
    if  0>= BN_mod_exp(pub_key, dsa.params.g, prk, dsa.params.p, ctx) then
        goto _err ;
    ret := 1;
_err:
    BN_clear_free(prk);
    Result := ret;
end;





end.
