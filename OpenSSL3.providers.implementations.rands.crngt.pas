unit OpenSSL3.providers.implementations.rands.crngt;

interface
uses OpenSSL.Api;



function ossl_crngt_get_entropy( drbg : PPROV_DRBG; pout : PPByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer):size_t;
function rand_crng_ossl_ctx_new( ctx : POSSL_LIB_CTX):Pointer;
procedure rand_crng_ossl_ctx_free( vcrngt_glob : Pointer);
function crngt_get_entropy(provctx : PPROV_CTX;const digest : PEVP_MD; buf, md : PByte; md_size : Puint32):integer;
function prov_crngt_compare_previous(const prev, cur : PByte; sz : size_t):integer;


const
    CRNGT_BUFSIZ =   16;
    rand_crng_ossl_ctx_method: TOSSL_LIB_CTX_METHOD = (
    PRIORITY:OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
    new_func: rand_crng_ossl_ctx_new;
    free_func: rand_crng_ossl_ctx_free
);

implementation
uses openssl3.providers.common.provider_ctx,  openssl3.crypto.evp.digest,
     openssl3.crypto.context, openssl3.crypto.mem, openssl3.crypto.self_test_core,
     openssl3.crypto.provider.provider_seeding, openssl3.crypto.mem_sec,
     openssl3.providers.fips.self_test, OpenSSL3.threads_none;





function prov_crngt_compare_previous(const prev, cur : PByte; sz : size_t):integer;
var
  res : Boolean;
begin
    res := memcmp(prev, cur, sz) <> 0;
    if  not res then
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_CRNG);
    Result := Int(res);
end;



function crngt_get_entropy(provctx : PPROV_CTX;const digest : PEVP_MD; buf, md : PByte; md_size : Puint32):integer;
var
  r : integer;
  n : size_t;
  p : PByte;
begin
    n := ossl_prov_get_entropy(provctx, p, 0, CRNGT_BUFSIZ, CRNGT_BUFSIZ);
    if n = CRNGT_BUFSIZ then
    begin
        r := EVP_Digest(p, CRNGT_BUFSIZ, md, md_size, digest, nil);
        if r <> 0 then
           memcpy(buf, p, CRNGT_BUFSIZ);
        ossl_prov_cleanup_entropy(provctx, p, n);
        Exit(Int(r <> 0));
    end;
    if n <> 0 then ossl_prov_cleanup_entropy(provctx, p, n);
    Result := 0;
end;

procedure rand_crng_ossl_ctx_free( vcrngt_glob : Pointer);
var
  crngt_glob : PCRNG_TEST_GLOBAL;
begin
    crngt_glob := vcrngt_glob;
    CRYPTO_THREAD_lock_free(crngt_glob.lock);
    EVP_MD_free(crngt_glob.md);
    OPENSSL_free(Pointer(crngt_glob));
end;



function rand_crng_ossl_ctx_new( ctx : POSSL_LIB_CTX):Pointer;
var
  crngt_glob : PCRNG_TEST_GLOBAL;
begin
    crngt_glob := OPENSSL_zalloc(sizeof( crngt_glob^));
    if crngt_glob = nil then Exit(nil);
    crngt_glob.md := EVP_MD_fetch(ctx, 'SHA256', '');
    if crngt_glob.md = nil then
    begin
        OPENSSL_free(Pointer(crngt_glob));
        Exit(nil);
    end;
    crngt_glob.lock := CRYPTO_THREAD_lock_new();
    if crngt_glob.lock = nil then
    begin
        EVP_MD_free(crngt_glob.md);
        OPENSSL_free(Pointer(crngt_glob));
        Exit(nil);
    end;
    Result := crngt_glob;
end;

function ossl_crngt_get_entropy( drbg : PPROV_DRBG; pout : PPByte; entropy : integer; min_len, max_len : size_t; prediction_resistance : integer):size_t;
var
    md             : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

    buf            : array[0..(CRNGT_BUFSIZ)-1] of Byte;

  ent,
entp,
  entbuf         : PByte;

    sz             : uint32;

  bytes_needed,
  r, s ,t              : size_t;

    crng_test_pass : integer;

    libctx         : POSSL_LIB_CTX;

    crngt_glob     : PCRNG_TEST_GLOBAL;

    stcb           : POSSL_CALLBACK;

    stcbarg        : Pointer;

    st             : POSSL_SELF_TEST;
    label _unlock_return, _err;
begin
    r := 0;
    crng_test_pass := 1;
    libctx := ossl_prov_ctx_get0_libctx(drbg.provctx);
    crngt_glob
        := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_RAND_CRNGT_INDEX,
                                @rand_crng_ossl_ctx_method);
    stcb := nil;
    stcbarg := nil;
    st := nil;
    if crngt_glob = nil then Exit(0);
    if  0>= CRYPTO_THREAD_write_lock(crngt_glob.lock) then
        Exit(0);
    if  0>= crngt_glob.preloaded then
    begin
        if ( 0>= crngt_get_entropy(drbg.provctx, crngt_glob.md, @buf,
                               @crngt_glob.crngt_prev, nil)) then
        begin
            OPENSSL_cleanse(@buf, sizeof(buf));
            goto _unlock_return ;
        end;
        crngt_glob.preloaded := 1;
    end;
    {
     * Calculate how many bytes of seed material we require, rounded up
     * to the nearest byte.  If the entropy is of less than full quality,
     * the amount required should be scaled up appropriately here.
     }
    bytes_needed := (entropy + 7) div 8;
    if bytes_needed < min_len then bytes_needed := min_len;
    if bytes_needed > max_len then goto _unlock_return ;
    ent := OPENSSL_secure_malloc(bytes_needed);
    entp := ent;
    if ent = nil then goto _unlock_return ;
    OSSL_SELF_TEST_get_callback(libctx, @stcb, @stcbarg);
    if Assigned(stcb) then
    begin
        st := OSSL_SELF_TEST_new(stcb, stcbarg);
        if st = nil then goto _err ;
        OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_CRNG,
                               OSSL_SELF_TEST_DESC_RNG);
    end;
    t := bytes_needed;
    while ( t > 0) do
    begin
        { Care needs to be taken to avoid overrunning the buffer }
        s := get_result(t >= CRNGT_BUFSIZ , CRNGT_BUFSIZ , t);
        if t >= CRNGT_BUFSIZ then
           entbuf := entp
        else
           entbuf := @buf;
        if  0>= crngt_get_entropy(drbg.provctx, crngt_glob.md, entbuf, @md, @sz)  then
            goto _err ;
        if t < CRNGT_BUFSIZ then memcpy(entp, @buf, t);
        { Force a failure here if the callback returns 1 }
        if OSSL_SELF_TEST_oncorrupt_byte(st, @md)>0 then
            memcpy(@md, @crngt_glob.crngt_prev, sz);
        if  0>= prov_crngt_compare_previous(@crngt_glob.crngt_prev, @md, sz )then
        begin
            crng_test_pass := 0;
            goto _err ;
        end;
        { Update for next block }
        memcpy(@crngt_glob.crngt_prev, @md, sz);
        entp  := entp + s;
        t  := t - s;
    end;
    r := bytes_needed;
    pout^ := ent;
    ent := nil;
 _err:
    OSSL_SELF_TEST_onend(st, crng_test_pass);
    OSSL_SELF_TEST_free(st);
    OPENSSL_secure_clear_free(ent, bytes_needed);
 _unlock_return:
    CRYPTO_THREAD_unlock(crngt_glob.lock);
    Result := r;
end;


end.
