unit openssl3.crypto.dsa.dsa_lib;

interface
uses OpenSSL.Api;

function ossl_dsa_new( libctx : POSSL_LIB_CTX):PDSA;
function ossl_dsa_get0_params( dsa : PDSA):PFFC_PARAMS;
function dsa_new_intern( engine : PENGINE; libctx : POSSL_LIB_CTX):PDSA;
function ossl_dsa_ffc_params_fromdata(dsa : PDSA;const params : POSSL_PARAM):integer;
function DSA_up_ref( r : PDSA):integer;
 procedure DSA_free( r : PDSA);
 function DSA_get0_p(const d : PDSA):PBIGNUM;
 function DSA_get0_q(const d : PDSA):PBIGNUM;
 function DSA_get0_g(const d : PDSA):PBIGNUM;
 function DSA_get0_pub_key(const d : PDSA):PBIGNUM;
 function DSA_new:PDSA;
  function DSA_set0_key( d : PDSA; pub_key, priv_key : PBIGNUM):integer;
 function DSA_get_method( d : PDSA):PDSA_METHOD;
 function _DSA_bits(const dsa : PDSA):integer;
 function _DSA_security_bits(const d : PDSA):integer;
  function DSA_get0_priv_key(const d : PDSA):PBIGNUM;
  procedure DSA_get0_key(const d : PDSA; pub_key, priv_key : PPBIGNUM);
 procedure DSA_get0_pqg(const d : PDSA; p, q, g : PPBIGNUM);
  procedure ossl_dsa_set0_libctx( d : PDSA; libctx : POSSL_LIB_CTX);

function DSA_set0_pqg( d : PDSA; p, q, g : PBIGNUM):integer;

implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.ex_data,
     openssl3.crypto.ffc.ffc_backend, openssl3.crypto.engine.eng_init,
     OpenSSL3.threads_none,  openssl3.crypto.dsa.dsa_ossl,
     openssl3.crypto.ffc.ffc_params,  openssl3.crypto.bn.bn_lib,
     openssl3.crypto.engine.tb_dsa, openssl3.include.internal.refcount;




function DSA_set0_pqg( d : PDSA; p, q, g : PBIGNUM):integer;
begin
    { If the fields p, q and g in d are nil, the corresponding input
     * parameters MUST be non-nil.
     }
    if ( (d.params.p = nil)  and  (p = nil) ) or
       ( (d.params.q = nil)  and  (q = nil) ) or
       ( (d.params.g = nil)  and  (g = nil) )  then
        Exit(0);
    ossl_ffc_params_set0_pqg(@d.params, p, q, g);
    Inc(d.dirty_cnt);
    Result := 1;
end;




procedure ossl_dsa_set0_libctx( d : PDSA; libctx : POSSL_LIB_CTX);
begin
    d.libctx := libctx;
end;


procedure DSA_get0_pqg(const d : PDSA; p, q, g : PPBIGNUM);
begin
    ossl_ffc_params_get0_pqg(@d.params, p, q, g);
end;



procedure DSA_get0_key(const d : PDSA; pub_key, priv_key : PPBIGNUM);
begin
    if pub_key <> nil then pub_key^ := d.pub_key;
    if priv_key <> nil then priv_key^ := d.priv_key;
end;


function DSA_get0_priv_key(const d : PDSA):PBIGNUM;
begin
    Result := d.priv_key;
end;

function _DSA_security_bits(const d : PDSA):integer;
begin
    if (d.params.p <> nil)  and  (d.params.q <> nil) then
        Exit(BN_security_bits(BN_num_bits(d.params.p),
                                BN_num_bits(d.params.q)));
    Result := -1;
end;




function _DSA_bits(const dsa : PDSA):integer;
begin
    if dsa.params.p <> nil then
       Exit(BN_num_bits(dsa.params.p));
    Result := -1;
end;

function DSA_get_method( d : PDSA):PDSA_METHOD;
begin
    Result := d.meth;
end;

function DSA_set0_key( d : PDSA; pub_key, priv_key : PBIGNUM):integer;
begin
    if pub_key <> nil then
    begin
        BN_free(d.pub_key);
        d.pub_key := pub_key;
    end;
    if priv_key <> nil then
    begin
        BN_free(d.priv_key);
        d.priv_key := priv_key;
    end;
    Inc(d.dirty_cnt);
    Result := 1;
end;



function DSA_new:PDSA;
begin
    Result := dsa_new_intern(nil, nil);
end;

function DSA_get0_pub_key(const d : PDSA):PBIGNUM;
begin
    Result := d.pub_key;
end;




function DSA_get0_g(const d : PDSA):PBIGNUM;
begin
    Result := d.params.g;
end;

function DSA_get0_q(const d : PDSA):PBIGNUM;
begin
    Result := d.params.q;
end;



function DSA_get0_p(const d : PDSA):PBIGNUM;
begin
    Result := d.params.p;
end;

procedure DSA_free( r : PDSA);
var
  i : integer;
begin
    if r = nil then exit;
    CRYPTO_DOWN_REF(r.references, i, r.lock);
    REF_PRINT_COUNT('DSA', r);
    if i > 0 then exit;
    REF_ASSERT_ISNT(i < 0);
    if (r.meth <> nil)  and  (Assigned(r.meth.finish)) then
       r.meth.finish(r);
{$IF not defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ENGINE)}
    ENGINE_finish(r.engine);
{$ENDIF}
{$IFNDEF FIPS_MODULE}
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, r, @r.ex_data);
{$ENDIF}
    CRYPTO_THREAD_lock_free(r.lock);
    ossl_ffc_params_cleanup(@r.params);
    BN_clear_free(r.pub_key);
    BN_clear_free(r.priv_key);
    OPENSSL_free(Pointer(r));
end;




function DSA_up_ref( r : PDSA):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(r.references, i, r.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('DSA', r);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result((i > 1) , 1 , 0);
end;

function ossl_dsa_ffc_params_fromdata(dsa : PDSA;const params : POSSL_PARAM):integer;
var
  ret : integer;

  ffc : PFFC_PARAMS;
begin
    if dsa = nil then Exit(0);
    ffc := ossl_dsa_get0_params(dsa);
    if ffc = nil then Exit(0);
    ret := ossl_ffc_params_fromdata(ffc, params);
    if ret >0 then
       Inc(dsa.dirty_cnt);
    Result := ret;
end;

function ossl_dsa_get0_params( dsa : PDSA):PFFC_PARAMS;
begin
    Result := @dsa.params;
end;

function dsa_new_intern( engine : PENGINE; libctx : POSSL_LIB_CTX):PDSA;
var
  ret : PDSA;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.references := 1;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then
    begin
        ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    ret.libctx := libctx;
    ret.meth := DSA_get_default_method();
{$IF not defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ENGINE)}
    ret.flags := ret.meth.flags and (not DSA_FLAG_NON_FIPS_ALLOW); { early default init }
    if Assigned(engine) then
    begin
        if  0>= ENGINE_init(engine) then
        begin
            ERR_raise(ERR_LIB_DSA, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
        ret.engine := engine;
    end
    else
        ret.engine := ENGINE_get_default_DSA();
    if Assigned(ret.engine) then
    begin
        ret.meth := ENGINE_get_DSA(ret.engine);
        if ret.meth = nil then
        begin
            ERR_raise(ERR_LIB_DSA, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
    end;
{$ENDIF}
    ret.flags := ret.meth.flags and (not DSA_FLAG_NON_FIPS_ALLOW);
{$IFNDEF FIPS_MODULE}
    if  0>= ossl_crypto_new_ex_data_ex(libctx, CRYPTO_EX_INDEX_DSA, ret,
                                    @ret.ex_data)  then
        goto _err ;
{$ENDIF}
    if (Assigned(ret.meth.init))  and   (0>= ret.meth.init(ret)) then
    begin
        ERR_raise(ERR_LIB_DSA, ERR_R_INIT_FAIL);
        goto _err ;
    end;
    Exit(ret);
 _err:
    DSA_free(ret);
    Result := nil;
end;


function ossl_dsa_new( libctx : POSSL_LIB_CTX):PDSA;
begin
    Result := dsa_new_intern(nil, libctx);
end;


end.
