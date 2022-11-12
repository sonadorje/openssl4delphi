unit openssl3.crypto.dh.dh_lib;

interface
uses OpenSSL.Api;

 function ossl_dh_get_method(const dh : PDH):PDH_METHOD;

function ossl_dh_new_ex( libctx : POSSL_LIB_CTX):PDH;
function ossl_dh_get0_params( dh : PDH):PFFC_PARAMS;
function dh_new_intern( engine : PENGINE; libctx : POSSL_LIB_CTX):PDH;
 procedure DH_free( r : PDH);
procedure DH_get0_pqg(const dh : PDH; p, q, g : PPBIGNUM);
 function DH_set0_key( dh : PDH; pub_key, priv_key : PBIGNUM):integer;
 function DH_get0_p(const dh : PDH):PBIGNUM;
 function DH_get0_q(const dh : PDH):PBIGNUM;
 function DH_get0_g(const dh : PDH):PBIGNUM;
 function DH_get0_priv_key(const dh : PDH):PBIGNUM;
 function DH_get0_pub_key(const dh : PDH):PBIGNUM;
 function DH_new:PDH;
 function DH_size(const dh : PDH):integer;
 function DH_set_length( dh : PDH; length : long):integer;
 procedure DH_get0_key(const dh : PDH; pub_key, priv_key : PPBIGNUM);
 function DH_get_length(const dh : PDH):long;
 procedure DH_clear_flags( dh : PDH; flags : integer);
 procedure DH_set_flags( dh : PDH; flags : integer);
  function DH_set0_pqg( dh : PDH; p, q, g : PBIGNUM):integer;
function _DH_bits(const dh : PDH):integer;
function _DH_security_bits(const dh : PDH):integer;
function DH_up_ref( r : PDH):integer;
function DH_test_flags(const dh : PDH; flags : integer):integer;
 procedure ossl_dh_set0_libctx( d : PDH; libctx : POSSL_LIB_CTX);

implementation
 uses OpenSSL3.common, openssl3.crypto.mem, openssl3.err,
      openssl3.crypto.engine.eng_init, openssl3.crypto.engine.tb_dh,
      openssl3.crypto.ex_data, openssl3.include.internal.refcount,
      openssl3.crypto.ffc.ffc_params, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.dh.dh_group_params,
      OpenSSL3.threads_none, openssl3.crypto.dh.dh_key;


procedure ossl_dh_set0_libctx( d : PDH; libctx : POSSL_LIB_CTX);
begin
    d.libctx := libctx;
end;

function DH_test_flags(const dh : PDH; flags : integer):integer;
begin
    Result := dh.flags and flags;
end;




function DH_up_ref( r : PDH):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(r.references, i, r.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('DH', r);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result(i > 1 , 1 , 0);
end;




function _DH_security_bits(const dh : PDH):integer;
var
  N : integer;
begin
    if dh.params.q <> nil then
       N := BN_num_bits(dh.params.q)
    else if (dh.length>0) then
        N := dh.length
    else
        N := -1;
    if dh.params.p <> nil then
       Exit(BN_security_bits(BN_num_bits(dh.params.p), N));
    Result := -1;
end;



function _DH_bits(const dh : PDH):integer;
begin
    if dh.params.p <> nil then Exit(BN_num_bits(dh.params.p));
    Result := -1;
end;

function DH_set0_pqg( dh : PDH; p, q, g : PBIGNUM):integer;
begin
    {
     * If the fields p and g in dh are nil, the corresponding input
     * parameters MUST be non-nil.  q may remain nil.
     }
    if ( (dh.params.p = nil)  and  (p = nil) )  or
       ( (dh.params.g = nil)  and  (g = nil) ) then
        Exit(0);
    ossl_ffc_params_set0_pqg(@dh.params, p, q, g);
    ossl_dh_cache_named_group(dh);
    PostInc(dh.dirty_cnt);
    Result := 1;
end;

procedure DH_set_flags( dh : PDH; flags : integer);
begin
    dh.flags  := dh.flags  or flags;
end;

procedure DH_clear_flags( dh : PDH; flags : integer);
begin
    dh.flags := dh.flags and (not flags);
end;




function DH_get_length(const dh : PDH):long;
begin
    Result := dh.length;
end;



procedure DH_get0_key(const dh : PDH; pub_key, priv_key : PPBIGNUM);
begin
    if pub_key <> nil then
       pub_key^ := dh.pub_key;
    if priv_key <> nil then
       priv_key^ := dh.priv_key;
end;



function DH_set_length( dh : PDH; length : long):integer;
begin
    dh.length := length;
    Inc(dh.dirty_cnt);
    Result := 1;
end;




function DH_size(const dh : PDH):integer;
begin
    if dh.params.p <> nil then Exit(BN_num_bytes(dh.params.p));
    Result := -1;
end;

function DH_new:PDH;
begin
    Result := dh_new_intern(nil, nil);
end;


function DH_get0_pub_key(const dh : PDH):PBIGNUM;
begin
    Result := dh.pub_key;
end;



function DH_get0_priv_key(const dh : PDH):PBIGNUM;
begin
    Result := dh.priv_key;
end;

function DH_get0_g(const dh : PDH):PBIGNUM;
begin
    Result := dh.params.g;
end;








function DH_get0_q(const dh : PDH):PBIGNUM;
begin
    Result := dh.params.q;
end;




function DH_get0_p(const dh : PDH):PBIGNUM;
begin
    Result := dh.params.p;
end;




function DH_set0_key( dh : PDH; pub_key, priv_key : PBIGNUM):integer;
begin
    if pub_key <> nil then
    begin
        BN_clear_free(dh.pub_key);
        dh.pub_key := pub_key;
    end;
    if priv_key <> nil then
    begin
        BN_clear_free(dh.priv_key);
        dh.priv_key := priv_key;
    end;
    Inc(dh.dirty_cnt);
    Result := 1;
end;

procedure DH_get0_pqg(const dh : PDH; p, q, g : PPBIGNUM);
begin
    ossl_ffc_params_get0_pqg(@dh.params, p, q, g);
end;

procedure DH_free( r : PDH);
var
  i : integer;
begin
    if r = nil then exit;
    CRYPTO_DOWN_REF(r.references, i, r.lock);
    REF_PRINT_COUNT('DH', r);
    if i > 0 then exit;
    REF_ASSERT_ISNT(i < 0);
    if (r.meth <> nil)  and  (Assigned(r.meth.finish)) then
       r.meth.finish(r);
{$IF not defined(FIPS_MODULE)}
{$IF not defined(OPENSSL_NO_ENGINE)}
    ENGINE_finish(r.engine);
{$ENDIF}
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, @r.ex_data);
{$ENDIF}
    CRYPTO_THREAD_lock_free(r.lock);
    ossl_ffc_params_cleanup(@r.params);
    BN_clear_free(r.pub_key);
    BN_clear_free(r.priv_key);
    OPENSSL_free(Pointer(r));
end;

function ossl_dh_get0_params( dh : PDH):PFFC_PARAMS;
begin
    Result := @dh.params;
end;

function dh_new_intern( engine : PENGINE; libctx : POSSL_LIB_CTX):PDH;
var
  ret : PDH;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.references := 1;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then begin
        ERR_raise(ERR_LIB_DH, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    ret.libctx := libctx;
    ret.meth := DH_get_default_method();
{$IF not defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ENGINE)}
    ret.flags := ret.meth.flags;  { early default init }
    if Assigned(engine) then
    begin
        if  0>= ENGINE_init(engine) then
        begin
            ERR_raise(ERR_LIB_DH, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
        ret.engine := engine;
    end
    else
        ret.engine := ENGINE_get_default_DH();
    if Assigned(ret.engine) then
    begin
        ret.meth := ENGINE_get_DH(ret.engine);
        if ret.meth = nil then
        begin
            ERR_raise(ERR_LIB_DH, ERR_R_ENGINE_LIB);
            goto _err ;
        end;
    end;
{$ENDIF}
    ret.flags := ret.meth.flags;
{$IFNDEF FIPS_MODULE}
    if  0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, @ret.ex_data )then
        goto _err ;
{$endif} { FIPS_MODULE }
    if (Assigned(ret.meth.init) )   and   (0>= ret.meth.init(ret) )then
    begin
        ERR_raise(ERR_LIB_DH, ERR_R_INIT_FAIL);
        goto _err ;
    end;
    Exit(ret);
 _err:
    DH_free(ret);
    Result := nil;
end;



function ossl_dh_new_ex( libctx : POSSL_LIB_CTX):PDH;
begin
    Result := dh_new_intern(nil, libctx);
end;



function ossl_dh_get_method(const dh : PDH):PDH_METHOD;
begin
    Result := dh.meth;
end;

end.
