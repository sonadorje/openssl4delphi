unit openssl3.crypto.bn.bn_blind;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

type
  Tbn_mod_exp_func = function(r: PBIGNUM; const a, p, m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): Integer;

const
   BN_BLINDING_COUNTER = 32;

  function BN_BLINDING_new(const A, Ai : PBIGNUM; &mod : PBIGNUM):PBN_BLINDING;
  procedure BN_BLINDING_free( r : PBN_BLINDING);
  function BN_BLINDING_update( b : PBN_BLINDING; ctx : PBN_CTX):integer;
  function BN_BLINDING_convert( n : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
  function BN_BLINDING_convert_ex( n, r : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
  function BN_BLINDING_invert( n : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
  function BN_BLINDING_invert_ex(n : PBIGNUM; r : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
  function BN_BLINDING_is_current_thread( b : PBN_BLINDING):integer;
  procedure BN_BLINDING_set_current_thread( b : PBN_BLINDING);
  function BN_BLINDING_lock( b : PBN_BLINDING):integer;
  function BN_BLINDING_unlock( b : PBN_BLINDING):integer;
  function BN_BLINDING_get_flags(const b : PBN_BLINDING):Cardinal;
  procedure BN_BLINDING_set_flags( b : PBN_BLINDING; flags : Cardinal);
  function BN_BLINDING_create_param(b : PBN_BLINDING;const e : PBIGNUM; m : PBIGNUM; ctx : PBN_CTX; bn_mod_exp_func : Tbn_mod_exp_func; m_ctx : PBN_MONT_CTX):PBN_BLINDING;


implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_mont,
     openssl3.crypto.bn.bn_gcd, openssl3.crypto.bn.bn_exp,
     openssl3.crypto.bn.bn_mod, openssl3.crypto.bn.bn_rand;

function BN_BLINDING_new(const A, Ai : PBIGNUM; &mod : PBIGNUM):PBN_BLINDING;
var
  ret : PBN_BLINDING;
  label _err;
begin
    ret := nil;
    //bn_check_top(mod);
    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    BN_BLINDING_set_current_thread(ret);
    if A <> nil then
    begin
        ret.A := BN_dup(A);
        if ret.A = nil then
            goto _err ;
    end;
    if Ai <> nil then
    begin
        ret.Ai := BN_dup(Ai);
        if (ret.Ai = nil) then
            goto _err ;
    end;
    { save a copy of mod in the BN_BLINDING structure }
    ret.&mod := BN_dup(&mod);
    if ret.&mod =  nil then
        goto _err ;
    if BN_get_flags(&mod, BN_FLG_CONSTTIME) <> 0  then
        BN_set_flags(ret.&mod, BN_FLG_CONSTTIME);
    {
     * Set the counter to the special value -1 to indicate that this is
     * never-used fresh blinding that does not need updating before first
     * use.
     }
    ret.counter := -1;
    Exit(ret);
 _err:
    BN_BLINDING_free(ret);
    Result := nil;
end;


procedure BN_BLINDING_free( r : PBN_BLINDING);
begin
    if r = nil then exit;
    BN_free(r.A);
    BN_free(r.Ai);
    BN_free(r.e);
    BN_free(r.&mod);
    CRYPTO_THREAD_lock_free(r.lock);
    OPENSSL_free(Pointer(r));
end;


function BN_BLINDING_update( b : PBN_BLINDING; ctx : PBN_CTX):integer;
var
  ret : integer;
  label _err;
begin
    ret := 0;
    if (b.A = nil)  or  (b.Ai = nil) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        goto _err ;
    end;
    if b.counter = -1 then
       b.counter := 0;
    if (PreInc(b.counter) = BN_BLINDING_COUNTER)  and  (b.e <> nil)  and
       (0>= (b.flags and BN_BLINDING_NO_RECREATE)) then
    begin
        { re-create blinding parameters }
        if nil = BN_BLINDING_create_param(b, nil, nil, ctx, nil, nil) then
            goto _err ;
    end
    else
    if (0>= (b.flags and BN_BLINDING_NO_UPDATE)) then
    begin
        if b.m_ctx <> nil then
        begin
            if (0>= bn_mul_mont_fixed_top(b.Ai, b.Ai, b.Ai, b.m_ctx, ctx))
                 or  (0>= bn_mul_mont_fixed_top(b.A, b.A, b.A, b.m_ctx, ctx)) then
                goto _err ;
        end
        else
        begin
            if (0>= BN_mod_mul(b.Ai, b.Ai, b.Ai, b.&mod, ctx))  or
               (0>= BN_mod_mul(b.A, b.A, b.A, b.&mod, ctx))  then
                goto _err ;
        end;
    end;
    ret := 1;
 _err:
    if b.counter = BN_BLINDING_COUNTER then
       b.counter := 0;
    Result := ret;
end;


function BN_BLINDING_convert( n : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
begin
    Result := BN_BLINDING_convert_ex(n, nil, b, ctx);
end;


function BN_BLINDING_convert_ex( n, r : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
var
  ret : integer;
begin
    ret := 1;
    bn_check_top(n);
    if (b.A = nil )  or  (b.Ai = nil) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        Exit(0);
    end;
    if b.counter = -1 then { Fresh blinding, doesn't need updating. }
       b.counter := 0
    else
    if (0>= BN_BLINDING_update(b, ctx)) then
        Exit(0);
    if (r <> nil)  and  (BN_copy(r, b.Ai) = nil) then
        Exit(0);
    if (b.m_ctx <> nil) then
        ret := BN_mod_mul_montgomery(n, n, b.A, b.m_ctx, ctx)
    else
        ret := BN_mod_mul(n, n, b.A, b.&mod, ctx);
    Result := ret;
end;


function BN_BLINDING_invert( n : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
begin
    Result := BN_BLINDING_invert_ex(n, nil, b, ctx);
end;


function BN_BLINDING_invert_ex(n : PBIGNUM; r : PBIGNUM; b : PBN_BLINDING; ctx : PBN_CTX):integer;
var
  ret : integer;
  i, rtop, ntop : size_t;
  mask : BN_ULONG;
begin
{$POINTERMATH ON}
    bn_check_top(n);

    if (r = nil) then
    begin
        r := b.Ai;
        if (r =  nil) then
        begin
            ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
            Exit(0);
        end;
    end;
    if b.m_ctx <> nil then
    begin
        { ensure that BN_mod_mul_montgomery takes pre-defined path }
        if n.dmax >= r.top then
        begin
            rtop := r.top; ntop := n.top;
            for i := 0 to rtop-1 do
            begin
                mask := BN_ULONG(0) - ((i - ntop)  shr  (8 * sizeof(i) - 1));
                n.d[i] := n.d[i] and mask;
            end;
            mask := BN_ULONG(0) - ((rtop - ntop)  shr  (8 * sizeof(ntop) - 1));
            { always true, if (rtop >= ntop) n.top = r.top; }
            n.top := int (rtop and not mask) or (ntop and mask);
            n.flags  := n.flags  or ((BN_FLG_FIXED_TOP and not mask));
        end;
        ret := BN_mod_mul_montgomery(n, n, r, b.m_ctx, ctx);
    end
    else
    begin
        ret := BN_mod_mul(n, n, r, b.&mod, ctx);
    end;
    bn_check_top(n);
    Result := ret;
{$POINTERMATH OFF}
end;


function BN_BLINDING_is_current_thread( b : PBN_BLINDING):integer;
begin
    Result := CRYPTO_THREAD_compare_id(CRYPTO_THREAD_get_current_id(), b.tid);
end;


procedure BN_BLINDING_set_current_thread( b : PBN_BLINDING);
begin
    b.tid := CRYPTO_THREAD_get_current_id();
end;


function BN_BLINDING_lock( b : PBN_BLINDING):integer;
begin
    Result := CRYPTO_THREAD_write_lock(b.lock);
end;


function BN_BLINDING_unlock( b : PBN_BLINDING):integer;
begin
    Result := CRYPTO_THREAD_unlock(b.lock);
end;


function BN_BLINDING_get_flags(const b : PBN_BLINDING):Cardinal;
begin
    Result := b.flags;
end;


procedure BN_BLINDING_set_flags( b : PBN_BLINDING; flags : Cardinal);
begin
    b.flags := flags;
end;


function BN_BLINDING_create_param(b : PBN_BLINDING;const e : PBIGNUM; m : PBIGNUM;
                                  ctx : PBN_CTX; bn_mod_exp_func : Tbn_mod_exp_func;
                                  m_ctx : PBN_MONT_CTX):PBN_BLINDING;
var
    retry_counter : integer;
    ret           : PBN_BLINDING;
    rv            : integer;
    label _err;
begin
    retry_counter := 32;
    ret := nil;
    if b = nil then
       ret := BN_BLINDING_new(nil, nil, m)
    else
        ret := b;
    if ret = nil then goto _err ;
    if (ret.A = nil) then
    begin
        ret.A := BN_new();
        if (ret.A = nil) then
        goto _err ;
    end;
    if ret.Ai = nil  then
    begin
        ret.Ai := BN_new();
        if ret.Ai = nil then
        goto _err ;
    end;

    if e <> nil then
    begin
        BN_free(ret.e);
        ret.e := BN_dup(e);
    end;
    if ret.e = nil then goto _err ;
    if Assigned(bn_mod_exp_func) then
       ret.bn_mod_exp := bn_mod_exp_func;
    if m_ctx <> nil then
       ret.m_ctx := m_ctx;
    while true do
    begin   //pool.current.vals is null
        if 0>= BN_priv_rand_range_ex(ret.A, ret.&mod, 0, ctx) then
            goto _err ;
        if int_bn_mod_inverse(ret.Ai, ret.A, ret.&mod, ctx, @rv) <> nil then
            break;
        {
         * this should almost never happen for good RSA keys
         }
        if 0>= rv then
           goto _err ;
        if PostDec(retry_counter) = 0  then
        begin
            ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS);
            goto _err ;
        end;
    end;

    if (Assigned(ret.bn_mod_exp))  and  (Assigned(ret.m_ctx)) then
    begin
        if 0>= ret.bn_mod_exp(ret.A, ret.A, ret.e, ret.&mod, ctx, ret.m_ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_mod_exp(ret.A, ret.A, ret.e, ret.&mod, ctx) then
            goto _err ;
    end;
    if ret.m_ctx <> nil then
    begin
        if (0>= bn_to_mont_fixed_top(ret.Ai, ret.Ai, ret.m_ctx, ctx))    or
           (0>= bn_to_mont_fixed_top(ret.A,   ret.A, ret.m_ctx, ctx)) then
            goto _err ;
    end;
    Exit(ret);
 _err:
    if b = nil then
    begin
        BN_BLINDING_free(ret);
        ret := nil;
    end;
    Result := ret;
end;


end.
