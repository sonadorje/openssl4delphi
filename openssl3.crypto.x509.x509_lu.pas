unit openssl3.crypto.x509.x509_lu;

interface
uses OpenSSL.Api;

function X509_STORE_CTX_get1_issuer( issuer : PPX509; ctx : PX509_STORE_CTX; x : PX509):integer;
 function X509_STORE_CTX_get_by_subject(const vs : PX509_STORE_CTX; _type : X509_LOOKUP_TYPE;const name : PX509_NAME; ret : PX509_OBJECT):integer;
function X509_STORE_lock( s : PX509_STORE):integer;
function X509_OBJECT_new:PX509_OBJECT;
function X509_OBJECT_retrieve_by_subject(h: Pstack_st_X509_OBJECT;_type : X509_LOOKUP_TYPE;const name : PX509_NAME):PX509_OBJECT;
function X509_OBJECT_idx_by_subject(h: Pstack_st_X509_OBJECT; _type : X509_LOOKUP_TYPE;const name : PX509_NAME):integer;
 function x509_object_idx_cnt(h: Pstack_st_X509_OBJECT;_type : X509_LOOKUP_TYPE;const name : PX509_NAME; pnmatch : PInteger):integer;
function X509_STORE_unlock( s : PX509_STORE):integer;
function X509_LOOKUP_by_subject_ex(ctx : PX509_LOOKUP; _type : X509_LOOKUP_TYPE;const name : PX509_NAME; ret : PX509_OBJECT; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function X509_OBJECT_up_ref_count( a : PX509_OBJECT):integer;
procedure X509_OBJECT_free( a : PX509_OBJECT);
 procedure x509_object_free_internal( a : PX509_OBJECT);
 function X509_STORE_CTX_get1_certs(ctx : PX509_STORE_CTX;const nm : PX509_NAME):Pstack_st_X509;
 function X509_STORE_CTX_get1_crls(const ctx : PX509_STORE_CTX; const nm : PX509_NAME):Pstack_st_X509_CRL;

implementation
uses openssl3.crypto.mem, OpenSSL3.Err, OpenSSL3.crypto.x509.x509_cmp,
     OpenSSL3.threads_none, OpenSSL3.crypto.x509.x509_vfy,
     openssl3.crypto.asn1.a_time, openssl3.crypto.x509,
     openssl3.crypto.t_x509,
     openssl3.crypto.x509.x_x509, openssl3.crypto.x509.x_crl,
     OpenSSL3.crypto.x509.x509_set, OpenSSL3.crypto.x509.x509cset;






function X509_STORE_CTX_get1_crls(const ctx : PX509_STORE_CTX; const nm : PX509_NAME):Pstack_st_X509_CRL;
var
  i, idx, cnt : integer;
  sk : Pstack_st_X509_CRL;
  x : PX509_CRL;
  obj, xobj : PX509_OBJECT;
  store : PX509_STORE;
begin
    sk := sk_X509_CRL_new_null;
    xobj := X509_OBJECT_new;
    store := ctx.store;
    { Always do lookup to possibly add new CRLs to cache }
    if (sk = nil)
             or  (xobj = nil)
             or  (store = nil)
             or  (0>=X509_STORE_CTX_get_by_subject(ctx, X509_LU_CRL, nm, xobj)) then
    begin
        X509_OBJECT_free(xobj);
        sk_X509_CRL_free(sk);
        Exit(nil);
    end;
    X509_OBJECT_free(xobj);
    if 0>=X509_STORE_lock(store ) then  begin
        sk_X509_CRL_free(sk);
        Exit(nil);
    end;
    idx := x509_object_idx_cnt(store.objs, X509_LU_CRL, nm, @cnt);
    if idx < 0 then begin
        X509_STORE_unlock(store);
        sk_X509_CRL_free(sk);
        Exit(nil);
    end;
    for i := 0 to cnt-1 do
    begin
        obj := sk_X509_OBJECT_value(store.objs, idx);
        x := obj.data.crl;
        if 0>=X509_CRL_up_ref(x ) then  begin
            X509_STORE_unlock(store);
            sk_X509_CRL_pop_free(sk, X509_CRL_free);
            Exit(nil);
        end;
        if 0>=sk_X509_CRL_push(sk, x ) then  begin
            X509_STORE_unlock(store);
            X509_CRL_free(x);
            sk_X509_CRL_pop_free(sk, X509_CRL_free);
            Exit(nil);
        end;
        Inc(idx);
    end;
    X509_STORE_unlock(store);
    Result := sk;
end;


function X509_STORE_CTX_get1_certs(ctx : PX509_STORE_CTX;const nm : PX509_NAME):Pstack_st_X509;
var
  i, idx, cnt : integer;
  sk : Pstack_st_X509;
  x : PX509;
  obj : PX509_OBJECT;
  store : PX509_STORE;
  xobj : PX509_OBJECT;
begin
    sk := nil;
    store := ctx.store;
    if store = nil then Exit(nil);
    if 0>=X509_STORE_lock(store ) then
        Exit(nil);
    idx := x509_object_idx_cnt(store.objs, X509_LU_X509, nm, @cnt);
    if idx < 0 then begin
        {
         * Nothing found in cache: do lookup to possibly add new objects to
         * cache
         }
        xobj := X509_OBJECT_new;
        X509_STORE_unlock(store);
        if xobj = nil then Exit(nil);
        if 0>=X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, nm, xobj ) then
        begin
            X509_OBJECT_free(xobj);
            Exit(nil);
        end;
        X509_OBJECT_free(xobj);
        if 0>=X509_STORE_lock(store ) then
            Exit(nil);
        idx := x509_object_idx_cnt(store.objs, X509_LU_X509, nm, @cnt);
        if idx < 0 then begin
            X509_STORE_unlock(store);
            Exit(nil);
        end;
    end;
    sk := sk_X509_new_null;
    for i := 0 to cnt-1 do
    begin
        obj := sk_X509_OBJECT_value(store.objs, idx);
        x := obj.data.x509;
        if 0>=X509_add_cert(sk, x, X509_ADD_FLAG_UP_REF) then
        begin
            X509_STORE_unlock(store);
            OSSL_STACK_OF_X509_free(sk);
            Exit(nil);
        end;
        Inc(idx);
    end;
    X509_STORE_unlock(store);
    Result := sk;
end;



procedure x509_object_free_internal( a : PX509_OBJECT);
begin
    if a = nil then exit;
    case a.&type of
      X509_LU_NONE:
      begin
        //break;
      end;
      X509_LU_X509:
          X509_free(a.data.x509);
          //break;
      X509_LU_CRL:
          X509_CRL_free(a.data.crl);
          //break;
    end;
end;

procedure X509_OBJECT_free( a : PX509_OBJECT);
begin
    x509_object_free_internal(a);
    OPENSSL_free(a);
end;


function X509_OBJECT_up_ref_count( a : PX509_OBJECT):integer;
begin
    case a.&type of
        X509_LU_NONE:
        begin
           //break;
        end;
        X509_LU_X509:
            Exit(X509_up_ref(a.data.x509));
        X509_LU_CRL:
            Exit(X509_CRL_up_ref(a.data.crl));
    end;
    Result := 1;
end;




function X509_LOOKUP_by_subject_ex(ctx : PX509_LOOKUP; _type : X509_LOOKUP_TYPE;const name : PX509_NAME; ret : PX509_OBJECT; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    if (ctx.skip > 0)
         or  (ctx.method = nil)
         or  ( (not Assigned(ctx.method.get_by_subject))
             and  (not Assigned(ctx.method.get_by_subject_ex)) ) then
        Exit(0);
    if Assigned(ctx.method.get_by_subject_ex) then
       Exit(ctx.method.get_by_subject_ex(ctx, _type, name, ret, libctx, propq))
    else
        Result := ctx.method.get_by_subject(ctx, _type, name, ret);
end;




function X509_STORE_unlock( s : PX509_STORE):integer;
begin
    Result := CRYPTO_THREAD_unlock(s.lock);
end;

function x509_object_idx_cnt(h: Pstack_st_X509_OBJECT;_type : X509_LOOKUP_TYPE;const name : PX509_NAME; pnmatch : PInteger):integer;
var
  stmp : TX509_OBJECT;
  x509_s : TX509;
  crl_s : TX509_CRL;
  idx : integer;
begin
    stmp.&type := _type;
    case _type of
    X509_LU_X509:
    begin
        stmp.data.x509 := @x509_s;
        x509_s.cert_info.subject := PX509_NAME(name); { won't modify it }
    end;
    X509_LU_CRL:
    begin
        stmp.data.crl := @crl_s;
        crl_s.crl.issuer := PX509_NAME(name); { won't modify it }
    end;
    X509_LU_NONE:
        { abort; }
        Exit(-1);
    end;
    idx := sk_X509_OBJECT_find_all(h, @stmp, pnmatch);
    Result := idx;
end;


function X509_OBJECT_idx_by_subject(h: Pstack_st_X509_OBJECT;_type : X509_LOOKUP_TYPE;const name : PX509_NAME):integer;
begin
    Result := x509_object_idx_cnt(h, _type, name, nil);
end;




function X509_OBJECT_retrieve_by_subject(h: Pstack_st_X509_OBJECT;_type : X509_LOOKUP_TYPE;const name : PX509_NAME):PX509_OBJECT;
var
  idx : integer;
begin
    idx := X509_OBJECT_idx_by_subject(h, _type, name);
    if idx = -1 then Exit(nil);
    Result := sk_X509_OBJECT_value(h, idx);
end;

function X509_STORE_lock( s : PX509_STORE):integer;
begin
    Result := CRYPTO_THREAD_write_lock(s.lock);
end;




function X509_STORE_CTX_get_by_subject(const vs : PX509_STORE_CTX; _type : X509_LOOKUP_TYPE;const name : PX509_NAME; ret : PX509_OBJECT):integer;
var
  store : PX509_STORE;
  lu : PX509_LOOKUP;
  stmp : TX509_OBJECT;
  tmp : PX509_OBJECT;
  i, j : integer;
begin
    store := vs.store;
    if store = nil then Exit(0);
    stmp.&type := X509_LU_NONE;
    stmp.data.ptr := nil;
    if 0>=X509_STORE_lock(store) then
        Exit(0);
    tmp := X509_OBJECT_retrieve_by_subject(store.objs, _type, name);
    X509_STORE_unlock(store);
    if (tmp = nil)  or  (_type = X509_LU_CRL) then
    begin
        for i := 0 to sk_X509_LOOKUP_num(store.get_cert_methods)-1 do
        begin
            lu := sk_X509_LOOKUP_value(store.get_cert_methods, i);
            j := X509_LOOKUP_by_subject_ex(lu, _type, name, @stmp, vs.libctx,
                                          vs.propq);
            if j > 0 then
            begin
                tmp := @stmp;
                break;
            end;
        end;
        if tmp = nil then Exit(0);
    end;
    if 0>=X509_OBJECT_up_ref_count(tmp) then
        Exit(0);
    ret.&type := tmp.&type;
    ret.data.ptr := tmp.data.ptr;
    Result := 1;
end;

function X509_OBJECT_new:PX509_OBJECT;
var
  ret : PX509_OBJECT;
begin
    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.&type := X509_LU_NONE;
    Result := ret;
end;



function X509_STORE_CTX_get1_issuer( issuer : PPX509; ctx : PX509_STORE_CTX; x : PX509):integer;
var
  xn : PX509_NAME;
  obj, pobj : PX509_OBJECT;
  store : PX509_STORE;
  i, ok, idx, ret, nmatch : integer;
begin
    obj := X509_OBJECT_new;
     pobj := nil;
    store := ctx.store;
    nmatch := 0;
    if obj = nil then Exit(-1);
    issuer^ := nil;
    xn := X509_get_issuer_name(x);
    ok := X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, xn, obj);
    if ok <> 1 then
    begin
        X509_OBJECT_free(obj);
        Exit(0);
    end;
    { If certificate matches and is currently valid all OK }
    if ctx.check_issued(ctx, x, obj.data.x509) > 0 then
    begin
        if ossl_x509_check_cert_time(ctx, obj.data.x509, -1) > 0 then
        begin
            issuer^ := obj.data.x509;
            { |*issuer| has taken over the cert reference from |obj| }
            obj.&type := X509_LU_NONE;
            X509_OBJECT_free(obj);
            Exit(1);
        end;
    end;
    X509_OBJECT_free(obj);
    {
     * Due to limitations of the API this can only retrieve a single cert.
     * However it will fill the cache with all matching certificates,
     * so we can examine the cache for all matches.
     }
    if store = nil then Exit(0);
    { Find index of first currently valid cert accepted by 'check_issued' }
    ret := 0;
    if 0>=X509_STORE_lock(store) then
        Exit(0);
    idx := x509_object_idx_cnt(store.objs, X509_LU_X509, xn, @nmatch);
    if idx <> -1 then begin  { should be true as we've had at least one match }
        { Look through all matching certs for suitable issuer }
        for i := idx to idx + nmatch-1 do
        begin
            pobj := sk_X509_OBJECT_value(store.objs, i);
            { See if we've run past the matches }
            if pobj.&type <> X509_LU_X509 then break;
            if ctx.check_issued(ctx, x, pobj.data.x509 ) > 0 then begin
                ret := 1;
                { If times check fine, exit with match, else keep looking. }
                if ossl_x509_check_cert_time(ctx, pobj.data.x509, -1) > 0 then
                begin
                    issuer^ := pobj.data.x509;
                    break;
                end;
                {
                 * Leave the so far most recently expired match in *issuer
                 * so we return nearest match if no certificate time is OK.
                 }
                if (issuer^ = nil)
                     or  (ASN1_TIME_compare(X509_get0_notAfter(pobj.data.x509),
                                            X509_get0_notAfter( issuer^)) > 0) then
                    issuer^ := pobj.data.x509;
            end;
        end;
    end;
    if (issuer^ <> nil)  and  (0>=X509_up_ref( issuer^))  then
    begin
        issuer^ := nil;
        ret := -1;
    end;
    X509_STORE_unlock(store);
    Result := ret;
end;


end.
