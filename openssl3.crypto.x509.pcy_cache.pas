unit openssl3.crypto.x509.pcy_cache;

interface
 uses OpenSSL.Api;

  function policy_cache_create( x : PX509; policies : PCERTIFICATEPOLICIES; crit : integer):integer;
  function policy_cache_new( x : PX509):integer;
  procedure ossl_policy_cache_free( cache : PX509_POLICY_CACHE);
  function ossl_policy_cache_set( x : PX509):PX509_POLICY_CACHE;
  function ossl_policy_cache_find_data(const cache : PX509_POLICY_CACHE; id : PASN1_OBJECT):PX509_POLICY_DATA;
  function policy_data_cmp(const a, b : PPX509_POLICY_DATA):integer;
  function policy_cache_set_int( _out : Plong; value : PASN1_INTEGER):integer;

  function sk_X509_POLICY_DATA_num(const sk : Pstack_st_X509_POLICY_DATA):integer;
  function sk_X509_POLICY_DATA_value(const sk : Pstack_st_X509_POLICY_DATA; idx : integer):PX509_POLICY_DATA;
  function sk_X509_POLICY_DATA_new( compare : sk_X509_POLICY_DATA_compfunc):Pstack_st_X509_POLICY_DATA;
  function sk_X509_POLICY_DATA_new_null:Pstack_st_X509_POLICY_DATA;
  function sk_X509_POLICY_DATA_new_reserve( compare : sk_X509_POLICY_DATA_compfunc; n : integer):Pstack_st_X509_POLICY_DATA;
  function sk_X509_POLICY_DATA_reserve( sk : Pstack_st_X509_POLICY_DATA; n : integer):integer;
  procedure sk_X509_POLICY_DATA_free( sk : Pstack_st_X509_POLICY_DATA);
  procedure sk_X509_POLICY_DATA_zero( sk : Pstack_st_X509_POLICY_DATA);
  function sk_X509_POLICY_DATA_delete( sk : Pstack_st_X509_POLICY_DATA; i : integer):PX509_POLICY_DATA;
  function sk_X509_POLICY_DATA_delete_ptr( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):PX509_POLICY_DATA;
  function sk_X509_POLICY_DATA_push( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
  function sk_X509_POLICY_DATA_unshift( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
  function sk_X509_POLICY_DATA_pop( sk : Pstack_st_X509_POLICY_DATA):PX509_POLICY_DATA;
  function sk_X509_POLICY_DATA_shift( sk : Pstack_st_X509_POLICY_DATA):PX509_POLICY_DATA;
  procedure sk_X509_POLICY_DATA_pop_free( sk : Pstack_st_X509_POLICY_DATA; freefunc : sk_X509_POLICY_DATA_freefunc);
  function sk_X509_POLICY_DATA_insert( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA; idx : integer):integer;
  function sk_X509_POLICY_DATA_set( sk : Pstack_st_X509_POLICY_DATA; idx : integer; ptr : PX509_POLICY_DATA):PX509_POLICY_DATA;
  function sk_X509_POLICY_DATA_find( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
  function sk_X509_POLICY_DATA_find_ex( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
  function sk_X509_POLICY_DATA_find_all( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA; pnum : PInteger):integer;
  procedure sk_X509_POLICY_DATA_sort( sk : Pstack_st_X509_POLICY_DATA);
  function sk_X509_POLICY_DATA_is_sorted(const sk : Pstack_st_X509_POLICY_DATA):integer;
  function sk_X509_POLICY_DATA_dup(const sk : Pstack_st_X509_POLICY_DATA):Pstack_st_X509_POLICY_DATA;
  function sk_X509_POLICY_DATA_deep_copy(const sk : Pstack_st_X509_POLICY_DATA; copyfunc : sk_X509_POLICY_DATA_copyfunc; freefunc : sk_X509_POLICY_DATA_freefunc):Pstack_st_X509_POLICY_DATA;
  function sk_X509_POLICY_DATA_set_cmp_func( sk : Pstack_st_X509_POLICY_DATA; compare : sk_X509_POLICY_DATA_compfunc):sk_X509_POLICY_DATA_compfunc;

implementation
 uses openssl3.crypto.x509v3, openssl3.crypto.stack, OpenSSL3.Err,
      OpenSSL3.crypto.x509.v3_cpols,  openssl3.crypto.mem,
      OpenSSL3.threads_none, openssl3.crypto.objects.obj_lib,
      openssl3.crypto.asn1.a_int,
      OpenSSL3.crypto.x509.v3_pcons,  openssl3.crypto.asn1.tasn_typ,
      OpenSSL3.crypto.x509.x509_ext,  openssl3.crypto.x509.pcy_map,
      openssl3.crypto.x509.pcy_data, openssl3.crypto.objects.obj_dat;


function sk_X509_POLICY_DATA_num(const sk : Pstack_st_X509_POLICY_DATA):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;


function sk_X509_POLICY_DATA_value(const sk : Pstack_st_X509_POLICY_DATA; idx : integer):PX509_POLICY_DATA;
begin
 Result := PX509_POLICY_DATA(OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;


function sk_X509_POLICY_DATA_new( compare : sk_X509_POLICY_DATA_compfunc):Pstack_st_X509_POLICY_DATA;
begin
 Result := Pstack_st_X509_POLICY_DATA(OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_X509_POLICY_DATA_new_null:Pstack_st_X509_POLICY_DATA;
begin
 Result := Pstack_st_X509_POLICY_DATA (OPENSSL_sk_new_null);
end;


function sk_X509_POLICY_DATA_new_reserve( compare : sk_X509_POLICY_DATA_compfunc; n : integer):Pstack_st_X509_POLICY_DATA;
begin
 Result := Pstack_st_X509_POLICY_DATA (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_X509_POLICY_DATA_reserve( sk : Pstack_st_X509_POLICY_DATA; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK(sk), n));
end;


procedure sk_X509_POLICY_DATA_free( sk : Pstack_st_X509_POLICY_DATA);
begin
 OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_X509_POLICY_DATA_zero( sk : Pstack_st_X509_POLICY_DATA);
begin
 OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;


function sk_X509_POLICY_DATA_delete( sk : Pstack_st_X509_POLICY_DATA; i : integer):PX509_POLICY_DATA;
begin
 Result := PX509_POLICY_DATA (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_X509_POLICY_DATA_delete_ptr( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):PX509_POLICY_DATA;
begin
 Result := PX509_POLICY_DATA (OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_X509_POLICY_DATA_push( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_X509_POLICY_DATA_unshift( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_X509_POLICY_DATA_pop( sk : Pstack_st_X509_POLICY_DATA):PX509_POLICY_DATA;
begin
 Result := PX509_POLICY_DATA (OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_X509_POLICY_DATA_shift( sk : Pstack_st_X509_POLICY_DATA):PX509_POLICY_DATA;
begin
 Result := PX509_POLICY_DATA (OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;


procedure sk_X509_POLICY_DATA_pop_free( sk : Pstack_st_X509_POLICY_DATA; freefunc : sk_X509_POLICY_DATA_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_X509_POLICY_DATA_insert( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer(ptr), idx));
end;


function sk_X509_POLICY_DATA_set( sk : Pstack_st_X509_POLICY_DATA; idx : integer; ptr : PX509_POLICY_DATA):PX509_POLICY_DATA;
begin
 Result := PX509_POLICY_DATA (OPENSSL_sk_set(POPENSSL_STACK(sk), idx, Pointer(ptr)));
end;


function sk_X509_POLICY_DATA_find( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_X509_POLICY_DATA_find_ex( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_X509_POLICY_DATA_find_all( sk : Pstack_st_X509_POLICY_DATA; ptr : PX509_POLICY_DATA; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK(sk), Pointer(ptr), pnum));
end;


procedure sk_X509_POLICY_DATA_sort( sk : Pstack_st_X509_POLICY_DATA);
begin
 OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_X509_POLICY_DATA_is_sorted(const sk : Pstack_st_X509_POLICY_DATA):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK(sk)));
end;


function sk_X509_POLICY_DATA_dup(const sk : Pstack_st_X509_POLICY_DATA):Pstack_st_X509_POLICY_DATA;
begin
 Result := Pstack_st_X509_POLICY_DATA (OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;


function sk_X509_POLICY_DATA_deep_copy(const sk : Pstack_st_X509_POLICY_DATA; copyfunc : sk_X509_POLICY_DATA_copyfunc; freefunc : sk_X509_POLICY_DATA_freefunc):Pstack_st_X509_POLICY_DATA;
begin
 Result := Pstack_st_X509_POLICY_DATA (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
                 OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)));
end;


function sk_X509_POLICY_DATA_set_cmp_func( sk : Pstack_st_X509_POLICY_DATA; compare : sk_X509_POLICY_DATA_compfunc):sk_X509_POLICY_DATA_compfunc;
begin
 Result := sk_X509_POLICY_DATA_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
                               OPENSSL_sk_compfunc(compare)));
end;

function policy_cache_create( x : PX509; policies : PCERTIFICATEPOLICIES; crit : integer):integer;
var
  i, num, ret : integer;
  cache : PX509_POLICY_CACHE;
  data : PX509_POLICY_DATA;
  policy : PPOLICYINFO;
  label _just_cleanup, _bad_policy;
begin
    ret := 0;
    cache := x.policy_cache;
    data := nil;
    num := sk_POLICYINFO_num(policies);
    if num <= 0 then
        goto _bad_policy;
    cache.data := sk_X509_POLICY_DATA_new(policy_data_cmp);
    if cache.data = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto _just_cleanup;
    end;
    for i := 0 to num-1 do
    begin
        policy := sk_POLICYINFO_value(policies, i);
        data := ossl_policy_data_new(policy, nil, crit);
        if data = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _just_cleanup;
        end;
        {
         * Duplicate policy OIDs are illegal: reject if matches found.
         }
        if OBJ_obj2nid(data.valid_policy) = NID_any_policy  then
        begin
            if cache.anyPolicy <> nil then
            begin
                ret := -1;
                goto _bad_policy;
            end;
            cache.anyPolicy := data;
        end
        else
        if (sk_X509_POLICY_DATA_find(cache.data, data) >=0) then
        begin
            ret := -1;
            goto _bad_policy;
        end
        else
        if (0>=sk_X509_POLICY_DATA_push(cache.data, data)) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _bad_policy;
        end;
        data := nil;
    end;
    ret := 1;
 _bad_policy:
    if ret = -1 then
       x.ex_flags  := x.ex_flags  or EXFLAG_INVALID_POLICY;
    ossl_policy_data_free(data);
 _just_cleanup:
    sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
    if ret <= 0 then
    begin
        sk_X509_POLICY_DATA_pop_free(cache.data, ossl_policy_data_free);
        cache.data := nil;
    end;
    Result := ret;
end;


function policy_cache_new( x : PX509):integer;
var
    cache     : PX509_POLICY_CACHE;
    ext_any   : PASN1_INTEGER;
    ext_pcons : PPOLICY_CONSTRAINTS;
    ext_cpols : PCERTIFICATEPOLICIES;
    ext_pmaps : PPOLICY_MAPPINGS;
    i         : integer;
    label _bad_cache, _just_cleanup;
begin
    ext_any := nil;
    ext_pcons := nil;
    ext_cpols := nil;
    ext_pmaps := nil;
    if x.policy_cache <> nil then Exit(1);
    cache := OPENSSL_malloc(sizeof( cache^));
    if cache = nil then begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    cache.anyPolicy := nil;
    cache.data := nil;
    cache.any_skip := -1;
    cache.explicit_skip := -1;
    cache.map_skip := -1;
    x.policy_cache := cache;
    {
     * Handle requireExplicitPolicy *first*. Need to process this even if we
     * don't have any policies.
     }
    ext_pcons := X509_get_ext_d2i(x, NID_policy_constraints, @i, nil);
    if nil =ext_pcons then
    begin
        if i <> -1 then
            goto _bad_cache;
    end
    else
    begin
        if (nil =ext_pcons.requireExplicitPolicy)
             and  (nil =ext_pcons.inhibitPolicyMapping) then
             goto _bad_cache;
        if 0>=policy_cache_set_int(@cache.explicit_skip,
                                  ext_pcons.requireExplicitPolicy) then
            goto _bad_cache;
        if 0>=policy_cache_set_int(@cache.map_skip,
                                  ext_pcons.inhibitPolicyMapping) then
            goto _bad_cache;
    end;
    { Process CertificatePolicies }
    ext_cpols := X509_get_ext_d2i(x, NID_certificate_policies, @i, nil);
    {
     * If no CertificatePolicies extension or problem decoding then there is
     * no point continuing because the valid policies will be nil.
     }
    if nil =ext_cpols then
    begin
        { If not absent some problem with extension }
        if i <> -1 then
            goto _bad_cache;
        Exit(1);
    end;
    i := policy_cache_create(x, ext_cpols, i);
    { NB: ext_cpols freed by policy_cache_set_policies }
    if i <= 0 then Exit(i);
    ext_pmaps := X509_get_ext_d2i(x, NID_policy_mappings, @i, nil);
    if nil =ext_pmaps then
    begin
        { If not absent some problem with extension }
        if i <> -1 then
            goto _bad_cache;
    end
    else
    begin
        i := ossl_policy_cache_set_mapping(x, ext_pmaps);
        if i <= 0 then goto _bad_cache;
    end;
    ext_any := X509_get_ext_d2i(x, NID_inhibit_any_policy, @i, nil);
    if nil =ext_any then
    begin
        if i <> -1 then
            goto _bad_cache;
    end
    else
    if (0>=policy_cache_set_int(@cache.any_skip, ext_any)) then
        goto _bad_cache;
    goto _just_cleanup;

 _bad_cache:
    x.ex_flags  := x.ex_flags  or EXFLAG_INVALID_POLICY;
 _just_cleanup:
    POLICY_CONSTRAINTS_free(ext_pcons);
    ASN1_INTEGER_free(ext_any);
    Exit(1);
end;


procedure ossl_policy_cache_free( cache : PX509_POLICY_CACHE);
begin
    if nil = cache then exit;
    ossl_policy_data_free(cache.anyPolicy);
    sk_X509_POLICY_DATA_pop_free(cache.data, ossl_policy_data_free);
    OPENSSL_free(cache);
end;


function ossl_policy_cache_set( x : PX509):PX509_POLICY_CACHE;
begin
    if x.policy_cache = nil then
    begin
        if 0>=CRYPTO_THREAD_write_lock(x.lock) then
            Exit(nil);
        policy_cache_new(x);
        CRYPTO_THREAD_unlock(x.lock);
    end;
    Exit(x.policy_cache);
end;


function ossl_policy_cache_find_data(const cache : PX509_POLICY_CACHE; id : PASN1_OBJECT):PX509_POLICY_DATA;
var
  idx : integer;

  tmp : TX509_POLICY_DATA;
begin
    tmp.valid_policy := PASN1_OBJECT (id);
    idx := sk_X509_POLICY_DATA_find(cache.data, @tmp);
    Result := sk_X509_POLICY_DATA_value(cache.data, idx);
end;


function policy_data_cmp(const a, b : PPX509_POLICY_DATA):integer;
begin
    Result := _OBJ_cmp((a^).valid_policy, (b^).valid_policy);
end;


function policy_cache_set_int( _out : Plong; value : PASN1_INTEGER):integer;
begin
    if value = nil then Exit(1);
    if value.&type = V_ASN1_NEG_INTEGER then Exit(0);
    _out^ := ASN1_INTEGER_get(value);
    Result := 1;
end;

end.
