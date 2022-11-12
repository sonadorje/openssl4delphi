unit openssl3.crypto.x509.pcy_map;

interface
uses OpenSSL.Api;

function ossl_policy_cache_set_mapping( x : PX509; maps : PPOLICY_MAPPINGS):integer;

implementation
uses OpenSSL3.crypto.x509v3, openssl3.crypto.objects.obj_dat,
     OpenSSL3.include.openssl.asn1, OpenSSL3.threads_none,
     OpenSSL3.crypto.x509.v3_pmaps,
     openssl3.crypto.x509.pcy_cache, openssl3.crypto.x509.pcy_data;

function ossl_policy_cache_set_mapping( x : PX509; maps : PPOLICY_MAPPINGS):integer;
var
  map : PPOLICY_MAPPING;
  data : PX509_POLICY_DATA;
  cache : PX509_POLICY_CACHE;
  i, ret : integer;
  label _bad_mapping;
begin
    cache := x.policy_cache;
    ret := 0;
    if sk_POLICY_MAPPING_num(maps) = 0  then
    begin
        ret := -1;
        goto _bad_mapping;
    end;
    for i := 0 to sk_POLICY_MAPPING_num(maps)-1 do
    begin
        map := sk_POLICY_MAPPING_value(maps, i);
        { Reject if map to or from anyPolicy }
        if (OBJ_obj2nid(map.subjectDomainPolicy) = NID_any_policy )
             or  (OBJ_obj2nid(map.issuerDomainPolicy) = NID_any_policy) then
        begin
            ret := -1;
            goto _bad_mapping;
        end;
        { Attempt to find matching policy data }
        data := ossl_policy_cache_find_data(cache, map.issuerDomainPolicy);
        { If we don't have anyPolicy can't map }
        if (data = nil)  and  (nil =cache.anyPolicy) then
           continue;
        { Create a NODE from anyPolicy }
        if data = nil then
        begin
            data := ossl_policy_data_new(nil, map.issuerDomainPolicy,
                                        cache.anyPolicy.flags
                                        and POLICY_DATA_FLAG_CRITICAL);
            if data = nil then goto _bad_mapping;
            data.qualifier_set := cache.anyPolicy.qualifier_set;
            {
             * map.issuerDomainPolicy = nil;
             }
            data.flags  := data.flags  or POLICY_DATA_FLAG_MAPPED_ANY;
            data.flags  := data.flags  or POLICY_DATA_FLAG_SHARED_QUALIFIERS;
            if 0>=sk_X509_POLICY_DATA_push(cache.data, data ) then
            begin
                ossl_policy_data_free(data);
                goto _bad_mapping;
            end;
        end
        else
            data.flags  := data.flags  or POLICY_DATA_FLAG_MAPPED;
        if 0>=sk_ASN1_OBJECT_push(data.expected_policy_set,
                                 map.subjectDomainPolicy) then
            goto _bad_mapping;
        map.subjectDomainPolicy := nil;
    end;
    ret := 1;
 _bad_mapping:
    if (ret = -1)  and  (CRYPTO_THREAD_write_lock(x.lock) > 0) then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID_POLICY;
        CRYPTO_THREAD_unlock(x.lock);
    end;
    sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
    Exit(ret);
end;


end.
