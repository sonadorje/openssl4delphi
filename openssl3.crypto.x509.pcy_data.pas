unit openssl3.crypto.x509.pcy_data;

interface
uses OpenSSL.Api;

 procedure ossl_policy_data_free( data : PX509_POLICY_DATA);
  function ossl_policy_data_new(policy : PPOLICYINFO;const cid : PASN1_OBJECT; crit : integer):PX509_POLICY_DATA;

implementation
uses openssl3.crypto.asn1.a_object, openssl3.crypto.x509v3,
     OpenSSL3.crypto.x509.v3_cpols, OpenSSL3.include.openssl.asn1,
     OpenSSL3.Err,
     openssl3.crypto.mem, openssl3.crypto.objects.obj_lib;

procedure ossl_policy_data_free( data : PX509_POLICY_DATA);
begin
    if data = nil then exit;
    ASN1_OBJECT_free(data.valid_policy);
    { Don't free qualifiers if shared }
    if 0>=(data.flags and POLICY_DATA_FLAG_SHARED_QUALIFIERS) then
        sk_POLICYQUALINFO_pop_free(data.qualifier_set, POLICYQUALINFO_free);
    sk_ASN1_OBJECT_pop_free(data.expected_policy_set, ASN1_OBJECT_free);
    OPENSSL_free(data);
end;


function ossl_policy_data_new(policy : PPOLICYINFO;const cid : PASN1_OBJECT; crit : integer):PX509_POLICY_DATA;
var
  ret : PX509_POLICY_DATA;
  id : PASN1_OBJECT;
begin
    if (policy = nil)  and  (cid = nil) then
       Exit(nil);
    if cid <> nil then
    begin
        id := OBJ_dup(cid);
        if id = nil then Exit(nil);
    end
    else
        id := nil;

    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then
    begin
        ASN1_OBJECT_free(id);
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.expected_policy_set := sk_ASN1_OBJECT_new_null;
    if ret.expected_policy_set = nil then
    begin
        OPENSSL_free(ret);
        ASN1_OBJECT_free(id);
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if crit > 0 then
       ret.flags := POLICY_DATA_FLAG_CRITICAL;
    if id <> nil then
       ret.valid_policy := id
    else
    begin
        ret.valid_policy := policy.policyid;
        policy.policyid := nil;
    end;
    if policy <> nil then
    begin
        ret.qualifier_set := policy.qualifiers;
        policy.qualifiers := nil;
    end;
    Result := ret;
end;


end.
