unit openssl3.crypto.dh.dh_group_params;

interface
uses OpenSSL.Api;

 procedure ossl_dh_cache_named_group( dh : PDH);
 function ossl_dh_is_named_safe_prime_group(const dh : PDH):integer;
 function ossl_dh_new_by_nid_ex( libctx : POSSL_LIB_CTX; nid : integer):PDH;
 function dh_param_init(libctx : POSSL_LIB_CTX;const group : PDH_NAMED_GROUP):PDH;
 function DH_get_nid(const dh : PDH):integer;
  function DH_new_by_nid( nid : integer):PDH;

implementation

uses openssl3.crypto.ffc.ffc_dh, OpenSSL3.Err, openssl3.crypto.dh.dh_lib;





function DH_new_by_nid( nid : integer):PDH;
begin
    Result := ossl_dh_new_by_nid_ex(nil, nid);
end;





function DH_get_nid(const dh : PDH):integer;
begin
    if dh = nil then Exit(NID_undef);
    Result := dh.params.nid;
end;

function dh_param_init(libctx : POSSL_LIB_CTX;const group : PDH_NAMED_GROUP):PDH;
var
  dh : PDH;
begin
    dh := ossl_dh_new_ex(libctx);
    if dh = nil then Exit(nil);
    ossl_ffc_named_group_set_pqg(@dh.params, group);
    dh.params.nid := ossl_ffc_named_group_get_uid(group);
    Inc(dh.dirty_cnt);
    Result := dh;
end;

function ossl_dh_new_by_nid_ex( libctx : POSSL_LIB_CTX; nid : integer):PDH;
var
  group : PDH_NAMED_GROUP;
begin
    group := ossl_ffc_uid_to_dh_named_group(nid );
    if group <> nil then
        Exit(dh_param_init(libctx, group));
    ERR_raise(ERR_LIB_DH, DH_R_INVALID_PARAMETER_NID);
    Result := nil;
end;

function ossl_dh_is_named_safe_prime_group(const dh : PDH):integer;
var
  id : integer;
begin
    id := DH_get_nid(dh);
    {
     * Exclude RFC5114 groups (id = 1..3) since they do not have
     * q = (p - 1) / 2
     }
    Result := int(id > 3);
end;

procedure ossl_dh_cache_named_group( dh : PDH);
var
  group: PDH_NAMED_GROUP;
begin
    if dh = nil then exit;
    dh.params.nid := NID_undef; { flush cached value }
    { Exit if p or g is not set }
    if (dh.params.p = nil)
         or  (dh.params.g = nil) then exit;
    group := ossl_ffc_numbers_to_dh_named_group(dh.params.p,
                                                    dh.params.q,
                                                    dh.params.g );
    if (group <> nil)then
    begin
        if dh.params.q = nil then
            dh.params.q := PBIGNUM ( ossl_ffc_named_group_get_q(group));
        { cache the nid }
        dh.params.nid := ossl_ffc_named_group_get_uid(group);
        Inc(dh.dirty_cnt);
    end;
end;

end.
