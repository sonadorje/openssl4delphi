unit openssl3.crypto.ffc.ffc_dh;

interface
uses OpenSSL.Api;



  const // 1d arrays
  dh_named_groups : array[0..13] of TDH_NAMED_GROUP = (
    (name:SN_ffdhe2048; uid:NID_ffdhe2048; nbits:2048; p:@ossl_bignum_ffdhe2048_p; q:@ossl_bignum_ffdhe2048_q; g:@ossl_bignum_const_2),
    (name:SN_ffdhe3072; uid:NID_ffdhe3072; nbits:3072; p:@ossl_bignum_ffdhe3072_p; q:@ossl_bignum_ffdhe3072_q; g:@ossl_bignum_const_2),
    (name:SN_ffdhe4096; uid:NID_ffdhe4096; nbits:4096; p:@ossl_bignum_ffdhe4096_p; q:@ossl_bignum_ffdhe4096_q; g:@ossl_bignum_const_2),
    (name:SN_ffdhe6144; uid:NID_ffdhe6144; nbits:6144; p:@ossl_bignum_ffdhe6144_p; q:@ossl_bignum_ffdhe6144_q; g:@ossl_bignum_const_2),
    (name:SN_ffdhe8192; uid:NID_ffdhe8192; nbits:8192; p:@ossl_bignum_ffdhe8192_p; q:@ossl_bignum_ffdhe8192_q; g:@ossl_bignum_const_2),
    {$ifndef FIPS_MODULE}
    (name:SN_modp_1536; uid:NID_modp_1536; nbits:1536; p: @ossl_bignum_modp_1536_p; q: @ossl_bignum_modp_1536_q; g: @ossl_bignum_const_2 ),
    {$endif}
    (name:SN_modp_2048; uid:NID_modp_2048; nbits:2048; p: @ossl_bignum_modp_2048_p; q: @ossl_bignum_modp_2048_q; g: @ossl_bignum_const_2 ),
    (name:SN_modp_3072; uid:NID_modp_3072; nbits:3072; p: @ossl_bignum_modp_3072_p; q: @ossl_bignum_modp_3072_q; g: @ossl_bignum_const_2 ),
    (name:SN_modp_4096; uid:NID_modp_4096; nbits:4096; p: @ossl_bignum_modp_4096_p; q: @ossl_bignum_modp_4096_q; g: @ossl_bignum_const_2 ),
    (name:SN_modp_6144; uid:NID_modp_6144; nbits:6144; p: @ossl_bignum_modp_6144_p; q: @ossl_bignum_modp_6144_q; g: @ossl_bignum_const_2 ),
    (name:SN_modp_8192; uid:NID_modp_8192; nbits:8192; p: @ossl_bignum_modp_8192_p; q: @ossl_bignum_modp_8192_q; g: @ossl_bignum_const_2 ),
    {$ifndef FIPS_MODULE}
    (name:'dh_1024_160'; uid:1; nbits:1024; p: @ossl_bignum_dh1024_160_p; q: @ossl_bignum_dh1024_160_q; g: @ossl_bignum_dh1024_160_g ),
    (name:'dh_2048_224'; uid:2; nbits:2048; p: @ossl_bignum_dh2048_224_p; q: @ossl_bignum_dh2048_224_q; g: @ossl_bignum_dh2048_224_g ),
    (name:'dh_2048_256'; uid:3; nbits:2048; p: @ossl_bignum_dh2048_256_p; q: @ossl_bignum_dh2048_256_q; g: @ossl_bignum_dh2048_256_g )
    {$endif}
    );

function ossl_ffc_name_to_dh_named_group(const name : PUTF8Char):PDH_NAMED_GROUP;
function ossl_ffc_uid_to_dh_named_group( uid : integer):PDH_NAMED_GROUP;
function ossl_ffc_named_group_get_name(const group : PDH_NAMED_GROUP):PUTF8Char;
function ossl_ffc_named_group_set_pqg(ffc : PFFC_PARAMS;const group : PDH_NAMED_GROUP):integer;
function ossl_ffc_numbers_to_dh_named_group(const p, q, g : PBIGNUM):PDH_NAMED_GROUP;
function ossl_ffc_named_group_get_q(const group : PDH_NAMED_GROUP):PBIGNUM;
function ossl_ffc_named_group_get_uid(const group : PDH_NAMED_GROUP):integer;


implementation
uses openssl3.crypto.ffc.ffc_params, openssl3.crypto.bn.bn_lib;


function ossl_ffc_named_group_get_uid(const group : PDH_NAMED_GROUP):integer;
begin
    if group = nil then Exit(NID_undef);
    Result := group.uid;
end;

function ossl_ffc_named_group_get_q(const group : PDH_NAMED_GROUP):PBIGNUM;
begin
    if group = nil then Exit(nil);
    Result := group.q;
end;




function ossl_ffc_numbers_to_dh_named_group(const p, q, g : PBIGNUM):PDH_NAMED_GROUP;
var
  i : size_t;
begin
    for i := 0 to Length(dh_named_groups)-1 do
    begin
        { Keep searching until a matching p and g is found }
        if (BN_cmp(p, dh_named_groups[i].p)  = 0 )
             and  (BN_cmp(g, dh_named_groups[i].g) = 0 )
            { Verify q is correct if it exists }
             and  ( (q = nil)  or  (BN_cmp(q, dh_named_groups[i].q) = 0)) then
            Exit(@dh_named_groups[i]);
    end;
    Result := nil;
end;

function ossl_ffc_named_group_set_pqg(ffc : PFFC_PARAMS;const group : PDH_NAMED_GROUP):integer;
begin
    if (ffc = nil)  or  (group = nil) then Exit(0);
    ossl_ffc_params_set0_pqg(ffc, PBIGNUM ( group.p), PBIGNUM ( group.q),
                             PBIGNUM ( group.g));
    { flush the cached nid, The DH layer is responsible for caching }
    ffc.nid := NID_undef;
    Result := 1;
end;






function ossl_ffc_named_group_get_name(const group : PDH_NAMED_GROUP):PUTF8Char;
begin
    if group = nil then
       Exit(nil);
    Result := group.name;
end;



function ossl_ffc_uid_to_dh_named_group( uid : integer):PDH_NAMED_GROUP;
var
  i : size_t;
begin
    for I := 0 to Length(dh_named_groups)-1 do
    begin
        if dh_named_groups[i].uid = uid then
           Exit(@dh_named_groups[i]);
    end;
    Result := nil;
end;




function ossl_ffc_name_to_dh_named_group(const name : PUTF8Char):PDH_NAMED_GROUP;
var
  i : size_t;
begin
    for i := 0  TO Length(dh_named_groups)-1 do
    begin
        if strcasecmp(dh_named_groups[i].name, name)= 0  then
            Exit(@dh_named_groups[i]);
    end;
    Result := nil;
end;


end.
