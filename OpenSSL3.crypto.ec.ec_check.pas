unit OpenSSL3.crypto.ec.ec_check;

interface
uses OpenSSL.Api;

function EC_GROUP_check_named_curve(const group : PEC_GROUP; nist_only : integer; ctx : PBN_CTX):integer;
function EC_GROUP_check(const group : PEC_GROUP; ctx : PBN_CTX):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec_curve,
     openssl3.crypto.ec.ec_lib, openssl3.crypto.bn.bn_lib;






function EC_GROUP_check(const group : PEC_GROUP; ctx : PBN_CTX):integer;
var
  ret : integer;
  order : PBIGNUM;
  new_ctx : PBN_CTX;
  point : PEC_POINT;
  label _err;
begin
{$IFDEF FIPS_MODULE}
    {
    * ECC domain parameter validation.
    * See SP800-56A R3 5.5.2 'Assurances of Domain-Parameter Validity' Part 1b.
    }
    Exit(EC_GROUP_check_named_curve(group, 1, ctx) >= 0 ? 1 : 0);
{$ELSE} ret := 0;
    new_ctx := nil;
    point := nil;
    if (group = nil)  or  (group.meth = nil) then begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { Custom curves assumed to be correct }
    if group.meth.flags and EC_FLAGS_CUSTOM_CURVE  <> 0 then
        Exit(1);
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new();
        ctx := new_ctx ;
        if ctx = nil then begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
    end;
    { check the discriminant }
    if 0>=EC_GROUP_check_discriminant(group, ctx) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_DISCRIMINANT_IS_ZERO);
        goto _err;
    end;
    { check the generator }
    if group.generator = nil then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
        goto _err;
    end;
    if EC_POINT_is_on_curve(group, group.generator, ctx) <= 0  then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        goto _err;
    end;
    { check the order of the generator }
    point := EC_POINT_new(group);
    if point = nil then
        goto _err;
    order := EC_GROUP_get0_order(group);
    if order = nil then goto _err;
    if BN_is_zero(order) then  begin
        ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_ORDER);
        goto _err;
    end;
    if 0>=EC_POINT_mul(group, point, order, nil, nil, ctx) then
        goto _err;
    if 0>=EC_POINT_is_at_infinity(group, point) then
    begin
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto _err;
    end;
    ret := 1;
 _err:
    BN_CTX_free(new_ctx);
    EC_POINT_free(point);
    Exit(ret);
{$endif} { FIPS_MODULE }
end;

function EC_GROUP_check_named_curve(const group : PEC_GROUP; nist_only : integer; ctx : PBN_CTX):integer;
var
  nid : integer;

  new_ctx : PBN_CTX;
begin
    new_ctx := nil;
    if group = nil then
    begin
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        Exit(NID_undef);
    end;
    if ctx = nil then
    begin
        new_ctx := BN_CTX_new_ex(nil);
        ctx := new_ctx;
        if ctx = nil then
        begin
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            Exit(NID_undef);
        end;
    end;
    nid := ossl_ec_curve_nid_from_params(group, ctx);
    if (nid > 0)  and  (nist_only>0)  and  (EC_curve_nid2nist(nid) = nil) then
        nid := NID_undef;
    BN_CTX_free(new_ctx);
    Result := nid;
end;

end.
