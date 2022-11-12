unit openssl3.crypto.ec.ec_cvt;

interface
uses OpenSSL.Api;

 function EC_GROUP_new_curve_GFp(const p, a, b : PBIGNUM; ctx : PBN_CTX):PEC_GROUP;
  function EC_GROUP_new_curve_GF2m(const p, a, b : PBIGNUM; ctx : PBN_CTX):PEC_GROUP;

implementation
uses
   openssl3.crypto.bn.bn_nist, openssl3.crypto.ec.ecp_nist,
   openssl3.crypto.ec.ecp_mont, openssl3.crypto.ec.ec_lib,
   openssl3.crypto.bn.bn_ctx, openssl3.crypto.ec.ec2_smpl;

function EC_GROUP_new_curve_GFp(const p, a, b : PBIGNUM; ctx : PBN_CTX):PEC_GROUP;
var
  meth : PEC_METHOD;

  ret : PEC_GROUP;
begin
{$IF defined(OPENSSL_BN_ASM_MONT)}
    {
     * This might appear controversial, but the fact is that generic
     * prime method was observed to deliver better performance even
     * for NIST primes on a range of platforms, e.g.: 60%-15%
     * improvement on IA-64, ~25% on ARM, 30%-90% on P4, 20%-25%
     * in 32-bit build and 35%PreDec(12)% in 64-bit build on Core2...
     * Coefficients are relative to optimized bn_nist.c for most
     * intensive ECDSA verify and ECDH operations for 192- and 521-
     * bit keys respectively. Choice of these boundary values is
     * arguable, because the dependency of improvement coefficient
     * from key length is not a 'monotone' curve. For example while
     * 571-bit result is 23% on ARM, 384-bit one is -1%. But it's
     * generally faster, sometimes 'respectfully' faster, sometimes
     * 'tolerably' slower... What effectively happens is that loop
     * with bn_mul_add_words is put against bn_mul_mont, and the
     * latter 'wins' on short vectors. Correct solution should be
     * implementing dedicated NxN multiplication subroutines for
     * small N. But till it materializes, let's stick to generic
     * prime method...
     *                                              <appro>
     }
    meth := EC_GFp_mont_method();
{$ELSE}
    if Assigned(BN_nist_mod_func(p)) then
        meth := EC_GFp_nist_method()
    else
        meth := EC_GFp_mont_method();
{$ENDIF}
    ret := ossl_ec_group_new_ex(ossl_bn_get_libctx(ctx), nil, meth);
    if ret = nil then Exit(nil);
    if 0>= EC_GROUP_set_curve(ret, p, a, b, ctx ) then
    begin
        EC_GROUP_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;


function EC_GROUP_new_curve_GF2m(const p, a, b : PBIGNUM; ctx : PBN_CTX):PEC_GROUP;
var
  meth : PEC_METHOD;

  ret : PEC_GROUP;
begin
    meth := EC_GF2m_simple_method();
    ret := ossl_ec_group_new_ex(ossl_bn_get_libctx(ctx), nil, meth);
    if ret = nil then Exit(nil);
    if 0>= EC_GROUP_set_curve(ret, p, a, b, ctx) then
    begin
        EC_GROUP_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;


end.
