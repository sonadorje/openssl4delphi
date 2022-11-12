unit OpenSSL3.providers.common.securitycheck;
{$I config.inc}
interface
uses OpenSSL.Api, SysUtils, Variants;

 function ossl_digest_is_allowed(ctx : POSSL_LIB_CTX;const md : PEVP_MD):Boolean;
 function ossl_dh_check_key(ctx : POSSL_LIB_CTX;const dh : PDH):integer;
 function ossl_ec_check_key(ctx : POSSL_LIB_CTX;const ec : PEC_KEY; protect : integer):integer;
 function ossl_digest_get_approved_nid_with_sha1(ctx : POSSL_LIB_CTX;const md : PEVP_MD; sha1_allowed : integer):integer;
 function ossl_dsa_check_key(ctx : POSSL_LIB_CTX;const dsa : PDSA; sign : integer):integer;
 function ossl_rsa_check_key(ctx : POSSL_LIB_CTX;const rsa : PRSA; operation : integer):integer;

implementation
uses OpenSSL3.providers.common.securitycheck_default,
     openssl3.crypto.rsa.rsa_lib,
     OpenSSL3.providers.common.digest_to_nid, OpenSSL3.Err;


function ossl_rsa_check_key(ctx : POSSL_LIB_CTX;const rsa : PRSA; operation : integer):integer;
var
  protect, sz : integer;
begin
    protect := 0;
    case operation of
        EVP_PKEY_OP_SIGN:
            protect := 1;
            { fallthrough }
        EVP_PKEY_OP_VERIFY:
            begin
              //
            end;
        EVP_PKEY_OP_ENCAPSULATE,
        EVP_PKEY_OP_ENCRYPT:
            protect := 1;
            { fallthrough }
        EVP_PKEY_OP_VERIFYRECOVER,
        EVP_PKEY_OP_DECAPSULATE,
        EVP_PKEY_OP_DECRYPT:
            if RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) = RSA_FLAG_TYPE_RSASSAPSS  then
            begin
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                               Format('operation: %d', [operation]));
                Exit(0);
            end;

        else
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           Format('invalid operation: %d', [operation]));
            Exit(0);
    end;
{$IF not defined(OPENSSL_NO_FIPS_SECURITYCHECKS)}
    if ossl_securitycheck_enabled(ctx)  then
    begin
        sz := RSA_bits(rsa);
        if protect ? (sz < 2048 then : (sz < 1024)) begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH,
                           'operation: %d', operation);
            Exit(0);
        end;
    end;
{$ELSE} { make protect used }
    protect := NULL;
{$endif} { OPENSSL_NO_FIPS_SECURITYCHECKS }
    Result := 1;
end;


function ossl_dsa_check_key(ctx : POSSL_LIB_CTX;const dsa : PDSA; sign : integer):integer;
var
  L, N : size_t;
begin
{$IF not defined(OPENSSL_NO_FIPS_SECURITYCHECKS)}
    if ossl_securitycheck_enabled(ctx then ) begin
        const PBIGNUM  p, *q;
        if dsa = nil then Exit(0);
        p := DSA_get0_p(dsa);
        q := DSA_get0_q(dsa);
        if p = nil  or  q = nil then Exit(0);
        L := BN_num_bits(p);
        N := BN_num_bits(q);
        {
         * For Digital signature verification DSA keys with < 112 bits of
         * security strength (i.e L < 2048 bits), are still allowed for legacy
         * use. The bounds given in SP800 131Ar2 - Table 2 are
         * (512 <= L < 2048 and 160 <= N < 224)
         }
        if 0>= sign  and  L < 2048 then Exit((L >= 512  and  N >= 160  and  N < 224));
         { Valid sizes for both sign and verify }
        if L = 2048  and  (N = 224  or  N = 256 then )
            Exit(1);
        Exit((L = 3072  and  N = 256));
    end;
{$endif} { OPENSSL_NO_FIPS_SECURITYCHECKS }
    Result := 1;
end;




function ossl_digest_get_approved_nid_with_sha1(ctx : POSSL_LIB_CTX;const md : PEVP_MD; sha1_allowed : integer):integer;
var
  mdnid : integer;
begin
    mdnid := ossl_digest_get_approved_nid(md);
{$IF not defined(OPENSSL_NO_FIPS_SECURITYCHECKS)}
    if ossl_securitycheck_enabled(ctx) then
    begin
        if (mdnid = NID_undef)  or  ( (mdnid = NID_sha1)  and  (0>= sha1_allowed) )then
            mdnid := -1; { disallowed by security checks }
    end;
{$endif} { OPENSSL_NO_FIPS_SECURITYCHECKS }
    Result := mdnid;
end;




function ossl_ec_check_key(ctx : POSSL_LIB_CTX;const ec : PEC_KEY; protect : integer):integer;
var
  nid,
  strength   : integer;

    curve_name : PUTF8Char;

    group      : PEC_GROUP;
begin
{$IF not defined(OPENSSL_NO_FIPS_SECURITYCHECKS)}
    if ossl_securitycheck_enabled(ctx then ) begin
        group := EC_KEY_get0_group(ec);
        if group = nil then begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE, 'No group');
            Exit(0);
        end;
        nid := EC_GROUP_get_curve_name(group);
        if nid = NID_undef then begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                           'Explicit curves are not allowed in fips mode');
            Exit(0);
        end;
        curve_name := EC_curve_nid2nist(nid);
        if curve_name = nil then begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                           'Curve %s is not approved in FIPS mode', curve_name);
            Exit(0);
        end;
        {
         * For EC the security strength is the (order_bits / 2)
         * e.g. P-224 is 112 bits.
         }
        strength := EC_GROUP_order_bits(group) / 2;
        { The min security strength allowed for legacy verification is 80 bits }
        if strength < 80 then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            Exit(0);
        end;
        {
         * For signing or key agreement only allow curves with at least 112 bits of
         * security strength
         }
        if protect  and  strength < 112 then begin
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                           'Curve %s cannot be used for signing', curve_name);
            Exit(0);
        end;
    end;
{$endif} { OPENSSL_NO_FIPS_SECURITYCHECKS }
    Result := 1;
end;


function ossl_dh_check_key(ctx : POSSL_LIB_CTX;const dh : PDH):integer;
var
  L, N : size_t;

  p, q : PBIGNUM;
begin
{$IF not defined(OPENSSL_NO_FIPS_SECURITYCHECKS)}
    if ossl_securitycheck_enabled(ctx then ) begin
        if dh = nil then
            Exit(0);
        p := DH_get0_p(dh);
        q := DH_get0_q(dh);
        if p = nil  or  q = nil then Exit(0);
        L := BN_num_bits(p);
        if L < 2048 then Exit(0);
        { If it is a safe prime group then it is ok }
        if DH_get_nid(dh then )
            Exit(1);
        { If not then it must be FFC, which only allows certain sizes. }
        N := BN_num_bits(q);
        Exit((L = 2048  and  (N = 224  or  N = 256)));
    end;
{$endif} { OPENSSL_NO_FIPS_SECURITYCHECKS }
    Result := 1;
end;

function ossl_digest_is_allowed(ctx : POSSL_LIB_CTX;const md : PEVP_MD):Boolean;
begin
{$IF not defined(OPENSSL_NO_FIPS_SECURITYCHECKS)}
    if ossl_securitycheck_enabled(ctx)  then
        Exit(ossl_digest_get_approved_nid(md) <> NID_undef);
{$endif} { OPENSSL_NO_FIPS_SECURITYCHECKS }
    Result := Boolean(1);
end;


end.
