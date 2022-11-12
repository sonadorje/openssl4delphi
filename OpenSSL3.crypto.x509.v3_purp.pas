unit OpenSSL3.crypto.x509.v3_purp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses  OpenSSL.Api;

const
    V1_ROOT = (EXFLAG_V1 or EXFLAG_SS);
    supported_nids: array[0..14] of int = (
        NID_netscape_cert_type, (* 71 *)
        NID_key_usage,          (* 83 *)
        NID_subject_alt_name,   (* 85 *)
        NID_basic_constraints,  (* 87 *)
        NID_certificate_policies, (* 89 *)
        NID_crl_distribution_points, (* 103 *)
        NID_ext_key_usage,      (* 126 *)
{$ifndef OPENSSL_NO_RFC3779 }
        NID_sbgp_ipAddrBlock,   (* 290 *)
        NID_sbgp_autonomousSysNum, (* 291 *)
{$ENDIF}
        NID_id_pkix_OCSP_noCheck, (* 369 *)
        NID_policy_constraints, (* 401 *)
        NID_proxyCertInfo,      (* 663 *)
        NID_name_constraints,   (* 666 *)
        NID_policy_mappings,    (* 747 *)
        NID_inhibit_any_policy  (* 748 *)
    );

function ossl_x509v3_cache_extensions( x : PX509):integer;
function check_sig_alg_match(const issuer_key : PEVP_PKEY; const subject : PX509):integer;
function setup_crldp( x : PX509):integer;
function setup_dp(const x : PX509; dp : PDIST_POINT):integer;
function ossl_x509_likely_issued( issuer, subject : PX509):integer;
function ossl_x509_signing_allowed(const issuer, subject : PX509):integer;
 function X509_check_akid(const issuer : PX509; akid : PAUTHORITY_KEYID):integer;
 function X509_supported_extension( ex : PX509_EXTENSION):integer;
  function nid_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_nid( key : PInteger; const base: PInteger; num : integer):PInteger;
 function nid_cmp(const a, b : PInteger):integer;
function X509_check_purpose( x : PX509; id, require_ca : integer):integer;
 function X509_PURPOSE_get_by_id( purpose : integer):integer;
 function X509_PURPOSE_get0( idx : integer):PX509_PURPOSE;
 function check_ssl_ca(const x : PX509):integer;
 function xku_reject(x: PX509; usage: int): Boolean;
 function check_ca(const x : PX509):integer;
 function ku_reject(x: PX509; usage: int): Boolean;
 function ns_reject(x: PX509; usage: int): Boolean;

 function check_purpose_ssl_client(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function check_purpose_ssl_server(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function check_purpose_ns_ssl_server(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function check_purpose_smime_sign(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function purpose_smime(const x : PX509; require_ca : integer):integer;
 function check_purpose_smime_encrypt(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function check_purpose_crl_sign(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function no_check_purpose(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function check_purpose_ocsp_helper(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function check_purpose_timestamp_sign(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
 function X509_check_ca( x : PX509):integer;
 function X509_get_extension_flags( x : PX509):uint32;
  function X509_PURPOSE_get_trust(const xp : PX509_PURPOSE):integer;


var
  xptable: Pstack_st_X509_PURPOSE  = nil;
  xstandard: array of TX509_PURPOSE;



implementation

uses
     OpenSSL3.Err, OpenSSL3.include.openssl.asn1, openssl3.crypto.evp.p_lib,
     openssl3.crypto.x509v3, OpenSSL3.crypto.x509.x509_set,
     openssl3.crypto.asn1.a_int,  OpenSSL3.crypto.x509.v3_crld,
     OpenSSL3.crypto.x509.x509_ext, openssl3.crypto.objects.obj_xref,
     openssl3.crypto.objects.obj_dat, OpenSSL3.threads_none,
     OpenSSL3.crypto.x509.x_all,  openssl3.crypto.evp.legacy_sha,
     OpenSSL3.crypto.x509.v3_pcia, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.a_object,  openssl3.crypto.x509.x509_v3,
     openssl3.providers.fips.fipsprov, OpenSSL3.crypto.x509.v3_bcons,
     OpenSSL3.crypto.x509.x509_cmp, openssl3.crypto.asn1.a_octet;





function X509_PURPOSE_get_trust(const xp : PX509_PURPOSE):integer;
begin
    Result := xp.trust;
end;


function X509_get_extension_flags( x : PX509):uint32;
begin
    { Call for side-effect of computing hash and caching extensions }
    X509_check_purpose(x, -1, 0);
    Result := x.ex_flags;
end;


function X509_check_ca( x : PX509):integer;
begin
    { Note 0 normally means 'not a CA' - but in this case means error. }
    if 0>=ossl_x509v3_cache_extensions(x ) then
        Exit(0);
    Result := check_ca(x);
end;

function check_purpose_timestamp_sign(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
var
  i_ext : integer;

  ext : PX509_EXTENSION;
begin
    { If ca is true we must return if this is a valid CA certificate. }
    if require_ca > 0 then
       Exit(check_ca(x));
    {
     * Check the optional key usage field:
     * if Key Usage is present, it must be one of digitalSignature
     * and/or nonRepudiation (other values are not consistent and shall
     * be rejected).
     }
    if (x.ex_flags and EXFLAG_KUSAGE > 0)  and
       ( ( (x.ex_kusage and not (KU_NON_REPUDIATION or KU_DIGITAL_SIGNATURE)) > 0)  or
         (not (x.ex_kusage and (KU_NON_REPUDIATION or KU_DIGITAL_SIGNATURE)) > 0 ) ) then
        Exit(0);
    { Only time stamp key usage is permitted and it's required. }
    if (0>=(x.ex_flags and EXFLAG_XKUSAGE))  or  (x.ex_xkusage <> XKU_TIMESTAMP) then
        Exit(0);
    { Extended Key Usage MUST be critical }
    i_ext := X509_get_ext_by_NID(x, NID_ext_key_usage, -1);
    if i_ext >= 0 then
    begin
        ext := X509_get_ext(PX509(x), i_ext);
        if 0>=X509_EXTENSION_get_critical(ext ) then
            Exit(0);
    end;
    Result := 1;
end;





function check_purpose_ocsp_helper(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
begin
    {
     * Must be a valid CA.  Should we really support the 'I don't know' value
     * (2)?
     }
    if require_ca > 0 then Exit(check_ca(x));
    { Leaf certificate is checked in OCSP_verify }
    Result := 1;
end;




function no_check_purpose(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
begin
    Result := 1;
end;




function check_purpose_crl_sign(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
var
  ca_ret : integer;
begin
    if require_ca > 0 then
    begin
        ca_ret := check_ca(x);
        if (ca_ret <> 2) then
            Exit(ca_ret)
        else
            Exit(0);
    end;
    if ku_reject(x, KU_CRL_SIGN ) then
        Exit(0);
    Result := 1;
end;



function check_purpose_smime_encrypt(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
var
  ret : integer;
begin
    ret := purpose_smime(x, require_ca);
    if (0>=ret)  or  (require_ca > 0) then
       Exit(ret);
    if ku_reject(x, KU_KEY_ENCIPHERMENT) then
        Exit(0);
    Result := ret;
end;



function purpose_smime(const x : PX509; require_ca : integer):integer;
var
  ca_ret : integer;
begin
    if xku_reject(x, XKU_SMIME) then
        Exit(0);
    if require_ca > 0 then
    begin
        ca_ret := check_ca(x);
        if ca_ret = 0 then Exit(0);
        { Check nsCertType if present }
        if (ca_ret <> 5)  or  (x.ex_nscert and NS_SMIME_CA > 0) then
           Exit(ca_ret)
        else
            Exit(0);
    end;
    if x.ex_flags and EXFLAG_NSCERT > 0 then
    begin
        if x.ex_nscert and NS_SMIME > 0 then
            Exit(1);
        { Workaround for some buggy certificates }
        if x.ex_nscert and NS_SSL_CLIENT > 0 then
           Exit(2);
        Exit(0);
    end;
    Result := 1;
end;

function check_purpose_smime_sign(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
var
  ret : integer;
begin
    ret := purpose_smime(x, require_ca);
    if (0>=ret)  or  (require_ca > 0) then
       Exit(ret);
    if ku_reject(x, KU_DIGITAL_SIGNATURE or KU_NON_REPUDIATION) then
        Exit(0);
    Result := ret;
end;


function check_purpose_ns_ssl_server(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
var
  ret : integer;
begin
    ret := check_purpose_ssl_server(xp, x, require_ca);
    if (0>=ret)  or  (require_ca > 0) then
       Exit(ret);
    { We need to encipher or Netscape complains }
    if ku_reject(x, KU_KEY_ENCIPHERMENT ) then
        Exit(0);
    Result := ret;
end;




const KU_TLS = KU_DIGITAL_SIGNATURE or KU_KEY_ENCIPHERMENT or KU_KEY_AGREEMENT;

function check_purpose_ssl_server(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
begin
    if xku_reject(x, XKU_SSL_SERVER or XKU_SGC ) then
        Exit(0);
    if require_ca > 0 then
       Exit(check_ssl_ca(x));
    if ns_reject(x, NS_SSL_SERVER) then
        Exit(0);
    if ku_reject(x, KU_TLS) then
        Exit(0);
    Exit(1);
end;

function ns_reject(x: PX509; usage: int): Boolean;
begin
    Result := ((x.ex_flags and EXFLAG_NSCERT) <> 0 ) and
              ((x.ex_nscert and usage) = 0)
end;


function check_ca(const x : PX509):integer;
begin
    { keyUsage if present should allow cert signing }
    if ku_reject(x, KU_KEY_CERT_SIGN ) then
        Exit(0);
    if x.ex_flags and EXFLAG_BCONS <> 0 then
    begin
        { If basicConstraints says not a CA then say so }
        Result := int( (x.ex_flags and EXFLAG_CA) <> 0);
    end
    else
    begin
        { We support V1 roots for...  uh, I don't really know why. }
        if (x.ex_flags and V1_ROOT) = V1_ROOT then
            Exit(3)
        {
         * If key usage present it must have certSign so tolerate it
         }
        else if (x.ex_flags and EXFLAG_KUSAGE) > 0 then
            Exit(4)
        { Older certificates could have Netscape-specific CA types }
        else if (x.ex_flags and EXFLAG_NSCERT > 0)  and  (x.ex_nscert and NS_ANY_CA > 0) then
            Exit(5);
        { Can this still be regarded a CA certificate?  I doubt it. }
        Exit(0);
    end;
end;



function check_ssl_ca(const x : PX509):integer;
var
  ca_ret : integer;
begin
    ca_ret := check_ca(x);
    if ca_ret = 0 then Exit(0);
    { Check nsCertType if present }
    Result := Int( (ca_ret <> 5)  or ( (x.ex_nscert and NS_SSL_CA) <> 0) );
end;

function xku_reject(x: PX509; usage: int): Boolean;
begin
    Result := ( (x.ex_flags and EXFLAG_XKUSAGE) <> 0 ) and
              ( (x.ex_xkusage and usage) = 0)
end;

function check_purpose_ssl_client(const xp : PX509_PURPOSE; const x : PX509; require_ca : integer):integer;
begin
    if xku_reject(x, XKU_SSL_CLIENT ) then
        Exit(0);
    if require_ca > 0 then
       Exit(check_ssl_ca(x));
    { We need to do digital signatures or key agreement }
    if ku_reject(x, KU_DIGITAL_SIGNATURE or KU_KEY_AGREEMENT) then
        Exit(0);
    { nsCertType if present should allow SSL client use }
    if ns_reject(x, NS_SSL_CLIENT ) then
        Exit(0);
    Result := 1;
end;





function X509_PURPOSE_get0( idx : integer):PX509_PURPOSE;
begin
{$POINTERMATH ON}
    if idx < 0 then Exit(nil);
    if idx < Length(xstandard) then
       Exit(PX509_PURPOSE(@xstandard) + idx);
    Result := sk_X509_PURPOSE_value(xptable, idx - Length(xstandard));
{$POINTERMATH ON}
end;




function X509_PURPOSE_get_by_id( purpose : integer):integer;
var
  tmp : TX509_PURPOSE;
  idx : integer;
begin
    if (purpose >= X509_PURPOSE_MIN)  and  (purpose <= X509_PURPOSE_MAX) then
       Exit(purpose - X509_PURPOSE_MIN);
    if xptable = nil then Exit(-1);
    tmp.purpose := purpose;
    idx := sk_X509_PURPOSE_find(xptable, @tmp);
    if idx < 0 then Exit(-1);
    Result := idx + Length(xstandard);
end;


function X509_check_purpose( x : PX509; id, require_ca : integer):integer;
var
  idx : integer;
  pt : PX509_PURPOSE;
begin
    if 0>=ossl_x509v3_cache_extensions(x) then
        Exit(-1);
    if id = -1 then Exit(1);
    idx := X509_PURPOSE_get_by_id(id);
    if idx = -1 then Exit(-1);
    pt := X509_PURPOSE_get0(idx);
    Result := pt.check_purpose(pt, x, require_ca);
end;

function nid_cmp(const a, b : PInteger):integer;
begin
    Result := a^ - b^;
end;

function nid_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : PInteger;
begin
   a := a_;
   b := b_;
   Result := nid_cmp(a,b);
end;


function OBJ_bsearch_nid( key : PInteger; const base: PInteger; num : integer):PInteger;
begin
   Result := PInteger (OBJ_bsearch_(key, base, num, sizeof(int), nid_cmp_BSEARCH_CMP_FN));
end;



function X509_supported_extension( ex : PX509_EXTENSION):integer;
var
  ex_nid : integer;
begin
    {
     * This table is a list of the NIDs of supported extensions: that is
     * those which are used by the verify process. If an extension is
     * critical and doesn't appear in this list then the verify process will
     * normally reject the certificate. The list must be kept in numerical
     * order because it will be searched using bsearch.
     }
    ex_nid := OBJ_obj2nid(X509_EXTENSION_get_object(ex));
    if ex_nid = NID_undef then
       Exit(0);
    if OBJ_bsearch_nid(@ex_nid, @supported_nids, Length(supported_nids)) <> nil then
        Exit(1);
    Result := 0;
end;



function X509_check_akid(const issuer : PX509; akid : PAUTHORITY_KEYID):integer;
var
  gens : PGENERAL_NAMES;

  gen : PGENERAL_NAME;

  nm : PX509_NAME;

  i : integer;
begin
    if akid = nil then Exit(X509_V_OK);
    { Check key ids (if present) }
    if (akid.keyid <> nil) and  (issuer.skid <> nil) and
       (ASN1_OCTET_STRING_cmp(akid.keyid, issuer.skid) > 0) then
        Exit(X509_V_ERR_AKID_SKID_MISMATCH);
    { Check serial number }
    if (akid.serial <>nil)  and
       (ASN1_INTEGER_cmp(X509_get0_serialNumber(issuer) , akid.serial)>0) then
        Exit(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
    { Check issuer name }
    if akid.issuer <> nil then
    begin
        {
         * Ugh, for some peculiar reason AKID includes SEQUENCE OF
         * GeneralName. So look for a DirName. There may be more than one but
         * we only take any notice of the first.
         }
        nm := nil;
        gens := akid.issuer;
        for i := 0 to sk_GENERAL_NAME_num(gens)-1 do
        begin
            gen := sk_GENERAL_NAME_value(gens, i);
            if gen.&type = GEN_DIRNAME then
            begin
                nm := gen.d.dirn;
                break;
            end;
        end;
        if (nm <> nil)  and  (X509_NAME_cmp(nm, X509_get_issuer_name(issuer)) <> 0)  then
            Exit(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
    end;
    Result := X509_V_OK;
end;

(*-
 * Check if certificate I<issuer> is allowed to issue certificate I<subject>
 * according to the B<keyUsage> field of I<issuer> if present
 * depending on any proxyCertInfo extension of I<subject>.
 * Returns 0 for OK, or positive for reason for rejection
 * where reason codes match those for X509_verify_cert().
 *)
function ku_reject(x: PX509; usage: int): Boolean;
begin
    Result := ( (x.ex_flags and EXFLAG_KUSAGE) <> 0 ) and ( (x.ex_kusage and usage) = 0);
end;

function ossl_x509_signing_allowed(const issuer, subject : PX509):integer;
begin
    if (subject.ex_flags and EXFLAG_PROXY)>0 then
    begin
        if ku_reject(issuer, KU_DIGITAL_SIGNATURE) then
            Exit(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE);
    end
    else
    if (ku_reject(issuer, KU_KEY_CERT_SIGN)) then
        Exit(X509_V_ERR_KEYUSAGE_NO_CERTSIGN);
    Result := X509_V_OK;
end;

function ossl_x509_likely_issued( issuer, subject : PX509):integer;
var
  ret : integer;
begin
    if X509_NAME_cmp(X509_get_subject_name(issuer),
                      X509_get_issuer_name(subject)) <> 0  then
        Exit(X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
    { set issuer.skid and subject.akid }
    if  (0>= ossl_x509v3_cache_extensions(issuer))  or
        (0>= ossl_x509v3_cache_extensions(subject))  then
        Exit(X509_V_ERR_UNSPECIFIED);
    ret := X509_check_akid(issuer, subject.akid);
    if ret <> X509_V_OK then Exit(ret);
    { Check if the subject signature alg matches the issuer's PUBKEY alg }
    Result := check_sig_alg_match(X509_get0_pubkey(issuer), subject);
end;

function setup_dp(const x : PX509; dp : PDIST_POINT):integer;
var
  iname : PX509_NAME;
  i : integer;
  gen : PGENERAL_NAME;
begin
    iname := nil;
    if (dp.distpoint = nil)  and  (sk_GENERAL_NAME_num(dp.CRLissuer) <= 0) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_INVALID_DISTPOINT);
        Exit(0);
    end;
    if dp.reasons <> nil then
    begin
        if dp.reasons.length > 0 then
            dp.dp_reasons := dp.reasons.data[0];
        if dp.reasons.length > 1 then
           dp.dp_reasons  := dp.dp_reasons  or ((dp.reasons.data[1]  shl  8));
        dp.dp_reasons := dp.dp_reasons and CRLDP_ALL_REASONS;
    end
    else
    begin
        dp.dp_reasons := CRLDP_ALL_REASONS;
    end;
    if (dp.distpoint = nil)  or  (dp.distpoint.&type <> 1) then
       Exit(1);
    { Handle name fragment given by nameRelativeToCRLIssuer }
    {
     * Note that the below way of determining iname is not really compliant
     * with https://tools.ietf.org/html/rfc5280#section-4.2.1.13
     * According to it, sk_GENERAL_NAME_num(dp.CRLissuer) MUST be <= 1
     * and any CRLissuer could be of type different to GEN_DIRNAME.
     }
    for i := 0 to sk_GENERAL_NAME_num(dp.CRLissuer)-1 do
    begin
        gen := sk_GENERAL_NAME_value(dp.CRLissuer, i);
        if gen.&type = GEN_DIRNAME then
        begin
            iname := gen.d.directoryName;
            break;
        end;
    end;
    if iname = nil then
       iname := X509_get_issuer_name(x);
    if DIST_POINT_set_dpname(dp.distpoint, iname)>0 then
       Result :=  1
    else
       Result := -1;
end;


function setup_crldp( x : PX509):integer;
var
  i, res : integer;
begin
    x.crldp := X509_get_ext_d2i(x, NID_crl_distribution_points, @i, nil);
    if (x.crldp = nil)  and  (i <> -1) then
       Exit(0);
    for i := 0 to sk_DIST_POINT_num(x.crldp)-1 do
    begin
        res := setup_dp(x, sk_DIST_POINT_value(x.crldp, i));
        if res < 1 then
           Exit(res);
    end;
    Result := 1;
end;

(* Check that issuer public key algorithm matches subject signature algorithm *)
function check_sig_alg_match(const issuer_key : PEVP_PKEY; const subject : PX509):integer;
var
  subj_sig_nid : integer;
begin
    if issuer_key = nil then
       Exit(X509_V_ERR_NO_ISSUER_PUBLIC_KEY);
    if OBJ_find_sigid_algs(OBJ_obj2nid(subject.cert_info.signature.algorithm)  ,
                            nil, @subj_sig_nid) = 0  then
         Exit(X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM);
    if ( EVP_PKEY_is_a(issuer_key, OBJ_nid2sn(subj_sig_nid) ) or
       ( ( EVP_PKEY_is_a(issuer_key, 'RSA') )  and
         ( subj_sig_nid = NID_rsassaPss) ) )then
        Exit(X509_V_OK);
    Result := X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH;
end;

function ossl_x509v3_cache_extensions(x : PX509):integer;
var
    bs       : PBASIC_CONSTRAINTS;
    pci      : PPROXY_CERT_INFO_EXTENSION;
    usage,
    ns       : PASN1_BIT_STRING;
    extusage : PEXTENDED_KEY_USAGE;
    i,
    res      : integer;
    ex       : PX509_EXTENSION;
    nid      : integer;
    label  err;
begin
{$IFDEF tsan_ld_acq}
    { Fast lock-free check, see end of the function for details. }
    if tsan_ld_acq((TSAN_QUALIFIER int * then &x.ex_cached))
        Exit((x.ex_flags and EXFLAG_INVALID) = 0);
{$ENDIF}
    if  0>= CRYPTO_THREAD_write_lock(x.lock) then
        Exit(0);
    if (x.ex_flags and EXFLAG_SET)>0 then begin  { Cert has already been processed }
        CRYPTO_THREAD_unlock(x.lock);
        Exit(integer( (x.ex_flags and EXFLAG_INVALID) = 0) );
    end;
    { Cache the SHA1 digest of the cert }
    if  0>= X509_digest(x, EVP_sha1, @x.sha1_hash, nil) then
        x.ex_flags  := (x.ex_flags  or EXFLAG_NO_FINGERPRINT);
    ERR_set_mark();
    { V1 should mean no extensions ... }
    if X509_get_version(x)= X509_VERSION_1    then
        x.ex_flags  := x.ex_flags  or EXFLAG_V1;
    { Handle basic constraints }
    x.ex_pathlen := -1;
    bs := X509_get_ext_d2i(x, NID_basic_constraints, @i, nil);
    if bs <> nil then
    begin
        if bs.ca > 0 then
            x.ex_flags  := x.ex_flags  or EXFLAG_CA;
        if bs.pathlen <> nil then
        begin
            {
             * The error case !bs.ca is checked by check_chain()
             * in case ctx.param.flags and X509_V_FLAG_X509_STRICT
             }
            if bs.pathlen.&type = V_ASN1_NEG_INTEGER then
            begin
                ERR_raise(ERR_LIB_X509, X509V3_R_NEGATIVE_PATHLEN);
                x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
            end
            else
            begin
                x.ex_pathlen := ASN1_INTEGER_get(bs.pathlen);
            end;
        end;
        BASIC_CONSTRAINTS_free(bs);
        x.ex_flags  := x.ex_flags  or EXFLAG_BCONS;
    end
    else
    if (i <> -1) then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    end;
    { Handle proxy certificates }
    pci := X509_get_ext_d2i(x, NID_proxyCertInfo, @i, nil );
    if pci <> nil then
    begin
        if ( (x.ex_flags and EXFLAG_CA) > 0 )
             or  (X509_get_ext_by_NID(x, NID_subject_alt_name, -1) >= 0 )
             or  (X509_get_ext_by_NID(x, NID_issuer_alt_name, -1) >= 0 ) then
        begin
            x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
        end;
        if pci.pcPathLengthConstraint <> nil then
           x.ex_pcpathlen := ASN1_INTEGER_get(pci.pcPathLengthConstraint)
        else
            x.ex_pcpathlen := -1;
        PROXY_CERT_INFO_EXTENSION_free(pci);
        x.ex_flags  := x.ex_flags  or EXFLAG_PROXY;
    end
    else if (i <> -1) then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    end;
    { Handle (basic) key usage }
    usage := X509_get_ext_d2i(x, NID_key_usage, @i, nil );
    if usage <> nil then
    begin
        x.ex_kusage := 0;
        if usage.length > 0 then begin
            x.ex_kusage := usage.data[0];
            if usage.length > 1 then
               x.ex_kusage  := x.ex_kusage  or (usage.data[1]  shl  8);
        end;
        x.ex_flags  := x.ex_flags  or EXFLAG_KUSAGE;
        ASN1_BIT_STRING_free(usage);
        { Check for empty key usage according to RFC 5280 section 4.2.1.3 }
        if x.ex_kusage = 0 then
        begin
            ERR_raise(ERR_LIB_X509, X509V3_R_EMPTY_KEY_USAGE);
            x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
        end;
    end
    else if (i <> -1) then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    end;
    { Handle extended key usage }
    x.ex_xkusage := 0;
    extusage := X509_get_ext_d2i(x, NID_ext_key_usage, @i, nil );
    if extusage <> nil then
    begin
        x.ex_flags  := (x.ex_flags  or EXFLAG_XKUSAGE);
        for i := 0 to sk_ASN1_OBJECT_num(extusage)-1 do
        begin
            case (OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage, i))) of
            NID_server_auth:
                x.ex_xkusage  := x.ex_xkusage  or XKU_SSL_SERVER;
                //break;
            NID_client_auth:
                x.ex_xkusage  := x.ex_xkusage  or XKU_SSL_CLIENT;
                //break;
            NID_email_protect:
                x.ex_xkusage  := x.ex_xkusage  or XKU_SMIME;
                //break;
            NID_code_sign:
                x.ex_xkusage  := x.ex_xkusage  or XKU_CODE_SIGN;
                //break;
            NID_ms_sgc,
            NID_ns_sgc:
                x.ex_xkusage  := x.ex_xkusage  or XKU_SGC;
                //break;
            NID_OCSP_sign:
                x.ex_xkusage  := x.ex_xkusage  or XKU_OCSP_SIGN;
                //break;
            NID_time_stamp:
                x.ex_xkusage  := x.ex_xkusage  or XKU_TIMESTAMP;
                //break;
            NID_dvcs:
                x.ex_xkusage  := x.ex_xkusage  or XKU_DVCS;
                //break;
            NID_anyExtendedKeyUsage:
                x.ex_xkusage  := x.ex_xkusage  or XKU_ANYEKU;
                //break;
            else
                { Ignore unknown extended key usage }
                begin

                end;  ;
            end;
        end;
        sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
    end
    else if (i <> -1) then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    end;
    { Handle legacy Netscape extension }
    ns := X509_get_ext_d2i(x, NID_netscape_cert_type, @i, nil );
    if ns <> nil then
    begin
        if ns.length > 0 then
            x.ex_nscert := ns.data[0]
        else
            x.ex_nscert := 0;
        x.ex_flags  := x.ex_flags  or EXFLAG_NSCERT;
        ASN1_BIT_STRING_free(ns);
    end
    else if (i <> -1) then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    end;
    { Handle subject key identifier and issuer/authority key identifier }
    x.skid := X509_get_ext_d2i(x, NID_subject_key_identifier, @i, nil);
    if (x.skid = nil)  and  (i <> -1) then
       x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    x.akid := X509_get_ext_d2i(x, NID_authority_key_identifier, @i, nil);
    if (x.akid = nil)  and  (i <> -1) then
       x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    { Check if subject name matches issuer }
    if X509_NAME_cmp(X509_get_subject_name(x)  , X509_get_issuer_name(x)) = 0 then
    begin
        x.ex_flags  := x.ex_flags  or EXFLAG_SI;
        if (X509_check_akid(x, x.akid) = X509_V_OK)   and { SKID matches AKID }
                { .. and the signature alg matches the PUBKEY alg: }
           (check_sig_alg_match(X509_get0_pubkey(x), x) = X509_V_OK) then
            x.ex_flags  := x.ex_flags  or EXFLAG_SS;
        { This is very related to ossl_x509_likely_issued(x, x) = X509_V_OK }
    end;
    { Handle subject alternative names and various other extensions }
    x.altname := X509_get_ext_d2i(x, NID_subject_alt_name, @i, nil);
    if (x.altname = nil)  and  (i <> -1) then
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    x.nc := X509_get_ext_d2i(x, NID_name_constraints, @i, nil);
    if (x.nc = nil)  and  (i <> -1) then
       x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    { Handle CRL distribution point entries }
    res := setup_crldp(x);
    if res = 0 then
       x.ex_flags  := x.ex_flags  or EXFLAG_INVALID
    else
    if (res < 0) then
{$IFNDEF OPENSSL_NO_RFC3779}
    x.rfc3779_addr := X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, @i, nil);
    if (x.rfc3779_addr = nil)  and  (i <> -1) then
        x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
    x.rfc3779_asid := X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, @i, nil);
    if (x.rfc3779_asid = nil)  and  (i <> -1) then
       x.ex_flags  := x.ex_flags  or EXFLAG_INVALID;
{$ENDIF}
    for i := 0 to X509_get_ext_count(x)-1 do
    begin
        ex := X509_get_ext(x, i);
        nid := OBJ_obj2nid(X509_EXTENSION_get_object(ex));
        if nid = NID_freshest_crl then x.ex_flags  := x.ex_flags  or EXFLAG_FRESHEST;
        if  0>= X509_EXTENSION_get_critical(ex) then
            continue;
        if  0>= X509_supported_extension(ex) then
        begin
            x.ex_flags  := x.ex_flags  or EXFLAG_CRITICAL;
            break;
        end;
        case nid of
        NID_basic_constraints:
            x.ex_flags  := x.ex_flags  or EXFLAG_BCONS_CRITICAL;

        NID_authority_key_identifier:
            x.ex_flags  := x.ex_flags  or EXFLAG_AKID_CRITICAL;

        NID_subject_key_identifier:
            x.ex_flags  := x.ex_flags  or EXFLAG_SKID_CRITICAL;

        NID_subject_alt_name:
            x.ex_flags  := x.ex_flags  or EXFLAG_SAN_CRITICAL;

        else
            break;
        end;
    end;
    { Set x.siginf, ignoring errors due to unsupported algos }
    ossl_x509_init_sig_info(x);
    x.ex_flags  := x.ex_flags  or EXFLAG_SET;
{$IFDEF tsan_st_rel}
    tsan_st_rel((TSAN_QUALIFIER int *)&x.ex_cached, 1);
    {
     * Above store triggers fast lock-free check in the beginning of the
     * function. But one has to ensure that the structure is 'stable', i.e.
     * all stores are visible on all processors. Hence the release fence.
     }
{$ENDIF}
    ERR_pop_to_mark();
    if (x.ex_flags and (EXFLAG_INVALID or EXFLAG_NO_FINGERPRINT ) ) = 0 then
    begin
        CRYPTO_THREAD_unlock(x.lock);
        Exit(1);
    end;
    if (x.ex_flags and EXFLAG_INVALID)  <> 0 then
        ERR_raise(ERR_LIB_X509, X509V3_R_INVALID_CERTIFICATE);
    { If computing sha1_hash failed the error queue already reflects this. }
 err:
    x.ex_flags  := x.ex_flags  or EXFLAG_SET;
    CRYPTO_THREAD_unlock(x.lock);
    Result := 0;
end;

initialization

  xstandard := [
    get_X509_PURPOSE(X509_PURPOSE_SSL_CLIENT, X509_TRUST_SSL_CLIENT, 0,
     check_purpose_ssl_client, 'SSL client', 'sslclient', nil),
    get_X509_PURPOSE(X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER, 0,
     check_purpose_ssl_server, 'SSL server', 'sslserver', nil),
    get_X509_PURPOSE(X509_PURPOSE_NS_SSL_SERVER, X509_TRUST_SSL_SERVER, 0,
     check_purpose_ns_ssl_server, 'Netscape SSL server', 'nssslserver', nil),
    get_X509_PURPOSE(X509_PURPOSE_SMIME_SIGN, X509_TRUST_EMAIL, 0, check_purpose_smime_sign,
     'S/MIME signing', 'smimesign', nil),
    get_X509_PURPOSE(X509_PURPOSE_SMIME_ENCRYPT, X509_TRUST_EMAIL, 0,
     check_purpose_smime_encrypt, 'S/MIME encryption', 'smimeencrypt', nil),
    get_X509_PURPOSE(X509_PURPOSE_CRL_SIGN, X509_TRUST_COMPAT, 0, check_purpose_crl_sign,
     'CRL signing', 'crlsign', nil),
    get_X509_PURPOSE(X509_PURPOSE_ANY, X509_TRUST_DEFAULT, 0, no_check_purpose,
     'Any Purpose', 'any',
     nil),
    get_X509_PURPOSE(X509_PURPOSE_OCSP_HELPER, X509_TRUST_COMPAT, 0, check_purpose_ocsp_helper,
     'OCSP helper', 'ocsphelper', nil),
    get_X509_PURPOSE(X509_PURPOSE_TIMESTAMP_SIGN, X509_TRUST_TSA, 0,
     check_purpose_timestamp_sign, 'Time Stamp signing', 'timestampsign',
     nil)
   ];

end.
