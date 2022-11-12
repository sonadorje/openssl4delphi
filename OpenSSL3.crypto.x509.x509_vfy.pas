unit OpenSSL3.crypto.x509.x509_vfy;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses OpenSSL.Api, DateUtils, SysUtils;

const
    CRL_SCORE_NOCRITICAL   = $100 (* No unhandled critical extensions *);
    CRL_SCORE_SCOPE        = $080 (* certificate is within CRL scope *);
    CRL_SCORE_TIME         = $040 (* CRL times valid *);
    CRL_SCORE_ISSUER_NAME  = $020 (* Issuer name matches certificate *);
    CRL_SCORE_VALID        = (CRL_SCORE_NOCRITICAL or CRL_SCORE_TIME or CRL_SCORE_SCOPE);
      (* If this score or above CRL is probably valid *)
    CRL_SCORE_ISSUER_CERT  = $018 (* CRL issuer is certificate issuer *);
    CRL_SCORE_SAME_PATH    = $008 (* CRL issuer is on certificate path *);
    CRL_SCORE_AKID         = $004 (* CRL issuer matches CRL AKID *);
    CRL_SCORE_TIME_DELTA   = $002 (* Have a delta CRL with valid times *);
    DANETLS_NONE           = 256 (* impossible uint8_t *);
    S_DOUNTRUSTED          = (1 shl 0) (* Search untrusted chain *);
    S_DOTRUSTED            = (1 shl 1) (* Search trusted store *);
    S_DOALTERNATE          = (1 shl 2) (* Retry with pruned alternate chain *);

  function null_callback(ok : integer;e : PX509_STORE_CTX):integer;
  function X509_self_signed(cert : PX509; verify_signature : integer):integer;
  function lookup_cert_match(result1 : ppX509; ctx : PX509_STORE_CTX; x : PX509):integer;

  function verify_cb_cert(ctx : PX509_STORE_CTX; x : PX509; depth, err : integer):integer;
  function check_auth_level(ctx : PX509_STORE_CTX):integer;
  function verify_chain(ctx : PX509_STORE_CTX):integer;
  function X509_STORE_CTX_verify(ctx : PX509_STORE_CTX):integer;
  function X509_verify_cert(ctx : PX509_STORE_CTX):integer;
  function sk_X509_contains(sk: PSTACK_st_X509;  cert : PX509):integer;
  function find_issuer(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509; x : PX509): PX509;
  function check_issued(ctx: PX509_STORE_CTX;x, issuer : PX509):integer;
  function get_issuer_sk(issuer : PPX509; ctx : PX509_STORE_CTX; x : PX509):integer;
  function check_purpose(ctx : PX509_STORE_CTX; x : PX509; purpose, depth, must_be_ca : integer):integer;
  function check_extensions(ctx : PX509_STORE_CTX):integer;
  function has_san_id( x : PX509; gtype : integer):integer;
  function check_name_constraints(ctx : PX509_STORE_CTX):integer;
  function check_id_error(ctx : PX509_STORE_CTX; errcode : integer):integer;
  function check_hosts( x : PX509; vpm : PX509_VERIFY_PARAM):Integer;
  function check_id(ctx : PX509_STORE_CTX):integer;
  function check_trust(ctx : PX509_STORE_CTX; num_untrusted : integer):integer;
  function check_revocation(ctx : PX509_STORE_CTX):integer;
  function check_cert(ctx : PX509_STORE_CTX):integer;
  function check_crl_time(ctx : PX509_STORE_CTX; crl : PX509_CRL; notify : integer):integer;
  function get_crl_sk(ctx : PX509_STORE_CTX; pcrl, pdcrl : PPX509_CRL;
                    pissuer : PPX509; pscore : Pinteger; preasons : Puint32;
                    crls: PSTACK_st_X509_CRL):integer;
  function crl_extension_match(a, b : PX509_CRL; nid : integer):integer;
  function check_delta_base(delta, base : PX509_CRL):integer;
  procedure get_delta_sk(ctx : PX509_STORE_CTX; dcrl : PPX509_CRL;
                       pscore : Pinteger; base : PX509_CRL;
                       crls: PSTACK_st_X509_CRL);
  function get_crl_score(ctx : PX509_STORE_CTX; pissuer : PPX509; preasons : Puint32; crl : PX509_CRL; x : PX509):integer;
  procedure crl_akid_check(ctx : PX509_STORE_CTX; crl : PX509_CRL; pissuer : PPX509; pcrl_score : Pinteger);
  function crl_crldp_check( x : PX509; crl : PX509_CRL; crl_score : integer;preasons : Puint32):integer;
  function check_crl_path(ctx : PX509_STORE_CTX; x : PX509):integer;
  function check_crl_chain(ctx : PX509_STORE_CTX;cert_path,
                          crl_path: PSTACK_st_X509):integer;
  function idp_check_dp(a, b : PDIST_POINT_NAME):integer;
  function crldp_check_crlissuer(dp : PDIST_POINT; crl : PX509_CRL; crl_score : integer):integer;
  //function crl_crldp_check( x : PX509; crl : PX509_CRL; crl_score : integer;var preasons : uint32):integer;
  function get_crl_delta(ctx : PX509_STORE_CTX; pcrl, pdcrl : PPX509_CRL; x : PX509):integer;
  function check_crl(ctx : PX509_STORE_CTX; crl : PX509_CRL):integer;
  function cert_crl(ctx : PX509_STORE_CTX; crl : PX509_CRL; x : PX509):integer;
  function check_policy(ctx : PX509_STORE_CTX):integer;
  function ossl_x509_check_cert_time(ctx : PX509_STORE_CTX; x : PX509; depth : integer):integer;
  function internal_verify(ctx : PX509_STORE_CTX):integer;
  function X509_cmp_current_time(const ctm : PASN1_TIME):integer;
  function X509_cmp_time( ctm : PASN1_TIME; cmp_time : Ptime_t):integer;
  function X509_cmp_timeframe(const vpm : PX509_VERIFY_PARAM; const start, _end : PASN1_TIME):integer;
  function X509_gmtime_adj(s : PASN1_TIME; adj : long):PASN1_TIME;
  function X509_time_adj(s : PASN1_TIME; offset_sec : long;in_tm : Ptime_t): PASN1_TIME;
  function X509_time_adj_ex(s : PASN1_TIME; offset_day : integer; offset_sec : long; in_tm : Ptime_t):PASN1_TIME;
  function X509_get_pubkey_parameters(pkey : PEVP_PKEY; chain: PSTACK_st_X509):integer;
  function X509_CRL_diff(base, newer : PX509_CRL; skey : PEVP_PKEY; const md : PEVP_MD; flags : uint32):PX509_CRL;
  function X509_STORE_CTX_set_ex_data(ctx : PX509_STORE_CTX; idx : integer; data: Pointer):integer;
  function X509_STORE_CTX_get_ex_data(ctx : PX509_STORE_CTX; idx : integer): Pointer;
  function X509_STORE_CTX_get_error(ctx : PX509_STORE_CTX):integer;
  procedure X509_STORE_CTX_set_error(ctx : PX509_STORE_CTX; err : integer);
  function X509_STORE_CTX_get_error_depth(ctx : PX509_STORE_CTX):integer;
  procedure X509_STORE_CTX_set_error_depth(ctx : PX509_STORE_CTX; depth : integer);
  function X509_STORE_CTX_get_current_cert(const ctx : PX509_STORE_CTX):PX509;
  procedure X509_STORE_CTX_set_current_cert(ctx : PX509_STORE_CTX; x : PX509);
  function X509_STORE_CTX_get0_current_issuer(ctx : PX509_STORE_CTX):PX509;
  function X509_STORE_CTX_get0_current_crl(ctx : PX509_STORE_CTX):PX509_CRL;
  function X509_STORE_CTX_get0_parent_ctx(ctx : PX509_STORE_CTX):PX509_STORE_CTX;
  procedure X509_STORE_CTX_set_cert(ctx : PX509_STORE_CTX; x : PX509);
  procedure X509_STORE_CTX_set0_crls(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509_CRL);
  function X509_STORE_CTX_set_purpose(ctx : PX509_STORE_CTX; purpose : integer):integer;
  function X509_STORE_CTX_set_trust(ctx : PX509_STORE_CTX; trust : integer):integer;
  function X509_STORE_CTX_purpose_inherit(ctx : PX509_STORE_CTX; def_purpose, purpose, trust : integer):integer;
  function X509_STORE_CTX_new_ex(libctx : POSSL_LIB_CTX; const propq : PUTF8Char): PX509_STORE_CTX;
  function X509_STORE_CTX_new:PX509_STORE_CTX;
  procedure X509_STORE_CTX_free(ctx : PX509_STORE_CTX);
  function X509_STORE_CTX_init(ctx : PX509_STORE_CTX; store : PX509_STORE;
                       x509 : PX509; chain: PSTACK_st_X509):integer;
  procedure X509_STORE_CTX_set0_trusted_stack(ctx : PX509_STORE_CTX;sk: PSTACK_st_X509);
  procedure X509_STORE_CTX_cleanup(ctx : PX509_STORE_CTX);
  procedure X509_STORE_CTX_set_depth(ctx : PX509_STORE_CTX; depth : integer);
  procedure X509_STORE_CTX_set_flags(ctx : PX509_STORE_CTX; flags : uint32);
  procedure X509_STORE_CTX_set_time(ctx : PX509_STORE_CTX; flags : uint32; t : time_t);
  function X509_STORE_CTX_get0_cert(ctx : PX509_STORE_CTX): PX509;
  procedure X509_STORE_CTX_set0_untrusted(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509);
  procedure X509_STORE_CTX_set0_verified_chain(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509);
  procedure X509_STORE_CTX_set_verify_cb(ctx : PX509_STORE_CTX; verify_cb : X509_STORE_CTX_verify_cb);
  function X509_STORE_CTX_get_verify_cb(ctx : PX509_STORE_CTX):X509_STORE_CTX_verify_cb;
  procedure X509_STORE_CTX_set_verify(ctx : PX509_STORE_CTX; verify : X509_STORE_CTX_verify_fn);
  function X509_STORE_CTX_get_verify(ctx : PX509_STORE_CTX):X509_STORE_CTX_verify_fn;
  function X509_STORE_CTX_get_get_issuer(ctx : PX509_STORE_CTX):X509_STORE_CTX_get_issuer_fn;
  function X509_STORE_CTX_get_check_issued(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_issued_fn;
  function X509_STORE_CTX_get_check_revocation(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_revocation_fn;
  function X509_STORE_CTX_get_get_crl(ctx : PX509_STORE_CTX):X509_STORE_CTX_get_crl_fn;
  function X509_STORE_CTX_get_check_crl(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_crl_fn;
  function X509_STORE_CTX_get_cert_crl(ctx : PX509_STORE_CTX):X509_STORE_CTX_cert_crl_fn;
  function X509_STORE_CTX_get_check_policy(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_policy_fn;
  function X509_STORE_CTX_get_lookup_certs(ctx : PX509_STORE_CTX):X509_STORE_CTX_lookup_certs_fn;
  function X509_STORE_CTX_get_lookup_crls(ctx : PX509_STORE_CTX):X509_STORE_CTX_lookup_crls_fn;
  function X509_STORE_CTX_get_cleanup(ctx : PX509_STORE_CTX):X509_STORE_CTX_cleanup_fn;
  function X509_STORE_CTX_get0_policy_tree(ctx : PX509_STORE_CTX):PX509_POLICY_TREE;
  function X509_STORE_CTX_get_explicit_policy(ctx : PX509_STORE_CTX):integer;
  function X509_STORE_CTX_get_num_untrusted(ctx : PX509_STORE_CTX):integer;
  function X509_STORE_CTX_set_default(ctx : PX509_STORE_CTX; const name : PUTF8Char):integer;
  function X509_STORE_CTX_get0_param(const ctx : PX509_STORE_CTX):PX509_VERIFY_PARAM;
  procedure X509_STORE_CTX_set0_param(ctx : PX509_STORE_CTX; param : PX509_VERIFY_PARAM);
  procedure X509_STORE_CTX_set0_dane(ctx : PX509_STORE_CTX; dane : PSSL_DANE);
  function dane_match(ctx : PX509_STORE_CTX; cert : PX509; depth : integer):integer;
  function check_dane_issuer(ctx : PX509_STORE_CTX; depth : integer):integer;
  function check_dane_pkeys(ctx : PX509_STORE_CTX):integer;
  procedure dane_reset(dane : PSSL_DANE);
  function check_leaf_suiteb(ctx : PX509_STORE_CTX; cert : PX509):integer;
  function dane_verify(ctx : PX509_STORE_CTX):integer;
  function get1_trusted_issuer( issuer : PPX509; ctx : PX509_STORE_CTX; cert : PX509):integer;
  function build_chain(ctx : PX509_STORE_CTX):integer;
  function check_key_level(ctx : PX509_STORE_CTX; cert : PX509):integer;
  function check_curve(cert : PX509):integer;
  function check_sig_level(ctx : PX509_STORE_CTX; cert : PX509):integer;
  function verify_cb_crl( ctx : PX509_STORE_CTX; err : integer):integer;
  function lookup_certs_sk(ctx : PX509_STORE_CTX;const nm : PX509_NAME):PSTACK_st_X509;

  function sk_X509_TRUST_find(sk, ptr: Pointer): int;
  function sk_X509_TRUST_value(sk: Pointer; idx: int): PX509_TRUST;
  function ossl_check_X509_TRUST_type( ptr : PX509_TRUST):PX509_TRUST;
  function ossl_check_const_X509_TRUST_sk_type(const sk : Pstack_st_X509_TRUST):POPENSSL_STACK;
  function ossl_check_X509_TRUST_sk_type( sk : Pstack_st_X509_TRUST):POPENSSL_STACK;
  function ossl_check_X509_TRUST_compfunc_type( cmp : sk_X509_TRUST_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_TRUST_copyfunc_type( cpy : sk_X509_TRUST_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_TRUST_freefunc_type( fr : sk_X509_TRUST_freefunc):OPENSSL_sk_freefunc;
  function sk_X509_OBJECT_find_all(sk, ptr: Pointer; pnum: PInteger): int;
  function sk_X509_OBJECT_value(sk: Pointer; idx: int):PX509_OBJECT;
  function sk_X509_LOOKUP_num(sk: Pointer): int;
  function sk_X509_LOOKUP_value(sk: Pointer; idx: int): PX509_LOOKUP;

  function ossl_check_X509_LOOKUP_type( ptr : PX509_LOOKUP):PX509_LOOKUP;
  function ossl_check_const_X509_LOOKUP_sk_type(const sk : Pstack_st_X509_LOOKUP):POPENSSL_STACK;
  function ossl_check_X509_LOOKUP_sk_type( sk : Pstack_st_X509_LOOKUP):POPENSSL_STACK;
  function ossl_check_X509_LOOKUP_compfunc_type( cmp : sk_X509_LOOKUP_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_LOOKUP_copyfunc_type( cpy : sk_X509_LOOKUP_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_LOOKUP_freefunc_type( fr : sk_X509_LOOKUP_freefunc):OPENSSL_sk_freefunc;

  function ossl_check_X509_OBJECT_type( ptr : PX509_OBJECT):PX509_OBJECT;
  function ossl_check_const_X509_OBJECT_sk_type(const sk : Pstack_st_X509_OBJECT):POPENSSL_STACK;
  function ossl_check_X509_OBJECT_sk_type( sk : Pstack_st_X509_OBJECT):POPENSSL_STACK;
  function ossl_check_X509_OBJECT_compfunc_type( cmp : sk_X509_OBJECT_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_OBJECT_copyfunc_type( cpy : sk_X509_OBJECT_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_OBJECT_freefunc_type( fr : sk_X509_OBJECT_freefunc):OPENSSL_sk_freefunc;
  function sk_X509_VERIFY_PARAM_find(sk, ptr: Pointer): int;
  function sk_X509_VERIFY_PARAM_value(sk: Pointer; idx: int): PX509_VERIFY_PARAM;

  function ossl_check_X509_VERIFY_PARAM_type( ptr : PX509_VERIFY_PARAM):PX509_VERIFY_PARAM;
  function ossl_check_const_X509_VERIFY_PARAM_sk_type(const sk : Pstack_st_X509_VERIFY_PARAM):POPENSSL_STACK;
  function ossl_check_X509_VERIFY_PARAM_sk_type( sk : Pstack_st_X509_VERIFY_PARAM):POPENSSL_STACK;
  function ossl_check_X509_VERIFY_PARAM_compfunc_type( cmp : sk_X509_VERIFY_PARAM_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_VERIFY_PARAM_copyfunc_type( cpy : sk_X509_VERIFY_PARAM_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_VERIFY_PARAM_freefunc_type( fr : sk_X509_VERIFY_PARAM_freefunc):OPENSSL_sk_freefunc;

{
var
    cnm                    : PX509_NAME = X509_CRL_get_issuer(crl);
    nm                     : PX509_NAME = X509_CRL_get_issuer(crl);
    nm                     : PX509_NAME = X509_get_issuer_name(x);

    utctime_length         : size_t = sizeof('YYMMDDHHMMSSZ') - 1;
    generalizedtime_length : size_t = sizeof('YYYYMMDDHHMMSSZ') - 1;

    upper_z                : byte = $5A;
    upper_z                : byte = 'Z';

    md                     : ^EVP_MD = dane->dctx->mdevp[mtype = t->mtype];

    NUM_AUTH_LEVELS        : integer = OSSL_NELEM(minbits_table);

    x                      : ^X509;

    i                      : integer;

    buf                    : ^byte;

    len,
    finish_chain           : integer;

    ctx                    : ^X509_STORE_CTX;

    flags                  : integer;

  err,
err,
  err                    : &goto;
}
const // 1d arrays
    minbits_table : array[0..4] of integer = (80, 112, 128, 192, 256 );

var
    NUM_AUTH_LEVELS: SmallInt;



implementation
uses OpenSSL3.Err, OpenSSL3.dane,  OpenSSL3.crypto.x509.v3_purp,
     openssl3.crypto.x509,
     openssl3.crypto.t_x509,        OpenSSL3.crypto.x509.x509_cmp,
     openssl3.crypto.x509v3,        openssl3.crypto.stack, openssl3.crypto.mem,
     openssl3.crypto.x509.x_crl,    openssl3.crypto.o_str, OpenSSL3.common,
     openssl3.crypto.evp.p_lib,     openssl3.crypto.x509.x_x509,
     OpenSSL3.crypto.x509.v3_asid,  OpenSSL3.crypto.x509.v3_addr,
     OpenSSL3.crypto.x509.x509name, openssl3.crypto.asn1.x_algor,
     OpenSSL3.crypto.x509.x509_ext, openssl3.crypto.x509.v3_genn,
     openssl3.crypto.asn1.a_time,   openssl3.crypto.x509.x509_trust,
     OpenSSL3.crypto.x509.x_name,   openssl3.crypto.objects.obj_dat,
     OpenSSL3.crypto.x509.v3_ncons, OpenSSL3.crypto.x509.v3_utl,
     openssl3.crypto.x509.x_all,    openssl3.providers.fips.fipsprov,
     openssl3.crypto.asn1.a_octet,  openssl3.crypto.asn1.a_int,
     openssl3.crypto.x509.pcy_tree, openssl3.crypto.asn1.a_utctm,
     OpenSSL3.crypto.x509.x509cset, openssl3.crypto.x509.x509_v3,
     openssl3.crypto.x509.x509_vpm, openssl3.crypto.asn1.a_gentm,
     openssl3.crypto.ex_data,       openssl3.crypto.x509.x509_lu,
     openssl3.crypto.x509.x509_obj, openssl3.crypto.evp.digest,
     openssl3.crypto.x509.x_pubkey, OpenSSL3.crypto.x509.x509_set;


function ossl_check_X509_VERIFY_PARAM_type( ptr : PX509_VERIFY_PARAM):PX509_VERIFY_PARAM;
begin
 Exit(ptr);
end;


function ossl_check_const_X509_VERIFY_PARAM_sk_type(const sk : Pstack_st_X509_VERIFY_PARAM):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_VERIFY_PARAM_sk_type( sk : Pstack_st_X509_VERIFY_PARAM):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_VERIFY_PARAM_compfunc_type( cmp : sk_X509_VERIFY_PARAM_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_VERIFY_PARAM_copyfunc_type( cpy : sk_X509_VERIFY_PARAM_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_VERIFY_PARAM_freefunc_type( fr : sk_X509_VERIFY_PARAM_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

(********************************x509_vfy.h************************************)

function sk_X509_VERIFY_PARAM_value(sk: Pointer; idx: int): PX509_VERIFY_PARAM;
begin
   Result := PX509_VERIFY_PARAM(OPENSSL_sk_value(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk), idx))
end;

function sk_X509_VERIFY_PARAM_find(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_VERIFY_PARAM_sk_type(sk),
                             ossl_check_X509_VERIFY_PARAM_type(ptr))
end;


function ossl_check_X509_OBJECT_type( ptr : PX509_OBJECT):PX509_OBJECT;
begin
 Exit(ptr);
end;


function ossl_check_const_X509_OBJECT_sk_type(const sk : Pstack_st_X509_OBJECT):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_OBJECT_sk_type( sk : Pstack_st_X509_OBJECT):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_OBJECT_compfunc_type( cmp : sk_X509_OBJECT_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_OBJECT_copyfunc_type( cpy : sk_X509_OBJECT_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_OBJECT_freefunc_type( fr : sk_X509_OBJECT_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function ossl_check_X509_LOOKUP_type( ptr : PX509_LOOKUP):PX509_LOOKUP;
begin
 Exit(ptr);
end;


function ossl_check_const_X509_LOOKUP_sk_type(const sk : Pstack_st_X509_LOOKUP):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_X509_LOOKUP_sk_type( sk : Pstack_st_X509_LOOKUP):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_LOOKUP_compfunc_type( cmp : sk_X509_LOOKUP_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_LOOKUP_copyfunc_type( cpy : sk_X509_LOOKUP_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_LOOKUP_freefunc_type( fr : sk_X509_LOOKUP_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509_LOOKUP_value(sk: Pointer; idx: int): PX509_LOOKUP;
begin
   Result := PX509_LOOKUP(OPENSSL_sk_value(ossl_check_const_X509_LOOKUP_sk_type(sk), idx))
end;

function sk_X509_LOOKUP_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_X509_LOOKUP_sk_type(sk))
end;

function sk_X509_OBJECT_value(sk: Pointer; idx: int):PX509_OBJECT;
begin
   Result := PX509_OBJECT(OPENSSL_sk_value(ossl_check_const_X509_OBJECT_sk_type(sk), idx));
end;

function sk_X509_OBJECT_find_all(sk, ptr: Pointer; pnum: PInteger): int;
begin
   Result := OPENSSL_sk_find_all(ossl_check_X509_OBJECT_sk_type(sk),
                       ossl_check_X509_OBJECT_type(ptr), pnum)
end;

function ossl_check_X509_TRUST_type( ptr : PX509_TRUST):PX509_TRUST;
begin
 Exit(ptr);
end;


function ossl_check_const_X509_TRUST_sk_type(const sk : Pstack_st_X509_TRUST):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_TRUST_sk_type( sk : Pstack_st_X509_TRUST):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_TRUST_compfunc_type( cmp : sk_X509_TRUST_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_TRUST_copyfunc_type( cpy : sk_X509_TRUST_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_TRUST_freefunc_type( fr : sk_X509_TRUST_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509_TRUST_value(sk: Pointer; idx: int): PX509_TRUST;
begin
    Result := PX509_TRUST(OPENSSL_sk_value(ossl_check_const_X509_TRUST_sk_type(sk), idx))
end;

function sk_X509_TRUST_find(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_TRUST_sk_type(sk),
                             ossl_check_X509_TRUST_type(ptr))
end;


function dane_i2d( cert : PX509; selector : byte; i2dlen : Puint32):PByte;
var
  buf : Pbyte;
  len : integer;
begin
    buf := nil;
    {
     * Extract ASN.1 DER form of certificate or public key.
     }
    case selector of
    DANETLS_SELECTOR_CERT:
        len := i2d_X509(cert, @buf);
        //break;
    DANETLS_SELECTOR_SPKI:
        len := i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), @buf);
        //break;
    else
        ERR_raise(ERR_LIB_X509, X509_R_BAD_SELECTOR);
        //Exit(nil);
    end;
    if (len < 0)  or  (buf = nil) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    i2dlen^ := uint32(len);
    Result := buf;
end;

function lookup_certs_sk(ctx : PX509_STORE_CTX;const nm : PX509_NAME):PSTACK_st_X509;
var
  sk : PSTACK_st_X509;

  x : PX509;

  i : integer;
begin
    sk := sk_X509_new_null();
    if sk = nil then Exit(nil);
    for i := 0 to sk_X509_num(ctx.other_ctx)-1 do begin
        x := sk_X509_value(ctx.other_ctx, i);
        if X509_NAME_cmp(nm, X509_get_subject_name(x)  ) = 0 then
        begin
            if  0>= X509_add_cert(sk, x, X509_ADD_FLAG_UP_REF) then
            begin
                OSSL_STACK_OF_X509_free(sk);
                ctx.error := X509_V_ERR_OUT_OF_MEM;
                Exit(nil);
            end;
        end;
    end;
    Result := sk;
end;

function verify_cb_crl( ctx : PX509_STORE_CTX; err : integer):integer;
begin
    ctx.error := err;
    Result := ctx.verify_cb(0, ctx);
end;

function null_callback(ok : integer;e : PX509_STORE_CTX):integer;
begin
    Result := ok;
end;


function X509_self_signed(cert : PX509; verify_signature : integer):integer;
var
  pkey : PEVP_PKEY;
begin
    pkey := X509_get0_pubkey(cert);
    if  pkey = nil then
    begin  { handles cert = nil }
        ERR_raise(ERR_LIB_X509, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY);
        Exit(-1);
    end;
    if  0>= ossl_x509v3_cache_extensions(cert) then
        Exit(-1);
    if (cert.ex_flags and EXFLAG_SS)  = 0 then
        Exit(0);
    if  0>= verify_signature then
        Exit(1);
    Result := X509_verify(cert, pkey);
end;


function lookup_cert_match(result1 : ppX509; ctx : PX509_STORE_CTX; x : PX509):integer;
var
  xtmp : PX509;
  certs: PSTACK_st_X509;
  i, ret : integer;
begin

    xtmp := nil;
    result1^ := nil;
    { Lookup all certs with matching subject name }
    ERR_set_mark();
    certs := ctx.lookup_certs(ctx, X509_get_subject_name(x));
    ERR_pop_to_mark();
    if certs = nil then
       Exit(-1);
    { Look for exact match }
    for i := 0 to sk_X509_num(certs)-1 do
    begin
        xtmp := sk_X509_value(certs, i);
        if X509_cmp(xtmp, x ) = 0 then
            break;
        xtmp := nil;
    end;
    ret := Int(xtmp <> nil);
    if ret > 0 then
    begin
        if  0>= X509_up_ref(xtmp) then
            ret := -1
        else
            result1^ := xtmp;
    end;
    OSSL_STACK_OF_X509_free(certs);
    Result := ret;
end;


function verify_cb_cert(ctx : PX509_STORE_CTX; x : PX509; depth, err : integer):integer;
begin
    if depth < 0 then
       depth := ctx.error_depth
    else
        ctx.error_depth := depth;
    if x <> nil then
       ctx.current_cert := x
    else
       ctx.current_cert := sk_X509_value(ctx.chain, depth);
    if err <> X509_V_OK then
       ctx.error := err;
    Result := ctx.verify_cb(0, ctx);
end;

function CB_FAIL_IF(cond: Boolean; ctx : PX509_STORE_CTX; cert : PX509; depth, err : integer): int;
begin
   if (cond) and (verify_cb_cert(ctx, cert, depth, err) = 0) then
       Result := 0 ;
end;

function check_auth_level(ctx : PX509_STORE_CTX):integer;
var
  i, num : integer;

  cert : PX509;
begin
    num := sk_X509_num(ctx.chain);
    if ctx.param.auth_level <= 0 then
       Exit(1);
    for i := 0 to  num - 1 do
    begin
        cert := sk_X509_value(ctx.chain, i);
        {
         * We've already checked the security of the leaf key, so here we only
         * check the security of issuer keys.
         }
        CB_FAIL_IF(  ( (i > 0)  and (0 >= check_key_level(ctx, cert) )),
                   ctx, cert, i, X509_V_ERR_CA_KEY_TOO_SMALL);
        {
         * We also check the signature algorithm security of all certificates
         * except those of the trust anchor at index num-1.
         }
        CB_FAIL_IF( ( (i < num - 1)  and (0>= check_sig_level(ctx, cert) )),
                   ctx, cert, i, X509_V_ERR_CA_MD_TOO_WEAK);
    end;
    Result := 1;
end;


function verify_chain(ctx : PX509_STORE_CTX):integer;
var
  err, ok, ok1 : integer;
begin
  if X509_get_pubkey_parameters(nil, ctx.chain) > 0 then
     ok1  := 1
  else
     ok1 := -1;
  if (build_chain(ctx) <= 0 ) or
     (check_extensions(ctx) <= 0) or
     (check_auth_level(ctx) <= 0) or
     (check_id(ctx) <= 0 ) or
     (ctx.check_revocation(ctx) <= 0) or
     (ok1 <=0 ) then
     Exit(0);

    err := X509_chain_check_suiteb(@ctx.error_depth, nil, ctx.chain,
                                  ctx.param.flags);
    CB_FAIL_IF(err <> X509_V_OK, ctx, nil, ctx.error_depth, err);
    { Verify chain signatures and expiration times }
    if Assigned(ctx.verify )  then
       ok :=  ctx.verify(ctx)
    else
       ok := internal_verify(ctx);
    if ok <= 0 then
       Exit(ok);
    ok := check_name_constraints(ctx);
    if ok <= 0 then
        Exit(ok);
{$IFNDEF OPENSSL_NO_RFC3779}
    { RFC 3779 path validation, now that CRL check has been done }
    ok := X509v3_asid_validate_path(ctx);
    if ok  <= 0 then
        Exit(ok);
    ok := X509v3_addr_validate_path(ctx);
    if ok <= 0 then
        Exit(ok);
{$ENDIF}
    { If we get this far evaluate policies }
    if (ctx.param.flags > 0) and (X509_V_FLAG_POLICY_CHECK  <> 0) then
        ok := ctx.check_policy(ctx);
    Result := ok;
end;


function X509_STORE_CTX_verify(ctx : PX509_STORE_CTX):integer;
begin
    if ctx = nil then begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if (ctx.cert = nil)  and  (sk_X509_num(ctx.untrusted)  >= 1) then
        ctx.cert := sk_X509_value(ctx.untrusted, 0);
    Result := X509_verify_cert(ctx);
end;


function X509_verify_cert(ctx : PX509_STORE_CTX):integer;
var
  ret : integer;
begin
    if ctx = nil then begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    if ctx.cert = nil then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
        ctx.error := X509_V_ERR_INVALID_CALL;
        Exit(-1);
    end;
    if ctx.chain <> nil then
    begin
        {
         * This X509_STORE_CTX has already been used to verify a cert. We
         * cannot do another one.
         }
        ERR_raise(ERR_LIB_X509, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        ctx.error := X509_V_ERR_INVALID_CALL;
        Exit(-1);
    end;
    if  0>= ossl_x509_add_cert_new(&ctx.chain, ctx.cert, X509_ADD_FLAG_UP_REF ) then
    begin
        ctx.error := X509_V_ERR_OUT_OF_MEM;
        Exit(-1);
    end;
    ctx.num_untrusted := 1;
    { If the peer's public key is too weak, we can stop early. }
    CB_FAIL_IF( (0>= check_key_level(ctx, ctx.cert) ),
               ctx, ctx.cert, 0, X509_V_ERR_EE_KEY_TOO_SMALL);
    if DANETLS_ENABLED(ctx.dane) then
       ret := dane_verify(ctx)
    else
       ret := verify_chain(ctx);
    {
     * Safety-net.  If we are returning an error, we must also set ctx.error,
     * so that the chain is not considered verified should the error be ignored
     * (e.g. TLS with SSL_VERIFY_NONE).
     }
    if (ret <= 0)  and  (ctx.error = X509_V_OK) then
       ctx.error := X509_V_ERR_UNSPECIFIED;
    Result := ret;
end;


function sk_X509_contains(sk: PSTACK_st_X509 ; cert : PX509):integer;
var
  i, n : integer;
begin
    n := sk_X509_num(sk);
    for i := 0 to n-1 do
        if X509_cmp(sk_X509_value(sk, i)  , cert) = 0 then
            Exit(1);
    Result := 0;
end;


function find_issuer(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509 ; x : PX509): PX509;
var
  i,n : integer;

  issuer, rv : PX509;
begin
    rv := nil;
    for i := 0 to sk_X509_num(sk)-1 do
    begin
        issuer := sk_X509_value(sk, i);
        n := x.ex_flags and EXFLAG_SI;
        if ( ctx.check_issued(ctx, x, issuer) >0 )   and
           ( ( (n <> 0)  and (sk_X509_num(ctx.chain) = 1) ) or
             (0>= sk_X509_contains(ctx.chain, issuer))
           ) then
        begin
            if ossl_x509_check_cert_time(ctx, issuer, -1)>0 then
                Exit(issuer);
            if (rv = nil)  or  (ASN1_TIME_compare(X509_get0_notAfter(issuer)  ,
                                                  X509_get0_notAfter(rv)) > 0) then
                rv := issuer;
        end;
    end;
    Result := rv;
end;


function check_issued(ctx: PX509_STORE_CTX;x, issuer : PX509):integer;
var
  err : integer;
begin
    err := ossl_x509_likely_issued(issuer, x);
    if err = X509_V_OK then Exit(1);
    {
     * SUBJECT_ISSUER_MISMATCH just means 'x' is clearly not issued by 'issuer'.
     * Every other error code likely indicates a real error.
     }
    if err <> X509_V_ERR_SUBJECT_ISSUER_MISMATCH then
       ctx.error := err;
    Result := 0;
end;


function get_issuer_sk(issuer : PPX509; ctx : PX509_STORE_CTX; x : PX509):integer;
begin
    issuer^ := find_issuer(ctx, ctx.other_ctx, x);
    if issuer^ <> nil then
       Exit(get_result(X509_up_ref( issuer^) > 0, 1 , -1));
    Result := 0;
end;


function check_purpose(ctx : PX509_STORE_CTX; x : PX509; purpose, depth, must_be_ca : integer):integer;
var
  tr_ok : integer;
begin
    tr_ok := X509_TRUST_UNTRUSTED;
    {
     * For trusted certificates we want to see whether any auxiliary trust
     * settings trump the purpose constraints.
     *
     * This is complicated by the fact that the trust ordinals in
     * ctx.param.trust are entirely independent of the purpose ordinals in
     * ctx.param.purpose!
     *
     * What connects them is their mutual initialization via calls from
     * X509_STORE_CTX_set_default() into X509_VERIFY_PARAM_lookup() which sets
     * related values of both param.trust and param.purpose.  It is however
     * typically possible to infer associated trust values from a purpose value
     * via the X509_PURPOSE API.
     *
     * Therefore, we can only check for trust overrides when the purpose we're
     * checking is the same as ctx.param.purpose and ctx.param.trust is
     * also set.
     }
    if (depth >= ctx.num_untrusted)  and (purpose = ctx.param.purpose) then
       tr_ok := X509_check_trust(x, ctx.param.trust, X509_TRUST_NO_SS_COMPAT);
    case tr_ok of
      X509_TRUST_TRUSTED:
          Exit(1);
      X509_TRUST_REJECTED:
      begin
        //
      end;
      else
      begin
          case X509_check_purpose(x, purpose, int(must_be_ca > 0) ) of
          1:
              Exit(1);
          0:
              begin
                //
              end;
          else
              if (ctx.param.flags and X509_V_FLAG_X509_STRICT) = 0 then
                  Exit(1);
          end;
      end;
    end;
    Result := verify_cb_cert(ctx, x, depth, X509_V_ERR_INVALID_PURPOSE);
end;


function check_extensions(ctx : PX509_STORE_CTX):integer;
var
  i,
  must_be_ca,
  plen              : integer;
  x                 : PX509;
  ret,
  proxy_path_length,
  purpose           : Integer;
  allow_proxy_certs : Boolean;
  num               : integer;
begin
    plen := 0;
    proxy_path_length := 0;
    num := sk_X509_num(ctx.chain);
    {-
     *  must_be_ca can have 1 of 3 values:
     * -1: we accept both CA and non-CA certificates, to allow direct
     *     use of self-signed certificates (which are marked as CA).
     * 0:  we only accept non-CA certificates.  This is currently not
     *     used, but the possibility is present for future extensions.
     * 1:  we only accept CA certificates.  This is currently used for
     *     all certificates in the chain except the leaf certificate.
     }
    must_be_ca := -1;
    { CRL path validation }
    if ctx.parent <> nil then
    begin
        allow_proxy_certs := Boolean(0);
        purpose := X509_PURPOSE_CRL_SIGN;
    end
    else
    begin
        allow_proxy_certs := (ctx.param.flags and X509_V_FLAG_ALLOW_PROXY_CERTS) <> 0;
        purpose := ctx.param.purpose;
    end;
    for i := 0 to num-1 do
    begin
        x := sk_X509_value(ctx.chain, i);
        CB_FAIL_IF( ( (ctx.param.flags and X509_V_FLAG_IGNORE_CRITICAL) = 0 ) and
                      ( (x.ex_flags and EXFLAG_CRITICAL) <> 0 ),
                   ctx, x, i, X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION);
        CB_FAIL_IF( (not allow_proxy_certs)  and  ((x.ex_flags and EXFLAG_PROXY) <> 0),
                   ctx, x, i, X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED);
        ret := X509_check_ca(x);
        case must_be_ca of
        -1:
            CB_FAIL_IF( ((ctx.param.flags and X509_V_FLAG_X509_STRICT) <> 0)
                            and  (ret <> 1)  and  (ret <> 0),
                       ctx, x, i, X509_V_ERR_INVALID_CA);

        0:
            CB_FAIL_IF(ret <> 0, ctx, x, i, X509_V_ERR_INVALID_NON_CA);

        else
            { X509_V_FLAG_X509_STRICT is implicit for intermediate CAs }
            CB_FAIL_IF( (ret = 0) or
                        ( (  (i + 1 < num ) or ( (ctx.param.flags and X509_V_FLAG_X509_STRICT) <> 0))  and
                          (ret <> 1)
                        ) , ctx, x, i, X509_V_ERR_INVALID_CA);
            break;
        end;
        if num > 1 then begin
            { Check for presence of explicit elliptic curve parameters }
            ret := check_curve(x);
            CB_FAIL_IF(ret < 0, ctx, x, i, X509_V_ERR_UNSPECIFIED);
            CB_FAIL_IF(ret = 0, ctx, x, i, X509_V_ERR_EC_KEY_EXPLICIT_PARAMS);
        end;
        {
         * Do the following set of checks only if strict checking is requested
         * and not for self-issued (including self-signed) EE (non-CA) certs
         * because RFC 5280 does not apply to them according RFC 6818 section 2.
         }
        if ( (ctx.param.flags and X509_V_FLAG_X509_STRICT) <> 0)
             and  (num > 1) then
        begin  {
                           * this should imply
                           * !(i = 0  and  (x.ex_flags and EXFLAG_CA) = 0
                           *           and  (x.ex_flags and EXFLAG_SI) <> 0)
                           }
            { Check Basic Constraints according to RFC 5280 section 4.2.1.9 }
            if x.ex_pathlen <> -1 then
            begin
                CB_FAIL_IF((x.ex_flags and EXFLAG_CA) = 0,
                           ctx, x, i, X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA);
                CB_FAIL_IF((x.ex_kusage and KU_KEY_CERT_SIGN) = 0, ctx,
                           x, i, X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN);
            end;
            CB_FAIL_IF( ((x.ex_flags and EXFLAG_CA) <> 0)  and
                         ((x.ex_flags and EXFLAG_BCONS) <> 0) and
                         ((x.ex_flags and EXFLAG_BCONS_CRITICAL) = 0),
                       ctx, x, i, X509_V_ERR_CA_BCONS_NOT_CRITICAL);
            { Check Key Usage according to RFC 5280 section 4.2.1.3 }
            if (x.ex_flags and EXFLAG_CA) <> 0 then
            begin
                CB_FAIL_IF((x.ex_flags and EXFLAG_KUSAGE) = 0,
                           ctx, x, i, X509_V_ERR_CA_CERT_MISSING_KEY_USAGE);
            end
            else
            begin
                CB_FAIL_IF((x.ex_kusage and KU_KEY_CERT_SIGN) <> 0, ctx, x, i,
                           X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA);
            end;
            { Check issuer is non-empty acc. to RFC 5280 section 4.1.2.4 }
            CB_FAIL_IF(X509_NAME_entry_count(X509_get_issuer_name(x)) = 0,
                       ctx, x, i, X509_V_ERR_ISSUER_NAME_EMPTY);
            { Check subject is non-empty acc. to RFC 5280 section 4.1.2.6 }
            CB_FAIL_IF(( ((x.ex_flags and EXFLAG_CA) <> 0) or
                         ((x.ex_kusage and KU_CRL_SIGN) <> 0) or
                         ( x.altname = nil)
                       )  and
                         (X509_NAME_entry_count(X509_get_subject_name(x)) = 0),
                       ctx, x, i, X509_V_ERR_SUBJECT_NAME_EMPTY);
            CB_FAIL_IF( (X509_NAME_entry_count(X509_get_subject_name(x)) = 0)
                            and  (x.altname <> nil)
                            and  ((x.ex_flags and EXFLAG_SAN_CRITICAL) = 0),
                       ctx, x, i, X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL);
            { Check SAN is non-empty according to RFC 5280 section 4.2.1.6 }
            CB_FAIL_IF( (x.altname <> nil)
                            and  (sk_GENERAL_NAME_num(x.altname) <= 0),
                       ctx, x, i, X509_V_ERR_EMPTY_SUBJECT_ALT_NAME);
            { Check sig alg consistency acc. to RFC 5280 section 4.1.1.2 }
            CB_FAIL_IF(X509_ALGOR_cmp(@x.sig_alg, @x.cert_info.signature) <> 0,
                       ctx, x, i, X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY);
            CB_FAIL_IF( (x.akid <> nil)
                            and  ((x.ex_flags and EXFLAG_AKID_CRITICAL) <> 0),
                       ctx, x, i, X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL);
            CB_FAIL_IF( (x.skid <> nil)
                            and  ((x.ex_flags and EXFLAG_SKID_CRITICAL) <> 0),
                       ctx, x, i, X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL);
            if X509_get_version(x)  >= X509_VERSION_3 then
            begin
                { Check AKID presence acc. to RFC 5280 section 4.2.1.1 }
                CB_FAIL_IF( (i + 1 < num) {
                                        * this means not last cert in chain,
                                        * taken as 'generated by conforming CAs'
                                        }
                            and  ( (x.akid = nil)  or  (x.akid.keyid = nil)), ctx,
                           x, i, X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER);
                { Check SKID presence acc. to RFC 5280 section 4.2.1.2 }
                CB_FAIL_IF( ((x.ex_flags and EXFLAG_CA) <> 0)  and  (x.skid = nil),
                           ctx, x, i, X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER);
            end
            else
            begin
                CB_FAIL_IF(sk_X509_EXTENSION_num(X509_get0_extensions(x)) > 0,
                           ctx, x, i, X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3);
            end;
        end;
        { check_purpose() makes the callback as needed }
        if (purpose > 0)  and
           (0>= check_purpose(ctx, x, purpose, i, must_be_ca)) then
            Exit(0);
        { Check path length }
        CB_FAIL_IF( (i > 1)  and  (x.ex_pathlen <> -1)
                        and  (plen > x.ex_pathlen + proxy_path_length),
                   ctx, x, i, X509_V_ERR_PATH_LENGTH_EXCEEDED);
        { Increment path length if not a self-issued intermediate CA }
        if (i > 0)  and  ((x.ex_flags and EXFLAG_SI) = 0) then
            Inc(plen);
        {
         * If this certificate is a proxy certificate, the next certificate
         * must be another proxy certificate or a EE certificate.  If not,
         * the next certificate must be a CA certificate.
         }
        if (x.ex_flags and EXFLAG_PROXY)>0 then
        begin
            {
             * RFC3820, 4.1.3 (b)(1) stipulates that if pCPathLengthConstraint
             * is less than max_path_length, the former should be copied to
             * the latter, and 4.1.4 (a) stipulates that max_path_length
             * should be verified to be larger than zero and decrement it.
             *
             * Because we're checking the certs in the reverse order, we start
             * with verifying that proxy_path_length isn't larger than pcPLC,
             * and copy the latter to the former if it is, and finally,
             * increment proxy_path_length.
             }
            if x.ex_pcpathlen <> -1 then
            begin
                CB_FAIL_IF(proxy_path_length > x.ex_pcpathlen,
                           ctx, x, i, X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED);
                proxy_path_length := x.ex_pcpathlen;
            end;
            Inc(proxy_path_length);
            must_be_ca := 0;
        end
        else
            must_be_ca := 1;

    end;
    Result := 1;
end;


function has_san_id( x : PX509; gtype : integer):integer;
var
  i, ret : integer;
  gs : PGENERAL_NAMES;
  g : PGENERAL_NAME;
begin
    ret := 0;
    gs := X509_get_ext_d2i(x, NID_subject_alt_name, nil, nil);
    if gs = nil then Exit(0);
    for i := 0 to sk_GENERAL_NAME_num(gs)-1 do
    begin
        g := sk_GENERAL_NAME_value(gs, i);
        if g.&type = gtype then
        begin
            ret := 1;
            break;
        end;
    end;
    GENERAL_NAMES_free(gs);
    Result := ret;
end;


function check_name_constraints(ctx : PX509_STORE_CTX):integer;
var
    i               : integer;
    x               : PX509;
    j               : integer;
    tmpsubject,
    tmpissuer       : PX509_NAME;
    tmpentry        : PX509_NAME_ENTRY;
    last_nid,
    err,
    last_loc        : integer;
    nc              : PNAME_CONSTRAINTS;
    rv,
    ret             : integer;
    label   proxy_name_done;
    function get_ret: Integer;
    begin
      ret := has_san_id(x, GEN_DNS) ;
      Exit(ret);
    end;
begin
    { Check name constraints for all certificates }
    i := sk_X509_num(ctx.chain) - 1;
    while ( i >= 0) do
    begin
        x := sk_X509_value(ctx.chain, i);
        { Ignore self-issued certs unless last in chain }
        if (i <> 0)  and  (x.ex_flags and EXFLAG_SI<> 0)  then
            continue;
        {
         * Proxy certificates policy has an extra constraint, where the
         * certificate subject MUST be the issuer with a single CN entry
         * added.
         * (RFC 3820: 3.4, 4.1.3 (a)(4))
         }
        if (x.ex_flags and EXFLAG_PROXY)  <> 0 then
        begin
            tmpsubject := X509_get_subject_name(x);
            tmpissuer := X509_get_issuer_name(x);
            tmpentry := nil;
            last_nid := 0;
            err := X509_V_OK;
            last_loc := X509_NAME_entry_count(tmpsubject) - 1;
            { Check that there are at least two RDNs }
            if last_loc < 1 then begin
                err := X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                goto proxy_name_done;
            end;
            {
             * Check that there is exactly one more RDN in subject as
             * there is in issuer.
             }
            if X509_NAME_entry_count(tmpsubject) <> X509_NAME_entry_count(tmpissuer) + 1 then
            begin
                err := X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                goto proxy_name_done;
            end;
            {
             * Check that the last subject component isn't part of a
             * multi-valued RDN
             }
            if X509_NAME_ENTRY_set(X509_NAME_get_entry(tmpsubject, last_loc ))
                = X509_NAME_ENTRY_set(X509_NAME_get_entry(tmpsubject,
                                                           last_loc - 1))then
            begin
                err := X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                goto proxy_name_done;
            end;
            {
             * Check that the last subject RDN is a commonName, and that
             * all the previous RDNs match the issuer exactly
             }
            tmpsubject := X509_NAME_dup(tmpsubject);
            if tmpsubject = nil then
            begin
                ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
                ctx.error := X509_V_ERR_OUT_OF_MEM;
                Exit(-1);
            end;
            tmpentry := X509_NAME_delete_entry(tmpsubject, last_loc);
            last_nid := OBJ_obj2nid(X509_NAME_ENTRY_get_object(tmpentry));
            if (last_nid <> NID_commonName)
                 or  (X509_NAME_cmp(tmpsubject, tmpissuer) <> 0)  then
            begin
                err := X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
            end;
            X509_NAME_ENTRY_free(tmpentry);
            X509_NAME_free(tmpsubject);
        proxy_name_done:
            CB_FAIL_IF(err <> X509_V_OK, ctx, x, i, err);
        end;
        {
         * Check against constraints for all certificates higher in chain
         * including trust anchor. Trust anchor not strictly speaking needed
         * but if it includes constraints it is to be assumed it expects them
         * to be obeyed.
         }
        j := sk_X509_num(ctx.chain) - 1;
        while ( j > i) do
        begin
            nc := sk_X509_value(ctx.chain, j).nc;
            if Assigned(nc) then
            begin
                rv := NAME_CONSTRAINTS_check(x, nc);
                ret := 1;
                { If EE certificate check commonName too }
                if (rv = X509_V_OK)  and  (i = 0)
                     and  ( (ctx.param.hostflags and X509_CHECK_FLAG_NEVER_CHECK_SUBJECT) = 0 )
                     and  ( ( (ctx.param.hostflags and X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) <> 0) or
                            (get_ret = 0)
                          ) then
                    rv := NAME_CONSTRAINTS_check_CN(x, nc);
                if (ret < 0) then
                   Exit(ret);
                case rv of
                X509_V_OK:
                begin
                  //
                end;
                X509_V_ERR_OUT_OF_MEM:
                    Exit(-1);
                else
                    CB_FAIL_IF(Boolean(1), ctx, x, i, rv);
                    //break;
                end;
            end;
            Dec(j);
        end;

    end;
    Result := 1;
end;


function check_id_error(ctx : PX509_STORE_CTX; errcode : integer):integer;
begin
    Result := verify_cb_cert(ctx, ctx.cert, 0, errcode);
end;


function check_hosts( x : PX509; vpm : PX509_VERIFY_PARAM):integer;
var
  i, n : integer;

  name : PUTF8Char;
begin
    n := sk_OPENSSL_STRING_num(vpm.hosts);
    if vpm.peername <> nil then begin
        OPENSSL_free(vpm.peername);
        vpm.peername := nil;
    end;
    for i := 0 to n-1 do
    begin
        name := sk_OPENSSL_STRING_value(vpm.hosts, i);
        if X509_check_host(x, name, 0, vpm.hostflags, @vpm.peername)  > 0 then
            Exit(1);
    end;
    Result := get_result(n = 0,1,0);
end;


function check_id(ctx : PX509_STORE_CTX):integer;
var
  vpm : PX509_VERIFY_PARAM;

  x : pX509;
begin
    vpm := ctx.param;
    x := ctx.cert;
    if (vpm.hosts <> nil)  and  (check_hosts(x, vpm)  <= 0)then
    begin
        if  0>= check_id_error(ctx, X509_V_ERR_HOSTNAME_MISMATCH) then
            Exit(0);
    end;
    if (vpm.email <> nil)
             and  (X509_check_email(x, vpm.email, vpm.emaillen, 0) <= 0) then
    begin
        if  0>= check_id_error(ctx, X509_V_ERR_EMAIL_MISMATCH) then
            Exit(0);
    end;
    if (vpm.ip <> nil)  and  (X509_check_ip(x, vpm.ip, vpm.iplen, 0) <= 0) then
    begin
        if  0>= check_id_error(ctx, X509_V_ERR_IP_ADDRESS_MISMATCH) then
            Exit(0);
    end;
    Result := 1;
end;


function check_trust(ctx : PX509_STORE_CTX; num_untrusted : integer):integer;
var
  i,
  res      : integer;
  x        : PX509;
  mx       : PX509;
  dane     : PSSL_DANE;
  num,
  trust    : integer;

  label trusted, rejected;

begin
    x := nil;
    dane := ctx.dane;
    num := sk_X509_num(ctx.chain);
    {
     * Check for a DANE issuer at depth 1 or greater, if it is a DANE-TA(2)
     * match, we're done, otherwise we'll merely record the match depth.
     }
    if (DANETLS_HAS_TA(dane) )  and  (num_untrusted > 0)  and  (num_untrusted < num) then
    begin
        trust := check_dane_issuer(ctx, num_untrusted);
        if trust <> X509_TRUST_UNTRUSTED then
           Exit(trust);
    end;
    {
     * Check trusted certificates in chain at depth num_untrusted and up.
     * Note, that depths 0..num_untrusted-1 may also contain trusted
     * certificates, but the caller is expected to have already checked those,
     * and wants to incrementally check just any added since.
     }
    for i := num_untrusted to num-1 do
    begin
        x := sk_X509_value(ctx.chain, i);
        trust := X509_check_trust(x, ctx.param.trust, 0);
        { If explicitly trusted (so not neutral nor rejected) return trusted }
        if trust = X509_TRUST_TRUSTED then
            goto trusted;
        if (trust = X509_TRUST_REJECTED) then
            goto trusted;
    end;
    {
     * If we are looking at a trusted certificate, and accept partial chains,
     * the chain is PKIX trusted.
     }
    if num_untrusted < num then  begin
        if (ctx.param.flags and X509_V_FLAG_PARTIAL_CHAIN) <> 0 then
            goto trusted;
        Exit(X509_TRUST_UNTRUSTED);
    end;
    if (num_untrusted = num)      and
       ( (ctx.param.flags and X509_V_FLAG_PARTIAL_CHAIN) <> 0 )  then
    begin
        {
         * Last-resort call with no new trusted certificates, check the leaf
         * for a direct trust store match.
         }
        i := 0;
        x := sk_X509_value(ctx.chain, i);
        res := lookup_cert_match(@mx, ctx, x);
        if res < 0 then
           Exit(res);
        if mx = nil then
           Exit(X509_TRUST_UNTRUSTED);
        {
         * Check explicit auxiliary trust/reject settings.  If none are set,
         * we'll accept X509_TRUST_UNTRUSTED when not self-signed.
         }
        trust := X509_check_trust(mx, ctx.param.trust, 0);
        if trust = X509_TRUST_REJECTED then
        begin
            X509_free(mx);
            goto rejected;
        end;
        { Replace leaf with trusted match }
        sk_X509_set(ctx.chain, 0, mx);
        X509_free(x);
        ctx.num_untrusted := 0;
        goto trusted;
    end;
    {
     * If no trusted certs in chain at all return untrusted and allow
     * standard (no issuer cert) etc errors to be indicated.
     }
    Exit(X509_TRUST_UNTRUSTED);
 rejected:
    if verify_cb_cert(ctx, x, i, X509_V_ERR_CERT_REJECTED) = 0 then
        Exit( X509_TRUST_REJECTED)
    else
       Exit(X509_TRUST_UNTRUSTED);
 trusted:
    if  not DANETLS_ENABLED(dane) then
        Exit(X509_TRUST_TRUSTED);
    if dane.pdpth < 0 then
       dane.pdpth := num_untrusted;
    { With DANE, PKIX alone is not trusted until we have both }
    if dane.mdpth >= 0 then Exit(X509_TRUST_TRUSTED);
    Result := X509_TRUST_UNTRUSTED;
end;


function check_revocation(ctx : PX509_STORE_CTX):integer;
var
  i, last, ok : integer;
begin
    i := 0; last := 0; ok := 0;
    if (ctx.param.flags and X509_V_FLAG_CRL_CHECK ) = 0 then
        Exit(1);
    if (ctx.param.flags and X509_V_FLAG_CRL_CHECK_ALL ) <> 0 then
    begin
        last := sk_X509_num(ctx.chain) - 1;
    end
    else
    begin
        { If checking CRL paths this isn't the EE certificate }
        if Assigned(ctx.parent )then
           Exit(1);
        last := 0;
    end;
    for i := 0 to last do
    begin
        ctx.error_depth := i;
        ok := check_cert(ctx);
        if  0>= ok then Exit(ok);
    end;
    Result := 1;
end;


function check_cert(ctx : PX509_STORE_CTX):integer;
var
  crl,dcrl     : PX509_CRL;
  ok,
  cnum         : integer;
  x            : PX509;
  last_reasons : uint32;

  label done;

begin
    crl := nil; dcrl := nil;
    ok := 0;
    cnum := ctx.error_depth;
    x := sk_X509_value(ctx.chain, cnum);
    ctx.current_cert := x;
    ctx.current_issuer := nil;
    ctx.current_crl_score := 0;
    ctx.current_reasons := 0;
    if (x.ex_flags and EXFLAG_PROXY ) <> 0 then
        Exit(1);
    while ctx.current_reasons <> CRLDP_ALL_REASONS do
    begin
        last_reasons := ctx.current_reasons;
        { Try to retrieve relevant CRL }
        if Assigned(ctx.get_crl)  then
           ok := ctx.get_crl(ctx, @crl, x)
        else
            ok := get_crl_delta(ctx, @crl, @dcrl, x);
        { If error looking up CRL, nothing we can do except notify callback }
        if  0>= ok then
        begin
            ok := verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL);
            goto done;
        end;
        ctx.current_crl := crl;
        ok := ctx.check_crl(ctx, crl);
        if  0>= ok then
            goto done;
        if (dcrl <> nil) then
        begin
            ok := ctx.check_crl(ctx, dcrl);
            if  0>= ok then
                goto done;
            ok := ctx.cert_crl(ctx, dcrl, x);
            if  0>= ok then
               goto done;
        end
        else
        begin
            ok := 1;
        end;
        { Don't look in full CRL if delta reason is removefromCRL }
        if ok <> 2 then
        begin
            ok := ctx.cert_crl(ctx, crl, x);
            if 0>= ok then
               goto done;
        end;
        X509_CRL_free(crl);
        X509_CRL_free(dcrl);
        crl := nil;
        dcrl := nil;
        {
         * If reasons not updated we won't get anywhere by another iteration,
         * so exit loop.
         }
        if last_reasons = ctx.current_reasons then
        begin
            ok := verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL);
            goto done;
        end;
    end;
 done:
    X509_CRL_free(crl);
    X509_CRL_free(dcrl);
    ctx.current_crl := nil;
    Result := ok;
end;


function check_crl_time(ctx : PX509_STORE_CTX; crl : PX509_CRL; notify : integer):integer;
var
  ptime : Ptime_t;

  i : integer;
begin
    if notify>0 then
       ctx.current_crl := crl;
    if (ctx.param.flags and X509_V_FLAG_USE_CHECK_TIME ) <> 0 then
        ptime := @ctx.param.check_time
    else
    if (ctx.param.flags and X509_V_FLAG_NO_CHECK_TIME) <> 0 then
        Exit(1)
    else
        ptime := nil;
    i := X509_cmp_time(X509_CRL_get0_lastUpdate(crl), ptime);
    if i = 0 then
    begin
        if  0>= notify then
            Exit(0);
        if  0>= verify_cb_crl(ctx, X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD ) then
            Exit(0);
    end;
    if i > 0 then
    begin
        if  0>= notify then
            Exit(0);
        if  0>= verify_cb_crl(ctx, X509_V_ERR_CRL_NOT_YET_VALID) then
            Exit(0);
    end;
    if Assigned(X509_CRL_get0_nextUpdate(crl )) then
    begin
        i := X509_cmp_time(X509_CRL_get0_nextUpdate(crl), ptime);
        if i = 0 then
        begin
            if  0>= notify then
                Exit(0);
            if  0>= verify_cb_crl(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD) then
                Exit(0);
        end;
        { Ignore expiration of base CRL is delta is valid }
        if (i < 0)  and  ( (ctx.current_crl_score and CRL_SCORE_TIME_DELTA) = 0) then
        begin
            if  (0>= notify)  or   (0>= verify_cb_crl(ctx, X509_V_ERR_CRL_HAS_EXPIRED)) then
                Exit(0);
        end;
    end;
    if notify>0 then
       ctx.current_crl := nil;
    Result := 1;
end;


function get_crl_sk(ctx : PX509_STORE_CTX; pcrl, pdcrl : PPX509_CRL;
                    pissuer : PPX509; pscore : Pinteger; preasons : Puint32;
                    crls: PSTACK_st_X509_CRL):integer;
var
  i,
  crl_score,
  best_score   : integer;
  reasons,
  best_reasons : uint32;
  x            : PX509;
  crl,
  best_crl     : PX509_CRL;
  crl_issuer,
  best_crl_issuer   : PX509;
  day,
  sec          : integer;
begin
    best_score := pscore^;
    best_reasons := 0;
    x := ctx.current_cert;
    best_crl := nil;
    crl_issuer := nil;
    best_crl_issuer := nil;
    for i := 0 to sk_X509_CRL_num(crls)-1 do
    begin
        crl := sk_X509_CRL_value(crls, i);
        reasons := preasons^;
        crl_score := get_crl_score(ctx, @crl_issuer, @reasons, crl, x);
        if (crl_score < best_score)  or  (crl_score = 0) then
           continue;
        { If current CRL is equivalent use it if it is newer }
        if (crl_score = best_score)  and  (best_crl <> nil) then
        begin
            if ASN1_TIME_diff(@day, @sec, X509_CRL_get0_lastUpdate(best_crl)  ,
                               X509_CRL_get0_lastUpdate(crl)) = 0 then
                continue;
            {
             * ASN1_TIME_diff never returns inconsistent signs for |day|
             * and |sec|.
             }
            if (day <= 0)  and  (sec <= 0) then
               continue;
        end;
        best_crl := crl;
        best_crl_issuer := crl_issuer;
        best_score := crl_score;
        best_reasons := reasons;
    end;
    if best_crl <> nil then
    begin
        X509_CRL_free( pcrl^);
        pcrl^ := best_crl;
        pissuer^ := best_crl_issuer;
        pscore^ := best_score;
        preasons^ := best_reasons;
        X509_CRL_up_ref(best_crl);
        X509_CRL_free( pdcrl^);
        pdcrl^ := nil;
        get_delta_sk(ctx, pdcrl, pscore, best_crl, crls);
    end;
    if best_score >= CRL_SCORE_VALID then
       Exit(1);
    Result := 0;
end;


function crl_extension_match(a, b : PX509_CRL; nid : integer):integer;
var
  exta,extb : PASN1_OCTET_STRING;
  i : integer;
begin
    exta := nil; extb := nil;
    i := X509_CRL_get_ext_by_NID(a, nid, -1);
    if i >= 0 then
    begin
        { Can't have multiple occurrences }
        if X509_CRL_get_ext_by_NID(a, nid, i) <> -1 then
            Exit(0);
        exta := X509_EXTENSION_get_data(X509_CRL_get_ext(a, i));
    end;
    i := X509_CRL_get_ext_by_NID(b, nid, -1);
    if i >= 0 then begin
        if X509_CRL_get_ext_by_NID(b, nid, i) <> -1 then
            Exit(0);
        extb := X509_EXTENSION_get_data(X509_CRL_get_ext(b, i));
    end;
    if (exta = nil)  and  (extb = nil) then
        Exit(1);
    if (exta = nil)  or  (extb = nil) then
        Exit(0);
    Result := Int(ASN1_OCTET_STRING_cmp(exta, extb) = 0);
end;


function check_delta_base(delta, base : PX509_CRL):integer;
begin
    { Delta CRL must be a delta }
    if delta.base_crl_number = nil then
       Exit(0);
    { Base must have a CRL number }
    if base.crl_number = nil then Exit(0);
    { Issuer names must match }
    if X509_NAME_cmp(X509_CRL_get_issuer(base)  ,
                      X509_CRL_get_issuer(delta)) <> 0 then
        Exit(0);
    { AKID and IDP must match }
    if  0>= crl_extension_match(delta, base, NID_authority_key_identifier )  then
        Exit(0);
    if  0>= crl_extension_match(delta, base, NID_issuing_distribution_point ) then
        Exit(0);
    { Delta CRL base number must not exceed Full CRL number. }
    if ASN1_INTEGER_cmp(delta.base_crl_number, base.crl_number)  > 0 then
        Exit(0);
    { Delta CRL number must exceed full CRL number }
    Result := Int(ASN1_INTEGER_cmp(delta.crl_number, base.crl_number) > 0);
end;


procedure get_delta_sk(ctx : PX509_STORE_CTX; dcrl : PPX509_CRL;
                       pscore : Pinteger; base : PX509_CRL;
                       crls: PSTACK_st_X509_CRL);
var
  delta : PX509_CRL;

  i : integer;
begin
    if (ctx.param.flags and X509_V_FLAG_USE_DELTAS) = 0 then
        exit;
    if ((ctx.current_cert.ex_flags or base.flags ) and EXFLAG_FRESHEST) = 0 then
        exit;
    for i := 0 to sk_X509_CRL_num(crls)-1 do
    begin
        delta := sk_X509_CRL_value(crls, i);
        if check_delta_base(delta, base )>0  then
        begin
            if check_crl_time(ctx, delta, 0)>0 then
                pscore^  := pscore^  or CRL_SCORE_TIME_DELTA;
            X509_CRL_up_ref(delta);
            dcrl^ := delta;
            exit;
        end;
    end;
    dcrl^ := nil;
end;


function get_crl_score(ctx : PX509_STORE_CTX; pissuer : PPX509; preasons : Puint32; crl : PX509_CRL; x : PX509):integer;
var
    crl_score   : integer;

    tmp_reasons,
    crl_reasons : uint32;
begin
    crl_score := 0;
    tmp_reasons := preasons^;
    { First see if we can reject CRL straight away }
    { Invalid IDP cannot be processed }
    if (crl.idp_flags and IDP_INVALID ) <> 0 then
        Exit(0);
    { Reason codes or indirect CRLs need extended CRL support }
    if (ctx.param.flags and X509_V_FLAG_EXTENDED_CRL_SUPPORT ) = 0 then
    begin
        if (crl.idp_flags and (IDP_INDIRECT or IDP_REASONS) )>0 then
            Exit(0);
    end
    else
    if ((crl.idp_flags and IDP_REASONS) <> 0) then
    begin
        { If no new reasons reject }
        if (crl.idp_reasons and  not tmp_reasons ) = 0 then
            Exit(0);
    end
    { Don't process deltas at this stage }
    else
    if (crl.base_crl_number <> nil) then
        Exit(0);
    { If issuer name doesn't match certificate need indirect CRL }
    if X509_NAME_cmp(X509_get_issuer_name(x) , X509_CRL_get_issuer(crl)) <> 0 then
    begin
        if (crl.idp_flags and IDP_INDIRECT) = 0 then
            Exit(0);
    end
    else
    begin
        crl_score  := crl_score  or CRL_SCORE_ISSUER_NAME;
    end;
    if (crl.flags and EXFLAG_CRITICAL ) = 0 then
        crl_score  := crl_score  or CRL_SCORE_NOCRITICAL;
    { Check expiration }
    if check_crl_time(ctx, crl, 0)>0   then
        crl_score  := crl_score  or CRL_SCORE_TIME;
    { Check authority key ID and locate certificate issuer }
    crl_akid_check(ctx, crl, pissuer, @crl_score);
    { If we can't locate certificate issuer at this point forget it }
    if (crl_score and CRL_SCORE_AKID ) = 0 then
        Exit(0);
    { Check cert for matching CRL distribution points }
    if crl_crldp_check(x, crl, crl_score, @crl_reasons)>0 then
    begin
        { If no new reasons reject }
        if (crl_reasons and not tmp_reasons) = 0 then
            Exit(0);
        tmp_reasons  := tmp_reasons  or crl_reasons;
        crl_score  := crl_score  or CRL_SCORE_SCOPE;
    end;
    preasons^ := tmp_reasons;
    Exit(crl_score);
end;


procedure crl_akid_check(ctx : PX509_STORE_CTX; crl : PX509_CRL; pissuer : PPX509; pcrl_score : Pinteger);
var
  crl_issuer : PX509;
  cnm        : PX509_NAME;
  cidx,
  i          : integer;
begin
    cnm        := X509_CRL_get_issuer(crl);
    crl_issuer := nil;
    cidx := ctx.error_depth;
    if cidx <> sk_X509_num(ctx.chain)  - 1 then
       Inc(cidx);
    crl_issuer := sk_X509_value(ctx.chain, cidx);
    if X509_check_akid(crl_issuer, crl.akid ) = X509_V_OK then
    begin
        if (pcrl_score^ and CRL_SCORE_ISSUER_NAME)>0 then
        begin
            pcrl_score^  := pcrl_score^  or (CRL_SCORE_AKID or CRL_SCORE_ISSUER_CERT);
            pissuer^ := crl_issuer;
            exit;
        end;
    end;
    Inc(cidx);
    while ( cidx < sk_X509_num(ctx.chain)) do
    begin
        crl_issuer := sk_X509_value(ctx.chain, cidx);
        if X509_NAME_cmp(X509_get_subject_name(crl_issuer) , cnm)>0  then
            continue;
        if X509_check_akid(crl_issuer, crl.akid) = X509_V_OK then
        begin
            pcrl_score^  := pcrl_score^  or (CRL_SCORE_AKID or CRL_SCORE_SAME_PATH);
            pissuer^ := crl_issuer;
            exit;
        end;
        Inc(cidx);
    end;
    { Anything else needs extended CRL support }
    if (ctx.param.flags and X509_V_FLAG_EXTENDED_CRL_SUPPORT ) = 0 then
        exit;
    {
     * Otherwise the CRL issuer is not on the path. Look for it in the set of
     * untrusted certificates.
     }
    for i := 0 to sk_X509_num(ctx.untrusted)-1 do
    begin
        crl_issuer := sk_X509_value(ctx.untrusted, i);
        if X509_NAME_cmp(X509_get_subject_name(crl_issuer), cnm) <> 0 then
            continue;
        if X509_check_akid(crl_issuer, crl.akid)  = X509_V_OK then
        begin
            pissuer^ := crl_issuer;
            pcrl_score^  := pcrl_score^  or CRL_SCORE_AKID;
            exit;
        end;
    end;
end;


function check_crl_path(ctx : PX509_STORE_CTX; x : PX509):integer;
var
  crl_ctx : TX509_STORE_CTX;

  ret : integer;

  label err ;
begin
    //crl_ctx := 0;

    { Don't allow recursive CRL path validation }
    if ctx.parent <> nil then
       Exit(0);
    if  0>= X509_STORE_CTX_init(@crl_ctx, ctx.store, x, ctx.untrusted) then
        Exit(-1);
    crl_ctx.crls := ctx.crls;
    { Copy verify params across }
    X509_STORE_CTX_set0_param(@crl_ctx, ctx.param);
    crl_ctx.parent := ctx;
    crl_ctx.verify_cb := ctx.verify_cb;
    { Verify CRL issuer }
    ret := X509_verify_cert(@crl_ctx);
    if ret <= 0 then { Check chain is acceptable }
       goto err;
    ret := check_crl_chain(ctx, ctx.chain, crl_ctx.chain);
 err:
    X509_STORE_CTX_cleanup(@crl_ctx);
    Result := ret;
end;


function check_crl_chain(ctx : PX509_STORE_CTX;cert_path,
                          crl_path: PSTACK_st_X509):integer;
var
  cert_ta, crl_ta : PX509;
begin
    cert_ta := sk_X509_value(cert_path, sk_X509_num(cert_path) - 1);
    crl_ta := sk_X509_value(crl_path, sk_X509_num(crl_path) - 1);
    Result := Int(X509_cmp(cert_ta, crl_ta) = 0);
end;


function idp_check_dp(a, b : PDIST_POINT_NAME):integer;
var
  nm : PX509_NAME;

  gens : PGENERAL_NAMES;

  gena, genb : PGENERAL_NAME;

  i, j : integer;
begin
    nm := nil;
    gens := nil;
    if (a = nil)  or ( b = nil) then
       Exit(1);
    if a.&type = 1 then
    begin
        if a.dpname = nil then
            Exit(0);
        { Case 1: two X509_NAME }
        if b.&type = 1 then
        begin
            if b.dpname = nil then
                Exit(0);
            Exit(Int(X509_NAME_cmp(a.dpname, b.dpname) = 0));
        end;
        { Case 2: set name and GENERAL_NAMES appropriately }
        nm := a.dpname;
        gens := b.name.fullname;
    end
    else
    if (b.&type = 1) then
    begin
        if b.dpname = nil then Exit(0);
        { Case 2: set name and GENERAL_NAMES appropriately }
        gens := a.name.fullname;
        nm := b.dpname;
    end;
    { Handle case 2 with one GENERAL_NAMES and one X509_NAME }
    if nm <> nil then
    begin
        for i := 0 to sk_GENERAL_NAME_num(gens)-1 do
        begin
            gena := sk_GENERAL_NAME_value(gens, i);
            if gena.&type <> GEN_DIRNAME then continue;
            if X509_NAME_cmp(nm, gena.d.directoryName) = 0  then
                Exit(1);
        end;
        Exit(0);
    end;
    { Else case 3: two GENERAL_NAMES }
    for i := 0 to sk_GENERAL_NAME_num(a.name.fullname)-1 do
    begin
        gena := sk_GENERAL_NAME_value(a.name.fullname, i);
        for j := 0 to sk_GENERAL_NAME_num(b.name.fullname)-1 do
        begin
            genb := sk_GENERAL_NAME_value(b.name.fullname, j);
            if GENERAL_NAME_cmp(gena, genb)  = 0 then
                Exit(1);
        end;
    end;
    Exit(0);
end;


function crldp_check_crlissuer(dp : PDIST_POINT; crl : PX509_CRL; crl_score : integer):integer;
var
  i : integer;

  nm : PX509_NAME;

  gen : PGENERAL_NAME;
begin
   nm := X509_CRL_get_issuer(crl);

    { If no CRLissuer return is successful iff don't need a match }
    if dp.CRLissuer = nil then
       Exit( Int( (crl_score and CRL_SCORE_ISSUER_NAME) <> 0));
    for i := 0 to sk_GENERAL_NAME_num(dp.CRLissuer)-1 do
    begin
        gen := sk_GENERAL_NAME_value(dp.CRLissuer, i);
        if gen.&type <> GEN_DIRNAME then continue;
        if X509_NAME_cmp(gen.d.directoryName, nm) = 0  then
            Exit(1);
    end;
    Result := 0;
end;


function crl_crldp_check( x : PX509; crl : PX509_CRL; crl_score : integer;preasons : Puint32):integer;
var
  i : integer;

  dp : PDIST_POINT;
begin
    if (crl.idp_flags and IDP_ONLYATTR ) <> 0 then
        Exit(0);
    if (x.ex_flags and EXFLAG_CA ) <> 0 then
    begin
        if (crl.idp_flags and IDP_ONLYUSER) <> 0 then
            Exit(0);
    end
    else
    begin
        if (crl.idp_flags and IDP_ONLYCA ) <> 0 then
            Exit(0);
    end;
    preasons^ := crl.idp_reasons;
    for i := 0 to sk_DIST_POINT_num(x.crldp)-1 do
    begin
        dp := sk_DIST_POINT_value(x.crldp, i);
        if crldp_check_crlissuer(dp, crl, crl_score )>0 then
        begin
            if (crl.idp = nil)
                     or  (idp_check_dp(dp.distpoint, crl.idp.distpoint)>0) then
            begin
                preasons^ := preasons^ and dp.dp_reasons;
                Exit(1);
            end;
        end;
    end;
    Exit( Int(( (crl.idp = nil)  or  (crl.idp.distpoint = nil) ) and
            ( (crl_score and CRL_SCORE_ISSUER_NAME) <> 0 )));
end;


function get_crl_delta(ctx : PX509_STORE_CTX; pcrl, pdcrl : PPX509_CRL; x : PX509):integer;
var
    ok        : integer;
    issuer    : PX509;
    crl_score : integer;
    reasons   : uint32;
    crl, dcrl       : PX509_CRL;
    nm        : PX509_NAME;
    skcrl     : PSTACK_st_X509_CRL ;
    label done;
begin
    nm        := X509_get_issuer_name(x);
    issuer := nil;
    crl_score := 0;
    crl := nil; dcrl := nil;

    reasons := ctx.current_reasons;
    ok := get_crl_sk(ctx, @crl, @dcrl,
                    @issuer, @crl_score, @reasons, ctx.crls);
    if ok>0 then goto done;{ Lookup CRLs from store }
    skcrl := ctx.lookup_crls(ctx, nm);
    { If no CRLs found and a near match from get_crl_sk use that }
    if (skcrl = nil)  and  (crl <> nil) then
       goto done;
    get_crl_sk(ctx, @crl, @dcrl, @issuer, @crl_score, @reasons, skcrl);
    sk_X509_CRL_pop_free(skcrl, X509_CRL_free);
 done:
    { If we got any kind of CRL use it and return success }
    if crl <> nil then
    begin
        ctx.current_issuer := issuer;
        ctx.current_crl_score := crl_score;
        ctx.current_reasons := reasons;
        pcrl^ := crl;
        pdcrl^ := dcrl;
        Exit(1);
    end;
    Result := 0;
end;


function check_crl(ctx : PX509_STORE_CTX; crl : PX509_CRL):integer;
var
  issuer : PX509;

  ikey : PEVP_PKEY;

  cnum, chnum, rv : integer;
begin
    issuer := nil;
    ikey := nil;
    cnum := ctx.error_depth;
    chnum := sk_X509_num(ctx.chain) - 1;
    { If we have an alternative CRL issuer cert use that }
    if ctx.current_issuer <> nil then
    begin
        issuer := ctx.current_issuer;
    {
     * Else find CRL issuer: if not last certificate then issuer is next
     * certificate in chain.
     }
    end
    else if (cnum < chnum) then
    begin
        issuer := sk_X509_value(ctx.chain, cnum + 1);
    end
    else
    begin
        issuer := sk_X509_value(ctx.chain, chnum);
        { If not self-issued, can't check signature }
        if  (0>= ctx.check_issued(ctx, issuer, issuer ))  and
            (0>= verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER)) then
            Exit(0);
    end;
    if issuer = nil then Exit(1);
    {
     * Skip most tests for deltas because they have already been done
     }
    if crl.base_crl_number = nil then
    begin
        { Check for cRLSign bit if keyUsage present }
        if ((issuer.ex_flags and EXFLAG_KUSAGE)  <> 0)  and
           ( (issuer.ex_kusage and KU_CRL_SIGN) = 0)  and
           (0>= verify_cb_crl(ctx, X509_V_ERR_KEYUSAGE_NO_CRL_SIGN))  then
            Exit(0);
        if ((ctx.current_crl_score and CRL_SCORE_SCOPE) = 0 ) and
            (0>= verify_cb_crl(ctx, X509_V_ERR_DIFFERENT_CRL_SCOPE)) then
            Exit(0);
        if ((ctx.current_crl_score and CRL_SCORE_SAME_PATH) = 0)  and
           ( check_crl_path(ctx, ctx.current_issuer) <= 0 ) and
            (0>= verify_cb_crl(ctx, X509_V_ERR_CRL_PATH_VALIDATION_ERROR)) then
            Exit(0);
        if ((crl.idp_flags and IDP_INVALID)  <> 0 ) and
           (0>= verify_cb_crl(ctx, X509_V_ERR_INVALID_EXTENSION)) then
            Exit(0);
    end;
    if ((ctx.current_crl_score and CRL_SCORE_TIME) = 0 ) and
       (0>= check_crl_time(ctx, crl, 1))  then
        Exit(0);
    { Attempt to get issuer certificate public key }
    ikey := X509_get0_pubkey(issuer);
    if (ikey = nil)  and
       (0>= verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY) )  then
        Exit(0);
    if ikey <> nil then
    begin
        rv := X509_CRL_check_suiteb(crl, ikey, ctx.param.flags);
        if (rv <> X509_V_OK)  and   (0>= verify_cb_crl(ctx, rv )) then
            Exit(0);
        { Verify CRL signature }
        if ( X509_CRL_verify(crl, ikey)  <= 0)  and
           ( 0>= verify_cb_crl(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE)) then
            Exit(0);
    end;
    Result := 1;
end;


function cert_crl(ctx : PX509_STORE_CTX; crl : PX509_CRL; x : PX509):integer;
var
  rev : PX509_REVOKED;
begin
    {
     * The rules changed for this... previously if a CRL contained unhandled
     * critical extensions it could still be used to indicate a certificate
     * was revoked. This has since been changed since critical extensions can
     * change the meaning of CRL entries.
     }
    if ( (ctx.param.flags and X509_V_FLAG_IGNORE_CRITICAL) = 0)  and
       ( (crl.flags and EXFLAG_CRITICAL) <> 0 )  and
        ( 0>= verify_cb_crl(ctx, X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION)) then
        Exit(0);
    {
     * Look for serial number of certificate in CRL.  If found, make sure
     * reason is not removeFromCRL.
     }
    if X509_CRL_get0_by_cert(crl, @rev, x )>0  then
    begin
        if rev.reason = CRL_REASON_REMOVE_FROM_CRL then
            Exit(2);
        if  0>= verify_cb_crl(ctx, X509_V_ERR_CERT_REVOKED ) then
            Exit(0);
    end;
    Result := 1;
end;


function check_policy(ctx : PX509_STORE_CTX):integer;
var
  ret : integer;
  i : integer;
  x : PX509;

  label memerr;
begin
    if ctx.parent <> nil then
       Exit(1);
    {
     * With DANE, the trust anchor might be a bare public key, not a
     * certificate!  In that case our chain does not have the trust anchor
     * certificate as a top-most element.  This comports well with RFC5280
     * chain verification, since there too, the trust anchor is not part of the
     * chain to be verified.  In particular, X509_policy_check() does not look
     * at the TA cert, but assumes that it is present as the top-most chain
     * element.  We therefore temporarily push a nil cert onto the chain if it
     * was verified via a bare public key, and pop it off right after the
     * X509_policy_check() call.
     }
    if (ctx.bare_ta_signed > 0) and ( 0>= sk_X509_push(ctx.chain, nil) ) then
       goto memerr;
    ret := X509_policy_check(@ctx.tree, @ctx.explicit_policy, ctx.chain,
                            ctx.param.policies, ctx.param.flags);
    if ctx.bare_ta_signed>0 then
       sk_X509_pop(ctx.chain);
    if ret = X509_PCY_TREE_INTERNAL then
       goto memerr; { Invalid or inconsistent extensions }
    if ret = X509_PCY_TREE_INVALID then
    begin
        { Locate certificates with bad extensions and notify callback. }
        for i := 1 to sk_X509_num(ctx.chain)-1 do
        begin
            x := sk_X509_value(ctx.chain, i);
            CB_FAIL_IF((x.ex_flags and EXFLAG_INVALID_POLICY) <> 0,
                       ctx, x, i, X509_V_ERR_INVALID_POLICY_EXTENSION);
        end;
        Exit(1);
    end;
    if ret = X509_PCY_TREE_FAILURE then begin
        ctx.current_cert := nil;
        ctx.error := X509_V_ERR_NO_EXPLICIT_POLICY;
        Exit(ctx.verify_cb(0, ctx));
    end;
    if ret <> X509_PCY_TREE_VALID then begin
        ERR_raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    if (ctx.param.flags and X509_V_FLAG_NOTIFY_POLICY ) <> 0 then
    begin
        ctx.current_cert := nil;
        {
         * Verification errors need to be 'sticky', a callback may have allowed
         * an SSL handshake to continue despite an error, and we must then
         * remain in an error state.  Therefore, we MUST NOT clear earlier
         * verification errors by setting the error to X509_V_OK.
         }
        if  0>= ctx.verify_cb(2, ctx ) then
            Exit(0);
    end;
    Exit(1);
 memerr:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    ctx.error := X509_V_ERR_OUT_OF_MEM;
    Result := -1;
end;


function ossl_x509_check_cert_time(ctx : PX509_STORE_CTX; x : PX509; depth : integer):integer;
var
  ptime : Ptime_t;

  i : integer;
begin
    if (ctx.param.flags and X509_V_FLAG_USE_CHECK_TIME ) <> 0 then
        ptime := @ctx.param.check_time
    else
    if (ctx.param.flags and X509_V_FLAG_NO_CHECK_TIME) <> 0 then
        Exit(1)
    else
        ptime := nil;
    i := X509_cmp_time(X509_get0_notBefore(x), ptime);
    if (i >= 0)  and  (depth < 0) then
       Exit(0);
    CB_FAIL_IF(i = 0, ctx, x, depth, X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD);
    CB_FAIL_IF(i > 0, ctx, x, depth, X509_V_ERR_CERT_NOT_YET_VALID);
    i := X509_cmp_time(X509_get0_notAfter(x), ptime);
    if (i <= 0)  and  (depth < 0) then
       Exit(0);
    CB_FAIL_IF(i = 0, ctx, x, depth, X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
    CB_FAIL_IF(i < 0, ctx, x, depth, X509_V_ERR_CERT_HAS_EXPIRED);
    Result := 1;
end;


function internal_verify(ctx : PX509_STORE_CTX):integer;
var
  n,k            : integer;
  xi,
  xs           : PX509;
  pkey         : PEVP_PKEY;

  issuer_depth,
  ret          : integer;
begin
    n := sk_X509_num(ctx.chain) - 1;
    xi := sk_X509_value(ctx.chain, n);
    xs := xi;
    ctx.error_depth := n;
    if ctx.bare_ta_signed>0 then
    begin
        {
         * With DANE-verified bare public key TA signatures,
         * on the top certificate we check only the timestamps.
         * We report the issuer as nil because all we have is a bare key.
         }
        xi := nil;
    end
    else
    if (ossl_x509_likely_issued(xi, xi) <> X509_V_OK) and
               { exceptional case: last cert in the chain is not self-issued }
       ((ctx.param.flags and X509_V_FLAG_PARTIAL_CHAIN) = 0) then
    begin
        if n > 0 then
        begin
            Dec(n);
            ctx.error_depth := n;
            xs := sk_X509_value(ctx.chain, n);
        end
        else
        begin
            CB_FAIL_IF(Boolean(1), ctx, xi, 0,
                       X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
        end;
        {
         * The below code will certainly not do a
         * self-signature check on xi because it is not self-issued.
         }
    end;
    {
     * Do not clear error (by ctx.error = X509_V_OK), it must be 'sticky',
     * only the user's callback is allowed to reset errors (at its own peril).
     }
    while n >= 0 do  begin
        {-
         * For each iteration of this loop:
         * n is the subject depth
         * xs is the subject cert, for which the signature is to be checked
         * xi is nil for DANE-verified bare public key TA signatures
         *       else the supposed issuer cert containing the public key to use
         * Initially xs = xi if the last cert in the chain is self-issued.
         }
        {
         * Do signature check for self-signed certificates only if explicitly
         * asked for because it does not add any security and just wastes time.
         }
        if (xi <> nil)    and
           ( (xs <> xi)   or
             ( ((ctx.param.flags and X509_V_FLAG_CHECK_SS_SIGNATURE)  <> 0 )  and
                 ( (xi.ex_flags and EXFLAG_SS) <> 0)
             )
           ) then
        begin
            {
             * If the issuer's public key is not available or its key usage
             * does not support issuing the subject cert, report the issuer
             * cert and its depth (rather than n, the depth of the subject).
             }
            issuer_depth := n + get_result(xs = xi , 0 , 1);
            {
             * According to https://tools.ietf.org/html/rfc5280#section-6.1.4
             * step (n) we must check any given key usage extension in a CA cert
             * when preparing the verification of a certificate issued by it.
             * According to https://tools.ietf.org/html/rfc5280#section-4.2.1.3
             * we must not verify a certificate signature if the key usage of
             * the CA certificate that issued the certificate prohibits signing.
             * In case the 'issuing' certificate is the last in the chain and is
             * not a CA certificate but a 'self-issued' end-entity cert (i.e.,
             * xs = xi  and  !(xi.ex_flags and EXFLAG_CA)) RFC 5280 does not apply
             * (see https://tools.ietf.org/html/rfc6818#section-2) and thus
             * we are free to ignore any key usage restrictions on such certs.
             }
            k := get_result( (xi.ex_flags and EXFLAG_CA) = 0,
                                   X509_V_OK , ossl_x509_signing_allowed(xi, xs));
            ret := Int( (xs = xi)  and (k>0 ));
            CB_FAIL_IF(ret <> X509_V_OK, ctx, xi, issuer_depth, ret);
            pkey := X509_get0_pubkey(xi ) ;
            if pkey = nil then
            begin
                CB_FAIL_IF(Boolean(1), ctx, xi, issuer_depth,
                           X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
            end
            else
            begin
                CB_FAIL_IF(X509_verify(xs, pkey) <= 0,
                           ctx, xs, n, X509_V_ERR_CERT_SIGNATURE_FAILURE);
            end;
        end;
        { In addition to RFC 5280 requirements do also for trust anchor cert }
        { Calls verify callback as needed }
        if  0>= ossl_x509_check_cert_time(ctx, xs, n) then
            Exit(0);
        {
         * Signal success at this depth.  However, the previous error (if any)
         * is retained.
         }
        ctx.current_issuer := xi;
        ctx.current_cert := xs;
        ctx.error_depth := n;
        if  0>= ctx.verify_cb(1, ctx )  then
            Exit(0);
        Dec(n);
        if n >= 0 then
        begin
            xi := xs;
            xs := sk_X509_value(ctx.chain, n);
        end;
    end;
    Result := 1;
end;


function X509_cmp_current_time(const ctm : PASN1_TIME):integer;
begin
    Result := X509_cmp_time(ctm, nil);
end;


function X509_cmp_time( ctm : PASN1_TIME; cmp_time : Ptime_t):integer;
var
  utctime_length         : size_t ;
  generalizedtime_length : size_t ;
  asn1_cmp_time          : PASN1_TIME;

  i,
  day,
  sec,
  ret                    : integer;
  label err;
const
{$ifdef CHARSET_EBCDIC}
    upper_z                = $5A;
{$ELSE}
    upper_z                = 'Z';
{$ENDIF}


begin
   utctime_length         := sizeof('YYMMDDHHMMSSZ') - 1;
   generalizedtime_length := sizeof('YYYYMMDDHHMMSSZ') - 1;
   asn1_cmp_time := nil;
    ret := 0;

    {-
     * Note that ASN.1 allows much more slack in the time format than RFC5280.
     * In RFC5280, the representation is fixed:
     * UTCTime: YYMMDDHHMMSSZ
     * GeneralizedTime: YYYYMMDDHHMMSSZ
     *
     * We do NOT currently enforce the following RFC 5280 requirement:
     * "CAs conforming to this profile MUST always encode certificate
     *  dates in 2050 or later MUST be encoded as GeneralizedTime."
     }
    case ctm.&type of
    V_ASN1_UTCTIME:
        if ctm.length <> (int(utctime_length)) then
            Exit(0);

    V_ASN1_GENERALIZEDTIME:
        if ctm.length <> (int (generalizedtime_length)) then
            Exit(0);

    else
        Exit(0);
    end;
    {*
     * Verify the format: the ASN.1 functions we use below allow a more
     * flexible format than what's mandated by RFC 5280.
     * Digit and date ranges will be verified in the conversion methods.
     }
    for i := 0 to ctm.length - 1-1 do
    begin
        if  0>= ossl_ascii_isdigit(ctm.data[i]) then
            Exit(0);
    end;
    if chr(ctm.data[ctm.length - 1]) <> upper_z then
       Exit(0);
    {
     * There is ASN1_UTCTIME_cmp_time_t but no
     * ASN1_GENERALIZEDTIME_cmp_time_t or ASN1_TIME_cmp_time_t,
     * so we go through ASN.1
     }
    asn1_cmp_time := X509_time_adj(nil, 0, cmp_time);
    if asn1_cmp_time = nil then
       goto err;
    if (ASN1_TIME_diff(@day, @sec, ctm, asn1_cmp_time) = 0) then
       goto err;
    {
     * X509_cmp_time comparison is <=.
     * The return value 0 is reserved for errors.
     }
    ret := get_result( (day >= 0)  and  (sec >= 0) , -1 , 1);
 err:
    ASN1_TIME_free(asn1_cmp_time);
    Result := ret;
end;


function X509_cmp_timeframe(const vpm : PX509_VERIFY_PARAM; const start, _end : PASN1_TIME):integer;
var
  ref_time : time_t;
  time     : Ptime_t;

    flags    : uint32;
begin
    time := nil;
    flags := get_result( vpm = nil , 0 , X509_VERIFY_PARAM_get_flags(vpm));
    if (flags and X509_V_FLAG_USE_CHECK_TIME ) <> 0 then
    begin
        ref_time := X509_VERIFY_PARAM_get_time(vpm);
        time := @ref_time;
    end
    else
    if ((flags and X509_V_FLAG_NO_CHECK_TIME) <> 0) then
    begin
        exit( 0); { this means ok }
    end;
 { else reference time is the current time }
    if (_end <> nil)  and ( X509_cmp_time(_end, time)  < 0) then
        Exit(1);
    if (start <> nil)  and ( X509_cmp_time(start, time) > 0) then
        Exit(-1);
    Result := 0;
end;


function X509_gmtime_adj( s : PASN1_TIME; adj : long): PASN1_TIME;
begin
    Result := X509_time_adj(s, adj, nil);
end;


function X509_time_adj(s : PASN1_TIME; offset_sec : long; in_tm : Ptime_t):PASN1_TIME;
begin
    Result := X509_time_adj_ex(s, 0, offset_sec, in_tm);
end;


function X509_time_adj_ex(s : PASN1_TIME; offset_day : integer; offset_sec : long; in_tm : Ptime_t):PASN1_TIME;
var
  t : time_t;
begin
    if in_tm <> nil then
      t := in_tm^
    else
      t := _time(@t);

    if (s <> nil)  and ( (s.flags and ASN1_STRING_FLAG_MSTRING)= 0 ) then
    begin
        if s.&type = V_ASN1_UTCTIME then
            Exit(PASN1_TIME(ASN1_UTCTIME_adj(PASN1_UTCTIME(s), t, offset_day, offset_sec)));
        if s.&type = V_ASN1_GENERALIZEDTIME then
           Exit(PASN1_TIME(ASN1_GENERALIZEDTIME_adj(PASN1_GENERALIZEDTIME(s), t, offset_day, offset_sec)));
    end;
    Result := ASN1_TIME_adj(s, t, offset_day, offset_sec);
end;


function X509_get_pubkey_parameters(pkey : PEVP_PKEY; chain: PSTACK_st_X509):integer;
var
  ktmp,ktmp2 : PEVP_PKEY;

  i, j : integer;
begin
    ktmp := nil;
    if (pkey <> nil)  and   (0>= EVP_PKEY_missing_parameters(pkey)) then
        Exit(1);
    for i := 0 to sk_X509_num(chain)-1 do
    begin
        ktmp := X509_get0_pubkey(sk_X509_value(chain, i));
        if ktmp = nil then
        begin
            ERR_raise(ERR_LIB_X509, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY);
            Exit(0);
        end;
        if 0>= EVP_PKEY_missing_parameters(ktmp) then
            break;
        ktmp := nil;
    end;
    if ktmp = nil then begin
        ERR_raise(ERR_LIB_X509, X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN);
        Exit(0);
    end;
    { first, populate the other certs }
    j := i - 1;
    while ( j >= 0) do
    begin
        ktmp2 := X509_get0_pubkey(sk_X509_value(chain, j));
        if  0>= EVP_PKEY_copy_parameters(ktmp2, ktmp) then
            Exit(0);
        Dec(j);
    end;
    if pkey <> nil then
       Exit(EVP_PKEY_copy_parameters(pkey, ktmp));
    Result := 1;
end;


function X509_CRL_diff(base, newer : PX509_CRL; skey : pEVP_PKEY;
                      const md : PEVP_MD; flags : uint32): PX509_CRL;
var
  crl : PX509_CRL;
  i : integer;
  ext : PX509_EXTENSION;
  rvn, rvtmp : PX509_REVOKED;
  revs: PSTACK_st_X509_REVOKED ;
  label memerr;

begin
    crl := nil;
    revs := nil;
    { CRLs can't be delta already }
    if (base.base_crl_number <> nil)  or
       (newer.base_crl_number <> nil) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_CRL_ALREADY_DELTA);
        Exit(nil);
    end;
    { Base and new CRL must have a CRL number }
    if (base.crl_number = nil)  or  (newer.crl_number = nil) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_NO_CRL_NUMBER);
        Exit(nil);
    end;
    { Issuer names must match }
    if X509_NAME_cmp(X509_CRL_get_issuer(base),
                      X509_CRL_get_issuer(newer)) <> 0 then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_ISSUER_MISMATCH);
        Exit(nil);
    end;
    { AKID and IDP must match }
    if  0>= crl_extension_match(base, newer, NID_authority_key_identifier ) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_AKID_MISMATCH);
        Exit(nil);
    end;
    if  0>= crl_extension_match(base, newer, NID_issuing_distribution_point  )then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_IDP_MISMATCH);
        Exit(nil);
    end;
    { Newer CRL number must exceed full CRL number }
    if ASN1_INTEGER_cmp(newer.crl_number, base.crl_number)<= 0 then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_NEWER_CRL_NOT_NEWER);
        Exit(nil);
    end;
    { CRLs must verify }
    if (skey <> nil)  and  (X509_CRL_verify(base, skey)<= 0)  or
                       (  X509_CRL_verify(newer, skey) <= 0)  then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_CRL_VERIFY_FAILURE);
        Exit(nil);
    end;
    { Create new CRL }
    crl := X509_CRL_new_ex(base.libctx, base.propq);
    if (crl = nil)  or   (0>= X509_CRL_set_version(crl, X509_CRL_VERSION_2)) then
        goto memerr;
    { Set issuer name }
    if 0>= X509_CRL_set_issuer_name(crl, X509_CRL_get_issuer(newer)) then
        goto memerr;
    if 0>= X509_CRL_set1_lastUpdate(crl, X509_CRL_get0_lastUpdate(newer)) then
        goto memerr;
    if  0>= X509_CRL_set1_nextUpdate(crl, X509_CRL_get0_nextUpdate(newer)) then
        goto memerr;
    { Set base CRL number: must be critical }
    if  0>= X509_CRL_add1_ext_i2d(crl, NID_delta_crl, base.crl_number, 1, 0) then
        goto memerr;
    {
     * Copy extensions across from newest CRL to delta: this will set CRL
     * number to correct value too.
     }
    for i := 0 to X509_CRL_get_ext_count(newer)-1 do
    begin
        ext := X509_CRL_get_ext(newer, i);
        if  0>= X509_CRL_add_ext(crl, ext, -1) then
            goto memerr;
    end;
    { Go through revoked entries, copying as needed }
    revs := X509_CRL_get_REVOKED(newer);
    for i := 0 to sk_X509_REVOKED_num(revs)-1 do
    begin
        rvn := sk_X509_REVOKED_value(revs, i);
        {
         * Add only if not also in base.
         * Need something cleverer here for some more complex CRLs covering
         * multiple CAs.
         }
        if  0>= X509_CRL_get0_by_serial(base, @rvtmp, @rvn.serialNumber ) then
        begin
            rvtmp := X509_REVOKED_dup(rvn);
            if rvtmp = nil then
                goto memerr;
            if ( 0>= X509_CRL_add0_revoked(crl, rvtmp)) then
            begin
                X509_REVOKED_free(rvtmp);
                 goto memerr;
            end;
        end;
    end;
    if (skey <> nil)  and  (md <> nil)  and  (0>= X509_CRL_sign(crl, skey, md)  )then
       goto memerr;
    Exit(crl);
 memerr:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    X509_CRL_free(crl);
    Result := nil;
end;


function X509_STORE_CTX_set_ex_data(ctx : PX509_STORE_CTX; idx : integer; data: Pointer):integer;
begin
    Result := CRYPTO_set_ex_data(@ctx.ex_data, idx, data);
end;


function X509_STORE_CTX_get_ex_data(ctx : PX509_STORE_CTX; idx : integer): Pointer;
begin
    Result := CRYPTO_get_ex_data(@ctx.ex_data, idx);
end;


function X509_STORE_CTX_get_error(ctx : PX509_STORE_CTX):integer;
begin
    Result := ctx.error;
end;


procedure X509_STORE_CTX_set_error(ctx : PX509_STORE_CTX; err : integer);
begin
    ctx.error := err;
end;


function X509_STORE_CTX_get_error_depth(ctx : PX509_STORE_CTX):integer;
begin
    Result := ctx.error_depth;
end;


procedure X509_STORE_CTX_set_error_depth(ctx : PX509_STORE_CTX; depth : integer);
begin
    ctx.error_depth := depth;
end;


function X509_STORE_CTX_get_current_cert(const ctx : PX509_STORE_CTX): PX509;
begin
    Result := ctx.current_cert;
end;


procedure X509_STORE_CTX_set_current_cert(ctx : PX509_STORE_CTX; x : PX509);
begin
    ctx.current_cert := x;
end;


function X509_STORE_CTX_get0_current_issuer(ctx : PX509_STORE_CTX): PX509;
begin
    Result := ctx.current_issuer;
end;


function X509_STORE_CTX_get0_current_crl(ctx : PX509_STORE_CTX): PX509_CRL;
begin
    Result := ctx.current_crl;
end;


function X509_STORE_CTX_get0_parent_ctx(ctx : PX509_STORE_CTX):PX509_STORE_CTX;
begin
    Result := ctx.parent;
end;


procedure X509_STORE_CTX_set_cert(ctx : PX509_STORE_CTX; x : PX509);
begin
    ctx.cert := x;
end;


procedure X509_STORE_CTX_set0_crls(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509_CRL);
begin
    ctx.crls := sk;
end;


function X509_STORE_CTX_set_purpose(ctx : PX509_STORE_CTX; purpose : integer):integer;
begin
    {
     * XXX: Why isn't this function always used to set the associated trust?
     * Should there even be a VPM.trust field at all?  Or should the trust
     * always be inferred from the purpose by X509_STORE_CTX_init().
     }
    Result := X509_STORE_CTX_purpose_inherit(ctx, 0, purpose, 0);
end;


function X509_STORE_CTX_set_trust(ctx : PX509_STORE_CTX; trust : integer):integer;
begin
    {
     * XXX: See above, this function would only be needed when the default
     * trust for the purpose needs an override in a corner case.
     }
    Result := X509_STORE_CTX_purpose_inherit(ctx, 0, 0, trust);
end;


function X509_STORE_CTX_purpose_inherit(ctx : PX509_STORE_CTX; def_purpose, purpose, trust : integer):integer;
var
  idx : integer;

  ptmp : PX509_PURPOSE;
begin
    { If purpose not set use default }
    if purpose = 0 then
       purpose := def_purpose;
    { If we have a purpose then check it is valid }
    if purpose <> 0 then
    begin
        idx := X509_PURPOSE_get_by_id(purpose);
        if idx = -1 then
        begin
            ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_PURPOSE_ID);
            Exit(0);
        end;
        ptmp := X509_PURPOSE_get0(idx);
        if ptmp.trust = X509_TRUST_DEFAULT then
        begin
            idx := X509_PURPOSE_get_by_id(def_purpose);
            {
             * XXX: In the two callers above def_purpose is always 0, which is
             * not a known value, so idx will always be -1.  How is the
             * X509_TRUST_DEFAULT case actually supposed to be handled?
             }
            if idx = -1 then begin
                ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_PURPOSE_ID);
                Exit(0);
            end;
            ptmp := X509_PURPOSE_get0(idx);
        end;
        { If trust not set then get from purpose default }
        if trust = 0 then
           trust := ptmp.trust;
    end;
    if trust <> 0 then
    begin
        idx := X509_TRUST_get_by_id(trust);
        if idx = -1 then begin
            ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_TRUST_ID);
            Exit(0);
        end;
    end;
    if (ctx.param.purpose = 0)  and  (purpose <> 0) then
       ctx.param.purpose := purpose;
    if (ctx.param.trust = 0)  and  (trust <> 0) then
       ctx.param.trust := trust;
    Result := 1;
end;


function X509_STORE_CTX_new_ex(libctx : POSSL_LIB_CTX; const propq : PUTF8Char): PX509_STORE_CTX;
var
  ctx : PX509_STORE_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ctx.libctx := libctx;
    if propq <> nil then
    begin
        OPENSSL_strdup(ctx.propq ,propq);
        if ctx.propq = nil then
        begin
            OPENSSL_free(ctx);
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end;
    Result := ctx;
end;


function X509_STORE_CTX_new: PX509_STORE_CTX;
begin
    Result := X509_STORE_CTX_new_ex(nil, nil);
end;


procedure X509_STORE_CTX_free(ctx : PX509_STORE_CTX);
begin
    if ctx = nil then exit;
    X509_STORE_CTX_cleanup(ctx);
    { libctx and propq survive X509_STORE_CTX_cleanup() }
    OPENSSL_free(ctx.propq);
    OPENSSL_free(ctx);
end;


function X509_STORE_CTX_init(ctx : PX509_STORE_CTX; store : PX509_STORE;
                       x509 : PX509; chain: PSTACK_st_X509):integer;
var
  ret : integer;
  idx : integer;
  xp : PX509_PURPOSE;
  label _err;
begin
    ret := 1;
    if ctx = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    X509_STORE_CTX_cleanup(ctx);
    ctx.store := store;
    ctx.cert := x509;
    ctx.untrusted := chain;
    ctx.crls := nil;
    ctx.num_untrusted := 0;
    ctx.other_ctx := nil;
    ctx.valid := 0;
    ctx.chain := nil;
    ctx.error := X509_V_OK;
    ctx.explicit_policy := 0;
    ctx.error_depth := 0;
    ctx.current_cert := nil;
    ctx.current_issuer := nil;
    ctx.current_crl := nil;
    ctx.current_crl_score := 0;
    ctx.current_reasons := 0;
    ctx.tree := nil;
    ctx.parent := nil;
    ctx.dane := nil;
    ctx.bare_ta_signed := 0;
    { Zero ex_data to make sure we're cleanup-safe }
    memset(@ctx.ex_data, 0, sizeof(ctx.ex_data));
    { store.cleanup is always 0 in OpenSSL, if set must be idempotent }
    if store <> nil then
       ctx.cleanup := store.cleanup
    else
        ctx.cleanup := nil;
    if (store <> nil)  and  Assigned(store.check_issued) then
       ctx.check_issued := store.check_issued
    else
        ctx.check_issued := check_issued;
    if (store <> nil)  and  Assigned(store.get_issuer) then
       ctx.get_issuer := store.get_issuer
    else
        ctx.get_issuer := X509_STORE_CTX_get1_issuer;
    if (store <> nil)  and  Assigned(store.verify_cb ) then
       ctx.verify_cb := store.verify_cb
    else
        ctx.verify_cb := null_callback;
    if (store <> nil)  and  Assigned(store.verify) then
        ctx.verify := store.verify
    else
        ctx.verify := internal_verify;
    if (store <> nil)  and  Assigned(store.check_revocation) then
        ctx.check_revocation := store.check_revocation
    else
        ctx.check_revocation := check_revocation;
    if (store <> nil)  and  Assigned(store.get_crl ) then
       ctx.get_crl := store.get_crl
    else
        ctx.get_crl := nil;
    if (store <> nil)  and  Assigned(store.check_crl) then
       ctx.check_crl := store.check_crl
    else
        ctx.check_crl := check_crl;
    if (store <> nil)  and  Assigned(store.cert_crl ) then
       ctx.cert_crl := store.cert_crl
    else
        ctx.cert_crl := cert_crl;
    if (store <> nil)  and  Assigned(store.check_policy ) then
       ctx.check_policy := store.check_policy
    else
        ctx.check_policy := check_policy;
    if (store <> nil)  and  Assigned(store.lookup_certs) then
       ctx.lookup_certs := store.lookup_certs
    else
        ctx.lookup_certs := X509_STORE_CTX_get1_certs;
    if (store <> nil)  and  Assigned(store.lookup_crls) then
       ctx.lookup_crls := store.lookup_crls
    else
        ctx.lookup_crls := X509_STORE_CTX_get1_crls;
    ctx.param := X509_VERIFY_PARAM_new();
    if ctx.param = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    { Inherit callbacks and flags from X509_STORE if not set use defaults. }
    if store <> nil then
       ret := X509_VERIFY_PARAM_inherit(ctx.param, store.param)
    else
        ctx.param.inh_flags  := ctx.param.inh_flags  or (X509_VP_FLAG_DEFAULT or X509_VP_FLAG_ONCE);
    if ret>0 then
       ret := X509_VERIFY_PARAM_inherit(ctx.param,
                                        X509_VERIFY_PARAM_lookup('default'));
    if ret = 0 then begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    {
     * XXX: For now, continue to inherit trust from VPM, but infer from the
     * purpose if this still yields the default value.
     }
    if ctx.param.trust = X509_TRUST_DEFAULT then
    begin
        idx := X509_PURPOSE_get_by_id(ctx.param.purpose);
        xp := X509_PURPOSE_get0(idx);
        if xp <> nil then
           ctx.param.trust := X509_PURPOSE_get_trust(xp);
    end;
    if CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx, @ctx.ex_data )>0  then
        Exit(1);
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
 _err:
    {
     * On error clean up allocated storage, if the store context was not
     * allocated with X509_STORE_CTX_new() this is our last chance to do so.
     }
    X509_STORE_CTX_cleanup(ctx);
    Result := 0;
end;


procedure X509_STORE_CTX_set0_trusted_stack(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509);
begin
    ctx.other_ctx := sk;
    ctx.get_issuer := get_issuer_sk;
    ctx.lookup_certs := lookup_certs_sk;
end;


procedure X509_STORE_CTX_cleanup(ctx : PX509_STORE_CTX);
begin
    {
     * We need to be idempotent because, unfortunately, free() also calls
     * cleanup(), so the natural call sequence new(), init(), cleanup(), free()
     * calls cleanup() for the same object twice!  Thus we must zero the
     * pointers below after they're freed!
     }
    { Seems to always be nil in OpenSSL, do this at most once. }
    if Assigned(ctx.cleanup) then
    begin
        ctx.cleanup(ctx);
        ctx.cleanup := nil;
    end;
    if ctx.param <> nil then
    begin
        if ctx.parent = nil then
           X509_VERIFY_PARAM_free(ctx.param);
        ctx.param := nil;
    end;
    X509_policy_tree_free(ctx.tree);
    ctx.tree := nil;
    OSSL_STACK_OF_X509_free(ctx.chain);
    ctx.chain := nil;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx, @(ctx.ex_data));
    memset(@ctx.ex_data, 0, sizeof(ctx.ex_data));
end;


procedure X509_STORE_CTX_set_depth(ctx : PX509_STORE_CTX; depth : integer);
begin
    X509_VERIFY_PARAM_set_depth(ctx.param, depth);
end;


procedure X509_STORE_CTX_set_flags(ctx : PX509_STORE_CTX; flags : uint32);
begin
    X509_VERIFY_PARAM_set_flags(ctx.param, flags);
end;


procedure X509_STORE_CTX_set_time(ctx : PX509_STORE_CTX; flags : uint32; t : time_t);
begin
    X509_VERIFY_PARAM_set_time(ctx.param, t);
end;


function X509_STORE_CTX_get0_cert(ctx : PX509_STORE_CTX):PX509;
begin
    Result := ctx.cert;
end;


procedure X509_STORE_CTX_set0_untrusted(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509);
begin
    ctx.untrusted := sk;
end;


procedure X509_STORE_CTX_set0_verified_chain(ctx : PX509_STORE_CTX; sk: PSTACK_st_X509);
begin
    OSSL_STACK_OF_X509_free(ctx.chain);
    ctx.chain := sk;
end;


procedure X509_STORE_CTX_set_verify_cb(ctx : PX509_STORE_CTX; verify_cb : X509_STORE_CTX_verify_cb);
begin
    ctx.verify_cb := verify_cb;
end;


function X509_STORE_CTX_get_verify_cb(ctx : PX509_STORE_CTX):X509_STORE_CTX_verify_cb;
begin
    Result := ctx.verify_cb;
end;


procedure X509_STORE_CTX_set_verify(ctx : PX509_STORE_CTX; verify : X509_STORE_CTX_verify_fn);
begin
    ctx.verify := verify;
end;


function X509_STORE_CTX_get_verify(ctx : PX509_STORE_CTX):X509_STORE_CTX_verify_fn;
begin
    Result := ctx.verify;
end;


function X509_STORE_CTX_get_get_issuer(ctx : PX509_STORE_CTX):X509_STORE_CTX_get_issuer_fn;
begin
    Result := ctx.get_issuer;
end;


function X509_STORE_CTX_get_check_issued(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_issued_fn;
begin
    Result := ctx.check_issued;
end;


function X509_STORE_CTX_get_check_revocation(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_revocation_fn;
begin
    Result := ctx.check_revocation;
end;


function X509_STORE_CTX_get_get_crl(ctx : PX509_STORE_CTX):X509_STORE_CTX_get_crl_fn;
begin
    Result := ctx.get_crl;
end;


function X509_STORE_CTX_get_check_crl(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_crl_fn;
begin
    Result := ctx.check_crl;
end;


function X509_STORE_CTX_get_cert_crl(ctx : PX509_STORE_CTX):X509_STORE_CTX_cert_crl_fn;
begin
    Result := ctx.cert_crl;
end;


function X509_STORE_CTX_get_check_policy(ctx : PX509_STORE_CTX):X509_STORE_CTX_check_policy_fn;
begin
    Result := ctx.check_policy;
end;


function X509_STORE_CTX_get_lookup_certs(ctx : PX509_STORE_CTX):X509_STORE_CTX_lookup_certs_fn;
begin
    Result := ctx.lookup_certs;
end;


function X509_STORE_CTX_get_lookup_crls(ctx : PX509_STORE_CTX):X509_STORE_CTX_lookup_crls_fn;
begin
    Result := ctx.lookup_crls;
end;


function X509_STORE_CTX_get_cleanup(ctx : PX509_STORE_CTX):X509_STORE_CTX_cleanup_fn;
begin
    Result := ctx.cleanup;
end;


function X509_STORE_CTX_get0_policy_tree(ctx : PX509_STORE_CTX): PX509_POLICY_TREE;
begin
    Result := ctx.tree;
end;


function X509_STORE_CTX_get_explicit_policy(ctx : PX509_STORE_CTX):integer;
begin
    Result := ctx.explicit_policy;
end;


function X509_STORE_CTX_get_num_untrusted(ctx : PX509_STORE_CTX):integer;
begin
    Result := ctx.num_untrusted;
end;


function X509_STORE_CTX_set_default(ctx : PX509_STORE_CTX; const name : PUTF8Char):integer;
var
  param: PX509_VERIFY_PARAM ;
begin
    param := X509_VERIFY_PARAM_lookup(name);
    if param = nil then Exit(0);
    Result := X509_VERIFY_PARAM_inherit(ctx.param, param);
end;


function X509_STORE_CTX_get0_param(const ctx : PX509_STORE_CTX): PX509_VERIFY_PARAM;
begin
    Result := ctx.param;
end;


procedure X509_STORE_CTX_set0_param(ctx : PX509_STORE_CTX; param : PX509_VERIFY_PARAM);
begin
    X509_VERIFY_PARAM_free(ctx.param);
    ctx.param := param;
end;


procedure X509_STORE_CTX_set0_dane(ctx : PX509_STORE_CTX; dane : PSSL_DANE);
begin
    ctx.dane := dane;
end;


function dane_match(ctx : PX509_STORE_CTX; cert : PX509; depth : integer):integer;
var
    dane     : PSSL_DANE;
    usage,
    selector,
    ordinal,
    mtype    : uint32;
    i2dbuf   : Pbyte;
    i2dlen   : uint32;
    mdbuf    : array[0..(EVP_MAX_MD_SIZE)-1] of byte;
    cmpbuf   : Pbyte;
    cmplen   : uint32;

  i,
  recnum,
  matched  : integer;

    t        : Pdanetls_record;
    mask     : uint32;
    md       : PEVP_MD;
begin
{$POINTERMATH ON}
    dane := ctx.dane;
    usage := DANETLS_NONE;
    selector := DANETLS_NONE;
    ordinal := DANETLS_NONE;
    mtype := DANETLS_NONE;
    i2dbuf := nil;
    i2dlen := 0;
    cmpbuf := nil;
    cmplen := 0;
    matched := 0;
    t := nil;
    mask := get_result(depth = 0,  DANETLS_EE_MASK , DANETLS_TA_MASK);
    { The trust store is not applicable with DANE-TA(2) }
    if depth >= ctx.num_untrusted then
       mask := mask and DANETLS_PKIX_MASK;
    {
     * If we've previously matched a PKIX-?? record, no need to test any
     * further PKIX-?? records, it remains to just build the PKIX chain.
     * Had the match been a DANE-?? record, we'd be done already.
     }
    if dane.mdpth >= 0 then
       mask := mask and  (not DANETLS_PKIX_MASK);
    {-
     * https://tools.ietf.org/html/rfc7671#section-5.1
     * https://tools.ietf.org/html/rfc7671#section-5.2
     * https://tools.ietf.org/html/rfc7671#section-5.3
     * https://tools.ietf.org/html/rfc7671#section-5.4
     *
     * We handle DANE-EE(3) records first as they require no chain building
     * and no expiration or hostname checks.  We also process digests with
     * higher ordinals first and ignore lower priorities except Full(0) which
     * is always processed (last).  If none match, we then process PKIX-EE(1).
     *
     * NOTE: This relies on DANE usages sorting before the corresponding PKIX
     * usages in SSL_dane_tlsa_add(), and also on descending sorting of digest
     * priorities.  See twin comment in ssl/ssl_lib.c.
     *
     * We expect that most TLSA RRsets will have just a single usage, so we
     * don't go out of our way to cache multiple selector-specific i2d buffers
     * across usages, but if the selector happens to remain the same as switch
     * usages, that's OK.  Thus, a set of '3 1 1", "3 0 1", "1 1 1", "1 0 1',
     * records would result in us generating each of the certificate and public
     * key DER forms twice, but more typically we'd just see multiple '3 1 1'
     * or multiple '3 0 1' records.
     *
     * As soon as we find a match at any given depth, we stop, because either
     * we've matched a DANE-?? record and the peer is authenticated, or, after
     * exhausting all DANE-?? records, we've matched a PKIX-?? record, which is
     * sufficient for DANE, and what remains to do is ordinary PKIX validation.
     }
    recnum := get_result((dane.umask and mask) <> 0 , sk_danetls_record_num(dane.trecs) , 0);
    i := 0;
    while(matched = 0) and   (i < recnum) do
    begin
        t := sk_danetls_record_value(dane.trecs, i);
        if (DANETLS_USAGE_BIT(t.usage) and mask) = 0 then
            continue;
        if t.usage <> usage then
        begin
            usage := t.usage;
            { Reset digest agility for each usage/selector pair }
            mtype := DANETLS_NONE;
            ordinal := dane.dctx.mdord[t.mtype];
        end;
        if t.selector <> selector then
        begin
            selector := t.selector;
            { Update per-selector state }
            OPENSSL_free(i2dbuf);
            i2dbuf := dane_i2d(cert, selector, @i2dlen);
            if i2dbuf = nil then Exit(-1);
            { Reset digest agility for each usage/selector pair }
            mtype := DANETLS_NONE;
            ordinal := dane.dctx.mdord[t.mtype];
        end
        else
        if (t.mtype <> DANETLS_MATCHING_FULL) then
        begin
            {-
             * Digest agility:
             *
             *     <https://tools.ietf.org/html/rfc7671#section-9>
             *
             * For a fixed selector, after processing all records with the
             * highest mtype ordinal, ignore all mtypes with lower ordinals
             * other than 'Full'.
             }
            if dane.dctx.mdord[t.mtype] < ordinal then
               continue;
        end;
        {
         * Each time we hit a (new selector or) mtype, re-compute the relevant
         * digest, more complex caching is not worth the code space.
         }
        if t.mtype <> mtype then
        begin
            mtype := t.mtype;
            md := dane.dctx.mdevp[mtype];
            cmpbuf := i2dbuf;
            cmplen := i2dlen;
            if md <> nil then
            begin
                cmpbuf := @mdbuf;
                if  0>= EVP_Digest(i2dbuf, i2dlen, cmpbuf, @cmplen, md, 0 )then
                begin
                    matched := -1;
                    break;
                end;
            end;
        end;
        {
         * Squirrel away the certificate and depth if we have a match.  Any
         * DANE match is dispositive, but with PKIX we still need to build a
         * full chain.
         }
        if (cmplen = t.dlen)  and
            (memcmp(cmpbuf, t.data, cmplen) = 0) then
        begin
            if (DANETLS_USAGE_BIT(usage) and DANETLS_DANE_MASK)>0 then
                matched := 1;
            if matched  or  dane.mdpth < 0 then
            begin
                dane.mdpth := depth;
                dane.mtlsa := t;
                OPENSSL_free(dane.mcert);
                dane.mcert := cert;
                X509_up_ref(cert);
            end;
            break;
        end;
        Inc(i);
    end;
    { Clear the one-element DER cache }
    OPENSSL_free(i2dbuf);
    Result := matched;
 {$POINTERMATH OFF}
end;


function check_dane_issuer(ctx : PX509_STORE_CTX; depth : integer):integer;
var
  dane : PSSL_DANE;

  matched : integer;

  cert : PX509;
begin
    dane := ctx.dane;
    matched := 0;
    if  (not DANETLS_HAS_TA(dane)) or  (depth = 0)  then
        Exit(X509_TRUST_UNTRUSTED);
    {
     * Record any DANE trust anchor matches, for the first depth to test, if
     * there's one at that depth. (This'll be false for length 1 chains looking
     * for an exact match for the leaf certificate).
     }
    cert := sk_X509_value(ctx.chain, depth);
    matched := dane_match(ctx, cert, depth );
    if (cert <> nil)  and  (matched < 0) then
        Exit(matched);
    if matched > 0 then
    begin
        ctx.num_untrusted := depth - 1;
        Exit(X509_TRUST_TRUSTED);
    end;
    Result := X509_TRUST_UNTRUSTED;
end;


function check_dane_pkeys(ctx : PX509_STORE_CTX):integer;
var
  dane : PSSL_DANE;
  t : Pdanetls_record;
  num : integer;
  cert : PX509;
  recnum, i : integer;
begin
    dane := ctx.dane;
    num := ctx.num_untrusted;
    cert := sk_X509_value(ctx.chain, num - 1);
    recnum := sk_danetls_record_num(dane.trecs);
    for i := 0 to recnum-1 do
    begin
        t := sk_danetls_record_value(dane.trecs, i);
        if (t.usage <> DANETLS_USAGE_DANE_TA)  or
           (t.selector <> DANETLS_SELECTOR_SPKI)  or
           (t.mtype <> DANETLS_MATCHING_FULL)  or
           ( X509_verify(cert, t.spki)  <= 0)  then
            continue;
        { Clear any PKIX-?? matches that failed to extend to a full chain }
        X509_free(dane.mcert);
        dane.mcert := nil;
        { Record match via a bare TA public key }
        ctx.bare_ta_signed := 1;
        dane.mdpth := num - 1;
        dane.mtlsa := t;
        { Prune any excess chain certificates }
        num := sk_X509_num(ctx.chain);
        while ( num > ctx.num_untrusted) do
        begin
            X509_free(sk_X509_pop(ctx.chain));
            Dec(num);
        end;
        Exit(X509_TRUST_TRUSTED);
    end;
    Result := X509_TRUST_UNTRUSTED;
end;


procedure dane_reset(dane : PSSL_DANE);
begin
    { Reset state to verify another chain, or clear after failure. }
    X509_free(dane.mcert);
    dane.mcert := nil;
    dane.mtlsa := nil;
    dane.mdpth := -1;
    dane.pdpth := -1;
end;


function check_leaf_suiteb(ctx : PX509_STORE_CTX; cert : PX509):integer;
var
  err : integer;
begin
    err := X509_chain_check_suiteb(nil, cert, nil, ctx.param.flags);
    CB_FAIL_IF(err <> X509_V_OK, ctx, cert, 0, err);
    Result := 1;
end;


function dane_verify(ctx : PX509_STORE_CTX):integer;
var
  cert : PX509;

  dane : PSSL_DANE;

  matched, done : integer;
begin
    cert := ctx.cert;
    dane := ctx.dane;
    dane_reset(dane);
    {-
     * When testing the leaf certificate, if we match a DANE-EE(3) record,
     * dane_match() returns 1 and we're done.  If however we match a PKIX-EE(1)
     * record, the match depth and matching TLSA record are recorded, but the
     * return value is 0, because we still need to find a PKIX trust anchor.
     * Therefore, when DANE authentication is enabled (required), we're done
     * if:
     *   + matched < 0, internal error.
     *   + matched = 1, we matched a DANE-EE(3) record
     *   + matched = 0, mdepth < 0 (no PKIX-EE match) and there are no
     *     DANE-TA(2) or PKIX-TA(0) to test.
     }
    matched := dane_match(ctx, ctx.cert, 0);
    done := Int((matched <> 0)  or  ( (not DANETLS_HAS_TA(dane))  and  (dane.mdpth < 0)));
    if (done > 0)  and (0>= X509_get_pubkey_parameters(nil, ctx.chain))  then
        Exit(-1);
    if matched > 0 then
    begin
        { Callback invoked as needed }
        if  0>= check_leaf_suiteb(ctx, cert) then
            Exit(0);
        { Callback invoked as needed }
        if ( (dane.flags and DANE_FLAG_NO_DANE_EE_NAMECHECKS) = 0 ) and
           (  0>= check_id(ctx))  then
            Exit(0);
        { Bypass internal_verify(), issue depth 0 success callback }
        ctx.error_depth := 0;
        ctx.current_cert := cert;
        Exit(ctx.verify_cb(1, ctx));
    end;
    if matched < 0 then begin
        ctx.error_depth := 0;
        ctx.current_cert := cert;
        ctx.error := X509_V_ERR_OUT_OF_MEM;
        Exit(-1);
    end;
    if done > 0 then
    begin
        { Fail early, TA-based success is not possible }
        if  0>= check_leaf_suiteb(ctx, cert) then
            Exit(0);
        Exit(verify_cb_cert(ctx, cert, 0, X509_V_ERR_DANE_NO_MATCH));
    end;
    {
     * Chain verification for usages 0/1/2.  TLSA record matching of depth > 0
     * certificates happens in-line with building the rest of the chain.
     }
    Result := verify_chain(ctx);
end;


function get1_trusted_issuer(issuer : PPX509; ctx : PX509_STORE_CTX; cert : PX509):integer;
var
  ok : integer;
  saved_chain: PSTACK_st_X509;
begin
    saved_chain := ctx.chain;
    ctx.chain := nil;
    ok := ctx.get_issuer(issuer, ctx, cert);
    ctx.chain := saved_chain;
    Result := ok;
end;


function build_chain(ctx : PX509_STORE_CTX):integer;
const
  S_DOUNTRUSTED = (1 shl 0); (* Search untrusted chain *)
  S_DOTRUSTED   = (1 shl 1); (* Search trusted store *)
  S_DOALTERNATE = (1 shl 2); (* Retry with pruned alternate chain *)
var
    dane          : PSSL_DANE;
    num           : integer;
    search        : uint32;
    b             : Boolean;
    may_trusted,
    may_alternate,
    trust,
    alt_untrusted,
    max_depth,
    ok,
    prev_error,
    i             : integer;
    sk_untrusted: PSTACK_st_X509;
  curr,
  issuer        : PX509;
  self_signed   : integer;

  label int_err, memerr;


begin
    dane := ctx.dane;
    num := sk_X509_num(ctx.chain);
    sk_untrusted := nil;
    may_trusted := 0;
    may_alternate := 0;
    trust := X509_TRUST_UNTRUSTED;
    alt_untrusted := 0;
    ok := 0;
    prev_error := ctx.error;
    b := (num = 1) and  (ctx.num_untrusted = num);
    { Our chain starts with a single untrusted element. }
    if  not ossl_assert(b) then
        goto int_err;
     (* Set up search policy, untrusted if possible, trusted-first if enabled,
     * which is the default.
     * If we're doing DANE and not doing PKIX-TA/PKIX-EE, we never look in the
     * trust_store, otherwise we might look there first.  If not trusted-first,
     * and alternate chains are not disabled, try building an alternate chain
     * if no luck with untrusted first.
     *)
    search := get_result( ctx.untrusted <> nil , S_DOUNTRUSTED , 0);
    if (DANETLS_HAS_PKIX(dane))  or  ( not DANETLS_HAS_DANE(dane)) then
    begin
        if (search = 0)  or  ((ctx.param.flags and X509_V_FLAG_TRUSTED_FIRST) <> 0) then
            search  := search  or S_DOTRUSTED
        else
        if ( 0>= (ctx.param.flags and X509_V_FLAG_NO_ALT_CHAINS)) then
            may_alternate := 1;
        may_trusted := 1;
    end;
    { Initialize empty untrusted stack. }
    sk_untrusted := sk_X509_new_null( );
    if sk_untrusted = nil then
       goto memerr;
    {
     * If we got any 'Cert(0) Full(0)' trust anchors from DNS, *prepend* them
     * to our working copy of the untrusted certificate stack.
     }
    if (DANETLS_ENABLED(dane))   and  (dane.certs <> nil)
         and   (0>= X509_add_certs(sk_untrusted, dane.certs, X509_ADD_FLAG_DEFAULT))then
          goto memerr;
    {
     * Shallow-copy the stack of untrusted certificates (with TLS, this is
     * typically the content of the peer's certificate message) so we can make
     * multiple passes over it, while free to remove elements as we go.
     }
    if  0>= X509_add_certs(sk_untrusted, ctx.untrusted, X509_ADD_FLAG_DEFAULT) then
        goto memerr;
    {
     * Still absurdly large, but arithmetically safe, a lower hard upper bound
     * might be reasonable.
     }
    if ctx.param.depth > INT_MAX div 2 then
        ctx.param.depth := INT_MAX div 2;
    {
     * Try to extend the chain until we reach an ultimately trusted issuer.
     * Build chains up to one longer the limit, later fail if we hit the limit,
     * with an X509_V_ERR_CERT_CHAIN_TOO_LONG error code.
     }
    max_depth := ctx.param.depth + 1;
    while search <> 0 do
    begin
        issuer := nil;
        num := sk_X509_num(ctx.chain);
        ctx.error_depth := num - 1;
        {
         * Look in the trust store if enabled for first lookup, or we've run
         * out of untrusted issuers and search here is not disabled.  When we
         * reach the depth limit, we stop extending the chain, if by that point
         * we've not found a trust anchor, any trusted chain would be too long.
         *
         * The error reported to the application verify callback is at the
         * maximal valid depth with the current certificate equal to the last
         * not ultimately-trusted issuer.  For example, with verify_depth = 0,
         * the callback will report errors at depth=1 when the immediate issuer
         * of the leaf certificate is not a trust anchor.  No attempt will be
         * made to locate an issuer for that certificate, since such a chain
         * would be a-priori too long.
         }
        if (search and S_DOTRUSTED ) <> 0 then
        begin
            i := num;
            if (search and S_DOALTERNATE ) <> 0 then
            begin
                {
                 * As high up the chain as we can, look for an alternative
                 * trusted issuer of an untrusted certificate that currently
                 * has an untrusted issuer.  We use the alt_untrusted variable
                 * to track how far up the chain we find the first match.  It
                 * is only if and when we find a match, that we prune the chain
                 * and reset ctx.num_untrusted to the reduced count of
                 * untrusted certificates.  While we're searching for such a
                 * match (which may never be found), it is neither safe nor
                 * wise to preemptively modify either the chain or
                 * ctx.num_untrusted.
                 *
                 * Note, like ctx.num_untrusted, alt_untrusted is a count of
                 * untrusted certificates, not a 'depth'.
                 }
                i := alt_untrusted;
            end;
            curr := sk_X509_value(ctx.chain, i - 1);
            { Note: get1_trusted_issuer() must be used even if self-signed. }
            ok := get_result(num > max_depth , 0 , get1_trusted_issuer(@issuer, ctx, curr));
            if ok < 0 then
            begin
                trust := -1;
                ctx.error := X509_V_ERR_STORE_LOOKUP;
                break;
            end;
            if ok > 0 then
            begin
                self_signed := X509_self_signed(curr, 0);
                if self_signed < 0 then
                begin
                    X509_free(issuer);
                     goto int_err;
                end;
                {
                 * Alternative trusted issuer for a mid-chain untrusted cert?
                 * Pop the untrusted cert's successors and retry.  We might now
                 * be able to complete a valid chain via the trust store.  Note
                 * that despite the current trust store match we might still
                 * fail complete the chain to a suitable trust anchor, in which
                 * case we may prune some more untrusted certificates and try
                 * again.  Thus the S_DOALTERNATE bit may yet be turned on
                 * again with an even shorter untrusted chain!
                 *
                 * If in the process we threw away our matching PKIX-TA trust
                 * anchor, reset DANE trust.  We might find a suitable trusted
                 * certificate among the ones from the trust store.
                 }
                if (search and S_DOALTERNATE ) <> 0 then
                begin
                    if  not ossl_assert(( (num > i)  and  (i > 0)  and   (0>= self_signed)) ) then
                    begin
                        X509_free(issuer);
                        goto int_err;
                    end;
                    search := search and ( not S_DOALTERNATE);
                    while num > i do
                    begin
                        X509_free(sk_X509_pop(ctx.chain));
                        Dec(num);
                    end;
                    ctx.num_untrusted := num;
                    if (DANETLS_ENABLED(dane)) and
                       ( dane.mdpth >= ctx.num_untrusted)  then
                    begin
                        dane.mdpth := -1;
                        X509_free(dane.mcert);
                        dane.mcert := nil;
                    end;
                    if (DANETLS_ENABLED(dane))  and
                       ( dane.pdpth >= ctx.num_untrusted) then
                        dane.pdpth := -1;
                end;
                {
                 * Self-signed untrusted certificates get replaced by their
                 * trusted matching issuer.  Otherwise, grow the chain.
                 }
                if  0>= self_signed then
                begin
                    if  0>= sk_X509_push(ctx.chain, issuer) then
                    begin
                        X509_free(issuer);
                        goto memerr;
                    end;
                    self_signed := X509_self_signed(issuer, 0 );
                    if self_signed  < 0 then
                        goto int_err;
                end
                else
                begin
                    {
                     * We have a self-signed certificate that has the same
                     * subject name (and perhaps keyid and/or serial number) as
                     * a trust anchor.  We must have an exact match to avoid
                     * possible impersonation via key substitution etc.
                     }
                    if X509_cmp(curr, issuer) <> 0 then
                    begin
                        { Self-signed untrusted mimic. }
                        X509_free(issuer);
                        ok := 0;
                    end
                    else
                    begin  { curr '=' issuer }
                        X509_free(curr);
                        Dec(num);
                        ctx.num_untrusted := (num);
                        sk_X509_set(ctx.chain, num, issuer);
                    end;
                end;
                {
                 * We've added a new trusted certificate to the chain, re-check
                 * trust.  If not done, and not self-signed look deeper.
                 * Whether or not we're doing 'trusted first', we no longer
                 * look for untrusted certificates from the peer's chain.
                 *
                 * At this point ctx.num_trusted and num must reflect the
                 * correct number of untrusted certificates, since the DANE
                 * logic in check_trust() depends on distinguishing CAs from
                 * 'the wire' from CAs from the trust store.  In particular, the
                 * certificate at depth 'num' should be the new trusted
                 * certificate with ctx.num_untrusted <= num.
                 }
                if ok >0 then
                begin
                    if  not ossl_assert(ctx.num_untrusted <= num) then
                        goto int_err;
                    search := search and (not S_DOUNTRUSTED);
                    trust := check_trust(ctx, num);
                    if trust <> X509_TRUST_UNTRUSTED then
                       break;
                    if  0>= self_signed then
                       continue;
                end;
            end;
            {
             * No dispositive decision, and either self-signed or no match, if
             * we were doing untrusted-first, and alt-chains are not disabled,
             * do that, by repeatedly losing one untrusted element at a time,
             * and trying to extend the shorted chain.
             }
            if (search and S_DOUNTRUSTED ) = 0 then
            begin
                { Continue search for a trusted issuer of a shorter chain? }
                Dec(alt_untrusted);
                if ((search and S_DOALTERNATE) <> 0)  and
                   (alt_untrusted > 0) then
                    continue;
                { Still no luck and no fallbacks left? }
                if  (0>= may_alternate)  or  ((search and S_DOALTERNATE ) <> 0)  or
                    (ctx.num_untrusted < 2) then
                    break;
                { Search for a trusted issuer of a shorter chain }
                search  := search  or S_DOALTERNATE;
                alt_untrusted := ctx.num_untrusted - 1;
            end;
        end;
        {
         * Extend chain with peer-provided untrusted certificates
         }
        if ((search and S_DOUNTRUSTED ) <> 0) then
        begin
            num := sk_X509_num(ctx.chain);
            if  not ossl_assert( (num = ctx.num_untrusted) )  then
               goto int_err;
            curr := sk_X509_value(ctx.chain, num - 1);
            if (X509_self_signed(curr, 0) > 0)  or ( num > max_depth) then
                issuer :=  nil
            else
                issuer := find_issuer(ctx, sk_untrusted, curr);
            if issuer = nil then begin
                {
                 * Once we have reached a self-signed cert or num > max_depth
                 * or can't find an issuer in the untrusted list we stop looking
                 * there and start looking only in the trust store if enabled.
                 }
                search := search and (not S_DOUNTRUSTED);
                if may_trusted>0 then
                   search  := search  or S_DOTRUSTED;
                continue;
            end;
            { Drop this issuer from future consideration }
            sk_X509_delete_ptr(sk_untrusted, issuer);
            if  0>= X509_add_cert(ctx.chain, issuer, X509_ADD_FLAG_UP_REF ) then
                 goto int_err;
            Inc(ctx.num_untrusted);
            { Check for DANE-TA trust of the topmost untrusted certificate. }
            trust := check_dane_issuer(ctx, ctx.num_untrusted - 1);
            if (trust = X509_TRUST_TRUSTED)  or  (trust = X509_TRUST_REJECTED) then
               break;
        end;
    end;
    sk_X509_free(sk_untrusted);
    if trust < 0 then { internal error }
        Exit(trust);
    {
     * Last chance to make a trusted chain, either bare DANE-TA public-key
     * signers, or else direct leaf PKIX trust.
     }
    num := sk_X509_num(ctx.chain);
    if num <= max_depth then
    begin
        if (trust = X509_TRUST_UNTRUSTED)  and  (DANETLS_HAS_DANE_TA(dane)) then
            trust := check_dane_pkeys(ctx);
        if (trust = X509_TRUST_UNTRUSTED)  and  (num = ctx.num_untrusted) then
            trust := check_trust(ctx, num);
    end;
    case trust of
        X509_TRUST_TRUSTED:
        begin
            { Must restore any previous error value for backward compatibility }
            ctx.error := prev_error;
            Exit(1);
        end;
        X509_TRUST_REJECTED:
            { Callback already issued }
            Exit(0);
        X509_TRUST_UNTRUSTED:
        else
        begin
            case ctx.error of
              X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
              X509_V_ERR_CERT_NOT_YET_VALID,
              X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
              X509_V_ERR_CERT_HAS_EXPIRED:
                  Exit( 0); { Callback already issued by ossl_x509_check_cert_time() }

              X509_V_OK:
                  begin
                    //
                  end;
              else { A preliminary error has become final }
                  Exit(verify_cb_cert(ctx, nil, num - 1, ctx.error));
            end;
            CB_FAIL_IF(num > max_depth,
                       ctx, nil, num - 1, X509_V_ERR_CERT_CHAIN_TOO_LONG);
            CB_FAIL_IF( (DANETLS_ENABLED(dane))  and
                    ( (not DANETLS_HAS_PKIX(dane))  or  (dane.pdpth >= 0) ),
                       ctx, nil, num - 1, X509_V_ERR_DANE_NO_MATCH);
            if X509_self_signed(sk_X509_value(ctx.chain, num - 1 ) , 0) > 0 then
                Exit(verify_cb_cert(ctx, nil, num - 1,
                                      get_result( num = 1
                                      , X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                                      , X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)));
            Exit(verify_cb_cert(ctx, nil, num - 1,
                                  get_result(ctx.num_untrusted < num
                                  , X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
                                  , X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)));
        end;
    end;
 int_err:
    ERR_raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR);
    ctx.error := X509_V_ERR_UNSPECIFIED;
    sk_X509_free(sk_untrusted);
    Exit(-1);
 memerr:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    ctx.error := X509_V_ERR_OUT_OF_MEM;
    sk_X509_free(sk_untrusted);
    Result := -1;
end;


function check_key_level(ctx : PX509_STORE_CTX; cert : PX509):integer;
var
  pkey : PEVP_PKEY;

  level : integer;
begin
    pkey := X509_get0_pubkey(cert);
    level := ctx.param.auth_level;
    {
     * At security level zero, return without checking for a supported public
     * key type.  Some engines support key types not understood outside the
     * engine, and we only need to understand the key when enforcing a security
     * floor.
     }
    if level <= 0 then Exit(1);
    { Unsupported or malformed keys are not secure }
    if pkey = nil then Exit(0);
    if level > NUM_AUTH_LEVELS then
       level := NUM_AUTH_LEVELS;
    Result := Integer(EVP_PKEY_get_security_bits(pkey) >= minbits_table[level - 1]);
end;


function check_curve(cert : PX509):integer;
var
  pkey : PEVP_PKEY;

  ret, val : integer;
begin
    pkey := X509_get0_pubkey(cert);
    { Unsupported or malformed key }
    if pkey = nil then Exit(-1);
    if EVP_PKEY_get_id(pkey) = EVP_PKEY_EC then
    begin
        ret := EVP_PKEY_get_int_param(pkey,
                                     OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
                                     @val);
        Exit(get_result( ret < 0 , ret ,  not val));
    end;
    Result := 1;
end;


function check_sig_level(ctx : PX509_STORE_CTX; cert : PX509):integer;
var
  secbits, level : integer;
begin
    secbits := -1;
    level := ctx.param.auth_level;
    if level <= 0 then Exit(1);
    if level > NUM_AUTH_LEVELS then
       level := NUM_AUTH_LEVELS;
    if  0>= X509_get_signature_info(cert, nil, nil, @secbits, nil )  then
        Exit(0);
    Result := int( secbits >= minbits_table[level - 1]);
end;

initialization
   NUM_AUTH_LEVELS := Length(minbits_table);

end.
