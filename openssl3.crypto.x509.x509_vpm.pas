unit openssl3.crypto.x509.x509_vpm;

interface
 uses OpenSSL.Api;

function X509_VERIFY_PARAM_get_flags(const param : PX509_VERIFY_PARAM):Cardinal;
function X509_VERIFY_PARAM_get_time(const param : PX509_VERIFY_PARAM):time_t;
function X509_VERIFY_PARAM_new:PX509_VERIFY_PARAM;
function X509_VERIFY_PARAM_inherit(dest : PX509_VERIFY_PARAM;const src : PX509_VERIFY_PARAM):integer;
function X509_VERIFY_PARAM_set1_policies( param : PX509_VERIFY_PARAM; policies : Pstack_st_ASN1_OBJECT):integer;
procedure str_free( s : PUTF8Char);
function str_copy(const s : PUTF8Char):PUTF8Char;
function X509_VERIFY_PARAM_set1_email(param : PX509_VERIFY_PARAM;const email : PUTF8Char; emaillen : size_t):integer;
 function int_x509_param_set1(pdest : PPUTF8Char; pdestlen : Psize_t;const src : PUTF8Char; srclen : size_t):integer;
 function X509_VERIFY_PARAM_set1_ip(param : PX509_VERIFY_PARAM;const ip : PByte; iplen : size_t):integer;
 function X509_VERIFY_PARAM_lookup(const name : PUTF8Char):PX509_VERIFY_PARAM;
function table_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
function OBJ_bsearch_table(key : PX509_VERIFY_PARAM;const base : PX509_VERIFY_PARAM; num : integer):PX509_VERIFY_PARAM;
function table_cmp(const a, b : PX509_VERIFY_PARAM):integer;
 procedure X509_VERIFY_PARAM_free( param : PX509_VERIFY_PARAM);
 procedure X509_VERIFY_PARAM_set_depth( param : PX509_VERIFY_PARAM; depth : integer);
function X509_VERIFY_PARAM_set_flags( param : PX509_VERIFY_PARAM; flags : Cardinal):integer;
 procedure X509_VERIFY_PARAM_set_time( param : PX509_VERIFY_PARAM; t : time_t);


var
   param_table: Pstack_st_X509_VERIFY_PARAM = nil;
   default_table: array of TX509_VERIFY_PARAM ;

implementation
 uses openssl3.crypto.mem, OpenSSL3.Err, OpenSSL3.include.openssl.asn1,
      openssl3.crypto.asn1.a_object, openssl3.crypto.objects.obj_lib,
      openssl3.crypto.stack, openssl3.crypto.o_str,
      openssl3.crypto.objects.obj_dat,
      OpenSSL3.crypto.x509.x509_vfy;


procedure X509_VERIFY_PARAM_set_time( param : PX509_VERIFY_PARAM; t : time_t);
begin
    param.check_time := t;
    param.flags  := param.flags  or X509_V_FLAG_USE_CHECK_TIME;
end;




function X509_VERIFY_PARAM_set_flags( param : PX509_VERIFY_PARAM; flags : Cardinal):integer;
begin
    param.flags  := param.flags  or flags;
    if flags and X509_V_FLAG_POLICY_MASK > 0 then
       param.flags  := param.flags  or X509_V_FLAG_POLICY_CHECK;
    Result := 1;
end;

procedure X509_VERIFY_PARAM_set_depth( param : PX509_VERIFY_PARAM; depth : integer);
begin
    param.depth := depth;
end;

procedure X509_VERIFY_PARAM_free( param : PX509_VERIFY_PARAM);
begin
    if param = nil then exit;
    sk_ASN1_OBJECT_pop_free(param.policies, ASN1_OBJECT_free);
    sk_OPENSSL_STRING_pop_free(param.hosts, str_free);
    OPENSSL_free(param.peername);
    OPENSSL_free(param.email);
    OPENSSL_free(param.ip);
    OPENSSL_free(param);
end;

function table_cmp(const a, b : PX509_VERIFY_PARAM):integer;
begin
    Result := strcmp(a.name, b.name);
end;

function table_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : PX509_VERIFY_PARAM;
begin
   a := a_;
   b := b_;
   Exit(table_cmp(a,b));
end;


function OBJ_bsearch_table(key : PX509_VERIFY_PARAM;const base : PX509_VERIFY_PARAM; num : integer):PX509_VERIFY_PARAM;
begin
   Result := PX509_VERIFY_PARAM (OBJ_bsearch_(key, base, num, sizeof(TX509_VERIFY_PARAM), table_cmp_BSEARCH_CMP_FN));
end;


function X509_VERIFY_PARAM_lookup(const name : PUTF8Char):PX509_VERIFY_PARAM;
var
  idx : integer;
  pm : TX509_VERIFY_PARAM;
begin
    pm.name := PUTF8Char( name);
    if param_table <> nil then begin
        idx := sk_X509_VERIFY_PARAM_find(param_table, @pm);
        if idx >= 0 then Exit(sk_X509_VERIFY_PARAM_value(param_table, idx));
    end;
    Result := OBJ_bsearch_table(@pm, @default_table, Length(default_table));
end;




function X509_VERIFY_PARAM_set1_ip(param : PX509_VERIFY_PARAM;const ip : PByte; iplen : size_t):integer;
begin
    if (iplen <> 0)  and  (iplen <> 4)  and  (iplen <> 16) then Exit(0);
    Exit(int_x509_param_set1(PPUTF8Char(@param.ip), @param.iplen,
                               PUTF8Char( ip), iplen));
end;

function int_x509_param_set1(pdest : PPUTF8Char; pdestlen : Psize_t;const src : PUTF8Char; srclen : size_t):integer;
var
  tmp : PUTF8Char;
begin
    if src <> nil then
    begin
        if srclen = 0 then
            srclen := Length(src);
        tmp := OPENSSL_malloc(srclen + 1);
        if tmp = nil then Exit(0);
        memcpy(tmp, src, srclen);
        tmp[srclen] := #0;
    end
    else
    begin
        tmp := nil;
        srclen := 0;
    end;
    OPENSSL_free(pdest^);
    pdest^ := tmp;
    if pdestlen <> nil then pdestlen^ := srclen;
    Result := 1;
end;



function X509_VERIFY_PARAM_set1_email(param : PX509_VERIFY_PARAM;const email : PUTF8Char; emaillen : size_t):integer;
begin
    Exit(int_x509_param_set1(@param.email, @param.emaillen, email, emaillen));
end;




function str_copy(const s : PUTF8Char):PUTF8Char;
begin
    Exit(strcpy(Result, s));
end;

procedure str_free( s : PUTF8Char);
begin
    OPENSSL_free(s);
end;





function X509_VERIFY_PARAM_set1_policies( param : PX509_VERIFY_PARAM; policies : Pstack_st_ASN1_OBJECT):integer;
var
  i : integer;

  oid, doid : PASN1_OBJECT;
begin
    if param = nil then Exit(0);
    sk_ASN1_OBJECT_pop_free(param.policies, ASN1_OBJECT_free);
    if policies = nil then begin
        param.policies := nil;
        Exit(1);
    end;
    param.policies := sk_ASN1_OBJECT_new_null;
    if param.policies = nil then Exit(0);
    for i := 0 to sk_ASN1_OBJECT_num(policies)-1 do begin
        oid := sk_ASN1_OBJECT_value(policies, i);
        doid := OBJ_dup(oid);
        if nil =doid then Exit(0);
        if 0>=sk_ASN1_OBJECT_push(param.policies, doid) then  begin
            ASN1_OBJECT_free(doid);
            Exit(0);
        end;
    end;
    param.flags  := param.flags  or X509_V_FLAG_POLICY_CHECK;
    Result := 1;
end;





function X509_VERIFY_PARAM_inherit(dest : PX509_VERIFY_PARAM;const src : PX509_VERIFY_PARAM):integer;
var
  inh_flags    : Cardinal;
  to_default,
  to_overwrite : integer;
begin
    if nil =src then Exit(1);
    inh_flags := dest.inh_flags or src.inh_flags;
    if inh_flags and X509_VP_FLAG_ONCE > 0 then dest.inh_flags := 0;
    if inh_flags and X509_VP_FLAG_LOCKED > 0 then Exit(1);
    if inh_flags and X509_VP_FLAG_DEFAULT > 0 then
        to_default := 1
    else
        to_default := 0;
    if inh_flags and X509_VP_FLAG_OVERWRITE > 0 then
        to_overwrite := 1
    else
        to_overwrite := 0;

    {x509_verify_param_copy(purpose, 0);
    x509_verify_param_copy(trust, X509_TRUST_DEFAULT);
    x509_verify_param_copy(depth, -1);
    x509_verify_param_copy(auth_level, -1);}
    if (to_overwrite > 0)  or  ((src.purpose <> 0)  and ( (to_default>0)  or  (dest.purpose = 0))) then
       dest.purpose := src.purpose;
    if (to_overwrite > 0)  or  ((src.trust <> 0)  and ( (to_default > 0) or  (dest.trust = 0))) then
       dest.trust := src.trust;
    if (to_overwrite > 0)  or  ((src.depth <> -1)  and ( (to_default > 0)  or  (dest.depth = -1))) then
       dest.depth := src.depth;
    if (to_overwrite > 0)  or  ((src.auth_level <> -1) and ( (to_default > 0) or  (dest.auth_level = -1))) then
       dest.auth_level := src.auth_level;


    { If overwrite or check time not set, copy across }
    if (to_overwrite > 0) or  (0 >= dest.flags and X509_V_FLAG_USE_CHECK_TIME) then  begin
        dest.check_time := src.check_time;
        dest.flags := dest.flags and  not X509_V_FLAG_USE_CHECK_TIME;
        { Don't need to copy flag: that is done below }
    end;
    if inh_flags and X509_VP_FLAG_RESET_FLAGS > 0 then dest.flags := 0;
    dest.flags  := dest.flags  or src.flags;

    if (to_overwrite > 0) or ((src.policies <> nil) and ( (to_default > 0) or (dest.policies = nil))) then
    begin
        if 0>=X509_VERIFY_PARAM_set1_policies(dest, src.policies) then
            Exit(0);
    end;

    if (to_overwrite > 0) or ((src.hostflags <> 0) and ( (to_default > 0) or (dest.hostflags = 0))) then
       dest.hostflags := src.hostflags;

    if (to_overwrite > 0) or ((src.hosts <> nil) and ( (to_default > 0) or (dest.hosts = nil))) then
    begin
        sk_OPENSSL_STRING_pop_free(dest.hosts, str_free);
        dest.hosts := nil;
        if src.hosts <> nil then
        begin
            dest.hosts := sk_OPENSSL_STRING_deep_copy(src.hosts, str_copy, str_free);
            if dest.hosts = nil then Exit(0);
        end;
    end;

    if (to_overwrite > 0) or ((src.email <> nil) and ( (to_default > 0) or (dest.email = nil))) then
    begin
        if 0>=X509_VERIFY_PARAM_set1_email(dest, src.email, src.emaillen) then
            Exit(0);
    end;
    if (to_overwrite > 0) or ((src.ip <> nil) and ( (to_default > 0) or (dest.ip = nil))) then
    begin
        if 0>=X509_VERIFY_PARAM_set1_ip(dest, src.ip, src.iplen) then
            Exit(0);
    end;
    Result := 1;
end;

function X509_VERIFY_PARAM_new:PX509_VERIFY_PARAM;
var
  param : PX509_VERIFY_PARAM;
begin
    param := OPENSSL_zalloc(sizeof( param^));
    if param = nil then begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    param.trust := X509_TRUST_DEFAULT;
    { param.inh_flags = X509_VP_FLAG_DEFAULT; }
    param.depth := -1;
    param.auth_level := -1; { -1 means unset, 0 is explicit }
    Result := param;
end;



function X509_VERIFY_PARAM_get_time(const param : PX509_VERIFY_PARAM):time_t;
begin
    Result := param.check_time;
end;




function X509_VERIFY_PARAM_get_flags(const param : PX509_VERIFY_PARAM):Cardinal;
begin
    Result := param.flags;
end;

initialization
   default_table := [
    get_X509_VERIFY_PARAM(
     'default',                 (* X509 default parameters *)
     0,                         (* check time to use *)
     0,                         (* inheritance flags *)
     X509_V_FLAG_TRUSTED_FIRST, (* flags *)
     0,                         (* purpose *)
     0,                         (* trust *)
     100,                       (* depth *)
     -1,                        (* auth_level *)
     nil,                      (* policies *)
     nil, 0, nil, nil, 0, nil, 0),
    get_X509_VERIFY_PARAM(
     'pkcs7',                   (* S/MIME sign parameters *)
     0,                         (* check time to use *)
     0,                         (* inheritance flags *)
     0,                         (* flags *)
     X509_PURPOSE_SMIME_SIGN,   (* purpose *)
     X509_TRUST_EMAIL,          (* trust *)
     -1,                        (* depth *)
     -1,                        (* auth_level *)
     nil,                      (* policies *)
     nil, 0, nil, nil, 0, nil, 0),
    get_X509_VERIFY_PARAM(
     'smime_sign',              (* S/MIME sign parameters *)
     0,                         (* check time to use *)
     0,                         (* inheritance flags *)
     0,                         (* flags *)
     X509_PURPOSE_SMIME_SIGN,   (* purpose *)
     X509_TRUST_EMAIL,          (* trust *)
     -1,                        (* depth *)
     -1,                        (* auth_level *)
     nil,                      (* policies *)
     nil, 0, nil, nil, 0, nil, 0),
    get_X509_VERIFY_PARAM(
     'ssl_client',              (* SSL/TLS client parameters *)
     0,                         (* check time to use *)
     0,                         (* inheritance flags *)
     0,                         (* flags *)
     X509_PURPOSE_SSL_CLIENT,   (* purpose *)
     X509_TRUST_SSL_CLIENT,     (* trust *)
     -1,                        (* depth *)
     -1,                        (* auth_level *)
     nil,                      (* policies *)
     nil, 0, nil, nil, 0, nil, 0),
    get_X509_VERIFY_PARAM(
     'ssl_server',              (* SSL/TLS server parameters *)
     0,                         (* check time to use *)
     0,                         (* inheritance flags *)
     0,                         (* flags *)
     X509_PURPOSE_SSL_SERVER,   (* purpose *)
     X509_TRUST_SSL_SERVER,     (* trust *)
     -1,                        (* depth *)
     -1,                        (* auth_level *)
     nil,                      (* policies *)
     nil, 0, nil, nil, 0, nil, 0)
];

end.
