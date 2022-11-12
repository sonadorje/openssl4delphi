unit OpenSSL3.crypto.x509.v3_utl;

interface
uses OpenSSL.Api;
type
  IPV6_STAT = record
    tmp      : array[0..15] of byte;
    total,
    zero_pos,
    zero_cnt : integer;
  end;
  PIPV6_STAT = ^IPV6_STAT;
  Tequal_fn = function ({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;

const
  HDR_NAME  =      1;
  HDR_VALUE =      2;
  LABEL_START  =   (1 shl 0);
  LABEL_END    =   (1 shl 1);
  LABEL_HYPHEN =   (1 shl 2);
  LABEL_IDNA   =   (1 shl 3);

 function ossl_v3_name_cmp(const name, cmp : PUTF8Char):integer;

function ossl_a2i_ipadd(ipout : PByte;const ipasc : PUTF8Char):integer;
function ipv6_from_asc(v6 : PByte;const &in : PUTF8Char):integer;
function ipv6_cb(const elem : PUTF8Char; len : integer; usr : Pointer):integer;
function ipv6_hex(&out : PByte;&in : PUTF8Char; inlen : integer):integer;
function ipv4_from_asc(v4 : PByte;&in : PUTF8Char):integer;
function X509V3_parse_list(const line : PUTF8Char):Pstack_st_CONF_VALUE;
function strip_spaces( name : PUTF8Char):PUTF8Char;
function X509V3_add_value(const name, value : PUTF8Char;extlist : PPstack_st_CONF_VALUE):integer;
function x509v3_add_len_value(const name, value : PUTF8Char; vallen : size_t; extlist : PPstack_st_CONF_VALUE):integer;
procedure X509V3_conf_free( conf : Pointer);
function a2i_IPADDRESS_NC(const ipasc : PUTF8Char):PASN1_OCTET_STRING;
function a2i_IPADDRESS(const ipasc : PUTF8Char):PASN1_OCTET_STRING;
function X509V3_get_value_bool(const value : PCONF_VALUE; asn1_bool : PInteger):integer;
function s2i_ASN1_INTEGER(method : PX509V3_EXT_METHOD; value : PUTF8Char):PASN1_INTEGER;
function X509V3_NAME_from_section( nm : PX509_NAME; dn_sk : Pstack_st_CONF_VALUE; chtype : Cardinal):integer;
function ossl_ipaddr_to_asc( p : PByte; len : integer):PUTF8Char;
function i2s_ASN1_INTEGER(method : PX509V3_EXT_METHOD;const a : PASN1_INTEGER):PUTF8Char;
function bignum_to_string(const bn : PBIGNUM):PUTF8Char;
 function x509v3_add_len_value_uchar(const name : PUTF8Char; value : PByte; vallen : size_t; extlist : PPstack_st_CONF_VALUE):integer;
 function X509V3_get_value_int(const value : PCONF_VALUE; aint : PPASN1_INTEGER):integer;
 function X509V3_add_value_bool(const name : PUTF8Char; asn1_bool : integer; extlist : PPstack_st_CONF_VALUE):integer;
 function X509V3_add_value_int(const name : PUTF8Char; aint : PASN1_INTEGER; extlist : PPstack_st_CONF_VALUE):integer;
 function i2s_ASN1_ENUMERATED(method : PX509V3_EXT_METHOD;const a : PASN1_ENUMERATED):PUTF8Char;
 function X509_check_host(x : PX509;const chk : PUTF8Char; chklen : size_t; flags : uint32; peername : PPUTF8Char):integer;
 function do_x509_check(x : PX509;const chk : PUTF8Char; chklen : size_t; flags : uint32; check_type : integer; peername : PPUTF8Char):integer;
 function equal_email({const} a : PByte; a_len : size_t;{const} b : PByte; b_len : size_t; unused_flags : uint32):integer;
 function equal_nocase({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;
 procedure skip_prefix(const p : PPByte; plen : Psize_t; subject_len : size_t; flags : uint32);
 function equal_case({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;
 function equal_wildcard({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;
 function valid_star(const p : PByte; len : size_t; flags : uint32):PByte;
  function wildcard_match(const prefix : PByte; prefix_len : size_t;const suffix : PByte; suffix_len : size_t;const subject : PByte; subject_len : size_t; flags : uint32):integer;
  function do_check_string(const a : PASN1_STRING; cmp_type : integer; equal : Tequal_fn; flags : uint32;const b : PUTF8Char; blen : size_t; peername : PPUTF8Char):integer;
  function X509_check_email(x : PX509;const chk : PUTF8Char; chklen : size_t; flags : uint32):integer;
 function X509_check_ip(x : PX509;const chk : PByte; chklen : size_t; flags : uint32):integer;

implementation
uses
   openssl3.crypto.ctype, openssl3.crypto.o_str, openssl3.crypto.conf.conf_mod,
   OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.openssl.conf,
   openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_conv,
   openssl3.crypto.asn1.a_int, OpenSSL3.crypto.x509.x509name,
   openssl3.crypto.bio.bio_print, OpenSSL3.common,
   openssl3.crypto.x509.v3_genn, OpenSSL3.crypto.x509.x509_cmp,
   openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.a_strex,
   OpenSSL3.crypto.x509.x509_ext, openssl3.crypto.x509v3,
   openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.a_octet;


function get_result(condition: Boolean;result1, result2: size_t): size_t;
begin
  if condition  then
     Result := Result1
  else
     Result := Result2;
end;


function X509_check_ip(x : PX509;const chk : PByte; chklen : size_t; flags : uint32):integer;
begin
    if chk = nil then
       Exit(-2);
    Result := do_x509_check(x, PUTF8Char( chk), chklen, flags, GEN_IPADD, nil);
end;



function X509_check_email(x : PX509;const chk : PUTF8Char; chklen : size_t; flags : uint32):integer;
var
  ret: size_t;
begin
    if chk = nil then Exit(-2);
    {
     * Embedded NULs are disallowed, except as the last character of a
     * string of length 2 or more (tolerate caller including terminating
     * NUL in string length).
     }
    if chklen = 0 then
       chklen := Length(chk)
    else
    begin
       if chklen > 1 then
         ret := chklen - 1
       else
         ret := chklen;
        if memchr(chk, #0, ret) <> nil then
            Exit(-2);
    end;
    if (chklen > 1)  and  (chk[chklen - 1] = #0) then
       Dec(chklen);
    Result := do_x509_check(x, chk, chklen, flags, GEN_EMAIL, nil);
end;



function do_check_string(const a : PASN1_STRING; cmp_type : integer; equal : Tequal_fn; flags : uint32;const b : PUTF8Char; blen : size_t; peername : PPUTF8Char):integer;
var
  rv, astrlen : integer;

  astr : PByte;
begin
    rv := 0;
    if (nil =a.data)  or  (0>=a.length) then Exit(0);
    if cmp_type > 0 then
    begin
        if cmp_type <> a.&type then
            Exit(0);
        if cmp_type = V_ASN1_IA5STRING then
           rv := equal(a.data, a.length, PByte(b), blen, flags)
        else
        if (a.length = int(blen))  and  (0>=memcmp(a.data, b, blen)) then
            rv := 1;
        if (rv > 0)  and  (peername <> nil) then
           OPENSSL_strndup(peername^, PUTF8Char( a.data), a.length);
    end
    else
    begin
        astrlen := ASN1_STRING_to_UTF8(@astr, a);
        if astrlen < 0 then
        begin
            {
             * -1 could be an internal malloc failure or a decoding error from
             }
            Exit(-1);
        end;
        rv := equal(astr, astrlen, PByte(b), blen, flags);
        if (rv > 0)  and  (peername <> nil) then
           OPENSSL_strndup(peername^, PUTF8Char( astr), astrlen);
        OPENSSL_free(astr);
    end;
    Result := rv;
end;

function wildcard_match(const prefix : PByte; prefix_len : size_t;const suffix : PByte; suffix_len : size_t;const subject : PByte; subject_len : size_t; flags : uint32):integer;
var
  wildcard_start,
  wildcard_end,
  p              : PByte;

  allow_multi,
  allow_idna     : integer;
begin
    allow_multi := 0;
    allow_idna := 0;
    if subject_len < prefix_len + suffix_len then
       Exit(0);
    if 0>=equal_nocase(prefix, prefix_len, subject, prefix_len, flags) then
        Exit(0);
    wildcard_start := subject + prefix_len;
    wildcard_end := subject + (subject_len - suffix_len);
    if 0>=equal_nocase(wildcard_end, suffix_len, suffix, suffix_len, flags) then
        Exit(0);
    {
     * If the wildcard makes up the entire first label, it must match at
     * least one character.
     }
    if (prefix_len = 0)  and  (suffix^ = Ord('.')) then
    begin
        if wildcard_start = wildcard_end then
            Exit(0);
        allow_idna := 1;
        if flags and X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS > 0 then
           allow_multi := 1;
    end;
    { IDNA labels cannot match partial wildcards }
    if (0>=allow_idna)  and
       (subject_len >= 4)  and  (HAS_CASE_PREFIX(PUTF8Char(subject), 'xn--')) then
        Exit(0);
    { The wildcard may match a literal '*' }
    if (wildcard_end = wildcard_start + 1)  and  (wildcard_start^ = Ord('*')) then
       Exit(1);
    {
     * Check that the part matched by the wildcard contains only
     * permitted characters and only matches a single label unless
     * allow_multi is set.
     }
    p := wildcard_start;
    while p <> wildcard_end do
    begin
        if not ( ( (Ord('0') <= p^)  and  (p^ <= Ord('9')) )  or
                 ( (Ord('A') <= p^)  and  (p^ <= Ord('Z')) )  or
                 ( (Ord('a') <= p^)  and  (p^ <= Ord('z')) )  or
                 (p^ = Ord('-'))  or  ( (allow_multi > 0)  and  (p^ = Ord('.')) ) ) then
            Exit(0);
        Inc(p);
    end;
    Result := 1;
end;


function valid_star(const p : PByte; len : size_t; flags : uint32):PByte;
var
  star : PByte;
  i : size_t;
  state, dots, atstart, atend : integer;
begin
    star := 0;
    state := LABEL_START;
    dots := 0;
    for i := 0 to len-1 do
    begin
        {
         * Locate first and only legal wildcard, either at the start
         * or end of a non-IDNA first and not final label.
         }
        if p[i] = Ord('*') then
        begin
            atstart := (state and LABEL_START);
            atend := int( (i = len - 1)  or  (p[i + 1] = Ord('.')));
            {-
             * At most one wildcard per pattern.
             * No wildcards in IDNA labels.
             * No wildcards after the first label.
             }
            if (star <> nil)  or  (state and LABEL_IDNA  <> 0)  or  (dots > 0) then
                Exit(nil);
            { Only full-label '*.example.com' wildcards? }
            if (flags and X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS > 0)  and
               ( (0>=atstart)  or  (0>=atend) ) then
                Exit(nil);
            { No 'foo*bar' wildcards }
            if (0 >= atstart)  and  (0 >= atend) then
               Exit(nil);
            star := @p[i];
            state := state and not LABEL_START;
        end
        else
        if ( (Ord('a') <= p[i])  and  (p[i] <= Ord('z')) )
                    or  ( (Ord('A') <= p[i])  and  (p[i] <= Ord('Z')) )
                    or  ( (Ord('0') <= p[i])  and  (p[i] <= Ord('9')) ) then
        begin
            if (state and LABEL_START  <> 0)
                 and  (len - i >= 4)  and  (HAS_CASE_PREFIX(PUTF8Char(@p[i]), 'xn--')) then
                state  := state  or LABEL_IDNA;
            state := state and not (LABEL_HYPHEN or LABEL_START);
        end
        else if (p[i] = Ord('.')) then
        begin
            if state and (LABEL_HYPHEN or LABEL_START ) <> 0 then
                Exit(nil);
            state := LABEL_START;
            PreInc(dots);
        end
        else if (p[i] = Ord('-')) then
        begin
            { no domain/subdomain starts with '-' }
            if state and LABEL_START <> 0 then
                Exit(nil);
            state  := state  or LABEL_HYPHEN;
        end
        else
        begin
            Exit(nil);
        end;
    end;
    {
     * The final label must not end in a hyphen or '.', and
     * there must be at least two dots after the star.
     }
    if (state and (LABEL_START or LABEL_HYPHEN ) <> 0)  or  (dots < 2) then
        Exit(nil);
    Result := star;
end;




function equal_wildcard({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;
var
  star : PByte;
begin
    star := nil;
    {
     * Subject names starting with '.' can only match a wildcard pattern
     * via a subject sub-domain pattern suffix match.
     }
    if not ( (subject_len > 1)  and  (subject[0] = Ord('.')) ) then
        star := valid_star(pattern, pattern_len, flags);
    if star = nil then
       Exit(equal_nocase(pattern, pattern_len, subject, subject_len, flags));
    Exit(wildcard_match(pattern, star - pattern,
                          star + 1, (pattern + pattern_len) - star - 1,
                          subject, subject_len, flags));
end;



function equal_case({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;
begin
    skip_prefix(@pattern, @pattern_len, subject_len, flags);
    if pattern_len <> subject_len then Exit(0);
    Result :=  not memcmp(pattern, subject, pattern_len);
end;



procedure skip_prefix(const p : PPByte; plen : Psize_t; subject_len : size_t; flags : uint32);
var
    pattern     : PByte;
    pattern_len : size_t;
begin
     pattern := p^;
     pattern_len := plen^;
    {
     * If subject starts with a leading '.' followed by more octets, and
     * pattern is longer, compare just an equal-length suffix with the
     * full subject (starting at the '.'), provided the prefix contains
     * no NULs.
     }
    if (flags and _X509_CHECK_FLAG_DOT_SUBDOMAINS ) = 0 then
        exit;
    while (pattern_len > subject_len)  and  (pattern^ > 0) do
    begin
        if (flags and X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS > 0) and
           (pattern^ = Ord('.')) then
            break;
        Inc(pattern);
        Dec(pattern_len);
    end;
    { Skip if entire prefix acceptable }
    if pattern_len = subject_len then
    begin
        p^ := pattern;
        plen^ := pattern_len;
    end;
end;

function equal_nocase({const} pattern : PByte; pattern_len : size_t;{const} subject : PByte; subject_len : size_t; flags : uint32):integer;
var
  l, r : Byte;
begin
    skip_prefix(@pattern, @pattern_len, subject_len, flags);
    if pattern_len <> subject_len then Exit(0);
    while pattern_len <> 0 do
    begin
        l := pattern^;
        r := subject^;
        { The pattern must not contain NUL characters. }
        if l = 0 then Exit(0);
        if l <> r then begin
            if (Ord('A') <= l)  and  (l <= Ord('Z')) then
                l := (l - Ord('A')) + Ord('a');
            if (Ord('A') <= r)  and  (r <= Ord('Z')) then
               r := (r - Ord('A')) + Ord('a');
            if l <> r then Exit(0);
        end;
        Inc(pattern);
        Inc(subject);
        Dec(pattern_len);
    end;
    Result := 1;
end;


function equal_email({const} a : PByte; a_len : size_t;{const} b : PByte; b_len : size_t; unused_flags : uint32):integer;
var
  i : size_t;
begin
    i := a_len;
    if a_len <> b_len then Exit(0);
    {
     * We search backwards for the '@' character, so that we do not have to
     * deal with quoted local-parts.  The domain part is compared in a
     * case-insensitive manner.
     }
    while i > 0 do  begin
        Dec(i);
        if (a[i] = Ord('@'))  or  (b[i] = Ord('@')) then
        begin
            if 0>=equal_nocase(a + i, a_len - i, b + i, a_len - i, 0) then
                Exit(0);
            break;
        end;
    end;
    if i = 0 then i := a_len;
    Result := equal_case(a, i, b, i, 0);
end;





function do_x509_check(x : PX509;const chk : PUTF8Char; chklen : size_t; flags : uint32; check_type : integer; peername : PPUTF8Char):integer;
var
  gens        : PGENERAL_NAMES;
  name        : PX509_NAME;
  i,
  cnid,
  alt_type,
  san_present,
  rv          : integer;
  equal       : Tequal_fn;
  gen         : PGENERAL_NAME;
  cstr        : PASN1_STRING;
  ne          : PX509_NAME_ENTRY;
  str         : PASN1_STRING;
  function get_i: Int;
  begin
     i := X509_NAME_get_index_by_NID(name, cnid, i);
     Result := i;
  end;
begin
    gens := nil;
    name := nil;
    cnid := NID_undef;
    san_present := 0;
    rv := 0;
    { See below, this flag is internal-only }
    flags := flags and  not _X509_CHECK_FLAG_DOT_SUBDOMAINS;
    if check_type = GEN_EMAIL then
    begin
        cnid := NID_pkcs9_emailAddress;
        alt_type := V_ASN1_IA5STRING;
        equal := equal_email;
    end
    else
    if (check_type = GEN_DNS) then
    begin
        cnid := NID_commonName;
        { Implicit client-side DNS sub-domain pattern }
        if (chklen > 1)  and  (chk[0] = '.') then
           flags  := flags  or _X509_CHECK_FLAG_DOT_SUBDOMAINS;
        alt_type := V_ASN1_IA5STRING;
        if flags and X509_CHECK_FLAG_NO_WILDCARDS > 0 then
           equal := equal_nocase
        else
           equal := equal_wildcard;
    end
    else
    begin
        alt_type := V_ASN1_OCTET_STRING;
        equal := equal_case;
    end;
    if chklen = 0 then
       chklen := Length(chk);
    gens := X509_get_ext_d2i(x, NID_subject_alt_name, nil, nil);
    if gens <> nil then
    begin
        for i := 0 to sk_GENERAL_NAME_num(gens)-1 do
        begin
            gen := sk_GENERAL_NAME_value(gens, i);
            if (gen.&type = GEN_OTHERNAME)  and  (check_type = GEN_EMAIL) then
            begin
                if OBJ_obj2nid(gen.d.otherName.type_id)  =  NID_id_on_SmtpUTF8Mailbox  then
                begin
                    san_present := 1;
                    {
                     * If it is not a UTF8String then that is unexpected and we
                     * treat it as no match
                     }
                    if gen.d.otherName.value._type = V_ASN1_UTF8STRING then
                    begin
                        cstr := gen.d.otherName.value.value.utf8string;
                        { Positive on success, negative on error! }
                        rv := do_check_string(cstr, 0, equal, flags,
                                                chk, chklen, peername);
                        if (rv <> 0) then
                            break;
                    end;
                end
                else
                    continue;
            end
            else
            begin
                if (gen.&type <> check_type)  and  (gen.&type <> GEN_OTHERNAME) then
                    continue;
            end;
            san_present := 1;
            if check_type = GEN_EMAIL then
               cstr := gen.d.rfc822Name
            else
            if (check_type = GEN_DNS) then
                cstr := gen.d.dNSName
            else
                cstr := gen.d.iPAddress;
            { Positive on success, negative on error! }
            rv := do_check_string(cstr, alt_type, equal, flags,
                                      chk, chklen, peername );
            if (rv <> 0) then
                break;
        end;
        GENERAL_NAMES_free(gens);
        if rv <> 0 then Exit(rv);
        if (san_present > 0)  and  (0>=(flags and X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) ) then
            Exit(0);
    end;
    { We're done if CN-ID is not pertinent }
    if (cnid = NID_undef)  or  (flags and X509_CHECK_FLAG_NEVER_CHECK_SUBJECT > 0) then
        Exit(0);
    i := -1;
    name := X509_get_subject_name(x);
    while get_i >= 0 do
    begin
         ne := X509_NAME_get_entry(name, i);
         str := X509_NAME_ENTRY_get_data(ne);
        { Positive on success, negative on error! }
        rv := do_check_string(str, -1, equal, flags, chk, chklen, peername );
        if (rv <> 0) then
            Exit(rv);
    end;
    Result := 0;
end;





function X509_check_host(x : PX509;const chk : PUTF8Char; chklen : size_t; flags : uint32; peername : PPUTF8Char):integer;
begin
    if chk = nil then Exit(-2);
    {
     * Embedded NULs are disallowed, except as the last character of a
     * string of length 2 or more (tolerate caller including terminating
     * NUL in string length).
     }
    if chklen = 0 then
       chklen := Length(chk)
    else
    if memchr(chk, #0, get_result(chklen > 1 , chklen - 1 , chklen)) <> nil then
        Exit(-2);
    if (chklen > 1)  and  (chk[chklen - 1] = #0) then
       Dec(chklen);
    Result := do_x509_check(x, chk, chklen, flags, GEN_DNS, peername);
end;





function i2s_ASN1_ENUMERATED(method : PX509V3_EXT_METHOD;const a : PASN1_ENUMERATED):PUTF8Char;
var
  bntmp : PBIGNUM;
  strtmp : PUTF8Char;
begin
    bntmp := nil;
    strtmp := nil;
    if nil = a then Exit(nil);
    bntmp := ASN1_ENUMERATED_to_BN(a, nil);
    strtmp := bignum_to_string(bntmp);

    if (bntmp = nil) or  (strtmp = nil) then
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    BN_free(bntmp);
    Result := strtmp;
end;

function X509V3_add_value_int(const name : PUTF8Char; aint : PASN1_INTEGER; extlist : PPstack_st_CONF_VALUE):integer;
var
  strtmp : PUTF8Char;

  ret : integer;
begin
    if nil = aint then Exit(1);
    strtmp := i2s_ASN1_INTEGER(nil, aint);
    if strtmp = nil then
        Exit(0);
    ret := X509V3_add_value(name, strtmp, extlist);
    OPENSSL_free(strtmp);
    Result := ret;
end;




function X509V3_add_value_bool(const name : PUTF8Char; asn1_bool : integer; extlist : PPstack_st_CONF_VALUE):integer;
begin
    if asn1_bool > 0 then
       Exit(X509V3_add_value(name, 'TRUE', extlist));
    Result := X509V3_add_value(name, 'FALSE', extlist);
end;



function X509V3_get_value_int(const value : PCONF_VALUE; aint : PPASN1_INTEGER):integer;
var
  itmp : PASN1_INTEGER;
begin
    itmp := s2i_ASN1_INTEGER(nil, value.value);
    if itmp = nil then
    begin
        X509V3_conf_add_error_name_value(value);
        Exit(0);
    end;
    aint^ := itmp;
    Result := 1;
end;

function x509v3_add_len_value_uchar(const name : PUTF8Char; value : PByte; vallen : size_t; extlist : PPstack_st_CONF_VALUE):integer;
begin
    Result := x509v3_add_len_value(name, PUTF8Char(value), vallen, extlist);
end;

function bignum_to_string(const bn : PBIGNUM):PUTF8Char;
var
  tmp, ret : PUTF8Char;

  len : size_t;
begin
    {
     * Display large numbers in hex and small numbers in decimal. Converting to
     * decimal takes quadratic time and is no more useful than hex for large
     * numbers.
     }
    if BN_num_bits(bn) < 128  then
        Exit(BN_bn2dec(bn));
    tmp := BN_bn2hex(bn);
    if tmp = nil then Exit(nil);
    len := Length(tmp) + 3;
    ret := OPENSSL_malloc(len);
    if ret = nil then begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(tmp);
        Exit(nil);
    end;
    { Prepend '0x", but place it after the "-' if negative. }
    if tmp[0] = '-' then
    begin
        OPENSSL_strlcpy(ret, '-0x', len);
        OPENSSL_strlcat(ret, tmp + 1, len);
    end
    else
    begin
        OPENSSL_strlcpy(ret, '0x', len);
        OPENSSL_strlcat(ret, tmp, len);
    end;
    OPENSSL_free(tmp);
    Result := ret;
end;



function i2s_ASN1_INTEGER(method : PX509V3_EXT_METHOD;const a : PASN1_INTEGER):PUTF8Char;
var
  bntmp : PBIGNUM;
  strtmp : PUTF8Char;
begin
    bntmp := nil;
    strtmp := nil;
    if nil = a then Exit(nil);
    bntmp := ASN1_INTEGER_to_BN(a, nil);
    strtmp := bignum_to_string(bntmp);
    if (bntmp = nil) or  (strtmp  = nil) then
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    BN_free(bntmp);
    Result := strtmp;
end;



function ossl_ipaddr_to_asc( p : PByte; len : integer):PUTF8Char;
var
    buf      : array[0..39] of UTF8Char;
    _out     : PUTF8Char;
    i, remain, bytes: integer;

    template : PUTF8Char;
begin
    {
     * 40 is enough space for the longest IPv6 address + nul terminator byte
     * XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX\0
     }

    i := 0; remain := 0; bytes := 0;
    case len of
        4:  { IPv4 }
            BIO_snprintf(buf, sizeof(buf), '%d.%d.%d.%d', [p[0], p[1], p[2], p[3]]);
            //break;
        16:  { IPv6 }
        begin
            _out := buf; i := 8; remain := sizeof(buf);
            while (PostDec(i) > 0)  and  (bytes >= 0) do
            begin
                if i > 0  then
                   template := '%X:'
                else
                   template := '%X';
                bytes := BIO_snprintf(_out, remain, template, [p[0]  shl  8 or p[1]]);
                p  := p + 2;
                remain := remain - bytes;
                _out := _out + bytes;
            end;
        end;
        else
            BIO_snprintf(buf, sizeof(buf), '<invalid length=%d>', [len]);
            //break;
    end;
    OPENSSL_strdup(Result ,buf);
end;



function X509V3_NAME_from_section( nm : PX509_NAME; dn_sk : Pstack_st_CONF_VALUE; chtype : Cardinal):integer;
var
  v         : PCONF_VALUE;
  i,
  mval,
  spec_char,
  plus_char : integer;
  p,
  _type     : PUTF8Char;
begin
    if nil = nm then Exit(0);
    for i := 0 to sk_CONF_VALUE_num(dn_sk)-1 do
    begin
        v := sk_CONF_VALUE_value(dn_sk, i);
        _type := v.name;
        {
         * Skip past any leading X. X: X, etc to allow for multiple instances
         }
        p := _type;
        while p^ <> #0 do
        begin
{$IFNDEF CHARSET_EBCDIC}
            spec_char := int(( p^ = ':')  or  ( p^ = ',')  or  ( p^ = '.'));
{$ELSE}
            spec_char = (( *p = os_toascii[':'])  or  ( *p = os_toascii[','])
                          or  ( *p = os_toascii['.']));
{$ENDIF}
            if spec_char > 0 then
            begin
                Inc(p);
                if p^ <> #0 then
                   _type := p;
                break;
            end;
            Inc(p);
        end;
{$IFNDEF CHARSET_EBCDIC}
        plus_char := int( _type^ = '+');
{$ELSE}
        plus_char = ( *_type = os_toascii['+']);
{$ENDIF}
        if plus_char > 0 then
        begin
            mval := -1;
            Inc(_type);
        end
        else
        begin
            mval := 0;
        end;
        if 0>= X509_NAME_add_entry_by_txt(nm, _type, chtype,
                                        PByte( v.value), -1, -1,
                                        mval) then
            Exit(0);
    end;
    Result := 1;
end;




function s2i_ASN1_INTEGER(method : PX509V3_EXT_METHOD; value : PUTF8Char):PASN1_INTEGER;
var
  bn : PBIGNUM;
  aint : PASN1_INTEGER;
  isneg, ishex, ret : integer;
begin
    bn := nil;
    if value = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_VALUE);
        Exit(nil);
    end;
    bn := BN_new();
    if bn = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if value[0] = '-' then
    begin
        Inc(value);
        isneg := 1;
    end
    else
    begin
        isneg := 0;
    end;
    if (value[0] = '0')  and  ((value[1] = 'x')  or  (value[1] = 'X'))  then
    begin
        value  := value + 2;
        ishex := 1;
    end
    else
    begin
        ishex := 0;
    end;
    if ishex > 0 then
       ret := BN_hex2bn(@bn, value)
    else
        ret := BN_dec2bn(@bn, value);
    if (0>= ret)  or  (value[ret] <> #0) then
    begin
        BN_free(bn);
        ERR_raise(ERR_LIB_X509V3, X509V3_R_BN_DEC2BN_ERROR);
        Exit(nil);
    end;
    if (isneg > 0)  and  (BN_is_zero(bn)) then
        isneg := 0;
    aint := BN_to_ASN1_INTEGER(bn, nil);
    BN_free(bn);
    if nil = aint then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_BN_TO_ASN1_INTEGER_ERROR);
        Exit(nil);
    end;
    if isneg > 0 then
       aint.&type  := aint.&type  or V_ASN1_NEG;
    Result := aint;
end;




function X509V3_get_value_bool(const value : PCONF_VALUE; asn1_bool : PInteger):integer;
var
  btmp : PUTF8Char;
  label _err;
begin
    btmp := value.value;
    if btmp =  nil then
        goto _err ;
    if (strcmp(btmp, 'TRUE') = 0)
         or  (strcmp(btmp, 'true') = 0)
         or  (strcmp(btmp, 'Y') = 0)
         or  (strcmp(btmp, 'y') = 0 )
         or  (strcmp(btmp, 'YES') = 0)
         or  (strcmp(btmp, 'yes') = 0) then
    begin
        asn1_bool^ := $ff;
        Exit(1);
    end;
    if (strcmp(btmp, 'FALSE') = 0)
         or  (strcmp(btmp, 'false') = 0)
         or  (strcmp(btmp, 'N') = 0)
         or  (strcmp(btmp, 'n') = 0)
         or  (strcmp(btmp, 'NO') = 0)
         or  (strcmp(btmp, 'no') = 0)  then
    begin
        asn1_bool^ := 0;
        Exit(1);
    end;
 _err:
    ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_BOOLEAN_STRING);
    X509V3_conf_add_error_name_value(value);
    Result := 0;
end;


function a2i_IPADDRESS(const ipasc : PUTF8Char):PASN1_OCTET_STRING;
var
  ipout : array[0..15] of Byte;

  ret : PASN1_OCTET_STRING;

  iplen : integer;
begin
    { If string contains a ':' assume IPv6 }
    iplen := ossl_a2i_ipadd(@ipout, ipasc);
    if 0>= iplen then
       Exit(nil);
    ret := ASN1_OCTET_STRING_new();
    if ret = nil then
       Exit(nil);
    if 0>= ASN1_OCTET_STRING_set(ret, @ipout, iplen) then
    begin
        ASN1_OCTET_STRING_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;




function a2i_IPADDRESS_NC(const ipasc : PUTF8Char):PASN1_OCTET_STRING;
var
  ret : PASN1_OCTET_STRING;

  ipout : array[0..31] of Byte;

  iptmp, p : PUTF8Char;

  iplen1, iplen2 : integer;
  label _err;
begin
    ret := nil;
    iptmp := nil;
    p := strchr(ipasc, '/');
    if p = nil then Exit(nil);
     OPENSSL_strdup(iptmp ,ipasc);
    if iptmp = nil then Exit(nil);
    p := iptmp + (p - ipasc);
    PostInc(p)^ :=  Chr(0);
    iplen1 := ossl_a2i_ipadd(@ipout, iptmp);
    if 0>= iplen1 then
       goto _err ;
    iplen2 := ossl_a2i_ipadd(PByte(@ipout) + iplen1, p);
    OPENSSL_free(iptmp);
    iptmp := nil;
    if (0>= iplen2)  or  (iplen1 <> iplen2) then
        goto _err ;
    ret := ASN1_OCTET_STRING_new();
    if ret = nil then goto _err ;
    if 0>= ASN1_OCTET_STRING_set(ret, @ipout, iplen1 + iplen2) then
        goto _err ;
    Exit(ret);
 _err:
    OPENSSL_free(iptmp);
    ASN1_OCTET_STRING_free(ret);
    Result := nil;
end;

procedure X509V3_conf_free( conf : Pointer);
begin
    if nil = conf then
       exit;
    OPENSSL_free(PCONF_VALUE(conf).name);
    OPENSSL_free(PCONF_VALUE(conf).value);
    OPENSSL_free(PCONF_VALUE(conf).section);
    OPENSSL_free(conf);
end;




function x509v3_add_len_value(const name, value : PUTF8Char; vallen : size_t; extlist : PPstack_st_CONF_VALUE):integer;
var
  vtmp         : PCONF_VALUE;
  tname,
  tvalue       : PUTF8Char;
  sk_allocated : integer;
  label _err;
begin
    vtmp := nil;
    tname := nil;
    tvalue := nil;
    sk_allocated := int( extlist^ = nil);
    OPENSSL_strdup(tname ,name);
    if (name <> nil)  and  (tname = nil) then
        goto _err ;
    if value <> nil then
    begin
        { We don't allow embedded NUL characters }
        if memchr(value, Chr(0), vallen) <> nil then
            goto _err ;
        OPENSSL_strndup(tvalue, value, vallen);
        if tvalue = nil then
           goto _err ;
    end;
    vtmp := OPENSSL_malloc(sizeof(vtmp^));
    if vtmp = nil then
        goto _err ;
    extlist^ := sk_CONF_VALUE_new_null();
    if (sk_allocated>0)  and  (extlist^ = nil) then
        goto _err ;
    vtmp.section := nil;
    vtmp.name := tname;
    vtmp.value := tvalue;
    if 0>= sk_CONF_VALUE_push(extlist^, vtmp) then
        goto _err ;
    Exit(1);
 _err:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    if sk_allocated > 0 then
    begin
        sk_CONF_VALUE_free( extlist^);
        extlist^ := nil;
    end;
    OPENSSL_free(vtmp);
    OPENSSL_free(tname);
    OPENSSL_free(tvalue);
    Result := 0;
end;




function X509V3_add_value(const name, value : PUTF8Char; extlist : PPstack_st_CONF_VALUE):integer;
begin
    Result := x509v3_add_len_value(name, value,
                          get_result(value <> nil , Length(PUTF8Char(value)) , 0),
                                extlist);
end;

function strip_spaces( name : PUTF8Char):PUTF8Char;
var
  p, q : PUTF8Char;
begin
    { Skip over leading spaces }
    p := name;
    while (p^ <> #0)  and  (ossl_isspace(p^)) do
        Inc(p);
    if p^ = #0 then
       Exit(nil);
    q := p + Length(p) - 1;
    while (q <> p)  and  (ossl_isspace(q^)) do
        Dec(q);
    if p <> q then
       q[1] := Chr(0);
    if p^ = #0 then
       Exit(nil);
    Result := p;
end;




function X509V3_parse_list(const line : PUTF8Char):Pstack_st_CONF_VALUE;
var
  p, q : PUTF8Char;
  c : UTF8Char;
  ntmp, vtmp : PUTF8Char;
  values : Pstack_st_CONF_VALUE;
  linebuf : PUTF8Char;
  state : integer;
  label _err;
begin
    values := nil;
    { We are going to modify the line so copy it first }
    OPENSSL_strdup(linebuf ,line);
    if linebuf = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    state := HDR_NAME;
    ntmp := nil;
    { Go through all characters }
    p := linebuf; q := linebuf;
    while (c = p^)  and  (c <> #13{'\r'})  and  (c <> #10{'\n'}) do
    begin
        case state of
        HDR_NAME:
        begin
            if c = ':' then
            begin
                state := HDR_VALUE;
                p^ := Chr(0);
                ntmp := strip_spaces(q);
                if nil = ntmp then
                begin
                    ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_EMPTY_NAME);
                    goto _err ;
                end;
                q := p + 1;
            end
            else
            if (c = ',') then
            begin
                p^ := Chr(0);
                ntmp := strip_spaces(q);
                q := p + 1;
                if nil = ntmp then
                begin
                    ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_EMPTY_NAME);
                    goto _err ;
                end;
                X509V3_add_value(ntmp, nil, @values);
            end;
        end;
        HDR_VALUE:
            if c = ',' then
            begin
                state := HDR_NAME;
                p^ := chr(0);
                vtmp := strip_spaces(q);
                if nil = vtmp then
                begin
                    ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_VALUE);
                    goto _err ;
                end;
                X509V3_add_value(ntmp, vtmp, &values);
                ntmp := nil;
                q := p + 1;
            end;
        end;
        Inc(p);
    end;

    if state = HDR_VALUE then
    begin
        vtmp := strip_spaces(q);
        if nil = vtmp then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_VALUE);
            goto _err ;
        end;
        X509V3_add_value(ntmp, vtmp, &values);
    end
    else
    begin
        ntmp := strip_spaces(q);
        if nil = ntmp then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_EMPTY_NAME);
            goto _err ;
        end;
        X509V3_add_value(ntmp, nil, @values);
    end;
    OPENSSL_free(linebuf);
    Exit(values);
 _err:
    OPENSSL_free(linebuf);
    sk_CONF_VALUE_pop_free(values, X509V3_conf_free);
    Exit(nil);
end;

function ipv6_hex(&out : PByte;&in : PUTF8Char; inlen : integer):integer;
var
  c : UTF8Char;

  num : uInt32;

  x : integer;
begin
    num := 0;
    if inlen > 4 then Exit(0);
    while (inlen>0) do
    begin
        c := &in^;
        Inc(&in);
        num  := num  shl 4;
        x := OPENSSL_hexChar2int(c);
        if x < 0 then Exit(0);
        num  := num  or Byte(x);
        Dec(inlen);
    end;
    &out[0] := num  shr  8;
    &out[1] := num and $ff;
    Result := 1;
end;

function ipv4_from_asc(v4 : PByte;&in : PUTF8Char):integer;
var
  p : PUTF8Char;

  a0, a1, a2, a3, n : integer;
begin
    if sscanf(&in, '%d.%d.%d.%d%n', [&a0, &a1, &a2, &a3, &n])<> 4   then
        Exit(0);
    if (a0 < 0 ) or  (a0 > 255)  or  (a1 < 0)  or  (a1 > 255)
         or  (a2 < 0)  or  (a2 > 255)  or  (a3 < 0)  or  (a3 > 255) then
        Exit(0);
    p := &in + n;
    if  not ( (p^ = #0)  or  (ossl_isspace(p^)) ) then
        Exit(0);
    v4[0] := a0;
    v4[1] := a1;
    v4[2] := a2;
    v4[3] := a3;
    Result := 1;
end;


function ipv6_cb(const elem : PUTF8Char; len : integer; usr : Pointer):integer;
var
  s : PIPV6_STAT;
begin
    s := usr;
    { Error if 16 bytes written }
    if s.total = 16 then Exit(0);
    if len = 0 then
    begin
        { Zero length element, corresponds to '.' }
        if s.zero_pos = -1 then
            s.zero_pos := s.total
        { If we've already got a . its an error }
        else
        if (s.zero_pos <> s.total) then
            Exit(0);
        Inc(s.zero_cnt);
    end
    else
    begin
        { If more than 4 Char acters could be final a.b.c.d form }
        if len > 4 then
        begin
            { Need at least 4 bytes left }
            if s.total > 12 then
                Exit(0);
            { Must be end of string }
            if elem[len] <> #0 then Exit(0);

            if  0>= ipv4_from_asc(PByte(@s.tmp) + s.total, elem  ) then
                Exit(0);
            s.total  := s.total + 4;
        end
        else
        begin
            if 0>= ipv6_hex(PByte(@s.tmp) + s.total, elem, len) then
                Exit(0);
            s.total  := s.total + 2;
        end;
    end;
    Result := 1;
end;



function ipv6_from_asc(v6 : PByte;const &in : PUTF8Char):integer;
var
  v6stat : IPV6_STAT;
begin
    v6stat.total := 0;
    v6stat.zero_pos := -1;
    v6stat.zero_cnt := 0;
    {
     * Treat the IPv6 representation as a list of values separated by ':'.
     * The presence of a '.' will parse as one, two or three zero length
     * elements.
     }
    if  0>= CONF_parse_list(&in, Ord(':'), 0, ipv6_cb, @v6stat) then
        Exit(0);
    { Now for some sanity checks }
    if v6stat.zero_pos = -1 then
    begin
        { If no '.' must have exactly 16 bytes }
        if v6stat.total <> 16 then
            Exit(0);
    end
    else
    begin
        { If '.' must have less than 16 bytes }
        if v6stat.total = 16 then Exit(0);
        { More than three zeroes is an error }
        if v6stat.zero_cnt > 3 then
        begin
            Exit(0);
        { Can only have three zeroes if nothing else present }
        end
        else
        if (v6stat.zero_cnt = 3) then
        begin
            if v6stat.total > 0 then Exit(0);
        end
        else
        if (v6stat.zero_cnt = 2) then
        begin
            { Can only have two zeroes if at start or end }
            if (v6stat.zero_pos <> 0 )  and  (v6stat.zero_pos <> v6stat.total) then
                Exit(0);
        end
        else
        begin
            { Can only have one zero if *not* start or end }
            if (v6stat.zero_pos = 0 ) or  (v6stat.zero_pos = v6stat.total) then
                Exit(0);
        end;
    end;
    { Format result }
    if v6stat.zero_pos >= 0 then
    begin
        { Copy initial part }
        memcpy(v6, @v6stat.tmp, v6stat.zero_pos);
        { Zero middle }
        memset(v6 + v6stat.zero_pos, 0, 16 - v6stat.total);
        { Copy final part }
        if v6stat.total <> v6stat.zero_pos then
            memcpy(v6 + v6stat.zero_pos + 16 - v6stat.total,
                   PByte(@v6stat.tmp) + v6stat.zero_pos,
                   v6stat.total - v6stat.zero_pos);
    end
    else
    begin
        memcpy(v6, @v6stat.tmp, 16);
    end;
    Result := 1;
end;



function ossl_a2i_ipadd(ipout : PByte;const ipasc : PUTF8Char):integer;
begin

    if strchr(ipasc, ':' ) <> nil then
    begin
        if  0>= ipv6_from_asc(ipout, ipasc) then
            Exit(0);
        Exit(16);
    end
    else
    begin
        if  0>= ipv4_from_asc(ipout, ipasc) then
            Exit(0);
        Exit(4);
    end;
end;



function ossl_v3_name_cmp(const name, cmp : PUTF8Char):integer;
var
  len, ret : integer;

  c : UTF8Char;
begin
    len := Length(cmp);
    ret := strncmp(name, cmp, len);
    if  ret > 0  then
        Exit(ret);
    c := name[len];
    if (0>= Ord(c) )  or  (c = '.')  then
        Exit(0);
    Result := 1;
end;


end.
