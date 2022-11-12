unit OpenSSL3.crypto.x509.v3_ncons;

interface
uses OpenSSL.Api;

function NAME_CONSTRAINTS_it:PASN1_ITEM;
function v2i_NAME_CONSTRAINTS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
function i2r_NAME_CONSTRAINTS(const method : PX509V3_EXT_METHOD; a : Pointer; bp : PBIO; ind : integer):integer;
function NAME_CONSTRAINTS_new:PNAME_CONSTRAINTS;
procedure NAME_CONSTRAINTS_free( a : PNAME_CONSTRAINTS);
function GENERAL_SUBTREE_new: PGENERAL_SUBTREE;
  procedure GENERAL_SUBTREE_free( a : PGENERAL_SUBTREE);
 function GENERAL_SUBTREE_it:PASN1_ITEM;
 function do_i2r_name_constraints(const method : PX509V3_EXT_METHOD; trees : Pstack_st_GENERAL_SUBTREE; bp : PBIO; ind : integer;const name : PUTF8Char):integer;
 function print_nc_ipadd( bp : PBIO; ip : PASN1_OCTET_STRING):integer;
 function NAME_CONSTRAINTS_check( x : PX509; nc : PNAME_CONSTRAINTS):integer;
 function add_lengths( _out : PInteger; a, b : integer):integer;
  function nc_match( gen : PGENERAL_NAME; nc : PNAME_CONSTRAINTS):integer;
  function nc_minmax_valid( sub : PGENERAL_SUBTREE):integer;
  function nc_match_single( gen, base : PGENERAL_NAME):integer;
  function nc_email_eai( emltype : PASN1_TYPE; base : PASN1_IA5STRING):integer;
  function ia5memrchr( str : PASN1_IA5STRING; c : integer):PUTF8Char;
  function ia5ncasecmp({const} s1, s2 : PUTF8Char; n : size_t):integer;
  function IA5_OFFSET_LEN(ia5base: PASN1_IA5STRING; const offset: PUTF8Char) :size_t;
  function safe_add_int( a, b : integer; err : PInteger):integer;
  function nc_dn(const nm, base : PX509_NAME):integer;
  function nc_dns( dns, base : PASN1_IA5STRING):integer;
  function nc_email( eml, base : PASN1_IA5STRING):integer;
  function nc_uri( uri, base : PASN1_IA5STRING):integer;
  function nc_ip( ip, base : PASN1_OCTET_STRING):integer;
  function  ia5memchr(str: PASN1_IA5STRING; start: PUTF8Char; c: UTF8Char): Pointer;
  function NAME_CONSTRAINTS_check_CN( x : PX509; nc : PNAME_CONSTRAINTS):integer;

var
   ossl_v3_name_constraints: TX509V3_EXT_METHOD;
   NAME_CONSTRAINTS_seq_tt, GENERAL_SUBTREE_seq_tt :array of TASN1_TEMPLATE;


implementation
uses OpenSSL3.openssl.conf, openssl3.crypto.x509v3, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_san, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.o_str,
     openssl3.crypto.x509.v3_genn,  OpenSSL3.common,
     OpenSSL3.crypto.x509.x_name,  openssl3.crypto.asn1.a_strex,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.punycode,
     OpenSSL3.crypto.x509.x509name,  openssl3.crypto.asn1.a_int,
     openssl3.crypto.bio.bio_lib,  OpenSSL3.crypto.x509.x509_cmp,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print, OpenSSL3.Err;

const
  NAME_CHECK_MAX = (1 shl 20);


function cn2dnsid( cn : PASN1_STRING; dnsid : PPByte; idlen : Psize_t):integer;
var
    utf8_length : integer;
    utf8_value  : PByte;
    i,
    isdnsname   : integer;
    c           : Byte;
begin
    isdnsname := 0;
    { Don't leave outputs uninitialized }
    dnsid^ := nil;
    idlen^ := 0;
    {-
     * Per RFC 6125, DNS-IDs representing internationalized domain names appear
     * in certificates in A-label encoded form:
     *
     *   https://tools.ietf.org/html/rfc6125#section-6.4.2
     *
     * The same applies to CNs which are intended to represent DNS names.
     * However, while in the SAN DNS-IDs are IA5Strings, as CNs they may be
     * needlessly encoded in 16-bit Unicode.  We perform a conversion to UTF-8
     * to ensure that we get an ASCII representation of any CNs that are
     * representable as ASCII, but just not encoded as ASCII.  The UTF-8 form
     * may contain some non-ASCII octets, and that's fine, such CNs are not
     * valid legacy DNS names.
     *
     * Note, 'int' is the return type of ASN1_STRING_to_UTF8 so that's what
     * we must use for 'utf8_length'.
     }
     utf8_length := ASN1_STRING_to_UTF8(@utf8_value, cn);
    if utf8_length < 0 then
        Exit(X509_V_ERR_OUT_OF_MEM);
    {
     * Some certificates have had names that include a *trailing* NUL byte.
     * Remove these harmless NUL characters. They would otherwise yield false
     * alarms with the following embedded NUL check.
     }
    while (utf8_length > 0)  and  (utf8_value[utf8_length - 1] = Ord(#0)) do
        Dec(utf8_length);
    { Reject *embedded* NULs }
    if memchr(utf8_value, 0, utf8_length) <> nil  then
    begin
        OPENSSL_free(utf8_value);
        Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    end;
    {
     * XXX: Deviation from strict DNS name syntax, also check names with '_'
     * Check DNS name syntax, any '-' or '.' must be internal,
     * and on either side of each '.' we can't have a '-' or '.'.
     *
     * If the name has just one label, we don't consider it a DNS name.  This
     * means that 'CN=sometld' cannot be precluded by DNS name constraints, but
     * that is not a problem.
     }
    for i := 0 to utf8_length-1 do
    begin
        c := utf8_value[i];
        if ( (c >= Ord('a'))  and  (c <= Ord('z')) )  or
           ( (c >= Ord('A'))  and  (c <= Ord('Z')) )  or
           ( (c >= Ord('0'))  and  (c <= Ord('9')) )  or  (c = Ord('_')) then
            continue;
        { Dot and hyphen cannot be first or last. }
        if (i > 0)  and  (i < utf8_length - 1) then
        begin
            if c = Ord('-') then
                continue;
            {
             * Next to a dot the preceding and following characters must not be
             * another dot or a hyphen.  Otherwise, record that the name is
             * plausible, since it has two or more labels.
             }
            if (c = Ord('.'))
                 and  (utf8_value[i + 1] <> Ord('.'))
                 and  (utf8_value[i - 1] <> Ord('-'))
                 and  (utf8_value[i + 1] <> Ord('-')) then
            begin
                isdnsname := 1;
                continue;
            end;
        end;
        isdnsname := 0;
        break;
    end;
    if isdnsname > 0 then
    begin
        dnsid^ := utf8_value;
        idlen^ := size_t(utf8_length);
        Exit(X509_V_OK);
    end;
    OPENSSL_free(utf8_value);
    Result := X509_V_OK;
end;

function NAME_CONSTRAINTS_check_CN( x : PX509; nc : PNAME_CONSTRAINTS):integer;
var
  r, i : integer;
  nm : PX509_NAME;
  stmp : TASN1_STRING;
  gntmp : TGENERAL_NAME;
  ne : PX509_NAME_ENTRY;
  cn : PASN1_STRING;
  idval : PByte;
  idlen : size_t;
begin
    nm := X509_get_subject_name(x);
    stmp.flags := 0;
    stmp.&type := V_ASN1_IA5STRING;
    gntmp.&type := GEN_DNS;
    gntmp.d.dNSName := @stmp;
    { Process any commonName attributes in subject name }
    i := -1;
    while True do
    begin
        i := X509_NAME_get_index_by_NID(nm, NID_commonName, i);
        if i = -1 then break;
        ne := X509_NAME_get_entry(nm, i);
        cn := X509_NAME_ENTRY_get_data(ne);
        { Only process attributes that look like host names }
        r := cn2dnsid(cn, @idval, @idlen);
        if r <> X509_V_OK then
            Exit(r);
        if idlen = 0 then continue;
        stmp.length := idlen;
        stmp.data := idval;
        r := nc_match(@gntmp, nc);
        OPENSSL_free(idval);
        if r <> X509_V_OK then Exit(r);
    end;
    Result := X509_V_OK;
end;

function  ia5memchr(str: PASN1_IA5STRING; start: PUTF8Char; c: UTF8Char): Pointer;
begin
  Result :=  memchr(start, c, IA5_OFFSET_LEN(str, start))
end;

function nc_email( eml, base : PASN1_IA5STRING):integer;
var
  baseptr,
  emlptr,
  baseat,
  emlat       : PUTF8Char;
  basehostlen,
  emlhostlen  : size_t;
begin
     baseptr := PUTF8Char( base.data);
     emlptr := PUTF8Char( eml.data);
     baseat := ia5memrchr(base, Ord('@'));
     emlat := ia5memrchr(eml, Ord('@'));
    if nil = emlat then
       Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    { Special case: initial '.' is RHS match }
    if (nil =baseat)  and  (base.length > 0)  and  ( baseptr^ = '.') then
    begin
        if eml.length > base.length then
        begin
            emlptr  := emlptr + (eml.length - base.length);
            if ia5ncasecmp(baseptr, emlptr, base.length) = 0  then
                Exit(X509_V_OK);
        end;
        Exit(X509_V_ERR_PERMITTED_VIOLATION);
    end;
    { If we have anything before '@' match local part }
    if baseat <> nil then
    begin
        if baseat <> baseptr then
        begin
            if (baseat - baseptr) <> (emlat - emlptr) then
                Exit(X509_V_ERR_PERMITTED_VIOLATION);
            if (memchr(baseptr, Chr(0), baseat - baseptr) <> nil)  or
               (memchr(emlptr, Chr(0), emlat - emlptr) <> nil) then
                Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
            { Case sensitive match of local part }
            if strncmp(baseptr, emlptr, emlat - emlptr) > 0 then
                Exit(X509_V_ERR_PERMITTED_VIOLATION);
        end;
        { Position base after '@' }
        baseptr := baseat + 1;
    end;
    emlptr := emlat + 1;
    basehostlen := IA5_OFFSET_LEN(base, baseptr);
    emlhostlen := IA5_OFFSET_LEN(eml, emlptr);
    { Just have hostname left to match: case insensitive }
    if (basehostlen <> emlhostlen)  or  (ia5ncasecmp(baseptr, emlptr, emlhostlen) > 0) then
        Exit(X509_V_ERR_PERMITTED_VIOLATION);
    Exit(X509_V_OK);
end;


function nc_uri( uri, base : PASN1_IA5STRING):integer;
var
  baseptr, hostptr, p : PUTF8Char;

  hostlen : integer;
begin
    baseptr := PUTF8Char( base.data);
    hostptr := PUTF8Char( uri.data);
    p := ia5memchr(uri, PUTF8Char( uri.data), ':');
    { Check for foo:// and skip past it }
    if (p = nil)
             or  (IA5_OFFSET_LEN(uri, p) < 3)
             or  (p[1] <> '/')
             or  (p[2] <> '/')  then
        Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    hostptr := p + 3;
    { Determine length of hostname part of URI }
    { Look for a port indicator as end of hostname first }
    p := ia5memchr(uri, hostptr, ':');
    { Otherwise look for trailing slash }
    if p = nil then
       p := ia5memchr(uri, hostptr, '/');
    if p = nil then
       hostlen := IA5_OFFSET_LEN(uri, hostptr)
    else
        hostlen := p - hostptr;
    if hostlen = 0 then Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    { Special case: initial '.' is RHS match }
    if (base.length > 0)  and  (baseptr^ = '.') then
    begin
        if hostlen > base.length then
        begin
            p := hostptr + hostlen - base.length;
            if ia5ncasecmp(p, baseptr, base.length) = 0  then
                Exit(X509_V_OK);
        end;
        Exit(X509_V_ERR_PERMITTED_VIOLATION);
    end;
    if (base.length <> int(hostlen)) or  (ia5ncasecmp(hostptr, baseptr, hostlen) > 0) then
        Exit(X509_V_ERR_PERMITTED_VIOLATION);
    Exit(X509_V_OK);
end;


function nc_ip( ip, base : PASN1_OCTET_STRING):integer;
var
  hostlen, baselen, i : integer;

  hostptr, baseptr, maskptr : PByte;
begin
    hostptr := ip.data;
    hostlen := ip.length;
    baseptr := base.data;
    baselen := base.length;
    { Invalid if not IPv4 or IPv6 }
    if not ( (hostlen = 4)  or  (hostlen = 16))  then
        Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    if not ( (baselen = 8)  or  (baselen = 32)) then
        Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    { Do not match IPv4 with IPv6 }
    if hostlen * 2 <> baselen then
       Exit(X509_V_ERR_PERMITTED_VIOLATION);
    maskptr := base.data + hostlen;
    { Considering possible not aligned base ipAddress }
    { Not checking for wrong mask definition: i.e.: 255.0.255.0 }
    for i := 0 to hostlen-1 do
        if (hostptr[i] and maskptr[i]) <> (baseptr[i] and maskptr[i]) then
            Exit(X509_V_ERR_PERMITTED_VIOLATION);
    Exit(X509_V_OK);
end;




function nc_dns( dns, base : PASN1_IA5STRING):integer;
var
  baseptr, dnsptr : PUTF8Char;
begin
    baseptr := PUTF8Char( base.data);
    dnsptr := PUTF8Char( dns.data);
    { Empty matches everything }
    if base.length = 0 then Exit(X509_V_OK);
    if dns.length < base.length then Exit(X509_V_ERR_PERMITTED_VIOLATION);
    {
     * Otherwise can add zero or more components on the left so compare RHS
     * and if dns is longer and expect '.' as preceding character.
     }
    if dns.length > base.length then
    begin
        dnsptr  := dnsptr + (dns.length - base.length);
        if (baseptr^ <> '.')  and  (dnsptr[-1] <> '.') then
           Exit(X509_V_ERR_PERMITTED_VIOLATION);
    end;
    if ia5ncasecmp(baseptr, dnsptr, base.length) > 0 then
        Exit(X509_V_ERR_PERMITTED_VIOLATION);
    Exit(X509_V_OK);
end;

function nc_dn(const nm, base : PX509_NAME):integer;
var
  p: PByte;
begin
    { Ensure canonical encodings are up to date.  }
    p := nil;
    if (nm.modified > 0) and  (i2d_X509_NAME(nm, @p) < 0) then
        Exit(X509_V_ERR_OUT_OF_MEM);
    p := nil;
    if (base.modified > 0)  and  (i2d_X509_NAME(base, @p) < 0) then
        Exit(X509_V_ERR_OUT_OF_MEM);
    if base.canon_enclen > nm.canon_enclen then
       Exit(X509_V_ERR_PERMITTED_VIOLATION);
    if memcmp(base.canon_enc, nm.canon_enc, base.canon_enclen) > 0 then
        Exit(X509_V_ERR_PERMITTED_VIOLATION);
    Result := X509_V_OK;
end;


function IA5_OFFSET_LEN(ia5base: PASN1_IA5STRING; const offset: PUTF8Char) :size_t;
begin
   Result := (ia5base.length - (PByte(offset) - ia5base.data))
end;




function ia5ncasecmp({const} s1, s2 : PUTF8Char; n : size_t):integer;
var
  c1, c2 : Byte;
begin
    while n > 0 do
    begin
        if s1^ <> s2^ then
        begin
            c1 := Byte( s1^);
            c2 := Byte( s2^);
            { Convert to lower case }
            if (c1 >= $41) { A }  and  (c1 <= $5A) { Z }  then
               c1  := c1 + $20;
            if (c2 >= $41) { A }  and  (c2 <= $5A) { Z } then
               c2  := c2 + $20;
            if c1 = c2 then continue;
            if c1 < c2 then Exit(-1);
            { c1 > c2 }
            Exit(1);
        end;
        Dec(n); Inc(s1); Inc(s2);
    end;
    Result := 0;
end;

function ia5memrchr( str : PASN1_IA5STRING; c : integer):PUTF8Char;
var
  i : integer;
begin
    i := str.length;
    while (i > 0)  and  (str.data[i - 1] <> c) do
       Dec(i);
    if i = 0 then Exit(nil);
    Result := PUTF8Char(@str.data[i - 1]);
end;




function nc_email_eai( emltype : PASN1_TYPE; base : PASN1_IA5STRING):integer;
var
    eml        : PASN1_UTF8STRING;
    baseptr,
    emlptr,
    emlat      : PUTF8Char;
    ulabel     : array[0..255] of UTF8Char;
    size       : size_t;
    ret        : integer;
    emlhostlen : size_t;
    label _end;
begin
    baseptr := nil;
    size := sizeof(ulabel) - 1;
    ret := X509_V_OK;
    { We do not accept embedded NUL characters }
    if (base.length > 0)  and  (memchr(base.data, 0, base.length) <> nil) then
        Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    { 'base' may not be NUL terminated. Create a copy that is }
    OPENSSL_strndup(baseptr, PUTF8Char( base.data), base.length);
    if baseptr = nil then Exit(X509_V_ERR_OUT_OF_MEM);
    if emltype._type <> V_ASN1_UTF8STRING then begin
        ret := X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
        goto _end;
    end;
    eml := emltype.value.utf8string;
    emlptr := PUTF8Char( eml.data);
    emlat := ia5memrchr(eml, Ord('@'));
    if emlat = nil then
    begin
        ret := X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
        goto _end;
    end;
    memset(@ulabel, 0, sizeof(ulabel));
    { Special case: initial '.' is RHS match }
    if baseptr^ = '.' then
    begin
        ulabel[0] := '.';
        size  := size - 1;
        if ossl_a2ulabel(baseptr, ulabel + 1, @size) <= 0  then
        begin
            ret := X509_V_ERR_UNSPECIFIED;
            goto _end;
        end;
        if size_t(eml.length) > Length(ulabel) then
        begin
            emlptr  := emlptr + (eml.length - Length(ulabel));
            { X509_V_OK }
            if ia5ncasecmp(ulabel, emlptr, Length(ulabel)) = 0  then
                goto _end;
        end;
        ret := X509_V_ERR_PERMITTED_VIOLATION;
        goto _end;
    end;
    if ossl_a2ulabel(baseptr, ulabel, @size) <= 0  then
    begin
        ret := X509_V_ERR_UNSPECIFIED;
        goto _end;
    end;
    { Just have hostname left to match: case insensitive }
    emlptr := emlat + 1;
    emlhostlen := IA5_OFFSET_LEN(eml, emlptr);
    if (emlhostlen <> Length(ulabel)) or  (ia5ncasecmp(ulabel, emlptr, emlhostlen) <> 0)  then
    begin
        ret := X509_V_ERR_PERMITTED_VIOLATION;
        goto _end;
    end;
 _end:
    OPENSSL_free(baseptr);
    Result := ret;
end;





function nc_match_single( gen, base : PGENERAL_NAME):integer;
begin
    case gen.&type of
    GEN_OTHERNAME:
        {
         * We are here only when we have SmtpUTF8 name,
         * so we match the value of othername with base.d.rfc822Name
         }
        Exit(nc_email_eai(gen.d.otherName.value, base.d.rfc822Name));
    GEN_DIRNAME:
        Exit(nc_dn(gen.d.directoryName, base.d.directoryName));
    GEN_DNS:
        Exit(nc_dns(gen.d.dNSName, base.d.dNSName));
    GEN_EMAIL:
        Exit(nc_email(gen.d.rfc822Name, base.d.rfc822Name));
    GEN_URI:
        Exit(nc_uri(gen.d.uniformResourceIdentifier, base.d.uniformResourceIdentifier));
    GEN_IPADD:
        Exit(nc_ip(gen.d.iPAddress, base.d.iPAddress));
    else
        Exit(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE);
    end;
end;


function nc_minmax_valid( sub : PGENERAL_SUBTREE):integer;
var
  bn : PBIGNUM;

  ok : integer;
begin
    bn := nil;
    ok := 1;
    if sub.maximum <> nil then ok := 0;
    if sub.minimum <> nil then
    begin
        bn := ASN1_INTEGER_to_BN(sub.minimum, nil);
        if (bn = nil)  or  (not BN_is_zero(bn)) then
            ok := 0;
        BN_free(bn);
    end;
    Result := ok;
end;





function nc_match( gen : PGENERAL_NAME; nc : PNAME_CONSTRAINTS):integer;
var
  sub            : PGENERAL_SUBTREE;
  i,  r,  match,
  effective_type : integer;
begin
    match := 0;
    {
     * We need to compare not gen.type field but an 'effective' type because
     * the otherName field may contain EAI email address treated specially
     * according to RFC 8398, section 6
     }
    effective_type := get_result((gen.&type = GEN_OTHERNAME)  and
                                  (OBJ_obj2nid(gen.d.otherName.type_id) =
                           NID_id_on_SmtpUTF8Mailbox) , GEN_EMAIL , gen.&type);
    {
     * Permitted subtrees: if any subtrees exist of matching the type at
     * least one subtree must match.
     }
    for i := 0 to sk_GENERAL_SUBTREE_num(nc.permittedSubtrees)-1 do
    begin
        sub := sk_GENERAL_SUBTREE_value(nc.permittedSubtrees, i);
        if effective_type <> sub.base.&type then continue;
        if 0>=nc_minmax_valid(sub) then
            Exit(X509_V_ERR_SUBTREE_MINMAX);
        { If we already have a match don't bother trying any more }
        if match = 2 then continue;
        if match = 0 then match := 1;
        r := nc_match_single(gen, sub.base);
        if r = X509_V_OK then
           match := 2
        else if (r <> X509_V_ERR_PERMITTED_VIOLATION) then
            Exit(r);
    end;
    if match = 1 then
       Exit(X509_V_ERR_PERMITTED_VIOLATION);
    { Excluded subtrees: must not match any of these }
    for i := 0 to sk_GENERAL_SUBTREE_num(nc.excludedSubtrees)-1 do
    begin
        sub := sk_GENERAL_SUBTREE_value(nc.excludedSubtrees, i);
        if effective_type <> sub.base.&type then continue;
        if 0>=nc_minmax_valid(sub) then
            Exit(X509_V_ERR_SUBTREE_MINMAX);
        r := nc_match_single(gen, sub.base);
        if r = X509_V_OK then
           Exit(X509_V_ERR_EXCLUDED_VIOLATION)
        else if (r <> X509_V_ERR_PERMITTED_VIOLATION) then
            Exit(r);
    end;
    Exit(X509_V_OK);
end;


function safe_add_int( a, b : integer; err : PInteger):integer;
begin
 if (a < 0)  xor  (b < 0)  or
    ( (a > 0)  and  (b <= (not(int(1) shl (sizeof(Integer) *8 - 1))) - a) ) or
    ( (a < 0)  and  (b >= (int(1) shl (sizeof(Int)*  8 - 1)) - a) ) or
    (a = 0) then
    Exit(a + b);
    err^  :=  err^  or 1;

    Result := get_result(a < 0 , (int(1) shl (sizeof(Int)*8 - 1)) ,
                        (not(int(1) shl (sizeof(Int)*8 - 1))) );
end;


function add_lengths( _out : PInteger; a, b : integer):integer;
var
  err : integer;
begin
    err := 0;
    { sk_FOO_num(nil) returns -1 but is effectively 0 when iterating. }
    if a < 0 then a := 0;
    if b < 0 then b := 0;
    _out^ := safe_add_int(a, b, @err);
    Result :=  not err;
end;




function NAME_CONSTRAINTS_check( x : PX509; nc : PNAME_CONSTRAINTS):integer;
var
  r,
  i,
  name_count,
  constraint_count : integer;
  nm               : PX509_NAME;
  gntmp            : TGENERAL_NAME;
  gen              : PGENERAL_NAME;
  ne: PX509_NAME_ENTRY;
begin
    nm := X509_get_subject_name(x);
    {
     * Guard against certificates with an excessive number of names or
     * constraints causing a computationally expensive name constraints check.
     }
    if (0>=add_lengths(@name_count, X509_NAME_entry_count(nm),
                     sk_GENERAL_NAME_num(x.altname)))
         or  (0>=add_lengths(@constraint_count,
                        sk_GENERAL_SUBTREE_num(nc.permittedSubtrees),
                        sk_GENERAL_SUBTREE_num(nc.excludedSubtrees)) )
         or ( (name_count > 0)  and  (constraint_count > (NAME_CHECK_MAX div name_count)) ) then
        Exit(X509_V_ERR_UNSPECIFIED);
    if X509_NAME_entry_count(nm) > 0  then
    begin
        gntmp.&type := GEN_DIRNAME;
        gntmp.d.directoryName := nm;
        r := nc_match(@gntmp, nc);
        if r <> X509_V_OK then Exit(r);
        gntmp.&type := GEN_EMAIL;
        { Process any email address attributes in subject name }
        i := -1;
        while true do
        begin
            i := X509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i);
            if i = -1 then break;
            ne := X509_NAME_get_entry(nm, i);
            gntmp.d.rfc822Name := X509_NAME_ENTRY_get_data(ne);
            if gntmp.d.rfc822Name.&type <> V_ASN1_IA5STRING then
               Exit(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
            r := nc_match(@gntmp, nc);
            if r <> X509_V_OK then Exit(r);
        end;
    end;
    for i := 0 to sk_GENERAL_NAME_num(x.altname)-1 do
    begin
        gen := sk_GENERAL_NAME_value(x.altname, i);
        r := nc_match(gen, nc);
        if r <> X509_V_OK then Exit(r);
    end;
    Exit(X509_V_OK);
end;


function print_nc_ipadd( bp : PBIO; ip : PASN1_OCTET_STRING):integer;
var
  len1, len2 : integer;
  ip1, ip2 : PUTF8Char;
  ret : integer;
begin
    { ip.length should be 8 or 32 and len1 = len2 = 4 or len1 = len2 = 16 }
    len1 := get_result(ip.length >= 16 , 16 ,
              get_result(ip.length >= 4 , 4 , ip.length));
    len2 := ip.length - len1;
    ip1 := ossl_ipaddr_to_asc(ip.data, len1);
    ip2 := ossl_ipaddr_to_asc(ip.data + len1, len2);
    ret := Int( (ip1 <> nil)  and  (ip2 <> nil)
                 and  (BIO_printf(bp, ' IP:%s/%s' , [ip1, ip2]) > 0) );
    OPENSSL_free(ip1);
    OPENSSL_free(ip2);
    Result := ret;
end;




function do_i2r_name_constraints(const method : PX509V3_EXT_METHOD; trees : Pstack_st_GENERAL_SUBTREE; bp : PBIO; ind : integer;const name : PUTF8Char):integer;
var
  tree : PGENERAL_SUBTREE;

  i : integer;
begin
    if sk_GENERAL_SUBTREE_num(trees)  > 0 then
        BIO_printf(bp, ' %*s%s:\n' , [ind, ' ' , name]);

    for i := 0 to sk_GENERAL_SUBTREE_num(trees)-1 do
    begin
        if i > 0 then BIO_puts(bp, ' '#10 );
        tree := sk_GENERAL_SUBTREE_value(trees, i);
        BIO_printf(bp, ' %*s' , [ind + 2, ' '] );
        if tree.base.&type = GEN_IPADD then
           print_nc_ipadd(bp, tree.base.d.ip)
        else
            GENERAL_NAME_print(bp, tree.base);
    end;
    Result := 1;
end;




function GENERAL_SUBTREE_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @GENERAL_SUBTREE_seq_tt,
                        sizeof(GENERAL_SUBTREE_seq_tt) div sizeof(TASN1_TEMPLATE),
            Pointer(0) , sizeof(GENERAL_SUBTREE), ' GENERAL_SUBTREE'  );
   Result := @local_it;
end;




function GENERAL_SUBTREE_new: PGENERAL_SUBTREE;
begin
 Result := PGENERAL_SUBTREE(ASN1_item_new(GENERAL_SUBTREE_it));
end;


procedure GENERAL_SUBTREE_free(a : PGENERAL_SUBTREE);
begin
 ASN1_item_free(PASN1_VALUE( a), GENERAL_SUBTREE_it);
end;

function NAME_CONSTRAINTS_new:PNAME_CONSTRAINTS;
begin
 Result := PNAME_CONSTRAINTS(ASN1_item_new(NAME_CONSTRAINTS_it));
end;


procedure NAME_CONSTRAINTS_free( a : PNAME_CONSTRAINTS);
begin
 ASN1_item_free(PASN1_VALUE( a), NAME_CONSTRAINTS_it);
end;

function v2i_NAME_CONSTRAINTS(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
var
  i : integer;
  tval: TCONF_VALUE;
  val : PCONF_VALUE;
  ptree : PPstack_st_GENERAL_SUBTREE;
  ncons : PNAME_CONSTRAINTS;

  sub : PGENERAL_SUBTREE;
  label _memerr, _err;
begin
    ptree := nil;
    ncons := nil;
    sub := nil;
    ncons := NAME_CONSTRAINTS_new();
    if ncons = nil then
       goto _memerr ;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        val := sk_CONF_VALUE_value(nval, i);
        if (HAS_PREFIX(val.name, ' permitted'))  and  (val.name[9]<>#0)   then
        begin
            ptree := &ncons.permittedSubtrees;
            tval.name := val.name + 10;
        end
        else
        if (HAS_PREFIX(val.name, ' excluded') )  and  (val.name[8] <> #0) then
        begin
            ptree := &ncons.excludedSubtrees;
            tval.name := val.name + 9;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SYNTAX);
            goto _err ;
        end;
        tval.value := val.value;
        sub := GENERAL_SUBTREE_new();
        if sub = nil then
           goto _memerr ;
        if nil = v2i_GENERAL_NAME_ex(sub.base, method, ctx, @tval, 1) then
            goto _err ;
        if ptree^ = nil then
           ptree^ := sk_GENERAL_SUBTREE_new_null();
        if (ptree^ = nil)  or  (0>= sk_GENERAL_SUBTREE_push(ptree^, sub)) then
            goto _memerr ;
        sub := nil;
    end;
    Exit(ncons);
 _memerr:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
 _err:
    NAME_CONSTRAINTS_free(ncons);
    GENERAL_SUBTREE_free(sub);
    Result := nil;
end;


function i2r_NAME_CONSTRAINTS(const method : PX509V3_EXT_METHOD; a : Pointer; bp : PBIO; ind : integer):integer;
var
  ncons : PNAME_CONSTRAINTS;
begin
    ncons := a;
    do_i2r_name_constraints(method, ncons.permittedSubtrees,
                            bp, ind, ' Permitted' );
    if (ncons.permittedSubtrees <> nil) and  (ncons.excludedSubtrees <> nil) then
       BIO_puts(bp, ' '#10 );
    do_i2r_name_constraints(method, ncons.excludedSubtrees,
                            bp, ind, ' Excluded' );
    Result := 1;
end;



function NAME_CONSTRAINTS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @NAME_CONSTRAINTS_seq_tt,
                       sizeof(NAME_CONSTRAINTS_seq_tt) div sizeof(TASN1_TEMPLATE),
             Pointer(0) , sizeof(NAME_CONSTRAINTS), ' NAME_CONSTRAINTS');

   Result := @local_it;
end;

initialization
   ossl_v3_name_constraints := get_V3_EXT_METHOD(
    NID_name_constraints, 0,
    NAME_CONSTRAINTS_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, v2i_NAME_CONSTRAINTS,
    i2r_NAME_CONSTRAINTS, nil,
    nil);
    NAME_CONSTRAINTS_seq_tt := [
            get_ASN1_TEMPLATE( ((($1 shl  3) or ($2 shl 6))  or  (($2 shl  1) or ($1))), 0,  size_t(@PNAME_CONSTRAINTS(0).permittedSubtrees), ' permittedSubtrees' , GENERAL_SUBTREE_it) ,
            get_ASN1_TEMPLATE( ((($1 shl  3) or ($2 shl 6))  or  (($2 shl  1) or ($1))), (1), size_t(@PNAME_CONSTRAINTS(0). excludedSubtrees),    ' excludedSubtrees' , GENERAL_SUBTREE_it)
    ] ;

     GENERAL_SUBTREE_seq_tt := [
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PGENERAL_SUBTREE(0).base), ' base' , GENERAL_NAME_it),
        get_ASN1_TEMPLATE( (($1 shl  3) or ($2 shl 6))  or  $1, 0, size_t(@PGENERAL_SUBTREE(0).minimum), ' minimum' , ASN1_INTEGER_it) ,
        get_ASN1_TEMPLATE( (($1 shl  3) or ($2 shl 6))  or  $1, 1, size_t(@PGENERAL_SUBTREE(0).maximum), ' maximum' , ASN1_INTEGER_it)
    ] ;

end.
