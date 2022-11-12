unit OpenSSL3.crypto.x509.x_name;

interface
uses OpenSSL.Api, Variants;

const
  ASN1_MASK_CANON =
        (B_ASN1_UTF8STRING or B_ASN1_BMPSTRING or B_ASN1_UNIVERSALSTRING
        or B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_IA5STRING
        or B_ASN1_VISIBLESTRING);

type
  sk_STACK_OF_X509_NAME_ENTRY_freefunc = procedure(a: PSTACK_OF_X509_NAME_ENTRY);

  function d2i_X509_NAME(a : PPX509_NAME;const _in : PPByte; len : long):PX509_NAME;
  function i2d_X509_NAME(const a : PX509_NAME; _out : PPByte):integer;
  function X509_NAME_new:PX509_NAME;
  procedure X509_NAME_free( a : PX509_NAME);
  function X509_NAME_it:PASN1_ITEM;
  function x509_name_ex_new(val : PPASN1_VALUE;const it : PASN1_ITEM):integer;
  procedure x509_name_ex_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  procedure local_sk_X509_NAME_ENTRY_free( ne : Pstack_st_X509_NAME_ENTRY);
  procedure local_sk_X509_NAME_ENTRY_pop_free( ne : Pstack_st_X509_NAME_ENTRY);
  function x509_name_ex_d2i(val : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : UTF8Char; ctx : PASN1_TLC):integer;
  function x509_name_ex_i2d(const val : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
  function x509_name_encode( a : PX509_NAME):integer;
  function x509_name_ex_print(_out : PBIO;const pval : PPASN1_VALUE; indent : integer;const fname : PUTF8Char; const pctx : PASN1_PCTX):integer;
  function x509_name_canon( a : PX509_NAME):integer;
  function asn1_string_canon(_out : PASN1_STRING;const _in : PASN1_STRING):integer;
  function i2d_name_canon(const _intname : Pstack_st_STACK_OF_X509_NAME_ENTRY; _in : PPByte):integer;
  function X509_NAME_set(xn : PPX509_NAME;const name : PX509_NAME):integer;
  function X509_NAME_print(bp : PBIO;const name : PX509_NAME; obase : integer):integer;
  function X509_NAME_get0_der(const nm : PX509_NAME; pder : PPByte; pderlen : Psize_t):integer;
  procedure sk_STACK_OF_X509_NAME_ENTRY_free( sk : Pstack_st_STACK_OF_X509_NAME_ENTRY);
  procedure X509_NAME_ENTRY_free( a : PX509_NAME_ENTRY);
  function X509_NAME_INTERNAL_it:PASN1_ITEM;
  function X509_NAME_ENTRY_it: PASN1_ITEM;
  function sk_STACK_OF_X509_NAME_ENTRY_num(const sk : Pstack_st_STACK_OF_X509_NAME_ENTRY):integer;
  function sk_STACK_OF_X509_NAME_ENTRY_value(const sk : Pstack_st_STACK_OF_X509_NAME_ENTRY; idx : integer): PSTACK_OF_X509_NAME_ENTRY;
  procedure sk_STACK_OF_X509_NAME_ENTRY_pop_free( sk : Pstack_st_STACK_OF_X509_NAME_ENTRY; freefunc : sk_STACK_OF_X509_NAME_ENTRY_freefunc);
  function sk_STACK_OF_X509_NAME_ENTRY_new_null:Pstack_st_STACK_OF_X509_NAME_ENTRY;
  function sk_STACK_OF_X509_NAME_ENTRY_push( sk : Pstack_st_STACK_OF_X509_NAME_ENTRY; ptr : PSTACK_OF_X509_NAME_ENTRY):integer;
  function X509_NAME_ENTRY_new:PX509_NAME_ENTRY;
  function X509_NAME_ENTRIES_it:PASN1_ITEM;
  function X509_NAME_dup(const x : PX509_NAME):PX509_NAME;
  function X509_NAME_ENTRY_dup(const x : PX509_NAME_ENTRY):PX509_NAME_ENTRY;

const
  x509_name_ff : TASN1_EXTERN_FUNCS = (
    app_data: nil;
    asn1_ex_new: x509_name_ex_new;
    asn1_ex_free: x509_name_ex_free;
    asn1_ex_clear: nil;
    asn1_ex_d2i: x509_name_ex_d2i;
    asn1_ex_i2d: x509_name_ex_i2d;
    asn1_ex_print: x509_name_ex_print
  );

  X509_NAME_MAX = (1024 * 1024);
var
  X509_NAME_ENTRY_seq_tt    : array[0..1] of TASN1_TEMPLATE;
  X509_NAME_INTERNAL_item_tt, X509_NAME_ENTRIES_item_tt: TASN1_TEMPLATE;

implementation
uses openssl3.crypto.asn1.tasn_dec, openssl3.crypto.mem, openssl3.crypto.x509,
     openssl3.crypto.buffer.buffer, OpenSSL3.Err, openssl3.crypto.stack,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.objects.obj_lib,
     openssl3.crypto.ctype, OpenSSL3.openssl.asn1t,
     openssl3.crypto.bio.bio_lib, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.a_dup,  openssl3.crypto.x509.x509_obj,
     openssl3.crypto.asn1.a_strex, openssl3.crypto.asn1.asn1_lib;





function X509_NAME_ENTRY_dup(const x : PX509_NAME_ENTRY):PX509_NAME_ENTRY;
begin
   Result := ASN1_item_dup(X509_NAME_ENTRY_it, x);
end;

function X509_NAME_dup(const x : PX509_NAME):PX509_NAME;
begin
   result := ASN1_item_dup(X509_NAME_it, x);
end;


function X509_NAME_ENTRIES_it:PASN1_ITEM;
var
  local_it: TASN1_ITEM ;
begin
  local_it := get_ASN1_ITEM($0, -1, @X509_NAME_ENTRIES_item_tt,
                 0, Pointer(0) , 0, 'X509_NAME_ENTRIES' );

  result := @local_it;
end;


function X509_NAME_ENTRY_new:PX509_NAME_ENTRY;
begin
   result := PX509_NAME_ENTRY(ASN1_item_new(X509_NAME_ENTRY_it));
end;



function sk_STACK_OF_X509_NAME_ENTRY_push( sk : Pstack_st_STACK_OF_X509_NAME_ENTRY; ptr : PSTACK_OF_X509_NAME_ENTRY):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), Pointer(ptr));
end;


function sk_STACK_OF_X509_NAME_ENTRY_new_null:Pstack_st_STACK_OF_X509_NAME_ENTRY;
begin
   Result := Pstack_st_STACK_OF_X509_NAME_ENTRY(OPENSSL_sk_new_null);
end;

procedure sk_STACK_OF_X509_NAME_ENTRY_pop_free( sk : Pstack_st_STACK_OF_X509_NAME_ENTRY;
                            freefunc : sk_STACK_OF_X509_NAME_ENTRY_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;




function sk_STACK_OF_X509_NAME_ENTRY_value(const sk : Pstack_st_STACK_OF_X509_NAME_ENTRY; idx : integer): PSTACK_OF_X509_NAME_ENTRY;
begin
   result := PSTACK_OF_X509_NAME_ENTRY(OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;




function sk_STACK_OF_X509_NAME_ENTRY_num(const sk : Pstack_st_STACK_OF_X509_NAME_ENTRY):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK( sk));
end;




function X509_NAME_INTERNAL_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($0, -1, @X509_NAME_INTERNAL_item_tt, 0,
                     Pointer(0) , 0, 'X509_NAME_INTERNAL');

   result := @local_it;
end;

function X509_NAME_ENTRY_it: PASN1_ITEM;
var
  local_it: TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM(
         $1, 16, @X509_NAME_ENTRY_seq_tt,
         sizeof(X509_NAME_ENTRY_seq_tt) div sizeof(TASN1_TEMPLATE),
         Pointer(0) , sizeof(TX509_NAME_ENTRY), 'X509_NAME_ENTRY' );
   result := @local_it;
end;


procedure X509_NAME_ENTRY_free( a : PX509_NAME_ENTRY);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_NAME_ENTRY_it);
end;

procedure sk_STACK_OF_X509_NAME_ENTRY_free( sk : Pstack_st_STACK_OF_X509_NAME_ENTRY);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


function x509_name_ex_new(val : PPASN1_VALUE;const it : PASN1_ITEM):integer;
var
  ret : PX509_NAME;
  label _memerr;
begin
    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then
       goto _memerr ;
    ret.entries := sk_X509_NAME_ENTRY_new_null();
    if ret.entries = nil then
        goto _memerr ;
    ret.bytes := BUF_MEM_new();
    if ret.bytes = nil then
        goto _memerr ;
    ret.modified := 1;
    val^ := PASN1_VALUE( ret);
    Exit(1);
 _memerr:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    if ret <> nil then
    begin
        sk_X509_NAME_ENTRY_free(ret.entries);
        OPENSSL_free(Pointer(ret));
    end;
    Result := 0;
end;


procedure x509_name_ex_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
var
  a : PX509_NAME;
begin
    if (pval = nil)  or  (pval^ = nil) then
       exit;
    a := PX509_NAME(pval^);
    BUF_MEM_free(a.bytes);
    sk_X509_NAME_ENTRY_pop_free(a.entries, X509_NAME_ENTRY_free);
    OPENSSL_free(Pointer(a.canon_enc));
    OPENSSL_free(Pointer(a));
    pval^ := nil;
end;


procedure local_sk_X509_NAME_ENTRY_free( ne : Pstack_st_X509_NAME_ENTRY);
begin
    sk_X509_NAME_ENTRY_free(ne);
end;


procedure local_sk_X509_NAME_ENTRY_pop_free( ne : Pstack_st_X509_NAME_ENTRY);
begin
    sk_X509_NAME_ENTRY_pop_free(ne, X509_NAME_ENTRY_free);
end;


function x509_name_ex_d2i(val : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : UTF8Char; ctx : PASN1_TLC):integer;
type
  intname_st = record
    case Integer of
      0: (s: Pstack_st_STACK_OF_X509_NAME_ENTRY);
      1: (a: PASN1_VALUE );
  end;

  nm_st = record
    case Integer of
      0: (x: PX509_NAME );
      1: (a: PASN1_VALUE);
  end;
var
  p, q : PByte;
  s : Pstack_st_STACK_OF_X509_NAME_ENTRY;
  x : PX509_NAME;
  i, j, ret : integer;
  entries : Pstack_st_X509_NAME_ENTRY;
  entry : PX509_NAME_ENTRY;
  intname: intname_st;
  nm: nm_st;
  label _err;
begin
    p := _in^;

    intname := default(intname_st);
    nm := default(nm_st);

    if len > X509_NAME_MAX then
       len := X509_NAME_MAX;
    q := p;
    { Get internal representation of Name }
    ret := ASN1_item_ex_d2i(@intname.a,
                           @p, len, X509_NAME_INTERNAL_it,
                           tag, aclass, Ord(opt), ctx);
    if ret <= 0 then Exit(ret);
    if val^ <> nil then
       x509_name_ex_free(val, nil);
    if 0>= x509_name_ex_new(@nm.a, nil) then
        goto _err ;
    { We've decoded it: now cache encoding }
    if 0>= BUF_MEM_grow(nm.x.bytes, p - q) then
        goto _err ;
    memcpy(nm.x.bytes.data, q, p - q);
    { Convert internal representation to X509_NAME structure }
    for i := 0 to sk_STACK_OF_X509_NAME_ENTRY_num(intname.s)-1 do
    begin
        entries := sk_STACK_OF_X509_NAME_ENTRY_value(intname.s, i);
        for j := 0 to sk_X509_NAME_ENTRY_num(entries)-1 do
        begin
            entry := sk_X509_NAME_ENTRY_value(entries, j);
            entry._set := i;
            if 0>= sk_X509_NAME_ENTRY_push(nm.x.entries, entry) then
                goto _err ;
            sk_X509_NAME_ENTRY_set(entries, j, nil);
        end;
    end;
    ret := x509_name_canon(nm.x);
    if 0>= ret then
       goto _err ;
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_free);
    nm.x.modified := 0;
    val^ := nm.a;
    _in^ := p;
    Exit(ret);
 _err:
    if nm.x <> nil then
       X509_NAME_free(nm.x);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_pop_free);
    ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
    Result := 0;
end;


function x509_name_ex_i2d(const val : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
var
  ret : integer;
  a : PX509_NAME;
begin
    a := PX509_NAME( val^);
    if a.modified > 0 then
    begin
        ret := x509_name_encode(a);
        if ret < 0 then Exit(ret);
        ret := x509_name_canon(a);
        if 0>= ret then Exit(-1);
    end;
    ret := a.bytes.length;
    if _out <> nil then
    begin
        memcpy( _out^, a.bytes.data, ret);
        _out^  := _out^ + ret;
    end;
    Result := ret;
end;


function x509_name_encode( a : PX509_NAME):integer;
type
  intname_st = record
    case Integer of
      0: (s: Pstack_st_STACK_OF_X509_NAME_ENTRY);
      1: (a: PASN1_VALUE );
  end;
var
  s : Pstack_st_STACK_OF_X509_NAME_ENTRY;
  len : integer;
  p : PByte;
  entries : Pstack_st_X509_NAME_ENTRY;
  entry : PX509_NAME_ENTRY;
  i, _set : integer;
  intname: intname_st;
  label _memerr;

begin
    memset(@intname, 0, Sizeof(intname_st));
    entries := nil;
    _set := -1;
    intname.s := sk_STACK_OF_X509_NAME_ENTRY_new_null();
    if nil = intname.s then
       goto _memerr ;
    for i := 0 to sk_X509_NAME_ENTRY_num(a.entries)-1 do
    begin
        entry := sk_X509_NAME_ENTRY_value(a.entries, i);
        if entry._set <> _set then
        begin
            entries := sk_X509_NAME_ENTRY_new_null();
            if nil = entries then
               goto _memerr ;
            if 0>= sk_STACK_OF_X509_NAME_ENTRY_push(intname.s, entries) then
            begin
                sk_X509_NAME_ENTRY_free(entries);
                goto _memerr ;
            end;
            _set := entry._set;
        end;
        if 0>= sk_X509_NAME_ENTRY_push(entries, entry) then
            goto _memerr ;
    end;

    len := ASN1_item_ex_i2d(@intname.a, nil,
                           X509_NAME_INTERNAL_it, -1, -1);
    if 0>= BUF_MEM_grow(a.bytes, len) then
        goto _memerr ;
    p := PByte( a.bytes.data);
    ASN1_item_ex_i2d(@intname.a, @p, X509_NAME_INTERNAL_it, -1, -1);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_free);
    a.modified := 0;
    Exit(len);
 _memerr:
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_free);
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    Result := -1;
end;


function x509_name_ex_print(_out : PBIO;const pval : PPASN1_VALUE; indent : integer;const fname : PUTF8Char; const pctx : PASN1_PCTX):integer;
begin
    if X509_NAME_print_ex(_out, PX509_NAME(pval^),
                           indent, pctx.nm_flags) <= 0 then
        Exit(0);
    Result := 2;
end;


function x509_name_canon( a : PX509_NAME):integer;
var
  p        : PByte;
  intname  : Pstack_st_STACK_OF_X509_NAME_ENTRY;
  entries  : Pstack_st_X509_NAME_ENTRY;

  entry,
  tmpentry : PX509_NAME_ENTRY;
  i,
  _set, ret, len     : integer;
  label _err;
begin
    entries := nil;
    tmpentry := nil;
    _set := -1; ret := 0;
    OPENSSL_free(Pointer(a.canon_enc));
    a.canon_enc := nil;
    { Special case: empty X509_NAME => null encoding }
    if sk_X509_NAME_ENTRY_num(a.entries) = 0  then
    begin
        a.canon_enclen := 0;
        Exit(1);
    end;
    intname := sk_STACK_OF_X509_NAME_ENTRY_new_null();
    if intname = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    for i := 0 to sk_X509_NAME_ENTRY_num(a.entries)-1 do
    begin
        entry := sk_X509_NAME_ENTRY_value(a.entries, i);
        if entry._set <> _set then
        begin
            entries := sk_X509_NAME_ENTRY_new_null();
            if entries = nil then
               goto _err ;
            if 0>= sk_STACK_OF_X509_NAME_ENTRY_push(intname, entries) then
            begin
                sk_X509_NAME_ENTRY_free(entries);
                ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            _set := entry._set;
        end;
        tmpentry := X509_NAME_ENTRY_new();
        if tmpentry = nil then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        tmpentry._object := OBJ_dup(entry._object);
        if tmpentry._object = nil then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if 0>= asn1_string_canon(tmpentry.value, entry.value) then
            goto _err ;
        if 0>= sk_X509_NAME_ENTRY_push(entries, tmpentry) then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        tmpentry := nil;
    end;
    { Finally generate encoding }
    len := i2d_name_canon(intname, nil);
    if len < 0 then
       goto _err ;
    a.canon_enclen := len;
    p := OPENSSL_malloc(a.canon_enclen);
    if p = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    a.canon_enc := p;
    i2d_name_canon(intname, @p);
    ret := 1;
 _err:
    X509_NAME_ENTRY_free(tmpentry);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname,
                                         local_sk_X509_NAME_ENTRY_pop_free);
    Result := ret;
end;


function asn1_string_canon(_out : PASN1_STRING;const _in : PASN1_STRING):integer;
var
  _to, from : PByte;

  len, i : integer;
begin
    { If type not in bitmask just copy string across }
    if 0>= (ASN1_tag2bit(_in.&type) and ASN1_MASK_CANON) then
    begin
        if 0>= ASN1_STRING_copy(_out, _in) then
            Exit(0);
        Exit(1);
    end;
    _out.&type := V_ASN1_UTF8STRING;
    _out.length := ASN1_STRING_to_UTF8(@_out.data, _in);
    if _out.length = -1 then
       Exit(0);
    _to := _out.data;
    from := _to;
    len := _out.length;
    {
     * Convert string in place to canonical form. Ultimately we may need to
     * handle a wider range of UTF8Characters but for now ignore anything with
     * MSB set and rely on the ossl_isspace() to fail on bad characters without
     * needing isascii or range checks as well.
     }
    { Ignore leading spaces }
    while (len > 0)  and  (ossl_isspace(UTF8Char(from^))) do
    begin
        Inc(from);
        Dec(len);
    end;
    _to := from + len;
    { Ignore trailing spaces }
    while (len > 0)  and  (ossl_isspace(UTF8Char(_to[-1]))) do
    begin
        Dec(_to);
        Dec(len);
    end;
    _to := _out.data;
    i := 0;
    while i < len do
    begin
        { If not ASCII set just copy across }
        if not ossl_isascii(from^) then
        begin
            PostInc(_to)^ :=  PostInc(from)^;
            Inc(i);
        end
        { Collapse multiple spaces }
        else
        if ossl_isspace(UTF8Char(from^)) then
        begin
            { Copy one space across }
            PostInc(_to)^ :=  ord(' ');
            {
             * Ignore subsequent spaces. Note: don't need to check len here
             * because we know the last character is a non-space so we can't
             * overflow.
             }
            repeat
                Inc(from);
                Inc(i);
            until not (ossl_isspace(UTF8Char(from^)));
        end
        else
        begin
            PostInc(_to)^ := ord( ossl_tolower(UTF8Char(from^)));
            Inc(from);
            Inc(i);
        end;
    end;
    _out.length := _to - _out.data;
    Exit(1);
end;


function i2d_name_canon(const _intname : Pstack_st_STACK_OF_X509_NAME_ENTRY; _in : PPByte):integer;
var
  i, len, ltmp : integer;
  v : PASN1_VALUE;
  intname : Pstack_st_ASN1_VALUE;
begin
    intname := Pstack_st_ASN1_VALUE(_intname);
    len := 0;
    for i := 0 to sk_ASN1_VALUE_num(intname)-1 do
    begin
        v := sk_ASN1_VALUE_value(intname, i);
        ltmp := ASN1_item_ex_i2d(@v, _in,
                                X509_NAME_ENTRIES_it, -1, -1);
        if ltmp < 0 then Exit(ltmp);
        len  := len + ltmp;
    end;
    Result := len;
end;


function X509_NAME_set(xn : PPX509_NAME;const name : PX509_NAME):integer;
var
  name_copy : PX509_NAME;
begin
    if xn^ = name then
       Exit(int(xn^ <> nil));
    name_copy := X509_NAME_dup(name);
    if name_copy = nil then
        Exit(0);
    X509_NAME_free(xn^);
    xn^ := name_copy;
    Result := 1;
end;


function X509_NAME_print(bp : PBIO;const name : PX509_NAME; obase : integer):integer;
var
  s, c, b : PUTF8Char;
  l, i : integer;
  label _err;
begin
    l := 80 - 2 - obase;
    b := X509_NAME_oneline(name, nil, 0);
    if b = nil then
       Exit(0);
    if b^ = #0 then
    begin
        OPENSSL_free(Pointer(b));
        Exit(1);
    end;
    s := b + 1;                  { skip the first slash }
    c := s;
    while true do
    begin
        if ( ( s^ = '/') and
             ( (ossl_isupper(s[1]))  and
               ( (s[2] = '=')  or ( (ossl_isupper(s[2]))  and  (s[3] = '=')) )
             )
           )  or  ( s^ = #0) then
        begin
            i := s - c;
            if BIO_write(bp, c, i) <> i  then
                goto _err ;
            c := s + 1;          { skip following slash }
            if s^ <> #0 then
            begin
                if BIO_write(bp, PUTF8Char(', '), 2) <> 2 then
                   goto _err ;
            end;
            Dec(l);
        end;
        if s^ = #0 then
           break;
        Inc(s);
        Dec(l);
    end;
    OPENSSL_free(Pointer(b));
    Exit(1);
 _err:
    ERR_raise(ERR_LIB_X509, ERR_R_BUF_LIB);
    OPENSSL_free(Pointer(b));
    Result := 0;
end;


function X509_NAME_get0_der(const nm : PX509_NAME; pder : PPByte; pderlen : Psize_t):integer;
begin
    { Make sure encoding is valid }
    if i2d_X509_NAME(nm, nil) <= 0 then
        Exit(0);
    if pder <> nil then
       pder^ := PByte( nm.bytes.data);
    if pderlen <> nil then
       pderlen^ := nm.bytes.length;
    Result := 1;
end;

function X509_NAME_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($4, 16, Pointer(0) , 0, @x509_name_ff, 0, 'X509_NAME');
   result := @local_it;
end;

function d2i_X509_NAME(a : PPX509_NAME;const _in : PPByte; len : long):PX509_NAME;
begin
 result :=  PX509_NAME(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, X509_NAME_it));
end;


function i2d_X509_NAME(const a : PX509_NAME; _out : PPByte):integer;
begin
 result :=  ASN1_item_i2d(PASN1_VALUE( a), _out, X509_NAME_it);
end;


function X509_NAME_new:PX509_NAME;
begin
   result :=  PX509_NAME( ASN1_item_new(X509_NAME_it));
end;


procedure X509_NAME_free( a : PX509_NAME);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_NAME_it);
end;

initialization

   X509_NAME_ENTRY_seq_tt[0]  := get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_NAME_ENTRY(0)._object), 'object', ASN1_OBJECT_it );
   X509_NAME_ENTRY_seq_tt[1]  := get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_NAME_ENTRY(0).value)  , 'value', ASN1_PRINTABLE_it );
   X509_NAME_INTERNAL_item_tt := get_ASN1_TEMPLATE(($2 shl 1), 0, 0, 'Name', X509_NAME_ENTRIES_it);
   X509_NAME_ENTRIES_item_tt  := get_ASN1_TEMPLATE(($1 shl 1), 0, 0, 'RDNS', X509_NAME_ENTRY_it);
end.
