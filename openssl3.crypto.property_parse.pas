unit openssl3.crypto.property_parse;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses  OpenSSL.Api, SysUtils;

type
  sk_OSSL_PROPERTY_DEFINITION_compfunc = function (const  a, b: POSSL_PROPERTY_DEFINITION):integer;
  sk_OSSL_PROPERTY_DEFINITION_freefunc = procedure(a: POSSL_PROPERTY_DEFINITION);
  sk_OSSL_PROPERTY_DEFINITION_copyfunc = function(const a: POSSL_PROPERTY_DEFINITION): POSSL_PROPERTY_DEFINITION;

  function ossl_property_parse_init( ctx : POSSL_LIB_CTX):integer;
  function ossl_parse_query(ctx : POSSL_LIB_CTX; s : PUTF8Char; create_values : integer):POSSL_PROPERTY_LIST;
  function sk_OSSL_PROPERTY_DEFINITION_num( sk : Pointer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_value( sk : Pointer;idx: integer):POSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_new( cmp : sk_OSSL_PROPERTY_DEFINITION_compfunc):PSTACK_st_OSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_new_null:PSTACK_st_OSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_new_reserve( cmp : sk_OSSL_PROPERTY_DEFINITION_compfunc; n : integer):PSTACK_st_OSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_reserve( sk : Pointer; n : integer):integer;
  procedure sk_OSSL_PROPERTY_DEFINITION_free( sk : Pointer);
  procedure sk_OSSL_PROPERTY_DEFINITION_zero( sk : Pointer);
  function sk_OSSL_PROPERTY_DEFINITION_delete( sk : Pointer; i : integer):POSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_delete_ptr( sk, ptr : Pointer):POSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_push( sk, ptr : Pointer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_unshift( sk, ptr : Pointer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_pop( sk : Pointer):POSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_shift( sk : Pointer):POSSL_PROPERTY_DEFINITION;
  procedure sk_OSSL_PROPERTY_DEFINITION_pop_free( sk : Pointer; freefunc : sk_OSSL_PROPERTY_DEFINITION_freefunc);
  function sk_OSSL_PROPERTY_DEFINITION_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_find( sk, ptr : Pointer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_find_ex( sk, ptr : Pointer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_OSSL_PROPERTY_DEFINITION_sort( sk : Pointer);
  function sk_OSSL_PROPERTY_DEFINITION_is_sorted( sk : Pointer):integer;
  function sk_OSSL_PROPERTY_DEFINITION_dup( sk : Pointer):PSTACK_st_OSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PROPERTY_DEFINITION_copyfunc; freefunc : sk_OSSL_PROPERTY_DEFINITION_freefunc):PSTACK_st_OSSL_PROPERTY_DEFINITION;
  function sk_OSSL_PROPERTY_DEFINITION_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PROPERTY_DEFINITION_compfunc):sk_OSSL_PROPERTY_DEFINITION_compfunc;
  function pd_compare(const p1, p2 : POSSL_PROPERTY_DEFINITION):integer;
  function skip_space(s : PUTF8Char):PUTF8Char;
  function match_ch(const t : PPUTF8Char; m : UTF8Char):Boolean;
  function parse_name(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; create : integer; idx : POSSL_PROPERTY_IDX):integer;
  function _match(const t : PPUTF8Char; m : PUTF8Char; m_len : size_t):integer;
  function parse_value(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION; create : integer):integer;
  function parse_string(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; delim : UTF8Char; res : POSSL_PROPERTY_DEFINITION;const create : integer):integer;
  function parse_number(const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION):integer;
  function parse_hex(const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION):integer;
  function parse_oct(const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION):integer;
  function parse_unquoted(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION;const create : integer):integer;
  function stack_to_property_list( ctx : POSSL_LIB_CTX; sk : Pstack_st_OSSL_PROPERTY_DEFINITION):POSSL_PROPERTY_LIST;
  procedure pd_free( pd : POSSL_PROPERTY_DEFINITION);
  procedure ossl_property_free( p : POSSL_PROPERTY_LIST);
  function ossl_property_merge(const a, b : POSSL_PROPERTY_LIST):POSSL_PROPERTY_LIST;
  function ossl_property_match_count(const query, defn : POSSL_PROPERTY_LIST):integer;
  function ossl_parse_property(ctx : POSSL_LIB_CTX;const defn : PUTF8Char):POSSL_PROPERTY_LIST;
  function ossl_property_list_to_string(ctx : POSSL_LIB_CTX;const list : POSSL_PROPERTY_LIST; buf : PUTF8Char; bufsize : size_t):size_t;
  procedure put_char( ch : UTF8Char; buf : PPUTF8Char; remain, needed : Psize_t);
  procedure put_str(const str : PUTF8Char; buf : PPUTF8Char; remain, needed : Psize_t);
  procedure put_num( val : int64; buf : PPUTF8Char; remain, needed : Psize_t);

implementation

uses
   openssl3.crypto.property_string, openssl3.crypto.stack,
   openssl3.crypto.ctype,           openssl3.crypto.bio.bio_print,
   openssl3.crypto.mem            , OpenSSL3.Err;

{$Q+}
procedure put_num( val : int64; buf : PPUTF8Char; remain, needed : Psize_t);
var
  tmpval : int64;
  len : size_t;
begin
    tmpval := val;
    len := 1;
    if tmpval < 0 then
    begin
        PostInc(len);
        tmpval := -tmpval;
    end;
    while tmpval > 9 do
    begin
       PostInc(len);
       tmpval := tmpval div (10);
    end;
    needed^  := needed^ + len;
    if remain^ = 0 then exit;
    BIO_snprintf( buf^, remain^, '%lld', [Int64(val)]);
    if remain^ < len then begin
        buf^  := buf^ + remain^;
        remain^ := 0;
    end
    else
    begin
        buf^  := buf^ + len;
        remain^  := remain^ - len;
    end;
end;



procedure put_str(const str : PUTF8Char; buf : PPUTF8Char; remain, needed : Psize_t);
var
  olen, len : size_t;
begin
    len := Length(str); olen := Length(str);
    needed^  := needed^ + len;
    if remain^ = 0 then exit;
    if remain^ < len + 1 then
       len := remain^ - 1;
    if len > 0 then begin
        strncpy( buf^, str, len);
        buf^  := buf^ + len;
        remain^  := remain^ - len;
    end;
    if (len < olen)  and  (remain^ = 1) then
    begin
        buf^^ := #0;
        Inc(buf^);
        Dec(remain^);
    end;
end;

procedure put_char( ch : UTF8Char; buf : PPUTF8Char; remain, needed : Psize_t);
begin
    if remain^ = 0 then begin
        Inc(needed^);
        Exit;
    end;
    if remain^ = 1 then
       buf^^ := #0
    else
        buf^^ := ch;
    Inc( buf^);
    Inc( needed^);
    Dec( remain^);
end;

function ossl_property_list_to_string(ctx : POSSL_LIB_CTX;const list : POSSL_PROPERTY_LIST; buf : PUTF8Char; bufsize : size_t):size_t;
var
  i : integer;
  prop : POSSL_PROPERTY_DEFINITION;
  needed : size_t;
  val : PUTF8Char;
begin
{$POINTERMATH ON}
    prop := nil;
    needed := 0;
    if list = nil then
    begin
        if bufsize > 0 then
            buf^ := #0;
        Exit(1);
    end;
    if list.num_properties <> 0 then
       prop := @list.properties[list.num_properties - 1];
    for i := 0 to list.num_properties - 1 do
    begin
        { Skip invalid names }
        if prop.name_idx = 0 then continue;
        if needed > 0 then
            put_char(',', @buf, @bufsize, @needed);
        if prop.optional > 0 then
            put_char('?', @buf, @bufsize, @needed)
        else
        if (prop.oper = OSSL_PROPERTY_OVERRIDE) then
            put_char('-', @buf, @bufsize, @needed);
        val := ossl_property_name_str(ctx, prop.name_idx);
        if val = nil then Exit(0);
        put_str(val, @buf, @bufsize, @needed);
        case prop.oper of
            OSSL_PROPERTY_OPER_NE:
                put_char('!', @buf, @bufsize, @needed);
                { fall through }
            OSSL_PROPERTY_OPER_EQ:
            begin
                put_char('=', @buf, @bufsize, @needed);
                { put value }
                case prop.&type of
                    OSSL_PROPERTY_TYPE_STRING:
                    begin
                        val := ossl_property_value_str(ctx, prop.v.str_val);
                        if val = nil then Exit(0);
                        put_str(val, @buf, @bufsize, @needed);
                    end;
                    OSSL_PROPERTY_TYPE_NUMBER:
                        put_num(prop.v.int_val, @buf, @bufsize, @needed);
                        //break;
                    else
                        Exit(0);
                end;
            end;
            else
                { do nothing }
             begin
                //break;
             end;
        end;
        Dec(prop);
    end;
    put_char(#0, @buf, @bufsize, @needed);
    Result := needed;
{$POINTERMATH OFF}
end;

function ossl_parse_property(ctx : POSSL_LIB_CTX;const defn : PUTF8Char):POSSL_PROPERTY_LIST;
var
  prop : POSSL_PROPERTY_DEFINITION;
  sk : Pstack_st_OSSL_PROPERTY_DEFINITION;
  s : PUTF8Char;
  done : Boolean;
  start : PUTF8Char;
  label _err;
begin
    prop := nil;
    result := nil;
    s := defn;
    sk := sk_OSSL_PROPERTY_DEFINITION_new(pd_compare);
    if (s = nil)  or  ( sk = nil) then
        Exit(nil);
    s := skip_space(s);
    done := (s^ = #0);
    while  not done do
    begin
        start := s;
        prop := OPENSSL_malloc(sizeof( prop^));
        if prop = nil then
           goto _err;
        FillChar(prop.v, sizeof(prop.v), 0);
        prop.optional := 0;
        if 0>=  parse_name(ctx, @s, 1, @prop.name_idx) then
           goto _err;
        prop.oper := OSSL_PROPERTY_OPER_EQ;
        if prop.name_idx = 0 then begin
            ERR_raise_data(ERR_LIB_PROP, PROP_R_PARSE_FAILED,
                           Format('Unknown name HERE-->%s', [start]));
            goto _err;
        end;
        if match_ch(@s, '=')  then
        begin
            if  0>= parse_value(ctx, @s, prop, 1) then
            begin
                ERR_raise_data(ERR_LIB_PROP, PROP_R_NO_VALUE,
                              Format('HERE-->%s', [start]));
                goto _err;
            end;
        end
        else
        begin
            { A name alone means a true Boolean }
            prop.&type := OSSL_PROPERTY_TYPE_STRING;
            prop.v.str_val := OSSL_PROPERTY_TRUE;
        end;
        if  0>= sk_OSSL_PROPERTY_DEFINITION_push(sk, prop)   then
            goto _err;
        prop := nil;
        done := not match_ch(@s, ',');
    end; //-->while  not done
    if s^ <> #0 then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_TRAILING_CHARACTERS,
                       Format('HERE-->%s', [s]) );
        goto _err;
    end;
    result := stack_to_property_list(ctx, sk);

_err:
    OPENSSL_free(prop);
    sk_OSSL_PROPERTY_DEFINITION_pop_free(sk, &pd_free);

end;

function ossl_property_match_count(const query, defn : POSSL_PROPERTY_LIST):integer;
var
  q, d : POSSL_PROPERTY_DEFINITION;
  eq :Boolean;
  i, j, matches : integer;
  oper : TOSSL_PROPERTY_OPER;
begin
{$POINTERMATH ON}
     q := @query.properties[0];
     d := @defn.properties[0];
    i := 0; j := 0; matches := 0;
    while i < query.num_properties do
    begin
        oper := q[i].oper ;
        if oper = OSSL_PROPERTY_OVERRIDE then
        begin
            Inc(i);
            continue;
        end;
        if j < defn.num_properties then
        begin
            if q[i].name_idx > d[j].name_idx then
            begin   { skip defn, not in query }
                Inc(j);
                continue;
            end;
            if q[i].name_idx = d[j].name_idx then
            begin  { both in defn and query }
                eq := (q[i].&type = d[j].&type )           and
                      (  memcmp(@q[i].v, @d[j].v, sizeof(q[i].v)) = 0);
                if ( (eq)  and  (oper = OSSL_PROPERTY_OPER_EQ)  )or
                   ( (not eq)  and  (oper = OSSL_PROPERTY_OPER_NE) )then
                    Inc(matches)
                else
                if ( 0>= q[i].optional) then
                    Exit(-1);
                Inc(i);
                Inc(j);
                continue;
            end;
        end;
        {
         * Handle the cases of a missing value and a query with no corresponding
         * definition.  The former fails for any comparison except inequality,
         * the latter is treated as a comparison against the Boolean false.
         }
        if q[i].&type = OSSL_PROPERTY_TYPE_VALUE_UNDEFINED then
        begin
            if oper = OSSL_PROPERTY_OPER_NE then
                Inc(matches)
            else
            if ( 0>= q[i].optional) then
                Exit(-1);
        end
        else
        if (q[i].&type <> OSSL_PROPERTY_TYPE_STRING)          or
           ( (oper = OSSL_PROPERTY_OPER_EQ) and
             (q[i].v.str_val <> OSSL_PROPERTY_FALSE) )        or
           ( (oper = OSSL_PROPERTY_OPER_NE)  and
             (q[i].v.str_val = OSSL_PROPERTY_FALSE) ) then
        begin
            if 0>= q[i].optional then
               Exit(-1);
        end
        else
        begin
            PostInc(matches);
        end;
        PostInc(i);
    end;
    Result := matches;
 {$POINTERMATH OFF}
end;

function ossl_property_merge(const a, b : POSSL_PROPERTY_LIST):POSSL_PROPERTY_LIST;
var
  ap, bp,
  copy : POSSL_PROPERTY_DEFINITION;
  r : POSSL_PROPERTY_LIST;
  i, j, n, t, count : integer;
begin
{$POINTERMATH ON}
    ap := @a.properties[0];
    bp := @b.properties[0];
    t := a.num_properties + b.num_properties;
    r := OPENSSL_malloc(sizeof( r^));
    count := get_result(t = 0 , 0 , t );
    SetLength(r.properties, count);

    if r = nil then Exit(nil);
    r.has_optional := 0;
    i := 0; j := 0; n := 0;
    while (i<a.num_properties)  or  (j < b.num_properties-1) do
    begin
        if i >= a.num_properties then
        begin
            copy := @bp[PostInc(j)];
        end
        else
        if (j >= b.num_properties) then
        begin
            copy := @ap[PostInc(i)];
        end
        else
        if (ap[i].name_idx <= bp[j].name_idx) then
        begin
            if ap[i].name_idx = bp[j].name_idx then
               Inc(j);
            copy := @ap[PostInc(i)];
        end
        else
        begin
           copy := @bp[PostInc(j)];
        end;
        memcpy(POSSL_PROPERTY_DEFINITION(@r.properties[0]) + n, copy, sizeof(r.properties[0]));
        r.has_optional  := r.has_optional  or copy.optional;
    end;
    r.num_properties := n;
    if n <> t then
       SetLength(r.properties, n);

    Result := r;
{$POINTERMATH OFF}
end;

procedure ossl_property_free( p : POSSL_PROPERTY_LIST);
begin
   if p = nil then
      Exit;
   //需要正确释放该动态数组，否则会在fpc中报raised exception class‘External SIGFPE’
   SetLength(p.properties, 0);
   OPENSSL_free(p);

end;


procedure pd_free( pd : POSSL_PROPERTY_DEFINITION);
begin
    OPENSSL_free(pd);
end;

function stack_to_property_list( ctx : POSSL_LIB_CTX; sk : Pstack_st_OSSL_PROPERTY_DEFINITION):POSSL_PROPERTY_LIST;
var
    n,count       : integer;
    prev_name_idx : OSSL_PROPERTY_IDX;
    i             : integer;
    value         : POSSL_PROPERTY_DEFINITION;
begin

    n := sk_OSSL_PROPERTY_DEFINITION_num(sk);
    prev_name_idx := 0;
    result := OPENSSL_malloc(sizeof(TOSSL_PROPERTY_LIST));
    count := get_result(n <= 0 , 0 , n);
    SetLength(result.properties, count);

    if result <> nil then
    begin
        sk_OSSL_PROPERTY_DEFINITION_sort(sk);
        result.has_optional := 0;
        for i := 0 to n-1 do
        begin
            value :=  sk_OSSL_PROPERTY_DEFINITION_value(sk, i);
            result.properties[i] := value^;
            result.has_optional  := result.has_optional  or (result.properties[i].optional);
            { Check for duplicated names }
            if (i > 0)  and  (result.properties[i].name_idx = prev_name_idx) then
            begin
                SetLength(result.properties, 0);
                OPENSSL_free(result);
                ERR_raise_data(ERR_LIB_PROP, PROP_R_PARSE_FAILED,
                              Format( 'Duplicated name `%s''',
                               [ossl_property_name_str(ctx, prev_name_idx)]));
                Exit(nil);
            end;
            prev_name_idx := result.properties[i].name_idx;
        end;
        result.num_properties := n;
    end;

end;

function parse_unquoted(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION;const create : integer):integer;
var
  v : array[0..999] of UTF8Char;
  s : PUTF8Char;
  i : size_t;
  err : Boolean;
begin
    s := t^;
    i := 0;
    err := Boolean(0);
    if (s^ = #0)  or  (s^ = ',') then Exit(0);
    while (ossl_isprint(s^))  and   (not ossl_isspace(s^) )  and  (s^ <> ',') do
    begin
        if i < sizeof(v)- 1 then
        begin
            v[i] := ossl_tolower( s^);
            Inc(i);
        end
        else
            err := Boolean(1);
        Inc(s);
    end;
    if  (not ossl_isspace( s^))   and ( s^ <> #0)  and  (s^ <> ',')then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_ASCII_CHARACTER,
                      Format('HERE->%s', [s]));
        Exit(0);
    end;
    v[i] := Chr(0);
    if err then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_STRING_TOO_LONG, Format('HERE-->%s', [t^]));
    end
    else
    begin
        res.v.str_val := ossl_property_value(ctx, v, create);
    end;
    t^ := skip_space(s);
    res.&type := OSSL_PROPERTY_TYPE_STRING;
    Result := int(not err);
end;

function parse_hex(const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION):integer;
var
  s : PUTF8Char;
  v : int64;
begin
    s := t^;
    v := 0;
    if  not ossl_isxdigit( s^) then
        Exit(0);
    repeat
        v  := v shl 4;
        if ossl_isdigit( s^ ) then
            v  := v + ( Ord(s^) - Ord('0'))
        else
            v  := v + (Ord(ossl_tolower( s^)) - Ord('a'));
    until (not ossl_isxdigit(PreInc(s)^));
    if  (not ossl_isspace( s^))  and  (s^ <> #0)  and  (s^ <> ',')then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_HEXADECIMAL_DIGIT,
                      Format('HERE-->%s', [t^]));
        Exit(0);
    end;
    t^ := skip_space(s);
    res.&type := OSSL_PROPERTY_TYPE_NUMBER;
    res.v.int_val := v;
    Result := 1;
end;


function parse_oct(const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION):integer;
var
  s : PUTF8Char;
  v : int64;
begin
    s := t^;
    v := 0;
    if (s^ = '9')  or  (s^ = '8')  or   (not ossl_isdigit( s^))  then
        Exit(0);
    repeat
        v := (v  shl  3) + ( Ord(s^) - Ord('0') );
    until not ( ossl_isdigit(PreInc(s)^)  and  (s^ <> '9')  and  (s^ <> '8'));
    if  (not ossl_isspace( s^))  and  (s^ <> #0)  and  (s^ <> ',') then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_OCTAL_DIGIT,
                       Format('HERE-->%s', [t^]));
        Exit(0);
    end;
    t^ := skip_space(s);
    res.&type := OSSL_PROPERTY_TYPE_NUMBER;
    res.v.int_val := v;
    Result := 1;
end;

function parse_number(const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION):integer;
var
  s : PUTF8Char;
  v : int64;
begin
    s := t^;
    v := 0;
    if  not ossl_isdigit(s^)  then
        Exit(0);
    repeat
        v := v * 10 + ( Ord(s^) - Ord('0'));
        Inc(s);
    until (not ossl_isdigit( s^));

    if  (not ossl_isspace(s^) ) and  (s^ <> #0)  and  (s^ <> ',')then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_A_DECIMAL_DIGIT,
                      Format('HERE-->%s', [t^]));
        Exit(0);
    end;
    t^ := skip_space(s);
    res.&type := OSSL_PROPERTY_TYPE_NUMBER;
    res.v.int_val := v;
    Result := 1;
end;

function parse_string(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; delim : UTF8Char; res : POSSL_PROPERTY_DEFINITION;const create : integer):integer;
var
  v : array[0..999] of UTF8Char;
  s : PUTF8Char;
  i : size_t;
  err : integer;
begin
    s := t^;
    i := 0;
    err := 0;
    while (s^ <> #0)  and  (s^ <> delim) do
    begin
        if i < sizeof(v) - 1  then
            v[PostInc(i)] := s^
        else
            err := 1;
        Inc(s);
    end;
    if s^ = #0 then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NO_MATCHING_STRING_DELIMITER,
                      Format('HERE-->%c%s', [delim, t^]));
        Exit(0);
    end;
    v[i] := #0;
    if err>0 then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_STRING_TOO_LONG,Format('HERE-->%s', [t^]));
    end
    else
    begin
        res.v.str_val := ossl_property_value(ctx, v, create);
    end;
    t^ := skip_space(s + 1);
    res.&type := OSSL_PROPERTY_TYPE_STRING;
    Result :=  not err;
end;



function parse_value(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; res : POSSL_PROPERTY_DEFINITION; create : integer):integer;
var
  s : PUTF8Char;
  r : integer;
begin
    s := t^;
    r := 0;
    if (s^ = '"')  or  (s^ = '''') then
    begin
        Inc(s);
        r := parse_string(ctx, @s, s[-1], res, create);
    end
    else
    if ( s^ = '+') then
    begin
        Inc(s);
        r := parse_number(@s, res);
    end
    else
    if ( s^ = '-') then
    begin
      Inc(s);
      r := parse_number(@s, res);
      res.v.int_val := -res.v.int_val;
    end
    else
    if ( s^ = '0')  and  (s[1] = 'x') then
    begin
        s  := s + 2;
        r := parse_hex(@s, res);
    end
    else
    if ( s^ = '0')  and  (ossl_isdigit(s[1])) then
    begin
      Inc(s);
      r := parse_oct(@s, res);
    end
    else
    if (ossl_isdigit( s^)) then
    begin
       Exit(parse_number(t, res));
    end
    else
    if (ossl_isalpha( s^)) then
       Exit(parse_unquoted(ctx, t, res, create));
    if r > 0 then
       t^ := s;
    Result := r;
end;

function MATCH(s, m: PUTF8Char): Integer;
begin
   Result := _match(@s, m, sizeof(m) - 1)
end;

function _match(const t : PPUTF8Char; m : PUTF8Char; m_len : size_t):integer;
var
  s : PUTF8Char;
begin
  s := t^;
  if strncasecmp(s, m, m_len) = 0 then
  begin
      t^ := skip_space(s + m_len);
      Exit(1);
  end;
  Result := 0;
end;

function parse_name(ctx : POSSL_LIB_CTX;const t : PPUTF8Char; create : integer; idx : POSSL_PROPERTY_IDX):integer;
var
    name      : array[0..99] of UTF8Char;
    err       : integer;
    i         : size_t;
    s         : PUTF8Char;
    user_name : integer;
begin
    err := 0;
    i := 0;
    s := t^;
    user_name := 0;
    FillChar(name, sizeof(name), Ord(#0));
    while True do
    begin
        if  not ossl_isalpha(s^ )  then
        begin
            ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_IDENTIFIER,
                           Format('HERE-->%s', [t^]));
            Exit(0);
        end;
        repeat
            if i < sizeof(name)- 1    then
                name[PostInc(i)] := ossl_tolower(s^)
            else
                err := 1;
        until not ( (PreInc(s)^ =  '_')  or  (ossl_isalnum(s^)) );
        if s^ <> '.' then break;
        user_name := 1;
        if i < sizeof(name)- 1  then
            name[PostInc(i)] := s^
        else
            err := 1;
        Inc(s);
    end;
    name[i] := #0;
    if err>0 then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NAME_TOO_LONG, Format('HERE-->%s', [t^]));
        Exit(0);
    end;
    t^ := skip_space(s);
    idx^ := ossl_property_name(ctx, name, Int( (user_name >0) and (create > 0) ) );
    Result := 1;
end;

function match_ch(const t : PPUTF8Char; m : UTF8Char):Boolean;
var
  s : PUTF8Char;
begin
    s := t^;
    if s^ = m then
    begin
       t^ := skip_space(s + 1);
        Exit(true);
    end;
    Result := Boolean(0);
end;

function skip_space(s : PUTF8Char):PUTF8Char;
begin
    while ossl_isspace( s^) do
        Inc(s);
    Result := s;
end;

function pd_compare(const p1, p2 : POSSL_PROPERTY_DEFINITION):integer;
begin
    if p1.name_idx < p2.name_idx then Exit(-1);
    if p1.name_idx > p2.name_idx then Exit(1);
    Result := 0;
end;


function sk_OSSL_PROPERTY_DEFINITION_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROPERTY_DEFINITION_value( sk : Pointer; idx: integer):POSSL_PROPERTY_DEFINITION;
begin
   Result := POSSL_PROPERTY_DEFINITION(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_OSSL_PROPERTY_DEFINITION_new( cmp : sk_OSSL_PROPERTY_DEFINITION_compfunc):PSTACK_st_OSSL_PROPERTY_DEFINITION;
begin
   Result := OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp));
end;


function sk_OSSL_PROPERTY_DEFINITION_new_null:PSTACK_st_OSSL_PROPERTY_DEFINITION;
begin
   Result := PSTACK_st_OSSL_PROPERTY_DEFINITION (OPENSSL_sk_new_null())
end;


function sk_OSSL_PROPERTY_DEFINITION_new_reserve( cmp : sk_OSSL_PROPERTY_DEFINITION_compfunc; n : integer):PSTACK_st_OSSL_PROPERTY_DEFINITION;
begin
   Result := PSTACK_st_OSSL_PROPERTY_DEFINITION (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_OSSL_PROPERTY_DEFINITION_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_OSSL_PROPERTY_DEFINITION_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_OSSL_PROPERTY_DEFINITION_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROPERTY_DEFINITION_delete( sk : Pointer; i : integer):POSSL_PROPERTY_DEFINITION;
begin
   Result := POSSL_PROPERTY_DEFINITION(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_OSSL_PROPERTY_DEFINITION_delete_ptr( sk, ptr : Pointer):POSSL_PROPERTY_DEFINITION;
begin
   Result := POSSL_PROPERTY_DEFINITION(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_OSSL_PROPERTY_DEFINITION_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), ptr)
end;


function sk_OSSL_PROPERTY_DEFINITION_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROPERTY_DEFINITION_pop( sk : Pointer):POSSL_PROPERTY_DEFINITION;
begin
   Result := POSSL_PROPERTY_DEFINITION(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PROPERTY_DEFINITION_shift( sk : Pointer):POSSL_PROPERTY_DEFINITION;
begin
   Result := POSSL_PROPERTY_DEFINITION(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_OSSL_PROPERTY_DEFINITION_pop_free( sk : Pointer; freefunc : sk_OSSL_PROPERTY_DEFINITION_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc))
end;


function sk_OSSL_PROPERTY_DEFINITION_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_OSSL_PROPERTY_DEFINITION_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PROPERTY_DEFINITION;
begin
   Result := POSSL_PROPERTY_DEFINITION(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_OSSL_PROPERTY_DEFINITION_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROPERTY_DEFINITION_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PROPERTY_DEFINITION_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_OSSL_PROPERTY_DEFINITION_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROPERTY_DEFINITION_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_OSSL_PROPERTY_DEFINITION_dup( sk : Pointer):PSTACK_st_OSSL_PROPERTY_DEFINITION;
begin
   Result := PSTACK_st_OSSL_PROPERTY_DEFINITION (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PROPERTY_DEFINITION_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PROPERTY_DEFINITION_copyfunc; freefunc : sk_OSSL_PROPERTY_DEFINITION_freefunc):PSTACK_st_OSSL_PROPERTY_DEFINITION;
begin
   Result := PSTACK_st_OSSL_PROPERTY_DEFINITION (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_OSSL_PROPERTY_DEFINITION_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PROPERTY_DEFINITION_compfunc):sk_OSSL_PROPERTY_DEFINITION_compfunc;
begin
   Result := sk_OSSL_PROPERTY_DEFINITION_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;

function ossl_parse_query(ctx : POSSL_LIB_CTX; s : PUTF8Char; create_values : integer):POSSL_PROPERTY_LIST;
var
    sk         : Pstack_st_OSSL_PROPERTY_DEFINITION;
    prop       : POSSL_PROPERTY_DEFINITION;
    done       : Boolean;
    label _err, _skip_value;
begin
    result := nil;
    prop := nil;
    sk := sk_OSSL_PROPERTY_DEFINITION_new(pd_compare);
    if (s = nil)  or  (sk = nil)  then
        Exit(nil);
    s := skip_space(s);
    done := (s^ = #0);
    while  not done do
    begin
        prop := OPENSSL_malloc(sizeof( prop^));
        if prop = nil then
           goto _err;
        memset(@prop.v, 0, sizeof(prop.v));
        if match_ch(@s, '-' ) then
        begin
            prop.oper := OSSL_PROPERTY_OVERRIDE;
            prop.optional := 0;
            if  0>= parse_name(ctx, @s, 1, @prop.name_idx )then
               goto _err;
            goto _skip_value;
        end;
        prop.optional := Int( match_ch(@s, '?'));
        if  0>= parse_name(ctx, @s, 1, @prop.name_idx )  then
            goto _err;
        if match_ch(@s, '=') then
        begin
            prop.oper := OSSL_PROPERTY_OPER_EQ;
        end
        else
        if MATCH(@s, '!=') > 0 then  //"!="
        begin
            prop.oper := OSSL_PROPERTY_OPER_NE;
        end
        else
        begin
            { A name alone is a Boolean comparison for true }
            prop.oper := OSSL_PROPERTY_OPER_EQ;
            prop.&type := OSSL_PROPERTY_TYPE_STRING;
            prop.v.str_val := OSSL_PROPERTY_TRUE;
            goto _skip_value;
        end;
        if  0>= parse_value(ctx, @s, prop, create_values ) then
            prop.&type := OSSL_PROPERTY_TYPE_VALUE_UNDEFINED;
_skip_value:
        if  0>= sk_OSSL_PROPERTY_DEFINITION_push(sk, prop)  then
             goto _err;
        prop := nil;
        done := not match_ch(@s, ',');
    end;
    if s^ <> #0 then
    begin
        ERR_raise_data(ERR_LIB_PROP, PROP_R_TRAILING_CHARACTERS,
                      Format('HERE-->%s', [s]));
         goto _err;
    end;
    result := stack_to_property_list(ctx, sk);

_err:
    OPENSSL_free(prop);
    sk_OSSL_PROPERTY_DEFINITION_pop_free(sk, @pd_free);

end;

const
    predefined_names: array[0..5] of PUTF8Char = (
        'provider',     { Name of provider (default, legacy, fips) }
        'version',      { Version number of this provider }
        'fips',         { FIPS validated or FIPS supporting algorithm }
        'output',       { Output type for encoders }
        'input',        { Input type for decoders }
        'structure'    { Structure name for encoders and decoders }
    );

function ossl_property_parse_init( ctx : POSSL_LIB_CTX):integer;
var
  i : size_t;
  label err;
begin
    for i := 0 to Length(predefined_names)-1 do
    begin
        //if i = 4 then
          // writeln('catch bug!!');
        if ossl_property_name(ctx, predefined_names[i], 1)  = 0 then
           goto err;
    end;
    {
     * Pre-populate the two Boolean values. We must do them before any other
     * values and in this order so that we get the same index as the global
     * OSSL_PROPERTY_TRUE and OSSL_PROPERTY_FALSE values
     }
    if (ossl_property_value(ctx, 'yes', 1) <> OSSL_PROPERTY_TRUE )   or
       (ossl_property_value(ctx, 'no', 1)  <> OSSL_PROPERTY_FALSE ) then
       goto err;
    Exit(1);
err:
    Result := 0;
end;

end.
