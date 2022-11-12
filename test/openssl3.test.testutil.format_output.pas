unit openssl3.test.testutil.format_output;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api, SysUtils;

const
  MEM_BUFFER_SIZE   =  (2000);
  MAX_STRING_WIDTH  =  (80)  ;
  BN_OUTPUT_SIZE    =  (8)   ;

  procedure test_fail_memory_message(const prefix, &type, left, right, op : PUTF8Char; m1 : PByte; l1 : size_t;const m2 : PByte; l2 : size_t);
procedure test_fail_memory_common(const prefix, &type, left, right, op : PUTF8Char; m1 : PByte; l1 : size_t;{const} m2 : PByte; l2 : size_t);
 procedure test_memory_null_empty(const m : PByte; c : UTF8Char);
 procedure test_diff_header(const left, right : PUTF8Char);
 procedure test_string_null_empty(const m : PUTF8Char; c : UTF8Char);
 procedure hex_convert_memory({const} m : PByte; n : size_t; b : PUTF8Char; width : size_t);
 procedure test_fail_string_message(const prefix, &type, left, right, op, m1 : PUTF8Char; l1 : size_t;const m2 : PUTF8Char; l2 : size_t);

procedure test_fail_string_common(const prefix, &type, left, right, op: PUTF8Char; m1 : PUTF8Char; l1 : size_t; m2 : PUTF8Char; l2 : size_t);
procedure test_fail_bignum_message(const prefix : PUTF8Char; const &type, left, right, op : PUTF8Char; bn1, bn2 : PBIGNUM);
procedure test_fail_bignum_common(const prefix, &type, left, right, op : PUTF8Char; bn1, bn2 : PBIGNUM);

procedure test_bignum_header_line;
procedure test_fail_bignum_mono_message(const prefix: PUTF8Char; const &type, left, right, op : PUTF8Char; bn : PBIGNUM);

implementation


uses openssl3.test.testutil.tests,            openssl3.test.testutil.basic_output,
     openssl3.test.testutil.output,           openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bio.bio_lib,              Character,
     openssl3.crypto.mem;

const bn_bytes: int = (MAX_STRING_WIDTH - 9) div (BN_OUTPUT_SIZE * 2 + 1) * BN_OUTPUT_SIZE;
      bn_chars: int = (MAX_STRING_WIDTH - 9) div (BN_OUTPUT_SIZE * 2 + 1) * (BN_OUTPUT_SIZE * 2 + 1) - 1;


procedure test_fail_bignum_mono_message(const prefix: PUTF8Char; const &type, left, right, op : PUTF8Char; bn : PBIGNUM);
begin
    test_fail_bignum_common(prefix, &type, left, right, op, bn, bn);
    test_printf_stderr(#10, []);
end;

function convert_bn_memory(const &in : PByte; bytes : size_t; &out : PUTF8Char; lz : PInteger;const bn : PBIGNUM):integer;
var
  n, i : integer;
  p, q, r : PUTF8Char;
begin
    n := bytes * 2;
    p := &out; q := nil;
    if (bn <> nil)  and  (not BN_is_zero(bn)) then
    begin
        hex_convert_memory(&in, bytes, &out, BN_OUTPUT_SIZE);
        if lz^ > 0 then
        begin
            while (p^ = '0')  or  (p^ = ' ') do
            begin
                if p^ = '0' then
                begin
                    q := p;
                    p^ := ' ';
                    Dec(n);
                end;
                Inc(p);
            end;
            if p^ = #0 then
            begin
                {
                 * in[bytes] is defined because we're converting a non-zero
                 * number and we've not seen a non-zero yet.
                 }
                if ( (&in[bytes] and $f0) <> 0)  and  (BN_is_negative(bn) > 0) then
                begin
                    lz^ := 0;
                    q^ := '-';
                    Inc(n);
                end;
            end
            else
            begin
                lz^ := 0;
                if BN_is_negative(bn) > 0 then
                begin
                    {
                     * This is valid because we always convert more digits than
                     * the number holds.
                     }
                    q^ := '-';
                    Inc(n);
                end;
            end;
        end;
       Exit(n);
    end;
    for i := 0 to n-1 do
    begin
        PostInc(p)^ := ' ';
        if (i mod (2 * BN_OUTPUT_SIZE) = 2 * BN_OUTPUT_SIZE - 1)  and  (i <> n - 1) then
            PostInc(p)^ := ' ';
    end;
    p^ := #0;
    if bn = nil then
       r := 'nil'
    else
        r := get_result( BN_is_negative(bn)>0 , '-0' , '0');
    strcpy(p - strlen(r), r);
    Result := 0;
end;

procedure test_bignum_header_line;
begin
    test_printf_stderr(' %*s'#10, [bn_chars + 6, 'bit position']);
end;

function test_bignum_zero_null(const bn : PBIGNUM):PUTF8Char;
begin
    if bn <> nil then
       Exit(get_result(BN_is_negative(bn) > 0, '-0' , '0'));
    Result := 'nil';
end;

procedure test_bignum_zero_print(const bn : PBIGNUM; sep : UTF8Char);
var
  v : PUTF8Char;
  suf : PUTF8Char ;
begin
    v := test_bignum_zero_null(bn);
    suf := get_result(bn <> nil , ':    0' , '');
    test_printf_stderr('%c%*s%s'#10, [sep, bn_chars, v, suf]);
end;

procedure test_fail_bignum_common(const prefix, &type, left, right, op : PUTF8Char; bn1, bn2 : PBIGNUM);
var
  bytes     : size_t;
  b1, b2, bdiff    : array[0..MAX_STRING_WIDTH] of UTF8Char;
  l1,l2,n1,n2,i,len       : size_t;
  cnt,
  diff,
  real_diff : uint32;
  m1, m2        : PByte;
  lz1, lz2       : integer;
  p: PUTF8Char ;
  buffer: array[0..MEM_BUFFER_SIZE * 2-1] of Byte;
  bufp: PByte;
  label _fin;
begin
    bytes := bn_bytes;
    m1 := nil; m2 := nil;
    lz1 := 1; lz2 := 1;
    bufp := @buffer;
    test_fail_message_prefix(prefix, &type, left, right, op);
    l1 := get_result(bn1 = nil , 0 , (BN_num_bytes(bn1) + get_result(BN_is_negative(bn1) > 0, 1 , 0)));
    l2 := get_result(bn2 = nil , 0 , (BN_num_bytes(bn2) + get_result(BN_is_negative(bn2) > 0, 1 , 0)));
    if (l1 = 0)  and  (l2 = 0) then
    begin
        if Boolean(bn1 = nil) = Boolean(bn2 = nil) then
        begin
            test_bignum_header_line;
            test_bignum_zero_print(bn1, ' ');
        end
        else
        begin
            test_diff_header(left, right);
            test_bignum_header_line;
            test_bignum_zero_print(bn1, '-');
            test_bignum_zero_print(bn2, '+');
        end;
        goto _fin;
    end;
    if (l1 <> l2)  or  (bn1 = nil)  or  (bn2 = nil)  or  (BN_cmp(bn1, bn2) <> 0) then
        test_diff_header(left, right);
    test_bignum_header_line;
    len := (get_result(l1 > l2 , l1 , l2) + bytes - 1) div bytes * bytes;
    if (len > MEM_BUFFER_SIZE) then
    begin
        bufp := OPENSSL_malloc(len * 2);
        if bufp = nil  then
        begin
          bufp := @buffer;
          len := MEM_BUFFER_SIZE;
          test_printf_stderr('WARNING: these BIGNUMs have been truncated'#10, []);
        end;
    end;
    if bn1 <> nil then begin
        m1 := bufp;
        BN_bn2binpad(bn1, m1, len);
    end;
    if bn2 <> nil then begin
        m2 := bufp + len;
        BN_bn2binpad(bn2, m2, len);
    end;
    while len > 0 do
    begin
        cnt := 8 * (len - bytes);
        n1 := convert_bn_memory(m1, bytes, @b1, @lz1, bn1);
        n2 := convert_bn_memory(m2, bytes, @b2, @lz2, bn2);
        diff := 0; real_diff := 0;
        i := 0;
        p := @bdiff;
        i := 0;
        while b1[i] <> #0 do
        begin
            if (b1[i] = b2[i])  or  (b1[i] = ' ')  or  (b2[i] = ' ') then
            begin
                PostInc(p)^ := ' ';
                diff  := diff  or int(b1[i] <> b2[i]);
            end
            else
            begin
                PostInc(p)^ := '^';
                real_diff := 1; diff := 1;
            end;
            PostInc(i);
        end;
        PostInc(p)^ := #0;
        if 0>=diff then
        begin
            test_printf_stderr(' %s:% 5d'#10, [get_result(n2 > n1 , PUTF8Char(@b2) , PUTF8Char(@b1)), cnt]);
        end
        else
        begin
            if (cnt = 0)  and  (bn1 = nil) then
               test_printf_stderr('-%s'#10, [b1])
            else if (cnt = 0)  or  (n1 > 0) then
                test_printf_stderr('-%s:% 5d'#10, [b1, cnt]);
            if (cnt = 0)  and  (bn2 = nil) then
                test_printf_stderr('+%s'#10, [b2])
            else if (cnt = 0)  or  (n2 > 0) then
                test_printf_stderr('+%s:% 5d'#10, [b2, cnt]);
            if (real_diff > 0) and ( (cnt = 0)  or  ((n1 > 0)  and  (n2 > 0)) )
                     and  (bn1 <> nil)  and  (bn2 <> nil) then
                test_printf_stderr(' %s'#10, [bdiff]);
        end;
        if m1 <> nil then m1  := m1 + bytes;
        if m2 <> nil then m2  := m2 + bytes;
        len  := len - bytes;
    end;
_fin:
    test_flush_stderr;
    if bufp <> @buffer then
       OPENSSL_free(bufp);
end;

procedure test_fail_bignum_message(const prefix : PUTF8Char; const &type, left, right, op : PUTF8Char; bn1, bn2 : PBIGNUM);
begin
    test_fail_bignum_common(prefix, &type, left, right, op, bn1, bn2);
    test_printf_stderr(#10, []);
end;



procedure test_fail_string_common(const prefix, &type, left, right, op: PUTF8Char; m1 : PUTF8Char; l1 : size_t; m2 : PUTF8Char; l2 : size_t);
var
  width : size_t;
  b1, b2: array[0..MAX_STRING_WIDTH + 1-1] of UTF8Char;
  bdiff : array[0..MAX_STRING_WIDTH + 1-1] of UTF8Char;
  n1, n2, i : size_t;
  cnt, diff : uint32;
  j : size_t;
  label _fin;
begin
    width := (MAX_STRING_WIDTH - BIO_get_indent(bio_err) - 12) div 16 * 16;

    cnt := 0;
    test_fail_message_prefix(prefix, &type, left, right, op);
    if m1 = nil then l1 := 0;
    if m2 = nil then l2 := 0;
    if (l1 = 0)  and  (l2 = 0) then
    begin
        if (m1 = nil) = (m2 = nil) then  begin
            test_string_null_empty(m1, ' ');
        end
        else begin
            test_diff_header(left, right);
            test_string_null_empty(m1, '-');
            test_string_null_empty(m2, '+');
        end;
        goto _fin;
    end;
    if (l1 <> l2)  or  (strncmp(m1, m2, l1) <> 0) then
        test_diff_header(left, right);
    while (l1 > 0)  or  (l2 > 0) do
    begin
        n1 := 0; n2 := 0;
        if l1 > 0 then begin
            n1 := get_result(l1 > width , width , l1);
            b1[n1] := Char(0);
            for i := 0 to n1-1 do
                b1[i] := get_result(isprint(Byte(m1[i])) >0, m1[i] , '.');
        end;
        if l2 > 0 then
        begin
            n2 := get_result(l2 > width , width , l2);
            b2[n2] := #0;
            for i := 0 to n2-1 do
                b2[i] := get_result(isprint(Byte(m2[i])) > 0, m2[i] , '.');
        end;
        diff := 0;
        i := 0;
        if (n1 > 0)  and  (n2 > 0) then
        begin
           j := get_result(n1 < n2 , n1 , n2);
           while  i < j do
           begin
                if m1[i] = m2[i] then begin
                    bdiff[i] := ' ';
                end
                else begin
                    bdiff[i] := '^';
                    diff := 1;
                end;
                Inc(i);
           end;
            bdiff[i] := #0;
        end;
        if (n1 = n2)  and  (0>=diff) then begin
            test_printf_stderr('%4u:  ''%s'''#10,
                                [cnt, get_result(n2 > n1 , b2 , b1)]);
        end
        else
        begin
            if (cnt = 0)  and ( (m1 = nil)  or  (m1^ = #0) ) then
                test_string_null_empty(m1, '-')
            else if (n1 > 0) then
                test_printf_stderr('%4u:- ''%s'''#10, [cnt, b1]);
            if (cnt = 0)  and ( (m2 = nil)  or  (m2^ = #0) ) then
               test_string_null_empty(m2, '+')
            else if (n2 > 0) then
                test_printf_stderr('%4u:+ ''%s'''#10, [cnt, b2]);
            if (diff > 0)  and  (i > 0) then
               test_printf_stderr('%4s    %s'#10, ['', bdiff]);
        end;
        if m1 <> nil then m1  := m1 + n1;
        if m2 <> nil then m2  := m2 + n2;
        l1  := l1 - n1;
        l2  := l2 - n2;
        cnt  := cnt + width;
    end;
_fin:
    test_flush_stderr;
end;


procedure test_fail_string_message(const prefix, &type, left, right, op, m1 : PUTF8Char; l1 : size_t;const m2 : PUTF8Char; l2 : size_t);
begin
    test_fail_string_common(prefix,  &type, left, right, op,
                            m1, l1, m2, l2);
    test_printf_stderr(#10,[]);
end;




procedure hex_convert_memory({const} m : PByte; n : size_t; b : PUTF8Char; width : size_t);
var
  i : size_t;
  c : Byte;
begin
    for i := 0 to n-1 do
    begin
         c := m^;
         Inc(m);
        PostInc(b)^ := PUTF8Char('0123456789abcdef')[c  shr  4];
        PostInc(b)^ := PUTF8Char('0123456789abcdef')[c and 15];
        if (i mod width = width - 1)  and  (i <> n - 1) then
           PostInc(b)^ := ' ';
    end;
    b^ := #0;
end;


procedure test_string_null_empty(const m : PUTF8Char; c : UTF8Char);
begin
    if m = nil then
       test_printf_stderr('%4s %c nil'#10, ['', c])
    else
        test_printf_stderr('%4u:%c '''#10, [0, c]);
end;





procedure test_diff_header(const left, right : PUTF8Char);
begin
    test_printf_stderr('--- %s'#10, [left]);
    test_printf_stderr('+++ %s'#10, [right]);
end;


procedure test_memory_null_empty(const m : PByte; c : UTF8Char);
begin
    if m = nil then
       test_printf_stderr('%4s %c%s'#10, ['', c, 'nil'])
    else
       test_printf_stderr('%04x %c%s'#10, [0, c, 'empty']);
end;

procedure test_fail_memory_common(const prefix, &type, left, right, op : PUTF8Char; m1 : PByte; l1 : size_t;{const} m2 : PByte; l2 : size_t);
var
  _bytes : size_t;
  b1, b2 : array[0..(MAX_STRING_WIDTH + 1)-1] of UTF8Char;
  p : PUTF8Char;
  bdiff : array[0..(MAX_STRING_WIDTH + 1)-1] of UTF8Char;
  n1, n2, i : size_t;
  cnt, diff : uint32;
  j : size_t;
  label _fin;
  //j : size_t = n1 < n2 ? n1 : n2;
begin
    _bytes := (MAX_STRING_WIDTH - 9) div 17 * 8;
    cnt := 0;
    test_fail_message_prefix(prefix, &type, left, right, op);
    if m1 = nil then l1 := 0;
    if m2 = nil then l2 := 0;
    if (l1 = 0)  and  (l2 = 0) then
    begin
        if (m1 = nil) = (m2 = nil) then
        begin
            test_memory_null_empty(m1, ' ');
        end
        else
        begin
            test_diff_header(left, right);
            test_memory_null_empty(m1, '-');
            test_memory_null_empty(m2, '+');
        end;
        goto _fin;
    end;
    if (l1 <> l2)  or  ( (m1 <> m2)  and  (memcmp(m1, m2, l1) <> 0)) then
        test_diff_header(left, right);
    while (l1 > 0)  or  (l2 > 0) do
    begin
        n1 := 0;n2 := 0;
        if l1 > 0 then begin
            n1 := get_result(l1 > _bytes , _bytes , l1);
            hex_convert_memory(m1, n1, b1, 8);
        end;
        if l2 > 0 then begin
            n2 := get_result(l2 > _bytes , _bytes , l2);
            hex_convert_memory(m2, n2, b2, 8);
        end;
        diff := 0;
        i := 0;
        p := bdiff;
        if (n1 > 0)  and  (n2 > 0) then
        begin
            j := get_result(n1 < n2 , n1 , n2);
            while i < j do
            begin
                if m1[i] = m2[i] then
                begin
                    PostInc(p)^ := ' ';
                    PostInc(p)^ := ' ';
                end
                else begin
                    PostInc(p)^ := '^';
                    PostInc(p)^ := '^';
                    diff := 1;
                end;
                if (i mod 8 = 7)  and  (i <> j - 1) then
                   PostInc(p)^ := ' ';
                PostInc(i);
            end;
            PostInc(p)^ := #0;
        end;
        if (n1 = n2)  and  (0>=diff) then
        begin
            test_printf_stderr('%04x: %s'#10, [cnt, b1]);
        end
        else
        begin
            if (cnt = 0)  and ( (m1 = nil)  or  (l1 = 0) ) then
                test_memory_null_empty(m1, '-')
            else if (n1 > 0) then
                test_printf_stderr('%04x:-%s'#10, [cnt, b1]);
            if (cnt = 0)  and ( (m2 = nil)  or  (l2 = 0) ) then
                test_memory_null_empty(m2, '+')
            else if (n2 > 0) then
                test_printf_stderr('%04x:+%s'#10, [cnt, b2]);
            if diff  and  i > 0 then
               test_printf_stderr('%4s  %s'#10, ['', bdiff]);
        end;
        if m1 <> nil then m1  := m1 + n1;
        if m2 <> nil then m2  := m2 + n2;
        l1  := l1 - n1;
        l2  := l2 - n2;
        cnt  := cnt + _bytes;
    end;
_fin:
    test_flush_stderr;
end;


procedure test_fail_memory_message(const prefix, &type, left, right, op : PUTF8Char; m1 : PByte; l1 : size_t;const m2 : PByte; l2 : size_t);
begin
    test_fail_memory_common(prefix,  &type, left, right, op,
                            m1, l1, m2, l2);
    test_printf_stderr(#10, []);
end;


end.
