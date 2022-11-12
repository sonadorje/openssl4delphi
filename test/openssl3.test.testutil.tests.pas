unit openssl3.test.testutil.tests;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api, SysUtils;

  function test_int_eq(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
  function test_int_ne(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
  function test_int_lt(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
  function test_int_le(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
  function test_int_gt(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
  function test_int_ge(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
  function test_uint_eq(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
  function test_uint_ne(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
  function test_uint_lt(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
  function test_uint_le(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
  function test_uint_gt(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
  function test_uint_ge(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
  function test_char_eq(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
  function test_char_ne(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
  function test_char_lt(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
  function test_char_le(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
  function test_char_gt(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
  function test_char_ge(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
  function test_uchar_eq(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
  function test_uchar_ne(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
  function test_uchar_lt(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
  function test_uchar_le(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
  function test_uchar_gt(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
  function test_uchar_ge(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
  function test_long_eq(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
  function test_long_ne(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
  function test_long_lt(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
  function test_long_le(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
  function test_long_gt(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
  function test_long_ge(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
  function test_ulong_eq(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
  function test_ulong_ne(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
  function test_ulong_lt(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
  function test_ulong_le(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
  function test_ulong_gt(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
  function test_ulong_ge(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
  function test_size_t_eq(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
  function test_size_t_ne(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
  function test_size_t_lt(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
  function test_size_t_le(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
  function test_size_t_gt(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
  function test_size_t_ge(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
  function test_double_eq(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
  function test_double_ne(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
  function test_double_lt(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
  function test_double_le(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
  function test_double_gt(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
  function test_double_ge(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
  function test_ptr_eq(const s1, s2 : PUTF8Char; t1, t2 : Pointer):integer;
  function test_ptr_ne(const s1, s2 : PUTF8Char; t1, t2 : Pointer):integer;

 procedure test_fail_message(const prefix, _type, left, right, op, fmt :PUTF8Char;
                            ap: array of const );
 procedure test_fail_message_va(const prefix : PUTF8Char;
                               const _type, left, right, op, fmt :PUTF8Char;
                               ap: array of const);
 procedure test_fail_message_prefix(const prefix, _type, left, right, op : PUTF8Char);

function test_mem_eq(const st1, st2 : PUTF8Char;const s1 : Pointer; n1 : size_t;const s2 : Pointer; n2 : size_t):integer;

function test_ptr_null(const s : PUTF8Char; p : Pointer):integer;
function test_ptr(const s : PUTF8Char; p : Pointer):integer;
function test_true(const s : PUTF8Char; b : integer):integer;
function test_false(const s : PUTF8Char; b : integer):integer;
function test_str_eq(const st1, st2, s1, s2 : PUTF8Char):integer;
function test_str_ne(const st1, st2, s1, s2 : PUTF8Char):integer;
function test_strn_eq(const st1, st2, s1 : PUTF8Char; n1 : size_t;const s2 : PUTF8Char; n2 : size_t):integer;
function test_strn_ne(const st1, st2, s1 : PUTF8Char; n1 : size_t;const s2 : PUTF8Char; n2 : size_t):integer;
function test_mem_ne(const st1, st2 : PUTF8Char; s1 : Pointer; n1 : size_t;const s2 : Pointer; n2 : size_t):integer;
function test_time_t_eq(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
function test_time_t_ne(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
function test_time_t_gt(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
function test_time_t_ge(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
function test_time_t_lt(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
function test_time_t_le(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
function print_time(const t : PASN1_TIME):PUTF8Char;
function test_skip_c90(const desc : PUTF8Char; ap: array of const):integer;

const
  TEST_skip:function(const desc : PUTF8Char; ap: array of const):integer = test_skip_c90;

function test_BN_eq_word(const bns, ws : PUTF8Char; a : PBIGNUM; w : BN_ULONG):integer;
function test_BN_eq_zero(const s : PUTF8Char; a : PBIGNUM):integer;
function test_BN_ne(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
function test_BN_ne_zero(const s : PUTF8Char; a : PBIGNUM):integer;
function test_BN_gt(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
function test_BN_gt_zero(const s : PUTF8Char; a : PBIGNUM):integer;
function test_BN_ge(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
function test_BN_ge_zero(const s : PUTF8Char; a : PBIGNUM):integer;
function test_BN_lt(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
function test_BN_lt_zero(const s : PUTF8Char; a : PBIGNUM):integer;
function test_BN_le(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
function test_BN_le_zero(const s : PUTF8Char; a : PBIGNUM):integer;
function test_BN_eq(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;

implementation
uses openssl3.test.testutil.output,        openssl3.crypto.o_str,
     openssl3.crypto.asn1.a_time,          openssl3.crypto.asn1.asn1_lib,
     openssl3.test.testutil.format_output, openssl3.crypto.bn.bn_lib,
     openssl3.test.testutil.basic_output;

function test_BN_eq(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
begin
 if BN_cmp(t1, t2) = 0 then Exit(1);
 test_fail_bignum_message(Pointer(0) , 'BIGNUM', s1, s2, '=', t1, t2);
 Exit(0);
end;

function test_BN_eq_zero(const s : PUTF8Char; a : PBIGNUM):integer;
begin
   if (a <> Pointer(0))   and (BN_is_zero(a)) then
      Exit(1);
   test_fail_bignum_mono_message(Pointer(0) , 'BIGNUM', s, '0', '=', a);
   Exit(0);
end;


function test_BN_ne(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
begin
   if BN_cmp(t1, t2) <> 0 then Exit(1);
   test_fail_bignum_message(Pointer(0) , 'BIGNUM', s1, s2, '<>', t1, t2);
   Exit(0);
end;


function test_BN_ne_zero(const s : PUTF8Char; a : PBIGNUM):integer;
begin
   if (a <> Pointer(0))   and (not BN_is_zero(a)) then
      Exit(1);
   test_fail_bignum_mono_message(Pointer(0) , 'BIGNUM', s, '0', '<>', a);
   Exit(0);
end;


function test_BN_gt(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
begin
   if BN_cmp(t1, t2) > 0 then Exit(1);
   test_fail_bignum_message(Pointer(0) , 'BIGNUM', s1, s2, '>', t1, t2);
   Exit(0);
end;


function test_BN_gt_zero(const s : PUTF8Char; a : PBIGNUM):integer;
begin
 if (a <> Pointer(0))   and ( (0>= BN_is_negative(a))  and  (not BN_is_zero(a)) ) then
    Exit(1);
 test_fail_bignum_mono_message(Pointer(0) , 'BIGNUM', s, '0', '>', a);
 Exit(0);
end;


function test_BN_ge(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
begin
 if BN_cmp(t1, t2) >= 0 then Exit(1);
 test_fail_bignum_message(Pointer(0) , 'BIGNUM', s1, s2, '>=', t1, t2);
 Exit(0);
end;


function test_BN_ge_zero(const s : PUTF8Char; a : PBIGNUM):integer;
begin
 if (a <> Pointer(0))   and ( (0>=BN_is_negative(a))  or  (BN_is_zero(a)) ) then Exit(1);
 test_fail_bignum_mono_message(Pointer(0) , 'BIGNUM', s, '0', '>=', a);
 Exit(0);
end;


function test_BN_lt(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
begin
 if BN_cmp(t1, t2) < 0 then Exit(1);
 test_fail_bignum_message(Pointer(0) , 'BIGNUM', s1, s2, '<', t1, t2);
 Exit(0);
end;


function test_BN_lt_zero(const s : PUTF8Char; a : PBIGNUM):integer;
begin
 if (a <> Pointer(0))   and ( (BN_is_negative(a) > 0)  and  (not BN_is_zero(a)) ) then Exit(1);
 test_fail_bignum_mono_message(Pointer(0) , 'BIGNUM', s, '0', '<', a);
 Exit(0);
end;


function test_BN_le(const s1, s2 : PUTF8Char; t1, t2 : PBIGNUM):integer;
begin
 if BN_cmp(t1, t2) <= 0 then Exit(1);
 test_fail_bignum_message(Pointer(0) ,'BIGNUM', s1, s2, '<=', t1, t2);
 Exit(0);
end;


function test_BN_le_zero(const s : PUTF8Char; a : PBIGNUM):integer;
begin
 if (a <> Pointer(0))   and ( (BN_is_negative(a) > 0)  or  (BN_is_zero(a)) ) then Exit(1);
 test_fail_bignum_mono_message(Pointer(0) , 'BIGNUM', s, '0', '<=', a);
 Exit(0);
end;

function test_BN_eq_word(const bns, ws : PUTF8Char; a : PBIGNUM; w : BN_ULONG):integer;
var
  bw : PBIGNUM;
begin
    if (a <> nil)  and  (BN_is_word(a, w)) then
        Exit(1);
    bw := BN_new();
    if bw <> nil then
        BN_set_word(bw, w);
    test_fail_bignum_message(nil, 'BIGNUM', bns, ws, '=', a, bw);
    BN_free(bw);
    Result := 0;
end;

function test_skip_c90(const desc : PUTF8Char; ap: array of const):integer;
begin

    test_fail_message_va('SKIP', nil, nil, nil, nil, desc, ap);
    test_printf_stderr(#10, []);
    Result := TEST_SKIP_CODE;
end;

function print_time(const t : PASN1_TIME):PUTF8Char;
begin
    Result := get_result(t = Pointer(0), '<null>' , PUTF8Char(ASN1_STRING_get0_data(t)));
end;

function test_time_t_eq(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
var
  at1, at2 : PASN1_TIME;
  r : integer;
begin
   at1 := ASN1_TIME_set(Pointer(0) , t1);
   at2 := ASN1_TIME_set(Pointer(0) , t2);
   r := Int( (at1 <> Pointer(0)) and  (at2 <> Pointer(0))   and  (ASN1_TIME_compare(at1, at2) = 0));
   if 0>=r then
      test_fail_message(Pointer(0) , 'time_t', s1, s2, '=',
         '[%s] compared to [%s]', [print_time(at1), print_time(at2)]);
   ASN1_STRING_free(at1);
   ASN1_STRING_free(at2);
   Exit(r);
end;


function test_time_t_ne(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
var
  at1, at2 : PASN1_TIME;
  r : integer;
begin
   at1 := ASN1_TIME_set(Pointer(0) , t1);
   at2 := ASN1_TIME_set(Pointer(0) , t2);
   r := Int( (at1 <> Pointer(0))   and  (at2 <> Pointer(0))   and  (ASN1_TIME_compare(at1, at2) <> 0));
   if 0>=r then
      test_fail_message(Pointer(0) , 'time_t', s1, s2, '<>',
             '[%s] compared to [%s]', [print_time(at1), print_time(at2)]);
   ASN1_STRING_free(at1);
   ASN1_STRING_free(at2);
   Exit(r);
end;


function test_time_t_gt(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
var
  at1, at2 : PASN1_TIME;
  r : integer;
begin
   at1 := ASN1_TIME_set(Pointer(0) , t1);
   at2 := ASN1_TIME_set(Pointer(0) , t2);
   r := Int( (at1 <> Pointer(0))   and  (at2 <> Pointer(0))   and  (ASN1_TIME_compare(at1, at2) > 0));
   if 0>=r then
      test_fail_message(Pointer(0) ,'time_t', s1, s2, '>',
              '[%s] compared to [%s]', [print_time(at1), print_time(at2)]);
   ASN1_STRING_free(at1);
   ASN1_STRING_free(at2);
   Exit(r);
end;


function test_time_t_ge(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
var
  at1, at2 : PASN1_TIME;
  r : integer;
begin
   at1 := ASN1_TIME_set(Pointer(0) , t1);
   at2 := ASN1_TIME_set(Pointer(0) , t2);
   r := Int( (at1 <> Pointer(0))   and  (at2 <> Pointer(0))   and  (ASN1_TIME_compare(at1, at2) >= 0));
   if 0>=r then
      test_fail_message(Pointer(0) , 'time_t', s1, s2, '>=',
                     '[%s] compared to [%s]', [print_time(at1), print_time(at2)]);
   ASN1_STRING_free(at1);
   ASN1_STRING_free(at2);
   Exit(r);
end;


function test_time_t_lt(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
var
  at1, at2 : PASN1_TIME;
  r : integer;
begin
   at1 := ASN1_TIME_set(Pointer(0) , t1);
   at2 := ASN1_TIME_set(Pointer(0) , t2);
   r := Int( (at1 <> Pointer(0))   and  (at2 <> Pointer(0))   and  (ASN1_TIME_compare(at1, at2) < 0));
   if 0>=r then
      test_fail_message(Pointer(0) , 'time_t', s1, s2, '<',
          '[%s] compared to [%s]', [print_time(at1), print_time(at2)]);
   ASN1_STRING_free(at1);
   ASN1_STRING_free(at2);
   Exit(r);
end;


function test_time_t_le(const s1, s2 : PUTF8Char; t1, t2 : time_t):integer;
var
  at1, at2 : PASN1_TIME;
  r : integer;
begin
   at1 := ASN1_TIME_set(nil , t1);
   at2 := ASN1_TIME_set(nil , t2);
   r := int( (at1 <> nil)   and  (at2 <> nil)   and
           (ASN1_TIME_compare(at1, at2) <= 0));
   if 0 >= r then
      test_fail_message(Pointer(0) , 'time_t', s1, s2, '<=',
                 '[%s] compared to [%s]', [print_time(at1), print_time(at2)]);
   ASN1_STRING_free(at1);
   ASN1_STRING_free(at2);
   Exit(r);
end;

function test_ptr_null(const s : PUTF8Char; p : Pointer):integer;
begin
    if p = nil then Exit(1);
    test_fail_message(nil, 'ptr', s, 'nil', '=', '%p', [p]);
    Result := 0;
end;


function test_ptr(const s : PUTF8Char; p : Pointer):integer;
begin
    if p <> nil then
       Exit(1);
    test_fail_message(nil,  'ptr', s, 'nil', '<>', '%p', [p]);
    Result := 0;
end;


function test_true(const s : PUTF8Char; b : integer):integer;
begin
    if b > 0 then
       Exit(1);
    test_fail_message(nil, 'bool', s, 'true', '==', 'false', []);
    Result := 0;
end;

function test_false(const s : PUTF8Char; b : integer):integer;
begin
    if 0>=b then Exit(1);
    test_fail_message(nil,  'bool', s, 'false', '==', 'true', []);
    Result := 0;
end;


function test_str_eq(const st1, st2, s1, s2 : PUTF8Char):integer;
begin
    if (s1 = nil)  and  (s2 = nil) then Exit(1);
    if (s1 = nil)  or  (s2 = nil)  or  (strcmp(s1, s2) <> 0) then
    begin
        test_fail_string_message(nil,  'string', st1, st2, '=',
                                 s1, get_result(s1 = nil , 0 , Length(s1)),
                                 s2, get_result(s2 = nil , 0 , Length(s2)));
        Exit(0);
    end;
    Result := 1;
end;


function test_str_ne(const st1, st2, s1, s2 : PUTF8Char):integer;
begin
    if Int(s1 = nil)  xor  int(s2 = nil) > 0 then
      Exit(1);
    if (s1 = nil)  or  (strcmp(s1, s2) = 0) then
    begin
        test_fail_string_message(nil,  'string', st1, st2, '<>',
                                 s1, get_result(s1 = nil , 0 , Length(s1)),
                                 s2, get_result(s2 = nil , 0 , Length(s2)));
        Exit(0);
    end;
    Result := 1;
end;


function test_strn_eq(const st1, st2, s1 : PUTF8Char; n1 : size_t;const s2 : PUTF8Char; n2 : size_t):integer;
begin
    if (s1 = nil)  and  (s2 = nil) then
        Exit(1);
    if (n1 <> n2)  or  (s1 = nil)  or  (s2 = nil)  or  (strncmp(s1, s2, n1) <> 0) then
    begin
        test_fail_string_message(nil,  'string', st1, st2, '=',
                                 s1, get_result(s1 = nil , 0 , OPENSSL_strnlen(s1, n1)),
                                 s2, get_result(s2 = nil , 0 , OPENSSL_strnlen(s2, n2)));
        Exit(0);
    end;
    Result := 1;
end;


function test_strn_ne(const st1, st2, s1 : PUTF8Char; n1 : size_t;const s2 : PUTF8Char; n2 : size_t):integer;
begin
    if Int(s1 = nil)  xor  int(s2 = nil) > 0 then
      Exit(1);
    if (n1 <> n2)  or  (s1 = nil)  or  (strncmp(s1, s2, n1) = 0) then
    begin
        test_fail_string_message(nil,  'string', st1, st2, '<>',
                                 s1, get_result(s1 = nil , 0 , OPENSSL_strnlen(s1, n1)),
                                 s2, get_result(s2 = nil , 0 , OPENSSL_strnlen(s2, n2)));
        Exit(0);
    end;
    Result := 1;
end;


function test_mem_ne(const st1, st2 : PUTF8Char; s1 : Pointer; n1 : size_t;const s2 : Pointer; n2 : size_t):integer;
begin
    if Int(s1 = nil)  xor  int(s2 = nil) > 0 then
        Exit(1);
    if n1 <> n2 then Exit(1);
    if (s1 = nil)  or  (memcmp(s1, s2, n1) = 0) then
    begin
        test_fail_memory_message(nil,  'memory', st1, st2, '<>',
                                 s1, n1, s2, n2);
        Exit(0);
    end;
    Result := 1;
end;


function test_mem_eq(const st1, st2 : PUTF8Char;const s1 : Pointer; n1 : size_t;const s2 : Pointer; n2 : size_t):integer;
begin
    if (s1 = nil)  and  (s2 = nil ) then
        Exit(1);
    if (n1 <> n2)  or  (s1 = nil) or  (s2 = nil)   or  (memcmp(s1, s2, n1) <> 0) then
    begin
        test_fail_memory_message(nil, 'memory', st1, st2, '=',
                                 s1, n1, s2, n2);
        Exit(0);
    end;
    Result := 1;
end;

procedure test_fail_message_prefix(const prefix, _type, left, right, op : PUTF8Char);
begin
    test_printf_stderr('%s: ', [get_result(prefix <> nil , prefix , PUTF8Char('ERROR'))]);
    if _type <> nil then
       test_printf_stderr('(%s) ', [_type]);
    if op <> nil then
    begin
        if (left <> nil)  and  (right <> nil) then
            test_printf_stderr('%s %s %s failed', [left, op, right])
        else
            test_printf_stderr('%s', [op]);
    end;
    test_printf_stderr(#10, []);
end;

procedure test_fail_message_va(const prefix : PUTF8Char;
                               const _type, left, right, op, fmt :PUTF8Char;
                               ap: array of const);
begin
    test_fail_message_prefix(prefix, _type, left, right, op);
    if fmt <> nil then
    begin
        test_vprintf_stderr(fmt, ap);
        test_printf_stderr(#10, []);
    end;
    test_flush_stderr;
end;

procedure test_fail_message(const prefix, _type, left, right, op, fmt :PUTF8Char;
                            ap: array of const );
begin
    test_fail_message_va(prefix, _type, left, right, op, fmt, ap);
end;


function test_int_eq(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
begin
   if t1 = t2 then
      Exit(1);
   test_fail_message(nil ,  'int', s1, s2, '=', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
   Exit(0);
end;


function test_int_ne(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'int', s1, s2, '<>', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_int_lt(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'int', s1, s2, '<', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_int_le(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'int', s1, s2, '<=', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_int_gt(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'int', s1, s2, '>', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_int_ge(const s1, s2 : PUTF8Char; t1, t2 : integer):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'int', s1, s2, '>=', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_uint_eq(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Uint32', s1, s2, '=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uint_ne(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Uint32', s1, s2, '<>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uint_lt(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Uint32', s1, s2, '<', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uint_le(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Uint32', s1, s2, '<=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uint_gt(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Uint32', s1, s2, '>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uint_ge(const s1, s2 : PUTF8Char; t1, t2 : uint32):integer;
begin
   if t1 >= t2 then Exit(1);
   test_fail_message(Pointer(0) ,  'Uint32', s1, s2, '>=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
   Exit(0);
end;


function test_char_eq(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'char', s1, s2, '=', '[ "%c" ] compared to [ "%c" ]', [t1, t2]);
 Exit(0);
end;


function test_char_ne(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'char', s1, s2, '<>', '[ "%c" ] compared to [ "%c" ]', [t1, t2]);
 Exit(0);
end;


function test_char_lt(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'char', s1, s2, '<', '[ "%c" ] compared to [ "%c" ]', [t1, t2]);
 Exit(0);
end;


function test_char_le(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'char', s1, s2, '<=', '[ "%c" ] compared to [ "%c" ]', [t1, t2]);
 Exit(0);
end;


function test_char_gt(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'char', s1, s2, '>', '[ "%c" ] compared to [ "%c" ]', [t1, t2]);
 Exit(0);
end;


function test_char_ge(const s1, s2 : PUTF8Char; t1, t2 : byte):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'char', s1, s2, '>=', '[ "%c" ] compared to [ "%c" ]', [t1, t2]);
 Exit(0);
end;


function test_uchar_eq(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Byte ', s1, s2, '=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uchar_ne(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Byte ', s1, s2, '<>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uchar_lt(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Byte ', s1, s2, '<', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uchar_le(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Byte ', s1, s2, '<=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uchar_gt(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Byte ', s1, s2, '>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_uchar_ge(const s1, s2 : PUTF8Char; t1, t2 : Byte):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Byte ', s1, s2, '>=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_long_eq(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'long', s1, s2, '=', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_long_ne(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'long', s1, s2, '<>', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_long_lt(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'long', s1, s2, '<', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_long_le(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'long', s1, s2, '<=', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_long_gt(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'long', s1, s2, '>', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_long_ge(const s1, s2 : PUTF8Char; t1, t2 : long):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'long', s1, s2, '>=', '[ "%d" ] compared to [ "%d" ]', [t1, t2]);
 Exit(0);
end;


function test_ulong_eq(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'ulong', s1, s2, '=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_ulong_ne(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'ulong', s1, s2, '<>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_ulong_lt(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'ulong', s1, s2, '<', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_ulong_le(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'ulong', s1, s2, '<=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_ulong_gt(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'ulong', s1, s2, '>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_ulong_ge(const s1, s2 : PUTF8Char; t1, t2 : Cardinal):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'ulong', s1, s2, '>=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_size_t_eq(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'size_t', s1, s2, '=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_size_t_ne(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'size_t', s1, s2, '<>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_size_t_lt(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'size_t', s1, s2, '<', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_size_t_le(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'size_t', s1, s2, '<=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_size_t_gt(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'size_t', s1, s2, '>', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_size_t_ge(const s1, s2 : PUTF8Char; t1, t2 : size_t):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'size_t', s1, s2, '>=', '[ "%u" ] compared to [ "%u" ]', [t1, t2]);
 Exit(0);
end;


function test_double_eq(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
begin
 if t1 = t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'double', s1, s2, '=', '[ "%g" ] compared to [ "%g" ]', [t1, t2]);
 Exit(0);
end;


function test_double_ne(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'double', s1, s2, '<>', '[ "%g" ] compared to [ "%g" ]', [t1, t2]);
 Exit(0);
end;


function test_double_lt(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
begin
 if t1 < t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'double', s1, s2, '<', '[ "%g" ] compared to [ "%g" ]', [t1, t2]);
 Exit(0);
end;


function test_double_le(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
begin
 if t1 <= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'double', s1, s2, '<=', '[ "%g" ] compared to [ "%g" ]', [t1, t2]);
 Exit(0);
end;


function test_double_gt(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
begin
 if t1 > t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'double', s1, s2, '>', '[ "%g" ] compared to [ "%g" ]', [t1, t2]);
 Exit(0);
end;


function test_double_ge(const s1, s2 : PUTF8Char; t1, t2 : Double):integer;
begin
 if t1 >= t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'double', s1, s2, '>=', '[ "%g" ] compared to [ "%g" ]', [t1, t2]);
 Exit(0);
end;


function test_ptr_eq(const s1, s2 : PUTF8Char; t1, t2 : Pointer):integer;
begin
   if t1 = t2 then
      Exit(1);
   test_fail_message(Pointer(0) ,  'Pointer ', s1, s2, '=', '[ "%p" ] compared to [ "%p" ]', [t1, t2]);
   Exit(0);
end;


function test_ptr_ne(const s1, s2 : PUTF8Char; t1, t2 : Pointer):integer;
begin
 if t1 <> t2 then Exit(1);
 test_fail_message(Pointer(0) ,  'Pointer ', s1, s2, '<>', '[ "%p" ] compared to [ "%p" ]', [t1, t2]);
 Exit(0);
end;

end.
