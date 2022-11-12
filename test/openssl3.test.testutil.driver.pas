unit openssl3.test.testutil.driver;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api, SysUtils, DateUtils;

type
 Tparam_test_fn  = function(idx: int): int;
 Ttest_fn = function: int;

  test_info = record
      test_case_name : PUTF8Char;
      test_fn        : function: int;
      param_test_fn  : function(idx: int): int;
      num ,subtest: integer;
  end;
  TTEST_INFO = test_info;

 procedure add_all_tests(const test_case_name : PUTF8Char; test_fn : Tparam_test_fn; num, subtest : integer);

var
  num_tests :int = 0;
  show_list :int = 0;
  single_test :int = -1;
  single_iter :int = -1;
  level :int = 0;
  seed :int = 0;
  rand_order :int = 0;
  num_test_cases: int = 0;
  all_tests   : array[0..1023] of TTEST_INFO;
  test_title: PUTF8Char = nil;

function setup_test_framework( argc : integer; argv : PPUTF8Char):integer;
procedure set_seed( s : integer);
function run_tests(const test_prog_name : PUTF8Char):integer;
function process_shared_options:integer;
function check_single_test_params( name, testname, itname : PUTF8Char):integer;
procedure set_test_title(const title : PUTF8Char);
procedure finalize( success : integer);
procedure test_verdict(verdict : integer;const description :PUTF8Char; ap: array of const);
function gcd( a, b : integer):integer;
function pulldown_test_framework( ret : integer):integer;
procedure add_test(const test_case_name : PUTF8Char; test_fn: Ttest_fn);

implementation

uses libc.win,                            openssl3.test.testutil.random,
     app.lib.opt, OpenSSL3.Err,           app.lib.win32_init,
     OpenSSL3.crypto.err.err_prn,         openssl3.test.testutil.basic_output,
     openssl3.test.testutil.test_options, openssl3.test.testutil.output ;

procedure add_test(const test_case_name : PUTF8Char; test_fn: Ttest_fn);
begin
    assert(num_tests <> Length(all_tests));
    all_tests[num_tests].test_case_name := test_case_name;
    all_tests[num_tests].test_fn := test_fn;
    all_tests[num_tests].num := -1;
    PreInc(num_tests);
    PreInc(num_test_cases);
end;

function pulldown_test_framework( ret : integer):integer;
begin
    set_test_title(nil);
    Result := ret;
end;


function gcd( a, b : integer):integer;
var
  t : integer;
begin
    while b <> 0 do
    begin
        t := b;
        b := a mod b;
        a := t;
    end;
    Result := a;
end;

procedure finalize( success : integer);
begin
    if success > 0 then
       ERR_clear_error()
    else
       ERR_print_errors_cb(openssl_error_cb, nil);
end;

procedure set_test_title(const title : PUTF8Char);
begin
    free(test_title);
    test_title := get_result(title = nil , nil , strdup(title));
end;

function check_single_test_params( name, testname, itname : PUTF8Char):integer;
var
  i : integer;
begin
    if name <> nil then
    begin
        for i := 0 to num_tests-1 do
        begin
            if strcmp(name, all_tests[i].test_case_name) = 0 then
            begin
                single_test := 1 + i;
                break;
            end;
        end;
        if i >= num_tests then
           single_test := StrToInt(name);
    end;
    { if only iteration is specified, assume we want the first test }
    if (single_test = -1)  and  (single_iter <> -1) then
       single_test := 1;
    if single_test <> -1 then
    begin
        if (single_test < 1)  or  (single_test > num_tests) then
        begin
            WriteLn(Format('Invalid -%s value '+
                               '(Value must be a valid test name OR a value between %d..%d)',
                               [testname, 1, num_tests]));
            Exit(0);
        end;
    end;
    if single_iter <> -1 then begin
        if all_tests[single_test - 1].num = -1 then  begin
            WriteLn(Format('-%s option is not valid for test %d:%s\n',
                               [itname,
                               single_test,
                               all_tests[single_test - 1].test_case_name]));
            Exit(0);
        end
        else
        if (single_iter < 1)
                    or  (single_iter > all_tests[single_test - 1].num) then
        begin
            WriteLn(Format('Invalid -%s value for test %d:%s'#9 +
                               '(Value must be in the range %d..%d)',
                               [itname, single_test,
                               all_tests[single_test - 1].test_case_name,
                               1, all_tests[single_test - 1].num]));
            Exit(0);
        end;
    end;
    Result := 1;
end;

function process_shared_options:integer;
var
  o         : OPTION_CHOICE_DEFAULT;
  value,
  ret       : integer;
  flag_test,
  flag_iter,
  testname  : PUTF8Char;
  label _end;
begin
    ret := -1;
    flag_test := '';
    flag_iter := '';
    testname := nil;
    opt_begin;
    o := OPTION_CHOICE_DEFAULT(opt_next);
    while o <> OPT_EOF do
    begin
        case o of
          { Ignore any test options at this level }

          OPT_ERR:
              Exit(ret);
          OPT_TEST_HELP:
          begin
              opt_help(test_get_options);
              Exit(0);
          end;
          OPT_TEST_LIST:
          begin
              show_list := 1;
              break;
          end;
          OPT_TEST_SINGLE:
          begin
              flag_test := opt_flag;
              testname := opt_arg;
              break;
          end;
          OPT_TEST_ITERATION:
          begin
              flag_iter := opt_flag;
              if 0>=opt_int(opt_arg, @single_iter) then
                  goto _end;
              break;
          end;
          OPT_TEST_INDENT:
          begin
              if 0>=opt_int(opt_arg, @value) then
                  goto _end;
              level := 4 * value;
              test_adjust_streams_tap_level(level);
              break;
          end;
          OPT_TEST_SEED:
          begin
              if 0>=opt_int(opt_arg, @value) then
                  goto _end;
              set_seed(value);
              break;
          end;
          else
          begin
            break;
          end;

        end;
    end;
    if 0>=check_single_test_params(testname, flag_test, flag_iter) then
        goto _end;
    ret := 1;

_end:
    Result := ret;
end;

procedure test_verdict(verdict : integer;const description :PUTF8Char; ap: array of const);
begin
    test_flush_stdout;
    test_flush_stderr;
    if (verdict = 0)  and  (seed <> 0) then
       test_printf_tapout('# OPENSSL_TEST_RAND_ORDER=%d'#10, [seed]);
    test_printf_tapout('%s ', [get_result(verdict <> 0 , PAnsiChar('ok') , PAnsiChar('not ok'))]);
    //va_start(ap, description);
    test_vprintf_tapout(description, ap);
    //va_end(ap);
    if verdict = TEST_SKIP_CODE then
       test_printf_tapout(' # skipped',[]);
    test_printf_tapout(#10,[]);
    test_flush_tapout;
end;


function run_tests(const test_prog_name : PUTF8Char):integer;
var
  num_failed,
  verdict,
  ii,  i,   jj,
  j,  jstep,
  test_case_count,
  subtest_case_count : integer;
  permute            : array[0..Length(all_tests)-1] of integer;
  num_failed_inner,
  v                  : integer;
begin
    num_failed := 0;
    verdict := 1;
    test_case_count := 0;
    subtest_case_count := 0;
    i := process_shared_options;
    if i = 0 then Exit(0{EXIT_SUCCESS});
    if i = -1 then Exit(1{EXIT_FAILURE});
    if num_tests < 1 then begin
        test_printf_tapout('1..0 # Skipped: %s'#10, [test_prog_name]);
    end
    else
    if (show_list = 0)  and  (single_test = -1) then
    begin
        if level > 0 then begin
            test_printf_stdout('Subtest: %s'#10, [test_prog_name]);
            test_flush_stdout;
        end;
        test_printf_tapout('1..%d'#10, [num_test_cases]);
    end;
    test_flush_tapout;
    for i := 0 to num_tests-1 do
        permute[i] := i;
    if rand_order <> 0 then
       for i := num_tests - 1 downto 1 do
       begin
            j := test_random mod (1 + i);
            ii := permute[j];
            permute[j] := permute[i];
            permute[i] := ii;
        end;
    ii := 0;
    while ii <> num_tests do
    begin
        i := permute[ii];
        if (single_test <> -1)  and  (i+1  <> single_test) then
        begin
            Inc(ii);
            continue;
        end
        else
        if (show_list > 0 ) then
        begin
            if all_tests[i].num <> -1 then
            begin
                test_printf_tapout('%d - %s (%d..%d)'#10, [ii + 1,
                                   all_tests[i].test_case_name, 1,
                                   all_tests[i].num]);
            end
            else
            begin
                test_printf_tapout('%d - %s'#10, [ii + 1,
                                   all_tests[i].test_case_name]);
            end;
            test_flush_tapout;
        end
        else
        if (all_tests[i].num = -1) then
        begin
            set_test_title(all_tests[i].test_case_name);
            verdict := all_tests[i].test_fn;
            finalize(Int(verdict <> 0));
            test_verdict(verdict, '%d - %s', [test_case_count + 1, test_title]);
            if verdict = 0 then
               Inc(num_failed);
            Inc(test_case_count);
        end
        else
        begin
            num_failed_inner := 0;
            verdict := TEST_SKIP_CODE;
            set_test_title(all_tests[i].test_case_name);
            if all_tests[i].subtest > 0 then
            begin
                level  := level + 4;
                test_adjust_streams_tap_level(level);
                if single_iter = -1 then
                begin
                    test_printf_stdout('Subtest: %s'#10, [test_title]);
                    test_printf_tapout('%d..%d'#10, [1, all_tests[i].num]);
                    test_flush_stdout;
                    test_flush_tapout;
                end;
            end;
            j := -1;
            if (rand_order = 0)  or  (all_tests[i].num < 3) then
               jstep := 1
            else
            begin
                repeat
                    jstep := test_random mod all_tests[i].num;
                until not ( (jstep = 0)  or  (gcd(all_tests[i].num, jstep) <> 1) ) ;
            end;

            for jj := 0 to all_tests[i].num-1 do
            begin
                j := (j + jstep) mod all_tests[i].num;
                if (single_iter <> -1)  and  (jj + 1 <> single_iter) then
                begin
                    Inc(ii);
                    continue;
                end;

                v := all_tests[i].param_test_fn(j);
                if v = 0 then begin
                    PreInc(num_failed_inner);
                    verdict := 0;
                end
                else
                if (v <> TEST_SKIP_CODE)  and  (verdict <> 0) then
                begin
                    verdict := 1;
                end;
                finalize(Int(v <> 0));
                if all_tests[i].subtest > 0 then
                   test_verdict(v, '%d - iteration %d',
                                 [subtest_case_count + 1, j + 1])
                else
                    test_verdict(v, '%d - %s - iteration %d',
                                 [test_case_count + subtest_case_count + 1,
                                 test_title, j + 1]);
                PostInc(subtest_case_count);
            end;
            if all_tests[i].subtest > 0 then
            begin
                level  := level - 4;
                test_adjust_streams_tap_level(level);
            end;
            if verdict = 0 then PreInc(num_failed);
            if (all_tests[i].num = -1)  or  (all_tests[i].subtest > 0) then
               test_verdict(verdict, '%d - %s', [test_case_count + 1,
                             all_tests[i].test_case_name]);
            PostInc(test_case_count);
        end;
        PreInc(ii);
    end;
    if num_failed <> 0 then
       Exit(1{EXIT_FAILURE});
    Result := 0{EXIT_SUCCESS};
end;

procedure set_seed( s : integer);
begin
    seed := s;
    if seed <= 0 then
       seed := Abs(Int(_time(nil)));
    test_random_seed(seed);
end;

function setup_test_framework( argc : integer; argv : PPUTF8Char):integer;
var
  test_seed,
  TAP_levels : PUTF8Char;
  opts:POPTIONS;
begin
    test_seed := getenv('OPENSSL_TEST_RAND_ORDER');
    TAP_levels := getenv('HARNESS_OSSL_LEVEL');
    if TAP_levels <> nil then
       level := 4 * StrToInt(TAP_levels);
    test_adjust_streams_tap_level(level);
    if test_seed <> nil then begin
        rand_order := 1;
        set_seed(StrToInt(test_seed));
    end
    else begin
        set_seed(0);
    end;
{$IF defined(OPENSSL_SYS_VMS)  and  defined(__DECC)}
    argv := copy_argv(&ParamCount, argv);
{$elseif defined(MSWINDOWS)}
    {
     * Replace argv[] with UTF-8 encoded strings.
     }
    win32_utf8argv(@argc, @argv);
{$ENDIF}
    opts := test_get_options;
    if nil = opt_init(argc, argv, opts) then
        Exit(0);
    Result := 1;
end;

procedure add_all_tests(const test_case_name : PUTF8Char; test_fn : Tparam_test_fn; num, subtest : integer);
begin
    assert(num_tests <> Length(all_tests));
    all_tests[num_tests].test_case_name := test_case_name;
    all_tests[num_tests].param_test_fn := test_fn;
    all_tests[num_tests].num := num;
    all_tests[num_tests].subtest := subtest;
    PreInc(num_tests);
    if subtest > 0 then
       PreInc(num_test_cases)
    else
        num_test_cases  := num_test_cases + num;
end;

end.
