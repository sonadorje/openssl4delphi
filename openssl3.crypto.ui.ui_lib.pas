unit openssl3.crypto.ui.ui_lib;

interface
uses OpenSSL.Api, SysUtils;

type
  Topener_func = function(ui: PUI):int;
  Tcloser_func = function(ui: PUI):int;
  Treader_func = function ( ui : PUI; uis : PUI_STRING):integer;
  Twriter_func = function ( ui : PUI; uis : PUI_STRING):integer;

const
  UI_FLAG_REDOABLE     = $0001;
  UI_FLAG_DUPL_DATA    = $0002;
  UI_FLAG_PRINT_ERRORS = $0100;
  OUT_STRING_FREEABLE  = $01;

  g_ui_null: TUI_METHOD  = (
    name: 'OpenSSL nil UI';
    ui_open_session: nil;                        { opener }
    ui_write_string: nil;                        { writer }
    ui_flush: nil;                        { flusher }
    ui_read_string: nil;                        { reader }
    ui_close_session: nil;                        { closer }
    ui_duplicate_data: nil
);

function UI_new:PUI;
function UI_new_method(method : PUI_METHOD):PUI;
function UI_get_string_type( uis : PUI_STRING):TUI_string_types;
function UI_get0_output_string( uis : PUI_STRING):PUTF8Char;
function UI_get0_action_string( uis : PUI_STRING):PUTF8Char;
function UI_set_result(ui : PUI; uis : PUI_STRING;const _result : PUTF8Char):integer;
function UI_get_input_flags( uis : PUI_STRING):integer;
function UI_get0_result_string( uis : PUI_STRING):PUTF8Char;
function UI_get0_test_string( uis : PUI_STRING):PUTF8Char;
function UI_set_result_ex(ui : PUI; uis : PUI_STRING;const _result : PUTF8Char; len : integer):integer;
function UI_null:PUI_METHOD;
procedure UI_free( ui : PUI);
function ossl_check_UI_STRING_sk_type(sk: Pstack_st_UI_STRING):POPENSSL_STACK;
function ossl_check_UI_STRING_type( ptr : PUI_STRING):PUI_STRING;
  function ossl_check_UI_STRING_compfunc_type( cmp : sk_UI_STRING_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_UI_STRING_copyfunc_type( cpy : sk_UI_STRING_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_UI_STRING_freefunc_type( fr : sk_UI_STRING_freefunc):OPENSSL_sk_freefunc;
  procedure free_string( uis : PUI_STRING);
  function UI_set_method(ui : PUI;const meth : PUI_METHOD):PUI_METHOD;
  function UI_add_user_data( ui : PUI; user_data : Pointer):Pointer;
  function UI_construct_prompt(ui : PUI;const phrase_desc, object_name : PUTF8Char):PUTF8Char;
  function UI_add_input_string(ui : PUI;const prompt : PUTF8Char; flags : integer; result_buf : PUTF8Char; minsize, maxsize : integer):integer;
  function general_allocate_string(ui : PUI;const prompt : PUTF8Char; prompt_freeable : integer; _type : TUI_string_types; input_flags : integer; result_buf : PUTF8Char; minsize, maxsize : integer;const test_buf : PUTF8Char):integer;
  function general_allocate_prompt(ui : PUI;const prompt : PUTF8Char; prompt_freeable : integer; _type: TUI_string_types; input_flags : integer; result_buf : PUTF8Char):PUI_STRING;
  function allocate_string_stack( ui : PUI):integer;
  function UI_add_verify_string(ui : PUI;const prompt : PUTF8Char; flags : integer; result_buf : PUTF8Char; minsize, maxsize : integer;const test_buf : PUTF8Char):integer;
  function UI_process( ui : PUI):integer;
  function print_error(const str : PUTF8Char; len : size_t; ui : Pointer):integer;
  function ossl_check_const_UI_STRING_sk_type(const sk : Pstack_st_UI_STRING):POPENSSL_STACK;
  function UI_get_result_length( ui : PUI; i : integer):integer;
  function UI_get_result_string_length( uis : PUI_STRING):integer;
  function UI_method_get_ex_data(const method : PUI_METHOD; idx : integer):Pointer;
  function UI_get_method( ui : PUI):PUI_METHOD;
  function UI_get_result_maxsize( uis : PUI_STRING):integer;
  function UI_get0_user_data( ui : PUI):Pointer;
  function UI_create_method(const name : PUTF8Char):PUI_METHOD;
  function UI_method_set_opener( method : PUI_METHOD; opener: Topener_func):integer;
  function UI_method_set_reader( method : PUI_METHOD; reader : Treader_func):integer;
  function UI_method_set_writer( method : PUI_METHOD; writer : Twriter_func):integer;
  function UI_method_set_closer( method : PUI_METHOD; closer : Tcloser_func):integer;
  function UI_method_set_ex_data( method : PUI_METHOD; idx : integer; data : Pointer):integer;
  procedure UI_destroy_method( ui_method : PUI_METHOD);

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
     OpenSSL3.crypto.err.err_prn,
     openssl3.include.openssl.ui, openssl3.crypto.o_str,
     openssl3.crypto.ui.ui_openssl, openssl3.crypto.ex_data;





procedure UI_destroy_method( ui_method : PUI_METHOD);
begin
    if ui_method = nil then exit;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_UI_METHOD, ui_method,
                        @ui_method.ex_data);
    OPENSSL_free(Pointer(ui_method.name));
    ui_method.name := nil;
    OPENSSL_free(Pointer(ui_method));
end;

function UI_method_set_ex_data( method : PUI_METHOD; idx : integer; data : Pointer):integer;
begin
    Result := CRYPTO_set_ex_data(@method.ex_data, idx, data);
end;

function UI_method_set_closer( method : PUI_METHOD; closer : Tcloser_func):integer;
begin
    if method <> nil then
    begin
        method.ui_close_session := closer;
        Exit(0);
    end;
    Result := -1;
end;




function UI_method_set_writer( method : PUI_METHOD; writer : Twriter_func):integer;
begin
    if method <> nil then begin
        method.ui_write_string := writer;
        Exit(0);
    end;
    Result := -1;
end;

function UI_method_set_reader( method : PUI_METHOD; reader : Treader_func):integer;
begin
    if method <> nil then
    begin
        method.ui_read_string := reader;
        Exit(0);
    end;
    Result := -1;
end;

function UI_method_set_opener( method : PUI_METHOD; opener: Topener_func):integer;
begin
    if method <> nil then
    begin
        method.ui_open_session := opener;
        Exit(0);
    end;
    Result := -1;
end;

function UI_create_method(const name : PUTF8Char):PUI_METHOD;
var
  ui_method : PUI_METHOD;
begin
    ui_method := nil;
    ui_method := OPENSSL_zalloc(sizeof(ui_method^));
    OPENSSL_strdup(ui_method.name ,name);
    if (ui_method = nil)
         or  (ui_method.name = nil)
         or  (0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_UI_METHOD, ui_method,
                               @ui_method.ex_data)) then
    begin
        if ui_method <> nil then
            OPENSSL_free(ui_method.name);
        OPENSSL_free(ui_method);
        ERR_raise(ERR_LIB_UI, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    Result := ui_method;
end;



function UI_get0_user_data( ui : PUI):Pointer;
begin
    Result := ui.user_data;
end;

function UI_get_result_maxsize( uis : PUI_STRING):integer;
begin
    case uis.&type of
      UIT_PROMPT,
      UIT_VERIFY:
          Exit(uis._.string_data.result_maxsize);
      UIT_NONE,
      UIT_INFO,
      UIT_ERROR,
      UIT_BOOLEAN:
      begin
        //break;
      end;
    end;
    Result := -1;
end;





function UI_get_method( ui : PUI):PUI_METHOD;
begin
    Result := ui.meth;
end;

function UI_method_get_ex_data(const method : PUI_METHOD; idx : integer):Pointer;
begin
    Result := CRYPTO_get_ex_data(@method.ex_data, idx);
end;



function UI_get_result_string_length( uis : PUI_STRING):integer;
begin
    case uis.&type of
      UIT_PROMPT,
      UIT_VERIFY:
          Exit(uis.result_len);
      UIT_NONE,
      UIT_BOOLEAN,
      UIT_INFO,
      UIT_ERROR:
      begin
         //break;
      end;
    end;
    Result := -1;
end;



function UI_get_result_length( ui : PUI; i : integer):integer;
begin
    if i < 0 then
    begin
        ERR_raise(ERR_LIB_UI, UI_R_INDEX_TOO_SMALL);
        Exit(-1);
    end;
    if i >= sk_UI_STRING_num(ui.strings) then
    begin
        ERR_raise(ERR_LIB_UI, UI_R_INDEX_TOO_LARGE);
        Exit(-1);
    end;
    Result := UI_get_result_string_length(sk_UI_STRING_value(ui.strings, i));
end;

function ossl_check_const_UI_STRING_sk_type(const sk : Pstack_st_UI_STRING):POPENSSL_STACK;
begin
   Exit(POPENSSL_STACK( sk));
end;

function print_error(const str : PUTF8Char; len : size_t; ui : Pointer):integer;
var
  uis : TUI_STRING;
begin
    memset(@uis, 0, sizeof(uis));
    uis.&type := UIT_ERROR;
    uis.out_string := str;
    if (Assigned(PUI(ui).meth.ui_write_string))
         and  (PUI(ui).meth.ui_write_string(ui, @uis) <= 0)  then
        Exit(-1);
    Result := 0;
end;



var state : PUTF8Char = 'processing';
function UI_process( ui : PUI):integer;
var
  i, ok : integer;

  label _err;
begin
    ok := 0;
    if (Assigned(ui.meth.ui_open_session))
         and  (ui.meth.ui_open_session(ui) <= 0)  then
    begin
        state := 'opening session';
        ok := -1;
        goto _err ;
    end;
    if (ui.flags and UI_FLAG_PRINT_ERRORS) > 0 then
       ERR_print_errors_cb(print_error, Pointer( ui));
    for i := 0 to sk_UI_STRING_num(ui.strings)-1 do
    begin
        if Assigned(ui.meth.ui_write_string) then
        begin
           if ui.meth.ui_write_string(ui, sk_UI_STRING_value(ui.strings, i))
                                     <= 0 then

            state := 'writing strings';
            ok := -1;
            goto _err ;
        end;
    end;
    if Assigned(ui.meth.ui_flush) then
    begin
       case ui.meth.ui_flush(ui) of
           -1:                { Interrupt/Cancel/something... }
           begin
                ui.flags := ui.flags and (not UI_FLAG_REDOABLE);
                ok := -2;
                goto _err ;
           end;
            0:                 { Errors }
           begin
                state := 'flushing';
                ok := -1;
                goto _err ;
           end
           else               { Success }
                ok := 0;
                //break;
       end;
    end;
    for i := 0 to sk_UI_STRING_num(ui.strings)-1 do
    begin
        if Assigned(ui.meth.ui_read_string) then
        begin
            case (ui.meth.ui_read_string(ui, sk_UI_STRING_value(ui.strings, i))) of
                -1:            { Interrupt/Cancel/something... }
                begin
                    ui.flags := ui.flags and (not UI_FLAG_REDOABLE);
                    ok := -2;
                    goto _err ;
                end;
                0:             { Errors }
                begin
                    state := 'reading strings';
                    ok := -1;
                    goto _err ;
                end
                else           { Success }
                    ok := 0;
                    //break;
            end;
        end;
    end;
    state := nil;
 _err:
    if (Assigned(ui.meth.ui_close_session))
         and  (ui.meth.ui_close_session(ui) <= 0)  then
    begin
        if state = nil then
           state := 'closing session';
        ok := -1;
    end;
    if ok = -1 then
       ERR_raise_data(ERR_LIB_UI, UI_R_PROCESSING_ERROR, Format('while %s', [state]));
    Result := ok;
end;



function UI_add_verify_string(ui : PUI;const prompt : PUTF8Char; flags : integer; result_buf : PUTF8Char; minsize, maxsize : integer;const test_buf : PUTF8Char):integer;
begin
    Exit(general_allocate_string(ui, prompt, 0,
                                   UIT_VERIFY, flags, result_buf, minsize,
                                   maxsize, test_buf));
end;






function allocate_string_stack( ui : PUI):integer;
begin
    if ui.strings = nil then
    begin
        ui.strings := sk_UI_STRING_new_null();
        if ui.strings = nil then
        begin
            Exit(-1);
        end;
    end;
    Result := 0;
end;




function general_allocate_prompt(ui : PUI;const prompt : PUTF8Char; prompt_freeable : integer; _type: TUI_string_types; input_flags : integer; result_buf : PUTF8Char):PUI_STRING;
var
  ret : PUI_STRING;
begin
    ret := nil;
    if prompt = nil then
    begin
        ERR_raise(ERR_LIB_UI, ERR_R_PASSED_NULL_PARAMETER);
    end
    else
    if ((_type = UIT_PROMPT)  or  (_type = UIT_VERIFY)
                 or  (_type = UIT_BOOLEAN) )  and  (result_buf = nil) then
    begin
        ERR_raise(ERR_LIB_UI, UI_R_NO_RESULT_BUFFER);
    end
    else
    begin
      ret := OPENSSL_zalloc(sizeof(ret^));
      if ret <> nil then
      begin
          ret.out_string := prompt;
          ret.flags := get_result(prompt_freeable>0 , OUT_STRING_FREEABLE , 0);
          ret.input_flags := input_flags;
          ret.&type := _type;
          ret.result_buf := result_buf;
      end;
    end;
    Result := ret;
end;


function general_allocate_string(ui : PUI;const prompt : PUTF8Char; prompt_freeable : integer; _type : TUI_string_types; input_flags : integer; result_buf : PUTF8Char; minsize, maxsize : integer;const test_buf : PUTF8Char):integer;
var
  ret : integer;
  s : PUI_STRING;
begin
    ret := -1;
    s := general_allocate_prompt(ui, prompt, prompt_freeable,
                                           _type, input_flags, result_buf);
    if s <> nil then
    begin
        if allocate_string_stack(ui) >= 0 then
        begin
            s._.string_data.result_minsize := minsize;
            s._.string_data.result_maxsize := maxsize;
            s._.string_data.test_buf := test_buf;
            ret := sk_UI_STRING_push(ui.strings, s);
            { sk_push() returns 0 on error.  Let's adapt that }
            if ret <= 0 then
            begin
                Dec(ret);
                free_string(s);
            end;
        end
        else
            free_string(s);
    end;
    Result := ret;
end;




function UI_add_input_string(ui : PUI;const prompt : PUTF8Char; flags : integer; result_buf : PUTF8Char; minsize, maxsize : integer):integer;
begin
    Result := general_allocate_string(ui, prompt, 0,
                                   UIT_PROMPT, flags, result_buf, minsize,
                                   maxsize, nil);
end;


function UI_construct_prompt(ui : PUI;const phrase_desc, object_name : PUTF8Char):PUTF8Char;
var
  prompt : PUTF8Char;
  prompt1, prompt2, prompt3 : PUTF8Char;
  len : integer;
begin
    prompt := nil;
    if (ui <> nil)  and  (ui.meth <> nil)  and
       (Assigned( ui.meth.ui_construct_prompt) ) then
       prompt := ui.meth.ui_construct_prompt(ui, phrase_desc, object_name)
    else
    begin
        prompt1 := 'Enter ';
        prompt2 := ' for ';
        prompt3 := ':';
        len := 0;
        if phrase_desc = nil then
           Exit(nil);
        len := sizeof(prompt1) - 1 + Length(phrase_desc);
        if object_name <> nil then
           len  := len + (sizeof(prompt2) - 1 + Length(object_name));
        len  := len + (sizeof(prompt3) - 1);
        prompt := OPENSSL_malloc(len + 1);
        if prompt =  nil then
        begin
            ERR_raise(ERR_LIB_UI, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        OPENSSL_strlcpy(prompt, prompt1, len + 1);
        OPENSSL_strlcat(prompt, phrase_desc, len + 1);
        if object_name <> nil then
        begin
            OPENSSL_strlcat(prompt, prompt2, len + 1);
            OPENSSL_strlcat(prompt, object_name, len + 1);
        end;
        OPENSSL_strlcat(prompt, prompt3, len + 1);
    end;
    Result := prompt;
end;


function UI_add_user_data( ui : PUI; user_data : Pointer):Pointer;
var
  old_data : Pointer;
begin
    old_data := ui.user_data;
    if (ui.flags and UI_FLAG_DUPL_DATA) <> 0 then
    begin
        ui.meth.ui_destroy_data(ui, old_data);
        old_data := nil;
    end;
    ui.user_data := user_data;
    ui.flags := ui.flags and (not UI_FLAG_DUPL_DATA);
    Result := old_data;
end;



function UI_set_method(ui : PUI;const meth : PUI_METHOD):PUI_METHOD;
begin
    ui.meth := meth;
    Result := ui.meth;
end;





procedure free_string( uis : PUI_STRING);
begin
    if (uis.flags and OUT_STRING_FREEABLE) > 0 then
    begin
        OPENSSL_free(PUTF8Char(uis.out_string));
        case uis.&type of
            UIT_BOOLEAN:
            begin
                OPENSSL_free(PUTF8Char(  uis._.boolean_data.action_desc));
                OPENSSL_free(PUTF8Char(  uis._.boolean_data.ok_chars));
                OPENSSL_free(PUTF8Char(  uis._.boolean_data.cancel_chars));
            end;
            UIT_NONE,
            UIT_PROMPT,
            UIT_VERIFY,
            UIT_ERROR,
            UIT_INFO:
            begin
              //break;
            end;
        end;
    end;
    OPENSSL_free(uis);
end;





function ossl_check_UI_STRING_type( ptr : PUI_STRING):PUI_STRING;
begin
  Result :=ptr;
end;


function ossl_check_UI_STRING_compfunc_type( cmp : sk_UI_STRING_compfunc):OPENSSL_sk_compfunc;
begin
  Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_UI_STRING_copyfunc_type( cpy : sk_UI_STRING_copyfunc):OPENSSL_sk_copyfunc;
begin
  Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_UI_STRING_freefunc_type( fr : sk_UI_STRING_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function ossl_check_UI_STRING_sk_type(sk: Pstack_st_UI_STRING):POPENSSL_STACK;
begin
   result := POPENSSL_STACK( sk);
end;



procedure UI_free( ui : PUI);
begin
    if ui = nil then Exit;
    if (ui.flags and UI_FLAG_DUPL_DATA) <> 0 then
    begin
        ui.meth.ui_destroy_data(ui, ui.user_data);
    end;
    sk_UI_STRING_pop_free(ui.strings, free_string);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_UI, ui, @ui.ex_data);
    CRYPTO_THREAD_lock_free(ui.lock);
    OPENSSL_free(ui);
end;

function UI_null:PUI_METHOD;
begin
    Result := @g_ui_null;
end;

function UI_set_result_ex(ui : PUI; uis : PUI_STRING;const _result : PUTF8Char; len : integer):integer;
var
  p : PUTF8Char;
  label _break;
begin
    ui.flags := ui.flags and (not UI_FLAG_REDOABLE);
    case uis.&type of
        UIT_PROMPT,
        UIT_VERIFY:
        begin
            if len < uis._.string_data.result_minsize then
            begin
                ui.flags  := ui.flags  or UI_FLAG_REDOABLE;
                ERR_raise_data(ERR_LIB_UI, UI_R_RESULT_TOO_SMALL,
                             Format('You must type in %d to %d characters',
                               [uis._.string_data.result_minsize,
                               uis._.string_data.result_maxsize]));
                Exit(-1);
            end;
            if len > uis._.string_data.result_maxsize then
            begin
                ui.flags  := ui.flags  or UI_FLAG_REDOABLE;
                ERR_raise_data(ERR_LIB_UI, UI_R_RESULT_TOO_LARGE,
                               Format('You must type in %d to %d characters',
                               [uis._.string_data.result_minsize,
                               uis._.string_data.result_maxsize]));
                Exit(-1);
            end;
            if uis.result_buf = nil then
            begin
                ERR_raise(ERR_LIB_UI, UI_R_NO_RESULT_BUFFER);
                Exit(-1);
            end;
            memcpy(uis.result_buf, _result, len);
            if len <= uis._.string_data.result_maxsize then
               uis.result_buf[len] := #0;
            uis.result_len := len;
        end;
        UIT_BOOLEAN:
        begin
            if uis.result_buf = nil then
            begin
                ERR_raise(ERR_LIB_UI, UI_R_NO_RESULT_BUFFER);
                Exit(-1);
            end;
            uis.result_buf[0] := #0;
            p := _result;
            while p^ <> #0 do
            begin
                if strchr(uis._.boolean_data.ok_chars, p^) <> nil then
                begin
                    uis.result_buf[0] := uis._.boolean_data.ok_chars[0];
                    break;
                end;
                if strchr(uis._.boolean_data.cancel_chars, p^) <> nil then
                begin
                    uis.result_buf[0] := uis._.boolean_data.cancel_chars[0];
                    break;
                end;
                Inc(p);
            end;
        end;
        UIT_NONE,
        UIT_INFO,
        UIT_ERROR:
            goto _break;
    end;
_break:
    Result := 0;
end;




function UI_get0_test_string( uis : PUI_STRING):PUTF8Char;
label _break;
begin
    case uis.&type of
    UIT_VERIFY:
        Exit(uis._.string_data.test_buf);
    UIT_NONE,
    UIT_BOOLEAN,
    UIT_INFO,
    UIT_ERROR,
    UIT_PROMPT:
        goto _break;
    end;
_break:
    Result := nil;
end;



function UI_get0_result_string( uis : PUI_STRING):PUTF8Char;
label _break;
begin
    case uis.&type of
    UIT_PROMPT,
    UIT_VERIFY:
        Exit(uis.result_buf);
    UIT_NONE,
    UIT_BOOLEAN,
    UIT_INFO,
    UIT_ERROR:
        goto _break;
    end;
_break:
    Result := nil;
end;

function UI_get_input_flags( uis : PUI_STRING):integer;
begin
    Result := uis.input_flags;
end;

function UI_set_result(ui : PUI; uis : PUI_STRING;const _result : PUTF8Char):integer;
begin
    Result := UI_set_result_ex(ui, uis, _result, Length(_result));
end;

function UI_get0_action_string( uis : PUI_STRING):PUTF8Char;
label _break;
begin
    case uis.&type of
        UIT_BOOLEAN:
            Exit(uis._.boolean_data.action_desc);
        UIT_PROMPT,
        UIT_NONE,
        UIT_VERIFY,
        UIT_INFO,
        UIT_ERROR:
           goto _break;
    end;
_break:
    Result := nil;
end;



function UI_get0_output_string( uis : PUI_STRING):PUTF8Char;
begin
    Result := uis.out_string;
end;


function UI_get_string_type( uis : PUI_STRING):TUI_string_types;
begin
    Result := uis.&type;
end;

function UI_new_method( method : PUI_METHOD):PUI;
var
  ret : PUI;
begin
    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_UI, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then
     begin
        ERR_raise(ERR_LIB_UI, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        Exit(nil);
    end;
    if method = nil then
       method := UI_get_default_method();
    if method = nil then
       method := UI_null();
    ret.meth := method;
    if 0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_UI, ret, @ret.ex_data) then
    begin
        UI_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;



function UI_new:PUI;
begin
    Result := UI_new_method(nil);
end;


end.
