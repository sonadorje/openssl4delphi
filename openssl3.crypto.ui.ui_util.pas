unit openssl3.crypto.ui.ui_util;

interface
uses OpenSSL.Api;
const
  BUFSIZ = 256;


  

  function UI_UTIL_read_pw_string(buf : PUTF8Char; length : integer;const prompt : PUTF8Char; verify : integer):integer;
  function UI_UTIL_read_pw(buf, buff : PUTF8Char; size : integer;const prompt : PUTF8Char; verify : integer):integer;
  procedure ui_new_method_data( parent, ptr : Pointer; ad : PCRYPTO_EX_DATA; idx : integer; argl : long; argp : Pointer);
  function ui_dup_method_data(&to : PCRYPTO_EX_DATA;const from : PCRYPTO_EX_DATA; pptr : PPointer; idx : integer; argl : long; argp : Pointer):integer;
  procedure ui_free_method_data( parent, ptr : Pointer; ad : PCRYPTO_EX_DATA; idx : integer; argl : long; argp : Pointer);
  function ui_open( ui : PUI):integer;
  function ui_read( ui : PUI; uis : PUI_STRING):integer;
  function ui_write( ui : PUI; uis : PUI_STRING):integer;
  function ui_close( ui : PUI):integer;
  function UI_UTIL_wrap_read_pem_callback( cb : Tpem_password_cb; rwflag : integer):PUI_METHOD;
  procedure ui_method_data_index_init_ossl_;
  function ui_method_data_index_init:integer;

var
  ui_method_data_index: int = -1;
  ui_method_data_index_init_ossl_ret_ :int = 0;
  get_index_once: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;

implementation
uses openssl3.crypto.mem, openssl3.crypto.ui.ui_lib, openssl3.crypto.o_str,
     openssl3.crypto.ex_data, OpenSSL3.threads_none,
     openssl3.crypto.pem.pem_lib;






procedure ui_method_data_index_init_ossl_;
begin
   ui_method_data_index_init_ossl_ret_ := ui_method_data_index_init();
end;


function ui_method_data_index_init:integer;
begin
    ui_method_data_index := CRYPTO_get_ex_new_index(14,
                                                   0, Pointer(0) , ui_new_method_data,
                                                   ui_dup_method_data,
                                                   ui_free_method_data);
    Result := 1;
end;


function UI_UTIL_read_pw_string(buf : PUTF8Char; length : integer;const prompt : PUTF8Char; verify : integer):integer;
var
  buff : array[0..(BUFSIZ)-1] of UTF8Char;
  ret : integer;
begin
    ret := UI_UTIL_read_pw(buf, buff, get_result(length > BUFSIZ , BUFSIZ , length),
                        prompt, verify);
    OPENSSL_cleanse(@buff, BUFSIZ);
    Result := ret;
end;


function UI_UTIL_read_pw(buf, buff : PUTF8Char; size : integer;const prompt : PUTF8Char; verify : integer):integer;
var
  ok : integer;

  ui : PUI;
begin
    ok := 0;
    if size < 1 then Exit(-1);
    ui := UI_new();
    if ui <> nil then begin
        ok := UI_add_input_string(ui, prompt, 0, buf, 0, size - 1);
        if (ok >= 0)  and  (verify > 0) then
           ok := UI_add_verify_string(ui, prompt, 0, buff, 0, size - 1, buf);
        if ok >= 0 then
           ok := UI_process(ui);
        UI_free(ui);
    end;
    if ok > 0 then
       ok := 0;
    Result := ok;
end;


procedure ui_new_method_data( parent, ptr : Pointer; ad : PCRYPTO_EX_DATA; idx : integer; argl : long; argp : Pointer);
begin
    {
     * Do nothing, the data is allocated externally and assigned later with
     * CRYPTO_set_ex_data()
     }
end;


function ui_dup_method_data(&to : PCRYPTO_EX_DATA;const from : PCRYPTO_EX_DATA; pptr : PPointer; idx : integer; argl : long; argp : Pointer):integer;
begin
    if pptr^ <> nil then
    begin
        pptr^ := OPENSSL_memdup(pptr^, sizeof(Tpem_password_cb_data));
        if pptr^ <> nil then
           Exit(1);
    end;
    Result := 0;
end;


procedure ui_free_method_data( parent, ptr : Pointer; ad : PCRYPTO_EX_DATA; idx : integer; argl : long; argp : Pointer);
begin
    OPENSSL_free(ptr);
end;


function ui_open( ui : PUI):integer;
begin
    Result := 1;
end;


function ui_read( ui : PUI; uis : PUI_STRING):integer;
var
  _result : array[0..(PEM_BUFSIZE + 1)-1] of UTF8Char;
  data : Ppem_password_cb_data;
  maxsize, len : integer;
begin
    case UI_get_string_type(uis) of

        UIT_PROMPT:
        begin
            data := UI_method_get_ex_data(UI_get_method(ui), ui_method_data_index);
            maxsize := UI_get_result_maxsize(uis);
            len := data.cb(_result,
                          get_result(maxsize > PEM_BUFSIZE , PEM_BUFSIZE , maxsize),
                               data.rwflag, UI_get0_user_data(ui));
            if len >= 0 then
               _result[len] := #0;
            if len < 0 then Exit(len);
            if UI_set_result_ex(ui, uis, _result, len) >= 0  then
                Exit(1);
            Exit(0);
        end;
        UIT_VERIFY,
        UIT_NONE,
        UIT_BOOLEAN,
        UIT_INFO,
        UIT_ERROR:
        begin
          //break;
        end;
    end;
    Result := 1;
end;


function ui_write( ui : PUI; uis : PUI_STRING):integer;
begin
    Result := 1;
end;


function ui_close( ui : PUI):integer;
begin
    Result := 1;
end;


function UI_UTIL_wrap_read_pem_callback( cb : Tpem_password_cb; rwflag : integer):PUI_METHOD;
var
    data      : Ppem_password_cb_data;

    ui_method : PUI_METHOD;
begin
    data := nil;
    ui_method := nil;
    data := OPENSSL_zalloc(sizeof(data^));
    ui_method := UI_create_method('PEM password callback wrapper');
    if (data =  nil)
         or  (ui_method = nil)
         or  (UI_method_set_opener(ui_method, ui_open) < 0)
         or  (UI_method_set_reader(ui_method, ui_read) < 0)
         or  (UI_method_set_writer(ui_method, ui_write) < 0)
         or  (UI_method_set_closer(ui_method, ui_close) < 0)
         or  (0>= get_result(CRYPTO_THREAD_run_once(@get_index_once,
                              ui_method_data_index_init_ossl_) >0,
                              ui_method_data_index_init_ossl_ret_ , 0))
         or  (UI_method_set_ex_data(ui_method, ui_method_data_index, data) < 0) then
    begin
        UI_destroy_method(ui_method);
        OPENSSL_free(Pointer(data));
        Exit(nil);
    end;
    data.rwflag := rwflag;
    if Assigned(cb) then
       data.cb := cb
    else
       data.cb := PEM_def_callback;
    Result := ui_method;
end;

end.
