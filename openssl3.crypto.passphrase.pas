unit openssl3.crypto.passphrase;

interface
uses OpenSSL.Api;


procedure ossl_pw_clear_passphrase_data( data : Possl_passphrase_data_st);
procedure ossl_pw_clear_passphrase_cache( data : Possl_passphrase_data_st);
function ossl_pw_set_passphrase(data : Possl_passphrase_data_st;const passphrase : PByte; passphrase_len : size_t):integer;
function ossl_pw_set_ossl_passphrase_cb( data : Possl_passphrase_data_st; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
function ossl_pw_set_ui_method(data : Possl_passphrase_data_st;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
function ossl_pw_enable_passphrase_caching( data : Possl_passphrase_data_st):integer;
function ossl_pw_disable_passphrase_caching( data : Possl_passphrase_data_st):integer;
function do_ui_passphrase(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const prompt_info : PUTF8Char; verify : integer;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
function ossl_pw_get_passphrase(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const params : POSSL_PARAM; verify : integer; data : Possl_passphrase_data_st):integer;
function ossl_pw_get_password(buf : PUTF8Char; size, rwflag : integer; userdata : Pointer;const info : PUTF8Char):integer;
function ossl_pw_pem_password( buf : PUTF8Char; size, rwflag : integer; userdata : Pointer):integer;
function ossl_pw_pvk_password( buf : PUTF8Char; size, rwflag : integer; userdata : Pointer):integer;
function ossl_pw_passphrase_callback_enc(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const params : POSSL_PARAM; arg : Pointer):integer;
function ossl_pw_passphrase_callback_dec(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const params : POSSL_PARAM; arg : Pointer):integer;
function ossl_pw_set_pem_password_cb(data : Possl_passphrase_data_st;cb : Tpem_password_cb; cbarg : Pointer):integer;

implementation

uses openssl3.crypto.mem, OpenSSL3.Err, OpenSSL3.common, openssl3.crypto.o_str,
     openssl3.crypto.params, OpenSSL3.openssl.params,
     openssl3.crypto.ui.ui_lib, openssl3.crypto.ui.ui_util;


function ossl_pw_set_pem_password_cb(data : Possl_passphrase_data_st;cb : Tpem_password_cb; cbarg : Pointer):integer;
begin
    if not ossl_assert( (data <> nil)  and  (Assigned(cb)) ) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ossl_pw_clear_passphrase_data(data);
    data.&type := is_pem_password;
    data._.pem_password.password_cb := cb;
    data._.pem_password.password_cbarg := cbarg;
    Result := 1;
end;


procedure ossl_pw_clear_passphrase_data( data : Possl_passphrase_data_st);
begin
    if data <> nil then
    begin
        if data.&type = is_expl_passphrase then
            OPENSSL_clear_free(Pointer(data._.expl_passphrase.passphrase_copy),
                               data._.expl_passphrase.passphrase_len);
        ossl_pw_clear_passphrase_cache(data);
        memset(data, 0, sizeof(data^));
    end;
end;


procedure ossl_pw_clear_passphrase_cache( data : Possl_passphrase_data_st);
begin
    OPENSSL_clear_free(Pointer(data.cached_passphrase), data.cached_passphrase_len);
    data.cached_passphrase := nil;
end;


function ossl_pw_set_passphrase(data : Possl_passphrase_data_st;const passphrase : PByte; passphrase_len : size_t):integer;
begin
    if not ossl_assert( (data <> nil)  and  (passphrase <> nil) ) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ossl_pw_clear_passphrase_data(data);
    data.&type := is_expl_passphrase;
    if passphrase_len <> 0  then
       data._.expl_passphrase.passphrase_copy := OPENSSL_memdup(passphrase, passphrase_len)
    else
       data._.expl_passphrase.passphrase_copy := OPENSSL_malloc(1);

    if data._.expl_passphrase.passphrase_copy = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    data._.expl_passphrase.passphrase_len := passphrase_len;
    Result := 1;
end;




function ossl_pw_set_ossl_passphrase_cb( data : Possl_passphrase_data_st; cb : TOSSL_PASSPHRASE_CALLBACK; cbarg : Pointer):integer;
begin
    if not ossl_assert( (data <> nil)  and  (Assigned(cb)) ) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ossl_pw_clear_passphrase_data(data);
    data.&type := is_ossl_passphrase;
    data._.ossl_passphrase.passphrase_cb := cb;
    data._.ossl_passphrase.passphrase_cbarg := cbarg;
    Result := 1;
end;


function ossl_pw_set_ui_method(data : Possl_passphrase_data_st;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
begin
    if not ossl_assert( (data <> nil)  and  (ui_method <> nil) ) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ossl_pw_clear_passphrase_data(data);
    data.&type := is_ui_method;
    data._.ui_method.ui_method := ui_method;
    data._.ui_method.ui_method_data := ui_data;
    Result := 1;
end;


function ossl_pw_enable_passphrase_caching( data : Possl_passphrase_data_st):integer;
begin
    data.flag_cache_passphrase := 1;
    Result := 1;
end;


function ossl_pw_disable_passphrase_caching( data : Possl_passphrase_data_st):integer;
begin
    data.flag_cache_passphrase := 0;
    Result := 1;
end;


function do_ui_passphrase(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const prompt_info : PUTF8Char; verify : integer;const ui_method : PUI_METHOD; ui_data : Pointer):integer;
var
  prompt,
  ipass,
  vpass      : PUTF8Char;
  prompt_idx,
  verify_idx,
  res        : integer;
  ui         : PUI;
  ret        : integer;
  label _end;
begin
    prompt := nil;
    ipass := nil;
    vpass := nil;
    prompt_idx := -1;
    verify_idx := -1;
    ui := nil;
    ret := 0;
    if not ossl_assert( (pass <> nil)  and  (pass_size <> 0)  and  (pass_len <> nil) ) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ui := UI_new();
    if ui = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if ui_method <> nil then
    begin
        UI_set_method(ui, ui_method);
        if ui_data <> nil then
           UI_add_user_data(ui, ui_data);
    end;
    { Get an application constructed prompt }
    prompt := UI_construct_prompt(ui, 'pass phrase', prompt_info);
    if prompt = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        goto _end ;
    end;
    { Get a buffer for verification prompt }
    ipass := OPENSSL_zalloc(pass_size + 1);
    if ipass = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        goto _end ;
    end;
    prompt_idx := UI_add_input_string(ui, prompt,
                                     UI_INPUT_FLAG_DEFAULT_PWD,
                                     ipass, 0, pass_size) - 1;
    if prompt_idx < 0 then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB);
        goto _end ;
    end;
    if verify>0 then
    begin
        { Get a buffer for verification prompt }
        vpass := OPENSSL_zalloc(pass_size + 1);
        if vpass = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            goto _end ;
        end;
        verify_idx := UI_add_verify_string(ui, prompt,
                                          UI_INPUT_FLAG_DEFAULT_PWD,
                                          vpass, 0, pass_size,
                                          ipass) - 1;
        if verify_idx < 0 then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB);
            goto _end ;
        end;
    end;
    case (UI_process(ui)) of
        -2:
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERRUPTED_OR_CANCELLED);
            //break;
        -1:
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB);
            //break;
        else
        begin
            res := UI_get_result_length(ui, prompt_idx);
            if res < 0 then
            begin
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB);
                exit;
            end;
            pass_len^ := size_t( res);
            memcpy(pass, ipass, pass_len^);
            ret := 1;

        end;
     end;
 _end:
    OPENSSL_clear_free(Pointer(vpass), pass_size + 1);
    OPENSSL_clear_free(Pointer(ipass), pass_size + 1);
    OPENSSL_free(Pointer(prompt));
    UI_free(ui);
    Result := ret;
end;


function ossl_pw_get_passphrase(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const params : POSSL_PARAM; verify : integer; data : Possl_passphrase_data_st):integer;
var
    source              : PUTF8Char;
    source_len          : size_t;
    prompt_info         : PUTF8Char;
    ui_method,
    allocated_ui_method : PUI_METHOD;
    ui_data             : Pointer;
    p                   : POSSL_PARAM;
    ret                 : integer;
    cb1                 : TOSSL_PASSPHRASE_CALLBACK;
    cbarg               : Pointer;
    cb2                 : Tpem_password_cb;
    new_cache           : Pointer;
    label _do_cache;
begin
    source := nil;
    source_len := 0;
    prompt_info := nil;
    ui_method := nil;
    allocated_ui_method := nil;
    ui_data := nil;
    p := nil;
    { Handle explicit and cached passphrases }
    if data.&type = is_expl_passphrase then
    begin
        source := data._.expl_passphrase.passphrase_copy;
        source_len := data._.expl_passphrase.passphrase_len;
    end
    else
    if (data.flag_cache_passphrase>0)  and  (data.cached_passphrase <> nil) then
    begin
        source := data.cached_passphrase;
        source_len := data.cached_passphrase_len;
    end;
    if source <> nil then
    begin
        if source_len > pass_size then
            source_len := pass_size;
        memcpy(pass, source, source_len);
        pass_len^ := source_len;
        Exit(1);
    end;
    { Handle the is_ossl_passphrase case...  that's pretty direct }
    if data.&type = is_ossl_passphrase then
    begin
        cb1 := data._.ossl_passphrase.passphrase_cb;
        cbarg := data._.ossl_passphrase.passphrase_cbarg;
        ret := cb1(pass, pass_size, pass_len, params, cbarg);
        goto _do_cache ;
    end;
    { Handle the is_pem_password and is_ui_method cases }
    p := OSSL_PARAM_locate_const(params, OSSL_PASSPHRASE_PARAM_INFO);
    if (p <> nil)  then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
        begin
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT,
                           'Prompt info data type incorrect');
            Exit(0);
        end;
        prompt_info := p.data;
    end;
    if data.&type = is_pem_password then
    begin
        { We use a UI wrapper for PEM }
        cb2 := data._.pem_password.password_cb;

        allocated_ui_method := UI_UTIL_wrap_read_pem_callback(cb2, verify);
        ui_method := allocated_ui_method;
        ui_data := data._.pem_password.password_cbarg;
        if ui_method = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end
    else
    if (data.&type = is_ui_method) then
    begin
        ui_method := data._.ui_method.ui_method;
        ui_data := data._.ui_method.ui_method_data;
    end;
    if ui_method = nil then
    begin
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT,
                       'No password method specified');
        Exit(0);
    end;
    ret := do_ui_passphrase(pass, pass_size, pass_len, prompt_info, verify,
                           ui_method, ui_data);
    UI_destroy_method(allocated_ui_method);
 _do_cache:
    if (ret >0) and  (data.flag_cache_passphrase>0) then
    begin
        if (data.cached_passphrase = nil )
             or  (pass_len^ > data.cached_passphrase_len) then
        begin
            new_cache :=
                OPENSSL_clear_realloc(Pointer(data.cached_passphrase),
                                      data.cached_passphrase_len,
                                      pass_len^ + 1);
            if new_cache = nil then
            begin
                OPENSSL_cleanse(pass, pass_len^);
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            data.cached_passphrase := new_cache;
        end;
        memcpy(data.cached_passphrase, pass, pass_len^);
        data.cached_passphrase[pass_len^] := #0;
        data.cached_passphrase_len := pass_len^;
    end;
    Result := ret;
end;


function ossl_pw_get_password(buf : PUTF8Char; size, rwflag : integer; userdata : Pointer;const info : PUTF8Char):integer;
var
    password_len : size_t;

    params       : array[0..1] of TOSSL_PARAM;
begin
    password_len := 0;
    params[0] := _OSSL_PARAM_utf8_string(OSSL_PASSPHRASE_PARAM_INFO, nil, 0);
    params[1] := OSSL_PARAM_END;
 
    params[0].data := Pointer( info);
    if ossl_pw_get_passphrase(buf, size_t( size), @password_len, @params,
                               rwflag, userdata)>0 then
        Exit(int (password_len));
    Result := -1;
end;


function ossl_pw_pem_password( buf : PUTF8Char; size, rwflag : integer; userdata : Pointer):integer;
begin
    Result := ossl_pw_get_password(buf, size, rwflag, userdata, 'PEM');
end;


function ossl_pw_pvk_password( buf : PUTF8Char; size, rwflag : integer; userdata : Pointer):integer;
begin
    Result := ossl_pw_get_password(buf, size, rwflag, userdata, 'PVK');
end;


function ossl_pw_passphrase_callback_enc(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const params : POSSL_PARAM; arg : Pointer):integer;
begin
    Result := ossl_pw_get_passphrase(pass, pass_size, pass_len, params, 1, arg);
end;


function ossl_pw_passphrase_callback_dec(pass : PUTF8Char; pass_size : size_t; pass_len : Psize_t;const params : POSSL_PARAM; arg : Pointer):integer;
begin
    Result := ossl_pw_get_passphrase(pass, pass_size, pass_len, params, 0, arg);
end;


end.
