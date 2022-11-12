unit openssl3.crypto.self_test_core;

interface
uses OpenSSL.Api;


procedure OSSL_SELF_TEST_set_callback( libctx : POSSL_LIB_CTX; cb : POSSL_CALLBACK; cbarg : Pointer);
 function self_test_set_callback_new( ctx : POSSL_LIB_CTX):Pointer;
  procedure self_test_set_callback_free( stcb : Pointer);
 procedure OSSL_SELF_TEST_get_callback( libctx : POSSL_LIB_CTX; cb : PPOSSL_CALLBACK; cbarg : PPointer);
 procedure OSSL_SELF_TEST_onbegin(st : POSSL_SELF_TEST;const &type, desc : PUTF8Char);
procedure OSSL_SELF_TEST_free( st : POSSL_SELF_TEST);

function get_self_test_callback( libctx : POSSL_LIB_CTX):PSELF_TEST_CB;
function OSSL_SELF_TEST_new( cb : POSSL_CALLBACK; cbarg : Pointer):POSSL_SELF_TEST;
procedure self_test_setparams( st : POSSL_SELF_TEST);
function OSSL_SELF_TEST_oncorrupt_byte( st : POSSL_SELF_TEST; bytes : PByte):integer;
procedure OSSL_SELF_TEST_onend( st : POSSL_SELF_TEST; ret : integer);


const self_test_set_callback_method : TOSSL_LIB_CTX_METHOD = (
    priority:OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
    new_func: self_test_set_callback_new;
    free_func: self_test_set_callback_free
);



implementation
uses openssl3.crypto.context, openssl3.crypto.mem, openssl3.crypto.params;


procedure OSSL_SELF_TEST_free( st : POSSL_SELF_TEST);
begin
    OPENSSL_free(Pointer(st));
end;

procedure OSSL_SELF_TEST_onend( st : POSSL_SELF_TEST; ret : integer);
begin
    if (st <> nil)  and  (Assigned(st.cb)) then
    begin
        if(ret = 1 ) then
          st.phase := OSSL_SELF_TEST_PHASE_PASS
        else
          st.phase := OSSL_SELF_TEST_PHASE_FAIL;
        self_test_setparams(st);
        st.cb(@st.params, st.cb_arg);
        st.phase := OSSL_SELF_TEST_PHASE_NONE;
        st.&type := OSSL_SELF_TEST_TYPE_NONE;
        st.desc := OSSL_SELF_TEST_DESC_NONE;
    end;
end;






function OSSL_SELF_TEST_oncorrupt_byte( st : POSSL_SELF_TEST; bytes : PByte):integer;
begin
    if (st <> nil)  and  Assigned(st.cb) then
    begin
        st.phase := OSSL_SELF_TEST_PHASE_CORRUPT;
        self_test_setparams(st);
        if  0>=st.cb(@st.params, st.cb_arg) then
        begin
            bytes[0]  := bytes[0] xor 1;
            Exit(1);
        end;
    end;
    Result := 0;
end;

procedure OSSL_SELF_TEST_onbegin(st : POSSL_SELF_TEST;const &type, desc : PUTF8Char);
begin
    if (st <> nil)  and  (Assigned(st.cb)) then
    begin
        st.phase := OSSL_SELF_TEST_PHASE_START;
        st.&type := &type;
        st.desc := desc;
        self_test_setparams(st);
        st.cb(@st.params, st.cb_arg);
    end;
end;




procedure self_test_setparams( st : POSSL_SELF_TEST);
var
  n : size_t;
begin
    n := 0;
    if Assigned(st.cb) then
    begin
        st.params[PostInc(n)] :=
            OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_PHASE,
                                             PUTF8Char (st.phase), 0);
        st.params[PostInc(n)] :=
            OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_TYPE,
                                             PUTF8Char (st.&type), 0);
        st.params[PostInc(n)] :=
            OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_DESC,
                                             PUTF8Char (st.desc), 0);
    end;
    st.params[PostInc(n)] := OSSL_PARAM_construct_end();
end;





function OSSL_SELF_TEST_new( cb : POSSL_CALLBACK; cbarg : Pointer):POSSL_SELF_TEST;
var
  ret : POSSL_SELF_TEST;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then Exit(nil);
    ret.cb := cb;
    ret.cb_arg := cbarg;
    ret.phase := '';
    ret.&type := '';
    ret.desc := '';
    self_test_setparams(ret);
    Result := ret;
end;

procedure OSSL_SELF_TEST_get_callback( libctx : POSSL_LIB_CTX; cb : PPOSSL_CALLBACK; cbarg : PPointer);
var
  stcb : PSELF_TEST_CB;
begin
    stcb := get_self_test_callback(libctx);
    if cb <> nil then
       if (stcb <> nil) then
          cb^ := stcb.cb
       else
          cb^ := nil;
    if cbarg <> nil then
       if (stcb <> nil ) then
          cbarg^ :=  stcb.cbarg
       else
          cbarg^ := nil;
end;

function self_test_set_callback_new( ctx : POSSL_LIB_CTX):Pointer;
var
  stcb : PSELF_TEST_CB;
begin
    stcb := OPENSSL_zalloc(sizeof( stcb^));
    Result := stcb;
end;


procedure self_test_set_callback_free( stcb : Pointer);
begin
    OPENSSL_free(stcb);
end;
function get_self_test_callback( libctx : POSSL_LIB_CTX):PSELF_TEST_CB;
begin
    Exit(ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_SELF_TEST_CB_INDEX,
                                 @self_test_set_callback_method));
end;



procedure OSSL_SELF_TEST_set_callback( libctx : POSSL_LIB_CTX; cb : POSSL_CALLBACK; cbarg : Pointer);
var
  stcb : PSELF_TEST_CB;
begin
    stcb := get_self_test_callback(libctx);
    if stcb <> nil then
    begin
        stcb.cb := cb;
        stcb.cbarg := cbarg;
    end;
end;


end.
