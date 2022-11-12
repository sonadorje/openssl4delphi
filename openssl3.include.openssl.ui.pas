unit openssl3.include.openssl.ui;

interface
uses OpenSSL.Api;

procedure sk_UI_STRING_pop_free(sk: Pointer; freefunc: sk_UI_STRING_freefunc) ;
function sk_UI_STRING_new_null: Pstack_st_UI_STRING;
function sk_UI_STRING_push(sk, ptr: Pointer): int;
function sk_UI_STRING_num(sk: Pointer): int;
function sk_UI_STRING_value(sk: Pointer; idx: int): PUI_STRING;

implementation
uses openssl3.crypto.stack, openssl3.crypto.ui.ui_lib;

function sk_UI_STRING_value(sk: Pointer; idx: int): PUI_STRING;
begin
    Result := PUI_STRING(OPENSSL_sk_value(ossl_check_const_UI_STRING_sk_type(sk), idx))
end;

function sk_UI_STRING_num(sk: Pointer): int;
begin
   result := OPENSSL_sk_num(ossl_check_const_UI_STRING_sk_type(sk));
end;

function sk_UI_STRING_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_UI_STRING_sk_type(sk),
                   ossl_check_UI_STRING_type(ptr))
end;

function sk_UI_STRING_new_null: Pstack_st_UI_STRING;
begin
   Result := Pstack_st_UI_STRING(OPENSSL_sk_new_null)
end;

procedure sk_UI_STRING_pop_free(sk: Pointer; freefunc: sk_UI_STRING_freefunc) ;
begin
   OPENSSL_sk_pop_free(ossl_check_UI_STRING_sk_type(sk),
                       ossl_check_UI_STRING_freefunc_type(freefunc))
end;

end.
