unit openssl3.crypto.param_build_set;

interface
uses OpenSSL.Api;

function ossl_param_build_set_bn(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; bn : PBIGNUM):integer;
function ossl_param_build_set_int(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; num : integer):integer;
function ossl_param_build_set_octet_string(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; data : PByte; data_len : size_t):int;
function ossl_param_build_set_utf8_string(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key, buf : PUTF8Char):integer;
function ossl_param_build_set_long(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; num : long):integer;
function ossl_param_build_set_multi_key_bn(bld : POSSL_PARAM_BLD; params : POSSL_PARAM;const names : PPUTF8Char; stk : Pstack_st_BIGNUM_const):integer;
function ossl_param_build_set_bn_pad(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; bn : PBIGNUM; sz : size_t):integer;


implementation

uses openssl3.crypto.mem, openssl3.crypto.stack,openssl3.crypto.param_build,
     openssl3.crypto.params, openssl3.crypto.evp.ctrl_params_translate,
     OpenSSL3.crypto.rsa.rsa_backend, OpenSSL3.Err;




function ossl_param_build_set_bn_pad(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; bn : PBIGNUM; sz : size_t):integer;
begin
    if bld <> nil then
       Exit(OSSL_PARAM_BLD_push_BN_pad(bld, key, bn, sz));
    p := OSSL_PARAM_locate(p, key);
    if p <> nil then
    begin
        if sz > p.data_size then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
            Exit(0);
        end;
        p.data_size := sz;
        Exit(OSSL_PARAM_set_BN(p, bn));
    end;
    Result := 1;
end;

function ossl_param_build_set_multi_key_bn(bld : POSSL_PARAM_BLD; params : POSSL_PARAM;const names : PPUTF8Char; stk : Pstack_st_BIGNUM_const):integer;
var
  i, sz : integer;

  p : POSSL_PARAM;
begin
{$POINTERMATH ON}
    sz := sk_BIGNUM_const_num(stk);
    if bld <> nil then
    begin
        i := 0;
        while ( i < sz)  and  (names[i] <> nil) do
        begin
            if  0>= OSSL_PARAM_BLD_push_BN(bld, names[i],
                                        sk_BIGNUM_const_value(stk, i))  then
                Exit(0);
            Inc(i);
        end;
        Exit(1);
    end;
    i := 0;
   while ( i < sz)  and  (names[i] <> nil) do
   begin
        p := OSSL_PARAM_locate(params, names[i]);
        if p <> nil then
        begin
            if 0>= OSSL_PARAM_set_BN(p, sk_BIGNUM_const_value(stk, i)) then
               Exit(0);
        end;
        Inc(i);
    end;
    Result := 1;
{$POINTERMATH OFF}
end;




function ossl_param_build_set_long(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; num : long):integer;
begin
    if bld <> nil then
       Exit(OSSL_PARAM_BLD_push_long(bld, key, num));
    p := OSSL_PARAM_locate(p, key);
    if p <> nil then Exit(OSSL_PARAM_set_long(p, num));
    Result := 1;
end;




function ossl_param_build_set_utf8_string(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key, buf : PUTF8Char):integer;
begin
    if bld <> nil then
       Exit(OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, 0));
    p := OSSL_PARAM_locate(p, key);
    if p <> nil then
       Exit(OSSL_PARAM_set_utf8_string(p, buf));
    Result := 1;
end;



function ossl_param_build_set_octet_string(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; data : PByte; data_len : size_t):int;
begin
    if bld <> nil then
       Exit(OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len));
    p := OSSL_PARAM_locate(p, key);
    if p <> nil then
       Exit(OSSL_PARAM_set_octet_string(p, data, data_len));
    Result := 1;
end;




function ossl_param_build_set_int(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; num : integer):integer;
begin
    if bld <> nil then
       Exit(OSSL_PARAM_BLD_push_int(bld, key, num));
    p := OSSL_PARAM_locate(p, key);
    if p <> nil then
       Exit(OSSL_PARAM_set_int(p, num));
    Result := 1;
end;



function ossl_param_build_set_bn(bld : POSSL_PARAM_BLD; p : POSSL_PARAM;const key : PUTF8Char; bn : PBIGNUM):integer;
begin
    if bld <> nil then
       Exit(OSSL_PARAM_BLD_push_BN(bld, key, bn));
    p := OSSL_PARAM_locate(p, key);
    if p <> nil then
       Exit( Int(OSSL_PARAM_set_BN(p, bn) > 0));
    Result := 1;
end;






end.
