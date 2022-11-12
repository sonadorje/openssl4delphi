unit OpenSSL3.Err;


interface
uses  OpenSSL.Api, SysUtils;

const

  { TODO : Unable to convert function-like macro: }
  (* ERR_PUT_error ( l , f , r , fn , ln ) ERR_put_error ( l , f , r , fn , ln ) *)
  ERR_TXT_MALLOCED = $01;
  ERR_TXT_STRING = $02;
  ERR_FLAG_MARK = $01;
  ERR_FLAG_CLEAR = $02;
  ERR_NUM_ERRORS = 16;
  ERR_LIB_NONE = 1;
  ERR_LIB_SYS = 2;
  ERR_LIB_BN = 3;
  ERR_LIB_RSA = 4;
  ERR_LIB_DH = 5;
  ERR_LIB_EVP = 6;
  ERR_LIB_BUF = 7;
  ERR_LIB_OBJ = 8;
  ERR_LIB_PEM = 9;
  ERR_LIB_DSA = 10;
  ERR_LIB_X509 = 11;
  ERR_LIB_ASN1 = 13;
  ERR_LIB_CONF = 14;
  ERR_LIB_CRYPTO = 15;
  ERR_LIB_EC = 16;
  ERR_LIB_SSL = 20;
  ERR_LIB_char = 32;
  ERR_LIB_PKCS7 = 33;
  ERR_LIB_X509V3 = 34;
  ERR_LIB_PKCS12 = 35;
  ERR_LIB_RAND = 36;
  ERR_LIB_DSO = 37;
  ERR_LIB_ENGINE = 38;
  ERR_LIB_OCSP = 39;
  ERR_LIB_UI = 40;
  ERR_LIB_COMP = 41;
  ERR_LIB_ECDSA = 42;
  ERR_LIB_ECDH = 43;
  ERR_LIB_OSSL_STORE = 44;
  ERR_LIB_FIPS = 45;
  ERR_LIB_CMS = 46;
  ERR_LIB_TS = 47;
  ERR_LIB_HMAC = 48;
  ERR_LIB_CT = 50;
  ERR_LIB_ASYNC = 51;
  ERR_LIB_KDF = 52;
  ERR_LIB_SM2 = 53;
  ERR_LIB_ESS = 54;
  ERR_LIB_PROP = 55;
  ERR_LIB_CRMF = 56;
  ERR_LIB_PROV = 57;
  ERR_LIB_CMP = 58;
  ERR_LIB_OSSL_ENCODER = 59;
  ERR_LIB_OSSL_DECODER = 60;
  ERR_LIB_HTTP = 61;
  ERR_LIB_USER = 128;
  ERR_LIB_OFFSET = 23;
  ERR_LIB_MASK = $FF;
  ERR_RFLAGS_OFFSET = 18;
  ERR_RFLAGS_MASK = $1F;
  ERR_REASON_MASK = $7FFFFF;
  ERR_RFLAG_FATAL = ($1 shl ERR_RFLAGS_OFFSET);
  ERR_RFLAG_COMMON = ($2 shl ERR_RFLAGS_OFFSET);

  SYS_F_FOPEN = 0;
  SYS_F_CONNECT = 0;
  SYS_F_GETSERVBYNAME = 0;
  SYS_F_SOCKET = 0;
  SYS_F_IOCTLSOCKET = 0;
  SYS_F_BIND = 0;
  SYS_F_LISTEN = 0;
  SYS_F_ACCEPT = 0;
  SYS_F_WSASTARTUP = 0;
  SYS_F_OPENDIR = 0;
  SYS_F_FREAD = 0;
  SYS_F_GETADDRINFO = 0;
  SYS_F_GETNAMEINFO = 0;
  SYS_F_SETSOCKOPT = 0;
  SYS_F_GETSOCKOPT = 0;
  SYS_F_GETSOCKNAME = 0;
  SYS_F_GETHOSTBYNAME = 0;
  SYS_F_FFLUSH = 0;
  SYS_F_OPEN = 0;
  SYS_F_CLOSE = 0;
  SYS_F_IOCTL = 0;
  SYS_F_STAT = 0;
  SYS_F_FCNTL = 0;
  SYS_F_FSTAT = 0;
  SYS_F_SENDFILE = 0;
  ERR_R_SYS_LIB = (ERR_LIB_SYS(* 2 *) or ERR_RFLAG_COMMON);
  ERR_R_BN_LIB = (ERR_LIB_BN(* 3 *) or ERR_RFLAG_COMMON);
  ERR_R_RSA_LIB = (ERR_LIB_RSA(* 4 *) or ERR_RFLAG_COMMON);
  ERR_R_DH_LIB = (ERR_LIB_DH(* 5 *) or ERR_RFLAG_COMMON);
  ERR_R_EVP_LIB = (ERR_LIB_EVP(* 6 *) or ERR_RFLAG_COMMON);
  ERR_R_BUF_LIB = (ERR_LIB_BUF(* 7 *) or ERR_RFLAG_COMMON);
  ERR_R_OBJ_LIB = (ERR_LIB_OBJ(* 8 *) or ERR_RFLAG_COMMON);
  ERR_R_PEM_LIB = (ERR_LIB_PEM(* 9 *) or ERR_RFLAG_COMMON);
  ERR_R_DSA_LIB = (ERR_LIB_DSA(* 10 *) or ERR_RFLAG_COMMON);
  ERR_R_X509_LIB = (ERR_LIB_X509(* 11 *) or ERR_RFLAG_COMMON);
  ERR_R_ASN1_LIB = (ERR_LIB_ASN1(* 13 *) or ERR_RFLAG_COMMON);
  ERR_R_CRYPTO_LIB = (ERR_LIB_CRYPTO(* 15 *) or ERR_RFLAG_COMMON);
  ERR_R_EC_LIB = (ERR_LIB_EC(* 16 *) or ERR_RFLAG_COMMON);
  ERR_R_char_LIB = (ERR_LIB_char(* 32 *) or ERR_RFLAG_COMMON);
  ERR_R_PKCS7_LIB = (ERR_LIB_PKCS7(* 33 *) or ERR_RFLAG_COMMON);
  ERR_R_X509V3_LIB = (ERR_LIB_X509V3(* 34 *) or ERR_RFLAG_COMMON);
  ERR_R_ENGINE_LIB = (ERR_LIB_ENGINE(* 38 *) or ERR_RFLAG_COMMON);
  ERR_R_UI_LIB = (ERR_LIB_UI(* 40 *) or ERR_RFLAG_COMMON);
  ERR_R_ECDSA_LIB = (ERR_LIB_ECDSA(* 42 *) or ERR_RFLAG_COMMON);
  ERR_R_OSSL_STORE_LIB = (ERR_LIB_OSSL_STORE(* 44 *) or ERR_RFLAG_COMMON);
  ERR_R_OSSL_DECODER_LIB = (ERR_LIB_OSSL_DECODER(* 60 *) or ERR_RFLAG_COMMON);
  ERR_R_FATAL = (ERR_RFLAG_FATAL or ERR_RFLAG_COMMON);
  ERR_R_MALLOC_FAILURE = (256 or ERR_R_FATAL);
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = (257 or ERR_R_FATAL);
  ERR_R_PASSED_NULL_PARAMETER = (258 or ERR_R_FATAL);
  ERR_R_INTERNAL_ERROR = (259 or ERR_R_FATAL);
  ERR_R_DISABLED = (260 or ERR_R_FATAL);
  ERR_R_INIT_FAIL = (261 or ERR_R_FATAL);
  ERR_R_PASSED_INVALID_ARGUMENT = (262 or ERR_RFLAG_COMMON);
  ERR_R_OPERATION_FAIL = (263 or ERR_R_FATAL);
  ERR_R_INVALID_PROVIDER_FUNCTIONS = (264 or ERR_R_FATAL);
  ERR_R_INTERRUPTED_OR_CANCELLED = (265 or ERR_RFLAG_COMMON);
  ERR_R_NESTED_ASN1_ERROR = (266 or ERR_RFLAG_COMMON);
  ERR_R_MISSING_ASN1_EOS = (267 or ERR_RFLAG_COMMON);
  ERR_R_UNSUPPORTED = (268 or ERR_RFLAG_COMMON);
  ERR_R_FETCH_FAILED = (269 or ERR_RFLAG_COMMON);
  ERR_R_INVALID_PROPERTY_DEFINITION = (270 or ERR_RFLAG_COMMON);
  ERR_R_UNABLE_TO_GET_READ_LOCK = (271 or ERR_R_FATAL);
  ERR_R_UNABLE_TO_GET_WRITE_LOCK = (272 or ERR_R_FATAL);
  ERR_SYSTEM_FLAG  =  (UInt32(INT_MAX) + 1);
  ERR_SYSTEM_MASK  = UInt32(INT_MAX);


var
  err_do_init_ossl_ret_ :int = 0;
  set_err_thread_local: int;
  err_thread_local: CRYPTO_THREAD_LOCAL ;
  err_init: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;

type
  lh_ERR_STRING_DATA_compfunc = function(const a, b : PERR_STRING_DATA):integer;
  lh_ERR_STRING_DATA_hashfunc = function(const a : PERR_STRING_DATA):Cardinal;
  lh_ERR_STRING_DATA_doallfunc = procedure( a : PERR_STRING_DATA);
  ERR_GET_ACTION_e = (EV_POP, EV_PEEK, EV_PEEK_LAST);
  TERR_GET_ACTION  = ERR_GET_ACTION_e;


procedure ERR_raise(lib, reason: Integer);
procedure ERR_raise_data(lib, reason: Integer; fmt: string);
procedure ERR_add_error_data( num : integer; args: array of const);
procedure ERR_add_error_vdata( num : integer; args : array of const);
procedure X509V3_conf_add_error_name_value(val: PCONF_VALUE);
function ossl_err_get_state_int:PERR_STATE;
function err_do_init_ossl_: integer;
function err_do_init():integer;
procedure err_delete_thread_state( unused : Pointer);
procedure ERR_STATE_free( s : PERR_STATE);
procedure err_clear( es : PERR_STATE; i : size_t; deall : integer);
procedure err_clear_data( es : PERR_STATE; i : size_t; deall : integer);
function err_set_error_data_int( data : PUTF8Char; size : size_t; flags, deallocate : integer):integer;
procedure err_set_data( es : PERR_STATE; i : size_t; data : Pointer; datasz : size_t; flags : integer);
procedure ECerr(f, r:integer);
function ERR_GET_REASON( errcode : Cardinal):integer;
function ERR_SYSTEM_ERROR(errcode: uint32): Boolean;
procedure err_free_strings_int;
function ERR_peek_last_error:Cardinal;
function ERR_GET_LIB( errcode : Cardinal):integer;
procedure err_clear_last_constant_time( clear : integer);
function ERR_get_error_all(const _file : PPUTF8Char; line : PInteger;const func, data : PPUTF8Char; flags : PInteger):Cardinal;
procedure ossl_err_string_int(e : Cardinal;const func : PUTF8Char; buf : PUTF8Char; len : size_t);
function ERR_peek_last_error_all(const _file : PPUTF8Char; line : PInteger;const func, data : PPUTF8Char; flags : PInteger):Cardinal;
procedure EVPerr(f, r: int);
function ERR_peek_error:Cardinal;
procedure ERR_clear_error;
function _ERR_load_strings(lib : integer; str : PERR_STRING_DATA):integer;
function ERR_get_next_error_library:integer;
function ERR_unload_strings( lib : integer; str : PERR_STRING_DATA):integer;
procedure err_cleanup;
function ossl_err_load_ERR_strings:integer;
function ERR_PACK(lib,func,reason: int): uint;
function ERR_reason_error_string( e : Cardinal):PUTF8Char;
function ERR_load_strings_const(const str : PERR_STRING_DATA):integer;
function err_load_strings({const} str : PERR_STRING_DATA):integer;
function lh_ERR_STRING_DATA_insert(lh: Plhash_st_ERR_STRING_DATA; ptr: Pointer) : PERR_STRING_DATA;

function ossl_check_ERR_STRING_DATA_lh_plain_type( ptr : PERR_STRING_DATA):PERR_STRING_DATA;
function ossl_check_const_ERR_STRING_DATA_lh_plain_type(const ptr : PERR_STRING_DATA):PERR_STRING_DATA;
function ossl_check_const_ERR_STRING_DATA_lh_type(const lh : Plhash_st_ERR_STRING_DATA):POPENSSL_LHASH;
function ossl_check_ERR_STRING_DATA_lh_type( lh : Plhash_st_ERR_STRING_DATA):POPENSSL_LHASH;
function ossl_check_ERR_STRING_DATA_lh_compfunc_type( cmp : lh_ERR_STRING_DATA_compfunc):TOPENSSL_LH_COMPFUNC;
function ossl_check_ERR_STRING_DATA_lh_hashfunc_type( hfn : lh_ERR_STRING_DATA_hashfunc):TOPENSSL_LH_HASHFUNC;
function ossl_check_ERR_STRING_DATA_lh_doallfunc_type( dfn : lh_ERR_STRING_DATA_doallfunc): TOPENSSL_LH_DOALL_FUNC;
procedure do_err_strings_init_ossl_;
function do_err_strings_init:integer;
function err_string_data_hash(const a : PERR_STRING_DATA):Cardinal;
function err_string_data_cmp(const a, b : PERR_STRING_DATA):integer;
function int_err_get_item(const d : PERR_STRING_DATA):PERR_STRING_DATA;
function lh_ERR_STRING_DATA_retrieve(lh, ptr: Pointer): PERR_STRING_DATA;
procedure lh_ERR_STRING_DATA_free(lh: Pointer);
function lh_ERR_STRING_DATA_delete(lh, ptr: Pointer): PERR_STRING_DATA;
procedure err_patch( lib : integer; str : PERR_STRING_DATA);
function get_error_values(g : TERR_GET_ACTION;const &file : PPUTF8Char; line : PInteger;const func, data : PPUTF8Char; flags : PInteger):Cardinal;
function ERR_lib_error_string( e : Cardinal):PUTF8Char;



var
  _errno: Integer;
  BN_str_reasons, ERR_str_libraries, ERR_str_reasons: array of TERR_STRING_DATA ;
   err_string_lock: PCRYPTO_RWLOCK ;
  int_error_hash: Plhash_st_ERR_STRING_DATA  = nil;
  err_string_init: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
  do_err_strings_init_ossl_ret_: int = 0;
  int_err_library_number: int = ERR_LIB_USER;

function ERR_get_error:Cardinal;
function ERR_error_string( e : Cardinal; ret : PUTF8Char):PUTF8Char;
procedure ERR_error_string_n( e : Cardinal; buf : PUTF8Char; len : size_t);
procedure ERR_load_crypto_strings;

implementation

uses
   openssl3.providers.fips.fipsprov,         OpenSSL3.e_os, openssl3.crypto.mem,
   OpenSSL3.threads_none,                    openssl3.crypto.initthread,
   openssl3.crypto.bio.bio_print,            openssl3.crypto.o_str,
   openssl3.internal.constant_time,
   openssl3.crypto.init,                     openssl3.crypto.lhash;


var
  buf : array[0..255] of UTF8Char;

procedure ERR_load_crypto_strings;
begin
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil)
end;

procedure ERR_error_string_n( e : Cardinal; buf : PUTF8Char; len : size_t);
begin
    ossl_err_string_int(e, '', buf, len);
end;

function ERR_error_string( e : Cardinal; ret : PUTF8Char):PUTF8Char;
begin
    if ret = nil then
       ret := @buf;
    ERR_error_string_n(e, ret, int(sizeof(buf)));
    Result := ret;
end;


function ERR_get_error:Cardinal;
begin
    Result := get_error_values(EV_POP, nil, nil, nil, nil, nil);
end;


function ERR_lib_error_string( e : Cardinal):PUTF8Char;
var
  d : TERR_STRING_DATA;
  p : PERR_STRING_DATA;
  l : Cardinal;
begin
    if 0>=get_result(CRYPTO_THREAD_run_once(@err_string_init, do_err_strings_init_ossl_) >0,
                   do_err_strings_init_ossl_ret_ , 0) then
    begin
        Exit(nil);
    end;
    l := ERR_GET_LIB(e);
    d.error := ERR_PACK(l, 0, 0);
    p := int_err_get_item(@d);
    if p = nil then
       Result := nil
    else
       Result := p._string;
end;

function get_error_values(g : TERR_GET_ACTION;const &file : PPUTF8Char; line : PInteger;const func, data : PPUTF8Char; flags : PInteger):Cardinal;
var
  i : integer;
  es : PERR_STATE;
  ret : Cardinal;
begin
    i := 0;
    es := ossl_err_get_state_int();
    if es = nil then Exit(0);
    {
     * Clear anything that should have been cleared earlier. We do this
     * here because this doesn't have constant-time issues.
     }
    while es.bottom <> es.top do
    begin
        if es.err_flags[es.top] and ERR_FLAG_CLEAR > 0 then
        begin
            err_clear(es, es.top, 0);
            es.top := get_result(es.top > 0 , es.top - 1 , ERR_NUM_ERRORS - 1);
            continue;
        end;
        i := (es.bottom + 1) mod ERR_NUM_ERRORS;
        if es.err_flags[i] and ERR_FLAG_CLEAR > 0 then
        begin
            es.bottom := i;
            err_clear(es, es.bottom, 0);
            continue;
        end;
        break;
    end;
    { If everything has been cleared, the stack is empty. }
    if es.bottom = es.top then Exit(0);
    { Which error, the top of stack (latest one) or the first one? }
    if g = EV_PEEK_LAST then
       i := es.top
    else
        i := (es.bottom + 1) mod ERR_NUM_ERRORS;
    ret := es.err_buffer[i];
    if g = EV_POP then begin
        es.bottom := i;
        es.err_buffer[i] := 0;
    end;
    if &file <> nil then begin
        &file^ := es.err_file[i];
        if &file^ = nil then &file^ := '';
    end;
    if line <> nil then
       line^ := es.err_line[i];
    if func <> nil then
    begin
        func^ := es.err_func[i];
        if func^ = nil then func^ := '';
    end;
    if flags <> nil then flags^ := es.err_data_flags[i];
    if data = nil then begin
        if g = EV_POP then  begin
            err_clear_data(es, i, 0);
        end;
    end
    else
    begin
        data^ := es.err_data[i];
        if data^ = nil then begin
            data^ := '';
            if flags <> nil then flags^ := 0;
        end;
    end;
    Result := ret;
end;


procedure err_patch( lib : integer; str : PERR_STRING_DATA);
var
  plib : Cardinal;
begin
    plib := ERR_PACK(lib, 0, 0);
    while str.error <> 0 do
    begin
        str.error  := str.error  or plib;
        Inc(str);
    end;
end;

function lh_ERR_STRING_DATA_delete(lh, ptr: Pointer): PERR_STRING_DATA;
begin
   Result := PERR_STRING_DATA(OPENSSL_LH_delete(ossl_check_ERR_STRING_DATA_lh_type(lh),
                   ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr)))
end;

procedure lh_ERR_STRING_DATA_free(lh: Pointer);
begin
   OPENSSL_LH_free(ossl_check_ERR_STRING_DATA_lh_type(lh))
end;

function lh_ERR_STRING_DATA_retrieve(lh, ptr: Pointer): PERR_STRING_DATA;
begin
   Result :=  PERR_STRING_DATA(OPENSSL_LH_retrieve(
                    ossl_check_ERR_STRING_DATA_lh_type(lh),
                    ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr)))
end;

function int_err_get_item(const d : PERR_STRING_DATA):PERR_STRING_DATA;
var
  p : PERR_STRING_DATA;
begin
    p := nil;
    if 0>=CRYPTO_THREAD_read_lock(err_string_lock )then
        Exit(nil);
    p := lh_ERR_STRING_DATA_retrieve(int_error_hash, d);
    CRYPTO_THREAD_unlock(err_string_lock);
    Result := p;
end;



function err_string_data_hash(const a : PERR_STRING_DATA):Cardinal;
var
  ret, l : Cardinal;
begin
    l := a.error;
    ret := l  xor  ERR_GET_LIB(l);
    Result := ret  xor  ret mod 19 * 13;
end;


function err_string_data_cmp(const a, b : PERR_STRING_DATA):integer;
begin
    if a.error = b.error then Exit(0);
    Result := get_result(a.error > b.error , 1 , -1);
end;




procedure do_err_strings_init_ossl_;
begin
 do_err_strings_init_ossl_ret_ := do_err_strings_init;
end;


function do_err_strings_init:integer;
begin
    if 0>=OPENSSL_init_crypto($00040000, Pointer(0)) then
        Exit(0);
    err_string_lock := CRYPTO_THREAD_lock_new;
    if err_string_lock = Pointer(0) then
        Exit(0);
    int_error_hash := Plhash_st_ERR_STRING_DATA (OPENSSL_LH_new(
              ossl_check_ERR_STRING_DATA_lh_hashfunc_type(err_string_data_hash),
              ossl_check_ERR_STRING_DATA_lh_compfunc_type(err_string_data_cmp)));
    if int_error_hash = Pointer(0) then
    begin
        CRYPTO_THREAD_lock_free(err_string_lock);
        err_string_lock := Pointer(0) ;
        Exit(0);
    end;
    Result := 1;
end;



function ossl_check_ERR_STRING_DATA_lh_plain_type( ptr : PERR_STRING_DATA):PERR_STRING_DATA;
begin
 Exit(ptr);
end;


function ossl_check_const_ERR_STRING_DATA_lh_plain_type(const ptr : PERR_STRING_DATA):PERR_STRING_DATA;
begin
 Exit(ptr);
end;


function ossl_check_const_ERR_STRING_DATA_lh_type(const lh : Plhash_st_ERR_STRING_DATA):POPENSSL_LHASH;
begin
 Result := POPENSSL_LHASH (lh);
end;


function ossl_check_ERR_STRING_DATA_lh_type( lh : Plhash_st_ERR_STRING_DATA):POPENSSL_LHASH;
begin
 Result := POPENSSL_LHASH (lh);
end;


function ossl_check_ERR_STRING_DATA_lh_compfunc_type( cmp : lh_ERR_STRING_DATA_compfunc): TOPENSSL_LH_COMPFUNC;
begin
 Result := TOPENSSL_LH_COMPFUNC(cmp);
end;


function ossl_check_ERR_STRING_DATA_lh_hashfunc_type( hfn : lh_ERR_STRING_DATA_hashfunc): TOPENSSL_LH_HASHFUNC;
begin
 Result := TOPENSSL_LH_HASHFUNC(hfn);
end;


function ossl_check_ERR_STRING_DATA_lh_doallfunc_type( dfn : lh_ERR_STRING_DATA_doallfunc): TOPENSSL_LH_DOALL_FUNC;
begin
 Result := TOPENSSL_LH_DOALL_FUNC(dfn);
end;

function lh_ERR_STRING_DATA_insert(lh: Plhash_st_ERR_STRING_DATA; ptr: Pointer) : PERR_STRING_DATA;
begin
    Result := PERR_STRING_DATA(OPENSSL_LH_insert(ossl_check_ERR_STRING_DATA_lh_type(lh),
                               ossl_check_ERR_STRING_DATA_lh_plain_type(ptr)))
end;

function err_load_strings({const} str : PERR_STRING_DATA):integer;
begin
    if 0>=CRYPTO_THREAD_write_lock(err_string_lock) then
        Exit(0);
    while str.error > 0 do
    begin
        lh_ERR_STRING_DATA_insert(int_error_hash, PERR_STRING_DATA (str));
        Inc(str);
    end;
    CRYPTO_THREAD_unlock(err_string_lock);
    Result := 1;
end;



function ERR_load_strings_const(const str : PERR_STRING_DATA):integer;
begin
    if ossl_err_load_ERR_strings = 0 then Exit(0);
    err_load_strings(str);
    Result := 1;
end;

function ERR_PACK(lib,func,reason: int): uint;
begin
   Result :=  ((ulong(lib)    and ERR_LIB_MASK   ) shl ERR_LIB_OFFSET) or
              ((ulong(reason) and ERR_REASON_MASK))
end;

function ERR_reason_error_string( e : Cardinal):PUTF8Char;
var
  p : PERR_STRING_DATA;
  d: TERR_STRING_DATA;
  l, r : Cardinal;
begin
    p := nil;
    if 0>= get_result(CRYPTO_THREAD_run_once(@err_string_init, do_err_strings_init_ossl_) > 0,
                          do_err_strings_init_ossl_ret_ , 0)  then
    begin
        Exit(nil);
    end;
    {
     * ERR_reason_error_string can't safely return system error strings,
     * since openssl_strerror_r needs a buffer for thread safety, and we
     * haven't got one that would serve any sensible purpose.
     }
    if ERR_SYSTEM_ERROR(e) then
        Exit(nil);
    l := ERR_GET_LIB(e);
    r := ERR_GET_REASON(e);
    d.error := ERR_PACK(l, 0, r);
    p := int_err_get_item(@d);
    if p = nil then
    begin
        d.error := ERR_PACK(0, 0, r);
        p := int_err_get_item(@d);
    end;
    if p = nil then
       Result := nil
    else
       Result := p._string;
end;

function ossl_err_load_ERR_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if 0>= get_result(CRYPTO_THREAD_run_once(@err_string_init, do_err_strings_init_ossl_) > 0,
                 do_err_strings_init_ossl_ret_ , 0) then
        Exit(0);
    err_load_strings(@ERR_str_libraries);
    err_load_strings(@ERR_str_reasons);
{$ENDIF}
    Result := 1;
end;




procedure err_cleanup;
begin
    if set_err_thread_local <> 0 then
       CRYPTO_THREAD_cleanup_local(@err_thread_local);
    CRYPTO_THREAD_lock_free(err_string_lock);
    err_string_lock := nil;
    lh_ERR_STRING_DATA_free(int_error_hash);
    int_error_hash := nil;
end;



function ERR_unload_strings( lib : integer; str : PERR_STRING_DATA):integer;
begin
   if 0 >= get_result(CRYPTO_THREAD_run_once(@err_string_init, do_err_strings_init_ossl_) > 0,
                      do_err_strings_init_ossl_ret_ , 0) then

        Exit(0);
    if 0>=CRYPTO_THREAD_write_lock(err_string_lock) then
        Exit(0);
    {
     * We don't need to ERR_PACK the lib, since that was done (to
     * the table) when it was loaded.
     }
    while str.error > 0 do
    begin
        lh_ERR_STRING_DATA_delete(int_error_hash, str);
        Inc(str);
    end;
    CRYPTO_THREAD_unlock(err_string_lock);
    Result := 1;
end;


function ERR_get_next_error_library:integer;
var
  ret : integer;
begin
    if (0 >= get_result(CRYPTO_THREAD_run_once(@err_string_init, do_err_strings_init_ossl_) > 0,
                do_err_strings_init_ossl_ret_ , 0)) then
        Exit(0);
    if 0>=CRYPTO_THREAD_write_lock(err_string_lock) then
        Exit(0);
    ret := PostInc(int_err_library_number);
    CRYPTO_THREAD_unlock(err_string_lock);
    Result := ret;
end;


function _ERR_load_strings(lib : integer; str : PERR_STRING_DATA):integer;
begin
    if ossl_err_load_ERR_strings = 0 then Exit(0);
    err_patch(lib, str);
    err_load_strings(str);
    Result := 1;
end;



procedure ERR_clear_error;
var
  i : integer;
  es : PERR_STATE;
begin
    es := ossl_err_get_state_int;
    if es = nil then exit;
    for i := 0 to ERR_NUM_ERRORS-1 do begin
        err_clear(es, i, 0);
    end;
    es.top := 0; es.bottom := 0;
end;




function ERR_peek_error:Cardinal;
begin
    Result := get_error_values(EV_PEEK, nil, nil, nil, nil, nil);
end;

procedure EVPerr(f, r: int);
begin
  ERR_raise_data(ERR_LIB_EVP, (r), '')
end;


function ERR_peek_last_error_all(const _file : PPUTF8Char; line : PInteger;const func, data : PPUTF8Char; flags : PInteger):Cardinal;
begin
    Result := get_error_values(EV_PEEK_LAST, _file, line, func, data, flags);
end;




procedure ossl_err_string_int(e : Cardinal;const func : PUTF8Char; buf : PUTF8Char; len : size_t);
var
  lsbuf : array[0..64-1] of UTF8Char;
  rsbuf : array[0..256-1] of UTF8Char;
  ls, rs : PUTF8Char;
  l, r : Cardinal;
begin

    rs := nil;
    if len = 0 then Exit;
    l := ERR_GET_LIB(e);
    ls := ERR_lib_error_string(e);
    if ls = nil then
    begin
        BIO_snprintf(lsbuf, sizeof(lsbuf), 'lib(%lu)', [l]);
        ls := lsbuf;
    end;
    {
     * ERR_reason_error_string() can't safely return system error strings,
     * since it would call openssl_strerror_r(), which needs a buffer for
     * thread safety.  So for system errors, we call openssl_strerror_r()
     * directly instead.
     }
    r := ERR_GET_REASON(e);
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_SYSTEM_ERROR(e)  then
    begin
        if openssl_strerror_r(r, rsbuf, sizeof(rsbuf)) > 0 then
            rs := rsbuf;
    end
    else
    begin
        rs := ERR_reason_error_string(e);
    end;
{$ENDIF}
    if rs = nil then
    begin
        BIO_snprintf(rsbuf, sizeof(rsbuf), 'reason(%lu)',
                     [r and not (ERR_RFLAGS_MASK  shl  ERR_RFLAGS_OFFSET)]);
        rs := rsbuf;
    end;
    BIO_snprintf(buf, len, 'error:%08lX:%s:%s:%s', [e, ls, func, rs]);
    if Length(buf) = len - 1  then
    begin
        BIO_snprintf(buf, len, 'err:%lx:%lx:%lx:%lx', [e, l, 0, r]);
    end;
end;

function ERR_get_error_all(const _file : PPUTF8Char; line : PInteger;const func, data : PPUTF8Char; flags : PInteger):Cardinal;
begin
    Result := get_error_values(EV_POP, _file, line, func, data, flags);
end;



procedure err_clear_last_constant_time( clear : integer);
var
  es : PERR_STATE;

  top : integer;
begin
    es := ossl_err_get_state_int();
    if es = nil then exit;
    top := es.top;
    {
     * Flag error as cleared but remove it elsewhere to avoid two errors
     * accessing the same error stack location, revealing timing information.
     }
    clear := constant_time_select_int(constant_time_eq_int(clear, 0),
                                     0, ERR_FLAG_CLEAR);
    es.err_flags[top]  := es.err_flags[top]  or clear;
end;



function ERR_GET_LIB( errcode : Cardinal):integer;
begin
    if ERR_SYSTEM_ERROR(errcode) then
        Exit(ERR_LIB_SYS);
    Result := (errcode  shr  ERR_LIB_OFFSET) and ERR_LIB_MASK;
end;

function ERR_peek_last_error:Cardinal;
begin
    Result := get_error_values(EV_PEEK_LAST, nil, nil, nil, nil, nil);
end;

procedure err_free_strings_int;
begin
    if 0>= get_result(CRYPTO_THREAD_run_once(@err_string_init, do_err_strings_init_ossl_) >0,
            do_err_strings_init_ossl_ret_ , 0) then
        exit;
end;

function ERR_SYSTEM_ERROR(errcode: uint32): Boolean;
begin
   Result :=  (((errcode) and ERR_SYSTEM_FLAG) <> 0)
end;

function ERR_GET_REASON( errcode : Cardinal):integer;
begin
    if ERR_SYSTEM_ERROR(errcode ) then
        Exit(errcode and ERR_SYSTEM_MASK);
    Result := errcode and ERR_REASON_MASK;
end;

procedure ECerr(f, r:integer);
begin
  ERR_raise_data(ERR_LIB_EC, r, '')
end;

procedure err_set_data( es : PERR_STATE; i : size_t; data : Pointer; datasz : size_t; flags : integer);
begin
    if (es.err_data_flags[i] and ERR_TXT_MALLOCED) <> 0 then
        OPENSSL_free(Pointer(es.err_data[i]));
    es.err_data[i] := data;
    es.err_data_size[i] := datasz;
    es.err_data_flags[i] := flags;
end;

function err_set_error_data_int( data : PUTF8Char; size : size_t; flags, deallocate : integer):integer;
var
  es : PERR_STATE;
begin
    es := ossl_err_get_state_int();
    if es = nil then Exit(0);
    err_clear_data(es, es.top, deallocate);
    err_set_data(es, es.top, data, size, flags);
    Result := 1;
end;




procedure err_clear_data( es : PERR_STATE; i : size_t; deall : integer);
begin
    if (es.err_data_flags[i] and ERR_TXT_MALLOCED)>0 then
    begin
        if deall>0 then
        begin
            OPENSSL_free(es.err_data[i]);
            es.err_data[i] := nil;
            es.err_data_size[i] := 0;
            es.err_data_flags[i] := 0;
        end
        else
        if (es.err_data[i] <> nil) then
        begin
          es.err_data[i][0] := #0;
          es.err_data_flags[i] := ERR_TXT_MALLOCED;
        end;
    end
    else
    begin
        es.err_data[i] := nil;
        es.err_data_size[i] := 0;
        es.err_data_flags[i] := 0;
    end;
end;


procedure err_clear( es : PERR_STATE; i : size_t; deall : integer);
begin
    err_clear_data(es, i, (deall));
    es.err_marks[i] := 0;
    es.err_flags[i] := 0;
    es.err_buffer[i] := 0;
    es.err_line[i] := -1;
    OPENSSL_free(es.err_file[i]);
    es.err_file[i] := nil;
    OPENSSL_free(es.err_func[i]);
    es.err_func[i] := nil;
end;


procedure ERR_STATE_free( s : PERR_STATE);
var
  i : integer;
begin
    if s = nil then exit;
    for i := 0 to ERR_NUM_ERRORS-1 do
    begin
        err_clear(s, i, 1);
    end;
    OPENSSL_free(s);
end;




procedure err_delete_thread_state( unused : Pointer);
var
  state : PERR_STATE;
begin
    state := CRYPTO_THREAD_get_local(@err_thread_local);
    if state = nil then exit;
    CRYPTO_THREAD_set_local(@err_thread_local, nil);
    ERR_STATE_free(state);
end;

function err_do_init_ossl_: integer;
begin
    err_do_init_ossl_ret_ := err_do_init();
end;


function err_do_init:integer;
begin
    set_err_thread_local := 1;
    Result := CRYPTO_THREAD_init_local(@err_thread_local, nil);
end;

function ossl_err_get_state_int:PERR_STATE;
var
    state     : PERR_STATE;
    saveerrno : integer;
    function RUN_ONCE(once : PCRYPTO_ONCE; init: Tthreads_none_init_func2): Integer;
    begin
       if CRYPTO_THREAD_run_once(once, err_do_init_ossl_) > 0 then
          Result := err_do_init_ossl_ret_
       else
          Result := 0;
    end;
begin
    saveerrno := get_last_sys_error();
    if  0>= OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, nil) then
        Exit(nil);
    if  0>= RUN_ONCE(@err_init, err_do_init ) then
        Exit(nil);
    state := CRYPTO_THREAD_get_local(@err_thread_local);
    if state = PERR_STATE(-1) then
        Exit(nil);
    if state = nil then
    begin
        if  0>= CRYPTO_THREAD_set_local(@err_thread_local, PERR_STATE(-1) ) then
            Exit(nil);
        state := OPENSSL_zalloc(sizeof(state^ ));
        if state = nil then
        begin
            CRYPTO_THREAD_set_local(@err_thread_local, nil);
            Exit(nil);
        end;
        if  (0>= ossl_init_thread_start(nil, nil, err_delete_thread_state ) ) or
            (0>= CRYPTO_THREAD_set_local(@err_thread_local, state) )then
        begin
            ERR_STATE_free(state);
            CRYPTO_THREAD_set_local(@err_thread_local, nil);
            Exit(nil);
        end;
        { Ignore failures from these }
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil);
    end;
    set_sys_error(saveerrno);
    Result := state;
end;

procedure X509V3_conf_add_error_name_value(val: PCONF_VALUE);
begin
    ERR_add_error_data(4, ['name=;', val.name, ', value=', val.value])
end;

procedure ERR_add_error_data( num : integer; args: array of const);
begin
   ERR_add_error_vdata(num, args);
end;


procedure ERR_add_error_vdata( num : integer; args : array of const);
var
  i, len, size, flags : integer;
  str, arg : PUTF8Char;
  es : PERR_STATE;
  p : PUTF8Char;
begin
    flags := ERR_TXT_MALLOCED or ERR_TXT_STRING;
    es := ossl_err_get_state_int();
    if es = nil then exit;
    i := es.top;
    {
     * If err_data is allocated already, re-use the space.
     * Otherwise, allocate a small new buffer.
     }
    if (es.err_data_flags[i] and flags ) = flags then
    begin
        str := es.err_data[i];
        size := es.err_data_size[i];
        {
         * To protect the string we just grabbed from tampering by other
         * functions we may call, or to protect them from freeing a pointer
         * that may no longer be valid at that point, we clear away the
         * data pointer and the flags.  We will set them again at the end
         * of this function.
         }
        es.err_data[i] := nil;
        es.err_data_flags[i] := 0;
    end
    else
    begin
        size := 81;
        str := OPENSSL_malloc(size);
        if (str = nil) then
        begin
           exit;
        end
        else
        begin
           str[0] := #0;
        end;
    end;
    len := strlen(str);
    while PreDec(num) >= 0 do
    begin
        arg := va_arg(args, TypeInfo(PUTF8Char) );
        if arg = nil then
           arg := '<nil>';
        len  := len + (Length(arg));
        if len >= size then begin
            size := len + 20;
            str := OPENSSL_realloc(str, size);
            if str = nil then begin
                OPENSSL_free(str);
                exit;
            end;
            //str := p;
        end;
        OPENSSL_strlcat(str, arg, size_t(size));
    end;
    if  0>= err_set_error_data_int(str, size, flags, 0 )  then
        OPENSSL_free(str);
end;

procedure ERR_raise_data(lib, reason: Integer; fmt: string);
begin
   {ERR_new();
   ERR_set_debug(OPENSSL_FUNC);
   ERR_set_error(lib, reason, fmt); }
   {$IFDEF _DEBUG_}
   raise Exception.Create(Format('Error Message lib=%d reason=%d ', [lib, reason]) + fmt);
   {$ELSE}
       Writeln(Format('Error Message lib=%d reason=%d ', [lib, reason]) + fmt);
   {$ENDIF}
end;

procedure ERR_raise(lib, reason: Integer);
begin
   ERR_raise_data(lib, reason, '');
end;

initialization
  BN_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_ARG2_LT_ARG3),'arg2 lt arg3'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_BAD_RECIPROCAL),'bad reciprocal'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_BIGNUM_TOO_LONG),'bignum too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_BITS_TOO_SMALL),'bits too small'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_CALLED_WITH_EVEN_MODULUS),'called with even modulus'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO),'div by zero'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_ENCODING_ERROR),'encoding error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA),'expand on static bignum data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_INPUT_NOT_REDUCED),'input not reduced'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_LENGTH),'invalid length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_RANGE),'invalid range'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_SHIFT),'invalid shift'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_NOT_A_SQUARE),'not a square'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_NOT_INITIALIZED),'not initialized'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_INVERSE),'no inverse'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_SOLUTION),'no solution'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_SUITABLE_DIGEST),'no suitable digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_PRIVATE_KEY_TOO_LARGE),'private key too large'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_P_IS_NOT_PRIME),'p is not prime'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_TOO_MANY_ITERATIONS),'too many iterations'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, BN_R_TOO_MANY_TEMPORARY_VARIABLES),'too many temporary variables'),
    get_ERR_STRING_DATA(0,nil)
];

  ERR_str_libraries := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_NONE, 0, 0), 'unknown library'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_SYS, 0, 0), 'system library'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BN, 0, 0), 'bignum routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RSA, 0, 0), 'rsa routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DH, 0, 0), 'Diffie-Hellman routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EVP, 0, 0), 'digital envelope routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BUF, 0, 0), 'memory buffer routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OBJ, 0, 0), 'object identifier routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PEM, 0, 0), 'PEM routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSA, 0, 0), 'dsa routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509, 0, 0), 'x509 certificate routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ASN1, 0, 0), 'asn1 encoding routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CONF, 0, 0), 'configuration file routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRYPTO, 0, 0), 'common libcrypto routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_EC, 0, 0), 'elliptic curve routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ECDSA, 0, 0), 'ECDSA routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ECDH, 0, 0), 'ECDH routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_SSL, 0, 0), 'SSL routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, 0), 'BIO routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS7, 0, 0), 'PKCS7 routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_X509V3, 0, 0), 'X509 V3 routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PKCS12, 0, 0), 'PKCS12 routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_RAND, 0, 0), 'random number generator'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_DSO, 0, 0), 'DSO support routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_TS, 0, 0), 'time stamp routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ENGINE, 0, 0), 'engine routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OCSP, 0, 0), 'OCSP routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_UI, 0, 0), 'UI routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_FIPS, 0, 0), 'FIPS routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, 0), 'CMS routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CRMF, 0, 0), 'CRMF routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMP, 0, 0), 'CMP routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HMAC, 0, 0), 'HMAC routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CT, 0, 0), 'CT routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ASYNC, 0, 0), 'ASYNC routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_KDF, 0, 0), 'KDF routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_STORE, 0, 0), 'STORE routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_SM2, 0, 0), 'SM2 routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_ESS, 0, 0), 'ESS routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_PROV, 0, 0), 'Provider routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_ENCODER, 0, 0), 'ENCODER routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_OSSL_DECODER, 0, 0), 'DECODER routines'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, 0), 'HTTP routines'),
    get_ERR_STRING_DATA(0, nil)
];

  ERR_str_reasons := [
    get_ERR_STRING_DATA(ERR_R_SYS_LIB, 'system lib'),
    get_ERR_STRING_DATA(ERR_R_BN_LIB, 'BN lib'),
    get_ERR_STRING_DATA(ERR_R_RSA_LIB, 'RSA lib'),
    get_ERR_STRING_DATA(ERR_R_DH_LIB, 'DH lib'),
    get_ERR_STRING_DATA(ERR_R_EVP_LIB, 'EVP lib'),
    get_ERR_STRING_DATA(ERR_R_BUF_LIB, 'BUF lib'),
    get_ERR_STRING_DATA(ERR_R_OBJ_LIB, 'OBJ lib'),
    get_ERR_STRING_DATA(ERR_R_PEM_LIB, 'PEM lib'),
    get_ERR_STRING_DATA(ERR_R_DSA_LIB, 'DSA lib'),
    get_ERR_STRING_DATA(ERR_R_X509_LIB, 'X509 lib'),
    get_ERR_STRING_DATA(ERR_R_ASN1_LIB, 'ASN1 lib'),
    get_ERR_STRING_DATA(ERR_R_CRYPTO_LIB, 'CRYPTO lib'),
    get_ERR_STRING_DATA(ERR_R_EC_LIB, 'EC lib'),
    get_ERR_STRING_DATA(ERR_R_BIO_LIB, 'BIO lib'),
    get_ERR_STRING_DATA(ERR_R_PKCS7_LIB, 'PKCS7 lib'),
    get_ERR_STRING_DATA(ERR_R_X509V3_LIB, 'X509V3 lib'),
    get_ERR_STRING_DATA(ERR_R_ENGINE_LIB, 'ENGINE lib'),
    get_ERR_STRING_DATA(ERR_R_UI_LIB, 'UI lib'),
    get_ERR_STRING_DATA(ERR_R_ECDSA_LIB, 'ECDSA lib'),
    get_ERR_STRING_DATA(ERR_R_OSSL_STORE_LIB, 'OSSL_STORE lib'),
    get_ERR_STRING_DATA(ERR_R_OSSL_DECODER_LIB, 'OSSL_DECODER lib'),

    get_ERR_STRING_DATA(ERR_R_FATAL, 'fatal'),
    get_ERR_STRING_DATA(ERR_R_MALLOC_FAILURE, 'malloc failure'),
    get_ERR_STRING_DATA(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,  'called a function you should not call'),
    get_ERR_STRING_DATA(ERR_R_PASSED_NULL_PARAMETER, 'passed a null parameter'),
    get_ERR_STRING_DATA(ERR_R_INTERNAL_ERROR, 'internal error'),
    get_ERR_STRING_DATA(ERR_R_DISABLED, 'called a function that was disabled at compile-time'),
    get_ERR_STRING_DATA(ERR_R_INIT_FAIL, 'init fail'),
    get_ERR_STRING_DATA(ERR_R_PASSED_INVALID_ARGUMENT, 'passed invalid argument'),
    get_ERR_STRING_DATA(ERR_R_OPERATION_FAIL, 'operation fail'),
    get_ERR_STRING_DATA(ERR_R_INVALID_PROVIDER_FUNCTIONS, 'invalid provider functions'),
    get_ERR_STRING_DATA(ERR_R_INTERRUPTED_OR_CANCELLED, 'interrupted or cancelled'),
    get_ERR_STRING_DATA(ERR_R_NESTED_ASN1_ERROR, 'nested asn1 error'),
    get_ERR_STRING_DATA(ERR_R_MISSING_ASN1_EOS, 'missing asn1 eos'),
    (*
     * Something is unsupported, exactly what is expressed with additional data
     *)
    get_ERR_STRING_DATA(ERR_R_UNSUPPORTED, 'unsupported'),
    (*
     * A fetch failed for other reasons than the name to be fetched being
     * unsupported.
     *)
    get_ERR_STRING_DATA(ERR_R_FETCH_FAILED, 'fetch failed'),
    get_ERR_STRING_DATA(ERR_R_INVALID_PROPERTY_DEFINITION, 'invalid property definition'),
    get_ERR_STRING_DATA(ERR_R_UNABLE_TO_GET_READ_LOCK, 'unable to get read lock'),
    get_ERR_STRING_DATA(ERR_R_UNABLE_TO_GET_WRITE_LOCK, 'unable to get write lock'),
    get_ERR_STRING_DATA(0, nil)
];

end.
