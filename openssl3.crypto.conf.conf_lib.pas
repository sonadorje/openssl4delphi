unit openssl3.crypto.conf.conf_lib;

interface
uses OpenSSL.Api, SysUtils;

 function NCONF_get_string(const conf : PCONF; group, name : PUTF8Char):PUTF8Char;
 function NCONF_new( meth : PCONF_METHOD):PCONF;
 function NCONF_new_ex( libctx : POSSL_LIB_CTX; meth : PCONF_METHOD):PCONF;
 procedure CONF_free( conf : Plhash_st_CONF_VALUE);
 procedure CONF_set_nconf( conf : PCONF; hash : Plhash_st_CONF_VALUE);
  procedure NCONF_free_data( conf : PCONF);
 function NCONF_load(conf : PCONF;const _file : PUTF8Char; eline : Plong):integer;
 procedure NCONF_free( conf : PCONF);

 var
   default_CONF_method: PCONF_METHOD  = nil;

function _CONF_get_number(const conf : PCONF; section, name : PUTF8Char):long;
function NCONF_get_number_e(const conf : PCONF; group, name : PUTF8Char; _result : Plong):integer;
function default_is_number(const conf : PCONF; c : UTF8Char):integer;
function default_to_int(const conf : PCONF; c : UTF8Char):integer;
function NCONF_get_section(const conf : PCONF; section : PUTF8Char):Pstack_st_CONF_VALUE;
function NCONF_get0_libctx(const conf : PCONF):POSSL_LIB_CTX;

implementation

uses openssl3.crypto.conf.conf_api,    OpenSSL3.Err,
     openssl3.crypto.ctype,
     openssl3.crypto.conf.conf_def,    openssl3.providers.fips.fipsprov;

type
   is_number_func = function(const p1 : PCONF; p2 : UTF8Char):integer;
   to_int_func    = function(const p1 : PCONF; p2 : UTF8Char):integer;




function NCONF_get0_libctx(const conf : PCONF):POSSL_LIB_CTX;
begin
    Result := conf.libctx;
end;



function NCONF_get_section(const conf : PCONF; section : PUTF8Char):Pstack_st_CONF_VALUE;
begin
    if conf = nil then begin
        ERR_raise(ERR_LIB_CONF, CONF_R_NO_CONF);
        Exit(nil);
    end;
    if section = nil then begin
        ERR_raise(ERR_LIB_CONF, CONF_R_NO_SECTION);
        Exit(nil);
    end;
    Result := _CONF_get_section_values(conf, section);
end;


function default_to_int(const conf : PCONF; c : UTF8Char):integer;
begin
    Result := Ord(c) - Ord('0');
end;


function default_is_number(const conf : PCONF; c : UTF8Char):integer;
begin
    Result := Int(ossl_isdigit(c));
end;

function NCONF_get_number_e(const conf : PCONF; group, name : PUTF8Char; _result : Plong):integer;
var
  str : PUTF8Char;
  res : long;
  d : integer;
  is_number: is_number_func;
  to_int: to_int_func;
begin
    is_number := @default_is_number;
    to_int    := @default_to_int;
    if _result = nil then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    str := NCONF_get_string(conf, group, name);
    if str = nil then Exit(0);
    if conf <> nil then
    begin
        if Assigned(conf.meth.is_number) then
            is_number := conf.meth.is_number;
        if Assigned(conf.meth.to_int) then
            to_int := conf.meth.to_int;
    end;
    res := 0;
    while is_number(conf, str^) > 0  do
    begin
        d := to_int(conf, str^);
        if res > (LONG_MAX - d) div 10 then
        begin
            ERR_raise(ERR_LIB_CONF, CONF_R_NUMBER_TOO_LARGE);
            Exit(0);
        end;
        res := res * 10 + d;
        Inc(str);
    end;
    _result^ := res;
    Result := 1;
end;


function _CONF_get_number(const conf : PCONF; section, name : PUTF8Char):long;
var
  status : integer;
begin
    result := 0;
    ERR_set_mark;
    status := NCONF_get_number_e(conf, section, name, @result);
    ERR_pop_to_mark;
    Result := get_result(status = 0 , 0, result);
end;




procedure NCONF_free( conf : PCONF);
begin
    if conf = nil then exit;
    conf.meth.destroy(conf);
end;




function NCONF_load(conf : PCONF;const _file : PUTF8Char; eline : Plong):integer;
begin
    if conf = nil then
    begin
        ERR_raise(ERR_LIB_CONF, CONF_R_NO_CONF);
        Exit(0);
    end;
    Result := conf.meth.load(conf, _file, eline);
end;



procedure NCONF_free_data( conf : PCONF);
begin
    if conf = nil then
       Exit;
    conf.meth.destroy_data(conf);
end;




procedure CONF_set_nconf( conf : PCONF; hash : Plhash_st_CONF_VALUE);
begin
    if default_CONF_method = nil then
       default_CONF_method := NCONF_default();
    default_CONF_method.init(conf);
    conf.data := hash;
end;


procedure CONF_free( conf : Plhash_st_CONF_VALUE);
var
  ctmp : TCONF;
begin
    CONF_set_nconf(@ctmp, conf);
    ctmp :=  TCONF.Empty;
    //NCONF_free_data(@ctmp);
end;



function NCONF_new_ex( libctx : POSSL_LIB_CTX; meth : PCONF_METHOD):PCONF;
var
  ret : PCONF;
begin
    if meth = nil then
       meth := NCONF_default();
    ret := meth.create(meth);
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.libctx := libctx;
    Result := ret;
end;




function NCONF_new( meth : PCONF_METHOD):PCONF;
begin
    Result := NCONF_new_ex(nil, meth);
end;


function NCONF_get_string(const conf : PCONF; group, name : PUTF8Char):PUTF8Char;
var
  s : PUTF8Char;
begin
    s := _CONF_get_string(conf, group, name);
    {
     * Since we may get a value from an environment variable even if conf is
     * nil, let's check the value first
     }
    if s <> nil then Exit(s);
    if conf = nil then
    begin
        ERR_raise(ERR_LIB_CONF, CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE);
        Exit(nil);
    end;
    ERR_raise_data(ERR_LIB_CONF, CONF_R_NO_VALUE,
                   Format(' group=%s name=%s' , [group, name]));
    Result := nil;
end;


end.
