unit openssl3.crypto.conf.conf_mod;

interface
 uses OpenSSL.Api, SysUtils;

 const
   DSO_mod_init_name = 'OPENSSL_init';
   DSO_mod_finish_name = 'OPENSSL_finish';

type
  Tlist_cb_func = function (const elem : PUTF8Char; len : integer; usr : Pointer):integer;

 function CONF_parse_list(const list_ : PUTF8Char; sep, nospc : integer; list_cb : Tlist_cb_func; arg : Pointer):integer;
 procedure ossl_config_modules_free;
 procedure CONF_modules_finish;

procedure module_finish(imod : PCONF_IMODULE);
function sk_CONF_MODULE_num(const sk : Pstack_st_CONF_MODULE):integer;
  function sk_CONF_MODULE_value(const sk : Pstack_st_CONF_MODULE; idx : integer):PCONF_MODULE;
  function sk_CONF_MODULE_new( compare : sk_CONF_MODULE_compfunc):Pstack_st_CONF_MODULE;
  function sk_CONF_MODULE_new_null:Pstack_st_CONF_MODULE;
  function sk_CONF_MODULE_new_reserve( compare : sk_CONF_MODULE_compfunc; n : integer):Pstack_st_CONF_MODULE;
  function sk_CONF_MODULE_reserve( sk : Pstack_st_CONF_MODULE; n : integer):integer;
  procedure sk_CONF_MODULE_free( sk : Pstack_st_CONF_MODULE);
  procedure sk_CONF_MODULE_zero( sk : Pstack_st_CONF_MODULE);
  function sk_CONF_MODULE_delete( sk : Pstack_st_CONF_MODULE; i : integer):PCONF_MODULE;
  function sk_CONF_MODULE_delete_ptr( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):PCONF_MODULE;
  function sk_CONF_MODULE_push( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
  function sk_CONF_MODULE_unshift( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
  function sk_CONF_MODULE_pop( sk : Pstack_st_CONF_MODULE):PCONF_MODULE;
  function sk_CONF_MODULE_shift( sk : Pstack_st_CONF_MODULE):PCONF_MODULE;
  procedure sk_CONF_MODULE_pop_free( sk : Pstack_st_CONF_MODULE; freefunc : sk_CONF_MODULE_freefunc);
  function sk_CONF_MODULE_insert( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE; idx : integer):integer;
  function sk_CONF_MODULE_set( sk : Pstack_st_CONF_MODULE; idx : integer; ptr : PCONF_MODULE):PCONF_MODULE;
  function sk_CONF_MODULE_find( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
  function sk_CONF_MODULE_find_ex( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
  function sk_CONF_MODULE_find_all( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE; pnum : PInteger):integer;
  procedure sk_CONF_MODULE_sort( sk : Pstack_st_CONF_MODULE);
  function sk_CONF_MODULE_is_sorted(const sk : Pstack_st_CONF_MODULE):integer;
  function sk_CONF_MODULE_dup(const sk : Pstack_st_CONF_MODULE):Pstack_st_CONF_MODULE;
  function sk_CONF_MODULE_deep_copy(const sk : Pstack_st_CONF_MODULE; copyfunc : sk_CONF_MODULE_copyfunc; freefunc : sk_CONF_MODULE_freefunc):Pstack_st_CONF_MODULE;
  function sk_CONF_MODULE_set_cmp_func( sk : Pstack_st_CONF_MODULE; compare : sk_CONF_MODULE_compfunc):sk_CONF_MODULE_compfunc;
  function sk_CONF_IMODULE_num(const sk : Pstack_st_CONF_IMODULE):integer;
  function sk_CONF_IMODULE_value(const sk : Pstack_st_CONF_IMODULE; idx : integer):PCONF_IMODULE;
  function sk_CONF_IMODULE_new( compare : sk_CONF_IMODULE_compfunc):Pstack_st_CONF_IMODULE;
  function sk_CONF_IMODULE_new_null:Pstack_st_CONF_IMODULE;
  function sk_CONF_IMODULE_new_reserve( compare : sk_CONF_IMODULE_compfunc; n : integer):Pstack_st_CONF_IMODULE;
  function sk_CONF_IMODULE_reserve( sk : Pstack_st_CONF_IMODULE; n : integer):integer;
  procedure sk_CONF_IMODULE_free( sk : Pstack_st_CONF_IMODULE);
  procedure sk_CONF_IMODULE_zero( sk : Pstack_st_CONF_IMODULE);
  function sk_CONF_IMODULE_delete( sk : Pstack_st_CONF_IMODULE; i : integer):PCONF_IMODULE;
  function sk_CONF_IMODULE_delete_ptr( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):PCONF_IMODULE;
  function sk_CONF_IMODULE_push( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
  function sk_CONF_IMODULE_unshift( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
  function sk_CONF_IMODULE_pop( sk : Pstack_st_CONF_IMODULE):PCONF_IMODULE;
  function sk_CONF_IMODULE_shift( sk : Pstack_st_CONF_IMODULE):PCONF_IMODULE;
  procedure sk_CONF_IMODULE_pop_free( sk : Pstack_st_CONF_IMODULE; freefunc : sk_CONF_IMODULE_freefunc);
  function sk_CONF_IMODULE_insert( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE; idx : integer):integer;
  function sk_CONF_IMODULE_set( sk : Pstack_st_CONF_IMODULE; idx : integer; ptr : PCONF_IMODULE):PCONF_IMODULE;
  function sk_CONF_IMODULE_find( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
  function sk_CONF_IMODULE_find_ex( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
  function sk_CONF_IMODULE_find_all( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE; pnum : PInteger):integer;
  procedure sk_CONF_IMODULE_sort( sk : Pstack_st_CONF_IMODULE);
  function sk_CONF_IMODULE_is_sorted(const sk : Pstack_st_CONF_IMODULE):integer;
  function sk_CONF_IMODULE_dup(const sk : Pstack_st_CONF_IMODULE):Pstack_st_CONF_IMODULE;
  function sk_CONF_IMODULE_deep_copy(const sk : Pstack_st_CONF_IMODULE; copyfunc : sk_CONF_IMODULE_copyfunc; freefunc : sk_CONF_IMODULE_freefunc):Pstack_st_CONF_IMODULE;
  function sk_CONF_IMODULE_set_cmp_func( sk : Pstack_st_CONF_IMODULE; compare : sk_CONF_IMODULE_compfunc):sk_CONF_IMODULE_compfunc;
  procedure CONF_modules_unload( all : integer);


var
  initialized_modules: PSTACK_st_CONF_IMODULE  = nil;
  supported_modules  : PSTACK_st_CONF_MODULE  = nil;

procedure module_free( md : PCONF_MODULE);

function CONF_modules_load_file(const filename, appname : PUTF8Char; flags : Cardinal):integer;
function CONF_modules_load_file_ex(libctx : POSSL_LIB_CTX;const filename, appname : PUTF8Char; flags : Cardinal):integer;
function CONF_get1_default_config_file:PUTF8Char;
function CONF_modules_load(const cnf : PCONF; appname : PUTF8Char; flags : Cardinal):integer;
function conf_diagnostics(const cnf : PCONF):integer;
function module_run(const cnf : PCONF; name, value : PUTF8Char; flags : Cardinal):integer;

var
   load_builtin_modules: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
   do_load_builtin_modules_ossl_ret_ : int = 0;

procedure do_load_builtin_modules_ossl_;
function do_load_builtin_modules:integer;
function CONF_module_add(const name : PUTF8Char; ifunc : Tconf_init_func; ffunc : Tconf_finish_func):integer;
function CONF_imodule_get_value(const md : PCONF_IMODULE):PUTF8Char;
function module_add(dso : PDSO;const name : PUTF8Char; ifunc : Tconf_init_func; ffunc : Tconf_finish_func):PCONF_MODULE;
function module_find(const name : PUTF8Char):PCONF_MODULE;
function module_load_dso(const cnf : PCONF; name, value : PUTF8Char):PCONF_MODULE;
function module_init(pmod : PCONF_MODULE;const name, value : PUTF8Char; cnf : PCONF):integer;

implementation



uses OpenSSL3.Err, openssl3.crypto.mem,    openssl3.crypto.stack,
     openssl3.crypto.o_str,                openssl3.crypto.x509.x509_def  ,
     openssl3.crypto.bio.bio_print,        openssl3.providers.fips.fipsprov,
     openssl3.crypto.conf.conf_lib,        OpenSSL3.openssl.conf,

     openssl3.crypto.engine.eng_lib,       openssl3.crypto.conf.conf_api,
     OpenSSL3.threads_none,                openssl3.crypto.conf.conf_mall ,
     openssl3.crypto.dso.dso_lib,          openssl3.crypto.getenv;



function module_init(pmod : PCONF_MODULE;const name, value : PUTF8Char; cnf : PCONF):integer;
var
  ret,
  init_called : integer;
  imod        : PCONF_IMODULE;
  label _memerr, _err;
begin
    ret := 1;
    init_called := 0;
    imod := nil;
    { Otherwise add initialized module to list }
    imod := OPENSSL_malloc(sizeof( imod^));
    if imod = nil then goto _err;
    imod.pmod := pmod;
     OPENSSL_strdup(imod.name ,name);
    OPENSSL_strdup(imod.value ,value);
    imod.usr_data := nil;
    if (nil =imod.name)  or  (nil =imod.value) then
       goto _memerr;
    { Try to initialize module }
    if Assigned(pmod.init) then
    begin
        ret := pmod.init(imod, cnf);
        init_called := 1;
        { Error occurred, exit }
        if ret <= 0 then
           goto _err;
    end;
    if initialized_modules = nil then
    begin
        initialized_modules := sk_CONF_IMODULE_new_null;
        if nil =initialized_modules then
        begin
            ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
    end;
    if 0>=sk_CONF_IMODULE_push(initialized_modules, imod) then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    PostInc(pmod.links);
    Exit(ret);
 _err:
    { We've started the module so we'd better finish it }
    if Assigned(pmod.finish)  and  (init_called > 0) then
       pmod.finish(imod);
 _memerr:
    if imod <> nil then
    begin
        OPENSSL_free(imod.name);
        OPENSSL_free(imod.value);
        OPENSSL_free(imod);
    end;
    Exit(-1);
end;



function module_load_dso(const cnf : PCONF; name, value : PUTF8Char):PCONF_MODULE;
var
  dso : PDSO;
  ifunc : Tconf_init_func;
  ffunc : Tconf_finish_func;
  path : PUTF8Char;
  errcode : integer;
  md : PCONF_MODULE;
  label _err;
begin
    dso := nil;
     path := nil;
    errcode := 0;
    { Look for alternative path in module section }
    path := _CONF_get_string(cnf, value, 'path');
    if path = nil then begin
        path := name;
    end;
    dso := DSO_load(nil, path, nil, 0);
    if dso = nil then begin
        errcode := CONF_R_ERROR_LOADING_DSO;
        goto _err;
    end;
    ifunc := Tconf_init_func(DSO_bind_func(dso, DSO_mod_init_name));
    if not Assigned(ifunc) then
    begin
        errcode := CONF_R_MISSING_INIT_FUNCTION;
        goto _err;
    end;
    ffunc := Tconf_finish_func(DSO_bind_func(dso, DSO_mod_finish_name));
    { All OK, add module }
    md := module_add(dso, name, ifunc, ffunc);
    if md = nil then goto _err;
    Exit(md);
 _err:
    DSO_free(dso);
    ERR_raise_data(ERR_LIB_CONF, errcode, Format('module=%s, path=%s', [name, path]));
    Result := nil;
end;



function module_find(const name : PUTF8Char):PCONF_MODULE;
var
  tmod : PCONF_MODULE;
  i, nchar : integer;
  p : PUTF8Char;
begin
    p := strrchr(name, '.');
    if p <> nil then
       nchar := p - name
    else
        nchar := Length(name);
    for i := 0 to sk_CONF_MODULE_num(supported_modules)-1 do
    begin
        tmod := sk_CONF_MODULE_value(supported_modules, i);
        if strncmp(tmod.name, name, nchar) = 0  then
            Exit(tmod);
    end;
    Exit(nil);
end;



function module_add(dso : PDSO;const name : PUTF8Char; ifunc : Tconf_init_func; ffunc : Tconf_finish_func):PCONF_MODULE;
begin
    Result := nil;
    if supported_modules = nil then
       supported_modules := sk_CONF_MODULE_new_null;
    if supported_modules = nil then Exit(nil);
    Result := OPENSSL_zalloc(sizeof(Result^ ));
    if Result = nil then
    begin
        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    Result.dso := dso;
    OPENSSL_strdup(Result.name ,name);
    Result.init := ifunc;
    Result.finish := ffunc;
    if Result.name = nil then begin
        OPENSSL_free(Result);
        Exit(nil);
    end;
    if 0>=sk_CONF_MODULE_push(supported_modules, Result )then
    begin
        OPENSSL_free(Result.name);
        OPENSSL_free(Result);
        Exit(nil);
    end;

end;





function CONF_imodule_get_value(const md : PCONF_IMODULE):PUTF8Char;
begin
    Result := md.value;
end;



function CONF_module_add(const name : PUTF8Char; ifunc : Tconf_init_func; ffunc : Tconf_finish_func):integer;
begin
    if module_add(nil, name, ifunc, ffunc) <> nil then
        Exit(1)
    else
        Result := 0;
end;



procedure do_load_builtin_modules_ossl_;
begin
 do_load_builtin_modules_ossl_ret_ := do_load_builtin_modules;
end;


function do_load_builtin_modules:integer;
begin
    OPENSSL_load_builtin_modules;
    ENGINE_load_builtin_engines;
    Result := 1;
end;



function module_run(const cnf : PCONF; name, value : PUTF8Char; flags : Cardinal):integer;
var
  md : PCONF_MODULE;
  ret : integer;
begin
   if 0>= get_result(CRYPTO_THREAD_run_once(@load_builtin_modules,
              do_load_builtin_modules_ossl_) > 0 , do_load_builtin_modules_ossl_ret_ , 0) then

        Exit(-1);
    md := module_find(name);
    { Module not found: try to load PDSO }
    if (nil =md)  and  (0>= flags and CONF_MFLAGS_NO_DSO) then
        md := module_load_dso(cnf, name, value);
    if nil =md then
    begin
        if 0>=(flags and CONF_MFLAGS_SILENT) then
        begin
            ERR_raise_data(ERR_LIB_CONF, CONF_R_UNKNOWN_MODULE_NAME,
                         Format('module=%s', [name]));
        end;
        Exit(-1);
    end;
    ret := module_init(md, name, value, cnf);
    if ret <= 0 then
    begin
        if 0>=(flags and CONF_MFLAGS_SILENT) then
            ERR_raise_data(ERR_LIB_CONF, CONF_R_MODULE_INITIALIZATION_ERROR,
                          Format('module=%s, value=%s retcode=%-8d',
                           [name, value, ret]));
    end;
    Result := ret;
end;



function conf_diagnostics(const cnf : PCONF):integer;
begin
    Result := int(_CONF_get_number(cnf, nil, 'config_diagnostics') <> 0);
end;



function CONF_modules_load(const cnf : PCONF; appname : PUTF8Char; flags : Cardinal):integer;
var
  values   : Pstack_st_CONF_VALUE;
  vl       : PCONF_VALUE;
  vsection : PUTF8Char;
  ret,
  i        : integer;
begin
    vsection := nil;
    if nil=cnf then Exit(1);
    if conf_diagnostics(cnf) > 0 then
        flags := flags and not (CONF_MFLAGS_IGNORE_ERRORS
                   or CONF_MFLAGS_IGNORE_RETURN_CODES
                   or CONF_MFLAGS_SILENT
                   or CONF_MFLAGS_IGNORE_MISSING_FILE);
    ERR_set_mark;
    if appname <> nil then
       vsection := NCONF_get_string(cnf, nil, appname);
    if (nil =appname)  or ( (nil =vsection)  and  (flags and CONF_MFLAGS_DEFAULT_SECTION > 0) ) then
        vsection := NCONF_get_string(cnf, nil, 'openssl_conf');
    if nil =vsection then
    begin
        ERR_pop_to_mark;
        Exit(1);
    end;
    //OSSL_TRACE1(CONF, 'Configuration in section %s\n', vsection);
    values := NCONF_get_section(cnf, vsection);
    if values = nil then
    begin
        if 0>=(flags and CONF_MFLAGS_SILENT) then
        begin
            ERR_clear_last_mark;
            ERR_raise_data(ERR_LIB_CONF,
                           CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION,
                          Format('openssl_conf=%s', [vsection]));
        end
        else begin
            ERR_pop_to_mark;
        end;
        Exit(0);
    end;
    ERR_pop_to_mark;
    for i := 0 to sk_CONF_VALUE_num(values)-1 do
    begin
        vl := sk_CONF_VALUE_value(values, i);
        ERR_set_mark;
        ret := module_run(cnf, vl.name, vl.value, flags);
        //OSSL_TRACE3(CONF, 'Running module %s (%s) returned %d\n',
          //          vl.name, vl.value, ret);
        if ret <= 0 then
           if (0>=(flags and CONF_MFLAGS_IGNORE_ERRORS)) then
           begin
                ERR_clear_last_mark;
                Exit(ret);
           end;
        ERR_pop_to_mark;
    end;
    Exit(1);
end;



function CONF_get1_default_config_file:PUTF8Char;
var
  t, &file, sep : PUTF8Char;
  s: Ansistring;
  size : size_t;
begin
    sep := '';
    &file := ossl_safe_getenv('OPENSSL_CONF');
    if &file  <> nil then
    begin
       OPENSSL_strdup(Result, &file);
        Exit(Result);
    end;
    t := X509_get_default_cert_area;
{$IFDEF MSWINDOWS}
    sep := '\';
{$ELSE}
    sep := '/';
{$ENDIF}
    size := Length(t) + Length(sep) + Length(OPENSSL_CONF);
    size := size*Char_Size + Char_Size;
    Result := OPENSSL_malloc(size);
    if Result = nil then Exit;
    //BIO_snprintf(&file, size, '%s%s%s', [t, sep, OPENSSL_CONF]);
    s:= FORMAT('%s%s%s', [t, sep, OPENSSL_CONF]);
    //&file  := PUTF8Char(s);
    OPENSSL_strdup(Result, PUTF8Char(s));
end;




function CONF_modules_load_file_ex(libctx : POSSL_LIB_CTX;const filename, appname : PUTF8Char; flags : Cardinal):integer;
var
  &file : PUTF8Char;
  conf : PCONF;
  ret, diagnostics : integer;
  label _err;
begin
    &file := nil;
    conf := nil;
    ret := 0; diagnostics := 0;
    if filename = nil then
    begin
        &file := CONF_get1_default_config_file;
        if &file = nil then goto _err;
    end
    else begin
        &file := PUTF8Char( filename);
    end;
    ERR_set_mark;
    conf := NCONF_new_ex(libctx, nil);
    if conf = nil then goto _err;
    if NCONF_load(conf, &file, nil) <= 0  then
    begin
        if (flags and CONF_MFLAGS_IGNORE_MISSING_FILE > 0)   and
            (ERR_GET_REASON(ERR_peek_last_error) = CONF_R_NO_SUCH_FILE)  then
        begin
            ret := 1;
        end;
        goto _err;
    end;
    ret := CONF_modules_load(conf, appname, flags);
    diagnostics := conf_diagnostics(conf);
 _err:
    if filename = nil then OPENSSL_free(&file);
    NCONF_free(conf);
    if (flags and CONF_MFLAGS_IGNORE_RETURN_CODES <> 0)  and  (0>=diagnostics) then
        ret := 1;
    if ret > 0 then
       ERR_pop_to_mark
    else
        ERR_clear_last_mark;
    Result := ret;
end;



function CONF_modules_load_file(const filename, appname : PUTF8Char; flags : Cardinal):integer;
begin
    Result := CONF_modules_load_file_ex(nil, filename, appname, flags);
end;



procedure module_free( md : PCONF_MODULE);
begin
    DSO_free(md.dso);
    OPENSSL_free(md.name);
    OPENSSL_free(md);
end;


procedure CONF_modules_unload( all : integer);
var
  i : integer;

  md : PCONF_MODULE;
begin
    CONF_modules_finish;
    { unload modules in reverse order }
    for i := sk_CONF_MODULE_num(supported_modules) - 1 downto 0 do
    begin
        md := sk_CONF_MODULE_value(supported_modules, i);
        { If   or in use and 'all' not set ignore it }
        if (md.links > 0)  or  (nil =md.dso)  and  (0>=all) then
            continue;
        { Since we're working in reverse this is OK }
        sk_CONF_MODULE_delete(supported_modules, i);
        module_free(md);
    end;
    if sk_CONF_MODULE_num(supported_modules ) = 0 then
    begin
        sk_CONF_MODULE_free(supported_modules);
        supported_modules := nil;
    end;
end;




function sk_CONF_MODULE_num(const sk : Pstack_st_CONF_MODULE):integer;
begin
 Exit(OPENSSL_sk_num(POPENSSL_STACK(sk)));
end;


function sk_CONF_MODULE_value(const sk : Pstack_st_CONF_MODULE; idx : integer):PCONF_MODULE;
begin
 Result := PCONF_MODULE (OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;


function sk_CONF_MODULE_new( compare : sk_CONF_MODULE_compfunc):Pstack_st_CONF_MODULE;
begin
 Result := Pstack_st_CONF_MODULE (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_CONF_MODULE_new_null:Pstack_st_CONF_MODULE;
begin
 Result := Pstack_st_CONF_MODULE (OPENSSL_sk_new_null);
end;


function sk_CONF_MODULE_new_reserve( compare : sk_CONF_MODULE_compfunc; n : integer):Pstack_st_CONF_MODULE;
begin
 Result := Pstack_st_CONF_MODULE (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_CONF_MODULE_reserve( sk : Pstack_st_CONF_MODULE; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK(sk), n));
end;


procedure sk_CONF_MODULE_free( sk : Pstack_st_CONF_MODULE);
begin
 OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_CONF_MODULE_zero( sk : Pstack_st_CONF_MODULE);
begin
 OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;


function sk_CONF_MODULE_delete( sk : Pstack_st_CONF_MODULE; i : integer):PCONF_MODULE;
begin
 Result := PCONF_MODULE (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_CONF_MODULE_delete_ptr( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):PCONF_MODULE;
begin
 Result := PCONF_MODULE (OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_MODULE_push( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
begin
   Result := OPENSSL_sk_push(sk, ptr);
end;


function sk_CONF_MODULE_unshift( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_MODULE_pop( sk : Pstack_st_CONF_MODULE):PCONF_MODULE;
begin
 Result := PCONF_MODULE (OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_CONF_MODULE_shift( sk : Pstack_st_CONF_MODULE):PCONF_MODULE;
begin
 Result := PCONF_MODULE (OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;


procedure sk_CONF_MODULE_pop_free( sk : Pstack_st_CONF_MODULE; freefunc : sk_CONF_MODULE_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_CONF_MODULE_insert( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer(ptr), idx));
end;


function sk_CONF_MODULE_set( sk : Pstack_st_CONF_MODULE; idx : integer; ptr : PCONF_MODULE):PCONF_MODULE;
begin
 Result := PCONF_MODULE (OPENSSL_sk_set(POPENSSL_STACK(sk), idx, Pointer(ptr)));
end;


function sk_CONF_MODULE_find( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_MODULE_find_ex( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_MODULE_find_all( sk : Pstack_st_CONF_MODULE; ptr : PCONF_MODULE; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK(sk), Pointer(ptr), pnum));
end;


procedure sk_CONF_MODULE_sort( sk : Pstack_st_CONF_MODULE);
begin
 OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_CONF_MODULE_is_sorted(const sk : Pstack_st_CONF_MODULE):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK(sk)));
end;


function sk_CONF_MODULE_dup(const sk : Pstack_st_CONF_MODULE):Pstack_st_CONF_MODULE;
begin
 Result := Pstack_st_CONF_MODULE (OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;


function sk_CONF_MODULE_deep_copy(const sk : Pstack_st_CONF_MODULE; copyfunc : sk_CONF_MODULE_copyfunc; freefunc : sk_CONF_MODULE_freefunc):Pstack_st_CONF_MODULE;
begin
 Result := Pstack_st_CONF_MODULE (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
            OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)));
end;


function sk_CONF_MODULE_set_cmp_func( sk : Pstack_st_CONF_MODULE; compare : sk_CONF_MODULE_compfunc):sk_CONF_MODULE_compfunc;
begin
 Result := sk_CONF_MODULE_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
              OPENSSL_sk_compfunc(compare)));
end;


function sk_CONF_IMODULE_num(const sk : Pstack_st_CONF_IMODULE):integer;
begin
 Exit(OPENSSL_sk_num(POPENSSL_STACK(sk)));
end;


function sk_CONF_IMODULE_value(const sk : Pstack_st_CONF_IMODULE; idx : integer):PCONF_IMODULE;
begin
 Result := PCONF_IMODULE (OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;


function sk_CONF_IMODULE_new( compare : sk_CONF_IMODULE_compfunc):Pstack_st_CONF_IMODULE;
begin
 Result := Pstack_st_CONF_IMODULE (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_CONF_IMODULE_new_null:Pstack_st_CONF_IMODULE;
begin
 Result := Pstack_st_CONF_IMODULE (OPENSSL_sk_new_null);
end;


function sk_CONF_IMODULE_new_reserve( compare : sk_CONF_IMODULE_compfunc; n : integer):Pstack_st_CONF_IMODULE;
begin
 Result := Pstack_st_CONF_IMODULE (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_CONF_IMODULE_reserve( sk : Pstack_st_CONF_IMODULE; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK(sk), n));
end;


procedure sk_CONF_IMODULE_free( sk : Pstack_st_CONF_IMODULE);
begin
 OPENSSL_sk_free(POPENSSL_STACK(sk));
end;


procedure sk_CONF_IMODULE_zero( sk : Pstack_st_CONF_IMODULE);
begin
 OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;


function sk_CONF_IMODULE_delete( sk : Pstack_st_CONF_IMODULE; i : integer):PCONF_IMODULE;
begin
 Result := PCONF_IMODULE (OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;


function sk_CONF_IMODULE_delete_ptr( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):PCONF_IMODULE;
begin
 Result := PCONF_IMODULE (OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_IMODULE_push( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_IMODULE_unshift( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_IMODULE_pop( sk : Pstack_st_CONF_IMODULE):PCONF_IMODULE;
begin
 Result := PCONF_IMODULE (OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;


function sk_CONF_IMODULE_shift( sk : Pstack_st_CONF_IMODULE):PCONF_IMODULE;
begin
 Result := PCONF_IMODULE (OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;


procedure sk_CONF_IMODULE_pop_free( sk : Pstack_st_CONF_IMODULE; freefunc : sk_CONF_IMODULE_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_CONF_IMODULE_insert( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK(sk), Pointer(ptr), idx));
end;


function sk_CONF_IMODULE_set( sk : Pstack_st_CONF_IMODULE; idx : integer; ptr : PCONF_IMODULE):PCONF_IMODULE;
begin
 Result := PCONF_IMODULE (OPENSSL_sk_set(POPENSSL_STACK(sk), idx, Pointer(ptr)));
end;


function sk_CONF_IMODULE_find( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_IMODULE_find_ex( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK(sk), Pointer(ptr)));
end;


function sk_CONF_IMODULE_find_all( sk : Pstack_st_CONF_IMODULE; ptr : PCONF_IMODULE; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK(sk), Pointer(ptr), pnum));
end;


procedure sk_CONF_IMODULE_sort( sk : Pstack_st_CONF_IMODULE);
begin
 OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;


function sk_CONF_IMODULE_is_sorted(const sk : Pstack_st_CONF_IMODULE):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK(sk)));
end;


function sk_CONF_IMODULE_dup(const sk : Pstack_st_CONF_IMODULE):Pstack_st_CONF_IMODULE;
begin
 Result := Pstack_st_CONF_IMODULE (OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;


function sk_CONF_IMODULE_deep_copy(const sk : Pstack_st_CONF_IMODULE; copyfunc : sk_CONF_IMODULE_copyfunc; freefunc : sk_CONF_IMODULE_freefunc):Pstack_st_CONF_IMODULE;
begin
 Result := Pstack_st_CONF_IMODULE (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
            OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)));
end;


function sk_CONF_IMODULE_set_cmp_func( sk : Pstack_st_CONF_IMODULE; compare : sk_CONF_IMODULE_compfunc):sk_CONF_IMODULE_compfunc;
begin
 Result := sk_CONF_IMODULE_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
             OPENSSL_sk_compfunc(compare)));
end;


procedure module_finish(imod : PCONF_IMODULE);
begin
    if nil =imod then Exit;
    if Assigned(imod.pmod.finish) then
       imod.pmod.finish(imod);
    PostDec(imod.pmod.links);
    OPENSSL_free(imod.name);
    OPENSSL_free(imod.value);
    OPENSSL_free(imod);
end;




procedure CONF_modules_finish;
var
  imod : PCONF_IMODULE;
begin
    while sk_CONF_IMODULE_num(initialized_modules) > 0 do
    begin
        imod := sk_CONF_IMODULE_pop(initialized_modules);
        module_finish(imod);
    end;
    sk_CONF_IMODULE_free(initialized_modules);
    initialized_modules := nil;
end;



procedure ossl_config_modules_free;
begin
    CONF_modules_finish;
    CONF_modules_unload(1);
end;
function CONF_parse_list(const list_ : PUTF8Char; sep, nospc : integer; list_cb : Tlist_cb_func; arg : Pointer):integer;
var
  ret : integer;

  lstart, tmpend, p : PUTF8Char;
begin
    if list_ = nil then
    begin
        ERR_raise(ERR_LIB_CONF, CONF_R_LIST_CANNOT_BE_NULL);
        Exit(0);
    end;
    lstart := list_;
    while true do
    begin
        if nospc > 0 then
        begin
            while (lstart^ <> #0)  and  (isspace(lstart^)) do
               Inc(lstart);
        end;
        p := strchr(lstart, UTF8Char(sep));
        if (p = lstart)  or  (lstart^ = #0) then
           ret := list_cb(nil, 0, arg)
        else
        begin
            if p <> nil then
               tmpend := p - 1
            else
                tmpend := lstart + Length(lstart) - 1;
            if nospc > 0 then
            begin
                while isspace(tmpend^) do
                    Dec(tmpend);
            end;
            ret := list_cb(lstart, tmpend - lstart + 1, arg);
        end;
        if ret <= 0 then Exit(ret);
        if p = nil then Exit(1);
        lstart := p + 1;
    end;
end;

end.
