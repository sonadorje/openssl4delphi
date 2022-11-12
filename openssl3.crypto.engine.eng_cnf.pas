unit openssl3.crypto.engine.eng_cnf;

interface
uses OpenSSL.Api, SysUtils;

function skip_dot(const name : PUTF8Char):PUTF8Char;
  function int_engine_init( e : PENGINE):integer;
  function int_engine_configure({const} name, value : PUTF8Char; cnf : PCONF):integer;
  function int_engine_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
  procedure int_engine_module_finish( md : PCONF_IMODULE);
  procedure ENGINE_add_conf_module;

var
  initialized_engines : Pstack_st_ENGINE;

implementation
uses OpenSSL3.Err, openssl3.openssl.conf,  openssl3.crypto.conf.conf_mod,
     openssl3.crypto.engine.eng_init,      openssl3.crypto.engine.eng_lib,
     openssl3.crypto.engine.eng_ctrl,      openssl3.crypto.engine.eng_fat,
     openssl3.crypto.conf.conf_lib,        openssl3.crypto.engine.eng_list;

function skip_dot(const name : PUTF8Char):PUTF8Char;
var
  p : PUTF8Char;
begin
    p := strchr(name, '.');
    if p <> nil then Exit(p + 1);
    Result := name;
end;


function int_engine_init( e : PENGINE):integer;
begin
    if 0>=ENGINE_init(e) then
        Exit(0);
    if nil =initialized_engines then
       initialized_engines := sk_ENGINE_new_null;
    if (nil =initialized_engines)  or  (0>=sk_ENGINE_push(initialized_engines, e)) then
    begin
        ENGINE_finish(e);
        Exit(0);
    end;
    Result := 1;
end;


function int_engine_configure({const} name, value : PUTF8Char; cnf : PCONF):integer;
var
  i,
  ret       : integer;
  do_init   : long;
  ecmds     : Pstack_st_CONF_VALUE;
  ecmd      : PCONF_VALUE;
  ctrlname,
  ctrlvalue : PUTF8Char;
  e         : PENGINE;
  soft      : integer;
  label _err;
begin
    ret := 0;
    do_init := -1;
    ecmd := nil;
    e := nil;
    soft := 0;
    name := skip_dot(name);
    //OSSL_TRACE1(CONF, 'Configuring engine %s\n', name);
    { Value is a section containing ENGINE commands }
    ecmds := NCONF_get_section(cnf, value);
    if nil =ecmds then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ENGINE_SECTION_ERROR);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(ecmds)-1 do
    begin
        ecmd := sk_CONF_VALUE_value(ecmds, i);
        ctrlname := skip_dot(ecmd.name);
        ctrlvalue := ecmd.value;
        //OSSL_TRACE2(CONF, 'ENGINE: doing ctrl(%s,%s)\n',
                   // ctrlname, ctrlvalue);
        { First handle some special pseudo ctrls }
        { Override engine name to use }
        if strcmp(ctrlname, 'engine_id') = 0  then
            name := ctrlvalue
        else if (strcmp(ctrlname, 'soft_load') = 0) then
            soft := 1
        { Load a dynamic PENGINE  }
        else if (strcmp(ctrlname, 'dynamic_path') = 0) then
        begin
            e := ENGINE_by_id('dynamic');
            if nil =e then goto _err;
            if 0>=ENGINE_ctrl_cmd_string(e, 'SO_PATH', ctrlvalue, 0 ) then
                goto _err;
            if 0>=ENGINE_ctrl_cmd_string(e, 'LIST_ADD', '2', 0 ) then
                goto _err;
            if 0>=ENGINE_ctrl_cmd_string(e, 'LOAD', nil, 0 ) then
                goto _err;
        end
        { ... add other pseudos here ... }
        else
        begin
            {
             * At this point we need an ENGINE structural reference if we
             * don't already have one.
             }
            if nil =e then
            begin
                e := ENGINE_by_id(name);
                if (nil =e)  and  (soft > 0) then
                begin
                    ERR_clear_error;
                    Exit(1);
                end;
                if nil =e then goto _err;
            end;
            {
             * Allow 'EMPTY' to mean no value: this allows a valid 'value' to
             * be passed to ctrls of type NO_INPUT
             }
            if strcmp(ctrlvalue, 'EMPTY' ) = 0 then
                ctrlvalue := nil;
            if strcmp(ctrlname, 'init') = 0  then
            begin
                if 0>=NCONF_get_number_e(cnf, value, 'init', @do_init) then
                    goto _err;
                if do_init = 1 then
                begin
                    if 0>=int_engine_init(e) then
                        goto _err;
                end
                else if (do_init <> 0) then
                begin
                    ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_INIT_VALUE);
                    goto _err;
                end;
            end
            else if (strcmp(ctrlname, 'default_algorithms') = 0) then
            begin
                if 0>=ENGINE_set_default_string(e, ctrlvalue ) then
                    goto _err;
            end
            else
            if (0>=ENGINE_ctrl_cmd_string(e, ctrlname, ctrlvalue, 0))  then
                goto _err;
        end;
    end;
    if (e <> nil) and ( (do_init = -1) and  (0>=int_engine_init(e)) ) then
    begin
        ecmd := nil;
        goto _err;
    end;
    ret := 1;
 _err:
    if ret <> 1 then
    begin
        if ecmd = nil then
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ENGINE_CONFIGURATION_ERROR)
        else
            ERR_raise_data(ERR_LIB_ENGINE, ENGINE_R_ENGINE_CONFIGURATION_ERROR,
                          Format( 'section=%s, name=%s, value=%s',
                           [ecmd.section, ecmd.name, ecmd.value]));
    end;
    ENGINE_free(e);
    Result := ret;
end;


function int_engine_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
  elist : Pstack_st_CONF_VALUE;
  cval : PCONF_VALUE;
  i : integer;
begin
   // OSSL_TRACE2(CONF, 'Called engine module: name %s, value %s\n',
     //           CONF_imodule_get_name(md), CONF_imodule_get_value(md));
    { Value is a section containing ENGINEs to configure }
    elist := NCONF_get_section(cnf, CONF_imodule_get_value(md));
    if nil =elist then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ENGINES_SECTION_ERROR);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(elist)-1 do
    begin
        cval := sk_CONF_VALUE_value(elist, i);
        if 0>=int_engine_configure(cval.name, cval.value, cnf) then
            Exit(0);
    end;
    Result := 1;
end;


procedure int_engine_module_finish( md : PCONF_IMODULE);
var
  e : PENGINE;
begin
    while (e = sk_ENGINE_pop(initialized_engines)) do
        ENGINE_finish(e);
    sk_ENGINE_free(initialized_engines);
    initialized_engines := nil;
end;


procedure ENGINE_add_conf_module;
begin
    CONF_module_add('engines',
                    int_engine_module_init, int_engine_module_finish);
end;


end.
