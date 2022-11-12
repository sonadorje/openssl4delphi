unit openssl3.crypto.conf.conf_ssl;

interface
uses OpenSSL.Api, SysUtils;

type
  PSSL_CONF_CMD = ^TSSL_CONF_CMD;
  ssl_conf_name_st = record
      name      : PUTF8Char;
      cmds      : PSSL_CONF_CMD;
      cmd_count : size_t;
  end;
  Pssl_conf_name_st = ^ssl_conf_name_st;


  ssl_conf_cmd_st = record
    cmd, arg : PUTF8Char;
  end;
  TSSL_CONF_CMD = ssl_conf_cmd_st;
  Pssl_conf_cmd_st = ^ssl_conf_cmd_st;

  procedure ssl_module_free( md : PCONF_IMODULE);
  function ssl_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
  function conf_ssl_get(idx : size_t;{const} name : PPUTF8Char; cnt : Psize_t): PSSL_CONF_CMD;
  function conf_ssl_name_find(const name : PUTF8Char; idx : Psize_t):integer;
  procedure conf_ssl_get_cmd( cmd : PSSL_CONF_CMD; idx : size_t; cmdstr, arg : PPUTF8Char);
  procedure ossl_config_add_ssl_module;

var
  ssl_names: Pssl_conf_name_st;
  ssl_names_count: size_t;

implementation

uses openssl3.crypto.mem, OpenSSL3.Err,       OpenSSL3.openssl.conf,
     openssl3.crypto.o_str,
     openssl3.crypto.conf.conf_mod,           openssl3.crypto.conf.conf_lib;

procedure ssl_module_free( md : PCONF_IMODULE);
var
  i, j : size_t;
  tname : Pssl_conf_name_st;
begin
{$POINTERMATH ON}
    if ssl_names = nil then exit;
    for i := 0 to ssl_names_count-1 do
    begin
        tname := ssl_names + i;
        OPENSSL_free(tname.name);
        for j := 0 to tname.cmd_count-1 do begin
            OPENSSL_free(tname.cmds[j].cmd);
            OPENSSL_free(tname.cmds[j].arg);
        end;
        OPENSSL_free(tname.cmds);
    end;
    OPENSSL_free(ssl_names);
    ssl_names := nil;
    ssl_names_count := 0;
{$POINTERMATH OFF}
end;


function ssl_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
  i,
  j,
  cnt              : size_t;

  rv               : integer;
  ssl_conf_section : PUTF8Char;
  cmd_lists        : Pstack_st_CONF_VALUE;
  rcode            : integer;
  ssl_name         : Pssl_conf_name_st;
  sect             : PCONF_VALUE;
  cmds             : Pstack_st_CONF_VALUE;
  name             : PUTF8Char;
  cmd_conf         : PCONF_VALUE;
  cmd              : PSSL_CONF_CMD;
  label _err;
begin
{$POINTERMATH ON}
    rv := 0;
    ssl_conf_section := CONF_imodule_get_value(md);
    cmd_lists := NCONF_get_section(cnf, ssl_conf_section);
    if sk_CONF_VALUE_num(cmd_lists) <= 0  then
    begin
         rcode := get_result(
            cmd_lists = nil
            , CONF_R_SSL_SECTION_NOT_FOUND
            , CONF_R_SSL_SECTION_EMPTY);
        ERR_raise_data(ERR_LIB_CONF, rcode, Format('section=%s', [ssl_conf_section]));
        goto _err;
    end;
    cnt := sk_CONF_VALUE_num(cmd_lists);
    ssl_module_free(md);
    ssl_names := OPENSSL_zalloc(sizeof( ssl_names^) * cnt);
    if ssl_names = nil then goto _err;
    ssl_names_count := cnt;
    for i := 0 to ssl_names_count-1 do
    begin
        ssl_name := ssl_names + i;
        sect := sk_CONF_VALUE_value(cmd_lists, int(i));
        cmds := NCONF_get_section(cnf, sect.value);
        if sk_CONF_VALUE_num(cmds) <= 0  then
        begin
            rcode := get_result(
                cmds = nil
                , CONF_R_SSL_COMMAND_SECTION_NOT_FOUND
                , CONF_R_SSL_COMMAND_SECTION_EMPTY);
            ERR_raise_data(ERR_LIB_CONF, rcode,
                          Format('name=%s, value=%s', [sect.name, sect.value]));
            goto _err;
        end;
        OPENSSL_strdup(ssl_name.name ,sect.name);
        if ssl_name.name = nil then goto _err;
        cnt := sk_CONF_VALUE_num(cmds);
        ssl_name.cmds := OPENSSL_zalloc(cnt * sizeof(ssl_conf_cmd_st));
        if ssl_name.cmds = nil then goto _err;
        ssl_name.cmd_count := cnt;
        for j := 0 to cnt-1 do
        begin
            cmd_conf := sk_CONF_VALUE_value(cmds, int(j));
            cmd := ssl_name.cmds + j;
            { Skip any initial dot in name }
            name := strchr(cmd_conf.name, '.');
            if name <> nil then
               Inc(name)
            else
                name := cmd_conf.name;
            OPENSSL_strdup(cmd.cmd ,name);
            OPENSSL_strdup(cmd.arg ,cmd_conf.value);
            if (cmd.cmd = nil)  or  (cmd.arg = nil) then
               goto _err;
        end;
    end;
    rv := 1;
 _err:
    if rv = 0 then ssl_module_free(md);
    Result := rv;
{$POINTERMATH OFF}
end;


function conf_ssl_get(idx : size_t;{const} name : PPUTF8Char; cnt : Psize_t): PSSL_CONF_CMD;
begin
{$POINTERMATH ON}
    name^ := ssl_names[idx].name;
    cnt^ := ssl_names[idx].cmd_count;
    Result := ssl_names[idx].cmds;
{$POINTERMATH OFF}
end;


function conf_ssl_name_find(const name : PUTF8Char; idx : Psize_t):integer;
var
  i : size_t;
  nm : Pssl_conf_name_st;
begin
    if name = nil then Exit(0);
    i := 0; nm := ssl_names;
    while i < ssl_names_count do
    begin
        if strcmp(nm.name, name)= 0  then
        begin
            idx^ := i;
            Exit(1);
        end;
        Inc(i); Inc(nm);
    end;
    Result := 0;
end;


procedure conf_ssl_get_cmd( cmd : PSSL_CONF_CMD; idx : size_t; cmdstr, arg : PPUTF8Char);
begin
{$POINTERMATH ON}
    cmdstr^ := cmd[idx].cmd;
    arg^ := cmd[idx].arg;
{$POINTERMATH OFF}
end;


procedure ossl_config_add_ssl_module;
begin
    CONF_module_add('ssl_conf', ssl_module_init, ssl_module_free);
end;


end.
